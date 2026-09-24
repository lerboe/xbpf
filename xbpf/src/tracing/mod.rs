//! Rich and event-based diagnostic information for eBPF.
//!
//! The `xbpf.h` header exports a set of macros that emit diagnostic events from
//! an eBPF program. The events are copied to user space through a ring buffer
//! and re-emitted here as ordinary [`tracing`] events, so they show up in
//! whatever subscriber the program already installed, nested in spans and
//! filtered by level like any other event.
//!
//! Which macros compile to anything is decided when the eBPF program is built,
//! because tracing is expensive in eBPF. See [`mod@crate::build`] for that, and
//! [`crate::event`] for the wire format in between.
//!
//! [`crate::Program::build`] calls [`try_init`] itself, so this module only has
//! to be driven directly when an object is loaded some other way.
//!
//! # Examples
//!
//! ```no_run
//! use xbpf::libbpf_rs::ObjectBuilder;
//!
//! # fn main() -> xbpf::libbpf_rs::Result<()> {
//! tracing_subscriber::fmt()
//!     .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
//!     .with_file(true)
//!     .with_line_number(true)
//!     .init();
//!
//! let obj = ObjectBuilder::default()
//!     .open_file("syscall_trace.bpf.o")?
//!     .load()?;
//!
//! xbpf::tracing::try_init(&obj)?;
//! # Ok(())
//! # }
//! ```
//!
//! And in the eBPF program:
//!
//! ```custom,{.language-c}
//! bpf_start_info_span("sockops");
//! bpf_info("Established socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
//! bpf_end_span("sockops");
//! ```
//!
//! [`tracing`]: https://github.com/tokio-rs/tracing
use crate::{
    collections::RingBuf,
    libbpf_rs::{self, MapCore, MapHandle, PrintLevel},
};
pub use event::{CallsiteKey, Event, Kind};
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    path::{Component, Path, PathBuf},
    thread::{self},
};
use tracing::{self, metadata::Metadata, span::EnteredSpan};

mod event;

/// The [`tracing`] target every event from an eBPF program is emitted under,
/// so that `RUST_LOG=bpf=debug` filters them as a group.
const TARGET: &str = "bpf";

/// How many events are buffered in user space before they are dropped. The
/// events are small, so this is generous enough to absorb a burst that the
/// eBPF ring buffer cannot hold on its own.
const USERSPACE_CAPACITY: usize = 16 * 1024;

/// The spans that are currently open, as a stack per CPU.
///
/// Each entry pairs the name a span was opened with, which is what
/// [`Kind::EndSpan`] matches on, with the guard that keeps it entered.
type Spans = Vec<VecDeque<(String, EnteredSpan)>>;

// Both of these are thread local because the ring buffer is polled from a
// single thread, so nothing else ever touches them.
thread_local! {
    static CALLSITES: RefCell<HashMap<CallsiteKey, &'static Metadata<'static>>> = RefCell::new(HashMap::new());
    static SPANS: RefCell<Spans> = {
        let cpus = thread::available_parallelism().unwrap().get();
        let mut spans: Spans = Vec::new();
        for _ in 0..cpus {
            spans.push(VecDeque::new());
        }
        RefCell::new(spans)
    };
}

/// Callback for libbpf to print messages to the tracing infrastructure.
fn print(level: libbpf_rs::PrintLevel, msg: String) {
    let msg = msg.trim_start_matches("libbpf:").trim();

    match level {
        PrintLevel::Debug => tracing::debug!(target: "libbpf", "{}", msg),
        PrintLevel::Info => tracing::info!(target: "libbpf", "{}", msg),
        PrintLevel::Warn => tracing::warn!(target: "libbpf", "{}", msg),
    }
}

/// Starts reading the events of `obj` and emitting them as [`tracing`] events.
///
/// This spawns a thread that polls the `bpf_tracing_events` ring buffer of the
/// object for as long as the process lives. It also installs [`print`] as the
/// libbpf print callback, unless one is already set, so that libbpf's own
/// messages end up in the same place under the `libbpf` target.
///
/// [`crate::Program::build`] calls this, so it only has to be called directly
/// for objects that were loaded some other way.
///
/// # Errors
///
/// Returns an error if `obj` has no `bpf_tracing_events` ring buffer, which is
/// the case for programs that don't include `xbpf.h`, or if querying that map
/// fails.
///
/// # Panics
///
/// Panics if the ring buffer cannot be set up, for instance because the map is
/// not of type `BPF_MAP_TYPE_RINGBUF`.
///
/// [`tracing`]: https://github.com/tokio-rs/tracing
pub fn try_init(obj: &libbpf_rs::Object) -> libbpf_rs::Result<()> {
    if libbpf_rs::get_print().is_none() {
        libbpf_rs::set_print(Some((PrintLevel::Debug, print)));
    }

    let mut events: Option<MapHandle> = None;

    for map in obj.maps() {
        if map.name().eq("bpf_tracing_events") {
            let map_id = map.info()?.info.id;
            events = Some(MapHandle::from_map_id(map_id)?);
        }
    }

    let Some(events) = events else {
        return Err(libbpf_rs::Error::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "event ring buffer not found",
        )));
    };

    let mut ring_buf: RingBuf<Event> = RingBuf::new(events, USERSPACE_CAPACITY)?;

    // A single long lived thread, so that the per CPU span stacks and the
    // callsite cache, which are thread local, stay consistent across events.
    thread::spawn(move || {
        while let Some(event) = ring_buf.blocking_recv() {
            match event {
                Ok(event) => emit(event),
                Err(err) => tracing::warn!(target: TARGET, "Failed to decode event: {err}"),
            }
        }
    });

    Ok(())
}

/// Returns `full` without the leading components it shares with `base`.
///
/// The eBPF side records `__FILE__` as it was passed to clang, which is an
/// absolute path. Dropping the part that the crate root also has makes the
/// logged location match how the file is written in the source tree.
fn strip_matching_prefix_components(full: &Path, base: &Path) -> PathBuf {
    let mut full_it = full.components().peekable();
    let mut base_it = base.components().peekable();

    while let (Some(f), Some(b)) = (full_it.peek(), base_it.peek()) {
        if f == b {
            full_it.next();
            base_it.next();
        } else {
            break;
        }
    }

    let mut out = PathBuf::new();
    for c in full_it {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => out.push("."),
            Component::ParentDir => out.push(".."),
            Component::RootDir => out.push(Path::new("/")),
            Component::Prefix(p) => out.push(p.as_os_str()),
        }
    }
    out
}

/// Returns the callsite for `key`, creating and leaking it on first use.
///
/// [`tracing`] requires the metadata of a callsite to live for `'static`, which
/// events decoded at run time cannot satisfy on their own. There is one
/// callsite per distinct [`CallsiteKey`], so the number that can be leaked is
/// bounded by the number of tracing macros in the eBPF program.
fn get_callsite(key: CallsiteKey) -> &'static Metadata<'static> {
    CALLSITES.with_borrow_mut(|cs| {
        if let Some(meta) = cs.get(&key) {
            *meta
        } else {
            let (file, line, is_span, level) = key;

            let callsite = if is_span {
                tracing::callsite!(name: "fake", kind: tracing::metadata::Kind::EVENT, fields: &[])
            } else {
                tracing::callsite!(name: "fake", kind: tracing::metadata::Kind::SPAN, fields: &[])
            };

            let static_file: Option<&'static str> = if let Some(ref file) = file {
                let path = Path::new(&file);
                let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
                let rel = strip_matching_prefix_components(path, manifest)
                    .to_string_lossy()
                    .to_string();

                Some(Box::leak(rel.into_boxed_str()) as &'static str)
            } else {
                None
            };

            let meta = Box::leak(Box::new(Metadata::new(
                "",
                TARGET,
                level,
                static_file,
                line,
                None,
                tracing::field::FieldSet::new(
                    &["message"],
                    tracing::callsite::Identifier(callsite),
                ),
                if is_span {
                    tracing::metadata::Kind::SPAN
                } else {
                    tracing::metadata::Kind::EVENT
                },
            )));

            let key = (file, line, is_span, level);
            cs.insert(key, meta);

            let meta: &'static Metadata = meta;
            meta
        }
    })
}

/// Emits `event` as a [`tracing`] event, nested in the spans that are open on
/// the CPU it came from.
///
/// A [`Kind::EndSpan`] closes the innermost span whose name matches, along with
/// every span opened inside it, so that a span whose end was dropped by a full
/// ring buffer doesn't stay open forever.
fn emit(event: Event) {
    let cpu = event.cpu;
    SPANS.with_borrow_mut(|spans| {
        // `available_parallelism` only counts the CPUs this process may run on,
        // which can be fewer than the ids the kernel reports events from.
        if cpu >= spans.len() {
            spans.resize_with(cpu + 1, VecDeque::new);
        }

        match &event.kind {
            Kind::Message(lvl) => {
                if *lvl <= tracing::metadata::LevelFilter::current() {
                    let content = event.content.clone();
                    let meta = get_callsite(event.try_into().unwrap());
                    let parent = spans[cpu].back().and_then(|(_, p)| p.id());

                    tracing::Event::child_of(
                        parent,
                        meta,
                        &tracing::valueset_all!(meta.fields(), "{}", content),
                    );
                }
            }
            Kind::StartSpan(lvl) => {
                if *lvl <= tracing::metadata::LevelFilter::current() {
                    let content = event.content.clone();
                    let meta = get_callsite(event.try_into().unwrap());
                    let parent = spans[cpu].back().and_then(|(_, p)| p.id());

                    let span = tracing::Span::child_of(
                        parent,
                        meta,
                        &tracing::valueset_all!(meta.fields(), "{}", content),
                    );
                    spans[cpu].push_back((content, span.entered()));
                }
            }
            Kind::EndSpan => {
                let content = event.content;
                while let Some((n, _)) = spans[cpu].pop_back() {
                    if n == content {
                        break;
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use tracing::Level;

    use super::*;

    #[test]
    fn leaks_one_callsite_per_level_and_kind() {
        fn callsite_len() -> usize {
            CALLSITES.with_borrow(|cs| cs.len())
        }

        let event_msg_info1 = Event {
            kind: Kind::Message(Level::INFO),
            content: "event 1".to_string(),
            cpu: 1,
            file: None,
            line: None,
        };

        let event_msg_info2 = Event {
            kind: Kind::Message(Level::INFO),
            content: "event 2".to_string(),
            cpu: 9,
            file: None,
            line: None,
        };

        let _callsite1 = get_callsite(event_msg_info1.try_into().unwrap());
        let _callsite2 = get_callsite(event_msg_info2.try_into().unwrap());
        assert_eq!(callsite_len(), 1);

        let event_span_info3 = Event {
            kind: Kind::StartSpan(Level::INFO),
            content: "event 3".to_string(),
            cpu: 29,
            file: None,
            line: None,
        };
        let _callsite3 = get_callsite(event_span_info3.try_into().unwrap());
        assert_eq!(callsite_len(), 2);

        let event_span_info4 = Event {
            kind: Kind::StartSpan(Level::INFO),
            content: "event 4".to_string(),
            cpu: 29,
            file: Some(String::from("this/is/a/test_file.rs")),
            line: Some(12),
        };
        let _callsite4 = get_callsite(event_span_info4.try_into().unwrap());
        assert_eq!(callsite_len(), 3);

        let event_span_info5 = Event {
            kind: Kind::StartSpan(Level::INFO),
            content: "event 5".to_string(),
            cpu: 29,
            file: Some(String::from("this/is/a/test_file.rs")),
            line: Some(12),
        };
        let _callsite5 = get_callsite(event_span_info5.try_into().unwrap());
        assert_eq!(callsite_len(), 3);
    }
}
