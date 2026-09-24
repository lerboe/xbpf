// The tests build eBPF programs with `xbpf::build` and assert on what
// `xbpf::tracing` emits, so they need both features.
#![cfg(all(feature = "build", feature = "tracing"))]

use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tracing::{Level, level_filters::LevelFilter};
use tracing_subscriber::fmt::MakeWriter;
use xbpf::{
    build::Builder,
    libbpf_rs::{ObjectBuilder, ProgramInput},
};

/// A `tracing_subscriber` writer that buffers everything in memory instead
/// of writing to stdout/stderr, so tests can inspect what was logged.
#[derive(Clone, Default)]
struct InMemoryWriter(Arc<Mutex<Vec<u8>>>);

impl InMemoryWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).expect("log output is valid utf-8")
    }
}

impl Write for InMemoryWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for InMemoryWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Compiles the eBPF source file `name` from `tests/bpf` into `dir` and
/// returns the path of the resulting object file.
///
/// The tests compile their eBPF programs at run time rather than from a build
/// script, so that `xbpf` itself doesn't need one.
fn build_bpf_obj(name: &str, dir: &Path) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("bpf")
        .join(name);

    let mut objs = Builder::new()
        .source(&src)
        .out_dir(dir)
        .tracing_level(LevelFilter::DEBUG)
        .tracing_ring_buf_size(512 * 1024)
        .build_objects();

    objs.pop()
        .unwrap_or_else(|| panic!("no object built for {}", src.display()))
}

mod tests {
    use super::*;

    #[test]
    fn high_tracing_freq() {
        let writer = InMemoryWriter::default();
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_writer(writer.clone())
            .with_ansi(false)
            .init();

        let dir = tempfile::tempdir().expect("temp dir");
        let obj_path = build_bpf_obj("loop.bpf.c", dir.path());

        let obj = ObjectBuilder::default()
            .open_file(&obj_path)
            .expect("open object")
            .load()
            .expect("load object");
        xbpf::tracing::try_init(&obj).expect("xbpf::tracing init");

        // `trace_loop` is a BPF_PROG_TYPE_SYSCALL program: it isn't
        // attached to anything, it's invoked directly via BPF_PROG_RUN.
        let prog = obj
            .progs_mut()
            .find(|prog| prog.name() == "trace_loop")
            .expect("trace_loop program");
        prog.test_run(ProgramInput::default()).expect("test run");

        let log = wait_for_events(&writer, 1000, Duration::from_secs(5));

        let numbers: Vec<u32> = log
            .lines()
            .filter_map(|line| line.rsplit_once("bpf: asdf qwer asdf qwer "))
            .filter_map(|(_, msg)| msg.trim().parse::<u32>().ok())
            .collect();

        assert_eq!(numbers, (0..1000).collect::<Vec<u32>>());
    }

    fn wait_for_events(writer: &InMemoryWriter, expected: usize, timeout: Duration) -> String {
        let start = Instant::now();
        loop {
            let log = writer.contents();
            let seen = log.lines().filter(|line| line.contains("bpf: ")).count();
            if seen >= expected || start.elapsed() > timeout {
                return log;
            }
        }
    }
}
