//! Wrappers around eBPF maps.
//!
//! The eBPF ring buffer drops records whenever an eBPF program submits one
//! while the buffer is full, so the time user space spends between two reads
//! of it directly translates into lost events. [`RingBuf`] keeps that time as
//! short as possible: its reader thread does nothing but copy records into a
//! [`tokio`] channel, and the records are only decoded once they are received
//! from it.
//!
//! Note that this can only reduce the loss, not avoid it. An eBPF program that
//! submits records faster than user space can read them still overruns the ring
//! buffer, and once the channel is full records are dropped from it as well.
//! [`RingBuf::dropped`] reports how many were lost that way.

use crate::libbpf_rs::{Error, MapCore, MapHandle, MapType, Result, RingBufferBuilder};
use std::{
    io,
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::sync::mpsc::{Receiver, Sender, channel, error::TrySendError};

/// How long the reader thread waits for records before it checks whether it
/// has been asked to stop.
const POLL_TIMEOUT: Duration = Duration::from_millis(1);

/// A reader for an eBPF ring buffer that buffers records in user space.
///
/// Records are read by a dedicated thread that copies them into a bounded
/// channel of `userspace_capacity` records, which decouples reading the ring
/// buffer from decoding and handling its records. See the [module
/// documentation][self] for what this does and doesn't guarantee.
///
/// The reader thread stops once the `RingBuf` is dropped.
pub struct RingBuf<V> {
    /// The channel the reader thread copies the records into.
    rx: Receiver<Box<[u8]>>,

    /// The number of records dropped because the channel was full.
    dropped: Arc<AtomicU64>,

    /// Tells the reader thread to stop.
    stop: Arc<AtomicBool>,

    /// The handle of the reader thread, taken when it is joined.
    reader: Option<JoinHandle<()>>,

    value: PhantomData<fn() -> V>,
}

impl<V> RingBuf<V> {
    /// Starts reading the ring buffer `map`, buffering up to
    /// `userspace_capacity` records in user space.
    ///
    /// # Errors
    /// Returns an error if `map` is not a ring buffer, if `userspace_capacity`
    /// is zero or if the ring buffer cannot be opened.
    pub fn new(map: MapHandle, userspace_capacity: usize) -> Result<Self> {
        if map.map_type() != MapType::RingBuf {
            return Err(invalid_input(format!(
                "expected a ring buffer map, got {:?}",
                map.map_type()
            )));
        }

        if userspace_capacity == 0 {
            return Err(invalid_input("userspace_capacity must not be zero"));
        }

        let (tx, rx) = channel(userspace_capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        // `RingBuffer` borrows the map it reads from, so the handle is moved
        // into the thread that outlives it instead of being stored alongside.
        let reader = {
            let dropped = Arc::clone(&dropped);
            let stop = Arc::clone(&stop);
            thread::Builder::new()
                .name(String::from("xbpf-ringbuf"))
                .spawn(move || read(map, tx, dropped, stop))
                .map_err(Error::from)?
        };

        Ok(Self {
            rx,
            dropped,
            stop,
            reader: Some(reader),
            value: PhantomData,
        })
    }

    /// Returns the number of records that were read from the ring buffer but
    /// dropped because the user space buffer was full.
    ///
    /// This does not count the records that the eBPF program failed to submit
    /// because the ring buffer itself was full, which user space cannot
    /// observe.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Returns the number of buffered records that have not been received yet.
    pub fn len(&self) -> usize {
        self.rx.len()
    }

    /// Returns whether there are no buffered records.
    pub fn is_empty(&self) -> bool {
        self.rx.is_empty()
    }
}

impl<V, E> RingBuf<V>
where
    V: for<'a> TryFrom<&'a [u8], Error = E>,
{
    /// Receives and decodes the next record, waiting for one to arrive.
    ///
    /// Returns `None` once the reader thread has stopped and all buffered
    /// records have been received.
    pub async fn recv(&mut self) -> Option<std::result::Result<V, E>> {
        self.rx.recv().await.map(|r| V::try_from(&r))
    }

    /// Like [`RingBuf::recv`], but blocks the current thread.
    ///
    /// # Panics
    /// Panics if called from within an asynchronous execution context.
    pub fn blocking_recv(&mut self) -> Option<std::result::Result<V, E>> {
        self.rx.blocking_recv().map(|r| V::try_from(&r))
    }

    /// Receives and decodes the next record if one is buffered.
    pub fn try_recv(&mut self) -> Option<std::result::Result<V, E>> {
        self.rx.try_recv().ok().map(|r| V::try_from(&r))
    }
}

impl<V> Drop for RingBuf<V> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.rx.close();

        if let Some(reader) = self.reader.take() {
            // The thread wakes up at least every `POLL_TIMEOUT` to notice that
            // it has been asked to stop.
            let _ = reader.join();
        }
    }
}

/// Reads `map` until `stop` is set, copying every record into `tx`.
fn read(map: MapHandle, tx: Sender<Box<[u8]>>, dropped: Arc<AtomicU64>, stop: Arc<AtomicBool>) {
    let mut builder = RingBufferBuilder::new();
    let res = builder.add(&map, |record: &[u8]| {
        // Copying the record is all that happens here. Anything more expensive
        // would keep the ring buffer from being drained and cost records that
        // the eBPF program then fails to submit.
        match tx.try_send(Box::from(record)) {
            Ok(()) => 0,
            Err(TrySendError::Full(_)) => {
                dropped.fetch_add(1, Ordering::Relaxed);
                0
            }
            Err(TrySendError::Closed(_)) => {
                stop.store(true, Ordering::Relaxed);
                0
            }
        }
    });
    if res.is_err() {
        return;
    }

    let Ok(ring_buf) = builder.build() else {
        return;
    };

    while !stop.load(Ordering::Relaxed) {
        // A timeout rather than an indefinite wait, so that the thread notices
        // when it is asked to stop even if no records ever arrive.
        let _ = ring_buf.poll(POLL_TIMEOUT);
    }
}

fn invalid_input<M: Into<Box<dyn std::error::Error + Send + Sync>>>(msg: M) -> Error {
    Error::from(io::Error::new(io::ErrorKind::InvalidInput, msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libbpf_rs::libbpf_sys;
    use std::{mem::MaybeUninit, time::Instant};

    /// A value that is never decoded, the tests only exercise the buffering.
    struct Raw;

    impl TryFrom<&[u8]> for Raw {
        type Error = ();

        fn try_from(_event: &[u8]) -> std::result::Result<Self, Self::Error> {
            Ok(Raw)
        }
    }

    fn create_map(map_type: MapType, max_entries: u32) -> MapHandle {
        let opts =
            unsafe { MaybeUninit::<libbpf_sys::bpf_map_create_opts>::zeroed().assume_init() };
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..opts
        };

        let (key_size, value_size) = match map_type {
            MapType::RingBuf => (0, 0),
            _ => (4, 4),
        };

        MapHandle::create(
            map_type,
            Some("xbpf_test"),
            key_size,
            value_size,
            max_entries,
            &opts,
        )
        .expect("create map")
    }

    #[test]
    fn rejects_a_map_that_is_not_a_ring_buffer() {
        let map = create_map(MapType::Array, 1);
        assert!(RingBuf::<Raw>::new(map, 1).is_err());
    }

    #[test]
    fn rejects_a_zero_capacity() {
        let map = create_map(MapType::RingBuf, 4096);
        assert!(RingBuf::<Raw>::new(map, 0).is_err());
    }

    #[test]
    fn dropping_it_stops_the_reader_thread() {
        let map = create_map(MapType::RingBuf, 4096);
        let ring_buf = RingBuf::<Raw>::new(map, 1).expect("ring buffer");

        // Wait for the reader thread to be inside `poll`, so that dropping
        // really has to interrupt it instead of winning a race against its
        // first iteration.
        thread::sleep(POLL_TIMEOUT + POLL_TIMEOUT / 2);

        // `Drop` joins the reader thread, which wakes up at least every
        // `POLL_TIMEOUT` to notice that it was asked to stop.
        let start = Instant::now();
        drop(ring_buf);

        assert!(
            start.elapsed() < 2 * POLL_TIMEOUT,
            "joining the reader thread took {:?}",
            start.elapsed()
        );
    }
}
