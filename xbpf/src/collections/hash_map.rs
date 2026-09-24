//! A typed `HashMap<K, V>` backed by an eBPF hash map, built on top of
//! [`libbpf_rs::MapHandle`].
//!
//! [`MapHandle`] owns a duplicated file descriptor rather than borrowing from
//! a skeleton, so [`HashMap`] can be constructed from a loaded skeleton map
//! and then used independently of the skeleton's lifetime.
//!
//! ```no_run
//! # use xbpf::collections::HashMap;
//! # fn get_map() -> &'static libbpf_rs::Map<'static> { todo!() }
//! // Wrap an existing map from a loaded skeleton.
//! let map: HashMap<u32, u64> = HashMap::from_map(get_map())?;
//! map.insert(1, 42)?;
//! assert_eq!(map.get(&1)?, Some(42));
//! # Ok::<(), libbpf_rs::Error>(())
//! ```
use crate::{
    Pod,
    libbpf_rs::{self, Error, ErrorKind, MapCore, MapFlags, MapHandle, MapType},
};
use std::{
    ffi::OsStr,
    fmt, io,
    marker::PhantomData,
    mem,
    os::unix::io::{AsFd, BorrowedFd},
    path::Path,
    ptr, slice,
};

type Result<T> = libbpf_rs::Result<T>;

fn pod_slice_bytes<T: Pod>(items: &[T]) -> &[u8] {
    // SAFETY: `T: Pod` guarantees no padding and array elements are laid out
    // contiguously with a stride of `size_of::<T>()`.
    unsafe { slice::from_raw_parts(items.as_ptr().cast::<u8>(), mem::size_of_val(items)) }
}

fn pod_bytes<T: Pod>(item: &T) -> &[u8] {
    pod_slice_bytes(slice::from_ref(item))
}

fn pod_from_bytes<T: Pod>(bytes: &[u8]) -> T {
    // `bytes` may be longer than `size_of::<T>()`: batch lookups on hash maps
    // pad small keys up to 4 bytes, with the real value in the leading bytes.
    debug_assert!(bytes.len() >= mem::size_of::<T>());
    // SAFETY: `T: Pod` is valid for any bit pattern and `bytes` holds at
    // least `size_of::<T>()` initialized bytes.
    unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
}

fn invalid_input(msg: impl ToString) -> Error {
    Error::from(io::Error::new(io::ErrorKind::InvalidInput, msg.to_string()))
}

fn validate<K: Pod, V: Pod>(handle: &MapHandle) -> Result<()> {
    let ty = handle.map_type();
    if !ty.is_hash_map() || ty.is_percpu() {
        return Err(invalid_input(format!(
            "map {:?} has type {ty:?}, expected a (non-per-cpu) hash map",
            handle.name(),
        )));
    }

    let key_size = mem::size_of::<K>() as u32;
    if handle.key_size() != key_size {
        return Err(invalid_input(format!(
            "map {:?} has key size {}, but `K` has size {key_size}",
            handle.name(),
            handle.key_size(),
        )));
    }

    let value_size = mem::size_of::<V>() as u32;
    if handle.value_size() != value_size {
        return Err(invalid_input(format!(
            "map {:?} has value size {}, but `V` has size {value_size}",
            handle.name(),
            handle.value_size(),
        )));
    }

    Ok(())
}

/// A `HashMap<K, V>` backed by an eBPF `BPF_MAP_TYPE_HASH` (or
/// `BPF_MAP_TYPE_LRU_HASH`) map.
///
/// All operations go through a [`MapHandle`], so `K` and `V` are copied to
/// and from raw bytes on every call; there is no in-process cache.
pub struct HashMap<K, V> {
    handle: MapHandle,
    _marker: PhantomData<fn() -> (K, V)>,
}

impl<K: Pod, V: Pod> HashMap<K, V> {
    /// Creates a new, freestanding `BPF_MAP_TYPE_HASH` map, not tied to any
    /// skeleton.
    pub fn create<T: AsRef<OsStr>>(name: Option<T>, max_entries: u32) -> Result<Self> {
        Self::create_with_type(MapType::Hash, name, max_entries)
    }

    /// Like [`Self::create`], but creates a `BPF_MAP_TYPE_LRU_HASH` map that
    /// evicts the least recently used entry once `max_entries` is reached.
    pub fn create_lru<T: AsRef<OsStr>>(name: Option<T>, max_entries: u32) -> Result<Self> {
        Self::create_with_type(MapType::LruHash, name, max_entries)
    }

    fn create_with_type<T: AsRef<OsStr>>(
        map_type: MapType,
        name: Option<T>,
        max_entries: u32,
    ) -> Result<Self> {
        let opts = libbpf_rs::libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_rs::libbpf_sys::bpf_map_create_opts>() as _,
            ..Default::default()
        };
        let handle = MapHandle::create(
            map_type,
            name,
            mem::size_of::<K>() as u32,
            mem::size_of::<V>() as u32,
            max_entries,
            &opts,
        )?;

        Ok(Self {
            handle,
            _marker: PhantomData,
        })
    }

    /// Wraps an existing map, such as `skel.maps.my_map` from a loaded
    /// skeleton, as a typed `HashMap<K, V>`.
    ///
    /// Fails if the map is not a (non-per-cpu) hash map, or if its key/value
    /// sizes don't match `size_of::<K>()`/`size_of::<V>()`.
    pub fn from_map<'a, M>(map: &'a M) -> Result<Self>
    where
        MapHandle: TryFrom<&'a M, Error = Error>,
    {
        MapHandle::try_from(map)?.try_into()
    }

    /// Opens a previously pinned hash map from its bpffs path.
    pub fn from_pinned_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        MapHandle::from_pinned_path(path)?.try_into()
    }

    /// Opens a loaded hash map from its kernel map id.
    pub fn from_map_id(id: u32) -> Result<Self> {
        MapHandle::from_map_id(id)?.try_into()
    }

    /// Returns the map's name.
    pub fn name(&self) -> &OsStr {
        self.handle.name()
    }

    /// Returns the map's type (`Hash` or `LruHash`).
    pub fn map_type(&self) -> MapType {
        self.handle.map_type()
    }

    /// Returns the maximum number of entries the map can hold.
    pub fn max_entries(&self) -> u32 {
        self.handle.max_entries()
    }

    /// Returns a reference to the underlying [`MapHandle`] primitive, for
    /// operations not exposed directly by `HashMap` (e.g. [`MapCore::info`]).
    pub fn handle(&self) -> &MapHandle {
        &self.handle
    }

    /// Consumes `self`, returning the underlying [`MapHandle`].
    pub fn into_handle(self) -> MapHandle {
        self.handle
    }

    /// Looks up `key`, returning a copy of its value if present.
    pub fn get(&self, key: &K) -> Result<Option<V>> {
        let value = self.handle.lookup(pod_bytes(key), MapFlags::ANY)?;
        Ok(value.map(|bytes| pod_from_bytes(&bytes)))
    }

    /// Returns `true` if the map contains `key`.
    pub fn contains_key(&self, key: &K) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }

    /// Inserts `key`/`value`, overwriting any existing entry, and returns
    /// the previous value if one was present.
    ///
    /// The read of the previous value and the write are not atomic with
    /// respect to concurrent updates from other threads or from the eBPF
    /// program; use [`Self::update`] if you don't need the old value.
    pub fn insert(&self, key: K, value: V) -> Result<Option<V>> {
        let old = self.get(&key)?;
        self.update(key, value)?;
        Ok(old)
    }

    /// Inserts `key`/`value`, overwriting any existing entry. Cheaper than
    /// [`Self::insert`] since it doesn't look up the previous value.
    pub fn update(&self, key: K, value: V) -> Result<()> {
        self.handle
            .update(pod_bytes(&key), pod_bytes(&value), MapFlags::ANY)
    }

    /// Inserts `key`/`value` only if `key` is not already present. Returns
    /// `true` if the entry was inserted.
    pub fn insert_new(&self, key: K, value: V) -> Result<bool> {
        match self
            .handle
            .update(pod_bytes(&key), pod_bytes(&value), MapFlags::NO_EXIST)
        {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Updates `key`'s value only if `key` is already present. Returns
    /// `true` if an existing entry was replaced.
    pub fn replace(&self, key: &K, value: V) -> Result<bool> {
        match self
            .handle
            .update(pod_bytes(key), pod_bytes(&value), MapFlags::EXIST)
        {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Removes `key`, returning its value if it was present.
    ///
    /// Like [`Self::insert`], the lookup and delete are not atomic; use
    /// [`Self::delete`] if you don't need the removed value.
    pub fn remove(&self, key: &K) -> Result<Option<V>> {
        let old = self.get(key)?;
        if old.is_some() {
            self.delete(key)?;
        }
        Ok(old)
    }

    /// Removes `key`. Cheaper than [`Self::remove`] since it doesn't look up
    /// the removed value first.
    pub fn delete(&self, key: &K) -> Result<()> {
        self.handle.delete(pod_bytes(key))
    }

    /// Returns an iterator over the map's keys.
    ///
    /// As with the underlying [`MapCore::keys`], concurrent modification of
    /// the map during iteration may skip or duplicate keys.
    pub fn keys(&self) -> impl Iterator<Item = K> + '_ {
        self.handle.keys().map(|bytes| pod_from_bytes(&bytes))
    }

    /// Returns an iterator over the map's key/value pairs, using batched
    /// lookups.
    pub fn iter(&self) -> Result<impl Iterator<Item = (K, V)> + '_> {
        let batch_size = self.handle.max_entries().clamp(1, 512);
        let iter = self
            .handle
            .lookup_batch(batch_size, MapFlags::ANY, MapFlags::ANY)?;
        Ok(iter.map(|(k, v)| (pod_from_bytes(&k), pod_from_bytes(&v))))
    }

    /// Returns an iterator over the map's values, using batched lookups.
    pub fn values(&self) -> Result<impl Iterator<Item = V> + '_> {
        Ok(self.iter()?.map(|(_, v)| v))
    }

    /// Returns the number of entries currently in the map.
    ///
    /// There's no O(1) primitive for this; it counts the map's keys, so it's
    /// O(n) and subject to the same concurrent-modification caveats as
    /// [`Self::keys`].
    pub fn len(&self) -> usize {
        self.keys().count()
    }

    /// Returns `true` if the map has no entries.
    pub fn is_empty(&self) -> bool {
        self.keys().next().is_none()
    }

    /// Inserts many entries in a single batch syscall.
    pub fn insert_batch(&self, entries: &[(K, V)]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let mut keys = Vec::with_capacity(entries.len() * mem::size_of::<K>());
        let mut values = Vec::with_capacity(entries.len() * mem::size_of::<V>());
        for (k, v) in entries {
            keys.extend_from_slice(pod_bytes(k));
            values.extend_from_slice(pod_bytes(v));
        }

        self.handle.update_batch(
            &keys,
            &values,
            entries.len() as u32,
            MapFlags::ANY,
            MapFlags::ANY,
        )
    }

    /// Removes many entries in a single batch syscall.
    pub fn remove_batch(&self, keys: &[K]) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }

        self.handle.delete_batch(
            pod_slice_bytes(keys),
            keys.len() as u32,
            MapFlags::ANY,
            MapFlags::ANY,
        )
    }

    /// Inserts every entry produced by `iter`, batching the underlying
    /// syscalls.
    pub fn extend<I: IntoIterator<Item = (K, V)>>(&self, iter: I) -> Result<()> {
        let entries: Vec<(K, V)> = iter.into_iter().collect();
        self.insert_batch(&entries)
    }

    /// Removes every entry currently in the map.
    pub fn clear(&self) -> Result<()> {
        let keys: Vec<K> = self.keys().collect();
        self.remove_batch(&keys)
    }

    /// Freezes the map as read-only from user space. Irreversible; see
    /// [`MapHandle::freeze`].
    pub fn freeze(&self) -> Result<()> {
        self.handle.freeze()
    }

    /// Pins the map to `path` on bpffs.
    pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        self.handle.pin(path)
    }

    /// Unpins the map from `path` on bpffs.
    pub fn unpin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        self.handle.unpin(path)
    }
}

impl<K: Pod, V: Pod> TryFrom<MapHandle> for HashMap<K, V> {
    type Error = Error;

    fn try_from(handle: MapHandle) -> Result<Self> {
        validate::<K, V>(&handle)?;
        Ok(Self {
            handle,
            _marker: PhantomData,
        })
    }
}

impl<K, V> AsFd for HashMap<K, V> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.handle.as_fd()
    }
}

impl<K, V> fmt::Debug for HashMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashMap")
            .field("name", &self.handle.name())
            .field("map_type", &self.handle.map_type())
            .field("max_entries", &self.handle.max_entries())
            .finish()
    }
}
