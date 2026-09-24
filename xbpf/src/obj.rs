//! Storage for the eBPF object a skeleton is opened into.
use crate::libbpf_rs;
use std::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};

/// The uninitialized storage a skeleton is opened into.
///
/// Opening a skeleton writes the [`libbpf_rs::OpenObject`] into memory the caller
/// provides, and the loaded skeleton borrows from it, so the storage has to
/// outlive the skeleton. This is a named place to put it that dereferences to
/// the [`MaybeUninit`] libbpf expects and, unlike it, can be moved across
/// threads.
///
/// # Examples
///
/// ```
/// use xbpf::OpenObject;
///
/// let mut open_obj = OpenObject::new();
/// // Pass `&mut open_obj` to `Program::build`, and keep it alive for as long
/// // as the program is loaded.
/// ```
pub struct OpenObject {
    inner: MaybeUninit<libbpf_rs::OpenObject>,
}

impl OpenObject {
    /// Creates storage for an eBPF object that has not been opened yet.
    pub fn new() -> Self {
        Self {
            inner: MaybeUninit::uninit(),
        }
    }
}

impl Deref for OpenObject {
    type Target = MaybeUninit<libbpf_rs::OpenObject>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for OpenObject {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

// SAFETY: the storage is either uninitialized or holds a `libbpf_rs::OpenObject`,
// which is itself `Send`: it owns nothing but a pointer to the `bpf_object`
// libbpf allocated, and that pointer isn't tied to the thread that opened it.
unsafe impl Send for OpenObject {}
