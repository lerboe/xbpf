//! Testing `BPF_PROG_TYPE_SYSCALL` programs from Rust.
//!
//! [`macro@crate::test`] turns a function into a test that loads an eBPF
//! object and exposes one of its syscall programs as a closure. The closure
//! takes the context of the program by value, runs the program on it with
//! `BPF_PROG_TEST_RUN` and returns the context as the program left it.
//!
//! ```custom,{.language-c}
//! // src/counter.bpf.c
//! #include "vmlinux.h"
//! #include <bpf/bpf_helpers.h>
//!
//! char LICENSE[] SEC("license") = "GPL";
//!
//! struct args {
//!     int a;
//!     int b;
//!     int sum;
//! };
//!
//! SEC("syscall")
//! int add(struct args *args) {
//!     args->sum = args->a + args->b;
//!     return 0;
//! }
//! ```
//!
//! ```ignore
//! mod counter {
//!     xbpf::include_bpf!("counter");
//!
//!     unsafe impl xbpf::Pod for types::args {}
//! }
//!
//! #[xbpf::test(counter, add)]
//! fn adds() {
//!     let args = add(types::args { a: 2, b: 3, sum: 0 }).unwrap();
//!     assert_eq!(args.sum, 5);
//! }
//! ```
//!
//! The first argument names a module in scope that includes the skeleton of
//! the eBPF object of the same name. The object must be built by the build
//! script of the crate, see [`mod@crate::build`], and the crate must depend on
//! `libbpf-rs`, which the generated skeleton refers to. The structs of the
//! eBPF program are available through `types`, and each context type must
//! implement [`Pod`]. The
//! program is loaded without [`mod@crate::tracing`], so the eBPF source
//! doesn't need to include `xbpf.h`.
//!
//! Running a program with `BPF_PROG_TEST_RUN` requires `CAP_BPF` and
//! `CAP_PERFMON`, so tests usually run as root.

use crate::{
    Pod,
    libbpf::{Error, Result, libbpf_sys},
};
use std::{
    io,
    mem::{self, MaybeUninit},
    os::fd::{AsFd, AsRawFd},
};

/// Runs the syscall program `prog` on `ctx` and returns `ctx` as the program
/// left it.
///
/// # Errors
///
/// Fails if the kernel rejects the run, or if the program returns anything
/// other than `0`.
///
pub fn run<T: Pod>(prog: &impl AsFd, ctx: T) -> Result<T> {
    let mut ctx = MaybeUninit::new(ctx);

    // SAFETY: `bpf_test_run_opts` is a plain C struct, all zeros is its default.
    let mut opts: libbpf_sys::bpf_test_run_opts = unsafe { mem::zeroed() };
    opts.sz = mem::size_of_val(&opts) as _;
    opts.ctx_in = ctx.as_mut_ptr().cast_const().cast();
    opts.ctx_size_in = mem::size_of::<T>() as _;

    // SAFETY: `ctx_in` points to `size_of::<T>()` writable bytes.
    let rc = unsafe { libbpf_sys::bpf_prog_test_run_opts(prog.as_fd().as_raw_fd(), &mut opts) };
    if rc < 0 {
        return Err(Error::from(io::Error::from_raw_os_error(-rc)));
    }

    let retval = opts.retval as i32;
    if retval != 0 {
        return Err(Error::from(io::Error::other(format!(
            "eBPF program returned {retval}"
        ))));
    }

    // SAFETY: `ctx` was initialized, and `T: Pod` is valid for whatever the
    // program wrote to it.
    Ok(unsafe { ctx.assume_init() })
}
