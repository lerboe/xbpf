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
    libbpf_rs::{Error, ProgramInput, ProgramMut, Result},
};
use std::{io, mem, slice};

/// Runs the syscall program `prog` on `ctx` and returns `ctx` as the program
/// left it.
///
/// # Errors
///
/// Fails if the kernel rejects the run, or if the program returns anything
/// other than `0`.
///
pub fn run<T: Pod>(prog: &ProgramMut<'_>, mut ctx: T) -> Result<T> {
    // SAFETY: `ctx` is `size_of::<T>()` writable bytes, and `T: Pod` is valid
    // for whatever the program writes to it.
    let bytes = unsafe { slice::from_raw_parts_mut((&raw mut ctx).cast(), mem::size_of::<T>()) };
    let output = prog.test_run(ProgramInput {
        context_in: Some(bytes),
        ..Default::default()
    })?;

    let retval = output.return_value as i32;
    if retval != 0 {
        return Err(Error::from(io::Error::other(format!(
            "eBPF program returned {retval}"
        ))));
    }

    Ok(ctx)
}
