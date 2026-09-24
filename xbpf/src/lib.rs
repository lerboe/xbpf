//! An ergonomic and light-weight eBPF library.
//!
//! xBPF is a thin layer on top of [`libbpf`], covering the parts of an eBPF
//! project that look the same everywhere: compiling the eBPF sources of a crate
//! and generating skeletons for them ([`mod@build`]), loading such a skeleton into
//! the kernel ([`Program`]), and turning the diagnostics an eBPF program emits
//! into ordinary [`tracing`] events ([`mod@tracing`]).
//!
//! # Examples
//!
//! Compile every `*.bpf.c` file below `src` from the build script of the crate:
//!
//! ```no_run
//! // build.rs
//! fn main() {
//!     xbpf::build();
//! }
//! ```
//!
//! Write the eBPF program, including `xbpf.h` to get the tracing macros:
//!
//! ```custom,{.language-c}
//! #include "vmlinux.h"
//! #include "xbpf.h"
//! #include <bpf/bpf_helpers.h>
//!
//! char LICENSE[] SEC("license") = "GPL";
//!
//! SEC("tracepoint/raw_syscalls/sys_enter")
//! int trace_syscall(struct trace_event_raw_sys_enter *ctx) {
//!     bpf_info("syscall %ld", ctx->id);
//!     return 0;
//! }
//! ```
//!
//! Include the generated skeleton and load it. [`Program::build`] also starts
//! the reader that emits what the program traces, so no further setup is needed
//! to see the events of the program in the log:
//!
//! ```no_run
//! # use std::mem::MaybeUninit;
//! # use xbpf::libbpf_rs::{
//! #     Object, ObjectBuilder, OpenObject as LibbpfOpenObject, Result, libbpf_sys,
//! #     skel::{OpenSkel, Skel, SkelBuilder},
//! # };
//! # #[derive(Default)]
//! # struct SyscallTraceSkelBuilder;
//! # struct OpenSyscallTraceSkel;
//! # struct SyscallTraceSkel;
//! #
//! # impl<'obj> SkelBuilder<'obj> for SyscallTraceSkelBuilder {
//! #     type Output = OpenSyscallTraceSkel;
//! #
//! #     fn open(self, _object: &'obj mut MaybeUninit<LibbpfOpenObject>) -> Result<Self::Output> {
//! #         unimplemented!()
//! #     }
//! #
//! #     fn open_opts(
//! #         self,
//! #         _opts: libbpf_sys::bpf_object_open_opts,
//! #         _object: &'obj mut MaybeUninit<LibbpfOpenObject>,
//! #     ) -> Result<Self::Output> {
//! #         unimplemented!()
//! #     }
//! #
//! #     fn object_builder(&self) -> &ObjectBuilder {
//! #         unimplemented!()
//! #     }
//! #
//! #     fn object_builder_mut(&mut self) -> &mut ObjectBuilder {
//! #         unimplemented!()
//! #     }
//! # }
//! #
//! # impl<'obj> OpenSkel<'obj> for OpenSyscallTraceSkel {
//! #     type Output = SyscallTraceSkel;
//! #
//! #     fn load(self) -> Result<Self::Output> {
//! #         unimplemented!()
//! #     }
//! #
//! #     fn open_object(&self) -> &LibbpfOpenObject {
//! #         unimplemented!()
//! #     }
//! #
//! #     fn open_object_mut(&mut self) -> &mut LibbpfOpenObject {
//! #         unimplemented!()
//! #     }
//! # }
//! #
//! # impl<'obj> Skel<'obj> for SyscallTraceSkel {
//! #     fn object(&self) -> &Object {
//! #         unimplemented!()
//! #     }
//! #
//! #     fn object_mut(&mut self) -> &mut Object {
//! #         unimplemented!()
//! #     }
//! # }
//! #
//! # fn main() -> xbpf::libbpf_rs::Result<()> {
//! use xbpf::{OpenObject, Program};
//!
//! // Brings `SyscallTraceSkelBuilder` into scope.
//! // xbpf::include_bpf!("syscall_trace");
//!
//! let mut open_obj = OpenObject::new();
//! let prog = Program::build(SyscallTraceSkelBuilder::default(), &mut open_obj)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! * `build` (enabled by default) — the [`mod@build`] module, which compiles eBPF
//!   sources from a build script.
//! * `tracing` (enabled by default) — the [`mod@tracing`] and [`event`] modules,
//!   which surface the events of an eBPF program as [`tracing`] events. Without
//!   it the macros of `xbpf.h` compile to nothing.
//! * `tracing-source-loc` — makes every event carry the file and line of the
//!   macro that emitted it, at the cost of a larger event. See
//!   [`build::tracing_str_len_args`].
//! * `test` — the [`mod@test`] module and the [`macro@test`] attribute, which
//!   run `BPF_PROG_TYPE_SYSCALL` programs from Rust tests.
//!
//! [`libbpf`]: libbpf_rs
//! [`tracing`]: https://github.com/tokio-rs/tracing

/// The eBPF build tooling [`mod@build`] drives, re-exported so that dependents
/// don't have to track its version themselves.
pub use libbpf_cargo;

/// The eBPF bindings xBPF is built on, re-exported so that dependents don't
/// have to track its version themselves.
pub use libbpf_rs;

mod obj;
pub use obj::OpenObject;

mod pod;
pub use pod::Pod;

mod prog;
pub use prog::Program;

#[cfg(feature = "collections")]
pub mod collections;

#[cfg(feature = "tracing")]
pub mod tracing;

#[cfg(feature = "test")]
pub mod test;
#[cfg(feature = "test")]
pub use xbpf_macros::test;

#[cfg(feature = "build")]
pub mod build;
#[cfg(feature = "build")]
pub use build::build;
