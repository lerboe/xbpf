#![allow(unused_imports)]
use anyhow::Result;
use std::{mem::MaybeUninit, thread::sleep, time::Duration};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use xbpf::{OpenObject, Program, libbpf_rs::skel::Skel};

xbpf::include_bpf!("syscall_trace");

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_file(true)
        .with_line_number(true)
        .init();

    let mut open_obj = OpenObject::new();
    let prog = Program::build(SyscallTraceSkelBuilder::default(), &mut open_obj)?;

    let _link = prog.skel.progs.trace_syscall.attach()?;

    println!("Tracing syscalls... press Ctrl-C to stop.");
    loop {
        sleep(Duration::from_secs(1));
    }
}
