// `xbpf::build::dump_kernel_btf` replaces `bpftool btf dump ... format c`, so
// this checks that both produce the same `vmlinux.h`.
#![cfg(feature = "build")]

use std::process::Command;

#[test]
fn dump_kernel_btf_matches_bpftool() {
    let output = Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .output()
        .unwrap_or_else(|e| panic!("Failed to run bpftool: {e}"));
    assert!(
        output.status.success(),
        "bpftool failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let dir = tempfile::tempdir().expect("temp dir");
    xbpf::build::dump_kernel_btf(dir.path());
    let ours = std::fs::read(dir.path().join("vmlinux.h")).expect("read vmlinux.h");

    if ours != output.stdout {
        let ours = String::from_utf8_lossy(&ours);
        let theirs = String::from_utf8_lossy(&output.stdout);
        let line = ours
            .lines()
            .zip(theirs.lines())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| ours.lines().count().min(theirs.lines().count()));
        panic!(
            "vmlinux.h differs from bpftool's at line {}:\n  xbpf:    {:?}\n  bpftool: {:?}",
            line + 1,
            ours.lines().nth(line),
            theirs.lines().nth(line),
        );
    }
}
