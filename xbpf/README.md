# xBPF

[![Crates.io][crates-badge]][crates-url]
[![GPL-v3 licensed][gpl-badge]][gpl-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/xbpf.svg
[crates-url]: https://crates.io/crates/xbpf
[gpl-badge]: https://img.shields.io/badge/License-MIT-blue.svg
[gpl-url]: LICENSE
[actions-badge]: https://github.com/lerboe/xbpf/actions/workflows/ci.yml/badge.svg
[actions-url]: https://github.com/lerboe/xbpf/actions/workflows/ci.yml
[libbpf-url]: https://docs.rs/libbpf-rs/latest/libbpf_rs/
[aya-url]: https://docs.rs/aya/latest/aya/

<p align="center">
    <img src="https://github.com/lerboe/xbpf/raw/main/xbpf.png" alt="xbpf" width="500">
</p>

xBPF (eXtended BPF) is a high-level eBPF library for Rust. It aims at providing an ergonomic and light-weight interface to eBPF. 

eBPF can be a bit of a footgun: Building, loading, and managing eBPF programs is not necessarily difficult, but can fail in many spectacular ways. xBPF addresses this with convenient helper functions that avoid common pitfalls, and reduce boiler plate code.

> [!NOTE]
> xBPF is still very much WIP. Feel free to open issues if you find bugs or have a feature request!

## Features

### Tracing

xBPF's tracing facility conveniently integrates into [tracing](https://docs.rs/tracing/latest/tracing/). It is more lightweight than [bpf_trace_printk](https://docs.ebpf.io/linux/helper-function/bpf_trace_printk), and allows you to filter the output with the `RUST_LOG` environment variable.

```c
SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ops) {
    if (ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        bpf_start_info_span("sockops");

        bpf_info("Established socket %d", skey.local.port);

        bpf_end_span("sockops");
    }

    return SK_PASS;
}
```

The program above yields the following output:
```text
2026-04-20T13:23:27.545062Z  INFO bpf: example/src/monitor.bpf.c:34: sockops
2026-04-20T13:23:27.545166Z  INFO bpf: example/src/monitor.bpf.c:50: Established socket [127.0.0.1:34812->127.0.0.1:9999]
2026-04-20T13:23:27.545239Z  INFO bpf: example/src/monitor.bpf.c:60: Add socket [127.0.0.1:34812->127.0.0.1:9999]
2026-04-20T13:23:27.545345Z  INFO bpf: example/src/monitor.bpf.c:34: sockops
2026-04-20T13:23:27.545450Z  INFO bpf: example/src/monitor.bpf.c:50: Established socket [127.0.0.1:9999->127.0.0.1:34812]
```

### Building

xBPF provides you with a simple interface to build your eBPF programs. This eliminates a lot of boilerplate code that is easy to get wrong. In many cases `xbpf::build()` is sufficient to build your program. It looks for all of your eBPF source files, makes sure they are recompiled when they change, dumps `vmlinux.h` with [bpftool](https://bpftool.dev/), and exports C headers to a path which you can point your IDE to. 

In your build script, call `xbpf::build`:
```rust
fn main() {
    xbpf::build();
}
```

Then, in your rust code, use `xbpf::include_bpf!` to include your eBPF program:
```rust
xbpf::include_bpf!("syscall_trace");
```

xbpf automatically exports all headers, including `vmlinux.h`, to `target/include`. To make code completion work in your IDE, add the following to your `.clangd` file:
```yaml
CompileFlags:
  Add:
    - "-I<WORKSPACE_DIR>/target/include"
```

### Testing

xbpf helps you write unit test for your eBPF programs. Simply declare a `syscall` function in your eBPF code:

```c
SEC("syscall")
int test_if_crazy_logic_returns_true(struct args *args) {
    // crazy logic here
    return 0;
}
```

and call it as follows:
```rust
#[xbpf::test(example, test_if_crazy_logic_returns_true)]
fn test_if_crazy_logic_returns_true() {
    let args = test_if_crazy_logic_returns_true(types::args { a: 2, b: 3, sum: 0 }).unwrap();
    assert_eq!(args.sum, 5);
}
```

### Colletions
Use `unsafe`-free collections to avoid boilerplate conversion code and common pitfalls.

## Why

xBPF is comparable to [aya][aya-url], but requires you to write your eBPF code in C, rather than Rust. In my opinion, implementing eBPF with Rust makes things unnecessarily complicated. eBPF is hard because [it's verified](https://docs.kernel.org/bpf/verifier.html). Using Rust in this case might seem convenient, but does not help the kernel verify your programs. 

But alternatives like [libbpf-rs][libbpf-url] are much more low level. Using it can be a pretty steep learning curve.

xBPF closes this gap by building on top of [libbpf-rs][libbpf-url] to provide a more user-friendly eBPF ecosystem for Rust.

## License
This project is licensed under the [MIT license](LICENSE).
