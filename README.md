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

<p align="center">
    <img src="https://github.com/lerboe/xbpf/raw/main/xbpf.png" alt="xbpf" width="500">
</p>

xBPF (eXtended BPF) is a high-level eBPF library for Rust. It aims at providing an ergonomic and light-weight interface to eBPF. 

eBPF can be a bit of a footgun: Building, loading, and managing eBPF programs is not necessarily difficult, but can fail in many spectacular ways. xBPF addresses this with convenient helper functions that avoid common pitfalls, and reduce boiler plate code.

> [!NOTE]
> xBPF is still very much WIP. Feel free to open issues if you find bugs or have a feature request!

## Why

xBPF is comparable to [aya](https://aya-rs.dev/), but requires you to write your eBPF code in C, rather than Rust. In my opinion, implementing eBPF with Rust makes things unnecessarily complicated. eBPF is hard because [it's verified](https://docs.kernel.org/bpf/verifier.html). Using Rust in this case might seem convenient, but does not help the kernel verify your programs. 

But alternatives like [libbpf-rs](https://github.com/libbpf/libbpf-rs) are much more low level. Using it can be a pretty steep learning curve.

xBPF closes this gap by building on top of [libbpf-rs](https://github.com/libbpf/libbpf-rs) to provide a more user-friendly eBPF ecosystem for Rust.

## License
This project is licensed under the [MIT license](LICENSE).
