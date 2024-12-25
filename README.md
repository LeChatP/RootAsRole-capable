# RootAsRole-capable

This side project is a proof of concept for helping people to configure their access policy in the [RootAsRole](https://github.com/LeChatP/RootAsRole) project.

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Build eBPF and Userspace

```bash
cargo xtask build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

## Notice

This project is a Proof of Concept and is not intended to be used in production. It should be used only in test environments. However, command output may be useful to help you configure your access policy.