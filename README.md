# RootAsRole-capable

## Prerequisites

We assume that you already installed the RootAsRole `sr` tool. We recommend to use it to take advantage of this project.

Many packages are required to build and run this project. The following is the command for installing them all on an Docker Image Ubuntu 22.04:
```shell
sr apt install clang curl build-essential libelf-dev llvm \
                linux-tools-generic binutils-dev libcap-dev libclang-dev \
                libdbus-1-dev pkg-config libacl1-dev strace
```

In addition to the above packages, the following are also required:

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. bpftool: [Compile it by following the Github](https://github.com/libbpf/bpftool) (or use the following commands copied from the Github)
    1. `git clone --recurse-submodules https://github.com/libbpf/bpftool.git`
    1. `cd bpftool/src`
    1. `sr make install`
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)
1. bindgen-cli: `cargo install bindgen-cli`

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sr"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.