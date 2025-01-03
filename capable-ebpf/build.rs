use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn main() {
    let bpf_linker = which("bpf-linker").expect("bpf-linker not found in $PATH");
    let aya_tool = which("aya-tool").expect("aya-tool not found in $PATH");
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().expect("bpf-linker path is not valid UTF-8"));
    // run aya-tool to rebuild task_struct bindings
    let output = std::process::Command::new(aya_tool)
        .arg("generate")
        .arg("task_struct")
        .output()
        .expect("Failed to run aya-tool");
    if !output.status.success() {
        eprintln!("Failed to generate task_struct bindings: {:?}", output);
        std::process::exit(1);
    }
    // Write the output to src/vmlinux.rs
    std::fs::write("src/vmlinux.rs", output.stdout).expect("Failed to write vmlinux.rs");
}