use std::{error::Error, fs};

use aya::util::KernelVersion;
use anyhow::{anyhow, Context as _};
use aya_build::cargo_metadata;

fn main() -> anyhow::Result<()> {
    // get kernel version

    match kernel_version() {
        Ok(version) => {
            // create version.rs file
            fs::write(
                "src/version.rs",
                format!("pub const LINUX_VERSION_CODE: u32 = {};", version.code()),
            )
            .unwrap();
        }
        Err(e) => eprintln!("Error: {}", e),
    };
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
    .no_deps()
    .exec()
    .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name == "capable-ebpf")
        .ok_or_else(|| anyhow!("capable-ebpf package not found"))?;
    aya_build::build_ebpf([ebpf_package])
}

fn kernel_version() -> Result<KernelVersion, impl Error> {
    aya::util::KernelVersion::current()

}
