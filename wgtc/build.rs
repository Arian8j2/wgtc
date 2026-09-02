use anyhow::Context;
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    const EBPF_RUST_VERSION: &str = "WGTC_EBPF_RUST_VERSION";
    println!("cargo:rerun-if-env-changed={EBPF_RUST_VERSION}");

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "wgtc_ebpf")
        .ok_or_else(|| anyhow::anyhow!("wgtc_ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        features: if cfg!(feature = "ebpf_log") {
            &["log"]
        } else {
            &[]
        },
        ..Default::default()
    };
    let ebpf_rust_version = std::env::var(EBPF_RUST_VERSION).ok();
    let toolchain = ebpf_rust_version
        .as_deref()
        .map(Toolchain::Custom)
        .unwrap_or_default();

    aya_build::build_ebpf([ebpf_package], toolchain)
}
