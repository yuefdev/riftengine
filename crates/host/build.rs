//! Gives the host its version resource.

#[path = "../version_info.rs"]
mod version_info;

fn main() {
    println!("cargo:rerun-if-changed=../version_info.rs");

    let rc = version_info::write_rc(
        "Host half of RiftEngine",
        "riftengine-host.exe",
        false,
    );
    embed_resource::compile(rc, embed_resource::NONE)
        .manifest_required()
        .expect("the version resource did not compile");
}
