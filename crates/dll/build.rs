//! Asks the linker to fill in the PE checksum, which a release DLL carries and a plain link leaves
//! at 0, and gives the DLL its version resource.

#[path = "../version_info.rs"]
mod version_info;

fn main() {
    println!("cargo:rerun-if-changed=../version_info.rs");
    println!("cargo:rustc-link-arg-cdylib=/RELEASE");

    let rc = version_info::write_rc(
        "In-game half of RiftEngine",
        "riftengine_dll.dll",
        true,
    );
    embed_resource::compile_for_cdylib(rc, embed_resource::NONE)
        .manifest_required()
        .expect("the version resource did not compile");
}
