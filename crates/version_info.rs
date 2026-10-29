//! Shared by the build scripts of the host and the DLL: writes the Windows version resource that
//! goes into each binary. The signing service's artifact configuration pins the product name and
//! the product version, so both come from here and from the package version.

use std::{env, fs, path::PathBuf};

pub const PRODUCT_NAME: &str = "RiftEngine";

/// Writes the version resource of the crate being built as an `.rc` file in `OUT_DIR`. `dll` picks
/// the file type that Explorer and the loader report.
pub fn write_rc(description: &str, original_filename: &str, dll: bool) -> PathBuf {
    let version = env::var("CARGO_PKG_VERSION").expect("cargo sets CARGO_PKG_VERSION");
    let mut numbers = version
        .split(['.', '-', '+'])
        .map(|part| part.parse::<u16>().unwrap_or(0));
    let mut next = || numbers.next().unwrap_or(0);
    let (major, minor, patch) = (next(), next(), next());
    let file_type = if dll { 2 } else { 1 };

    let rc = format!(
        r#"1 VERSIONINFO
FILEVERSION {major},{minor},{patch},0
PRODUCTVERSION {major},{minor},{patch},0
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x{file_type}L
FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "FileDescription", "{description}"
            VALUE "FileVersion", "{version}"
            VALUE "InternalName", "{original_filename}"
            VALUE "LegalCopyright", "Copyright (c) 2026 RiftEngine contributors"
            VALUE "OriginalFilename", "{original_filename}"
            VALUE "ProductName", "{PRODUCT_NAME}"
            VALUE "ProductVersion", "{version}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"#
    );

    let path = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR")).join("version.rc");
    fs::write(&path, rc).expect("write version.rc");
    path
}
