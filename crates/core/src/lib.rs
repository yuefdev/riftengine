//! Pieces of RiftEngine that do not touch Win32: the host/DLL wire protocol, the
//! overlay manifest, the table that maps game file opens onto overlay files and the reader of an
//! executable's link time.

pub mod manifest;
pub mod pe;
pub mod proto;
pub mod redirect;

/// Lower-case hex SHA-256, used for the manifest and rule-set digests.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for byte in digest.iter() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
