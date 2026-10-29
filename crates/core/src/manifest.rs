//! The overlay manifest: the exact set of WAD copies the host validated and the DLL may serve.
//!
//! The host writes it after the rule checks pass. The DLL re-reads it at session start, checks
//! it against the digest sent in the handshake and against what is really on disk, and serves
//! nothing that is not listed.
//!
//! It also names the game build the overlay was made for. The packs were checked against that
//! build's files and the WADs carry its chunks, so the overlay is good for that build and no other.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::sha256_hex;

pub const MANIFEST_NAME: &str = "riftengine-overlay.json";
/// 2 added `game_linked`; an overlay of format 1 is not served.
pub const MANIFEST_FORMAT: u32 = 2;
const WAD_SUFFIX: &str = ".wad.client";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ManifestFile {
    /// Forward-slash path relative to the overlay root, e.g. `DATA/FINAL/Champions/Ahri.wad.client`.
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayManifest {
    pub format: u32,
    pub rules_digest: String,
    /// When the game the overlay was built for was linked: the `TimeDateStamp` of its executable,
    /// in seconds since the Unix epoch.
    pub game_linked: u32,
    pub files: Vec<ManifestFile>,
}

/// Just enough of a manifest to tell which format it is, so that an overlay of another format is
/// reported as that and not as a missing field.
#[derive(Deserialize)]
struct Header {
    format: u32,
}

#[derive(Debug)]
pub enum ManifestError {
    Io(io::Error),
    Parse(String),
    Format(u32),
    Mismatch(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "manifest i/o: {e}"),
            Self::Parse(e) => write!(f, "manifest is not valid: {e}"),
            Self::Format(v) => write!(f, "manifest format {v} is not {MANIFEST_FORMAT}; rebuild the overlay"),
            Self::Mismatch(m) => write!(f, "overlay does not match its manifest: {m}"),
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<io::Error> for ManifestError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Lists every `*.wad.client` under `DATA/FINAL`, sorted. Symlinks and junctions are skipped.
pub fn scan_overlay(overlay_root: &Path) -> io::Result<Vec<ManifestFile>> {
    let base = overlay_root.join("DATA").join("FINAL");
    let mut out = Vec::new();
    if base.is_dir() {
        walk(&base, overlay_root, &mut out)?;
    }
    out.sort();
    Ok(out)
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<ManifestFile>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let path = entry.path();
        if kind.is_dir() {
            walk(&path, root, out)?;
        } else if kind.is_file()
            && entry
                .file_name()
                .to_string_lossy()
                .to_ascii_lowercase()
                .ends_with(WAD_SUFFIX)
        {
            let rel = path.strip_prefix(root).map_err(io::Error::other)?;
            let rel = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push(ManifestFile {
                path: rel,
                size: entry.metadata()?.len(),
            });
        }
    }
    Ok(())
}

impl OverlayManifest {
    pub fn scan(overlay_root: &Path, rules_digest: String, game_linked: u32) -> io::Result<Self> {
        Ok(Self {
            format: MANIFEST_FORMAT,
            rules_digest,
            game_linked,
            files: scan_overlay(overlay_root)?,
        })
    }

    /// Writes the manifest and returns the SHA-256 of the bytes written.
    pub fn write(&self, overlay_root: &Path) -> io::Result<String> {
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let target = overlay_root.join(MANIFEST_NAME);
        let staging = overlay_root.join(format!("{MANIFEST_NAME}.tmp"));
        fs::write(&staging, &bytes)?;
        fs::rename(&staging, &target)?;
        Ok(sha256_hex(&bytes))
    }

    /// Reads the manifest and returns it with the SHA-256 of the bytes read.
    pub fn load(overlay_root: &Path) -> Result<(Self, String), ManifestError> {
        let bytes = fs::read(overlay_root.join(MANIFEST_NAME))?;
        let digest = sha256_hex(&bytes);
        let parse = |e: serde_json::Error| ManifestError::Parse(e.to_string());
        let header: Header = serde_json::from_slice(&bytes).map_err(parse)?;
        if header.format != MANIFEST_FORMAT {
            return Err(ManifestError::Format(header.format));
        }
        let manifest: Self = serde_json::from_slice(&bytes).map_err(parse)?;
        Ok((manifest, digest))
    }

    /// The overlay folder must hold exactly the listed files at exactly the listed sizes.
    pub fn verify_against_disk(&self, overlay_root: &Path) -> Result<(), ManifestError> {
        let disk: BTreeMap<String, u64> = scan_overlay(overlay_root)?
            .into_iter()
            .map(|f| (f.path, f.size))
            .collect();
        for file in &self.files {
            match disk.get(&file.path) {
                None => return Err(ManifestError::Mismatch(format!("missing {}", file.path))),
                Some(size) if *size != file.size => {
                    return Err(ManifestError::Mismatch(format!(
                        "{} is {size} bytes, manifest says {}",
                        file.path, file.size
                    )));
                }
                Some(_) => {}
            }
        }
        let listed: BTreeMap<&str, ()> = self.files.iter().map(|f| (f.path.as_str(), ())).collect();
        if let Some(extra) = disk.keys().find(|p| !listed.contains_key(p.as_str())) {
            return Err(ManifestError::Mismatch(format!("unlisted file {extra}")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// When the game the test overlay was built for was linked.
    const GAME: u32 = 1_792_188_909;

    fn overlay() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let champs = dir.path().join("DATA/FINAL/Champions");
        fs::create_dir_all(&champs).unwrap();
        fs::write(champs.join("Ahri.wad.client"), b"AHRI").unwrap();
        fs::write(champs.join("Zed.WAD.CLIENT"), b"ZED!!").unwrap();
        fs::write(champs.join("notes.txt"), b"ignored").unwrap();
        dir
    }

    #[test]
    fn scan_lists_only_wads_with_forward_slashes() {
        let dir = overlay();
        let files = scan_overlay(dir.path()).unwrap();
        assert_eq!(
            files,
            vec![
                ManifestFile { path: "DATA/FINAL/Champions/Ahri.wad.client".into(), size: 4 },
                ManifestFile { path: "DATA/FINAL/Champions/Zed.WAD.CLIENT".into(), size: 5 },
            ]
        );
    }

    #[test]
    fn write_then_load_round_trips_with_matching_digest() {
        let dir = overlay();
        let manifest = OverlayManifest::scan(dir.path(), "rules".into(), GAME).unwrap();
        let written = manifest.write(dir.path()).unwrap();
        let (loaded, read) = OverlayManifest::load(dir.path()).unwrap();
        assert_eq!(loaded, manifest);
        assert_eq!(loaded.game_linked, GAME);
        assert_eq!(written, read);
        loaded.verify_against_disk(dir.path()).unwrap();
    }

    #[test]
    fn the_game_build_is_part_of_what_the_digest_covers() {
        let dir = overlay();
        let mut manifest = OverlayManifest::scan(dir.path(), "rules".into(), GAME).unwrap();
        let first = manifest.write(dir.path()).unwrap();
        manifest.game_linked = GAME + 1;
        let second = manifest.write(dir.path()).unwrap();
        assert_ne!(first, second);
        assert_eq!(OverlayManifest::load(dir.path()).unwrap().0.game_linked, GAME + 1);
    }

    #[test]
    fn verify_catches_missing_resized_and_unlisted_files() {
        let dir = overlay();
        let manifest = OverlayManifest::scan(dir.path(), "rules".into(), GAME).unwrap();
        let champs = dir.path().join("DATA/FINAL/Champions");

        fs::write(champs.join("Extra.wad.client"), b"x").unwrap();
        let err = manifest.verify_against_disk(dir.path()).unwrap_err().to_string();
        assert!(err.contains("unlisted file DATA/FINAL/Champions/Extra.wad.client"), "{err}");
        fs::remove_file(champs.join("Extra.wad.client")).unwrap();

        fs::write(champs.join("Ahri.wad.client"), b"AHRI+").unwrap();
        let err = manifest.verify_against_disk(dir.path()).unwrap_err().to_string();
        assert!(err.contains("is 5 bytes, manifest says 4"), "{err}");

        fs::remove_file(champs.join("Ahri.wad.client")).unwrap();
        let err = manifest.verify_against_disk(dir.path()).unwrap_err().to_string();
        assert!(err.contains("missing DATA/FINAL/Champions/Ahri.wad.client"), "{err}");
    }

    #[test]
    fn load_rejects_wrong_format_and_garbage() {
        let dir = overlay();
        fs::write(dir.path().join(MANIFEST_NAME), b"not json").unwrap();
        assert!(matches!(OverlayManifest::load(dir.path()), Err(ManifestError::Parse(_))));

        let mut manifest = OverlayManifest::scan(dir.path(), "r".into(), GAME).unwrap();
        manifest.format = 99;
        manifest.write(dir.path()).unwrap();
        assert!(matches!(OverlayManifest::load(dir.path()), Err(ManifestError::Format(99))));
    }

    #[test]
    fn an_overlay_of_the_earlier_format_is_reported_as_that() {
        let dir = overlay();
        // What format 1 looked like: no game build in it.
        fs::write(dir.path().join(MANIFEST_NAME), br#"{"format":1,"rules_digest":"r","files":[]}"#).unwrap();
        let error = OverlayManifest::load(dir.path()).unwrap_err();
        assert!(matches!(error, ManifestError::Format(1)), "{error}");
        assert!(error.to_string().contains("rebuild the overlay"), "{error}");
    }

    #[test]
    fn a_manifest_without_a_game_build_is_not_valid() {
        let dir = overlay();
        // The current format, but with no game build: it must not read as one built for any game.
        fs::write(
            dir.path().join(MANIFEST_NAME),
            format!(r#"{{"format":{MANIFEST_FORMAT},"rules_digest":"r","files":[]}}"#),
        )
        .unwrap();
        let error = OverlayManifest::load(dir.path()).unwrap_err();
        assert!(matches!(error, ManifestError::Parse(_)), "{error}");
        assert!(error.to_string().contains("game_linked"), "{error}");
    }
}
