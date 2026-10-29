//! Maps game file opens onto overlay files.
//!
//! Only the manifest's `*.wad.client` copies are ever served. Anything else, and any open that
//! is not under the game folder's `DATA/FINAL`, falls through to the real file.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::manifest::ManifestFile;

/// Where a redirected open is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// NUL-terminated UTF-16, ready for `CreateFileW`.
    pub wide: Vec<u16>,
    pub display: String,
}

#[derive(Debug)]
pub struct Redirector {
    root_prefix: String,
    files: HashMap<String, Target>,
}

/// Lower-cased, backslash-separated form of a Windows path with `.`/`..` folded away and any
/// `\\?\` or `\\.\` prefix removed. Both sides of every comparison go through this.
pub fn normalise(raw: &str) -> String {
    let mut s = raw;
    for prefix in [r"\\?\", r"\\.\", "//?/", "//./"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest;
            break;
        }
    }
    let unified: String = s.chars().map(|c| if c == '/' { '\\' } else { c }).collect();
    let unc = unified.starts_with(r"\\");
    let mut parts: Vec<&str> = Vec::new();
    for part in unified.split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("\\");
    let joined = if unc { format!(r"\\{joined}") } else { joined };
    joined.to_lowercase()
}

impl Redirector {
    pub fn new(game_root: &Path, overlay_root: &Path, files: &[ManifestFile]) -> Self {
        let root_prefix = format!("{}\\", normalise(&game_root.to_string_lossy()));
        let files = files
            .iter()
            .map(|file| {
                let mut abs = PathBuf::from(overlay_root);
                for part in file.path.split('/') {
                    abs.push(part);
                }
                let display = abs.to_string_lossy().into_owned();
                let mut wide: Vec<u16> = display.encode_utf16().collect();
                wide.push(0);
                (normalise(&file.path), Target { wide, display })
            })
            .collect();
        Self { root_prefix, files }
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn lookup(&self, requested: &str) -> Option<&Target> {
        let path = normalise(requested);
        let relative = match path.strip_prefix(&self.root_prefix) {
            Some(rest) => rest,
            None if path.starts_with("data\\final\\") => path.as_str(),
            None => return None,
        };
        self.files.get(relative)
    }

    pub fn lookup_wide(&self, requested: &[u16]) -> Option<&Target> {
        self.lookup(&String::from_utf16_lossy(requested))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redirector() -> Redirector {
        let files = [
            ManifestFile { path: "DATA/FINAL/Champions/Ahri.wad.client".into(), size: 1 },
            ManifestFile { path: "DATA/FINAL/Global.wad.client".into(), size: 1 },
        ];
        Redirector::new(
            Path::new(r"C:\Riot Games\League of Legends\Game"),
            Path::new(r"D:\profile\overlay"),
            &files,
        )
    }

    #[test]
    fn normalise_folds_case_separators_and_dots() {
        assert_eq!(normalise(r"C:/A\b/./C/../D"), r"c:\a\b\d");
        assert_eq!(normalise(r"\\?\C:\Game\DATA"), r"c:\game\data");
        assert_eq!(normalise(r"\\server\Share\x"), r"\\server\share\x");
        assert_eq!(normalise(r"DATA\\FINAL//x.wad.client"), r"data\final\x.wad.client");
    }

    #[test]
    fn absolute_and_relative_opens_are_redirected() {
        let r = redirector();
        let expected = r"D:\profile\overlay\DATA\FINAL\Champions\Ahri.wad.client";
        for spelling in [
            r"C:\Riot Games\League of Legends\Game\DATA\FINAL\Champions\Ahri.wad.client",
            r"c:/riot games/league of legends/game/data/final/champions/AHRI.WAD.CLIENT",
            r"\\?\C:\Riot Games\League of Legends\Game\DATA\FINAL\Champions\Ahri.wad.client",
            r"C:\Riot Games\League of Legends\Game\DATA\FINAL\..\FINAL\Champions\Ahri.wad.client",
            r"DATA\FINAL\Champions\Ahri.wad.client",
            r".\data\final\champions\ahri.wad.client",
        ] {
            let target = r.lookup(spelling).unwrap_or_else(|| panic!("no redirect for {spelling}"));
            assert_eq!(target.display, expected, "{spelling}");
        }
    }

    #[test]
    fn wide_target_is_nul_terminated() {
        let r = redirector();
        let target = r.lookup(r"DATA\FINAL\Global.wad.client").unwrap();
        assert_eq!(target.wide.last(), Some(&0));
        assert_eq!(
            String::from_utf16_lossy(&target.wide[..target.wide.len() - 1]),
            r"D:\profile\overlay\DATA\FINAL\Global.wad.client"
        );
        let wide: Vec<u16> = r"DATA\FINAL\Global.wad.client".encode_utf16().collect();
        assert!(r.lookup_wide(&wide).is_some());
    }

    #[test]
    fn everything_else_passes_through() {
        let r = redirector();
        assert_eq!(r.len(), 2);
        for other in [
            r"C:\Riot Games\League of Legends\Game\DATA\FINAL\Champions\Zed.wad.client",
            r"C:\Riot Games\League of Legends\Game\League of Legends.exe",
            r"C:\Other Game\DATA\FINAL\Champions\Ahri.wad.client",
            r"D:\profile\overlay\DATA\FINAL\Champions\Ahri.wad.client",
            r"C:\Riot Games\League of Legends\Game\DATA\FINAL\Champions\Ahri.wad.client.bak",
            r"\\.\pipe\riftengine-1",
            "",
        ] {
            assert!(r.lookup(other).is_none(), "{other}");
        }
    }
}
