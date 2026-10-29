//! The installed game as the host sees it: every WAD under `DATA/FINAL`, mounted once, and which
//! of them holds which chunk. The validator compares packs with this, and the audit compares the
//! overlay with it.
//!
//! [`check_build`] asks whether the rules reach the game's executable at all.

use std::cell::{Ref, RefCell, RefMut};
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use ltk_wad::{Wad, WadChunk, WadHash};
use riftengine_core::pe;
use riftengine_core::proto::GAME_EXE_NAME;
use riftengine_validator::GameFiles;

const WAD_SUFFIX: &str = ".wad.client";

/// Largest game file the host reads back for a comparison. The game's own BINs are a few MiB.
const MAX_GAME_FILE_BYTES: usize = 64 << 20;

#[derive(Debug)]
pub enum GameError {
    Io(String, io::Error),
    /// `DATA/FINAL/Champions` holds no WAD: this is not a game folder.
    NoChampions,
    /// Two WADs of the install share a file name, so a name does not say which one is meant.
    Ambiguous(String),
}

impl fmt::Display for GameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(what, error) => write!(f, "{what}: {error}"),
            Self::NoChampions => f.write_str("DATA/FINAL/Champions holds no WAD; is this the game's `Game` folder?"),
            Self::Ambiguous(name) => write!(f, "two WADs of the install are called {name}"),
        }
    }
}

impl std::error::Error for GameError {}

/// The game's executable has to have been linked within the time the rules reach
/// ([`riftengine_rules::END_OF_LIFE`]). This reads the file. The DLL makes the same check on
/// the image the game runs, which is the one that counts; the host asks first, so that it says no
/// before it builds an overlay or waits for a game.
///
/// Returns when the game was linked, which is the build an overlay made for it is tied to.
pub fn check_build(game_dir: &Path) -> Result<u32, String> {
    let exe = game_dir.join(GAME_EXE_NAME);
    let mut head = Vec::new();
    File::open(&exe)
        .and_then(|file| file.take(pe::HEAD_BYTES as u64).read_to_end(&mut head))
        .map_err(|error| format!("cannot read {}: {error}", exe.display()))?;
    let linked = pe::link_time(&head).map_err(|error| format!("{} {error}", exe.display()))?;
    riftengine_rules::check_build(linked).map_err(|error| format!("{} {error}", exe.display()))?;
    Ok(linked)
}

struct GameWad {
    /// Lower-case file name.
    name: String,
    /// Directly in `DATA/FINAL/Champions`.
    champion: bool,
    wad: Wad<File>,
}

/// A chunk that WADs outside `DATA/FINAL/Champions` hold as well. An overlay never carries those
/// WADs, so it can replace the chunk in some of its places only.
#[derive(Debug, PartialEq, Eq)]
pub struct Shared {
    /// Lower-case file names of those WADs.
    pub others: Vec<String>,
    /// Whether the chunk is in a champion WAD the overlay replaces it in: the WAD the pack names, or
    /// for a `RAW/` file any champion WAD. When it is not, the overlay has nothing of it to replace
    /// and the game keeps the copies it has.
    pub carried: bool,
}

pub struct GameWads {
    wads: Vec<GameWad>,
    by_name: HashMap<String, usize>,
    /// Every chunk of every WAD as (path hash, index into `wads`), sorted.
    chunks: Vec<(u64, u32)>,
    /// WADs that did not mount. The overlay builder cannot patch them either.
    unreadable: Vec<PathBuf>,
}

impl GameWads {
    /// Mounts every `*.wad.client` under `<game_dir>/DATA/FINAL`. Symlinks and junctions are not
    /// followed.
    pub fn open(game_dir: &Path) -> Result<Self, GameError> {
        let root = game_dir.join("DATA").join("FINAL");
        let mut found = Vec::new();
        walk(&root, &mut found).map_err(|error| GameError::Io(format!("cannot list {}", root.display()), error))?;
        found.sort();

        let mut game = Self { wads: Vec::new(), by_name: HashMap::new(), chunks: Vec::new(), unreadable: Vec::new() };
        for path in found {
            let name = path.file_name().map(|name| name.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
            let relative: Vec<String> = path
                .strip_prefix(&root)
                .map(|rest| rest.components().map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase()).collect())
                .unwrap_or_default();
            let champion = relative.len() == 2 && relative[0] == "champions";

            let mounted = File::open(&path).ok().and_then(|file| catch_unwind(AssertUnwindSafe(|| Wad::mount(file))).ok()?.ok());
            let Some(wad) = mounted else {
                game.unreadable.push(path);
                continue;
            };
            if game.by_name.contains_key(&name) {
                return Err(GameError::Ambiguous(name));
            }
            let at = game.wads.len();
            game.chunks.extend(wad.chunks().iter().map(|chunk| (chunk.path_hash.0, at as u32)));
            game.by_name.insert(name.clone(), at);
            game.wads.push(GameWad { name, champion, wad });
        }
        if !game.wads.iter().any(|wad| wad.champion) {
            return Err(GameError::NoChampions);
        }
        game.chunks.sort_unstable();
        Ok(game)
    }

    /// Lower-case file names of the WADs directly in `DATA/FINAL/Champions`.
    pub fn champion_wads(&self) -> Vec<&str> {
        self.wads.iter().filter(|wad| wad.champion).map(|wad| wad.name.as_str()).collect()
    }

    /// Lower-case file names of every other WAD: the ones an overlay never carries.
    pub fn other_wads(&self) -> Vec<String> {
        self.wads.iter().filter(|wad| !wad.champion).map(|wad| wad.name.clone()).collect()
    }

    pub fn wad_count(&self) -> usize {
        self.wads.len()
    }

    /// Whether a WAD, by lower-case file name, is directly in `DATA/FINAL/Champions`.
    pub fn is_champion(&self, wad: &str) -> bool {
        self.by_name.get(wad).is_some_and(|at| self.wads[*at].champion)
    }

    /// The WADs outside `DATA/FINAL/Champions` that hold the chunk, if there are any. `wad` is the
    /// lower-case file name of the WAD the pack files the chunk under, or `None` for a `RAW/` file,
    /// which lands in every WAD that holds it.
    pub fn shared_outside(&self, wad: Option<&str>, hash: u64) -> Option<Shared> {
        let holders = self.holders_of(hash);
        let others: Vec<String> =
            holders.iter().filter(|holder| !self.is_champion(holder)).map(|holder| (*holder).to_owned()).collect();
        if others.is_empty() {
            return None;
        }
        let carried = match wad {
            Some(wad) => self.is_champion(wad) && holders.contains(&wad),
            None => holders.iter().any(|holder| self.is_champion(holder)),
        };
        Some(Shared { others, carried })
    }

    /// WADs that could not be mounted.
    pub fn unreadable(&self) -> &[PathBuf] {
        &self.unreadable
    }

    /// The WADs that hold the chunk, as lower-case file names.
    pub fn holders_of(&self, hash: u64) -> Vec<&str> {
        let start = self.chunks.partition_point(|(held, _)| *held < hash);
        self.chunks[start..]
            .iter()
            .take_while(|(held, _)| *held == hash)
            .map(|(_, at)| self.wads[*at as usize].name.as_str())
            .collect()
    }

    /// The table entry of a chunk of one WAD.
    pub fn chunk(&self, wad: &str, hash: u64) -> Option<WadChunk> {
        let at = *self.by_name.get(wad)?;
        self.wads[at].wad.chunks().get(WadHash(hash)).copied()
    }

    /// Every table entry of one WAD.
    pub fn chunks_of(&self, wad: &str) -> Option<Vec<WadChunk>> {
        let at = *self.by_name.get(wad)?;
        Some(self.wads[at].wad.chunks().iter().copied().collect())
    }

    /// The game's own copy of a chunk as the WAD stores it, compressed. `None` when it is not there,
    /// is too big or does not read.
    pub fn raw(&mut self, wad: &str, hash: u64) -> Option<Vec<u8>> {
        let at = *self.by_name.get(wad)?;
        let mounted = &mut self.wads[at].wad;
        let chunk = mounted.chunks().get(WadHash(hash)).copied()?;
        if chunk.compressed_size > MAX_GAME_FILE_BYTES {
            return None;
        }
        let loaded = catch_unwind(AssertUnwindSafe(|| mounted.load_chunk_raw(&chunk))).ok()?.ok()?;
        Some(loaded.into_vec())
    }

    /// The game's own copy of a chunk, decompressed. `None` when it is not there, is too big or
    /// does not read.
    pub fn load(&mut self, wad: &str, hash: u64) -> Option<Vec<u8>> {
        let at = *self.by_name.get(wad)?;
        let mounted = &mut self.wads[at].wad;
        let chunk = mounted.chunks().get(WadHash(hash)).copied()?;
        if chunk.uncompressed_size > MAX_GAME_FILE_BYTES {
            return None;
        }
        let loaded = catch_unwind(AssertUnwindSafe(|| mounted.load_chunk_decompressed(&chunk))).ok()?.ok()?;
        Some(loaded.into_vec())
    }
}

fn walk(folder: &Path, found: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(folder)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let path = entry.path();
        if kind.is_dir() {
            walk(&path, found)?;
        } else if kind.is_file() && entry.file_name().to_string_lossy().to_ascii_lowercase().ends_with(WAD_SUFFIX) {
            found.push(path);
        }
    }
    Ok(())
}

/// A shared handle on the game's WADs that the validator reads through.
#[derive(Clone)]
pub struct GameView(Rc<RefCell<GameWads>>);

impl GameView {
    pub fn new(game: GameWads) -> Self {
        Self(Rc::new(RefCell::new(game)))
    }

    pub fn borrow(&self) -> Ref<'_, GameWads> {
        self.0.borrow()
    }

    pub fn borrow_mut(&self) -> RefMut<'_, GameWads> {
        self.0.borrow_mut()
    }
}

impl GameFiles for GameView {
    fn holders(&mut self, path_hash: u64) -> Option<Vec<String>> {
        Some(self.0.borrow().holders_of(path_hash).into_iter().map(str::to_owned).collect())
    }

    fn file(&mut self, wad: &str, path_hash: u64) -> Option<Vec<u8>> {
        self.0.borrow_mut().load(wad, path_hash)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use riftengine_rules::{END_OF_LIFE, utc};

    use super::*;

    /// The head of an executable linked at `time`: the smallest that reads as one.
    pub(crate) fn exe_linked_at(time: u32) -> Vec<u8> {
        let mut head = vec![0u8; 0x200];
        head[..2].copy_from_slice(b"MZ");
        head[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        head[0x80..0x84].copy_from_slice(b"PE\0\0");
        head[0x88..0x8c].copy_from_slice(&time.to_le_bytes());
        head
    }

    /// A folder with an executable of these bytes, named as the game's is.
    fn game_with_exe(bytes: &[u8]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(GAME_EXE_NAME), bytes).unwrap();
        dir
    }

    #[test]
    fn a_build_the_rules_reach_is_accepted() {
        // What it answers is the link time itself, which an overlay is then made for.
        assert_eq!(check_build(game_with_exe(&exe_linked_at(1_792_188_909)).path()), Ok(1_792_188_909));
        assert_eq!(check_build(game_with_exe(&exe_linked_at(END_OF_LIFE - 1)).path()), Ok(END_OF_LIFE - 1));
    }

    #[test]
    fn a_build_from_the_end_of_life_on_is_refused_and_both_times_are_named() {
        for linked in [END_OF_LIFE, END_OF_LIFE + 1, u32::MAX] {
            let message = check_build(game_with_exe(&exe_linked_at(linked)).path()).unwrap_err();
            assert!(message.contains("League of Legends.exe was linked"), "{message}");
            assert!(message.contains(&utc(linked)) && message.contains(&utc(END_OF_LIFE)), "{message}");
        }
    }

    #[test]
    fn an_executable_without_a_build_time_is_refused() {
        let message = check_build(game_with_exe(&exe_linked_at(0)).path()).unwrap_err();
        assert!(message.contains("carries no build time"), "{message}");
    }

    #[test]
    fn a_missing_or_foreign_executable_is_refused() {
        let empty = tempfile::tempdir().unwrap();
        let message = check_build(empty.path()).unwrap_err();
        assert!(message.contains("cannot read") && message.contains(GAME_EXE_NAME), "{message}");

        let message = check_build(game_with_exe(b"#!/bin/sh\n").path()).unwrap_err();
        assert!(message.contains("is not a Windows executable"), "{message}");

        let message = check_build(game_with_exe(&exe_linked_at(1)[..0x40]).path()).unwrap_err();
        assert!(message.contains("ends inside its headers"), "{message}");
    }
}
