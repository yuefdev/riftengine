//! Builds the overlay from community packs: the one place where a pack, the rules and the overlay
//! builder meet.
//!
//! 1. The game's executable has to be a build the rules reach ([`crate::game::check_build`]).
//! 2. Every pack is read into memory once ([`pack`]).
//! 3. Every file in it is checked by the validator against the installed game. One violation
//!    refuses the whole build, and nothing on disk is touched. A chunk that a WAD outside the
//!    champions holds too is refused unless the champion WAD the file is filed under holds it as
//!    well; then it is replaced there alone, and the build says so.
//! 4. The overlay builder is handed those same bytes from memory. It never opens an archive.
//! 5. What the builder wrote is audited against the game and the packs: a chunk may differ from
//!    the game's only by being a file that was checked.
//! 6. Only then is the manifest written, which is what the DLL serves from. It names the build of
//!    the game the overlay was made for, and is no good for another.
//!
//! Anything that goes wrong after the old overlay was cleared leaves no overlay and no manifest.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use camino::{Utf8Path, Utf8PathBuf};
use ltk_fantome::{FantomeInfo, is_layer_name};
use ltk_mod_project::{ModProject, ModProjectAuthor, ModProjectLayer};
use ltk_overlay::utils::resolve_chunk_hash;
use ltk_overlay::{EnabledMod, ModContentProvider, OverlayBuilder};
use ltk_wad::{Wad, WadChunk};
use riftengine_core::manifest::{MANIFEST_NAME, OverlayManifest, scan_overlay};
use riftengine_core::sha256_hex;
use riftengine_rules::id;
use riftengine_validator::{Entry, Report, Validator};

use crate::Event;
use crate::game::{GameError, GameView, GameWads, Shared};
use crate::pack::{self, MAX_ENTRY_BYTES, Pack, PackError};

/// The overlay builder keeps its own files here, inside the overlay folder, and they are removed
/// again when the build is done.
const STATE_DIR: &str = ".state";

/// What a folder may hold to be taken for an overlay folder. Anything else in it, and it is
/// somebody's folder.
const OVERLAY_FILES: [&str; 4] = ["DATA", STATE_DIR, MANIFEST_NAME, "riftengine-overlay.json.tmp"];

/// The builder reads BINs the validator has already walked; this is the same room it was given.
const BUILD_STACK_BYTES: usize = 256 << 20;

/// Most problems the audit lists before it stops looking.
const MAX_PROBLEMS: usize = 50;

pub struct Options<'a> {
    /// The game's `Game` folder.
    pub game_dir: &'a Path,
    /// Where the overlay goes. Missing, empty, or an overlay folder from an earlier build.
    pub overlay_root: &'a Path,
    /// The packs, highest priority first.
    pub packs: &'a [PathBuf],
}

#[derive(Debug)]
pub struct Built {
    /// WAD files in the overlay.
    pub wads: usize,
    /// Chunks in them that are not the game's.
    pub chunks: usize,
    /// SHA-256 of the manifest file.
    pub manifest: String,
}

#[derive(Debug)]
pub enum BuildError {
    Game(GameError),
    /// The game's executable is not a build the rules reach. Nothing was touched.
    GameBuild(String),
    Pack { pack: String, error: PackError },
    /// The rules refuse the packs. The violations were reported as events.
    Refused { violations: usize },
    Folder(String),
    Builder(String),
    /// The builder's output is not what the packs say it should be. Nothing was kept.
    Audit(Vec<String>),
    Io(String, io::Error),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Game(error) => write!(f, "the game folder: {error}"),
            Self::GameBuild(what) => write!(f, "the game build: {what}"),
            Self::Pack { pack, error } => write!(f, "{pack}: {error}"),
            Self::Refused { violations } => write!(f, "the rules refuse the packs ({violations} violations)"),
            Self::Folder(what) => write!(f, "the overlay folder: {what}"),
            Self::Builder(what) => write!(f, "the overlay builder failed: {what}"),
            Self::Audit(problems) => {
                write!(f, "the overlay is not what the packs say it should be, and was not kept:")?;
                for problem in problems {
                    write!(f, "\n  {problem}")?;
                }
                Ok(())
            }
            Self::Io(what, error) => write!(f, "{what}: {error}"),
        }
    }
}

impl std::error::Error for BuildError {}

pub fn build(options: &Options<'_>, emit: &mut dyn FnMut(Event)) -> Result<Built, BuildError> {
    let game_dir = real_path(options.game_dir)
        .map_err(|error| BuildError::Io(format!("cannot open {}", options.game_dir.display()), error))?;
    let overlay_root = claim_folder(&game_dir, options.overlay_root)?;
    let game = GameView::new(GameWads::open(&game_dir).map_err(BuildError::Game)?);
    let linked = crate::game::check_build(&game_dir).map_err(BuildError::GameBuild)?;
    for path in game.borrow().unreadable() {
        emit(Event::Log { level: 2, text: format!("{} does not mount, so it is left out", path.display()) });
    }

    // Every pack is read and checked before anything on disk is touched.
    let mut checked = Vec::with_capacity(options.packs.len());
    let mut notes = Vec::new();
    let mut violations = 0;
    for path in options.packs {
        let label = path.file_name().map_or_else(|| path.display().to_string(), |name| name.to_string_lossy().into_owned());
        let pack = pack::read(path).map_err(|error| BuildError::Pack { pack: label.clone(), error })?;
        let outcome = check(&pack, &game);
        let found = outcome.report.violations.len();
        emit(Event::Validated {
            pack: label.clone(),
            files: outcome.report.entries,
            base_skins: outcome.report.base_skins,
            violations: found,
        });
        for violation in &outcome.report.violations {
            emit(Event::Violation {
                pack: label.clone(),
                rule: violation.rule.to_owned(),
                location: violation.location.clone(),
                detail: violation.detail.clone(),
            });
        }
        if outcome.report.truncated {
            emit(Event::Log { level: 2, text: format!("{label}: more violations than are listed") });
        }
        violations += found;
        notes.push((label, outcome.shared));
        checked.push((pack, outcome.digests));
    }
    if violations > 0 {
        return Err(BuildError::Refused { violations });
    }
    // Said only of a build that goes ahead: a refused one has more to say than this.
    for (label, shared) in notes {
        for (wad, chunks) in shared {
            emit(Event::Log { level: 2, text: shared_note(&label, chunks, &wad) });
        }
    }

    let mut expected: HashMap<u64, Vec<String>> = HashMap::new();
    let mut mods = Vec::with_capacity(checked.len());
    for (index, (pack, digests)) in checked.into_iter().enumerate() {
        for (hash, digest) in digests {
            expected.entry(hash).or_default().push(digest);
        }
        mods.push(EnabledMod {
            id: format!("pack{index}"),
            content: Box::new(Snapshot(snapshot(index, pack))),
            enabled_layers: None,
        });
    }

    clear_folder(&overlay_root).map_err(|error| {
        BuildError::Io(format!("cannot clear {} (is the game running from it?)", overlay_root.display()), error)
    })?;
    let result = run(&game, &game_dir, linked, &overlay_root, mods, &expected, emit);
    match &result {
        Ok(built) => emit(Event::Built { wads: built.wads, chunks: built.chunks, manifest: built.manifest.clone() }),
        // No half overlay, and no manifest to vouch for one.
        Err(_) => {
            let _ = clear_folder(&overlay_root);
        }
    }
    result
}

/// `game_linked` is when the game was linked, as [`crate::game::check_build`] read it before the
/// packs were looked at. A game patched while this runs then no longer matches the manifest.
fn run(
    game: &GameView,
    game_dir: &Path,
    game_linked: u32,
    overlay_root: &Path,
    mods: Vec<EnabledMod>,
    expected: &HashMap<u64, Vec<String>>,
    emit: &mut dyn FnMut(Event),
) -> Result<Built, BuildError> {
    let state = overlay_root.join(STATE_DIR);
    fs::create_dir_all(&state).map_err(|error| BuildError::Io(format!("cannot create {}", state.display()), error))?;

    let utf8 = |path: &Path| {
        Utf8PathBuf::from_path_buf(path.to_owned())
            .map_err(|path| BuildError::Folder(format!("{} is not valid UTF-8, which the overlay builder needs", path.display())))
    };
    let (game_dir, overlay_dir, state_dir) = (utf8(game_dir)?, utf8(overlay_root)?, utf8(&state)?);

    // Everything outside DATA/FINAL/Champions is out of reach of the builder, whatever it is asked.
    let blocked = game.borrow().other_wads();

    let (progress, stages) = mpsc::channel();
    let worker = thread::Builder::new()
        .name("overlay-build".into())
        .stack_size(BUILD_STACK_BYTES)
        .spawn(move || {
            let mut builder = OverlayBuilder::new(game_dir, overlay_dir, state_dir)
                .with_blocked_wads(blocked)
                .with_progress(move |update| {
                    let _ = progress.send(update);
                });
            builder.set_enabled_mods(mods);
            builder.build().map_err(|error| render(&error))
        })
        .map_err(|error| BuildError::Io("cannot start the build thread".into(), error))?;
    // Ends when the builder, and the sender it holds, is gone.
    for update in stages {
        emit(Event::Building { stage: format!("{:?}", update.stage), current: update.current, total: update.total });
    }
    let built = worker
        .join()
        .map_err(|_| BuildError::Builder("the overlay builder panicked".into()))?
        .map_err(BuildError::Builder)?;
    for skipped in &built.skipped_archives {
        emit(Event::Log { level: 2, text: format!("the builder could not index a game archive: {skipped:?}") });
    }

    let audited = audit(game, overlay_root, expected).map_err(BuildError::Audit)?;

    fs::remove_dir_all(&state).map_err(|error| BuildError::Io(format!("cannot remove {}", state.display()), error))?;
    let manifest = OverlayManifest::scan(overlay_root, riftengine_rules::digest(), game_linked)
        .map_err(|error| BuildError::Io("cannot list the overlay".into(), error))?;
    let digest = manifest
        .write(overlay_root)
        .map_err(|error| BuildError::Io(format!("cannot write {MANIFEST_NAME}"), error))?;
    Ok(Built { wads: audited.wads, chunks: audited.chunks, manifest: digest })
}

fn render(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        text.push_str(": ");
        text.push_str(&next.to_string());
        source = next.source();
    }
    text
}

// ---- checking the packs ----

struct Outcome {
    report: Report,
    /// Chunk path hash and SHA-256 of each file the pack carries.
    digests: Vec<(u64, String)>,
    /// How many of the chunks the pack replaces are also in a WAD outside the champions, by that
    /// WAD's lower-case file name. The overlay replaces them in the champion WAD alone.
    shared: BTreeMap<String, usize>,
}

/// Runs every file of a pack through the validator, together with the checks that only the host
/// can make: that the overlay builder files each name where the validator thinks it does, and that
/// no chunk is one that only WADs the overlay could not carry hold. A chunk the champion WAD holds
/// as well is replaced there, and counted in [`Outcome::shared`].
fn check(pack: &Pack, game: &GameView) -> Outcome {
    let champion_wads: Vec<String> = game.borrow().champion_wads().into_iter().map(str::to_owned).collect();
    let mut validator = Validator::new(champion_wads).with_game_files(game.clone());
    for declaration in &pack.game_data {
        validator.violation(
            id::DATA_DECL,
            declaration.as_str(),
            "the pack declares game data; a pack may carry files and nothing that changes how they are read",
        );
    }

    let mut filed: HashSet<(&str, Option<String>, u64)> = HashSet::new();
    let mut digests = Vec::with_capacity(pack.files.len());
    let mut shared: BTreeMap<String, usize> = BTreeMap::new();
    for file in &pack.files {
        let wad = file.wad.as_deref();
        let location = match wad {
            Some(wad) => format!("{wad}/{}", file.path),
            None => format!("RAW/{}", file.path),
        };
        let hash = match resolve_chunk_hash(Utf8Path::new(&file.path), &file.bytes) {
            Ok(hash) => hash.0,
            Err(error) => {
                validator.violation(id::PATH, location, format!("the overlay builder cannot place it: {error}"));
                continue;
            }
        };
        validator.check(&Entry::new(wad, &file.path, &file.bytes).filed_under(hash));

        let lower = wad.map(str::to_ascii_lowercase);
        if !filed.insert((file.layer.as_str(), lower.clone(), hash)) {
            validator.violation(id::PATH, &location, "another file of the same layer is filed under the same chunk");
        }
        let outside = game.borrow().shared_outside(lower.as_deref(), hash);
        if let Some(Shared { others, carried }) = outside {
            if carried {
                for other in others {
                    *shared.entry(other).or_default() += 1;
                }
            } else if lower.as_deref().is_none_or(|wad| game.borrow().is_champion(wad)) {
                // A WAD that is no champion's was refused by name above, which is not said twice.
                let lacking = match wad {
                    Some(wad) => format!("but not in {wad}"),
                    None => "and in no champion WAD".to_owned(),
                };
                validator.violation(
                    id::TARGET,
                    &location,
                    format!("the chunk is in {}, which is not a champion WAD and which the overlay does not carry, {lacking}", others[0]),
                );
            }
        }
        digests.push((hash, sha256_hex(&file.bytes)));
    }
    Outcome { report: validator.finish(), digests, shared }
}

/// What a build says of the chunks a pack replaces that a WAD outside the champions holds as well.
fn shared_note(pack: &str, chunks: usize, wad: &str) -> String {
    let (noun, verb) = if chunks == 1 { ("chunk", "is") } else { ("chunks", "are") };
    format!(
        "{pack}: {chunks} {noun} it replaces {verb} also in {wad}, which the overlay does not carry; \
         the game may keep using its own copy there"
    )
}

// ---- handing the packs to the builder ----

struct WadDir {
    /// The WAD's name as the pack spells it.
    name: String,
    files: Vec<(Utf8PathBuf, Vec<u8>)>,
}

/// A pack as the overlay builder sees it: the bytes the validator checked, in memory.
struct PackData {
    project: ModProject,
    /// Layer, then lower-case WAD name.
    layers: BTreeMap<String, BTreeMap<String, WadDir>>,
    raw: Vec<(Utf8PathBuf, Vec<u8>)>,
}

fn snapshot(index: usize, pack: Pack) -> PackData {
    let Pack { info, files, .. } = pack;
    let mut layers: BTreeMap<String, BTreeMap<String, WadDir>> = BTreeMap::new();
    let mut raw = Vec::new();
    for file in files {
        let path = Utf8PathBuf::from(file.path);
        match file.wad {
            None => raw.push((path, file.bytes)),
            Some(wad) => {
                let layer = file.layer.to_ascii_lowercase();
                let key = wad.to_ascii_lowercase();
                layers
                    .entry(layer)
                    .or_default()
                    .entry(key)
                    .or_insert_with(|| WadDir { name: wad, files: Vec::new() })
                    .files
                    .push((path, file.bytes));
            }
        }
    }
    let project = project(index, &info, layers.keys().map(String::as_str));
    PackData { project, layers, raw }
}

/// The project the builder reads layers from. Layer names are lower-cased, which is how the
/// builder wants them; the pack's layers come in with the priorities its `info.json` gives them,
/// and a layer that has files but no entry gets the lowest.
#[allow(clippy::field_reassign_with_default)] // `ModProject` is non-exhaustive: this is how it is built.
fn project<'a>(index: usize, info: &FantomeInfo, found: impl Iterator<Item = &'a str>) -> ModProject {
    let mut project = ModProject::default();
    project.name = project_name(&info.name, index);
    project.display_name = info.name.clone();
    project.version = info.version.clone();
    project.description = info.description.clone();
    project.authors = vec![ModProjectAuthor::Name(info.author.clone())];

    let mut table: Vec<ModProjectLayer> = info
        .layers
        .iter()
        .filter(|(name, _)| is_layer_name(name))
        .map(|(name, layer)| ModProjectLayer {
            name: name.to_ascii_lowercase(),
            display_name: layer.display_name.clone(),
            priority: layer.priority,
            ..ModProjectLayer::default()
        })
        .collect();
    for name in found {
        if !table.iter().any(|layer| layer.name == name) {
            table.push(ModProjectLayer { name: name.to_owned(), ..ModProjectLayer::default() });
        }
    }
    ModProjectLayer::normalize_table(&mut table);
    project.layers = table;
    project
}

fn project_name(name: &str, index: usize) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c.to_ascii_lowercase() } else { '-' })
        .take(64)
        .collect();
    let cleaned = cleaned.trim_matches(['-', '_']);
    if cleaned.is_empty() { format!("pack{index}") } else { cleaned.to_owned() }
}

/// Serves a pack to the overlay builder from memory. It offers nothing the validator did not see:
/// no declarations, no pass-through of stored chunks, no fingerprint to skip a rebuild on.
struct Snapshot(PackData);

impl Snapshot {
    fn dir(&self, layer: &str, wad: &str) -> Option<&WadDir> {
        self.0.layers.get(layer)?.get(&wad.to_ascii_lowercase())
    }
}

fn missing(path: &Utf8Path) -> ltk_overlay::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("{path} is not in the pack")).into()
}

impl ModContentProvider for Snapshot {
    fn mod_project(&mut self) -> ltk_overlay::Result<ModProject> {
        Ok(self.0.project.clone())
    }

    fn list_layer_wads(&mut self, layer: &str) -> ltk_overlay::Result<Vec<String>> {
        Ok(self.0.layers.get(layer).map(|wads| wads.values().map(|dir| dir.name.clone()).collect()).unwrap_or_default())
    }

    fn read_wad_overrides(&mut self, layer: &str, wad_name: &str) -> ltk_overlay::Result<Vec<(Utf8PathBuf, Vec<u8>)>> {
        Ok(self.dir(layer, wad_name).map(|dir| dir.files.clone()).unwrap_or_default())
    }

    fn visit_wad_override(
        &mut self,
        layer: &str,
        wad_name: &str,
        visit: &mut dyn FnMut(Utf8PathBuf, Vec<u8>) -> ltk_overlay::Result<()>,
    ) -> ltk_overlay::Result<()> {
        if let Some(dir) = self.dir(layer, wad_name) {
            for (path, bytes) in &dir.files {
                visit(path.clone(), bytes.clone())?;
            }
        }
        Ok(())
    }

    fn read_raw_overrides(&mut self) -> ltk_overlay::Result<Vec<(Utf8PathBuf, Vec<u8>)>> {
        Ok(self.0.raw.clone())
    }

    fn visit_raw_override(
        &mut self,
        visit: &mut dyn FnMut(Utf8PathBuf, Vec<u8>) -> ltk_overlay::Result<()>,
    ) -> ltk_overlay::Result<()> {
        for (path, bytes) in &self.0.raw {
            visit(path.clone(), bytes.clone())?;
        }
        Ok(())
    }

    fn read_wad_override_file(&mut self, layer: &str, wad_name: &str, rel_path: &Utf8Path) -> ltk_overlay::Result<Vec<u8>> {
        self.dir(layer, wad_name)
            .and_then(|dir| dir.files.iter().find(|(path, _)| path == rel_path))
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(|| missing(rel_path))
    }

    fn read_raw_override_file(&mut self, rel_path: &Utf8Path) -> ltk_overlay::Result<Vec<u8>> {
        self.0
            .raw
            .iter()
            .find(|(path, _)| path == rel_path)
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(|| missing(rel_path))
    }
}

// ---- the audit ----

struct Audited {
    wads: usize,
    chunks: usize,
}

/// Compares what the builder wrote with the game and with the packs, WAD by WAD. A chunk has to be
/// the game's own or the bytes of a file that passed the validator. The builder is somebody else's
/// code working on somebody else's archives; this is what makes its output the host's to vouch for.
fn audit(game: &GameView, overlay_root: &Path, expected: &HashMap<u64, Vec<String>>) -> Result<Audited, Vec<String>> {
    let files = scan_overlay(overlay_root).map_err(|error| vec![format!("cannot list the overlay: {error}")])?;
    let mut problems = Vec::new();
    let mut chunks = 0;
    for file in &files {
        chunks += audit_wad(game, overlay_root, &file.path, expected, &mut problems);
        if problems.len() >= MAX_PROBLEMS {
            problems.push("... and more".into());
            break;
        }
    }
    if problems.is_empty() { Ok(Audited { wads: files.len(), chunks }) } else { Err(problems) }
}

fn same_entry(a: &WadChunk, b: &WadChunk) -> bool {
    a.compression_type == b.compression_type
        && a.compressed_size == b.compressed_size
        && a.uncompressed_size == b.uncompressed_size
        && a.checksum == b.checksum
}

/// Audits one overlay WAD and returns how many of its chunks are not the game's.
fn audit_wad(
    game: &GameView,
    overlay_root: &Path,
    relative: &str,
    expected: &HashMap<u64, Vec<String>>,
    problems: &mut Vec<String>,
) -> usize {
    let name = match relative.split('/').collect::<Vec<_>>().as_slice() {
        [data, fin, champions, name]
            if data.eq_ignore_ascii_case("data") && fin.eq_ignore_ascii_case("final") && champions.eq_ignore_ascii_case("champions") =>
        {
            name.to_ascii_lowercase()
        }
        _ => {
            problems.push(format!("{relative}: not directly in DATA/FINAL/Champions"));
            return 0;
        }
    };
    let mut game = game.borrow_mut();
    if !game.is_champion(&name) {
        problems.push(format!("{relative}: not a champion WAD of the game"));
        return 0;
    }
    let Some(original) = game.chunks_of(&name) else {
        problems.push(format!("{relative}: the game has no such WAD"));
        return 0;
    };
    let original: HashMap<u64, WadChunk> = original.into_iter().map(|chunk| (chunk.path_hash.0, chunk)).collect();

    let path = overlay_root.join(relative);
    let opened = File::open(&path).and_then(|file| file.metadata().map(|meta| (file, meta.len())));
    let Ok((file, length)) = opened else {
        problems.push(format!("{relative}: cannot be opened"));
        return 0;
    };
    let mounted = catch_unwind(AssertUnwindSafe(|| Wad::mount(file))).ok().and_then(Result::ok);
    let Some(mut wad) = mounted else {
        problems.push(format!("{relative}: is not a WAD that mounts"));
        return 0;
    };
    let ours: Vec<WadChunk> = wad.chunks().iter().copied().collect();

    let mut changed = 0;
    for chunk in &ours {
        let hash = chunk.path_hash.0;
        let unchanged = original.get(&hash).is_some_and(|theirs| same_entry(theirs, chunk));
        let wanted = expected.get(&hash);
        if unchanged && wanted.is_none() {
            continue;
        }

        // New, different from the game's, or named by a pack: its bytes have to be accounted for.
        let reach = (chunk.data_offset as u64).saturating_add(chunk.compressed_size as u64);
        if reach > length || chunk.uncompressed_size as u64 > MAX_ENTRY_BYTES {
            problems.push(format!("{relative}: chunk {hash:016x} has a size or place that cannot be right"));
            continue;
        }
        let digest = catch_unwind(AssertUnwindSafe(|| wad.load_chunk_decompressed(chunk)))
            .ok()
            .and_then(Result::ok)
            .map(|bytes| sha256_hex(&bytes));
        let from_a_pack = digest.as_ref().is_some_and(|digest| wanted.is_some_and(|held| held.contains(digest)));
        if from_a_pack {
            if !unchanged {
                changed += 1;
            }
            continue;
        }
        if unchanged {
            // A pack names this chunk, and the entry still looks like the game's. It has to be the
            // game's bytes too; a checksum alone is not proof of that.
            let theirs = game.raw(&name, hash);
            let ours = catch_unwind(AssertUnwindSafe(|| wad.load_chunk_raw(chunk))).ok().and_then(Result::ok);
            if theirs.is_some() && theirs.as_deref() == ours.as_deref() {
                continue;
            }
        }
        let what = if original.contains_key(&hash) { "differs from the game's" } else { "is not in the game" };
        problems.push(format!("{relative}: chunk {hash:016x} {what} and is not the bytes of any file that was checked"));
    }

    let have: HashSet<u64> = ours.iter().map(|chunk| chunk.path_hash.0).collect();
    let lost = original.keys().filter(|hash| !have.contains(hash)).count();
    if lost > 0 {
        problems.push(format!("{relative}: {lost} chunks of the game's WAD are missing"));
    }
    changed
}

// ---- the overlay folder ----

/// The folder as the filesystem names it, without the `\\?\` prefix the builder cannot take.
fn real_path(path: &Path) -> io::Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    let text = canonical.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return Ok(PathBuf::from(format!(r"\\{rest}")));
    }
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => Ok(PathBuf::from(rest)),
        _ => Ok(canonical),
    }
}

fn inside(path: &Path, base: &Path) -> bool {
    let parts = |path: &Path| -> Vec<String> {
        path.components().map(|part| part.as_os_str().to_string_lossy().to_ascii_lowercase()).collect()
    };
    parts(path).starts_with(&parts(base))
}

fn is_link(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// Where `folder` is or would be: the part that exists is resolved, the rest is kept as given. A
/// folder can then be judged before it is made.
fn resolve_future(folder: &Path) -> io::Result<PathBuf> {
    let mut missing = Vec::new();
    let mut at = folder;
    loop {
        match real_path(at) {
            Ok(mut resolved) => {
                resolved.extend(missing.iter().rev());
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let (Some(parent), Some(name)) = (at.parent(), at.file_name()) else { return Err(error) };
                missing.push(name);
                // A relative folder of one part has the working directory for a parent.
                at = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
            }
            Err(error) => return Err(error),
        }
    }
}

/// Makes sure the folder is one the host may empty: apart from the game, and holding nothing but
/// what an overlay holds. It need not exist yet. Nothing is made here, so a build that is refused
/// leaves the disk as it found it.
fn claim_folder(game_dir: &Path, folder: &Path) -> Result<PathBuf, BuildError> {
    let folder = resolve_future(folder)
        .map_err(|error| BuildError::Io(format!("cannot open {}", folder.display()), error))?;
    if inside(&folder, game_dir) || inside(game_dir, &folder) {
        return Err(BuildError::Folder(format!("{} and the game folder overlap", folder.display())));
    }
    let listing = match fs::read_dir(&folder) {
        Ok(listing) => listing,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(folder),
        Err(error) => return Err(BuildError::Io(format!("cannot list {}", folder.display()), error)),
    };
    for entry in listing {
        let entry = entry.map_err(|error| BuildError::Io(format!("cannot list {}", folder.display()), error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !OVERLAY_FILES.iter().any(|ours| ours.eq_ignore_ascii_case(&name)) {
            return Err(BuildError::Folder(format!(
                "{} holds {name}, which is not part of an overlay; use an empty folder",
                folder.display()
            )));
        }
        if is_link(&entry.path()) {
            return Err(BuildError::Folder(format!("{name} in {} is a link", folder.display())));
        }
    }
    Ok(folder)
}

/// Empties the folder of everything a build writes. The manifest goes first: without it nothing is
/// served, whatever state the rest is left in.
fn clear_folder(folder: &Path) -> io::Result<()> {
    for file in [MANIFEST_NAME.to_owned(), format!("{MANIFEST_NAME}.tmp")] {
        match fs::remove_file(folder.join(file)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    for dir in [STATE_DIR, "DATA"] {
        match fs::remove_dir_all(folder.join(dir)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io::{Cursor, Write};

    use ltk_wad::{WadBuilder, WadChunkBuilder, WadChunkCompression, WadHash};
    use riftengine_core::proto::GAME_EXE_NAME;
    use riftengine_rules::END_OF_LIFE;
    use tempfile::{NamedTempFile, TempDir};

    use super::*;
    use crate::game::tests::exe_linked_at;
    use crate::pack::tests::{INFO, archive, wad as packed_wad};

    const AHRI_TEXTURE: &str = "assets/characters/ahri/skins/base/ahri_base_tx_cm.dds";
    const AHRI_MODEL: &str = "assets/characters/ahri/skins/base/ahri_base.skn";
    const ZED_TEXTURE: &str = "assets/characters/zed/skins/base/zed_base_tx_cm.dds";
    /// Held by Ahri's WAD and by `Global.wad.client`, which an overlay never carries. Like the
    /// rest, it is in a folder that `RAW/` files may name.
    const SHARED: &str = "assets/characters/ahri/skins/base/ahri_spark_tx.dds";
    /// Held by `Global.wad.client` alone, and by no champion's WAD.
    const GLOBAL_ONLY: &str = "assets/characters/ahri/skins/base/ahri_global_tx.dds";
    /// Another one that Ahri's WAD and `Global.wad.client` share, for the few tests that count them.
    const SHARED_TOO: &str = "assets/characters/ahri/skins/base/ahri_spark_nm.dds";

    const AHRI: &str = "DATA/FINAL/Champions/Ahri.wad.client";
    const ZED: &str = "DATA/FINAL/Champions/Zed.wad.client";
    const GLOBAL: &str = "DATA/FINAL/Global.wad.client";

    const AHRI_CHUNKS: [(&str, &[u8]); 3] = [
        (AHRI_TEXTURE, b"DDS ahri as the game has it"),
        (AHRI_MODEL, b"SKN ahri as the game has it"),
        (SHARED, b"DDS shared as the game has it"),
    ];

    fn hash_of(path: &str) -> WadHash {
        resolve_chunk_hash(Utf8Path::new(path), b"").unwrap()
    }

    /// Writes a WAD of stored chunks, which makes an unchanged entry the same in every copy.
    fn write_wad(path: &Path, chunks: &[(&str, &[u8])]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut builder = WadBuilder::default();
        let mut bytes = BTreeMap::new();
        for (name, content) in chunks {
            let hash = hash_of(name);
            builder = builder
                .with_chunk(WadChunkBuilder::default().with_hash(hash).with_force_compression(WadChunkCompression::None));
            bytes.insert(hash, content.to_vec());
        }
        let mut out = Cursor::new(Vec::new());
        builder
            .build_to_writer(&mut out, |hash, chunk| {
                chunk.write_all(&bytes[&hash])?;
                Ok(())
            })
            .unwrap();
        fs::write(path, out.into_inner()).unwrap();
    }

    /// A game folder with two champion WADs and one other, and a place beside it for an overlay.
    struct Install {
        dir: TempDir,
    }

    impl Install {
        fn new() -> Self {
            let install = Self { dir: tempfile::tempdir().unwrap() };
            let game = install.game();
            write_wad(&game.join(AHRI), &AHRI_CHUNKS);
            write_wad(&game.join(ZED), &[(ZED_TEXTURE, b"DDS zed as the game has it")]);
            write_wad(&game.join(GLOBAL), &[(GLOBAL_ONLY, b"DDS global as the game has it"), AHRI_CHUNKS[2]]);
            // The newest build the rules reach.
            fs::write(game.join(GAME_EXE_NAME), exe_linked_at(END_OF_LIFE - 1)).unwrap();
            install
        }

        fn game(&self) -> PathBuf {
            self.dir.path().join("Game")
        }

        fn overlay(&self) -> PathBuf {
            self.dir.path().join("overlay")
        }

        fn build(&self, packs: &[&NamedTempFile]) -> (Result<Built, BuildError>, Vec<Event>) {
            self.build_in(&self.overlay(), packs)
        }

        fn build_in(&self, overlay: &Path, packs: &[&NamedTempFile]) -> (Result<Built, BuildError>, Vec<Event>) {
            let game = self.game();
            let packs: Vec<PathBuf> = packs.iter().map(|pack| pack.path().to_owned()).collect();
            let mut events = Vec::new();
            let options = Options { game_dir: &game, overlay_root: overlay, packs: &packs };
            let result = build(&options, &mut |event| events.push(event));
            (result, events)
        }
    }

    fn pack(entries: &[(&str, &[u8])]) -> NamedTempFile {
        let mut all: Vec<(&str, &[u8])> = vec![("META/info.json", INFO.as_bytes())];
        all.extend_from_slice(entries);
        archive(&all)
    }

    fn ahri(path: &str) -> String {
        format!("WAD/Ahri.wad.client/{path}")
    }

    /// One chunk of a WAD file, decompressed.
    fn chunk_at(wad: &Path, hash: WadHash) -> Vec<u8> {
        let mut wad = Wad::mount(File::open(wad).unwrap()).unwrap();
        let chunk = *wad.chunks().get(hash).expect("the WAD holds the chunk");
        wad.load_chunk_decompressed(&chunk).unwrap().into_vec()
    }

    fn chunk_of(wad: &Path, path: &str) -> Vec<u8> {
        chunk_at(wad, hash_of(path))
    }

    /// Every WAD under `DATA/FINAL` with the SHA-256 of its bytes.
    fn contents_of(root: &Path) -> Vec<(String, String)> {
        scan_overlay(root)
            .unwrap()
            .into_iter()
            .map(|file| {
                let bytes = fs::read(root.join(&file.path)).unwrap();
                (file.path, sha256_hex(&bytes))
            })
            .collect()
    }

    fn rules(events: &[Event]) -> BTreeSet<&str> {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Violation { rule, .. } => Some(rule.as_str()),
                _ => None,
            })
            .collect()
    }

    fn details(events: &[Event]) -> Vec<&str> {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Violation { detail, .. } => Some(detail.as_str()),
                _ => None,
            })
            .collect()
    }

    /// What the build said besides its findings: the log lines.
    fn logged(events: &[Event]) -> Vec<&str> {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Log { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    // ---- the whole build ----

    #[test]
    fn a_clean_pack_builds_an_overlay_the_host_vouches_for() {
        let install = Install::new();
        let before = contents_of(&install.game());
        let pack = pack(&[(&ahri(AHRI_TEXTURE), b"DDS ahri modded")]);

        let (result, events) = install.build(&[&pack]);
        let built = result.unwrap();

        assert_eq!((built.wads, built.chunks), (1, 1));
        let overlay = install.overlay();
        assert_eq!(chunk_of(&overlay.join(AHRI), AHRI_TEXTURE), b"DDS ahri modded");
        assert_eq!(chunk_of(&overlay.join(AHRI), AHRI_MODEL), AHRI_CHUNKS[1].1);
        assert_eq!(chunk_of(&overlay.join(AHRI), SHARED), AHRI_CHUNKS[2].1);
        assert!(!overlay.join(ZED).exists(), "a WAD nothing replaces in is not carried");
        assert!(!overlay.join(STATE_DIR).exists());

        let (manifest, digest) = OverlayManifest::load(&overlay).unwrap();
        assert_eq!(digest, built.manifest);
        assert_eq!(manifest.rules_digest, riftengine_rules::digest());
        assert_eq!(manifest.game_linked, END_OF_LIFE - 1, "made for the game that was there");
        assert_eq!(manifest.files.iter().map(|file| file.path.as_str()).collect::<Vec<_>>(), [AHRI]);
        manifest.verify_against_disk(&overlay).unwrap();
        assert_eq!(contents_of(&install.game()), before, "the game is not touched");

        assert!(events.iter().any(|e| matches!(e, Event::Validated { files: 1, violations: 0, .. })), "{events:?}");
        assert!(events.iter().any(|e| matches!(e, Event::Building { .. })), "{events:?}");
        assert_eq!(events.last(), Some(&Event::Built { wads: 1, chunks: 1, manifest: built.manifest }));
    }

    #[test]
    fn raw_files_and_packed_wads_reach_the_chunks_they_name() {
        let install = Install::new();
        let packed = packed_wad(&[(hash_of(AHRI_MODEL).0, b"SKN ahri modded")]);
        let pack = pack(&[(&format!("RAW/{AHRI_TEXTURE}"), b"DDS ahri modded"), ("WAD/Ahri.wad.client", &packed)]);

        let built = install.build(&[&pack]).0.unwrap();

        assert_eq!((built.wads, built.chunks), (1, 2));
        let served = install.overlay().join(AHRI);
        assert_eq!(chunk_of(&served, AHRI_TEXTURE), b"DDS ahri modded");
        assert_eq!(chunk_of(&served, AHRI_MODEL), b"SKN ahri modded");
        assert_eq!(chunk_of(&served, SHARED), AHRI_CHUNKS[2].1);
    }

    #[test]
    fn a_chunk_the_champion_wad_shares_with_another_wad_is_replaced_there_and_reported() {
        let install = Install::new();
        let before = contents_of(&install.game());
        let pack = pack(&[(&ahri(SHARED), b"DDS shared modded")]);

        let (result, events) = install.build(&[&pack]);

        let built = result.unwrap();
        assert_eq!((built.wads, built.chunks), (1, 1));
        let overlay = install.overlay();
        assert_eq!(chunk_of(&overlay.join(AHRI), SHARED), b"DDS shared modded");
        assert!(!overlay.join(GLOBAL).exists(), "the other WAD is not carried");
        assert_eq!(contents_of(&install.game()), before, "and the game keeps its own copy of the chunk there");
        OverlayManifest::load(&overlay).unwrap().0.verify_against_disk(&overlay).unwrap();

        let said = logged(&events);
        assert_eq!(said.len(), 1, "{events:?}");
        assert!(said[0].contains("1 chunk it replaces is also in global.wad.client"), "{said:?}");
        assert!(said[0].ends_with("the game may keep using its own copy there"), "{said:?}");
        // After the packs were checked, before anything is built.
        let at = |is: fn(&Event) -> bool| events.iter().position(is).unwrap();
        let validated = at(|e| matches!(e, Event::Validated { violations: 0, .. }));
        let note = at(|e| matches!(e, Event::Log { level: 2, .. }));
        let building = at(|e| matches!(e, Event::Building { .. }));
        assert!(validated < note && note < building, "{events:?}");
    }

    #[test]
    fn a_raw_file_is_replaced_where_a_champion_wad_holds_it_and_reported() {
        let install = Install::new();
        let pack = pack(&[(&format!("RAW/{SHARED}"), b"DDS shared modded")]);

        let (result, events) = install.build(&[&pack]);

        let built = result.unwrap();
        assert_eq!((built.wads, built.chunks), (1, 1));
        assert_eq!(chunk_of(&install.overlay().join(AHRI), SHARED), b"DDS shared modded");
        assert!(!install.overlay().join(GLOBAL).exists());
        let said = logged(&events);
        assert!(said.len() == 1 && said[0].contains("1 chunk it replaces is also in global.wad.client"), "{said:?}");
    }

    #[test]
    fn every_chunk_of_every_pack_is_counted_in_what_is_reported() {
        let install = Install::new();
        let game = install.game();
        let ahri_with_more = [AHRI_CHUNKS[0], AHRI_CHUNKS[1], AHRI_CHUNKS[2], (SHARED_TOO, &b"DDS also shared"[..])];
        write_wad(&game.join(AHRI), &ahri_with_more);
        write_wad(&game.join(GLOBAL), &[(GLOBAL_ONLY, &b"DDS global as the game has it"[..]), AHRI_CHUNKS[2], ahri_with_more[3]]);
        let two = pack(&[(&ahri(SHARED), b"DDS shared one"), (&ahri(SHARED_TOO), b"DDS also one")]);
        let one = pack(&[(&ahri(SHARED), b"DDS shared two"), (&ahri(AHRI_TEXTURE), b"DDS ahri modded")]);

        let (result, events) = install.build(&[&two, &one]);

        result.unwrap();
        let said = logged(&events);
        assert_eq!(said.len(), 2, "{said:?}");
        assert!(said[0].contains("2 chunks it replaces are also in global.wad.client"), "{said:?}");
        assert!(said[1].contains("1 chunk it replaces is also in global.wad.client"), "{said:?}");
        assert_ne!(said[0].split(':').next(), said[1].split(':').next(), "each is named by its own pack");
    }

    #[test]
    fn a_chunk_that_no_other_wad_holds_is_not_reported() {
        let install = Install::new();
        let pack = pack(&[(&ahri(AHRI_TEXTURE), b"DDS ahri modded"), (&ahri(AHRI_MODEL), b"SKN ahri modded")]);

        let (result, events) = install.build(&[&pack]);

        result.unwrap();
        assert!(logged(&events).is_empty(), "{events:?}");
    }

    #[test]
    fn a_shared_chunk_is_carried_where_a_champion_wad_the_pack_names_holds_it() {
        let install = Install::new();
        let game = GameWads::open(&install.game()).unwrap();
        let hash = |path: &str| hash_of(path).0;
        let global = vec!["global.wad.client".to_owned()];
        let in_global = |carried| Some(Shared { others: global.clone(), carried });

        // In Ahri's WAD and in Global's: carried by the first, and by a file that names no WAD.
        assert_eq!(game.shared_outside(Some("ahri.wad.client"), hash(SHARED)), in_global(true));
        assert_eq!(game.shared_outside(None, hash(SHARED)), in_global(true));
        // Zed's WAD does not hold it, and Global's is no champion's, whatever it holds.
        assert_eq!(game.shared_outside(Some("zed.wad.client"), hash(SHARED)), in_global(false));
        assert_eq!(game.shared_outside(Some("global.wad.client"), hash(SHARED)), in_global(false));
        // Only in Global's: no champion WAD has it, so nothing is carried.
        assert_eq!(game.shared_outside(Some("ahri.wad.client"), hash(GLOBAL_ONLY)), in_global(false));
        assert_eq!(game.shared_outside(None, hash(GLOBAL_ONLY)), in_global(false));
        // In no WAD outside the champions, or in none at all.
        assert_eq!(game.shared_outside(Some("ahri.wad.client"), hash(AHRI_TEXTURE)), None);
        assert_eq!(game.shared_outside(None, hash("assets/characters/ahri/skins/base/new.dds")), None);
    }

    #[test]
    fn the_report_of_shared_chunks_counts_and_names_the_wad() {
        assert_eq!(
            shared_note("a.fantome", 1, "map30.wad.client"),
            "a.fantome: 1 chunk it replaces is also in map30.wad.client, which the overlay does not carry; \
             the game may keep using its own copy there"
        );
        assert!(
            shared_note("a.fantome", 36, "ui.wad.client")
                .starts_with("a.fantome: 36 chunks it replaces are also in ui.wad.client, which")
        );
    }

    #[test]
    fn the_first_pack_has_the_say() {
        let install = Install::new();
        let high = pack(&[(&ahri(AHRI_TEXTURE), b"DDS from the first")]);
        let low = pack(&[(&ahri(AHRI_TEXTURE), b"DDS from the second"), (&ahri(AHRI_MODEL), b"SKN from the second")]);

        let built = install.build(&[&high, &low]).0.unwrap();

        assert_eq!((built.wads, built.chunks), (1, 2));
        let served = install.overlay().join(AHRI);
        assert_eq!(chunk_of(&served, AHRI_TEXTURE), b"DDS from the first");
        assert_eq!(chunk_of(&served, AHRI_MODEL), b"SKN from the second");
    }

    #[test]
    fn a_higher_layer_wins_over_the_base() {
        let install = Install::new();
        let info = r#"{"Name":"Layered","Author":"me","Description":"","Layers":{"pink":{"Name":"pink","Priority":5}}}"#;
        let layered = archive(&[
            ("META/info.json", info.as_bytes()),
            (&ahri(AHRI_TEXTURE), b"DDS base layer"),
            (&format!("WAD_pink/Ahri.wad.client/{AHRI_TEXTURE}"), b"DDS pink layer"),
        ]);

        let (result, events) = install.build(&[&layered]);

        let built = result.unwrap();
        assert_eq!((built.wads, built.chunks), (1, 1));
        assert!(events.iter().any(|e| matches!(e, Event::Validated { files: 2, violations: 0, .. })), "{events:?}");
        assert_eq!(chunk_of(&install.overlay().join(AHRI), AHRI_TEXTURE), b"DDS pink layer");
    }

    #[test]
    fn a_rebuild_replaces_the_old_overlay() {
        let install = Install::new();
        let first = pack(&[(&ahri(AHRI_TEXTURE), b"DDS ahri modded")]);
        let second = pack(&[("WAD/Zed.wad.client/assets/characters/zed/skins/base/zed_base_tx_cm.dds", b"DDS zed modded")]);
        install.build(&[&first]).0.unwrap();

        let built = install.build(&[&second]).0.unwrap();

        assert_eq!((built.wads, built.chunks), (1, 1));
        let overlay = install.overlay();
        assert!(!overlay.join(AHRI).exists());
        assert_eq!(chunk_of(&overlay.join(ZED), ZED_TEXTURE), b"DDS zed modded");
        let (manifest, digest) = OverlayManifest::load(&overlay).unwrap();
        assert_eq!(digest, built.manifest);
        assert_eq!(manifest.files.iter().map(|file| file.path.as_str()).collect::<Vec<_>>(), [ZED]);
        manifest.verify_against_disk(&overlay).unwrap();
    }

    // ---- what is refused ----

    #[test]
    fn a_pack_the_rules_refuse_builds_nothing() {
        let install = Install::new();
        let program = pack(&[
            (&ahri("assets/characters/ahri/skins/base/ahri.exe"), b"MZ\x90\0"),
            (&ahri(AHRI_MODEL), b"SKN ahri modded"),
        ]);

        let (result, events) = install.build(&[&program]);

        assert!(matches!(result, Err(BuildError::Refused { violations }) if violations > 0), "{result:?}");
        assert_eq!(rules(&events), BTreeSet::from([id::FILE_KIND]));
        assert!(!events.iter().any(|e| matches!(e, Event::Building { .. } | Event::Built { .. })), "{events:?}");
        assert!(!install.overlay().exists(), "nothing was made");
    }

    #[test]
    fn a_refused_rebuild_leaves_the_earlier_overlay_as_it_was() {
        let install = Install::new();
        let fine = pack(&[(&ahri(AHRI_TEXTURE), b"DDS ahri modded")]);
        install.build(&[&fine]).0.unwrap();
        let overlay = install.overlay();
        let kept = contents_of(&overlay);

        let program = pack(&[(&ahri("assets/characters/ahri/skins/base/ahri.dll"), b"MZ\x90\0")]);
        let (result, _) = install.build(&[&fine, &program]);

        assert!(matches!(result, Err(BuildError::Refused { .. })), "{result:?}");
        assert_eq!(contents_of(&overlay), kept);
        OverlayManifest::load(&overlay).unwrap().0.verify_against_disk(&overlay).unwrap();
    }

    #[test]
    fn a_wad_that_is_not_a_champions_is_refused() {
        let install = Install::new();
        let pack = pack(&[(&format!("WAD/Global.wad.client/{GLOBAL_ONLY}"), b"DDS global modded")]);

        let (result, events) = install.build(&[&pack]);

        // Once, by name. That the chunk is in that WAD is not a second reason.
        assert!(matches!(result, Err(BuildError::Refused { violations: 1 })), "{result:?}");
        assert_eq!(rules(&events), BTreeSet::from([id::TARGET]));
        assert!(!install.overlay().exists());
    }

    #[test]
    fn a_chunk_only_a_non_champion_wad_holds_is_refused_in_any_champion_wad() {
        let install = Install::new();
        // `GLOBAL_ONLY` is in Global's WAD and in no champion's. The shared chunk beside it is fine.
        let pack = pack(&[(&ahri(GLOBAL_ONLY), b"DDS global modded"), (&ahri(SHARED), b"DDS shared modded")]);

        let (result, events) = install.build(&[&pack]);

        assert!(matches!(result, Err(BuildError::Refused { violations: 1 })), "{result:?}");
        assert_eq!(rules(&events), BTreeSet::from([id::TARGET]));
        let found = details(&events);
        assert!(found[0].contains("global.wad.client") && found[0].ends_with("but not in Ahri.wad.client"), "{found:?}");
        assert!(logged(&events).is_empty(), "a refused build does not report what it would have kept: {events:?}");
        assert!(!install.overlay().exists());
    }

    #[test]
    fn a_chunk_another_champion_wad_holds_is_not_this_wads() {
        let install = Install::new();
        // Ahri's WAD and Global's hold `SHARED`. Zed's does not, so there is nothing of it to replace there.
        let pack = pack(&[(&format!("WAD/Zed.wad.client/{SHARED}"), b"DDS shared modded")]);

        let (result, events) = install.build(&[&pack]);

        assert!(matches!(result, Err(BuildError::Refused { violations: 1 })), "{result:?}");
        assert_eq!(rules(&events), BTreeSet::from([id::TARGET]));
        assert!(details(&events)[0].ends_with("but not in Zed.wad.client"), "{events:?}");
        assert!(!install.overlay().exists());
    }

    #[test]
    fn a_raw_file_only_a_non_champion_wad_holds_is_refused() {
        let install = Install::new();
        let pack = pack(&[(&format!("RAW/{GLOBAL_ONLY}"), b"DDS global modded")]);

        let (result, events) = install.build(&[&pack]);

        assert!(matches!(result, Err(BuildError::Refused { violations: 1 })), "{result:?}");
        assert_eq!(rules(&events), BTreeSet::from([id::TARGET]));
        let found = details(&events);
        assert!(found[0].contains("global.wad.client") && found[0].ends_with("and in no champion WAD"), "{found:?}");
        assert!(!install.overlay().exists());
    }

    #[test]
    fn two_files_filed_under_one_chunk_of_a_layer_are_refused() {
        let install = Install::new();
        let pack = pack(&[
            (&ahri(AHRI_TEXTURE), b"DDS one"),
            (&ahri(&AHRI_TEXTURE.to_ascii_uppercase()), b"DDS two"),
        ]);

        let (result, events) = install.build(&[&pack]);

        assert!(matches!(result, Err(BuildError::Refused { violations: 1 })), "{result:?}");
        assert_eq!(rules(&events), BTreeSet::from([id::PATH]));
    }

    #[test]
    fn a_pack_that_declares_game_data_is_refused() {
        let install = Install::new();
        let info = r#"{"Name":"T","Author":"a","Description":"d","Layers":{"base":{"Name":"base","Priority":0,"GameData":{"format":1}}}}"#;
        let pack = archive(&[("META/info.json", info.as_bytes()), (&ahri(AHRI_TEXTURE), b"DDS ahri modded")]);

        let (result, events) = install.build(&[&pack]);

        assert!(matches!(result, Err(BuildError::Refused { .. })), "{result:?}");
        assert_eq!(rules(&events), BTreeSet::from([id::DATA_DECL]));
    }

    #[test]
    fn a_file_that_is_no_pack_is_named_in_the_error() {
        let install = Install::new();
        let junk = tempfile::Builder::new().suffix(".fantome").tempfile().unwrap();
        fs::write(junk.path(), b"not a zip").unwrap();

        let (result, _) = install.build(&[&junk]);

        let error = result.unwrap_err();
        assert!(matches!(error, BuildError::Pack { .. }), "{error:?}");
        assert!(error.to_string().contains(&*junk.path().file_name().unwrap().to_string_lossy()), "{error}");
        assert!(!install.overlay().exists());
    }

    #[test]
    fn a_folder_that_is_not_a_game_builds_nothing() {
        let install = Install::new();
        let empty = tempfile::tempdir().unwrap();
        let pack = pack(&[(&ahri(AHRI_TEXTURE), b"DDS ahri modded")]);
        let overlay = install.overlay();
        let packs = [pack.path().to_owned()];

        let result = build(&Options { game_dir: empty.path(), overlay_root: &overlay, packs: &packs }, &mut |_| {});

        assert!(matches!(result, Err(BuildError::Game(_))), "{result:?}");
        assert!(!overlay.exists());
    }

    #[test]
    fn a_game_the_rules_do_not_reach_gets_no_overlay() {
        let install = Install::new();
        let pack = pack(&[(&ahri(AHRI_TEXTURE), b"DDS ahri modded")]);
        let before = contents_of(&install.game());

        for (linked, said) in [(END_OF_LIFE, "the rules cover only builds before"), (0, "carries no build time")] {
            fs::write(install.game().join(GAME_EXE_NAME), exe_linked_at(linked)).unwrap();

            let (result, events) = install.build(&[&pack]);

            let message = match result {
                Err(BuildError::GameBuild(message)) => message,
                other => panic!("{other:?}"),
            };
            assert!(message.contains(said), "{message}");
            // Not even the pack was looked at, and the game is as it was.
            assert!(events.is_empty(), "{events:?}");
            assert!(!install.overlay().exists());
            assert_eq!(contents_of(&install.game()), before);
        }
    }

    #[test]
    fn the_overlay_is_made_for_the_build_the_executable_says() {
        let install = Install::new();
        let pack = pack(&[(&ahri(AHRI_TEXTURE), b"DDS ahri modded")]);

        // Not the newest build the rules reach and not a constant: whatever the executable carries.
        for linked in [1_792_188_909, 1_792_188_910, 1] {
            fs::write(install.game().join(GAME_EXE_NAME), exe_linked_at(linked)).unwrap();

            install.build(&[&pack]).0.unwrap();

            let (manifest, _) = OverlayManifest::load(&install.overlay()).unwrap();
            assert_eq!(manifest.game_linked, linked);
        }
    }

    // ---- the overlay folder ----

    #[test]
    fn a_folder_that_is_not_an_overlay_is_left_alone() {
        let install = Install::new();
        let overlay = install.overlay();
        fs::create_dir_all(&overlay).unwrap();
        fs::write(overlay.join("notes.txt"), b"mine").unwrap();
        let pack = pack(&[(&ahri(AHRI_TEXTURE), b"DDS ahri modded")]);

        let (result, events) = install.build(&[&pack]);

        assert!(matches!(result, Err(BuildError::Folder(_))), "{result:?}");
        assert_eq!(fs::read(overlay.join("notes.txt")).unwrap(), b"mine");
        assert!(events.is_empty(), "{events:?}");
    }

    #[test]
    fn an_overlay_in_or_around_the_game_is_refused_before_anything_is_made() {
        let install = Install::new();
        let pack = pack(&[(&ahri(AHRI_TEXTURE), b"DDS ahri modded")]);
        let before = contents_of(&install.game());

        for folder in [install.game().join("overlay"), install.game(), install.dir.path().to_owned()] {
            let (result, events) = install.build_in(&folder, &[&pack]);
            assert!(matches!(result, Err(BuildError::Folder(_))), "{}: {result:?}", folder.display());
            assert!(events.is_empty(), "{events:?}");
        }

        assert!(!install.game().join("overlay").exists());
        assert!(!install.game().join(MANIFEST_NAME).exists());
        assert_eq!(contents_of(&install.game()), before);
    }

    #[test]
    fn a_folder_that_is_not_there_yet_is_judged_where_it_would_be() {
        let dir = tempfile::tempdir().unwrap();
        let wanted = dir.path().join("a").join("b");

        assert_eq!(resolve_future(&wanted).unwrap(), real_path(dir.path()).unwrap().join("a").join("b"));
        assert!(!dir.path().join("a").exists());

        // One part, so the working directory is where it would be.
        let relative = resolve_future(Path::new("riftengine-not-there")).unwrap();
        assert_eq!(relative, real_path(&std::env::current_dir().unwrap()).unwrap().join("riftengine-not-there"));
    }

    #[test]
    fn project_names_are_safe_to_hand_to_the_builder() {
        assert_eq!(project_name("Cool Skin v2!", 3), "cool-skin-v2");
        assert_eq!(project_name("!!!", 3), "pack3");
        assert_eq!(project_name(&"a".repeat(100), 0).len(), 64);
    }

    // ---- the audit ----

    /// Puts WADs in the overlay folder by hand and audits them against the game.
    fn audited(
        install: &Install,
        wads: &[(&str, &[(&str, &[u8])])],
        expected: &[(&str, &[u8])],
    ) -> Result<Audited, Vec<String>> {
        let overlay = install.overlay();
        for (relative, chunks) in wads {
            write_wad(&overlay.join(relative), chunks);
        }
        let mut wanted: HashMap<u64, Vec<String>> = HashMap::new();
        for (path, bytes) in expected {
            wanted.entry(hash_of(path).0).or_default().push(sha256_hex(bytes));
        }
        let game = GameView::new(GameWads::open(&install.game()).unwrap());
        audit(&game, &overlay, &wanted)
    }

    fn with_texture(bytes: &'static [u8]) -> [(&'static str, &'static [u8]); 3] {
        [(AHRI_TEXTURE, bytes), AHRI_CHUNKS[1], AHRI_CHUNKS[2]]
    }

    #[test]
    fn an_overlay_of_the_games_own_chunks_passes() {
        let install = Install::new();
        let done = audited(&install, &[(AHRI, &AHRI_CHUNKS)], &[]).unwrap();
        assert_eq!((done.wads, done.chunks), (1, 0));
    }

    #[test]
    fn a_chunk_that_a_checked_file_accounts_for_passes() {
        let install = Install::new();
        let done = audited(&install, &[(AHRI, &with_texture(b"DDS ahri modded"))], &[(AHRI_TEXTURE, b"DDS ahri modded")])
            .unwrap();
        assert_eq!((done.wads, done.chunks), (1, 1));
    }

    #[test]
    fn a_pack_file_the_game_already_has_passes_unchanged() {
        let install = Install::new();
        let same = AHRI_CHUNKS[0].1;
        let done = audited(&install, &[(AHRI, &AHRI_CHUNKS)], &[(AHRI_TEXTURE, same)]).unwrap();
        assert_eq!((done.wads, done.chunks), (1, 0));
    }

    #[test]
    fn a_chunk_no_checked_file_accounts_for_does_not_pass() {
        let install = Install::new();
        let problems = audited(&install, &[(AHRI, &with_texture(b"DDS tampered"))], &[]).err().unwrap();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("differs from the game's"), "{problems:?}");

        // A file was checked, but it was not this one.
        let problems =
            audited(&install, &[(AHRI, &with_texture(b"DDS tampered"))], &[(AHRI_TEXTURE, b"DDS what was checked")])
                .err()
                .unwrap();
        assert!(problems[0].contains("differs from the game's"), "{problems:?}");
    }

    #[test]
    fn a_chunk_the_game_does_not_have_does_not_pass() {
        let install = Install::new();
        let extra = [AHRI_CHUNKS[0], AHRI_CHUNKS[1], AHRI_CHUNKS[2], (ZED_TEXTURE, b"DDS smuggled".as_slice())];
        let problems = audited(&install, &[(AHRI, &extra)], &[]).err().unwrap();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("is not in the game"), "{problems:?}");
    }

    #[test]
    fn a_dropped_chunk_does_not_pass() {
        let install = Install::new();
        let problems = audited(&install, &[(AHRI, &AHRI_CHUNKS[..2])], &[]).err().unwrap();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("1 chunks of the game's WAD are missing"), "{problems:?}");
    }

    // ---- the installed game ----

    /// Three textures of a champion WAD with their last byte changed, so that a pack of them is
    /// clean whatever the build, and the real WADs show what the audit makes of their entries. It
    /// takes the smallest champion WAD that has three whose holders `fit`;
    /// `RIFTENGINE_TEST_WAD=<name>.wad.client` names another.
    fn changed_textures(
        game: &GameView,
        game_dir: &Path,
        fit: impl Fn(&GameWads, &str, u64) -> bool,
    ) -> (String, Vec<(u64, Vec<u8>)>) {
        let asked = std::env::var("RIFTENGINE_TEST_WAD").ok();
        let folder = game_dir.join("DATA").join("FINAL").join("Champions");
        let mut candidates: Vec<(u64, String)> = game
            .borrow()
            .champion_wads()
            .into_iter()
            .map(|name| (fs::metadata(folder.join(name)).map_or(u64::MAX, |meta| meta.len()), name.to_owned()))
            .collect();
        candidates.sort();
        candidates
            .iter()
            .filter(|(_, name)| asked.as_deref().is_none_or(|asked| asked.eq_ignore_ascii_case(name)))
            .find_map(|(_, name)| {
                let chunks = game.borrow().chunks_of(name)?;
                let mut found = Vec::new();
                for chunk in chunks {
                    let hash = chunk.path_hash.0;
                    if !(64..=1 << 20).contains(&chunk.uncompressed_size) || !fit(&game.borrow(), name, hash) {
                        continue;
                    }
                    let Some(mut bytes) = game.borrow_mut().load(name, hash) else { continue };
                    if !(bytes.starts_with(b"TEX ") || bytes.starts_with(b"DDS ")) {
                        continue;
                    }
                    *bytes.last_mut().unwrap() ^= 1;
                    found.push((hash, bytes));
                    if found.len() == 3 {
                        return Some((name.clone(), found));
                    }
                }
                None
            })
            .expect("a champion WAD with three textures that fit")
    }

    /// Builds a pack of those textures against the installed game, into a folder of its own, and
    /// checks that the champion WAD of the overlay serves them. The overlay goes when the folder does.
    fn build_changed(game_dir: &Path, name: &str, changed: &[(u64, Vec<u8>)]) -> (TempDir, Vec<Event>) {
        let entries: Vec<(String, Vec<u8>)> =
            changed.iter().map(|(hash, bytes)| (format!("WAD/{name}/{hash:016x}"), bytes.clone())).collect();
        let listed: Vec<(&str, &[u8])> = entries.iter().map(|(entry, bytes)| (entry.as_str(), bytes.as_slice())).collect();
        let pack = pack(&listed);
        let overlay = tempfile::tempdir().unwrap();
        let root = overlay.path().join("overlay");
        let packs = [pack.path().to_owned()];
        let mut events = Vec::new();

        let started = std::time::Instant::now();
        let result = build(&Options { game_dir, overlay_root: &root, packs: &packs }, &mut |event| events.push(event));
        let built = result.unwrap_or_else(|error| panic!("{error}"));

        eprintln!("{name}: {} textures changed, {} WADs and {} chunks built in {:?}", changed.len(), built.wads, built.chunks, started.elapsed());
        assert_eq!((built.wads, built.chunks), (1, changed.len()));
        assert!(events.iter().any(|e| matches!(e, Event::Validated { violations: 0, .. })), "{events:?}");
        let served = root.join("DATA").join("FINAL").join("Champions").join(name);
        for (hash, bytes) in changed {
            assert_eq!(&chunk_at(&served, WadHash(*hash)), bytes, "{hash:016x}");
        }
        OverlayManifest::load(&root).unwrap().0.verify_against_disk(&root).unwrap();
        (overlay, events)
    }

    /// Needs an installed game, which it only reads:
    /// `RIFTENGINE_GAME_DIR=<Game> cargo test -p riftengine-host --lib -- --ignored --nocapture`.
    /// The textures are ones that only the champion's WAD holds.
    #[test]
    #[ignore = "needs an installed game"]
    fn the_installed_game_takes_a_pack_of_its_own_textures() {
        let game_dir = PathBuf::from(std::env::var("RIFTENGINE_GAME_DIR").expect("RIFTENGINE_GAME_DIR names the game's `Game` folder"));
        let game = GameView::new(GameWads::open(&game_dir).unwrap());
        let (name, changed) = changed_textures(&game, &game_dir, |game, _, hash| game.holders_of(hash).len() == 1);

        let (_overlay, events) = build_changed(&game_dir, &name, &changed);

        assert!(logged(&events).is_empty(), "{events:?}");
    }

    /// The same, with textures that the champion's WAD shares with WADs outside the champions (a
    /// map's, say). The build has to go ahead and say so.
    #[test]
    #[ignore = "needs an installed game"]
    fn the_installed_game_takes_textures_a_map_wad_shares_with_the_champion_wad() {
        let game_dir = PathBuf::from(std::env::var("RIFTENGINE_GAME_DIR").expect("RIFTENGINE_GAME_DIR names the game's `Game` folder"));
        let game = GameView::new(GameWads::open(&game_dir).unwrap());
        let shared = |game: &GameWads, name: &str, hash: u64| {
            let holders = game.holders_of(hash);
            holders.len() == 2 && holders.iter().any(|holder| *holder != name && !game.is_champion(holder))
        };
        let (name, changed) = changed_textures(&game, &game_dir, shared);

        let (_overlay, events) = build_changed(&game_dir, &name, &changed);

        // Each chunk is in one other WAD, so the counts of the notes add up to the chunks.
        let said = logged(&events);
        let counted: usize = said
            .iter()
            .map(|note| note.split_once(": ").and_then(|(_, rest)| rest.split(' ').next()).unwrap().parse::<usize>().unwrap())
            .sum();
        eprintln!("{said:#?}");
        assert_eq!(counted, changed.len(), "{said:?}");
        assert!(said.iter().all(|note| note.contains(".wad.client, which the overlay does not carry")), "{said:?}");
    }

    #[test]
    fn only_champion_wads_directly_in_the_champions_folder_pass() {
        let install = Install::new();
        let zed = [(ZED_TEXTURE, b"DDS zed as the game has it".as_slice())];
        for (relative, what) in [
            (GLOBAL, "not directly in DATA/FINAL/Champions"),
            ("DATA/FINAL/Champions/Sub/Zed.wad.client", "not directly in DATA/FINAL/Champions"),
            ("DATA/FINAL/Champions/Nobody.wad.client", "not a champion WAD of the game"),
        ] {
            let problems = audited(&install, &[(relative, &zed)], &[]).err().unwrap();
            assert!(problems.iter().any(|problem| problem.contains(what)), "{relative}: {problems:?}");
            fs::remove_dir_all(install.overlay()).unwrap();
        }
    }
}
