//! Checks the files of a pack against the rule set in `riftengine-rules`.
//!
//! The host runs this on every pack before an overlay is built, and builds from the very bytes it
//! checked. The checks look at what the files contain, never at what a pack's metadata claims.
//!
//! What this is, and is not: a starter set of structural checks, grounded in the BIN files of the
//! installed game. It refuses the patterns it knows. It cannot prove a pack harmless, and it does
//! not look inside textures, meshes or audio. See `engine/README.md` for the coverage and its gaps.
//!
//! BIN files are parsed with the streaming reader of `ltk_meta`, which holds one object at a time
//! and builds no tree. Packs come from the internet, so the reader is fenced in: counts in the
//! header and the table of objects are checked against the file size before the parser sizes any
//! table from them, files over [`MAX_BIN_BYTES`] and objects over [`MAX_OBJECT_BYTES`] are refused,
//! and the scan runs on its own thread with a stack large enough for the deepest nesting such an
//! object can hold, under a time limit.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::io::Cursor;
use std::ops::Range;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use ltk_hash::BinHash;
use ltk_meta::walk::{ChildSegment, Leaf, Node, RawValue, TreeValue, Visit, Visitor};
use ltk_meta::{BinStream, Error as BinError};
use riftengine_rules::{clause_of, id};
use xxhash_rust::xxh64::xxh64;

/// BIN files bigger than this are refused rather than parsed. The biggest BIN of the installed
/// game was 3.9 MB when this was measured (see the real-game test), so this is about twice that.
pub const MAX_BIN_BYTES: usize = 8 * 1024 * 1024;
/// One object of a BIN may declare at most this many bytes. The parser recurses once per nesting
/// level inside an object, and nothing nests in fewer than 15 bytes a level, so this is what
/// bounds the depth the scan has to survive, whatever the size of the file around it. The biggest
/// object of the installed game was 0.5 MB, and none nests deeper than 13 levels.
pub const MAX_OBJECT_BYTES: usize = 1024 * 1024;
/// Deepest property nesting (counted in path segments) the scan follows before it gives up.
pub const MAX_DEPTH: usize = 96;
/// Violations kept per report; a pack that breaks this many rules is refused either way.
const MAX_VIOLATIONS: usize = 200;
/// Findings of one kind reported per BIN, so one file cannot fill the report.
const MAX_PER_BIN: usize = 8;
/// Stack of the scan thread, for the most deeply nested object [`MAX_OBJECT_BYTES`] can hold. The
/// nesting test runs that worst case, in every shape it can take, and the debug profile, which
/// has the largest frames, is the tightest fit. Only address space is reserved; pages are
/// committed as they are touched.
const SCAN_STACK_BYTES: usize = 512 * 1024 * 1024;
/// How long one BIN may take to check.
const SCAN_TIME_LIMIT: Duration = Duration::from_secs(30);

/// File kinds that can only change how the game looks or sounds.
const COSMETIC_EXTENSIONS: &[&str] = &[
    "bin", "dds", "tex", "skn", "skl", "anm", "scb", "sco", "bnk", "wpk", "png", "jpg", "jpeg", "tga", "ogg",
    "wav",
];

const SKIN_CLASS: &str = "SkinCharacterDataProperties";
const SKIN_NAME_FIELD: &str = "championSkinName";
const SKIN_CLASS_HASH: u32 = name_hash(SKIN_CLASS);
const SKIN_NAME_HASH: u32 = name_hash(SKIN_NAME_FIELD);

/// Classes that define what a character or spell does. Names as the game's BIN files use them.
const GAMEPLAY_CLASSES: [(u32, &str); 4] = [
    (name_hash("CharacterRecord"), "CharacterRecord"),
    (name_hash("SpellObject"), "SpellObject"),
    (name_hash("SpellDataResource"), "SpellDataResource"),
    (name_hash("AttackSlotData"), "AttackSlotData"),
];

/// BIN class and field names are hashed with FNV-1a over the lower-cased text.
pub const fn name_hash(text: &str) -> u32 {
    let bytes = text.as_bytes();
    let mut hash = 0x811c_9dc5_u32;
    let mut at = 0;
    while at < bytes.len() {
        hash ^= bytes[at].to_ascii_lowercase() as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        at += 1;
    }
    hash
}

/// WAD chunk paths are hashed with XXH64 over the lower-cased path.
pub fn path_hash(path: &str) -> u64 {
    xxh64(path.to_ascii_lowercase().as_bytes(), 0)
}

/// Most WADs that may hold one chunk before the validator stops comparing and applies the strict
/// pattern instead. A chunk that is in that many WADs is not one a champion skin has any business
/// replacing.
const MAX_HOLDERS: usize = 16;

/// Where the validator reads the game's own files from, for the checks that compare a pack with
/// the game.
pub trait GameFiles {
    /// Every WAD of the install that holds the chunk with `path_hash`, as lower-case file names
    /// such as `ahri.wad.client`. The overlay builder writes a replaced chunk into each of them, so
    /// a pack file is held to all of them. `None` when that cannot be said.
    fn holders(&mut self, path_hash: u64) -> Option<Vec<String>>;

    /// The game's own copy of a file, decompressed: the chunk with `path_hash` in the WAD called
    /// `wad` (one of the names [`holders`](Self::holders) gives).
    fn file(&mut self, wad: &str, path_hash: u64) -> Option<Vec<u8>>;
}

/// What the game's own base skin of a champion already says. A pack's base skin may keep it.
struct Baseline {
    /// Lower-cased `championSkinName` values.
    names: Vec<String>,
    /// Other-skin references, in the form [`normalise`] gives them.
    others: BTreeSet<String>,
}

impl Baseline {
    fn of(facts: &BinFacts) -> Self {
        Self {
            names: facts.skin_names.iter().map(|name| name.to_ascii_lowercase()).collect(),
            others: facts.other_skins.keys().map(|text| normalise(text)).collect(),
        }
    }
}

/// One file of a pack, as the host reads it out of the pack.
pub struct Entry<'a> {
    /// The WAD the pack puts the file in (`Ahri.wad.client`), or `None` for a `RAW/` entry.
    pub wad: Option<&'a str>,
    /// Path inside the WAD with forward slashes, or `<16 hex digits>[.ext]` when the pack is a
    /// packed WAD whose original paths are lost.
    pub name: &'a str,
    pub bytes: &'a [u8],
    /// The chunk path hash the overlay builder files this entry under, as the builder worked it
    /// out. `None` takes the hash from the name by this crate's own reading of it.
    filed_under: Option<u64>,
}

impl<'a> Entry<'a> {
    pub fn new(wad: Option<&'a str>, name: &'a str, bytes: &'a [u8]) -> Self {
        Self { wad, name, bytes, filed_under: None }
    }

    /// States the hash the overlay builder files this entry under. The validator works out the
    /// hash from the name too, and refuses an entry on which the two disagree: names that the
    /// builder reads differently from the validator (a `.ltk` marker, a hash-like file name in a
    /// folder) would otherwise let a file be checked as one thing and built as another.
    #[must_use]
    pub fn filed_under(mut self, hash: u64) -> Self {
        self.filed_under = Some(hash);
        self
    }
}

impl Entry<'_> {
    fn location(&self) -> String {
        match self.wad {
            Some(wad) => format!("{wad}/{}", self.name),
            None => format!("RAW/{}", self.name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub rule: &'static str,
    pub location: String,
    pub detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (clause {}) {}: {}", self.rule, clause_of(self.rule), self.location, self.detail)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Files looked at.
    pub entries: usize,
    /// Base skins (`skin0.bin`) among them.
    pub base_skins: usize,
    pub violations: Vec<Violation>,
    /// More violations were found than the report keeps.
    pub truncated: bool,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for violation in &self.violations {
            writeln!(f, "  {violation}")?;
        }
        if self.truncated {
            writeln!(f, "  ... and more")?;
        }
        write!(f, "  {} files checked, {} base skins, {} violations", self.entries, self.base_skins, self.violations.len())
    }
}

pub struct Validator {
    /// Lower-case file names of the champion WADs of the game install.
    wads: BTreeSet<String>,
    /// Lower-case champion folder names, taken from those file names.
    champions: BTreeSet<String>,
    /// Chunk path hash of each champion's `skin0.bin`, for packs that only carry hashes.
    skin0: HashMap<u64, String>,
    /// The game's own files, when the host can supply them.
    game: Option<Box<dyn GameFiles>>,
    /// What the game's own base skin says, per champion; `None` when it could not be read.
    baselines: HashMap<String, Option<Rc<Baseline>>>,
    report: Report,
}

impl Validator {
    /// `champion_wads` are the file names found in the game's `DATA/FINAL/Champions` folder.
    pub fn new<I, S>(champion_wads: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut wads = BTreeSet::new();
        let mut champions = BTreeSet::new();
        for wad in champion_wads {
            let lower = wad.as_ref().to_ascii_lowercase();
            if let Some(stem) = lower.strip_suffix(".wad.client") {
                // `Ahri.tr_TR` is Ahri's tr_TR voice WAD.
                let champion = stem.split('.').next().unwrap_or_default();
                if !champion.is_empty() {
                    champions.insert(champion.to_owned());
                }
            }
            wads.insert(lower);
        }
        let skin0 = champions
            .iter()
            .map(|champion| (path_hash(&format!("data/characters/{champion}/skins/skin0.bin")), champion.clone()))
            .collect();
        Self { wads, champions, skin0, game: None, baselines: HashMap::new(), report: Report::default() }
    }

    /// Lets the validator read the game's own files, so that a pack is held to "nothing the game
    /// does not already have" instead of to fixed patterns. The game's own files break the fixed
    /// patterns: its base skins use other skins' particle textures and names like `AmumuBase`,
    /// and a skin of Morgana carries `SpellObject`s. Without the game's files the fixed patterns
    /// apply, and refuse those.
    #[must_use]
    pub fn with_game_files(mut self, files: impl GameFiles + 'static) -> Self {
        self.game = Some(Box::new(files));
        self
    }

    fn baseline(&mut self, champion: &str) -> Option<Rc<Baseline>> {
        if let Some(known) = self.baselines.get(champion) {
            return known.clone();
        }
        let path = format!("data/characters/{champion}/skins/skin0.bin");
        let loaded = self
            .game
            .as_mut()
            .and_then(|game| game.file(&format!("{champion}.wad.client"), path_hash(&path)))
            .and_then(|bytes| read_bin(&bytes, Some(champion)).ok())
            .map(|facts| Rc::new(Baseline::of(&facts)));
        self.baselines.insert(champion.to_owned(), loaded.clone());
        loaded
    }

    /// Which WAD and chunk of the game a file of a pack would replace.
    fn game_key(&self, wad: Option<&str>, lower: &str, hash: u64) -> Option<(String, u64)> {
        let wad = match wad {
            Some(wad) => wad.to_ascii_lowercase(),
            None => format!("{}.wad.client", self.raw_champion(lower)?),
        };
        Some((wad, hash))
    }

    /// The game's own copies of the chunk `hash`, one for each WAD that holds it, with what the
    /// scan finds in each. The WAD the pack names has to be one of them: a file that would also
    /// land in a WAD that has no such chunk is a new file there. `None` when anything cannot be
    /// established, and the caller applies the strict pattern.
    fn game_copies(&mut self, declared: &str, hash: u64) -> Option<Vec<(Vec<u8>, BinFacts)>> {
        let game = self.game.as_mut()?;
        let holders = game.holders(hash)?;
        if holders.len() > MAX_HOLDERS || !holders.iter().any(|holder| holder == declared) {
            return None;
        }
        let mut copies: Vec<(Vec<u8>, BinFacts)> = Vec::with_capacity(holders.len());
        for holder in &holders {
            let bytes = game.file(holder, hash)?;
            // WADs usually hold byte-identical copies; one reading of those is enough.
            if copies.iter().any(|(held, _)| *held == bytes) {
                continue;
            }
            let facts = read_bin(&bytes, None).ok()?;
            copies.push((bytes, facts));
        }
        Some(copies)
    }

    /// Records a violation found outside the file checks (the host uses it for declarations).
    pub fn violation(&mut self, rule: &'static str, location: impl Into<String>, detail: impl Into<String>) {
        if self.report.violations.len() >= MAX_VIOLATIONS {
            self.report.truncated = true;
            return;
        }
        self.report.violations.push(Violation { rule, location: location.into(), detail: detail.into() });
    }

    pub fn finish(self) -> Report {
        self.report
    }

    pub fn check(&mut self, entry: &Entry<'_>) {
        self.report.entries += 1;
        let location = entry.location();

        if let Some(wad) = entry.wad {
            if let Some(problem) = wad_name_problem(wad) {
                self.violation(id::PATH, &location, problem);
            } else if !self.wads.contains(&wad.to_ascii_lowercase()) {
                self.violation(id::TARGET, &location, "not a champion WAD of this game install");
            }
        }
        if let Some(problem) = path_problem(entry.name) {
            // A name like that is not looked at any further.
            self.violation(id::PATH, &location, problem);
            return;
        }

        let lower = entry.name.to_ascii_lowercase();
        let hashed = hashed_name(&lower);
        let hash = hashed.unwrap_or_else(|| path_hash(&lower));
        if let Some(filed) = entry.filed_under
            && filed != hash
        {
            // Not looked at any further, like a name that is not safe.
            self.violation(
                id::PATH,
                &location,
                format!(
                    "the name says chunk {hash:016x}, but the overlay builder files it under {filed:016x} \
                     (a `.ltk` marker, or a hash-like file name inside a folder)"
                ),
            );
            return;
        }
        if entry.wad.is_none() && self.raw_champion(&lower).is_none() {
            self.violation(
                id::TARGET,
                &location,
                "RAW files must live under assets/characters/<champion>/ or data/characters/<champion>/",
            );
        }
        let extension = lower.rsplit_once('.').map(|(_, ext)| ext);
        if hashed.is_none() && !extension.is_some_and(|ext| COSMETIC_EXTENSIONS.contains(&ext)) {
            self.violation(
                id::FILE_KIND,
                &location,
                format!("`.{}` files are not an accepted cosmetic kind", extension.unwrap_or("")),
            );
        }

        match sniff(entry.bytes) {
            Content::Override => {
                self.violation(id::FILE_KIND, &location, "override (PTCH) BINs cannot be reviewed");
            }
            Content::Lua => self.violation(id::FILE_KIND, &location, "compiled Lua scripts are not cosmetic"),
            Content::Executable => self.violation(id::FILE_KIND, &location, "executable code is not cosmetic"),
            Content::Bin => {
                let skin0 = self.skin0.get(&hash).cloned();
                let game_key = self.game_key(entry.wad, &lower, hash);
                self.check_bin(&location, entry.bytes, skin0.as_deref(), game_key);
            }
            Content::Other => {
                if extension == Some("bin") {
                    self.violation(id::BIN_READABLE, &location, "named like a BIN but is not a PROP file");
                }
            }
        }
    }

    /// The champion whose folder a `RAW/` path is in, if it is in one of this install's.
    fn raw_champion<'a>(&self, lower: &'a str) -> Option<&'a str> {
        ["assets/characters/", "data/characters/"].iter().find_map(|prefix| {
            lower
                .strip_prefix(prefix)
                .and_then(|rest| rest.split('/').next())
                .filter(|champion| self.champions.contains(*champion))
        })
    }

    fn check_bin(&mut self, location: &str, bytes: &[u8], skin0: Option<&str>, game_key: Option<(String, u64)>) {
        let facts = match read_bin(bytes, skin0) {
            Ok(facts) => facts,
            Err(problem) => {
                self.violation(id::BIN_READABLE, location, problem);
                return;
            }
        };
        if facts.too_deep {
            self.violation(
                id::BIN_READABLE,
                location,
                format!("properties are nested deeper than {MAX_DEPTH} levels, too deep to check"),
            );
        }
        self.check_gameplay(location, bytes, &facts, game_key);

        let Some(champion) = skin0 else { return };
        self.report.base_skins += 1;
        let baseline = self.baseline(champion);
        let compared = if baseline.is_some() { ", which the game's own base skin does not" } else { "" };
        for name in &facts.skin_names {
            let lower = name.to_ascii_lowercase();
            let is_games = baseline.as_ref().is_some_and(|b| b.names.contains(&lower));
            if lower.len() > champion.len() && lower.starts_with(champion) && !is_games {
                self.violation(
                    id::BASE_NAME,
                    location,
                    format!("{SKIN_NAME_FIELD} is `{name}`, which is another skin of {champion}{compared}"),
                );
            }
        }
        // Every reference is compared with the game's, however many there are; only the report
        // is cut short.
        let new: Vec<_> = facts
            .other_skins
            .iter()
            .filter(|(text, _)| !baseline.as_ref().is_some_and(|b| b.others.contains(&normalise(text))))
            .collect();
        for (text, number) in new.iter().take(MAX_PER_BIN) {
            self.violation(
                id::BASE_ASSETS,
                location,
                format!("names skin {number} of {champion}: `{}`{compared}", shorten(text)),
            );
        }
        if new.len() > MAX_PER_BIN {
            self.violation(id::BASE_ASSETS, location, format!("and {} more like it", new.len() - MAX_PER_BIN));
        }
    }

    /// RR-GAMEPLAY-CLASS. A pack's BIN may hold the game's own gameplay objects as they are, and
    /// nothing else of that kind: an object that is new, changed, left out or rewritten is refused.
    /// "The game's own" means the copy of this very file in the game, compared object by object,
    /// byte for byte, in every WAD that holds the file (the overlay builder writes the pack's file
    /// into each of them); a BIN that replaces a file of the game is held to that, one that adds a
    /// file has no game copy and may hold no gameplay class at all. The same goes when the host
    /// gave no game files, a copy does not read, or the WAD the pack names does not hold the file.
    fn check_gameplay(&mut self, location: &str, bytes: &[u8], facts: &BinFacts, game_key: Option<(String, u64)>) {
        let copies = game_key.and_then(|(wad, hash)| self.game_copies(&wad, hash));
        let differences = copies.as_ref().and_then(|copies| {
            let mut all: Vec<String> = Vec::new();
            for (game_bytes, game_facts) in copies {
                for line in gameplay_differences((bytes, facts), (game_bytes, game_facts))? {
                    if !all.contains(&line) {
                        all.push(line);
                    }
                }
            }
            Some(all)
        });
        match differences {
            Some(differences) => {
                for difference in differences {
                    self.violation(id::GAMEPLAY_CLASS, location, difference);
                }
            }
            None => {
                for (hash, name) in GAMEPLAY_CLASSES {
                    if facts.gameplay.contains_key(&hash) {
                        self.violation(id::GAMEPLAY_CLASS, location, format!("defines `{name}` objects"));
                    }
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Content {
    Bin,
    Override,
    Lua,
    Executable,
    Other,
}

fn sniff(bytes: &[u8]) -> Content {
    if bytes.starts_with(b"PROP") {
        Content::Bin
    } else if bytes.starts_with(b"PTCH") {
        Content::Override
    } else if bytes.starts_with(b"\x1bLua") {
        Content::Lua
    } else if bytes.starts_with(b"MZ") || bytes.starts_with(b"\x7fELF") {
        Content::Executable
    } else {
        Content::Other
    }
}

/// What the scan of one BIN found.
#[derive(Debug, Default)]
struct BinFacts {
    /// For each gameplay class that appears, as an object or as a nested struct, the path hashes
    /// of the objects it is in.
    gameplay: BTreeMap<u32, BTreeSet<u32>>,
    /// The `championSkinName` of every skin data object (base skins only).
    skin_names: Vec<String>,
    /// Strings and links that name another skin of the champion, each with that skin's number
    /// (base skins only). Not capped: they are all compared with the game's own.
    other_skins: BTreeMap<String, u32>,
    /// Some node sat deeper than [`MAX_DEPTH`] and was not looked at.
    too_deep: bool,
    /// Deepest node seen, in path segments.
    deepest: usize,
}

impl BinFacts {
    fn note_text(&mut self, champion: &str, text: &str) {
        if self.other_skins.contains_key(text) {
            return;
        }
        if let Some(number) = other_skin_reference(text, champion) {
            self.other_skins.insert(text.to_owned(), number);
        }
    }
}

/// Reads one BIN and reports what the rules care about. `champion` is set when the file is that
/// champion's base skin, which is the only file whose strings and links are looked at.
fn read_bin(bytes: &[u8], champion: Option<&str>) -> Result<BinFacts, String> {
    if bytes.len() > MAX_BIN_BYTES {
        return Err(format!("larger than {MAX_BIN_BYTES} bytes, too big to check"));
    }
    read_table(bytes)?;

    let owned = bytes.to_vec();
    let champion = champion.map(str::to_owned);
    let (send, receive) = mpsc::channel();
    thread::Builder::new()
        .name("riftengine-bin-scan".into())
        .stack_size(SCAN_STACK_BYTES)
        .spawn(move || {
            let outcome = catch_unwind(AssertUnwindSafe(|| scan_stream(&owned, champion.as_deref())));
            // The receiver is gone when the scan ran out of time; nobody is waiting any more.
            let _ = send.send(outcome);
        })
        .map_err(|error| format!("could not start the BIN scan: {error}"))?;
    match receive.recv_timeout(SCAN_TIME_LIMIT) {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("the BIN parser gave up on it".to_owned()),
        Err(_) => Err(format!("took longer than {} seconds to check", SCAN_TIME_LIMIT.as_secs())),
    }
}

/// One row of the table of objects of a BIN.
struct Row {
    path_hash: u32,
    class_hash: u32,
    /// The object's bytes in the file, from its size field to its last byte.
    range: Range<usize>,
}

/// Walks the header and steps from object to object by their declared sizes, without looking
/// inside any of them. The parser sizes its tables from the counts in here before it reads the
/// bytes they describe, so a garbled or hostile header could otherwise ask it for tens of
/// gigabytes. No object may be larger than [`MAX_OBJECT_BYTES`], which is what bounds how deeply
/// anything can nest, because the parser stays inside an object's declared bytes.
///
/// Hands each object's row to `each`, in file order.
fn walk_table(bytes: &[u8], mut each: impl FnMut(Row)) -> Result<(), String> {
    const SHORT: &str = "does not parse: the header is cut short";
    let u32_at = |at: usize| {
        bytes.get(at..at + 4).map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    };
    let version = u32_at(4).ok_or(SHORT)?;
    if !(1..=3).contains(&version) {
        return Err(format!("does not parse: BIN version {version} is not supported"));
    }
    let mut at = 8;
    if version >= 2 {
        let links = u32_at(at).ok_or(SHORT)?;
        at += 4;
        // Every linked file is at least its two length bytes, so this stops within the file.
        for _ in 0..links {
            let length = bytes.get(at..at + 2).map(|raw| usize::from(u16::from_le_bytes([raw[0], raw[1]])));
            at += 2 + length.ok_or("does not parse: the list of linked files runs past the end")?;
            if at > bytes.len() {
                return Err("does not parse: the list of linked files runs past the end".to_owned());
            }
        }
    }
    let objects = u32_at(at).ok_or(SHORT)? as usize;
    at += 4;
    // Each object has a class hash in the table and at least ten bytes of its own.
    if objects > (bytes.len() - at) / 14 {
        return Err("does not parse: the object count is larger than the file can hold".to_owned());
    }
    // The class hashes, then the objects one after the other, each led by its own size.
    let classes = at;
    at += objects * 4;
    for index in 0..objects {
        let size = u32_at(at).ok_or("does not parse: the table of objects is cut short")? as usize;
        if size > MAX_OBJECT_BYTES {
            return Err(format!("an object declares {size} bytes, over the {MAX_OBJECT_BYTES} limit, too big to check"));
        }
        let end = at
            .checked_add(4 + size)
            .filter(|end| *end <= bytes.len())
            .ok_or("does not parse: an object runs past the end of the file")?;
        // An object opens with its path hash and the number of its properties.
        let path_hash = u32_at(at + 4).filter(|_| size >= 6).ok_or("does not parse: an object is too short")?;
        let class_hash = u32_at(classes + index * 4).ok_or(SHORT)?;
        each(Row { path_hash, class_hash, range: at..end });
        at = end;
    }
    Ok(())
}

/// [`walk_table`] for its checks alone. Returns the declared size of the biggest object.
fn read_table(bytes: &[u8]) -> Result<usize, String> {
    let mut largest = 0;
    walk_table(bytes, |row| largest = largest.max(row.range.len() - 4))?;
    Ok(largest)
}

/// The rows of the objects with the path hashes in `wanted`, kept by path hash: a hostile file
/// may hold several objects under one.
fn rows_of(bytes: &[u8], wanted: &BTreeSet<u32>) -> Option<BTreeMap<u32, Vec<Row>>> {
    let mut rows: BTreeMap<u32, Vec<Row>> = BTreeMap::new();
    walk_table(bytes, |row| {
        if wanted.contains(&row.path_hash) {
            rows.entry(row.path_hash).or_default().push(row);
        }
    })
    .ok()?;
    Some(rows)
}

/// What a pack's BIN does to the gameplay objects of the game's copy of the same file, one line
/// for each class: objects the pack has that the game's copy does not have as they are, and
/// objects of the game's copy that the pack leaves out or rewrites. Objects are compared by path
/// hash, then class and bytes, so their order in the file does not matter. Nothing comes back
/// when the pack changes none of them.
///
/// `None` when the two cannot be compared, because a table does not read.
fn gameplay_differences(pack: (&[u8], &BinFacts), game: (&[u8], &BinFacts)) -> Option<Vec<String>> {
    let ((pack_bytes, pack_facts), (game_bytes, game_facts)) = (pack, game);
    let flagged = |facts: &BinFacts| facts.gameplay.values().flatten().copied().collect::<BTreeSet<u32>>();
    let (pack_flagged, game_flagged) = (flagged(pack_facts), flagged(game_facts));
    let wanted: BTreeSet<u32> = pack_flagged.union(&game_flagged).copied().collect();
    if wanted.is_empty() {
        return Some(Vec::new());
    }
    let (ours, theirs) = (rows_of(pack_bytes, &wanted)?, rows_of(game_bytes, &wanted)?);
    // The game's own: it has the object once, and every object of the pack under that path hash
    // is that one, class and bytes.
    let unchanged = |hash: &u32| match (ours.get(hash), theirs.get(hash).map(Vec::as_slice)) {
        (Some(mine), Some([game])) => mine.iter().all(|row| {
            row.class_hash == game.class_hash && pack_bytes[row.range.clone()] == game_bytes[game.range.clone()]
        }),
        _ => false,
    };
    let count = |hashes: Option<&BTreeSet<u32>>, counted: &dyn Fn(&u32) -> bool| {
        hashes.map_or(0, |hashes| hashes.iter().filter(|hash| counted(hash)).count())
    };
    let objects = |n: usize| if n == 1 { "1 object".to_owned() } else { format!("{n} objects") };

    let mut lines = Vec::new();
    for (hash, name) in GAMEPLAY_CLASSES {
        let new_or_changed = count(pack_facts.gameplay.get(&hash), &|object| !unchanged(object));
        if new_or_changed > 0 {
            lines.push(format!("defines `{name}` in {} that differ from the game's own file", objects(new_or_changed)));
        }
        // Objects the pack still has as gameplay objects were counted above.
        let gone = count(game_facts.gameplay.get(&hash), &|object| !unchanged(object) && !pack_flagged.contains(object));
        if gone > 0 {
            lines.push(format!("leaves out or rewrites {} of the game's own file that define `{name}`", objects(gone)));
        }
    }
    Some(lines)
}

fn scan_stream(bytes: &[u8], champion: Option<&str>) -> Result<BinFacts, String> {
    let unreadable = |error: BinError| format!("does not parse: {error}");
    let mut stream = BinStream::mount(Cursor::new(bytes)).map_err(unreadable)?;
    let mut facts = BinFacts::default();
    if let Some(champion) = champion {
        for link in stream.dependencies() {
            facts.note_text(champion, link);
        }
    }
    let mut visitor = Collect { facts: &mut facts, champion };
    stream.walk::<BinError, _>(&mut visitor).map_err(unreadable)?;
    Ok(facts)
}

struct Collect<'f, 'c> {
    facts: &'f mut BinFacts,
    champion: Option<&'c str>,
}

impl<'a> Visitor<'a, RawValue<'a>> for Collect<'_, '_> {
    type Error = BinError;

    fn enter_node(&mut self, node: &Node<'_, 'a, RawValue<'a>>) -> Result<Visit, BinError> {
        let depth = node.trail().len();
        self.facts.deepest = self.facts.deepest.max(depth);
        if depth > MAX_DEPTH {
            self.facts.too_deep = true;
            return Ok(Visit::Skip);
        }
        let class = node.class_hash().0;
        if GAMEPLAY_CLASSES.iter().any(|(hash, _)| *hash == class) {
            self.facts.gameplay.entry(class).or_default().insert(node.object_hash().0);
        }
        Ok(Visit::Continue)
    }

    fn enter_property(
        &mut self,
        field: BinHash,
        value: RawValue<'a>,
        node: &Node<'_, 'a, RawValue<'a>>,
    ) -> Result<Visit, BinError> {
        let Some(champion) = self.champion else { return Ok(Visit::Continue) };
        match value.as_leaf()? {
            Some(Leaf::String(text)) => {
                if field.0 == SKIN_NAME_HASH && node.class_hash().0 == SKIN_CLASS_HASH {
                    self.facts.skin_names.push(text.to_owned());
                }
                self.facts.note_text(champion, text);
            }
            Some(_) => {}
            None => {
                // A list, optional or map. Nodes inside are visited by the walk itself; the
                // strings among them are looked at here.
                for child in value.children()? {
                    let (segment, item) = child?;
                    if let ChildSegment::Key(key) = segment
                        && let Some(Leaf::String(text)) = key.as_leaf()?
                    {
                        self.facts.note_text(champion, text);
                    }
                    if let Some(Leaf::String(text)) = item.as_leaf()? {
                        self.facts.note_text(champion, text);
                    }
                }
            }
        }
        Ok(Visit::Continue)
    }
}

/// The number of another skin of `champion` that `text` names, if it names one.
///
/// The base skin keeps its assets in `Skins/Base` (or `Skins/Skin0`) and its animations in
/// `Animations/Skin0.bin`. Any other `SkinN` folder is a different skin's content.
fn other_skin_reference(text: &str, champion: &str) -> Option<u32> {
    let text = normalise(text);
    for folder in ["skins/skin", "animations/skin"] {
        let needle = format!("characters/{champion}/{folder}");
        let mut from = 0;
        while let Some(at) = text[from..].find(&needle) {
            let start = from + at + needle.len();
            let digits: String = text[start..].chars().take_while(char::is_ascii_digit).collect();
            match digits.parse::<u32>() {
                Ok(0) => {}
                Ok(number) => return Some(number),
                Err(_) if !digits.is_empty() => return Some(u32::MAX),
                Err(_) => {}
            }
            from = start;
        }
    }
    None
}

/// The form in which paths are compared: lower case, forward slashes.
fn normalise(text: &str) -> String {
    text.to_ascii_lowercase().replace('\\', "/")
}

/// `<16 hex digits>` with an optional extension: a chunk whose path the pack lost.
fn hashed_name(lower: &str) -> Option<u64> {
    if lower.contains('/') {
        return None;
    }
    let stem = lower.split('.').next()?;
    if stem.len() == 16 && stem.bytes().all(|b| b.is_ascii_hexdigit()) {
        u64::from_str_radix(stem, 16).ok()
    } else {
        None
    }
}

fn wad_name_problem(wad: &str) -> Option<&'static str> {
    let plain = wad.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b' '));
    if wad.is_empty() || !plain || !wad.to_ascii_lowercase().ends_with(".wad.client") || wad.starts_with('.') {
        Some("not a plain `<name>.wad.client` file name")
    } else {
        None
    }
}

fn path_problem(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        return Some("empty name");
    }
    if name.starts_with('/') {
        return Some("absolute path");
    }
    if name.contains('\\') {
        return Some("backslash in path");
    }
    if name.contains(':') {
        return Some("drive or stream marker in path");
    }
    if name.chars().any(char::is_control) {
        return Some("control character in path");
    }
    if name.split('/').any(|part| part.is_empty() || part == "." || part == "..") {
        return Some("empty, `.` or `..` path component");
    }
    None
}

fn shorten(text: &str) -> String {
    const LIMIT: usize = 120;
    if text.chars().count() <= LIMIT {
        text.to_owned()
    } else {
        let head: String = text.chars().take(LIMIT).collect();
        format!("{head}...")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Cursor;

    use ltk_hash::{BinHash, Hash as _, WadHash};
    use ltk_meta::property::values;
    use ltk_meta::{Bin, BinObject};
    use riftengine_rules::{RULES, id};

    use super::*;

    const WADS: &[&str] = &["Ahri.wad.client", "Ahri.tr_TR.wad.client", "Zed.wad.client"];

    fn validator() -> Validator {
        Validator::new(WADS)
    }

    fn bytes_of(bin: &Bin) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        bin.to_writer(&mut out).expect("serialise");
        out.into_inner()
    }

    /// A base skin the way the game ships it, with the given name, assets and linked BINs.
    fn skin_bin(skin_name: &str, assets: &[&str], dependencies: &[&str]) -> Vec<u8> {
        let mut mesh =
            values::Struct { class_hash: BinHash::hash_str("SkinMeshDataProperties"), properties: Default::default() };
        for (index, asset) in assets.iter().enumerate() {
            mesh.properties.insert(BinHash(0x1000 + index as u32), values::String::from(*asset).into());
        }
        let skin = BinObject::builder(0x2a5d_eb8f_u32, BinHash::hash_str(SKIN_CLASS))
            .property(BinHash::hash_str(SKIN_NAME_FIELD), values::String::from(skin_name))
            .property(BinHash::hash_str("skinMeshProperties"), mesh)
            .build();
        let mut builder = Bin::builder().object(skin);
        for dependency in dependencies {
            builder = builder.dependency(*dependency);
        }
        bytes_of(&builder.build())
    }

    fn class_bin(class: &str) -> Vec<u8> {
        let object = BinObject::builder(0x1_u32, BinHash::hash_str(class)).build();
        bytes_of(&Bin::builder().object(object).build())
    }

    fn rules_of(report: &Report) -> BTreeSet<&'static str> {
        report.violations.iter().map(|v| v.rule).collect()
    }

    fn check(wad: Option<&str>, name: &str, bytes: &[u8]) -> Report {
        let mut v = validator();
        v.check(&Entry::new(wad, name, bytes));
        v.finish()
    }

    const BASE: &str = "data/characters/ahri/skins/skin0.bin";

    #[test]
    fn hashes_match_the_game_and_the_toolkit() {
        // Class hashes read out of the installed game's Ahri BINs.
        assert_eq!(SKIN_CLASS_HASH, 0x9b67_e9f6);
        assert_eq!(name_hash("CharacterRecord"), 0x23ea_1915);
        assert_eq!(name_hash("SpellObject"), 0x5e7e_5a06);
        for (hash, name) in GAMEPLAY_CLASSES {
            assert_eq!(hash, BinHash::hash_str(name).0, "{name}");
        }
        assert_eq!(SKIN_CLASS_HASH, BinHash::hash_str(SKIN_CLASS).0);
        assert_eq!(SKIN_NAME_HASH, BinHash::hash_str(SKIN_NAME_FIELD).0);
        assert_eq!(path_hash(BASE), WadHash::hash_str(BASE).0);
        assert_eq!(path_hash("Data/Characters/AHRI/Skins/Skin0.BIN"), WadHash::hash_str(BASE).0);
    }

    #[test]
    fn a_plain_cosmetic_pack_is_clean() {
        let mut v = validator();
        let base = skin_bin("Ahri", &["ASSETS/Characters/Ahri/Skins/Base/Ahri_Base.skn"], &[
            "DATA/Characters/Ahri/Ahri.bin",
            "DATA/Characters/Ahri/Animations/Skin0.bin",
        ]);
        v.check(&Entry::new(Some("Ahri.wad.client"), BASE, &base));
        v.check(&Entry::new(
            Some("Ahri.wad.client"),
            "assets/characters/ahri/skins/base/ahri_base_tx_cm.dds",
            b"DDS whatever",
        ));
        v.check(&Entry::new(Some("Ahri.tr_TR.wad.client"), "assets/sounds/ahri_vo.wpk", b"r3d2"));
        let report = v.finish();
        assert!(report.is_clean(), "{report}");
        assert_eq!((report.entries, report.base_skins), (3, 1));
    }

    #[test]
    fn unsafe_names_are_refused_and_not_read_further() {
        for name in ["/etc/x.dds", "..\\x.dds", "a/../b.dds", "a//b.dds", "c:/x.dds", "a/b\u{1}.dds", ""] {
            let report = check(Some("Ahri.wad.client"), name, b"x");
            assert_eq!(rules_of(&report), BTreeSet::from([id::PATH]), "{name:?}");
        }
        for wad in ["..\\Ahri.wad.client", "sub/Ahri.wad.client", "Ahri.exe", ".wad.client"] {
            assert!(rules_of(&check(Some(wad), "a.dds", b"x")).contains(id::PATH), "{wad:?}");
        }
    }

    #[test]
    fn only_champion_wads_are_targets() {
        assert_eq!(rules_of(&check(Some("Map11.wad.client"), "a.dds", b"x")), BTreeSet::from([id::TARGET]));
        assert_eq!(rules_of(&check(Some("Common.wad.client"), "a.dds", b"x")), BTreeSet::from([id::TARGET]));
        // The match is on the file name, not on case.
        assert!(check(Some("ZED.WAD.CLIENT"), "a.dds", b"x").is_clean());
    }

    #[test]
    fn raw_files_must_name_a_champion_folder() {
        assert!(check(None, "assets/characters/ahri/skins/base/a.dds", b"x").is_clean());
        assert!(check(None, "data/characters/zed/zed.dds", b"x").is_clean());
        for name in ["assets/maps/map11/scene.dds", "assets/characters/nobody/a.dds", "a.dds"] {
            assert_eq!(rules_of(&check(None, name, b"x")), BTreeSet::from([id::TARGET]), "{name}");
        }
    }

    #[test]
    fn only_cosmetic_kinds_are_accepted() {
        for name in ["a.exe", "a.dll", "a.lua", "a.luaobj", "a.txt", "a.mapgeo", "noext"] {
            let report = check(Some("Ahri.wad.client"), name, b"x");
            assert_eq!(rules_of(&report), BTreeSet::from([id::FILE_KIND]), "{name}");
        }
        for (label, bytes) in [("PTCH", &b"PTCH\0\0\0\0"[..]), ("Lua", b"\x1bLuaQ"), ("MZ", b"MZ\x90"), ("ELF", b"\x7fELF")] {
            let report = check(Some("Ahri.wad.client"), "a.dds", bytes);
            assert_eq!(rules_of(&report), BTreeSet::from([id::FILE_KIND]), "{label}");
        }
        // A hashed chunk has no extension to judge, so only its content counts.
        assert!(check(Some("Ahri.wad.client"), "0123456789abcdef", b"whatever").is_clean());
        assert_eq!(
            rules_of(&check(Some("Ahri.wad.client"), "0123456789abcdef.bin", b"PTCH....")),
            BTreeSet::from([id::FILE_KIND])
        );
    }

    #[test]
    fn a_bin_that_cannot_be_read_is_refused() {
        let report = check(Some("Ahri.wad.client"), "data/x.bin", b"not a bin");
        assert_eq!(rules_of(&report), BTreeSet::from([id::BIN_READABLE]));
        // Counts read out of garbage used to ask the parser for 39 GB, which aborted the process.
        let report = check(Some("Ahri.wad.client"), "data/x.bin", b"PROP\x03\0\0\0garbage");
        assert_eq!(rules_of(&report), BTreeSet::from([id::BIN_READABLE]));
        let report = check(Some("Ahri.wad.client"), "data/x.bin", b"PROP\x09\0\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(rules_of(&report), BTreeSet::from([id::BIN_READABLE]));
    }

    #[test]
    fn counts_that_cannot_fit_the_file_are_refused_before_anything_is_reserved() {
        let header = |version: u32, links: u32, objects: u32| {
            let mut out = b"PROP".to_vec();
            out.extend(version.to_le_bytes());
            if version >= 2 {
                out.extend(links.to_le_bytes());
            }
            out.extend(objects.to_le_bytes());
            out
        };
        for (what, bytes) in [
            ("links", header(3, u32::MAX, 0)),
            ("objects", header(3, 0, u32::MAX)),
            ("objects in a version 1 file", header(1, 0, u32::MAX)),
            ("objects, just over", header(3, 0, 1)),
        ] {
            let problem = read_bin(&bytes, None).expect_err(what);
            assert!(problem.starts_with("does not parse"), "{what}: {problem}");
        }
    }

    #[test]
    fn counts_inside_a_body_that_cannot_fit_do_not_abort() {
        // One object holding a list of 4 billion bytes, in a region that is a few bytes long.
        let mut list = vec![3u8]; // item kind: u8
        list.extend(8u32.to_le_bytes()); // size of the region
        list.extend(u32::MAX.to_le_bytes()); // item count
        list.extend([0u8; 4]);
        let bytes = raw_bin(&property(128, &list), 1);
        let problem = read_bin(&bytes, None).expect_err("a list that cannot fit");
        assert!(problem.starts_with("does not parse"), "{problem}");
        // The same through the validator.
        let report = check(Some("Ahri.wad.client"), "data/x.bin", &bytes);
        assert_eq!(rules_of(&report), BTreeSet::from([id::BIN_READABLE]));
    }

    /// A one-object BIN (version 3, no links) whose object holds `props`.
    fn raw_bin(props: &[u8], count: u16) -> Vec<u8> {
        let mut out = b"PROP".to_vec();
        out.extend(3u32.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(1u32.to_le_bytes());
        out.extend(0x1234_u32.to_le_bytes());
        out.extend(((4 + 2 + props.len()) as u32).to_le_bytes());
        out.extend(0x42_u32.to_le_bytes());
        out.extend(count.to_le_bytes());
        out.extend(props);
        out
    }

    fn property(kind: u8, value: &[u8]) -> Vec<u8> {
        let mut out = 0x7_u32.to_le_bytes().to_vec();
        out.push(kind);
        out.extend(value);
        out
    }

    /// How a struct holds the next one in a nest: straight in a property, or through a container.
    #[derive(Clone, Copy, Debug)]
    enum Shape {
        Struct,
        Optional,
        List,
        Map,
    }

    impl Shape {
        const ALL: [Shape; 4] = [Shape::Struct, Shape::Optional, Shape::List, Shape::Map];

        /// Bytes a level takes: a struct header (10) and what holds the next struct.
        fn step(self) -> usize {
            10 + match self {
                Shape::Struct => 5,
                Shape::Optional => 7,
                Shape::List => 14,
                Shape::Map => 19,
            }
        }

        /// A property that holds a struct of `inner_len` bytes, up to where that struct starts.
        fn holder(self, out: &mut Vec<u8>, inner_len: usize) {
            const U32: u8 = 7;
            const LIST: u8 = 128;
            const STRUCT: u8 = 130;
            const OPTIONAL: u8 = 133;
            const MAP: u8 = 134;
            out.extend(0x7_u32.to_le_bytes()); // the property's name
            match self {
                Shape::Struct => out.push(STRUCT),
                Shape::Optional => out.extend([OPTIONAL, STRUCT, 1]),
                Shape::List => {
                    out.extend([LIST, STRUCT]);
                    out.extend((4 + inner_len as u32).to_le_bytes()); // size: the count and the item
                    out.extend(1u32.to_le_bytes());
                }
                Shape::Map => {
                    out.extend([MAP, U32, STRUCT]);
                    out.extend((8 + inner_len as u32).to_le_bytes()); // size: the count, a key and the value
                    out.extend(1u32.to_le_bytes());
                    out.extend(0u32.to_le_bytes());
                }
            }
        }
    }

    /// One property holding structs nested `depth` deep, each inside the last through `shape`. The
    /// property bytes of an object that is `depth * shape.step() + 10` bytes long.
    fn nested(depth: usize, shape: Shape) -> Vec<u8> {
        let step = shape.step();
        let mut out = Vec::with_capacity(depth * step + 32);
        shape.holder(&mut out, 10 + depth * step);
        for level in (1..=depth).rev() {
            out.extend(0x77_u32.to_le_bytes());
            out.extend(((10 + level * step - 8) as u32).to_le_bytes());
            out.extend(1u16.to_le_bytes());
            shape.holder(&mut out, 10 + (level - 1) * step);
        }
        out.extend(0x77_u32.to_le_bytes());
        out.extend(2u32.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out
    }

    /// The densest nesting the format allows, in each of the ways it allows it, filling an object
    /// to the limit. The parser recurses once per level, so this is the most stack a file can ask
    /// for. Measured with this test: about 4.8 KiB a level in the debug profile (the largest
    /// frames), about 0.4 KiB in release.
    #[test]
    fn the_deepest_nesting_an_object_can_hold_does_not_overflow_the_scan() {
        for shape in Shape::ALL {
            // The shape is a valid one: a moderate nest of it reads, and is noticed as deep.
            let moderate = raw_bin(&nested(MAX_DEPTH + 8, shape), 1);
            let facts = read_bin(&moderate, None).unwrap_or_else(|problem| panic!("{shape:?}: {problem}"));
            assert!(facts.too_deep, "{shape:?}");

            let depth = (MAX_OBJECT_BYTES - 64) / shape.step();
            let bytes = raw_bin(&nested(depth, shape), 1);
            let largest = read_table(&bytes).expect("an object at the limit is still accepted");
            assert!(largest > MAX_OBJECT_BYTES - 64, "{largest} bytes is not a worst case");
            let started = std::time::Instant::now();
            // Either answer is fine. What matters is that the process is still here to see it.
            match read_bin(&bytes, None) {
                Ok(facts) => assert!(facts.too_deep, "{} levels went unnoticed", facts.deepest),
                Err(problem) => assert!(problem.starts_with("does not parse"), "{shape:?}: {problem}"),
            }
            eprintln!("{depth} levels of {shape:?} took {:?}", started.elapsed());
        }
    }

    #[test]
    fn an_object_over_the_size_limit_is_refused() {
        let bytes = raw_bin(&vec![0u8; MAX_OBJECT_BYTES], 0);
        assert!(bytes.len() < MAX_BIN_BYTES);
        let report = check(Some("Ahri.wad.client"), "data/x.bin", &bytes);
        assert_eq!(rules_of(&report), BTreeSet::from([id::BIN_READABLE]));
        assert!(report.violations[0].detail.contains("too big"), "{report}");
        // Exactly at the limit is still checked.
        let bytes = raw_bin(&vec![0u8; MAX_OBJECT_BYTES - 6], 0);
        assert_eq!(read_table(&bytes), Ok(MAX_OBJECT_BYTES));
    }

    #[test]
    fn a_table_of_objects_that_runs_past_the_file_is_refused() {
        let whole = raw_bin(&property(7, &[0; 4]), 1);
        // The object declares its path hash, its count and one property of nine bytes.
        assert_eq!(read_table(&whole), Ok(4 + 2 + 9));
        for cut in 1..8 {
            let problem = read_table(&whole[..whole.len() - cut]).expect_err("cut");
            assert!(problem.starts_with("does not parse"), "{problem}");
        }
    }

    #[test]
    fn a_bin_over_the_size_limit_is_refused() {
        let mut bytes = b"PROP".to_vec();
        bytes.resize(MAX_BIN_BYTES + 1, 0);
        let report = check(Some("Ahri.wad.client"), "data/x.bin", &bytes);
        assert_eq!(rules_of(&report), BTreeSet::from([id::BIN_READABLE]));
        assert!(report.violations[0].detail.contains("too big"));
    }

    #[test]
    fn gameplay_classes_are_refused_wherever_they_sit() {
        for (_, class) in GAMEPLAY_CLASSES {
            let report = check(Some("Ahri.wad.client"), "data/characters/ahri/ahri.bin", &class_bin(class));
            assert_eq!(rules_of(&report), BTreeSet::from([id::GAMEPLAY_CLASS]), "{class}");
            assert!(report.violations[0].detail.contains(class));
        }
        // Nested inside another object's property.
        let inner = values::Struct { class_hash: BinHash::hash_str("SpellObject"), properties: Default::default() };
        let items: Vec<ltk_meta::PropertyValueEnum> = vec![values::Embedded(inner).into()];
        let outer = values::Container::try_from(items).expect("container");
        let object = BinObject::builder(0x1_u32, BinHash::hash_str("Whatever")).property(0x7_u32, outer).build();
        let bytes = bytes_of(&Bin::builder().object(object).build());
        let report = check(Some("Ahri.wad.client"), "data/x.bin", &bytes);
        assert_eq!(rules_of(&report), BTreeSet::from([id::GAMEPLAY_CLASS]));
        // Cosmetic classes are fine.
        let report = check(Some("Ahri.wad.client"), "data/x.bin", &class_bin("VfxSystemDefinitionData"));
        assert!(report.is_clean(), "{report}");
    }

    #[test]
    fn the_base_skin_may_not_take_another_skins_name() {
        let ok = skin_bin("Ahri", &[], &[]);
        assert!(check(Some("Ahri.wad.client"), BASE, &ok).is_clean());
        for name in ["AhriSkin22", "AhriFoxfire", "ahriskin1"] {
            let report = check(Some("Ahri.wad.client"), BASE, &skin_bin(name, &[], &[]));
            assert_eq!(rules_of(&report), BTreeSet::from([id::BASE_NAME]), "{name}");
        }
        // Only the base skin is held to it: skin22 is named after itself.
        let report = check(Some("Ahri.wad.client"), "data/characters/ahri/skins/skin22.bin", &skin_bin("AhriSkin22", &[], &[]));
        assert!(report.is_clean(), "{report}");
    }

    #[test]
    fn the_base_skin_may_not_name_another_skins_assets() {
        let own = ["ASSETS/Characters/Ahri/Skins/Base/Ahri_Base.skn", "assets/characters/ahri/skins/skin0/a.skl"];
        assert!(check(Some("Ahri.wad.client"), BASE, &skin_bin("Ahri", &own, &[])).is_clean());
        for theirs in [
            "ASSETS/Characters/Ahri/Skins/Skin17/Ahri_Skin17.skn",
            "assets\\characters\\ahri\\skins\\SKIN22\\a.skl",
        ] {
            let report = check(Some("Ahri.wad.client"), BASE, &skin_bin("Ahri", &[theirs], &[]));
            assert_eq!(rules_of(&report), BTreeSet::from([id::BASE_ASSETS]), "{theirs}");
        }
        // Another champion's folder is not "another skin of this champion".
        let report = check(Some("Ahri.wad.client"), BASE, &skin_bin("Ahri", &["assets/characters/zed/skins/skin3/z.skn"], &[]));
        assert!(report.is_clean(), "{report}");
    }

    #[test]
    fn the_base_skin_may_not_link_another_skins_data() {
        let report = check(
            Some("Ahri.wad.client"),
            BASE,
            &skin_bin("Ahri", &[], &["DATA/Characters/Ahri/Animations/Skin17.bin"]),
        );
        assert_eq!(rules_of(&report), BTreeSet::from([id::BASE_ASSETS]));
        let report = check(
            Some("Ahri.wad.client"),
            BASE,
            &skin_bin("Ahri", &[], &["DATA/Characters/Ahri/Skins/Skin22.bin"]),
        );
        assert_eq!(rules_of(&report), BTreeSet::from([id::BASE_ASSETS]));
    }

    #[test]
    fn strings_in_lists_and_maps_count_too() {
        let theirs = "assets/characters/ahri/skins/skin17/a.skn";
        let list: Vec<ltk_meta::PropertyValueEnum> = vec![values::String::from("fine").into(), values::String::from(theirs).into()];
        let list = values::Container::try_from(list).expect("list");
        let object = BinObject::builder(0x1_u32, BinHash::hash_str(SKIN_CLASS))
            .property(BinHash::hash_str(SKIN_NAME_FIELD), values::String::from("Ahri"))
            .property(0x9_u32, list)
            .build();
        let bytes = bytes_of(&Bin::builder().object(object).build());
        let report = check(Some("Ahri.wad.client"), BASE, &bytes);
        assert_eq!(rules_of(&report), BTreeSet::from([id::BASE_ASSETS]), "{report}");
    }

    /// The game's files as the validator asks for them: which WADs hold a chunk, and what each
    /// holds. It keeps a record of every read it is asked for.
    #[derive(Clone, Default)]
    struct FakeGame {
        /// Lower-case WAD file name, path hash, bytes.
        files: Vec<(String, u64, Vec<u8>)>,
        reads: std::rc::Rc<std::cell::RefCell<Vec<(String, u64)>>>,
    }

    impl FakeGame {
        /// The game's file at `path` in the WAD called `wad`, and nothing else.
        fn with(wad: &str, path: &str, bytes: Vec<u8>) -> Self {
            Self::default().and(wad, path_hash(path), bytes)
        }

        /// Another WAD that holds the chunk `hash`.
        fn and(mut self, wad: &str, hash: u64, bytes: Vec<u8>) -> Self {
            self.files.push((wad.to_owned(), hash, bytes));
            self
        }
    }

    impl GameFiles for FakeGame {
        fn holders(&mut self, hash: u64) -> Option<Vec<String>> {
            Some(self.files.iter().filter(|(_, held, _)| *held == hash).map(|(wad, _, _)| wad.clone()).collect())
        }

        fn file(&mut self, wad: &str, hash: u64) -> Option<Vec<u8>> {
            self.reads.borrow_mut().push((wad.to_owned(), hash));
            self.files
                .iter()
                .find(|(held_wad, held, _)| held_wad == wad && *held == hash)
                .map(|(_, _, bytes)| bytes.clone())
        }
    }

    /// Checks `pack` as Ahri's base skin, with `own` as the game's own Ahri base skin.
    fn check_against(own: &[u8], pack: &[u8]) -> Report {
        let mut v = validator().with_game_files(FakeGame::with("ahri.wad.client", BASE, own.to_vec()));
        v.check(&Entry::new(Some("Ahri.wad.client"), BASE, pack));
        v.finish()
    }

    const OWN_DEPENDENCIES: [&str; 1] = ["DATA/Characters/Ahri/Animations/Skin0.bin"];

    /// A base skin the way the game ships some: a name with a suffix, and particle textures that
    /// live in other skins' folders.
    fn games_own_base_skin(extra_assets: &[&str], extra_dependencies: &[&str]) -> Vec<u8> {
        let mut assets = vec![
            "assets/characters/ahri/skins/skin01/particles/a.tex",
            "ASSETS/Characters/Ahri/Skins/Skin07/Particles/b.tex",
        ];
        assets.extend(extra_assets);
        let mut dependencies = OWN_DEPENDENCIES.to_vec();
        dependencies.extend(extra_dependencies);
        skin_bin("AhriBase", &assets, &dependencies)
    }

    #[test]
    fn the_base_skin_may_keep_what_the_games_own_says() {
        let own = games_own_base_skin(&[], &[]);
        // The strict pattern knows nothing of the game and refuses the game's own file.
        let strict = check(Some("Ahri.wad.client"), BASE, &own);
        assert_eq!(rules_of(&strict), BTreeSet::from([id::BASE_NAME, id::BASE_ASSETS]));
        // Compared with the game's file, it is clean, and so is a pack that adds something of its own.
        assert!(check_against(&own, &own).is_clean());
        let recolour = games_own_base_skin(&["assets/characters/ahri/skins/base/new.tex"], &[]);
        assert!(check_against(&own, &recolour).is_clean());
    }

    #[test]
    fn anything_the_games_own_base_skin_does_not_say_is_refused() {
        let own = games_own_base_skin(&[], &[]);
        let renamed = skin_bin("AhriSkin22", &["assets/characters/ahri/skins/skin01/particles/a.tex"], &OWN_DEPENDENCIES);
        let report = check_against(&own, &renamed);
        assert_eq!(rules_of(&report), BTreeSet::from([id::BASE_NAME]), "{report}");
        assert!(report.violations[0].detail.contains("game's own base skin does not"));

        let report = check_against(&own, &games_own_base_skin(&["assets/characters/ahri/skins/skin17/particles/c.tex"], &[]));
        assert_eq!(rules_of(&report), BTreeSet::from([id::BASE_ASSETS]), "{report}");
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].detail.contains("skin 17"), "{report}");

        let report = check_against(&own, &games_own_base_skin(&[], &["DATA/Characters/Ahri/Animations/Skin17.bin"]));
        assert_eq!(rules_of(&report), BTreeSet::from([id::BASE_ASSETS]), "{report}");
        // The same texture under another spelling is the same texture; a different one is not.
        let report = check_against(&own, &games_own_base_skin(&["ASSETS\\CHARACTERS\\AHRI\\SKINS\\SKIN01\\PARTICLES\\A.TEX"], &[]));
        assert!(report.is_clean(), "{report}");
        let report = check_against(&own, &games_own_base_skin(&["assets/characters/ahri/skins/skin01/particles/other.tex"], &[]));
        assert_eq!(rules_of(&report), BTreeSet::from([id::BASE_ASSETS]), "{report}");
    }

    #[test]
    fn every_reference_is_compared_whatever_the_report_keeps() {
        // Twenty of the game's own references, then one more of the pack's: the pack is refused for
        // that one, even though the first twenty are more than a report lists.
        let many: Vec<String> = (0..20).map(|n| format!("assets/characters/ahri/skins/skin01/particles/p{n}.tex")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let own = games_own_base_skin(&many, &[]);
        assert!(check_against(&own, &own).is_clean());
        let mut more = many.clone();
        more.push("assets/characters/ahri/skins/skin22/particles/new.tex");
        let report = check_against(&own, &games_own_base_skin(&more, &[]));
        assert_eq!(report.violations.len(), 1, "{report}");
        assert!(report.violations[0].detail.contains("skin 22"));
        // A pack with far more than a report lists says so.
        let fresh: Vec<String> = (0..30).map(|n| format!("assets/characters/ahri/skins/skin22/particles/n{n}.tex")).collect();
        let fresh: Vec<&str> = fresh.iter().map(String::as_str).collect();
        let report = check_against(&own, &games_own_base_skin(&fresh, &[]));
        assert_eq!(report.violations.len(), MAX_PER_BIN + 1, "{report}");
        assert!(report.violations.last().unwrap().detail.contains("22 more"));
    }

    #[test]
    fn without_a_readable_game_file_the_strict_pattern_applies() {
        let own = games_own_base_skin(&[], &[]);
        for game in [FakeGame::default(), FakeGame::with("ahri.wad.client", BASE, b"not a bin".to_vec())] {
            let mut v = validator().with_game_files(game);
            v.check(&Entry::new(Some("Ahri.wad.client"), BASE, &own));
            assert_eq!(rules_of(&v.finish()), BTreeSet::from([id::BASE_NAME, id::BASE_ASSETS]));
        }
    }

    #[test]
    fn the_games_base_skin_is_worked_out_once_per_champion() {
        let own = games_own_base_skin(&[], &[]);
        let game = FakeGame::with("ahri.wad.client", BASE, own.clone());
        let reads = game.reads.clone();
        let mut v = validator().with_game_files(game);
        for _ in 0..3 {
            v.check(&Entry::new(Some("Ahri.wad.client"), BASE, &own));
        }
        assert!(v.finish().is_clean());
        // Once for the baseline of the champion, then once per file for the gameplay comparison.
        assert_eq!(reads.borrow().len(), 1 + 3);
    }

    const RECORD: &str = "data/characters/ahri/ahri.bin";

    /// A BIN of `SpellObject`s and of `VfxSystemDefinitionData`s, each given as a path hash and
    /// some text, so that two objects under one path hash can differ.
    fn spells_bin(spells: &[(u32, &str)], effects: &[(u32, &str)]) -> Vec<u8> {
        let mut builder = Bin::builder();
        for (class, objects) in [("SpellObject", spells), ("VfxSystemDefinitionData", effects)] {
            for (hash, text) in objects {
                builder = builder.object(
                    BinObject::builder(*hash, BinHash::hash_str(class))
                        .property(0x9_u32, values::String::from(*text))
                        .build(),
                );
            }
        }
        bytes_of(&builder.build())
    }

    /// Checks `pack` as Ahri's character record, with `own` as the game's own.
    fn check_record_against(own: &[u8], pack: &[u8]) -> Report {
        let mut v = validator().with_game_files(FakeGame::with("ahri.wad.client", RECORD, own.to_vec()));
        v.check(&Entry::new(Some("Ahri.wad.client"), RECORD, pack));
        v.finish()
    }

    /// A BIN made of whole objects as they sit in a file: the class hash and the bytes from the
    /// size field on, for each.
    fn bin_of_objects(objects: &[(u32, &[u8])]) -> Vec<u8> {
        let mut out = b"PROP".to_vec();
        out.extend(3u32.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend((objects.len() as u32).to_le_bytes());
        for (class, _) in objects {
            out.extend(class.to_le_bytes());
        }
        for (_, bytes) in objects {
            out.extend(*bytes);
        }
        out
    }

    /// The class hash and the bytes of the first object of a BIN.
    fn first_object(bin: &[u8]) -> (u32, Vec<u8>) {
        let mut first = None;
        walk_table(bin, |row| {
            first.get_or_insert((row.class_hash, bin[row.range.clone()].to_vec()));
        })
        .expect("a table that reads");
        first.expect("an object")
    }

    #[test]
    fn a_file_may_keep_the_gameplay_objects_the_game_has() {
        let own = spells_bin(&[(1, "q"), (2, "w")], &[(10, "glow")]);
        // Without the game's file, any gameplay class is refused.
        assert_eq!(rules_of(&check(Some("Ahri.wad.client"), RECORD, &own)), BTreeSet::from([id::GAMEPLAY_CLASS]));
        // Compared with it, the very same file is the game's own...
        let report = check_record_against(&own, &own);
        assert!(report.is_clean(), "{report}");
        // ...and so is one that only changes what is around the same spells, whatever their order.
        let reskin = spells_bin(&[(2, "w"), (1, "q")], &[(10, "other glow"), (11, "new glow")]);
        let report = check_record_against(&own, &reskin);
        assert!(report.is_clean(), "{report}");
    }

    #[test]
    fn a_gameplay_object_that_is_new_or_changed_is_refused() {
        let own = spells_bin(&[(1, "q"), (2, "w")], &[]);
        for (what, pack) in [
            ("changed", spells_bin(&[(1, "q"), (2, "w, but faster")], &[])),
            ("added", spells_bin(&[(1, "q"), (2, "w"), (3, "e")], &[])),
            ("under another path hash", spells_bin(&[(1, "q"), (4, "w")], &[])),
        ] {
            let report = check_record_against(&own, &pack);
            assert_eq!(rules_of(&report), BTreeSet::from([id::GAMEPLAY_CLASS]), "{what}");
            assert!(report.violations[0].detail.contains("differ from the game's own file"), "{what}: {report}");
        }
        let report = check_record_against(&own, &spells_bin(&[(1, "q"), (2, "w, but faster")], &[]));
        assert_eq!(report.violations.len(), 1, "{report}");
        assert!(report.violations[0].detail.contains("in 1 object that differ"), "{report}");
    }

    #[test]
    fn a_gameplay_object_that_is_left_out_or_rewritten_is_refused() {
        let own = spells_bin(&[(1, "q"), (2, "w")], &[]);
        for (what, pack) in [
            ("left out", spells_bin(&[(1, "q")], &[])),
            ("all of them left out", spells_bin(&[], &[(10, "glow")])),
            ("made into another class", spells_bin(&[(1, "q")], &[(2, "w")])),
        ] {
            let report = check_record_against(&own, &pack);
            assert_eq!(rules_of(&report), BTreeSet::from([id::GAMEPLAY_CLASS]), "{what}");
            assert!(report.violations[0].detail.contains("leaves out or rewrites"), "{what}: {report}");
        }
        // The game has none, the pack has none: nothing to compare.
        let cosmetic = spells_bin(&[], &[(10, "glow")]);
        assert!(check_record_against(&cosmetic, &spells_bin(&[], &[(10, "other glow")])).is_clean());
    }

    #[test]
    fn a_file_the_game_does_not_have_gets_no_leniency() {
        const NEW: &str = "data/characters/ahri/skins/skin99.bin";
        let pack = spells_bin(&[(1, "q")], &[]);
        for (what, game) in [
            ("nothing", FakeGame::default()),
            ("something that is not a BIN", FakeGame::with("ahri.wad.client", NEW, b"not a bin".to_vec())),
            ("a copy of some other file", FakeGame::with("ahri.wad.client", RECORD, pack.clone())),
            ("the file, but only in another WAD", FakeGame::with("zed.wad.client", NEW, pack.clone())),
        ] {
            let mut v = validator().with_game_files(game);
            v.check(&Entry::new(Some("Ahri.wad.client"), NEW, &pack));
            let report = v.finish();
            assert_eq!(rules_of(&report), BTreeSet::from([id::GAMEPLAY_CLASS]), "{what}: {report}");
            assert_eq!(report.violations[0].detail, "defines `SpellObject` objects", "{what}: {report}");
        }
    }

    #[test]
    fn a_file_is_held_to_every_wad_that_has_it() {
        let own = spells_bin(&[(1, "q")], &[]);
        let other = spells_bin(&[(1, "q, but slower")], &[]);
        let record = path_hash(RECORD);
        // The pack's file is the game's own in the WAD it names, and different from the game's in
        // another that the overlay builder writes it into as well.
        let game = FakeGame::with("ahri.wad.client", RECORD, own.clone()).and("zed.wad.client", record, other.clone());
        let mut v = validator().with_game_files(game);
        v.check(&Entry::new(Some("Ahri.wad.client"), RECORD, &own));
        let report = v.finish();
        assert_eq!(rules_of(&report), BTreeSet::from([id::GAMEPLAY_CLASS]), "{report}");
        assert!(report.violations[0].detail.contains("differ from the game's own file"), "{report}");
        // Copies that are the same everywhere are one comparison, and clean.
        let game = FakeGame::with("ahri.wad.client", RECORD, own.clone()).and("zed.wad.client", record, own.clone());
        let mut v = validator().with_game_files(game);
        v.check(&Entry::new(Some("Ahri.wad.client"), RECORD, &own));
        assert!(v.finish().is_clean());
        // A copy that does not read is a copy that cannot be compared.
        let game = FakeGame::with("ahri.wad.client", RECORD, own.clone()).and("zed.wad.client", record, b"not a bin".to_vec());
        let mut v = validator().with_game_files(game);
        v.check(&Entry::new(Some("Ahri.wad.client"), RECORD, &own));
        assert_eq!(rules_of(&v.finish()), BTreeSet::from([id::GAMEPLAY_CLASS]));
    }

    #[test]
    fn a_file_in_very_many_wads_gets_no_leniency() {
        let own = spells_bin(&[(1, "q")], &[]);
        let record = path_hash(RECORD);
        let mut game = FakeGame::with("ahri.wad.client", RECORD, own.clone());
        for n in 0..MAX_HOLDERS {
            game = game.and(&format!("w{n}.wad.client"), record, own.clone());
        }
        let mut v = validator().with_game_files(game);
        v.check(&Entry::new(Some("Ahri.wad.client"), RECORD, &own));
        let report = v.finish();
        assert_eq!(rules_of(&report), BTreeSet::from([id::GAMEPLAY_CLASS]), "{report}");
        assert_eq!(report.violations[0].detail, "defines `SpellObject` objects");
    }

    #[test]
    fn the_hash_the_builder_files_a_file_under_has_to_be_the_names() {
        let theirs = skin_bin("Ahri", &["assets/characters/ahri/skins/skin17/a.skn"], &[]);
        let base = path_hash(BASE);
        // The builder agrees with the name: the file is a base skin and is held to the base skin rules.
        let mut v = validator();
        v.check(&Entry::new(Some("Ahri.wad.client"), BASE, &theirs).filed_under(base));
        assert_eq!(rules_of(&v.finish()), BTreeSet::from([id::BASE_ASSETS]));
        // A `.ltk` marker, or a hash-like file name in a folder: the builder files these under the
        // base skin's hash while the name says something else, so the file is refused outright.
        for name in ["data/characters/ahri/skins/skin0.bin.ltk".to_owned(), format!("data/x/{base:016x}.bin")] {
            let mut v = validator();
            v.check(&Entry::new(Some("Ahri.wad.client"), &name, &theirs).filed_under(base));
            let report = v.finish();
            assert_eq!(rules_of(&report), BTreeSet::from([id::PATH]), "{name}: {report}");
            assert!(report.violations[0].detail.contains("overlay builder files it under"), "{name}: {report}");
        }
        // A packed WAD's entry is named by its hash, and the builder agrees.
        let hashed = format!("{base:016x}.bin");
        let mut v = validator();
        v.check(&Entry::new(Some("Ahri.wad.client"), &hashed, &theirs).filed_under(base));
        assert_eq!(rules_of(&v.finish()), BTreeSet::from([id::BASE_ASSETS]));
    }

    #[test]
    fn several_objects_under_one_path_hash_must_all_be_the_games() {
        let own = spells_bin(&[(1, "q")], &[]);
        let (class, object) = first_object(&own);
        let (_, faster) = first_object(&spells_bin(&[(1, "faster q")], &[]));

        let twice = bin_of_objects(&[(class, &object), (class, &object)]);
        let report = check_record_against(&own, &twice);
        assert!(report.is_clean(), "{report}");
        // One of them the game's and one not: the game could use either.
        let one_of_each = bin_of_objects(&[(class, &object), (class, &faster)]);
        let report = check_record_against(&own, &one_of_each);
        assert_eq!(rules_of(&report), BTreeSet::from([id::GAMEPLAY_CLASS]), "{report}");
        let report = check_record_against(&own, &bin_of_objects(&[(class, &faster), (class, &object)]));
        assert_eq!(rules_of(&report), BTreeSet::from([id::GAMEPLAY_CLASS]), "{report}");
        // An object the game itself has twice is not one that can be compared.
        let report = check_record_against(&twice, &twice);
        assert_eq!(rules_of(&report), BTreeSet::from([id::GAMEPLAY_CLASS]), "{report}");
    }

    #[test]
    fn a_pack_file_is_compared_with_the_game_file_it_replaces() {
        let own = spells_bin(&[(1, "q")], &[]);
        let record = path_hash(RECORD);
        let game = FakeGame::with("ahri.wad.client", RECORD, own.clone()).and("zed.wad.client", record, own.clone());
        let reads = game.reads.clone();
        let mut v = validator().with_game_files(game);
        v.check(&Entry::new(Some("Ahri.wad.client"), RECORD, &own));
        v.check(&Entry::new(Some("Zed.wad.client"), &format!("{record:016x}.bin"), &own));
        v.check(&Entry::new(None, RECORD, &own));
        let report = v.finish();
        // Each way of naming the same file ends up at the same game file: clean if it is the game's.
        assert!(report.is_clean(), "{report}");
        // ... which is read in every WAD that holds it, each time.
        let both = [("ahri.wad.client".to_owned(), record), ("zed.wad.client".to_owned(), record)];
        assert_eq!(*reads.borrow(), [both.clone(), both.clone(), both].concat());
    }

    #[test]
    fn a_packed_wad_is_held_to_the_same_base_skin_rules_by_hash() {
        let hashed = format!("{:016x}.bin", path_hash(BASE));
        let theirs = skin_bin("Ahri", &["assets/characters/ahri/skins/skin17/a.skn"], &[]);
        let report = check(Some("Ahri.wad.client"), &hashed, &theirs);
        assert_eq!(rules_of(&report), BTreeSet::from([id::BASE_ASSETS]));
        assert_eq!(report.base_skins, 1);
        // The same bytes under some other hash are not a base skin.
        let report = check(Some("Ahri.wad.client"), "0000000000000001.bin", &theirs);
        assert!(report.is_clean(), "{report}");
    }

    #[test]
    fn the_base_skin_is_found_by_path_not_by_wad() {
        let theirs = skin_bin("Ahri", &["assets/characters/ahri/skins/skin17/a.skn"], &[]);
        let report = check(Some("Zed.wad.client"), BASE, &theirs);
        assert_eq!(rules_of(&report), BTreeSet::from([id::BASE_ASSETS]));
    }

    #[test]
    fn deep_nesting_is_refused_not_followed() {
        let bytes = raw_bin(&nested(MAX_DEPTH + 8, Shape::Struct), 1);
        let report = check(Some("Ahri.wad.client"), "data/x.bin", &bytes);
        assert_eq!(rules_of(&report), BTreeSet::from([id::BIN_READABLE]));
        assert!(report.violations[0].detail.contains("too deep"));
        // Ordinary nesting passes.
        let bytes = raw_bin(&nested(MAX_DEPTH / 4, Shape::Struct), 1);
        assert!(check(Some("Ahri.wad.client"), "data/x.bin", &bytes).is_clean());
    }

    #[test]
    fn every_rule_in_the_table_can_fire() {
        let mut seen = BTreeSet::new();
        let cases: Vec<(Option<&str>, &str, Vec<u8>)> = vec![
            (Some("Ahri.wad.client"), "a/../b.dds", b"x".to_vec()),
            (Some("Map11.wad.client"), "a.dds", b"x".to_vec()),
            (Some("Ahri.wad.client"), "a.exe", b"x".to_vec()),
            (Some("Ahri.wad.client"), "a.bin", b"junk".to_vec()),
            (Some("Ahri.wad.client"), "a.bin", class_bin("CharacterRecord")),
            (Some("Ahri.wad.client"), BASE, skin_bin("AhriSkin22", &[], &[])),
            (Some("Ahri.wad.client"), BASE, skin_bin("Ahri", &["assets/characters/ahri/skins/skin3/a.skn"], &[])),
        ];
        for (wad, name, bytes) in &cases {
            seen.extend(rules_of(&check(*wad, name, bytes)));
        }
        let mut v = validator();
        v.violation(id::DATA_DECL, "META/info.json", "declares game data");
        seen.extend(rules_of(&v.finish()));
        let all: BTreeSet<_> = RULES.iter().map(|r| r.id).collect();
        assert_eq!(seen, all);
    }

    #[test]
    fn the_report_is_capped_and_says_so() {
        let mut v = validator();
        for n in 0..(MAX_VIOLATIONS + 5) {
            v.violation(id::PATH, format!("f{n}"), "x");
        }
        let report = v.finish();
        assert_eq!(report.violations.len(), MAX_VIOLATIONS);
        assert!(report.truncated);
        assert!(report.to_string().contains("and more"));
    }

    #[test]
    fn champion_names_come_from_the_wad_names() {
        let v = validator();
        assert_eq!(v.champions, BTreeSet::from(["ahri".to_owned(), "zed".to_owned()]));
        assert_eq!(v.skin0.len(), 2);
    }

    /// The WADs of an installed game, each mounted once, and which of them holds which chunk: what
    /// the host serves the validator with.
    struct InstalledGame {
        /// Lower-case file name, mounted WAD.
        wads: Vec<(String, ltk_wad::Wad<std::fs::File>)>,
        holders: HashMap<u64, Vec<usize>>,
    }

    impl InstalledGame {
        fn open(root: &std::path::Path) -> Self {
            fn walk(folder: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
                for entry in std::fs::read_dir(folder).expect("a folder that reads").flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        walk(&path, found);
                    } else if path.to_string_lossy().to_ascii_lowercase().ends_with(".wad.client") {
                        found.push(path);
                    }
                }
            }
            let mut paths = Vec::new();
            walk(root, &mut paths);
            paths.sort();
            let mut game = Self { wads: Vec::new(), holders: HashMap::new() };
            for path in paths {
                let name = path.file_name().expect("a file").to_string_lossy().to_ascii_lowercase();
                assert!(game.wads.iter().all(|(known, _)| *known != name), "two WADs called {name}");
                let wad = ltk_wad::Wad::mount(std::fs::File::open(&path).expect("open"))
                    .unwrap_or_else(|error| panic!("{} does not mount: {error}", path.display()));
                for chunk in wad.chunks().iter() {
                    game.holders.entry(chunk.path_hash.0).or_default().push(game.wads.len());
                }
                game.wads.push((name, wad));
            }
            game
        }
    }

    /// One validator's view of an [`InstalledGame`].
    struct Installed(Rc<std::cell::RefCell<InstalledGame>>);

    impl GameFiles for Installed {
        fn holders(&mut self, hash: u64) -> Option<Vec<String>> {
            let game = self.0.borrow();
            let held = game.holders.get(&hash).map(Vec::as_slice).unwrap_or_default();
            Some(held.iter().map(|at| game.wads[*at].0.clone()).collect())
        }

        fn file(&mut self, wad: &str, hash: u64) -> Option<Vec<u8>> {
            let mut game = self.0.borrow_mut();
            let (_, mounted) = game.wads.iter_mut().find(|(name, _)| name == wad)?;
            let chunk = mounted.chunks().get(WadHash(hash)).copied()?;
            Some(mounted.load_chunk_decompressed(&chunk).ok()?[..].to_vec())
        }
    }

    /// Runs the rules over the BINs of the installed game, with the game's files to compare them
    /// with, the way the host runs them. The game's own skins must pass (false positives would
    /// refuse honest packs), and so must its character records, unchanged. On their own the
    /// records must be refused, though (the rule has to see what it is there for), and so must a
    /// record with a gameplay object changed. The sizes the limits are chosen from are printed.
    ///
    /// `cargo test -p riftengine-validator -- --ignored --nocapture`, with `RIFTENGINE_GAME_DIR`
    /// set to the `Game` folder when the game is not in the default place.
    #[test]
    #[ignore = "needs an installed game"]
    fn the_installed_game_agrees_with_the_rules() {
        use std::fs::File;
        use std::time::Instant;

        use ltk_wad::Wad;

        let game = std::env::var("RIFTENGINE_GAME_DIR")
            .unwrap_or_else(|_| r"C:\Riot Games\League of Legends\Game".to_owned());
        let folder = std::path::Path::new(&game).join("DATA").join("FINAL").join("Champions");
        let mut names: Vec<String> = std::fs::read_dir(&folder)
            .unwrap_or_else(|error| panic!("no champion WADs in {}: {error}", folder.display()))
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| name.ends_with(".wad.client"))
            .collect();
        names.sort();
        let main_wads: BTreeMap<String, String> = names
            .iter()
            .filter(|name| !name.trim_end_matches(".wad.client").contains('.'))
            .map(|name| (name.trim_end_matches(".wad.client").to_ascii_lowercase(), name.clone()))
            .collect();
        // What the host does: every WAD of the install mounted once, and an index of which hold
        // which chunk.
        let started = Instant::now();
        let installed = Rc::new(std::cell::RefCell::new(InstalledGame::open(
            &std::path::Path::new(&game).join("DATA").join("FINAL"),
        )));
        println!(
            "{} WADs indexed in {:?}, {} chunks, {} held by more than one WAD",
            installed.borrow().wads.len(),
            started.elapsed(),
            installed.borrow().holders.len(),
            installed.borrow().holders.values().filter(|held| held.len() > 1).count(),
        );

        let started = Instant::now();
        let (mut files, mut bases, mut records, mut flagged_records) = (0, 0, 0, 0);
        let (mut biggest_file, mut biggest_object, mut deepest) = ((0, String::new()), (0, String::new()), (0, String::new()));
        let mut surprises = Vec::new();
        let mut odd_names = BTreeSet::new();
        let mut gameplay_outside_records = Vec::new();
        for (champion, name) in &main_wads {
            let mut wad = Wad::mount(File::open(folder.join(name)).expect("open")).expect("mount");
            let mut paths = vec![format!("data/characters/{champion}/{champion}.bin")];
            for number in 0..=150 {
                paths.push(format!("data/characters/{champion}/skins/skin{number}.bin"));
                paths.push(format!("data/characters/{champion}/animations/skin{number}.bin"));
            }
            for path in paths {
                let Some(chunk) = wad.chunks().get(WadHash(path_hash(&path))).copied() else { continue };
                let bytes = wad.load_chunk_decompressed(&chunk).expect("decompress");
                let is_record = path.ends_with(&format!("/{champion}/{champion}.bin"));
                let is_base = path.ends_with("/skins/skin0.bin");
                files += 1;

                // Checked the way the host does, against the game's copy of the very same file.
                let run = |bytes: &[u8], compared: bool| {
                    let mut v = Validator::new(&names);
                    if compared {
                        v = v.with_game_files(Installed(installed.clone()));
                    }
                    v.check(&Entry::new(Some(name), &path, bytes));
                    v.finish()
                };
                let report = run(&bytes, true);

                if let Ok(largest) = read_table(&bytes)
                    && largest > biggest_object.0
                {
                    biggest_object = (largest, format!("{name}/{path}"));
                }
                if bytes.len() > biggest_file.0 {
                    biggest_file = (bytes.len(), format!("{name}/{path}"));
                }
                let facts = read_bin(&bytes, is_base.then_some(champion.as_str())).ok();
                if let Some(facts) = &facts {
                    if facts.deepest > deepest.0 {
                        deepest = (facts.deepest, format!("{name}/{path}"));
                    }
                    if is_base {
                        odd_names.extend(facts.skin_names.iter().filter(|n| !n.eq_ignore_ascii_case(champion)).cloned());
                    }
                }
                let gameplay: BTreeSet<u32> =
                    facts.iter().flat_map(|facts| facts.gameplay.values().flatten().copied()).collect();

                if is_record {
                    records += 1;
                    // On its own, the rule sees what it is there for...
                    if rules_of(&run(&bytes, false)).contains(id::GAMEPLAY_CLASS) {
                        flagged_records += 1;
                    } else {
                        surprises.push(format!("{path}: the character record was not recognised"));
                    }
                    // ...the game's record, unchanged, is not a change...
                    if !report.is_clean() {
                        surprises.push(format!("{path}: the game's own record was refused against itself\n{report}"));
                    }
                    // ...and one gameplay object under another path hash is.
                    let mut first = None;
                    walk_table(&bytes, |row| {
                        if gameplay.contains(&row.path_hash) {
                            first.get_or_insert(row.range.start);
                        }
                    })
                    .expect("the game's own table reads");
                    let mut changed = bytes.to_vec();
                    changed[first.expect("a gameplay object in the record") + 4] ^= 1;
                    if !rules_of(&run(&changed, true)).contains(id::GAMEPLAY_CLASS) {
                        surprises.push(format!("{path}: a record with a gameplay object changed was let through"));
                    }
                } else {
                    if !gameplay.is_empty() {
                        gameplay_outside_records.push(path.clone());
                    }
                    if is_base {
                        bases += 1;
                    }
                    if !report.is_clean() {
                        surprises.push(format!("{path}: the game's own file was refused\n{report}"));
                    }
                }
            }
        }
        println!("{files} BINs in {:?}: {bases} base skins, {flagged_records}/{records} character records flagged", started.elapsed());
        println!("biggest file:   {} bytes, {}", biggest_file.0, biggest_file.1);
        println!("biggest object: {} bytes, {}", biggest_object.0, biggest_object.1);
        println!("deepest nest:   {} levels, {}", deepest.0, deepest.1);
        println!("base skins not named after the champion: {odd_names:?}");
        println!("gameplay objects outside the records, which only the comparison lets through: {gameplay_outside_records:?}");
        for surprise in surprises.iter().take(20) {
            println!("{surprise}");
        }
        assert!(files > 0 && bases > 0 && records > 0, "found nothing to check in {}", folder.display());
        assert!(surprises.is_empty(), "{} surprises, first: {}", surprises.len(), surprises[0]);
        assert!(biggest_file.0 <= MAX_BIN_BYTES && biggest_object.0 <= MAX_OBJECT_BYTES);
    }
}
