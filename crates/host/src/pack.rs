//! Reads a Fantome archive into memory, once, within limits.
//!
//! Everything downstream works from this snapshot: the validator checks these bytes, and the
//! overlay builder is handed these same bytes. The builder never opens the archive itself, so a
//! pack cannot change between the check and the build, and nothing in it reaches the overlay
//! without being read here first.

use std::borrow::Cow;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Cursor, Read, Seek};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use ltk_fantome::{BASE_LAYER, FantomeEntry, FantomeInfo, classify_entry};
use ltk_wad::Wad;
use zip::ZipArchive;

/// Most entries an archive may have.
pub const MAX_ENTRIES: usize = 100_000;
/// Largest single file of a pack, decompressed.
pub const MAX_ENTRY_BYTES: u64 = 256 << 20;
/// Most a pack may take once decompressed, counting what packed WADs hold.
pub const MAX_PACK_BYTES: u64 = 1 << 30;
/// Most chunks a packed WAD may hold.
const MAX_WAD_CHUNKS: usize = 100_000;
/// `META/info.json` is a few lines.
const MAX_INFO_BYTES: u64 = 1 << 20;

const WAD_HEADER_BYTES: usize = 272;
const WAD_ENTRY_BYTES: usize = 32;

#[derive(Debug)]
pub enum PackError {
    Io(io::Error),
    Zip(String),
    /// The pack is bigger than the host reads.
    Limit(String),
    /// The pack is not a pack, or has a part that is not what it says it is.
    Malformed(String),
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "cannot read the pack: {error}"),
            Self::Zip(error) => write!(f, "not a readable archive: {error}"),
            Self::Limit(what) => write!(f, "too big: {what}"),
            Self::Malformed(what) => f.write_str(what),
        }
    }
}

impl std::error::Error for PackError {}

impl From<io::Error> for PackError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// One file of a pack, at the place the archive puts it.
pub struct PackFile {
    /// `base`, or the name of the `WAD_<layer>` directory it is in.
    pub layer: String,
    /// The WAD it is meant for, as the archive spells it; `None` for a `RAW/` file.
    pub wad: Option<String>,
    /// Path inside the WAD (or under `RAW/`) with forward slashes, or `<16 hex digits>` for a chunk
    /// of a packed WAD, whose original path is lost. It has no extension: what a chunk is follows
    /// from its bytes, and an invented extension would make the validator misread it.
    pub path: String,
    pub bytes: Vec<u8>,
}

pub struct Pack {
    /// The archive's file name.
    pub label: String,
    pub info: FantomeInfo,
    pub files: Vec<PackFile>,
    /// Where the pack declares game data, which no pack may.
    pub game_data: Vec<String>,
    /// Entries that are not content: readme, thumbnail, licence, hashtables, unplaced names.
    pub other_entries: usize,
}

pub fn read(path: &Path) -> Result<Pack, PackError> {
    let label = path
        .file_name()
        .map_or_else(|| path.display().to_string(), |name| name.to_string_lossy().into_owned());
    let mut zip = ZipArchive::new(BufReader::new(File::open(path)?)).map_err(zip_error)?;
    if zip.len() > MAX_ENTRIES {
        return Err(PackError::Limit(format!("the archive has {} entries; the limit is {MAX_ENTRIES}", zip.len())));
    }

    let mut info = None;
    let mut files = Vec::new();
    let mut game_data = Vec::new();
    let mut other_entries = 0;
    let mut total: u64 = 0;
    for index in 0..zip.len() {
        let (name, declared) = {
            let entry = zip.by_index_raw(index).map_err(zip_error)?;
            match entry.name().map(Cow::into_owned) {
                Ok(name) => (name, entry.size()),
                Err(_) => {
                    other_entries += 1;
                    continue;
                }
            }
        };
        // A folder entry holds no file; there is nothing in it to read or to ignore.
        if name.ends_with('/') {
            continue;
        }
        match classify_entry(&name) {
            Some(FantomeEntry::Info) => {
                if info.is_some() {
                    return Err(PackError::Malformed("META/info.json is in the archive twice".into()));
                }
                let bytes = read_entry(&mut zip, index, declared, MAX_INFO_BYTES)?;
                info = Some(parse_info(&bytes)?);
            }
            Some(FantomeEntry::GameData(_)) => game_data.push(name.clone()),
            Some(FantomeEntry::PackedWad { layer, name: wad }) => {
                let bytes = read_entry(&mut zip, index, declared, MAX_ENTRY_BYTES)?;
                charge(&mut total, bytes.len() as u64)?;
                for (hash, chunk) in unpack(&bytes, &mut total)? {
                    files.push(PackFile {
                        layer: layer.to_owned(),
                        wad: Some(wad.to_owned()),
                        path: format!("{hash:016x}"),
                        bytes: chunk,
                    });
                }
            }
            Some(FantomeEntry::WadFile { layer, path }) => {
                let Some((wad, rest)) = path.split_once('/') else {
                    other_entries += 1;
                    continue;
                };
                if !is_wad_name(wad) || rest.is_empty() {
                    other_entries += 1;
                    continue;
                }
                let (layer, wad, rest) = (layer.to_owned(), wad.to_owned(), rest.to_owned());
                let bytes = read_entry(&mut zip, index, declared, MAX_ENTRY_BYTES)?;
                charge(&mut total, bytes.len() as u64)?;
                files.push(PackFile { layer, wad: Some(wad), path: rest, bytes });
            }
            Some(FantomeEntry::Raw(rest)) => {
                let rest = rest.to_owned();
                let bytes = read_entry(&mut zip, index, declared, MAX_ENTRY_BYTES)?;
                charge(&mut total, bytes.len() as u64)?;
                files.push(PackFile { layer: BASE_LAYER.to_owned(), wad: None, path: rest, bytes });
            }
            Some(_) | None => other_entries += 1,
        }
    }

    let info = info.ok_or_else(|| PackError::Malformed("the archive has no META/info.json".into()))?;
    for (key, layer) in &info.layers {
        if layer.game_data.is_some() {
            game_data.push(format!("META/info.json: layer {key}"));
        }
    }
    Ok(Pack { label, info, files, game_data, other_entries })
}

fn zip_error(error: zip::result::ZipError) -> PackError {
    PackError::Zip(error.to_string())
}

fn charge(total: &mut u64, bytes: u64) -> Result<(), PackError> {
    *total += bytes;
    if *total > MAX_PACK_BYTES {
        return Err(PackError::Limit(format!("the pack takes more than {MAX_PACK_BYTES} bytes once unpacked")));
    }
    Ok(())
}

/// Reads one entry in full, never more than the size it declares. The archive's own checksum is
/// not checked, since some tools write bad ones; a stream that does not decompress is an error.
fn read_entry<R: Read + Seek>(zip: &mut ZipArchive<R>, index: usize, declared: u64, cap: u64) -> Result<Vec<u8>, PackError> {
    if declared > cap {
        return Err(PackError::Limit(format!("an entry is {declared} bytes; the limit is {cap}")));
    }
    let mut entry = zip.by_index(index).map_err(zip_error)?;
    let mut bytes = Vec::new();
    (&mut entry).take(declared).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn parse_info(bytes: &[u8]) -> Result<FantomeInfo, PackError> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    serde_json::from_slice(bytes).map_err(|error| PackError::Malformed(format!("META/info.json is not valid: {error}")))
}

fn is_wad_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".wad.client") || lower.ends_with(".wad") || lower.ends_with(".wad.mobile")
}

/// Checks the header and table of contents of a packed WAD against its own length. The WAD reader
/// reserves memory for the chunk count and reads at the offsets the table gives, as the file says,
/// so a table that lies has to be refused before the reader sees it.
fn check_wad(bytes: &[u8], total: u64) -> Result<usize, PackError> {
    let bad = |what: String| PackError::Malformed(format!("a packed WAD {what}"));
    if bytes.len() < WAD_HEADER_BYTES || &bytes[..2] != b"RW" || bytes[2] != 3 {
        return Err(bad("is not a version 3 WAD".into()));
    }
    let count = i32::from_le_bytes(bytes[268..272].try_into().expect("four bytes"));
    let count = usize::try_from(count).ok().filter(|count| *count <= MAX_WAD_CHUNKS);
    let Some(count) = count else {
        return Err(PackError::Limit(format!("a packed WAD has more than {MAX_WAD_CHUNKS} chunks")));
    };
    let table_end = WAD_HEADER_BYTES + count * WAD_ENTRY_BYTES;
    if table_end > bytes.len() {
        return Err(bad("has a table of contents that runs past the end of the file".into()));
    }
    let mut unpacked = total;
    for entry in bytes[WAD_HEADER_BYTES..table_end].chunks_exact(WAD_ENTRY_BYTES) {
        let offset = u64::from(u32::from_le_bytes(entry[8..12].try_into().expect("four bytes")));
        let packed = u32::from_le_bytes(entry[12..16].try_into().expect("four bytes"));
        let size = u32::from_le_bytes(entry[16..20].try_into().expect("four bytes"));
        let kind = entry[20] & 0xF;
        if packed > i32::MAX as u32 || size > i32::MAX as u32 {
            return Err(bad("has a chunk of an impossible size".into()));
        }
        if offset + u64::from(packed) > bytes.len() as u64 {
            return Err(bad("has a chunk that runs past the end of the file".into()));
        }
        if kind > 4 || kind == 2 {
            return Err(bad(format!("has a chunk of a kind ({kind}) that holds no file of its own")));
        }
        if u64::from(size) > MAX_ENTRY_BYTES {
            return Err(PackError::Limit(format!("a chunk of a packed WAD is {size} bytes; the limit is {MAX_ENTRY_BYTES}")));
        }
        unpacked += u64::from(size);
        if unpacked > MAX_PACK_BYTES {
            return Err(PackError::Limit(format!("the pack takes more than {MAX_PACK_BYTES} bytes once unpacked")));
        }
    }
    Ok(count)
}

/// The chunks of a packed WAD with their path hashes, decompressed. A library that reads
/// untrusted compressed data can panic on it; that is an error here, not a crash.
fn unpack(bytes: &[u8], total: &mut u64) -> Result<Vec<(u64, Vec<u8>)>, PackError> {
    let count = check_wad(bytes, *total)?;
    let broken = || PackError::Malformed("a packed WAD does not read".into());
    let loaded = catch_unwind(AssertUnwindSafe(|| -> Option<Vec<(u64, Vec<u8>)>> {
        let mut wad = Wad::mount(Cursor::new(bytes)).ok()?;
        let chunks: Vec<_> = wad.chunks().iter().copied().collect();
        let mut out = Vec::with_capacity(count.min(chunks.len()));
        for chunk in chunks {
            out.push((chunk.path_hash.0, wad.load_chunk_decompressed(&chunk).ok()?.into_vec()));
        }
        Some(out)
    }))
    .map_err(|_| broken())?
    .ok_or_else(broken)?;
    for (_, chunk) in &loaded {
        charge(total, chunk.len() as u64)?;
    }
    Ok(loaded)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write;

    use zip::write::SimpleFileOptions;

    use super::*;

    pub(crate) const INFO: &str = r#"{"Name":"Test","Author":"me","Version":"1.0.0","Description":"a test"}"#;

    pub(crate) fn archive(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let file = tempfile::Builder::new().suffix(".fantome").tempfile().unwrap();
        let mut zip = zip::ZipWriter::new(file.reopen().unwrap());
        for (name, bytes) in entries {
            zip.start_file(*name, SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored)).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
        file
    }

    /// A version 3.4 WAD with these chunks, stored uncompressed.
    pub(crate) fn wad(chunks: &[(u64, &[u8])]) -> Vec<u8> {
        let mut out = b"RW\x03\x04".to_vec();
        out.resize(268, 0);
        out.extend((chunks.len() as i32).to_le_bytes());
        let mut offset = WAD_HEADER_BYTES + chunks.len() * WAD_ENTRY_BYTES;
        for (hash, bytes) in chunks {
            out.extend(hash.to_le_bytes());
            out.extend((offset as u32).to_le_bytes());
            out.extend((bytes.len() as u32).to_le_bytes());
            out.extend((bytes.len() as u32).to_le_bytes());
            out.extend([0u8, 0, 0, 0]);
            out.extend(0u64.to_le_bytes());
            offset += bytes.len();
        }
        for (_, bytes) in chunks {
            out.extend(*bytes);
        }
        out
    }

    #[test]
    fn a_directory_pack_is_read_with_its_layers_and_raw_files() {
        let file = archive(&[
            ("META/info.json", INFO.as_bytes()),
            ("META/README.md", b"hello"),
            ("WAD/Ahri.wad.client/assets/characters/ahri/skins/base/a.dds", b"DDS 1"),
            ("WAD_Pink/Ahri.wad.client/assets/characters/ahri/skins/base/b.dds", b"DDS 2"),
            ("RAW/assets/characters/ahri/skins/base/c.dds", b"DDS 3"),
            ("WAD/", b""),
        ]);
        let pack = read(file.path()).unwrap();
        assert_eq!(pack.info.name, "Test");
        assert_eq!(pack.other_entries, 1);
        let listed: Vec<_> = pack
            .files
            .iter()
            .map(|f| (f.layer.as_str(), f.wad.as_deref(), f.path.as_str(), f.bytes.as_slice()))
            .collect();
        assert_eq!(
            listed,
            [
                ("base", Some("Ahri.wad.client"), "assets/characters/ahri/skins/base/a.dds", &b"DDS 1"[..]),
                ("Pink", Some("Ahri.wad.client"), "assets/characters/ahri/skins/base/b.dds", &b"DDS 2"[..]),
                ("base", None, "assets/characters/ahri/skins/base/c.dds", &b"DDS 3"[..]),
            ]
        );
    }

    #[test]
    fn a_packed_wad_is_read_as_hash_named_chunks() {
        let packed = wad(&[(0x0123_4567_89ab_cdef, b"one"), (7, b"two")]);
        let file = archive(&[("META/info.json", INFO.as_bytes()), ("WAD/Ahri.wad.client", &packed)]);
        let pack = read(file.path()).unwrap();
        let mut names: Vec<_> = pack.files.iter().map(|f| (f.path.clone(), f.bytes.clone())).collect();
        names.sort();
        assert_eq!(
            names,
            [("0000000000000007".to_owned(), b"two".to_vec()), ("0123456789abcdef".to_owned(), b"one".to_vec())]
        );
    }

    #[test]
    fn a_packed_wad_that_lies_about_itself_is_refused_before_it_is_read() {
        let good = wad(&[(1, b"one")]);
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        let mut huge_count = good.clone();
        huge_count[268..272].copy_from_slice(&i32::MAX.to_le_bytes());
        cases.push(("a chunk count the file cannot hold", huge_count));
        let mut negative_count = good.clone();
        negative_count[268..272].copy_from_slice(&(-1i32).to_le_bytes());
        cases.push(("a negative chunk count", negative_count));
        let mut past_the_end = good.clone();
        past_the_end[272 + 12..272 + 16].copy_from_slice(&1_000u32.to_le_bytes());
        cases.push(("a chunk that runs past the end", past_the_end));
        let mut negative_size = good.clone();
        negative_size[272 + 12..272 + 16].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(("a negative size", negative_size));
        let mut bomb = good.clone();
        bomb[272 + 16..272 + 20].copy_from_slice(&(MAX_ENTRY_BYTES as u32 + 1).to_le_bytes());
        cases.push(("a chunk that claims to unpack to more than the limit", bomb));
        let mut satellite = good.clone();
        satellite[272 + 20] = 2;
        cases.push(("a satellite chunk", satellite));
        cases.push(("a short file", good[..100].to_vec()));
        cases.push(("another version", {
            let mut other = good.clone();
            other[2] = 2;
            other
        }));
        for (what, packed) in cases {
            let file = archive(&[("META/info.json", INFO.as_bytes()), ("WAD/Ahri.wad.client", &packed)]);
            assert!(read(file.path()).is_err(), "{what}");
        }
    }

    #[test]
    fn game_data_is_reported_not_read() {
        let info = r#"{"Name":"T","Author":"a","Description":"d","Layers":{"base":{"Name":"base","Priority":0,"GameData":{"format":1}}}}"#;
        let file = archive(&[("META/info.json", info.as_bytes()), ("META/game_data/base/rules.json", b"{}")]);
        let pack = read(file.path()).unwrap();
        assert_eq!(pack.game_data.len(), 2, "{:?}", pack.game_data);
    }

    #[test]
    fn archives_without_info_or_with_too_much_are_refused() {
        let file = archive(&[("WAD/Ahri.wad.client/a.dds", b"x")]);
        assert!(matches!(read(file.path()), Err(PackError::Malformed(_))));
        let file = archive(&[("META/info.json", INFO.as_bytes()), ("meta/Info.json", INFO.as_bytes())]);
        assert!(matches!(read(file.path()), Err(PackError::Malformed(_))));
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"not a zip").unwrap();
        assert!(matches!(read(file.path()), Err(PackError::Zip(_))));
    }
}
