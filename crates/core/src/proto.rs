//! Messages exchanged over the per-game named pipe.
//!
//! The host writes one [`Hello`] frame, then only reads. The DLL reads that frame, then only
//! writes [`DllMsg`] frames. Each frame is a little-endian `u32` length followed by CBOR.

use std::fmt;
use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;
pub const GAME_EXE_NAME: &str = "League of Legends.exe";
pub const PIPE_PREFIX: &str = r"\\.\pipe\riftengine-";
pub const MAX_FRAME_BYTES: usize = 16 * 1024;

pub fn pipe_name(game_pid: u32) -> String {
    format!("{PIPE_PREFIX}{game_pid}")
}

/// Event the DLL creates when it has been loaded into the game. The host looks for it to tell a
/// DLL that never loaded from one that loaded and never reached the pipe.
pub fn loaded_event_name(game_pid: u32) -> String {
    format!(r"Local\riftengine-loaded-{game_pid}")
}

/// Flag bits of [`Hello::flags`].
///
/// There is deliberately no bit that skips, relaxes or reports on the rule checks. The DLL
/// refuses a session that sets a bit outside [`KNOWN`](flags::KNOWN), so a newer host cannot
/// smuggle one in past an older DLL.
pub mod flags {
    /// Resolve and report redirects but serve the original files.
    pub const DRY_RUN: u32 = 1 << 0;
    pub const KNOWN: u32 = DRY_RUN;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub version: u32,
    pub host_pid: u32,
    pub game_pid: u32,
    /// Directory that holds `League of Legends.exe`.
    pub game_root: String,
    /// Directory that holds `DATA/FINAL/**.wad.client` copies and the manifest.
    pub overlay_root: String,
    pub flags: u32,
    /// The DLL refuses to overlay a game process older than this: its WADs are already open.
    pub max_process_age_ms: u64,
    pub rules_digest: String,
    pub manifest_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloError {
    Version { expected: u32, got: u32 },
    UnknownFlags(u32),
    WrongProcess { expected: u32, got: u32 },
}

impl fmt::Display for HelloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version { expected, got } => {
                write!(f, "protocol version {got}, this DLL speaks {expected}")
            }
            Self::UnknownFlags(bits) => write!(f, "unknown flag bits {bits:#x}"),
            Self::WrongProcess { expected, got } => {
                write!(f, "session is for pid {got}, this process is {expected}")
            }
        }
    }
}

impl std::error::Error for HelloError {}

impl Hello {
    pub fn check(&self, own_pid: u32) -> Result<(), HelloError> {
        if self.version != PROTOCOL_VERSION {
            return Err(HelloError::Version {
                expected: PROTOCOL_VERSION,
                got: self.version,
            });
        }
        let unknown = self.flags & !flags::KNOWN;
        if unknown != 0 {
            return Err(HelloError::UnknownFlags(unknown));
        }
        if self.game_pid != own_pid {
            return Err(HelloError::WrongProcess {
                expected: own_pid,
                got: self.game_pid,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DllMsg {
    Ready {
        dll_version: String,
        hooks: Vec<String>,
        files: u32,
    },
    Refused {
        reason: String,
    },
    Redirected {
        requested: String,
        served: String,
    },
    Log {
        level: u8,
        text: String,
    },
}

pub fn write_frame<T: Serialize>(out: &mut impl Write, msg: &T) -> io::Result<()> {
    let mut frame = vec![0u8; 4];
    ciborium::into_writer(msg, &mut frame).map_err(|e| io::Error::other(e.to_string()))?;
    let payload = frame.len() - 4;
    if payload > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("frame of {payload} bytes exceeds {MAX_FRAME_BYTES}"),
        ));
    }
    frame[..4].copy_from_slice(&(payload as u32).to_le_bytes());
    out.write_all(&frame)?;
    out.flush()
}

pub fn read_frame<T: DeserializeOwned>(input: &mut impl Read) -> io::Result<T> {
    let mut len = [0u8; 4];
    input.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds {MAX_FRAME_BYTES}"),
        ));
    }
    let mut payload = vec![0u8; len];
    input.read_exact(&mut payload)?;
    ciborium::from_reader(payload.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> Hello {
        Hello {
            version: PROTOCOL_VERSION,
            host_pid: 10,
            game_pid: 20,
            game_root: r"C:\Riot Games\League of Legends\Game".into(),
            overlay_root: r"C:\overlay".into(),
            flags: 0,
            max_process_age_ms: 15_000,
            rules_digest: "r".into(),
            manifest_digest: "m".into(),
        }
    }

    #[test]
    fn frames_round_trip() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &hello()).unwrap();
        let back: Hello = read_frame(&mut wire.as_slice()).unwrap();
        assert_eq!(back, hello());

        let mut wire = Vec::new();
        let msg = DllMsg::Redirected {
            requested: "a".into(),
            served: "b".into(),
        };
        write_frame(&mut wire, &msg).unwrap();
        assert_eq!(read_frame::<DllMsg>(&mut wire.as_slice()).unwrap(), msg);
    }

    #[test]
    fn oversized_and_truncated_frames_are_rejected() {
        let mut wire = ((MAX_FRAME_BYTES + 1) as u32).to_le_bytes().to_vec();
        wire.extend(std::iter::repeat_n(0u8, 64));
        let err = read_frame::<Hello>(&mut wire.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut wire = Vec::new();
        write_frame(&mut wire, &hello()).unwrap();
        wire.truncate(wire.len() - 3);
        let err = read_frame::<Hello>(&mut wire.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        let big = DllMsg::Log {
            level: 1,
            text: "x".repeat(MAX_FRAME_BYTES),
        };
        assert!(write_frame(&mut Vec::new(), &big).is_err());
    }

    #[test]
    fn garbage_payload_is_invalid_data() {
        let mut wire = 3u32.to_le_bytes().to_vec();
        wire.extend([0xff, 0xff, 0xff]);
        let err = read_frame::<Hello>(&mut wire.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn names_carry_the_game_pid() {
        assert_eq!(pipe_name(7), r"\\.\pipe\riftengine-7");
        assert_eq!(loaded_event_name(7), r"Local\riftengine-loaded-7");
    }

    #[test]
    fn hello_checks() {
        assert_eq!(hello().check(20), Ok(()));
        assert_eq!(
            hello().check(21),
            Err(HelloError::WrongProcess { expected: 21, got: 20 })
        );
        let mut h = hello();
        h.version += 1;
        assert!(matches!(h.check(20), Err(HelloError::Version { .. })));
        let mut h = hello();
        h.flags = flags::DRY_RUN | (1 << 7);
        assert_eq!(h.check(20), Err(HelloError::UnknownFlags(1 << 7)));
    }
}
