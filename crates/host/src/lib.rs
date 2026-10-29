//! Host half of RiftEngine: finds the game, serves the pipe, loads the DLL into the game
//! and reports what the DLL does.
#![cfg(windows)]

pub mod attach;
pub mod game;
pub mod inject;
pub mod overlay;
pub mod pack;
pub mod pipe_server;
pub mod watch;

use serde::Serialize;

/// One line of the host's JSON event stream (`--events` on stdout).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Waiting { game_dir: String },
    Found { pid: u32, age_ms: u64 },
    Attached { pid: u32, hooks: Vec<String>, files: u32 },
    Redirected { requested: String, served: String },
    Refused { pid: u32, reason: String },
    Log { level: u8, text: String },
    Detached { pid: u32 },
    Failed { pid: u32, message: String },
    /// A pack was read and checked against the rules.
    Validated { pack: String, files: usize, base_skins: usize, violations: usize },
    /// One thing in a pack that the rules refuse. Nothing is built while there is one.
    Violation { pack: String, rule: String, location: String, detail: String },
    /// The overlay builder moved on.
    Building { stage: String, current: u32, total: u32 },
    /// The overlay is built, audited and its manifest written.
    Built { wads: usize, chunks: usize, manifest: String },
}
