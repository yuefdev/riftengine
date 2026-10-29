//! One game session: prepare the handshake, load the DLL, then relay what it reports.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use riftengine_core::manifest::OverlayManifest;
use riftengine_core::proto::{DllMsg, Hello, PROTOCOL_VERSION, pipe_name, read_frame, write_frame};

use crate::inject;
use crate::pipe_server::PipeServer;
use crate::watch::GameProcess;
use crate::Event;

/// How often the hooked thread is woken again while the DLL has not answered.
const NUDGE_EVERY: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct Options {
    pub game_dir: PathBuf,
    pub overlay_root: PathBuf,
    pub dll: PathBuf,
    pub max_process_age_ms: u64,
    pub flags: u32,
    /// How long to wait for the game window and for the DLL to answer.
    pub timeout: Duration,
}

#[derive(Debug)]
pub enum AttachError {
    /// The overlay is not usable (stale, tampered with, or built under other rules).
    Overlay(String),
    /// The game could not be reached or did not answer.
    Game(String),
    /// The DLL looked at the session and said no.
    Refused(String),
}

impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overlay(m) | Self::Game(m) => f.write_str(m),
            Self::Refused(m) => write!(f, "the DLL refused the session: {m}"),
        }
    }
}

impl std::error::Error for AttachError {}

/// Loads the DLL into `game`, then relays its events until the game closes the pipe.
pub fn attach(opts: &Options, game: &GameProcess, emit: &mut dyn FnMut(Event)) -> Result<(), AttachError> {
    let rules = riftengine_rules::digest();
    let (manifest, manifest_digest) =
        OverlayManifest::load(&opts.overlay_root).map_err(|e| AttachError::Overlay(e.to_string()))?;
    if manifest.rules_digest != rules {
        return Err(AttachError::Overlay("the overlay was validated under a different rule set; rebuild it".into()));
    }
    // Read again for every game: it may have been patched since `watch` began, or since the overlay
    // was built. The DLL asks the same of the image the game runs.
    let linked = crate::game::check_build(&opts.game_dir).map_err(AttachError::Game)?;
    riftengine_rules::check_overlay_build(manifest.game_linked, linked)
        .map_err(|e| AttachError::Overlay(e.to_string()))?;
    manifest.verify_against_disk(&opts.overlay_root).map_err(|e| AttachError::Overlay(e.to_string()))?;

    let accepting = PipeServer::create(&pipe_name(game.pid))
        .map_err(|e| AttachError::Game(format!("cannot create the engine pipe: {e}")))?
        .accept();

    let started = Instant::now();
    let deadline = started + opts.timeout;
    let thread = loop {
        match inject::find_window_thread(game.pid) {
            Ok(Some(thread)) => break thread,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => return Err(AttachError::Game("the game has no window thread yet".into())),
            Err(e) => return Err(AttachError::Game(format!("cannot list the game's threads: {e}"))),
        }
    };
    emit(Event::Log {
        level: 1,
        text: format!(
            "host: hooking thread {} (window class {}) when the game was about {} ms old",
            thread.id,
            thread.class,
            game.age_ms + started.elapsed().as_millis() as u64,
        ),
    });
    let guard = inject::install(&opts.dll, thread.id)
        .map_err(|e| AttachError::Game(format!("cannot hook the game's window thread: {e}")))?;
    let hooked = Instant::now();

    // The DLL connects once the thread reads a message. The game reads them all the time; the
    // nudge in `install` only wakes a thread that sleeps in a wait, and this repeats it slowly in
    // case that one went unnoticed.
    let (connected, connection) = mpsc::channel();
    let waiter = thread::spawn(move || {
        let _ = connected.send(accepting.wait(Duration::from_secs(3600)));
    });
    let (mut last_nudge, mut nudges) = (hooked, 1u32);
    let mut pipe = loop {
        match connection.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(file)) => break file,
            Ok(Err(e)) => return Err(AttachError::Game(format!("pipe: {e}"))),
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {
                if last_nudge.elapsed() >= NUDGE_EVERY {
                    guard.nudge();
                    (last_nudge, nudges) = (Instant::now(), nudges + 1);
                }
            }
            Err(_) => {
                // Dropping the guard unhooks; the waiter ends when the pipe handle is dropped
                // by the process exiting, so do not block on it here.
                drop(waiter);
                emit(Event::Log {
                    level: 1,
                    text: format!("host: giving up {} ms after hooking, {nudges} nudge(s) sent", hooked.elapsed().as_millis()),
                });
                return Err(AttachError::Game(if inject::dll_loaded_in(game.pid) {
                    "the engine DLL is loaded in the game but did not reach the engine pipe".into()
                } else {
                    "the game did not load the engine DLL (run the host at the same privilege level as the game)".into()
                }));
            }
        }
    };
    let _ = waiter.join();
    emit(Event::Log { level: 1, text: format!("host: the DLL reached the pipe {} ms after hooking", hooked.elapsed().as_millis()) });

    let hello = Hello {
        version: PROTOCOL_VERSION,
        host_pid: std::process::id(),
        game_pid: game.pid,
        game_root: opts.game_dir.to_string_lossy().into_owned(),
        overlay_root: opts.overlay_root.to_string_lossy().into_owned(),
        flags: opts.flags,
        max_process_age_ms: opts.max_process_age_ms,
        rules_digest: rules,
        manifest_digest,
    };
    write_frame(&mut pipe, &hello).map_err(|e| AttachError::Game(format!("handshake: {e}")))?;

    // A reader thread lets the first reply be bounded by a timeout.
    let (frames, incoming) = mpsc::channel();
    thread::spawn(move || {
        while let Ok(msg) = read_frame::<DllMsg>(&mut pipe) {
            if frames.send(msg).is_err() {
                break;
            }
        }
    });
    let first = incoming
        .recv_timeout(opts.timeout)
        .map_err(|_| AttachError::Game("the DLL did not answer the handshake".into()))?;
    match first {
        DllMsg::Ready { hooks, files, .. } => {
            drop(guard); // the DLL is pinned in the game; the hook has done its job
            emit(Event::Attached { pid: game.pid, hooks, files });
        }
        DllMsg::Refused { reason } => return Err(AttachError::Refused(reason)),
        other => return Err(AttachError::Game(format!("unexpected first message: {other:?}"))),
    }

    while let Ok(msg) = incoming.recv() {
        match msg {
            DllMsg::Redirected { requested, served } => emit(Event::Redirected { requested, served }),
            DllMsg::Log { level, text } => emit(Event::Log { level, text }),
            DllMsg::Refused { reason } => emit(Event::Log { level: 2, text: reason }),
            DllMsg::Ready { .. } => {}
        }
    }
    emit(Event::Detached { pid: game.pid });
    Ok(())
}

/// Checks the pieces `attach` needs before a game even exists, so a bad setup fails fast.
pub fn preflight(opts: &Options) -> Result<(), String> {
    if !opts.dll.is_file() {
        return Err(format!("engine DLL not found: {}", opts.dll.display()));
    }
    let exe: &Path = &opts.game_dir;
    if !exe.join(riftengine_core::proto::GAME_EXE_NAME).is_file() {
        return Err(format!("{} is not a game folder", exe.display()));
    }
    // The DLL checks the image the game runs; this says no before anything waits for a game.
    crate::game::check_build(exe)?;
    Ok(())
}
