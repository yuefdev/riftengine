//! Session start: authenticate the host, check the overlay, then install the hooks.
//!
//! Anything that fails here leaves the game untouched; the reason goes back over the pipe.

use std::fs::File;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use riftengine_core::manifest::OverlayManifest;
use riftengine_core::proto::{DllMsg, Hello, flags, read_frame, write_frame};
use riftengine_core::redirect::{Redirector, normalise};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

use crate::gate::{game_link_time, module_path, process_age_ms};
use crate::hook::{self, HookState};
use crate::pipe::{self, TimeoutReader};
use crate::trace;

const HELLO_TIMEOUT: Duration = Duration::from_secs(3);

pub fn start() {
    // SAFETY: trivial Win32 getter.
    let own_pid = unsafe { GetCurrentProcessId() };
    // No pipe for this pid means no host asked for a session: stay inert.
    let mut pipe = match pipe::connect(own_pid) {
        Ok(pipe) => pipe,
        Err(error) => return trace::note(&format!("no engine pipe for pid {own_pid}: {error}")),
    };
    if let Err(reason) = establish(&pipe, own_pid) {
        trace::note(&format!("session refused: {reason}"));
        let _ = write_frame(&mut pipe, &DllMsg::Refused { reason });
    }
}

fn same_folder(a: &Path, b: &Path) -> bool {
    normalise(&a.to_string_lossy()) == normalise(&b.to_string_lossy())
}

fn establish(pipe: &File, own_pid: u32) -> Result<(), String> {
    let hello: Hello = read_frame(&mut TimeoutReader::new(pipe, HELLO_TIMEOUT))
        .map_err(|e| format!("handshake: {e}"))?;
    hello.check(own_pid).map_err(|e| e.to_string())?;

    // The rules reach only so far past the game they were reviewed against. This reads the image
    // the process runs, so neither the host nor the disk has a say in it.
    let linked = game_link_time().map_err(|e| format!("cannot read the game's build time: {e}"))?;
    riftengine_rules::check_build(linked).map_err(|e| format!("the game {e}"))?;

    // The host must be the process serving this pipe, and must be installed beside this DLL.
    let server = pipe::server_pid(pipe).map_err(|e| format!("pipe server: {e}"))?;
    if server != hello.host_pid {
        return Err(format!("pipe is served by pid {server}, handshake names {}", hello.host_pid));
    }
    let host_image = pipe::process_image(server).map_err(|e| format!("host image: {e}"))?;
    let dll_path = module_path(crate::module_handle()).ok_or("cannot locate this DLL")?;
    let (Some(host_dir), Some(dll_dir)) = (host_image.parent(), dll_path.parent()) else {
        return Err("cannot compare host and DLL folders".into());
    };
    if !same_folder(host_dir, dll_dir) {
        return Err(format!("host {} is not installed beside this DLL", host_image.display()));
    }

    // The game must be the one the host prepared the overlay for, and still early in its start.
    let exe = module_path(core::ptr::null_mut()).ok_or("cannot locate the game executable")?;
    let exe_dir = exe.parent().ok_or("the game executable has no folder")?;
    if !same_folder(exe_dir, Path::new(&hello.game_root)) {
        return Err("handshake game folder is not this game's folder".into());
    }
    let age = process_age_ms().ok_or("cannot read the game's start time")?;
    if age > hello.max_process_age_ms {
        return Err(format!("joined too late: the game has been running for {age} ms"));
    }

    // The overlay must be exactly what the host validated, under the rules this DLL carries, and
    // for the build of the game that is running.
    let rules = riftengine_rules::digest();
    if hello.rules_digest != rules {
        return Err("host and DLL were built with different rule sets".into());
    }
    let overlay_root = Path::new(&hello.overlay_root);
    let (manifest, manifest_digest) = OverlayManifest::load(overlay_root).map_err(|e| e.to_string())?;
    if manifest_digest != hello.manifest_digest {
        return Err("the manifest changed after the host prepared the handshake".into());
    }
    if manifest.rules_digest != rules {
        return Err("the overlay was validated under a different rule set".into());
    }
    riftengine_rules::check_overlay_build(manifest.game_linked, linked).map_err(|e| e.to_string())?;
    manifest.verify_against_disk(overlay_root).map_err(|e| e.to_string())?;

    let sink = pipe.try_clone().map_err(|e| format!("pipe handle: {e}"))?;
    let hooks = hook::install(HookState {
        redirector: Redirector::new(exe_dir, overlay_root, &manifest.files),
        dry_run: hello.flags & flags::DRY_RUN != 0,
        sink: Mutex::new(Some(sink)),
    })?;

    let mut reply = pipe.try_clone().map_err(|e| format!("pipe handle: {e}"))?;
    write_frame(&mut reply, &DllMsg::Ready {
        dll_version: env!("CARGO_PKG_VERSION").to_string(),
        hooks,
        files: manifest.files.len() as u32,
    })
    .map_err(|e| format!("reply: {e}"))
}
