//! Breadcrumbs for the cases where the pipe to the host cannot carry the reason.

use core::ptr::null;

use riftengine_core::proto::loaded_event_name;
use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW;
use windows_sys::Win32::System::Threading::CreateEventW;

/// Debug output: it reaches a debugger or DebugView and nothing else.
pub fn note(text: &str) {
    let line: Vec<u16> = format!("riftengine-dll: {text}\0").encode_utf16().collect();
    // SAFETY: `line` is NUL-terminated and outlives the call.
    unsafe { OutputDebugStringW(line.as_ptr()) };
}

/// Creates the named event that tells the host this DLL has been loaded into the game. It is
/// never closed, so it lasts as long as the process does.
pub fn mark_loaded(game_pid: u32) {
    let name: Vec<u16> = loaded_event_name(game_pid).encode_utf16().chain(Some(0)).collect();
    // SAFETY: `name` is NUL-terminated and outlives the call.
    unsafe { CreateEventW(null(), 1, 0, name.as_ptr()) };
}
