//! Facts about the process we were loaded into.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use riftengine_core::pe;
use riftengine_core::proto::GAME_EXE_NAME;
use windows_sys::Win32::Foundation::{FILETIME, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

/// Full path of a loaded module; a null handle means the process executable.
pub fn module_path(module: HMODULE) -> Option<PathBuf> {
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: the buffer is valid for `buf.len()` UTF-16 units.
        let len = unsafe { GetModuleFileNameW(module, buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if len == 0 {
            return None;
        }
        if len < buf.len() {
            return Some(PathBuf::from(OsString::from_wide(&buf[..len])));
        }
        if buf.len() >= 32 * 1024 {
            return None;
        }
        buf.resize(buf.len() * 2, 0);
    }
}

pub fn is_game_process() -> bool {
    module_path(core::ptr::null_mut())
        .and_then(|path| path.file_name().map(|n| n.to_string_lossy().into_owned()))
        .is_some_and(|name| name.eq_ignore_ascii_case(GAME_EXE_NAME))
}

/// When the game's executable was linked, read from the headers of the image this process runs:
/// not from what the host says, and not from the file on disk. The hooks walk the same headers
/// for the import table, so they have to be there anyway.
pub fn game_link_time() -> Result<u32, String> {
    // SAFETY: a null name asks for the process executable, and the first page of a loaded image
    // holds its headers.
    let head = unsafe {
        let base = GetModuleHandleW(core::ptr::null());
        if base.is_null() {
            return Err("the process has no executable module".into());
        }
        core::slice::from_raw_parts(base.cast::<u8>(), pe::HEAD_BYTES)
    };
    pe::link_time(head).map_err(|error| format!("the executable {error}"))
}

fn filetime_u64(t: &FILETIME) -> u64 {
    (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
}

/// Milliseconds since this process was created.
pub fn process_age_ms() -> Option<u64> {
    let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    let mut now = zero;
    // SAFETY: all out-pointers are valid for the duration of the calls.
    let ok = unsafe {
        GetProcessTimes(GetCurrentProcess(), &mut created, &mut exited, &mut kernel, &mut user)
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: as above.
    unsafe { GetSystemTimeAsFileTime(&mut now) };
    filetime_u64(&now).checked_sub(filetime_u64(&created)).map(|ticks| ticks / 10_000)
}
