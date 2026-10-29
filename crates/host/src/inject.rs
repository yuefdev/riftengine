//! Gets the DLL into the game with a `WH_GETMESSAGE` hook on the game's window thread.
//!
//! This is the ordinary Windows hook mechanism: the system loads the DLL into the thread's
//! process the next time the thread reads a message. Nothing is hidden or disguised.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use riftengine_core::proto::loaded_event_name;
use windows_sys::Win32::Foundation::{
    CloseHandle, FILETIME, FreeLibrary, HMODULE, INVALID_HANDLE_VALUE, LPARAM, LRESULT, WPARAM,
};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Threading::{
    GetThreadTimes, OpenEventW, OpenThread, THREAD_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumThreadWindows, GetClassNameW, HHOOK, PostThreadMessageW, SetWindowsHookExW, UnhookWindowsHookEx,
    WH_GETMESSAGE, WM_NULL,
};

pub const HOOK_EXPORT: &[u8] = b"riftengine_hookproc\0";

type HookProc = unsafe extern "system" fn(i32, WPARAM, LPARAM) -> LRESULT;

/// Keeps the hook (and the host's copy of the DLL) alive; removes both on drop.
pub struct HookGuard {
    hook: HHOOK,
    module: HMODULE,
    thread_id: u32,
}

impl HookGuard {
    /// Wakes the thread so it reads a message, which is what makes the system load the DLL.
    pub fn nudge(&self) {
        // SAFETY: plain Win32 call.
        unsafe { PostThreadMessageW(self.thread_id, WM_NULL, 0, 0) };
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        // SAFETY: both handles were created in `install` and are released once.
        unsafe {
            UnhookWindowsHookEx(self.hook);
            FreeLibrary(self.module);
        }
    }
}

pub fn install(dll: &Path, thread_id: u32) -> io::Result<HookGuard> {
    let path: Vec<u16> = dll.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: handles are checked before use and released on every failure path.
    unsafe {
        let module = LoadLibraryW(path.as_ptr());
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        let Some(proc) = GetProcAddress(module, HOOK_EXPORT.as_ptr()) else {
            FreeLibrary(module);
            return Err(io::Error::new(io::ErrorKind::NotFound, "the DLL does not export riftengine_hookproc"));
        };
        let proc = core::mem::transmute::<unsafe extern "system" fn() -> isize, HookProc>(proc);
        let hook = SetWindowsHookExW(WH_GETMESSAGE, Some(proc), module, thread_id);
        if hook.is_null() {
            let err = io::Error::last_os_error();
            FreeLibrary(module);
            return Err(err);
        }
        let guard = HookGuard { hook, module, thread_id };
        guard.nudge();
        Ok(guard)
    }
}

/// Whether the DLL says it has been loaded into the game `pid`. The DLL marks itself on loading, so
/// a game that never loaded it can be told from one where the DLL never reached the pipe.
pub fn dll_loaded_in(pid: u32) -> bool {
    let name: Vec<u16> = loaded_event_name(pid).encode_utf16().chain(Some(0)).collect();
    // SAFETY: `name` is NUL-terminated; an event that was opened is closed again.
    unsafe {
        let event = OpenEventW(SYNCHRONIZE, 0, name.as_ptr());
        if event.is_null() {
            return false;
        }
        CloseHandle(event);
        true
    }
}

/// A thread of the game that owns a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowThread {
    pub id: u32,
    /// Class of the thread's first window; only for the log.
    pub class: String,
}

struct Windows {
    count: u32,
    first: *mut core::ffi::c_void,
}

unsafe extern "system" fn note_window(window: *mut core::ffi::c_void, found: LPARAM) -> i32 {
    // SAFETY: `found` points at the `Windows` passed to EnumThreadWindows below.
    let found = unsafe { &mut *(found as *mut Windows) };
    if found.count == 0 {
        found.first = window;
    }
    found.count += 1;
    1
}

fn class_of(window: *mut core::ffi::c_void) -> String {
    let mut name = [0u16; 128];
    // SAFETY: the buffer is valid for its length; asking for a class name sends no message.
    let len = unsafe { GetClassNameW(window, name.as_mut_ptr(), name.len() as i32) };
    String::from_utf16_lossy(&name[..len.max(0) as usize])
}

fn created_at(thread_id: u32) -> u64 {
    // SAFETY: the handle is closed before returning.
    unsafe {
        let thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, thread_id);
        if thread.is_null() {
            return u64::MAX;
        }
        let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        let ok = GetThreadTimes(thread, &mut created, &mut exited, &mut kernel, &mut user);
        CloseHandle(thread);
        if ok == 0 { u64::MAX } else { crate::watch::filetime_u64(&created) }
    }
}

/// The oldest thread of `pid` that owns a window; that is the game's message thread.
pub fn find_window_thread(pid: u32) -> io::Result<Option<WindowThread>> {
    // SAFETY: the snapshot is closed below; `entry` is sized as the API requires.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut best: Option<(u64, WindowThread)> = None;
        let mut entry: THREADENTRY32 = core::mem::zeroed();
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        let mut more = Thread32First(snapshot, &mut entry) != 0;
        while more {
            if entry.th32OwnerProcessID == pid {
                let mut windows = Windows { count: 0, first: core::ptr::null_mut() };
                EnumThreadWindows(entry.th32ThreadID, Some(note_window), &mut windows as *mut Windows as LPARAM);
                if windows.count > 0 {
                    let born = created_at(entry.th32ThreadID);
                    if best.as_ref().is_none_or(|(oldest, _)| born < *oldest) {
                        let thread = WindowThread { id: entry.th32ThreadID, class: class_of(windows.first) };
                        best = Some((born, thread));
                    }
                }
            }
            more = Thread32Next(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
        Ok(best.map(|(_, thread)| thread))
    }
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::System::Threading::CreateEventW;

    use super::*;

    #[test]
    fn marker_event_is_found_by_pid() {
        let pid = u32::MAX - 1;
        assert!(!dll_loaded_in(pid));
        let name: Vec<u16> = loaded_event_name(pid).encode_utf16().chain(Some(0)).collect();
        // SAFETY: `name` is NUL-terminated; the event is closed before the test ends.
        let event = unsafe { CreateEventW(core::ptr::null(), 1, 0, name.as_ptr()) };
        assert!(!event.is_null());
        assert!(dll_loaded_in(pid));
        assert!(!dll_loaded_in(pid - 1));
        // SAFETY: the handle was created above and is closed once.
        unsafe { CloseHandle(event) };
        assert!(!dll_loaded_in(pid));
    }
}
