//! Stand-in for the game process, used only by the end-to-end tests.
//!
//! It owns a hidden window and pumps messages like the real game's main thread, and opens files
//! through `CreateFileA`/`CreateFileW` (imported by name from kernel32, as the game does) when
//! told to on stdin: `a <path>`, `w <path>` or `quit`. `stamp <seconds>` changes the link time in
//! its own headers, to pass for a game of another build.

use std::ffi::CString;
use std::io::{BufRead, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use riftengine_core::pe;
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileA, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING, ReadFile,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{PAGE_READWRITE, VirtualProtect};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, TranslateMessage, WS_POPUP,
};

fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn open_and_read(kind: &str, path: &str) -> String {
    // SAFETY: the path buffers outlive the calls and the handle is closed before returning.
    unsafe {
        let handle = match kind {
            "a" => {
                let Ok(c_path) = CString::new(path) else { return "RESULT a ERR bad-path".into() };
                CreateFileA(
                    c_path.as_ptr().cast(),
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    core::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    core::ptr::null_mut(),
                )
            }
            _ => {
                let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    core::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    core::ptr::null_mut(),
                )
            }
        };
        if handle == INVALID_HANDLE_VALUE {
            return format!("RESULT {kind} ERR {}", std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        let mut buf = [0u8; 64];
        let mut read = 0u32;
        ReadFile(handle, buf.as_mut_ptr().cast(), buf.len() as u32, &mut read, core::ptr::null_mut());
        CloseHandle(handle);
        let text = String::from_utf8_lossy(&buf[..read as usize]).replace(['\r', '\n'], " ");
        format!("RESULT {kind} OK {text}")
    }
}

/// Makes the headers of the running image say it was linked at `time` (seconds, in decimal), as
/// the image of another game build would. The DLL reads them there; the host's look at the file on
/// disk does not see the change.
fn restamp(time: &str) -> String {
    let Ok(time) = time.trim().parse::<u32>() else { return "RESULT stamp ERR bad-time".into() };
    // SAFETY: the headers of our own image are mapped at the module base. Their page is read-only,
    // so it is made writable for the four bytes and put back.
    unsafe {
        let base = GetModuleHandleW(core::ptr::null()).cast::<u8>();
        let head = core::slice::from_raw_parts(base, pe::HEAD_BYTES);
        let Ok(at) = pe::link_time_offset(head) else { return "RESULT stamp ERR not-a-pe".into() };
        let field = base.add(at);
        let mut before = 0;
        if VirtualProtect(field.cast::<core::ffi::c_void>(), 4, PAGE_READWRITE, &mut before) == 0 {
            return "RESULT stamp ERR protect".into();
        }
        field.cast::<u32>().write_unaligned(time);
        VirtualProtect(field.cast::<core::ffi::c_void>(), 4, before, &mut before);
    }
    "RESULT stamp OK".into()
}

fn main() {
    let class: Vec<u16> = "STATIC\0".encode_utf16().collect();
    let title: Vec<u16> = "fake game\0".encode_utf16().collect();
    // SAFETY: standard window creation; the window is never shown.
    let window = unsafe {
        CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_POPUP,
            0,
            0,
            1,
            1,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null(),
        )
    };
    assert!(!window.is_null(), "could not create the hidden window");
    // SAFETY: trivial getters.
    say(&format!("READY pid={} tid={}", unsafe { GetCurrentProcessId() }, unsafe { GetCurrentThreadId() }));

    let (commands, lines) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            if commands.send(line).is_err() {
                break;
            }
        }
    });

    loop {
        // SAFETY: MSG is plain data; this is the usual message pump.
        unsafe {
            let mut msg: MSG = core::mem::zeroed();
            while PeekMessageW(&mut msg, core::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        match lines.recv_timeout(Duration::from_millis(5)) {
            Ok(line) => {
                let (command, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
                match command {
                    "a" | "w" => say(&open_and_read(command, rest)),
                    "stamp" => say(&restamp(rest)),
                    "quit" => break,
                    other => say(&format!("RESULT {other} ERR unknown-command")),
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}
