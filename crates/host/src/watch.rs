//! Finds running game processes that belong to a given install folder.

use std::io;
use std::path::{Path, PathBuf};

use riftengine_core::proto::GAME_EXE_NAME;
use riftengine_core::redirect::normalise;
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameProcess {
    pub pid: u32,
    pub image: PathBuf,
    pub age_ms: u64,
}

pub fn filetime_u64(t: &FILETIME) -> u64 {
    (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
}

pub fn now_filetime() -> u64 {
    let mut now = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    // SAFETY: valid out-pointer.
    unsafe { GetSystemTimeAsFileTime(&mut now) };
    filetime_u64(&now)
}

/// Owns a process handle opened for querying.
struct Process(HANDLE);

impl Process {
    fn open(pid: u32) -> io::Result<Self> {
        // SAFETY: plain Win32 call; the handle is closed in `Drop`.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    fn image(&self) -> io::Result<PathBuf> {
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        // SAFETY: the buffer is valid for `len` units.
        if unsafe { QueryFullProcessImageNameW(self.0, 0, buf.as_mut_ptr(), &mut len) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
    }

    fn age_ms(&self) -> io::Result<u64> {
        let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        // SAFETY: valid out-pointers.
        if unsafe { GetProcessTimes(self.0, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(now_filetime().saturating_sub(filetime_u64(&created)) / 10_000)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: the handle came from `OpenProcess` and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Game processes whose executable is `League of Legends.exe` inside `game_dir`.
pub fn find_games(game_dir: &Path) -> io::Result<Vec<GameProcess>> {
    let wanted = normalise(&game_dir.to_string_lossy());
    // SAFETY: the snapshot handle is closed below; `entry` is sized as the API requires.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut games = Vec::new();
        let mut entry: PROCESSENTRY32W = core::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot, &mut entry) != 0;
        while more {
            let name_len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);
            if name.eq_ignore_ascii_case(GAME_EXE_NAME)
                && let Ok(process) = Process::open(entry.th32ProcessID)
                && let (Ok(image), Ok(age_ms)) = (process.image(), process.age_ms())
                && image.parent().is_some_and(|dir| normalise(&dir.to_string_lossy()) == wanted)
            {
                games.push(GameProcess { pid: entry.th32ProcessID, image, age_ms });
            }
            more = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
        Ok(games)
    }
}
