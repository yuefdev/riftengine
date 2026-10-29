//! Client end of the per-game pipe.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use riftengine_core::proto::pipe_name;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_BROKEN_PIPE};
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, PeekNamedPipe};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

pub fn connect(game_pid: u32) -> io::Result<File> {
    OpenOptions::new().read(true).write(true).open(pipe_name(game_pid))
}

pub fn server_pid(pipe: &File) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: the handle is owned by `pipe`; `pid` is a valid out-pointer.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

pub fn process_image(pid: u32) -> io::Result<PathBuf> {
    // SAFETY: the process handle is closed below; the buffer outlives the call.
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(process, 0, buf.as_mut_ptr(), &mut len);
        let err = io::Error::last_os_error();
        CloseHandle(process);
        if ok == 0 {
            return Err(err);
        }
        Ok(PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
    }
}

/// Reads from a pipe without ever blocking past a deadline, so a stalled host cannot freeze the
/// game's message thread.
pub struct TimeoutReader<'a> {
    pipe: &'a File,
    deadline: Instant,
}

impl<'a> TimeoutReader<'a> {
    pub fn new(pipe: &'a File, timeout: Duration) -> Self {
        Self { pipe, deadline: Instant::now() + timeout }
    }
}

impl Read for TimeoutReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut available = 0u32;
            // SAFETY: only the `available` out-pointer is supplied.
            let ok = unsafe {
                PeekNamedPipe(
                    self.pipe.as_raw_handle(),
                    core::ptr::null_mut(),
                    0,
                    core::ptr::null_mut(),
                    &mut available,
                    core::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = io::Error::last_os_error();
                return if err.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                    Ok(0)
                } else {
                    Err(err)
                };
            }
            if available > 0 {
                let n = buf.len().min(available as usize);
                return (&*self.pipe).read(&mut buf[..n]);
            }
            if Instant::now() >= self.deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
