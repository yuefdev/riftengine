//! The host's end of the per-game pipe. Only the current user can open it, and only one DLL
//! session can connect.

use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

/// SID of the user this process runs as, in `S-1-5-21-...` form.
fn current_user_sid() -> io::Result<String> {
    // SAFETY: every buffer is sized by the preceding length query; the token and the SID string
    // are released before returning.
    unsafe {
        let mut token: HANDLE = core::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            let mut needed = 0u32;
            GetTokenInformation(token, TokenUser, core::ptr::null_mut(), 0, &mut needed);
            let mut buf = vec![0u8; needed as usize];
            if GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), needed, &mut needed) == 0 {
                return Err(io::Error::last_os_error());
            }
            let user = buf.as_ptr().cast::<TOKEN_USER>().read_unaligned();
            let mut text: *mut u16 = core::ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0;
            while *text.add(len) != 0 {
                len += 1;
            }
            let sid = String::from_utf16_lossy(core::slice::from_raw_parts(text, len));
            LocalFree(text.cast());
            Ok(sid)
        })();
        CloseHandle(token);
        result
    }
}

/// A pipe instance that exists but has no client yet.
pub struct PipeServer {
    handle: OwnedHandle,
}

impl PipeServer {
    /// Creates the pipe. Fails if the name is already taken, so a squatter cannot pre-empt us.
    pub fn create(name: &str) -> io::Result<Self> {
        let sddl = wide(&format!("D:P(A;;GA;;;{})", current_user_sid()?));
        let mut descriptor: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
        // SAFETY: `descriptor` is freed after the pipe has copied it.
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                core::ptr::null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let pipe = CreateNamedPipeW(
                wide(name).as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                0,
                &attributes,
            );
            let error = io::Error::last_os_error();
            LocalFree(descriptor);
            if pipe == INVALID_HANDLE_VALUE {
                return Err(error);
            }
            Ok(Self { handle: OwnedHandle::from_raw_handle(pipe) })
        }
    }

    /// Starts waiting for the DLL to connect.
    pub fn accept(self) -> Accepting {
        let raw = self.handle.as_raw_handle() as usize;
        let (done, wait) = mpsc::channel();
        let worker = thread::spawn(move || {
            // SAFETY: `raw` stays valid because `Accepting` owns the handle until the worker ends.
            let ok = unsafe { ConnectNamedPipe(raw as HANDLE, core::ptr::null_mut()) };
            let result = if ok != 0 || io::Error::last_os_error().raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32) {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            };
            let _ = done.send(result);
        });
        Accepting { handle: Some(self.handle), worker: Some(worker), wait }
    }
}

pub struct Accepting {
    handle: Option<OwnedHandle>,
    worker: Option<JoinHandle<()>>,
    wait: mpsc::Receiver<io::Result<()>>,
}

impl Accepting {
    /// Waits for the DLL; on timeout the pending connect is cancelled and the pipe closed.
    pub fn wait(mut self, timeout: Duration) -> io::Result<File> {
        let result = match self.wait.recv_timeout(timeout) {
            Ok(result) => result,
            Err(_) => {
                self.cancel();
                Err(io::Error::new(io::ErrorKind::TimedOut, "the game did not connect to the engine pipe"))
            }
        };
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        result?;
        Ok(File::from(self.handle.take().expect("handle is present until accepted")))
    }

    fn cancel(&mut self) {
        let Some(worker) = &self.worker else { return };
        // The worker may not have entered ConnectNamedPipe yet, so keep cancelling until it ends.
        for _ in 0..100 {
            // SAFETY: the thread handle is valid while the JoinHandle exists.
            unsafe { CancelSynchronousIo(worker.as_raw_handle() as HANDLE) };
            if self.wait.recv_timeout(Duration::from_millis(20)).is_ok() {
                break;
            }
        }
    }
}

impl Drop for Accepting {
    fn drop(&mut self) {
        if self.worker.is_some() {
            self.cancel();
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }
}
