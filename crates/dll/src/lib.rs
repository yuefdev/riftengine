//! In-game half of RiftEngine.
//!
//! The host loads this DLL into `League of Legends.exe` with a `WH_GETMESSAGE` hook that points
//! at [`riftengine_hookproc`]. `DllMain` only decides whether this process is the game and pins the
//! module; the rest runs from the hook procedure, outside the loader lock, on the game's own
//! message thread. In any other process the DLL does nothing.
#![cfg(windows)]

mod gate;
mod hook;
mod pipe;
mod session;
mod trace;

use core::ffi::c_void;
use core::ptr::null_mut;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use windows_sys::Win32::Foundation::{HMODULE, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::{
    DisableThreadLibraryCalls, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_PIN, GetModuleHandleExW,
};
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::UI::WindowsAndMessaging::CallNextHookEx;

/// Handle of this DLL, kept so the session can find the folder it was loaded from.
static MODULE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static IN_GAME: AtomicBool = AtomicBool::new(false);
static INIT: Once = Once::new();

/// # Safety
/// Called by the Windows loader with the usual `DllMain` arguments.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(module: HMODULE, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        MODULE.store(module, Ordering::Release);
        // SAFETY: plain Win32 calls on our own module handle; nothing here loads other modules.
        unsafe {
            DisableThreadLibraryCalls(module);
            if gate::is_game_process() {
                IN_GAME.store(true, Ordering::Release);
                // The hook that loaded us is removed once the host is done; stay mapped.
                let mut pinned: HMODULE = null_mut();
                GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                    DllMain as *const () as *const u16,
                    &mut pinned,
                );
                trace::mark_loaded(GetCurrentProcessId());
            }
        }
    }
    1
}

/// `WH_GETMESSAGE` hook procedure. The first call in the game starts the session; every call
/// then passes straight on to the next hook.
///
/// # Safety
/// Called by Windows with the usual hook arguments.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn riftengine_hookproc(
    code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if IN_GAME.load(Ordering::Acquire) {
        INIT.call_once(|| {
            trace::note("hook procedure is running in the game");
            let _ = std::panic::catch_unwind(session::start);
        });
    }
    // SAFETY: forwards the arguments we were given.
    unsafe { CallNextHookEx(null_mut(), code, wparam, lparam) }
}

pub(crate) fn module_handle() -> HMODULE {
    MODULE.load(Ordering::Acquire)
}
