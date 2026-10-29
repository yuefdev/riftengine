//! File-open redirection: patches the game's import table entries for `CreateFileA`/`CreateFileW`.
//!
//! Only opens that the manifest-backed [`Redirector`] knows are touched. Every other call, and
//! every open that is not a plain read, goes to the original function untouched. A panic in the
//! redirect logic falls back to the original call.

use core::ffi::c_void;
use core::mem::transmute;
use core::ptr::{null, null_mut};
use std::fs::File;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use riftengine_core::proto::{DllMsg, write_frame};
use riftengine_core::redirect::Redirector;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Globalization::{CP_ACP, MultiByteToWideChar};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{PAGE_READWRITE, VirtualProtect};

type CreateFileA = unsafe extern "system" fn(
    *const u8, u32, u32, *const SECURITY_ATTRIBUTES, u32, u32, HANDLE,
) -> HANDLE;
type CreateFileW = unsafe extern "system" fn(
    *const u16, u32, u32, *const SECURITY_ATTRIBUTES, u32, u32, HANDLE,
) -> HANDLE;

pub struct HookState {
    pub redirector: Redirector,
    pub dry_run: bool,
    /// Where redirects are reported; dropped the first time a write fails.
    pub sink: Mutex<Option<File>>,
}

static STATE: OnceLock<HookState> = OnceLock::new();
static NEXT_A: AtomicUsize = AtomicUsize::new(0);
static NEXT_W: AtomicUsize = AtomicUsize::new(0);
static REPORTED: AtomicU32 = AtomicU32::new(0);
const MAX_REPORTS: u32 = 256;

const OPEN_EXISTING: u32 = 3;
/// Rights a plain read needs. An open that asks for anything else is never redirected.
const READ_RIGHTS: u32 = 0x8000_0000 // GENERIC_READ
    | 0x0000_0001 // FILE_READ_DATA
    | 0x0000_0008 // FILE_READ_EA
    | 0x0000_0020 // FILE_EXECUTE
    | 0x0000_0080 // FILE_READ_ATTRIBUTES
    | 0x0002_0000 // READ_CONTROL
    | 0x0010_0000; // SYNCHRONIZE

/// Installs the hooks and returns the names of the functions that were patched.
pub fn install(state: HookState) -> Result<Vec<String>, String> {
    if STATE.set(state).is_err() {
        return Err("hooks are already installed".into());
    }
    let mut installed = Vec::new();
    // SAFETY: walks and patches the import table of our own process image.
    unsafe {
        let exe = GetModuleHandleW(null());
        let kernel32: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let real_w = GetProcAddress(GetModuleHandleW(kernel32.as_ptr()), c"CreateFileW".as_ptr().cast());
        // The A hook serves redirects through W, so W's target must be known even if the game
        // does not import it.
        NEXT_W.store(real_w.map_or(0, |f| f as usize), Ordering::Release);

        if let Some(slot) = find_import(exe, b"CreateFileA") {
            NEXT_A.store(swap_slot(slot, hook_a as *const () as usize)?, Ordering::Release);
            installed.push("CreateFileA".to_string());
        }
        if let Some(slot) = find_import(exe, b"CreateFileW") {
            NEXT_W.store(swap_slot(slot, hook_w as *const () as usize)?, Ordering::Release);
            installed.push("CreateFileW".to_string());
        }
    }
    if installed.is_empty() {
        return Err("the game does not import CreateFileA or CreateFileW".into());
    }
    if NEXT_W.load(Ordering::Acquire) == 0 {
        return Err("CreateFileW could not be resolved".into());
    }
    Ok(installed)
}

fn wants_redirect(access: u32, disposition: u32) -> bool {
    disposition == OPEN_EXISTING && access & !READ_RIGHTS == 0
}

unsafe extern "system" fn hook_a(
    name: *const u8,
    access: u32,
    share: u32,
    security: *const SECURITY_ATTRIBUTES,
    disposition: u32,
    attributes: u32,
    template: HANDLE,
) -> HANDLE {
    if !name.is_null() && wants_redirect(access, disposition) {
        let served = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: the caller promises a NUL-terminated ANSI string, as CreateFileA requires.
            let requested = unsafe { ansi_to_wide(name) };
            serve(&requested, access, share, security, disposition, attributes, template)
        }));
        if let Ok(Some(handle)) = served {
            return handle;
        }
    }
    // SAFETY: NEXT_A holds the import table's original value, set before the patch went live.
    unsafe { transmute::<usize, CreateFileA>(NEXT_A.load(Ordering::Acquire))(
        name, access, share, security, disposition, attributes, template,
    ) }
}

unsafe extern "system" fn hook_w(
    name: *const u16,
    access: u32,
    share: u32,
    security: *const SECURITY_ATTRIBUTES,
    disposition: u32,
    attributes: u32,
    template: HANDLE,
) -> HANDLE {
    if !name.is_null() && wants_redirect(access, disposition) {
        let served = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: the caller promises a NUL-terminated UTF-16 string, as CreateFileW requires.
            let requested = unsafe { read_wide(name) };
            serve(&requested, access, share, security, disposition, attributes, template)
        }));
        if let Ok(Some(handle)) = served {
            return handle;
        }
    }
    // SAFETY: NEXT_W holds the import table's original value, set before the patch went live.
    unsafe { transmute::<usize, CreateFileW>(NEXT_W.load(Ordering::Acquire))(
        name, access, share, security, disposition, attributes, template,
    ) }
}

/// Opens the overlay copy in place of the requested file. `None` means "let the original run".
fn serve(
    requested: &[u16],
    access: u32,
    share: u32,
    security: *const SECURITY_ATTRIBUTES,
    disposition: u32,
    attributes: u32,
    template: HANDLE,
) -> Option<HANDLE> {
    let state = STATE.get()?;
    let target = state.redirector.lookup_wide(requested)?;
    let requested_text = String::from_utf16_lossy(requested);
    if state.dry_run {
        report(state, DllMsg::Redirected {
            requested: requested_text,
            served: format!("(dry run) {}", target.display),
        });
        return None;
    }
    // SAFETY: NEXT_W is the real CreateFileW; `target.wide` is NUL-terminated.
    let handle = unsafe {
        transmute::<usize, CreateFileW>(NEXT_W.load(Ordering::Acquire))(
            target.wide.as_ptr(), access, share, security, disposition, attributes, template,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        report(state, DllMsg::Log {
            level: 2,
            text: format!("could not open {}: {err}; serving the original", target.display),
        });
        return None;
    }
    report(state, DllMsg::Redirected { requested: requested_text, served: target.display.clone() });
    Some(handle)
}

fn report(state: &HookState, msg: DllMsg) {
    if REPORTED.fetch_add(1, Ordering::Relaxed) >= MAX_REPORTS {
        return;
    }
    let mut sink = state.sink.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(file) = sink.as_mut()
        && write_frame(file, &msg).is_err()
    {
        *sink = None;
    }
}

/// # Safety
/// `ptr` must point at a NUL-terminated ANSI string.
unsafe fn ansi_to_wide(ptr: *const u8) -> Vec<u16> {
    // SAFETY: per the contract above; the first call only measures.
    let len = unsafe { MultiByteToWideChar(CP_ACP, 0, ptr, -1, null_mut(), 0) };
    if len <= 0 {
        return Vec::new();
    }
    let mut out = vec![0u16; len as usize];
    // SAFETY: `out` holds `len` units.
    unsafe { MultiByteToWideChar(CP_ACP, 0, ptr, -1, out.as_mut_ptr(), len) };
    out.pop(); // the trailing NUL
    out
}

/// # Safety
/// `ptr` must point at a NUL-terminated UTF-16 string.
unsafe fn read_wide(ptr: *const u16) -> Vec<u16> {
    let mut out = Vec::new();
    for i in 0..32 * 1024 {
        // SAFETY: reads up to and including the terminator the caller guarantees.
        let unit = unsafe { ptr.add(i).read_unaligned() };
        if unit == 0 {
            break;
        }
        out.push(unit);
    }
    out
}

/// Reads a value of type `T` at `base + offset`.
///
/// # Safety
/// The range must lie inside the mapped image.
unsafe fn read_at<T: Copy>(base: *const u8, offset: usize) -> T {
    // SAFETY: per the contract above.
    unsafe { base.add(offset).cast::<T>().read_unaligned() }
}

fn is_kernel_dll(name: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    [&b"kernel32"[..], b"kernelbase", b"api-ms-win-core-file"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Finds the import table slot for `function` among the kernel DLLs `module` imports from.
///
/// # Safety
/// `module` must be the base of a mapped PE32+ image.
unsafe fn find_import(module: *mut c_void, function: &[u8]) -> Option<*mut usize> {
    let base = module as *const u8;
    // SAFETY: header offsets are validated by the magic checks before use.
    unsafe {
        if read_at::<u16>(base, 0) != 0x5A4D {
            return None;
        }
        let nt = read_at::<i32>(base, 0x3C) as usize;
        if read_at::<u32>(base, nt) != 0x0000_4550 || read_at::<u16>(base, nt + 24) != 0x20B {
            return None;
        }
        // DataDirectory[IMPORT] starts 112 + 8 bytes into the PE32+ optional header.
        let mut descriptor = read_at::<u32>(base, nt + 24 + 112 + 8) as usize;
        if descriptor == 0 {
            return None;
        }
        for _ in 0..1024 {
            let lookup_rva = read_at::<u32>(base, descriptor) as usize;
            let name_rva = read_at::<u32>(base, descriptor + 12) as usize;
            let address_rva = read_at::<u32>(base, descriptor + 16) as usize;
            if name_rva == 0 && address_rva == 0 {
                return None;
            }
            let dll_name = c_str(base.add(name_rva));
            if is_kernel_dll(dll_name) {
                let names = if lookup_rva != 0 { lookup_rva } else { address_rva };
                for i in 0..16 * 1024 {
                    let entry = read_at::<u64>(base, names + i * 8);
                    if entry == 0 {
                        break;
                    }
                    if entry >> 63 == 0 && c_str(base.add((entry & 0x7FFF_FFFF) as usize + 2)) == function {
                        return Some(base.add(address_rva + i * 8) as *mut usize);
                    }
                }
            }
            descriptor += 20;
        }
    }
    None
}

/// # Safety
/// `ptr` must point at a NUL-terminated string.
unsafe fn c_str<'a>(ptr: *const u8) -> &'a [u8] {
    // SAFETY: per the contract above.
    unsafe { core::ffi::CStr::from_ptr(ptr.cast()).to_bytes() }
}

/// Atomically replaces an import table entry and returns what it held.
///
/// # Safety
/// `slot` must be an import table entry of this process.
unsafe fn swap_slot(slot: *mut usize, new: usize) -> Result<usize, String> {
    let mut old_protection = 0;
    // SAFETY: per the contract above; protection is restored before returning.
    unsafe {
        if VirtualProtect(slot.cast(), size_of::<usize>(), PAGE_READWRITE, &mut old_protection) == 0 {
            return Err(format!("VirtualProtect failed: {}", std::io::Error::last_os_error()));
        }
        let previous = AtomicUsize::from_ptr(slot).swap(new, Ordering::SeqCst);
        let mut ignored = 0;
        VirtualProtect(slot.cast(), size_of::<usize>(), old_protection, &mut ignored);
        Ok(previous)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_reads_of_existing_files_are_redirected() {
        assert!(wants_redirect(0x8000_0000, OPEN_EXISTING)); // GENERIC_READ
        assert!(wants_redirect(0x0012_0089, OPEN_EXISTING)); // FILE_GENERIC_READ
        assert!(!wants_redirect(0x8000_0000, 2)); // CREATE_ALWAYS
        assert!(!wants_redirect(0x4000_0000, OPEN_EXISTING)); // GENERIC_WRITE
        assert!(!wants_redirect(0x8000_0000 | 0x4000_0000, OPEN_EXISTING));
        assert!(!wants_redirect(0x0001_0000, OPEN_EXISTING)); // DELETE
    }

    #[test]
    fn kernel_dll_names() {
        assert!(is_kernel_dll(b"KERNEL32.dll"));
        assert!(is_kernel_dll(b"api-ms-win-core-file-l1-1-0.dll"));
        assert!(!is_kernel_dll(b"user32.dll"));
    }
}
