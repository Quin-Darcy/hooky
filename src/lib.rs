use std::arch::asm;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::iter::once;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

extern crate winapi;
use winapi::shared::minwindef::HINSTANCE__;
use winapi::shared::minwindef::{BOOL, DWORD, FARPROC, HINSTANCE, LPARAM, UINT, WPARAM};
use winapi::shared::windef::{HWND, POINT};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::{FreeLibraryAndExitThread, GetModuleHandleW};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect};
use winapi::um::winnt::{MEM_COMMIT, PAGE_EXECUTE_READWRITE};
use winapi::um::winuser::{MapVirtualKeyW, LPMSG, WM_KEYDOWN};

extern crate simplelog;
use simplelog::*;

extern crate log;
use log::{error, info, warn};

use time::macros::format_description;

const target_module_name: &str = "USER32.dll";
const target_function_name: &str = "GetMessageW";
const NUM_STOLEN_BYTES: usize = 18;
const CLEANUP_FILE_PATH: &str = "C:\\Users\\User\\Music\\test.txt";

static TRAMPOLINE_FUNC: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(hinst_dll: *mut HINSTANCE__, fdw_reason: u32, _: usize) -> bool {
    todo!()
}

fn setup() -> Result<HookState, DWORD> {
    todo!()
}

fn cleanup(hook_state: Arc<Mutex<HookState>>, safe_hinst_dll: SafeHINSTANCE) {
    todo!()
}

fn install_hook(hook_state: Arc<Mutex<HookState>>) {
    todo!()
}

fn get_target_func_addr() -> Result<*const u8, DWORD> {
    todo!()
}

fn create_trampoline(
    stolen_bytes: &[u8; NUM_STOLEN_BYTES],
    target_func_addr: *const u8,
) -> Result<*mut u8, DWORD> {
    todo!()
}

pub fn set_hook(target_func_addr: *const u8, hook_func_addr: *mut u8) -> Result<(), DWORD> {
    todo!()
}

#[no_mangle]
pub extern "system" fn hook_func(
    lpMsg: LPMSG,
    hWnd: HWND,
    wMsgFilterMin: UINT,
    wMsgFilterMax: UINT,
) -> BOOL {
    // Fetch the trampoline function from the global variable
    let trampoline: extern "system" fn(LPMSG, HWND, UINT, UINT) -> BOOL =
        unsafe { std::mem::transmute(TRAMPOLINE_FUNC.load(Ordering::SeqCst)) };

    trampoline(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax)
}

fn get_last_error() -> Option<String> {
    let error_code = unsafe { GetLastError() };

    if error_code == 0 {
        None
    } else {
        let mut buffer: Vec<u16> = Vec::with_capacity(256);
        buffer.resize(buffer.capacity(), 0);
        let len = unsafe {
            winapi::um::winbase::FormatMessageW(
                winapi::um::winbase::FORMAT_MESSAGE_FROM_SYSTEM
                    | winapi::um::winbase::FORMAT_MESSAGE_IGNORE_INSERTS,
                ptr::null(),
                error_code,
                0,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                ptr::null_mut(),
            )
        };
        buffer.resize(len as usize, 0);
        Some(OsString::from_wide(&buffer).to_string_lossy().into_owned())
    }
}

struct SafeHINSTANCE(*mut HINSTANCE__);
unsafe impl Send for SafeHINSTANCE {}

struct SafePtr(*const u8);
unsafe impl Send for SafePtr {}
unsafe impl Sync for SafePtr {}

struct HookState {
    stolen_bytes: [u8; NUM_STOLEN_BYTES],
    target_func_addr: SafePtr,
    trampoline_func_addr: SafePtr,
}

struct MSG {
    hwnd: HWND,
    message: UINT,
    wParam: WPARAM,
    lParam: LPARAM,
    time: DWORD,
    pt: POINT,
}
