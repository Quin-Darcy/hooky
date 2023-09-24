use std::ffi::{CString, OsString};
use std::fs::File;
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

extern crate winapi;
use winapi::shared::minwindef::HINSTANCE__;
use winapi::shared::minwindef::{BOOL, DWORD, FARPROC, UINT};
use winapi::shared::windef::HWND;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::{FreeLibraryAndExitThread, GetModuleHandleW};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect};
use winapi::um::winnt::{MEM_COMMIT, PAGE_EXECUTE_READWRITE};
use winapi::um::winuser::LPMSG;

extern crate simplelog;
use simplelog::*;

extern crate log;
use log::{error, info, warn};

use time::macros::format_description;

const TARGET_MODULE_NAME: &str = "USER32.dll";
const TARGET_FUNCTION_NAME: &str = "GetMessageW";
const NUM_STOLEN_BYTES: usize = 18;
const CLEANUP_FILE_PATH: &str = "C:\\Users\\User\\Music\\test.txt";
const LOG_PATH: &str = "C:\\Users\\Public\\hooker.log";

#[cfg(target_pointer_width = "32")]
const JMP_INSTRUCTION_SIZE: usize = 5;

#[cfg(target_pointer_width = "64")]
const JMP_INSTRUCTION_SIZE: usize = 14;

static TRAMPOLINE_FUNC: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

//=============== YOUR HOOK FUNCTION ==============//

#[no_mangle]
pub extern "system" fn YOUR_HOOK_FUNCTION_NAME(
    // TODO: Add your function arguments here.
) -> YOUR_RETURN_TYPE {
    // TODO: Define the trampoline function type here based on the original function you're hooking.
    let trampoline: YOUR_TRAMPOLINE_TYPE = unsafe { 
        std::mem::transmute(TRAMPOLINE_FUNC.load(Ordering::SeqCst)) 
    };

    // TODO: Add your hook logic here.

    // Example trampoline call; adjust arguments as needed
    trampoline(/* TODO: Add your arguments for the trampoline call here */)
}

//=================================================//

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(hinst_dll: *mut HINSTANCE__, fdw_reason: u32, _: usize) -> bool {
    // Create instance of SafeHINSTANCE
    let safe_hinst_dll = SafeHINSTANCE(hinst_dll);

    if fdw_reason == winapi::um::winnt::DLL_PROCESS_ATTACH {
        // Initialize the logger
        let config = ConfigBuilder::new()
            .set_time_format_custom(format_description!("[hour]:[minute]:[second].[subsecond]"))
            .build();

        let _ = WriteLogger::init(
            LevelFilter::Trace,
            config,
            File::create(LOG_PATH)
                .expect("Failed to initialize logger"),
        );

        info!("[{}] fwd_reason: {}", "DllMain", "DLL_PROCESS_ATTACH");
        info!(
            "[{}] Base address of the DLL: {:?}",
            "DllMain",
            hinst_dll.clone()
        );
        info!("[{}] Target module name: {}", "DllMain", TARGET_MODULE_NAME);
        info!(
            "[{}] Target function name: {}",
            "DllMain", TARGET_FUNCTION_NAME
        );

        // Setup the hook
        if let Ok(hook_state) = setup() {
            let hook_state_arc = Arc::new(Mutex::new(hook_state));

            // Thread for installing the hook
            info!("[{}] Spawning thread for hook installation", "DllMain");
            let hook_state_arc_clone1 = Arc::clone(&hook_state_arc);
            thread::spawn(move || install_hook(hook_state_arc_clone1));

            // Thread for unloading the Dll and uninstalling the hook
            info!("[{}] Spawning thread for cleanup", "DllMain");
            let hook_state_arc_clone2 = Arc::clone(&hook_state_arc);
            thread::spawn(move || cleanup(hook_state_arc_clone2, safe_hinst_dll));
        } else {
            error!("[{}] Failed to setup hook", "DllMain");
            return false;
        }
    }
    true
}

fn setup() -> Result<HookState, DWORD> {
    // Initialize HookState
    let mut hook_state = HookState {
        stolen_bytes: [0; NUM_STOLEN_BYTES],
        target_func_addr: SafePtr(ptr::null()),
        trampoline_func_addr: SafePtr(ptr::null_mut()),
    };

    // Get the address of the target function
    let target_func_addr: *const u8 = match get_target_func_addr() {
        Ok(addr) => addr,
        Err(err) => {
            error!(
                "[{}] Failed to get address of {}",
                "setup", TARGET_FUNCTION_NAME
            );
            return Err(err);
        }
    };

    hook_state.target_func_addr = SafePtr(target_func_addr);

    // Allocate buffer for stolen bytes
    let mut stolen_bytes: [u8; NUM_STOLEN_BYTES] = [0; NUM_STOLEN_BYTES];

    // Copy the stolen bytes into the buffer
    info!(
        "[{}] Stealing {} bytes from address 0x{:X} to 0x{:X}",
        "setup",
        NUM_STOLEN_BYTES,
        target_func_addr as usize,
        stolen_bytes.as_mut_ptr() as usize
    );
    unsafe {
        ptr::copy(
            target_func_addr,
            stolen_bytes.as_mut_ptr(),
            NUM_STOLEN_BYTES,
        );
    }

    // Log the stolen bytes
    let hex_bytes: Vec<String> = stolen_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    let hex_str = hex_bytes.join(" ");
    info!("[{}] Stolen bytes: {}", "setup", hex_str);

    // Add this to HookState
    hook_state.stolen_bytes = stolen_bytes;

    // Now we create the trampline function
    let trampoline: *mut u8 = match create_trampoline(&stolen_bytes, target_func_addr) {
        Ok(trampoline) => trampoline,
        Err(err) => {
            error!("[{}] Failed to create trampoline function", "setup");
            return Err(err);
        }
    };

    // Add this to HookState
    hook_state.trampoline_func_addr = SafePtr(trampoline);

    Ok(hook_state)
}

fn cleanup(hook_state: Arc<Mutex<HookState>>, safe_hinst_dll: SafeHINSTANCE) {
    loop {
        // Check if the UNLOAD_FILE_PATH exists
        if std::path::Path::new(CLEANUP_FILE_PATH).exists() {
            info!("[{}] Cleanup file found - Cleaning up ...", "cleanup");

            // Restore the stolen bytes
            let hook_state = match hook_state.lock() {
                Ok(hook_state) => {
                    info!("[{}] Mutex locked", "cleanup");
                    hook_state
                }
                Err(_) => {
                    error!("[{}] Failed to lock mutex", "cleanup");
                    return;
                }
            };

            // Check the memory protection at the address of the target function to verify we can write to it
            info!(
                "[{}] Getting memory information for target function at address: 0x{:X}",
                "cleanup", hook_state.target_func_addr.0 as usize
            );
            let mut mbi: winapi::um::winnt::MEMORY_BASIC_INFORMATION =
                unsafe { std::mem::zeroed() };
            let result = unsafe {
                winapi::um::memoryapi::VirtualQuery(
                    hook_state.target_func_addr.0 as *const _,
                    &mut mbi as *mut _,
                    std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>() as usize,
                )
            };

            if result == 0 {
                error!(
                    "[{}] Failed to get memory information for target function",
                    "cleanup"
                );
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "cleanup", win_err);
                }
                drop(hook_state);
                return;
            } else {
                // Use a match statement to check if the protection allows for writing
                let writable: bool = match mbi.Protect {
                    winapi::um::winnt::PAGE_EXECUTE_READWRITE => true,
                    winapi::um::winnt::PAGE_EXECUTE_WRITECOPY => true,
                    winapi::um::winnt::PAGE_EXECUTE_READ => false,
                    winapi::um::winnt::PAGE_EXECUTE => false,
                    winapi::um::winnt::PAGE_READWRITE => true,
                    winapi::um::winnt::PAGE_WRITECOPY => true,
                    winapi::um::winnt::PAGE_READONLY => false,
                    winapi::um::winnt::PAGE_NOACCESS => false,
                    _ => {
                        error!("[{}] Unknown memory protection", "cleanup");
                        false
                    }
                };

                if !writable {
                    warn!("[{}] Target function is not writable", "cleanup");
                    info!(
                        "[{}] Changing protection of target function to PAGE_EXECUTE_READWRITE",
                        "cleanup"
                    );

                    // Change the protection of the target function to PAGE_EXECUTE_READWRITE
                    let mut old_protect: DWORD = 0;
                    let result = unsafe {
                        VirtualProtect(
                            hook_state.target_func_addr.0 as *mut _,
                            NUM_STOLEN_BYTES,
                            PAGE_EXECUTE_READWRITE,
                            &mut old_protect as *mut _,
                        )
                    };

                    if result == 0 {
                        error!(
                            "[{}] Failed to change protection of target function",
                            "cleanup"
                        );
                        if let Some(win_err) = get_last_error() {
                            error!("[{}] Windows error: {}", "cleanup", win_err);
                        }
                        drop(hook_state);
                        return;
                    }
                }
            }

            // Restore the stolen bytes
            info!(
                "[{}] Copying stolen bytes back to address: 0x{:X}",
                "cleanup", hook_state.target_func_addr.0 as usize
            );
            unsafe {
                ptr::copy(
                    hook_state.stolen_bytes.as_ptr(),
                    hook_state.target_func_addr.0 as *mut u8,
                    NUM_STOLEN_BYTES,
                );
            }

            // Change the protection of the stolen bytes back to the original
            info!(
                "[{}] Restoring memory protection of target function",
                "cleanup"
            );
            let result = unsafe {
                VirtualProtect(
                    hook_state.target_func_addr.0 as *mut _,
                    NUM_STOLEN_BYTES,
                    mbi.Protect,
                    &mut mbi.Protect as *mut _,
                )
            };

            if result == 0 {
                error!(
                    "[{}] Failed to change protection of target function",
                    "cleanup"
                );
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "cleanup", win_err);
                }
                drop(hook_state);
                return;
            }

            // Free the memory allocated for the trampoline function
            info!(
                "[{}] Freeing memory for trampoline function at address: 0x{:X}",
                "cleanup", hook_state.trampoline_func_addr.0 as usize
            );
            let result = unsafe {
                VirtualFree(
                    hook_state.trampoline_func_addr.0 as *mut _,
                    0,
                    winapi::um::winnt::MEM_RELEASE,
                )
            };

            if result == 0 {
                error!(
                    "[{}] Failed to free memory for trampoline function",
                    "cleanup"
                );
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "cleanup", win_err);
                }
                drop(hook_state);
                return;
            } else {
                info!("[{}] Trampoline function memory freed", "cleanup");
            }

            // Unlock the mutex
            info!("[{}] Dropping mutex", "cleanup");
            drop(hook_state);

            // Unload the DLL
            unsafe {
                let hmodule = if safe_hinst_dll.0.is_null() {
                    GetModuleHandleW(null_mut())
                } else {
                    safe_hinst_dll.0
                };

                if hmodule == null_mut() {
                    error!("[{}] Failed to get handle to DLL", "cleanup");
                    if let Some(win_err) = get_last_error() {
                        error!("[{}] Windows error: {}", "cleanup", win_err);
                    }
                    return;
                }

                info!(
                    "[{}] Unloading DLL with handle: 0x{:X}",
                    "cleanup", hmodule as usize
                );
                FreeLibraryAndExitThread(hmodule, 0);
            }
        }
        // Sleep for 1 second
        thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn install_hook(hook_state: Arc<Mutex<HookState>>) {
    // Lock the mutex
    let hook_state = match hook_state.lock() {
        Ok(hook_state) => {
            info!("[{}] Mutex locked", "install_hook");
            hook_state
        }
        Err(_) => {
            error!("[{}] Failed to lock mutex", "install_hook");
            return;
        }
    };

    // Store the trampoline function in the global variable
    let trampoline_func_addr: *const u8 = hook_state.trampoline_func_addr.0;
    TRAMPOLINE_FUNC.store(trampoline_func_addr as *mut _, Ordering::SeqCst);

    // Get the address of the hook function
    let hook_func_addr = hook_func as *const () as *mut u8;

    // Get the target_func_addr from HookState
    let target_func_addr: *const u8 = hook_state.target_func_addr.0;

    // Now we actually hook the function
    match set_hook(target_func_addr, hook_func_addr) {
        Ok(_) => {
            info!(
                "[{}] Hooked {} successfully",
                "install_hook", TARGET_FUNCTION_NAME
            );
            info!(
                "[{}] Trampoline function address: 0x{:X}",
                "install_hook", trampoline_func_addr as usize
            );
            info!(
                "[{}] Hook function address: 0x{:X}",
                "install_hook", hook_func_addr as usize
            );
        }
        Err(_) => {
            error!(
                "[{}] Failed to hook {}",
                "install_hook", TARGET_FUNCTION_NAME
            );
            drop(hook_state);
            return;
        }
    }

    // Unlock the mutex
    info!("[{}] Dropping mutex", "install_hook");
    drop(hook_state);
}

fn get_target_func_addr() -> Result<*const u8, DWORD> {
    // Convert the target module name to a CString
    let target_module_cstr: CString = match CString::new(TARGET_MODULE_NAME) {
        Ok(cstr) => cstr,
        Err(_) => {
            error!(
                "[{}] Failed to convert target module name to CString",
                "get_target_func_addr"
            );
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "get_target_func_addr", win_err);
            }
            return Err(0);
        }
    };
    // Convert the target function name to a CString
    let target_function_cstr: CString = match CString::new(TARGET_FUNCTION_NAME) {
        Ok(cstr) => cstr,
        Err(_) => {
            error!(
                "[{}] Failed to convert target function name to CString",
                "get_target_func_addr"
            );
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "get_target_func_addr", win_err);
            }
            return Err(0);
        }
    };

    // Call GetModuleHandleA to get the base address of the target module
    let mod_handle: *mut HINSTANCE__ =
        unsafe { winapi::um::libloaderapi::GetModuleHandleA(target_module_cstr.as_ptr()) };

    // If the handle is null, the function failed
    if mod_handle.is_null() {
        error!(
            "[{}] Returned handle to {:?} is null",
            "get_target_func_addr", target_module_cstr
        );
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "get_target_func_addr", win_err);
        }
        return Err(0);
    } else {
        info!(
            "[{}] {:?} base address: 0x{:X}",
            "get_exe_base_address", target_module_cstr, mod_handle as usize
        );
    }

    // Get the address of the target function
    let target_func_addr: FARPROC = unsafe {
        winapi::um::libloaderapi::GetProcAddress(mod_handle, target_function_cstr.as_ptr())
    };

    // If the address is null, the function failed
    if target_func_addr.is_null() {
        error!(
            "[{}] Returned address to {:?} is null",
            "get_target_func_addr", target_function_cstr
        );
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "get_target_func_addr", win_err);
        }
        return Err(0);
    } else {
        info!(
            "[{}] {:?} address: 0x{:X}",
            "get_target_func_addr", target_function_cstr, target_func_addr as usize
        );
    }
    Ok(target_func_addr as *const u8)
}

// This function will create the trampoline function
fn create_trampoline(
    stolen_bytes: &[u8; NUM_STOLEN_BYTES],
    target_func_addr: *const u8,
) -> Result<*mut u8, DWORD> {
    // Allocate memory for the trampoline function
    let trampoline = unsafe {
        VirtualAlloc(
            ptr::null_mut(),
            NUM_STOLEN_BYTES + JMP_INSTRUCTION_SIZE,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8
    };

    // If the allocation failed, return an error
    if trampoline.is_null() {
        error!(
            "[{}] Failed to allocate memory for trampoline function",
            "create_trampoline"
        );
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "create_trampoline", win_err);
        }
        return Err(0);
    } else {
        info!(
            "[{}] Trampoline function allocated at 0x{:X}",
            "create_trampoline", trampoline as usize
        );
    }

    // Copy the stolen bytes into the trampoline function
    unsafe {
        ptr::copy(stolen_bytes.as_ptr(), trampoline, NUM_STOLEN_BYTES);
    }

    // Create the JMP instruction back to the original function
    unsafe {
        // Depending on the target architecture, we'll need to create a different JMP instruction
        #[cfg(target_pointer_width = "64")]
        {
            // 64-bit JMP instruction
            // Assemble the machine code for:
            // mov r10, target_address
            // jmp r10

            // We are using R10 as the register to store the target address
            // because it is a non-volatile register, meaning it is not used by the target function

            // MOV R10, IMM64 = 48 B8 [IMM64]
            // 0x49 is a prefix indicating that the operation is using 64-bit operands using the R8-R15 registers
            // 0xBA is essentially telling the CPU that the next 8 bytes after the opcode are
            // the immediate value to be moved into R10
            let mov_r10 = [0x49, 0xBA];

            // JMP R10 = 41 FF E2
            let jmp_r10 = [0x41, 0xFF, 0xE2];

            // Calculate the target address for the jump back
            let target_address = (target_func_addr as usize) + NUM_STOLEN_BYTES;

            // Prepare the buffer for our instruction set
            let mut instruction_set: [u8; JMP_INSTRUCTION_SIZE] = [0; JMP_INSTRUCTION_SIZE]; // 2 for MOV, 8 for target_address, 2 for JMP

            // Copy the machine code into the buffer
            instruction_set[0..2].copy_from_slice(&mov_r10);
            instruction_set[2..10].copy_from_slice(&target_address.to_le_bytes());
            instruction_set[10..13].copy_from_slice(&jmp_r10);

            // Write the instruction set to the trampoline
            ptr::copy(
                instruction_set.as_ptr(),
                trampoline.add(NUM_STOLEN_BYTES),
                instruction_set.len(),
            );
        }

        #[cfg(target_pointer_width = "32")]
        {
            // Offset for the JMP in 32-bit
            let offset: i32 = (target_func_addr as i32 + NUM_STOLEN_BYTES as i32)
                - (trampoline as i32 + NUM_STOLEN_BYTES as i32 + JMP_INSTRUCTION_SIZE as i32);

            // JMP opcode for near jump is 0xE9 in 32-bit
            let jmp_opcode: u8 = 0xE9;

            // Write the JMP opcode to the trampoline
            ptr::write(trampoline.add(NUM_STOLEN_BYTES), jmp_opcode);

            // Write the offset for the JMP
            ptr::copy(
                &offset as *const i32 as *const u8,
                trampoline.add(NUM_STOLEN_BYTES + 1),
                JMP_INSTRUCTION_SIZE - 1,
            );
        }
    }

    // Change the protection of the stolen bytes to PAGE_EXECUTE_READWRITE
    let mut old_protect: DWORD = 0;
    let success = unsafe {
        VirtualProtect(
            trampoline as _,
            (NUM_STOLEN_BYTES + JMP_INSTRUCTION_SIZE) as _,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect as *mut u32,
        ) != 0
    };

    // If the protection change failed, return an error
    if !success {
        error!(
            "[{}] Failed to change protection of trampoline function",
            "create_trampoline"
        );
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "create_trampoline", win_err);
        }
        return Err(0);
    } else {
        info!(
            "[{}] Trampoline function protection changed to PAGE_EXECUTE_READWRITE",
            "create_trampoline"
        );
    }

    // Log the trampoline function
    let hex_bytes: Vec<String> = unsafe {
        (0..NUM_STOLEN_BYTES + JMP_INSTRUCTION_SIZE)
            .map(|i| format!("{:02x}", *trampoline.add(i)))
            .collect()
    };
    let hex_str = hex_bytes.join(" ");

    info!("[{}] Trampoline function: {}", "create_trampoline", hex_str);

    Ok(trampoline)
}

pub fn set_hook(target_func_addr: *const u8, hook_func_addr: *mut u8) -> Result<(), DWORD> {
    // Change the protection of the target function to PAGE_EXECUTE_READWRITE so we can write to it
    let mut old_protect: DWORD = 0;
    if unsafe {
        VirtualProtect(
            target_func_addr as *mut _,
            JMP_INSTRUCTION_SIZE,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect as *mut _,
        )
    } == 0
    {
        error!(
            "[{}] Failed to change protection of target function",
            "set_hook"
        );
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "set_hook", win_err);
        }
        return Err(0);
    } else {
        info!(
            "[{}] Target function protection changed to PAGE_EXECUTE_READWRITE",
            "set_hook"
        );
    }

    let mut jmp_instr: [u8; JMP_INSTRUCTION_SIZE] = [0; JMP_INSTRUCTION_SIZE];

    unsafe {
        #[cfg(target_pointer_width = "64")]
        {
            let mov_r10 = [0x48, 0xB8];
            let jmp_r10 = [0xFF, 0xE0];
            let target_address = hook_func_addr as usize;

            let mut instruction_set: [u8; 14] = [0; 14];

            instruction_set[0..2].copy_from_slice(&mov_r10);
            instruction_set[2..10].copy_from_slice(&target_address.to_le_bytes());
            instruction_set[10..12].copy_from_slice(&jmp_r10);

            ptr::copy(
                instruction_set.as_ptr(),
                jmp_instr.as_mut_ptr(),
                instruction_set.len(),
            );
        }

        #[cfg(target_pointer_width = "32")]
        {
            let offset: i32 = (hook_func_addr as i32 + JMP_INSTRUCTION_SIZE as i32)
                - (target_func_addr as i32 + JMP_INSTRUCTION_SIZE as i32);

            let jmp_opcode: u8 = 0xE9;

            ptr::write(jmp_instr.as_mut_ptr(), jmp_opcode);

            ptr::copy(
                &offset as *const i32 as *const u8,
                jmp_instr.as_mut_ptr().add(1),
                4,
            );
        }

        ptr::copy(
            jmp_instr.as_ptr(),
            target_func_addr as *mut u8,
            JMP_INSTRUCTION_SIZE,
        );

        // Log the JMP instruction as a hex string
        let hex_bytes: Vec<String> = jmp_instr.iter().map(|b| format!("{:02x}", b)).collect();

        let hex_str = hex_bytes.join(" ");

        info!(
            "[{}] Bytes written to target function: {:?}",
            "set_hook", hex_str
        );

        // Restore the protection of the target function
        let result = VirtualProtect(
            target_func_addr as *mut _,
            JMP_INSTRUCTION_SIZE,
            old_protect,
            &mut old_protect as *mut _,
        );

        if result == 0 {
            error!(
                "[{}] Failed to change protection of target function",
                "set_hook"
            );
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "set_hook", win_err);
            }
            return Err(0);
        } else {
            info!("[{}] Target function protection restored", "set_hook");
        }
    }

    Ok(())
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