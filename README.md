# Hooky - Dynamic DLL Generation Tool

## Overview

Hooky is a command-line tool for generating dynamic DLLs with pre-configured hooks for Windows API functions. The tool uses Tera templating to generate Rust-based `Cargo.toml` and `lib.rs` files that can be compiled into a DLL. This project aims to make the process of function hooking more accessible and streamlined.

**Important Note**: The generated `lib.rs` file is not compilable as-is. You need to manually add the signature and logic for the hook function.

## Usage

To generate a DLL, run the following command:

```
hooky.exe [OPTIONS] --module_name <MODULE_NAME> --function_name <FUNCTION_NAME> --num_stolen_bytes <NUM_STOLEN_BYTES> --cleanup_file_path <CLEANUP_FILE_PATH> --dll_name <DLL_NAME>
```

After the DLL has been generated, you will find it along with the associated Cargo.toml file in the `generated_dlls/` folder under the folder name you specified in the `dll_name` argument. Navigate to the `src` folder and open `lib.rs` in your editor of choice. From here, all you need to do is finish writing the hook function, i.e., complete function signature and hooking logic. Finally, just compile and you should have a nice DLL ready to be injected and hook your target function. 

### Options:

- `-m, --module_name <MODULE_NAME>`  
  The name of the module containing the function to hook.
- `-f, --function_name <FUNCTION_NAME>`  
  The name of the function to hook.
- `-b, --num_stolen_bytes <NUM_STOLEN_BYTES>`  
  The number of bytes to steal from the function to hook.
- `-p, --cleanup_file_path <CLEANUP_FILE_PATH>`  
  The path to the file whose existence will trigger the cleanup of the generated DLL.
- `-n, --dll_name <DLL_NAME>`  
  The name of the DLL to generate.
- `-l, --log_path <LOG_PATH>`  
  The path to the DLL's log file. Defaults to `C:\\Users\\Public\\<dll_name>.log`.
- `-h, --help`  
  Print help.
- `-V, --version`  
  Print version.

## Installation

### Prerequisites

- Rust programming language: [Download and install from the official site](https://www.rust-lang.org/tools/install).
- Cargo package manager: This comes pre-installed when you install Rust.

### Build From Source

1. **Clone the repository**

  ```shell
  git clone https://github.com/Quin-Darcy/hooky.git
  ```

2. **Build the project**

  ```shell
  cd hooky
  cargo build --release
  ```

3. **Add to PATH**

  On Windows, follow these steps to add the executable to your system's PATH.

  1. Type `Win+r` to open the Run window.
  2. Enter `systempropertiesadvanced`.
  3. In the System Properties window, click on "Environment Variables..."
  4. Under the "System variables" section, find the "Path" variable, and click on "Edit."
  5. Click "New" and add the new path: `C:\\Projects\\hooky\\target\\release`
  6. Click "OK" to save.

  Now, open a new Command Prompt and you should be able to use `hooky` as a command.

## Important Notes

- **Num Stolen Bytes**: This argument specifies the number of bytes to "steal" from the beginning of the target function. It should be at least as big as the number of bytes required for a 32-bit or 64-bit JMP instruction, which are 5 and 14 bytes, respectively. To avoid breaking any instructions, you can use a disassembler like xdbg to count the bytes of machine code in the target function.
  
- **Compiler Target Conditionals**: The generated `lib.rs` file contains conditionals based on whether the compiler target is 32-bit or 64-bit, affecting the trampoline function and JMP statement constructions.

## Shameless Recommendation 
After you have completed the hook function and compiled your DLL, you can inject it using this awesome [injector](https://github.com/Quin-Darcy/injector)! With this you get a very stable injector that includes extensive logging similar to that found in the DLL itself so you can maintain complete visibility over the entire process.  

## TODO

- Add templates that include or don't include logging depending on user input.
- Implement automatic calculation of `num_stolen_bytes` based on disassembled instructions.
