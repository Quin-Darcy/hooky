use std::fs::File;
use std::io::Write;

use clap::Parser;
use tera::{Tera, Context};


#[derive(Parser, Debug)]
#[command(name = "hooky")]
#[command(author = "Quin Darcy")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(
    help_template = "\n{name}\n{author}\nVersion: {version}\n{about}\n\n{usage-heading} {usage} \n\n {all-args} {tab}\n\n"
)]
#[command(about, long_about = None)]
/// A dynamic Windows DLL generator for hooking functions.
struct Cli {
    #[arg(short = 'm', long = "module_name")]
    /// The name of the module containing the function to hook.
    module_name: String,

    #[arg(short = 'f', long = "function_name")]
    /// The name of the function to hook.
    function_name: String,

    #[arg(short = 'b', long = "num_stolen_bytes")]
    /// The number of bytes to steal from the function to hook.
    num_stolen_bytes: usize,

    #[arg(short = 'p', long = "cleanup_file_path")]
    /// The path to the file whose existence will trigger the cleanup of the generated DLL.
    cleanup_file_path: String,

    #[arg(short = 'n', long = "dll_name")]
    /// The name of the DLL to generate.
    dll_name: String,

    #[arg(short = 'l', long = "log_path")]
    /// The path to the DLL's log file. Defaults to C:\\Users\\Public\\<dll_name>.log
    log_path: Option<String>,
}

impl Cli {
    pub fn validate_args(&mut self) -> Result<(), String> {
        if self.num_stolen_bytes <= 0 {
            let err_type = "InvalidArgumentError";
            let err_msg = "Please specify a valid number of bytes to steal.";
            return Err(format!("{}: {}", err_type, err_msg));
        }

        // Confirm that the cleanup file directory exists.
        let cleanup_file_path = std::path::Path::new(&self.cleanup_file_path);
        if !cleanup_file_path.parent().unwrap().exists() {
            let err_type = "InvalidArgumentError";
            let err_msg = "Please specify a valid path to the cleanup file.";
            return Err(format!("{}: {}", err_type, err_msg));
        }

        // Confirm that the log file directory exists.
        if self.log_path.is_some() {
            let log_path = std::path::Path::new(self.log_path.as_ref().unwrap());
            if !log_path.parent().unwrap().exists() {
                let err_type = "InvalidArgumentError";
                let err_msg = "Please specify a valid path to the log file.";
                return Err(format!("{}: {}", err_type, err_msg));
            }
        }

        Ok(())
    }
}

fn write_to_file(filename: &str, content: &str) -> std::io::Result<()> {
    let mut file = File::create(filename)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

fn main() {
    let mut cli = Cli::parse();

    // Validate user arguments.
    let _result = match cli.validate_args() {
        Ok(_) => (),
        Err(err) => {
            println!("\n{}\n", err);
            println!(
                "{}\n\n{}\n", 
                "USAGE:\nhooky.exe --module_name <module_name> --function_name <function_name> --num_stolen_bytes <num_stolen_bytes> --cleanup_file_path <cleanup_file_path> --dll_name <dll_name> [OPTIONS]", 
                "EXAMPLE:\nhooky.exe --module_name kernel32.dll --function_name CreateFileW --num_stolen_bytes 5 --cleanup_file_path 'C:\\Users\\Public\\test.txt' --dll_name hook.dll --log_path 'C:\\Users\\Public\\hook.log'",
            );
            println!("For more information try --help\n");
            return;
        }
    };

    // Check if module name has a .dll extension.
    if !cli.module_name.ends_with(".dll") {
        cli.module_name.push_str(".dll");
    }

    // Check if log path was specified.
    if cli.log_path.is_none() {
        cli.log_path = Some(format!("C:\\\\Users\\\\Public\\\\{}.log", cli.dll_name));
    }

    // Create new folder in generated_dlls/ with name equal to the dll_name argument.
    let _result = match std::fs::create_dir(format!("generated_dlls/{}", cli.dll_name)) {
        Ok(_) => (),
        Err(err) => {
            println!("\n{}\n", err);
            return;
        }
    };

    // Create src folder in generated_dlls/<dll_name>/.
    let _result = match std::fs::create_dir(format!("generated_dlls/{}/src", cli.dll_name)) {
        Ok(_) => (),
        Err(err) => {
            println!("\n{}\n", err);
            return;
        }
    };

    // Initialize Tera engine
    let tera = match Tera::new("templates/*") {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {}", e);
            return;
        }
    };
    
    // Context for Cargo.toml template
    let mut cargo_context = Context::new();
    cargo_context.insert("dll_name", &cli.dll_name);


    // Context for lib.rs template
    let mut lib_context = Context::new();
    lib_context.insert("module_name", &cli.module_name);
    lib_context.insert("function_name", &cli.function_name);
    lib_context.insert("num_stolen_bytes", &cli.num_stolen_bytes);
    lib_context.insert("cleanup_file_path", &cli.cleanup_file_path);
    lib_context.insert("log_path", &cli.log_path.unwrap());

    // Render Cargo.toml template.
    match tera.render("Cargo.toml.tera", &cargo_context) {
        Ok(content) => {
            let _result = match write_to_file(format!("generated_dlls/{}/Cargo.toml", cli.dll_name).as_str(), content.as_str()) {
                Ok(_) => (),
                Err(err) => {
                    println!("\n{}\n", err);
                    return;
                }
            };
        },
        Err(e) => {
            println!("Parsing error(s): {}", e);
            return;
        }
    }

    // Render lib.rs template.
    match tera.render("lib.rs.tera", &lib_context) {
        Ok(content) => {
            let _result = match write_to_file(format!("generated_dlls/{}/src/lib.rs", cli.dll_name).as_str(), content.as_str()) {
                Ok(_) => (),
                Err(err) => {
                    println!("\n{}\n", err);
                    return;
                }
            };
        },
        Err(e) => {
            println!("Parsing error(s): {}", e);
            return;
        }
    };
}