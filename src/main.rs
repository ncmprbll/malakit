use std::{env, process::exit};

use dynamic_analysis_kit::*;

const HELP_MESSAGE: &str = "Usage: dynamic_analysis_kit [COMMAND]
\nCommands:
  ps                   List processes in the system
  scan <pid> <PATTERN> Scan the process for a given pattern (e.g. dynamic_analysis_kit scan 20300 \"FF ?? FF ?? 05 0C\")
\nPattern:
  Must be a valid sequence of hex bytes (without \"0x\" prefix) optionally separated by space. Special sequence \"??\" indicates ANY byte.";

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() <= 1 {
        help();
        return;
    }

    match args[1].as_str() {
        "ps" => {
            let mut list = match process::list() {
                Ok(list) => list,
                Err(err) => {
                    eprintln!("Failed to get a list of processes: {err}");
                    exit(1);
                }
            };

            if list.len() == 0 {
                println!("Nothing to show");
                return;
            }

            list.sort_by(|a, b| a.th32ProcessID.cmp(&b.th32ProcessID));
            let width = list.last().unwrap().th32ProcessID.to_string().len();

            for process in list {
                println!(
                    "{:<width$} {}",
                    process.th32ProcessID,
                    process.executable_name,
                    width = width,
                );
            }
        }
        "scan" => {
            if args.len() < 4 {
                help();
                return;
            };

            let process_id = match args[2].parse::<u32>() {
                Ok(value) => value,
                Err(err) => {
                    eprintln!("Failed to parse process id: {err}");
                    exit(1);
                }
            };

            let handle = match process::handle_by_pid(process_id) {
                Ok(handle) => handle,
                Err(err) => {
                    eprintln!("Failed to get process's handle by id {process_id}: {err}");
                    exit(1);
                }
            };

            for page in memory::list_every_readonly_page_by_handle(&handle) {
                let base_address = page.BaseAddress as usize;

                let buffer = match page.read(&handle) {
                    Some(buffer) => buffer,
                    None => {
                        eprintln!("Failed to read the page at the base 0x{:X}", base_address);
                        continue;
                    }
                };

                for result in aob::scan(&buffer, &args[3]) {
                    println!("0x{:X} +0x{:X}", base_address, result)
                }
            }
        }
        _ => {
            help();
        }
    };
}

fn help() {
    println!("{HELP_MESSAGE}");
}
