use std::ffi::c_void;

use dynamic_analysis_kit::*;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

fn main() {
    let processes = list_processes().unwrap();

    // for entry in processes.iter() {
    //     println!(
    //         "{} {:?}",
    //         entry.executable_name, entry.process_entry.th32ProcessID
    //     );
    // }

    let entry = processes
        .iter()
        .find(|x| x.executable_name == "msedge.exe")
        .unwrap();

    let handle = process_handle_by_id(entry.th32ProcessID).unwrap();

    // for entry in process_modules_by_id(entry.th32ProcessID).unwrap() {
    //     if entry.module_name == "telclient.dll" {
    //         println!("{} 0x{:X}", entry.module_name, entry.modBaseAddr as i64);
    //         for info in consecutive_readable_pages_at(&handle, entry.modBaseAddr) {
    //             let mut buffer: Vec<u8> = vec![0; info.RegionSize];

    //             if let Err(err) = unsafe {
    //                 ReadProcessMemory(
    //                     *handle,
    //                     info.BaseAddress as *const c_void,
    //                     buffer.as_mut_ptr() as *mut c_void,
    //                     info.RegionSize,
    //                     None,
    //                 )
    //             } {
    //                 eprintln!("Failed to read process memory: {err}");
    //             }

    //             match aob(&buffer, &[1, 2, 3, 4]) {
    //                 Some(index) => println!("0x{:X} +0x{:X}", info.BaseAddress as i64, index),
    //                 None => println!("None"),
    //             }
    //         }
    //     }
    // }

    for page in every_readable_page(&handle) {
        println!("{:?}", page)
    }
}
