use dynamic_analysis_kit::*;

fn main() {
    let processes = process::list().unwrap();

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

    let handle = process::handle_by_pid(entry.th32ProcessID).unwrap();

    // for entry in memory::list_modules_by_pid(entry.th32ProcessID).unwrap() {
    //     if entry.module_name == "telclient.dll" {
    //         println!("{} 0x{:X}", entry.module_name, entry.modBaseAddr as i64);
    //         for info in memory::list_readonly_pages_by_handle(
    //             &handle,
    //             entry.modBaseAddr,
    //             memory::PageAllocation::Same,
    //         ) {
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

    let module = memory::module_by_name(entry.th32ProcessID, "telclient.dll")
        .unwrap()
        .unwrap();
    let pages = memory::list_readonly_pages_by_handle(
        &handle,
        module.modBaseAddr,
        memory::PageAllocation::Same,
    );

    for page in pages {
        for buffer in page.sized_reader(&handle, 1 << 13, 7) {
            println!("{:?} {}", buffer, buffer.len())
        }
    }

    for page in memory::list_every_readonly_page_by_handle(&handle) {
        // println!("{:?}", page)
    }
}
