//! # process
//!
//! `process` abstracts away working with processes in a really plain way

use std::ops::Deref;

use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{Diagnostics::ToolHelp::*, Threading::*},
    },
    core::Result,
};

const DEFAULT_PROCESS_ACCESS_RIGHTS: PROCESS_ACCESS_RIGHTS = PROCESS_ALL_ACCESS;

#[derive(Debug)]
pub struct ProcessEntryWrapper {
    pub process_entry: PROCESSENTRY32W,
    pub executable_name: String,
}

impl ProcessEntryWrapper {
    pub fn new(process_entry: PROCESSENTRY32W) -> Result<Self> {
        Ok(Self {
            process_entry,
            executable_name: crate::u16_to_string(&process_entry.szExeFile)?,
        })
    }
}

impl Deref for ProcessEntryWrapper {
    type Target = PROCESSENTRY32W;

    fn deref(&self) -> &Self::Target {
        &self.process_entry
    }
}

/// Returns a list of processes in the system
///
/// # Examples
///
/// ```
/// let processes = process::list().unwrap();
/// let entry = processes
///     .iter()
///     .find(|&x| x.executable_name == "svchost.exe") // Stops at the first match!
///     .unwrap();
/// ```
pub fn list() -> Result<Vec<ProcessEntryWrapper>> {
    let mut process_entry = PROCESSENTRY32W::default();
    process_entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;

    unsafe { Process32FirstW(snapshot, &mut process_entry) }?;

    let mut processes: Vec<ProcessEntryWrapper> = Vec::new();
    processes.push(ProcessEntryWrapper::new(process_entry)?);

    while let Ok(()) = unsafe { Process32NextW(snapshot, &mut process_entry) } {
        processes.push(ProcessEntryWrapper::new(process_entry)?);
    }

    unsafe { CloseHandle(snapshot) }?;

    Ok(processes)
}

#[derive(Debug)]
pub struct HandleWrapper {
    pub handle: HANDLE,
}

impl Drop for HandleWrapper {
    fn drop(&mut self) {
        match unsafe { CloseHandle(self.handle) } {
            Ok(_) => (),
            Err(err) => panic!("Failed to close the handle with code: {}", err.code()),
        };
    }
}

impl Deref for HandleWrapper {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

pub fn handle_by_pid(pid: u32) -> Result<HandleWrapper> {
    Ok(HandleWrapper {
        handle: unsafe { OpenProcess(DEFAULT_PROCESS_ACCESS_RIGHTS, false, pid) }?,
    })
}
