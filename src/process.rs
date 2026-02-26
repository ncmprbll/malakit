//! # Process manipulation
//!
//! `process` abstracts away working with processes in a really plain way

use std::ops::Deref;

use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{Diagnostics::ToolHelp::*, Threading::OpenProcess},
    },
    core::Result,
};

pub use windows::Win32::System::Threading::{
    PROCESS_ACCESS_RIGHTS, PROCESS_ALL_ACCESS, PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD,
    PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

pub const DEFAULT_PROCESS_ACCESS_RIGHTS: PROCESS_ACCESS_RIGHTS = PROCESS_ALL_ACCESS;

/// A wrapper around process's entry. Has a handy `executable_name` field
/// for simpler identification.
///
/// # Examples
/// ```
/// use crate::dynamic_analysis_kit::*;
///
/// let processes = process::list().unwrap();
/// let entry = processes
///     .iter()
///     .filter(|&x| x.executable_name == "svchost.exe"); // A list of svchost.exe-s
/// ```
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

/// Returns a list of processes in the system.
///
/// # Examples
///
/// ```
/// use crate::dynamic_analysis_kit::*;
///
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

/// A wrapper around Windows's handle. Closes the handle on drop.
#[derive(Debug)]
pub struct HandleWrapper {
    pub handle: HANDLE,
}

impl Drop for HandleWrapper {
    fn drop(&mut self) {
        match unsafe { CloseHandle(self.handle) } {
            Ok(_) => (),
            Err(err) => panic!("Failed to close the handle: {}", err),
        };
    }
}

impl Deref for HandleWrapper {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

/// Returns a process handle wrapper by its identifier.
///
/// # Examples
/// ```
/// use crate::dynamic_analysis_kit::*;
///
/// let processes = process::list().unwrap();
/// let entry = processes
///     .iter()
///     .find(|&x| x.executable_name == "LockApp.exe") // System processes are gonna be upset with our meddling
///     .unwrap();
///
/// let handle_wrapper = process::handle_by_pid(entry.th32ProcessID).unwrap();
/// let handle = *handle_wrapper; // Implements Deref
/// ```
pub fn handle_by_pid(pid: u32) -> Result<HandleWrapper> {
    handle_by_pid_with_rights(pid, DEFAULT_PROCESS_ACCESS_RIGHTS)
}

/// Returns a process handle wrapper by its identifier and given rights.
///
/// # Examples
/// ```
/// use crate::dynamic_analysis_kit::*;
///
/// let processes = process::list().unwrap();
/// let entry = processes
///     .iter()
///     .find(|&x| x.executable_name == "LockApp.exe") // System processes are gonna be upset with our meddling
///     .unwrap();
///
/// let handle_wrapper = process::handle_by_pid_with_rights(entry.th32ProcessID, process::PROCESS_QUERY_INFORMATION).unwrap();
/// let handle = *handle_wrapper; // Implements Deref
/// ```
pub fn handle_by_pid_with_rights(pid: u32, rights: PROCESS_ACCESS_RIGHTS) -> Result<HandleWrapper> {
    Ok(HandleWrapper {
        handle: unsafe { OpenProcess(rights, false, pid) }?,
    })
}
