//! # Virtual address space shenanigans
//!
//! `memory` abstracts away working with process's virtual address space

use std::{ffi::c_void, ops::Deref};

use windows::{
    Win32::{
        Foundation::CloseHandle, Foundation::HANDLE, System::Diagnostics::ToolHelp::*,
        System::Memory::*,
    },
    core::Result,
};

/// Read-only combination of flags
pub const DEFAULT_PAGE_PROTECTION_FLAGS: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(
    PAGE_READONLY.0
        | PAGE_READWRITE.0
        | PAGE_WRITECOPY.0
        | PAGE_EXECUTE_READ.0
        | PAGE_EXECUTE_READWRITE.0
        | PAGE_EXECUTE_WRITECOPY.0,
);

/// A wrapper around module's entry. Has a handy `module_name` field
/// for simpler identification.
///
/// # Examples
/// ```
/// use crate::dynamic_analysis_kit::*;
///
/// let processes = process::list().unwrap();
/// let entry = processes
///     .iter()
///     .find(|&x| x.executable_name == "LockApp.exe")
///     .unwrap();
///
/// let modules = module::list_modules_by_pid(entry.th32ProcessID).unwrap();
/// let entry_wrapper = modules
///     .into_iter()
///     .find(|x| x.module_name == "ntdll.dll")
///     .unwrap();
/// let entry = *entry_wrapper; // Implements Deref
/// ```
#[derive(Debug)]
pub struct ModuleEntryWrapper {
    pub module_entry: MODULEENTRY32W,
    pub module_name: String,
}

impl ModuleEntryWrapper {
    pub fn new(module_entry: MODULEENTRY32W) -> Result<Self> {
        Ok(Self {
            module_entry,
            module_name: crate::u16_to_string(&module_entry.szModule)?,
        })
    }
}

impl Deref for ModuleEntryWrapper {
    type Target = MODULEENTRY32W;

    fn deref(&self) -> &Self::Target {
        &self.module_entry
    }
}

/// Lists proccess's modules by a given identifier.
///
/// # Examples
/// ```
/// use crate::dynamic_analysis_kit::*;
///
/// let processes = process::list().unwrap();
/// let entry = processes
///     .iter()
///     .find(|&x| x.executable_name == "LockApp.exe")
///     .unwrap();
///
/// let modules = module::list_modules_by_pid(entry.th32ProcessID).unwrap();
/// let entry = modules
///     .iter()
///     .find(|&x| x.module_name == "ntdll.dll")
///     .unwrap();
/// ```
pub fn list_modules_by_pid(process_id: u32) -> Result<Vec<ModuleEntryWrapper>> {
    let mut module_entry = MODULEENTRY32W::default();
    module_entry.dwSize = size_of::<MODULEENTRY32W>() as u32;

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id) }?;

    unsafe { Module32FirstW(snapshot, &mut module_entry) }?;

    let mut modules: Vec<ModuleEntryWrapper> = Vec::new();
    modules.push(ModuleEntryWrapper::new(module_entry)?);

    while let Ok(()) = unsafe { Module32NextW(snapshot, &mut module_entry) } {
        modules.push(ModuleEntryWrapper::new(module_entry)?);
    }

    unsafe { CloseHandle(snapshot) }?;

    Ok(modules)
}
