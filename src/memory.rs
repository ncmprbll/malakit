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
///     .find(|&x| x.executable_name == "conhost.exe")
///     .unwrap();
///
/// let modules = memory::list_modules_by_pid(entry.th32ProcessID).unwrap();
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
///     .find(|&x| x.executable_name == "conhost.exe")
///     .unwrap();
///
/// let modules = memory::list_modules_by_pid(entry.th32ProcessID).unwrap();
/// let entry = modules
///     .iter()
///     .find(|&x| x.module_name == "ntdll.dll")
///     .unwrap();
/// ```
pub fn list_modules_by_pid(pid: u32) -> Result<Vec<ModuleEntryWrapper>> {
    let mut module_entry = MODULEENTRY32W::default();
    module_entry.dwSize = size_of::<MODULEENTRY32W>() as u32;

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) }?;

    unsafe { Module32FirstW(snapshot, &mut module_entry) }?;

    let mut modules: Vec<ModuleEntryWrapper> = Vec::new();
    modules.push(ModuleEntryWrapper::new(module_entry)?);

    while let Ok(()) = unsafe { Module32NextW(snapshot, &mut module_entry) } {
        modules.push(ModuleEntryWrapper::new(module_entry)?);
    }

    unsafe { CloseHandle(snapshot) }?;

    Ok(modules)
}

/// Shorthand for [`module_by_name`] followed by a call to [`Vec::into_iter`] and [`Iterator::find`]
pub fn module_by_name(pid: u32, needle: &str) -> Result<Option<ModuleEntryWrapper>> {
    Ok(list_modules_by_pid(pid)?
        .into_iter()
        .find(|x| x.module_name == needle))
}

/// Determines which pages to look for.
pub enum PageAllocation {
    /// Looks for pages of the same initial allocation (that is, if the initial page is not MEM_FREE,
    /// as stated at [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex))
    Same,
    /// Do not stop whenever we jump to a different allocation base
    Any,
}

/// Retrieves information about a range of pages within the virtual address space of a
/// specified process at a given `base_address`. See [`PageAllocation`] or
/// [examples section](`list_pages_by_handle_with_flags#examples`) for information on function's behaviour.
///
/// # Examples
/// ```
/// use crate::dynamic_analysis_kit::*;
///
/// let processes = process::list().unwrap();
/// let entry = processes
///     .iter()
///     .find(|&x| x.executable_name == "conhost.exe")
///     .unwrap();
///
/// let handle_wrapper =
///     process::handle_by_pid_with_rights(entry.th32ProcessID, process::PROCESS_QUERY_INFORMATION)
///         .unwrap();
///
/// let module = memory::list_modules_by_pid(entry.th32ProcessID)
///     .unwrap()
///     .into_iter()
///     .find(|x| x.module_name == "ntdll.dll")
///     .unwrap();
///
/// let pages = memory::list_pages_by_handle_with_flags(
///     &handle_wrapper,
///     module.modBaseAddr,
///     memory::PageAllocation::Same,
///     memory::DEFAULT_PAGE_PROTECTION_FLAGS,
/// );
/// ```
pub fn list_pages_by_handle_with_flags(
    handle: &HANDLE,
    base_address: *mut u8,
    page_allocation: PageAllocation,
    flags: PAGE_PROTECTION_FLAGS,
) -> Vec<MEMORY_BASIC_INFORMATION> {
    let mut region_address = base_address;
    let mut region_information = MEMORY_BASIC_INFORMATION::default();

    let mut regions: Vec<MEMORY_BASIC_INFORMATION> = Vec::new();

    loop {
        if unsafe {
            VirtualQueryEx(
                *handle,
                Some(region_address as *const c_void),
                &mut region_information,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        } == 0
        {
            break;
        }

        match page_allocation {
            PageAllocation::Same => {
                // Not part of the same initial allocation
                if region_information.State == MEM_FREE {
                    break;
                }
            }
            PageAllocation::Any => (),
        }

        // We trust Windows not to point us in the wrong direction
        region_address = unsafe { region_address.add(region_information.RegionSize) };

        if region_information.State != MEM_COMMIT {
            continue;
        }

        if (region_information.Protect & flags).0 == 0 {
            continue;
        }

        regions.push(region_information);
    }

    regions
}

/// Shorthand for [`list_pages_by_handle_with_flags`]
pub fn list_readonly_pages_by_handle(
    handle: &HANDLE,
    base_address: *mut u8,
    page_allocation: PageAllocation,
) -> Vec<MEMORY_BASIC_INFORMATION> {
    list_pages_by_handle_with_flags(
        handle,
        base_address,
        page_allocation,
        DEFAULT_PAGE_PROTECTION_FLAGS,
    )
}

/// Shorthand for [`list_pages_by_handle_with_flags`]
pub fn list_every_readonly_page_by_handle(handle: &HANDLE) -> Vec<MEMORY_BASIC_INFORMATION> {
    list_readonly_pages_by_handle(handle, 0 as *mut u8, PageAllocation::Any)
}
