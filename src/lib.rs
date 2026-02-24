//! # dynamic-analysis-kit
//!
//! `dynamic-analysis-kit` is a collection of utilities to make performing certain
//! calls to Win32 API simpler and aid in reverse engineering or malware analysis

use std::{ffi::c_void, ops::Deref};

use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{Diagnostics::ToolHelp::*, Memory::*},
    },
    core::Result,
};

pub mod process;

fn u16_to_string(array: &[u16]) -> Result<String> {
    let first_null_position = array
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(array.len());

    Ok(String::from_utf16(&array[..first_null_position])?)
}

#[derive(Debug)]
pub struct ModuleEntryWrapper {
    pub module_entry: MODULEENTRY32W,
    pub module_name: String,
}

impl ModuleEntryWrapper {
    fn u16_to_string(array: &[u16]) -> Result<String> {
        let first_null_position = array
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(array.len());

        Ok(String::from_utf16(&array[..first_null_position])?)
    }

    pub fn new(module_entry: MODULEENTRY32W) -> Result<Self> {
        Ok(Self {
            module_entry,
            module_name: Self::u16_to_string(&module_entry.szModule)?,
        })
    }
}

impl Deref for ModuleEntryWrapper {
    type Target = MODULEENTRY32W;

    fn deref(&self) -> &Self::Target {
        &self.module_entry
    }
}

pub fn process_modules_by_id(process_id: u32) -> Result<Vec<ModuleEntryWrapper>> {
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

pub fn consecutive_readable_pages_at(
    handle: &HANDLE,
    base_address: *mut u8,
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

        // Not part of the same initial allocation
        if region_information.State == MEM_FREE {
            break;
        }

        // We trust Windows not to point us in the wrong direction
        region_address = unsafe { region_address.add(region_information.RegionSize) };

        if region_information.State != MEM_COMMIT {
            continue;
        }

        if (region_information.Protect
            & (PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY))
            .0
            == 0
        {
            continue;
        }

        regions.push(region_information);
    }

    regions
}

pub fn every_readable_page(handle: &HANDLE) -> Vec<MEMORY_BASIC_INFORMATION> {
    let mut region_address: *mut u8 = std::ptr::null_mut();
    let mut region_information = MEMORY_BASIC_INFORMATION::default();

    let mut regions: Vec<MEMORY_BASIC_INFORMATION> = Vec::new();

    println!("{}", region_address as i64);

    loop {
        let result = unsafe {
            VirtualQueryEx(
                *handle,
                Some(region_address as *const c_void),
                &mut region_information,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break;
        }

        // We trust Windows not to point us in the wrong direction
        region_address = unsafe { region_address.add(region_information.RegionSize) };

        if region_information.State != MEM_COMMIT {
            continue;
        }

        if (region_information.Protect
            & (PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY))
            .0
            == 0
        {
            continue;
        }

        regions.push(region_information);
    }

    regions
}

pub fn aob(buffer: &[u8], pattern: &[u8]) -> Option<usize> {
    buffer
        .windows(pattern.len())
        .position(|window| window == pattern)
}
