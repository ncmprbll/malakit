//! # dynamic-analysis-kit
//!
//! `dynamic-analysis-kit` is a collection of utilities to make performing certain
//! calls to Win32 API simpler and aid in reverse engineering or malware analysis

use windows::core::Result;

pub mod memory;
pub mod process;

fn u16_to_string(array: &[u16]) -> Result<String> {
    let first_null_position = array
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(array.len());

    Ok(String::from_utf16(&array[..first_null_position])?)
}

pub fn aob(buffer: &[u8], pattern: &[u8]) -> Option<usize> {
    buffer
        .windows(pattern.len())
        .position(|window| window == pattern)
}
