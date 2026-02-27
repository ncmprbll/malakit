//! # dynamic-analysis-kit
//!
//! `dynamic-analysis-kit` is a collection of utilities to make performing certain
//! calls to Win32 API simpler and aid in reverse engineering or malware analysis

use windows::core::Result;

pub mod aob;
pub mod memory;
pub mod process;

fn u16_to_string(array: &[u16]) -> Result<String> {
    let first_null_position = array
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(array.len());

    Ok(String::from_utf16(&array[..first_null_position])?)
}
