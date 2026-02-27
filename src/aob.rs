//! # Array of bytes scanning
//!
//! `aob` lets you search for a pattern of bytes

pub fn aob(buffer: &[u8], pattern: &[u8]) -> Option<usize> {
    buffer
        .windows(pattern.len())
        .position(|window| window == pattern)
}
