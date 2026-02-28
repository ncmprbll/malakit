//! # Array of bytes scanning
//!
//! `aob` lets you search for a pattern of bytes

use std::{iter::zip, u8};

enum Token {
    Byte(u8),
    Any,
}

/// Returns indices of all the matches inside buffer.
///
/// Pattern should contain a string representation of hex bytes or a `??`
/// sequence. See [examples section](`scan#examples`) for possible valid
/// patterns.
///
/// # Panics
/// This function expects valid hex bytes (without `0x` prefix) or `??` as an
/// exception. Culprits which can cause a panic are [`u8::from_str_radix`] and
/// [`str::from_utf8`].
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
///     process::handle_by_pid_with_rights(entry.th32ProcessID, process::PROCESS_ALL_ACCESS)
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
///
/// let pattern = "73 00 69 00 73 00 74 00 73 00 2C";
///
/// for page in pages {
///     for buffer in page.sized_reader(&handle_wrapper, 2 << 13, 11) {
///         for index in aob::scan(&buffer, pattern) {
///             println!("{:X} +0x{:X}", page.BaseAddress as usize, index);
///         }
///     }
/// }
/// ```
pub fn scan(buffer: &[u8], pattern: &str) -> Vec<usize> {
    let tokens = pattern
        .trim()
        .split_whitespace()
        .map(|x| {
            x.as_bytes().chunks_exact(2).map(|x| match x {
                &[b'?', b'?'] => Token::Any,
                _ => Token::Byte(u8::from_str_radix(str::from_utf8(x).unwrap(), 16).unwrap()),
            })
        })
        .flatten();

    let mut indices: Vec<usize> = Vec::new();

    let pattern_size: usize = tokens.clone().count();
    let mut windows = buffer.windows(pattern_size).peekable();
    let mut windows_progress: usize = 0;

    loop {
        match windows.position(|window| {
            zip(window, tokens.clone()).all(|(byte, token)| match token {
                Token::Byte(u8) => byte == &u8,
                Token::Any => true,
            })
        }) {
            Some(index) => {
                indices.push(windows_progress + index);
                windows_progress += index + 1;
            }
            None => break,
        }

        if let None = windows.peek() {
            break;
        }
    }

    indices
}

#[cfg(test)]
mod tests {
    use super::scan;

    #[test]
    fn test_catch_all() {
        let buffer: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let pattern = "??";

        assert_eq!(scan(buffer, pattern), vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_three_byte_catch_all() {
        let buffer: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let pattern = "?? ?? ??";

        assert_eq!(scan(buffer, pattern), vec![0, 1]);
    }

    #[test]
    fn test_three_byte_catch_all_no_spaces() {
        let buffer: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let pattern = "??????";

        assert_eq!(scan(buffer, pattern), vec![0, 1]);
    }

    #[test]
    fn test_concrete_pattern() {
        let buffer: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let pattern = "02 03";

        assert_eq!(scan(buffer, pattern), vec![1]);
    }

    #[test]
    fn test_concrete_pattern_no_spaces() {
        let buffer: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let pattern = "0203";

        assert_eq!(scan(buffer, pattern), vec![1]);
    }

    #[test]
    fn test_concrete_pattern_uppercase() {
        let buffer: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
        let pattern = "CC DD";

        assert_eq!(scan(buffer, pattern), vec![2]);
    }

    #[test]
    fn test_concrete_pattern_lowercase() {
        let buffer: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
        let pattern = "ccdd";

        assert_eq!(scan(buffer, pattern), vec![2]);
    }

    #[test]
    fn test_incomplete_pattern() {
        let buffer: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];

        let pattern = "CC DD A";
        assert_eq!(scan(buffer, pattern), vec![2]);

        let pattern = "CC DD F";
        assert_eq!(scan(buffer, pattern), vec![2]);

        let pattern = "CC DD Z";
        assert_eq!(scan(buffer, pattern), vec![2]);
    }

    #[test]
    #[should_panic]
    fn test_bad_pattern() {
        let buffer: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
        let pattern = "gg wp";

        assert_eq!(scan(buffer, pattern), vec![]);
    }

    #[test]
    fn test_general_cases() {
        let buffer: &[u8] = &[
            0x01, 0x02, 0x03, 0xDA, 0xAC, 0x06, 0x07, 0x07, 0x00, 0x05, 0x06, 0x02, 0x04, 0xDA,
            0xFF, 0x06,
        ];

        let pattern = "DA AC";
        assert_eq!(scan(buffer, pattern), vec![3]);

        let pattern = "FF 06";
        assert_eq!(scan(buffer, pattern), vec![14]);

        let pattern = "?? FF 06";
        assert_eq!(scan(buffer, pattern), vec![13]);

        let pattern = "FF 06 ??";
        assert_eq!(scan(buffer, pattern), vec![]);

        let pattern = "DA AC 06";
        assert_eq!(scan(buffer, pattern), vec![3]);

        let pattern = "da AC 06";
        assert_eq!(scan(buffer, pattern), vec![3]);

        let pattern = "da ?? 06";
        assert_eq!(scan(buffer, pattern), vec![3, 13]);

        let pattern = "07";
        assert_eq!(scan(buffer, pattern), vec![6, 7]);

        let pattern = "07 ??";
        assert_eq!(scan(buffer, pattern), vec![6, 7]);

        let pattern = "07 ?? ??";
        assert_eq!(scan(buffer, pattern), vec![6, 7]);

        let pattern = "07 ?? ?? ??";
        assert_eq!(scan(buffer, pattern), vec![6, 7]);

        let pattern = "07 ?? ?? ?? ?? ?? ?? ?? ?? ??";
        assert_eq!(scan(buffer, pattern), vec![6]);

        let pattern = "07 ?? 00";
        assert_eq!(scan(buffer, pattern), vec![6]);

        let pattern = "02 ?? DA ?? 06";
        assert_eq!(scan(buffer, pattern), vec![1, 11]);
    }
}
