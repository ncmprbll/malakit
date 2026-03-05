//! # Array of bytes scanning
//!
//! `aob` lets you search for a pattern of bytes

use core::fmt;
use std::{fmt::Debug, iter::zip, num::ParseIntError, str::Utf8Error};

/// Pattern is a collection of tokens.
#[derive(Debug)]
pub struct Pattern {
    tokens: Vec<Token>,
}

impl Pattern {
    /// String must be a valid sequence of hex bytes (without `0x` prefix) optionally
    /// separated by space. Special sequence `??` indicates ANY byte.
    ///
    /// # Examples
    /// ```
    /// use crate::dynamic_analysis_kit::*;
    ///
    /// let pattern = aob::Pattern::new("00 CC AA FA ?? ?? FC ?? ?? 0B").unwrap();
    /// let pattern = aob::Pattern::new("00CCAAFA????FC????0B").unwrap();
    /// ```
    pub fn new(s: &str) -> Result<Self, PatternError> {
        Ok(Pattern {
            tokens: s
                .trim()
                .split_whitespace()
                .flat_map(|x| {
                    x.as_bytes().chunks_exact(2).map(|x| match x {
                        &[b'?', b'?'] => Ok(Token::Any),
                        _ => Ok::<Token, PatternError>(Token::Byte(u8::from_str_radix(
                            str::from_utf8(x)?,
                            16,
                        )?)),
                    })
                })
                .collect::<Result<Vec<Token>, PatternError>>()?,
        })
    }
}

/// Represents a combination of errors: [`ParseIntError`] and [`Utf8Error`].
#[derive(Debug, Clone)]
pub struct PatternError {
    details: String,
}

impl From<ParseIntError> for PatternError {
    fn from(err: ParseIntError) -> Self {
        PatternError {
            details: err.to_string(),
        }
    }
}

impl From<Utf8Error> for PatternError {
    fn from(err: Utf8Error) -> Self {
        PatternError {
            details: err.to_string(),
        }
    }
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.details)
    }
}

#[derive(Debug)]
enum Token {
    Byte(u8),
    Any,
}

/// Returns indices of all the matches inside buffer.
///
/// See [`Pattern::new`] or [examples section](`scan#examples`) for possible
/// valid patterns.
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
/// let pattern = aob::Pattern::new("73 00 69 00 73 00 74 00 73 00 2C").unwrap();
///
/// for page in pages {
///     for buffer in page.sized_reader(&handle_wrapper, 2 << 13, 11) {
///         for index in aob::scan(&buffer, &pattern) {
///             println!("{:X} +0x{:X}", page.BaseAddress as usize, index);
///         }
///     }
/// }
/// ```
pub fn scan(buffer: &[u8], pattern: &Pattern) -> Vec<usize> {
    let mut indices: Vec<usize> = Vec::new();

    let pattern_size = pattern.tokens.len();
    let mut windows = buffer.windows(pattern_size).peekable();
    let mut windows_progress: usize = 0;

    loop {
        match windows.position(|window| {
            zip(window, &pattern.tokens).all(|(byte, token)| match token {
                Token::Byte(u8) => byte == u8,
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
    use super::*;

    #[test]
    fn test_catch_all() {
        let buffer: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let pattern = &Pattern::new("??").unwrap();

        assert_eq!(scan(buffer, pattern), vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_three_byte_catch_all() {
        let buffer: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let pattern = &Pattern::new("?? ?? ??").unwrap();

        assert_eq!(scan(buffer, pattern), vec![0, 1]);
    }

    #[test]
    fn test_three_byte_catch_all_no_spaces() {
        let buffer: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let pattern = &Pattern::new("??????").unwrap();

        assert_eq!(scan(buffer, pattern), vec![0, 1]);
    }

    #[test]
    fn test_concrete_pattern() {
        let buffer: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let pattern = &Pattern::new("02 03").unwrap();

        assert_eq!(scan(buffer, pattern), vec![1]);
    }

    #[test]
    fn test_concrete_pattern_no_spaces() {
        let buffer: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let pattern = &Pattern::new("0203").unwrap();

        assert_eq!(scan(buffer, pattern), vec![1]);
    }

    #[test]
    fn test_concrete_pattern_uppercase() {
        let buffer: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
        let pattern = &Pattern::new("CC DD").unwrap();

        assert_eq!(scan(buffer, pattern), vec![2]);
    }

    #[test]
    fn test_concrete_pattern_lowercase() {
        let buffer: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
        let pattern = &Pattern::new("ccdd").unwrap();

        assert_eq!(scan(buffer, pattern), vec![2]);
    }

    #[test]
    fn test_incomplete_pattern() {
        let buffer: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];

        let pattern = &Pattern::new("CC DD A").unwrap();
        assert_eq!(scan(buffer, pattern), vec![2]);

        let pattern = &Pattern::new("CC DD F").unwrap();
        assert_eq!(scan(buffer, pattern), vec![2]);

        let pattern = &Pattern::new("CC DD Z").unwrap();
        assert_eq!(scan(buffer, pattern), vec![2]);
    }

    #[test]
    #[should_panic]
    fn test_bad_pattern() {
        let buffer: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
        let pattern = &Pattern::new("gg wp").unwrap();

        scan(buffer, pattern);
    }

    #[test]
    fn test_general_cases() {
        let buffer: &[u8] = &[
            0x01, 0x02, 0x03, 0xDA, 0xAC, 0x06, 0x07, 0x07, 0x00, 0x05, 0x06, 0x02, 0x04, 0xDA,
            0xFF, 0x06,
        ];

        let pattern = &Pattern::new("DA AC").unwrap();
        assert_eq!(scan(buffer, pattern), vec![3]);

        let pattern = &Pattern::new("FF 06").unwrap();
        assert_eq!(scan(buffer, pattern), vec![14]);

        let pattern = &Pattern::new("?? FF 06").unwrap();
        assert_eq!(scan(buffer, pattern), vec![13]);

        let pattern = &Pattern::new("FF 06 ??").unwrap();
        assert_eq!(scan(buffer, pattern), vec![]);

        let pattern = &Pattern::new("DA AC 06").unwrap();
        assert_eq!(scan(buffer, pattern), vec![3]);

        let pattern = &Pattern::new("da AC 06").unwrap();
        assert_eq!(scan(buffer, pattern), vec![3]);

        let pattern = &Pattern::new("da ?? 06").unwrap();
        assert_eq!(scan(buffer, pattern), vec![3, 13]);

        let pattern = &Pattern::new("07").unwrap();
        assert_eq!(scan(buffer, pattern), vec![6, 7]);

        let pattern = &Pattern::new("07 ??").unwrap();
        assert_eq!(scan(buffer, pattern), vec![6, 7]);

        let pattern = &Pattern::new("07 ?? ??").unwrap();
        assert_eq!(scan(buffer, pattern), vec![6, 7]);

        let pattern = &Pattern::new("07 ?? ?? ??").unwrap();
        assert_eq!(scan(buffer, pattern), vec![6, 7]);

        let pattern = &Pattern::new("07 ?? ?? ?? ?? ?? ?? ?? ?? ??").unwrap();
        assert_eq!(scan(buffer, pattern), vec![6]);

        let pattern = &Pattern::new("07 ?? 00").unwrap();
        assert_eq!(scan(buffer, pattern), vec![6]);

        let pattern = &Pattern::new("02 ?? DA ?? 06").unwrap();
        assert_eq!(scan(buffer, pattern), vec![1, 11]);
    }
}
