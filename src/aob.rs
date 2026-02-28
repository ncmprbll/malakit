//! # Array of bytes scanning
//!
//! `aob` lets you search for a pattern of bytes

use std::u8;

enum Token {
    Byte(u8),
    Any,
}

/// Scans buffer for a given pattern.
pub fn position(buffer: &[u8], pattern: &str) -> Vec<usize> {
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
            std::iter::zip(window, tokens.clone()).all(|(byte, token)| match token {
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
