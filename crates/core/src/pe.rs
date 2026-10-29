//! When an executable was linked, read from the start of its file or of its loaded image.
//!
//! The rules are tied to the game by this time, so the host reads it from the file on disk and the
//! DLL from the image the game runs. Both read it with this code, so they cannot disagree about
//! where it sits.

use std::fmt;

/// How much of an image holds the headers: the DOS header points at the NT headers, which sit
/// near the start. A loaded image always has its first page mapped.
pub const HEAD_BYTES: usize = 0x1000;

/// Offset of `e_lfanew`, the pointer to the NT headers, in the DOS header.
const E_LFANEW: usize = 0x3c;
/// From the start of the NT headers: the signature (4), `Machine` (2), `NumberOfSections` (2),
/// then `TimeDateStamp`.
const STAMP_FROM_NT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeError {
    /// Not an executable image.
    NotPe,
    /// Cut off before the headers it points at.
    Truncated,
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPe => f.write_str("is not a Windows executable"),
            Self::Truncated => f.write_str("ends inside its headers"),
        }
    }
}

impl std::error::Error for PeError {}

/// Where the link time (`TimeDateStamp`, seconds since the Unix epoch) sits in the image head.
/// The four bytes at that offset are inside `head`.
pub fn link_time_offset(head: &[u8]) -> Result<usize, PeError> {
    if head.get(..2) != Some(b"MZ".as_slice()) {
        return Err(PeError::NotPe);
    }
    let pointer = head.get(E_LFANEW..E_LFANEW + 4).ok_or(PeError::Truncated)?;
    let nt = u32::from_le_bytes(pointer.try_into().expect("four bytes")) as usize;
    let signature = nt.checked_add(4).and_then(|end| head.get(nt..end)).ok_or(PeError::Truncated)?;
    if signature != b"PE\0\0" {
        return Err(PeError::NotPe);
    }
    let at = nt + STAMP_FROM_NT;
    if head.len() < at + 4 {
        return Err(PeError::Truncated);
    }
    Ok(at)
}

/// When the executable was linked, in seconds since the Unix epoch.
pub fn link_time(head: &[u8]) -> Result<u32, PeError> {
    let at = link_time_offset(head)?;
    Ok(u32::from_le_bytes(head[at..at + 4].try_into().expect("four bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest head that reads as an executable, with the NT headers at 0x80.
    fn head_linked_at(time: u32) -> Vec<u8> {
        let mut head = vec![0u8; 0x200];
        head[..2].copy_from_slice(b"MZ");
        head[E_LFANEW..E_LFANEW + 4].copy_from_slice(&0x80u32.to_le_bytes());
        head[0x80..0x84].copy_from_slice(b"PE\0\0");
        head[0x88..0x8c].copy_from_slice(&time.to_le_bytes());
        head
    }

    #[test]
    fn the_link_time_is_read_from_the_nt_headers() {
        assert_eq!(link_time(&head_linked_at(0x6ad2_a1ed)), Ok(0x6ad2_a1ed));
        assert_eq!(link_time(&head_linked_at(0)), Ok(0));
        assert_eq!(link_time(&head_linked_at(u32::MAX)), Ok(u32::MAX));
    }

    #[test]
    fn the_offset_is_where_the_time_can_be_changed() {
        let mut head = head_linked_at(1);
        let at = link_time_offset(&head).unwrap();
        assert_eq!(at, 0x88);
        head[at..at + 4].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(link_time(&head), Ok(7));
    }

    #[test]
    fn data_that_is_no_executable_is_refused() {
        assert_eq!(link_time(&[]), Err(PeError::NotPe));
        assert_eq!(link_time(b"#!/bin/sh\n"), Err(PeError::NotPe));

        let mut head = head_linked_at(1);
        head[0x80] = b'X';
        assert_eq!(link_time(&head), Err(PeError::NotPe));
    }

    #[test]
    fn a_head_that_stops_short_is_refused() {
        assert_eq!(link_time(b"MZ"), Err(PeError::Truncated));
        // Cut inside the field itself.
        assert_eq!(link_time(&head_linked_at(1)[..0x8b]), Err(PeError::Truncated));
        // The pointer leads past the end, however far.
        for pointer in [0x1fdu32, 0x200, 0x10000, u32::MAX - 1, u32::MAX] {
            let mut head = head_linked_at(1);
            head[E_LFANEW..E_LFANEW + 4].copy_from_slice(&pointer.to_le_bytes());
            assert_eq!(link_time(&head), Err(PeError::Truncated), "{pointer:#x}");
        }
        // It leads to bytes inside the head that are no signature.
        let mut head = head_linked_at(1);
        head[E_LFANEW..E_LFANEW + 4].copy_from_slice(&0x1f0u32.to_le_bytes());
        assert_eq!(link_time(&head), Err(PeError::NotPe));
    }

    #[cfg(windows)]
    #[test]
    fn a_real_executable_has_a_link_time() {
        use std::io::Read;

        let mut head = Vec::new();
        std::fs::File::open(std::env::current_exe().unwrap())
            .unwrap()
            .take(HEAD_BYTES as u64)
            .read_to_end(&mut head)
            .unwrap();
        assert!(link_time(&head).is_ok());
    }
}
