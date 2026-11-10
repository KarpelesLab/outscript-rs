//! The CryptoNote varint: an unsigned LEB128, seven bits per byte, least
//! significant group first, the high bit set on every byte but the last.

use super::Error;

/// The longest encoding of a `u64`.
pub const MAX_VARINT_LEN: usize = 10;

/// The number of bytes [`write_varint`] produces for `value` (1 to
/// [`MAX_VARINT_LEN`]).
pub const fn varint_len(value: u64) -> usize {
    let mut n = 1;
    let mut v = value >> 7;
    while v != 0 {
        n += 1;
        v >>= 7;
    }
    n
}

/// Encodes `value`, returning the buffer and the number of bytes used.
fn encode(value: u64) -> ([u8; MAX_VARINT_LEN], usize) {
    let mut buf = [0u8; MAX_VARINT_LEN];
    let mut v = value;
    let mut n = 0;
    for byte in buf.iter_mut() {
        n += 1;
        if v < 0x80 {
            *byte = v as u8;
            break;
        }
        *byte = (v & 0x7f) as u8 | 0x80;
        v >>= 7;
    }
    (buf, n)
}

/// Writes `value` at the start of `out`, returning the number of bytes
/// written.
///
/// Fails with [`Error::BufferTooSmall`] if `out` is shorter than
/// [`varint_len`]`(value)`; a [`MAX_VARINT_LEN`]-byte buffer always fits.
pub fn write_varint(value: u64, out: &mut [u8]) -> Result<usize, Error> {
    let (buf, n) = encode(value);
    let dst = out.get_mut(..n).ok_or(Error::BufferTooSmall)?;
    for (d, s) in dst.iter_mut().zip(buf) {
        *d = s;
    }
    Ok(n)
}

/// Appends the encoding of `value` to `out`.
#[cfg(feature = "alloc")]
pub fn push_varint(out: &mut crate::prelude::Vec<u8>, value: u64) {
    let (buf, n) = encode(value);
    out.extend(buf.iter().take(n));
}

/// Reads a varint from the start of `data`, returning the value and the
/// number of bytes it occupied.
///
/// Only the canonical encoding is accepted, as in Monero's `read_varint`:
/// [`Error::NonCanonical`] for a zero group after the first byte (a padded
/// encoding), [`Error::Overflow`] for a value that does not fit in 64 bits,
/// and [`Error::UnexpectedEof`] when `data` ends before the last byte.
pub fn read_varint(data: &[u8]) -> Result<(u64, usize), Error> {
    let mut value = 0u64;
    for (i, &byte) in data.iter().enumerate() {
        // The tenth byte holds bit 63 alone, and must be the last.
        if i + 1 >= MAX_VARINT_LEN && byte > 1 {
            return Err(Error::Overflow);
        }
        if byte == 0 && i != 0 {
            return Err(Error::NonCanonical);
        }
        let group = u64::from(byte & 0x7f);
        let shift = u32::try_from(i).map_err(|_| Error::Overflow)? * 7;
        value |= group.checked_shl(shift).ok_or(Error::Overflow)?;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(Error::UnexpectedEof)
}
