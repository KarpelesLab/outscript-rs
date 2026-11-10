//! CryptoNote base58: the Bitcoin alphabet applied block by block.
//!
//! Unlike Bitcoin's base58, which converts the whole input as one big number,
//! CryptoNote cuts the data into 8-byte blocks and writes each as exactly 11
//! characters (a big-endian number, padded with `1`). A shorter final block of
//! 1 to 7 bytes becomes 2, 3, 5, 6, 7, 9 or 10 characters. The length of the
//! text therefore determines the length of the data, and the reverse.
//!
//! Decoding is canonical: a text of an impossible length, a character outside
//! the alphabet, and a block whose value does not fit in the bytes it stands
//! for are all rejected, so every accepted string is the one
//! [`encode_to_slice`] produces for the decoded bytes.

use super::Error;

#[cfg(feature = "alloc")]
use crate::prelude::*;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Bytes in a full block.
const BLOCK_LEN: usize = 8;
/// Characters in a full block.
const ENCODED_BLOCK_LEN: usize = 11;

/// The characters needed for a block of 0 to 8 bytes.
const ENCODED_BLOCK_SIZES: [usize; BLOCK_LEN + 1] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

/// The value of an alphabet character.
fn digit(c: u8) -> Option<u8> {
    Some(match c {
        b'1'..=b'9' => c - b'1',
        b'A'..=b'H' => c - b'A' + 9,
        b'J'..=b'N' => c - b'J' + 17,
        b'P'..=b'Z' => c - b'P' + 22,
        b'a'..=b'k' => c - b'a' + 33,
        b'm'..=b'z' => c - b'm' + 44,
        _ => return None,
    })
}

/// The number of bytes a block of `chars` characters stands for, if any does.
const fn decoded_block_len(chars: usize) -> Option<usize> {
    Some(match chars {
        0 => 0,
        2 => 1,
        3 => 2,
        5 => 3,
        6 => 4,
        7 => 5,
        9 => 6,
        10 => 7,
        11 => 8,
        _ => return None,
    })
}

/// The number of characters that encode `len` bytes.
///
/// Saturates at `usize::MAX` for a `len` no slice can have.
pub const fn encoded_len(len: usize) -> usize {
    let tail = match len % BLOCK_LEN {
        0 => 0,
        1 => 2,
        2 => 3,
        3 => 5,
        4 => 6,
        5 => 7,
        6 => 9,
        _ => 10,
    };
    (len / BLOCK_LEN)
        .saturating_mul(ENCODED_BLOCK_LEN)
        .saturating_add(tail)
}

/// The number of bytes a string of `len` characters decodes to, or `None` if
/// no encoding has that length.
pub const fn decoded_len(len: usize) -> Option<usize> {
    match decoded_block_len(len % ENCODED_BLOCK_LEN) {
        // `len / 11 * 8 + 8` cannot overflow.
        Some(tail) => Some(len / ENCODED_BLOCK_LEN * BLOCK_LEN + tail),
        None => None,
    }
}

/// Encodes one block of 1 to 8 bytes into `out`, which has the matching
/// length from [`ENCODED_BLOCK_SIZES`].
pub(super) fn encode_block(block: &[u8], out: &mut [u8]) {
    let mut n = block.iter().fold(0u64, |n, &b| (n << 8) | u64::from(b));
    for c in out.iter_mut().rev() {
        // `n % 58` indexes the 58-entry alphabet.
        *c = ALPHABET[(n % 58) as usize];
        n /= 58;
    }
}

/// Decodes one block of characters into `out`, which has the matching length
/// from [`decoded_block_len`].
fn decode_block(block: &[u8], out: &mut [u8]) -> Result<(), Error> {
    // Eleven digits stay far below 2^128.
    let mut n = 0u128;
    for &c in block {
        let d = digit(c).ok_or(Error::InvalidCharacter)?;
        n = n * 58 + u128::from(d);
    }
    let bits = out.len() * 8;
    if bits < 128 && n >> bits != 0 {
        return Err(Error::Overflow);
    }
    for b in out.iter_mut().rev() {
        *b = (n & 0xff) as u8;
        n >>= 8;
    }
    Ok(())
}

/// Encodes `data` at the start of `out`, returning the number of characters
/// written ([`encoded_len`]`(data.len())`). The output is ASCII.
///
/// Fails with [`Error::BufferTooSmall`] if `out` is too short.
pub fn encode_to_slice(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let n = encoded_len(data.len());
    let dst = out.get_mut(..n).ok_or(Error::BufferTooSmall)?;
    // The last chunk of `dst` has exactly the length of a partial block.
    for (block, chars) in data
        .chunks(BLOCK_LEN)
        .zip(dst.chunks_mut(ENCODED_BLOCK_LEN))
    {
        encode_block(block, chars);
    }
    Ok(n)
}

/// Decodes `text` at the start of `out`, returning the number of bytes
/// written ([`decoded_len`]`(text.len())`).
///
/// Fails with [`Error::InvalidLength`] for a length no encoding has,
/// [`Error::InvalidCharacter`] for a character outside the alphabet,
/// [`Error::Overflow`] for a block that is not canonical, and
/// [`Error::BufferTooSmall`] if `out` is too short. `out` may have been
/// partly written when an error is returned.
pub fn decode_to_slice(text: &str, out: &mut [u8]) -> Result<usize, Error> {
    let text = text.as_bytes();
    let n = decoded_len(text.len()).ok_or(Error::InvalidLength)?;
    let dst = out.get_mut(..n).ok_or(Error::BufferTooSmall)?;
    // The last chunk of `dst` has exactly the length of a partial block.
    for (chars, block) in text
        .chunks(ENCODED_BLOCK_LEN)
        .zip(dst.chunks_mut(BLOCK_LEN))
    {
        decode_block(chars, block)?;
    }
    Ok(n)
}

/// Encodes `data` as a string.
#[cfg(feature = "alloc")]
pub fn encode(data: &[u8]) -> String {
    let mut out = vec![0u8; encoded_len(data.len())];
    for (block, chars) in data
        .chunks(BLOCK_LEN)
        .zip(out.chunks_mut(ENCODED_BLOCK_LEN))
    {
        encode_block(block, chars);
    }
    // Only alphabet characters were written.
    out.into_iter().map(char::from).collect()
}

/// Decodes `text`, with the errors of [`decode_to_slice`].
#[cfg(feature = "alloc")]
pub fn decode(text: &str) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; decoded_len(text.len()).ok_or(Error::InvalidLength)?];
    decode_to_slice(text, &mut out)?;
    Ok(out)
}

// The block-size table and `encoded_len` agree.
const _: () = {
    let mut i = 0;
    while i <= BLOCK_LEN {
        assert!(encoded_len(i) == ENCODED_BLOCK_SIZES[i]);
        i += 1;
    }
};
