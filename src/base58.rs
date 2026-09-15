//! Base58 encoding using the Bitcoin alphabet.
//!
//! Port of the parts of `github.com/KarpelesLab/base58` used by outscript
//! (`base58.Bitcoin.Encode` / `Decode`).
//!
//! The `*_to_slice` functions work on caller-provided buffers and never
//! allocate; `encode` and `decode` are `alloc` conveniences over them.

#[cfg(feature = "alloc")]
use crate::prelude::*;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Errors from base58 operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input contained a character outside the base58 alphabet.
    InvalidChar(char),
    /// The output buffer is too small for the result.
    BufferTooSmall,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidChar(c) => write!(f, "invalid base58 character: {c:?}"),
            Error::BufferTooSmall => f.write_str("base58 output buffer too small"),
        }
    }
}

impl core::error::Error for Error {}

/// Returns an upper bound on the encoded length of `n` input bytes.
pub fn encoded_len_bound(n: usize) -> usize {
    // log(256)/log(58) ~= 1.366; leading zero bytes encode 1:1, which fits.
    n * 138 / 100 + 1
}

/// Encodes the bytes yielded by `input` into `out`, returning the encoded
/// length. The iterator is walked twice (leading zeros, then digits).
pub(crate) fn encode_iter_to_slice<I>(input: I, out: &mut [u8]) -> Result<usize, Error>
where
    I: Iterator<Item = u8> + Clone,
{
    // Count leading zero bytes; each becomes a leading '1'.
    let zeros = input.clone().take_while(|&b| b == 0).count();
    if zeros > out.len() {
        return Err(Error::BufferTooSmall);
    }

    // Convert base-256 to base-58 via repeated division, accumulating
    // little-endian base-58 digits in out[zeros..].
    let (_, digits) = out.split_at_mut(zeros);
    let mut len = 0;
    for byte in input.skip(zeros) {
        let mut carry = byte as u32;
        for d in digits[..len].iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            *digits.get_mut(len).ok_or(Error::BufferTooSmall)? = (carry % 58) as u8;
            len += 1;
            carry /= 58;
        }
    }

    let digits = &mut digits[..len];
    digits.reverse();
    for d in digits.iter_mut() {
        *d = ALPHABET[*d as usize];
    }
    out[..zeros].fill(b'1');
    Ok(zeros + len)
}

/// Encodes `input` as base58 into `out`, returning the number of bytes
/// written. `out` of [`encoded_len_bound`]`(input.len())` bytes always
/// suffices. The written bytes are ASCII.
pub fn encode_to_slice(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    encode_iter_to_slice(input.iter().copied(), out)
}

/// Encodes bytes to a base58 string (Bitcoin alphabet).
#[cfg(feature = "alloc")]
pub fn encode(input: &[u8]) -> String {
    let mut buf = vec![0u8; encoded_len_bound(input.len())];
    let n = encode_to_slice(input, &mut buf).expect("buffer sized by encoded_len_bound");
    buf.truncate(n);
    String::from_utf8(buf).expect("base58 output is ASCII")
}

fn char_value(c: u8) -> Option<u8> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u8)
}

/// Decodes a base58 string into `out`, returning the number of bytes written.
/// `out` of `input.len()` bytes always suffices.
pub fn decode_to_slice(input: &str, out: &mut [u8]) -> Result<usize, Error> {
    let bytes = input.as_bytes();
    let zeros = bytes.iter().take_while(|&&b| b == b'1').count();
    if zeros > out.len() {
        return Err(Error::BufferTooSmall);
    }

    // Accumulate little-endian base-256 bytes in out[zeros..].
    let (_, acc) = out.split_at_mut(zeros);
    let mut len = 0;
    for &c in &bytes[zeros..] {
        let mut carry = char_value(c).ok_or(Error::InvalidChar(c as char))? as u32;
        for b in acc[..len].iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            *acc.get_mut(len).ok_or(Error::BufferTooSmall)? = (carry & 0xff) as u8;
            len += 1;
            carry >>= 8;
        }
    }

    acc[..len].reverse();
    out[..zeros].fill(0);
    Ok(zeros + len)
}

/// Decodes a base58 string (Bitcoin alphabet) to bytes.
#[cfg(feature = "alloc")]
pub fn decode(input: &str) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; input.len()];
    let n = decode_to_slice(input, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// Decodes a base58 string that must represent exactly 32 bytes, at compile
/// time. Panics (a compile error in const context) on invalid input.
pub(crate) const fn decode_32_const(input: &str) -> [u8; 32] {
    let bytes = input.as_bytes();
    let mut zeros = 0;
    while zeros < bytes.len() && bytes[zeros] == b'1' {
        zeros += 1;
    }
    // Little-endian accumulator; one spare byte to detect overflow.
    let mut acc = [0u8; 33];
    let mut len = 0;
    let mut i = zeros;
    while i < bytes.len() {
        let mut v = 0;
        while v < 58 && ALPHABET[v] != bytes[i] {
            v += 1;
        }
        assert!(v < 58, "invalid base58 character");
        let mut carry = v as u32;
        let mut j = 0;
        while j < len {
            carry += acc[j] as u32 * 58;
            acc[j] = (carry & 0xff) as u8;
            carry >>= 8;
            j += 1;
        }
        while carry > 0 {
            assert!(len < 33, "base58 value longer than 32 bytes");
            acc[len] = (carry & 0xff) as u8;
            len += 1;
            carry >>= 8;
        }
        i += 1;
    }
    assert!(zeros + len == 32, "base58 value is not 32 bytes");
    let mut out = [0u8; 32];
    let mut k = 0;
    while k < len {
        out[31 - k] = acc[k];
        k += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CASES: &[&str] = &[
        "",
        "61",
        "626262",
        "516b6fcd0f",
        "00000000",
        "00010966776006953d5567439e5e39f86a0d273beed61967f6",
    ];

    #[test]
    fn slice_roundtrip() {
        for c in CASES {
            let raw = hex::decode(c).unwrap();
            let mut enc = [0u8; 128];
            let n = encode_to_slice(&raw, &mut enc).unwrap();
            let s = core::str::from_utf8(&enc[..n]).unwrap();
            let mut dec = [0u8; 128];
            let m = decode_to_slice(s, &mut dec).unwrap();
            assert_eq!(&dec[..m], &raw[..], "roundtrip failed for {c}");
        }
    }

    #[test]
    fn slice_buffer_too_small() {
        let mut out = [0u8; 14];
        assert_eq!(
            encode_to_slice(b"hello world", &mut out),
            Err(Error::BufferTooSmall)
        );
        let mut out = [0u8; 10];
        assert_eq!(
            decode_to_slice("StV1DL6CwTryKyV", &mut out),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(
            decode_to_slice("11", &mut [0u8; 1]),
            Err(Error::BufferTooSmall)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn roundtrip() {
        for c in CASES {
            let raw = hex::decode(c).unwrap();
            let enc = encode(&raw);
            let dec = decode(&enc).unwrap();
            assert_eq!(dec, raw, "roundtrip failed for {c}");
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn known_vectors() {
        assert_eq!(encode(&[0x00, 0x00, 0x01]), "112");
        assert_eq!(encode(b"hello world"), "StV1DL6CwTryKyV");
        assert_eq!(decode("StV1DL6CwTryKyV").unwrap(), b"hello world");
    }

    #[test]
    fn const_decode_matches_runtime() {
        for s in [
            "11111111111111111111111111111111",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "SysvarRecentB1ockHashes11111111111111111111",
        ] {
            let mut buf = [0u8; 32];
            assert_eq!(decode_to_slice(s, &mut buf), Ok(32));
            assert_eq!(decode_32_const(s), buf);
        }
    }

    #[test]
    fn invalid_char() {
        assert_eq!(
            decode_to_slice("0OIl", &mut [0u8; 8]),
            Err(Error::InvalidChar('0'))
        );
    }
}
