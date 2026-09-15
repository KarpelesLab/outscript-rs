//! Standard base64 (RFC 4648, `+/` alphabet, `=` padding) into caller buffers,
//! as used for PSBT text encoding.

#[cfg(feature = "alloc")]
use crate::prelude::*;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Errors from base64 operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input is not canonical padded base64.
    InvalidEncoding,
    /// The output buffer is too small.
    BufferTooSmall,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::InvalidEncoding => "invalid base64",
            Error::BufferTooSmall => "base64 output buffer too small",
        })
    }
}

impl core::error::Error for Error {}

/// The encoded length of `n` bytes.
pub const fn encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// An upper bound on the decoded length of `n` base64 characters.
pub const fn decoded_len_bound(n: usize) -> usize {
    n / 4 * 3
}

/// Encodes `data` into `out`, returning the number of (ASCII) bytes written.
pub fn encode_to_slice(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let len = encoded_len(data.len());
    let out = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;
    for (chunk, dst) in data.chunks(3).zip(out.chunks_mut(4)) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let v = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for (i, d) in dst.iter_mut().enumerate() {
            *d = if i <= chunk.len() {
                ALPHABET[((v >> (18 - 6 * i)) & 63) as usize]
            } else {
                b'='
            };
        }
    }
    Ok(len)
}

fn value(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

/// Decodes canonical padded base64 into `out`, returning the number of bytes
/// written. Whitespace, missing padding and non-zero trailing bits are
/// rejected.
pub fn decode_to_slice(text: &str, out: &mut [u8]) -> Result<usize, Error> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(Error::InvalidEncoding);
    }
    let mut pos = 0;
    let groups = bytes.len() / 4;
    for (g, chunk) in bytes.chunks(4).enumerate() {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && g + 1 != groups) {
            return Err(Error::InvalidEncoding);
        }
        let mut v = 0u32;
        for &c in &chunk[..4 - pad] {
            v = v << 6 | value(c).ok_or(Error::InvalidEncoding)?;
        }
        v <<= 6 * pad;
        // canonical: the bits dropped by padding must be zero
        if pad > 0 && v & ((1 << (8 * pad)) - 1) != 0 {
            return Err(Error::InvalidEncoding);
        }
        let n = 3 - pad;
        let dst = out.get_mut(pos..pos + n).ok_or(Error::BufferTooSmall)?;
        dst.copy_from_slice(&v.to_be_bytes()[1..1 + n]);
        pos += n;
    }
    Ok(pos)
}

/// Encodes `data` as a base64 string.
#[cfg(feature = "alloc")]
pub fn encode(data: &[u8]) -> String {
    let mut buf = vec![0u8; encoded_len(data.len())];
    encode_to_slice(data, &mut buf).expect("buffer sized by encoded_len");
    String::from_utf8(buf).expect("base64 is ASCII")
}

/// Decodes canonical padded base64.
#[cfg(feature = "alloc")]
pub fn decode(text: &str) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; decoded_len_bound(text.len())];
    let n = decode_to_slice(text, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        for (raw, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            let mut buf = [0u8; 16];
            let n = encode_to_slice(raw.as_bytes(), &mut buf).unwrap();
            assert_eq!(&buf[..n], enc.as_bytes());
            let n = decode_to_slice(enc, &mut buf).unwrap();
            assert_eq!(&buf[..n], raw.as_bytes());
        }
        for bad in ["Zg=", "Zh==", "Z===", "Zg==Zg==", "Zm9v\n", "Zm9!"] {
            assert_eq!(
                decode_to_slice(bad, &mut [0u8; 16]),
                Err(Error::InvalidEncoding),
                "{bad}"
            );
        }
        assert_eq!(
            encode_to_slice(b"foo", &mut [0u8; 3]),
            Err(Error::BufferTooSmall)
        );
    }
}
