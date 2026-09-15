//! Bitcoin variable-length integer (CompactSize).

#[cfg(feature = "alloc")]
use crate::prelude::*;
#[cfg(feature = "std")]
use std::io::{self, Read, Write};

/// A Bitcoin variable-length integer as defined in the Bitcoin protocol.
/// Values 0-0xfc are a single byte; larger values use a prefix byte (0xfd,
/// 0xfe, 0xff) followed by 2, 4, or 8 little-endian bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BtcVarInt(pub u64);

impl BtcVarInt {
    /// Returns the encoding in a fixed 9-byte buffer, with its used length.
    pub fn to_array(self) -> ([u8; 9], usize) {
        let v = self.0;
        let mut out = [0u8; 9];
        if v <= 0xfc {
            out[0] = v as u8;
            (out, 1)
        } else if v <= 0xffff {
            out[0] = 0xfd;
            out[1..3].copy_from_slice(&(v as u16).to_le_bytes());
            (out, 3)
        } else if v <= 0xffff_ffff {
            out[0] = 0xfe;
            out[1..5].copy_from_slice(&(v as u32).to_le_bytes());
            (out, 5)
        } else {
            out[0] = 0xff;
            out[1..9].copy_from_slice(&v.to_le_bytes());
            (out, 9)
        }
    }

    /// Returns the encoded variable-length integer.
    #[cfg(feature = "alloc")]
    pub fn bytes(self) -> Vec<u8> {
        let (buf, len) = self.to_array();
        buf[..len].to_vec()
    }

    /// Returns the number of bytes needed to encode this value (always >= 1).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> usize {
        self.to_array().1
    }

    /// Decodes a variable-length integer from the start of `buf`, returning the
    /// value and the number of bytes consumed, or `None` if `buf` is truncated.
    pub fn decode(buf: &[u8]) -> Option<(BtcVarInt, usize)> {
        let (&t, rest) = buf.split_first()?;
        let n = match t {
            0xfd => 2,
            0xfe => 4,
            0xff => 8,
            _ => return Some((BtcVarInt(t as u64), 1)),
        };
        let mut le = [0u8; 8];
        le[..n].copy_from_slice(rest.get(..n)?);
        Some((BtcVarInt(u64::from_le_bytes(le)), n + 1))
    }

    /// Reads a variable-length integer from `r`, returning the value and the
    /// number of bytes consumed.
    #[cfg(feature = "std")]
    pub fn read_from<R: Read>(r: &mut R) -> io::Result<(BtcVarInt, u64)> {
        let mut buf = [0u8; 9];
        r.read_exact(&mut buf[..1])?;
        let n = match buf[0] {
            0xfd => 2,
            0xfe => 4,
            0xff => 8,
            _ => 0,
        };
        r.read_exact(&mut buf[1..1 + n])?;
        let (v, used) = BtcVarInt::decode(&buf).expect("buffer holds a full varint");
        Ok((v, used as u64))
    }

    /// Writes the encoded variable-length integer to `w`, returning the number
    /// of bytes written.
    #[cfg(feature = "std")]
    pub fn write_to<W: Write>(self, w: &mut W) -> io::Result<u64> {
        let (buf, len) = self.to_array();
        w.write_all(&buf[..len])?;
        Ok(len as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: u64, expected_len: usize, prefix: Option<u8>) {
        let bi = BtcVarInt(v);
        let (buf, len) = bi.to_array();
        let b = &buf[..len];
        assert_eq!(b.len(), expected_len);
        assert_eq!(bi.len(), expected_len);
        if let Some(p) = prefix {
            assert_eq!(b[0], p);
        }
        assert_eq!(BtcVarInt::decode(b), Some((bi, expected_len)));
        assert_eq!(BtcVarInt::decode(&b[..len - 1]), None);
        #[cfg(feature = "std")]
        {
            let (got, n) = BtcVarInt::read_from(&mut &b[..]).unwrap();
            assert_eq!(got.0, v);
            assert_eq!(n as usize, expected_len);
        }
    }

    #[test]
    fn sizes() {
        roundtrip(42, 1, None);
        roundtrip(0xfc, 1, None);
        roundtrip(0xfd, 3, Some(0xfd));
        roundtrip(0xffff, 3, None);
        roundtrip(0x10000, 5, Some(0xfe));
        roundtrip(0x1_0000_0000, 9, Some(0xff));
    }

    #[cfg(feature = "std")]
    #[test]
    fn write_to_roundtrip() {
        let mut buf = Vec::new();
        let n = BtcVarInt(300).write_to(&mut buf).unwrap();
        assert_eq!(n, 3);
        let (got, _) = BtcVarInt::read_from(&mut &buf[..]).unwrap();
        assert_eq!(got.0, 300);
    }
}
