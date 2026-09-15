//! Bitcoin script PUSHDATA encoding/decoding.

#[cfg(feature = "alloc")]
use crate::prelude::*;

/// Returns the push opcode header for a payload of `n` bytes, as a buffer and
/// its used length (1 byte for <=75 bytes, else OP_PUSHDATA1/2/4 + length).
fn push_header(n: usize) -> ([u8; 5], usize) {
    let mut h = [0u8; 5];
    if n <= 75 {
        h[0] = n as u8;
        (h, 1)
    } else if n <= 0xff {
        h[0] = 0x4c; // OP_PUSHDATA1
        h[1] = n as u8;
        (h, 2)
    } else if n <= 0xffff {
        h[0] = 0x4d; // OP_PUSHDATA2
        h[1..3].copy_from_slice(&(n as u16).to_le_bytes());
        (h, 3)
    } else {
        h[0] = 0x4e; // OP_PUSHDATA4
        h[1..5].copy_from_slice(&(n as u32).to_le_bytes());
        (h, 5)
    }
}

/// Returns the encoded length of a push of `n` bytes.
pub fn push_bytes_len(n: usize) -> usize {
    push_header(n).1 + n
}

/// Encodes `v` as a Bitcoin script push operation into `out`, returning the
/// number of bytes written, or `None` if `out` is shorter than
/// [`push_bytes_len`]`(v.len())`.
pub fn push_bytes_to_slice(v: &[u8], out: &mut [u8]) -> Option<usize> {
    let (h, hl) = push_header(v.len());
    let total = hl + v.len();
    let out = out.get_mut(..total)?;
    out[..hl].copy_from_slice(&h[..hl]);
    out[hl..].copy_from_slice(v);
    Some(total)
}

/// Encodes a byte slice as a Bitcoin script push operation, choosing the
/// appropriate opcode (direct push for <=75 bytes, OP_PUSHDATA1/2/4 for larger).
#[cfg(feature = "alloc")]
pub fn push_bytes(v: &[u8]) -> Vec<u8> {
    let (h, hl) = push_header(v.len());
    let mut out = Vec::with_capacity(hl + v.len());
    out.extend_from_slice(&h[..hl]);
    out.extend_from_slice(v);
    out
}

/// Decodes a Bitcoin script push operation at the start of `v`, returning the
/// pushed data and the total number of bytes consumed. Returns `None` on error.
pub fn parse_push_bytes(v: &[u8]) -> Option<(&[u8], usize)> {
    if v.is_empty() {
        return None;
    }
    let p = v[0];
    let rest = &v[1..];
    if p <= 75 {
        let n = p as usize;
        if rest.len() >= n {
            return Some((&rest[..n], n + 1));
        }
        return None;
    }
    match p {
        0x4c => {
            // OP_PUSHDATA1
            if rest.is_empty() {
                return None;
            }
            let n = rest[0] as usize;
            let rest = &rest[1..];
            if rest.len() >= n {
                Some((&rest[..n], n + 2))
            } else {
                None
            }
        }
        0x4d => {
            // OP_PUSHDATA2
            if rest.len() < 2 {
                return None;
            }
            let n = u16::from_le_bytes([rest[0], rest[1]]) as usize;
            let rest = &rest[2..];
            if rest.len() >= n {
                Some((&rest[..n], n + 3))
            } else {
                None
            }
        }
        0x4e => {
            // OP_PUSHDATA4
            if rest.len() < 4 {
                return None;
            }
            let n = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            let rest = &rest[4..];
            if rest.len() >= n {
                Some((&rest[..n], n + 5))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    #[test]
    fn small_push() {
        let v = [1u8, 2, 3];
        let enc = push_bytes(&v);
        assert_eq!(enc, vec![3, 1, 2, 3]);
        let (data, n) = parse_push_bytes(&enc).unwrap();
        assert_eq!(data, &v);
        assert_eq!(n, 4);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn pushdata1() {
        let v = vec![0xaau8; 100];
        let enc = push_bytes(&v);
        assert_eq!(enc[0], 0x4c);
        assert_eq!(enc[1], 100);
        let (data, n) = parse_push_bytes(&enc).unwrap();
        assert_eq!(data, &v[..]);
        assert_eq!(n, 102);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn pushdata2() {
        let v = vec![0xbbu8; 300];
        let enc = push_bytes(&v);
        assert_eq!(enc[0], 0x4d);
        let (data, n) = parse_push_bytes(&enc).unwrap();
        assert_eq!(data, &v[..]);
        assert_eq!(n, 303);
    }

    #[test]
    fn to_slice_matches_vec() {
        for n in [0usize, 75, 76, 255, 256, 70_000] {
            let v = vec![0x5au8; n];
            let mut buf = vec![0u8; push_bytes_len(n)];
            assert_eq!(push_bytes_to_slice(&v, &mut buf), Some(buf.len()));
            let (data, used) = parse_push_bytes(&buf).unwrap();
            assert_eq!((data, used), (&v[..], buf.len()));
            assert!(push_bytes_to_slice(&v, &mut buf[1..]).is_none());
        }
    }

    #[test]
    fn truncated() {
        assert!(parse_push_bytes(&[5, 1, 2]).is_none());
        assert!(parse_push_bytes(&[]).is_none());
    }
}
