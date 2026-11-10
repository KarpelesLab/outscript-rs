//! Small building blocks shared by the Orchard modules: the personalized
//! BLAKE2b instances of the protocol and the compact size encoding.

use purecrypto::hash::Blake2bMac;
use purecrypto::zeroize::Zeroizing;

use super::Error;
use super::fields::{Fp, Fq};

/// BLAKE2b with a personalization (no key, no salt) over the concatenation
/// of `parts`, into `out` (1 to 64 bytes).
pub(crate) fn blake2b(personal: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Blake2bMac::try_new_with_salt_personal(&[], out.len(), &[], personal)
        .expect("valid BLAKE2b parameters");
    for part in parts {
        h.update(part);
    }
    h.finalize_into(out);
}

/// `PRF^expand(sk, t)`: BLAKE2b-512 personalized with `Zcash_ExpandSeed` over
/// `sk || t`, the concatenation of `parts` being `t`. The output is wiped on
/// drop.
pub fn prf_expand(sk: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut out = Zeroizing::new([0u8; 64]);
    let mut h = Blake2bMac::try_new_with_salt_personal(&[], 64, &[], b"Zcash_ExpandSeed")
        .expect("valid BLAKE2b parameters");
    h.update(sk);
    for part in parts {
        h.update(part);
    }
    h.finalize_into(&mut out[..]);
    out
}

/// `ToScalar(PRF^expand(sk, t))`.
pub(crate) fn prf_expand_scalar(sk: &[u8], parts: &[&[u8]]) -> Fq {
    Fq::from_uniform_bytes(&prf_expand(sk, parts))
}

/// `ToBase(PRF^expand(sk, t))`.
pub(crate) fn prf_expand_base(sk: &[u8], parts: &[&[u8]]) -> Fp {
    Fp::from_uniform_bytes(&prf_expand(sk, parts))
}

/// Reads a canonical Bitcoin-style compact size off the front of `data`.
pub(crate) fn read_compact_size(data: &mut &[u8]) -> Result<u64, Error> {
    let (&first, rest) = data.split_first().ok_or(Error::UnexpectedEof)?;
    let (len, min): (usize, u64) = match first {
        0..=0xfc => {
            *data = rest;
            return Ok(first as u64);
        }
        0xfd => (2, 0xfd),
        0xfe => (4, 0x1_0000),
        0xff => (8, 0x1_0000_0000),
    };
    let bytes = rest.get(..len).ok_or(Error::UnexpectedEof)?;
    let mut le = [0u8; 8];
    le[..len].copy_from_slice(bytes);
    let value = u64::from_le_bytes(le);
    if value < min {
        return Err(Error::NonCanonical);
    }
    *data = &rest[len..];
    Ok(value)
}

/// The compact size encoding of `value`, as (bytes, length).
pub(crate) fn compact_size(value: u64) -> ([u8; 9], usize) {
    let mut out = [0u8; 9];
    let le = value.to_le_bytes();
    let len = match value {
        0..=0xfc => {
            out[0] = value as u8;
            return (out, 1);
        }
        0xfd..=0xffff => {
            out[0] = 0xfd;
            2
        }
        0x1_0000..=0xffff_ffff => {
            out[0] = 0xfe;
            4
        }
        _ => {
            out[0] = 0xff;
            8
        }
    };
    out[1..1 + len].copy_from_slice(&le[..len]);
    (out, 1 + len)
}

/// Takes `len` bytes off the front of `data`.
pub(crate) fn take<'a>(data: &mut &'a [u8], len: usize) -> Result<&'a [u8], Error> {
    let bytes = data.get(..len).ok_or(Error::UnexpectedEof)?;
    *data = &data[len..];
    Ok(bytes)
}

/// Takes an array off the front of `data`.
pub(crate) fn take_array<const N: usize>(data: &mut &[u8]) -> Result<[u8; N], Error> {
    let bytes = take(data, N)?;
    Ok(bytes.try_into().expect("N bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_sizes() {
        for v in [
            0u64,
            1,
            0xfc,
            0xfd,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ] {
            let (bytes, len) = compact_size(v);
            let mut data = &bytes[..len];
            assert_eq!(read_compact_size(&mut data), Ok(v));
            assert!(data.is_empty());
            let mut short = &bytes[..len - 1];
            assert_eq!(read_compact_size(&mut short), Err(Error::UnexpectedEof));
        }
        for bad in [
            &[0xfd, 0xfc, 0][..],
            &[0xfe, 0xff, 0xff, 0, 0],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0],
        ] {
            assert_eq!(read_compact_size(&mut &*bad), Err(Error::NonCanonical));
        }
    }
}
