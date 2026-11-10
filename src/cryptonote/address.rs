//! The CryptoNote address framing:
//! `base58(varint(prefix) || payload || cn_fast_hash(varint(prefix) || payload)[..4])`.
//!
//! The prefix (or "tag") names the network and the kind of address, and
//! decides the leading characters of the text; the payload is usually the
//! public spend and view keys, followed by whatever the kind adds (a payment
//! id, flags, ...). What the payload means is up to each chain.

use super::base58;
use super::{Error, Hasher, MAX_VARINT_LEN, read_varint, varint_len, write_varint};

#[cfg(feature = "alloc")]
use crate::prelude::*;

/// The length of the checksum that ends the framed data.
pub const ADDRESS_CHECKSUM_LEN: usize = 4;

/// The number of characters of the address with this prefix and a payload of
/// `payload_len` bytes: the buffer size [`encode_address_to_slice`] needs.
pub const fn address_encoded_len(prefix: u64, payload_len: usize) -> usize {
    base58::encoded_len(
        payload_len
            .saturating_add(varint_len(prefix))
            .saturating_add(ADDRESS_CHECKSUM_LEN),
    )
}

/// The number of bytes of scratch space [`decode_address_to_slice`] needs for
/// an address of `address_len` characters (prefix and checksum included, so a
/// little more than the payload), or `None` if no address has that length.
pub const fn address_decoded_len(address_len: usize) -> Option<usize> {
    base58::decoded_len(address_len)
}

/// Writes the address with this `prefix` and `payload` at the start of `out`,
/// returning its length ([`address_encoded_len`]). The output is ASCII.
///
/// Fails with [`Error::BufferTooSmall`] if `out` is too short.
pub fn encode_address_to_slice(
    prefix: u64,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut tag = [0u8; MAX_VARINT_LEN];
    let tag_len = write_varint(prefix, &mut tag)?;
    let tag = tag.get(..tag_len).unwrap_or(&[]);

    let mut h = Hasher::new();
    h.update(tag);
    h.update(payload);
    let checksum = h.finalize();

    let n = address_encoded_len(prefix, payload.len());
    let dst = out.get_mut(..n).ok_or(Error::BufferTooSmall)?;

    // Encode block by block, so that no buffer for the framed data is needed.
    let mut bytes = tag
        .iter()
        .chain(payload)
        .chain(checksum.iter().take(ADDRESS_CHECKSUM_LEN))
        .copied();
    // The last chunk of `dst` has exactly the length of a partial block.
    for chars in dst.chunks_mut(11) {
        let mut block = [0u8; 8];
        let mut len = 0;
        for (slot, byte) in block.iter_mut().zip(bytes.by_ref()) {
            *slot = byte;
            len += 1;
        }
        base58::encode_block(block.get(..len).unwrap_or(&[]), chars);
    }
    Ok(n)
}

/// Decodes `address` into `out`, returning the prefix and the length of the
/// payload, which is left at the start of `out`.
///
/// `out` is used as scratch space for the whole framed data, so it must hold
/// [`address_decoded_len`]`(address.len())` bytes; its content past the
/// payload, or after an error, is unspecified.
///
/// Fails with the errors of [`base58::decode_to_slice`],
/// [`Error::InvalidLength`] if the data is too short for a checksum and a
/// prefix, [`Error::BadChecksum`], and the errors of [`read_varint`] for a
/// malformed prefix. Checking the prefix and the payload against what the
/// chain expects is left to the caller.
pub fn decode_address_to_slice(address: &str, out: &mut [u8]) -> Result<(u64, usize), Error> {
    let n = base58::decode_to_slice(address, out)?;
    let data = out.get_mut(..n).ok_or(Error::BufferTooSmall)?;
    let body_len = match n.checked_sub(ADDRESS_CHECKSUM_LEN) {
        Some(len) if len > 0 => len,
        _ => return Err(Error::InvalidLength),
    };
    let (body, checksum) = data.split_at_mut(body_len);

    let mut h = Hasher::new();
    h.update(body);
    if h.finalize().get(..ADDRESS_CHECKSUM_LEN) != Some(&*checksum) {
        return Err(Error::BadChecksum);
    }

    let (prefix, tag_len) = read_varint(body)?;
    body.copy_within(tag_len.., 0);
    Ok((prefix, body_len.saturating_sub(tag_len)))
}

/// The address with this `prefix` and `payload`.
#[cfg(feature = "alloc")]
pub fn encode_address(prefix: u64, payload: &[u8]) -> String {
    let mut out = vec![0u8; address_encoded_len(prefix, payload.len())];
    // The buffer has the exact length; only alphabet characters are written.
    let n = encode_address_to_slice(prefix, payload, &mut out).unwrap_or(0);
    out.into_iter().take(n).map(char::from).collect()
}

/// Decodes `address` into its prefix and payload, with the errors of
/// [`decode_address_to_slice`].
#[cfg(feature = "alloc")]
pub fn decode_address(address: &str) -> Result<(u64, Vec<u8>), Error> {
    let mut out = vec![0u8; address_decoded_len(address.len()).ok_or(Error::InvalidLength)?];
    let (prefix, n) = decode_address_to_slice(address, &mut out)?;
    out.truncate(n);
    Ok((prefix, out))
}
