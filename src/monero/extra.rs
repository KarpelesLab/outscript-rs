//! The `extra` field of a transaction: the transaction public key, the
//! per-output public keys, the nonce (payment ids) and the rest.
//!
//! The field is a sequence of tagged entries. Nothing forces a transaction to
//! carry a well-formed one, so the parser hands out what it understands and
//! stops at the first entry it does not, as wallets do.

use super::Error;
use crate::cryptonote::read_varint;

#[cfg(feature = "alloc")]
use crate::cryptonote::push_varint;
#[cfg(feature = "alloc")]
use crate::prelude::*;

/// Tag of the padding entry.
pub const TX_EXTRA_TAG_PADDING: u8 = 0x00;
/// Tag of the transaction public key.
pub const TX_EXTRA_TAG_PUBKEY: u8 = 0x01;
/// Tag of the nonce.
pub const TX_EXTRA_TAG_NONCE: u8 = 0x02;
/// Tag of the merge-mining entry.
pub const TX_EXTRA_TAG_MERGE_MINING: u8 = 0x03;
/// Tag of the additional (per-output) public keys.
pub const TX_EXTRA_TAG_ADDITIONAL_PUBKEYS: u8 = 0x04;
/// Tag of the "mysterious MinerGate" entry.
pub const TX_EXTRA_TAG_MYSTERIOUS_MINERGATE: u8 = 0xde;

/// The longest nonce (and the longest padding).
pub const TX_EXTRA_NONCE_MAX_LEN: usize = 255;

/// First byte of a nonce holding a 32-byte unencrypted payment id.
pub const TX_EXTRA_NONCE_PAYMENT_ID: u8 = 0x00;
/// First byte of a nonce holding an 8-byte encrypted payment id.
pub const TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID: u8 = 0x01;

/// One entry of the extra field, borrowing from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtraField<'a> {
    /// Zero bytes up to the end of the field: the number of bytes after the
    /// tag.
    Padding(usize),
    /// The transaction public key `R`.
    PublicKey([u8; 32]),
    /// The nonce, usually a payment id (see [`PaymentId::from_nonce`]).
    Nonce(&'a [u8]),
    /// The merge-mining tag of a coinbase transaction.
    MergeMining {
        /// The depth of the merkle branch.
        depth: u64,
        /// The merkle root.
        merkle_root: [u8; 32],
    },
    /// The per-output public keys, 32 bytes each (see
    /// [`additional_keys`](Self::additional_keys)).
    AdditionalPublicKeys(&'a [u8]),
    /// The "mysterious MinerGate" entry.
    MysteriousMinergate(&'a [u8]),
}

impl<'a> ExtraField<'a> {
    /// The keys of an [`AdditionalPublicKeys`](Self::AdditionalPublicKeys)
    /// entry (nothing for the other entries).
    pub fn additional_keys(&self) -> impl ExactSizeIterator<Item = [u8; 32]> + 'a {
        let data: &'a [u8] = match *self {
            ExtraField::AdditionalPublicKeys(data) => data,
            _ => &[],
        };
        data.as_chunks::<32>().0.iter().copied()
    }
}

/// A payment id found in a nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentId {
    /// The long, unencrypted form (deprecated).
    Unencrypted([u8; 32]),
    /// The short form, encrypted for the recipient (see
    /// [`encrypt_payment_id`](super::encrypt_payment_id)).
    Encrypted([u8; 8]),
}

impl PaymentId {
    /// The payment id a nonce holds, if it is one.
    pub fn from_nonce(nonce: &[u8]) -> Option<PaymentId> {
        let (tag, id) = nonce.split_first()?;
        match *tag {
            TX_EXTRA_NONCE_PAYMENT_ID => Some(PaymentId::Unencrypted(id.try_into().ok()?)),
            TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID => Some(PaymentId::Encrypted(id.try_into().ok()?)),
            _ => None,
        }
    }
}

/// Splits `n` bytes off the front of `data`.
fn take<'a>(data: &mut &'a [u8], n: usize) -> Result<&'a [u8], Error> {
    let (head, tail) = data.split_at_checked(n).ok_or(Error::UnexpectedEof)?;
    *data = tail;
    Ok(head)
}

/// Reads a varint off the front of `data`.
fn take_varint(data: &mut &[u8]) -> Result<u64, Error> {
    let (value, n) = read_varint(data)?;
    take(data, n)?;
    Ok(value)
}

/// Reads a length-prefixed blob off the front of `data`.
fn take_blob<'a>(data: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let len = usize::try_from(take_varint(data)?).map_err(|_| Error::UnexpectedEof)?;
    take(data, len)
}

/// An iterator over the entries of an extra field.
///
/// It yields each entry in turn; at the first malformed or unknown entry it
/// yields the error and ends.
#[derive(Debug, Clone)]
pub struct ExtraIter<'a> {
    rest: &'a [u8],
}

/// Iterates over the entries of the extra field `extra`.
pub fn parse_extra(extra: &[u8]) -> ExtraIter<'_> {
    ExtraIter { rest: extra }
}

impl<'a> ExtraIter<'a> {
    fn read_field(&mut self) -> Result<ExtraField<'a>, Error> {
        let data = &mut self.rest;
        let tag = take(data, 1)?.first().copied().unwrap_or(0);
        Ok(match tag {
            TX_EXTRA_TAG_PADDING => {
                let padding = take(data, data.len())?;
                if padding.len() > TX_EXTRA_NONCE_MAX_LEN || padding.iter().any(|b| *b != 0) {
                    return Err(Error::InvalidExtra);
                }
                ExtraField::Padding(padding.len())
            }
            TX_EXTRA_TAG_PUBKEY => {
                let mut key = [0u8; 32];
                key.copy_from_slice(take(data, 32)?);
                ExtraField::PublicKey(key)
            }
            TX_EXTRA_TAG_NONCE => {
                let nonce = take_blob(data)?;
                if nonce.len() > TX_EXTRA_NONCE_MAX_LEN {
                    return Err(Error::InvalidExtra);
                }
                ExtraField::Nonce(nonce)
            }
            TX_EXTRA_TAG_MERGE_MINING => {
                let mut body = take_blob(data)?;
                let depth = take_varint(&mut body)?;
                let mut merkle_root = [0u8; 32];
                merkle_root.copy_from_slice(take(&mut body, 32)?);
                if !body.is_empty() {
                    return Err(Error::InvalidExtra);
                }
                ExtraField::MergeMining { depth, merkle_root }
            }
            TX_EXTRA_TAG_ADDITIONAL_PUBKEYS => {
                let count =
                    usize::try_from(take_varint(data)?).map_err(|_| Error::UnexpectedEof)?;
                let len = count.checked_mul(32).ok_or(Error::UnexpectedEof)?;
                ExtraField::AdditionalPublicKeys(take(data, len)?)
            }
            TX_EXTRA_TAG_MYSTERIOUS_MINERGATE => ExtraField::MysteriousMinergate(take_blob(data)?),
            _ => return Err(Error::InvalidExtra),
        })
    }
}

impl<'a> Iterator for ExtraIter<'a> {
    type Item = Result<ExtraField<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let field = self.read_field();
        if field.is_err() {
            self.rest = &[];
        }
        Some(field)
    }
}

/// The well-formed entries at the start of `extra`.
fn fields(extra: &[u8]) -> impl Iterator<Item = ExtraField<'_>> {
    parse_extra(extra).map_while(Result::ok)
}

/// The transaction public keys in `extra`. There is normally one; a wallet
/// tries each when there are more.
pub fn tx_public_keys(extra: &[u8]) -> impl Iterator<Item = [u8; 32]> + '_ {
    fields(extra).filter_map(|field| match field {
        ExtraField::PublicKey(key) => Some(key),
        _ => None,
    })
}

/// The first transaction public key in `extra`.
pub fn tx_public_key(extra: &[u8]) -> Option<[u8; 32]> {
    tx_public_keys(extra).next()
}

/// The per-output public keys in `extra` (those of the first such entry), 32
/// bytes each; empty if there are none.
pub fn additional_public_keys(extra: &[u8]) -> &[u8] {
    fields(extra)
        .find_map(|field| match field {
            ExtraField::AdditionalPublicKeys(keys) => Some(keys),
            _ => None,
        })
        .unwrap_or(&[])
}

/// The per-output public key of the output `index`, when `extra` has exactly
/// one for each of the transaction's `outputs` outputs (otherwise they are
/// ignored, as wallets do).
pub fn additional_public_key(extra: &[u8], outputs: usize, index: usize) -> Option<[u8; 32]> {
    let keys = additional_public_keys(extra);
    if keys.len() / 32 != outputs {
        return None;
    }
    keys.as_chunks::<32>().0.get(index).copied()
}

/// The payment id in `extra`: that of the first nonce holding one.
pub fn payment_id(extra: &[u8]) -> Option<PaymentId> {
    fields(extra).find_map(|field| match field {
        ExtraField::Nonce(nonce) => PaymentId::from_nonce(nonce),
        _ => None,
    })
}

/// Appends a transaction public key entry to `extra`.
#[cfg(feature = "alloc")]
pub fn push_tx_public_key(extra: &mut Vec<u8>, key: &[u8; 32]) {
    extra.push(TX_EXTRA_TAG_PUBKEY);
    extra.extend_from_slice(key);
}

/// Appends a nonce entry to `extra`.
///
/// Fails with [`Error::InvalidExtra`] if the nonce is longer than
/// [`TX_EXTRA_NONCE_MAX_LEN`].
#[cfg(feature = "alloc")]
pub fn push_nonce(extra: &mut Vec<u8>, nonce: &[u8]) -> Result<(), Error> {
    if nonce.len() > TX_EXTRA_NONCE_MAX_LEN {
        return Err(Error::InvalidExtra);
    }
    extra.push(TX_EXTRA_TAG_NONCE);
    push_varint(extra, nonce.len() as u64);
    extra.extend_from_slice(nonce);
    Ok(())
}

/// Appends a nonce holding a payment id to `extra`.
#[cfg(feature = "alloc")]
pub fn push_payment_id(extra: &mut Vec<u8>, id: &PaymentId) {
    extra.push(TX_EXTRA_TAG_NONCE);
    match id {
        PaymentId::Unencrypted(id) => {
            extra.push(33);
            extra.push(TX_EXTRA_NONCE_PAYMENT_ID);
            extra.extend_from_slice(id);
        }
        PaymentId::Encrypted(id) => {
            extra.push(9);
            extra.push(TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID);
            extra.extend_from_slice(id);
        }
    }
}

/// Appends the per-output public keys entry to `extra`.
#[cfg(feature = "alloc")]
pub fn push_additional_public_keys(extra: &mut Vec<u8>, keys: &[[u8; 32]]) {
    extra.push(TX_EXTRA_TAG_ADDITIONAL_PUBKEYS);
    push_varint(extra, keys.len() as u64);
    for key in keys {
        extra.extend_from_slice(key);
    }
}
