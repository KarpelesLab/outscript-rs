//! Monero: addresses, keys and transactions, built on the primitives the
//! CryptoNote family shares ([`cryptonote`](crate::cryptonote)).
//!
//! Keys and points go in and out as `[u8; 32]`, as in `cryptonote`.

mod address;
#[cfg(feature = "alloc")]
mod build;
#[cfg(feature = "alloc")]
mod bulletproofs_plus;
mod clsag;
mod extra;
mod keys;
mod ringct;
mod scan;
#[cfg(feature = "alloc")]
mod tx;

#[cfg(test)]
mod tests;

pub use address::{
    Address, AddressKind, MAX_ADDRESS_LEN, Network, PAYMENT_ID_LEN, STANDARD_ADDRESS_LEN,
};
#[cfg(feature = "alloc")]
pub use build::{BuiltTransaction, TransactionBuilder, TransactionInput};
#[cfg(feature = "alloc")]
pub use bulletproofs_plus::{
    BULLETPROOF_PLUS_MAX_OUTPUTS, BulletproofPlus, BulletproofPlusGenerators,
};
#[cfg(feature = "alloc")]
pub use clsag::Clsag;
pub use clsag::{ClsagParts, RingMember, clsag_sign, clsag_verify};
pub use extra::{
    ExtraField, ExtraIter, PaymentId, TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID, TX_EXTRA_NONCE_MAX_LEN,
    TX_EXTRA_NONCE_PAYMENT_ID, TX_EXTRA_TAG_ADDITIONAL_PUBKEYS, TX_EXTRA_TAG_MERGE_MINING,
    TX_EXTRA_TAG_MYSTERIOUS_MINERGATE, TX_EXTRA_TAG_NONCE, TX_EXTRA_TAG_PADDING,
    TX_EXTRA_TAG_PUBKEY, additional_public_key, additional_public_keys, parse_extra, payment_id,
    tx_public_key, tx_public_keys,
};
#[cfg(feature = "alloc")]
pub use extra::{push_additional_public_keys, push_nonce, push_payment_id, push_tx_public_key};
pub use keys::{AccountKeys, SubaddressIndex, ViewKeys, subaddress_secret_key};
pub use ringct::{H, commit, verify_balance, zero_commit};
#[cfg(feature = "alloc")]
pub use scan::OwnedOutput;
pub use scan::{
    OutputAmount, commitment_mask, decode_amount, decrypt_amount, derive_subaddress_public_key,
    derive_view_tag, encrypt_amount, encrypt_payment_id,
};
#[cfg(feature = "alloc")]
pub use tx::{
    Bulletproof, EcdhInfo, Input, Mlsag, Output, RCT_TYPE_BULLETPROOF, RCT_TYPE_BULLETPROOF_PLUS,
    RCT_TYPE_BULLETPROOF2, RCT_TYPE_CLSAG, RCT_TYPE_FULL, RCT_TYPE_NULL, RCT_TYPE_SIMPLE, RangeSig,
    RctSignatures, Transaction, TransactionPrefix, output_commitment, relative_offsets,
};

use crate::cryptonote::Scalar;
use purecrypto::zeroize::Zeroizing;

/// Errors specific to Monero.
///
/// It converts into the crate's [`Error`](crate::Error) (as
/// [`Error::Monero`](crate::Error::Monero)), so `?` composes; so does the
/// shared [`cryptonote::Error`](crate::cryptonote::Error), which this one
/// wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An error of the shared CryptoNote primitives: a bad varint, base58
    /// text or checksum, a key that is not a curve point, a secret that is
    /// not a reduced scalar, a buffer too small.
    CryptoNote(crate::cryptonote::Error),
    /// The address has an unknown prefix, a payload of the wrong length or
    /// keys that are not curve points, or cannot be used this way.
    InvalidAddress,
    /// The data ended in the middle of a value, or a count in it calls for
    /// more data than there is.
    UnexpectedEof,
    /// Data is left after the end of the value.
    TrailingData,
    /// The transaction version, RingCT type or kind of input or output is
    /// not supported.
    Unsupported,
    /// The transaction is malformed: its parts do not fit together.
    InvalidTransaction,
    /// The extra field has a malformed or unknown entry.
    InvalidExtra,
    /// The amount and mask of an output do not open its commitment.
    CommitmentMismatch,
    /// A secret key does not belong to the public key or commitment it is
    /// used for.
    KeyMismatch,
    /// A ring is empty, of the wrong size, not in increasing order, or does
    /// not contain the output being spent.
    InvalidRing,
    /// A range proof cannot be made for these values (none, too many, or
    /// not as many masks as amounts).
    InvalidProof,
    /// The random source returned only zeros.
    BadRandomness,
    /// The transaction being built does not add up: no inputs, fewer than
    /// two outputs, more than sixteen, or the inputs do not equal the
    /// outputs plus the fee.
    InvalidAmounts,
    /// The mnemonic has the wrong number of words, a word that is not in
    /// the list, or a bad checksum.
    InvalidMnemonic,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::CryptoNote(e) => return e.fmt(f),
            Error::InvalidAddress => "invalid Monero address",
            Error::UnexpectedEof => "unexpected end of data",
            Error::TrailingData => "trailing data",
            Error::Unsupported => "unsupported transaction format",
            Error::InvalidTransaction => "malformed transaction",
            Error::InvalidExtra => "malformed transaction extra field",
            Error::CommitmentMismatch => "amount does not match the commitment",
            Error::KeyMismatch => "secret key does not match the public key",
            Error::InvalidRing => "invalid ring",
            Error::InvalidProof => "invalid range proof input",
            Error::BadRandomness => "random source returned zeros",
            Error::InvalidAmounts => "transaction amounts do not balance",
            Error::InvalidMnemonic => "invalid mnemonic",
        })
    }
}

impl core::error::Error for Error {}

impl From<crate::cryptonote::Error> for Error {
    fn from(e: crate::cryptonote::Error) -> Self {
        Error::CryptoNote(e)
    }
}

/// A uniformly random non-zero scalar from the caller's random source: 64
/// bytes reduced modulo the group order.
///
/// Fails with [`Error::BadRandomness`] if the source keeps giving zero, which
/// is what a source that does not write anything looks like.
pub(crate) fn random_scalar(rng: &mut dyn FnMut(&mut [u8])) -> Result<Scalar, Error> {
    for _ in 0..4 {
        let mut wide = Zeroizing::new([0u8; 64]);
        rng(&mut *wide);
        let scalar = Scalar::from_bytes_mod_order(&wide);
        if scalar != Scalar::ZERO {
            return Ok(scalar);
        }
    }
    Err(Error::BadRandomness)
}

/// A random secret key (for a transaction, or for one of its outputs).
#[cfg(any(feature = "alloc", test))]
pub(crate) fn random_secret(rng: &mut dyn FnMut(&mut [u8])) -> Result<Zeroizing<[u8; 32]>, Error> {
    Ok(Zeroizing::new(random_scalar(rng)?.to_bytes()))
}
