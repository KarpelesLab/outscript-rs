//! Monero: addresses, keys and transactions, built on the primitives the
//! CryptoNote family shares ([`cryptonote`](crate::cryptonote)).
//!
//! Keys, scalars and points go in and out as `[u8; 32]`, as in `cryptonote`
//! (scalars little-endian and reduced, points compressed). Amounts are in
//! atomic units (piconero, 10^-12 XMR).
//!
//! # What is here
//!
//! - **Addresses**: [`Address`] — standard, integrated (with an 8-byte
//!   payment id) and subaddress, on mainnet, testnet and stagenet — parsed
//!   and printed as base58 without a heap.
//! - **Keys**: [`AccountKeys`] (spend and view secrets, from a seed or a
//!   spend key), the view-only [`ViewKeys`], subaddresses by
//!   [`SubaddressIndex`], and the 25-word English mnemonic
//!   ([`seed_from_mnemonic`], [`seed_to_mnemonic_words`]).
//! - **Scanning**: [`ViewKeys::key_derivation`] and
//!   [`ViewKeys::check_output`] recognise an output (view tag first, then the
//!   main address or a subaddress from the caller's table);
//!   [`decode_amount`] opens its amount and mask against the commitment;
//!   [`AccountKeys::output_key_image`] gives the one-time secret key and the
//!   key image. With `alloc`, `ViewKeys::scan_transaction` does all of it
//!   for a parsed transaction.
//! - **The extra field**: [`parse_extra`] and the lookups on top of it
//!   ([`tx_public_key`], [`additional_public_key`], [`payment_id`]).
//! - **RingCT**: Pedersen commitments ([`commit`], [`zero_commit`],
//!   [`verify_balance`]) and CLSAG ring signatures ([`clsag_sign`],
//!   [`clsag_verify`]) without a heap; with `alloc`, the Bulletproofs+ range
//!   proof (`BulletproofPlus`).
//! - **Transactions** (with `alloc`): `Transaction` parses and serializes
//!   every format the chain has seen — version 1, and RingCT types 0 to 6 —
//!   and computes the transaction id and the hash the signatures sign;
//!   for the current format (version 2, RingCT type 6: CLSAG and
//!   Bulletproofs+) it also verifies the ring signatures, the range proof
//!   and the balance. `TransactionBuilder` builds and signs such a
//!   transaction from the caller's inputs, rings and destinations.
//!
//! Not here: decoy selection, fee estimation, the daemon RPC, verification
//! of the proofs of the older formats (MLSAG, Borromean, the original
//! Bulletproofs), and multisignature.
//!
//! # Randomness
//!
//! The crate has no random number generator. Whatever needs randomness —
//! [`clsag_sign`], `BulletproofPlus::prove`, `TransactionBuilder::build` —
//! takes `rng: &mut dyn FnMut(&mut [u8])`, which must fill the slice it is
//! given with cryptographically secure random bytes on every call. Transaction
//! keys, commitment masks and signature nonces come from it: a predictable or
//! repeating source reveals amounts and secret keys. A source that leaves its
//! buffer zeroed is detected ([`Error::BadRandomness`]); nothing else about
//! its quality can be.
//!
//! # Secrets and timing
//!
//! Secret keys are held in [`Zeroizing`] buffers
//! and wiped on drop, as are the secret-derived intermediates. Scalar
//! multiplications by a secret use `purecrypto`'s constant-time ones, and the
//! multi-scalar multiplications of the Bulletproofs+ prover pick their table
//! entries without branching or indexing on the scalars. Verification is
//! variable-time and only sees public data. The position of the real output
//! in a ring is not hidden from an observer of the local machine's timing:
//! signing walks the ring starting from it.
//!
//! # Untrusted input
//!
//! Parsing addresses, extra fields and transactions never panics, and a
//! count read from the data never causes an allocation larger than the data
//! itself. Parsing checks the structure only; verifying is a separate step.
//!
//! # Example
//!
//! Keys and addresses, then recognising and opening an output the way a
//! wallet does (here the sender's side is played with the shared
//! primitives):
//!
//! ```
//! use outscript::cryptonote::{derivation_to_scalar, derive_public_key, generate_key_derivation};
//! use outscript::monero::{
//!     AccountKeys, Address, Network, SubaddressIndex, commit, commitment_mask, decode_amount,
//!     derive_view_tag, encrypt_amount, seed_from_mnemonic,
//! };
//!
//! let seed = seed_from_mnemonic(
//!     "washing thirsty occur lectures tuesday fainted toxic adapt \
//!      abnormal memoir nylon mostly building shrugged online ember northern \
//!      ruby woes dauntless boil family illness inroads northern",
//! )?;
//! let account = AccountKeys::from_seed(&seed)?;
//! let address = account.address(Network::Mainnet);
//! let mut text = [0u8; outscript::monero::MAX_ADDRESS_LEN];
//! let n = address.encode_to_slice(&mut text)?;
//! let text = core::str::from_utf8(&text[..n]).unwrap();
//! assert_eq!(Address::decode(text)?, address);
//!
//! // A sender with the transaction secret key `r` pays output 0 to the address.
//! let mut r = [0u8; 32];
//! r[0] = 42;
//! let tx_public = outscript::cryptonote::secret_key_to_public_key(&r)?;
//! let derivation = generate_key_derivation(&address.view_public, &r)?;
//! let output_key = derive_public_key(&derivation, 0, &address.spend_public)?;
//! let view_tag = derive_view_tag(&derivation, 0);
//! let shared = derivation_to_scalar(&derivation, 0);
//! let encrypted_amount = encrypt_amount(&shared, 1_500_000_000_000);
//! let commitment = commit(1_500_000_000_000, &commitment_mask(&shared))?;
//!
//! // The recipient, with the view key only, finds and opens it.
//! let view = account.view_keys();
//! let derivation = view.key_derivation(&tx_public)?;
//! let found = view.check_output(&derivation, 0, &output_key, Some(view_tag), &mut |_| None)?;
//! assert_eq!(found, Some(SubaddressIndex::MAIN));
//! let opened = decode_amount(&derivation, 0, &encrypted_amount, &commitment)?;
//! assert_eq!(opened.amount, 1_500_000_000_000);
//!
//! // With the spend key: the one-time secret key and the key image.
//! let (_secret, _key_image) =
//!     account.output_key_image(&derivation, 0, SubaddressIndex::MAIN, &output_key)?;
//! # Ok::<(), outscript::monero::Error>(())
//! ```
//!
//! Building a transaction is shown with `TransactionBuilder`.

mod address;
#[cfg(feature = "alloc")]
mod bp_common;
#[cfg(feature = "alloc")]
mod build;
#[cfg(feature = "alloc")]
mod bulletproofs;
#[cfg(feature = "alloc")]
mod bulletproofs_plus;
mod clsag;
mod extra;
mod keys;
mod legacy_sig;
mod mnemonic;
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
pub use bulletproofs::{BULLETPROOF_MAX_OUTPUTS, BulletproofGenerators};
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
pub use legacy_sig::{BORROMEAN_PROOF_LEN, borromean_verify, check_ring_signature};
pub use mnemonic::{
    MNEMONIC_WORDS, MnemonicLanguage, seed_from_mnemonic, seed_from_mnemonic_any,
    seed_from_mnemonic_in, seed_to_mnemonic_words, seed_to_mnemonic_words_in,
};
#[cfg(feature = "alloc")]
pub use mnemonic::{seed_to_mnemonic, seed_to_mnemonic_in};
pub use ringct::{H, commit, verify_balance, zero_commit};
#[cfg(feature = "alloc")]
pub use scan::OwnedOutput;
pub use scan::{
    OutputAmount, commitment_mask, decode_amount, decode_amount_legacy, decrypt_amount,
    derive_subaddress_public_key, derive_view_tag, encrypt_amount, encrypt_amount_legacy,
    encrypt_payment_id,
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
