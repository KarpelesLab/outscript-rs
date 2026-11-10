//! Zcash Orchard shielded pool (feature `zcash-orchard`).
//!
//! Everything a wallet needs short of producing proofs, per the Zcash
//! protocol specification (NU5 and later) and ZIPs 32, 212, 224 and 316:
//!
//! - **Arithmetic**: the Pasta fields [`Fp`] and [`Fq`] ([`fields`]) and the
//!   curves [`pallas`] and [`vesta`], with hashing to the curve.
//! - **Hashes**: [`sinsemilla`] (hash, commit, short commit), [`poseidon`],
//!   and the fixed generators in [`constants`].
//! - **Keys** ([`keys`]): spending keys and their ZIP-32 derivation, full,
//!   incoming and outgoing viewing keys, diversified [`Address`]es.
//! - **Unified encodings** ([`unified`]): ZIP-316 unified addresses and
//!   viewing keys, of Revision 0 and of Revision 2 (with expiry and
//!   birthday metadata).
//! - **Notes** ([`note`], [`value`], [`tree`]): note commitments,
//!   nullifiers, value commitments, the note commitment tree and
//!   witnesses kept up to date as it grows.
//! - **Note encryption** ([`note_encryption`]): encryption to an address,
//!   trial decryption with an incoming viewing key (full or compact, one
//!   action at a time or many actions and keys at once), recovery with an
//!   outgoing viewing key.
//! - **Signatures** ([`redpallas`]): spend authorization and binding
//!   signatures, verified singly or in batches.
//! - **Bundles** ([`bundle`]): the Orchard part of a version 5 or version 6
//!   transaction, and the Ironwood part of a version 6 one.
//! - **Proofs** (feature `zcash-orchard-prover`): `circuit` verifies and
//!   creates the Halo 2 proofs of bundles, on the proving system of
//!   `halo2`; `builder` builds, proves and signs whole bundles.
//!
//! Keys, addresses, signatures and trial decryption work on fixed-size arrays
//! and never allocate, so they run on `no_std` targets without a heap; the
//! owned bundle and the unified containers need `alloc`.
//!
//! # The Ironwood pool
//!
//! From NU6.3 (ZIPs 229, 258, 2005 and 2006) the Orchard protocol serves
//! two value pools: the Orchard pool, which then only empties, and the
//! Ironwood pool. They share everything here (keys, addresses, the Action
//! circuit of NU6.3, signatures, the encoding of bundles, the shape of the
//! note commitment tree) but for three things: the notes of the Ironwood
//! pool are of another plaintext version
//! ([`NoteVersion::V3`](note::NoteVersion), whose commitment randomness
//! binds every field of the note; the `*_versioned` functions of
//! [`note_encryption`] read them), the flags of its bundles have an
//! `enableCrossAddress` bit ([`bundle::Flags::CROSS_ADDRESS_ENABLED`],
//! [`bundle::BundleRef::parse_ironwood`]), and its bundles are built with
//! `builder::Builder::new_ironwood`. Each pool has its own tree: an anchor
//! or a Merkle path of one means nothing in the other.
//!
//! ZIP 2005 also defines keys derived with a quantum spending key
//! (`use_qsk`), which are optional and which this module does not
//! implement, as `orchard` 0.16.0 does not: the keys here are the ones
//! that read and spend the notes of both pools at the addresses in use
//! before NU6.3.
//!
//! # For a prover
//!
//! An Orchard proof is a Halo 2 proof: the circuit is written over [`Fp`]
//! (the scalar field of [`vesta`]) and its polynomials are committed to with
//! an inner product argument on Vesta. What that needs is public here: both
//! fields with their `2^32` roots of unity
//! ([`Fp::ROOT_OF_UNITY`], [`Fp::S`], [`Fp::DELTA`], [`Fp::ZETA`],
//! [`Fp::TWO_INV`]), batch inversion, both curves with their endomorphism,
//! hashing to either curve (the commitment generators of Halo 2 are
//! `vesta::Point::hash_to_curve("Halo2-Parameters", ..)`), batch
//! normalization and a variable-time multi-scalar multiplication
//! ([`vesta::Point::msm_vartime`]), plus the Sinsemilla and Poseidon
//! constants the circuit's gadgets are built from.

#[cfg(feature = "zcash-orchard-prover")]
pub mod builder;
pub mod bundle;
#[cfg(feature = "zcash-orchard-prover")]
pub mod circuit;
pub mod constants;
mod curves;
pub mod fields;
#[cfg(feature = "zcash-orchard-prover")]
pub mod halo2;
pub mod keys;
pub mod note;
pub mod note_encryption;
#[cfg(feature = "alloc")]
mod par;
pub mod poseidon;
pub mod redpallas;
pub mod sinsemilla;
mod spec;
pub mod tree;
pub mod unified;
pub mod value;

#[cfg(test)]
mod tests;

pub use curves::{pallas, vesta};
pub use fields::{Fp, Fq};
pub use keys::{
    Address, Diversifier, DiversifierIndex, DiversifierKey, ExtendedSpendingKey, FullViewingKey,
    IncomingViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendValidatingKey,
    SpendingKey,
};
pub use note::{ExtractedNoteCommitment, Note, Nullifier};
#[cfg(feature = "std")]
pub use par::{max_threads, set_max_threads};
pub use spec::prf_expand;
pub use value::ValueCommitment;

/// Errors of the Orchard module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not a valid spending key (or extended spending key).
    InvalidSpendingKey,
    /// A ZIP-32 seed must be 32 to 252 bytes long.
    InvalidSeedLength,
    /// A ZIP-32 child index must be below `2^31`, and a key cannot be more
    /// than 255 levels deep.
    InvalidChildIndex,
    /// The bytes are not a valid full viewing key.
    InvalidFullViewingKey,
    /// The bytes are not a valid incoming viewing key.
    InvalidIncomingViewingKey,
    /// The bytes are not a valid raw address.
    InvalidAddress,
    /// The note is not valid (its `esk` is zero or its commitment
    /// undefined).
    InvalidNote,
    /// A signature does not verify, or is not canonically encoded.
    InvalidSignature,
    /// The proof of a bundle does not verify, or does not have the length
    /// its number of actions implies.
    InvalidProof,
    /// A point or field element is not canonically encoded.
    InvalidEncoding,
    /// The data ends before the structure does.
    UnexpectedEof,
    /// Data follows the end of the structure.
    TrailingData,
    /// A compact size is not in its shortest form.
    NonCanonical,
    /// A count or length does not fit.
    TooLarge,
    /// The flags of a bundle have unknown bits set.
    InvalidFlags,
    /// The output buffer is too small.
    BufferTooSmall,
    /// The note commitment tree is full.
    TreeFull,
    /// A unified encoding is not valid bech32m.
    Bech32(crate::bech32::Error),
    /// A unified encoding has an unknown or unexpected human-readable part.
    InvalidPrefix,
    /// A unified encoding is shorter or longer than F4Jumble allows.
    InvalidLength,
    /// The padding of a unified encoding is wrong.
    InvalidPadding,
    /// The items of a unified encoding are not in ascending typecode order.
    InvalidTypecodeOrder,
    /// A unified encoding has two items of the same typecode.
    DuplicateTypecode,
    /// A typecode is above the allowed maximum.
    InvalidTypecode,
    /// A unified address has both a P2PKH and a P2SH receiver.
    BothP2pkhAndP2sh,
    /// A unified encoding has only transparent items (or none).
    OnlyTransparent,
    /// An item of a unified encoding has the wrong length for its typecode,
    /// or is not allowed in this kind of encoding.
    InvalidItem,
    /// A unified encoding has a metadata item that must be understood to
    /// use it (typecodes `0xE0` to `0xFC`) and is not: unknown, or in an
    /// encoding of Revision 0, which cannot have any.
    MustUnderstand,
    /// A unified encoding has only metadata items (or none).
    OnlyMetadata,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Error::InvalidSpendingKey => "invalid Orchard spending key",
            Error::InvalidSeedLength => "ZIP-32 seed must be 32 to 252 bytes",
            Error::InvalidChildIndex => "invalid ZIP-32 child index",
            Error::InvalidFullViewingKey => "invalid Orchard full viewing key",
            Error::InvalidIncomingViewingKey => "invalid Orchard incoming viewing key",
            Error::InvalidAddress => "invalid Orchard address",
            Error::InvalidNote => "invalid Orchard note",
            Error::InvalidSignature => "invalid RedPallas signature",
            Error::InvalidProof => "invalid Orchard proof",
            Error::InvalidEncoding => "non-canonical point or field element",
            Error::UnexpectedEof => "unexpected end of data",
            Error::TrailingData => "trailing data",
            Error::NonCanonical => "non-canonical compact size",
            Error::TooLarge => "count or length too large",
            Error::InvalidFlags => "invalid Orchard flags",
            Error::BufferTooSmall => "output buffer too small",
            Error::TreeFull => "note commitment tree is full",
            Error::Bech32(e) => return write!(f, "bech32m: {e}"),
            Error::InvalidPrefix => "unexpected human-readable part",
            Error::InvalidLength => "invalid unified encoding length",
            Error::InvalidPadding => "invalid unified encoding padding",
            Error::InvalidTypecodeOrder => "unified items out of order",
            Error::DuplicateTypecode => "duplicate unified typecode",
            Error::InvalidTypecode => "invalid unified typecode",
            Error::BothP2pkhAndP2sh => "both P2PKH and P2SH receivers",
            Error::OnlyTransparent => "no shielded item",
            Error::InvalidItem => "invalid unified item",
            Error::MustUnderstand => "unified metadata that must be understood",
            Error::OnlyMetadata => "no receiver or key",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for Error {}

impl From<crate::bech32::Error> for Error {
    fn from(e: crate::bech32::Error) -> Self {
        Error::Bech32(e)
    }
}
