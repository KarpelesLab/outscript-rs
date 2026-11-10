//! Zcash Sapling shielded pool (feature `zcash-sapling`).
//!
//! Everything a wallet needs, following the Zcash protocol specification
//! (NU5/NU6) and ZIPs 32, 212, 216 and 225:
//!
//! - [`field`] and [`jubjub`]: the Jubjub curve and its two fields;
//! - [`group_hash`], [`generators`] and [`pedersen`]: `GroupHash`, the fixed
//!   generators, Pedersen hashes and commitments;
//! - [`tree`]: the note commitment tree (`MerkleCRH`, empty roots, frontiers,
//!   witnesses and authentication paths);
//! - [`keys`] and [`zip32`]: spending, viewing and incoming viewing keys,
//!   payment addresses, hierarchical derivation and their Bech32 encodings;
//! - [`note`]: notes, note commitments, nullifiers and value commitments;
//! - [`note_encryption`]: note encryption, trial decryption and recovery
//!   with an outgoing viewing key;
//! - [`redjubjub`]: the spend authorization and binding signature schemes;
//! - [`bundle`]: the Sapling part of a v5 transaction.
//!
//! Keys, addresses, signatures, trees and trial decryption work without an
//! allocator; only the owned bundle type needs `alloc`.
//!
//! All secret-dependent curve arithmetic is constant time, and types holding
//! secret keys wipe themselves when dropped.
//!
//! # Proofs and shielded transactions
//!
//! The feature `zcash-sapling-prover` (not in the default set; it needs an
//! allocator and enables `purecrypto`'s BLS12-381) adds the proof system:
//!
//! - `groth16`: Groth16 over BLS12-381, compatible with `bellman` (the
//!   parameter file format, proof creation and verification);
//! - `circuit`: the Spend and Output circuits;
//! - `prover`: the Sapling proving parameters (supplied by the caller and
//!   checked by hash), the embedded verifying keys, and typed proving and
//!   verification of Spend and Output descriptions;
//! - `builder`: a builder that turns notes to spend and outputs to create
//!   into a complete, proven and signed Sapling bundle for
//!   [`zcashtx`](crate::zcashtx).
//!
//! Verifying proofs needs no external file; creating them needs
//! `sapling-spend.params` and `sapling-output.params`. The prover's
//! multi-scalar multiplications run in variable time, as in every Groth16
//! prover.
//!
//! # Building blocks for a prover
//!
//! The pieces the circuits are synthesized from are public: field and curve
//! arithmetic with `const` constructors ([`field::Fq`],
//! [`jubjub::AffinePoint`]), the generators and their window tables
//! ([`generators`]), the Pedersen hash chunk encoding and segment generators
//! ([`pedersen`]), and the bit decompositions the circuits consume
//! ([`pedersen::bits_le`], [`note::note_commitment_bits`]).

#[cfg(feature = "zcash-sapling-prover")]
pub mod builder;
pub mod bundle;
#[cfg(feature = "zcash-sapling-prover")]
pub mod circuit;
pub mod field;
pub mod generators;
#[cfg(feature = "zcash-sapling-prover")]
pub mod groth16;
pub mod group_hash;
pub mod jubjub;
pub mod keys;
pub mod note;
pub mod note_encryption;
pub mod pedersen;
pub mod prf;
#[cfg(feature = "zcash-sapling-prover")]
pub mod prover;
pub mod redjubjub;
pub mod tree;
pub mod zip32;

#[cfg(test)]
mod test_vectors;

pub use field::{Fq, Fr};
pub use jubjub::{AffinePoint, Point};

/// Errors from Sapling operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A byte string is not the canonical encoding of a Jubjub point, or the
    /// point is not in the subgroup the context requires.
    InvalidPoint,
    /// A byte string is not the canonical encoding of a scalar or field
    /// element, or the value is not allowed in its context (such as a zero
    /// key).
    InvalidScalar,
    /// The diversifier does not hash to a point of the curve.
    InvalidDiversifier,
    /// The encoding of a payment address is malformed.
    InvalidAddress,
    /// The encoding of a key is malformed.
    InvalidKey,
    /// A hardened child cannot be derived from a viewing key.
    InvalidChildIndex,
    /// The derivation would exceed the maximum depth of 255.
    MaxDepthExceeded,
    /// The Bech32 string is malformed.
    Bech32(crate::bech32::Error),
    /// The Bech32 string has another human-readable part, checksum variant
    /// or payload length than expected.
    InvalidEncoding,
    /// The output buffer is too small.
    BufferTooSmall,
    /// The note plaintext is malformed (unknown lead byte, bad randomness).
    InvalidNotePlaintext,
    /// A signature does not verify.
    InvalidSignature,
    /// A value or value balance is outside the allowed range.
    ValueOutOfRange,
    /// The serialized bundle ends early.
    UnexpectedEof,
    /// Bytes are left after the bundle.
    TrailingData,
    /// A length prefix is not minimally encoded or is implausibly large.
    InvalidLength,
    /// The note commitment tree is full, or a position is outside it.
    TreeFull,
    /// The authentication path does not belong to this tree or leaf.
    InvalidPath,
    /// The random bytes supplied have the wrong length.
    RandomLength,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidPoint => f.write_str("invalid Jubjub point"),
            Error::InvalidScalar => f.write_str("invalid scalar"),
            Error::InvalidDiversifier => f.write_str("invalid diversifier"),
            Error::InvalidAddress => f.write_str("invalid Sapling payment address"),
            Error::InvalidKey => f.write_str("invalid Sapling key"),
            Error::InvalidChildIndex => f.write_str("invalid child index"),
            Error::MaxDepthExceeded => f.write_str("maximum derivation depth exceeded"),
            Error::Bech32(e) => write!(f, "bech32: {e}"),
            Error::InvalidEncoding => f.write_str("unexpected prefix or length"),
            Error::BufferTooSmall => f.write_str("output buffer too small"),
            Error::InvalidNotePlaintext => f.write_str("invalid note plaintext"),
            Error::InvalidSignature => f.write_str("invalid signature"),
            Error::ValueOutOfRange => f.write_str("value out of range"),
            Error::UnexpectedEof => f.write_str("unexpected end of data"),
            Error::TrailingData => f.write_str("trailing data"),
            Error::InvalidLength => f.write_str("invalid length prefix"),
            Error::TreeFull => f.write_str("note commitment tree is full"),
            Error::InvalidPath => f.write_str("invalid authentication path"),
            Error::RandomLength => f.write_str("wrong amount of randomness"),
        }
    }
}

impl core::error::Error for Error {}

impl From<crate::bech32::Error> for Error {
    fn from(e: crate::bech32::Error) -> Self {
        Error::Bech32(e)
    }
}
