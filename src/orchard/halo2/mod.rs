//! A Halo 2 proving system over the Pasta curves, compatible with the
//! `halo2_proofs` crate Zcash uses for Orchard (feature
//! `zcash-orchard-prover`).
//!
//! This is a reimplementation of the parts of `halo2_proofs` an Orchard
//! Action proof needs, specialized to circuits over [`Fp`](super::Fp) with
//! polynomial commitments on [`vesta`](super::vesta): the PLONKish
//! constraint system ([`plonk`]), circuit synthesis with the `V1` floor
//! planner ([`circuit`]), and the polynomial, commitment, transcript and
//! proof machinery built on them. Layout, key generation, transcript and
//! proof encoding follow the reference exactly: verifying keys are equal and
//! proofs are interchangeable.
//!
//! The frontend types keep the names and shapes of `halo2_proofs` (which is
//! dual-licensed MIT/Apache-2.0), so that circuits written for it port
//! mechanically.

pub mod circuit;
mod commitment;
#[cfg(test)]
pub(crate) mod dev;
mod keygen;
mod multiopen;
mod pdqsort;
pub mod plonk;
mod poly;
mod prover;
#[cfg(test)]
mod tests;
mod transcript;
mod value;
mod verifier;

#[cfg(feature = "std")]
pub use super::par::{max_threads, set_max_threads};
pub use commitment::Params;
#[cfg(test)]
pub(crate) use keygen::keygen_vk_with_plan;
pub(crate) use keygen::vk_from_parts;
pub use keygen::{PinnedVerificationKey, ProvingKey, VerifyingKey, keygen_pk, keygen_vk};
pub use prover::create_proof;
pub(crate) use prover::create_proof_sync;
pub use value::Value;
pub use verifier::{BatchVerifier, verify_proof};

/// Errors of circuit synthesis, key generation, proving and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A witness is missing, or does not satisfy the circuit.
    Synthesis,
    /// The circuit does not fit in the rows available.
    NotEnoughRows,
    /// A cell is outside the circuit.
    BoundsFailure,
    /// A copy constraint involves a column without equality enabled.
    ColumnNotInPermutation,
    /// The public inputs do not have the shape the circuit expects.
    InvalidInstances,
    /// The proof is malformed or does not verify.
    InvalidProof,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::Synthesis => "circuit synthesis failed",
            Error::NotEnoughRows => "not enough rows in the circuit",
            Error::BoundsFailure => "cell out of bounds",
            Error::ColumnNotInPermutation => "column not in the permutation",
            Error::InvalidInstances => "invalid public inputs",
            Error::InvalidProof => "invalid proof",
        })
    }
}

impl core::error::Error for Error {}
