//! Groth16 over BLS12-381 (feature `zcash-sapling-prover`): the proof
//! system of the Sapling Spend and Output circuits.
//!
//! This is a from-scratch implementation that is interoperable with
//! `bellman`'s `groth16` module, byte for byte:
//!
//! - [`Parameters`] and [`VerifyingKey`] parse the `bellman` parameter file
//!   format (what `sapling-spend.params` and `sapling-output.params` are);
//! - [`create_proof`] produces, for the same circuit, witness and blinding
//!   scalars, the same [`Proof`] as `bellman::groth16::create_proof`;
//! - [`verify_proof`] accepts exactly the proofs `bellman` accepts.
//!
//! Circuits are written against the [`ConstraintSystem`] trait and
//! implement [`Circuit`]. The Sapling circuits are in
//! [`circuit`](super::circuit); most users want the typed wrappers in
//! [`prover`](super::prover) rather than this module.
//!
//! The pairing, the groups and their encodings come from `purecrypto::bls`;
//! the scalar field is [`Fq`], the field the circuits compute in.
//!
//! # Side channels
//!
//! Like every practical Groth16 prover, [`create_proof`] runs its
//! multi-scalar multiplications over the witness in variable time (zero and
//! one scalars are skipped, and bucket additions branch on the points), and
//! witness synthesis branches on witness bits. The blinding scalars `r` and
//! `s` are only ever used with the constant-time group arithmetic of
//! `purecrypto`. The witness vectors are wiped when a proof is done.
//!
//! # Randomness
//!
//! The crate has no random number generator: [`create_proof`] takes the two
//! blinding scalars from the caller. They must be uniformly random and never
//! reused; derive them from 64 random bytes each with
//! [`Fq::from_bytes_wide`], which is also how `bellman` samples them from
//! its generator.

mod curve;
mod domain;
mod prover;
mod r1cs;

use crate::prelude::*;
use crate::sapling::field::Fq;
use curve::Affine;
use purecrypto::bls::{Fp, Fp2, Fr, G1, G2, Gt, multi_pairing, pairing};

pub use prover::create_proof;
#[cfg(test)]
pub(crate) use r1cs::test::TestConstraintSystem;
pub use r1cs::{Circuit, ConstraintSystem, LinearCombination, SynthesisError, Variable};

/// The size of an encoded proof: two compressed `G1` points and one
/// compressed `G2` point.
pub const PROOF_SIZE: usize = 192;

/// Errors from decoding and verifying.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The data ends before the structure is complete.
    UnexpectedEof,
    /// Bytes are left after the structure.
    TrailingData,
    /// A point is not a valid encoding of an element of its group.
    InvalidPoint,
    /// A point is the identity where none is allowed.
    PointAtInfinity,
    /// The number of public inputs does not fit the verifying key.
    InvalidVerifyingKey,
    /// The proof does not verify.
    InvalidProof,
    /// A public input is not valid for the statement (a non-canonical
    /// field element, a point off the curve or of small order).
    InvalidPublicInput,
    /// The parameters are not the expected ones: their hash differs.
    HashMismatch,
    /// Reading the parameters failed.
    Io,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::UnexpectedEof => "unexpected end of data",
            Error::TrailingData => "trailing data",
            Error::InvalidPoint => "invalid BLS12-381 point",
            Error::PointAtInfinity => "point at infinity",
            Error::InvalidVerifyingKey => "public inputs do not fit the verifying key",
            Error::InvalidProof => "proof verification failed",
            Error::InvalidPublicInput => "invalid public input",
            Error::HashMismatch => "parameter hash mismatch",
            Error::Io => "could not read the parameters",
        })
    }
}

impl core::error::Error for Error {}

/// The scalar as `purecrypto`'s scalar type (same field, big-endian
/// encoding).
pub(crate) fn to_bls_scalar(s: &Fq) -> Fr {
    let mut be = s.to_bytes();
    be.reverse();
    // canonical by construction
    Fr::from_bytes(&be).unwrap_or(Fr::ZERO)
}

/// A cursor over untrusted bytes.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::UnexpectedEof);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<usize, Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }

    fn g1(&mut self) -> Result<G1, Error> {
        G1::from_uncompressed(self.take(96)?).map_err(|_| Error::InvalidPoint)
    }

    fn g2(&mut self) -> Result<G2, Error> {
        G2::from_uncompressed(self.take(192)?).map_err(|_| Error::InvalidPoint)
    }

    /// A length prefix followed by that many `size`-byte elements: the
    /// bytes of the elements, after checking that they are all there.
    fn vector(&mut self, size: usize) -> Result<&'a [u8], Error> {
        let len = self.u32()?;
        let bytes = len.checked_mul(size).ok_or(Error::UnexpectedEof)?;
        self.take(bytes)
    }
}

/// A Groth16 proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    /// `A`, in `G1`.
    pub a: G1,
    /// `B`, in `G2`.
    pub b: G2,
    /// `C`, in `G1`.
    pub c: G1,
}

impl Proof {
    /// Decodes a proof: compressed `A`, `B` and `C`. Each must be a valid
    /// encoding of a point of the prime-order group other than the
    /// identity.
    pub fn from_bytes(bytes: &[u8; PROOF_SIZE]) -> Result<Self, Error> {
        let a = G1::from_compressed(&bytes[..48]).map_err(|_| Error::InvalidPoint)?;
        let b = G2::from_compressed(&bytes[48..144]).map_err(|_| Error::InvalidPoint)?;
        let c = G1::from_compressed(&bytes[144..]).map_err(|_| Error::InvalidPoint)?;
        if bool::from(a.is_identity() | b.is_identity() | c.is_identity()) {
            return Err(Error::PointAtInfinity);
        }
        Ok(Proof { a, b, c })
    }

    /// Encodes the proof: compressed `A`, `B` and `C`.
    pub fn to_bytes(&self) -> [u8; PROOF_SIZE] {
        let mut out = [0u8; PROOF_SIZE];
        out[..48].copy_from_slice(&self.a.to_compressed());
        out[48..144].copy_from_slice(&self.b.to_compressed());
        out[144..].copy_from_slice(&self.c.to_compressed());
        out
    }
}

/// A Groth16 verifying key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    /// `α` in `G1`.
    pub alpha_g1: G1,
    /// `β` in `G1`.
    pub beta_g1: G1,
    /// `β` in `G2`.
    pub beta_g2: G2,
    /// `γ` in `G2`.
    pub gamma_g2: G2,
    /// `δ` in `G1`.
    pub delta_g1: G1,
    /// `δ` in `G2`.
    pub delta_g2: G2,
    /// The input commitment bases: one for the constant and one per public
    /// input.
    pub ic: Vec<G1>,
}

impl VerifyingKey {
    fn read_from(r: &mut Reader<'_>) -> Result<Self, Error> {
        let alpha_g1 = r.g1()?;
        let beta_g1 = r.g1()?;
        let beta_g2 = r.g2()?;
        let gamma_g2 = r.g2()?;
        let delta_g1 = r.g1()?;
        let delta_g2 = r.g2()?;
        let ic = r
            .vector(96)?
            .as_chunks::<96>()
            .0
            .iter()
            .map(|bytes| {
                let p = G1::from_uncompressed(bytes).map_err(|_| Error::InvalidPoint)?;
                if bool::from(p.is_identity()) {
                    return Err(Error::PointAtInfinity);
                }
                Ok(p)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerifyingKey {
            alpha_g1,
            beta_g1,
            beta_g2,
            gamma_g2,
            delta_g1,
            delta_g2,
            ic,
        })
    }

    /// Decodes a verifying key in `bellman`'s format (uncompressed points,
    /// a big-endian count before the input bases), validating every point.
    pub fn read(data: &[u8]) -> Result<Self, Error> {
        let mut r = Reader(data);
        let vk = Self::read_from(&mut r)?;
        if !r.0.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(vk)
    }

    /// Encodes the key in `bellman`'s format.
    pub fn write(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(868 + 96 * self.ic.len());
        out.extend_from_slice(&self.alpha_g1.to_uncompressed());
        out.extend_from_slice(&self.beta_g1.to_uncompressed());
        out.extend_from_slice(&self.beta_g2.to_uncompressed());
        out.extend_from_slice(&self.gamma_g2.to_uncompressed());
        out.extend_from_slice(&self.delta_g1.to_uncompressed());
        out.extend_from_slice(&self.delta_g2.to_uncompressed());
        out.extend_from_slice(&(self.ic.len() as u32).to_be_bytes());
        for p in &self.ic {
            out.extend_from_slice(&p.to_uncompressed());
        }
        out
    }

    /// Precomputes what verification needs.
    pub fn prepare(&self) -> PreparedVerifyingKey {
        PreparedVerifyingKey {
            alpha_g1_beta_g2: pairing(&self.alpha_g1, &self.beta_g2),
            neg_gamma_g2: self.gamma_g2.neg(),
            neg_delta_g2: self.delta_g2.neg(),
            ic: self.ic.clone(),
        }
    }
}

/// A verifying key with the pairing `e(α, β)` and the negated `γ` and `δ`
/// precomputed.
#[derive(Clone, Debug)]
pub struct PreparedVerifyingKey {
    alpha_g1_beta_g2: Gt,
    neg_gamma_g2: G2,
    neg_delta_g2: G2,
    ic: Vec<G1>,
}

impl PreparedVerifyingKey {
    /// The number of public inputs the key is for (the constant one
    /// excluded).
    pub fn num_inputs(&self) -> usize {
        self.ic.len().saturating_sub(1)
    }
}

/// Verifies `proof` for the given public inputs:
/// `e(A, B) · e(Σ inputᵢ·ICᵢ, -γ) · e(C, -δ) = e(α, β)`.
pub fn verify_proof(
    pvk: &PreparedVerifyingKey,
    proof: &Proof,
    public_inputs: &[Fq],
) -> Result<(), Error> {
    if public_inputs.len() + 1 != pvk.ic.len() {
        return Err(Error::InvalidVerifyingKey);
    }
    let mut acc = pvk.ic[0];
    for (input, base) in public_inputs.iter().zip(&pvk.ic[1..]) {
        acc = acc.add(&base.mul(&to_bls_scalar(input)));
    }
    let product = multi_pairing(&[
        (&proof.a, &proof.b),
        (&acc, &pvk.neg_gamma_g2),
        (&proof.c, &pvk.neg_delta_g2),
    ]);
    if product == pvk.alpha_g1_beta_g2 {
        Ok(())
    } else {
        Err(Error::InvalidProof)
    }
}

/// Groth16 proving parameters, in memory.
///
/// The query vectors are kept as affine coordinates: the Sapling Spend
/// parameters take about 48 MB.
pub struct Parameters {
    /// The verifying key.
    pub vk: VerifyingKey,
    h: Vec<Affine<Fp>>,
    l: Vec<Affine<Fp>>,
    a: Vec<Affine<Fp>>,
    b_g1: Vec<Affine<Fp>>,
    b_g2: Vec<Affine<Fp2>>,
}

impl core::fmt::Debug for Parameters {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Parameters")
            .field("h", &self.h.len())
            .field("l", &self.l.len())
            .field("a", &self.a.len())
            .field("b_g1", &self.b_g1.len())
            .field("b_g2", &self.b_g2.len())
            .finish_non_exhaustive()
    }
}

fn fp(bytes: &[u8]) -> Result<Fp, Error> {
    let bytes: &[u8; 48] = bytes.try_into().map_err(|_| Error::UnexpectedEof)?;
    Fp::from_bytes(bytes)
        .into_option()
        .ok_or(Error::InvalidPoint)
}

/// The flag bits of an uncompressed encoding must all be clear: neither
/// compressed, nor the identity.
fn check_flags(bytes: &[u8]) -> Result<(), Error> {
    match bytes.first() {
        Some(b) if b & 0xe0 == 0 => Ok(()),
        Some(b) if b & 0xe0 == 0x40 => Err(Error::PointAtInfinity),
        _ => Err(Error::InvalidPoint),
    }
}

fn g1_affine(bytes: &[u8], checked: bool) -> Result<Affine<Fp>, Error> {
    check_flags(bytes)?;
    let p = Affine {
        x: fp(&bytes[..48])?,
        y: fp(&bytes[48..])?,
    };
    if checked {
        G1::from_affine(p.x, p.y).map_err(|_| Error::InvalidPoint)?;
    } else if !p.is_on_curve() {
        return Err(Error::InvalidPoint);
    }
    Ok(p)
}

fn g2_affine(bytes: &[u8], checked: bool) -> Result<Affine<Fp2>, Error> {
    check_flags(bytes)?;
    // each coordinate is c1 ‖ c0
    let p = Affine {
        x: Fp2::new(fp(&bytes[48..96])?, fp(&bytes[..48])?),
        y: Fp2::new(fp(&bytes[144..])?, fp(&bytes[96..144])?),
    };
    if checked {
        G2::from_affine(p.x, p.y).map_err(|_| Error::InvalidPoint)?;
    } else if !p.is_on_curve() {
        return Err(Error::InvalidPoint);
    }
    Ok(p)
}

impl Parameters {
    /// Decodes parameters in `bellman`'s format: the verifying key, then
    /// the `H`, `L`, `A`, `B` (in `G1`) and `B` (in `G2`) query vectors as
    /// uncompressed points, each with a big-endian count.
    ///
    /// With `checked`, every point is verified to be in its prime-order
    /// group, which takes minutes for parameters the size of Sapling's.
    /// Without it only the curve equation is checked (points of the
    /// verifying key are always fully checked): do that only for
    /// parameters whose integrity is established otherwise, such as by
    /// their hash. No point may be the identity.
    ///
    /// Bytes after the last vector are ignored, as `bellman` does: the
    /// Sapling parameter files end with the transcript of the ceremony
    /// that produced them.
    ///
    /// Malformed input gives an error, never a panic, and nothing is
    /// allocated for more elements than the data holds.
    pub fn read(data: &[u8], checked: bool) -> Result<Self, Error> {
        let mut r = Reader(data);
        let vk = VerifyingKey::read_from(&mut r)?;
        let g1s = |r: &mut Reader<'_>| {
            r.vector(96)?
                .as_chunks::<96>()
                .0
                .iter()
                .map(|bytes| g1_affine(bytes, checked))
                .collect::<Result<Vec<_>, _>>()
        };
        let h = g1s(&mut r)?;
        let l = g1s(&mut r)?;
        let a = g1s(&mut r)?;
        let b_g1 = g1s(&mut r)?;
        let b_g2 = r
            .vector(192)?
            .as_chunks::<192>()
            .0
            .iter()
            .map(|bytes| g2_affine(bytes, checked))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Parameters {
            vk,
            h,
            l,
            a,
            b_g1,
            b_g2,
        })
    }
}

#[cfg(test)]
mod tests;
