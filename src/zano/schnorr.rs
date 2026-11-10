//! The Schnorr-style proofs of `zarcanum.h`/`zarcanum.cpp` a transaction
//! uses besides the ring signatures: the double Schnorr proof of the balance
//! proof, and the vector UG aggregation proof of the range proof.

use crate::cryptonote::{EdwardsPoint, Scalar};
use crate::prelude::*;

use super::Error;
use super::crypto::{
    self, Transcript, generator_u, generator_x, msm_vartime, mul_vartime, random_scalar,
    scalar_1div8,
};
use super::tx::{DoubleSchnorrSig, UgAggProof};

/// The generator the first secret of a double Schnorr proof is over; the
/// second one is always over `G`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchnorrGenerator {
    /// The basepoint `G`: transactions without confidential inputs.
    G,
    /// The generator `X`: transactions with confidential inputs.
    X,
}

impl SchnorrGenerator {
    fn point(self) -> EdwardsPoint {
        match self {
            SchnorrGenerator::G => EdwardsPoint::generator(),
            SchnorrGenerator::X => generator_x(),
        }
    }
}

/// Proves knowledge of `secret_a` and `secret_b` with
/// `a == secret_a * generator` and `b == secret_b * G`
/// (`generate_double_schnorr_sig`).
///
/// `rng` must fill its buffer from a cryptographically secure source.
///
/// Fails with [`Error::SecretMismatch`] if a secret does not match its
/// point.
pub fn generate_double_schnorr_sig(
    rng: &mut dyn FnMut(&mut [u8]),
    generator: SchnorrGenerator,
    m: &[u8; 32],
    a: &EdwardsPoint,
    secret_a: &Scalar,
    b: &EdwardsPoint,
    secret_b: &Scalar,
) -> Result<DoubleSchnorrSig, Error> {
    let gen0 = generator.point();
    if gen0.mul(secret_a) != *a || EdwardsPoint::mul_base(secret_b) != *b {
        return Err(Error::SecretMismatch);
    }
    let r0 = random_scalar(rng);
    let r1 = random_scalar(rng);
    let mut hsc = Transcript::new();
    hsc.bytes(m)
        .point(a)
        .point(b)
        .point(&gen0.mul(&r0))
        .point(&EdwardsPoint::mul_base(&r1));
    let c = hsc.take_scalar();
    Ok(DoubleSchnorrSig {
        y0: r0.sub(&c.mul(secret_a)).to_bytes(),
        y1: r1.sub(&c.mul(secret_b)).to_bytes(),
        c: c.to_bytes(),
    })
}

/// Verifies a double Schnorr proof (`verify_double_schnorr_sig`); `b` is
/// given as its encoding. Variable-time.
pub fn verify_double_schnorr_sig(
    generator: SchnorrGenerator,
    m: &[u8; 32],
    a: &EdwardsPoint,
    b: &[u8; 32],
    sig: &DoubleSchnorrSig,
) -> bool {
    let (Ok(c), Ok(y0), Ok(y1), Ok(b_pt)) = (
        crypto::scalar(&sig.c),
        crypto::scalar(&sig.y0),
        crypto::scalar(&sig.y1),
        crypto::point(b),
    ) else {
        return false;
    };
    let r0 = match generator {
        SchnorrGenerator::G => EdwardsPoint::double_scalar_mul_base_vartime(&c, a, &y0),
        SchnorrGenerator::X => msm_vartime(&[(y0, generator_x()), (c.clone(), *a)]),
    };
    let r1 = EdwardsPoint::double_scalar_mul_base_vartime(&c, &b_pt, &y1);
    let mut hsc = Transcript::new();
    hsc.bytes(m).point(a).bytes(b).point(&r0).point(&r1);
    hsc.take_scalar() == c
}

/// The weighting factor `w`, leaving the transcript ready for the
/// commitments `R`.
fn ug_weight(
    m: &[u8; 32],
    amount_commitments: &[EdwardsPoint],
    rp_commitments: &[EdwardsPoint],
) -> (Transcript, Scalar) {
    let mut hsc = Transcript::new();
    hsc.bytes(m);
    for point in amount_commitments.iter().chain(rp_commitments) {
        hsc.point(point);
    }
    let w = hsc.peek_scalar();
    (hsc, w)
}

/// Proves, for each output `j`, knowledge of the amount `e_j` and of the
/// masks `y_j`, `y'_j` behind both its amount commitment
/// `E_j = e_j * T_j + y_j * G` and the commitment `E'_j = e_j * U + y'_j * G`
/// the range proof is about (`generate_vector_UG_aggregation_proof`).
///
/// - `u_secrets`: the amounts `e_j`;
/// - `g_secrets0`, `g_secrets1`: the masks `y_j` and `y'_j`;
/// - `amount_commitments`, `amount_commitments_for_rp_aggregation`,
///   `blinded_asset_ids`: `E_j`, `E'_j` and `T_j`, as full points.
///
/// `rng` must fill its buffer from a cryptographically secure source.
///
/// Fails with [`Error::TooLarge`] if the slices are empty or differ in
/// length, and [`Error::SecretMismatch`] if the secrets do not open the
/// commitments.
#[allow(clippy::too_many_arguments)]
pub fn generate_vector_ug_aggregation_proof(
    rng: &mut dyn FnMut(&mut [u8]),
    m: &[u8; 32],
    u_secrets: &[Scalar],
    g_secrets0: &[Scalar],
    g_secrets1: &[Scalar],
    amount_commitments: &[EdwardsPoint],
    amount_commitments_for_rp_aggregation: &[EdwardsPoint],
    blinded_asset_ids: &[EdwardsPoint],
) -> Result<UgAggProof, Error> {
    let n = u_secrets.len();
    if n == 0
        || [
            g_secrets0.len(),
            g_secrets1.len(),
            amount_commitments.len(),
            amount_commitments_for_rp_aggregation.len(),
            blinded_asset_ids.len(),
        ]
        .iter()
        .any(|&len| len != n)
    {
        return Err(Error::TooLarge);
    }
    let (mut hsc, w) = ug_weight(m, amount_commitments, amount_commitments_for_rp_aggregation);
    let w_u = mul_vartime(&w, &generator_u());

    let mut r0 = Vec::with_capacity(n);
    let mut r1 = Vec::with_capacity(n);
    for _ in 0..n {
        r0.push(random_scalar(rng));
        r1.push(random_scalar(rng));
    }
    for j in 0..n {
        let base = blinded_asset_ids[j].add(&w_u);
        let g_secret = g_secrets0[j].add(&w.mul(&g_secrets1[j]));
        // E_j + w * E'_j == e_j * (T_j + w * U) + (y_j + w * y'_j) * G
        let lhs =
            amount_commitments[j].add(&mul_vartime(&w, &amount_commitments_for_rp_aggregation[j]));
        if base
            .mul(&u_secrets[j])
            .add(&EdwardsPoint::mul_base(&g_secret))
            != lhs
        {
            return Err(Error::SecretMismatch);
        }
        hsc.point(&base.mul(&r0[j]).add(&EdwardsPoint::mul_base(&r1[j])));
    }
    let c = hsc.take_scalar();

    let inv8 = scalar_1div8();
    let mut proof = UgAggProof {
        c: c.to_bytes(),
        ..Default::default()
    };
    for j in 0..n {
        proof.y0s.push(r0[j].sub(&c.mul(&u_secrets[j])).to_bytes());
        let g_secret = g_secrets0[j].add(&w.mul(&g_secrets1[j]));
        proof.y1s.push(r1[j].sub(&c.mul(&g_secret)).to_bytes());
        proof
            .amount_commitments_for_rp_aggregation
            .push(mul_vartime(&inv8, &amount_commitments_for_rp_aggregation[j]).compress());
    }
    Ok(proof)
}

/// Verifies a vector UG aggregation proof against the outputs' amount
/// commitments and blinded asset ids, both as they are on chain (times
/// `1/8`) (`verify_vector_UG_aggregation_proof`). Variable-time.
pub fn verify_vector_ug_aggregation_proof(
    m: &[u8; 32],
    amount_commitments_1div8: &[[u8; 32]],
    blinded_asset_ids_1div8: &[[u8; 32]],
    proof: &UgAggProof,
) -> bool {
    verify_ug(m, amount_commitments_1div8, blinded_asset_ids_1div8, proof).unwrap_or(false)
}

fn verify_ug(
    m: &[u8; 32],
    amount_commitments_1div8: &[[u8; 32]],
    blinded_asset_ids_1div8: &[[u8; 32]],
    proof: &UgAggProof,
) -> Option<bool> {
    let n = amount_commitments_1div8.len();
    if n == 0
        || blinded_asset_ids_1div8.len() != n
        || proof.amount_commitments_for_rp_aggregation.len() != n
        || proof.y0s.len() != n
        || proof.y1s.len() != n
    {
        return None;
    }
    let decode = |points: &[[u8; 32]]| -> Option<Vec<EdwardsPoint>> {
        points
            .iter()
            .map(|p| Some(crypto::point(p).ok()?.mul_by_cofactor()))
            .collect()
    };
    let commitments = decode(amount_commitments_1div8)?;
    let rp_commitments = decode(&proof.amount_commitments_for_rp_aggregation)?;
    let asset_ids = decode(blinded_asset_ids_1div8)?;
    let c = crypto::scalar(&proof.c).ok()?;

    let (mut hsc, w) = ug_weight(m, &commitments, &rp_commitments);
    let w_u = mul_vartime(&w, &generator_u());
    for j in 0..n {
        let y0 = crate::cryptonote::scalar_reduce(proof.y0s.get(j)?);
        let y1 = crate::cryptonote::scalar_reduce(proof.y1s.get(j)?);
        let base = asset_ids.get(j)?.add(&w_u);
        let lhs = commitments
            .get(j)?
            .add(&mul_vartime(&w, rp_commitments.get(j)?));
        hsc.point(&msm_vartime(&[
            (y0, base),
            (c.clone(), lhs),
            (y1, EdwardsPoint::generator()),
        ]));
    }
    Some(hsc.take_scalar() == c)
}
