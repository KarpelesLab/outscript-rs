//! The original Bulletproofs: the aggregated range proof of RingCT types 3
//! to 5 (2018 to 2022), verification only — a port of
//! `bulletproof_VERIFY` of Monero's `bulletproofs.cc`.
//!
//! One proof shows that each of up to 16 commitments hides an amount below
//! 2^64. The three RingCT types carry the same proof: what changed with
//! type 4 ("bulletproof2") is the encoding of the amounts next to it, not
//! the proof or its transcript.

use super::bp_common::{
    Accumulator, Generators, Kind, LOG_N, MAX_OUTPUTS, N, batch_invert, challenge_products, padded,
    powers, with_generators,
};
use super::ringct::{Table, inv_eight, multiexp};
use super::tx::Bulletproof;
use super::{Error, random_scalar};
use crate::cryptonote::{Hasher, Scalar, point_from_bytes, scalar_from_bytes, scalar_from_u64};
use crate::prelude::*;

/// The most commitments (outputs) one original Bulletproof can cover.
pub const BULLETPROOF_MAX_OUTPUTS: usize = MAX_OUTPUTS;

/// The generators `Gi` and `Hi` of the original Bulletproofs: 64 of each per
/// commitment. They are not those of Bulletproofs+.
///
/// As with
/// [`BulletproofPlusGenerators`](super::BulletproofPlusGenerators), making
/// them takes a moment: with `std`, [`Bulletproof::verify`] makes the ones
/// it needs once and keeps them for the life of the process; without, on
/// every call. [`Bulletproof::verify_with`] and
/// [`Bulletproof::verify_batch`] take them from the caller.
#[derive(Debug, Clone)]
pub struct BulletproofGenerators(Generators);

impl BulletproofGenerators {
    /// The generators for proofs over up to `outputs` commitments (at most
    /// [`BULLETPROOF_MAX_OUTPUTS`]; more is treated as that).
    pub fn new(outputs: usize) -> Self {
        BulletproofGenerators(Generators::new(Kind::Original, outputs))
    }

    /// The number of commitments these generators can serve.
    pub fn max_outputs(&self) -> usize {
        self.0.max_outputs()
    }
}

/// `Hs(parts...)`, the transcript's hash.
fn mash(parts: &[&[u8; 32]]) -> Scalar {
    let mut h = Hasher::new();
    for part in parts {
        h.update(*part);
    }
    h.finalize_to_scalar()
}

impl Bulletproof {
    /// Verifies the proof against the output `commitments` of the
    /// transaction (as they are in its RingCT data, not divided by 8).
    /// Variable-time: everything here is public.
    ///
    /// The two equations of the proof are checked one after the other; a
    /// verifier with a random source can check them, and several proofs, in
    /// one go with [`verify_batch`](Self::verify_batch).
    pub fn verify(&self, commitments: &[[u8; 32]]) -> bool {
        if padded(commitments.len()).is_none() {
            return false;
        }
        with_generators(Kind::Original, commitments.len(), |generators| {
            verify_one(self, generators, commitments)
        })
    }

    /// [`verify`](Self::verify) with generators made beforehand, which must
    /// serve at least `commitments.len()` commitments.
    pub fn verify_with(
        &self,
        generators: &BulletproofGenerators,
        commitments: &[[u8; 32]],
    ) -> bool {
        verify_one(self, &generators.0, commitments)
    }

    /// Verifies several proofs at once, each against its own commitments,
    /// in a single multi-scalar multiplication.
    ///
    /// Each equation of each proof is scaled by a random weight before they
    /// are added up, so that invalid proofs cannot cancel each other out.
    /// `rng` fills its argument with random bytes for these weights; they
    /// must not be predictable by whoever made the proofs (128 bytes are
    /// drawn per proof). `generators` must serve the largest proof.
    ///
    /// Returns `Ok(true)` if every proof holds (or there are none),
    /// `Ok(false)` if at least one does not — the batch does not tell
    /// which. Fails with [`Error::BadRandomness`] if `rng` yields only
    /// zeros.
    ///
    /// ```
    /// use outscript::monero::{Bulletproof, BulletproofGenerators};
    /// # let mut rng = |out: &mut [u8]| out.fill(7);
    /// let generators = BulletproofGenerators::new(2);
    /// // The proofs and output commitments of the transactions of a block...
    /// let proofs: Vec<(&Bulletproof, &[[u8; 32]])> = Vec::new();
    /// assert!(Bulletproof::verify_batch(&generators, &proofs, &mut rng)?);
    /// # Ok::<(), outscript::monero::Error>(())
    /// ```
    pub fn verify_batch(
        generators: &BulletproofGenerators,
        proofs: &[(&Bulletproof, &[[u8; 32]])],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<bool, Error> {
        let mut accumulator = Accumulator::new();
        for (proof, commitments) in proofs {
            let weights = (random_scalar(rng)?, random_scalar(rng)?);
            if !accumulate(proof, commitments, &weights, &mut accumulator, None).unwrap_or(false) {
                return Ok(false);
            }
        }
        Ok(accumulator.is_identity(&generators.0))
    }
}

/// Verifies one proof on its own: its two equations separately, which needs
/// no random weights.
pub(crate) fn verify_one(
    proof: &Bulletproof,
    generators: &Generators,
    commitments: &[[u8; 32]],
) -> bool {
    let mut first = Accumulator::new();
    let mut second = Accumulator::new();
    let weights = (Scalar::ONE, Scalar::ONE);
    accumulate(proof, commitments, &weights, &mut first, Some(&mut second)).unwrap_or(false)
        && first.is_identity(generators)
        && second.is_identity(generators)
}

/// Adds the terms of the two verification equations of `proof`, scaled by
/// `weights`, to `accumulator` (the second equation to `second` if given):
/// the proof holds if each sums to the identity. `Ok(false)` or an error if
/// the proof cannot hold whatever the sums.
pub(crate) fn accumulate(
    proof: &Bulletproof,
    commitments: &[[u8; 32]],
    weights: &(Scalar, Scalar),
    accumulator: &mut Accumulator,
    second: Option<&mut Accumulator>,
) -> Result<bool, Error> {
    let Some((m, log_m)) = padded(commitments.len()) else {
        return Ok(false);
    };
    let mn = m * N;
    let rounds = log_m + LOG_N;
    if proof.l.len() != rounds || proof.r.len() != rounds {
        return Ok(false);
    }
    let taux = scalar_from_bytes(&proof.taux)?;
    let mu = scalar_from_bytes(&proof.mu)?;
    let a = scalar_from_bytes(&proof.aa)?;
    let b = scalar_from_bytes(&proof.b)?;
    let t = scalar_from_bytes(&proof.t)?;

    // The proof is about the commitments divided by 8, and every point of
    // it is multiplied by 8 before use, which takes any torsion out.
    let inv8 = inv_eight();
    let mut tables = [Table::new()];
    let mut transcript = Hasher::new();
    let mut v8 = Vec::with_capacity(commitments.len());
    for commitment in commitments {
        let point = point_from_bytes(commitment)?;
        let divided = multiexp(core::slice::from_ref(&inv8), &[point], &mut tables, false);
        transcript.update(&divided.compress());
        v8.push(divided.mul_by_cofactor());
    }
    let times8 = |bytes: &[u8; 32]| Ok::<_, Error>(point_from_bytes(bytes)?.mul_by_cofactor());

    // The challenges. Each hash is also the state the next one starts from.
    let cache = transcript.finalize_scalar();
    let y = mash(&[&cache, &proof.a, &proof.s]);
    let z = mash(&[&y.to_bytes()]);
    let z_bytes = z.to_bytes();
    let x = mash(&[&z_bytes, &z_bytes, &proof.t1, &proof.t2]);
    let x_bytes = x.to_bytes();
    let x_ip = mash(&[&x_bytes, &x_bytes, &proof.taux, &proof.mu, &proof.t]);
    if y == Scalar::ZERO || z == Scalar::ZERO || x == Scalar::ZERO || x_ip == Scalar::ZERO {
        return Ok(false);
    }
    let mut challenges = Vec::with_capacity(rounds + 1);
    let mut cache = x_ip.to_bytes();
    for (l, r) in proof.l.iter().zip(&proof.r) {
        let challenge = mash(&[&cache, l, r]);
        if challenge == Scalar::ZERO {
            return Ok(false);
        }
        cache = challenge.to_bytes();
        challenges.push(challenge);
    }
    // One inversion for y and the round challenges.
    challenges.push(y.clone());
    let mut challenges_inv = batch_invert(&challenges);
    challenges.pop();
    let Some(y_inv) = challenges_inv.pop() else {
        return Ok(false);
    };

    // z^0 .. z^(M + 2)
    let z_powers = powers(&z, m + 3);
    let (Some(z_squared), sum_two) = (z_powers.get(2), scalar_from_u64(u64::MAX)) else {
        return Ok(false);
    };

    // --- the first equation: the polynomial t ---
    // taux * G + (t - delta) * H = sum(z^(j + 2) * V[j]) + x * T1 + x^2 * T2,
    // delta = (z - z^2) * sum(y^0..y^(MN - 1)) - (2^64 - 1) * sum(z^3..z^(M + 2)).
    let (weight_y, weight_z) = weights;
    let mut sum_y = Scalar::ZERO;
    let mut y_power = Scalar::ONE;
    for _ in 0..mn {
        sum_y = sum_y.add(&y_power);
        y_power = y_power.mul(&y);
    }
    let mut sum_z = Scalar::ZERO;
    for z_power in z_powers.iter().skip(3) {
        sum_z = sum_z.add(z_power);
    }
    let delta = z.sub(z_squared).mul(&sum_y).sub(&sum_two.mul(&sum_z));
    accumulator.g = accumulator.g.add(&taux.mul(weight_y));
    accumulator.h = accumulator.h.add(&t.sub(&delta).mul(weight_y));
    let minus_weight_y = Scalar::ZERO.sub(weight_y);
    for (point, z_power) in v8.iter().zip(z_powers.iter().skip(2)) {
        accumulator.push(minus_weight_y.mul(z_power), *point);
    }
    let minus_weight_y_x = minus_weight_y.mul(&x);
    accumulator.push(minus_weight_y_x.clone(), times8(&proof.t1)?);
    accumulator.push(minus_weight_y_x.mul(&x), times8(&proof.t2)?);

    // --- the second equation: the inner product ---
    // A + x * S - mu * G + sum((-z - a * w[i]) * Gi[i])
    //   + sum((z + y^-i * (z^(2 + j) * 2^k - b * w[!i])) * Hi[i])
    //   + x_ip * (t - a * b) * H + sum(c^2 * L + c^-2 * R) = 0,
    // for i = 64 * j + k and w the products of the round challenges.
    let accumulator = match second {
        Some(second) => second,
        None => accumulator,
    };
    accumulator.push(weight_z.clone(), times8(&proof.a)?);
    accumulator.push(weight_z.mul(&x), times8(&proof.s)?);
    accumulator.g = accumulator.g.sub(&mu.mul(weight_z));
    accumulator.h = accumulator
        .h
        .add(&x_ip.mul(&t.sub(&a.mul(&b))).mul(weight_z));
    for (((l, r), challenge), challenge_inv) in proof
        .l
        .iter()
        .zip(&proof.r)
        .zip(&challenges)
        .zip(&challenges_inv)
    {
        accumulator.push(weight_z.mul(challenge).mul(challenge), times8(l)?);
        accumulator.push(weight_z.mul(challenge_inv).mul(challenge_inv), times8(r)?);
    }

    let Some(products) = challenge_products(&challenges, &challenges_inv) else {
        return Ok(false);
    };
    accumulator.grow(mn);
    let weight_z_z = weight_z.mul(&z);
    let weight_z_a = weight_z.mul(&a);
    let weight_z_b = weight_z.mul(&b);
    // y^-i
    let mut y_inv_power = Scalar::ONE;
    let mut slots = accumulator.gi.iter_mut().zip(accumulator.hi.iter_mut());
    for (j, z_power) in z_powers.iter().skip(2).take(m).enumerate() {
        // weight_z * z^(2 + j) * 2^k
        let mut z_two = weight_z.mul(z_power);
        for k in 0..N {
            let i = j * N + k;
            let (Some((g_slot, h_slot)), Some(direct), Some(mirrored)) =
                (slots.next(), products.get(i), products.get(!i & (mn - 1)))
            else {
                return Ok(false);
            };
            *g_slot = g_slot.sub(&weight_z_z).sub(&weight_z_a.mul(direct));
            *h_slot = h_slot
                .add(&weight_z_z)
                .add(&y_inv_power.mul(&z_two.sub(&weight_z_b.mul(mirrored))));
            y_inv_power = y_inv_power.mul(&y_inv);
            z_two = z_two.add(&z_two);
        }
    }
    Ok(true)
}
