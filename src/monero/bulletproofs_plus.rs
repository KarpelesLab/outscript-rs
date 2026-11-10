//! Bulletproofs+: the aggregated range proof of RingCT type 6, a port of
//! Monero's `bulletproofs_plus.cc`.
//!
//! One proof shows that each of up to 16 commitments hides an amount below
//! 2^64, in `2 * (6 + log2(M)) + 6` group elements and scalars for `M`
//! commitments (rounded up to a power of two).

use purecrypto::ct::Choice;

use super::ringct::{Table, commit_point, h_point, inv_eight, multiexp, select_point};
use super::{Error, random_scalar};
use crate::cryptonote::{
    EdwardsPoint, Hasher, Scalar, cn_fast_hash, point_from_bytes, point_from_hash, push_varint,
    scalar_from_bytes, scalar_from_hash, scalar_from_u64,
};
use crate::prelude::*;

/// The most commitments (outputs) one proof can cover.
pub const BULLETPROOF_PLUS_MAX_OUTPUTS: usize = 16;

/// Bits of an amount.
const N: usize = 64;
/// `log2(N)`.
const LOG_N: usize = 6;
/// How many points share their doublings in a multi-scalar multiplication.
const GROUP: usize = 32;

/// A Bulletproofs+ range proof, as a transaction carries it. The commitments
/// it is about are not part of it: they are the transaction's output
/// commitments.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct BulletproofPlus {
    pub a: [u8; 32],
    pub a1: [u8; 32],
    pub b: [u8; 32],
    pub r1: [u8; 32],
    pub s1: [u8; 32],
    pub d1: [u8; 32],
    pub l: Vec<[u8; 32]>,
    pub r: Vec<[u8; 32]>,
}

/// The generators `Gi` and `Hi` of the proofs: 64 of each per commitment.
///
/// Each is a hash to the curve, so making them takes a moment (a few
/// thousand field operations per generator, 128 generators per commitment).
/// [`BulletproofPlus::prove`] and [`BulletproofPlus::verify`] make the ones
/// they need on every call; to prove or verify several proofs, make them
/// once and use [`BulletproofPlus::prove_with`] and
/// [`BulletproofPlus::verify_with`].
#[derive(Debug, Clone)]
pub struct BulletproofPlusGenerators {
    gi: Vec<EdwardsPoint>,
    hi: Vec<EdwardsPoint>,
}

/// `get_exponent`: the generator number `index`,
/// `Hp(cn_fast_hash(H || "bulletproof_plus" || varint(index)))`.
fn generator(index: u64) -> EdwardsPoint {
    let mut data = Vec::with_capacity(32 + 16 + 10);
    data.extend_from_slice(&super::H);
    data.extend_from_slice(b"bulletproof_plus");
    push_varint(&mut data, index);
    point_from_hash(&cn_fast_hash(&data))
}

/// The smallest power of two that is at least `outputs`, and its logarithm.
fn padded(outputs: usize) -> Option<(usize, usize)> {
    if outputs == 0 || outputs > BULLETPROOF_PLUS_MAX_OUTPUTS {
        return None;
    }
    let m = outputs.next_power_of_two();
    Some((m, m.trailing_zeros() as usize))
}

impl BulletproofPlusGenerators {
    /// The generators for proofs over up to `outputs` commitments (at most
    /// [`BULLETPROOF_PLUS_MAX_OUTPUTS`]; more is treated as that).
    pub fn new(outputs: usize) -> Self {
        let outputs = outputs.clamp(1, BULLETPROOF_PLUS_MAX_OUTPUTS);
        let count = outputs.next_power_of_two() * N;
        let mut gi = Vec::with_capacity(count);
        let mut hi = Vec::with_capacity(count);
        for i in 0..count as u64 {
            hi.push(generator(2 * i));
            gi.push(generator(2 * i + 1));
        }
        BulletproofPlusGenerators { gi, hi }
    }

    /// The number of commitments these generators can serve.
    pub fn max_outputs(&self) -> usize {
        self.gi.len() / N
    }
}

/// The transcript before anything is absorbed:
/// `Hp(cn_fast_hash("bulletproof_plus_transcript"))`, compressed.
fn initial_transcript() -> [u8; 32] {
    point_from_hash(&cn_fast_hash(b"bulletproof_plus_transcript")).compress()
}

/// Absorbs `parts` into the transcript and returns the challenge, which is
/// also the new transcript.
fn transcript_update(transcript: &mut [u8; 32], parts: &[&[u8; 32]]) -> Scalar {
    let mut h = Hasher::new();
    h.update(transcript);
    for part in parts {
        h.update(*part);
    }
    let challenge = h.finalize_to_scalar();
    *transcript = challenge.to_bytes();
    challenge
}

/// The challenges `y` and `z` from the commitments (divided by 8) and `A`,
/// leaving the transcript ready for the rounds. `None` if one is zero.
fn challenges_yz(v: &[[u8; 32]], a: &[u8; 32]) -> Option<([u8; 32], Scalar, Scalar)> {
    let mut transcript = initial_transcript();
    let mut h = Hasher::new();
    for commitment in v {
        h.update(commitment);
    }
    let hash_v = h.finalize_scalar();
    transcript_update(&mut transcript, &[&hash_v]);
    let y = transcript_update(&mut transcript, &[a]);
    if y == Scalar::ZERO {
        return None;
    }
    let z = scalar_from_hash(&[&y.to_bytes()]);
    if z == Scalar::ZERO {
        return None;
    }
    transcript = z.to_bytes();
    Some((transcript, y, z))
}

/// `d[j * N + i] = z^(2 * (j + 1)) * 2^i`.
fn d_vector(z_squared: &Scalar, m: usize) -> Vec<Scalar> {
    let mut d: Vec<Scalar> = Vec::with_capacity(m * N);
    let mut z_power = z_squared.clone();
    for _ in 0..m {
        let mut value = z_power.clone();
        for _ in 0..N {
            let next = value.add(&value);
            d.push(value);
            value = next;
        }
        z_power = z_power.mul(z_squared);
    }
    d
}

/// `x^0, x^1, ..., x^(n - 1)`.
fn powers(x: &Scalar, n: usize) -> Vec<Scalar> {
    let mut out = Vec::with_capacity(n);
    let mut value = Scalar::ONE;
    for _ in 0..n {
        let next = value.mul(x);
        out.push(value);
        value = next;
    }
    out
}

/// `sum(a[i] * b[i] * y^(i + 1))`.
fn weighted_inner_product(a: &[Scalar], b: &[Scalar], y: &Scalar) -> Scalar {
    let mut sum = Scalar::ZERO;
    let mut y_power = Scalar::ONE;
    for (a, b) in a.iter().zip(b) {
        y_power = y_power.mul(y);
        sum = sum.add(&a.mul(b).mul(&y_power));
    }
    sum
}

fn new_tables() -> Vec<Table> {
    vec![Table::new(); GROUP]
}

impl BulletproofPlus {
    /// Proves that every amount is below 2^64, for the commitments
    /// `masks[i] * G + amounts[i] * H` ([`commit`](super::commit)).
    ///
    /// `rng` fills its argument with cryptographically secure random bytes;
    /// the proof's blinding comes from it, and a predictable one reveals the
    /// amounts and masks.
    ///
    /// Fails with [`Error::InvalidProof`] if there are no amounts, more than
    /// [`BULLETPROOF_PLUS_MAX_OUTPUTS`], or not as many masks;
    /// [`Error::CryptoNote`] if a mask is not a reduced scalar;
    /// [`Error::BadRandomness`] if `rng` yields only zeros.
    ///
    /// The operations on the amounts and masks are constant-time.
    pub fn prove(
        amounts: &[u64],
        masks: &[[u8; 32]],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Self, Error> {
        let generators = BulletproofPlusGenerators::new(amounts.len());
        Self::prove_with(&generators, amounts, masks, rng)
    }

    /// [`prove`](Self::prove) with generators made beforehand, which must
    /// serve at least `amounts.len()` commitments.
    pub fn prove_with(
        generators: &BulletproofPlusGenerators,
        amounts: &[u64],
        masks: &[[u8; 32]],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Self, Error> {
        let (m, log_m) = padded(amounts.len()).ok_or(Error::InvalidProof)?;
        if masks.len() != amounts.len() || generators.max_outputs() < m {
            return Err(Error::InvalidProof);
        }
        let gamma = masks
            .iter()
            .map(|mask| Ok(scalar_from_bytes(mask)?))
            .collect::<Result<Vec<Scalar>, Error>>()?;
        // A zero challenge is as likely as guessing a key: one retry is
        // already more than will ever be needed.
        for _ in 0..4 {
            if let Some(proof) = prove_once(generators, amounts, &gamma, m, log_m, rng)? {
                return Ok(proof);
            }
        }
        Err(Error::BadRandomness)
    }

    /// Verifies the proof against the output `commitments` of the
    /// transaction (as they are in its RingCT data, not divided by 8).
    /// Variable-time: everything here is public.
    pub fn verify(&self, commitments: &[[u8; 32]]) -> bool {
        if padded(commitments.len()).is_none() {
            return false;
        }
        let generators = BulletproofPlusGenerators::new(commitments.len());
        self.verify_with(&generators, commitments)
    }

    /// [`verify`](Self::verify) with generators made beforehand, which must
    /// serve at least `commitments.len()` commitments.
    pub fn verify_with(
        &self,
        generators: &BulletproofPlusGenerators,
        commitments: &[[u8; 32]],
    ) -> bool {
        verify_inner(self, generators, commitments).unwrap_or(false)
    }
}

/// One attempt at a proof: `None` if a challenge came out zero.
fn prove_once(
    generators: &BulletproofPlusGenerators,
    amounts: &[u64],
    gamma: &[Scalar],
    m: usize,
    log_m: usize,
    rng: &mut dyn FnMut(&mut [u8]),
) -> Result<Option<BulletproofPlus>, Error> {
    let mn = m * N;
    let inv8 = inv_eight();
    let (Some(gi), Some(hi)) = (generators.gi.get(..mn), generators.hi.get(..mn)) else {
        return Err(Error::InvalidProof);
    };
    let g = EdwardsPoint::generator();
    let h = h_point();

    // The commitments, divided by 8 as the transcript has them.
    let v: Vec<[u8; 32]> = amounts
        .iter()
        .zip(gamma)
        .map(|(amount, mask)| {
            commit_point(&scalar_from_u64(*amount).mul(&inv8), &mask.mul(&inv8)).compress()
        })
        .collect();

    // aL holds the bits of the amounts and aR = aL - 1. Their commitment is
    // the sum of Gi where the bit is set and of -Hi where it is not.
    let minus_one = Scalar::ZERO.sub(&Scalar::ONE);
    let mut a_l: Vec<Scalar> = Vec::with_capacity(mn);
    let mut a_r: Vec<Scalar> = Vec::with_capacity(mn);
    let mut sum = EdwardsPoint::identity();
    for j in 0..m {
        let amount = amounts.get(j).copied().unwrap_or(0);
        for i in 0..N {
            let bit = ((amount >> i) & 1) as u8;
            let choice = Choice::from(bit);
            let (Some(gen_g), Some(gen_h)) = (gi.get(j * N + i), hi.get(j * N + i)) else {
                return Err(Error::InvalidProof);
            };
            sum = sum.add(&select_point(gen_g, &gen_h.negate(), choice));
            // bit and bit - 1, without branching on the bit.
            let bit = scalar_from_u64(u64::from(bit));
            a_r.push(bit.add(&minus_one));
            a_l.push(bit);
        }
    }
    let alpha = random_scalar(rng)?;
    let a = sum
        .mul(&inv8)
        .add(&EdwardsPoint::mul_base(&alpha.mul(&inv8)))
        .compress();

    let Some((mut transcript, y, z)) = challenges_yz(&v, &a) else {
        return Ok(None);
    };
    let z_squared = z.mul(&z);
    let d = d_vector(&z_squared, m);
    // y^0 .. y^(MN + 1)
    let y_powers = powers(&y, mn + 2);
    let y_inv = y.invert();
    let y_inv_powers = powers(&y_inv, mn);

    // a' = aL - z, b' = aR + z + d[i] * y^(MN - i)
    let mut a_prime: Vec<Scalar> = a_l.iter().map(|a| a.sub(&z)).collect();
    let mut b_prime: Vec<Scalar> = Vec::with_capacity(mn);
    for (i, (a_r, d)) in a_r.iter().zip(&d).enumerate() {
        let y_power = y_powers.get(mn - i).ok_or(Error::InvalidProof)?;
        b_prime.push(a_r.add(&z).add(&d.mul(y_power)));
    }

    // alpha1 = alpha + sum(z^(2 * (j + 1)) * y^(MN + 1) * gamma[j])
    let y_mn_1 = y_powers.get(mn + 1).ok_or(Error::InvalidProof)?;
    let mut alpha1 = alpha;
    let mut z_power = Scalar::ONE;
    for mask in gamma {
        z_power = z_power.mul(&z_squared);
        alpha1 = alpha1.add(&z_power.mul(y_mn_1).mul(mask));
    }

    let mut g_prime = gi.to_vec();
    let mut h_prime = hi.to_vec();
    let mut tables = new_tables();
    let rounds = log_m + LOG_N;
    let mut l_points = Vec::with_capacity(rounds);
    let mut r_points = Vec::with_capacity(rounds);
    let mut n_prime = mn;
    while n_prime > 1 {
        n_prime /= 2;
        let (a_lo, a_hi) = a_prime.split_at(n_prime);
        let (b_lo, b_hi) = b_prime.split_at(n_prime);
        let (g_lo, g_hi) = g_prime.split_at(n_prime);
        let (h_lo, h_hi) = h_prime.split_at(n_prime);
        let y_n = y_powers.get(n_prime).ok_or(Error::InvalidProof)?;
        let y_inv_n = y_inv_powers.get(n_prime).ok_or(Error::InvalidProof)?;

        let c_l = weighted_inner_product(a_lo, b_hi, &y);
        let a_hi_y: Vec<Scalar> = a_hi.iter().map(|a| a.mul(y_n)).collect();
        let c_r = weighted_inner_product(&a_hi_y, b_lo, &y);
        let d_l = random_scalar(rng)?;
        let d_r = random_scalar(rng)?;

        // L = (sum(a_lo[i] * y^-n * G_hi[i] + b_hi[i] * H_lo[i]) + cL * H + dL * G) / 8
        let l = compute_lr(
            a_lo,
            y_inv_n,
            g_hi,
            b_hi,
            h_lo,
            &c_l,
            &d_l,
            &h,
            &g,
            &inv8,
            &mut tables,
        );
        // R = (sum(a_hi[i] * y^n * G_lo[i] + b_lo[i] * H_hi[i]) + cR * H + dR * G) / 8
        let r = compute_lr(
            a_hi,
            y_n,
            g_lo,
            b_lo,
            h_hi,
            &c_r,
            &d_r,
            &h,
            &g,
            &inv8,
            &mut tables,
        );
        let challenge = transcript_update(&mut transcript, &[&l, &r]);
        if challenge == Scalar::ZERO {
            return Ok(None);
        }
        let challenge_inv = challenge.invert();

        // G' = e^-1 * G_lo + e * y^-n * G_hi, H' = e * H_lo + e^-1 * H_hi
        let g_scalars = [challenge_inv.clone(), challenge.mul(y_inv_n)];
        let h_scalars = [challenge.clone(), challenge_inv.clone()];
        let mut g_next = Vec::with_capacity(n_prime);
        let mut h_next = Vec::with_capacity(n_prime);
        for (lo, hi) in g_lo.iter().zip(g_hi) {
            g_next.push(multiexp(&g_scalars, &[*lo, *hi], &mut tables, false));
        }
        for (lo, hi) in h_lo.iter().zip(h_hi) {
            h_next.push(multiexp(&h_scalars, &[*lo, *hi], &mut tables, false));
        }

        // a' = e * a_lo + e^-1 * y^n * a_hi, b' = e^-1 * b_lo + e * b_hi
        let a_factor = challenge_inv.mul(y_n);
        let a_next: Vec<Scalar> = a_lo
            .iter()
            .zip(a_hi)
            .map(|(lo, hi)| lo.mul(&challenge).add(&hi.mul(&a_factor)))
            .collect();
        let b_next: Vec<Scalar> = b_lo
            .iter()
            .zip(b_hi)
            .map(|(lo, hi)| lo.mul(&challenge_inv).add(&hi.mul(&challenge)))
            .collect();

        alpha1 = alpha1
            .add(&d_l.mul(&challenge).mul(&challenge))
            .add(&d_r.mul(&challenge_inv).mul(&challenge_inv));
        a_prime = a_next;
        b_prime = b_next;
        g_prime = g_next;
        h_prime = h_next;
        l_points.push(l);
        r_points.push(r);
    }

    let (Some(a0), Some(b0), Some(g0), Some(h0)) = (
        a_prime.first(),
        b_prime.first(),
        g_prime.first(),
        h_prime.first(),
    ) else {
        return Err(Error::InvalidProof);
    };
    let r = random_scalar(rng)?;
    let s = random_scalar(rng)?;
    let d_ = random_scalar(rng)?;
    let eta = random_scalar(rng)?;

    // A1 = (r * G' + s * H' + d * G + (r * y * b' + s * y * a') * H) / 8
    let h_scalar = r.mul(&y).mul(b0).add(&s.mul(&y).mul(a0));
    let a1 = multiexp(
        &[
            r.mul(&inv8),
            s.mul(&inv8),
            d_.mul(&inv8),
            h_scalar.mul(&inv8),
        ],
        &[*g0, *h0, g, h],
        &mut tables,
        true,
    )
    .compress();
    // B = (eta * G + r * y * s * H) / 8
    let b = commit_point(&r.mul(&y).mul(&s).mul(&inv8), &eta.mul(&inv8)).compress();

    let e = transcript_update(&mut transcript, &[&a1, &b]);
    if e == Scalar::ZERO {
        return Ok(None);
    }
    let r1 = r.add(&a0.mul(&e));
    let s1 = s.add(&b0.mul(&e));
    let d1 = eta.add(&d_.mul(&e)).add(&alpha1.mul(&e).mul(&e));
    Ok(Some(BulletproofPlus {
        a,
        a1,
        b,
        r1: r1.to_bytes(),
        s1: s1.to_bytes(),
        d1: d1.to_bytes(),
        l: l_points,
        r: r_points,
    }))
}

/// `(sum(a[i] * y * G[i] + b[i] * H[i]) + c * H + d * G) / 8`, in constant
/// time. (The scalars wipe themselves when dropped.)
#[allow(clippy::too_many_arguments)]
fn compute_lr(
    a: &[Scalar],
    y: &Scalar,
    g_points: &[EdwardsPoint],
    b: &[Scalar],
    h_points: &[EdwardsPoint],
    c: &Scalar,
    d: &Scalar,
    h: &EdwardsPoint,
    g: &EdwardsPoint,
    inv8: &Scalar,
    tables: &mut [Table],
) -> [u8; 32] {
    let mut scalars: Vec<Scalar> = Vec::with_capacity(2 * a.len() + 2);
    let mut points = Vec::with_capacity(2 * a.len() + 2);
    for (a, point) in a.iter().zip(g_points) {
        scalars.push(a.mul(y).mul(inv8));
        points.push(*point);
    }
    for (b, point) in b.iter().zip(h_points) {
        scalars.push(b.mul(inv8));
        points.push(*point);
    }
    scalars.push(c.mul(inv8));
    points.push(*h);
    scalars.push(d.mul(inv8));
    points.push(*g);
    multiexp(&scalars, &points, tables, true).compress()
}

fn verify_inner(
    proof: &BulletproofPlus,
    generators: &BulletproofPlusGenerators,
    commitments: &[[u8; 32]],
) -> Result<bool, Error> {
    let Some((m, log_m)) = padded(commitments.len()) else {
        return Ok(false);
    };
    let mn = m * N;
    let rounds = log_m + LOG_N;
    if proof.l.len() != rounds || proof.r.len() != rounds {
        return Ok(false);
    }
    let (Some(gi), Some(hi)) = (generators.gi.get(..mn), generators.hi.get(..mn)) else {
        return Ok(false);
    };
    let r1 = scalar_from_bytes(&proof.r1)?;
    let s1 = scalar_from_bytes(&proof.s1)?;
    let d1 = scalar_from_bytes(&proof.d1)?;

    // The proof is about the commitments divided by 8, and every point of
    // it is multiplied by 8 before use, which takes any torsion out.
    let inv8 = inv_eight();
    let mut tables = new_tables();
    let mut v = Vec::with_capacity(commitments.len());
    let mut v8 = Vec::with_capacity(commitments.len());
    for commitment in commitments {
        let point = point_from_bytes(commitment)?;
        let divided = multiexp(core::slice::from_ref(&inv8), &[point], &mut tables, false);
        v.push(divided.compress());
        v8.push(divided.mul_by_cofactor());
    }
    let times8 = |bytes: &[u8; 32]| Ok::<_, Error>(point_from_bytes(bytes)?.mul_by_cofactor());

    let Some((mut transcript, y, z)) = challenges_yz(&v, &proof.a) else {
        return Ok(false);
    };
    let mut challenges = Vec::with_capacity(rounds);
    let mut challenges_inv = Vec::with_capacity(rounds);
    for (l, r) in proof.l.iter().zip(&proof.r) {
        let challenge = transcript_update(&mut transcript, &[l, r]);
        if challenge == Scalar::ZERO {
            return Ok(false);
        }
        challenges_inv.push(challenge.invert());
        challenges.push(challenge);
    }
    let e = transcript_update(&mut transcript, &[&proof.a1, &proof.b]);
    if e == Scalar::ZERO {
        return Ok(false);
    }
    let y_inv = y.invert();

    // y^MN by squaring (MN is a power of two), then y^(MN + 1).
    let mut y_mn = y.clone();
    for _ in 0..rounds {
        y_mn = y_mn.mul(&y_mn);
    }
    let y_mn_1 = y_mn.mul(&y);
    let e_squared = e.mul(&e);
    let z_squared = z.mul(&z);
    let minus_e_squared = Scalar::ZERO.sub(&e_squared);

    let mut scalars: Vec<Scalar> = Vec::with_capacity(2 * mn + 2 * rounds + m + 5);
    let mut points: Vec<EdwardsPoint> = Vec::with_capacity(2 * mn + 2 * rounds + m + 5);

    // V[j]: -e^2 * y^(MN + 1) * z^(2 * (j + 1))
    let mut v_scalar = minus_e_squared.mul(&y_mn_1);
    for point in &v8 {
        v_scalar = v_scalar.mul(&z_squared);
        scalars.push(v_scalar.clone());
        points.push(*point);
    }
    // B: -1, A1: -e, A: -e^2
    scalars.push(Scalar::ZERO.sub(&Scalar::ONE));
    points.push(times8(&proof.b)?);
    scalars.push(Scalar::ZERO.sub(&e));
    points.push(times8(&proof.a1)?);
    scalars.push(minus_e_squared.clone());
    points.push(times8(&proof.a)?);
    // G: d1
    scalars.push(d1);
    points.push(EdwardsPoint::generator());

    // H: ((z^2 - z) * sum(y^1..y^MN) + y^(MN + 1) * z * sum(d)) * e^2 + r1 * y * s1,
    // with sum(d) = (2^64 - 1) * (z^2 + z^4 + ... + z^(2M)).
    let d = d_vector(&z_squared, m);
    let mut sum_y = Scalar::ZERO;
    let mut y_power = Scalar::ONE;
    for _ in 0..mn {
        y_power = y_power.mul(&y);
        sum_y = sum_y.add(&y_power);
    }
    let mut sum_z = Scalar::ZERO;
    let mut z_power = Scalar::ONE;
    for _ in 0..m {
        z_power = z_power.mul(&z_squared);
        sum_z = sum_z.add(&z_power);
    }
    let sum_d = scalar_from_u64(u64::MAX).mul(&sum_z);
    let h_scalar = z_squared
        .sub(&z)
        .mul(&sum_y)
        .add(&y_mn_1.mul(&z).mul(&sum_d))
        .mul(&e_squared)
        .add(&r1.mul(&y).mul(&s1));
    scalars.push(h_scalar);
    points.push(h_point());

    // The products of the round challenges and their inverses, one per
    // generator: entry i multiplies, for each round j, the challenge if bit
    // (rounds - 1 - j) of i is set and its inverse otherwise.
    let mut cache: Vec<Scalar> = vec![Scalar::ZERO; mn];
    if let (Some(first), Some(first_inv)) = (challenges.first(), challenges_inv.first()) {
        if let Some(slot) = cache.get_mut(0) {
            *slot = first_inv.clone();
        }
        if let Some(slot) = cache.get_mut(1) {
            *slot = first.clone();
        }
    }
    for (j, (challenge, challenge_inv)) in challenges.iter().zip(&challenges_inv).enumerate() {
        if j == 0 {
            continue;
        }
        let slots = 1usize << (j + 1);
        let mut s = slots;
        while s >= 2 {
            // s is even: the slots s - 1 and s - 2 both descend from slot
            // (s - 1) / 2, which is overwritten only after them.
            let Some(base) = cache.get((s - 1) / 2).cloned() else {
                return Ok(false);
            };
            if let Some(slot) = cache.get_mut(s - 1) {
                *slot = base.mul(challenge);
            }
            if let Some(slot) = cache.get_mut(s - 2) {
                *slot = base.mul(challenge_inv);
            }
            s -= 2;
        }
    }

    // Gi[i]: e * r1 * y^-i * cache[i] + e^2 * z
    // Hi[i]: e * s1 * cache[!i] - e^2 * z - e^2 * y^(MN - i) * d[i]
    let e_squared_z = e_squared.mul(&z);
    let e_s1 = e.mul(&s1);
    let mut e_r1_y = e.mul(&r1);
    let mut minus_e_squared_y = minus_e_squared.mul(&y_mn);
    for (i, ((g_point, h_point), d)) in gi.iter().zip(hi).zip(&d).enumerate() {
        let (Some(direct), Some(mirrored)) = (cache.get(i), cache.get(!i & (mn - 1))) else {
            return Ok(false);
        };
        scalars.push(e_r1_y.mul(direct).add(&e_squared_z));
        points.push(*g_point);
        scalars.push(
            e_s1.mul(mirrored)
                .sub(&e_squared_z)
                .add(&minus_e_squared_y.mul(d)),
        );
        points.push(*h_point);
        e_r1_y = e_r1_y.mul(&y_inv);
        minus_e_squared_y = minus_e_squared_y.mul(&y_inv);
    }

    // L[j]: -e^2 * challenge^2, R[j]: -e^2 * challenge^-2
    for (((l, r), challenge), challenge_inv) in proof
        .l
        .iter()
        .zip(&proof.r)
        .zip(&challenges)
        .zip(&challenges_inv)
    {
        scalars.push(minus_e_squared.mul(challenge).mul(challenge));
        points.push(times8(l)?);
        scalars.push(minus_e_squared.mul(challenge_inv).mul(challenge_inv));
        points.push(times8(r)?);
    }

    let sum = multiexp(&scalars, &points, &mut tables, false);
    Ok(sum == EdwardsPoint::identity())
}
