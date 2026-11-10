//! Bulletproofs+ aggregated range proofs, as Zano instantiates them for
//! confidential outputs (`range_proof_bpp.h`, with the crypto trait
//! `bpp_crypto_trait_ZC_out`: 64-bit values, at most 32 per proof, value
//! generator `U` and mask generator `G`).
//!
//! The proof shows that each commitment `value * U + mask * G` commits to a
//! value below `2^64`. All points of the proof and the commitments are
//! exchanged multiplied by `1/8`.

use purecrypto::ct::Choice;

use crate::cryptonote::{EdwardsPoint, FieldElement, Scalar, point_from_hash, scalar_from_hash};
use crate::prelude::*;

use super::Error;
use super::crypto::{
    self, Transcript, generator_u, msm_vartime, mul_vartime, random_scalar, scalar_1div8,
};
use super::tx::BppSignature;

/// The number of bits of a value.
const N: usize = 64;
/// The most values one proof covers (`c_bpp_values_max`).
pub const BPP_MAX_VALUES: usize = 32;

/// The proof generators `g_i` (even positions) and `h_i` (odd positions):
/// `Hp(Hs("Zano BP+ generator") || position)`.
fn generators(mn: usize) -> (Vec<EdwardsPoint>, Vec<EdwardsPoint>) {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&scalar_from_hash(&[b"Zano BP+ generator"]).to_bytes());
    let mut generator = |position: usize| {
        buf[32..40].copy_from_slice(&(position as u64).to_le_bytes());
        point_from_hash(&buf)
    };
    let g = (0..mn).map(|i| generator(2 * i)).collect();
    let h = (0..mn).map(|i| generator(2 * i + 1)).collect();
    (g, h)
}

/// The generator at `index` of the `g` (`select_h == false`) or `h` vector
/// (`CT::get_generator`).
#[cfg(test)]
pub(crate) fn generator(select_h: bool, index: usize) -> EdwardsPoint {
    let (g, h) = generators(index + 1);
    if select_h { h[index] } else { g[index] }
}

/// `value * U + mask * G` (`CT::calc_pedersen_commitment`), in constant time.
fn pedersen(value: &Scalar, mask: &Scalar) -> EdwardsPoint {
    generator_u().mul(value).add(&EdwardsPoint::mul_base(mask))
}

/// `a` if `choice`, else `b`, without branching on `choice`.
fn select(a: &EdwardsPoint, b: &EdwardsPoint, choice: Choice) -> EdwardsPoint {
    let (a, b) = (a.to_extended(), b.to_extended());
    let coords = core::array::from_fn(|i| FieldElement::conditional_select(&a[i], &b[i], choice));
    // Either set of coordinates is a point's.
    EdwardsPoint::from_extended(&coords).unwrap_or_else(EdwardsPoint::identity)
}

/// The number of padded values `m` (a power of two) and its logarithm.
fn dimensions(values: usize) -> Option<(usize, usize)> {
    if values == 0 || values > BPP_MAX_VALUES {
        return None;
    }
    let m = values.next_power_of_two();
    Some((m, m.trailing_zeros() as usize))
}

/// The challenges `y` and `z` from the commitments and `A0`.
fn challenges_yz(commitments_1div8: &[[u8; 32]], a0: &[u8; 32]) -> (Transcript, Scalar, Scalar) {
    let mut hsc = Transcript::new();
    hsc.scalar(&scalar_from_hash(&[b"Zano BP+ initial transcript"]));
    for commitment in commitments_1div8 {
        hsc.bytes(commitment);
    }
    let e = hsc.take_scalar();
    hsc.scalar(&e).bytes(a0);
    let y = hsc.take_scalar();
    let z = scalar_from_hash(&[&y.to_bytes()]);
    (hsc, y, z)
}

/// The vector `d`: `d[i * N + j] = 2^j * z^(2 * (i + 1))`.
fn d_vector(m: usize, z_sq: &Scalar) -> Vec<Scalar> {
    d_vector_n(m, N, z_sq)
}

/// `2^bits - 1`, for `bits` up to 248.
fn all_ones(bits: usize) -> Scalar {
    let mut bytes = [0u8; 32];
    for byte in bytes.iter_mut().take(bits / 8) {
        *byte = 0xff;
    }
    Scalar::from_bytes_canonical(&bytes).unwrap_or(Scalar::ZERO)
}

/// The vector `d` for values of `n` bits.
fn d_vector_n(m: usize, n: usize, z_sq: &Scalar) -> Vec<Scalar> {
    let mut d = Vec::with_capacity(m * n);
    let mut z_power = z_sq.clone();
    for _ in 0..m {
        let mut v = z_power.clone();
        for _ in 0..n {
            let next = v.add(&v);
            d.push(v);
            v = next;
        }
        z_power = z_power.mul(z_sq);
    }
    d
}

/// Proves that each of `values` is below `2^64` (`bpp_gen`).
///
/// `masks[i]` is the blinding mask of the commitment
/// `values[i] * U + masks[i] * G`, and `commitments_1div8[i]` is that
/// commitment times `1/8`, as it will be published.
///
/// `rng` must fill its buffer from a cryptographically secure source.
///
/// Fails with [`Error::TooLarge`] unless there are between 1 and
/// [`BPP_MAX_VALUES`] values, with as many masks and commitments.
pub fn generate_bpp(
    rng: &mut dyn FnMut(&mut [u8]),
    values: &[u64],
    masks: &[Scalar],
    commitments_1div8: &[[u8; 32]],
) -> Result<BppSignature, Error> {
    let (m, _) = dimensions(values.len()).ok_or(Error::TooLarge)?;
    if masks.len() != values.len() || commitments_1div8.len() != values.len() {
        return Err(Error::TooLarge);
    }
    let mn = m * N;
    let inv8 = scalar_1div8();
    let (mut g, mut h) = generators(mn);

    // The bits: aL[i] is the bit, aR[i] = aL[i] - 1. Values past the end are
    // zero.
    let bit = |i: usize| {
        let value = values.get(i / N).copied().unwrap_or(0);
        ((value >> (i % N)) & 1) as u8
    };

    // A0 = alpha * G + sum(aL_i * g_i + aR_i * h_i): each position adds g_i
    // or -h_i.
    let alpha = random_scalar(rng);
    let mut a0 = EdwardsPoint::mul_base(&alpha);
    for (i, (g_i, h_i)) in g.iter().zip(&h).enumerate() {
        a0 = a0.add(&select(g_i, &h_i.negate(), Choice::from(bit(i))));
    }
    let a0 = a0.mul(&inv8).compress();

    let (mut hsc, y, z) = challenges_yz(commitments_1div8, &a0);
    let mut e = z.clone();
    let z_sq = z.mul(&z);
    let d = d_vector(m, &z_sq);

    // y_powers = (1, y, ..., y^(mn+1)).
    let mut y_powers = Vec::with_capacity(mn + 2);
    y_powers.push(Scalar::ONE);
    for i in 0..=mn {
        let next = y_powers[i].mul(&y);
        y_powers.push(next);
    }

    // a = aL - z, b = aR + z + d o (y^mn, ..., y).
    let one_minus_z = Scalar::ONE.sub(&z);
    let minus_z = z.negate();
    let z_minus_one = z.sub(&Scalar::ONE);
    let mut a = Vec::with_capacity(mn);
    let mut b = Vec::with_capacity(mn);
    // The part of b that does not depend on the bits: z + d o (y^mn, ..., y).
    let mut b_public = Vec::with_capacity(mn);
    for i in 0..mn {
        // Both alternatives are computed already; only a copy depends on
        // the bit.
        let (a_i, b_i) = if bit(i) == 1 {
            (&one_minus_z, &z)
        } else {
            (&minus_z, &z_minus_one)
        };
        let weight = d[i].mul(&y_powers[mn - i]);
        a.push(a_i.clone());
        b.push(b_i.add(&weight));
        b_public.push(z.add(&weight));
    }

    // alpha_hat = alpha + y^(mn+1) * sum(z^(2j) * mask_j).
    let mut alpha_hat = Scalar::ZERO;
    for (mask, d_row) in masks.iter().zip(d.as_chunks::<N>().0.iter()) {
        alpha_hat = alpha_hat.add(&d_row[0].mul(mask));
    }
    let mut alpha_hat = alpha.add(&y_powers[mn + 1].mul(&alpha_hat));

    let y_inverse = y.invert();
    let mut y_inverse_powers = Vec::with_capacity(mn / 2 + 1);
    y_inverse_powers.push(Scalar::ONE);
    for i in 0..mn / 2 {
        let next = y_inverse_powers[i].mul(&y_inverse);
        y_inverse_powers.push(next);
    }

    let mut sig = BppSignature {
        a0,
        ..Default::default()
    };

    // The rounds of the weighted inner product argument, halving the vectors.
    let mut n = mn / 2;
    while n >= 1 {
        let d_l = random_scalar(rng);
        let d_r = random_scalar(rng);
        let (a1, a2) = a.split_at(n);
        let (b1, b2) = b.split_at(n);
        let (g1, g2) = g.split_at(n);
        let (h1, h2) = h.split_at(n);

        // cL = <a1, (y, y^2, ...) o b2>, cR = <a2, (y, y^2, ...) o b1> * y^n.
        let mut c_l = Scalar::ZERO;
        let mut c_r = Scalar::ZERO;
        for i in 0..n {
            c_l = c_l.add(&a1[i].mul(&y_powers[i + 1]).mul(&b2[i]));
            c_r = c_r.add(&a2[i].mul(&y_powers[i + 1]).mul(&b1[i]));
        }
        c_r = c_r.mul(&y_powers[n]);

        // L = y^-n * <a1, g2> + <b2, h1> + cL * U + dL * G
        // R = y^n  * <a2, g1> + <b1, h2> + cR * U + dR * G
        let mut l_sum = EdwardsPoint::identity();
        let mut r_sum = EdwardsPoint::identity();
        let mut l = pedersen(&c_l, &d_l);
        let mut r = pedersen(&c_r, &d_r);
        if 2 * n == mn {
            // The first round, half of all the work: the secret part of each
            // scalar is still one bit (a = bit - z, b = bit - 1 + b_public),
            // so the sums are additions chosen by the bits, plus sums with
            // public scalars.
            let identity = EdwardsPoint::identity();
            let mut g1_sum = identity;
            let mut g2_sum = identity;
            let mut l_public = Vec::with_capacity(n);
            let mut r_public = Vec::with_capacity(n);
            for i in 0..n {
                let (low, high) = (Choice::from(bit(i)), Choice::from(bit(n + i)));
                l_sum = l_sum.add(&select(&g2[i], &identity, low));
                r_sum = r_sum.add(&select(&g1[i], &identity, high));
                l = l.sub(&select(&identity, &h1[i], high));
                r = r.sub(&select(&identity, &h2[i], low));
                g1_sum = g1_sum.add(&g1[i]);
                g2_sum = g2_sum.add(&g2[i]);
                l_public.push((b_public[n + i].clone(), h1[i]));
                r_public.push((b_public[i].clone(), h2[i]));
            }
            l_sum = l_sum.add(&mul_vartime(&minus_z, &g2_sum));
            r_sum = r_sum.add(&mul_vartime(&minus_z, &g1_sum));
            l = l.add(&msm_vartime(&l_public));
            r = r.add(&msm_vartime(&r_public));
        } else {
            for i in 0..n {
                l_sum = l_sum.add(&g2[i].mul(&a1[i]));
                r_sum = r_sum.add(&g1[i].mul(&a2[i]));
                l = l.add(&h1[i].mul(&b2[i]));
                r = r.add(&h2[i].mul(&b1[i]));
            }
        }
        let l = l
            .add(&l_sum.mul(&y_inverse_powers[n]))
            .mul(&inv8)
            .compress();
        let r = r.add(&r_sum.mul(&y_powers[n])).mul(&inv8).compress();
        sig.lv.push(l);
        sig.rv.push(r);

        hsc.scalar(&e).bytes(&l).bytes(&r);
        e = hsc.take_scalar();

        let e_inverse = e.invert();
        let e_y_inv_n = e.mul(&y_inverse_powers[n]);
        let e_inv_y_n = e_inverse.mul(&y_powers[n]);
        // The challenges are public, so the generators fold in variable time.
        for i in 0..n {
            g[i] = msm_vartime(&[(e_inverse.clone(), g[i]), (e_y_inv_n.clone(), g[n + i])]);
            h[i] = msm_vartime(&[(e.clone(), h[i]), (e_inverse.clone(), h[n + i])]);
            a[i] = e.mul(&a[i]).add(&e_inv_y_n.mul(&a[n + i]));
            b[i] = e_inverse.mul(&b[i]).add(&e.mul(&b[n + i]));
        }
        g.truncate(n);
        h.truncate(n);
        a.truncate(n);
        b.truncate(n);
        alpha_hat = alpha_hat
            .add(&e.mul(&e).mul(&d_l))
            .add(&e_inverse.mul(&e_inverse).mul(&d_r));
        n /= 2;
    }

    // The last round.
    let r = random_scalar(rng);
    let s = random_scalar(rng);
    let delta = random_scalar(rng);
    let eta = random_scalar(rng);
    // A = r * g + s * h + (r * y * b + s * y * a) * U + delta * G
    let a_pt = pedersen(&y.mul(&r.mul(&b[0]).add(&s.mul(&a[0]))), &delta)
        .add(&g[0].mul(&r))
        .add(&h[0].mul(&s))
        .mul(&inv8)
        .compress();
    // B = (r * y * s) * U + eta * G
    let b_pt = pedersen(&r.mul(&y).mul(&s), &eta).mul(&inv8).compress();
    sig.a = a_pt;
    sig.b = b_pt;

    hsc.scalar(&e).bytes(&a_pt).bytes(&b_pt);
    let e = hsc.take_scalar();
    sig.r = r.add(&e.mul(&a[0])).to_bytes();
    sig.s = s.add(&e.mul(&b[0])).to_bytes();
    sig.delta = eta
        .add(&e.mul(&delta))
        .add(&e.mul(&e).mul(&alpha_hat))
        .to_bytes();
    Ok(sig)
}

/// Verifies a range proof over `commitments_1div8` (`bpp_verify`, for one
/// proof). Variable-time.
pub fn verify_bpp(sig: &BppSignature, commitments_1div8: &[[u8; 32]]) -> bool {
    verify(sig, commitments_1div8).unwrap_or(false)
}

fn verify(sig: &BppSignature, commitments_1div8: &[[u8; 32]]) -> Option<bool> {
    let delta = crypto::scalar(&sig.delta).ok()?;
    verify_range(
        &RangeProof {
            bits: N,
            max_values: BPP_MAX_VALUES,
            lv: &sig.lv,
            rv: &sig.rv,
            a0: &sig.a0,
            a: &sig.a,
            b: &sig.b,
            r: &sig.r,
            s: &sig.s,
            value_generator: generator_u(),
            masks: &[(delta, EdwardsPoint::generator())],
        },
        commitments_1div8,
    )
}

/// A Bulletproofs+ range proof with the parameters of its crypto trait
/// (`bpp_crypto_trait_zano`).
pub(crate) struct RangeProof<'a> {
    /// The number of bits of a value (`c_bpp_n`), a power of two.
    pub bits: usize,
    /// The most values a proof covers (`c_bpp_values_max`).
    pub max_values: usize,
    pub lv: &'a [[u8; 32]],
    pub rv: &'a [[u8; 32]],
    pub a0: &'a [u8; 32],
    pub a: &'a [u8; 32],
    pub b: &'a [u8; 32],
    pub r: &'a [u8; 32],
    pub s: &'a [u8; 32],
    /// The generator of the values (`bpp_G`).
    pub value_generator: EdwardsPoint,
    /// The final responses for the masks, each with its generator
    /// (`delta` and `bpp_H`; for a double-blinded proof also `delta_2` and
    /// `bpp_H2`).
    pub masks: &'a [(Scalar, EdwardsPoint)],
}

/// `bpp_verify` / `bppe_verify` for one proof.
pub(crate) fn verify_range(sig: &RangeProof<'_>, commitments_1div8: &[[u8; 32]]) -> Option<bool> {
    if commitments_1div8.is_empty() || commitments_1div8.len() > sig.max_values {
        return None;
    }
    let n = sig.bits;
    let m = commitments_1div8.len().next_power_of_two();
    let log2_mn = (m.trailing_zeros() + n.trailing_zeros()) as usize;
    let mn = m * n;
    if sig.lv.len() != log2_mn || sig.rv.len() != log2_mn {
        return None;
    }
    let r = crypto::scalar(sig.r).ok()?;
    let s = crypto::scalar(sig.s).ok()?;
    let point = |bytes: &[u8; 32]| crypto::point(bytes).ok();

    // Restore the challenges.
    let (mut hsc, y, z) = challenges_yz(commitments_1div8, sig.a0);
    let z_sq = z.mul(&z);
    let mut e = z.clone();
    let mut e_sq = Vec::with_capacity(log2_mn);
    let mut e_inv = Vec::with_capacity(log2_mn);
    for (l, r) in sig.lv.iter().zip(sig.rv) {
        hsc.scalar(&e).bytes(l).bytes(r);
        e = hsc.take_scalar();
        e_sq.push(e.mul(&e));
        e_inv.push(e.invert());
    }
    hsc.scalar(&e).bytes(sig.a).bytes(sig.b);
    let e_final = hsc.take_scalar();
    let e_final_sq = e_final.mul(&e_final);
    let y_inv = y.invert();

    let d = d_vector_n(m, n, &z_sq);
    // sum(d) = (2^N - 1) * (z^2 + z^4 + ... + z^(2m))
    let mut z_powers_sum = Scalar::ZERO;
    let mut z_power = z_sq.clone();
    for _ in 0..m {
        z_powers_sum = z_powers_sum.add(&z_power);
        z_power = z_power.mul(&z_sq);
    }
    let sum_d = all_ones(n).mul(&z_powers_sum);

    // s_vec[i] = prod_j e_j^(+1 if bit (log2_mn - 1 - j) of i is set, else -1)
    let mut s_vec: Vec<Scalar> = Vec::with_capacity(mn);
    s_vec.push(e_inv.iter().fold(Scalar::ONE, |acc, v| acc.mul(v)));
    for i in 1..mn {
        let base = s_vec.get(i & (i - 1))?;
        let bit_index = log2_mn.checked_sub(1 + i.trailing_zeros() as usize)?;
        let next = base.mul(e_sq.get(bit_index)?);
        s_vec.push(next);
    }

    // The scalars of the fixed generators.
    let e_sq_z = e_final_sq.mul(&z);
    let r_e = e_final.mul(&r);
    let s_e = e_final.mul(&s);
    let (g, h) = generators(mn);
    let mut terms = Vec::with_capacity(2 * mn + 2);
    let mut y_inverse_power = Scalar::ONE;
    // sum(y^1 .. y^mn), built along the way.
    let mut sum_y = Scalar::ZERO;
    let mut e_sq_y = e_final_sq.mul(&y);
    let mut y_power = y.clone();
    for i in 0..mn {
        // g_i: r' * e * y^-i * s_vec[i] + e^2 * z
        let g_scalar = r_e.mul(&y_inverse_power).mul(s_vec.get(i)?).add(&e_sq_z);
        terms.push((g_scalar, *g.get(i)?));
        y_inverse_power = y_inverse_power.mul(&y_inv);
        // h_j, for j = mn - 1 - i: s' * e * s_vec[i] - e^2 * z - e^2 * y^(i+1) * d[j]
        let j = mn - 1 - i;
        let h_scalar = s_e
            .mul(s_vec.get(i)?)
            .sub(&e_sq_z)
            .sub(&e_sq_y.mul(d.get(j)?));
        terms.push((h_scalar, *h.get(j)?));
        e_sq_y = e_sq_y.mul(&y);
        sum_y = sum_y.add(&y_power);
        y_power = y_power.mul(&y);
    }
    // Now e_sq_y = e^2 * y^(mn+1).
    let g_scalar = r
        .mul(&y)
        .mul(&s)
        .add(&e_sq_y.mul(&sum_d).mul(&z))
        .sub(&e_final_sq.mul(&z.sub(&z_sq)).mul(&sum_y));
    terms.push((g_scalar, sig.value_generator));
    terms.extend(sig.masks.iter().cloned());
    let fixed = msm_vartime(&terms);

    // The points of the proof, all to be multiplied by 8.
    let mut terms = Vec::with_capacity(commitments_1div8.len() + 2 * log2_mn + 3);
    terms.push((e_final_sq.clone(), point(sig.a0)?));
    let mut v_scalar = e_sq_y;
    for commitment in commitments_1div8 {
        v_scalar = v_scalar.mul(&z_sq);
        terms.push((v_scalar.clone(), point(commitment)?));
    }
    for (((l, r), e_sq), e_inv) in sig.lv.iter().zip(sig.rv).zip(&e_sq).zip(&e_inv) {
        terms.push((e_final_sq.mul(e_sq), point(l)?));
        terms.push((e_final_sq.mul(&e_inv.mul(e_inv)), point(r)?));
    }
    terms.push((e_final, point(sig.a)?));
    terms.push((Scalar::ONE, point(sig.b)?));
    Some(fixed == msm_vartime(&terms).mul_by_cofactor())
}
