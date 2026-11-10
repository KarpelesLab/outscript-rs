//! The Bootle–Groth–Esgin one-out-of-many proof Zano uses for asset
//! surjection (`one_out_of_many_proofs.cpp`): a proof of knowing the discrete
//! logarithm, with respect to `X`, of one member of a ring of points, without
//! telling which.

use crate::cryptonote::{EdwardsPoint, Scalar, point_from_hash, scalar_from_hash, scalar_reduce};
use crate::prelude::*;

use super::Error;
use super::crypto::{
    self, Transcript, generator_x, msm_vartime, mul_vartime, random_scalar, scalar_1div8,
};
use super::tx::BgeProof;

/// The base of the decomposition of the secret index.
const N: usize = 4;
/// The largest `m * N` the generators cover (`mn_max`).
const MN_MAX: usize = 16;
/// The largest ring: `N^(MN_MAX / N)` (`N_max`).
pub const BGE_MAX_RING_SIZE: usize = 256;

/// The smallest `m >= 1` with `ring_size <= N^m`, and `N^m`.
fn dimensions(ring_size: usize) -> Option<(usize, usize)> {
    if ring_size == 0 || ring_size > BGE_MAX_RING_SIZE {
        return None;
    }
    let mut m = 1;
    let mut size = N;
    while size < ring_size {
        m += 1;
        size = size.checked_mul(N)?;
    }
    (m * N <= MN_MAX).then_some((m, size))
}

/// The generators: `Hp(Hs("Zano BGE generator") || index)`, the index as a
/// 256-bit little-endian integer.
fn generators(m: usize) -> Vec<EdwardsPoint> {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&scalar_from_hash(&[b"Zano BGE generator"]).to_bytes());
    (0..m * N * 2)
        .map(|i| {
            buf[32..40].copy_from_slice(&(i as u64).to_le_bytes());
            point_from_hash(&buf)
        })
        .collect()
}

/// The challenge `x`.
fn challenge(context_hash: &[u8; 32], ring_1div8: &[[u8; 32]], proof: &BgeProof) -> Scalar {
    let mut hsc = Transcript::new();
    hsc.bytes(context_hash);
    for member in ring_1div8 {
        hsc.bytes(member);
    }
    hsc.bytes(&proof.a).bytes(&proof.b);
    for pk in &proof.pk {
        hsc.bytes(pk);
    }
    hsc.take_scalar()
}

/// Proves knowledge of `secret` with `ring[secret_index] == secret * X`
/// (`generate_BGE_proof`). The ring members are full points (not multiplied
/// by `1/8`).
///
/// `rng` must fill its buffer from a cryptographically secure source.
///
/// Fails with [`Error::InvalidRing`] for an empty ring, one of more than
/// [`BGE_MAX_RING_SIZE`] members or an index outside it, and
/// [`Error::SecretMismatch`] if `secret` does not open the member.
pub fn generate_bge_proof(
    rng: &mut dyn FnMut(&mut [u8]),
    context_hash: &[u8; 32],
    ring: &[EdwardsPoint],
    secret: &Scalar,
    secret_index: usize,
) -> Result<BgeProof, Error> {
    let (m, size) = dimensions(ring.len()).ok_or(Error::InvalidRing)?;
    let (Some(real), Some(last)) = (ring.get(secret_index), ring.last()) else {
        return Err(Error::InvalidRing);
    };
    let x_gen = generator_x();
    if x_gen.mul(secret) != *real {
        return Err(Error::SecretMismatch);
    }

    // a: an m x N matrix whose rows sum to zero; l_digits: the base-N digits
    // of the secret index.
    let mut a_mat = vec![Scalar::ZERO; m * N];
    let mut l_digits = Vec::with_capacity(m);
    let mut l = secret_index;
    for row in a_mat.as_chunks_mut::<N>().0.iter_mut() {
        let mut first = Scalar::ZERO;
        for a in row.iter_mut().skip(1).rev() {
            *a = random_scalar(rng);
            first = first.sub(a);
        }
        row[0] = first;
        l_digits.push(l % N);
        l /= N;
    }

    // coeffs: an m x size matrix; column i holds the coefficients of the
    // polynomial p_i(x) = prod_j (delta(i_j, l_j) * x + a[j][i_j]), without
    // its leading one.
    let mut coeffs = vec![Scalar::ZERO; m * size];
    for i in 0..size {
        let mut column = vec![Scalar::ZERO; m];
        column[0] = Scalar::ONE;
        let mut i_tmp = i;
        let mut m_bound = 1;
        for (row, &digit) in a_mat.as_chunks::<N>().0.iter().zip(&l_digits) {
            let i_j = i_tmp % N;
            i_tmp /= N;
            let a = &row[i_j];
            if i_j == digit {
                let mut carry = Scalar::ZERO;
                for c in column.iter_mut().take(m_bound) {
                    let old = c.clone();
                    *c = c.mul(a).add(&carry);
                    carry = old;
                }
                if let Some(c) = column.get_mut(m_bound) {
                    *c = c.add(&carry);
                }
                m_bound += 1;
            } else {
                for c in column.iter_mut().take(m_bound) {
                    *c = c.mul(a);
                }
            }
        }
        for (k, c) in column.into_iter().enumerate() {
            coeffs[k * size + i] = c;
        }
    }

    let r_a = random_scalar(rng);
    let r_b = random_scalar(rng);
    let ro: Vec<Scalar> = (0..m).map(|_| random_scalar(rng)).collect();

    let gens = generators(m);
    let inv8 = scalar_1div8();
    let mut a_pt = EdwardsPoint::identity();
    let mut b_pt = EdwardsPoint::identity();
    let mut proof = BgeProof::default();
    for (j, row) in a_mat.as_chunks::<N>().0.iter().enumerate() {
        for (i, a) in row.iter().enumerate() {
            let gen_1 = &gens[(j * N + i) * 2];
            let gen_2 = &gens[(j * N + i) * 2 + 1];
            a_pt = a_pt.add(&gen_1.mul(a)).sub(&gen_2.mul(&a.mul(a)));
            b_pt = if l_digits[j] == i {
                b_pt.add(gen_1).sub(&gen_2.mul(a))
            } else {
                b_pt.add(&gen_2.mul(a))
            };
        }
        let row_coeffs = &coeffs[j * size..(j + 1) * size];
        let mut pk = x_gen.mul(&ro[j]);
        for (i, c) in row_coeffs.iter().enumerate() {
            // Past the end of the ring, its last member is repeated.
            pk = pk.add(&ring.get(i).unwrap_or(last).mul(c));
        }
        proof.pk.push(pk.mul(&inv8).compress());
    }
    proof.a = a_pt.add(&x_gen.mul(&r_a)).mul(&inv8).compress();
    proof.b = b_pt.add(&x_gen.mul(&r_b)).mul(&inv8).compress();

    let ring_1div8: Vec<[u8; 32]> = ring
        .iter()
        .map(|p| mul_vartime(&inv8, p).compress())
        .collect();
    let x = challenge(context_hash, &ring_1div8, &proof);

    for (row, &digit) in a_mat.as_chunks::<N>().0.iter().zip(&l_digits) {
        for (i, a) in row.iter().enumerate().skip(1) {
            let f = if digit == i { a.add(&x) } else { a.clone() };
            proof.f.push(f.to_bytes());
        }
    }
    proof.y = r_a.add(&x.mul(&r_b)).to_bytes();
    let mut z = Scalar::ZERO;
    let mut x_power = Scalar::ONE;
    for r in &ro {
        z = z.sub(&x_power.mul(r));
        x_power = x_power.mul(&x);
    }
    proof.z = z.add(&secret.mul(&x_power)).to_bytes();
    Ok(proof)
}

/// Verifies a [`BgeProof`] (`verify_BGE_proof`). The ring members are given
/// as they are hashed: multiplied by `1/8`. Variable-time.
pub fn verify_bge_proof(
    context_hash: &[u8; 32],
    ring_1div8: &[[u8; 32]],
    proof: &BgeProof,
) -> bool {
    verify(context_hash, ring_1div8, proof).unwrap_or(false)
}

fn verify(context_hash: &[u8; 32], ring_1div8: &[[u8; 32]], proof: &BgeProof) -> Option<bool> {
    let (m, size) = dimensions(ring_1div8.len())?;
    if proof.pk.len() != m || proof.f.len() != m * (N - 1) {
        return None;
    }
    let x = challenge(context_hash, ring_1div8, proof);

    // f: the m x N matrix of responses, its first column restored as
    // f[j][0] = x - sum(f[j][1..]).
    let mut f = Vec::with_capacity(m * N);
    for row in proof.f.as_chunks::<{ N - 1 }>().0.iter() {
        let rest: Vec<Scalar> = row.iter().map(scalar_reduce).collect();
        let first = rest.iter().fold(x.clone(), |acc, v| acc.sub(v));
        f.push(first);
        f.extend(rest);
    }

    let x_gen = generator_x();
    let gens = generators(m);
    let point8 = |bytes: &[u8; 32]| Some(crypto::point(bytes).ok()?.mul_by_cofactor());

    // 1: A + x * B == sum(f * gen_1 + f * (x - f) * gen_2) + y * X
    let mut terms = Vec::with_capacity(2 * m * N + 1);
    for (f_ji, pair) in f.iter().zip(gens.as_chunks::<2>().0.iter()) {
        terms.push((f_ji.clone(), pair[0]));
        terms.push((f_ji.mul(&x.sub(f_ji)), pair[1]));
    }
    terms.push((scalar_reduce(&proof.y), x_gen));
    let lhs = point8(&proof.a)?.add(&mul_vartime(&x, &point8(&proof.b)?));
    if lhs != msm_vartime(&terms) {
        return Some(false);
    }

    // 2: sum(p_i * ring_i) == sum(x^k * Pk_k) + z * X, with
    // p_i = prod_j f[j][i_j].
    let mut ring = Vec::with_capacity(ring_1div8.len());
    for member in ring_1div8 {
        ring.push(point8(member)?);
    }
    let last_index = ring.len().checked_sub(1)?;
    // The last member stands for the positions past the end of the ring, so
    // its coefficients add up.
    let mut coeffs = vec![Scalar::ZERO; ring.len()];
    for i in 0..size {
        let mut p = Scalar::ONE;
        let mut i_tmp = i;
        for row in f.as_chunks::<N>().0.iter() {
            p = p.mul(&row[i_tmp % N]);
            i_tmp /= N;
        }
        let coeff = coeffs.get_mut(i.min(last_index))?;
        *coeff = coeff.add(&p);
    }
    let terms: Vec<(Scalar, EdwardsPoint)> = coeffs.into_iter().zip(ring).collect();
    let lhs = msm_vartime(&terms);

    let mut terms = Vec::with_capacity(m + 1);
    let mut x_power = Scalar::ONE;
    for pk in &proof.pk {
        terms.push((x_power.clone(), point8(pk)?));
        x_power = x_power.mul(&x);
    }
    terms.push((scalar_reduce(&proof.z), x_gen));
    Some(lhs == msm_vartime(&terms))
}
