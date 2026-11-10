//! The multipoint opening argument of `halo2_proofs`: many polynomials,
//! each opened at a few points, reduced to one opening of one polynomial.
//! Polynomials opened at the same set of points are combined first; the
//! grouping (and so the transcript) depends on the order of the queries,
//! which follows the reference.

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

use super::Error;
use super::commitment::{self, Msm, Params, ProverRng};
use super::poly::{eval_polynomial, kate_division, lagrange_interpolate};
use super::transcript::{TranscriptRead, TranscriptWrite};
use crate::orchard::{Fp, vesta};

/// A commitment the verifier queries: a point, or a linear combination.
#[derive(Clone, Copy)]
pub(crate) enum CommitmentReference<'r> {
    /// A single commitment.
    Commitment(&'r vesta::Affine),
    /// A linear combination of commitments.
    Msm(&'r Msm),
}

impl CommitmentReference<'_> {
    /// The identity of the commitment: two queries concern the same
    /// commitment when they refer to the same object, as in the reference.
    fn id(&self) -> usize {
        match self {
            CommitmentReference::Commitment(c) => *c as *const vesta::Affine as usize,
            CommitmentReference::Msm(m) => *m as *const Msm as usize,
        }
    }
}

/// A claim that a commitment opens to `eval` at `point`.
#[derive(Clone, Copy)]
pub(crate) struct VerifierQuery<'r> {
    point: Fp,
    commitment: CommitmentReference<'r>,
    eval: Fp,
}

impl<'r> VerifierQuery<'r> {
    /// A query of a commitment.
    pub(crate) fn new_commitment(commitment: &'r vesta::Affine, point: Fp, eval: Fp) -> Self {
        VerifierQuery {
            point,
            eval,
            commitment: CommitmentReference::Commitment(commitment),
        }
    }

    /// A query of a linear combination of commitments.
    pub(crate) fn new_msm(msm: &'r Msm, point: Fp, eval: Fp) -> Self {
        VerifierQuery {
            point,
            eval,
            commitment: CommitmentReference::Msm(msm),
        }
    }
}

/// A polynomial the prover opens at `point`.
#[derive(Clone, Copy)]
pub(crate) struct ProverQuery<'a> {
    /// The point.
    pub(crate) point: Fp,
    /// The coefficients of the polynomial.
    pub(crate) poly: &'a [Fp],
    /// The blinding factor of its commitment.
    pub(crate) blind: Fp,
}

/// A commitment (or polynomial) with the set of points it is opened at.
struct CommitmentData<T, E> {
    commitment: T,
    set_index: usize,
    point_indices: Vec<usize>,
    evals: Vec<E>,
}

/// Groups queries by commitment and commitments by point set, as
/// `construct_intermediate_sets` of the reference: returns the commitments
/// in order of first appearance, and the point sets in order of first
/// appearance (each listing its points in order of first appearance among
/// all queries). `None` if a commitment is queried twice at one point.
#[allow(clippy::type_complexity)]
fn construct_intermediate_sets<T: Copy, E: Copy + Default>(
    queries: &[(usize, Fp, T, E)],
) -> Option<(Vec<CommitmentData<T, E>>, Vec<Vec<Fp>>)> {
    // The distinct points, in order of first appearance.
    let mut points: Vec<Fp> = Vec::new();
    // The distinct commitments, in order of first appearance.
    let mut ids: Vec<usize> = Vec::new();
    let mut commitment_map: Vec<CommitmentData<T, Option<E>>> = Vec::new();

    let point_index = |points: &[Fp], p: &Fp| points.iter().position(|q| q == p);
    for (id, point, commitment, _) in queries {
        let point_idx = match point_index(&points, point) {
            Some(i) => i,
            None => {
                points.push(*point);
                points.len() - 1
            }
        };
        let pos = match ids.iter().position(|i| i == id) {
            Some(pos) => pos,
            None => {
                ids.push(*id);
                commitment_map.push(CommitmentData {
                    commitment: *commitment,
                    set_index: 0,
                    point_indices: vec![],
                    evals: vec![],
                });
                ids.len() - 1
            }
        };
        commitment_map[pos].point_indices.push(point_idx);
    }

    // The distinct point sets, in order of first appearance.
    let mut point_idx_sets: Vec<BTreeSet<usize>> = Vec::new();
    let mut commitment_sets: Vec<Vec<usize>> = Vec::with_capacity(commitment_map.len());
    for commitment_data in commitment_map.iter_mut() {
        let point_index_set: BTreeSet<usize> =
            commitment_data.point_indices.iter().copied().collect();
        commitment_data.evals = vec![None; point_index_set.len()];
        commitment_data.set_index = match point_idx_sets.iter().position(|s| s == &point_index_set)
        {
            Some(i) => i,
            None => {
                point_idx_sets.push(point_index_set.clone());
                point_idx_sets.len() - 1
            }
        };
        commitment_sets.push(point_index_set.into_iter().collect());
    }

    // The evaluation of each commitment at each point of its set.
    for (id, point, _, eval) in queries {
        let pos = ids.iter().position(|i| i == id)?;
        let point_idx = point_index(&points, point)?;
        let point_index_in_set = commitment_sets[pos].iter().position(|i| *i == point_idx)?;
        let slot = &mut commitment_map[pos].evals[point_index_in_set];
        if slot.is_some() {
            return None;
        }
        *slot = Some(*eval);
    }

    let commitment_map = commitment_map
        .into_iter()
        .map(|d| {
            Some(CommitmentData {
                commitment: d.commitment,
                set_index: d.set_index,
                point_indices: d.point_indices,
                evals: d.evals.into_iter().collect::<Option<Vec<E>>>()?,
            })
        })
        .collect::<Option<Vec<_>>>()?;

    let point_sets = point_idx_sets
        .iter()
        .map(|set| set.iter().map(|i| points[*i]).collect())
        .collect();

    Some((commitment_map, point_sets))
}

/// Creates a multipoint opening proof for the queries.
pub(crate) fn create_proof(
    params: &Params,
    rng: &mut ProverRng,
    transcript: &mut TranscriptWrite,
    queries: &[ProverQuery<'_>],
) -> Result<(), Error> {
    let x_1 = transcript.squeeze_challenge();
    let x_2 = transcript.squeeze_challenge();

    let keyed: Vec<(usize, Fp, _, ())> = queries
        .iter()
        .map(|q| (q.poly.as_ptr() as usize, q.point, (q.poly, q.blind), ()))
        .collect();
    let (poly_map, point_sets) = construct_intermediate_sets(&keyed).ok_or(Error::Synthesis)?;

    // Collapse the polynomials of each point set into one.
    let mut q_polys: Vec<Option<Vec<Fp>>> = vec![None; point_sets.len()];
    let mut q_blinds = vec![Fp::ZERO; point_sets.len()];
    for commitment_data in poly_map {
        let set_idx = commitment_data.set_index;
        let (new_poly, blind) = commitment_data.commitment;
        match &mut q_polys[set_idx] {
            Some(poly) => {
                for (p, n) in poly.iter_mut().zip(new_poly.iter()) {
                    *p = *p * x_1 + *n;
                }
            }
            None => q_polys[set_idx] = Some(new_poly.to_vec()),
        }
        q_blinds[set_idx] *= x_1;
        q_blinds[set_idx] += blind;
    }
    let q_polys: Vec<Vec<Fp>> = q_polys
        .into_iter()
        .collect::<Option<_>>()
        .ok_or(Error::Synthesis)?;

    // q'(X) combines the quotients of each q_i by the vanishing polynomial
    // of its point set (the remainders are dropped: they are checked at x_3
    // through the evaluations sent below).
    let mut q_prime_poly: Option<Vec<Fp>> = None;
    for (points, poly) in point_sets.iter().zip(q_polys.iter()) {
        let mut poly = points
            .iter()
            .fold(poly.clone(), |poly, point| kate_division(&poly, *point));
        poly.resize(params.n, Fp::ZERO);
        q_prime_poly = Some(match q_prime_poly {
            None => poly,
            Some(mut acc) => {
                for (a, p) in acc.iter_mut().zip(poly.iter()) {
                    *a = *a * x_2 + *p;
                }
                acc
            }
        });
    }
    let q_prime_poly = q_prime_poly.ok_or(Error::Synthesis)?;

    let q_prime_blind = rng.next();
    let q_prime_commitment = params.commit_par(&q_prime_poly, q_prime_blind).to_affine();
    transcript.write_point(&q_prime_commitment)?;

    let x_3 = transcript.squeeze_challenge();

    // Each q_i evaluated at x_3.
    for q_i_poly in &q_polys {
        transcript.write_scalar(&eval_polynomial(q_i_poly, x_3));
    }

    let x_4 = transcript.squeeze_challenge();

    let (p_poly, p_poly_blind) = q_polys.into_iter().zip(q_blinds).fold(
        (q_prime_poly, q_prime_blind),
        |(mut acc, acc_blind), (poly, blind)| {
            for (a, p) in acc.iter_mut().zip(poly.iter()) {
                *a = *a * x_4 + *p;
            }
            (acc, acc_blind * x_4 + blind)
        },
    );

    commitment::create_proof(params, rng, transcript, &p_poly, p_poly_blind, x_3)
}

/// Verifies a multipoint opening proof; returns the terms that must sum to
/// the identity, added to `msm`.
pub(crate) fn verify_proof(
    params: &Params,
    transcript: &mut TranscriptRead<'_>,
    queries: &[VerifierQuery<'_>],
    mut msm: Msm,
) -> Result<Msm, Error> {
    // Sample x_1 for compressing openings at the same point sets together
    let x_1 = transcript.squeeze_challenge();
    // Sample a challenge x_2 for keeping the multi-point quotient
    // polynomial terms linearly independent.
    let x_2 = transcript.squeeze_challenge();

    let keyed: Vec<(usize, Fp, CommitmentReference<'_>, Fp)> = queries
        .iter()
        .map(|q| (q.commitment.id(), q.point, q.commitment, q.eval))
        .collect();
    let (commitment_map, point_sets) =
        construct_intermediate_sets(&keyed).ok_or(Error::InvalidProof)?;

    // Compress the commitments and expected evaluations at x together,
    // using the challenge x_1.
    let mut q_commitments: Vec<(Msm, Fp)> = vec![(Msm::new(), Fp::ONE); point_sets.len()];
    // A vec of vecs of evals. The outer vec corresponds to the point set,
    // while the inner vec corresponds to the points in a particular set.
    let mut q_eval_sets: Vec<Vec<Fp>> = point_sets
        .iter()
        .map(|point_set| vec![Fp::ZERO; point_set.len()])
        .collect();

    // Each commitment corresponds to evaluations at a set of points. For
    // each set, we collapse each commitment's evals pointwise. Run in
    // order of increasing x_1 powers.
    for commitment_data in commitment_map.into_iter().rev() {
        let set_idx = commitment_data.set_index;
        let (q_commitment, x_1_power) = &mut q_commitments[set_idx];
        match commitment_data.commitment {
            CommitmentReference::Commitment(c) => {
                q_commitment.append_term(*x_1_power, *c);
            }
            CommitmentReference::Msm(m) => {
                let mut m = m.clone();
                m.scale(*x_1_power);
                q_commitment.add_msm(&m);
            }
        }
        for (eval, set_eval) in commitment_data
            .evals
            .iter()
            .zip(q_eval_sets[set_idx].iter_mut())
        {
            *set_eval += *eval * *x_1_power;
        }
        *x_1_power *= x_1;
    }

    // Obtain the commitment to the multi-point quotient polynomial f(X).
    let q_prime_commitment = transcript.read_point()?;

    // Sample a challenge x_3 for checking that f(X) was committed to
    // correctly.
    let x_3 = transcript.squeeze_challenge();

    // u is a vector containing the evaluations of the Q polynomial
    // commitments at x_3
    let u = transcript.read_n_scalars(q_eval_sets.len())?;

    // We can compute the expected msm_eval at x_3 using the u provided
    // by the prover and from x_2
    let mut msm_eval = Fp::ZERO;
    for ((points, evals), proof_eval) in point_sets.iter().zip(q_eval_sets.iter()).zip(u.iter()) {
        let r_poly = lagrange_interpolate(points, evals);
        let r_eval = eval_polynomial(&r_poly, x_3);
        let mut eval = *proof_eval - r_eval;
        for point in points {
            eval *= (x_3 - *point).invert().ok_or(Error::InvalidProof)?;
        }
        msm_eval = msm_eval * x_2 + eval;
    }

    // Sample a challenge x_4 that we will use to collapse the openings of
    // the various remaining polynomials at x_3 together.
    let x_4 = transcript.squeeze_challenge();

    // Compute the final commitment that has to be opened
    msm.append_term(Fp::ONE, q_prime_commitment);
    let mut v = msm_eval;
    for ((q_commitment, _), q_eval) in q_commitments.into_iter().zip(u.iter()) {
        msm.scale(x_4);
        msm.add_msm(&q_commitment);
        v = v * x_4 + *q_eval;
    }

    // Verify the opening proof
    commitment::verify_proof(params, msm, transcript, x_3, v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiopen_roundtrip() {
        const K: u32 = 4;
        let params = Params::new(K);
        let poly = |s: u64| -> Vec<Fp> { (0..16u64).map(|i| Fp::from_u64(s + i * s)).collect() };
        let (ax, bx, cx) = (poly(10), poly(100), poly(1000));
        let blind = Fp::from_u64(5);
        let a = params.commit(&ax, blind).to_affine();
        let b = params.commit(&bx, blind).to_affine();
        let c = params.commit(&cx, blind).to_affine();
        let x = Fp::from_u64(17);
        let y = Fp::from_u64(23);
        let (avx, bvx, cvy, bvy) = (
            eval_polynomial(&ax, x),
            eval_polynomial(&bx, x),
            eval_polynomial(&cx, y),
            eval_polynomial(&bx, y),
        );

        let mut rng = ProverRng::new(&[1u8; 64]);
        let mut t = TranscriptWrite::new();
        let q = |point, poly| ProverQuery { point, poly, blind };
        create_proof(
            &params,
            &mut rng,
            &mut t,
            &[q(x, &ax), q(x, &bx), q(y, &cx), q(y, &bx)],
        )
        .unwrap();
        let proof = t.finalize();

        let check = |proof: &[u8], avx: Fp| {
            let mut t = TranscriptRead::new(proof);
            let queries = [
                VerifierQuery::new_commitment(&a, x, avx),
                VerifierQuery::new_commitment(&b, x, bvx),
                VerifierQuery::new_commitment(&c, y, cvy),
                VerifierQuery::new_commitment(&b, y, bvy),
            ];
            verify_proof(&params, &mut t, &queries, Msm::new()).map(|msm| msm.eval(&params))
        };
        assert_eq!(check(&proof, avx), Ok(true));
        assert_eq!(check(&proof, avx + Fp::ONE), Ok(false));
        let mut bad = proof.clone();
        bad[40] ^= 1;
        assert_ne!(check(&bad, avx), Ok(true));
    }
}
