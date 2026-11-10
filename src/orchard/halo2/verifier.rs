//! Proof verification, as `halo2_proofs::plonk::verify_proof`.

use alloc::vec::Vec;

use super::Error;
use super::commitment::{Msm, Params, ProverRng};
use super::keygen::VerifyingKey;
use super::multiopen::{self, VerifierQuery};
use super::plonk::{Any, Expression, Rotation};
use super::transcript::TranscriptRead;
use crate::orchard::{Fp, vesta};

/// The commitments and evaluations of one permutation product polynomial.
struct PermutationSet {
    commitment: vesta::Affine,
    eval: Fp,
    next_eval: Fp,
    last_eval: Option<Fp>,
}

/// The commitments and evaluations of one lookup argument.
struct Lookup {
    permuted_input_commitment: vesta::Affine,
    permuted_table_commitment: vesta::Affine,
    product_commitment: vesta::Affine,
    product_eval: Fp,
    product_next_eval: Fp,
    permuted_input_eval: Fp,
    permuted_input_inv_eval: Fp,
    permuted_table_eval: Fp,
}

/// Evaluates an expression of the (selector-free) constraint system from
/// the evaluations of its queries.
fn evaluate(expr: &Expression, fixed: &[Fp], advice: &[Fp], instance: &[Fp]) -> Fp {
    expr.evaluate(
        &|scalar| scalar,
        &|_| unreachable!("virtual selectors are removed during optimization"),
        &|query| fixed[query.index],
        &|query| advice[query.index],
        &|query| instance[query.index],
        &|a| -a,
        &|a, b| a + b,
        &|a, b| a * b,
        &|a, scalar| a * scalar,
    )
}

/// Reads and checks a proof for `instances` (for each of the statements
/// proven together, the public inputs of each instance column), up to the
/// final multi-scalar multiplication: the returned sum is the identity if
/// and only if the proof is valid.
pub(crate) fn verify_proof_msm(
    params: &Params,
    vk: &VerifyingKey,
    instances: &[&[&[Fp]]],
    proof: &[u8],
) -> Result<Msm, Error> {
    let cs = &vk.cs;
    // Check that instances matches the expected number of instance columns
    for instances in instances.iter() {
        if instances.len() != cs.num_instance_columns {
            return Err(Error::InvalidInstances);
        }
    }
    let blinding_factors = cs.blinding_factors();
    let max_instance_len = params
        .n
        .checked_sub(blinding_factors + 1)
        .ok_or(Error::NotEnoughRows)?
        .min(params.g_lagrange.len());
    if instances
        .iter()
        .flat_map(|instance| instance.iter())
        .any(|instance| instance.len() > max_instance_len)
    {
        return Err(Error::InvalidInstances);
    }

    let instance_commitments: Vec<Vec<vesta::Affine>> = instances
        .iter()
        .map(|instance| {
            instance
                .iter()
                .map(|instance| params.commit_lagrange(instance, Fp::ONE).to_affine())
                .collect()
        })
        .collect();

    let num_proofs = instance_commitments.len();
    let mut transcript = TranscriptRead::new(proof);

    // Hash verification key into transcript
    transcript.transcript.common_scalar(&vk.transcript_repr);

    for instance_commitments in instance_commitments.iter() {
        // Hash the instance (external) commitments into the transcript
        for commitment in instance_commitments {
            transcript.transcript.common_point(commitment)?;
        }
    }

    let advice_commitments = (0..num_proofs)
        .map(|_| transcript.read_n_points(cs.num_advice_columns))
        .collect::<Result<Vec<_>, _>>()?;

    // Sample theta challenge for keeping lookup columns linearly independent
    let theta = transcript.squeeze_challenge();

    // Hash each lookup permuted commitment
    let lookups_permuted = (0..num_proofs)
        .map(|_| {
            cs.lookups
                .iter()
                .map(|_| Ok((transcript.read_point()?, transcript.read_point()?)))
                .collect::<Result<Vec<_>, Error>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Sample beta challenge
    let beta = transcript.squeeze_challenge();
    // Sample gamma challenge
    let gamma = transcript.squeeze_challenge();

    // Hash each permutation product commitment
    let chunk_len = vk.cs_degree - 2;
    let permutations_committed = (0..num_proofs)
        .map(|_| {
            cs.permutation
                .columns
                .chunks(chunk_len)
                .map(|_| transcript.read_point())
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Hash each lookup product commitment
    let lookups_committed = lookups_permuted
        .into_iter()
        .map(|lookups| {
            lookups
                .into_iter()
                .map(|permuted| Ok((permuted, transcript.read_point()?)))
                .collect::<Result<Vec<_>, Error>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let random_poly_commitment = transcript.read_point()?;

    // Sample y challenge, which keeps the gates linearly independent.
    let y = transcript.squeeze_challenge();

    let h_commitments = transcript.read_n_points(vk.domain.quotient_poly_degree())?;

    // Sample x challenge, which is used to ensure the circuit is
    // satisfied with high probability.
    let x = transcript.squeeze_challenge();
    let instance_evals = (0..num_proofs)
        .map(|_| transcript.read_n_scalars(cs.instance_queries.len()))
        .collect::<Result<Vec<_>, _>>()?;
    let advice_evals = (0..num_proofs)
        .map(|_| transcript.read_n_scalars(cs.advice_queries.len()))
        .collect::<Result<Vec<_>, _>>()?;
    let fixed_evals = transcript.read_n_scalars(cs.fixed_queries.len())?;

    let random_eval = transcript.read_scalar()?;

    let permutations_common = transcript.read_n_scalars(vk.permutation_commitments.len())?;

    let permutations_evaluated = permutations_committed
        .into_iter()
        .map(|commitments| {
            let mut sets = Vec::with_capacity(commitments.len());
            let mut iter = commitments.into_iter();
            while let Some(commitment) = iter.next() {
                let eval = transcript.read_scalar()?;
                let next_eval = transcript.read_scalar()?;
                let last_eval = if iter.len() > 0 {
                    Some(transcript.read_scalar()?)
                } else {
                    None
                };
                sets.push(PermutationSet {
                    commitment,
                    eval,
                    next_eval,
                    last_eval,
                });
            }
            Ok(sets)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let lookups_evaluated = lookups_committed
        .into_iter()
        .map(|lookups| {
            lookups
                .into_iter()
                .map(|((input, table), product)| {
                    Ok(Lookup {
                        permuted_input_commitment: input,
                        permuted_table_commitment: table,
                        product_commitment: product,
                        product_eval: transcript.read_scalar()?,
                        product_next_eval: transcript.read_scalar()?,
                        permuted_input_eval: transcript.read_scalar()?,
                        permuted_input_inv_eval: transcript.read_scalar()?,
                        permuted_table_eval: transcript.read_scalar()?,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // This check ensures the circuit is satisfied so long as the polynomial
    // commitments open to the correct values.
    let xn = x.pow_vartime(&[params.n as u64, 0, 0, 0]);
    let l_evals = vk
        .domain
        .l_i_range(x, xn, -((blinding_factors + 1) as i32)..=0);
    let l_last = l_evals[0];
    let l_blind = l_evals[1..(1 + blinding_factors)]
        .iter()
        .fold(Fp::ZERO, |acc, eval| acc + *eval);
    let l_0 = l_evals[1 + blinding_factors];
    let active_rows = Fp::ONE - (l_last + l_blind);

    // Compute the expected value of h(x): the expressions of every
    // statement, combined with powers of y.
    let mut h_eval = Fp::ZERO;
    let mut push = |v: Fp| h_eval = h_eval * y + v;
    for (((advice_evals, instance_evals), permutation), lookups) in advice_evals
        .iter()
        .zip(instance_evals.iter())
        .zip(permutations_evaluated.iter())
        .zip(lookups_evaluated.iter())
    {
        let column_eval = |column: &super::plonk::Column<Any>| {
            let index = cs.get_any_query_index(*column);
            match column.column_type {
                Any::Advice => advice_evals[index],
                Any::Fixed => fixed_evals[index],
                Any::Instance => instance_evals[index],
            }
        };

        // The custom gates.
        for poly in cs.gates.iter().flat_map(|gate| gate.polys.iter()) {
            push(evaluate(poly, &fixed_evals, advice_evals, instance_evals));
        }

        // The permutation argument.
        // Enforce only for the first set: l_0(X) * (1 - z_0(X)) = 0
        if let Some(first_set) = permutation.first() {
            push(l_0 * (Fp::ONE - first_set.eval));
        }
        // Enforce only for the last set: l_last(X) * (z_l(X)^2 - z_l(X)) = 0
        if let Some(last_set) = permutation.last() {
            push((last_set.eval.square() - last_set.eval) * l_last);
        }
        // Except for the first set, enforce
        // l_0(X) * (z_i(X) - z_{i-1}(\omega^(last) X)) = 0
        for (set, prev) in permutation.iter().skip(1).zip(permutation.iter()) {
            let prev_last = prev.last_eval.ok_or(Error::InvalidProof)?;
            push((set.eval - prev_last) * l_0);
        }
        // And for all the sets we enforce:
        // (1 - (l_last(X) + l_blind(X))) * (
        //   z_i(\omega X) \prod (p(X) + \beta s_i(X) + \gamma)
        // - z_i(X) \prod (p(X) + \delta^i \beta X + \gamma)
        // )
        for (chunk_index, ((set, columns), permutation_evals)) in permutation
            .iter()
            .zip(cs.permutation.columns.chunks(chunk_len))
            .zip(permutations_common.chunks(chunk_len))
            .enumerate()
        {
            let mut left = set.next_eval;
            for (column, permutation_eval) in columns.iter().zip(permutation_evals.iter()) {
                left *= column_eval(column) + beta * *permutation_eval + gamma;
            }
            let mut right = set.eval;
            let mut current_delta =
                (beta * x) * Fp::DELTA.pow_vartime(&[(chunk_index * chunk_len) as u64, 0, 0, 0]);
            for column in columns.iter() {
                right *= column_eval(column) + current_delta + gamma;
                current_delta *= Fp::DELTA;
            }
            push((left - right) * active_rows);
        }

        // The lookup arguments.
        for (p, argument) in lookups.iter().zip(cs.lookups.iter()) {
            let compress = |expressions: &[Expression]| {
                expressions
                    .iter()
                    .map(|e| evaluate(e, &fixed_evals, advice_evals, instance_evals))
                    .fold(Fp::ZERO, |acc, eval| acc * theta + eval)
            };
            // l_0(X) * (1 - z(X)) = 0
            push(l_0 * (Fp::ONE - p.product_eval));
            // l_last(X) * (z(X)^2 - z(X)) = 0
            push(l_last * (p.product_eval.square() - p.product_eval));
            // (1 - (l_last(X) + l_blind(X))) * (
            //   z(\omega X) (a'(X) + \beta) (s'(X) + \gamma)
            //   - z(X) (\theta^{m-1} a_0(X) + ... + a_{m-1}(X) + \beta)
            //          (\theta^{m-1} s_0(X) + ... + s_{m-1}(X) + \gamma)
            // ) = 0
            let left = p.product_next_eval
                * (p.permuted_input_eval + beta)
                * (p.permuted_table_eval + gamma);
            let right = p.product_eval
                * (compress(&argument.input_expressions) + beta)
                * (compress(&argument.table_expressions) + gamma);
            push((left - right) * active_rows);
            // l_0(X) * (a'(X) - s'(X)) = 0
            push(l_0 * (p.permuted_input_eval - p.permuted_table_eval));
            // (1 - (l_last(X) + l_blind(X))) * (a′(X) − s′(X))⋅(a′(X) − a′(\omega^{-1} X)) = 0
            push(
                (p.permuted_input_eval - p.permuted_table_eval)
                    * (p.permuted_input_eval - p.permuted_input_inv_eval)
                    * active_rows,
            );
        }
    }
    let expected_h_eval = h_eval * (xn - Fp::ONE).invert().ok_or(Error::InvalidProof)?;

    // The commitment to h(X) from its pieces.
    let h_commitment = h_commitments
        .iter()
        .rev()
        .fold(Msm::new(), |mut acc, commitment| {
            acc.scale(xn);
            acc.append_term(Fp::ONE, *commitment);
            acc
        });

    let x_inv = vk.domain.rotate_omega(x, Rotation::prev());
    let x_next = vk.domain.rotate_omega(x, Rotation::next());
    let x_last = vk
        .domain
        .rotate_omega(x, Rotation(-((blinding_factors + 1) as i32)));

    let mut queries: Vec<VerifierQuery<'_>> = Vec::new();
    for (
        ((((instance_commitments, instance_evals), advice_commitments), advice_evals), sets),
        lookups,
    ) in instance_commitments
        .iter()
        .zip(instance_evals.iter())
        .zip(advice_commitments.iter())
        .zip(advice_evals.iter())
        .zip(permutations_evaluated.iter())
        .zip(lookups_evaluated.iter())
    {
        for (query_index, (column, at)) in cs.instance_queries.iter().enumerate() {
            queries.push(VerifierQuery::new_commitment(
                &instance_commitments[column.index],
                vk.domain.rotate_omega(x, *at),
                instance_evals[query_index],
            ));
        }
        for (query_index, (column, at)) in cs.advice_queries.iter().enumerate() {
            queries.push(VerifierQuery::new_commitment(
                &advice_commitments[column.index],
                vk.domain.rotate_omega(x, *at),
                advice_evals[query_index],
            ));
        }
        for set in sets.iter() {
            // Open permutation product commitments at x and \omega x
            queries.push(VerifierQuery::new_commitment(&set.commitment, x, set.eval));
            queries.push(VerifierQuery::new_commitment(
                &set.commitment,
                x_next,
                set.next_eval,
            ));
        }
        // Open it at \omega^{last} x for all but the last set
        for set in sets.iter().rev().skip(1) {
            queries.push(VerifierQuery::new_commitment(
                &set.commitment,
                x_last,
                set.last_eval.ok_or(Error::InvalidProof)?,
            ));
        }
        for p in lookups.iter() {
            // Open lookup product commitment at x
            queries.push(VerifierQuery::new_commitment(
                &p.product_commitment,
                x,
                p.product_eval,
            ));
            // Open lookup input commitments at x
            queries.push(VerifierQuery::new_commitment(
                &p.permuted_input_commitment,
                x,
                p.permuted_input_eval,
            ));
            // Open lookup table commitments at x
            queries.push(VerifierQuery::new_commitment(
                &p.permuted_table_commitment,
                x,
                p.permuted_table_eval,
            ));
            // Open lookup input commitments at \omega^{-1} x
            queries.push(VerifierQuery::new_commitment(
                &p.permuted_input_commitment,
                x_inv,
                p.permuted_input_inv_eval,
            ));
            // Open lookup product commitment at \omega x
            queries.push(VerifierQuery::new_commitment(
                &p.product_commitment,
                x_next,
                p.product_next_eval,
            ));
        }
    }
    for (query_index, (column, at)) in cs.fixed_queries.iter().enumerate() {
        queries.push(VerifierQuery::new_commitment(
            &vk.fixed_commitments[column.index],
            vk.domain.rotate_omega(x, *at),
            fixed_evals[query_index],
        ));
    }
    // Open permutation commitments for each permutation argument at x
    for (commitment, eval) in vk
        .permutation_commitments
        .iter()
        .zip(permutations_common.iter())
    {
        queries.push(VerifierQuery::new_commitment(commitment, x, *eval));
    }
    queries.push(VerifierQuery::new_msm(&h_commitment, x, expected_h_eval));
    queries.push(VerifierQuery::new_commitment(
        &random_poly_commitment,
        x,
        random_eval,
    ));

    // We are now convinced the circuit is satisfied so long as the
    // polynomial commitments open to the correct values.
    // (As in the reference, bytes after the end of the proof are ignored.)
    multiopen::verify_proof(params, &mut transcript, &queries, Msm::new())
}

/// Verifies a proof for `instances`: for each of the statements proven
/// together, the public inputs of each instance column. Never panics on
/// malformed proofs.
pub fn verify_proof(
    params: &Params,
    vk: &VerifyingKey,
    instances: &[&[&[Fp]]],
    proof: &[u8],
) -> Result<(), Error> {
    if verify_proof_msm(params, vk, instances, proof)?.eval(params) {
        Ok(())
    } else {
        Err(Error::InvalidProof)
    }
}

/// Verifies several proofs of one circuit together, with a single final
/// multi-scalar multiplication: a random linear combination of the checks
/// of each proof.
pub struct BatchVerifier {
    msm: Msm,
    rng: ProverRng,
    failed: bool,
}

impl BatchVerifier {
    /// A new batch. `random` must be 64 uniformly random bytes the provers
    /// could not predict.
    pub fn new(random: &[u8; 64]) -> Self {
        BatchVerifier {
            msm: Msm::new(),
            rng: ProverRng::new(random),
            failed: false,
        }
    }

    /// Adds a proof to the batch.
    pub fn add_proof(
        &mut self,
        params: &Params,
        vk: &VerifyingKey,
        instances: &[&[&[Fp]]],
        proof: &[u8],
    ) {
        match verify_proof_msm(params, vk, instances, proof) {
            Ok(msm) => {
                self.msm.scale(self.rng.next());
                self.msm.add_msm(&msm);
            }
            Err(_) => self.failed = true,
        }
    }

    /// Whether every proof of the batch is valid.
    pub fn finalize(self, params: &Params) -> bool {
        !self.failed && self.msm.eval(params)
    }
}
