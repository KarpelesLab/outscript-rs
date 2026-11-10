//! Proof creation, as `halo2_proofs::plonk::create_proof`: the transcript
//! is the one the verifier replays, the polynomials are computed here in a
//! simpler way than the reference (expressions are compiled to small stack
//! programs and evaluated row by row on the extended domain).

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use purecrypto::zeroize::Zeroize;

use super::circuit::{Assignment, Circuit, synthesize};
use super::commitment::{Params, ProverRng};
use super::keygen::ProvingKey;
use super::multiopen::{self, ProverQuery};
use super::plonk::{Advice, Any, Column, ConstraintSystem, Expression, Fixed, Instance, Selector};
use super::poly::{EvaluationDomain, eval_polynomial};
use super::transcript::TranscriptWrite;
use super::{Error, Value};
use crate::orchard::{Fp, vesta};

/// Columns of witness-derived values, wiped when dropped.
struct Secret(Vec<Vec<Fp>>);

impl Drop for Secret {
    fn drop(&mut self) {
        for column in self.0.iter_mut() {
            for v in column.iter_mut() {
                v.zeroize();
            }
        }
    }
}

/// The backend of proving: records the advice cells.
struct WitnessCollection<'a> {
    advice: Secret,
    instances: &'a [&'a [Fp]],
    usable_rows: usize,
}

impl Assignment for WitnessCollection<'_> {
    fn enable_selector(&mut self, _: &Selector, _: usize) -> Result<(), Error> {
        // We only care about advice columns here
        Ok(())
    }

    fn query_instance(&self, column: Column<Instance>, row: usize) -> Result<Value<Fp>, Error> {
        if row >= self.usable_rows {
            return Err(Error::NotEnoughRows);
        }
        // Rows past the given public inputs hold zero.
        let column = self
            .instances
            .get(column.index)
            .ok_or(Error::BoundsFailure)?;
        Ok(Value::known(column.get(row).copied().unwrap_or(Fp::ZERO)))
    }

    fn assign_advice(
        &mut self,
        column: Column<Advice>,
        row: usize,
        to: &mut dyn FnMut() -> Value<Fp>,
    ) -> Result<(), Error> {
        if row >= self.usable_rows {
            return Err(Error::NotEnoughRows);
        }
        *self
            .advice
            .0
            .get_mut(column.index)
            .and_then(|v| v.get_mut(row))
            .ok_or(Error::BoundsFailure)? = to().into_option().ok_or(Error::Synthesis)?;
        Ok(())
    }

    fn assign_fixed(
        &mut self,
        _: Column<Fixed>,
        _: usize,
        _: &mut dyn FnMut() -> Value<Fp>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn copy(&mut self, _: Column<Any>, _: usize, _: Column<Any>, _: usize) -> Result<(), Error> {
        Ok(())
    }

    fn fill_from_row(&mut self, _: Column<Fixed>, _: usize, _: Value<Fp>) -> Result<(), Error> {
        Ok(())
    }
}

/// One instruction of a compiled expression.
#[derive(Clone, Copy)]
enum Op {
    Constant(Fp),
    Fixed(usize, i32),
    Advice(usize, i32),
    Instance(usize, i32),
    Negate,
    Add,
    Mul,
    Scale(Fp),
}

/// Appends the postfix program of `expr` to `out`.
fn compile(expr: &Expression, out: &mut Vec<Op>) {
    match expr {
        Expression::Constant(c) => out.push(Op::Constant(*c)),
        Expression::Selector(_) => unreachable!("virtual selectors are removed"),
        Expression::Fixed(q) => out.push(Op::Fixed(q.column_index, q.rotation.0)),
        Expression::Advice(q) => out.push(Op::Advice(q.column_index, q.rotation.0)),
        Expression::Instance(q) => out.push(Op::Instance(q.column_index, q.rotation.0)),
        Expression::Negated(a) => {
            compile(a, out);
            out.push(Op::Negate);
        }
        Expression::Sum(a, b) => {
            compile(a, out);
            compile(b, out);
            out.push(Op::Add);
        }
        Expression::Product(a, b) => {
            compile(a, out);
            compile(b, out);
            out.push(Op::Mul);
        }
        Expression::Scaled(a, f) => {
            compile(a, out);
            out.push(Op::Scale(*f));
        }
    }
}

/// The columns an expression is evaluated over, as values on a domain of
/// `len` points where one row of the circuit is `step` points.
struct Columns<'a> {
    fixed: &'a [Vec<Fp>],
    advice: &'a [Vec<Fp>],
    instance: &'a [Vec<Fp>],
    len: usize,
    step: usize,
}

impl Columns<'_> {
    /// The index of the point `rotation` rows away from point `i`.
    #[inline]
    fn rotated(&self, i: usize, rotation: i32) -> usize {
        let shift = (rotation as i64 * self.step as i64).rem_euclid(self.len as i64) as usize;
        (i + shift) % self.len
    }

    /// Runs a program at point `i`.
    fn run(&self, program: &[Op], i: usize, stack: &mut Vec<Fp>) -> Fp {
        stack.clear();
        for op in program {
            match *op {
                Op::Constant(c) => stack.push(c),
                Op::Fixed(c, r) => stack.push(self.fixed[c][self.rotated(i, r)]),
                Op::Advice(c, r) => stack.push(self.advice[c][self.rotated(i, r)]),
                Op::Instance(c, r) => stack.push(self.instance[c][self.rotated(i, r)]),
                Op::Negate => {
                    let a = stack.pop().expect("well-formed program");
                    stack.push(-a);
                }
                Op::Add => {
                    let b = stack.pop().expect("well-formed program");
                    let a = stack.pop().expect("well-formed program");
                    stack.push(a + b);
                }
                Op::Mul => {
                    let b = stack.pop().expect("well-formed program");
                    let a = stack.pop().expect("well-formed program");
                    stack.push(a * b);
                }
                Op::Scale(f) => {
                    let a = stack.pop().expect("well-formed program");
                    stack.push(a * f);
                }
            }
        }
        stack.pop().expect("well-formed program")
    }
}

/// The compiled input and table expressions of a lookup argument.
struct LookupPrograms {
    input: Vec<Vec<Op>>,
    table: Vec<Vec<Op>>,
}

impl LookupPrograms {
    /// The expressions compressed with powers of theta, at point `i`.
    fn compressed(
        programs: &[Vec<Op>],
        columns: &Columns<'_>,
        theta: Fp,
        i: usize,
        stack: &mut Vec<Fp>,
    ) -> Fp {
        programs.iter().fold(Fp::ZERO, |acc, program| {
            acc * theta + columns.run(program, i, stack)
        })
    }
}

/// A committed polynomial: coefficients, blinding factor, and the values
/// on the extended domain.
struct Committed {
    poly: Vec<Fp>,
    blind: Fp,
    coset: Vec<Fp>,
}

impl Drop for Committed {
    fn drop(&mut self) {
        self.poly.zeroize();
        self.coset.zeroize();
        self.blind.zeroize();
    }
}

/// The state of one lookup argument of one statement.
struct LookupState {
    compressed_input: Vec<Fp>,
    compressed_table: Vec<Fp>,
    permuted_input_values: Vec<Fp>,
    permuted_table_values: Vec<Fp>,
    permuted_input: Committed,
    permuted_table: Committed,
    product: Option<Committed>,
}

impl Drop for LookupState {
    fn drop(&mut self) {
        self.compressed_input.zeroize();
        self.compressed_table.zeroize();
        self.permuted_input_values.zeroize();
        self.permuted_table_values.zeroize();
    }
}

/// Everything the prover holds for one statement.
struct Statement {
    instance_values: Vec<Vec<Fp>>,
    instance_polys: Vec<Vec<Fp>>,
    instance_cosets: Vec<Vec<Fp>>,
    advice_values: Secret,
    advice_polys: Secret,
    advice_cosets: Secret,
    advice_blinds: Vec<Fp>,
    lookups: Vec<LookupState>,
    permutation_sets: Vec<Committed>,
}

/// Field elements in a total order (any will do: it only groups equal
/// values).
fn sort_key(v: &Fp) -> [u64; 4] {
    let l = v.to_raw();
    [l[3], l[2], l[1], l[0]]
}

/// Given the values of the compressed input and table expressions, a
/// permutation of the inputs (sorted, so equal values are adjacent) and a
/// permutation of the table such that each input either repeats the one
/// above or equals the table value on its row. The rows after the usable
/// ones are random.
fn permute_expression_pair(
    usable_rows: usize,
    n: usize,
    rng: &mut ProverRng,
    input_expression: &[Fp],
    table_expression: &[Fp],
) -> Result<(Vec<Fp>, Vec<Fp>), Error> {
    let mut permuted_input: Vec<Fp> = input_expression[..usable_rows].to_vec();
    permuted_input.sort_by_key(sort_key);

    // A multiset of the table values.
    let mut leftover_table_map: BTreeMap<[u64; 4], (Fp, u32)> = BTreeMap::new();
    for coeff in table_expression[..usable_rows].iter() {
        leftover_table_map
            .entry(sort_key(coeff))
            .or_insert((*coeff, 0))
            .1 += 1;
    }
    let mut permuted_table = vec![Fp::ZERO; usable_rows];
    let mut repeated_input_rows = Vec::new();
    for row in 0..usable_rows {
        let input_value = permuted_input[row];
        // If this is the first occurrence of `input_value` in the input
        // expression
        if row == 0 || input_value != permuted_input[row - 1] {
            permuted_table[row] = input_value;
            // Remove one instance of input_value from leftover_table_map
            match leftover_table_map.get_mut(&sort_key(&input_value)) {
                Some((_, count)) if *count > 0 => *count -= 1,
                // The input is not in the table.
                _ => return Err(Error::Synthesis),
            }
        } else {
            repeated_input_rows.push(row);
        }
    }
    // Populate permuted table at unfilled rows with leftover table elements
    for (coeff, count) in leftover_table_map.values() {
        for _ in 0..*count {
            let row = repeated_input_rows.pop().ok_or(Error::Synthesis)?;
            permuted_table[row] = *coeff;
        }
    }
    if !repeated_input_rows.is_empty() {
        return Err(Error::Synthesis);
    }
    permuted_input.extend((usable_rows..n).map(|_| rng.next()));
    permuted_table.extend((usable_rows..n).map(|_| rng.next()));
    Ok((permuted_input, permuted_table))
}

/// Inverts every element (zero stays zero).
fn batch_invert(values: &mut [Fp]) {
    let mut scratch = vec![Fp::ZERO; values.len()];
    Fp::batch_invert(values, &mut scratch);
}

/// Commits to the values of a polynomial on the domain with a fresh
/// blinding factor, writes the commitment to the transcript, and keeps the
/// polynomial in the forms needed later.
fn commit_values(
    params: &Params,
    domain: &EvaluationDomain,
    rng: &mut ProverRng,
    transcript: &mut TranscriptWrite,
    values: &[Fp],
) -> Result<Committed, Error> {
    let blind = rng.next();
    let commitment = params.commit_lagrange(values, blind).to_affine();
    transcript.write_point(&commitment)?;
    let poly = domain.lagrange_to_coeff(values.to_vec());
    let coset = domain.coeff_to_extended(poly.clone());
    Ok(Committed { poly, blind, coset })
}

/// Creates a proof that each of `circuits` is satisfied with the
/// corresponding public inputs of `instances` (for each circuit, the values
/// of each instance column). `random` must be 64 fresh uniformly random
/// bytes: every blinding factor is derived from them, so reusing them for
/// two different witnesses leaks the witnesses.
///
/// The proof is not checked: with a witness that does not satisfy the
/// circuit this returns either an error or a proof that will not verify.
pub fn create_proof<C: Circuit>(
    params: &Params,
    pk: &ProvingKey,
    circuits: &[C],
    instances: &[&[&[Fp]]],
    random: &[u8; 64],
) -> Result<Vec<u8>, Error> {
    let vk = &pk.vk;
    let meta = &vk.cs;
    let domain = &vk.domain;
    let n = params.n;
    if params.g_lagrange.len() != n || domain.n != n {
        return Err(Error::NotEnoughRows);
    }
    if circuits.len() != instances.len() {
        return Err(Error::InvalidInstances);
    }
    for instance in instances.iter() {
        if instance.len() != meta.num_instance_columns {
            return Err(Error::InvalidInstances);
        }
    }

    let mut rng = ProverRng::new(random);
    let mut transcript = TranscriptWrite::new();

    // Hash verification key into transcript
    transcript.transcript.common_scalar(&vk.transcript_repr);

    let blinding_factors = meta.blinding_factors();
    let usable_rows = n - (blinding_factors + 1);
    let ext_n = domain.extended_len();
    let ext_step = ext_n / n;

    let to_extended = |polys: &[Vec<Fp>]| -> Vec<Vec<Fp>> {
        polys
            .iter()
            .map(|p| domain.coeff_to_extended(p.clone()))
            .collect()
    };
    let to_coeff = |values: &[Vec<Fp>]| -> Vec<Vec<Fp>> {
        values
            .iter()
            .map(|v| domain.lagrange_to_coeff(v.clone()))
            .collect()
    };

    // The instance columns: committed (with the default blinding factor,
    // as the verifier does) and hashed into the transcript.
    let mut instance_parts = Vec::with_capacity(instances.len());
    for instance in instances.iter() {
        let mut instance_values = Vec::with_capacity(instance.len());
        for values in instance.iter() {
            if values.len() > usable_rows {
                return Err(Error::InvalidInstances);
            }
            let mut poly = vec![Fp::ZERO; n];
            poly[..values.len()].copy_from_slice(values);
            let commitment = params.commit_lagrange(values, Fp::ONE).to_affine();
            transcript.transcript.common_point(&commitment)?;
            instance_values.push(poly);
        }
        let instance_polys = to_coeff(&instance_values);
        let instance_cosets = to_extended(&instance_polys);
        instance_parts.push((instance_values, instance_polys, instance_cosets));
    }

    // The advice columns: synthesized, blinded, committed.
    let mut statements = Vec::with_capacity(circuits.len());
    for ((circuit, instances), (instance_values, instance_polys, instance_cosets)) in
        circuits.iter().zip(instances.iter()).zip(instance_parts)
    {
        let mut cs = ConstraintSystem::default();
        let config = circuit.configure(&mut cs);
        let mut witness = WitnessCollection {
            advice: Secret(vec![vec![Fp::ZERO; n]; meta.num_advice_columns]),
            instances,
            usable_rows,
        };
        // Synthesize the circuit to obtain the witness and other
        // information.
        synthesize(&mut witness, circuit, config, meta.constants.clone())?;
        let mut advice_values = witness.advice;

        // Add blinding factors to advice columns
        for advice in advice_values.0.iter_mut() {
            for cell in advice[usable_rows..].iter_mut() {
                *cell = rng.next();
            }
        }
        // Compute commitments to advice column polynomials
        let advice_blinds: Vec<Fp> = advice_values.0.iter().map(|_| rng.next()).collect();
        let commitments: Vec<vesta::Point> = advice_values
            .0
            .iter()
            .zip(advice_blinds.iter())
            .map(|(poly, blind)| params.commit_lagrange(poly, *blind))
            .collect();
        let mut affine = vec![vesta::Affine::IDENTITY; commitments.len()];
        vesta::Point::batch_normalize(&commitments, &mut affine);
        for commitment in &affine {
            transcript.write_point(commitment)?;
        }
        let advice_polys = Secret(to_coeff(&advice_values.0));
        let advice_cosets = Secret(to_extended(&advice_polys.0));
        statements.push(Statement {
            instance_values,
            instance_polys,
            instance_cosets,
            advice_values,
            advice_polys,
            advice_cosets,
            advice_blinds,
            lookups: Vec::new(),
            permutation_sets: Vec::new(),
        });
    }

    // Compile the expressions once.
    let gate_programs: Vec<Vec<Op>> = meta
        .gates
        .iter()
        .flat_map(|gate| gate.polys.iter())
        .map(|poly| {
            let mut program = Vec::new();
            compile(poly, &mut program);
            program
        })
        .collect();
    let compile_all = |expressions: &[Expression]| -> Vec<Vec<Op>> {
        expressions
            .iter()
            .map(|e| {
                let mut program = Vec::new();
                compile(e, &mut program);
                program
            })
            .collect()
    };
    let lookup_programs: Vec<LookupPrograms> = meta
        .lookups
        .iter()
        .map(|lookup| LookupPrograms {
            input: compile_all(&lookup.input_expressions),
            table: compile_all(&lookup.table_expressions),
        })
        .collect();
    let mut stack: Vec<Fp> = Vec::with_capacity(64);

    // Sample theta challenge for keeping lookup columns linearly independent
    let theta = transcript.squeeze_challenge();

    // The permuted input and table columns of each lookup.
    for statement in statements.iter_mut() {
        let columns = Columns {
            fixed: &pk.fixed_values,
            advice: &statement.advice_values.0,
            instance: &statement.instance_values,
            len: n,
            step: 1,
        };
        let mut lookups = Vec::with_capacity(lookup_programs.len());
        for programs in lookup_programs.iter() {
            let compressed_input: Vec<Fp> = (0..n)
                .map(|i| {
                    LookupPrograms::compressed(&programs.input, &columns, theta, i, &mut stack)
                })
                .collect();
            let compressed_table: Vec<Fp> = (0..n)
                .map(|i| {
                    LookupPrograms::compressed(&programs.table, &columns, theta, i, &mut stack)
                })
                .collect();
            let (permuted_input_values, permuted_table_values) = permute_expression_pair(
                usable_rows,
                n,
                &mut rng,
                &compressed_input,
                &compressed_table,
            )?;
            let permuted_input = commit_values(
                params,
                domain,
                &mut rng,
                &mut transcript,
                &permuted_input_values,
            )?;
            let permuted_table = commit_values(
                params,
                domain,
                &mut rng,
                &mut transcript,
                &permuted_table_values,
            )?;
            lookups.push(LookupState {
                compressed_input,
                compressed_table,
                permuted_input_values,
                permuted_table_values,
                permuted_input,
                permuted_table,
                product: None,
            });
        }
        statement.lookups = lookups;
    }

    // Sample beta challenge
    let beta = transcript.squeeze_challenge();
    // Sample gamma challenge
    let gamma = transcript.squeeze_challenge();

    // The permutation product polynomials.
    let chunk_len = vk.cs_degree - 2;
    for statement in statements.iter_mut() {
        // Each column contributes a factor delta to the coset labels.
        let mut deltaomega = Fp::ONE;
        // Track the "last" value from the previous columns set
        let mut last_z = Fp::ONE;
        let mut sets = Vec::new();
        for (columns, permutations) in meta
            .permutation
            .columns
            .chunks(chunk_len)
            .zip(pk.permutations.chunks(chunk_len))
        {
            let values_of = |column: &Column<Any>| -> &Vec<Fp> {
                match column.column_type {
                    Any::Advice => &statement.advice_values.0[column.index],
                    Any::Fixed => &pk.fixed_values[column.index],
                    Any::Instance => &statement.instance_values[column.index],
                }
            };
            // The denominators: prod (p_j(omega^i) + beta s_j(omega^i) + gamma)
            let mut modified_values = vec![Fp::ONE; n];
            for (column, permuted_column_values) in columns.iter().zip(permutations.iter()) {
                let values = values_of(column);
                for ((m, value), permuted_value) in modified_values
                    .iter_mut()
                    .zip(values.iter())
                    .zip(permuted_column_values.iter())
                {
                    *m *= beta * *permuted_value + gamma + *value;
                }
            }
            batch_invert(&mut modified_values);
            // The numerators: prod (p_j(omega^i) + delta^j omega^i beta + gamma)
            for column in columns.iter() {
                let values = values_of(column);
                let mut cur = deltaomega;
                for (m, value) in modified_values.iter_mut().zip(values.iter()) {
                    *m *= cur * beta + gamma + *value;
                    cur *= domain.omega;
                }
                deltaomega *= Fp::DELTA;
            }
            // The running product.
            let mut z = Vec::with_capacity(n);
            z.push(last_z);
            for row in 1..n {
                z.push(z[row - 1] * modified_values[row - 1]);
            }
            for z in z[n - blinding_factors..].iter_mut() {
                *z = rng.next();
            }
            // Set new "last" value
            last_z = z[n - (blinding_factors + 1)];
            sets.push(commit_values(
                params,
                domain,
                &mut rng,
                &mut transcript,
                &z,
            )?);
        }
        statement.permutation_sets = sets;
    }

    // The lookup product polynomials.
    for statement in statements.iter_mut() {
        for lookup in statement.lookups.iter_mut() {
            // Denominator uses the permuted input and table expressions
            let mut lookup_product: Vec<Fp> = lookup
                .permuted_input_values
                .iter()
                .zip(lookup.permuted_table_values.iter())
                .map(|(input, table)| (beta + *input) * (gamma + *table))
                .collect();
            batch_invert(&mut lookup_product);
            // Finish the computation of the entire fraction by computing
            // the numerators
            for ((product, input_term), table_term) in lookup_product
                .iter_mut()
                .zip(lookup.compressed_input.iter())
                .zip(lookup.compressed_table.iter())
            {
                *product *= *input_term + beta;
                *product *= *table_term + gamma;
            }
            let mut z = Vec::with_capacity(n);
            let mut state = Fp::ONE;
            z.push(state);
            for cur in lookup_product.iter().take(n - blinding_factors - 1) {
                state *= *cur;
                z.push(state);
            }
            z.extend((0..blinding_factors).map(|_| rng.next()));
            debug_assert_eq!(z.len(), n);
            lookup.product = Some(commit_values(
                params,
                domain,
                &mut rng,
                &mut transcript,
                &z,
            )?);
        }
    }

    // A random polynomial that blinds h(X).
    let random_poly: Vec<Fp> = (0..n).map(|_| rng.next()).collect();
    let random_blind = rng.next();
    transcript.write_point(&params.commit(&random_poly, random_blind).to_affine())?;

    // Obtain challenge for keeping all separate gates linearly independent
    let y = transcript.squeeze_challenge();

    // The numerator of h(X) on the extended domain: every expression of
    // every statement, combined with powers of y.
    let mut h_values = vec![Fp::ZERO; ext_n];
    let last_rotation = -((blinding_factors + 1) as i32);
    // The identity polynomial on the extended coset.
    let extended_omega = (Fp::ZETA, domain.extended_omega);
    for statement in statements.iter() {
        let columns = Columns {
            fixed: &pk.fixed_cosets,
            advice: &statement.advice_cosets.0,
            instance: &statement.instance_cosets,
            len: ext_n,
            step: ext_step,
        };
        let coset_of = |column: &Column<Any>| -> &Vec<Fp> {
            match column.column_type {
                Any::Advice => &statement.advice_cosets.0[column.index],
                Any::Fixed => &pk.fixed_cosets[column.index],
                Any::Instance => &statement.instance_cosets[column.index],
            }
        };
        let sets = &statement.permutation_sets;
        let mut x_coset = extended_omega.0;
        for (i, h) in h_values.iter_mut().enumerate() {
            let mut acc = *h;
            let l0 = pk.l0[i];
            let l_last = pk.l_last[i];
            let active_rows = Fp::ONE - (l_last + pk.l_blind[i]);
            let next = columns.rotated(i, 1);

            // The custom gates.
            for program in gate_programs.iter() {
                acc = acc * y + columns.run(program, i, &mut stack);
            }

            // The permutation argument (see the verifier for the
            // identities).
            if let Some(first_set) = sets.first() {
                acc = acc * y + l0 * (Fp::ONE - first_set.coset[i]);
            }
            if let Some(last_set) = sets.last() {
                let z = last_set.coset[i];
                acc = acc * y + (z.square() - z) * l_last;
            }
            let last = columns.rotated(i, last_rotation);
            for (set, prev) in sets.iter().skip(1).zip(sets.iter()) {
                acc = acc * y + (set.coset[i] - prev.coset[last]) * l0;
            }
            let mut current_delta = beta * x_coset;
            for ((set, cols), permutation_cosets) in sets
                .iter()
                .zip(meta.permutation.columns.chunks(chunk_len))
                .zip(pk.permutation_cosets.chunks(chunk_len))
            {
                let mut left = set.coset[next];
                for (column, permutation_coset) in cols.iter().zip(permutation_cosets.iter()) {
                    left *= coset_of(column)[i] + beta * permutation_coset[i] + gamma;
                }
                let mut right = set.coset[i];
                for column in cols.iter() {
                    right *= coset_of(column)[i] + current_delta + gamma;
                    current_delta *= Fp::DELTA;
                }
                acc = acc * y + (left - right) * active_rows;
            }

            // The lookup arguments.
            let prev = columns.rotated(i, -1);
            for (lookup, programs) in statement.lookups.iter().zip(lookup_programs.iter()) {
                let product = lookup.product.as_ref().expect("committed above");
                let z = product.coset[i];
                let a = lookup.permuted_input.coset[i];
                let s = lookup.permuted_table.coset[i];
                acc = acc * y + (Fp::ONE - z) * l0;
                acc = acc * y + (z.square() - z) * l_last;
                let left = product.coset[next] * (a + beta) * (s + gamma);
                let right = z
                    * (LookupPrograms::compressed(&programs.input, &columns, theta, i, &mut stack)
                        + beta)
                    * (LookupPrograms::compressed(&programs.table, &columns, theta, i, &mut stack)
                        + gamma);
                acc = acc * y + (left - right) * active_rows;
                acc = acc * y + (a - s) * l0;
                acc = acc * y + (a - s) * (a - lookup.permuted_input.coset[prev]) * active_rows;
            }

            *h = acc;
            x_coset *= extended_omega.1;
        }
    }
    stack.zeroize();

    // Divide by the vanishing polynomial and split h(X) into pieces of n
    // coefficients.
    domain.divide_by_vanishing_poly(&mut h_values);
    let h_poly = domain.extended_to_coeff(h_values);
    let h_pieces: Vec<&[Fp]> = h_poly.chunks_exact(n).collect();
    let h_blinds: Vec<Fp> = h_pieces.iter().map(|_| rng.next()).collect();
    for (h_piece, blind) in h_pieces.iter().zip(h_blinds.iter()) {
        transcript.write_point(&params.commit(h_piece, *blind).to_affine())?;
    }

    let x = transcript.squeeze_challenge();
    let xn = x.pow_vartime(&[n as u64, 0, 0, 0]);

    // Compute and hash instance evals for each circuit instance
    for statement in statements.iter() {
        for (column, at) in meta.instance_queries.iter() {
            let eval = eval_polynomial(
                &statement.instance_polys[column.index],
                domain.rotate_omega(x, *at),
            );
            transcript.write_scalar(&eval);
        }
    }
    // Compute and hash advice evals for each circuit instance
    for statement in statements.iter() {
        for (column, at) in meta.advice_queries.iter() {
            let eval = eval_polynomial(
                &statement.advice_polys.0[column.index],
                domain.rotate_omega(x, *at),
            );
            transcript.write_scalar(&eval);
        }
    }
    // Compute and hash fixed evals
    for (column, at) in meta.fixed_queries.iter() {
        let eval = eval_polynomial(&pk.fixed_polys[column.index], domain.rotate_omega(x, *at));
        transcript.write_scalar(&eval);
    }

    // h(X) recombined from its pieces at x, and the random polynomial.
    let mut h_combined = vec![Fp::ZERO; n];
    let mut h_blind = Fp::ZERO;
    for (h_piece, blind) in h_pieces.iter().zip(h_blinds.iter()).rev() {
        for (acc, c) in h_combined.iter_mut().zip(h_piece.iter()) {
            *acc = *acc * xn + *c;
        }
        h_blind = h_blind * xn + *blind;
    }
    transcript.write_scalar(&eval_polynomial(&random_poly, x));

    // Evaluate common permutation data
    for poly in pk.permutation_polys.iter() {
        transcript.write_scalar(&eval_polynomial(poly, x));
    }

    let x_inv = domain.rotate_omega(x, super::plonk::Rotation::prev());
    let x_next = domain.rotate_omega(x, super::plonk::Rotation::next());
    let x_last = domain.rotate_omega(x, super::plonk::Rotation(last_rotation));

    // Evaluate the permutations, if any, at omega^i x.
    for statement in statements.iter() {
        let mut sets = statement.permutation_sets.iter();
        while let Some(set) = sets.next() {
            transcript.write_scalar(&eval_polynomial(&set.poly, x));
            transcript.write_scalar(&eval_polynomial(&set.poly, x_next));
            // If we have any remaining sets to process, evaluate this set
            // at omega^u so we can constrain the last value of its running
            // product to equal the first value of the next set's.
            if sets.len() > 0 {
                transcript.write_scalar(&eval_polynomial(&set.poly, x_last));
            }
        }
    }

    // Evaluate the lookups, if any, at omega^i x.
    for statement in statements.iter() {
        for lookup in statement.lookups.iter() {
            let product = lookup.product.as_ref().expect("committed above");
            transcript.write_scalar(&eval_polynomial(&product.poly, x));
            transcript.write_scalar(&eval_polynomial(&product.poly, x_next));
            transcript.write_scalar(&eval_polynomial(&lookup.permuted_input.poly, x));
            transcript.write_scalar(&eval_polynomial(&lookup.permuted_input.poly, x_inv));
            transcript.write_scalar(&eval_polynomial(&lookup.permuted_table.poly, x));
        }
    }

    // The openings, in the order the verifier checks them.
    let mut queries: Vec<ProverQuery<'_>> = Vec::new();
    fn query(point: Fp, poly: &[Fp], blind: Fp) -> ProverQuery<'_> {
        ProverQuery { point, poly, blind }
    }
    for statement in statements.iter() {
        for (column, at) in meta.instance_queries.iter() {
            queries.push(query(
                domain.rotate_omega(x, *at),
                &statement.instance_polys[column.index],
                Fp::ONE,
            ));
        }
        for (column, at) in meta.advice_queries.iter() {
            queries.push(query(
                domain.rotate_omega(x, *at),
                &statement.advice_polys.0[column.index],
                statement.advice_blinds[column.index],
            ));
        }
        for set in statement.permutation_sets.iter() {
            queries.push(query(x, &set.poly, set.blind));
            queries.push(query(x_next, &set.poly, set.blind));
        }
        for set in statement.permutation_sets.iter().rev().skip(1) {
            queries.push(query(x_last, &set.poly, set.blind));
        }
        for lookup in statement.lookups.iter() {
            let product = lookup.product.as_ref().expect("committed above");
            let (input, table) = (&lookup.permuted_input, &lookup.permuted_table);
            queries.push(query(x, &product.poly, product.blind));
            queries.push(query(x, &input.poly, input.blind));
            queries.push(query(x, &table.poly, table.blind));
            queries.push(query(x_inv, &input.poly, input.blind));
            queries.push(query(x_next, &product.poly, product.blind));
        }
    }
    for (column, at) in meta.fixed_queries.iter() {
        queries.push(query(
            domain.rotate_omega(x, *at),
            &pk.fixed_polys[column.index],
            Fp::ONE,
        ));
    }
    for poly in pk.permutation_polys.iter() {
        queries.push(query(x, poly, Fp::ONE));
    }
    queries.push(query(x, &h_combined, h_blind));
    queries.push(query(x, &random_poly, random_blind));

    multiopen::create_proof(params, &mut rng, &mut transcript, &queries)?;
    Ok(transcript.finalize())
}
