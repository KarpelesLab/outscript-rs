//! Proof creation, as `halo2_proofs::plonk::create_proof`: the transcript
//! is the one the verifier replays, the polynomials are computed here in a
//! simpler way than the reference (the expressions are compiled together
//! into one straight-line program, run point by point on the extended
//! domain).
//!
//! What does not depend on an order (commitments, transforms, the values
//! of the quotient polynomial) is split over threads when there are some;
//! the blinding factors are drawn and the transcript is written on the
//! calling thread, in the order of the reference, so the proof is the same
//! whatever the number of threads.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use purecrypto::zeroize::Zeroize;

use super::circuit::{Assignment, Circuit, synthesize};
use super::commitment::{Params, ProverRng};
use super::keygen::ProvingKey;
use super::multiopen::{self, ProverQuery};
use super::par;
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

/// One step of a [`Graph`]: a value computed from the columns or from the
/// values of earlier steps.
#[derive(Clone, Copy)]
enum Node {
    Constant(Fp),
    /// The value of a fixed column, this many points further.
    Fixed(usize, usize),
    /// The value of an advice column, this many points further.
    Advice(usize, usize),
    /// The value of an instance column, this many points further.
    Instance(usize, usize),
    Negate(usize),
    Add(usize, usize),
    Mul(usize, usize),
    Square(usize),
    Scale(usize, Fp),
}

/// What identifies a node: two nodes with the same key have the same
/// value.
type NodeKey = (u8, [u64; 4], usize, usize);

impl Node {
    fn key(&self) -> NodeKey {
        match *self {
            Node::Constant(c) => (0, c.to_raw(), 0, 0),
            Node::Fixed(c, s) => (1, [0; 4], c, s),
            Node::Advice(c, s) => (2, [0; 4], c, s),
            Node::Instance(c, s) => (3, [0; 4], c, s),
            Node::Negate(a) => (4, [0; 4], a, 0),
            Node::Add(a, b) => (5, [0; 4], a, b),
            Node::Mul(a, b) => (6, [0; 4], a, b),
            Node::Square(a) => (7, [0; 4], a, 0),
            Node::Scale(a, f) => (8, f.to_raw(), a, 0),
        }
    }
}

/// Expressions compiled together into one straight-line program over a
/// domain: every distinct subexpression is computed once per point, however
/// many of the expressions it appears in.
struct Graph {
    nodes: Vec<Node>,
    index: BTreeMap<NodeKey, usize>,
    /// The number of points of the domain (a power of two).
    len: usize,
    /// The number of points one row of the circuit spans.
    step: usize,
}

impl Graph {
    /// An empty program over a domain of `len` points where one row of the
    /// circuit is `step` points.
    fn new(len: usize, step: usize) -> Self {
        debug_assert!(len.is_power_of_two());
        Graph {
            nodes: Vec::new(),
            index: BTreeMap::new(),
            len,
            step,
        }
    }

    fn node(&mut self, node: Node) -> usize {
        let nodes = &mut self.nodes;
        *self.index.entry(node.key()).or_insert_with(|| {
            nodes.push(node);
            nodes.len() - 1
        })
    }

    /// The number of points `rotation` rows further.
    fn shift(&self, rotation: i32) -> usize {
        (rotation as i64 * self.step as i64).rem_euclid(self.len as i64) as usize
    }

    /// Adds an expression; returns the step holding its value.
    fn add(&mut self, expr: &Expression) -> usize {
        match expr {
            Expression::Constant(c) => self.node(Node::Constant(*c)),
            Expression::Selector(_) => unreachable!("virtual selectors are removed"),
            Expression::Fixed(q) => {
                let shift = self.shift(q.rotation.0);
                self.node(Node::Fixed(q.column_index, shift))
            }
            Expression::Advice(q) => {
                let shift = self.shift(q.rotation.0);
                self.node(Node::Advice(q.column_index, shift))
            }
            Expression::Instance(q) => {
                let shift = self.shift(q.rotation.0);
                self.node(Node::Instance(q.column_index, shift))
            }
            Expression::Negated(a) => {
                let a = self.add(a);
                self.node(Node::Negate(a))
            }
            Expression::Sum(a, b) => {
                let (a, b) = (self.add(a), self.add(b));
                // (the field is commutative: order the operands so that
                // both orders share a step)
                self.node(Node::Add(a.min(b), a.max(b)))
            }
            Expression::Product(a, b) => {
                let (a, b) = (self.add(a), self.add(b));
                if a == b {
                    self.node(Node::Square(a))
                } else {
                    self.node(Node::Mul(a.min(b), a.max(b)))
                }
            }
            Expression::Scaled(a, f) => {
                let a = self.add(a);
                self.node(Node::Scale(a, *f))
            }
        }
    }

    /// Adds expressions; returns the steps holding their values.
    fn add_all(&mut self, exprs: &[Expression]) -> Vec<usize> {
        exprs.iter().map(|e| self.add(e)).collect()
    }

    /// A buffer for the values of the steps.
    fn scratch(&self) -> Vec<Fp> {
        vec![Fp::ZERO; self.nodes.len()]
    }

    /// Runs the program at point `i` of the domain: `values[s]` becomes the
    /// value of step `s`.
    fn run(&self, columns: &Columns<'_>, i: usize, values: &mut [Fp]) {
        let mask = self.len - 1;
        for (step, node) in self.nodes.iter().enumerate() {
            let value = match *node {
                Node::Constant(c) => c,
                Node::Fixed(c, s) => columns.fixed[c][(i + s) & mask],
                Node::Advice(c, s) => columns.advice[c][(i + s) & mask],
                Node::Instance(c, s) => columns.instance[c][(i + s) & mask],
                Node::Negate(a) => -values[a],
                Node::Add(a, b) => values[a] + values[b],
                Node::Mul(a, b) => values[a] * values[b],
                Node::Square(a) => values[a].square(),
                Node::Scale(a, f) => values[a] * f,
            };
            values[step] = value;
        }
    }
}

/// The columns an expression is evaluated over, as values on a domain.
struct Columns<'a> {
    fixed: &'a [Vec<Fp>],
    advice: &'a [Vec<Fp>],
    instance: &'a [Vec<Fp>],
}

/// The steps of a [`Graph`] holding the input and table expressions of a
/// lookup argument.
struct LookupSteps {
    input: Vec<usize>,
    table: Vec<usize>,
}

/// Expressions compressed with powers of theta, from the values of their
/// steps.
#[inline]
fn compressed(steps: &[usize], values: &[Fp], theta: Fp) -> Fp {
    steps
        .iter()
        .fold(Fp::ZERO, |acc, step| acc * theta + values[*step])
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

/// Given the values of the compressed input and table expressions on the
/// usable rows, a permutation of the inputs (sorted, so equal values are
/// adjacent) and a permutation of the table such that each input either
/// repeats the one above or equals the table value on its row.
fn permute_expression_pair(
    usable_rows: usize,
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
    Ok((permuted_input, permuted_table))
}

/// Inverts every element (zero stays zero).
fn batch_invert(values: &mut [Fp]) {
    let mut scratch = vec![Fp::ZERO; values.len()];
    Fp::batch_invert(values, &mut scratch);
    scratch.zeroize();
}

/// Commits to polynomials given by their values on the domain, each with
/// its blinding factor, and puts them in the forms needed later. The
/// commitments are computed side by side; the caller writes them to the
/// transcript, in order.
fn commit_values(
    params: &Params,
    domain: &EvaluationDomain,
    polys: &[(&[Fp], Fp)],
) -> Vec<(vesta::Affine, Committed)> {
    par::map(polys, |_, (values, blind)| {
        let commitment = params.commit_lagrange(values, *blind).to_affine();
        let poly = domain.lagrange_to_coeff(values.to_vec());
        let coset = domain.coeff_to_extended(poly.clone());
        (
            commitment,
            Committed {
                poly,
                blind: *blind,
                coset,
            },
        )
    })
}

/// Checks the shape of what a proof is asked for; returns the number of
/// usable rows.
fn check_shape(
    params: &Params,
    pk: &ProvingKey,
    circuits: usize,
    instances: &[&[&[Fp]]],
) -> Result<usize, Error> {
    let meta = &pk.vk.cs;
    let n = params.n;
    if params.g_lagrange.len() != n || pk.vk.domain.n != n {
        return Err(Error::NotEnoughRows);
    }
    if circuits != instances.len() {
        return Err(Error::InvalidInstances);
    }
    let usable_rows = n - (meta.blinding_factors() + 1);
    for instance in instances.iter() {
        if instance.len() != meta.num_instance_columns
            || instance.iter().any(|values| values.len() > usable_rows)
        {
            return Err(Error::InvalidInstances);
        }
    }
    Ok(usable_rows)
}

/// Synthesizes a circuit to obtain its witness: the advice columns.
fn synthesize_advice<C: Circuit>(
    pk: &ProvingKey,
    circuit: &C,
    instances: &[&[Fp]],
    usable_rows: usize,
) -> Result<Secret, Error> {
    let meta = &pk.vk.cs;
    let mut cs = ConstraintSystem::default();
    let config = circuit.configure(&mut cs);
    let mut witness = WitnessCollection {
        advice: Secret(vec![
            vec![Fp::ZERO; pk.vk.domain.n];
            meta.num_advice_columns
        ]),
        instances,
        usable_rows,
    };
    synthesize(&mut witness, circuit, config, meta.constants.clone())?;
    Ok(witness.advice)
}

/// Creates a proof that each of `circuits` is satisfied with the
/// corresponding public inputs of `instances` (for each circuit, the values
/// of each instance column). `random` must be 64 fresh uniformly random
/// bytes: every blinding factor is derived from them, so reusing them for
/// two different witnesses leaks the witnesses.
///
/// The proof is not checked: with a witness that does not satisfy the
/// circuit this returns either an error or a proof that will not verify.
///
/// With the `std` feature the work is split over several threads (see
/// `set_max_threads`); the proof does not depend on their number.
pub fn create_proof<C: Circuit>(
    params: &Params,
    pk: &ProvingKey,
    circuits: &[C],
    instances: &[&[&[Fp]]],
    random: &[u8; 64],
) -> Result<Vec<u8>, Error> {
    let usable_rows = check_shape(params, pk, circuits.len(), instances)?;
    let advice = circuits
        .iter()
        .zip(instances.iter())
        .map(|(circuit, instances)| synthesize_advice(pk, circuit, instances, usable_rows))
        .collect::<Result<Vec<Secret>, Error>>()?;
    prove(params, pk, advice, instances, random)
}

/// [`create_proof`] for circuits that can be shared between threads: they
/// are synthesized side by side too. The proof is the same.
pub(crate) fn create_proof_sync<C: Circuit + Sync>(
    params: &Params,
    pk: &ProvingKey,
    circuits: &[C],
    instances: &[&[&[Fp]]],
    random: &[u8; 64],
) -> Result<Vec<u8>, Error> {
    let usable_rows = check_shape(params, pk, circuits.len(), instances)?;
    let advice = par::map(circuits, |i, circuit| {
        synthesize_advice(pk, circuit, instances[i], usable_rows)
    })
    .into_iter()
    .collect::<Result<Vec<Secret>, Error>>()?;
    prove(params, pk, advice, instances, random)
}

/// Creates the proof from the witnesses of the circuits.
fn prove(
    params: &Params,
    pk: &ProvingKey,
    advice: Vec<Secret>,
    instances: &[&[&[Fp]]],
    random: &[u8; 64],
) -> Result<Vec<u8>, Error> {
    let vk = &pk.vk;
    let meta = &vk.cs;
    let domain = &vk.domain;
    let n = params.n;

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

    // The advice columns: synthesized and blinded, one statement after the
    // other.
    let mut statements = Vec::with_capacity(advice.len());
    for (mut advice_values, (instance_values, instance_polys, instance_cosets)) in
        advice.into_iter().zip(instance_parts)
    {
        // Add blinding factors to advice columns
        for advice in advice_values.0.iter_mut() {
            for cell in advice[usable_rows..].iter_mut() {
                *cell = rng.next();
            }
        }
        // The blinding factors of the commitments to the advice columns.
        let advice_blinds: Vec<Fp> = advice_values.0.iter().map(|_| rng.next()).collect();
        statements.push(Statement {
            instance_values,
            instance_polys,
            instance_cosets,
            advice_values,
            advice_polys: Secret(Vec::new()),
            advice_cosets: Secret(Vec::new()),
            advice_blinds,
            lookups: Vec::new(),
            permutation_sets: Vec::new(),
        });
    }
    // Compute commitments to advice column polynomials
    {
        let columns: Vec<(&[Fp], Fp)> = statements
            .iter()
            .flat_map(|statement| {
                statement
                    .advice_values
                    .0
                    .iter()
                    .map(|values| &values[..])
                    .zip(statement.advice_blinds.iter().copied())
            })
            .collect();
        let mut committed = commit_values(params, domain, &columns).into_iter();
        drop(columns);
        for statement in statements.iter_mut() {
            for _ in 0..meta.num_advice_columns {
                let (commitment, mut column) = committed.next().expect("one for each column");
                transcript.write_point(&commitment)?;
                statement
                    .advice_polys
                    .0
                    .push(core::mem::take(&mut column.poly));
                statement
                    .advice_cosets
                    .0
                    .push(core::mem::take(&mut column.coset));
            }
        }
    }

    // Compile the expressions once: the lookups alone on the domain, and
    // everything on the extended domain.
    let lookup_graphs: Vec<(Graph, LookupSteps)> = meta
        .lookups
        .iter()
        .map(|lookup| {
            let mut graph = Graph::new(n, 1);
            let steps = LookupSteps {
                input: graph.add_all(&lookup.input_expressions),
                table: graph.add_all(&lookup.table_expressions),
            };
            (graph, steps)
        })
        .collect();
    let mut graph = Graph::new(ext_n, ext_step);
    let gate_steps: Vec<usize> = meta
        .gates
        .iter()
        .flat_map(|gate| gate.polys.iter())
        .map(|poly| graph.add(poly))
        .collect();
    let lookup_steps: Vec<LookupSteps> = meta
        .lookups
        .iter()
        .map(|lookup| LookupSteps {
            input: graph.add_all(&lookup.input_expressions),
            table: graph.add_all(&lookup.table_expressions),
        })
        .collect();

    // Sample theta challenge for keeping lookup columns linearly independent
    let theta = transcript.squeeze_challenge();

    // The permuted input and table columns of each lookup.
    {
        // What does not depend on an order, for every lookup of every
        // statement: the compressed expressions and their permutations on
        // the usable rows.
        let work: Vec<(&Statement, &(Graph, LookupSteps))> = statements
            .iter()
            .flat_map(|statement| lookup_graphs.iter().map(move |lookup| (statement, lookup)))
            .collect();
        type Permuted = (Vec<Fp>, Vec<Fp>, Vec<Fp>, Vec<Fp>);
        let permuted = par::map(&work, |_, (statement, (graph, steps))| {
            let columns = Columns {
                fixed: &pk.fixed_values,
                advice: &statement.advice_values.0,
                instance: &statement.instance_values,
            };
            let mut values = graph.scratch();
            let mut compressed_input = Vec::with_capacity(n);
            let mut compressed_table = Vec::with_capacity(n);
            for i in 0..n {
                graph.run(&columns, i, &mut values);
                compressed_input.push(compressed(&steps.input, &values, theta));
                compressed_table.push(compressed(&steps.table, &values, theta));
            }
            values.zeroize();
            let result: Result<Permuted, Error> =
                permute_expression_pair(usable_rows, &compressed_input, &compressed_table).map(
                    |(permuted_input, permuted_table)| {
                        (
                            compressed_input,
                            compressed_table,
                            permuted_input,
                            permuted_table,
                        )
                    },
                );
            result
        });
        drop(work);
        // The rows after the usable ones are random; then the blinding
        // factors of the two commitments.
        let mut parts = Vec::with_capacity(permuted.len());
        for result in permuted {
            let (compressed_input, compressed_table, mut permuted_input, mut permuted_table) =
                result?;
            permuted_input.extend((usable_rows..n).map(|_| rng.next()));
            permuted_table.extend((usable_rows..n).map(|_| rng.next()));
            let blinds = [rng.next(), rng.next()];
            parts.push((
                compressed_input,
                compressed_table,
                permuted_input,
                permuted_table,
                blinds,
            ));
        }
        let polys: Vec<(&[Fp], Fp)> = parts
            .iter()
            .flat_map(|(_, _, input, table, blinds)| {
                [(&input[..], blinds[0]), (&table[..], blinds[1])]
            })
            .collect();
        let mut committed = commit_values(params, domain, &polys).into_iter();
        drop(polys);
        let mut parts = parts.into_iter();
        for statement in statements.iter_mut() {
            for _ in 0..lookup_graphs.len() {
                let (compressed_input, compressed_table, input, table, _) =
                    parts.next().expect("one for each lookup");
                let (commitment, permuted_input) = committed.next().expect("two for each lookup");
                transcript.write_point(&commitment)?;
                let (commitment, permuted_table) = committed.next().expect("two for each lookup");
                transcript.write_point(&commitment)?;
                statement.lookups.push(LookupState {
                    compressed_input,
                    compressed_table,
                    permuted_input_values: input,
                    permuted_table_values: table,
                    permuted_input,
                    permuted_table,
                    product: None,
                });
            }
        }
    }

    // Sample beta challenge
    let beta = transcript.squeeze_challenge();
    // Sample gamma challenge
    let gamma = transcript.squeeze_challenge();

    // The permutation product polynomials.
    let chunk_len = vk.cs_degree - 2;
    {
        let column_sets: Vec<_> = meta
            .permutation
            .columns
            .chunks(chunk_len)
            .zip(pk.permutations.chunks(chunk_len))
            .collect();
        // Each column contributes a factor delta to the coset labels.
        let mut deltaomegas = Vec::with_capacity(column_sets.len());
        let mut deltaomega = Fp::ONE;
        for (columns, _) in column_sets.iter() {
            deltaomegas.push(deltaomega);
            for _ in columns.iter() {
                deltaomega *= Fp::DELTA;
            }
        }
        // The factors of the running products, for every set of columns of
        // every statement.
        let work: Vec<(&Statement, usize)> = statements
            .iter()
            .flat_map(|statement| (0..column_sets.len()).map(move |set| (statement, set)))
            .collect();
        let factors = par::map(&work, |_, (statement, set)| {
            let (columns, permutations) = column_sets[*set];
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
            let mut deltaomega = deltaomegas[*set];
            for column in columns.iter() {
                let values = values_of(column);
                let mut cur = deltaomega;
                for (m, value) in modified_values.iter_mut().zip(values.iter()) {
                    *m *= cur * beta + gamma + *value;
                    cur *= domain.omega;
                }
                deltaomega *= Fp::DELTA;
            }
            Secret(vec![modified_values])
        });
        drop(work);
        // The running products, each starting where the previous set of
        // columns of its statement ended, with random last rows.
        let mut products = Secret(Vec::with_capacity(factors.len()));
        let mut blinds = Vec::with_capacity(factors.len());
        for (index, modified_values) in factors.iter().enumerate() {
            let modified_values = &modified_values.0[0];
            // Track the "last" value from the previous columns set
            let last_z = if index % column_sets.len() == 0 {
                Fp::ONE
            } else {
                products.0[index - 1][n - (blinding_factors + 1)]
            };
            let mut z = Vec::with_capacity(n);
            z.push(last_z);
            for row in 1..n {
                z.push(z[row - 1] * modified_values[row - 1]);
            }
            for z in z[n - blinding_factors..].iter_mut() {
                *z = rng.next();
            }
            products.0.push(z);
            blinds.push(rng.next());
        }
        drop(factors);
        let polys: Vec<(&[Fp], Fp)> = products
            .0
            .iter()
            .map(|z| &z[..])
            .zip(blinds.iter().copied())
            .collect();
        let mut committed = commit_values(params, domain, &polys).into_iter();
        for statement in statements.iter_mut() {
            for _ in 0..column_sets.len() {
                let (commitment, set) = committed.next().expect("one for each set");
                transcript.write_point(&commitment)?;
                statement.permutation_sets.push(set);
            }
        }
    }

    // The lookup product polynomials.
    {
        let work: Vec<&LookupState> = statements
            .iter()
            .flat_map(|statement| statement.lookups.iter())
            .collect();
        let factors = par::map(&work, |_, lookup| {
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
            Secret(vec![lookup_product])
        });
        drop(work);
        let mut products = Secret(Vec::with_capacity(factors.len()));
        let mut blinds = Vec::with_capacity(factors.len());
        for lookup_product in factors.iter() {
            let mut z = Vec::with_capacity(n);
            let mut state = Fp::ONE;
            z.push(state);
            for cur in lookup_product.0[0].iter().take(n - blinding_factors - 1) {
                state *= *cur;
                z.push(state);
            }
            z.extend((0..blinding_factors).map(|_| rng.next()));
            debug_assert_eq!(z.len(), n);
            products.0.push(z);
            blinds.push(rng.next());
        }
        drop(factors);
        let polys: Vec<(&[Fp], Fp)> = products
            .0
            .iter()
            .map(|z| &z[..])
            .zip(blinds.iter().copied())
            .collect();
        let mut committed = commit_values(params, domain, &polys).into_iter();
        for statement in statements.iter_mut() {
            for lookup in statement.lookups.iter_mut() {
                let (commitment, product) = committed.next().expect("one for each lookup");
                transcript.write_point(&commitment)?;
                lookup.product = Some(product);
            }
        }
    }

    // A random polynomial that blinds h(X).
    let random_poly: Vec<Fp> = (0..n).map(|_| rng.next()).collect();
    let random_blind = rng.next();
    transcript.write_point(&params.commit_par(&random_poly, random_blind).to_affine())?;

    // Obtain challenge for keeping all separate gates linearly independent
    let y = transcript.squeeze_challenge();

    // The numerator of h(X) on the extended domain: every expression of
    // every statement, combined with powers of y.
    let mut h_values = vec![Fp::ZERO; ext_n];
    let last_rotation = -((blinding_factors + 1) as i32);
    let mask = ext_n - 1;
    let next_shift = graph.shift(1);
    let prev_shift = graph.shift(-1);
    let last_shift = graph.shift(last_rotation);
    par::chunks_mut(&mut h_values, 64, 1, |start, chunk| {
        let mut values = graph.scratch();
        // The identity polynomial on the extended coset.
        let mut x_coset = Fp::ZETA * domain.extended_omega.pow_vartime(&[start as u64, 0, 0, 0]);
        for (offset, h) in chunk.iter_mut().enumerate() {
            let i = start + offset;
            let mut acc = *h;
            let l0 = pk.l0[i];
            let l_last = pk.l_last[i];
            let active_rows = Fp::ONE - (l_last + pk.l_blind[i]);
            let next = (i + next_shift) & mask;
            let prev = (i + prev_shift) & mask;
            let last = (i + last_shift) & mask;
            for statement in statements.iter() {
                let columns = Columns {
                    fixed: &pk.fixed_cosets,
                    advice: &statement.advice_cosets.0,
                    instance: &statement.instance_cosets,
                };
                let coset_of = |column: &Column<Any>| -> &Vec<Fp> {
                    match column.column_type {
                        Any::Advice => &statement.advice_cosets.0[column.index],
                        Any::Fixed => &pk.fixed_cosets[column.index],
                        Any::Instance => &statement.instance_cosets[column.index],
                    }
                };
                let sets = &statement.permutation_sets;
                graph.run(&columns, i, &mut values);

                // The custom gates.
                for step in gate_steps.iter() {
                    acc = acc * y + values[*step];
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
                for (lookup, steps) in statement.lookups.iter().zip(lookup_steps.iter()) {
                    let product = lookup.product.as_ref().expect("committed above");
                    let z = product.coset[i];
                    let a = lookup.permuted_input.coset[i];
                    let s = lookup.permuted_table.coset[i];
                    acc = acc * y + (Fp::ONE - z) * l0;
                    acc = acc * y + (z.square() - z) * l_last;
                    let left = product.coset[next] * (a + beta) * (s + gamma);
                    let right = z
                        * (compressed(&steps.input, &values, theta) + beta)
                        * (compressed(&steps.table, &values, theta) + gamma);
                    acc = acc * y + (left - right) * active_rows;
                    acc = acc * y + (a - s) * l0;
                    acc = acc * y + (a - s) * (a - lookup.permuted_input.coset[prev]) * active_rows;
                }
            }
            *h = acc;
            x_coset *= domain.extended_omega;
        }
        values.zeroize();
    });

    // Divide by the vanishing polynomial and split h(X) into pieces of n
    // coefficients.
    domain.divide_by_vanishing_poly(&mut h_values);
    let h_poly = domain.extended_to_coeff(h_values);
    let h_pieces: Vec<&[Fp]> = h_poly.chunks_exact(n).collect();
    let h_blinds: Vec<Fp> = h_pieces.iter().map(|_| rng.next()).collect();
    let h_commitments = par::map(&h_pieces, |i, h_piece| {
        params.commit(h_piece, h_blinds[i]).to_affine()
    });
    for commitment in h_commitments.iter() {
        transcript.write_point(commitment)?;
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
