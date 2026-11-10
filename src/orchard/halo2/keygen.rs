//! Key generation: the verifying key (commitments to the fixed columns and
//! to the permutation, and a hash of the whole circuit description) and the
//! proving key, as `halo2_proofs::plonk::{keygen_vk, keygen_pk}`.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Write};

use purecrypto::hash::Blake2bMac;

use super::circuit::{Assignment, Circuit, synthesize};
use super::commitment::Params;
use super::plonk::{
    Advice, Any, Column, ConstraintSystem, Fixed, Hex, Instance, PermutationArgument,
    PinnedConstraintSystem, Selector, SelectorPlan,
};
use super::poly::EvaluationDomain;
use super::{Error, Value};
use crate::orchard::{Fp, vesta};

/// A verifying key: everything the verifier knows about a circuit.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    pub(crate) domain: EvaluationDomain,
    pub(crate) fixed_commitments: Vec<vesta::Affine>,
    pub(crate) permutation_commitments: Vec<vesta::Affine>,
    pub(crate) cs: ConstraintSystem,
    pub(crate) cs_degree: usize,
    /// The hash of the key, which every transcript starts with.
    pub(crate) transcript_repr: Fp,
}

/// A proving key: the verifying key and the fixed polynomials in the forms
/// the prover needs.
#[derive(Clone, Debug)]
pub struct ProvingKey {
    pub(crate) vk: VerifyingKey,
    pub(crate) l0: Vec<Fp>,
    pub(crate) l_blind: Vec<Fp>,
    pub(crate) l_last: Vec<Fp>,
    pub(crate) fixed_values: Vec<Vec<Fp>>,
    pub(crate) fixed_polys: Vec<Vec<Fp>>,
    pub(crate) fixed_cosets: Vec<Vec<Fp>>,
    pub(crate) permutations: Vec<Vec<Fp>>,
    pub(crate) permutation_polys: Vec<Vec<Fp>>,
    pub(crate) permutation_cosets: Vec<Vec<Fp>>,
}

impl ProvingKey {
    /// The verifying key.
    pub fn vk(&self) -> &VerifyingKey {
        &self.vk
    }
}

/// A point printed as `pasta_curves` prints an affine point.
struct PointDebug<'a>(&'a vesta::Affine);

impl fmt::Debug for PointDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if bool::from(self.0.is_identity()) {
            write!(f, "Infinity")
        } else {
            let (x, y) = (self.0.x().to_raw(), self.0.y().to_raw());
            write!(f, "({:?}, {:?})", RawHex(&x), RawHex(&y))
        }
    }
}

/// Four little-endian limbs printed as `0x` and 64 hex digits.
struct RawHex<'a>(&'a [u64; 4]);

impl fmt::Debug for RawHex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let l = self.0;
        write!(f, "0x{:016x}{:016x}{:016x}{:016x}", l[3], l[2], l[1], l[0])
    }
}

struct Points<'a>(&'a [vesta::Affine]);

impl fmt::Debug for Points<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(PointDebug))
            .finish()
    }
}

struct PinnedDomain<'a>(&'a EvaluationDomain);

impl fmt::Debug for PinnedDomain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedEvaluationDomain")
            .field("k", &self.0.k)
            .field("extended_k", &self.0.extended_k)
            .field("omega", &Hex(&self.0.omega))
            .finish()
    }
}

struct PinnedPermutationKey<'a>(&'a [vesta::Affine]);

impl fmt::Debug for PinnedPermutationKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("commitments", &Points(self.0))
            .finish()
    }
}

/// The description of a verifying key that is hashed into transcripts;
/// its `Debug` output is byte for byte that of the reference's
/// `PinnedVerificationKey` (`{:?}` and `{:#?}` alike).
pub struct PinnedVerificationKey<'a>(&'a VerifyingKey);

impl fmt::Debug for PinnedVerificationKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let vk = self.0;
        f.debug_struct("PinnedVerificationKey")
            .field(
                "base_modulus",
                &"0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001",
            )
            .field(
                "scalar_modulus",
                &"0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001",
            )
            .field("domain", &PinnedDomain(&vk.domain))
            .field("cs", &PinnedConstraintSystem(&vk.cs))
            .field("fixed_commitments", &Points(&vk.fixed_commitments))
            .field(
                "permutation",
                &PinnedPermutationKey(&vk.permutation_commitments),
            )
            .finish()
    }
}

/// A sink counting the bytes written to it.
struct Counter(u64);

impl Write for Counter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0 += s.len() as u64;
        Ok(())
    }
}

/// A sink hashing the bytes written to it.
struct HashWriter(Blake2bMac);

impl Write for HashWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.update(s.as_bytes());
        Ok(())
    }
}

impl VerifyingKey {
    /// Assembles a verifying key and computes its transcript
    /// representation: BLAKE2b-512, personalized `Halo2-Verify-Key`, of the
    /// length-prefixed `Debug` text of the pinned key, reduced to a scalar.
    pub(crate) fn from_parts(
        domain: EvaluationDomain,
        fixed_commitments: Vec<vesta::Affine>,
        permutation_commitments: Vec<vesta::Affine>,
        cs: ConstraintSystem,
    ) -> Self {
        let cs_degree = cs.degree();
        let mut vk = VerifyingKey {
            domain,
            fixed_commitments,
            permutation_commitments,
            cs,
            cs_degree,
            transcript_repr: Fp::ZERO,
        };
        let mut counter = Counter(0);
        write!(counter, "{:?}", vk.pinned()).expect("counting cannot fail");
        let mut hasher = HashWriter(
            Blake2bMac::try_new_with_salt_personal(&[], 64, &[], b"Halo2-Verify-Key")
                .expect("valid BLAKE2b parameters"),
        );
        hasher.0.update(&counter.0.to_le_bytes());
        write!(hasher, "{:?}", vk.pinned()).expect("hashing cannot fail");
        let mut out = [0u8; 64];
        hasher.0.finalize_into(&mut out);
        vk.transcript_repr = Fp::from_uniform_bytes(&out);
        vk
    }

    /// The description of the key that is hashed into transcripts.
    pub fn pinned(&self) -> PinnedVerificationKey<'_> {
        PinnedVerificationKey(self)
    }

    /// The hash of the key every transcript starts with.
    pub fn transcript_repr(&self) -> Fp {
        self.transcript_repr
    }

    /// The commitments to the fixed columns.
    pub fn fixed_commitments(&self) -> &[vesta::Affine] {
        &self.fixed_commitments
    }

    /// The commitments to the permutation polynomials.
    pub fn permutation_commitments(&self) -> &[vesta::Affine] {
        &self.permutation_commitments
    }
}

/// The copy constraints of a circuit, as cycles over the cells of the
/// permutation columns.
#[derive(Debug)]
pub(crate) struct PermutationAssembly {
    columns: Vec<Column<Any>>,
    pub(crate) mapping: Vec<Vec<(usize, usize)>>,
    aux: Vec<Vec<(usize, usize)>>,
    sizes: Vec<Vec<usize>>,
}

impl PermutationAssembly {
    pub(crate) fn new(n: usize, p: &PermutationArgument) -> Self {
        // Initialize the copy vector to keep track of copy constraints in
        // all the permutation arguments.
        let columns: Vec<Vec<(usize, usize)>> = (0..p.columns.len())
            .map(|i| (0..n).map(|j| (i, j)).collect())
            .collect();
        PermutationAssembly {
            columns: p.columns.clone(),
            mapping: columns.clone(),
            aux: columns,
            sizes: vec![vec![1usize; n]; p.columns.len()],
        }
    }

    pub(crate) fn copy(
        &mut self,
        left_column: Column<Any>,
        left_row: usize,
        right_column: Column<Any>,
        right_row: usize,
    ) -> Result<(), Error> {
        let left_column = self
            .columns
            .iter()
            .position(|c| c == &left_column)
            .ok_or(Error::ColumnNotInPermutation)?;
        let right_column = self
            .columns
            .iter()
            .position(|c| c == &right_column)
            .ok_or(Error::ColumnNotInPermutation)?;

        // Check bounds
        if left_row >= self.mapping[left_column].len()
            || right_row >= self.mapping[right_column].len()
        {
            return Err(Error::BoundsFailure);
        }

        // See book/src/design/permutation.md for a description of this
        // algorithm.
        let mut left_cycle = self.aux[left_column][left_row];
        let mut right_cycle = self.aux[right_column][right_row];

        // If left and right are in the same cycle, do nothing.
        if left_cycle == right_cycle {
            return Ok(());
        }

        if self.sizes[left_cycle.0][left_cycle.1] < self.sizes[right_cycle.0][right_cycle.1] {
            core::mem::swap(&mut left_cycle, &mut right_cycle);
        }

        // Merge the right cycle into the left one.
        self.sizes[left_cycle.0][left_cycle.1] += self.sizes[right_cycle.0][right_cycle.1];
        let mut i = right_cycle;
        loop {
            self.aux[i.0][i.1] = left_cycle;
            i = self.mapping[i.0][i.1];
            if i == right_cycle {
                break;
            }
        }

        let tmp = self.mapping[left_column][left_row];
        self.mapping[left_column][left_row] = self.mapping[right_column][right_row];
        self.mapping[right_column][right_row] = tmp;

        Ok(())
    }

    /// The permutation polynomials, as values on the domain: cell `(i, j)`
    /// holds the label `DELTA^i' * omega^j'` of the cell it maps to.
    pub(crate) fn build_permutations(&self, domain: &EvaluationDomain) -> Vec<Vec<Fp>> {
        let n = domain.n;
        // Compute [omega^0, omega^1, ..., omega^{params.n - 1}]
        let mut omega_powers = Vec::with_capacity(n);
        let mut cur = Fp::ONE;
        for _ in 0..n {
            omega_powers.push(cur);
            cur *= domain.omega;
        }
        // Compute [omega_powers * \delta^0, omega_powers * \delta^1, ...]
        let mut deltaomega = Vec::with_capacity(self.columns.len());
        let mut cur = Fp::ONE;
        for _ in 0..self.columns.len() {
            deltaomega.push(omega_powers.iter().map(|o| *o * cur).collect::<Vec<Fp>>());
            cur *= Fp::DELTA;
        }
        (0..self.columns.len())
            .map(|i| {
                (0..n)
                    .map(|j| {
                        let (permuted_i, permuted_j) = self.mapping[i][j];
                        deltaomega[permuted_i][permuted_j]
                    })
                    .collect()
            })
            .collect()
    }
}

/// The backend of key generation: records the fixed cells, the selectors
/// and the copy constraints.
struct Assembly {
    fixed: Vec<Vec<Fp>>,
    permutation: PermutationAssembly,
    selectors: Vec<Vec<bool>>,
    usable_rows: usize,
}

impl Assignment for Assembly {
    fn enable_selector(&mut self, selector: &Selector, row: usize) -> Result<(), Error> {
        if row >= self.usable_rows {
            return Err(Error::NotEnoughRows);
        }
        self.selectors[selector.0][row] = true;
        Ok(())
    }

    fn query_instance(&self, _: Column<Instance>, row: usize) -> Result<Value<Fp>, Error> {
        if row >= self.usable_rows {
            return Err(Error::NotEnoughRows);
        }
        // There is no instance in this context.
        Ok(Value::unknown())
    }

    fn assign_advice(
        &mut self,
        _: Column<Advice>,
        _: usize,
        _: &mut dyn FnMut() -> Value<Fp>,
    ) -> Result<(), Error> {
        // We only care about fixed columns here
        Ok(())
    }

    fn assign_fixed(
        &mut self,
        column: Column<Fixed>,
        row: usize,
        to: &mut dyn FnMut() -> Value<Fp>,
    ) -> Result<(), Error> {
        if row >= self.usable_rows {
            return Err(Error::NotEnoughRows);
        }
        *self
            .fixed
            .get_mut(column.index)
            .and_then(|v| v.get_mut(row))
            .ok_or(Error::BoundsFailure)? = to().into_option().ok_or(Error::Synthesis)?;
        Ok(())
    }

    fn copy(
        &mut self,
        left_column: Column<Any>,
        left_row: usize,
        right_column: Column<Any>,
        right_row: usize,
    ) -> Result<(), Error> {
        if left_row >= self.usable_rows || right_row >= self.usable_rows {
            return Err(Error::NotEnoughRows);
        }
        self.permutation
            .copy(left_column, left_row, right_column, right_row)
    }

    fn fill_from_row(
        &mut self,
        column: Column<Fixed>,
        from_row: usize,
        to: Value<Fp>,
    ) -> Result<(), Error> {
        if from_row >= self.usable_rows {
            return Err(Error::NotEnoughRows);
        }
        let usable_rows = self.usable_rows;
        let col = self
            .fixed
            .get_mut(column.index)
            .ok_or(Error::BoundsFailure)?;
        let filler = to.into_option().ok_or(Error::Synthesis)?;
        for cell in col[..usable_rows].iter_mut().skip(from_row) {
            *cell = filler;
        }
        Ok(())
    }
}

/// What key generation computes before committing: the final constraint
/// system, the fixed columns (selectors included) and the permutation.
struct Synthesized {
    domain: EvaluationDomain,
    cs: ConstraintSystem,
    fixed: Vec<Vec<Fp>>,
    permutations: Vec<Vec<Fp>>,
    #[cfg_attr(not(test), allow(dead_code))]
    selector_plan: Vec<SelectorPlan>,
}

fn assemble<C: Circuit>(params: &Params, circuit: &C) -> Result<Synthesized, Error> {
    let mut cs = ConstraintSystem::default();
    let config = circuit.configure(&mut cs);
    let domain = EvaluationDomain::new(cs.degree() as u32, params.k);

    if params.n < cs.minimum_rows() {
        return Err(Error::NotEnoughRows);
    }

    let mut assembly = Assembly {
        fixed: vec![vec![Fp::ZERO; params.n]; cs.num_fixed_columns],
        permutation: PermutationAssembly::new(params.n, &cs.permutation),
        selectors: vec![vec![false; params.n]; cs.num_selectors],
        usable_rows: params.n - (cs.blinding_factors() + 1),
    };

    // Synthesize the circuit to obtain URS
    synthesize(&mut assembly, circuit, config, cs.constants.clone())?;

    let mut fixed = assembly.fixed;
    let (cs, selector_polys, selector_plan) = cs.compress_selectors(assembly.selectors);
    fixed.extend(selector_polys);
    let permutations = assembly.permutation.build_permutations(&domain);
    Ok(Synthesized {
        domain,
        cs,
        fixed,
        permutations,
        selector_plan,
    })
}

/// Rebuilds a verifying key from what key generation computed for the
/// same circuit: how the selectors were merged into fixed columns, and the
/// commitments. The circuit is configured but not synthesized, which makes
/// this much cheaper than [`keygen_vk`].
pub(crate) fn vk_from_parts<C: Circuit>(
    k: u32,
    circuit: &C,
    selector_plan: &[SelectorPlan],
    fixed_commitments: Vec<vesta::Affine>,
    permutation_commitments: Vec<vesta::Affine>,
) -> Result<VerifyingKey, Error> {
    let mut cs = ConstraintSystem::default();
    circuit.configure(&mut cs);
    let domain = EvaluationDomain::new(cs.degree() as u32, k);
    let cs = cs
        .apply_selector_plan(selector_plan)
        .ok_or(Error::Synthesis)?;
    if fixed_commitments.len() != cs.num_fixed_columns
        || permutation_commitments.len() != cs.permutation.columns.len()
    {
        return Err(Error::Synthesis);
    }
    Ok(VerifyingKey::from_parts(
        domain,
        fixed_commitments,
        permutation_commitments,
        cs,
    ))
}

/// Generates the verifying key of a circuit, and the plan by which its
/// selectors were merged (see [`vk_from_parts`]).
#[cfg(test)]
pub(crate) fn keygen_vk_with_plan<C: Circuit>(
    params: &Params,
    circuit: &C,
) -> Result<(VerifyingKey, Vec<SelectorPlan>), Error> {
    let s = assemble(params, circuit)?;
    Ok((vk_of(params, &s), s.selector_plan))
}

/// Generates the verifying key of a circuit.
pub fn keygen_vk<C: Circuit>(params: &Params, circuit: &C) -> Result<VerifyingKey, Error> {
    let s = assemble(params, circuit)?;
    Ok(vk_of(params, &s))
}

fn vk_of(params: &Params, s: &Synthesized) -> VerifyingKey {
    let commit = |polys: &[Vec<Fp>]| {
        let points: Vec<vesta::Point> = polys
            .iter()
            .map(|poly| params.commit_lagrange(poly, Fp::ONE))
            .collect();
        let mut out = vec![vesta::Affine::IDENTITY; points.len()];
        vesta::Point::batch_normalize(&points, &mut out);
        out
    };
    VerifyingKey::from_parts(
        s.domain.clone(),
        commit(&s.fixed),
        commit(&s.permutations),
        s.cs.clone(),
    )
}

/// Generates the proving key (and with it the verifying key) of a circuit.
pub fn keygen_pk<C: Circuit>(params: &Params, circuit: &C) -> Result<ProvingKey, Error> {
    let s = assemble(params, circuit)?;
    let vk = vk_of(params, &s);
    let domain = &vk.domain;
    let n = params.n;

    let to_coeff = |values: &[Vec<Fp>]| -> Vec<Vec<Fp>> {
        values
            .iter()
            .map(|v| domain.lagrange_to_coeff(v.clone()))
            .collect()
    };
    let to_extended = |polys: &[Vec<Fp>]| -> Vec<Vec<Fp>> {
        polys
            .iter()
            .map(|p| domain.coeff_to_extended(p.clone()))
            .collect()
    };
    let fixed_polys = to_coeff(&s.fixed);
    let fixed_cosets = to_extended(&fixed_polys);
    let permutation_polys = to_coeff(&s.permutations);
    let permutation_cosets = to_extended(&permutation_polys);

    let blinding_factors = vk.cs.blinding_factors();
    let extended = |values: Vec<Fp>| domain.coeff_to_extended(domain.lagrange_to_coeff(values));

    // Compute l_0(X)
    let mut l0 = vec![Fp::ZERO; n];
    l0[0] = Fp::ONE;
    // Compute l_blind(X) which evaluates to 1 for each blinding factor row
    // and 0 otherwise over the domain.
    let mut l_blind = vec![Fp::ZERO; n];
    for evaluation in l_blind.iter_mut().rev().take(blinding_factors) {
        *evaluation = Fp::ONE;
    }
    // Compute l_last(X) which evaluates to 1 on the first inactive row
    // (just before the blinding factors) and 0 otherwise over the domain
    let mut l_last = vec![Fp::ZERO; n];
    l_last[n - blinding_factors - 1] = Fp::ONE;

    Ok(ProvingKey {
        l0: extended(l0),
        l_blind: extended(l_blind),
        l_last: extended(l_last),
        fixed_values: s.fixed,
        fixed_polys,
        fixed_cosets,
        permutations: s.permutations,
        permutation_polys,
        permutation_cosets,
        vk,
    })
}
