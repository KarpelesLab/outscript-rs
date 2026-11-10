//! Proof creation, following `bellman::groth16::create_proof` step by step.

use super::curve::{Affine, CurveField, Jacobian, msm};
use super::domain::Domain;
use super::{
    Circuit, ConstraintSystem, LinearCombination, Parameters, Proof, SynthesisError, Variable,
    to_bls_scalar,
};
use crate::prelude::*;
use crate::sapling::field::Fq;
use purecrypto::zeroize::Zeroize;

/// Which variables occur in a query, so that the parameters only hold bases
/// for those.
#[derive(Default)]
struct Density(Vec<bool>);

impl Density {
    fn add_element(&mut self) {
        self.0.push(false);
    }

    fn inc(&mut self, index: usize) {
        if let Some(bit) = self.0.get_mut(index) {
            *bit = true;
        }
    }
}

/// The constraint system of the prover: the assignment and the evaluations
/// of every constraint's three combinations.
#[derive(Default)]
struct ProvingAssignment {
    a_aux_density: Density,
    b_input_density: Density,
    b_aux_density: Density,
    a: Vec<Fq>,
    b: Vec<Fq>,
    c: Vec<Fq>,
    input_assignment: Vec<Fq>,
    aux_assignment: Vec<Fq>,
}

impl Drop for ProvingAssignment {
    fn drop(&mut self) {
        self.a.zeroize();
        self.b.zeroize();
        self.c.zeroize();
        self.aux_assignment.zeroize();
    }
}

impl ProvingAssignment {
    /// Evaluates a combination, marking the variables it uses. As in
    /// `bellman`, terms with a zero coefficient neither count nor mark.
    fn eval(
        lc: &LinearCombination,
        mut input_density: Option<&mut Density>,
        mut aux_density: Option<&mut Density>,
        inputs: &[Fq],
        aux: &[Fq],
    ) -> Fq {
        let mut acc = Fq::ZERO;
        for (var, coeff) in lc.terms() {
            if coeff.is_zero() {
                continue;
            }
            let mut tmp = match *var {
                Variable::Input(i) => {
                    if let Some(d) = input_density.as_deref_mut() {
                        d.inc(i);
                    }
                    inputs.get(i).copied().unwrap_or(Fq::ZERO)
                }
                Variable::Aux(i) => {
                    if let Some(d) = aux_density.as_deref_mut() {
                        d.inc(i);
                    }
                    aux.get(i).copied().unwrap_or(Fq::ZERO)
                }
            };
            if *coeff != Fq::ONE {
                tmp *= *coeff;
            }
            acc += tmp;
        }
        acc
    }
}

impl ConstraintSystem for ProvingAssignment {
    fn alloc(
        &mut self,
        value: impl FnOnce() -> Result<Fq, SynthesisError>,
    ) -> Result<Variable, SynthesisError> {
        self.aux_assignment.push(value()?);
        self.a_aux_density.add_element();
        self.b_aux_density.add_element();
        Ok(Variable::Aux(self.aux_assignment.len() - 1))
    }

    fn alloc_input(
        &mut self,
        value: impl FnOnce() -> Result<Fq, SynthesisError>,
    ) -> Result<Variable, SynthesisError> {
        self.input_assignment.push(value()?);
        self.b_input_density.add_element();
        Ok(Variable::Input(self.input_assignment.len() - 1))
    }

    fn enforce(
        &mut self,
        a: impl FnOnce(LinearCombination) -> LinearCombination,
        b: impl FnOnce(LinearCombination) -> LinearCombination,
        c: impl FnOnce(LinearCombination) -> LinearCombination,
    ) {
        let a = a(LinearCombination::zero());
        let b = b(LinearCombination::zero());
        let c = c(LinearCombination::zero());
        // the A query is dense in the inputs, and there is no C query
        self.a.push(Self::eval(
            &a,
            None,
            Some(&mut self.a_aux_density),
            &self.input_assignment,
            &self.aux_assignment,
        ));
        self.b.push(Self::eval(
            &b,
            Some(&mut self.b_input_density),
            Some(&mut self.b_aux_density),
            &self.input_assignment,
            &self.aux_assignment,
        ));
        self.c.push(Self::eval(
            &c,
            None,
            None,
            &self.input_assignment,
            &self.aux_assignment,
        ));
    }
}

/// Runs up to three jobs, on their own threads when there are threads.
fn join3<A: Send, B: Send, C: Send>(
    fa: impl FnOnce() -> A + Send,
    fb: impl FnOnce() -> B + Send,
    fc: impl FnOnce() -> C + Send,
) -> (A, B, C) {
    #[cfg(feature = "std")]
    {
        std::thread::scope(|scope| {
            let hb = scope.spawn(fb);
            let hc = scope.spawn(fc);
            let a = fa();
            let b = match hb.join() {
                Ok(v) => v,
                Err(panic) => std::panic::resume_unwind(panic),
            };
            let c = match hc.join() {
                Ok(v) => v,
                Err(panic) => std::panic::resume_unwind(panic),
            };
            (a, b, c)
        })
    }
    #[cfg(not(feature = "std"))]
    {
        (fa(), fb(), fc())
    }
}

/// The coefficients of `H = (A·B - C) / Z`, one fewer than the domain
/// has points.
fn h_coefficients(
    mut a: Vec<Fq>,
    mut b: Vec<Fq>,
    mut c: Vec<Fq>,
) -> Result<Vec<Fq>, SynthesisError> {
    let domain = Domain::new(a.len())?;
    let n = domain.size();
    a.resize(n, Fq::ZERO);
    b.resize(n, Fq::ZERO);
    c.resize(n, Fq::ZERO);
    let to_coset = |v: &mut Vec<Fq>| {
        domain.ifft(v);
        domain.coset_fft(v);
    };
    join3(
        || to_coset(&mut a),
        || to_coset(&mut b),
        || to_coset(&mut c),
    );
    let z_inv = domain.z_inv_on_coset()?;
    for ((a, b), c) in a.iter_mut().zip(&b).zip(&c) {
        *a = (*a * *b - *c) * z_inv;
    }
    b.zeroize();
    c.zeroize();
    domain.icoset_fft(&mut a);
    a.truncate(n - 1);
    Ok(a)
}

/// The canonical limbs of the scalars `density` selects.
fn limbs(values: &[Fq], density: Option<&Density>) -> Vec<[u64; 4]> {
    match density {
        None => values.iter().map(Fq::to_raw).collect(),
        Some(d) => values
            .iter()
            .zip(&d.0)
            .filter(|(_, used)| **used)
            .map(|(v, _)| v.to_raw())
            .collect(),
    }
}

/// `Σ scalars[i]·bases[offset + i]`; the parameters must hold that many
/// bases.
fn query<F: CurveField>(
    bases: &[Affine<F>],
    offset: usize,
    scalars: &[[u64; 4]],
) -> Result<Jacobian<F>, SynthesisError> {
    let bases = offset
        .checked_add(scalars.len())
        .and_then(|end| bases.get(offset..end))
        .ok_or(SynthesisError::MalformedParameters)?;
    Ok(msm(bases, scalars))
}

/// Creates a proof that `circuit` is satisfied, with the blinding scalars
/// `r` and `s`.
///
/// For the same circuit, witness, parameters and scalars the result is the
/// proof `bellman::groth16::create_proof` gives. `r` and `s` must be
/// uniformly random, secret and used once: see the
/// [module documentation](super).
///
/// A witness that does not satisfy the circuit is not detected here unless
/// its synthesis fails: the proof simply does not verify.
pub fn create_proof<C: Circuit>(
    circuit: &C,
    params: &Parameters,
    r: &Fq,
    s: &Fq,
) -> Result<Proof, SynthesisError> {
    let mut prover = ProvingAssignment::default();
    prover.alloc_input(|| Ok(Fq::ONE))?;
    circuit.synthesize(&mut prover)?;
    for i in 0..prover.input_assignment.len() {
        prover.enforce(|lc| lc + Variable::Input(i), |lc| lc, |lc| lc);
    }

    let vk = &params.vk;
    if bool::from(vk.delta_g1.is_identity() | vk.delta_g2.is_identity()) {
        // a subverted reference string
        return Err(SynthesisError::UnexpectedIdentity);
    }

    let mut h_scalars = {
        let mut h = h_coefficients(
            core::mem::take(&mut prover.a),
            core::mem::take(&mut prover.b),
            core::mem::take(&mut prover.c),
        )?;
        let scalars = limbs(&h, None);
        h.zeroize();
        scalars
    };
    let h = query(&params.h, 0, &h_scalars);
    h_scalars.zeroize();
    let h = h?;

    let inputs = limbs(&prover.input_assignment, None);
    let mut aux = limbs(&prover.aux_assignment, None);
    let mut a_aux = limbs(&prover.aux_assignment, Some(&prover.a_aux_density));
    let b_inputs = limbs(&prover.input_assignment, Some(&prover.b_input_density));
    let mut b_aux = limbs(&prover.aux_assignment, Some(&prover.b_aux_density));

    let result = (|| {
        let l = query(&params.l, 0, &aux)?;
        let a_answer = query(&params.a, 0, &inputs)?.add(&query(&params.a, inputs.len(), &a_aux)?);
        let b1_answer =
            query(&params.b_g1, 0, &b_inputs)?.add(&query(&params.b_g1, b_inputs.len(), &b_aux)?);
        let b2_answer =
            query(&params.b_g2, 0, &b_inputs)?.add(&query(&params.b_g2, b_inputs.len(), &b_aux)?);
        Ok::<_, SynthesisError>((h.add(&l), a_answer, b1_answer, b2_answer))
    })();
    aux.zeroize();
    a_aux.zeroize();
    b_aux.zeroize();
    let (hl, a_answer, b1_answer, b2_answer) = result?;

    // the sums are in the groups whenever the parameters are
    let bad = SynthesisError::MalformedParameters;
    let hl = hl.to_g1().ok_or(bad)?;
    let a_answer = a_answer.to_g1().ok_or(bad)?;
    let b1_answer = b1_answer.to_g1().ok_or(bad)?;
    let b2_answer = b2_answer.to_g2().ok_or(bad)?;

    // everything involving r and s is constant time
    let r_s = to_bls_scalar(&(*r * *s));
    let r = to_bls_scalar(r);
    let s = to_bls_scalar(s);

    let g_a = vk.delta_g1.mul(&r).add(&vk.alpha_g1).add(&a_answer);
    let g_b = vk.delta_g2.mul(&s).add(&vk.beta_g2).add(&b2_answer);
    let g_c = vk
        .delta_g1
        .mul(&r_s)
        .add(&vk.alpha_g1.mul(&s))
        .add(&vk.beta_g1.mul(&r))
        .add(&a_answer.mul(&s))
        .add(&b1_answer.mul(&r))
        .add(&hl);

    Ok(Proof {
        a: g_a,
        b: g_b,
        c: g_c,
    })
}
