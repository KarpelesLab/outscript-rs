//! Rank-1 constraint systems: variables, linear combinations and the
//! interface a circuit is written against.
//!
//! The model is `bellman`'s. A circuit allocates variables (public *inputs*
//! and private *auxiliary* values) and enforces constraints of the form
//! `A · B = C` over linear combinations of them. The order of allocations
//! and constraints is part of a circuit's identity: proving parameters are
//! generated for one exact sequence.

use crate::prelude::*;
use crate::sapling::field::Fq;

/// A variable of a constraint system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Variable {
    /// The public input with this index; input 0 is the constant one.
    Input(usize),
    /// The auxiliary (private) variable with this index.
    Aux(usize),
}

/// A linear combination of variables: a list of `(variable, coefficient)`
/// terms. Terms are kept as written, without merging.
#[derive(Clone, Debug, Default)]
pub struct LinearCombination(Vec<(Variable, Fq)>);

impl LinearCombination {
    /// The empty combination.
    pub const fn zero() -> Self {
        LinearCombination(Vec::new())
    }

    /// The terms, in the order they were added.
    pub fn terms(&self) -> &[(Variable, Fq)] {
        &self.0
    }
}

impl core::ops::Add<(Fq, Variable)> for LinearCombination {
    type Output = LinearCombination;

    fn add(mut self, (coeff, var): (Fq, Variable)) -> LinearCombination {
        self.0.push((var, coeff));
        self
    }
}

impl core::ops::Sub<(Fq, Variable)> for LinearCombination {
    type Output = LinearCombination;

    fn sub(self, (coeff, var): (Fq, Variable)) -> LinearCombination {
        self + (-coeff, var)
    }
}

impl core::ops::Add<Variable> for LinearCombination {
    type Output = LinearCombination;

    fn add(self, var: Variable) -> LinearCombination {
        self + (Fq::ONE, var)
    }
}

impl core::ops::Sub<Variable> for LinearCombination {
    type Output = LinearCombination;

    fn sub(self, var: Variable) -> LinearCombination {
        self - (Fq::ONE, var)
    }
}

impl core::ops::Add<&LinearCombination> for LinearCombination {
    type Output = LinearCombination;

    fn add(mut self, other: &LinearCombination) -> LinearCombination {
        self.0.extend_from_slice(&other.0);
        self
    }
}

impl core::ops::Sub<&LinearCombination> for LinearCombination {
    type Output = LinearCombination;

    fn sub(mut self, other: &LinearCombination) -> LinearCombination {
        self.0
            .extend(other.0.iter().map(|(var, coeff)| (*var, -*coeff)));
        self
    }
}

impl core::ops::Add<(Fq, &LinearCombination)> for LinearCombination {
    type Output = LinearCombination;

    fn add(mut self, (coeff, other): (Fq, &LinearCombination)) -> LinearCombination {
        self.0
            .extend(other.0.iter().map(|(var, c)| (*var, *c * coeff)));
        self
    }
}

impl core::ops::Sub<(Fq, &LinearCombination)> for LinearCombination {
    type Output = LinearCombination;

    fn sub(mut self, (coeff, other): (Fq, &LinearCombination)) -> LinearCombination {
        self.0
            .extend(other.0.iter().map(|(var, c)| (*var, -(*c * coeff))));
        self
    }
}

/// Why a circuit could not be synthesized or a proof created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SynthesisError {
    /// A witness value needed a division by zero: the witness does not
    /// satisfy the circuit.
    DivisionByZero,
    /// The witness cannot satisfy the circuit.
    Unsatisfiable,
    /// The circuit has more constraints than the field has roots of unity
    /// for.
    PolynomialDegreeTooLarge,
    /// The parameters contain an identity where none is allowed (a sign of
    /// a subverted reference string).
    UnexpectedIdentity,
    /// The parameters are too short for this circuit, or contain points
    /// outside the group: they belong to another circuit or are corrupt.
    MalformedParameters,
}

impl core::fmt::Display for SynthesisError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            SynthesisError::DivisionByZero => "division by zero",
            SynthesisError::Unsatisfiable => "unsatisfiable constraint system",
            SynthesisError::PolynomialDegreeTooLarge => "polynomial degree is too large",
            SynthesisError::UnexpectedIdentity => "identity element in the parameters",
            SynthesisError::MalformedParameters => "parameters do not fit the circuit",
        })
    }
}

impl core::error::Error for SynthesisError {}

/// A constraint system under construction.
pub trait ConstraintSystem {
    /// The variable that is always one: input 0.
    fn one() -> Variable {
        Variable::Input(0)
    }

    /// Allocates a private variable. `value` is called at most once, and
    /// only by systems that need the assignment.
    fn alloc(
        &mut self,
        value: impl FnOnce() -> Result<Fq, SynthesisError>,
    ) -> Result<Variable, SynthesisError>;

    /// Allocates a public input.
    fn alloc_input(
        &mut self,
        value: impl FnOnce() -> Result<Fq, SynthesisError>,
    ) -> Result<Variable, SynthesisError>;

    /// Enforces `a · b = c`. Each closure receives the empty combination
    /// and returns the combination to use.
    fn enforce(
        &mut self,
        a: impl FnOnce(LinearCombination) -> LinearCombination,
        b: impl FnOnce(LinearCombination) -> LinearCombination,
        c: impl FnOnce(LinearCombination) -> LinearCombination,
    );
}

/// A circuit: something that can lay out its constraints, with a witness,
/// in a constraint system.
pub trait Circuit {
    /// Allocates the circuit's variables and enforces its constraints.
    fn synthesize<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<(), SynthesisError>;
}

/// A constraint system that records everything, to check that a witness
/// satisfies a circuit and to fingerprint the circuit's structure.
#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use alloc::collections::BTreeMap;

    type Constraint = (LinearCombination, LinearCombination, LinearCombination);

    /// See the [module documentation](self).
    pub(crate) struct TestConstraintSystem {
        pub(crate) inputs: Vec<Fq>,
        pub(crate) aux: Vec<Fq>,
        pub(crate) constraints: Vec<Constraint>,
    }

    impl TestConstraintSystem {
        pub(crate) fn new() -> Self {
            TestConstraintSystem {
                inputs: vec![Fq::ONE],
                aux: Vec::new(),
                constraints: Vec::new(),
            }
        }

        fn eval(&self, lc: &LinearCombination) -> Fq {
            lc.terms().iter().fold(Fq::ZERO, |acc, (var, coeff)| {
                acc + *coeff
                    * match var {
                        Variable::Input(i) => self.inputs[*i],
                        Variable::Aux(i) => self.aux[*i],
                    }
            })
        }

        /// The index of the first constraint the assignment violates.
        pub(crate) fn which_is_unsatisfied(&self) -> Option<usize> {
            self.constraints
                .iter()
                .position(|(a, b, c)| self.eval(a) * self.eval(b) != self.eval(c))
        }

        pub(crate) fn is_satisfied(&self) -> bool {
            self.which_is_unsatisfied().is_none()
        }

        /// The fingerprint `bellman`'s `TestConstraintSystem::hash` gives
        /// the same system: BLAKE2s-256 over the numbers of inputs,
        /// auxiliary variables and constraints, then every constraint's
        /// three combinations with their terms merged, sorted and stripped
        /// of zero coefficients.
        pub(crate) fn hash(&self) -> String {
            use purecrypto::hash::Blake2sMac;
            let mut h = Blake2sMac::try_new_with_salt_personal(&[], 32, &[], &[]).unwrap();
            h.update(&(self.inputs.len() as u64).to_be_bytes());
            h.update(&(self.aux.len() as u64).to_be_bytes());
            h.update(&(self.constraints.len() as u64).to_be_bytes());
            let mut hash_lc = |lc: &LinearCombination| {
                let mut map: BTreeMap<Variable, Fq> = BTreeMap::new();
                for (var, coeff) in lc.terms() {
                    *map.entry(*var).or_insert(Fq::ZERO) += *coeff;
                }
                map.retain(|_, coeff| !coeff.is_zero());
                h.update(&(map.len() as u64).to_be_bytes());
                for (var, coeff) in map {
                    let (tag, index) = match var {
                        Variable::Input(i) => (b'I', i),
                        Variable::Aux(i) => (b'A', i),
                    };
                    h.update(&[tag]);
                    h.update(&(index as u64).to_be_bytes());
                    let mut be = coeff.to_bytes();
                    be.reverse();
                    h.update(&be);
                }
            };
            for (a, b, c) in &self.constraints {
                hash_lc(a);
                hash_lc(b);
                hash_lc(c);
            }
            let mut out = [0u8; 32];
            h.finalize_into(&mut out);
            hex::encode(out)
        }
    }

    impl ConstraintSystem for TestConstraintSystem {
        fn alloc(
            &mut self,
            value: impl FnOnce() -> Result<Fq, SynthesisError>,
        ) -> Result<Variable, SynthesisError> {
            self.aux.push(value()?);
            Ok(Variable::Aux(self.aux.len() - 1))
        }

        fn alloc_input(
            &mut self,
            value: impl FnOnce() -> Result<Fq, SynthesisError>,
        ) -> Result<Variable, SynthesisError> {
            self.inputs.push(value()?);
            Ok(Variable::Input(self.inputs.len() - 1))
        }

        fn enforce(
            &mut self,
            a: impl FnOnce(LinearCombination) -> LinearCombination,
            b: impl FnOnce(LinearCombination) -> LinearCombination,
            c: impl FnOnce(LinearCombination) -> LinearCombination,
        ) {
            self.constraints.push((
                a(LinearCombination::zero()),
                b(LinearCombination::zero()),
                c(LinearCombination::zero()),
            ));
        }
    }
}
