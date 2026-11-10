//! The basic gadgets of the Sapling circuits: bits, field elements, window
//! lookups and the packing of bits into public inputs.
//!
//! Each function allocates the variables and enforces the constraints of
//! the `bellman` gadget of the same name, in the same order: the circuits
//! must reproduce the reference constraint systems exactly. Unlike
//! `bellman`'s, these gadgets always carry a witness.

use crate::prelude::*;
use crate::sapling::field::{Fq, Fr};
use crate::sapling::groth16::{ConstraintSystem, LinearCombination, SynthesisError, Variable};

/// The number of bits that always fit a field element: 254.
pub(super) const FQ_CAPACITY: usize = 254;
/// The number of bits of the field modulus: 255.
pub(super) const FQ_NUM_BITS: usize = 255;

/// The bit `i` (little-endian) of a 32-byte little-endian integer.
fn bit(bytes: &[u8; 32], i: usize) -> bool {
    (bytes[i / 8] >> (i % 8)) & 1 == 1
}

fn fq_from_bool(b: bool) -> Fq {
    if b { Fq::ONE } else { Fq::ZERO }
}

/// A variable constrained to be 0 or 1.
#[derive(Clone, Copy)]
pub(super) struct AllocatedBit {
    variable: Variable,
    value: bool,
}

impl AllocatedBit {
    pub(super) fn get_variable(&self) -> Variable {
        self.variable
    }

    /// Allocates a bit: `(1 - a) · a = 0`.
    pub(super) fn alloc<CS: ConstraintSystem>(
        cs: &mut CS,
        value: bool,
    ) -> Result<Self, SynthesisError> {
        let var = cs.alloc(|| Ok(fq_from_bool(value)))?;
        cs.enforce(|lc| lc + CS::one() - var, |lc| lc + var, |lc| lc);
        Ok(AllocatedBit {
            variable: var,
            value,
        })
    }

    /// Allocates a bit that must be zero when `must_be_false` is set:
    /// `(1 - must_be_false - a) · a = 0`.
    pub(super) fn alloc_conditionally<CS: ConstraintSystem>(
        cs: &mut CS,
        value: bool,
        must_be_false: &AllocatedBit,
    ) -> Result<Self, SynthesisError> {
        let var = cs.alloc(|| Ok(fq_from_bool(value)))?;
        cs.enforce(
            |lc| lc + CS::one() - must_be_false.variable - var,
            |lc| lc + var,
            |lc| lc,
        );
        Ok(AllocatedBit {
            variable: var,
            value,
        })
    }

    /// `a ^ b`: `2a · b = a + b - c`.
    fn xor<CS: ConstraintSystem>(cs: &mut CS, a: &Self, b: &Self) -> Result<Self, SynthesisError> {
        let value = a.value ^ b.value;
        let var = cs.alloc(|| Ok(fq_from_bool(value)))?;
        cs.enforce(
            |lc| lc + a.variable + a.variable,
            |lc| lc + b.variable,
            |lc| lc + a.variable + b.variable - var,
        );
        Ok(AllocatedBit {
            variable: var,
            value,
        })
    }

    /// `a & b`: `a · b = c`.
    pub(super) fn and<CS: ConstraintSystem>(
        cs: &mut CS,
        a: &Self,
        b: &Self,
    ) -> Result<Self, SynthesisError> {
        let value = a.value & b.value;
        let var = cs.alloc(|| Ok(fq_from_bool(value)))?;
        cs.enforce(|lc| lc + a.variable, |lc| lc + b.variable, |lc| lc + var);
        Ok(AllocatedBit {
            variable: var,
            value,
        })
    }

    /// `a & !b`: `a · (1 - b) = c`.
    fn and_not<CS: ConstraintSystem>(
        cs: &mut CS,
        a: &Self,
        b: &Self,
    ) -> Result<Self, SynthesisError> {
        let value = a.value & !b.value;
        let var = cs.alloc(|| Ok(fq_from_bool(value)))?;
        cs.enforce(
            |lc| lc + a.variable,
            |lc| lc + CS::one() - b.variable,
            |lc| lc + var,
        );
        Ok(AllocatedBit {
            variable: var,
            value,
        })
    }

    /// `!a & !b`: `(1 - a) · (1 - b) = c`.
    fn nor<CS: ConstraintSystem>(cs: &mut CS, a: &Self, b: &Self) -> Result<Self, SynthesisError> {
        let value = !a.value & !b.value;
        let var = cs.alloc(|| Ok(fq_from_bool(value)))?;
        cs.enforce(
            |lc| lc + CS::one() - a.variable,
            |lc| lc + CS::one() - b.variable,
            |lc| lc + var,
        );
        Ok(AllocatedBit {
            variable: var,
            value,
        })
    }
}

/// A boolean: an allocated bit, its negation, or a constant.
#[derive(Clone, Copy)]
pub(super) enum Boolean {
    /// The bit.
    Is(AllocatedBit),
    /// The negation of the bit.
    Not(AllocatedBit),
    /// A constant, which costs no variable.
    Constant(bool),
}

impl From<AllocatedBit> for Boolean {
    fn from(b: AllocatedBit) -> Boolean {
        Boolean::Is(b)
    }
}

impl Boolean {
    pub(super) fn is_constant(&self) -> bool {
        matches!(self, Boolean::Constant(_))
    }

    pub(super) fn get_value(&self) -> bool {
        match self {
            Boolean::Constant(c) => *c,
            Boolean::Is(v) => v.value,
            Boolean::Not(v) => !v.value,
        }
    }

    /// `coeff` times the boolean, as a linear combination.
    pub(super) fn lc(&self, one: Variable, coeff: Fq) -> LinearCombination {
        match self {
            Boolean::Constant(true) => LinearCombination::zero() + (coeff, one),
            Boolean::Constant(false) => LinearCombination::zero(),
            Boolean::Is(v) => LinearCombination::zero() + (coeff, v.variable),
            Boolean::Not(v) => LinearCombination::zero() + (coeff, one) - (coeff, v.variable),
        }
    }

    pub(super) fn not(&self) -> Self {
        match self {
            Boolean::Constant(c) => Boolean::Constant(!*c),
            Boolean::Is(v) => Boolean::Not(*v),
            Boolean::Not(v) => Boolean::Is(*v),
        }
    }

    /// `a ^ b`; free when either is constant.
    pub(super) fn xor<CS: ConstraintSystem>(
        cs: &mut CS,
        a: &Self,
        b: &Self,
    ) -> Result<Self, SynthesisError> {
        match (a, b) {
            (Boolean::Constant(false), x) | (x, Boolean::Constant(false)) => Ok(*x),
            (Boolean::Constant(true), x) | (x, Boolean::Constant(true)) => Ok(x.not()),
            // a ^ !b = !(a ^ b)
            (is @ Boolean::Is(_), not @ Boolean::Not(_))
            | (not @ Boolean::Not(_), is @ Boolean::Is(_)) => {
                Ok(Boolean::xor(cs, is, &not.not())?.not())
            }
            (Boolean::Is(a), Boolean::Is(b)) | (Boolean::Not(a), Boolean::Not(b)) => {
                Ok(Boolean::Is(AllocatedBit::xor(cs, a, b)?))
            }
        }
    }

    /// `a & b`; free when either is constant.
    pub(super) fn and<CS: ConstraintSystem>(
        cs: &mut CS,
        a: &Self,
        b: &Self,
    ) -> Result<Self, SynthesisError> {
        match (a, b) {
            (Boolean::Constant(false), _) | (_, Boolean::Constant(false)) => {
                Ok(Boolean::Constant(false))
            }
            (Boolean::Constant(true), x) | (x, Boolean::Constant(true)) => Ok(*x),
            (Boolean::Is(is), Boolean::Not(not)) | (Boolean::Not(not), Boolean::Is(is)) => {
                Ok(Boolean::Is(AllocatedBit::and_not(cs, is, not)?))
            }
            (Boolean::Not(a), Boolean::Not(b)) => Ok(Boolean::Is(AllocatedBit::nor(cs, a, b)?)),
            (Boolean::Is(a), Boolean::Is(b)) => Ok(Boolean::Is(AllocatedBit::and(cs, a, b)?)),
        }
    }
}

/// The 64 bits of `value`, least significant first.
pub(super) fn u64_into_boolean_vec_le<CS: ConstraintSystem>(
    cs: &mut CS,
    value: u64,
) -> Result<Vec<Boolean>, SynthesisError> {
    (0..64)
        .map(|i| {
            Ok(Boolean::from(AllocatedBit::alloc(
                cs,
                (value >> i) & 1 == 1,
            )?))
        })
        .collect()
}

/// The low `n` bits of a little-endian integer as allocated bits, least
/// significant first. The bits are not constrained to form a reduced
/// value.
fn bytes_into_allocated_bits_le<CS: ConstraintSystem>(
    cs: &mut CS,
    bytes: &[u8; 32],
    n: usize,
) -> Result<Vec<AllocatedBit>, SynthesisError> {
    (0..n)
        .map(|i| AllocatedBit::alloc(cs, bit(bytes, i)))
        .collect()
}

/// The 252 bits of a Jubjub scalar, least significant first.
pub(super) fn fr_into_boolean_vec_le<CS: ConstraintSystem>(
    cs: &mut CS,
    value: &Fr,
) -> Result<Vec<Boolean>, SynthesisError> {
    let mut bytes = value.to_bytes();
    let bits = bytes_into_allocated_bits_le(cs, &bytes, Fr::NUM_BITS as usize);
    purecrypto::zeroize::Zeroize::zeroize(&mut bytes);
    Ok(bits?.into_iter().map(Boolean::from).collect())
}

/// The 255 bits of a field element, least significant first.
pub(super) fn fq_into_boolean_vec_le<CS: ConstraintSystem>(
    cs: &mut CS,
    value: &Fq,
) -> Result<Vec<Boolean>, SynthesisError> {
    let bits = bytes_into_allocated_bits_le(cs, &value.to_bytes(), FQ_NUM_BITS)?;
    Ok(bits.into_iter().map(Boolean::from).collect())
}

/// A variable holding a field element.
#[derive(Clone, Copy)]
pub(super) struct AllocatedNum {
    value: Fq,
    variable: Variable,
}

impl AllocatedNum {
    pub(super) fn alloc<CS: ConstraintSystem>(
        cs: &mut CS,
        value: Fq,
    ) -> Result<Self, SynthesisError> {
        let variable = cs.alloc(|| Ok(value))?;
        Ok(AllocatedNum { value, variable })
    }

    pub(super) fn get_value(&self) -> Fq {
        self.value
    }

    pub(super) fn get_variable(&self) -> Variable {
        self.variable
    }

    /// Exposes the value as a public input: `input · 1 = self`.
    pub(super) fn inputize<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let input = cs.alloc_input(|| Ok(self.value))?;
        cs.enforce(
            |lc| lc + input,
            |lc| lc + CS::one(),
            |lc| lc + self.variable,
        );
        Ok(())
    }

    /// The 255 bits of the value, least significant first, constrained to
    /// be the canonical (reduced) representation.
    pub(super) fn to_bits_le_strict<CS: ConstraintSystem>(
        self,
        cs: &mut CS,
    ) -> Result<Vec<Boolean>, SynthesisError> {
        fn kary_and<CS: ConstraintSystem>(
            cs: &mut CS,
            v: &[AllocatedBit],
        ) -> Result<AllocatedBit, SynthesisError> {
            let mut cur = v[0];
            for bit in &v[1..] {
                cur = AllocatedBit::and(cs, &cur, bit)?;
            }
            Ok(cur)
        }

        // The bits of the value are compared with those of q - 1, most
        // significant first: wherever q - 1 has a zero, the value's bit
        // must be zero if all the more significant bits matched the ones
        // of q - 1.
        let a = self.value.to_bytes();
        let b = (-Fq::ONE).to_bytes();

        let mut result: Vec<AllocatedBit> = Vec::with_capacity(FQ_NUM_BITS);
        let mut last_run: Option<AllocatedBit> = None;
        let mut current_run: Vec<AllocatedBit> = Vec::new();
        let mut found_one = false;
        for i in (0..256).rev() {
            let (a_bit, b_bit) = (bit(&a, i), bit(&b, i));
            found_one |= b_bit;
            if !found_one {
                // above the modulus: the value has no such bit
                continue;
            }
            if b_bit {
                let a_bit = AllocatedBit::alloc(cs, a_bit)?;
                current_run.push(a_bit);
                result.push(a_bit);
            } else {
                if !current_run.is_empty() {
                    if let Some(last) = last_run {
                        current_run.push(last);
                    }
                    last_run = Some(kary_and(cs, &current_run)?);
                    current_run.clear();
                }
                // q - 1 starts with a one, so there is a run by now
                let run = last_run.as_ref().ok_or(SynthesisError::Unsatisfiable)?;
                let a_bit = AllocatedBit::alloc_conditionally(cs, a_bit, run)?;
                result.push(a_bit);
            }
        }

        let mut lc = LinearCombination::zero();
        let mut coeff = Fq::ONE;
        for bit in result.iter().rev() {
            lc = lc + (coeff, bit.get_variable());
            coeff = coeff.double();
        }
        lc = lc - self.variable;
        cs.enforce(|lc| lc, |lc| lc, |_| lc);

        Ok(result.into_iter().rev().map(Boolean::from).collect())
    }

    /// The 255 bits of a representation of the value, least significant
    /// first; nothing forces the canonical one.
    pub(super) fn to_bits_le<CS: ConstraintSystem>(
        self,
        cs: &mut CS,
    ) -> Result<Vec<Boolean>, SynthesisError> {
        let bits = bytes_into_allocated_bits_le(cs, &self.value.to_bytes(), FQ_NUM_BITS)?;
        let mut lc = LinearCombination::zero();
        let mut coeff = Fq::ONE;
        for bit in &bits {
            lc = lc + (coeff, bit.get_variable());
            coeff = coeff.double();
        }
        lc = lc - self.variable;
        cs.enforce(|lc| lc, |lc| lc, |_| lc);
        Ok(bits.into_iter().map(Boolean::from).collect())
    }

    /// `self · other`.
    pub(super) fn mul<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        other: &Self,
    ) -> Result<Self, SynthesisError> {
        let value = self.value * other.value;
        let variable = cs.alloc(|| Ok(value))?;
        cs.enforce(
            |lc| lc + self.variable,
            |lc| lc + other.variable,
            |lc| lc + variable,
        );
        Ok(AllocatedNum { value, variable })
    }

    /// `self²`.
    pub(super) fn square<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<Self, SynthesisError> {
        let value = self.value.square();
        let variable = cs.alloc(|| Ok(value))?;
        cs.enforce(
            |lc| lc + self.variable,
            |lc| lc + self.variable,
            |lc| lc + variable,
        );
        Ok(AllocatedNum { value, variable })
    }

    /// Asserts the value is not zero, by exhibiting its inverse.
    pub(super) fn assert_nonzero<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let inv = cs.alloc(|| self.value.invert().ok_or(SynthesisError::DivisionByZero))?;
        cs.enforce(|lc| lc + self.variable, |lc| lc + inv, |lc| lc + CS::one());
        Ok(())
    }

    /// `(a, b)`, swapped if `condition` is set.
    pub(super) fn conditionally_reverse<CS: ConstraintSystem>(
        cs: &mut CS,
        a: &Self,
        b: &Self,
        condition: &Boolean,
    ) -> Result<(Self, Self), SynthesisError> {
        let swap = condition.get_value();
        let c = Self::alloc(cs, if swap { b.value } else { a.value })?;
        cs.enforce(
            |lc| lc + a.variable - b.variable,
            |_| condition.lc(CS::one(), Fq::ONE),
            |lc| lc + a.variable - c.variable,
        );
        let d = Self::alloc(cs, if swap { a.value } else { b.value })?;
        cs.enforce(
            |lc| lc + b.variable - a.variable,
            |_| condition.lc(CS::one(), Fq::ONE),
            |lc| lc + b.variable - d.variable,
        );
        Ok((c, d))
    }
}

/// A field element known as a linear combination of variables.
pub(super) struct Num {
    value: Fq,
    lc: LinearCombination,
}

impl From<AllocatedNum> for Num {
    fn from(num: AllocatedNum) -> Num {
        Num {
            value: num.value,
            lc: LinearCombination::zero() + num.variable,
        }
    }
}

impl Num {
    pub(super) fn zero() -> Self {
        Num {
            value: Fq::ZERO,
            lc: LinearCombination::zero(),
        }
    }

    pub(super) fn get_value(&self) -> Fq {
        self.value
    }

    /// `coeff` times the number.
    pub(super) fn lc(&self, coeff: Fq) -> LinearCombination {
        LinearCombination::zero() + (coeff, &self.lc)
    }

    /// Adds `coeff` if `bit` is set.
    pub(super) fn add_bool_with_coeff(self, one: Variable, bit: &Boolean, coeff: Fq) -> Self {
        Num {
            value: if bit.get_value() {
                self.value + coeff
            } else {
                self.value
            },
            lc: self.lc + &bit.lc(one, coeff),
        }
    }
}

/// The coefficients of the multilinear polynomial that takes the value
/// `constants[i]` at the bits of `i`.
fn synth<const N: usize>(constants: impl Iterator<Item = Fq>) -> [Fq; N] {
    let mut assignment = [Fq::ZERO; N];
    for (i, constant) in constants.enumerate().take(N) {
        let cur = constant - assignment[i];
        assignment[i] = cur;
        for (j, eval) in assignment.iter_mut().enumerate().skip(i + 1) {
            if j & i == i {
                *eval += cur;
            }
        }
    }
    assignment
}

/// Looks up the point `coords[b0 + 2·b1 + 4·b2]` of a 3-bit window table.
pub(super) fn lookup3_xy<CS: ConstraintSystem>(
    cs: &mut CS,
    bits: &[Boolean; 3],
    coords: &[(Fq, Fq); 8],
) -> Result<(AllocatedNum, AllocatedNum), SynthesisError> {
    let i = usize::from(bits[0].get_value())
        | usize::from(bits[1].get_value()) << 1
        | usize::from(bits[2].get_value()) << 2;
    let res_x = AllocatedNum::alloc(cs, coords[i].0)?;
    let res_y = AllocatedNum::alloc(cs, coords[i].1)?;

    let x_coeffs: [Fq; 8] = synth(coords.iter().map(|c| c.0));
    let y_coeffs: [Fq; 8] = synth(coords.iter().map(|c| c.1));

    let precomp = Boolean::and(cs, &bits[1], &bits[2])?;
    let one = CS::one();

    for (res, coeffs) in [(res_x, x_coeffs), (res_y, y_coeffs)] {
        cs.enforce(
            |lc| {
                lc + (coeffs[0b001], one)
                    + &bits[1].lc(one, coeffs[0b011])
                    + &bits[2].lc(one, coeffs[0b101])
                    + &precomp.lc(one, coeffs[0b111])
            },
            |lc| lc + &bits[0].lc(one, Fq::ONE),
            |lc| {
                lc + res.get_variable()
                    - (coeffs[0b000], one)
                    - &bits[1].lc(one, coeffs[0b010])
                    - &bits[2].lc(one, coeffs[0b100])
                    - &precomp.lc(one, coeffs[0b110])
            },
        );
    }
    Ok((res_x, res_y))
}

/// Looks up the point `coords[b0 + 2·b1]` of a 2-bit window table and
/// negates its `y` if `b2` is set.
pub(super) fn lookup3_xy_with_conditional_negation<CS: ConstraintSystem>(
    cs: &mut CS,
    bits: &[Boolean; 3],
    coords: &[(Fq, Fq); 4],
) -> Result<(Num, Num), SynthesisError> {
    let i = usize::from(bits[0].get_value()) | usize::from(bits[1].get_value()) << 1;
    let y = AllocatedNum::alloc(
        cs,
        if bits[2].get_value() {
            -coords[i].1
        } else {
            coords[i].1
        },
    )?;
    let one = CS::one();

    let x_coeffs: [Fq; 4] = synth(coords.iter().map(|c| c.0));
    let y_coeffs: [Fq; 4] = synth(coords.iter().map(|c| c.1));

    let precomp = Boolean::and(cs, &bits[0], &bits[1])?;

    let x = Num::zero()
        .add_bool_with_coeff(one, &Boolean::Constant(true), x_coeffs[0b00])
        .add_bool_with_coeff(one, &bits[0], x_coeffs[0b01])
        .add_bool_with_coeff(one, &bits[1], x_coeffs[0b10])
        .add_bool_with_coeff(one, &precomp, x_coeffs[0b11]);

    let y_lc = precomp.lc(one, y_coeffs[0b11])
        + &bits[1].lc(one, y_coeffs[0b10])
        + &bits[0].lc(one, y_coeffs[0b01])
        + (y_coeffs[0b00], one);

    cs.enforce(
        |lc| lc + &y_lc + &y_lc,
        |lc| lc + &bits[2].lc(one, Fq::ONE),
        |lc| lc + &y_lc - y.get_variable(),
    );

    Ok((x, y.into()))
}

/// Exposes `bits` as public inputs, 254 bits (least significant first) per
/// input.
pub(super) fn pack_into_inputs<CS: ConstraintSystem>(
    cs: &mut CS,
    bits: &[Boolean],
) -> Result<(), SynthesisError> {
    for chunk in bits.chunks(FQ_CAPACITY) {
        let mut num = Num::zero();
        let mut coeff = Fq::ONE;
        for bit in chunk {
            num = num.add_bool_with_coeff(CS::one(), bit, coeff);
            coeff = coeff.double();
        }
        let input = cs.alloc_input(|| Ok(num.get_value()))?;
        cs.enforce(|_| num.lc(Fq::ONE), |lc| lc + CS::one(), |lc| lc + input);
    }
    Ok(())
}

/// The public inputs [`pack_into_inputs`] produces for these bytes, whose
/// bits are taken least significant first.
pub(crate) fn multipack(bytes: &[u8]) -> impl Iterator<Item = Fq> + '_ {
    let bit = |i: usize| (bytes[i / 8] >> (i % 8)) & 1 == 1;
    (0..bytes.len() * 8).step_by(FQ_CAPACITY).map(move |start| {
        let end = (start + FQ_CAPACITY).min(bytes.len() * 8);
        (start..end)
            .rev()
            .fold(Fq::ZERO, |acc, i| acc.double() + fq_from_bool(bit(i)))
    })
}
