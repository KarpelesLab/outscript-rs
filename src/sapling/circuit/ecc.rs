//! Jubjub arithmetic in the circuit: twisted Edwards and Montgomery points,
//! fixed-base and variable-base scalar multiplication and the Pedersen
//! hash (`sapling-crypto`'s `circuit::ecc` and `circuit::pedersen_hash`).

use super::gadgets::{
    AllocatedNum, Boolean, Num, lookup3_xy, lookup3_xy_with_conditional_negation,
};
use crate::prelude::*;
use crate::sapling::field::Fq;
use crate::sapling::generators::{
    MONTGOMERY_A, MONTGOMERY_SCALE, PEDERSEN_HASH_CHUNKS_PER_GENERATOR, pedersen_hash_generator,
};
use crate::sapling::groth16::{ConstraintSystem, SynthesisError};
use crate::sapling::jubjub::{AffinePoint, D as EDWARDS_D, Point};

/// `num / den`, failing as a witness that cannot exist when `den` is zero.
fn div(num: Fq, den: Fq) -> Result<Fq, SynthesisError> {
    Ok(num * den.invert().ok_or(SynthesisError::DivisionByZero)?)
}

/// The window tables of a fixed-base multiplication by `base`: for each of
/// the `windows` 3-bit windows `w`, the points `[j·8^w] base`, `j` in
/// `0..8`.
pub(super) fn fixed_base_table(base: &AffinePoint, windows: usize) -> Vec<[(Fq, Fq); 8]> {
    let mut points = Vec::with_capacity(8 * windows);
    let mut generator = base.to_point();
    for _ in 0..windows {
        let mut p = Point::IDENTITY;
        for _ in 0..8 {
            points.push(p);
            p = p.add(&generator);
        }
        generator = p;
    }
    let mut affine = vec![AffinePoint::IDENTITY; points.len()];
    Point::batch_to_affine(&points, &mut affine);
    affine
        .as_chunks::<8>()
        .0
        .iter()
        .map(|w| w.map(|p| (p.u(), p.v())))
        .collect()
}

/// Inverts every element in place with one field inversion; zeros stay
/// zero.
fn batch_invert(values: &mut [Fq]) {
    let mut prefix = Vec::with_capacity(values.len());
    let mut acc = Fq::ONE;
    for v in values.iter() {
        prefix.push(acc);
        if !v.is_zero() {
            acc *= *v;
        }
    }
    let mut inv = acc.invert().unwrap_or(Fq::ZERO);
    for (v, pre) in values.iter_mut().zip(prefix).rev() {
        if !v.is_zero() {
            let next = inv * *v;
            *v = inv * pre;
            inv = next;
        }
    }
}

/// The lookup tables of the Pedersen hash, in Montgomery coordinates.
pub(super) struct PedersenTables(Vec<Vec<[(Fq, Fq); 4]>>);

impl PedersenTables {
    /// The tables of the first `segments` segments: for each, 63 windows
    /// `w` holding `[j·16^w] I_segment` for `j` in `1..=4`.
    pub(super) fn new(segments: u32) -> Self {
        let per_segment = 4 * PEDERSEN_HASH_CHUNKS_PER_GENERATOR;
        let mut points = Vec::with_capacity(per_segment * segments as usize);
        for segment in 0..segments {
            let mut generator = pedersen_hash_generator(segment);
            for _ in 0..PEDERSEN_HASH_CHUNKS_PER_GENERATOR {
                let mut p = generator;
                for _ in 0..4 {
                    points.push(p);
                    p = p.add(&generator);
                }
                generator = generator.double().double().double().double();
            }
        }
        let mut affine = vec![AffinePoint::IDENTITY; points.len()];
        Point::batch_to_affine(&points, &mut affine);
        // x = (1 + v) / (1 - v), y = scale · x / u; no table entry is the
        // identity or the point of order two
        let mut dens: Vec<Fq> = affine
            .iter()
            .flat_map(|p| [Fq::ONE - p.v(), p.u()])
            .collect();
        batch_invert(&mut dens);
        let mont: Vec<(Fq, Fq)> = affine
            .iter()
            .zip(dens.as_chunks::<2>().0)
            .map(|(p, d)| {
                let x = (Fq::ONE + p.v()) * d[0];
                (x, x * d[1] * MONTGOMERY_SCALE)
            })
            .collect();
        PedersenTables(
            mont.chunks_exact(per_segment)
                .map(|segment| segment.as_chunks::<4>().0.to_vec())
                .collect(),
        )
    }
}

/// A point of the twisted Edwards curve.
#[derive(Clone, Copy)]
pub(super) struct EdwardsPoint {
    u: AllocatedNum,
    v: AllocatedNum,
}

/// `[by] base` for a fixed base, three bits at a time; `by` is least
/// significant first and `table` covers its windows.
pub(super) fn fixed_base_multiplication<CS: ConstraintSystem>(
    cs: &mut CS,
    base: &AffinePoint,
    by: &[Boolean],
) -> Result<EdwardsPoint, SynthesisError> {
    let table = fixed_base_table(base, by.len().div_ceil(3));
    let mut result: Option<EdwardsPoint> = None;
    for (chunk, window) in by.chunks(3).zip(&table) {
        let bit = |i: usize| chunk.get(i).copied().unwrap_or(Boolean::Constant(false));
        let (u, v) = lookup3_xy(cs, &[bit(0), bit(1), bit(2)], window)?;
        let p = EdwardsPoint { u, v };
        result = Some(match result {
            None => p,
            Some(acc) => acc.add(cs, &p)?,
        });
    }
    result.ok_or(SynthesisError::Unsatisfiable)
}

impl EdwardsPoint {
    pub(super) fn get_u(&self) -> &AllocatedNum {
        &self.u
    }

    #[cfg(test)]
    pub(super) fn get_v(&self) -> &AllocatedNum {
        &self.v
    }

    /// Asserts the point's order is not 1, 2, 4 or 8: `[8] P` has a
    /// nonzero `u`.
    pub(super) fn assert_not_small_order<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let tmp = self.double(cs)?;
        let tmp = tmp.double(cs)?;
        let tmp = tmp.double(cs)?;
        tmp.u.assert_nonzero(cs)
    }

    /// Exposes both coordinates as public inputs.
    pub(super) fn inputize<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        self.u.inputize(cs)?;
        self.v.inputize(cs)
    }

    /// The 256 bits of the point's canonical encoding: `v`, then the sign
    /// of `u`.
    pub(super) fn repr<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<Boolean>, SynthesisError> {
        let u = self.u.to_bits_le_strict(cs)?;
        let mut tmp = self.v.to_bits_le_strict(cs)?;
        tmp.push(u[0]);
        Ok(tmp)
    }

    /// Allocates a point and checks it is on the curve.
    pub(super) fn witness<CS: ConstraintSystem>(
        cs: &mut CS,
        p: &AffinePoint,
    ) -> Result<Self, SynthesisError> {
        let u = AllocatedNum::alloc(cs, p.u())?;
        let v = AllocatedNum::alloc(cs, p.v())?;
        Self::interpret(cs, &u, &v)
    }

    /// The point if `condition` is set, the identity otherwise.
    fn conditionally_select<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        condition: &Boolean,
    ) -> Result<Self, SynthesisError> {
        let selected = condition.get_value();
        let one = CS::one();

        let u_prime = AllocatedNum::alloc(
            cs,
            if selected {
                self.u.get_value()
            } else {
                Fq::ZERO
            },
        )?;
        cs.enforce(
            |lc| lc + self.u.get_variable(),
            |_| condition.lc(one, Fq::ONE),
            |lc| lc + u_prime.get_variable(),
        );

        let v_prime = AllocatedNum::alloc(
            cs,
            if selected {
                self.v.get_value()
            } else {
                Fq::ONE
            },
        )?;
        cs.enforce(
            |lc| lc + self.v.get_variable(),
            |_| condition.lc(one, Fq::ONE),
            |lc| lc + v_prime.get_variable() - &condition.not().lc(one, Fq::ONE),
        );

        Ok(EdwardsPoint {
            u: u_prime,
            v: v_prime,
        })
    }

    /// `[by] self` by double-and-add; `by` is least significant first.
    pub(super) fn mul<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        by: &[Boolean],
    ) -> Result<Self, SynthesisError> {
        let mut curbase: Option<EdwardsPoint> = None;
        let mut result: Option<EdwardsPoint> = None;
        for bit in by {
            let base = match curbase {
                None => *self,
                Some(base) => base.double(cs)?,
            };
            curbase = Some(base);
            let thisbase = base.conditionally_select(cs, bit)?;
            result = Some(match result {
                None => thisbase,
                Some(acc) => acc.add(cs, &thisbase)?,
            });
        }
        result.ok_or(SynthesisError::Unsatisfiable)
    }

    /// Checks `(u, v)` is on the curve: `-u² + v² = 1 + d·u²·v²`.
    fn interpret<CS: ConstraintSystem>(
        cs: &mut CS,
        u: &AllocatedNum,
        v: &AllocatedNum,
    ) -> Result<Self, SynthesisError> {
        let u2 = u.square(cs)?;
        let v2 = v.square(cs)?;
        let u2v2 = u2.mul(cs, &v2)?;
        let one = CS::one();
        cs.enforce(
            |lc| lc - u2.get_variable() + v2.get_variable(),
            |lc| lc + one,
            |lc| lc + one + (EDWARDS_D, u2v2.get_variable()),
        );
        Ok(EdwardsPoint { u: *u, v: *v })
    }

    /// `[2] self`.
    pub(super) fn double<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<Self, SynthesisError> {
        let (su, sv) = (self.u.get_value(), self.v.get_value());
        let one = CS::one();

        // T = (u + v)²
        let t = AllocatedNum::alloc(cs, (su + sv).square())?;
        cs.enforce(
            |lc| lc + self.u.get_variable() + self.v.get_variable(),
            |lc| lc + self.u.get_variable() + self.v.get_variable(),
            |lc| lc + t.get_variable(),
        );

        // A = u·v
        let a = self.u.mul(cs, &self.v)?;

        // C = d·A²
        let c = AllocatedNum::alloc(cs, a.get_value().square() * EDWARDS_D)?;
        cs.enforce(
            |lc| lc + (EDWARDS_D, a.get_variable()),
            |lc| lc + a.get_variable(),
            |lc| lc + c.get_variable(),
        );

        // u3 = 2A / (1 + C)
        let u3 = AllocatedNum::alloc(cs, div(a.get_value().double(), Fq::ONE + c.get_value())?)?;
        cs.enforce(
            |lc| lc + one + c.get_variable(),
            |lc| lc + u3.get_variable(),
            |lc| lc + a.get_variable() + a.get_variable(),
        );

        // v3 = (T - 2A) / (1 - C)
        let v3 = AllocatedNum::alloc(
            cs,
            div(
                t.get_value() - a.get_value().double(),
                Fq::ONE - c.get_value(),
            )?,
        )?;
        cs.enforce(
            |lc| lc + one - c.get_variable(),
            |lc| lc + v3.get_variable(),
            |lc| lc + t.get_variable() - a.get_variable() - a.get_variable(),
        );

        Ok(EdwardsPoint { u: u3, v: v3 })
    }

    /// `self + other`.
    pub(super) fn add<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        other: &Self,
    ) -> Result<Self, SynthesisError> {
        let one = CS::one();

        // U = (u1 + v1)·(u2 + v2)
        let uppercase_u = AllocatedNum::alloc(
            cs,
            (self.u.get_value() + self.v.get_value()) * (other.u.get_value() + other.v.get_value()),
        )?;
        cs.enforce(
            |lc| lc + self.u.get_variable() + self.v.get_variable(),
            |lc| lc + other.u.get_variable() + other.v.get_variable(),
            |lc| lc + uppercase_u.get_variable(),
        );

        // A = v2·u1, B = u2·v1
        let a = other.v.mul(cs, &self.u)?;
        let b = other.u.mul(cs, &self.v)?;

        // C = d·A·B
        let c = AllocatedNum::alloc(cs, a.get_value() * b.get_value() * EDWARDS_D)?;
        cs.enforce(
            |lc| lc + (EDWARDS_D, a.get_variable()),
            |lc| lc + b.get_variable(),
            |lc| lc + c.get_variable(),
        );

        // u3 = (A + B) / (1 + C)
        let u3 = AllocatedNum::alloc(
            cs,
            div(a.get_value() + b.get_value(), Fq::ONE + c.get_value())?,
        )?;
        cs.enforce(
            |lc| lc + one + c.get_variable(),
            |lc| lc + u3.get_variable(),
            |lc| lc + a.get_variable() + b.get_variable(),
        );

        // v3 = (U - A - B) / (1 - C)
        let v3 = AllocatedNum::alloc(
            cs,
            div(
                uppercase_u.get_value() - a.get_value() - b.get_value(),
                Fq::ONE - c.get_value(),
            )?,
        )?;
        cs.enforce(
            |lc| lc + one - c.get_variable(),
            |lc| lc + v3.get_variable(),
            |lc| lc + uppercase_u.get_variable() - a.get_variable() - b.get_variable(),
        );

        Ok(EdwardsPoint { u: u3, v: v3 })
    }
}

/// A point of the Montgomery form of the curve, with coordinates known as
/// linear combinations.
struct MontgomeryPoint {
    x: Num,
    y: Num,
}

impl MontgomeryPoint {
    /// Converts to the twisted Edwards form: `u = scale·x / y`,
    /// `v = (x - 1) / (x + 1)`.
    fn into_edwards<CS: ConstraintSystem>(
        self,
        cs: &mut CS,
    ) -> Result<EdwardsPoint, SynthesisError> {
        let (x, y) = (self.x.get_value(), self.y.get_value());

        let u = AllocatedNum::alloc(cs, div(x * MONTGOMERY_SCALE, y)?)?;
        cs.enforce(
            |lc| lc + &self.y.lc(Fq::ONE),
            |lc| lc + u.get_variable(),
            |lc| lc + &self.x.lc(MONTGOMERY_SCALE),
        );

        let v = AllocatedNum::alloc(cs, div(x - Fq::ONE, x + Fq::ONE)?)?;
        let one = CS::one();
        cs.enforce(
            |lc| lc + &self.x.lc(Fq::ONE) + one,
            |lc| lc + v.get_variable(),
            |lc| lc + &self.x.lc(Fq::ONE) - one,
        );

        Ok(EdwardsPoint { u, v })
    }

    /// `self + other`, for points with different `x`.
    fn add<CS: ConstraintSystem>(&self, cs: &mut CS, other: &Self) -> Result<Self, SynthesisError> {
        let (x1, y1) = (self.x.get_value(), self.y.get_value());
        let (x2, y2) = (other.x.get_value(), other.y.get_value());

        let lambda = AllocatedNum::alloc(cs, div(y2 - y1, x2 - x1)?)?;
        cs.enforce(
            |lc| lc + &other.x.lc(Fq::ONE) - &self.x.lc(Fq::ONE),
            |lc| lc + lambda.get_variable(),
            |lc| lc + &other.y.lc(Fq::ONE) - &self.y.lc(Fq::ONE),
        );

        let xprime = AllocatedNum::alloc(cs, lambda.get_value().square() - MONTGOMERY_A - x1 - x2)?;
        let one = CS::one();
        cs.enforce(
            |lc| lc + lambda.get_variable(),
            |lc| lc + lambda.get_variable(),
            |lc| {
                lc + (MONTGOMERY_A, one)
                    + &self.x.lc(Fq::ONE)
                    + &other.x.lc(Fq::ONE)
                    + xprime.get_variable()
            },
        );

        let yprime =
            AllocatedNum::alloc(cs, -((xprime.get_value() - x1) * lambda.get_value() + y1))?;
        cs.enforce(
            |lc| lc + &self.x.lc(Fq::ONE) - xprime.get_variable(),
            |lc| lc + lambda.get_variable(),
            |lc| lc + yprime.get_variable() + &self.y.lc(Fq::ONE),
        );

        Ok(MontgomeryPoint {
            x: xprime.into(),
            y: yprime.into(),
        })
    }
}

/// The Pedersen hash of the six personalization bits followed by `bits`.
pub(super) fn pedersen_hash<CS: ConstraintSystem>(
    cs: &mut CS,
    tables: &PedersenTables,
    personalization: [bool; 6],
    bits: &[Boolean],
) -> Result<EdwardsPoint, SynthesisError> {
    let personalization = personalization.map(Boolean::Constant);
    let mut bits = personalization.iter().chain(bits).copied().peekable();
    let mut segments = tables.0.iter();
    let mut edwards_result: Option<EdwardsPoint> = None;

    while bits.peek().is_some() {
        // more input than there are tables for cannot be hashed
        let windows = segments.next().ok_or(SynthesisError::Unsatisfiable)?;
        let mut segment_result: Option<MontgomeryPoint> = None;
        for window in windows {
            let Some(a) = bits.next() else { break };
            let b = bits.next().unwrap_or(Boolean::Constant(false));
            let c = bits.next().unwrap_or(Boolean::Constant(false));
            let (x, y) = lookup3_xy_with_conditional_negation(cs, &[a, b, c], window)?;
            let tmp = MontgomeryPoint { x, y };
            segment_result = Some(match segment_result {
                None => tmp,
                Some(acc) => tmp.add(cs, &acc)?,
            });
        }
        let segment_result = segment_result
            .ok_or(SynthesisError::Unsatisfiable)?
            .into_edwards(cs)?;
        edwards_result = Some(match edwards_result {
            None => segment_result,
            Some(acc) => segment_result.add(cs, &acc)?,
        });
    }
    edwards_result.ok_or(SynthesisError::Unsatisfiable)
}
