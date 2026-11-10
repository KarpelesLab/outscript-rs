//! Elliptic curve gadgets on Pallas (port of `halo2_gadgets::ecc`).
//!
//! The reference is generic over the curve, over an `EccInstructions` chip
//! and over the fixed bases; here there is one chip ([`EccChip`]) on Pallas
//! with the fixed bases of Orchard, and the gadgets call its inherent
//! methods. What vanilla Orchard does not use is left out: `mul_sign` (ZSA)
//! and the full-width variable-base scalar (`ScalarVar::new`), which the
//! reference does not implement either.

use self::chip::{
    EccChip, EccPoint, EccScalarFixed, EccScalarFixedShort, NonIdentityEccPoint,
    OrchardBaseFieldBases, OrchardFixedBasesFull, OrchardShortScalarBases,
};
use crate::orchard::halo2::circuit::{AssignedCell, Layouter};
use crate::orchard::halo2::{Error, Value};
use crate::orchard::{Fp, Fq, pallas};

pub(crate) mod chip;
#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub(crate) use chip::CircuitVersion;

/// An element of the base field used as a scalar for variable-base scalar
/// multiplication.
#[derive(Debug)]
pub(crate) struct ScalarVar {
    chip: EccChip,
    inner: chip::ScalarVar,
}

impl ScalarVar {
    /// Constructs a scalar for variable-base scalar multiplication from a
    /// base field element that is already a variable of the circuit.
    pub(crate) fn from_base(
        chip: EccChip,
        layouter: &mut Layouter<'_>,
        base: &AssignedCell<Fp>,
    ) -> Result<Self, Error> {
        let scalar = chip.scalar_var_from_base(layouter, base);
        scalar.map(|inner| ScalarVar { chip, inner })
    }
}

/// A full-width element of the given elliptic curve's scalar field, to be
/// used for fixed-base scalar multiplication.
#[derive(Debug)]
pub(crate) struct ScalarFixed {
    chip: EccChip,
    inner: EccScalarFixed,
}

impl ScalarFixed {
    /// Constructs a new ScalarFixed with the given value.
    pub(crate) fn new(
        chip: EccChip,
        layouter: &mut Layouter<'_>,
        value: Value<Fq>,
    ) -> Result<Self, Error> {
        let scalar = chip.witness_scalar_fixed(layouter, value);
        scalar.map(|inner| ScalarFixed { chip, inner })
    }
}

/// A signed short element of the scalar field, to be used for fixed-base
/// scalar multiplication.
#[derive(Debug)]
pub(crate) struct ScalarFixedShort {
    chip: EccChip,
    inner: EccScalarFixedShort,
}

impl ScalarFixedShort {
    /// Converts the given signed short scalar (a magnitude and a sign that
    /// already exist as variables in the circuit) into a ScalarFixedShort.
    ///
    /// # Assumptions
    ///
    /// The magnitude is a 64-bit value and the sign is 1 or −1; the chip
    /// constrains both when the scalar is used.
    pub(crate) fn new(
        chip: EccChip,
        layouter: &mut Layouter<'_>,
        magnitude_sign: (AssignedCell<Fp>, AssignedCell<Fp>),
    ) -> Result<Self, Error> {
        let scalar = chip.scalar_fixed_from_signed_short(layouter, magnitude_sign);
        scalar.map(|inner| ScalarFixedShort { chip, inner })
    }
}

/// A non-identity elliptic curve point over the given curve.
#[derive(Clone, Debug)]
pub(crate) struct NonIdentityPoint {
    chip: EccChip,
    inner: NonIdentityEccPoint,
}

impl NonIdentityPoint {
    /// Constructs a new point with the given value.
    pub(crate) fn new(
        chip: EccChip,
        layouter: &mut Layouter<'_>,
        value: Value<pallas::Affine>,
    ) -> Result<Self, Error> {
        let point = chip.witness_point_non_id(layouter, value);
        point.map(|inner| NonIdentityPoint { chip, inner })
    }

    /// Constructs a new point with the given fixed value.
    pub(crate) fn new_from_constant(
        chip: EccChip,
        layouter: &mut Layouter<'_>,
        value: pallas::Affine,
    ) -> Result<Self, Error> {
        let point = chip.witness_point_non_id_from_constant(layouter, value);
        point.map(|inner| NonIdentityPoint { chip, inner })
    }

    /// Constrains this point to be equal in value to another point.
    pub(crate) fn constrain_equal<Other: Into<Point> + Clone>(
        &self,
        layouter: &mut Layouter<'_>,
        other: &Other,
    ) -> Result<(), Error> {
        let other: Point = (other.clone()).into();
        self.chip
            .constrain_equal(layouter, &Point::from(self.clone()).inner, &other.inner)
    }

    /// Returns the inner point.
    pub(crate) fn inner(&self) -> &NonIdentityEccPoint {
        &self.inner
    }

    /// Extracts the x-coordinate of a point.
    pub(crate) fn extract_p(&self) -> X {
        X::from_inner(self.chip, EccChip::extract_p(&self.inner))
    }

    /// Wraps the given point (obtained directly from an instruction) in a
    /// gadget.
    pub(crate) fn from_inner(chip: EccChip, inner: NonIdentityEccPoint) -> Self {
        NonIdentityPoint { chip, inner }
    }

    /// Returns `self + other` using complete addition.
    pub(crate) fn add<Other: Into<Point> + Clone>(
        &self,
        layouter: &mut Layouter<'_>,
        other: &Other,
    ) -> Result<Point, Error> {
        let other: Point = (other.clone()).into();

        assert_eq!(self.chip, other.chip);
        self.chip
            .add(layouter, &self.inner, &other.inner)
            .map(|inner| Point {
                chip: self.chip,
                inner,
            })
    }

    /// Returns `self + other` using incomplete addition.
    /// The arguments are type-constrained not to be the identity point,
    /// and since exceptional cases return an Error, the result also cannot
    /// be the identity point.
    pub(crate) fn add_incomplete(
        &self,
        layouter: &mut Layouter<'_>,
        other: &Self,
    ) -> Result<Self, Error> {
        assert_eq!(self.chip, other.chip);
        self.chip
            .add_incomplete(layouter, &self.inner, &other.inner)
            .map(|inner| NonIdentityPoint {
                chip: self.chip,
                inner,
            })
    }

    /// Returns `[by] self`.
    pub(crate) fn mul(
        &self,
        layouter: &mut Layouter<'_>,
        by: ScalarVar,
    ) -> Result<(Point, ScalarVar), Error> {
        assert_eq!(self.chip, by.chip);
        self.chip
            .mul(layouter, &by.inner, &self.inner.clone())
            .map(|(point, scalar)| {
                (
                    Point {
                        chip: self.chip,
                        inner: point,
                    },
                    ScalarVar {
                        chip: self.chip,
                        inner: scalar,
                    },
                )
            })
    }
}

impl From<NonIdentityPoint> for Point {
    fn from(non_id_point: NonIdentityPoint) -> Self {
        Self {
            chip: non_id_point.chip,
            inner: non_id_point.inner.into(),
        }
    }
}

/// An elliptic curve point over the given curve.
#[derive(Clone, Debug)]
pub(crate) struct Point {
    chip: EccChip,
    inner: EccPoint,
}

impl Point {
    /// Constructs a new point with the given value.
    pub(crate) fn new(
        chip: EccChip,
        layouter: &mut Layouter<'_>,
        value: Value<pallas::Affine>,
    ) -> Result<Self, Error> {
        let point = chip.witness_point(layouter, value);
        point.map(|inner| Point { chip, inner })
    }

    /// Constructs a new point with the given fixed value.
    pub(crate) fn new_from_constant(
        chip: EccChip,
        layouter: &mut Layouter<'_>,
        value: pallas::Affine,
    ) -> Result<Self, Error> {
        let point = chip.witness_point_from_constant(layouter, value);
        point.map(|inner| Point { chip, inner })
    }

    /// Constrains this point to be equal in value to another point.
    pub(crate) fn constrain_equal<Other: Into<Point> + Clone>(
        &self,
        layouter: &mut Layouter<'_>,
        other: &Other,
    ) -> Result<(), Error> {
        let other: Point = (other.clone()).into();
        self.chip
            .constrain_equal(layouter, &self.inner, &other.inner)
    }

    /// Returns the inner point.
    pub(crate) fn inner(&self) -> &EccPoint {
        &self.inner
    }

    /// Extracts the x-coordinate of a point.
    pub(crate) fn extract_p(&self) -> X {
        X::from_inner(self.chip, EccChip::extract_p(&self.inner))
    }

    /// Wraps the given point (obtained directly from an instruction) in a
    /// gadget.
    pub(crate) fn from_inner(chip: EccChip, inner: EccPoint) -> Self {
        Point { chip, inner }
    }

    /// Returns `self + other` using complete addition.
    pub(crate) fn add<Other: Into<Point> + Clone>(
        &self,
        layouter: &mut Layouter<'_>,
        other: &Other,
    ) -> Result<Point, Error> {
        let other: Point = (other.clone()).into();

        assert_eq!(self.chip, other.chip);
        self.chip
            .add(layouter, &self.inner, &other.inner)
            .map(|inner| Point {
                chip: self.chip,
                inner,
            })
    }
}

/// The affine short Weierstrass x-coordinate of an elliptic curve point
/// over the given curve.
#[derive(Debug)]
pub(crate) struct X {
    inner: AssignedCell<Fp>,
}

impl X {
    /// Wraps the given x-coordinate (obtained directly from an instruction)
    /// in a gadget.
    pub(crate) fn from_inner(chip: EccChip, inner: AssignedCell<Fp>) -> Self {
        let _ = chip; // unused
        X { inner }
    }

    /// Returns the inner x-coordinate.
    pub(crate) fn inner(&self) -> &AssignedCell<Fp> {
        &self.inner
    }
}

/// Precomputed multiples of a fixed point, for full-width scalar
/// multiplication.
///
/// Fixing the curve point enables window tables to be baked into the
/// circuit, making scalar multiplication more efficient. These window
/// tables are tuned to full-width scalar multiplication.
#[derive(Clone, Debug)]
pub(crate) struct FixedPoint {
    chip: EccChip,
    inner: OrchardFixedBasesFull,
}

/// Precomputed multiples of a fixed point, that can be multiplied by base
/// field elements.
///
/// Fixing the curve point enables window tables to be baked into the
/// circuit, making scalar multiplication more efficient. These window
/// tables are tuned to scalar multiplication by base field elements.
#[derive(Clone, Debug)]
pub(crate) struct FixedPointBaseField {
    chip: EccChip,
    inner: OrchardBaseFieldBases,
}

/// Precomputed multiples of a fixed point, for short signed scalar
/// multiplication.
#[derive(Clone, Debug)]
pub(crate) struct FixedPointShort {
    chip: EccChip,
    inner: OrchardShortScalarBases,
}

impl FixedPoint {
    /// Returns `[by] self`.
    pub(crate) fn mul(
        &self,
        layouter: &mut Layouter<'_>,
        by: ScalarFixed,
    ) -> Result<(Point, ScalarFixed), Error> {
        assert_eq!(self.chip, by.chip);
        self.chip
            .mul_fixed(layouter, &by.inner, &self.inner)
            .map(|(point, scalar)| {
                (
                    Point {
                        chip: self.chip,
                        inner: point,
                    },
                    ScalarFixed {
                        chip: self.chip,
                        inner: scalar,
                    },
                )
            })
    }

    /// Wraps the given fixed base (obtained directly from an instruction)
    /// in a gadget.
    pub(crate) fn from_inner(chip: EccChip, inner: OrchardFixedBasesFull) -> Self {
        Self { chip, inner }
    }
}

impl FixedPointBaseField {
    /// Returns `[by] self`.
    pub(crate) fn mul(
        &self,
        layouter: &mut Layouter<'_>,
        by: AssignedCell<Fp>,
    ) -> Result<Point, Error> {
        self.chip
            .mul_fixed_base_field_elem(layouter, by, &self.inner)
            .map(|inner| Point {
                chip: self.chip,
                inner,
            })
    }

    /// Wraps the given fixed base (obtained directly from an instruction)
    /// in a gadget.
    pub(crate) fn from_inner(chip: EccChip, inner: impl Into<OrchardBaseFieldBases>) -> Self {
        Self {
            chip,
            inner: inner.into(),
        }
    }
}

impl FixedPointShort {
    /// Returns `[by] self`.
    pub(crate) fn mul(
        &self,
        layouter: &mut Layouter<'_>,
        by: ScalarFixedShort,
    ) -> Result<(Point, ScalarFixedShort), Error> {
        assert_eq!(self.chip, by.chip);
        self.chip
            .mul_fixed_short(layouter, &by.inner, &self.inner)
            .map(|(point, scalar)| {
                (
                    Point {
                        chip: self.chip,
                        inner: point,
                    },
                    ScalarFixedShort {
                        chip: self.chip,
                        inner: scalar,
                    },
                )
            })
    }

    /// Wraps the given fixed base (obtained directly from an instruction)
    /// in a gadget.
    pub(crate) fn from_inner(chip: EccChip, inner: impl Into<OrchardShortScalarBases>) -> Self {
        Self {
            chip,
            inner: inner.into(),
        }
    }
}
