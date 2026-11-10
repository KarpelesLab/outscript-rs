//! The chip implementing the elliptic curve gadgets (port of
//! `halo2_gadgets::ecc::chip`).

use alloc::vec::Vec;

use crate::orchard::circuit::utilities::lookup_range_check::LookupRangeCheckConfig;
use crate::orchard::halo2::circuit::{AssignedCell, Layouter};
use crate::orchard::halo2::plonk::{Advice, Column, ConstraintSystem, Fixed};
use crate::orchard::halo2::{Error, Value};
use crate::orchard::{Fp, Fq, pallas};

pub(super) mod add;
pub(super) mod add_incomplete;
pub(crate) mod constants;
pub(crate) mod fixed_bases;
pub(super) mod mul;
pub(super) mod mul_fixed;
pub(super) mod witness_point;

pub(crate) use constants::*;
// (Some of these are only used by the other gadgets.)
#[allow(unused_imports)]
pub(crate) use fixed_bases::{
    FixedPoint, NullifierK, OrchardBaseFieldBases, OrchardFixedBasesFull, OrchardShortScalarBases,
    ValueCommitV,
};
#[allow(unused_imports)]
pub(crate) use mul::incomplete::DoubleAndAdd;

/// Which version of the variable-base scalar multiplication circuit to
/// build.
///
/// The original Orchard circuit (the "insecure" circuit) left the base
/// point `(x_p, y_p)` of the incomplete-addition rows as an unconstrained
/// witness instead of copy-constraining it to the base of the
/// multiplication. `AnchoredBase` closes that gap; the two versions have
/// different verifying keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CircuitVersion {
    /// The original circuit, with the unanchored base. It is unsound: only
    /// for the proofs made before the fix.
    InsecureUnanchoredBase,
    /// The fixed circuit: the first incomplete-addition row copies the base.
    AnchoredBase,
}

/// A curve point represented in affine (x, y) coordinates, or the identity
/// represented as (0, 0). Each coordinate is assigned to a cell.
#[derive(Clone, Debug)]
pub(crate) struct EccPoint {
    /// x-coordinate
    x: AssignedCell<Fp>,
    /// y-coordinate
    y: AssignedCell<Fp>,
}

impl EccPoint {
    /// Constructs a point from its coordinates, without checking they are
    /// on the curve.
    pub(crate) fn from_coordinates_unchecked(x: AssignedCell<Fp>, y: AssignedCell<Fp>) -> Self {
        EccPoint { x, y }
    }

    /// Returns the value of this curve point, if known.
    #[cfg(test)]
    pub(crate) fn point(&self) -> Value<pallas::Affine> {
        self.x.value().zip(self.y.value()).map(|(x, y)| {
            if bool::from(x.is_zero()) && bool::from(y.is_zero()) {
                pallas::Affine::IDENTITY
            } else {
                pallas::Affine::from_xy(*x, *y).expect("on the curve")
            }
        })
    }

    /// The cell containing the affine x-coordinate, or 0 for the identity.
    pub(crate) fn x(&self) -> AssignedCell<Fp> {
        self.x.clone()
    }

    /// The cell containing the affine y-coordinate, or 0 for the identity.
    pub(crate) fn y(&self) -> AssignedCell<Fp> {
        self.y.clone()
    }

    /// Whether the point is the identity, if known.
    #[cfg(test)]
    pub(crate) fn is_identity(&self) -> Value<bool> {
        self.x.value().map(|x| bool::from(x.is_zero()))
    }
}

/// A non-identity point represented in affine (x, y) coordinates. Each
/// coordinate is assigned to a cell.
#[derive(Clone, Debug)]
pub(crate) struct NonIdentityEccPoint {
    /// x-coordinate
    x: AssignedCell<Fp>,
    /// y-coordinate
    y: AssignedCell<Fp>,
}

impl NonIdentityEccPoint {
    /// Constructs a point from its coordinates, without checking they are
    /// on the curve.
    pub(crate) fn from_coordinates_unchecked(x: AssignedCell<Fp>, y: AssignedCell<Fp>) -> Self {
        NonIdentityEccPoint { x, y }
    }

    /// Returns the value of this curve point, if known.
    #[cfg(test)]
    pub(crate) fn point(&self) -> Value<pallas::Affine> {
        self.x.value().zip(self.y.value()).map(|(x, y)| {
            assert!(!bool::from(x.is_zero()) && !bool::from(y.is_zero()));
            pallas::Affine::from_xy(*x, *y).expect("on the curve")
        })
    }

    /// The cell containing the affine x-coordinate.
    pub(crate) fn x(&self) -> AssignedCell<Fp> {
        self.x.clone()
    }

    /// The cell containing the affine y-coordinate.
    pub(crate) fn y(&self) -> AssignedCell<Fp> {
        self.y.clone()
    }
}

impl From<NonIdentityEccPoint> for EccPoint {
    fn from(non_id_point: NonIdentityEccPoint) -> Self {
        Self {
            x: non_id_point.x,
            y: non_id_point.y,
        }
    }
}

/// Configuration for [`EccChip`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EccConfig {
    /// Advice columns needed by instructions in the ECC chip.
    pub(crate) advices: [Column<Advice>; 10],

    /// Incomplete addition
    add_incomplete: add_incomplete::Config,

    /// Complete addition
    add: add::Config,

    /// Variable-base scalar multiplication
    mul: mul::Config,

    /// Fixed-base full-width scalar multiplication
    mul_fixed_full: mul_fixed::full_width::Config,
    /// Fixed-base signed short scalar multiplication
    mul_fixed_short: mul_fixed::short::Config,
    /// Fixed-base mul using a base field element as a scalar
    mul_fixed_base_field: mul_fixed::base_field_elem::Config,

    /// Witness point
    witness_point: witness_point::Config,

    /// Lookup range check using 10-bit lookup table
    pub(crate) lookup_config: LookupRangeCheckConfig,
}

/// A chip implementing the elliptic curve instructions on 10 advice columns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EccChip {
    config: EccConfig,
    circuit_version: CircuitVersion,
}

impl EccChip {
    /// Reconstructs this chip from the given config.
    pub(crate) fn construct(config: EccConfig, circuit_version: CircuitVersion) -> Self {
        Self {
            config,
            circuit_version,
        }
    }

    /// The configuration of the chip.
    pub(crate) fn config(&self) -> &EccConfig {
        &self.config
    }

    /// # Side effects
    ///
    /// All columns in `advices` will be equality-enabled.
    #[allow(non_snake_case)]
    pub(crate) fn configure(
        meta: &mut ConstraintSystem,
        advices: [Column<Advice>; 10],
        lagrange_coeffs: [Column<Fixed>; 8],
        range_check: LookupRangeCheckConfig,
    ) -> EccConfig {
        // Create witness point gate
        let witness_point = witness_point::Config::configure(meta, advices[0], advices[1]);
        // Create incomplete point addition gate
        let add_incomplete =
            add_incomplete::Config::configure(meta, advices[0], advices[1], advices[2], advices[3]);

        // Create complete point addition gate
        let add = add::Config::configure(
            meta, advices[0], advices[1], advices[2], advices[3], advices[4], advices[5],
            advices[6], advices[7], advices[8],
        );

        // Create variable-base scalar mul gates
        let mul = mul::Config::configure(meta, add, range_check, advices);

        // Create config that is shared across short, base-field, and full-width
        // fixed-base scalar mul.
        let mul_fixed = mul_fixed::Config::configure(
            meta,
            lagrange_coeffs,
            advices[4],
            advices[5],
            add,
            add_incomplete,
        );

        // Create gate that is only used in full-width fixed-base scalar mul.
        let mul_fixed_full = mul_fixed::full_width::Config::configure(meta, mul_fixed);

        // Create gate that is only used in short fixed-base scalar mul.
        let mul_fixed_short = mul_fixed::short::Config::configure(meta, mul_fixed);

        // Create gate that is only used in fixed-base mul using a base field element.
        let mul_fixed_base_field = mul_fixed::base_field_elem::Config::configure(
            meta,
            [advices[6], advices[7], advices[8]],
            range_check,
            mul_fixed,
        );

        EccConfig {
            advices,
            add_incomplete,
            add,
            mul,
            mul_fixed_full,
            mul_fixed_short,
            mul_fixed_base_field,
            witness_point,
            lookup_config: range_check,
        }
    }
}

/// A full-width scalar used for fixed-base scalar multiplication.
/// This is decomposed into 85 3-bit windows in little-endian order,
/// i.e. `windows` = [k_0, k_1, ..., k_84] (for a 255-bit scalar)
/// where `scalar = k_0 + k_1 * (2^3) + ... + k_84 * (2^3)^84` and
/// each `k_i` is in the range [0..2^3).
#[derive(Clone, Debug)]
pub(crate) struct EccScalarFixed {
    value: Value<Fq>,
    /// The circuit-assigned windows representing this scalar, or `None` if
    /// the scalar has not been used yet.
    windows: Option<Vec<AssignedCell<Fp>>>,
}

// TODO: Make V a `u64`
type MagnitudeCell = AssignedCell<Fp>;
// TODO: Make V an enum Sign { Positive, Negative }
type SignCell = AssignedCell<Fp>;
/// The magnitude and the sign (1 or -1) of a signed short scalar.
pub(crate) type MagnitudeSign = (MagnitudeCell, SignCell);

/// A signed short scalar used for fixed-base scalar multiplication.
/// A short scalar must have magnitude in the range [0..2^64), with
/// a sign of either 1 or -1.
/// This is decomposed into 3-bit windows in little-endian order
/// using a running sum `z`, where z_{i+1} = (z_i - a_i) / (2^3)
/// for element α = a_0 + (2^3) a_1 + ... + (2^{3(n-1)}) a_{n-1}.
/// Each `a_i` is in the range [0..2^3).
///
/// `windows` = [k_0, k_1, ..., k_21] (for a 64-bit magnitude)
/// where `scalar = k_0 + k_1 * (2^3) + ... + k_84 * (2^3)^84` and
/// each `k_i` is in the range [0..2^3).
/// k_21 must be a single bit, i.e. 0 or 1.
#[derive(Clone, Debug)]
pub(crate) struct EccScalarFixedShort {
    magnitude: MagnitudeCell,
    sign: SignCell,
    /// The circuit-assigned running sum constraining this signed short
    /// scalar (`NUM_WINDOWS_SHORT + 1` cells), or `None` if the scalar has
    /// not been used yet.
    running_sum: Option<Vec<AssignedCell<Fp>>>,
}

/// A base field element used for fixed-base scalar multiplication.
/// This is decomposed into 3-bit windows in little-endian order
/// using a running sum `z`, where z_{i+1} = (z_i - a_i) / (2^3)
/// for element α = a_0 + (2^3) a_1 + ... + (2^{3(n-1)}) a_{n-1}.
/// Each `a_i` is in the range [0..2^3).
///
/// `running_sum` = [z_0, ..., z_85], where we expect z_85 = 0.
/// Since z_0 is initialized as the scalar α, we store it as
/// `base_field_elem`.
#[derive(Clone, Debug)]
struct EccBaseFieldElemFixed {
    base_field_elem: AssignedCell<Fp>,
    running_sum: Vec<AssignedCell<Fp>>,
}

impl EccBaseFieldElemFixed {
    #[cfg(test)]
    fn base_field_elem(&self) -> AssignedCell<Fp> {
        self.base_field_elem.clone()
    }
}

/// An enumeration of the possible types of scalars used in variable-base
/// multiplication. (The reference also declares a full-width scalar, which
/// it does not implement.)
#[derive(Clone, Debug)]
pub(crate) enum ScalarVar {
    /// An element of the elliptic curve's base field, that is used as a
    /// scalar in variable-base scalar mul.
    ///
    /// It is not true in general that a scalar field element fits in a
    /// curve's base field, and in particular it is untrue for the Pallas
    /// curve, whose scalar field `Fq` is larger than its base field `Fp`.
    ///
    /// However, the only use of variable-base scalar mul in the Orchard
    /// protocol is in deriving diversified addresses `[ivk] g_d`, and `ivk`
    /// is guaranteed to be in the base field of the curve. (See
    /// non-normative notes in [4.2.3 Orchard Key Components][orchardkeycomponents].)
    ///
    /// [orchardkeycomponents]: https://zips.z.cash/protocol/protocol.pdf#orchardkeycomponents
    BaseFieldElem(AssignedCell<Fp>),
}

/// The elliptic curve instructions (`EccInstructions` and
/// `BaseFitsInScalarInstructions` of the reference).
impl EccChip {
    /// Constrains point `a` to be equal in value to point `b`.
    pub(crate) fn constrain_equal(
        &self,
        layouter: &mut Layouter<'_>,
        a: &EccPoint,
        b: &EccPoint,
    ) -> Result<(), Error> {
        layouter.assign_region(|mut region| {
            region.constrain_equal(a.x().cell(), b.x().cell())?;
            region.constrain_equal(a.y().cell(), b.y().cell())
        })
    }

    /// Witnesses the given point as a private input to the circuit.
    /// This allows the point to be the identity, mapped to (0, 0) in
    /// affine coordinates.
    pub(crate) fn witness_point(
        &self,
        layouter: &mut Layouter<'_>,
        value: Value<pallas::Affine>,
    ) -> Result<EccPoint, Error> {
        let config = self.config().witness_point;
        layouter.assign_region(|mut region| config.point(value, 0, &mut region))
    }

    /// Witnesses the given constant point as a private input to the circuit.
    /// This allows the point to be the identity, mapped to (0, 0) in
    /// affine coordinates.
    #[cfg(test)]
    pub(crate) fn witness_point_from_constant(
        &self,
        layouter: &mut Layouter<'_>,
        value: pallas::Affine,
    ) -> Result<EccPoint, Error> {
        let config = self.config().witness_point;
        layouter.assign_region(|mut region| config.constant_point(value, 0, &mut region))
    }

    /// Witnesses the given point as a private input to the circuit.
    /// This returns an error if the point is the identity.
    pub(crate) fn witness_point_non_id(
        &self,
        layouter: &mut Layouter<'_>,
        value: Value<pallas::Affine>,
    ) -> Result<NonIdentityEccPoint, Error> {
        let config = self.config().witness_point;
        layouter.assign_region(|mut region| config.point_non_id(value, 0, &mut region))
    }

    /// Witnesses the given constant point as a private input to the circuit.
    /// This returns an error if the point is the identity.
    #[cfg(test)]
    pub(crate) fn witness_point_non_id_from_constant(
        &self,
        layouter: &mut Layouter<'_>,
        value: pallas::Affine,
    ) -> Result<NonIdentityEccPoint, Error> {
        let config = self.config().witness_point;
        layouter.assign_region(|mut region| config.constant_point_non_id(value, 0, &mut region))
    }

    /// Witnesses a full-width scalar to be used in fixed-base
    /// multiplication.
    pub(crate) fn witness_scalar_fixed(
        &self,
        _layouter: &mut Layouter<'_>,
        value: Value<Fq>,
    ) -> Result<EccScalarFixed, Error> {
        Ok(EccScalarFixed {
            value,
            // This chip uses lazy witnessing.
            windows: None,
        })
    }

    /// Converts a magnitude and sign that exists as variables in the circuit
    /// into a signed short scalar to be used in fixed-base scalar
    /// multiplication.
    pub(crate) fn scalar_fixed_from_signed_short(
        &self,
        _layouter: &mut Layouter<'_>,
        (magnitude, sign): MagnitudeSign,
    ) -> Result<EccScalarFixedShort, Error> {
        Ok(EccScalarFixedShort {
            magnitude,
            sign,
            // This chip uses lazy constraining.
            running_sum: None,
        })
    }

    /// Extracts the x-coordinate of a point.
    pub(crate) fn extract_p<Point: Into<EccPoint> + Clone>(point: &Point) -> AssignedCell<Fp> {
        let point: EccPoint = (point.clone()).into();
        point.x()
    }

    /// Performs incomplete point addition, returning `a + b`.
    ///
    /// This returns an error in exceptional cases.
    #[cfg(test)]
    pub(crate) fn add_incomplete(
        &self,
        layouter: &mut Layouter<'_>,
        a: &NonIdentityEccPoint,
        b: &NonIdentityEccPoint,
    ) -> Result<NonIdentityEccPoint, Error> {
        let config = self.config().add_incomplete;
        layouter.assign_region(|mut region| config.assign_region(a, b, 0, &mut region))
    }

    /// Performs complete point addition, returning `a + b`.
    pub(crate) fn add<A: Into<EccPoint> + Clone, B: Into<EccPoint> + Clone>(
        &self,
        layouter: &mut Layouter<'_>,
        a: &A,
        b: &B,
    ) -> Result<EccPoint, Error> {
        let config = self.config().add;
        layouter.assign_region(|mut region| {
            config.assign_region(&(a.clone()).into(), &(b.clone()).into(), 0, &mut region)
        })
    }

    /// Performs variable-base scalar multiplication, returning `[scalar]
    /// base`.
    pub(crate) fn mul(
        &self,
        layouter: &mut Layouter<'_>,
        scalar: &ScalarVar,
        base: &NonIdentityEccPoint,
    ) -> Result<(EccPoint, ScalarVar), Error> {
        let config = self.config().mul;
        match scalar {
            ScalarVar::BaseFieldElem(scalar) => config.assign(
                layouter.namespace(),
                scalar.clone(),
                base,
                self.circuit_version,
            ),
        }
    }

    /// Performs fixed-base scalar multiplication using a full-width scalar,
    /// returning `[scalar] base`.
    pub(crate) fn mul_fixed(
        &self,
        layouter: &mut Layouter<'_>,
        scalar: &EccScalarFixed,
        base: &OrchardFixedBasesFull,
    ) -> Result<(EccPoint, EccScalarFixed), Error> {
        let config = self.config().mul_fixed_full;
        config.assign(layouter.namespace(), scalar, base)
    }

    /// Performs fixed-base scalar multiplication using a short signed
    /// scalar, returning `[scalar] base`.
    pub(crate) fn mul_fixed_short(
        &self,
        layouter: &mut Layouter<'_>,
        scalar: &EccScalarFixedShort,
        base: &OrchardShortScalarBases,
    ) -> Result<(EccPoint, EccScalarFixedShort), Error> {
        let config = self.config().mul_fixed_short;
        config.assign(layouter.namespace(), scalar, base)
    }

    /// Performs fixed-base scalar multiplication using a base field element
    /// as the scalar. In the current implementation, this base field element
    /// must be output from another instruction.
    pub(crate) fn mul_fixed_base_field_elem(
        &self,
        layouter: &mut Layouter<'_>,
        base_field_elem: AssignedCell<Fp>,
        base: &OrchardBaseFieldBases,
    ) -> Result<EccPoint, Error> {
        let config = self.config().mul_fixed_base_field;
        config.assign(layouter.namespace(), base_field_elem, base)
    }

    /// Converts a base field element that exists as a variable in the
    /// circuit into a scalar to be used in variable-base scalar mul.
    pub(crate) fn scalar_var_from_base(
        &self,
        _layouter: &mut Layouter<'_>,
        base: &AssignedCell<Fp>,
    ) -> Result<ScalarVar, Error> {
        Ok(ScalarVar::BaseFieldElem(base.clone()))
    }
}
