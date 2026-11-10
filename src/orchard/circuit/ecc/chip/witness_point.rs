//! Witnessing a point (port of `halo2_gadgets::ecc::chip::witness_point`).

use super::{EccPoint, NonIdentityEccPoint};
use crate::orchard::halo2::circuit::{AssignedCell, Region};
use crate::orchard::halo2::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Expression, Rotation, Selector, VirtualCells,
};
use crate::orchard::halo2::{Error, Value};
use crate::orchard::{Fp, pallas};

type Coordinates = (AssignedCell<Fp>, AssignedCell<Fp>);

/// The configuration of the point witnessing gates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Config {
    q_point: Selector,
    q_point_non_id: Selector,
    // x-coordinate
    pub(crate) x: Column<Advice>,
    // y-coordinate
    pub(crate) y: Column<Advice>,
}

/// The coordinates of a point, (0, 0) for the identity.
fn coordinates(value: pallas::Affine) -> (Fp, Fp) {
    if bool::from(value.is_identity()) {
        (Fp::ZERO, Fp::ZERO)
    } else {
        (value.x(), value.y())
    }
}

impl Config {
    pub(super) fn configure(
        meta: &mut ConstraintSystem,
        x: Column<Advice>,
        y: Column<Advice>,
    ) -> Self {
        let config = Self {
            q_point: meta.selector(),
            q_point_non_id: meta.selector(),
            x,
            y,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) {
        let curve_eqn = |meta: &mut VirtualCells<'_>| {
            let x = meta.query_advice(self.x, Rotation::cur());
            let y = meta.query_advice(self.y, Rotation::cur());

            // y^2 = x^3 + b
            y.square() - (x.clone().square() * x) - Expression::Constant(pallas::B)
        };

        // https://p.z.cash/halo2-0.1:ecc-witness-point
        meta.create_gate("witness point", |meta| {
            // Check that the point being witnessed is either:
            // - the identity, which is mapped to (0, 0) in affine coordinates; or
            // - a valid curve point y^2 = x^3 + b, where b = 5 in the Pallas equation

            let q_point = meta.query_selector(self.q_point);
            let x = meta.query_advice(self.x, Rotation::cur());
            let y = meta.query_advice(self.y, Rotation::cur());

            // We can't use `Constraints::with_selector` because that creates
            // constraints of the form `q_point * (x * curve_eqn)`, but this
            // was implemented without parentheses, and thus evaluates as
            // `(q_point * x) * curve_eqn`, which is structurally different
            // in the pinned verifying key.
            [
                // x == 0 v on_curve
                q_point.clone() * x * curve_eqn(meta),
                // y == 0 v on_curve
                q_point * y * curve_eqn(meta),
            ]
        });

        // https://p.z.cash/halo2-0.1:ecc-witness-non-identity-point
        meta.create_gate("witness non-identity point", |meta| {
            // Check that the point being witnessed is a valid curve point
            // y^2 = x^3 + b, where b = 5 in the Pallas equation

            let q_point_non_id = meta.query_selector(self.q_point_non_id);

            // on_curve
            Constraints::with_selector(q_point_non_id, Some(curve_eqn(meta)))
        });
    }

    fn assign_xy(
        &self,
        value: Value<(Fp, Fp)>,
        offset: usize,
        region: &mut Region<'_, '_>,
    ) -> Result<Coordinates, Error> {
        // Assign `x` value
        let x_val = value.map(|value| value.0);
        let x_var = region.assign_advice(self.x, offset, || x_val)?;

        // Assign `y` value
        let y_val = value.map(|value| value.1);
        let y_var = region.assign_advice(self.y, offset, || y_val)?;

        Ok((x_var, y_var))
    }

    #[cfg(test)]
    fn assign_xy_from_constant(
        &self,
        value: (Fp, Fp),
        offset: usize,
        region: &mut Region<'_, '_>,
    ) -> Result<Coordinates, Error> {
        // Assign `x` value
        let x_var = region.assign_advice_from_constant(self.x, offset, value.0)?;

        // Assign `y` value
        let y_var = region.assign_advice_from_constant(self.y, offset, value.1)?;

        Ok((x_var, y_var))
    }

    /// Assigns a point that can be the identity.
    pub(super) fn point(
        &self,
        value: Value<pallas::Affine>,
        offset: usize,
        region: &mut Region<'_, '_>,
    ) -> Result<EccPoint, Error> {
        // Enable `q_point` selector
        self.q_point.enable(region, offset)?;

        let value = value.map(coordinates);

        self.assign_xy(value, offset, region)
            .map(|(x, y)| EccPoint::from_coordinates_unchecked(x, y))
    }

    /// Assigns a constant point that can be the identity.
    #[cfg(test)]
    pub(super) fn constant_point(
        &self,
        value: pallas::Affine,
        offset: usize,
        region: &mut Region<'_, '_>,
    ) -> Result<EccPoint, Error> {
        // Enable `q_point` selector
        self.q_point.enable(region, offset)?;

        let value = coordinates(value);

        self.assign_xy_from_constant(value, offset, region)
            .map(|(x, y)| EccPoint::from_coordinates_unchecked(x, y))
    }

    /// Assigns a nonidentity point.
    pub(super) fn point_non_id(
        &self,
        value: Value<pallas::Affine>,
        offset: usize,
        region: &mut Region<'_, '_>,
    ) -> Result<NonIdentityEccPoint, Error> {
        // Enable `q_point_non_id` selector
        self.q_point_non_id.enable(region, offset)?;

        // Return an error if the point is the identity.
        value.error_if_known_and(|value| bool::from(value.is_identity()))?;

        let value = value.map(|value| (value.x(), value.y()));

        self.assign_xy(value, offset, region)
            .map(|(x, y)| NonIdentityEccPoint::from_coordinates_unchecked(x, y))
    }

    /// Assigns a constant nonidentity point.
    #[cfg(test)]
    pub(super) fn constant_point_non_id(
        &self,
        value: pallas::Affine,
        offset: usize,
        region: &mut Region<'_, '_>,
    ) -> Result<NonIdentityEccPoint, Error> {
        // Enable `q_point_non_id` selector
        self.q_point_non_id.enable(region, offset)?;

        // Return an error if the point is the identity.
        if bool::from(value.is_identity()) {
            return Err(Error::Synthesis);
        }

        let value = (value.x(), value.y());

        self.assign_xy_from_constant(value, offset, region)
            .map(|(x, y)| NonIdentityEccPoint::from_coordinates_unchecked(x, y))
    }
}
