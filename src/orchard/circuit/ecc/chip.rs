//! The chip implementing the elliptic curve gadgets (port of
//! `halo2_gadgets::ecc::chip`).

use crate::orchard::halo2::Value;
use crate::orchard::halo2::circuit::AssignedCell;
use crate::orchard::{Fp, pallas};

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
