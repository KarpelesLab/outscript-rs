//! Incomplete point addition (port of
//! `halo2_gadgets::ecc::chip::add_incomplete`).

use super::NonIdentityEccPoint;
use crate::orchard::Fp;
use crate::orchard::halo2::Error;
use crate::orchard::halo2::circuit::Region;
use crate::orchard::halo2::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Rotation, Selector,
};

/// The configuration of the incomplete addition gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Config {
    q_add_incomplete: Selector,
    // x-coordinate of P in P + Q = R
    pub(crate) x_p: Column<Advice>,
    // y-coordinate of P in P + Q = R
    pub(crate) y_p: Column<Advice>,
    // x-coordinate of Q or R in P + Q = R
    pub(crate) x_qr: Column<Advice>,
    // y-coordinate of Q or R in P + Q = R
    pub(crate) y_qr: Column<Advice>,
}

impl Config {
    pub(super) fn configure(
        meta: &mut ConstraintSystem,
        x_p: Column<Advice>,
        y_p: Column<Advice>,
        x_qr: Column<Advice>,
        y_qr: Column<Advice>,
    ) -> Self {
        meta.enable_equality(x_p);
        meta.enable_equality(y_p);
        meta.enable_equality(x_qr);
        meta.enable_equality(y_qr);

        let config = Self {
            q_add_incomplete: meta.selector(),
            x_p,
            y_p,
            x_qr,
            y_qr,
        };

        config.create_gate(meta);

        config
    }

    /// The advice columns of the gate.
    pub(crate) fn advice_columns(&self) -> [Column<Advice>; 4] {
        [self.x_p, self.y_p, self.x_qr, self.y_qr]
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) {
        // https://p.z.cash/halo2-0.1:ecc-incomplete-addition
        meta.create_gate("incomplete addition", |meta| {
            let q_add_incomplete = meta.query_selector(self.q_add_incomplete);
            let x_p = meta.query_advice(self.x_p, Rotation::cur());
            let y_p = meta.query_advice(self.y_p, Rotation::cur());
            let x_q = meta.query_advice(self.x_qr, Rotation::cur());
            let y_q = meta.query_advice(self.y_qr, Rotation::cur());
            let x_r = meta.query_advice(self.x_qr, Rotation::next());
            let y_r = meta.query_advice(self.y_qr, Rotation::next());

            // (x_r + x_q + x_p)⋅(x_p − x_q)^2 − (y_p − y_q)^2 = 0
            let poly1 = {
                (x_r.clone() + x_q.clone() + x_p.clone())
                    * (x_p.clone() - x_q.clone())
                    * (x_p.clone() - x_q.clone())
                    - (y_p.clone() - y_q.clone()).square()
            };

            // (y_r + y_q)(x_p − x_q) − (y_p − y_q)(x_q − x_r) = 0
            let poly2 = (y_r + y_q.clone()) * (x_p - x_q.clone()) - (y_p - y_q) * (x_q - x_r);

            // x_r, y_r
            Constraints::with_selector(q_add_incomplete, [poly1, poly2])
        });
    }

    pub(super) fn assign_region(
        &self,
        p: &NonIdentityEccPoint,
        q: &NonIdentityEccPoint,
        offset: usize,
        region: &mut Region<'_, '_>,
    ) -> Result<NonIdentityEccPoint, Error> {
        // Enable `q_add_incomplete` selector
        self.q_add_incomplete.enable(region, offset)?;

        // Handle exceptional cases
        let (x_p, y_p) = (p.x.value().copied(), p.y.value().copied());
        let (x_q, y_q) = (q.x.value().copied(), q.y.value().copied());
        x_p.zip(y_p)
            .zip(x_q)
            .zip(y_q)
            .error_if_known_and(|(((x_p, y_p), x_q), y_q)| {
                // P is point at infinity
                (*x_p == Fp::ZERO && *y_p == Fp::ZERO)
                // Q is point at infinity
                || (*x_q == Fp::ZERO && *y_q == Fp::ZERO)
                // x_p = x_q
                || (x_p == x_q)
            })?;

        // Copy point `p` into `x_p`, `y_p` columns
        p.x.copy_advice(region, self.x_p, offset)?;
        p.y.copy_advice(region, self.y_p, offset)?;

        // Copy point `q` into `x_qr`, `y_qr` columns
        q.x.copy_advice(region, self.x_qr, offset)?;
        q.y.copy_advice(region, self.y_qr, offset)?;

        // Compute the sum `P + Q = R`
        let r = x_p
            .zip(y_p)
            .zip(x_q)
            .zip(y_q)
            .map(|(((x_p, y_p), x_q), y_q)| {
                // We can invert `(x_q - x_p)` because we rejected the
                // `x_q == x_p` case.
                let lambda = (y_q - y_p) * (x_q - x_p).invert_or_zero();
                let x_r = lambda.square() - x_p - x_q;
                let y_r = lambda * (x_p - x_r) - y_p;
                (x_r, y_r)
            });

        // Assign the sum to `x_qr`, `y_qr` columns in the next row
        let x_r = r.map(|r| r.0);
        let x_r_var = region.assign_advice(self.x_qr, offset + 1, || x_r)?;

        let y_r = r.map(|r| r.1);
        let y_r_var = region.assign_advice(self.y_qr, offset + 1, || y_r)?;

        let result = NonIdentityEccPoint::from_coordinates_unchecked(x_r_var, y_r_var);

        Ok(result)
    }
}
