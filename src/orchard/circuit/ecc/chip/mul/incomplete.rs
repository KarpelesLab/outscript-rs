//! The incomplete-addition part of variable-base scalar multiplication
//! (port of `halo2_gadgets::ecc::chip::mul::incomplete`).

use alloc::vec::Vec;

use super::super::{CircuitVersion, NonIdentityEccPoint};
use super::{X, Y, Z};
use crate::orchard::Fp;
use crate::orchard::circuit::utilities::bool_check;
use crate::orchard::halo2::circuit::Region;
use crate::orchard::halo2::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Expression, Rotation, Selector, VirtualCells,
};
use crate::orchard::halo2::{Error, Value};

/// A helper struct for implementing single-row double-and-add using
/// incomplete addition.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct DoubleAndAdd {
    // x-coordinate of the accumulator in each double-and-add iteration.
    pub(crate) x_a: Column<Advice>,
    // x-coordinate of the point being added in each double-and-add iteration.
    pub(crate) x_p: Column<Advice>,
    // lambda1 in each double-and-add iteration.
    pub(crate) lambda_1: Column<Advice>,
    // lambda2 in each double-and-add iteration.
    pub(crate) lambda_2: Column<Advice>,
}

impl DoubleAndAdd {
    /// Derives the expression `x_r = lambda_1^2 - x_a - x_p`.
    pub(crate) fn x_r(&self, meta: &mut VirtualCells<'_>, rotation: Rotation) -> Expression {
        let x_a = meta.query_advice(self.x_a, rotation);
        let x_p = meta.query_advice(self.x_p, rotation);
        let lambda_1 = meta.query_advice(self.lambda_1, rotation);
        lambda_1.square() - x_a - x_p
    }

    /// Derives the expression `Y_A = (lambda_1 + lambda_2) * (x_a - x_r)`.
    ///
    /// Note that this is missing the factor of `1/2`; the Sinsemilla
    /// constraints factor it out, so we add it in the callsite needing it.
    #[allow(non_snake_case)]
    pub(crate) fn Y_A(&self, meta: &mut VirtualCells<'_>, rotation: Rotation) -> Expression {
        let x_a = meta.query_advice(self.x_a, rotation);
        let lambda_1 = meta.query_advice(self.lambda_1, rotation);
        let lambda_2 = meta.query_advice(self.lambda_2, rotation);
        (lambda_1 + lambda_2) * (x_a - self.x_r(meta, rotation))
    }
}

/// The configuration of one half of the incomplete additions.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Config<const NUM_BITS: usize> {
    // Selector constraining the first row of incomplete addition.
    pub(super) q_mul_1: Selector,
    // Selector constraining the main loop of incomplete addition.
    pub(super) q_mul_2: Selector,
    // Selector constraining the last row of incomplete addition.
    pub(super) q_mul_3: Selector,
    // Cumulative sum used to decompose the scalar.
    pub(super) z: Column<Advice>,
    // Logic specific to merged double-and-add.
    pub(super) double_and_add: DoubleAndAdd,
    // y-coordinate of the point being added in each double-and-add iteration.
    pub(super) y_p: Column<Advice>,
}

impl<const NUM_BITS: usize> Config<NUM_BITS> {
    pub(super) fn configure(
        meta: &mut ConstraintSystem,
        z: Column<Advice>,
        x_a: Column<Advice>,
        x_p: Column<Advice>,
        y_p: Column<Advice>,
        lambda_1: Column<Advice>,
        lambda_2: Column<Advice>,
    ) -> Self {
        meta.enable_equality(z);
        meta.enable_equality(lambda_1);

        let config = Self {
            q_mul_1: meta.selector(),
            q_mul_2: meta.selector(),
            q_mul_3: meta.selector(),
            z,
            double_and_add: DoubleAndAdd {
                x_a,
                x_p,
                lambda_1,
                lambda_2,
            },
            y_p,
        };

        config.create_gate(meta);

        config
    }

    // Gate for incomplete addition part of variable-base scalar multiplication.
    fn create_gate(&self, meta: &mut ConstraintSystem) {
        // Closure to compute x_{R,i} = λ_{1,i}^2 - x_{A,i} - x_{P,i}
        let x_r = |meta: &mut VirtualCells<'_>, rotation: Rotation| {
            self.double_and_add.x_r(meta, rotation)
        };

        // Closure to compute y_{A,i} = (λ_{1,i} + λ_{2,i}) * (x_{A,i} - x_{R,i}) / 2
        let y_a = |meta: &mut VirtualCells<'_>, rotation: Rotation| {
            self.double_and_add.Y_A(meta, rotation) * Fp::TWO_INV
        };

        // Constraints used for q_mul_{2, 3} == 1
        // https://p.z.cash/halo2-0.1:ecc-var-mul-incomplete-main-loop?partial
        // https://p.z.cash/halo2-0.1:ecc-var-mul-incomplete-last-row?partial
        let for_loop = |meta: &mut VirtualCells<'_>, y_a_next: Expression| {
            let one = Expression::Constant(Fp::ONE);

            // z_i
            let z_cur = meta.query_advice(self.z, Rotation::cur());
            // z_{i+1}
            let z_prev = meta.query_advice(self.z, Rotation::prev());
            // x_{A,i}
            let x_a_cur = meta.query_advice(self.double_and_add.x_a, Rotation::cur());
            // x_{A,i-1}
            let x_a_next = meta.query_advice(self.double_and_add.x_a, Rotation::next());
            // x_{P,i}
            let x_p_cur = meta.query_advice(self.double_and_add.x_p, Rotation::cur());
            // y_{P,i}
            let y_p_cur = meta.query_advice(self.y_p, Rotation::cur());
            // λ_{1,i}
            let lambda1_cur = meta.query_advice(self.double_and_add.lambda_1, Rotation::cur());
            // λ_{2,i}
            let lambda2_cur = meta.query_advice(self.double_and_add.lambda_2, Rotation::cur());

            let y_a_cur = y_a(meta, Rotation::cur());

            // The current bit in the scalar decomposition, k_i = z_i - 2⋅z_{i+1}.
            // Recall that we assigned the cumulative variable `z_i` in descending order,
            // i from n down to 0. So z_{i+1} corresponds to the `z_prev` query.
            let k = z_cur - z_prev * Fp::from_u64(2);
            // Check booleanity of decomposition.
            let bool_check = bool_check(k.clone());

            // λ_{1,i}⋅(x_{A,i} − x_{P,i}) − y_{A,i} + (2k_i - 1) y_{P,i} = 0
            let gradient_1 = lambda1_cur * (x_a_cur.clone() - x_p_cur) - y_a_cur.clone()
                + (k * Fp::from_u64(2) - one) * y_p_cur;

            // λ_{2,i}^2 − x_{A,i-1} − x_{R,i} − x_{A,i} = 0
            let secant_line = lambda2_cur.clone().square()
                - x_a_next.clone()
                - x_r(meta, Rotation::cur())
                - x_a_cur.clone();

            // λ_{2,i}⋅(x_{A,i} − x_{A,i-1}) − y_{A,i} − y_{A,i-1} = 0
            let gradient_2 = lambda2_cur * (x_a_cur - x_a_next) - y_a_cur - y_a_next;

            // bool_check, gradient_1, secant_line, gradient_2
            [bool_check, gradient_1, secant_line, gradient_2]
        };

        // q_mul_1 == 1 checks
        // https://p.z.cash/halo2-0.1:ecc-var-mul-incomplete-first-row
        meta.create_gate("q_mul_1 == 1 checks", |meta| {
            let q_mul_1 = meta.query_selector(self.q_mul_1);

            let y_a_next = y_a(meta, Rotation::next());
            let y_a_witnessed = meta.query_advice(self.double_and_add.lambda_1, Rotation::cur());
            // init y_a
            Constraints::with_selector(q_mul_1, Some(y_a_witnessed - y_a_next))
        });

        // q_mul_2 == 1 checks
        // https://p.z.cash/halo2-0.1:ecc-var-mul-incomplete-main-loop?partial
        meta.create_gate("q_mul_2 == 1 checks", |meta| {
            let q_mul_2 = meta.query_selector(self.q_mul_2);

            let y_a_next = y_a(meta, Rotation::next());

            // x_{P,i}
            let x_p_cur = meta.query_advice(self.double_and_add.x_p, Rotation::cur());
            // x_{P,i-1}
            let x_p_next = meta.query_advice(self.double_and_add.x_p, Rotation::next());
            // y_{P,i}
            let y_p_cur = meta.query_advice(self.y_p, Rotation::cur());
            // y_{P,i-1}
            let y_p_next = meta.query_advice(self.y_p, Rotation::next());

            // The base point (x_p, y_p) stays constant in the main loop
            let x_p_check = x_p_cur - x_p_next;
            let y_p_check = y_p_cur - y_p_next;

            // x_p_check, y_p_check, then the main loop
            Constraints::with_selector(
                q_mul_2,
                core::iter::empty()
                    .chain(Some(x_p_check))
                    .chain(Some(y_p_check))
                    .chain(for_loop(meta, y_a_next)),
            )
        });

        // q_mul_3 == 1 checks
        // https://p.z.cash/halo2-0.1:ecc-var-mul-incomplete-last-row?partial
        meta.create_gate("q_mul_3 == 1 checks", |meta| {
            let q_mul_3 = meta.query_selector(self.q_mul_3);
            let y_a_final = meta.query_advice(self.double_and_add.lambda_1, Rotation::next());
            Constraints::with_selector(q_mul_3, for_loop(meta, y_a_final))
        });
    }

    /// We perform incomplete addition on all but the last three bits of the
    /// decomposed scalar.
    /// We split the bits in the incomplete addition range into "hi" and "lo"
    /// halves and process them side by side, using the same rows but with
    /// non-overlapping columns. The base is never the identity point even
    /// though it is given as (x_p, y_p) here.
    /// Returns (x, y, z).
    #[allow(clippy::type_complexity)]
    pub(super) fn double_and_add(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        base: &NonIdentityEccPoint,
        bits: &[Value<bool>],
        acc: (X, Y, Z),
        circuit_version: CircuitVersion,
    ) -> Result<(X, Y, Vec<Z>), Error> {
        // Check that we have the correct number of bits for this double-and-add.
        assert_eq!(bits.len(), NUM_BITS);

        // Handle exceptional cases
        let (x_p, y_p) = (base.x.value().cloned(), base.y.value().cloned());
        let (x_a, y_a) = (acc.0.value().cloned(), acc.1.value().cloned());

        x_a.zip(y_a)
            .zip(x_p.zip(y_p))
            .error_if_known_and(|((x_a, y_a), (x_p, y_p))| {
                // A is point at infinity
                (*x_p == Fp::ZERO && *y_p == Fp::ZERO)
                // Q is point at infinity
                || (*x_a == Fp::ZERO && *y_a == Fp::ZERO)
                // x_p = x_a
                || (x_p == x_a)
            })?;

        // Set q_mul values
        {
            // q_mul_1 == 1 on offset 0
            self.q_mul_1.enable(region, offset)?;

            let offset = offset + 1;
            // q_mul_2 == 1 on all rows after offset 0, excluding the last row.
            for idx in 0..(NUM_BITS - 1) {
                self.q_mul_2.enable(region, offset + idx)?;
            }

            // q_mul_3 == 1 on the last row.
            self.q_mul_3.enable(region, offset + NUM_BITS - 1)?;
        }

        // Initialise double-and-add
        let (mut x_a, mut y_a, mut z) = {
            // Initialise the running `z` sum for the scalar bits.
            let z = acc.2.copy_advice(region, self.z, offset)?;

            // Initialise acc
            let x_a = acc
                .0
                .copy_advice(region, self.double_and_add.x_a, offset + 1)?;
            let y_a = acc
                .1
                .copy_advice(region, self.double_and_add.lambda_1, offset)?;

            (x_a, y_a.value().cloned(), z)
        };

        // Increase offset by 1; we used row 0 for initializing `z`.
        let offset = offset + 1;

        // Initialise vector to store all interstitial `z` running sum values.
        let mut zs: Vec<Z> = Vec::with_capacity(bits.len());

        // Incomplete addition
        for (row, k) in bits.iter().enumerate() {
            // z_{i} = 2 * z_{i+1} + k_i
            let z_val = z
                .value()
                .zip(k.as_ref())
                .map(|(z_val, k)| Fp::from_u64(2) * *z_val + Fp::from_u64(*k as u64));
            z = region.assign_advice(self.z, row + offset, || z_val)?;
            zs.push(Z(z.clone()));

            // Assign `x_p`, `y_p`.
            //
            // On the first row of the fixed circuit, copy `(x_p, y_p)` from
            // the base cells; the `q_mul_2` gate propagates them to the
            // remaining rows. On every other row (and on every row of the
            // insecure circuit), witness the values with no extra
            // constraint.
            match circuit_version {
                CircuitVersion::AnchoredBase if row == 0 => {
                    base.x
                        .copy_advice(region, self.double_and_add.x_p, row + offset)?;
                    base.y.copy_advice(region, self.y_p, row + offset)?;
                }
                _ => {
                    region.assign_advice(self.double_and_add.x_p, row + offset, || x_p)?;
                    region.assign_advice(self.y_p, row + offset, || y_p)?;
                }
            }

            // If the bit is set, use `y`; if the bit is not set, use `-y`
            let y_p = y_p
                .zip(k.as_ref())
                .map(|(y_p, k)| if !k { -y_p } else { y_p });

            // Compute and assign λ1⋅(x_A − x_P) = y_A − y_P
            let lambda1 = y_a
                .zip(y_p)
                .zip(x_a.value())
                .zip(x_p)
                .map(|(((y_a, y_p), x_a), x_p)| (y_a - y_p) * (*x_a - x_p).invert_or_zero());
            region.assign_advice(self.double_and_add.lambda_1, row + offset, || lambda1)?;

            // x_R = λ1^2 - x_A - x_P
            let x_r = lambda1
                .zip(x_a.value())
                .zip(x_p)
                .map(|((lambda1, x_a), x_p)| lambda1.square() - *x_a - x_p);

            // λ2 = (2(y_A) / (x_A - x_R)) - λ1
            let lambda2 =
                lambda1
                    .zip(y_a)
                    .zip(x_a.value())
                    .zip(x_r)
                    .map(|(((lambda1, y_a), x_a), x_r)| {
                        y_a * Fp::from_u64(2) * (*x_a - x_r).invert_or_zero() - lambda1
                    });
            region.assign_advice(self.double_and_add.lambda_2, row + offset, || lambda2)?;

            // Compute and assign `x_a` for the next row
            let x_a_new = lambda2.square() - x_a.value().copied() - x_r;
            y_a = lambda2 * (x_a.value().copied() - x_a_new) - y_a;
            let x_a_val = x_a_new;
            x_a = region.assign_advice(self.double_and_add.x_a, row + offset + 1, || x_a_val)?;
        }

        // Witness final y_a
        let y_a = region.assign_advice(self.double_and_add.lambda_1, offset + NUM_BITS, || y_a)?;

        Ok((X(x_a), Y(y_a), zs))
    }
}
