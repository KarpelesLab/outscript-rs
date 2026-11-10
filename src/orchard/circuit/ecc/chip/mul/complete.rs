//! The complete-addition part of variable-base scalar multiplication (port
//! of `halo2_gadgets::ecc::chip::mul::complete`).

use alloc::vec::Vec;

use super::super::{EccPoint, add};
use super::{COMPLETE_RANGE, X, Y, Z};
use crate::orchard::Fp;
use crate::orchard::circuit::utilities::{bool_check, ternary};
use crate::orchard::halo2::circuit::Region;
use crate::orchard::halo2::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Expression, Rotation, Selector,
};
use crate::orchard::halo2::{Error, Value};

/// The configuration of the complete additions of the last bits.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Config {
    // Selector used to constrain the cells used in complete addition.
    q_mul_decompose_var: Selector,
    // Advice column used to decompose scalar in complete addition.
    pub(crate) z_complete: Column<Advice>,
    // Configuration used in complete addition
    add_config: add::Config,
}

impl Config {
    pub(super) fn configure(
        meta: &mut ConstraintSystem,
        z_complete: Column<Advice>,
        add_config: add::Config,
    ) -> Self {
        meta.enable_equality(z_complete);

        let config = Self {
            q_mul_decompose_var: meta.selector(),
            z_complete,
            add_config,
        };

        config.create_gate(meta);

        config
    }

    /// Gate used to check scalar decomposition is correct.
    /// This is used to check the bits used in complete addition, since the
    /// incomplete addition gate (controlled by `q_mul`) already checks
    /// scalar decomposition for the other bits.
    fn create_gate(&self, meta: &mut ConstraintSystem) {
        // | y_p | z_complete |
        // --------------------
        // | y_p | z_{i + 1}  |
        // |     | base_y     |
        // |     | z_i        |
        // https://p.z.cash/halo2-0.1:ecc-var-mul-complete-gate
        meta.create_gate(
            "Decompose scalar for complete bits of variable-base mul",
            |meta| {
                let q_mul_decompose_var = meta.query_selector(self.q_mul_decompose_var);
                // z_{i + 1}
                let z_prev = meta.query_advice(self.z_complete, Rotation::prev());
                // z_i
                let z_next = meta.query_advice(self.z_complete, Rotation::next());

                // k_{i} = z_{i} - 2⋅z_{i+1}
                let k = z_next - Expression::Constant(Fp::from_u64(2)) * z_prev;
                // (k_i) ⋅ (1 - k_i) = 0
                let bool_check = bool_check(k.clone());

                // base_y
                let base_y = meta.query_advice(self.z_complete, Rotation::cur());
                // y_p
                let y_p = meta.query_advice(self.add_config.y_p, Rotation::prev());

                // k_i = 0 => y_p = -base_y
                // k_i = 1 => y_p = base_y
                let y_switch = ternary(k, base_y.clone() - y_p.clone(), base_y + y_p);

                // bool_check, y_switch
                Constraints::with_selector(q_mul_decompose_var, [bool_check, y_switch])
            },
        );
    }

    #[allow(clippy::type_complexity)]
    #[allow(non_snake_case)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn assign_region(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        bits: &[Value<bool>],
        base: &EccPoint,
        x_a: X,
        y_a: Y,
        z: Z,
    ) -> Result<(EccPoint, Vec<Z>), Error> {
        // Make sure we have the correct number of bits for the complete addition
        // part of variable-base scalar mul.
        assert_eq!(bits.len(), COMPLETE_RANGE.len());

        // Enable selectors for complete range
        for row in 0..COMPLETE_RANGE.len() {
            // Each iteration uses 2 rows (two complete additions)
            let row = 2 * row;
            // Check scalar decomposition for each iteration. Since the gate enabled by
            // `q_mul_decompose_var` queries the previous row, we enable the selector on
            // `row + offset + 1` (instead of `row + offset`).
            self.q_mul_decompose_var.enable(region, row + offset + 1)?;
        }

        // Use x_a, y_a output from incomplete addition
        let mut acc = EccPoint::from_coordinates_unchecked(x_a.0, y_a.0);

        // Copy running sum `z` from incomplete addition
        let mut z = {
            let z = z.copy_advice(region, self.z_complete, offset)?;
            Z(z)
        };

        // Store interstitial running sum `z`s in vector
        let mut zs: Vec<Z> = Vec::with_capacity(bits.len());

        // Complete addition
        for (iter, k) in bits.iter().enumerate() {
            // Each iteration uses 2 rows (two complete additions)
            let row = 2 * iter;

            // Update `z`.
            z = {
                // z_next = z_cur * 2 + k_next
                let z_val = z.value().copied() * Value::known(Fp::from_u64(2))
                    + k.map(|k| Fp::from_u64(k as u64));
                let z_cell = region.assign_advice(self.z_complete, row + offset + 2, || z_val)?;
                Z(z_cell)
            };
            zs.push(z.clone());

            // Assign `y_p` for complete addition.
            let y_p = {
                let base_y = base
                    .y
                    .copy_advice(region, self.z_complete, row + offset + 1)?;

                // If the bit is set, use `y`; if the bit is not set, use `-y`
                let y_p = base_y
                    .value()
                    .cloned()
                    .zip(k.as_ref())
                    .map(|(base_y, k)| if !k { -base_y } else { base_y });

                // Assign the conditionally-negated y coordinate into the
                // complete-addition `y_p` column.
                //
                // The complete-addition gate is enabled on `row + offset`, so it reads
                // this cell as `y_p`.
                region.assign_advice(self.add_config.y_p, row + offset, || y_p)?
            };

            // U = P if the bit is set; U = -P is the bit is not set.
            let U = EccPoint::from_coordinates_unchecked(base.x.clone(), y_p);

            // Acc + U
            let tmp_acc = self
                .add_config
                .assign_region(&U, &acc, row + offset, region)?;

            // Acc + U + Acc
            acc = self
                .add_config
                .assign_region(&acc, &tmp_acc, row + offset + 1, region)?;
        }

        Ok((acc, zs))
    }
}
