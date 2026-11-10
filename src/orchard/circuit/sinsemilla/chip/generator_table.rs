//! The lookup table of the Sinsemilla generators (port of
//! `halo2_gadgets::sinsemilla::chip::generator_table`).

use alloc::vec;

use super::SinsemillaConfig;
use crate::orchard::Fp;
use crate::orchard::circuit::utilities::lookup_range_check::LookupRangeCheckConfig;
use crate::orchard::constants::SINSEMILLA_S;
use crate::orchard::halo2::Error;
use crate::orchard::halo2::circuit::Layouter;
use crate::orchard::halo2::plonk::{ConstraintSystem, Expression, Rotation, TableColumn};
use crate::orchard::sinsemilla::K;

/// Table containing independent generators S\[0..2^k\]
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub(crate) struct GeneratorTableConfig {
    /// The index `j` of the generator.
    pub(crate) table_idx: TableColumn,
    /// The x-coordinate of `S[j]`.
    pub(crate) table_x: TableColumn,
    /// The y-coordinate of `S[j]`.
    pub(crate) table_y: TableColumn,
}

impl GeneratorTableConfig {
    /// Even though the lookup table can be used in other parts of the
    /// circuit, this specific configuration sets up Sinsemilla-specific
    /// constraints controlled by `q_sinsemilla`, and would likely not apply
    /// to other chips.
    #[allow(non_snake_case)]
    pub(crate) fn configure(meta: &mut ConstraintSystem, config: SinsemillaConfig) {
        let (table_idx, table_x, table_y) = (
            config.generator_table.table_idx,
            config.generator_table.table_x,
            config.generator_table.table_y,
        );

        // https://p.z.cash/halo2-0.1:sinsemilla-constraints?partial
        meta.lookup(|meta| {
            let q_s1 = meta.query_selector(config.q_sinsemilla1);
            let q_s2 = meta.query_fixed(config.q_sinsemilla2);
            let q_s3 = config.q_s3(meta);
            let q_run = q_s2 - q_s3;

            // m_{i+1} = z_{i} - 2^K * q_{run,i} * z_{i + 1}
            // Note that the message words m_i's are 1-indexed while the
            // running sum z_i's are 0-indexed.
            let word = {
                let z_cur = meta.query_advice(config.bits, Rotation::cur());
                let z_next = meta.query_advice(config.bits, Rotation::next());
                z_cur - (q_run * z_next * Fp::from_u64(1 << K))
            };

            let x_p = meta.query_advice(config.double_and_add.x_p, Rotation::cur());

            // y_{p,i} = (Y_{A,i} / 2) - lambda1 * (x_{A,i} - x_{P,i})
            let y_p = {
                let lambda1 = meta.query_advice(config.double_and_add.lambda_1, Rotation::cur());
                let x_a = meta.query_advice(config.double_and_add.x_a, Rotation::cur());
                let Y_A = config.double_and_add.Y_A(meta, Rotation::cur());

                (Y_A * Fp::TWO_INV) - (lambda1 * (x_a - x_p.clone()))
            };

            // Lookup expressions default to the first entry when `q_s1` is
            // not enabled.
            let (init_x, init_y) = (SINSEMILLA_S[0].x(), SINSEMILLA_S[0].y());
            let not_q_s1 = Expression::Constant(Fp::ONE) - q_s1.clone();

            let m = q_s1.clone() * word; // The first table index is 0.
            let x_p = q_s1.clone() * x_p + not_q_s1.clone() * init_x;
            let y_p = q_s1 * y_p + not_q_s1 * init_y;

            vec![(m, table_idx), (x_p, table_x), (y_p, table_y)]
        });
    }

    /// Load the generator table into the circuit.
    ///
    /// The table is assigned by the range check configuration (it shares
    /// `table_idx` with it).
    pub(crate) fn load(
        &self,
        lookup_config: LookupRangeCheckConfig,
        layouter: &mut Layouter<'_>,
    ) -> Result<(), Error> {
        lookup_config.load(self.table_idx, self.table_x, self.table_y, layouter)
    }
}
