//! Chip implementations for the Sinsemilla gadgets (port of
//! `halo2_gadgets::sinsemilla::chip`).
//!
//! Only the variant Orchard configures is ported: the hash starts from a
//! public point `Q` whose y-coordinate sits in a fixed column
//! (`allow_init_from_private_point = false`, so the trailing boolean of
//! `configure`, `hash_to_point_with_private_init` and the private
//! initialization are gone), with the 10-bit `LookupRangeCheckConfig`.

use alloc::vec::Vec;

use super::message::{Message, MessagePiece};
use crate::orchard::circuit::ecc::chip::NonIdentityEccPoint;
use crate::orchard::circuit::utilities::lookup_range_check::LookupRangeCheckConfig;
use crate::orchard::halo2::circuit::{AssignedCell, Layouter};
use crate::orchard::halo2::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Expression, Fixed, Rotation, Selector,
    TableColumn, VirtualCells,
};
use crate::orchard::halo2::{Error, Value};
use crate::orchard::{Fp, pallas};

pub(crate) mod generator_table;
use generator_table::GeneratorTableConfig;

mod hash_to_point;

/// The running sum `[z_0, ..., z_{n-1}]` of a message piece of `n` words
/// (`SinsemillaInstructions::RunningSum` of the reference).
pub(crate) type RunningSum = Vec<AssignedCell<Fp>>;

/// The columns of the merged double-and-add of Sinsemilla.
///
/// This is `halo2_gadgets::ecc::chip::DoubleAndAdd`
/// (`ecc/chip/mul/incomplete.rs`), which the reference shares with the
/// incomplete addition of the variable-base scalar multiplication; it is
/// duplicated here until the ECC chip is ported, and builds the same
/// expressions.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct DoubleAndAdd {
    /// x-coordinate of the accumulator in each double-and-add iteration.
    pub(crate) x_a: Column<Advice>,
    /// x-coordinate of the point being added in each double-and-add
    /// iteration.
    pub(crate) x_p: Column<Advice>,
    /// lambda1 in each double-and-add iteration.
    pub(crate) lambda_1: Column<Advice>,
    /// lambda2 in each double-and-add iteration.
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
    /// constraints factor it out, so we leave it up to the caller to handle
    /// it.
    #[allow(non_snake_case)]
    pub(crate) fn Y_A(&self, meta: &mut VirtualCells<'_>, rotation: Rotation) -> Expression {
        let x_a = meta.query_advice(self.x_a, rotation);
        let lambda_1 = meta.query_advice(self.lambda_1, rotation);
        let lambda_2 = meta.query_advice(self.lambda_2, rotation);
        (lambda_1 + lambda_2) * (x_a - self.x_r(meta, rotation))
    }
}

/// Configuration for the Sinsemilla hash chip
#[derive(Eq, PartialEq, Clone, Debug)]
pub(crate) struct SinsemillaConfig {
    /// Binary selector used in lookup argument and in the body of the
    /// Sinsemilla hash.
    q_sinsemilla1: Selector,
    /// Non-binary selector used in lookup argument and in the body of the
    /// Sinsemilla hash.
    q_sinsemilla2: Column<Fixed>,
    /// q_sinsemilla2 is used to define a synthetic selector,
    ///         q_sinsemilla3 = (q_sinsemilla2) ⋅ (q_sinsemilla2 - 1)
    /// Simple selector used to constrain hash initialization to be
    /// consistent with the y-coordinate of the domain $Q$.
    q_sinsemilla4: Selector,
    /// Fixed column used to load the y-coordinate of the domain $Q$.
    fixed_y_q: Column<Fixed>,
    /// Logic specific to merged double-and-add.
    double_and_add: DoubleAndAdd,
    /// Advice column used to load the message.
    bits: Column<Advice>,
    /// Advice column used to witness message pieces. This may or may not be
    /// the same column as `bits`.
    witness_pieces: Column<Advice>,
    /// The lookup table where $(\mathsf{idx}, x_p, y_p)$ are loaded for the
    /// $2^K$ generators of the Sinsemilla hash.
    pub(super) generator_table: GeneratorTableConfig,
    /// An advice column configured to perform lookup range checks.
    lookup_config: LookupRangeCheckConfig,
}

impl SinsemillaConfig {
    /// Returns an array of all advice columns in this config, in arbitrary
    /// order.
    pub(crate) fn advices(&self) -> [Column<Advice>; 5] {
        [
            self.double_and_add.x_a,
            self.double_and_add.x_p,
            self.bits,
            self.double_and_add.lambda_1,
            self.double_and_add.lambda_2,
        ]
    }

    /// Returns the lookup range check config used in this config.
    pub(crate) fn lookup_config(&self) -> LookupRangeCheckConfig {
        self.lookup_config
    }

    /// Derives the expression `q_s3 = (q_s2) * (q_s2 - 1)`.
    fn q_s3(&self, meta: &mut VirtualCells<'_>) -> Expression {
        let one = Expression::Constant(Fp::ONE);
        let q_s2 = meta.query_fixed(self.q_sinsemilla2);
        q_s2.clone() * (q_s2 - one)
    }
}

/// A chip that implements 10-bit Sinsemilla using a lookup table and 5
/// advice columns.
///
/// [Chip description](https://zcash.github.io/halo2/design/gadgets/sinsemilla.html#plonk--halo-2-constraints).
#[derive(Eq, PartialEq, Clone, Debug)]
pub(crate) struct SinsemillaChip {
    config: SinsemillaConfig,
}

impl SinsemillaChip {
    /// The configuration of this chip (`Chip::config`).
    pub(crate) fn config(&self) -> &SinsemillaConfig {
        &self.config
    }

    /// Reconstructs this chip from the given config.
    pub(crate) fn construct(config: SinsemillaConfig) -> Self {
        Self { config }
    }

    /// Loads the lookup table required by this chip into the circuit.
    pub(crate) fn load(config: SinsemillaConfig, layouter: &mut Layouter<'_>) -> Result<(), Error> {
        // Load the lookup table.
        config.generator_table.load(config.lookup_config, layouter)
    }

    /// # Side-effects
    ///
    /// All columns in `advices` and will be equality-enabled.
    #[allow(non_snake_case)]
    pub(crate) fn configure(
        meta: &mut ConstraintSystem,
        advices: [Column<Advice>; 5],
        witness_pieces: Column<Advice>,
        fixed_y_q: Column<Fixed>,
        lookup: (TableColumn, TableColumn, TableColumn),
        range_check: LookupRangeCheckConfig,
    ) -> SinsemillaConfig {
        // Enable equality on all advice columns
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        let config = SinsemillaConfig {
            q_sinsemilla1: meta.complex_selector(),
            q_sinsemilla2: meta.fixed_column(),
            q_sinsemilla4: meta.selector(),
            fixed_y_q,
            double_and_add: DoubleAndAdd {
                x_a: advices[0],
                x_p: advices[1],
                lambda_1: advices[3],
                lambda_2: advices[4],
            },
            bits: advices[2],
            witness_pieces,
            generator_table: GeneratorTableConfig {
                table_idx: lookup.0,
                table_x: lookup.1,
                table_y: lookup.2,
            },
            lookup_config: range_check,
        };

        // Set up lookup argument
        GeneratorTableConfig::configure(meta, config.clone());

        let two = Fp::from_u64(2);

        // Closures for expressions that are derived multiple times
        // x_r = lambda_1^2 - x_a - x_p
        let x_r = |meta: &mut VirtualCells<'_>, rotation| config.double_and_add.x_r(meta, rotation);

        // Y_A = (lambda_1 + lambda_2) * (x_a - x_r)
        let Y_A = |meta: &mut VirtualCells<'_>, rotation| config.double_and_add.Y_A(meta, rotation);

        // Check that the initial x_A, x_P, lambda_1, lambda_2 are consistent
        // with y_Q.
        // https://p.z.cash/halo2-0.1:sinsemilla-constraints?partial
        meta.create_gate("Initial y_Q", |meta| {
            let q_s4 = meta.query_selector(config.q_sinsemilla4);
            let y_q = meta.query_fixed(config.fixed_y_q);

            // Y_A = (lambda_1 + lambda_2) * (x_a - x_r)
            let Y_A_cur = Y_A(meta, Rotation::cur());

            // 2 * y_q - Y_{A,0} = 0
            let init_y_q_check = y_q * two - Y_A_cur;

            // "init_y_q_check"
            Constraints::with_selector(q_s4, Some(init_y_q_check))
        });

        // https://p.z.cash/halo2-0.1:sinsemilla-constraints?partial
        meta.create_gate("Sinsemilla gate", |meta| {
            let q_s1 = meta.query_selector(config.q_sinsemilla1);
            let q_s3 = config.q_s3(meta);

            let lambda_1_next = meta.query_advice(config.double_and_add.lambda_1, Rotation::next());
            let lambda_2_cur = meta.query_advice(config.double_and_add.lambda_2, Rotation::cur());
            let x_a_cur = meta.query_advice(config.double_and_add.x_a, Rotation::cur());
            let x_a_next = meta.query_advice(config.double_and_add.x_a, Rotation::next());

            // x_r = lambda_1^2 - x_a_cur - x_p
            let x_r = x_r(meta, Rotation::cur());

            // Y_A = (lambda_1 + lambda_2) * (x_a - x_r)
            let Y_A_cur = Y_A(meta, Rotation::cur());

            // Y_A = (lambda_1 + lambda_2) * (x_a - x_r)
            let Y_A_next = Y_A(meta, Rotation::next());

            // lambda2^2 - (x_a_next + x_r + x_a_cur) = 0
            let secant_line =
                lambda_2_cur.clone().square() - (x_a_next.clone() + x_r + x_a_cur.clone());

            // lhs - rhs = 0, where
            //    - lhs = 4 * lambda_2_cur * (x_a_cur - x_a_next)
            //    - rhs = (2 * Y_A_cur + (2 - q_s3) * Y_A_next + 2 * q_s3 * y_a_final)
            let y_check = {
                // lhs = 4 * lambda_2_cur * (x_a_cur - x_a_next)
                let lhs = lambda_2_cur * Fp::from_u64(4) * (x_a_cur - x_a_next);

                // rhs = 2 * Y_A_cur + (2 - q_s3) * Y_A_next + 2 * q_s3 * y_a_final
                let rhs = {
                    // y_a_final is assigned to the lambda1 column on the
                    // next offset.
                    let y_a_final = lambda_1_next;

                    Y_A_cur * two
                        + (Expression::Constant(two) - q_s3.clone()) * Y_A_next
                        + q_s3 * two * y_a_final
                };
                lhs - rhs
            };

            // "Secant line", "y check"
            Constraints::with_selector(q_s1, [secant_line, y_check])
        });

        config
    }

    /// Witness a message piece, given a field element. Returns a
    /// [`MessagePiece`] encoding the given message.
    ///
    /// # Panics
    ///
    /// Panics if the message piece does not fit into a base field element.
    pub(crate) fn witness_message_piece(
        &self,
        layouter: &mut Layouter<'_>,
        field_elem: Value<Fp>,
        num_words: usize,
    ) -> Result<MessagePiece, Error> {
        let config = self.config().clone();

        let cell = layouter.assign_region(|mut region| {
            region.assign_advice(config.witness_pieces, 0, || field_elem)
        })?;
        Ok(MessagePiece::new(cell, num_words))
    }

    /// Hashes a message to an ECC curve point.
    /// This returns both the resulting point, as well as the message
    /// decomposition in the form of intermediate values in a cumulative
    /// sum.
    /// The initial point `Q` is a public point.
    #[allow(non_snake_case)]
    pub(crate) fn hash_to_point(
        &self,
        layouter: &mut Layouter<'_>,
        Q: pallas::Affine,
        message: Message,
    ) -> Result<(NonIdentityEccPoint, Vec<RunningSum>), Error> {
        layouter.assign_region(|mut region| self.hash_message(&mut region, Q, &message))
    }

    /// Extracts the x-coordinate of the output of a Sinsemilla hash.
    pub(crate) fn extract(point: &NonIdentityEccPoint) -> AssignedCell<Fp> {
        point.x()
    }
}
