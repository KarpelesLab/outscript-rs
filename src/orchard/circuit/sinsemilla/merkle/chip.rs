//! Chip implementing a Merkle hash using Sinsemilla as the hash function
//! (port of `halo2_gadgets::sinsemilla::merkle::chip`).

use alloc::vec;
use alloc::vec::Vec;

use crate::orchard::circuit::ecc::chip::NonIdentityEccPoint;
use crate::orchard::circuit::sinsemilla::chip::{RunningSum, SinsemillaChip, SinsemillaConfig};
use crate::orchard::circuit::sinsemilla::{MessagePiece, message};
use crate::orchard::circuit::utilities::RangeConstrained;
use crate::orchard::circuit::utilities::cond_swap::{CondSwapChip, CondSwapConfig};
use crate::orchard::halo2::circuit::{AssignedCell, Layouter};
use crate::orchard::halo2::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Rotation, Selector,
};
use crate::orchard::halo2::{Error, Value};
use crate::orchard::{Fp, pallas};

/// The number of bits of an element of the Pallas base field
/// (`pallas::Base::NUM_BITS`).
const FIELD_NUM_BITS: usize = 255;

/// Configuration for the `MerkleChip` implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MerkleConfig {
    advices: [Column<Advice>; 5],
    q_decompose: Selector,
    pub(super) cond_swap_config: CondSwapConfig,
    pub(super) sinsemilla_config: SinsemillaConfig,
}

impl MerkleConfig {
    /// Returns the cond_swap_config of this config.
    pub(crate) fn cond_swap_config(&self) -> &CondSwapConfig {
        &self.cond_swap_config
    }

    /// Returns the Sinsemilla config of this config.
    pub(crate) fn sinsemilla_config(&self) -> &SinsemillaConfig {
        &self.sinsemilla_config
    }
}

/// Chip implementing `MerkleInstructions`.
///
/// This chip specifically implements `MerkleInstructions::hash_layer` as the
/// `MerkleCRH` function `hash = SinsemillaHash(Q, 𝑙⋆ || left⋆ || right⋆)`,
/// where:
/// - `𝑙⋆ = I2LEBSP_10(l)`
/// - `left⋆ = I2LEBSP_255(left)`
/// - `right⋆ = I2LEBSP_255(right)`
///
/// This chip does **NOT** constrain `left⋆` and `right⋆` to be canonical
/// encodings of `left` and `right`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MerkleChip {
    config: MerkleConfig,
}

impl MerkleChip {
    /// The configuration of this chip (`Chip::config`).
    pub(crate) fn config(&self) -> &MerkleConfig {
        &self.config
    }

    /// Configures the [`MerkleChip`].
    pub(crate) fn configure(
        meta: &mut ConstraintSystem,
        sinsemilla_config: SinsemillaConfig,
    ) -> MerkleConfig {
        // All five advice columns are equality-enabled by SinsemillaConfig.
        let advices = sinsemilla_config.advices();
        let cond_swap_config = CondSwapChip::configure(meta, advices);

        // This selector enables the decomposition gate.
        let q_decompose = meta.selector();

        // Check that pieces have been decomposed correctly for Sinsemilla
        // hash.
        // <https://zips.z.cash/protocol/protocol.pdf#orchardmerklecrh>
        //
        // a = a_0||a_1 = l || (bits 0..=239 of left)
        // b = b_0||b_1||b_2
        //   = (bits 240..=249 of left) || (bits 250..=254 of left) || (bits 0..=4 of right)
        // c = bits 5..=254 of right
        //
        // The message pieces `a`, `b`, `c` are constrained by Sinsemilla to
        // be 250 bits, 20 bits, and 250 bits respectively.
        //
        // The pieces and subpieces are arranged in the following
        // configuration:
        // |  A_0  |  A_1  |  A_2  |  A_3  |  A_4  | q_decompose |
        // -------------------------------------------------------
        // |   a   |   b   |   c   |  left | right |      1      |
        // |  z1_a |  z1_b |  b_1  |  b_2  |   l   |      0      |
        meta.create_gate("Decomposition check", |meta| {
            let q_decompose = meta.query_selector(q_decompose);
            let l_whole = meta.query_advice(advices[4], Rotation::next());

            let two_pow_5 = Fp::from_u64(1 << 5);
            let two_pow_10 = two_pow_5.square();

            // a_whole is constrained by Sinsemilla to be 250 bits.
            let a_whole = meta.query_advice(advices[0], Rotation::cur());
            // b_whole is constrained by Sinsemilla to be 20 bits.
            let b_whole = meta.query_advice(advices[1], Rotation::cur());
            // c_whole is constrained by Sinsemilla to be 250 bits.
            let c_whole = meta.query_advice(advices[2], Rotation::cur());
            let left_node = meta.query_advice(advices[3], Rotation::cur());
            let right_node = meta.query_advice(advices[4], Rotation::cur());

            // a = a_0||a_1 = l || (bits 0..=239 of left)
            //
            // z_1 of SinsemillaHash(a) = a_1
            // => a_0 = a - (a_1 * 2^10)
            let z1_a = meta.query_advice(advices[0], Rotation::next());
            let a_1 = z1_a;
            // a_0 = a - (a_1 * 2^10)
            let a_0 = a_whole - a_1.clone() * two_pow_10;

            // b = b_0||b_1||b_2
            //   = (bits 240..=249 of left) || (bits 250..=254 of left) || (bits 0..=4 of right)
            // The Orchard specification allows this representation to be
            // non-canonical.
            // <https://zips.z.cash/protocol/protocol.pdf#merklepath>
            //
            //    z_1 of SinsemillaHash(b) = b_1 + 2^5 b_2
            // => b_0 = b - (z1_b * 2^10)
            let z1_b = meta.query_advice(advices[1], Rotation::next());
            // b_1 has been constrained to be 5 bits outside this gate.
            let b_1 = meta.query_advice(advices[2], Rotation::next());
            // b_2 has been constrained to be 5 bits outside this gate.
            let b_2 = meta.query_advice(advices[3], Rotation::next());
            // Constrain b_1 + 2^5 b_2 = z1_b
            // https://p.z.cash/halo2-0.1:sinsemilla-merkle-crh-bit-lengths?partial
            let b1_b2_check = z1_b.clone() - (b_1.clone() + b_2.clone() * two_pow_5);
            // Derive b_0 (constrained by SinsemillaHash to be 10 bits)
            let b_0 = b_whole - (z1_b * two_pow_10);

            // Check that left = a_1 (240 bits) || b_0 (10 bits) || b_1 (5 bits)
            // https://p.z.cash/halo2-0.1:sinsemilla-merkle-crh-decomposition?partial
            let left_check = {
                let reconstructed = {
                    let two_pow_240 = Fp::from_u128(1 << 120).square();
                    a_1 + (b_0 + b_1 * two_pow_10) * two_pow_240
                };
                reconstructed - left_node
            };

            // Check that right = b_2 (5 bits) || c (250 bits)
            // The Orchard specification allows this representation to be
            // non-canonical.
            // <https://zips.z.cash/protocol/protocol.pdf#merklepath>
            // https://p.z.cash/halo2-0.1:sinsemilla-merkle-crh-decomposition?partial
            let right_check = b_2 + c_whole * two_pow_5 - right_node;

            Constraints::with_selector(
                q_decompose,
                [
                    // "l_check"
                    a_0 - l_whole,
                    // "left_check"
                    left_check,
                    // "right_check"
                    right_check,
                    // "b1_b2_check"
                    b1_b2_check,
                ],
            )
        });

        MerkleConfig {
            advices,
            q_decompose,
            cond_swap_config,
            sinsemilla_config,
        }
    }

    /// Constructs a [`MerkleChip`] given a [`MerkleConfig`].
    pub(crate) fn construct(config: MerkleConfig) -> Self {
        MerkleChip { config }
    }

    /// The Sinsemilla chip this chip hashes with.
    fn sinsemilla_chip(&self) -> SinsemillaChip {
        SinsemillaChip::construct(self.config().sinsemilla_config.clone())
    }

    /// Compute MerkleCRH for a given `layer`. The hash that computes the
    /// root is at layer 0, and the hashes that are applied to two leaves
    /// are at layer `MERKLE_DEPTH - 1` = layer 31.
    #[allow(non_snake_case)]
    pub(crate) fn hash_layer(
        &self,
        layouter: &mut Layouter<'_>,
        Q: pallas::Affine,
        // l = MERKLE_DEPTH - layer - 1
        l: usize,
        left: AssignedCell<Fp>,
        right: AssignedCell<Fp>,
    ) -> Result<AssignedCell<Fp>, Error> {
        let config = self.config().clone();
        // The reference passes `self.clone()` as the Sinsemilla chip, which
        // delegates to this one.
        let sinsemilla_chip = self.sinsemilla_chip();

        // We need to hash `l || left || right`, where `l` is a 10-bit value.
        // We allow `left` and `right` to be non-canonical 255-bit encodings.
        //
        // a = a_0||a_1 = l || (bits 0..=239 of left)
        // b = b_0||b_1||b_2
        //   = (bits 240..=249 of left) || (bits 250..=254 of left) || (bits 0..=4 of right)
        // c = bits 5..=254 of right
        //
        // We start by witnessing all of the individual pieces, and range-
        // constraining the short pieces b_1 and b_2.
        //
        // https://p.z.cash/halo2-0.1:sinsemilla-merkle-crh-bit-lengths?partial

        // `a = a_0||a_1` = `l` || (bits 0..=239 of `left`)
        let a = MessagePiece::from_subpieces(
            sinsemilla_chip.clone(),
            layouter,
            [
                RangeConstrained::bitrange_of(Value::known(&Fp::from_u64(l as u64)), 0..10),
                RangeConstrained::bitrange_of(left.value(), 0..240),
            ],
        )?;

        // b = b_0 || b_1 || b_2
        //   = (bits 240..=249 of left) || (bits 250..=254 of left) || (bits 0..=4 of right)
        let (b_1, b_2, b) = {
            // b_0 = (bits 240..=249 of `left`)
            let b_0 = RangeConstrained::bitrange_of(left.value(), 240..250);

            // b_1 = (bits 250..=254 of `left`)
            // Constrain b_1 to 5 bits.
            let b_1 = RangeConstrained::witness_short(
                &config.sinsemilla_config.lookup_config(),
                layouter,
                left.value(),
                250..FIELD_NUM_BITS,
            )?;

            // b_2 = (bits 0..=4 of `right`)
            // Constrain b_2 to 5 bits.
            let b_2 = RangeConstrained::witness_short(
                &config.sinsemilla_config.lookup_config(),
                layouter,
                right.value(),
                0..5,
            )?;

            let b = MessagePiece::from_subpieces(
                sinsemilla_chip.clone(),
                layouter,
                [b_0, b_1.value(), b_2.value()],
            )?;

            (b_1, b_2, b)
        };

        // c = bits 5..=254 of `right`
        let c = MessagePiece::from_subpieces(
            sinsemilla_chip,
            layouter,
            [RangeConstrained::bitrange_of(
                right.value(),
                5..FIELD_NUM_BITS,
            )],
        )?;

        // hash = SinsemillaHash(Q, 𝑙⋆ || left⋆ || right⋆)
        //
        // `hash = ⊥` is handled internally to `SinsemillaChip::hash_to_point`:
        // incomplete addition constraints allows ⊥ to occur, and then during
        // synthesis it detects these edge cases and raises an error (aborting
        // proof creation).
        //
        // Note that MerkleCRH as-defined maps ⊥ to 0. This is for
        // completeness outside the circuit (so that the ⊥ does not propagate
        // into the type system). The chip explicitly doesn't map ⊥ to 0; in
        // fact it cannot, as doing so would require constraints that amount
        // to using complete addition.
        //
        // https://p.z.cash/proto:merkle-crh-orchard
        let (point, zs) =
            self.hash_to_point(layouter, Q, vec![a.inner(), b.inner(), c.inner()].into())?;
        let hash = Self::extract(&point);

        // `SinsemillaChip::hash_to_point` returns the running sum for each
        // `MessagePiece`. Grab the outputs that we will need for the
        // decomposition constraints.
        let z1_a = zs[0][1].clone();
        let z1_b = zs[1][1].clone();

        // Check that the pieces have been decomposed properly.
        //
        // The pieces and subpieces are arranged in the following
        // configuration:
        // |  A_0  |  A_1  |  A_2  |  A_3  |  A_4  | q_decompose |
        // -------------------------------------------------------
        // |   a   |   b   |   c   |  left | right |      1      |
        // |  z1_a |  z1_b |  b_1  |  b_2  |   l   |      0      |
        {
            layouter.assign_region(|mut region| {
                // Set the fixed column `l` to the current l.
                // Recall that l = MERKLE_DEPTH - layer - 1.
                // The layer with 2^n nodes is called "layer n".
                config.q_decompose.enable(&mut region, 0)?;
                region.assign_advice_from_constant(config.advices[4], 1, Fp::from_u64(l as u64))?;

                // Offset 0
                // Copy and assign `a` at the correct position.
                a.inner()
                    .cell_value()
                    .copy_advice(&mut region, config.advices[0], 0)?;
                // Copy and assign `b` at the correct position.
                b.inner()
                    .cell_value()
                    .copy_advice(&mut region, config.advices[1], 0)?;
                // Copy and assign `c` at the correct position.
                c.inner()
                    .cell_value()
                    .copy_advice(&mut region, config.advices[2], 0)?;
                // Copy and assign the left node at the correct position.
                left.copy_advice(&mut region, config.advices[3], 0)?;
                // Copy and assign the right node at the correct position.
                right.copy_advice(&mut region, config.advices[4], 0)?;

                // Offset 1
                // Copy and assign z_1 of SinsemillaHash(a) = a_1
                z1_a.copy_advice(&mut region, config.advices[0], 1)?;
                // Copy and assign z_1 of SinsemillaHash(b) = b_1
                z1_b.copy_advice(&mut region, config.advices[1], 1)?;
                // Copy `b_1`, which has been constrained to be a 5-bit value
                b_1.inner().copy_advice(&mut region, config.advices[2], 1)?;
                // Copy `b_2`, which has been constrained to be a 5-bit value
                b_2.inner().copy_advice(&mut region, config.advices[3], 1)?;

                Ok(())
            })?;
        }

        // Check layer hash output against Sinsemilla primitives hash
        #[cfg(test)]
        {
            use crate::orchard::circuit::utilities::i2lebsp;
            use crate::orchard::sinsemilla::HashDomain;

            left.value()
                .zip(right.value())
                .zip(hash.value())
                .assert_if_known(|((left, right), hash)| {
                    let l = i2lebsp::<10>(l as u64);
                    let merkle_crh = HashDomain::from_q(Q);
                    let message = l
                        .into_iter()
                        .chain((0..FIELD_NUM_BITS).map(|i| left.bit(i)))
                        .chain((0..FIELD_NUM_BITS).map(|i| right.bit(i)));
                    let expected = merkle_crh.hash(message).unwrap();
                    expected == **hash
                });
        }

        Ok(hash)
    }

    /// Given an input pair (a,b) and a `swap` boolean flag, returns (b,a)
    /// if `swap` is set, else (a,b) if `swap` is not set
    /// (`CondSwapInstructions::swap`, delegated to the cond-swap chip).
    #[allow(clippy::type_complexity)]
    pub(crate) fn swap(
        &self,
        layouter: &mut Layouter<'_>,
        pair: (AssignedCell<Fp>, Value<Fp>),
        swap: Value<bool>,
    ) -> Result<(AssignedCell<Fp>, AssignedCell<Fp>), Error> {
        let config = self.config().cond_swap_config.clone();
        let chip = CondSwapChip::construct(config);
        chip.swap(layouter, pair, swap)
    }

    /// `SinsemillaInstructions::witness_message_piece`, delegated to the
    /// Sinsemilla chip.
    pub(crate) fn witness_message_piece(
        &self,
        layouter: &mut Layouter<'_>,
        value: Value<Fp>,
        num_words: usize,
    ) -> Result<message::MessagePiece, Error> {
        self.sinsemilla_chip()
            .witness_message_piece(layouter, value, num_words)
    }

    /// `SinsemillaInstructions::hash_to_point`, delegated to the Sinsemilla
    /// chip.
    #[allow(non_snake_case)]
    pub(crate) fn hash_to_point(
        &self,
        layouter: &mut Layouter<'_>,
        Q: pallas::Affine,
        message: message::Message,
    ) -> Result<(NonIdentityEccPoint, Vec<RunningSum>), Error> {
        self.sinsemilla_chip().hash_to_point(layouter, Q, message)
    }

    /// `SinsemillaInstructions::extract`, delegated to the Sinsemilla chip.
    pub(crate) fn extract(point: &NonIdentityEccPoint) -> AssignedCell<Fp> {
        SinsemillaChip::extract(point)
    }
}
