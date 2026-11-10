//! Gadgets for implementing a Merkle tree with Sinsemilla (port of
//! `halo2_gadgets::sinsemilla::merkle`).
//!
//! The `MerkleInstructions` trait of the reference is gone: `hash_layer` is
//! an inherent method of [`chip::MerkleChip`], the only implementation.

use self::chip::MerkleChip;
use super::OrchardHashDomains;
use crate::orchard::Fp;
use crate::orchard::circuit::utilities::i2lebsp;
use crate::orchard::halo2::circuit::{AssignedCell, Layouter};
use crate::orchard::halo2::{Error, Value};

pub(crate) mod chip;

/// The depth of the Orchard note commitment tree
/// (`orchard::constants::MERKLE_DEPTH_ORCHARD`).
#[cfg(test)]
pub(crate) const MERKLE_DEPTH_ORCHARD: usize = 32;

/// The number of bits of a node of the Orchard note commitment tree
/// (`orchard::constants::sinsemilla::L_ORCHARD_MERKLE`).
#[cfg(test)]
pub(crate) const L_ORCHARD_MERKLE: usize = 255;

/// Gadget representing a Merkle path that proves a leaf exists in a Merkle
/// tree at a specific position.
///
/// The `PAR` chips share the layers of the path between them, so that they
/// can be laid out side by side.
#[derive(Clone, Debug)]
pub(crate) struct MerklePath<const PATH_LENGTH: usize, const PAR: usize> {
    chips: [MerkleChip; PAR],
    domain: OrchardHashDomains,
    leaf_pos: Value<u32>,
    // The Merkle path is ordered from leaves to root.
    path: Value<[Fp; PATH_LENGTH]>,
}

impl<const PATH_LENGTH: usize, const PAR: usize> MerklePath<PATH_LENGTH, PAR> {
    /// Constructs a [`MerklePath`].
    ///
    /// A circuit may have many more columns available than are required by
    /// a single `MerkleChip`. To make better use of the available circuit
    /// area, the `MerklePath` gadget will distribute its path hashing
    /// "chunks" across each `MerkleChip` in `chips`, such that each chip
    /// processes `ceil(PATH_LENGTH / PAR)` layers (with the last chip
    /// processing fewer layers if the division is inexact).
    pub(crate) fn construct(
        chips: [MerkleChip; PAR],
        domain: OrchardHashDomains,
        leaf_pos: Value<u32>,
        path: Value<[Fp; PATH_LENGTH]>,
    ) -> Self {
        assert_ne!(PAR, 0);
        Self {
            chips,
            domain,
            leaf_pos,
            path,
        }
    }

    /// Calculates the root of the tree containing the given leaf at this
    /// Merkle path.
    ///
    /// Implements [Zcash Protocol Specification Section 4.9: Merkle Path Validity][merklepath].
    ///
    /// [merklepath]: https://zips.z.cash/protocol/protocol.pdf#merklepath
    #[allow(non_snake_case)]
    pub(crate) fn calculate_root(
        &self,
        layouter: &mut Layouter<'_>,
        leaf: AssignedCell<Fp>,
    ) -> Result<AssignedCell<Fp>, Error> {
        // Each chip processes `ceil(PATH_LENGTH / PAR)` layers.
        let layers_per_chip = PATH_LENGTH.div_ceil(PAR);

        // Assign each layer to a chip.
        let chips = (0..PATH_LENGTH).map(|i| self.chips[i / layers_per_chip].clone());

        // The Merkle path is ordered from leaves to root, which is
        // consistent with the little-endian representation of `pos` below.
        let path = self.path.transpose_array();

        // Get position as a PATH_LENGTH-bit bitstring (little-endian bit
        // order).
        let pos: [Value<bool>; PATH_LENGTH] = {
            let pos: Value<[bool; PATH_LENGTH]> = self.leaf_pos.map(|pos| i2lebsp(pos as u64));
            pos.transpose_array()
        };

        let Q = self.domain.Q();

        let mut node = leaf;
        for (l, ((sibling, pos), chip)) in path.iter().zip(pos.iter()).zip(chips).enumerate() {
            // `l` = MERKLE_DEPTH - layer - 1, which is the index obtained
            // from enumerating this Merkle path (going from leaf to root).
            // For example, when `layer = 31` (the first sibling on the
            // Merkle path), we have `l` = 32 - 31 - 1 = 0. On the other
            // hand, when `layer = 0` (the final sibling on the Merkle
            // path), we have `l` = 32 - 0 - 1 = 31.

            // Constrain which of (node, sibling) is (left, right) with a
            // conditional swap tied to the current bit of the position.
            let pair = {
                let pair = (node, *sibling);

                // Swap node and sibling if needed
                chip.swap(layouter, pair, *pos)?
            };

            // Compute the node in layer l from its children:
            //     M^l_i = MerkleCRH(l, M^{l+1}_{2i}, M^{l+1}_{2i+1})
            node = chip.hash_layer(layouter, Q, l, pair.0, pair.1)?;
        }

        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::chip::MerkleChip;
    use super::{L_ORCHARD_MERKLE, MERKLE_DEPTH_ORCHARD, MerklePath};
    use crate::orchard::circuit::poseidon::test_util::{assert_dump, dump};
    use crate::orchard::circuit::sinsemilla::OrchardHashDomains;
    use crate::orchard::circuit::sinsemilla::chip::SinsemillaChip;
    use crate::orchard::circuit::sinsemilla::tests::{Config, configure, sample_a, sample_b};
    use crate::orchard::circuit::utilities::load_private;
    use crate::orchard::halo2::circuit::{Circuit, Layouter};
    use crate::orchard::halo2::dev::MockProver;
    use crate::orchard::halo2::plonk::ConstraintSystem;
    use crate::orchard::halo2::{Error, Value};
    use crate::orchard::{Fp, tree};

    const MERKLE_DEPTH: usize = 32;

    /// `MyMerkleCircuit` of the tests of the reference, on the configuration
    /// of the Orchard circuit (two Merkle chips), with the root constrained
    /// to a constant.
    struct MyMerkleCircuit {
        leaf: Value<Fp>,
        leaf_pos: Value<u32>,
        merkle_path: Value<[Fp; MERKLE_DEPTH]>,
        root: Fp,
    }

    impl MyMerkleCircuit {
        /// The circuit of a path, with the root of the native
        /// implementation.
        fn new(leaf: Fp, leaf_pos: u32, merkle_path: [Fp; MERKLE_DEPTH]) -> Self {
            // The fold of the test of the reference.
            let root = merkle_path
                .iter()
                .enumerate()
                .fold(leaf, |node, (l, sibling)| {
                    let (left, right) = if leaf_pos & (1 << l) == 0 {
                        (&node, sibling)
                    } else {
                        (sibling, &node)
                    };
                    tree::merkle_crh(l, left, right)
                });
            assert_eq!(
                root,
                tree::MerklePath::from_parts(leaf_pos, merkle_path).root(leaf)
            );
            MyMerkleCircuit {
                leaf: Value::known(leaf),
                leaf_pos: Value::known(leaf_pos),
                merkle_path: Value::known(merkle_path),
                root,
            }
        }

        /// A path of siblings `x, x^2 + 7, ...`.
        fn from_seed(leaf: Fp, leaf_pos: u32, seed: Fp) -> Self {
            let mut merkle_path = [Fp::ZERO; MERKLE_DEPTH];
            let mut x = seed;
            for node in merkle_path.iter_mut() {
                *node = x;
                x = x.square() + Fp::from_u64(7);
            }
            Self::new(leaf, leaf_pos, merkle_path)
        }

        /// The circuit of the reference dump.
        fn sample() -> Self {
            Self::from_seed(sample_a(), 0x9e37_79b9, sample_b())
        }
    }

    impl Circuit for MyMerkleCircuit {
        type Config = Config;

        fn without_witnesses(&self) -> Self {
            MyMerkleCircuit {
                leaf: Value::unknown(),
                leaf_pos: Value::unknown(),
                merkle_path: Value::unknown(),
                root: self.root,
            }
        }

        fn configure(&self, meta: &mut ConstraintSystem) -> Config {
            configure(meta)
        }

        fn synthesize(&self, config: Config, layouter: &mut Layouter<'_>) -> Result<(), Error> {
            // Load generator table (shared across both configs)
            SinsemillaChip::load(config.sinsemilla_config_1.clone(), layouter)?;

            // Construct Merkle chips which will be placed side-by-side in
            // the circuit.
            let chip_1 = MerkleChip::construct(config.merkle_config_1.clone());
            let chip_2 = MerkleChip::construct(config.merkle_config_2.clone());

            let leaf = load_private(
                layouter,
                config.merkle_config_1.cond_swap_config().a(),
                self.leaf,
            )?;

            let path = MerklePath::construct(
                [chip_1, chip_2],
                OrchardHashDomains::MerkleCrh,
                self.leaf_pos,
                self.merkle_path,
            );

            let computed_final_root = path.calculate_root(layouter, leaf)?;

            layouter.assign_region(|mut region| {
                let e = region.assign_advice_from_constant(config.advices[0], 0, self.root)?;
                region.constrain_equal(computed_final_root.cell(), e.cell())
            })
        }
    }

    #[test]
    fn constants() {
        assert_eq!(MERKLE_DEPTH_ORCHARD, tree::DEPTH);
        assert_eq!(L_ORCHARD_MERKLE, 255);
    }

    /// The layout is that of the reference: see
    /// `sinsemilla_chip_matches_reference` in the parent module for how the
    /// expected values were produced (`out/merkle_events.txt` of the same
    /// scratch project, whose circuit is the `MyMerkleCircuit` of the tests
    /// of `halo2_gadgets::sinsemilla::merkle` on Orchard's configuration and
    /// hash domain, with the `V1` floor planner). With its 258 regions, many
    /// of the same advice area, this layout depends on the legacy pdqsort
    /// of the floor planner.
    #[test]
    fn merkle_chip_matches_reference() {
        let circuit = MyMerkleCircuit::sample();
        // The root the reference computed for this path.
        let mut root: [u8; 32] =
            hex::decode("0dba6d49cb5f0a5a4045509843d2b0dbf2ac060b43982ab4cca278f09e3d0e11")
                .unwrap()
                .try_into()
                .unwrap();
        root.reverse();
        assert_eq!(circuit.root.to_bytes(), root);

        let (pinned, events) = dump(&circuit);
        assert_dump(
            "merkle_config_pinned",
            &pinned,
            20919,
            "b4b22f43f0ff5705280ae1bce5f7f9a48a5b1714786bcb56d74cf7cd5934fe7b",
        );
        assert_dump(
            "merkle_events",
            &events,
            1701712,
            "f834064a06f69a48233413dfc605784328d68d5c51339ad35eec61b5a9f5706b",
        );
    }

    /// The `merkle_chip` test of the reference: the circuit is satisfied by
    /// a valid path.
    #[test]
    fn merkle_chip() {
        let circuit = MyMerkleCircuit::sample();
        let prover = MockProver::run(11, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // Extreme positions and nodes.
        for (leaf, pos, seed) in [
            (Fp::ZERO, 0, Fp::ZERO),
            (-Fp::ONE, u32::MAX, -Fp::ONE),
            (tree::UNCOMMITTED, 1, Fp::from_u64(3)),
        ] {
            let circuit = MyMerkleCircuit::from_seed(leaf, pos, seed);
            let prover = MockProver::run(11, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    /// A wrong root does not satisfy the circuit.
    #[test]
    fn merkle_chip_rejects_wrong_root() {
        let valid = MyMerkleCircuit::sample();
        // The same path with another position: the root differs.
        let circuit = MyMerkleCircuit {
            leaf_pos: Value::known(0x9e37_79b8),
            ..valid
        };
        let prover = MockProver::run(11, &circuit, vec![]).unwrap();
        let err = prover.verify().unwrap_err();
        assert!(err.contains("copy constraint"), "{err}");
    }
}
