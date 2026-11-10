//! The Sinsemilla hash gadget (port of `halo2_gadgets::sinsemilla`).
//!
//! Specialized to what Orchard instantiates: the curve is Pallas, `K = 10`,
//! `MAX_WORDS = C = 253`, the chip is [`chip::SinsemillaChip`] and the hash
//! domains are [`OrchardHashDomains`]. The `SinsemillaInstructions`,
//! `HashDomains`, `CommitDomains` and `FixedPoints` traits of the reference
//! are gone: their methods are inherent methods of the chip, with the same
//! names and arguments.
//!
//! Dropped, as Orchard does not use them: `hash_to_point_with_private_init`
//! / `hash_with_private_init` / `q_init` (the ZSA "hash from a private
//! point" paths, together with the `allow_init_from_private_point` flag of
//! the chip) and the private `from_bitstring` constructors, which only the
//! tests of the reference call.
//!
//! [`HashDomain`] has no ECC chip, as the ECC gadget layer is not ported
//! yet: `hash_to_point` returns the [`NonIdentityEccPoint`] of the chip
//! (the `inner` of the reference's `ecc::NonIdentityPoint`) and `hash` the
//! cell of its x-coordinate (the `inner` of `ecc::X`).

use alloc::vec::Vec;

use self::chip::{RunningSum, SinsemillaChip};
use crate::orchard::circuit::ecc::chip::NonIdentityEccPoint;
use crate::orchard::circuit::utilities::{FieldValue, RangeConstrained};
use crate::orchard::halo2::circuit::{AssignedCell, Layouter};
use crate::orchard::halo2::{Error, Value};
use crate::orchard::sinsemilla::K;
use crate::orchard::{Fp, constants, pallas};

pub(crate) mod chip;
pub(crate) mod merkle;
mod message;

/// The hash domains of Orchard (`orchard::constants::OrchardHashDomains`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum OrchardHashDomains {
    /// The message part of `NoteCommit^Orchard`.
    NoteCommit,
    /// The message part of `Commit^ivk`.
    CommitIvk,
    /// `MerkleCRH^Orchard`.
    MerkleCrh,
}

impl OrchardHashDomains {
    /// The starting point `Q` of the domain (`HashDomains::Q`).
    #[allow(non_snake_case)]
    pub(crate) fn Q(&self) -> pallas::Affine {
        match self {
            OrchardHashDomains::CommitIvk => constants::COMMIT_IVK_Q,
            OrchardHashDomains::NoteCommit => constants::NOTE_COMMIT_Q,
            OrchardHashDomains::MerkleCrh => constants::MERKLE_CRH_Q,
        }
    }
}

/// The commit domains of Orchard (`orchard::constants::OrchardCommitDomains`).
///
/// Only the hash domain is available for now: `r()` (the fixed base `R` of
/// the blinding factor, `OrchardFixedBasesFull::{NoteCommitR, CommitIvkR}`)
/// needs the fixed bases of the ECC chip.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum OrchardCommitDomains {
    /// `NoteCommit^Orchard`.
    NoteCommit,
    /// `Commit^ivk`.
    CommitIvk,
}

impl OrchardCommitDomains {
    /// The hash domain of the message (`CommitDomains::hash_domain`).
    pub(crate) fn hash_domain(&self) -> OrchardHashDomains {
        match self {
            Self::NoteCommit => OrchardHashDomains::NoteCommit,
            Self::CommitIvk => OrchardHashDomains::CommitIvk,
        }
    }
}

/// A message to be hashed.
///
/// Composed of [`MessagePiece`]s with bitlength some multiple of `K`.
#[derive(Clone, Debug)]
pub(crate) struct Message {
    chip: SinsemillaChip,
    inner: message::Message,
}

impl Message {
    /// Constructs a message from a vector of [`MessagePiece`]s.
    pub(crate) fn from_pieces(chip: SinsemillaChip, pieces: Vec<MessagePiece>) -> Self {
        Self {
            chip,
            inner: pieces
                .into_iter()
                .map(|piece| piece.inner)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

/// A message piece with a bitlength of some multiple of `K`.
///
/// The piece must fit within a base field element.
#[derive(Clone, Debug)]
pub(crate) struct MessagePiece {
    inner: message::MessagePiece,
}

impl MessagePiece {
    /// Returns the inner MessagePiece contained in this gadget.
    pub(crate) fn inner(&self) -> message::MessagePiece {
        self.inner.clone()
    }

    /// Constructs a `MessagePiece` from a field element. The field element
    /// must be pre-witnessed.
    pub(crate) fn from_field_elem(
        chip: SinsemillaChip,
        layouter: &mut Layouter<'_>,
        field_elem: Value<Fp>,
        num_words: usize,
    ) -> Result<Self, Error> {
        let inner = chip.witness_message_piece(layouter, field_elem, num_words)?;
        Ok(Self { inner })
    }

    /// Constructs a `MessagePiece` by concatenating a sequence of
    /// [`RangeConstrained`] subpieces.
    ///
    /// # Panics
    ///
    /// Panics if the total number of bits is not a multiple of `K`, or if
    /// one of the subpieces starts at bit 64 or above.
    pub(crate) fn from_subpieces(
        chip: SinsemillaChip,
        layouter: &mut Layouter<'_>,
        subpieces: impl IntoIterator<Item = RangeConstrained<Value<Fp>>>,
    ) -> Result<Self, Error> {
        let (field_elem, total_bits) =
            subpieces
                .into_iter()
                .fold((Value::known(Fp::ZERO), 0), |(acc, bits), subpiece| {
                    assert!(bits < 64);
                    let subpiece_shifted = subpiece
                        .inner()
                        .value()
                        .map(|v| Fp::from_u64(1 << bits) * *v);
                    (acc + subpiece_shifted, bits + subpiece.num_bits())
                });

        // Message must be composed of `K`-bit words.
        assert_eq!(total_bits % K, 0);
        let num_words = total_bits / K;

        Self::from_field_elem(chip, layouter, field_elem, num_words)
    }
}

/// A domain in which $\mathsf{SinsemillaHashToPoint}$ and
/// $\mathsf{SinsemillaHash}$ can be used.
#[derive(Debug)]
#[allow(non_snake_case)]
pub(crate) struct HashDomain {
    sinsemilla_chip: SinsemillaChip,
    pub(crate) Q: pallas::Affine,
}

impl HashDomain {
    /// Constructs a new `HashDomain` for the given domain.
    ///
    /// The reference also takes the ECC chip, between the two arguments, to
    /// wrap the result as a point of the ECC gadget.
    pub(crate) fn new(sinsemilla_chip: SinsemillaChip, domain: &OrchardHashDomains) -> Self {
        HashDomain {
            sinsemilla_chip,
            Q: domain.Q(),
        }
    }

    /// $\mathsf{SinsemillaHashToPoint}$ from
    /// [§ 5.4.1.9](https://zips.z.cash/protocol/protocol.pdf#concretesinsemillahash).
    ///
    /// Returns the point and the running sum of each piece of the message.
    pub(crate) fn hash_to_point(
        &self,
        layouter: &mut Layouter<'_>,
        message: Message,
    ) -> Result<(NonIdentityEccPoint, Vec<RunningSum>), Error> {
        assert_eq!(self.sinsemilla_chip, message.chip);
        self.sinsemilla_chip
            .hash_to_point(layouter, self.Q, message.inner)
    }

    /// $\mathsf{SinsemillaHash}$ from
    /// [§ 5.4.1.9](https://zips.z.cash/protocol/protocol.pdf#concretesinsemillahash).
    pub(crate) fn hash(
        &self,
        layouter: &mut Layouter<'_>,
        message: Message,
    ) -> Result<(AssignedCell<Fp>, Vec<RunningSum>), Error> {
        assert_eq!(self.sinsemilla_chip, message.chip);
        let (p, zs) = self.hash_to_point(layouter, message)?;
        Ok((SinsemillaChip::extract(&p), zs))
    }
}

// TODO(CommitDomain): port `halo2_gadgets::sinsemilla::CommitDomain`
// (`halo2_gadgets-0.6.0/src/sinsemilla.rs`, after `HashDomain`) here once
// the ECC gadget layer exists:
//
//   struct CommitDomain { M: HashDomain, R: ecc::FixedPoint }
//   new(sinsemilla_chip, ecc_chip, &OrchardCommitDomains)
//       M = HashDomain::new(sinsemilla_chip, &domain.hash_domain()),
//       R = ecc::FixedPoint::from_inner(ecc_chip, domain.r())
//   blinding_factor(layouter, r) = self.R.mul(layouter, r)?.0
//   commit(layouter, message, r):
//       let (blind, _) = self.R.mul(layouter, r)?;                 // "[r] R"
//       let (p, zs) = self.M.hash_to_point(layouter, message)?;    // "M"
//       let commitment = p.add(layouter, &blind)?;                 // "M + [r] R"
//       Ok((commitment, zs))
//   short_commit(layouter, message, r) = commit(..) then extract_p()
//
// in that order (the regions are laid out in call order). It also needs
// `OrchardCommitDomains::r()`.

#[cfg(test)]
pub(crate) mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::chip::{SinsemillaChip, SinsemillaConfig};
    use super::merkle::chip::{MerkleChip, MerkleConfig};
    use super::{HashDomain, Message, MessagePiece, OrchardCommitDomains, OrchardHashDomains};
    use crate::orchard::Fp;
    use crate::orchard::circuit::poseidon::test_util::{assert_dump, dump};
    use crate::orchard::circuit::utilities::RangeConstrained;
    use crate::orchard::circuit::utilities::lookup_range_check::LookupRangeCheckConfig;
    use crate::orchard::halo2::circuit::{Circuit, Layouter};
    use crate::orchard::halo2::dev::MockProver;
    use crate::orchard::halo2::plonk::{Advice, Column, ConstraintSystem};
    use crate::orchard::halo2::{Error, Value};
    use crate::orchard::sinsemilla;

    /// The configuration of the test circuits: the Sinsemilla and Merkle
    /// part of the Orchard circuit.
    #[derive(Clone, Debug)]
    pub(crate) struct Config {
        pub(crate) advices: [Column<Advice>; 10],
        pub(crate) sinsemilla_config_1: SinsemillaConfig,
        pub(crate) sinsemilla_config_2: SinsemillaConfig,
        pub(crate) merkle_config_1: MerkleConfig,
        pub(crate) merkle_config_2: MerkleConfig,
    }

    /// The Sinsemilla / Merkle part of `configure` of
    /// `orchard-0.16.0/src/circuit.rs`: two Sinsemilla chips side by side on
    /// ten advice columns, sharing the generator table and the range check;
    /// the first Lagrange column holds the constants and the y_Q of the
    /// first chip.
    pub(crate) fn configure(meta: &mut ConstraintSystem) -> Config {
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        // Fixed columns for the Sinsemilla generator lookup table
        let table_idx = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        let lagrange_coeffs = [meta.fixed_column(), meta.fixed_column()];
        meta.enable_constant(lagrange_coeffs[0]);

        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

        let (sinsemilla_config_1, merkle_config_1) = {
            let sinsemilla_config_1 = SinsemillaChip::configure(
                meta,
                advices[..5].try_into().unwrap(),
                advices[6],
                lagrange_coeffs[0],
                lookup,
                range_check,
            );
            let merkle_config_1 = MerkleChip::configure(meta, sinsemilla_config_1.clone());

            (sinsemilla_config_1, merkle_config_1)
        };

        let (sinsemilla_config_2, merkle_config_2) = {
            let sinsemilla_config_2 = SinsemillaChip::configure(
                meta,
                advices[5..].try_into().unwrap(),
                advices[7],
                lagrange_coeffs[1],
                lookup,
                range_check,
            );
            let merkle_config_2 = MerkleChip::configure(meta, sinsemilla_config_2.clone());

            (sinsemilla_config_2, merkle_config_2)
        };

        Config {
            advices,
            sinsemilla_config_1,
            sinsemilla_config_2,
            merkle_config_1,
            merkle_config_2,
        }
    }

    /// The first witness of the reference dumps.
    pub(crate) fn sample_a() -> Fp {
        Fp::from_raw([
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            0x0f1e_2d3c_4b5a_6978,
            0x1234_5678_9abc_def0,
        ])
    }

    /// The second witness of the reference dumps.
    pub(crate) fn sample_b() -> Fp {
        Fp::from_raw([
            0x1111_2222_3333_4444,
            0x5555_6666_7777_8888,
            0x9999_aaaa_bbbb_cccc,
            0x2ddd_eeee_ffff_0000,
        ])
    }

    fn bits(v: &Fp, range: core::ops::Range<usize>) -> Vec<bool> {
        range.map(|i| v.bit(i)).collect()
    }

    /// Three Sinsemilla hashes: MerkleCrh on chip 1 (pieces of 1, 25 and 25
    /// words), NoteCommit (pieces of 25, 1, 25 and 2 words) and CommitIvk
    /// (one piece of 25 words) on chip 2. The x-coordinate of each result is
    /// constrained to a constant.
    struct HashCircuit {
        l: Value<Fp>,
        left: Value<Fp>,
        right: Value<Fp>,
        d: Value<Fp>,
        expected: [Fp; 3],
    }

    impl HashCircuit {
        /// The three hashes, from the native implementation.
        fn expected(l: u64, left: &Fp, right: &Fp, d: u64) -> [Fp; 3] {
            let h = |domain: OrchardHashDomains, msg: Vec<bool>| {
                sinsemilla::HashDomain::from_q(domain.Q())
                    .hash(msg)
                    .unwrap()
            };
            let l = Fp::from_u64(l);
            let d = Fp::from_u64(d);
            [
                h(
                    OrchardHashDomains::MerkleCrh,
                    [bits(&l, 0..10), bits(left, 0..250), bits(right, 0..250)].concat(),
                ),
                h(
                    OrchardHashDomains::NoteCommit,
                    [bits(left, 0..255), bits(right, 0..255), bits(&d, 0..20)].concat(),
                ),
                h(OrchardHashDomains::CommitIvk, bits(left, 0..250)),
            ]
        }

        fn new(l: u64, left: Fp, right: Fp, d: u64) -> Self {
            HashCircuit {
                l: Value::known(Fp::from_u64(l)),
                left: Value::known(left),
                right: Value::known(right),
                d: Value::known(Fp::from_u64(d)),
                expected: Self::expected(l, &left, &right, d),
            }
        }

        /// The circuit of the reference dumps.
        fn sample() -> Self {
            Self::new(0x2a5, sample_a(), sample_b(), 0xb_6c3d)
        }
    }

    fn hash_and_constrain(
        chip: &SinsemillaChip,
        layouter: &mut Layouter<'_>,
        domain: OrchardHashDomains,
        pieces: Vec<MessagePiece>,
        columns: &[Column<Advice>],
        expected: Fp,
    ) -> Result<(), Error> {
        let (point, zs) = HashDomain::new(chip.clone(), &domain)
            .hash_to_point(layouter, Message::from_pieces(chip.clone(), pieces))?;
        layouter.assign_region(|mut region| {
            let e = region.assign_advice_from_constant(columns[0], 0, expected)?;
            region.constrain_equal(point.x().cell(), e.cell())?;
            point.y().copy_advice(&mut region, columns[1], 0)?;
            zs[0][0].copy_advice(&mut region, columns[2], 0)?;
            zs.last().unwrap()[1].copy_advice(&mut region, columns[3], 0)?;
            Ok(())
        })
    }

    impl Circuit for HashCircuit {
        type Config = Config;

        fn without_witnesses(&self) -> Self {
            HashCircuit {
                l: Value::unknown(),
                left: Value::unknown(),
                right: Value::unknown(),
                d: Value::unknown(),
                expected: self.expected,
            }
        }

        fn configure(&self, meta: &mut ConstraintSystem) -> Config {
            configure(meta)
        }

        fn synthesize(&self, config: Config, layouter: &mut Layouter<'_>) -> Result<(), Error> {
            SinsemillaChip::load(config.sinsemilla_config_1.clone(), layouter)?;
            let chip1 = SinsemillaChip::construct(config.sinsemilla_config_1.clone());
            let chip2 = SinsemillaChip::construct(config.sinsemilla_config_2.clone());
            {
                let l = MessagePiece::from_field_elem(chip1.clone(), layouter, self.l, 1)?;
                let left = MessagePiece::from_subpieces(
                    chip1.clone(),
                    layouter,
                    [RangeConstrained::bitrange_of(self.left.as_ref(), 0..250)],
                )?;
                let right = MessagePiece::from_subpieces(
                    chip1.clone(),
                    layouter,
                    [RangeConstrained::bitrange_of(self.right.as_ref(), 0..250)],
                )?;
                hash_and_constrain(
                    &chip1,
                    layouter,
                    OrchardHashDomains::MerkleCrh,
                    vec![l, left, right],
                    &config.advices[..5],
                    self.expected[0],
                )?;
            }
            {
                let a = MessagePiece::from_subpieces(
                    chip2.clone(),
                    layouter,
                    [RangeConstrained::bitrange_of(self.left.as_ref(), 0..250)],
                )?;
                let b = MessagePiece::from_subpieces(
                    chip2.clone(),
                    layouter,
                    [
                        RangeConstrained::bitrange_of(self.left.as_ref(), 250..255),
                        RangeConstrained::bitrange_of(self.right.as_ref(), 0..5),
                    ],
                )?;
                let c = MessagePiece::from_subpieces(
                    chip2.clone(),
                    layouter,
                    [RangeConstrained::bitrange_of(self.right.as_ref(), 5..255)],
                )?;
                let d = MessagePiece::from_field_elem(chip2.clone(), layouter, self.d, 2)?;
                hash_and_constrain(
                    &chip2,
                    layouter,
                    OrchardCommitDomains::NoteCommit.hash_domain(),
                    vec![a, b, c, d],
                    &config.advices[5..],
                    self.expected[1],
                )?;
            }
            {
                let a = MessagePiece::from_subpieces(
                    chip2.clone(),
                    layouter,
                    [RangeConstrained::bitrange_of(self.left.as_ref(), 0..250)],
                )?;
                hash_and_constrain(
                    &chip2,
                    layouter,
                    OrchardCommitDomains::CommitIvk.hash_domain(),
                    vec![a],
                    &config.advices[5..],
                    self.expected[2],
                )?;
            }
            Ok(())
        }
    }

    /// The constraint system and the layout are those of the reference.
    ///
    /// The expected values are the SHA-256 hashes of the dumps of the
    /// scratch project `/tmp/claude-1000/sp/ref-sinsemilla/` (`cargo run`),
    /// which runs the chips of `halo2_gadgets` 0.6.0 on `halo2_proofs`
    /// 0.4.1 in the same circuit (same configuration, same witnesses, the
    /// `V1` floor planner with the `floor-planner-v1-legacy-pdqsort`
    /// feature, as `orchard` enables it) and writes the `{:?}` of
    /// `ConstraintSystem::pinned()` after `configure`
    /// (`out/config_pinned.txt`) and the ordered log of every call the
    /// floor planner makes on a recording `Assignment` backend
    /// (`out/hash_events.txt`), as
    /// [`dump`](crate::orchard::circuit::poseidon::test_util::dump) does.
    /// The reference fills the rest of the three table columns (the `L`
    /// lines) in the order of a `HashMap`, which changes from run to run:
    /// the scratch project sorts these three consecutive lines, which is
    /// the order they are made in here.
    #[test]
    fn sinsemilla_chip_matches_reference() {
        let circuit = HashCircuit::sample();
        // The hashes the reference computed for this message.
        let expected: Vec<[u8; 32]> = [
            "3532c5f086136c01be42ecc132b30bd432184ea09d6f7eb67701b5d0911f9cd5",
            "1b881d98a04e3e9b271cd6d136dd74a2152d89bb972510a4ff6cea66cb13051f",
            "20f62830cb809200d4621609dbda3096b9ed854bde453eaaf5d79115a101d0bc",
        ]
        .iter()
        .map(|h| {
            let mut bytes: [u8; 32] = hex::decode(h).unwrap().try_into().unwrap();
            bytes.reverse();
            bytes
        })
        .collect();
        assert_eq!(
            circuit.expected.map(|h| h.to_bytes()).to_vec(),
            expected,
            "native hashes"
        );

        let (pinned, events) = dump(&circuit);
        assert_dump(
            "sinsemilla_config_pinned",
            &pinned,
            20919,
            "b4b22f43f0ff5705280ae1bce5f7f9a48a5b1714786bcb56d74cf7cd5934fe7b",
        );
        assert_dump(
            "sinsemilla_hash_events",
            &events,
            444525,
            "b4da5ebf47e1ceb426553d566e8132b44fe2a2969d0591eab416eafe4945055e",
        );
    }

    /// The `sinsemilla_chip` test of the reference: the circuit is
    /// satisfied by a valid witness.
    #[test]
    fn sinsemilla_chip() {
        let circuit = HashCircuit::sample();
        let prover = MockProver::run(11, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    /// Other witnesses, and tampered ones.
    #[test]
    fn sinsemilla_chip_other_witnesses() {
        let mut x = Fp::from_u64(0x1234_5678_9abc_def1);
        let mut next = || {
            x = x.square() + Fp::from_u64(7);
            x
        };
        for (l, d) in [(0, 0), (1023, 0xf_ffff)] {
            let circuit = HashCircuit::new(l, next(), next(), d);
            let prover = MockProver::run(11, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
        // All-zero and all-one pieces.
        for v in [Fp::ZERO, -Fp::ONE] {
            let circuit = HashCircuit::new(0, v, v, 0);
            let prover = MockProver::run(11, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    /// A piece that does not fit in its words, or a wrong result, does not
    /// satisfy the circuit.
    #[test]
    fn sinsemilla_chip_rejects_tampering() {
        // `l` does not fit in one word: the last word of the piece is not in
        // the table.
        let mut circuit = HashCircuit::sample();
        circuit.l = Value::known(Fp::from_u64(1 << 10));
        let prover = MockProver::run(11, &circuit, vec![]).unwrap();
        let err = prover.verify().unwrap_err();
        assert!(err.contains("lookup"), "{err}");

        // A wrong expected hash: the copy constraint fails.
        let mut circuit = HashCircuit::sample();
        circuit.expected[1] += Fp::ONE;
        let prover = MockProver::run(11, &circuit, vec![]).unwrap();
        let err = prover.verify().unwrap_err();
        assert!(err.contains("copy constraint"), "{err}");
    }
}
