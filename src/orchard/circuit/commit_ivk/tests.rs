//! Tests of the CommitIvk gadget.
//!
//! [`MyCircuit`] is the circuit of the `commit_ivk` test of the reference
//! (`orchard` 0.16.0, `circuit::commit_ivk::tests`), with a deterministic
//! `rivk`.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use super::{CommitIvkChip, CommitIvkConfig, gadgets};
use crate::orchard::circuit::ecc::chip::{CircuitVersion, EccChip, EccConfig, T_P, T_Q};
use crate::orchard::circuit::ecc::{ScalarFixed, X};
use crate::orchard::circuit::gadget::assign_free_advice;
use crate::orchard::circuit::poseidon::test_util::{assert_dump, dump};
use crate::orchard::circuit::sinsemilla::chip::{SinsemillaChip, SinsemillaConfig};
use crate::orchard::circuit::sinsemilla::tests::{sample_a, sample_b};
use crate::orchard::circuit::utilities::lookup_range_check::LookupRangeCheckConfig;
use crate::orchard::halo2::circuit::{Circuit, Layouter};
use crate::orchard::halo2::dev::MockProver;
use crate::orchard::halo2::plonk::ConstraintSystem;
use crate::orchard::halo2::{Error, Value};
use crate::orchard::keys::{Scope, SpendingKey};
use crate::orchard::sinsemilla::{CommitDomain, le_bits};
use crate::orchard::{Fp, Fq};

/// The `i`-th scalar of the reference dumps (`sample_fq` of the scratch
/// project).
pub(crate) fn sample_fq(i: u64) -> Fq {
    (Fq::from_u128(0x0f1e2d3c4b5a6978_8796a5b4c3d2e1f0) + Fq::from_u64(i)).square()
        + Fq::from_u64(11)
}

/// `Commit^ivk_rivk(ak, nk)`, natively.
fn native(ak: &Fp, nk: &Fp, rivk: &Fq) -> Fp {
    CommitDomain::COMMIT_IVK
        .short_commit(
            le_bits(&ak.to_bytes(), 255).chain(le_bits(&nk.to_bytes(), 255)),
            rivk,
        )
        .unwrap()
}

/// The configuration of the test circuit.
#[derive(Clone, Debug)]
struct Config {
    sinsemilla_config: SinsemillaConfig,
    commit_ivk_config: CommitIvkConfig,
    ecc_config: EccConfig,
}

/// The circuit of the `commit_ivk` test of the reference.
#[derive(Default)]
struct MyCircuit {
    ak: Value<Fp>,
    nk: Value<Fp>,
    rivk: Value<Fq>,
}

impl MyCircuit {
    fn new(ak: Fp, nk: Fp, rivk: Fq) -> Self {
        MyCircuit {
            ak: Value::known(ak),
            nk: Value::known(nk),
            rivk: Value::known(rivk),
        }
    }
}

impl Circuit for MyCircuit {
    type Config = Config;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(&self, meta: &mut ConstraintSystem) -> Config {
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

        let constants = meta.fixed_column();
        meta.enable_constant(constants);

        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        let table_idx = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );
        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];

        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);
        let sinsemilla_config = SinsemillaChip::configure(
            meta,
            advices[..5].try_into().unwrap(),
            advices[2],
            lagrange_coeffs[0],
            lookup,
            range_check,
        );

        let commit_ivk_config = CommitIvkChip::configure(meta, advices);

        let ecc_config = EccChip::configure(meta, advices, lagrange_coeffs, range_check);

        Config {
            sinsemilla_config,
            commit_ivk_config,
            ecc_config,
        }
    }

    fn synthesize(&self, config: Config, layouter: &mut Layouter<'_>) -> Result<(), Error> {
        let Config {
            sinsemilla_config,
            commit_ivk_config,
            ecc_config,
        } = config;

        // Load the Sinsemilla generator lookup table used by the whole
        // circuit.
        SinsemillaChip::load(sinsemilla_config.clone(), layouter)?;

        // Construct a Sinsemilla chip
        let sinsemilla_chip = SinsemillaChip::construct(sinsemilla_config);

        // Construct an ECC chip
        let ecc_chip = EccChip::construct(ecc_config, CircuitVersion::AnchoredBase);

        let commit_ivk_chip = CommitIvkChip::construct(commit_ivk_config.clone());

        // Witness ak
        let ak = assign_free_advice(layouter, commit_ivk_config.advices[0], self.ak)?;

        // Witness nk
        let nk = assign_free_advice(layouter, commit_ivk_config.advices[0], self.nk)?;

        // Use a deterministic rivk
        let rivk_gadget = ScalarFixed::new(ecc_chip, layouter, self.rivk)?;

        let ivk: X = gadgets::commit_ivk(
            sinsemilla_chip,
            ecc_chip,
            commit_ivk_chip,
            layouter,
            ak,
            nk,
            rivk_gadget,
        )?;

        self.ak
            .zip(self.nk)
            .zip(self.rivk)
            .zip(ivk.inner().value().copied())
            .assert_if_known(|(((ak, nk), rivk), ivk)| native(ak, nk, rivk) == *ivk);

        Ok(())
    }
}

/// The witnesses of the reference dumps (`commit_ivk` in `main` of the
/// scratch project), with the SHA-256 hash of the dump of each: the name of
/// the case, `ak`, `nk`; `rivk` is `sample_fq(index)`.
fn cases() -> Vec<(&'static str, Fp, Fp, &'static str)> {
    let two_pow_254 = Fp::from_u128(1 << 127).square();
    let tq = Fp::from_u128(T_Q);
    let tp = Fp::from_u128(T_P);
    let two_pow_127 = Fp::from_u128(1 << 127);
    vec![
        (
            "zero",
            Fp::ZERO,
            Fp::ZERO,
            "8949f372b93206317299b4af56c2842439028bb3b0e00687550e2f501b6f8a41",
        ),
        (
            "tq_m1",
            tq - Fp::ONE,
            tq - Fp::ONE,
            "1bdaae53cadc68f73e263a78a589be7c6001aeb53dda33a08ad6cf8f64fd51eb",
        ),
        (
            "tq",
            tq,
            tq,
            "ee76efa9f45f10ef15381a5bc838b0276c8cc28a5116fa008044e3ad616a691e",
        ),
        (
            "tp_m1",
            tp - Fp::ONE,
            tp - Fp::ONE,
            "db4497c02072923ae910dcfbefd1109039843cc1e4fe3f62c6a99d9296b90793",
        ),
        (
            "tp",
            tp,
            tp,
            "414b05b151736e8076c8ff062a5f654f8d96b18c9be5a7b01992e4cd5c4e04a7",
        ),
        (
            "2p127_m1",
            two_pow_127 - Fp::ONE,
            two_pow_127 - Fp::ONE,
            "beb45005ff7c922d3864a0e5a990b69cfc98e1e0b54a4d37c23d03505699ca6e",
        ),
        (
            "2p127",
            two_pow_127,
            two_pow_127,
            "6b1ed414a52cf7eee0795c57561854bc44c940783693ec433bea0dea682be652",
        ),
        (
            "2p254_m1",
            two_pow_254 - Fp::ONE,
            two_pow_254 - Fp::ONE,
            "f0889fc3b479c197a7d3a2890dca10144743b9e005737aa1dc4162ec08cabf33",
        ),
        (
            "2p254",
            two_pow_254,
            two_pow_254,
            "47c18d2e80e98fc4eda1a400d4911ced060781d46328c41ef87c0e6dd9ea8a41",
        ),
        (
            "max",
            -Fp::ONE,
            -Fp::ONE,
            "80d87997c59266c970eaa758a891f8ea53b5a5db757c70e69c2ccf93a760f618",
        ),
        (
            "mixed",
            sample_a(),
            sample_b(),
            "75dd5b211dbf1d6d0baa5dc073fcd3ddc79f919eb7d4c6316ca8a17c14540743",
        ),
        (
            "mixed2",
            sample_b(),
            tp,
            "c97af00262763c2bbc7040bc89710ae6f10e8417c264c6c3408e3129a8d2dfb0",
        ),
    ]
}

/// Compares the dumps of every case with the reference's.
fn check_dumps() {
    for (i, (name, ak, nk, sha256)) in cases().into_iter().enumerate() {
        let circuit = MyCircuit::new(ak, nk, sample_fq(i as u64));
        let (pinned, events) = dump(&circuit);
        assert_dump(
            "commit_ivk_pinned",
            &pinned,
            69399,
            "83993fd7ab08fbd684f2e9c974dfedee78e117e6e42e79801a8a3fdd282ecda2",
        );
        assert_dump(
            &format!("commit_ivk_{name}_events"),
            &events,
            614321,
            sha256,
        );
    }
}

/// The constraint system and the layout are those of the reference.
///
/// The expected values are the lengths and SHA-256 hashes (`wc -c`,
/// `sha256sum`) of the dumps of the scratch project
/// `/tmp/claude-1000/sp/ref-notecommit/` (`cargo run --release`), which runs
/// `orchard::circuit::gadget::commit_ivk` of `orchard` 0.16.0
/// (`halo2_gadgets` 0.6.0, `halo2_proofs` 0.4.1) in the same circuit (the
/// one of the reference's `commit_ivk` test, with the `V1` floor planner and
/// the `floor-planner-v1-legacy-pdqsort` feature, as `orchard` enables it)
/// for the same witnesses, and writes the `{:?}` of
/// `ConstraintSystem::pinned()` after `configure`
/// (`out/commit_ivk_pinned.txt`) and the ordered log of every call the floor
/// planner makes on a recording `Assignment` backend
/// (`out/commit_ivk_<case>_events.txt`), as
/// [`dump`](crate::orchard::circuit::poseidon::test_util::dump) does (the
/// consecutive `L` lines, which the reference makes in the order of a
/// `HashMap`, are sorted there). The reference circuit is also checked there
/// with the reference `MockProver`.
#[test]
fn commit_ivk_matches_reference() {
    check_dumps();
}

/// The `commit_ivk` test of the reference: the circuit is satisfied by valid
/// witnesses (`synthesize` compares the result with the native
/// implementation).
#[test]
fn commit_ivk() {
    for (i, (name, ak, nk, _)) in cases().into_iter().enumerate() {
        if name != "tp" {
            continue;
        }
        let circuit = MyCircuit::new(ak, nk, sample_fq(i as u64));
        let prover = MockProver::run(11, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()), "{name}");
    }
}

/// The same for every case.
#[test]
#[ignore = "slow: the mock prover on every case"]
fn commit_ivk_all() {
    for (i, (name, ak, nk, _)) in cases().into_iter().enumerate() {
        let circuit = MyCircuit::new(ak, nk, sample_fq(i as u64));
        let prover = MockProver::run(11, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()), "{name}");
    }
}

/// The incoming viewing key of a full viewing key.
#[test]
fn commit_ivk_of_a_key() {
    let fvk = SpendingKey::from_bytes([7; 32]).unwrap().to_fvk();
    let ak = fvk.ak().to_point().x();
    let rivk = fvk.rivk(Scope::External);
    assert_eq!(
        native(&ak, &fvk.nk(), &rivk),
        fvk.to_ivk(Scope::External).ivk()
    );
    // `synthesize` compares the output of the gadget with `native`.
    let circuit = MyCircuit::new(ak, fvk.nk(), rivk);
    let (_, events) = dump(&circuit);
    assert_eq!(events.len(), 614321);
}

/// The first row of the region of the canonicity gate.
fn gate_row(prover: &MockProver) -> usize {
    let mut cs = ConstraintSystem::default();
    let config = MyCircuit::default().configure(&mut cs);
    let rows = &prover.selectors[config.commit_ivk_config.q_commit_ivk.0];
    assert_eq!(rows.iter().filter(|on| **on).count(), 1);
    rows.iter().position(|on| *on).unwrap()
}

/// The failures of the gates in the error of the mock prover.
fn gate_errors(err: &str) -> Vec<&str> {
    err.lines().filter(|l| l.starts_with("gate")).collect()
}

/// Tampered cells of the canonicity gate do not satisfy the circuit.
#[test]
fn commit_ivk_rejects_tampering() {
    // ak = nk = 0.
    let circuit = MyCircuit::new(Fp::ZERO, Fp::ZERO, sample_fq(0));
    let run = || MockProver::run(11, &circuit, vec![]).unwrap();
    let prover = run();
    let row = gate_row(&prover);
    assert_eq!(prover.verify(), Ok(()));
    let failure = |constraint: usize| {
        format!(
            "gate 'CommitIvk canonicity check' constraint {constraint} not satisfied on row {row}"
        )
    };

    // b_1 and d_1 are bits: 2 fails the boolean checks (constraints 0 and 1
    // of the gate).
    for (offset, constraint) in [(0, 0), (1, 1)] {
        let mut prover = run();
        prover.advice[4][row + offset] = Fp::from_u64(2);
        let err = prover.verify().unwrap_err();
        assert!(err.contains(&failure(constraint)), "{err}");
    }

    // The non-canonical encoding of ak = 0 as p = t_P + 2^254: a = t_P,
    // b_0 = 0, b_1 = 1, so b = 2^4, a' = 2^130 and z13_a' = 1. Both
    // decompositions hold, and only the canonicity check
    // `b_1 * z13_a_prime = 0` (constraint 9) fails.
    let mut prover = run();
    prover.advice[1][row] = Fp::from_u128(T_P);
    prover.advice[2][row] = Fp::from_u64(1 << 4);
    prover.advice[4][row] = Fp::ONE;
    prover.advice[7][row] = Fp::from_u128(1 << 65).square();
    prover.advice[8][row] = Fp::ONE;
    let err = prover.verify().unwrap_err();
    assert_eq!(gate_errors(&err), [failure(9)], "{err}");

    // The same for nk = 0 as p: b_2 + 2^5 c = t_P (b_2 = 1, t_P being odd),
    // d_0 = 0, d_1 = 1, so b = 2^5, d = 2^9, b2_c' = 2^140 and
    // z14_b2_c' = 1; only constraint 13 fails.
    let mut prover = run();
    let c = (Fp::from_u128(T_P) - Fp::ONE) * Fp::from_u64(32).invert().unwrap();
    prover.advice[5][row] = Fp::ONE;
    prover.advice[2][row] = Fp::from_u64(1 << 5);
    prover.advice[1][row + 1] = c;
    prover.advice[2][row + 1] = Fp::from_u64(1 << 9);
    prover.advice[4][row + 1] = Fp::ONE;
    prover.advice[7][row + 1] = Fp::from_u128(1 << 70).square();
    prover.advice[8][row + 1] = Fp::ONE;
    let err = prover.verify().unwrap_err();
    assert_eq!(gate_errors(&err), [failure(13)], "{err}");
}

/// Every cell of the region of the canonicity gate is constrained.
#[test]
#[ignore = "slow: the mock prover for every cell of the gate"]
fn commit_ivk_rejects_tampering_all() {
    let circuit = MyCircuit::new(Fp::ZERO, Fp::ZERO, sample_fq(0));
    let run = || MockProver::run(11, &circuit, vec![]).unwrap();
    let row = gate_row(&run());

    // Every cell of the region is constrained.
    let mut tampered = run();
    for (column, offset) in (0..9)
        .map(|c| (c, 0))
        .chain([0, 1, 2, 3, 4, 6, 7, 8].map(|c| (c, 1)))
    {
        let original = tampered.advice[column][row + offset];
        tampered.advice[column][row + offset] += Fp::ONE;
        assert!(
            tampered.verify().is_err(),
            "column {column} offset {offset}"
        );
        tampered.advice[column][row + offset] = original;
    }
    assert_eq!(tampered.verify(), Ok(()));
}
