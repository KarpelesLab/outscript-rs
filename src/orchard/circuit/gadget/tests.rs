//! Tests of `derive_nullifier` and `value_commit_orchard`.
//!
//! The reference has no test of its own for these two gadgets (they are
//! covered by the Action circuit): [`MyCircuit`] runs both on the columns
//! their chips have in the Action circuit.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use super::{assign_free_advice, derive_nullifier, value_commit_orchard};
use crate::orchard::circuit::add_chip::{AddChip, AddConfig};
use crate::orchard::circuit::commit_ivk::tests::sample_fq;
use crate::orchard::circuit::ecc::chip::{CircuitVersion, EccChip, EccConfig};
use crate::orchard::circuit::ecc::{NonIdentityPoint, Point, ScalarFixed, ScalarFixedShort};
use crate::orchard::circuit::poseidon::test_util::{assert_dump, dump};
use crate::orchard::circuit::poseidon::{Pow5Chip, Pow5Config};
use crate::orchard::circuit::sinsemilla::tests::{sample_a, sample_b};
use crate::orchard::circuit::utilities::lookup_range_check::LookupRangeCheckConfig;
use crate::orchard::constants::{NULLIFIER_K, VALUE_COMMIT_R, VALUE_COMMIT_V};
use crate::orchard::halo2::circuit::{Circuit, Layouter};
use crate::orchard::halo2::dev::MockProver;
use crate::orchard::halo2::plonk::{Advice, Column, ConstraintSystem};
use crate::orchard::halo2::{Error, Value};
use crate::orchard::keys::{DiversifierIndex, Scope, SpendingKey};
use crate::orchard::note::{Note, Nullifier};
use crate::orchard::value::ValueCommitment;
use crate::orchard::{Fp, Fq, pallas, poseidon};

/// `DeriveNullifier_nk(rho, psi, cm)`, natively.
fn native_nullifier(nk: Fp, rho: Fp, psi: Fp, cm: &pallas::Affine) -> Fp {
    let scalar = poseidon::hash(nk, rho) + psi;
    NULLIFIER_K
        .to_point()
        .mul(&Fq::from_fp(&scalar))
        .add_affine(cm)
        .to_affine()
        .x()
}

/// `ValueCommit^Orchard_rcv(v)`, natively.
fn native_value_commit(magnitude: u64, negative: bool, rcv: &Fq) -> pallas::Affine {
    let v = if negative {
        -Fq::from_u64(magnitude)
    } else {
        Fq::from_u64(magnitude)
    };
    VALUE_COMMIT_V
        .to_point()
        .mul(&v)
        .add(&VALUE_COMMIT_R.to_point().mul(rcv))
        .to_affine()
}

/// The configuration of the test circuit.
#[derive(Clone, Debug)]
struct Config {
    advices: [Column<Advice>; 10],
    add_config: AddConfig,
    ecc_config: EccConfig,
    poseidon_config: Pow5Config,
}

/// A nullifier derivation and a value commitment.
#[derive(Default)]
struct MyCircuit {
    nk: Value<Fp>,
    rho: Value<Fp>,
    psi: Value<Fp>,
    cm: Value<pallas::Affine>,
    /// The magnitude and the sign (negative if true) of the value.
    v: Value<(u64, bool)>,
    rcv: Value<Fq>,
    /// Added to the expected nullifier (to make a wrong one).
    nf_offset: Fp,
}

impl Circuit for MyCircuit {
    type Config = Config;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    /// The columns of these chips in the Action circuit.
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

        // Addition of two field elements.
        let add_config = AddChip::configure(meta, advices[7], advices[8], advices[6]);

        let table_idx = meta.lookup_table_column();

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
        let rc_a = lagrange_coeffs[2..5].try_into().unwrap();
        let rc_b = lagrange_coeffs[5..8].try_into().unwrap();

        // Also use the first Lagrange coefficient column for loading global
        // constants.
        meta.enable_constant(lagrange_coeffs[0]);

        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

        let ecc_config = EccChip::configure(meta, advices, lagrange_coeffs, range_check);

        let poseidon_config = Pow5Chip::configure(
            meta,
            advices[6..9].try_into().unwrap(),
            advices[5],
            rc_a,
            rc_b,
        );

        Config {
            advices,
            add_config,
            ecc_config,
            poseidon_config,
        }
    }

    fn synthesize(&self, config: Config, layouter: &mut Layouter<'_>) -> Result<(), Error> {
        // Load the 10-bit lookup table.
        config
            .ecc_config
            .lookup_config
            .load_range_check_table(layouter)?;

        let ecc_chip = EccChip::construct(config.ecc_config, CircuitVersion::AnchoredBase);
        let column = config.advices[0];

        // Nullifier.
        {
            let nk = assign_free_advice(layouter, column, self.nk)?;
            let rho = assign_free_advice(layouter, column, self.rho)?;
            let psi = assign_free_advice(layouter, column, self.psi)?;
            let cm = Point::new(ecc_chip, layouter, self.cm)?;

            let nf = derive_nullifier(
                layouter,
                Pow5Chip::construct(config.poseidon_config.clone()),
                AddChip::construct(config.add_config.clone()),
                ecc_chip,
                rho,
                &psi,
                &cm,
                nk,
            )?;

            let expected = self
                .nk
                .zip(self.rho)
                .zip(self.psi.zip(self.cm))
                .map(|((nk, rho), (psi, cm))| native_nullifier(nk, rho, psi, &cm) + self.nf_offset);
            layouter.assign_region(|mut region| {
                let cell = region.assign_advice(column, 0, || expected)?;
                region.constrain_equal(nf.inner().cell(), cell.cell())
            })?;
        }

        // Value commitment.
        {
            let magnitude = assign_free_advice(
                layouter,
                column,
                self.v.map(|(magnitude, _)| Fp::from_u64(magnitude)),
            )?;
            let sign = assign_free_advice(
                layouter,
                column,
                self.v
                    .map(|(_, negative)| if negative { -Fp::ONE } else { Fp::ONE }),
            )?;
            let v = ScalarFixedShort::new(ecc_chip, layouter, (magnitude, sign))?;
            let rcv = ScalarFixed::new(ecc_chip, layouter, self.rcv)?;

            let cv = value_commit_orchard(layouter, ecc_chip, v, rcv)?;

            let expected = self
                .v
                .zip(self.rcv)
                .map(|((magnitude, negative), rcv)| native_value_commit(magnitude, negative, &rcv));
            let expected = NonIdentityPoint::new(ecc_chip, layouter, expected)?;
            cv.constrain_equal(layouter, &expected)?;
        }

        Ok(())
    }
}

/// A witness of the reference dumps: the name of the case, `nk`, `rho`,
/// `psi`, `cm`, the magnitude and the sign of the value, and the SHA-256
/// hash of the dump.
type Case = (
    &'static str,
    Fp,
    Fp,
    Fp,
    pallas::Affine,
    u64,
    bool,
    &'static str,
);

/// The witnesses of the reference dumps (`gadget` in `main` of the scratch
/// project); `rcv` is `sample_fq(200 + index)`.
fn cases() -> Vec<Case> {
    let g = pallas::Point::GENERATOR;
    let p = g.mul_vartime(&Fq::from_u64(7919)).to_affine();
    let q = g.mul_vartime(&Fq::from_u64(104729)).to_affine();
    let (a, b) = (sample_a(), sample_b());
    vec![
        (
            "mixed",
            a,
            b,
            a.square(),
            p,
            0x0123_4567_89ab_cdef,
            false,
            "670d4a90d8bc378d1c148dea9b6f2e7358d939a54e9549d2324ce027d1880431",
        ),
        (
            "zero",
            Fp::ZERO,
            Fp::ZERO,
            Fp::ZERO,
            q,
            0,
            true,
            "47e3650c6c0b5b39a4d12134feeaa715d9e9acfd83537781846a74c74c1258c5",
        ),
        (
            "max",
            -Fp::ONE,
            -Fp::ONE,
            -Fp::ONE,
            p.neg(),
            u64::MAX,
            true,
            "94910d7aafb35852115aacd361c195f62977f4d1f8462d23be202f8c96e21983",
        ),
    ]
}

/// The circuit of a case.
fn circuit(index: usize, case: &Case) -> MyCircuit {
    let (_, nk, rho, psi, cm, v, negative, _) = *case;
    MyCircuit {
        nk: Value::known(nk),
        rho: Value::known(rho),
        psi: Value::known(psi),
        cm: Value::known(cm),
        v: Value::known((v, negative)),
        rcv: Value::known(sample_fq(200 + index as u64)),
        nf_offset: Fp::ZERO,
    }
}

/// Compares the dumps of every case with the reference's.
fn check_dumps() {
    for (i, case) in cases().iter().enumerate() {
        let (name, sha256) = (case.0, case.7);
        let (pinned, events) = dump(&circuit(i, case));
        assert_dump(
            "gadget_pinned",
            &pinned,
            74592,
            "05545a0ab9e7194ca6b6cffd49c9144712c9b7efd279eb9da92da344a6ceeef9",
        );
        assert_dump(&format!("gadget_{name}_events"), &events, 661323, sha256);
    }
}

/// The constraint system and the layout are those of the reference.
///
/// The expected values are the lengths and SHA-256 hashes (`wc -c`,
/// `sha256sum`) of the dumps of the scratch project
/// `/tmp/claude-1000/sp/ref-notecommit/` (`cargo run --release`), which runs
/// `orchard::circuit::gadget::derive_nullifier` of `orchard` 0.16.0
/// (`halo2_gadgets` 0.6.0, `halo2_proofs` 0.4.1) and the body of
/// `value_commit_orchard` (which `orchard` does not export) in the same
/// circuit, with the `V1` floor planner and the
/// `floor-planner-v1-legacy-pdqsort` feature, for the same witnesses, and
/// writes the `{:?}` of `ConstraintSystem::pinned()` after `configure`
/// (`out/gadget_pinned.txt`) and the ordered log of every call the floor
/// planner makes on a recording `Assignment` backend
/// (`out/gadget_<case>_events.txt`), as
/// [`dump`](crate::orchard::circuit::poseidon::test_util::dump) does. The
/// reference circuit is also checked there with the reference `MockProver`.
/// The expected nullifier and value commitment in the dump come from the
/// primitives of the reference, and ours from the native implementation of
/// this crate.
#[test]
fn gadgets_match_reference() {
    check_dumps();
}

/// The circuit is satisfied by valid witnesses, and not by a wrong
/// nullifier.
#[test]
fn nullifier_and_value_commitment() {
    let cases = cases();
    let mut circuit = circuit(2, &cases[2]);
    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    circuit.nf_offset = Fp::ONE;
    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    let err = prover.verify().unwrap_err();
    assert!(err.contains("copy constraint"), "{err}");
}

/// The same for every case.
#[test]
#[ignore = "slow: the mock prover on every case"]
fn nullifier_and_value_commitment_all() {
    for (i, case) in cases().iter().enumerate() {
        let prover = MockProver::run(11, &circuit(i, case), vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()), "{}", case.0);
    }
}

/// The nullifier of a note and a value commitment, as the wallet computes
/// them.
#[test]
fn nullifier_of_a_note() {
    let fvk = SpendingKey::from_bytes([7; 32]).unwrap().to_fvk();
    let recipient = fvk.address_at(DiversifierIndex::from_bytes([0; 11]), Scope::External);
    let rho = Nullifier::from_fp(sample_a());
    let note = Note::from_parts(recipient, 123_456_789, rho, [9; 32]).unwrap();
    assert_eq!(
        native_nullifier(fvk.nk(), sample_a(), note.psi(), &note.commitment()),
        note.nullifier(&fvk).to_fp()
    );
    let rcv = sample_fq(300);
    assert_eq!(
        native_value_commit(5000, true, &rcv),
        ValueCommitment::derive(-5000, &rcv).to_point()
    );
    assert_eq!(
        native_value_commit(u64::MAX, false, &rcv),
        ValueCommitment::derive(u64::MAX as i128, &rcv).to_point()
    );

    // The circuit constrains the outputs of the gadgets to be the native
    // values.
    let circuit = MyCircuit {
        nk: Value::known(fvk.nk()),
        rho: Value::known(sample_a()),
        psi: Value::known(note.psi()),
        cm: Value::known(note.commitment()),
        v: Value::known((5000, true)),
        rcv: Value::known(rcv),
        nf_offset: Fp::ZERO,
    };
    let (_, events) = dump(&circuit);
    assert_eq!(events.len(), 661323);
}
