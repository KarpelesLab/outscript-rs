//! Tests of the NoteCommit gadget.
//!
//! [`MyCircuit`] is the circuit of the `note_commit` test of the reference
//! (`orchard` 0.16.0, `circuit::note_commit::tests`), with the points
//! `g_d` and `pk_d` given as such and a deterministic value and `rcm`.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use super::{NoteCommitChip, NoteCommitConfig, gadgets};
use crate::orchard::circuit::commit_ivk::tests::sample_fq;
use crate::orchard::circuit::ecc::chip::{CircuitVersion, EccChip, EccConfig, T_P, T_Q};
use crate::orchard::circuit::ecc::{NonIdentityPoint, ScalarFixed};
use crate::orchard::circuit::gadget::assign_free_advice;
use crate::orchard::circuit::poseidon::test_util::{assert_dump, dump};
use crate::orchard::circuit::sinsemilla::chip::SinsemillaChip;
use crate::orchard::circuit::sinsemilla::tests::{sample_a, sample_b};
use crate::orchard::circuit::utilities::lookup_range_check::LookupRangeCheckConfig;
use crate::orchard::halo2::circuit::{Circuit, Layouter};
use crate::orchard::halo2::dev::MockProver;
use crate::orchard::halo2::plonk::{ConstraintSystem, Selector};
use crate::orchard::halo2::{Error, Value};
use crate::orchard::keys::{DiversifierIndex, Scope, SpendingKey};
use crate::orchard::note::{Note, Nullifier};
use crate::orchard::sinsemilla::{CommitDomain, le_bits};
use crate::orchard::{Fp, Fq, pallas};

/// `NoteCommit^Orchard_rcm(g_d, pk_d, v, rho, psi)`, natively.
fn native(
    g_d: &pallas::Affine,
    pk_d: &pallas::Affine,
    value: u64,
    rho: &Fp,
    psi: &Fp,
    rcm: &Fq,
) -> pallas::Affine {
    CommitDomain::NOTE_COMMIT
        .commit(
            le_bits(&g_d.to_bytes(), 256)
                .chain(le_bits(&pk_d.to_bytes(), 256))
                .chain(le_bits(&value.to_le_bytes(), 64))
                .chain(le_bits(&rho.to_bytes(), 255))
                .chain(le_bits(&psi.to_bytes(), 255)),
            rcm,
        )
        .unwrap()
        .to_affine()
}

/// The circuit of the `note_commit` test of the reference.
#[derive(Default)]
struct MyCircuit {
    g_d: Value<pallas::Affine>,
    pk_d: Value<pallas::Affine>,
    value: Value<u64>,
    rho: Value<Fp>,
    psi: Value<Fp>,
    rcm: Value<Fq>,
}

impl MyCircuit {
    fn new(
        g_d: pallas::Affine,
        pk_d: pallas::Affine,
        value: u64,
        rho: Fp,
        psi: Fp,
        rcm: Fq,
    ) -> Self {
        MyCircuit {
            g_d: Value::known(g_d),
            pk_d: Value::known(pk_d),
            value: Value::known(value),
            rho: Value::known(rho),
            psi: Value::known(psi),
            rcm: Value::known(rcm),
        }
    }
}

impl Circuit for MyCircuit {
    type Config = (NoteCommitConfig, EccConfig);

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(&self, meta: &mut ConstraintSystem) -> Self::Config {
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

        // Shared fixed column for loading constants.
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
        let note_commit_config = NoteCommitChip::configure(meta, advices, sinsemilla_config);

        let ecc_config = EccChip::configure(meta, advices, lagrange_coeffs, range_check);

        (note_commit_config, ecc_config)
    }

    fn synthesize(&self, config: Self::Config, layouter: &mut Layouter<'_>) -> Result<(), Error> {
        let (note_commit_config, ecc_config) = config;

        // Load the Sinsemilla generator lookup table used by the whole
        // circuit.
        SinsemillaChip::load(note_commit_config.sinsemilla_config.clone(), layouter)?;

        // Construct a Sinsemilla chip
        let sinsemilla_chip =
            SinsemillaChip::construct(note_commit_config.sinsemilla_config.clone());

        // Construct an ECC chip
        let ecc_chip = EccChip::construct(ecc_config, CircuitVersion::AnchoredBase);

        // Construct a NoteCommit chip
        let note_commit_chip = NoteCommitChip::construct(note_commit_config.clone());

        // Witness g_d
        let g_d = NonIdentityPoint::new(ecc_chip, layouter, self.g_d)?;

        // Witness pk_d
        let pk_d = NonIdentityPoint::new(ecc_chip, layouter, self.pk_d)?;

        // Witness a u64 value.
        let value_var = assign_free_advice(layouter, note_commit_config.advices[0], self.value)?;

        // Witness rho
        let rho = assign_free_advice(layouter, note_commit_config.advices[0], self.rho)?;

        // Witness psi
        let psi = assign_free_advice(layouter, note_commit_config.advices[0], self.psi)?;

        let rcm_gadget = ScalarFixed::new(ecc_chip, layouter, self.rcm)?;

        let cm = gadgets::note_commit(
            layouter,
            sinsemilla_chip,
            ecc_chip,
            note_commit_chip,
            g_d.inner(),
            pk_d.inner(),
            value_var,
            rho,
            psi,
            rcm_gadget,
        )?;
        let expected_cm = {
            // Hash g★_d || pk★_d || i2lebsp_{64}(v) || rho || psi
            let point = self
                .g_d
                .zip(self.pk_d)
                .zip(self.value.zip(self.rcm))
                .zip(self.rho.zip(self.psi))
                .map(|(((g_d, pk_d), (value, rcm)), (rho, psi))| {
                    native(&g_d, &pk_d, value, &rho, &psi, &rcm)
                });
            NonIdentityPoint::new(ecc_chip, layouter, point)?
        };
        cm.constrain_equal(layouter, &expected_cm)
    }
}

/// A witness of the reference dumps: the name of the case, `g_d`, `pk_d`,
/// the value, `rho`, `psi`, and the SHA-256 hash of the dump.
type Case = (
    &'static str,
    pallas::Affine,
    pallas::Affine,
    u64,
    Fp,
    Fp,
    &'static str,
);

/// The witnesses of the reference dumps (`note_commit` in `main` of the
/// scratch project); `rcm` is `sample_fq(100 + index)`.
fn cases() -> Vec<Case> {
    let g = pallas::Point::GENERATOR;
    let p = g.mul_vartime(&Fq::from_u64(7919)).to_affine();
    let q = g.mul_vartime(&Fq::from_u64(104729)).to_affine();
    // The points of the reference's test: x = -1, y = 2 (even) or -2 (odd).
    let m_even = pallas::Affine::from_xy(-Fp::ONE, Fp::from_u64(2)).unwrap();
    let m_odd = pallas::Affine::from_xy(-Fp::ONE, -Fp::from_u64(2)).unwrap();
    // Both signs of y for every position.
    assert!(bool::from(p.y().is_odd()) && !bool::from(q.y().is_odd()));
    assert!(bool::from(m_odd.y().is_odd()) && !bool::from(m_even.y().is_odd()));

    let two_pow_254 = Fp::from_u128(1 << 127).square();
    let two_pow_127 = Fp::from_u128(1 << 127);
    let tq = Fp::from_u128(T_Q);
    let tp = Fp::from_u128(T_P);
    vec![
        (
            "zero",
            m_odd,
            m_odd,
            0,
            Fp::ZERO,
            Fp::ZERO,
            "e1ec1cd84e268a7a3db9d3de5d589a6e15b15cc9177d4318191195ae77ab0c71",
        ),
        (
            "tq_m1",
            m_even,
            m_even,
            u64::MAX,
            tq - Fp::ONE,
            tq - Fp::ONE,
            "d7a11be67da4eaa98ce274740545a6817896a47e32e9797196217eda127d0a80",
        ),
        (
            "tq",
            m_odd,
            m_even,
            0x0123_4567_89ab_cdef,
            tq,
            tq,
            "c1adf5248c412f1aac854dde1a75b7f673cdb686418419e27a95887a380286cc",
        ),
        (
            "2p127_m1",
            m_even,
            m_odd,
            1 << 58,
            two_pow_127 - Fp::ONE,
            two_pow_127 - Fp::ONE,
            "fd3cc02f9b4780eea6862fd6c07f2b8cbe6e3cf384fe65e76a8d6bf3c67732d3",
        ),
        (
            "2p127",
            p,
            q.neg(),
            (1 << 58) - 1,
            two_pow_127,
            two_pow_127,
            "501ed95af4b9cb726d69a714603c701ba9fdc1ec1674e138665555d0c811f7bd",
        ),
        (
            "2p254_m1",
            p.neg(),
            q,
            255,
            two_pow_254 - Fp::ONE,
            two_pow_254 - Fp::ONE,
            "6e118f97b87d109bfeda78fab68289fdb40a2ca98ccd8d7596946f0128cefa51",
        ),
        (
            "2p254",
            q,
            p,
            256,
            two_pow_254,
            two_pow_254,
            "a6398a3c863d7e1069a2dc48e97d8bceea26ea06f1f9903f226d4c022a221b39",
        ),
        (
            "tp_m1_tp",
            p,
            q,
            0xfedc_ba98_7654_3210,
            tp - Fp::ONE,
            tp,
            "2fcc77aaa0e2e5b7b09e7380d6d15584d513792e669a14af2f85261d89eae110",
        ),
        (
            "tp_tp_m1",
            q.neg(),
            p.neg(),
            1,
            tp,
            tp - Fp::ONE,
            "fdcc0224b01dc601040d1c2c904ebf1ea683ae11776ff664085dfad589793838",
        ),
        (
            "mixed",
            p,
            q,
            0x8000_0000_0000_0001,
            sample_a(),
            sample_b(),
            "d4a50300efd2169714e8d64f342d525f8ca77562d863eb08e7fe3fcca79d64e4",
        ),
        (
            "max",
            q,
            q.neg(),
            u64::MAX,
            -Fp::ONE,
            -Fp::ONE,
            "873e70da891ab690b142050ca6b5302dc10407b282694dd7b342def91a79c6a9",
        ),
    ]
}

/// The circuit of a case.
fn circuit(index: usize, case: &Case) -> MyCircuit {
    let (_, g_d, pk_d, value, rho, psi, _) = *case;
    MyCircuit::new(g_d, pk_d, value, rho, psi, sample_fq(100 + index as u64))
}

/// Compares the dumps of every case with the reference's.
fn check_dumps() {
    for (i, case) in cases().iter().enumerate() {
        let (name, sha256) = (case.0, case.6);
        let (pinned, events) = dump(&circuit(i, case));
        assert_dump(
            "note_commit_pinned",
            &pinned,
            77479,
            "e4481b7dc59b1f79c0a59455a36962bbc3a709fef38c3e9fcad139798c18e913",
        );
        assert_dump(
            &format!("note_commit_{name}_events"),
            &events,
            693416,
            sha256,
        );
    }
}

/// The constraint system and the layout are those of the reference.
///
/// The expected values are the lengths and SHA-256 hashes (`wc -c`,
/// `sha256sum`) of the dumps of the scratch project
/// `/tmp/claude-1000/sp/ref-notecommit/` (`cargo run --release`), which runs
/// `orchard::circuit::gadget::note_commit` of `orchard` 0.16.0
/// (`halo2_gadgets` 0.6.0, `halo2_proofs` 0.4.1) in the same circuit (the
/// one of the reference's `note_commit` test, with the `V1` floor planner
/// and the `floor-planner-v1-legacy-pdqsort` feature, as `orchard` enables
/// it) for the same witnesses, and writes the `{:?}` of
/// `ConstraintSystem::pinned()` after `configure`
/// (`out/note_commit_pinned.txt`) and the ordered log of every call the
/// floor planner makes on a recording `Assignment` backend
/// (`out/note_commit_<case>_events.txt`), as
/// [`dump`](crate::orchard::circuit::poseidon::test_util::dump) does (the
/// consecutive `L` lines, which the reference makes in the order of a
/// `HashMap`, are sorted there). The reference circuit is also checked there
/// with the reference `MockProver`. The expected commitment in the dump is
/// the one of the Sinsemilla primitives of the reference, and ours comes
/// from the native implementation of this crate.
#[test]
fn note_commit_matches_reference() {
    check_dumps();
}

/// The `note_commit` test of the reference: the circuit is satisfied by
/// valid witnesses.
#[test]
fn note_commit() {
    for (i, case) in cases().iter().enumerate() {
        if case.0 != "2p254" {
            continue;
        }
        let prover = MockProver::run(11, &circuit(i, case), vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()), "{}", case.0);
    }
}

/// The same for every case.
#[test]
#[ignore = "slow: the mock prover on every case"]
fn note_commit_all() {
    for (i, case) in cases().iter().enumerate() {
        let prover = MockProver::run(11, &circuit(i, case), vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()), "{}", case.0);
    }
}

/// The commitment of a note.
#[test]
fn note_commit_of_a_note() {
    let fvk = SpendingKey::from_bytes([7; 32]).unwrap().to_fvk();
    let recipient = fvk.address_at(DiversifierIndex::from_bytes([0; 11]), Scope::External);
    let rho = Nullifier::from_fp(sample_a());
    let note = Note::from_parts(recipient, 123_456_789, rho, [9; 32]).unwrap();
    let g_d = recipient.g_d().to_affine();
    assert_eq!(
        native(
            &g_d,
            &recipient.pk_d(),
            note.value(),
            &sample_a(),
            &note.psi(),
            &note.rcm()
        ),
        note.commitment()
    );
    // The circuit constrains the output of the gadget to be `native`.
    let circuit = MyCircuit::new(
        g_d,
        recipient.pk_d(),
        note.value(),
        sample_a(),
        note.psi(),
        note.rcm(),
    );
    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

/// The configuration of the NoteCommit chip in the test circuit.
fn config() -> NoteCommitConfig {
    let mut cs = ConstraintSystem::default();
    MyCircuit::default().configure(&mut cs).0
}

/// The rows a selector is enabled on.
fn rows(prover: &MockProver, selector: Selector) -> Vec<usize> {
    prover.selectors[selector.0]
        .iter()
        .enumerate()
        .filter_map(|(row, on)| on.then_some(row))
        .collect()
}

/// The failures of the gates in the error of the mock prover.
fn gate_errors(err: &str) -> Vec<&str> {
    err.lines().filter(|l| l.starts_with("gate")).collect()
}

/// Tampered cells of the gates do not satisfy the circuit.
#[test]
fn note_commit_rejects_tampering() {
    // g_d = pk_d = (-1, -2), value = rho = psi = 0.
    let cases = cases();
    let circuit = circuit(0, &cases[0]);
    let run = || MockProver::run(11, &circuit, vec![]).unwrap();
    let cfg = config();
    let prover = run();
    assert_eq!(prover.verify(), Ok(()));

    let (m, r, z) = (7, 8, 9);

    // b_1 is a bit: 2 fails the boolean check (constraint 0 of the gate).
    let row = rows(&prover, cfg.b.q_notecommit_b)[0];
    let mut tampered = run();
    tampered.advice[r][row] = Fp::from_u64(2);
    let err = tampered.verify().unwrap_err();
    assert!(
        err.contains(&format!(
            "gate 'NoteCommit MessagePiece b' constraint 0 not satisfied on row {row}"
        )),
        "{err}"
    );

    // The non-canonical encoding of rho = 0 as p = t_P + 2^254:
    // e_1 + 2^4 f = t_P (e_1 = 1, t_P being odd), g_0 = 1, so
    // e1_f' = 2^140 and z14_e1_f' = 1. The decomposition holds, and only
    // the canonicity check `g_0 * z14_e1_f_prime = 0` (constraint 3) fails.
    let row = rows(&prover, cfg.rho.q_notecommit_rho)[0];
    let mut tampered = run();
    let f = (Fp::from_u128(T_P) - Fp::ONE) * Fp::from_u64(16).invert().unwrap();
    tampered.advice[m][row] = Fp::ONE;
    tampered.advice[m][row + 1] = Fp::ONE;
    tampered.advice[r][row] = f;
    tampered.advice[r][row + 1] = Fp::from_u128(1 << 70).square();
    tampered.advice[z][row + 1] = Fp::ONE;
    let err = tampered.verify().unwrap_err();
    assert_eq!(
        gate_errors(&err),
        [format!(
            "gate 'NoteCommit input rho' constraint 3 not satisfied on row {row}"
        )],
        "{err}"
    );

    // The same for psi = 0: g_1 + 2^9 g_2 = t_P (g_1 = 1), h_0 = 0,
    // h_1 = 1, so g1_g2' = 2^130 and z13_g1_g2' = 1; only
    // `h_1 * z13_g1_g2_prime = 0` (constraint 4) fails.
    let row = rows(&prover, cfg.psi.q_notecommit_psi)[0];
    let mut tampered = run();
    let g_2 = (Fp::from_u128(T_P) - Fp::ONE) * Fp::from_u64(1 << 9).invert().unwrap();
    tampered.advice[m][row] = Fp::ONE;
    tampered.advice[m][row + 1] = Fp::ONE;
    tampered.advice[r][row] = g_2;
    tampered.advice[r][row + 1] = Fp::from_u128(1 << 65).square();
    tampered.advice[z][row + 1] = Fp::ONE;
    let err = tampered.verify().unwrap_err();
    assert_eq!(
        gate_errors(&err),
        [format!(
            "gate 'NoteCommit input psi' constraint 4 not satisfied on row {row}"
        )],
        "{err}"
    );
}

/// Every cell of the regions of the gates is constrained.
#[test]
#[ignore = "slow: the mock prover for every cell of the gates"]
fn note_commit_rejects_tampering_all() {
    let cases = cases();
    let circuit = circuit(0, &cases[0]);
    let run = || MockProver::run(11, &circuit, vec![]).unwrap();
    let cfg = config();
    let prover = run();

    // The regions of the gates, by selector, with the cells (column,
    // offset) each one assigns.
    let (l, m, r, z) = (6, 7, 8, 9);
    #[allow(clippy::type_complexity)]
    let regions: [(Selector, usize, &[(usize, usize)]); 11] = [
        (
            cfg.b.q_notecommit_b,
            1,
            &[(l, 0), (m, 0), (r, 0), (m, 1), (r, 1)],
        ),
        (
            cfg.d.q_notecommit_d,
            1,
            &[(l, 0), (m, 0), (r, 0), (m, 1), (r, 1)],
        ),
        (cfg.e.q_notecommit_e, 1, &[(l, 0), (m, 0), (r, 0)]),
        (cfg.g.q_notecommit_g, 1, &[(l, 0), (m, 0), (l, 1), (m, 1)]),
        (cfg.h.q_notecommit_h, 1, &[(l, 0), (m, 0), (r, 0)]),
        (
            cfg.g_d.q_notecommit_g_d,
            1,
            &[(l, 0), (m, 0), (m, 1), (r, 0), (r, 1), (z, 0), (z, 1)],
        ),
        (
            cfg.pk_d.q_notecommit_pk_d,
            1,
            &[(l, 0), (m, 0), (m, 1), (r, 0), (r, 1), (z, 0), (z, 1)],
        ),
        (
            cfg.value.q_notecommit_value,
            1,
            &[(l, 0), (m, 0), (r, 0), (z, 0)],
        ),
        (
            cfg.rho.q_notecommit_rho,
            1,
            &[(l, 0), (m, 0), (m, 1), (r, 0), (r, 1), (z, 0), (z, 1)],
        ),
        (
            cfg.psi.q_notecommit_psi,
            1,
            &[
                (l, 0),
                (l, 1),
                (m, 0),
                (m, 1),
                (r, 0),
                (r, 1),
                (z, 0),
                (z, 1),
            ],
        ),
        // y(g_d) and y(pk_d).
        (
            cfg.y_canon.q_y_canon,
            2,
            &[
                (5, 0),
                (6, 0),
                (7, 0),
                (8, 0),
                (9, 0),
                (5, 1),
                (6, 1),
                (7, 1),
                (8, 1),
                (9, 1),
            ],
        ),
    ];
    let mut tampered = run();
    for (i, (selector, count, cells)) in regions.into_iter().enumerate() {
        let rows = rows(&prover, selector);
        assert_eq!(rows.len(), count, "region {i}");
        for row in rows {
            for (column, offset) in cells {
                let cell = &mut tampered.advice[*column][row + offset];
                let original = *cell;
                *cell += Fp::ONE;
                assert!(
                    tampered.verify().is_err(),
                    "region {i} column {column} offset {offset}"
                );
                tampered.advice[*column][row + offset] = original;
            }
        }
    }
    assert_eq!(tampered.verify(), Ok(()));
}
