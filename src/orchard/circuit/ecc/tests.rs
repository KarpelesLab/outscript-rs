//! Tests of the ECC gadgets and chip.
//!
//! [`EccCircuit`] mirrors `MyEccCircuit` of the reference (`halo2_gadgets`
//! 0.6.0, `ecc::tests`), with the fixed bases of Orchard and deterministic
//! witnesses. The same circuit, written against the reference, lives in the
//! scratch project `/tmp/claude-1000/sp/ref-ecc/` (`cargo run --release`),
//! which writes for each `CircuitVersion` the `{:?}` of
//! `ConstraintSystem::pinned()` after `configure`, and the log of every
//! call the `V1` floor planner makes on a recording `Assignment` backend
//! (`out/{anchored,unanchored}_{pinned,events}.txt`; the reference circuit
//! is also checked there with the reference `MockProver`). The lengths and
//! SHA-256 hashes below are those of these files (`sha256sum`), and our
//! dumps (`poseidon::test_util::dump`) must be byte-identical.

use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;

use super::chip::{
    EccChip, EccConfig, NullifierK, OrchardBaseFieldBases, OrchardFixedBasesFull,
    OrchardShortScalarBases, ValueCommitV,
};
use super::{
    CircuitVersion, FixedPoint, FixedPointBaseField, FixedPointShort, NonIdentityPoint, Point,
    ScalarFixed, ScalarFixedShort, ScalarVar,
};
use crate::orchard::circuit::poseidon::test_util::{assert_dump, dump};
use crate::orchard::circuit::utilities::load_private;
use crate::orchard::circuit::utilities::lookup_range_check::LookupRangeCheckConfig;
use crate::orchard::constants::{
    COMMIT_IVK_R, NOTE_COMMIT_R, NULLIFIER_K, SPEND_AUTH_G, VALUE_COMMIT_R, VALUE_COMMIT_V,
};
use crate::orchard::halo2::circuit::{Circuit, Layouter};
use crate::orchard::halo2::dev::MockProver;
use crate::orchard::halo2::plonk::{Any, Column, ConstraintSystem};
use crate::orchard::halo2::{Error, Value};
use crate::orchard::{Fp, Fq, pallas};

/// The parts of the test circuit.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    /// Everything (the circuit of the reference dumps).
    All,
    /// Witnessed and constant points.
    Points,
    /// Complete and incomplete addition.
    Add,
    /// Variable-base scalar multiplication.
    Mul,
    /// Fixed-base multiplication by a full-width scalar.
    MulFixedFull,
    /// Fixed-base multiplication by a signed short scalar.
    MulFixedShort,
    /// Fixed-base multiplication by a base field element.
    MulFixedBaseField,
}

struct EccCircuit {
    version: CircuitVersion,
    part: Part,
    /// Whether to try the incomplete additions that must fail.
    test_errors: bool,
}

impl EccCircuit {
    fn new(version: CircuitVersion, part: Part) -> Self {
        EccCircuit {
            version,
            part,
            test_errors: false,
        }
    }

    fn has(&self, part: Part) -> bool {
        self.part == Part::All || self.part == part
    }
}

fn to_scalar(x: Fp) -> Fq {
    Fq::from_bytes(&x.to_bytes()).unwrap()
}

/// The digits (base 8) of the scalars for which the last addition of a
/// fixed-base multiplication is a doubling.
const LAST_DOUBLING: &str =
    "1333333333333333333333333333333333333333333333333333333333333333333333333333333333334";

fn last_doubling_fq() -> Fq {
    let h = Fq::from_u64(8);
    LAST_DOUBLING.chars().fold(Fq::ZERO, |acc, c| {
        acc * h + Fq::from_u64(c.to_digit(8).unwrap() as u64)
    })
}

fn last_doubling_fp() -> Fp {
    let h = Fp::from_u64(8);
    LAST_DOUBLING.chars().fold(Fp::ZERO, |acc, c| {
        acc * h + Fp::from_u64(c.to_digit(8).unwrap() as u64)
    })
}

fn rand_fp() -> Fp {
    Fp::from_u128(0x0123456789abcdef_fedcba9876543210).square() + Fp::from_u64(7)
}

fn rand_fq() -> Fq {
    Fq::from_u128(0x0f1e2d3c4b5a6978_8796a5b4c3d2e1f0).square() + Fq::from_u64(11)
}

fn configure(meta: &mut ConstraintSystem) -> EccConfig {
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
    let lookup_table = meta.lookup_table_column();
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
    // Shared fixed column for loading constants
    let constants = meta.fixed_column();
    meta.enable_constant(constants);

    let range_check = LookupRangeCheckConfig::configure(meta, advices[9], lookup_table);
    EccChip::configure(meta, advices, lagrange_coeffs, range_check)
}

/// Constrains `result` to be the point `expected` computed natively.
fn expect(
    chip: EccChip,
    layouter: &mut Layouter<'_>,
    result: &Point,
    expected: pallas::Point,
) -> Result<(), Error> {
    if bool::from(expected.is_identity()) {
        result
            .inner()
            .is_identity()
            .assert_if_known(|is_identity| *is_identity);
        return Ok(());
    }
    let expected = NonIdentityPoint::new(chip, layouter, Value::known(expected.to_affine()))?;
    result.constrain_equal(layouter, &expected)
}

impl Circuit for EccCircuit {
    type Config = EccConfig;

    fn without_witnesses(&self) -> Self {
        EccCircuit {
            version: self.version,
            part: self.part,
            test_errors: self.test_errors,
        }
    }

    fn configure(&self, meta: &mut ConstraintSystem) -> EccConfig {
        configure(meta)
    }

    #[allow(clippy::type_complexity)]
    fn synthesize(&self, config: EccConfig, layouter: &mut Layouter<'_>) -> Result<(), Error> {
        let chip = EccChip::construct(config, self.version);
        let column = config.advices[0];

        // Load 10-bit lookup table. In the Action circuit, this will be
        // provided by the Sinsemilla chip.
        config.lookup_config.load_range_check_table(layouter)?;

        let g = pallas::Point::GENERATOR;
        let p_pt = g.mul_vartime(&Fq::from_u64(7919));
        let q_pt = g.mul_vartime(&Fq::from_u64(104729));
        let p_val = p_pt.to_affine();
        let q_val = q_pt.to_affine();

        // Generate random-looking points
        let p = NonIdentityPoint::new(chip, layouter, Value::known(p_val))?;
        let p_neg = NonIdentityPoint::new(chip, layouter, Value::known(p_val.neg()))?;
        let q = NonIdentityPoint::new(chip, layouter, Value::known(q_val))?;

        if self.has(Part::Points) {
            // Make sure P and Q are not the same point.
            assert!(p_val.x() != q_val.x());

            // Test that we can witness the identity as a point, but not as a
            // non-identity point (see `witness_errors` for the latter).
            let _ = Point::new(chip, layouter, Value::known(pallas::Affine::IDENTITY))?;

            // Test witnessing constant points
            let _ = NonIdentityPoint::new_from_constant(chip, layouter, g.to_affine())?;
            let _ = Point::new_from_constant(chip, layouter, pallas::Affine::IDENTITY)?;
            let _ = Point::new_from_constant(chip, layouter, g.to_affine())?;
        }

        // Test complete addition (`add::tests::test_add` of the reference)
        if self.has(Part::Add) {
            // Check complete addition P + (-P)
            let zero = p.add(layouter, &p_neg)?;
            zero.inner()
                .is_identity()
                .assert_if_known(|is_identity| *is_identity);

            // Check complete addition 𝒪 + 𝒪
            let result = zero.add(layouter, &zero)?;
            result.constrain_equal(layouter, &zero)?;

            // Check P + Q
            let result = p.add(layouter, &q)?;
            expect(chip, layouter, &result, p_pt.add(&q_pt))?;

            // P + P
            let result = p.add(layouter, &p)?;
            expect(chip, layouter, &result, p_pt.add(&p_pt))?;

            // P + 𝒪
            let result = p.add(layouter, &zero)?;
            result.constrain_equal(layouter, &p)?;

            // 𝒪 + P
            let result = zero.add(layouter, &p)?;
            result.constrain_equal(layouter, &p)?;

            // (x, y) + (ζx, y), (x, y) + (ζx, -y), (x, y) + ((ζ^2)x, y) and
            // (x, y) + ((ζ^2)x, -y) should behave like normal P + Q.
            for e in [
                p_pt.endo(),
                p_pt.neg().endo(),
                p_pt.endo().endo(),
                p_pt.neg().endo().endo(),
            ] {
                let endo = NonIdentityPoint::new(chip, layouter, Value::known(e.to_affine()))?;
                let result = p.add(layouter, &endo)?;
                expect(chip, layouter, &result, p_pt.add(&e))?;
            }
        }

        // Test incomplete addition
        // (`add_incomplete::tests::test_add_incomplete` of the reference)
        if self.has(Part::Add) {
            // P + Q
            let result = p.add_incomplete(layouter, &q)?;
            let witnessed =
                NonIdentityPoint::new(chip, layouter, Value::known(p_pt.add(&q_pt).to_affine()))?;
            result.constrain_equal(layouter, &witnessed)?;

            // The exceptional cases are detected from the values of the
            // cells, which only exist in the second pass of the floor
            // planner.
            let known = p.inner().x().value().into_option().is_some();
            if self.test_errors {
                // P + P should return an error
                let result = p.add_incomplete(layouter, &p);
                assert_eq!(result.is_err(), known);

                // P + (-P) should return an error
                let result = p.add_incomplete(layouter, &p_neg);
                assert_eq!(result.is_err(), known);
            }
        }

        // Test variable-base scalar multiplication
        if self.has(Part::Mul) {
            // [a]B, [0]B, [1]B and [-1]B
            for scalar_val in [rand_fp(), Fp::ZERO, Fp::ONE, -Fp::ONE] {
                let scalar = load_private(layouter, column, Value::known(scalar_val))?;
                let scalar = ScalarVar::from_base(chip, layouter, &scalar)?;
                let (result, _) = p.mul(layouter, scalar)?;
                expect(chip, layouter, &result, p_pt.mul(&to_scalar(scalar_val)))?;
            }
        }

        // Test full-width fixed-base scalar multiplication
        if self.has(Part::MulFixedFull) {
            let full: [(OrchardFixedBasesFull, pallas::Affine, Vec<Fq>); 4] = [
                (
                    OrchardFixedBasesFull::ValueCommitR,
                    VALUE_COMMIT_R,
                    // [a]B; a scalar whose last window addition is a
                    // doubling ([2^254 + 2^251 + ...]B); [0]B; [-1]B
                    vec![rand_fq(), last_doubling_fq(), Fq::ZERO, -Fq::ONE],
                ),
                (
                    OrchardFixedBasesFull::CommitIvkR,
                    COMMIT_IVK_R,
                    vec![rand_fq() + Fq::ONE],
                ),
                (
                    OrchardFixedBasesFull::NoteCommitR,
                    NOTE_COMMIT_R,
                    vec![rand_fq().square()],
                ),
                (
                    OrchardFixedBasesFull::SpendAuthG,
                    SPEND_AUTH_G,
                    vec![rand_fq().double()],
                ),
            ];
            for (base, base_val, scalars) in full {
                let base = FixedPoint::from_inner(chip, base);
                for scalar_val in scalars {
                    let by = ScalarFixed::new(chip, layouter, Value::known(scalar_val))?;
                    let (result, _) = base.mul(layouter, by)?;
                    expect(
                        chip,
                        layouter,
                        &result,
                        base_val.to_point().mul(&scalar_val),
                    )?;
                }
            }
        }

        // Test signed short fixed-base scalar multiplication
        if self.has(Part::MulFixedShort) {
            let short: [(OrchardShortScalarBases, pallas::Affine, Vec<(u64, bool)>); 2] = [
                (
                    ValueCommitV.into(),
                    VALUE_COMMIT_V,
                    vec![
                        // -[a]B
                        (0x0123_4567_89ab_cdef, true),
                        // [2^64 - 1]B and -[2^64 - 1]B
                        (0xFFFF_FFFF_FFFF_FFFF, false),
                        (0xFFFF_FFFF_FFFF_FFFF, true),
                        // There is a single canonical sequence of window
                        // values for which a doubling occurs on the last
                        // step: 1333333333333333333334 in octal.
                        // [0xB6DB_6DB6_DB6D_B6DC] B, and its opposite
                        (0xB6DB_6DB6_DB6D_B6DC, false),
                        (0xB6DB_6DB6_DB6D_B6DC, true),
                        // mul by +zero and by -zero
                        (0, false),
                        (0, true),
                    ],
                ),
                (
                    OrchardShortScalarBases::SpendAuthGShort,
                    SPEND_AUTH_G,
                    vec![(0xfedc_ba98_7654_3210, false)],
                ),
            ];
            for (base, base_val, scalars) in short {
                let base = FixedPointShort::from_inner(chip, base);
                for (magnitude_val, negative) in scalars {
                    let magnitude =
                        load_private(layouter, column, Value::known(Fp::from_u64(magnitude_val)))?;
                    let sign = load_private(
                        layouter,
                        column,
                        Value::known(if negative { -Fp::ONE } else { Fp::ONE }),
                    )?;
                    let by = ScalarFixedShort::new(chip, layouter, (magnitude, sign))?;
                    let (result, _) = base.mul(layouter, by)?;
                    let scalar = if negative {
                        -Fq::from_u64(magnitude_val)
                    } else {
                        Fq::from_u64(magnitude_val)
                    };
                    expect(chip, layouter, &result, base_val.to_point().mul(&scalar))?;
                }
            }
        }

        // Test fixed-base scalar multiplication with a base field element
        if self.has(Part::MulFixedBaseField) {
            let base_field: [(OrchardBaseFieldBases, pallas::Affine, Vec<Fp>); 2] = [
                (
                    NullifierK.into(),
                    NULLIFIER_K,
                    // [a]B; a scalar whose last window addition is a
                    // doubling; [0]B; [1]B; [-1]B
                    vec![rand_fp(), last_doubling_fp(), Fp::ZERO, Fp::ONE, -Fp::ONE],
                ),
                (
                    OrchardBaseFieldBases::SpendAuthGBase,
                    SPEND_AUTH_G,
                    vec![rand_fp().square()],
                ),
            ];
            for (base, base_val, scalars) in base_field {
                let base = FixedPointBaseField::from_inner(chip, base);
                for scalar_val in scalars {
                    let scalar = load_private(layouter, column, Value::known(scalar_val))?;
                    let result = base.mul(layouter, scalar)?;
                    expect(
                        chip,
                        layouter,
                        &result,
                        base_val.to_point().mul(&to_scalar(scalar_val)),
                    )?;
                }
            }
        }

        Ok(())
    }
}

/// The constraint system and the layout are those of the reference, for
/// both circuit versions (see the module documentation).
#[test]
fn ecc_chip_matches_reference() {
    const PINNED_SHA256: &str = "8004724efe906e62a64263f6132d5cc3c3a0873c50841a16049a0785c6e93701";

    let (pinned, events) = dump(&EccCircuit::new(CircuitVersion::AnchoredBase, Part::All));
    assert_dump("ecc_anchored_pinned", &pinned, 58943, PINNED_SHA256);
    assert_dump(
        "ecc_anchored_events",
        &events,
        4326631,
        "307ed868a2246da029f947e9bffc78b19ec42a49e6b3a975690ebeccc77fb3cd",
    );

    let (pinned, events) = dump(&EccCircuit::new(
        CircuitVersion::InsecureUnanchoredBase,
        Part::All,
    ));
    assert_dump("ecc_unanchored_pinned", &pinned, 58943, PINNED_SHA256);
    assert_dump(
        "ecc_unanchored_events",
        &events,
        4325151,
        "049d4b5682d70ff031fb6a8a29933521e21b36ff988c75b97576e4eb5ccd2b60",
    );
}

fn check(k: u32, version: CircuitVersion, part: Part) {
    let mut circuit = EccCircuit::new(version, part);
    circuit.test_errors = true;
    MockProver::run(k, &circuit, vec![])
        .unwrap()
        .assert_satisfied();
}

/// The whole test circuit is satisfied (`ecc_chip` of the reference), for
/// both circuit versions.
#[test]
#[ignore = "slow in the dev profile"]
fn ecc_chip() {
    check(13, CircuitVersion::AnchoredBase, Part::All);
    check(13, CircuitVersion::InsecureUnanchoredBase, Part::All);
}

#[test]
fn witness_points() {
    check(11, CircuitVersion::AnchoredBase, Part::Points);
}

#[test]
fn add() {
    check(11, CircuitVersion::AnchoredBase, Part::Add);
}

#[test]
fn mul() {
    check(11, CircuitVersion::AnchoredBase, Part::Mul);
}

#[test]
fn mul_unanchored() {
    check(11, CircuitVersion::InsecureUnanchoredBase, Part::Mul);
}

#[test]
fn mul_fixed_full() {
    check(11, CircuitVersion::AnchoredBase, Part::MulFixedFull);
}

#[test]
fn mul_fixed_short() {
    check(11, CircuitVersion::AnchoredBase, Part::MulFixedShort);
}

#[test]
fn mul_fixed_base_field() {
    check(11, CircuitVersion::AnchoredBase, Part::MulFixedBaseField);
}

/// Witnessing the identity as a non-identity point is an error (and so is
/// it as a constant).
///
/// These errors do not depend on the value of a cell, so they happen in
/// both passes of the floor planner, which then disagree on the number of
/// regions (the reference tests them with its `SimpleFloorPlanner`). They
/// are only tried in the first pass here, where a failed region is simply
/// not recorded.
struct WitnessErrorCircuit<'a> {
    passes: &'a Cell<usize>,
}

impl Circuit for WitnessErrorCircuit<'_> {
    type Config = EccConfig;

    fn without_witnesses(&self) -> Self {
        WitnessErrorCircuit {
            passes: self.passes,
        }
    }

    fn configure(&self, meta: &mut ConstraintSystem) -> EccConfig {
        configure(meta)
    }

    fn synthesize(&self, config: EccConfig, layouter: &mut Layouter<'_>) -> Result<(), Error> {
        let chip = EccChip::construct(config, CircuitVersion::AnchoredBase);
        config.lookup_config.load_range_check_table(layouter)?;

        let pass = self.passes.get();
        self.passes.set(pass + 1);
        if pass == 0 {
            NonIdentityPoint::new(chip, layouter, Value::known(pallas::Affine::IDENTITY))
                .expect_err("witnessing 𝒪 should return an error");
            NonIdentityPoint::new_from_constant(chip, layouter, pallas::Affine::IDENTITY)
                .expect_err("witnessing 𝒪 should return an error");
        }
        Ok(())
    }
}

#[test]
fn witness_errors() {
    let passes = Cell::new(0);
    let circuit = WitnessErrorCircuit { passes: &passes };
    MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(passes.get(), 2);
}

/// `MyMagnitudeSignCircuit` of the reference: a short fixed-base
/// multiplication by an arbitrary magnitude and sign.
struct MagnitudeSignCircuit {
    magnitude: Value<Fp>,
    sign: Value<Fp>,
}

impl Circuit for MagnitudeSignCircuit {
    type Config = EccConfig;

    fn without_witnesses(&self) -> Self {
        MagnitudeSignCircuit {
            magnitude: Value::unknown(),
            sign: Value::unknown(),
        }
    }

    fn configure(&self, meta: &mut ConstraintSystem) -> EccConfig {
        configure(meta)
    }

    fn synthesize(&self, config: EccConfig, layouter: &mut Layouter<'_>) -> Result<(), Error> {
        let column = config.advices[0];
        let chip = EccChip::construct(config, CircuitVersion::AnchoredBase);
        config.lookup_config.load_range_check_table(layouter)?;

        let magnitude = load_private(layouter, column, self.magnitude)?;
        let sign = load_private(layouter, column, self.sign)?;
        let by = ScalarFixedShort::new(chip, layouter, (magnitude, sign))?;
        FixedPointShort::from_inner(chip, ValueCommitV).mul(layouter, by)?;
        Ok(())
    }
}

fn magnitude_sign_failure(magnitude: Fp, sign: Fp) -> alloc::string::String {
    let circuit = MagnitudeSignCircuit {
        magnitude: Value::known(magnitude),
        sign: Value::known(sign),
    };
    MockProver::run(11, &circuit, vec![])
        .unwrap()
        .verify()
        .unwrap_err()
}

/// `invalid_magnitude_sign` of the reference.
#[test]
fn invalid_magnitude_sign() {
    // Magnitude larger than 64 bits should fail
    for magnitude in [
        // 2^64
        Fp::from_u128(1 << 64),
        // 2^66
        Fp::from_u128(1 << 66),
        // 2^254
        Fp::from_u128(1 << 127).square(),
    ] {
        for sign in [Fp::ONE, -Fp::ONE] {
            let failure = magnitude_sign_failure(magnitude, sign);
            // The last window is not a bit (last_window_check), and the
            // running sum does not end with zero.
            assert!(
                failure.contains("gate 'Short fixed-base mul gate' constraint 0 not satisfied"),
                "{failure}"
            );
            assert!(failure.contains("copy constraint"), "{failure}");
        }
    }

    // Sign that is not +/- 1 should fail
    let failure = magnitude_sign_failure(Fp::from_u64(1 << 3), Fp::ZERO);
    // sign_check and negation_check
    assert!(
        failure.contains("gate 'Short fixed-base mul gate' constraint 1 not satisfied"),
        "{failure}"
    );
    assert!(
        failure.contains("gate 'Short fixed-base mul gate' constraint 3 not satisfied"),
        "{failure}"
    );
    assert!(!failure.contains("copy constraint"), "{failure}");
}

/// A single variable-base multiplication, as `base_anchoring::MulCircuit`
/// of the reference.
struct MulCircuit {
    version: CircuitVersion,
}

impl Circuit for MulCircuit {
    type Config = EccConfig;

    fn without_witnesses(&self) -> Self {
        MulCircuit {
            version: self.version,
        }
    }

    fn configure(&self, meta: &mut ConstraintSystem) -> EccConfig {
        configure(meta)
    }

    fn synthesize(&self, config: EccConfig, layouter: &mut Layouter<'_>) -> Result<(), Error> {
        let chip = EccChip::construct(config, self.version);
        config.lookup_config.load_range_check_table(layouter)?;
        let base = NonIdentityPoint::new(chip, layouter, Value::known(pallas::Affine::GENERATOR))?;
        let scalar = load_private(layouter, config.advices[0], Value::known(Fp::from_u64(7)))?;
        let scalar = ScalarVar::from_base(chip, layouter, &scalar)?;
        base.mul(layouter, scalar)?;
        Ok(())
    }
}

/// `fixed_circuit_anchors_incomplete_base` of the reference: the anchored
/// circuit has every copy constraint of the unanchored one, plus the two
/// that bind the base of the first incomplete-addition row to the base of
/// the multiplication.
#[test]
fn fixed_circuit_anchors_incomplete_base() {
    type Copy = ((Column<Any>, usize), (Column<Any>, usize));
    let record = |version| MockProver::run(11, &MulCircuit { version }, vec![]).unwrap();
    let insecure = record(CircuitVersion::InsecureUnanchoredBase).copies;
    let prover = record(CircuitVersion::AnchoredBase);
    let fixed = &prover.copies;

    assert!(
        insecure.iter().all(|copy| fixed.contains(copy)),
        "the fixed circuit must retain every copy constraint of the insecure circuit"
    );
    // (The `hi` and `lo` halves share these cells: each copy is made twice.)
    let mut extra: Vec<Copy> = fixed
        .iter()
        .filter(|copy| !insecure.contains(copy))
        .cloned()
        .collect();
    extra.sort();
    extra.dedup();

    // `x_p` and `y_p` of the incomplete additions are the first two advice
    // columns, where the base is witnessed too.
    let mut cs = ConstraintSystem::default();
    let config = configure(&mut cs);
    let x_p = Column::<Any>::from(config.advices[0]);
    let y_p = Column::<Any>::from(config.advices[1]);
    // The multiplication region is the largest: the floor planner puts it
    // on row 0, and its first incomplete-addition row (the first one with
    // `q_mul_2`) is row 2. The other end of the copies is the witnessed base.
    assert_eq!(extra.len(), 2);
    let base_row = extra[0].1.1;
    assert_eq!(
        extra,
        [((x_p, 2), (x_p, base_row)), ((y_p, 2), (y_p, base_row))]
    );
    assert!(prover.advice[0][base_row] == pallas::Affine::GENERATOR.x());
    assert!(prover.advice[1][base_row] == pallas::Affine::GENERATOR.y());
    // The cells of the multiplication region themselves hold the base in
    // both versions; the gadget of the reference checks the same thing.
    assert!(prover.advice[0][2] == pallas::Affine::GENERATOR.x());
    prover.assert_satisfied();
}
