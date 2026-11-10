//! The circuits against `sapling-crypto`: the fingerprints of the two
//! constraint systems that its tests pin, and the public inputs of a
//! reference witness (`testdata/sapling_proofs.json`, made with
//! `sapling-crypto` and the real parameters).

use super::*;
use crate::sapling::groth16::TestConstraintSystem;
use crate::sapling::keys::{ExpandedSpendingKey, PaymentAddress};
use crate::sapling::note::{Note, Rseed};
use crate::sapling::prover::{output_public_inputs, spend_public_inputs};
use crate::sapling::tree::MerklePath;
use serde_json::Value;

/// `cs.hash()` of the Spend circuit in `sapling-crypto`'s tests.
const SPEND_HASH: &str = "d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89";
/// `cs.hash()` of the Output circuit in `sapling-crypto`'s tests.
const OUTPUT_HASH: &str = "c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee";

/// The reference witnesses and proofs.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(crate) struct Fixture {
    /// The 128 random bytes of both proofs.
    pub random: [u8; 128],
    pub expanded_spending_key: ExpandedSpendingKey,
    pub address: PaymentAddress,
    pub path: MerklePath,
    pub spend: Spend,
    pub spend_cv: [u8; 32],
    pub anchor: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub spend_cmu: [u8; 32],
    pub spend_proof: [u8; 192],
    pub output: Output,
    pub output_cv: [u8; 32],
    pub cmu: [u8; 32],
    pub epk: [u8; 32],
    pub output_proof: [u8; 192],
}

fn array<const N: usize>(v: &Value, name: &str) -> [u8; N] {
    hex::decode(v[name].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn fr(v: &Value, name: &str) -> Fr {
    Fr::from_bytes(&array(v, name)).unwrap()
}

pub(crate) fn fixture() -> Fixture {
    let json: Value =
        serde_json::from_str(include_str!("../testdata/sapling_proofs.json")).unwrap();
    let mut random = [0u8; 128];
    random[..64].copy_from_slice(&array::<64>(&json, "r_wide"));
    random[64..].copy_from_slice(&array::<64>(&json, "s_wide"));

    let s = &json["spend"];
    let expanded_spending_key =
        ExpandedSpendingKey::from_bytes(&array(s, "expanded_spending_key")).unwrap();
    let address = PaymentAddress::from_bytes(&array(s, "address")).unwrap();
    let siblings: Vec<[u8; 32]> = s["siblings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            hex::decode(v.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    let path = MerklePath {
        position: s["position"].as_u64().unwrap(),
        siblings: siblings.try_into().unwrap(),
    };
    let anchor: [u8; 32] = array(s, "anchor");
    let spend = Spend {
        value: s["value"].as_u64().unwrap(),
        rcv: fr(s, "rcv"),
        proof_generation_key: expanded_spending_key.proof_generation_key(),
        g_d: *address.g_d(),
        rcm: fr(s, "rcm"),
        alpha: fr(s, "alpha"),
        auth_path: path
            .siblings
            .iter()
            .enumerate()
            .map(|(i, node)| (Fq::from_bytes(node).unwrap(), (path.position >> i) & 1 == 1))
            .collect(),
        anchor: Fq::from_bytes(&anchor).unwrap(),
    };

    let o = &json["output"];
    let recipient = PaymentAddress::from_bytes(&array(o, "address")).unwrap();
    let output = Output {
        value: o["value"].as_u64().unwrap(),
        rcv: fr(o, "rcv"),
        g_d: *recipient.g_d(),
        pk_d: *recipient.pk_d(),
        rcm: fr(o, "rcm"),
        esk: fr(o, "esk"),
    };

    Fixture {
        random,
        expanded_spending_key,
        address,
        path,
        spend,
        spend_cv: array(s, "cv"),
        anchor,
        nullifier: array(s, "nullifier"),
        rk: array(s, "rk"),
        spend_cmu: array(s, "cmu"),
        spend_proof: array(s, "proof"),
        output,
        output_cv: array(o, "cv"),
        cmu: array(o, "cmu"),
        epk: array(o, "epk"),
        output_proof: array(o, "proof"),
    }
}

/// The fixture agrees with this crate's keys, notes, tree and signatures.
#[test]
fn fixture_is_consistent() {
    let f = fixture();
    let s = &f.spend;
    assert_eq!(
        f.expanded_spending_key
            .full_viewing_key()
            .to_payment_address(*f.address.diversifier())
            .unwrap(),
        f.address
    );
    let note = Note::new(f.address, s.value, Rseed::BeforeZip212(s.rcm));
    assert_eq!(note.cmu(), f.spend_cmu);
    assert_eq!(f.path.root(&f.spend_cmu), f.anchor);
    assert_eq!(
        note.nullifier(&s.proof_generation_key.nk(), f.path.position),
        f.nullifier
    );
    assert_eq!(
        crate::sapling::note::value_commitment(s.value, &s.rcv).to_bytes(),
        f.spend_cv
    );
    assert_eq!(
        crate::sapling::redjubjub::randomized_spend_key(&s.proof_generation_key.ak, &s.alpha)
            .to_bytes(),
        f.rk
    );

    let o = &f.output;
    let recipient = PaymentAddress::from_parts(*f.address.diversifier(), o.pk_d).unwrap();
    let note = Note::new(recipient, o.value, Rseed::BeforeZip212(o.rcm));
    assert_eq!(note.cmu(), f.cmu);
    assert_eq!(
        crate::sapling::note::value_commitment(o.value, &o.rcv).to_bytes(),
        f.output_cv
    );
    assert_eq!(
        crate::sapling::note_encryption::ka_derive_public(&o.esk, &o.g_d).to_bytes(),
        f.epk
    );
}

#[test]
fn output_circuit_matches_reference() {
    let f = fixture();
    let mut cs = TestConstraintSystem::new();
    f.output.synthesize(&mut cs).unwrap();
    assert!(cs.is_satisfied());
    assert_eq!(cs.constraints.len(), OUTPUT_CONSTRAINTS);
    assert_eq!(cs.hash(), OUTPUT_HASH);
    let inputs = output_public_inputs(&f.output_cv, &f.cmu, &f.epk).unwrap();
    assert_eq!(cs.inputs[0], Fq::ONE);
    assert_eq!(cs.inputs[1..], inputs);

    // a witness for another commitment
    let mut other = f.output.clone();
    other.value += 1;
    let mut cs = TestConstraintSystem::new();
    other.synthesize(&mut cs).unwrap();
    assert!(cs.is_satisfied());
    assert_eq!(cs.hash(), OUTPUT_HASH);
    assert_ne!(cs.inputs[1..], inputs);

    // g_d of small order cannot be witnessed
    let mut bad = f.output.clone();
    bad.g_d = Point::IDENTITY;
    assert_eq!(
        bad.synthesize(&mut TestConstraintSystem::new()),
        Err(SynthesisError::DivisionByZero)
    );
}

#[test]
fn spend_circuit_matches_reference() {
    let f = fixture();
    let mut cs = TestConstraintSystem::new();
    f.spend.synthesize(&mut cs).unwrap();
    assert!(cs.is_satisfied());
    assert_eq!(cs.constraints.len(), SPEND_CONSTRAINTS);
    assert_eq!(cs.hash(), SPEND_HASH);
    let inputs = spend_public_inputs(&f.spend_cv, &f.anchor, &f.nullifier, &f.rk).unwrap();
    assert_eq!(cs.inputs[0], Fq::ONE);
    assert_eq!(cs.inputs[1..], inputs);
}

/// A wrong anchor violates exactly the root constraint, unless the value
/// is zero.
#[test]
fn spend_circuit_anchor_check() {
    let f = fixture();
    let mut spend = f.spend.clone();
    spend.anchor += Fq::ONE;
    let mut cs = TestConstraintSystem::new();
    spend.synthesize(&mut cs).unwrap();
    assert!(!cs.is_satisfied());

    spend.value = 0;
    let mut cs = TestConstraintSystem::new();
    spend.synthesize(&mut cs).unwrap();
    assert!(cs.is_satisfied());
    assert_eq!(cs.hash(), SPEND_HASH);
}

#[test]
fn edwards_gadgets_match_the_curve() {
    use crate::sapling::generators::{NOTE_COMMITMENT_RANDOMNESS_BASE, SPENDING_KEY_BASE};
    let mut cs = TestConstraintSystem::new();
    let p = SPENDING_KEY_BASE.to_point().mul(&Fr::from_u64(77));
    let q = NOTE_COMMITMENT_RANDOMNESS_BASE.to_point();
    let gp = EdwardsPoint::witness(&mut cs, &p.to_affine()).unwrap();
    let gq = EdwardsPoint::witness(&mut cs, &q.to_affine()).unwrap();
    let value = |g: &EdwardsPoint| {
        AffinePoint::new(g.get_u().get_value(), g.get_v().get_value())
            .unwrap()
            .to_point()
    };
    assert_eq!(value(&gp.add(&mut cs, &gq).unwrap()), p + q);
    assert_eq!(value(&gp.double(&mut cs).unwrap()), p.double());

    let scalar = Fr::from_bytes_wide(&[0x5c; 64]);
    let bits = gadgets::fr_into_boolean_vec_le(&mut cs, &scalar).unwrap();
    assert_eq!(bits.len(), 252);
    assert_eq!(value(&gp.mul(&mut cs, &bits).unwrap()), p.mul(&scalar));
    assert_eq!(
        value(&fixed_base_multiplication(&mut cs, &SPENDING_KEY_BASE, &bits).unwrap()),
        SPENDING_KEY_BASE.to_point().mul(&scalar)
    );

    // the Pedersen hash, over two segments
    let data = [0xa7u8; 40];
    let tables = PedersenTables::new(2);
    let input: Vec<Boolean> = crate::sapling::pedersen::bits_le(&data)
        .map(|b| Boolean::from(AllocatedBit::alloc(&mut cs, b).unwrap()))
        .collect();
    let person = merkle_personalization(5);
    let hash = pedersen_hash(&mut cs, &tables, person, &input).unwrap();
    assert_eq!(
        value(&hash),
        crate::sapling::pedersen::pedersen_hash_to_point(
            person
                .into_iter()
                .chain(crate::sapling::pedersen::bits_le(&data))
        )
    );
    // more input than tables
    let long: Vec<Boolean> = input.iter().chain(&input).copied().collect();
    assert!(pedersen_hash(&mut cs, &tables, person, &long).is_err());

    // the canonical bits of a point's encoding
    let repr = gp.repr(&mut cs).unwrap();
    let got: Vec<bool> = repr.iter().map(Boolean::get_value).collect();
    let expected: Vec<bool> = crate::sapling::pedersen::bits_le(&p.to_bytes()).collect();
    assert_eq!(got, expected);
    assert!(cs.is_satisfied());
}

use crate::sapling::jubjub::AffinePoint;
