//! Cross-checks of the proving system against `halo2_proofs` 0.4.1.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::dev::tests::Mul;
use super::*;
use crate::orchard::Fp;

/// The output of the reference for the small circuit of the mock prover
/// tests: generators of the parameters for `k = 4` and `k = 11`, the pinned
/// verifying key and a proof of two statements. Produced by the scratch
/// program `small.rs` (see `orchard::circuit`'s tests for how the reference
/// programs are run).
const REFERENCE: &str = include_str!("../testdata/halo2_small_circuit.txt");

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let start = line.find(key).unwrap() + key.len();
    line[start..].split(' ').next().unwrap().trim()
}

fn point(p: &crate::orchard::vesta::Affine) -> String {
    hex::encode(p.to_bytes())
}

fn check_params(params: &Params, line: &str, full: bool) {
    let n = params.n;
    assert_eq!(point(&params.g[0]), field(line, " g0="));
    assert_eq!(point(&params.g[1]), field(line, " g1="));
    assert_eq!(point(&params.g[n - 1]), field(line, " glast="));
    assert_eq!(point(&params.g_lagrange[0]), field(line, " gl0="));
    assert_eq!(point(&params.g_lagrange[5]), field(line, " gl5="));
    if full {
        assert_eq!(point(&params.g_lagrange[n - 1]), field(line, " gllast="));
    }
    assert_eq!(point(&params.w), field(line, " w="));
    assert_eq!(point(&params.u), field(line, " u="));
}

fn mul_circuit() -> Mul {
    Mul {
        a: Value::known(Fp::from_u64(7)),
        b: Fp::from_u64(6),
    }
}

#[test]
fn small_circuit_matches_the_reference() {
    let lines: Vec<&str> = REFERENCE.lines().collect();
    let params = Params::new(4);
    check_params(&params, lines[0], true);

    let vk = keygen_vk(&params, &mul_circuit()).unwrap();
    assert_eq!(
        format!("{:?}", vk.pinned()),
        lines[2].strip_prefix("pinned=").unwrap()
    );

    let proof = hex::decode(lines[3].strip_prefix("proof=").unwrap()).unwrap();
    let instance = [Fp::from_u64(42)];
    let instances: [&[&[Fp]]; 2] = [&[&instance], &[&instance]];
    assert_eq!(verify_proof(&params, &vk, &instances, &proof), Ok(()));

    // the verifier-only parameters suffice
    let short = Params::for_verifier(4, 1);
    assert_eq!(verify_proof(&short, &vk, &instances, &proof), Ok(()));

    // a wrong instance, and every kind of malformed proof, is rejected
    let wrong = [Fp::from_u64(43)];
    let bad: [&[&[Fp]]; 2] = [&[&instance], &[&wrong]];
    assert_eq!(
        verify_proof(&params, &vk, &bad, &proof),
        Err(Error::InvalidProof)
    );
    for len in [0, 1, 31, 32, 33, proof.len() / 2, proof.len() - 1] {
        assert!(verify_proof(&params, &vk, &instances, &proof[..len]).is_err());
    }
    for i in (0..proof.len()).step_by(37) {
        let mut p = proof.clone();
        p[i] ^= 0x40;
        assert!(verify_proof(&params, &vk, &instances, &p).is_err());
    }

    // batched
    let mut batch = BatchVerifier::new(&[9u8; 64]);
    batch.add_proof(&params, &vk, &instances, &proof);
    batch.add_proof(&params, &vk, &instances, &proof);
    assert!(batch.finalize(&params));
    let mut batch = BatchVerifier::new(&[9u8; 64]);
    batch.add_proof(&params, &vk, &instances, &proof);
    batch.add_proof(&params, &vk, &bad, &proof);
    assert!(!batch.finalize(&params));
}

/// The `2^11` generators of the Orchard parameters.
#[test]
#[ignore = "slow in the test profile"]
fn orchard_parameters_match_the_reference() {
    let lines: Vec<&str> = REFERENCE.lines().collect();
    check_params(&Params::new(11), lines[1], true);
    check_params(&Params::for_verifier(11, 10), lines[1], false);
}
