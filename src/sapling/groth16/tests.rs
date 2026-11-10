//! Tests against a fixture made with `bellman` and the `groth16` crate:
//! parameters for a small circuit (`testdata/groth16_toy.params`), and the
//! proof the reference prover gives for fixed blinding scalars
//! (`testdata/groth16_toy.json`).

use super::*;

/// `x_{i+1} = x_i² + x_i + (i + 1)` iterated `n` times; the last value is
/// the public input.
struct Chain {
    x: Fq,
    n: u64,
}

impl Chain {
    fn output(&self) -> Fq {
        (0..self.n).fold(self.x, |x, i| x.square() + x + Fq::from_u64(i + 1))
    }
}

impl Circuit for Chain {
    fn synthesize<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let mut value = self.x;
        let mut var = cs.alloc(|| Ok(value))?;
        for i in 0..self.n {
            let t_value = value.square();
            let t = cs.alloc(|| Ok(t_value))?;
            cs.enforce(|lc| lc + var, |lc| lc + var, |lc| lc + t);
            let k = Fq::from_u64(i + 1);
            let next_value = t_value + value + k;
            let next = cs.alloc(|| Ok(next_value))?;
            cs.enforce(
                |lc| lc + t + var + (k, CS::one()),
                |lc| lc + CS::one(),
                |lc| lc + next,
            );
            value = next_value;
            var = next;
        }
        let y = cs.alloc_input(|| Ok(value))?;
        cs.enforce(|lc| lc + var - y, |lc| lc + CS::one(), |lc| lc);
        Ok(())
    }
}

const PARAMS: &[u8] = include_bytes!("../testdata/groth16_toy.params");

struct Fixture {
    circuit: Chain,
    y: Fq,
    r: Fq,
    s: Fq,
    proof: [u8; PROOF_SIZE],
}

fn fixture() -> Fixture {
    let json: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/groth16_toy.json")).unwrap();
    let bytes = |name: &str| hex::decode(json[name].as_str().unwrap()).unwrap();
    let fq = |name: &str| Fq::from_bytes(&bytes(name).try_into().unwrap()).unwrap();
    let wide = |name: &str| Fq::from_bytes_wide(&bytes(name).try_into().unwrap());
    Fixture {
        circuit: Chain {
            x: fq("x"),
            n: json["n"].as_u64().unwrap(),
        },
        y: fq("y"),
        r: wide("r_wide"),
        s: wide("s_wide"),
        proof: bytes("proof").try_into().unwrap(),
    }
}

#[test]
fn toy_circuit_is_satisfied() {
    let f = fixture();
    assert_eq!(f.circuit.output(), f.y);
    let mut cs = TestConstraintSystem::new();
    f.circuit.synthesize(&mut cs).unwrap();
    assert!(cs.is_satisfied());
    assert_eq!(cs.constraints.len(), 41);
    assert_eq!(cs.inputs, [Fq::ONE, f.y]);
    cs.aux[3] += Fq::ONE;
    assert_eq!(cs.which_is_unsatisfied(), Some(2));
}

#[test]
fn reference_proof_verifies() {
    let f = fixture();
    let params = Parameters::read(PARAMS, true).unwrap();
    let pvk = params.vk.prepare();
    assert_eq!(pvk.num_inputs(), 1);
    let proof = Proof::from_bytes(&f.proof).unwrap();
    assert_eq!(proof.to_bytes(), f.proof);
    verify_proof(&pvk, &proof, &[f.y]).unwrap();
    assert_eq!(
        verify_proof(&pvk, &proof, &[f.y + Fq::ONE]),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        verify_proof(&pvk, &proof, &[]),
        Err(Error::InvalidVerifyingKey)
    );
    assert_eq!(
        verify_proof(&pvk, &proof, &[f.y, f.y]),
        Err(Error::InvalidVerifyingKey)
    );
    // any other point of the group in place of one of the proof's
    for tampered in [
        Proof {
            a: proof.a.double(),
            ..proof
        },
        Proof {
            b: proof.b.double(),
            ..proof
        },
        Proof {
            c: proof.c.neg(),
            ..proof
        },
    ] {
        assert_eq!(
            verify_proof(&pvk, &tampered, &[f.y]),
            Err(Error::InvalidProof)
        );
    }
}

#[test]
fn proof_matches_reference_prover() {
    let f = fixture();
    // both the fully checked and the fast decoding
    for checked in [true, false] {
        let params = Parameters::read(PARAMS, checked).unwrap();
        let proof = create_proof(&f.circuit, &params, &f.r, &f.s).unwrap();
        assert_eq!(hex::encode(proof.to_bytes()), hex::encode(f.proof));
    }
}

#[test]
fn other_witnesses_and_blindings_verify() {
    let params = Parameters::read(PARAMS, false).unwrap();
    let pvk = params.vk.prepare();
    for seed in 1..4u64 {
        let circuit = Chain {
            x: Fq::from_u64(seed).square() + Fq::from_u64(1000 * seed),
            n: 20,
        };
        let r = Fq::from_bytes_wide(&[seed as u8; 64]);
        let s = Fq::from_bytes_wide(&[0x80 | seed as u8; 64]);
        let proof = create_proof(&circuit, &params, &r, &s).unwrap();
        let proof = Proof::from_bytes(&proof.to_bytes()).unwrap();
        verify_proof(&pvk, &proof, &[circuit.output()]).unwrap();
        assert!(verify_proof(&pvk, &proof, &[circuit.output() + Fq::ONE]).is_err());
    }
    // a circuit the parameters are too small for
    let big = Chain { x: Fq::ONE, n: 40 };
    assert_eq!(
        create_proof(&big, &params, &Fq::ONE, &Fq::ONE).unwrap_err(),
        SynthesisError::MalformedParameters
    );
}

#[test]
fn verifying_key_roundtrip() {
    let params = Parameters::read(PARAMS, false).unwrap();
    let bytes = params.vk.write();
    assert_eq!(bytes, PARAMS[..bytes.len()]);
    assert_eq!(VerifyingKey::read(&bytes).unwrap(), params.vk);
    assert_eq!(
        VerifyingKey::read(&PARAMS[..bytes.len() + 1]),
        Err(Error::TrailingData)
    );
}

#[test]
fn malformed_parameters_are_rejected() {
    // every truncation fails cleanly
    for len in (0..PARAMS.len())
        .step_by(97)
        .chain(PARAMS.len() - 3..PARAMS.len())
    {
        assert!(Parameters::read(&PARAMS[..len], false).is_err(), "{len}");
    }
    // what follows the vectors is not part of the parameters
    let mut extra = PARAMS.to_vec();
    extra.extend_from_slice(&[0xff; 100]);
    assert!(Parameters::read(&extra, false).is_ok());

    let vk_len = Parameters::read(PARAMS, false).unwrap().vk.write().len();
    // a huge element count does not allocate
    let mut bad = PARAMS.to_vec();
    bad[vk_len..vk_len + 4].copy_from_slice(&[0xff; 4]);
    assert_eq!(
        Parameters::read(&bad, false).unwrap_err(),
        Error::UnexpectedEof
    );
    // the first H point: off the curve, flagged compressed, the identity
    let first = vk_len + 4;
    let mut bad = PARAMS.to_vec();
    bad[first + 95] ^= 1;
    assert_eq!(
        Parameters::read(&bad, false).unwrap_err(),
        Error::InvalidPoint
    );
    assert_eq!(
        Parameters::read(&bad, true).unwrap_err(),
        Error::InvalidPoint
    );
    let mut bad = PARAMS.to_vec();
    bad[first] |= 0x80;
    assert_eq!(
        Parameters::read(&bad, false).unwrap_err(),
        Error::InvalidPoint
    );
    let mut bad = PARAMS.to_vec();
    bad[first..first + 96].fill(0);
    bad[first] = 0x40;
    assert_eq!(
        Parameters::read(&bad, false).unwrap_err(),
        Error::PointAtInfinity
    );
    // a coordinate that is not reduced
    let mut bad = PARAMS.to_vec();
    bad[first..first + 48].fill(0xff);
    bad[first] = 0x1f;
    assert_eq!(
        Parameters::read(&bad, false).unwrap_err(),
        Error::InvalidPoint
    );

    // proofs: bad encodings and the identity
    let f = fixture();
    let mut bad = f.proof;
    bad[0] &= 0x7f;
    assert_eq!(Proof::from_bytes(&bad), Err(Error::InvalidPoint));
    let mut bad = f.proof;
    bad[..48].fill(0);
    bad[0] = 0xc0;
    assert_eq!(Proof::from_bytes(&bad), Err(Error::PointAtInfinity));
    assert!(Proof::from_bytes(&[0xff; PROOF_SIZE]).is_err());
    assert!(Proof::from_bytes(&[0; PROOF_SIZE]).is_err());
}
