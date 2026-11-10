//! Verification of real mainnet proofs and of reference proofs with the
//! embedded keys, and (ignored by default, since they need the parameter
//! files) proving with the real parameters.
//!
//! The ignored tests read `sapling-spend.params` and
//! `sapling-output.params` from the directory named by the `ZCASH_PARAMS`
//! environment variable, `~/.zcash-params` by default. Run them optimized:
//!
//! ```text
//! cargo test --release --features zcash-sapling-prover -- --ignored
//! ```

use super::*;
use crate::sapling::bundle::BundleRef;
use crate::sapling::circuit::tests::fixture;
use crate::zcashtx::{SIGHASH_ALL, ZcashTx};
use serde_json::Value;

/// The directory holding the Sapling parameters.
#[cfg(feature = "std")]
pub(crate) fn params_dir() -> std::path::PathBuf {
    match std::env::var_os("ZCASH_PARAMS") {
        Some(dir) => dir.into(),
        None => std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join(".zcash-params"),
    }
}

/// Both sets of parameters, from [`params_dir`].
#[cfg(feature = "std")]
pub(crate) fn load_params() -> (SpendParameters, OutputParameters) {
    let dir = params_dir();
    let fail = |e: Error| -> ! { panic!("cannot load the parameters from {}: {e}", dir.display()) };
    (
        SpendParameters::load(&dir).unwrap_or_else(|e| fail(e)),
        OutputParameters::load(&dir).unwrap_or_else(|e| fail(e)),
    )
}

fn array<const N: usize>(v: &Value, name: &str) -> [u8; N] {
    hex::decode(v[name].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn embedded_keys() {
    assert_eq!(SpendVerifyingKey::mainnet().0.num_inputs(), 7);
    assert_eq!(OutputVerifyingKey::mainnet().0.num_inputs(), 5);
    assert_eq!(
        hex::encode(SPEND_PARAMS_HASH),
        "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c"
    );
    assert_eq!(
        hex::encode(OUTPUT_PARAMS_HASH),
        "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028"
    );
    // anything that is not the parameters is refused before parsing
    assert_eq!(
        SpendParameters::read(SPEND_VK).unwrap_err(),
        Error::HashMismatch
    );
    assert_eq!(
        OutputParameters::read(&[]).unwrap_err(),
        Error::HashMismatch
    );
}

/// Mainnet transaction
/// `84be2b0a8634a76ff87a5192d259155e9718222261b83134ecc8866819b3f602`
/// (block 1899974, NU5): one Sapling spend and two outputs.
#[test]
fn mainnet_v5_transaction() {
    let raw = hex::decode(include_str!("../testdata/mainnet_v5_sapling_tx.hex").trim()).unwrap();
    let tx = ZcashTx::parse_into(&raw, &mut [], &mut []).unwrap();
    assert_eq!(
        hex::encode(tx.txid().unwrap()),
        "84be2b0a8634a76ff87a5192d259155e9718222261b83134ecc8866819b3f602"
    );
    let bundle = BundleRef::parse(tx.sapling).unwrap();
    assert_eq!((bundle.n_spends(), bundle.n_outputs()), (1, 2));
    assert_eq!(bundle.value_balance(), 1000);

    let spend_vk = SpendVerifyingKey::mainnet();
    let output_vk = OutputVerifyingKey::mainnet();
    verify_bundle_proofs(&bundle, &spend_vk, &output_vk).unwrap();
    let sighash = tx.sighash(None, SIGHASH_ALL, &[]).unwrap();
    bundle.verify(&sighash).unwrap();

    // every public input is bound by the proofs
    let anchor = bundle.anchor().unwrap();
    let spend = bundle.spend(0).unwrap();
    let verify = |cv: &[u8; 32], anchor: &[u8; 32], nf: &[u8; 32], rk: &[u8; 32]| {
        spend_vk.verify(cv, anchor, nf, rk, spend.zkproof)
    };
    verify(spend.cv, anchor, spend.nullifier, spend.rk).unwrap();
    let out0 = bundle.output(0).unwrap();
    let out1 = bundle.output(1).unwrap();
    assert_eq!(
        verify(out0.cv, anchor, spend.nullifier, spend.rk),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        verify(spend.cv, out0.cmu, spend.nullifier, spend.rk),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        verify(spend.cv, anchor, anchor, spend.rk),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        verify(spend.cv, anchor, spend.nullifier, out0.ephemeral_key),
        Err(Error::InvalidProof)
    );
    let mut flipped = *spend.nullifier;
    flipped[31] ^= 0x80;
    assert_eq!(
        verify(spend.cv, anchor, &flipped, spend.rk),
        Err(Error::InvalidProof)
    );
    // inputs consensus forbids
    assert_eq!(
        verify(spend.cv, &[0xff; 32], spend.nullifier, spend.rk),
        Err(Error::InvalidPublicInput)
    );
    let identity = crate::sapling::jubjub::AffinePoint::IDENTITY.to_bytes();
    assert_eq!(
        verify(&identity, anchor, spend.nullifier, spend.rk),
        Err(Error::InvalidPublicInput)
    );
    assert_eq!(
        verify(spend.cv, anchor, spend.nullifier, &identity),
        Err(Error::InvalidPublicInput)
    );

    let verify = |cv: &[u8; 32], cmu: &[u8; 32], epk: &[u8; 32]| {
        output_vk.verify(cv, cmu, epk, out0.zkproof)
    };
    verify(out0.cv, out0.cmu, out0.ephemeral_key).unwrap();
    assert_eq!(
        verify(out1.cv, out0.cmu, out0.ephemeral_key),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        verify(out0.cv, out1.cmu, out0.ephemeral_key),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        verify(out0.cv, out0.cmu, out1.ephemeral_key),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        verify(out0.cv, out0.cmu, &identity),
        Err(Error::InvalidPublicInput)
    );
    assert_eq!(
        output_vk.verify(out0.cv, out0.cmu, out0.ephemeral_key, out1.zkproof),
        Err(Error::InvalidProof)
    );
    // a spend proof is not an output proof
    assert!(
        output_vk
            .verify(out0.cv, out0.cmu, out0.ephemeral_key, spend.zkproof)
            .is_err()
    );
}

/// The proofs of mainnet transaction
/// `b2cc959423b4cb9b9237010316d3a45f6cd2cc8eeacbf461bd350d5bfdd1afaf`
/// (block 1001000, a v4 transaction of the Heartwood era).
#[test]
fn mainnet_v4_proofs() {
    let json: Value =
        serde_json::from_str(include_str!("../testdata/mainnet_v4_sapling_proofs.json")).unwrap();
    let spend_vk = SpendVerifyingKey::mainnet();
    let output_vk = OutputVerifyingKey::mainnet();
    let spends = json["spends"].as_array().unwrap();
    let outputs = json["outputs"].as_array().unwrap();
    assert_eq!((spends.len(), outputs.len()), (1, 2));
    for s in spends {
        spend_vk
            .verify(
                &array(s, "cv"),
                &array(s, "anchor"),
                &array(s, "nullifier"),
                &array(s, "rk"),
                &array(s, "zkproof"),
            )
            .unwrap();
    }
    for o in outputs {
        output_vk
            .verify(
                &array(o, "cv"),
                &array(o, "cmu"),
                &array(o, "ephemeral_key"),
                &array(o, "zkproof"),
            )
            .unwrap();
    }
}

/// The proofs `sapling-crypto` made for the fixture's witnesses.
#[test]
fn reference_proofs_verify() {
    let f = fixture();
    SpendVerifyingKey::mainnet()
        .verify(&f.spend_cv, &f.anchor, &f.nullifier, &f.rk, &f.spend_proof)
        .unwrap();
    OutputVerifyingKey::mainnet()
        .verify(&f.output_cv, &f.cmu, &f.epk, &f.output_proof)
        .unwrap();
}

/// Deterministic stand-in for the verifier's random generator.
fn batch_random(tag: u8, len: usize) -> Vec<u8> {
    (0..len)
        .flat_map(|i| {
            crate::sapling::prf::blake2b::<64>(b"outscript_test__", &[&[tag], &i.to_le_bytes()])
        })
        .take(len)
        .collect()
}

/// Every real proof at hand (mainnet v4 and v5, `sapling-crypto`'s) in one
/// batch for the two keys; a batch with one of them altered fails.
#[test]
fn batch_of_real_proofs() {
    type SpendArgs = ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 192]);
    type OutputArgs = ([u8; 32], [u8; 32], [u8; 32], [u8; 192]);
    let mut spends: Vec<SpendArgs> = Vec::new();
    let mut outputs: Vec<OutputArgs> = Vec::new();

    let raw = hex::decode(include_str!("../testdata/mainnet_v5_sapling_tx.hex").trim()).unwrap();
    let tx = ZcashTx::parse_into(&raw, &mut [], &mut []).unwrap();
    let bundle = BundleRef::parse(tx.sapling).unwrap();
    let anchor = bundle.anchor().unwrap();
    for s in bundle.spends() {
        spends.push((*s.cv, *anchor, *s.nullifier, *s.rk, *s.zkproof));
    }
    for o in bundle.outputs() {
        outputs.push((*o.cv, *o.cmu, *o.ephemeral_key, *o.zkproof));
    }
    let json: Value =
        serde_json::from_str(include_str!("../testdata/mainnet_v4_sapling_proofs.json")).unwrap();
    for s in json["spends"].as_array().unwrap() {
        spends.push((
            array(s, "cv"),
            array(s, "anchor"),
            array(s, "nullifier"),
            array(s, "rk"),
            array(s, "zkproof"),
        ));
    }
    for o in json["outputs"].as_array().unwrap() {
        outputs.push((
            array(o, "cv"),
            array(o, "cmu"),
            array(o, "ephemeral_key"),
            array(o, "zkproof"),
        ));
    }
    let f = fixture();
    spends.push((f.spend_cv, f.anchor, f.nullifier, f.rk, f.spend_proof));
    outputs.push((f.output_cv, f.cmu, f.epk, f.output_proof));
    assert_eq!((spends.len(), outputs.len()), (3, 5));

    let spend_vk = SpendVerifyingKey::mainnet();
    let output_vk = OutputVerifyingKey::mainnet();
    let run = |spends: &[SpendArgs], outputs: &[OutputArgs]| -> Result<(), Error> {
        let random = batch_random(1, 16 * (spends.len() + outputs.len()));
        let mut random = random.as_chunks::<16>().0.iter();
        let mut batch = BatchVerifier::new();
        // interleaved: the order does not matter
        let mut outputs = outputs.iter();
        for (cv, anchor, nf, rk, proof) in spends {
            spend_vk.queue(
                &mut batch,
                cv,
                anchor,
                nf,
                rk,
                proof,
                random.next().unwrap(),
            )?;
            if let Some((cv, cmu, epk, proof)) = outputs.next() {
                output_vk.queue(&mut batch, cv, cmu, epk, proof, random.next().unwrap())?;
            }
        }
        for (cv, cmu, epk, proof) in outputs {
            output_vk.queue(&mut batch, cv, cmu, epk, proof, random.next().unwrap())?;
        }
        assert!(format!("{batch:?}").contains("keys: 2"));
        batch.verify()
    };
    assert_eq!(run(&spends, &outputs), Ok(()));

    // one altered public input or proof, in either kind
    let mut bad = spends.clone();
    bad[1].2[0] ^= 1;
    assert_eq!(run(&bad, &outputs), Err(Error::InvalidProof));
    let (cv, anchor, nf, rk, proof) = &bad[1];
    assert_eq!(
        spend_vk.verify(cv, anchor, nf, rk, proof),
        Err(Error::InvalidProof)
    );
    let mut bad = outputs.clone();
    bad[4].3 = outputs[3].3;
    assert_eq!(run(&spends, &bad), Err(Error::InvalidProof));
    let (cv, cmu, epk, proof) = &bad[4];
    assert_eq!(
        output_vk.verify(cv, cmu, epk, proof),
        Err(Error::InvalidProof)
    );
    // what cannot be valid is refused when queued
    let mut bad = spends.clone();
    bad[0].1 = [0xff; 32];
    assert_eq!(run(&bad, &outputs), Err(Error::InvalidPublicInput));
    let mut bad = outputs.clone();
    bad[0].3 = [0; 192];
    assert!(run(&spends, &bad).is_err());
}

/// `verify_bundle` on a mainnet transaction, and on altered copies of it.
#[test]
fn verify_mainnet_bundle() {
    let raw = hex::decode(include_str!("../testdata/mainnet_v5_sapling_tx.hex").trim()).unwrap();
    let tx = ZcashTx::parse_into(&raw, &mut [], &mut []).unwrap();
    let sighash = tx.sighash(None, SIGHASH_ALL, &[]).unwrap();
    let bundle = BundleRef::parse(tx.sapling).unwrap();
    let spend_vk = SpendVerifyingKey::mainnet();
    let output_vk = OutputVerifyingKey::mainnet();
    assert_eq!(bundle.n_signatures(), 2);
    let len = verify_bundle_random_len(&bundle);
    assert_eq!(len, 16 * (2 + 1 + 2));
    let random = batch_random(2, len);
    let check = |bundle: &BundleRef<'_>, sighash: &[u8; 32], random: &[u8]| {
        verify_bundle(bundle, sighash, &spend_vk, &output_vk, random)
    };
    assert_eq!(check(&bundle, &sighash, &random), Ok(()));
    assert_eq!(check(&bundle, &sighash, &vec![0; len]), Ok(()));
    assert_eq!(bundle.verify_batched(&sighash, &random[..32]), Ok(()));
    assert_eq!(
        verify_bundle_proofs_batch(&bundle, &spend_vk, &output_vk, &random[32..]),
        Ok(())
    );

    for bad in [&random[..len - 1], &[][..], &vec![0; len + 16][..]] {
        assert_eq!(
            check(&bundle, &sighash, bad),
            Err(BundleError::RandomLength)
        );
    }
    assert_eq!(
        bundle.verify_batched(&sighash, &random[..31]),
        Err(SaplingError::RandomLength)
    );
    assert_eq!(
        verify_bundle_proofs_batch(&bundle, &spend_vk, &output_vk, &random[..32]),
        Err(Error::RandomLength)
    );
    // another transaction's signature hash
    let signature = Err(BundleError::Sapling(SaplingError::InvalidSignature));
    assert_eq!(check(&bundle, &[7; 32], &random), signature);
    assert_eq!(bundle.verify(&[7; 32]), Err(SaplingError::InvalidSignature));

    // a bit flipped in each part of the serialized bundle
    let sapling = tx.sapling;
    let n = sapling.len();
    let offsets = [
        (1 + 32, "nullifier"),
        (1 + 96 + 1 + 100, "enc_ciphertext"),
        (1 + 96 + 1 + 2 * 756 + 3, "value balance"),
        (1 + 96 + 1 + 2 * 756 + 8 + 1, "anchor"),
        (n - 64 - 2 * 192 - 64 + 5, "spend auth signature"),
        (n - 64 + 40, "binding signature"),
    ];
    for (offset, what) in offsets {
        let mut bytes = sapling.to_vec();
        bytes[offset] ^= 1;
        let altered = BundleRef::parse(&bytes).unwrap();
        // the signature hash covers all but the signatures: keep it, so
        // that only the proofs and the binding signature can object
        let batched = check(&altered, &sighash, &random);
        let single = altered
            .verify(&sighash)
            .map_err(BundleError::Sapling)
            .and_then(|()| {
                verify_bundle_proofs(&altered, &spend_vk, &output_vk).map_err(BundleError::Proof)
            });
        assert_eq!(batched, single, "{what}");
        // the note ciphertext is only bound by the signature hash
        assert_eq!(batched.is_ok(), what == "enc_ciphertext", "{what}");
    }
    // an empty bundle has nothing to verify
    let empty = BundleRef::parse(&[]).unwrap();
    assert_eq!(verify_bundle_random_len(&empty), 0);
    assert_eq!(check(&empty, &sighash, &[]), Ok(()));
}

/// The parameter files contain the embedded keys, and nothing but the
/// exact files is accepted.
#[cfg(feature = "std")]
#[test]
#[ignore = "needs the Sapling parameters"]
fn parameters_match_embedded_keys() {
    let (spend, output) = load_params();
    assert_eq!(spend.parameters().vk.write(), SPEND_VK);
    assert_eq!(output.parameters().vk.write(), OUTPUT_VK);

    let mut data = std::fs::read(params_dir().join(OUTPUT_PARAMS_NAME)).unwrap();
    assert!(OutputParameters::read(&data).is_ok());
    assert_eq!(
        SpendParameters::read(&data).unwrap_err(),
        Error::HashMismatch
    );
    let last = data.len() - 1;
    data[last] ^= 1;
    assert_eq!(
        OutputParameters::read(&data).unwrap_err(),
        Error::HashMismatch
    );
    data.pop();
    assert_eq!(
        OutputParameters::read(&data).unwrap_err(),
        Error::HashMismatch
    );
}

/// With the real parameters and the reference's blinding scalars, the
/// proofs are byte for byte those of `sapling-crypto`.
#[cfg(feature = "std")]
#[test]
#[ignore = "needs the Sapling parameters"]
fn proofs_match_reference_prover() {
    let f = fixture();
    let start = std::time::Instant::now();
    let (spend, output) = load_params();
    std::eprintln!("parameters loaded in {:?}", start.elapsed());

    let start = std::time::Instant::now();
    let proof = output.prove(&f.output, &f.random).unwrap();
    std::eprintln!("output proof in {:?}", start.elapsed());
    assert_eq!(hex::encode(proof), hex::encode(f.output_proof));
    output
        .verifying_key()
        .verify(&f.output_cv, &f.cmu, &f.epk, &proof)
        .unwrap();

    let start = std::time::Instant::now();
    let proof = spend.prove(&f.spend, &f.random).unwrap();
    std::eprintln!("spend proof in {:?}", start.elapsed());
    assert_eq!(hex::encode(proof), hex::encode(f.spend_proof));
    spend
        .verifying_key()
        .verify(&f.spend_cv, &f.anchor, &f.nullifier, &f.rk, &proof)
        .unwrap();

    // other randomness, other proof, still valid
    let proof = output.prove(&f.output, &[0x7b; 128]).unwrap();
    assert_ne!(proof, f.output_proof);
    OutputVerifyingKey::mainnet()
        .verify(&f.output_cv, &f.cmu, &f.epk, &proof)
        .unwrap();
}
