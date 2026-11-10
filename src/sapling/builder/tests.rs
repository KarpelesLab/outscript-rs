//! The builder's checks, and (ignored by default: it needs the parameter
//! files, see `prover/tests.rs`) a complete shielded transaction.

use super::*;
use crate::sapling::tree::Frontier;
use crate::sapling::zip32::ExtendedSpendingKey;

/// Deterministic stand-in for the caller's random generator.
fn random<const N: usize>(tag: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, chunk) in out.chunks_mut(64).enumerate() {
        let block: [u8; 64] =
            crate::sapling::prf::blake2b(b"outscript_test__", &[&[tag], &(i as u32).to_le_bytes()]);
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    out
}

/// A wallet with one note of `value` in a tree with other commitments.
struct Wallet {
    key: ExtendedSpendingKey,
    address: PaymentAddress,
    note: Note,
    path: MerklePath,
    anchor: [u8; 32],
}

fn wallet(seed: u8, value: u64) -> Wallet {
    let key = ExtendedSpendingKey::from_seed_account(&[seed; 32], 133, 0).unwrap();
    let (_, address) = key.default_address().unwrap();
    let note = Note::new(address, value, Rseed::AfterZip212(random(seed)));

    let mut frontier: Frontier = Frontier::new();
    for i in 0..5u64 {
        frontier.append(&Fq::from_u64(1000 + i).to_bytes()).unwrap();
    }
    let mut witness = frontier.append_witnessed(&note.cmu()).unwrap();
    for i in 0..9u64 {
        witness.append(&Fq::from_u64(2000 + i).to_bytes()).unwrap();
    }
    let path = witness.path();
    assert_eq!(path.position, 5);
    Wallet {
        key,
        address,
        note,
        path,
        anchor: witness.root(),
    }
}

#[test]
fn spend_checks() {
    let w = wallet(1, 100_000);
    let expsk = w.key.expanded_spending_key();
    let rnd = random::<SPEND_RANDOM_SIZE>(9);

    let mut builder = Builder::new(w.anchor);
    builder.add_spend(expsk, &w.note, &w.path, &rnd).unwrap();
    assert_eq!((builder.n_spends(), builder.n_outputs()), (1, 0));
    assert_eq!(builder.value_balance(), 100_000);
    assert_eq!(
        builder.add_spend(expsk, &w.note, &w.path, &rnd),
        Err(Error::DuplicateSpend)
    );
    // proofs need parameters
    assert_eq!(
        builder.build(None, None).unwrap_err(),
        Error::MissingParameters
    );

    // another wallet's key
    let other = wallet(2, 5);
    let mut builder = Builder::new(w.anchor);
    assert_eq!(
        builder.add_spend(other.key.expanded_spending_key(), &w.note, &w.path, &rnd),
        Err(Error::WrongKey)
    );
    // a path to another root, or of another note
    let mut bad = w.path;
    bad.siblings[3][0] ^= 1;
    assert_eq!(
        builder.add_spend(expsk, &w.note, &bad, &rnd),
        Err(Error::Sapling(SaplingError::InvalidPath))
    );
    let mut bad = w.path;
    bad.position ^= 2;
    assert_eq!(
        builder.add_spend(expsk, &w.note, &bad, &rnd),
        Err(Error::Sapling(SaplingError::InvalidPath))
    );
    let other_note = Note::new(w.address, 100_001, *w.note.rseed());
    assert_eq!(
        builder.add_spend(expsk, &other_note, &w.path, &rnd),
        Err(Error::Sapling(SaplingError::InvalidPath))
    );
    let mut wrong_anchor = Builder::new([0; 32]);
    assert_eq!(
        wrong_anchor.add_spend(expsk, &w.note, &w.path, &rnd),
        Err(Error::Sapling(SaplingError::InvalidPath))
    );
    let huge = Note::new(w.address, MAX_MONEY as u64 + 1, *w.note.rseed());
    assert_eq!(
        builder.add_spend(expsk, &huge, &w.path, &rnd),
        Err(Error::Sapling(SaplingError::ValueOutOfRange))
    );
    assert_eq!(builder.n_spends(), 0);
}

#[test]
fn output_checks_and_empty_bundle() {
    let w = wallet(3, 1);
    let rnd = random::<OUTPUT_RANDOM_SIZE>(4);
    let mut builder = Builder::new([0; 32]);
    assert_eq!(
        builder.add_output(None, &w.address, MAX_MONEY as u64 + 1, None, &rnd),
        Err(Error::Sapling(SaplingError::ValueOutOfRange))
    );

    // nothing to prove or sign
    let unauthorized = builder.build(None, None).unwrap();
    assert_eq!(unauthorized.signature_random_len(), 0);
    assert_eq!(unauthorized.to_bytes().unwrap(), [0, 0]);
    let bundle = unauthorized.sign(&[0; 32], &[]).unwrap();
    assert_eq!(bundle.serialize().unwrap(), [0, 0]);

    let mut builder = Builder::new([0; 32]);
    let note = builder.add_output(None, &w.address, 7, None, &rnd).unwrap();
    assert_eq!((note.value(), *note.recipient()), (7, w.address));
    assert_eq!(builder.value_balance(), -7);
    assert_eq!(
        builder.build(None, None).unwrap_err(),
        Error::MissingParameters
    );
}

/// A transaction with one Sapling spend and two outputs, built, signed,
/// serialized, parsed back and verified in full.
///
/// With `SAPLING_TX_DUMP` set to a path, the raw transaction is written
/// there in hex, to check it with other implementations.
#[cfg(feature = "std")]
#[test]
#[ignore = "needs the Sapling parameters"]
fn shielded_transaction() {
    use crate::sapling::bundle::BundleRef;
    use crate::sapling::keys::Diversifier;
    use crate::sapling::note_encryption::{
        Zip212Enforcement, try_note_decryption, try_output_recovery_with_ovk,
    };
    use crate::sapling::prover::{
        OutputVerifyingKey, SpendVerifyingKey, tests::load_params, verify_bundle_proofs,
    };
    use crate::zcashtx::{SIGHASH_ALL, ZcashTx, branch};

    let (spend_params, output_params) = load_params();
    let w = wallet(1, 100_000);
    let expsk = w.key.expanded_spending_key();
    let recipient = wallet(2, 0);
    let mut memo = [0u8; MEMO_SIZE];
    memo[..5].copy_from_slice(b"hello");

    let start = std::time::Instant::now();
    let mut builder = Builder::new(w.anchor);
    builder
        .add_spend(expsk, &w.note, &w.path, &random(10))
        .unwrap();
    let sent = builder
        .add_output(
            Some(expsk.ovk()),
            &recipient.address,
            60_000,
            Some(&memo),
            &random(11),
        )
        .unwrap();
    // change, to a second address of the sender, not recoverable
    let change_address = (1u8..)
        .find_map(|i| {
            let mut d = [0u8; 11];
            d[0] = i;
            expsk.full_viewing_key().to_payment_address(Diversifier(d))
        })
        .unwrap();
    let change = builder
        .add_output(None, &change_address, 30_000, None, &random(12))
        .unwrap();
    assert_eq!(builder.value_balance(), 10_000);
    let unauthorized = builder
        .build(Some(&spend_params), Some(&output_params))
        .unwrap();
    std::eprintln!("bundle built in {:?}", start.elapsed());

    // the digests are those of the final transaction
    let unsigned_bytes = unauthorized.to_bytes().unwrap();
    let tx = ZcashTx {
        consensus_branch_id: branch::NU6,
        expiry_height: 2_800_000,
        sapling: &unsigned_bytes,
        ..ZcashTx::default()
    };
    let sighash = tx.sighash(None, SIGHASH_ALL, &[]).unwrap();
    let txid = tx.txid().unwrap();
    // without transparent inputs the signature hash is the transaction id
    let mut reversed = txid;
    reversed.reverse();
    assert_eq!(sighash, reversed);

    assert_eq!(unauthorized.signature_random_len(), 160);
    assert_eq!(
        wallet_clone_sign(&unauthorized, &sighash),
        Err(Error::RandomLength)
    );
    let bundle = unauthorized.sign(&sighash, &random::<160>(13)).unwrap();
    let sapling = bundle.serialize().unwrap();
    assert_eq!(sapling.len(), unsigned_bytes.len());
    let tx = ZcashTx {
        sapling: &sapling,
        ..tx
    };
    let raw = tx.serialize();
    if let Some(path) = std::env::var_os("SAPLING_TX_DUMP") {
        std::fs::write(path, hex::encode(&raw)).unwrap();
    }

    // parse it back and verify everything
    let parsed = ZcashTx::parse_into(&raw, &mut [], &mut []).unwrap();
    assert_eq!(parsed.txid().unwrap(), txid);
    assert_eq!(parsed.sighash(None, SIGHASH_ALL, &[]).unwrap(), sighash);
    let parsed = BundleRef::parse(parsed.sapling).unwrap();
    assert_eq!((parsed.n_spends(), parsed.n_outputs()), (1, 2));
    assert_eq!(parsed.value_balance(), 10_000);
    assert_eq!(parsed.anchor(), Some(&w.anchor));
    parsed.verify(&sighash).unwrap();
    let spend_vk = SpendVerifyingKey::mainnet();
    let output_vk = OutputVerifyingKey::mainnet();
    verify_bundle_proofs(&parsed, &spend_vk, &output_vk).unwrap();
    // for another transaction the signatures fail
    assert!(parsed.verify(&[0x55; 32]).is_err());

    // the spend reveals the note's nullifier
    let spend = parsed.spend(0).unwrap();
    let nk = expsk.proof_generation_key().nk();
    assert_eq!(*spend.nullifier, w.note.nullifier(&nk, w.path.position));

    // the recipient decrypts the first output, the sender recovers it
    let out = parsed.output(0).unwrap();
    assert_eq!(*out.cmu, sent.cmu());
    let ivk = recipient
        .key
        .expanded_spending_key()
        .proof_generation_key()
        .ivk();
    let (note, got_memo) = try_note_decryption(
        &ivk,
        out.ephemeral_key,
        out.cmu,
        out.enc_ciphertext,
        Zip212Enforcement::On,
    )
    .unwrap();
    assert_eq!(note, sent);
    assert_eq!(got_memo, memo);
    let recover = |out: &crate::sapling::bundle::OutputRef<'_>| {
        try_output_recovery_with_ovk(
            expsk.ovk(),
            out.cv,
            out.cmu,
            out.ephemeral_key,
            out.enc_ciphertext,
            out.out_ciphertext,
            Zip212Enforcement::On,
        )
    };
    assert_eq!(recover(&out).unwrap().0, sent);

    // the change comes back to the sender, and cannot be recovered
    let out = parsed.output(1).unwrap();
    let ivk = expsk.proof_generation_key().ivk();
    let (note, got_memo) = try_note_decryption(
        &ivk,
        out.ephemeral_key,
        out.cmu,
        out.enc_ciphertext,
        Zip212Enforcement::On,
    )
    .unwrap();
    assert_eq!(note, change);
    assert_eq!(got_memo, EMPTY_MEMO);
    assert!(recover(&out).is_none());
}

/// A copy of an unauthorized bundle, keys included.
fn clone_unauthorized(unauthorized: &UnauthorizedBundle) -> UnauthorizedBundle {
    UnauthorizedBundle {
        bundle: unauthorized.bundle().clone(),
        signing_keys: unauthorized
            .signing_keys
            .iter()
            .map(|k| SigningKey {
                ask: k.ask,
                alpha: k.alpha,
                ak: k.ak,
            })
            .collect(),
        bsk: unauthorized.bsk,
    }
}

/// Signing with the wrong amount of randomness, on a copy.
#[cfg(feature = "std")]
fn wallet_clone_sign(
    unauthorized: &UnauthorizedBundle,
    sighash: &[u8; 32],
) -> Result<Bundle, Error> {
    clone_unauthorized(unauthorized).sign(sighash, &[0; 80])
}

/// The padding rules are those of `sapling-crypto`'s `BundleType`
/// (`num_spends` and `num_outputs` in its `builder.rs`).
#[test]
fn bundle_types() {
    let required = BundleType::Transactional {
        bundle_required: true,
    };
    assert_eq!(
        BundleType::DEFAULT,
        BundleType::Transactional {
            bundle_required: false
        }
    );
    // (type, spends, outputs) -> (spends, outputs)
    let table = [
        (BundleType::DEFAULT, 0, 0, Ok((0, 0))),
        (BundleType::DEFAULT, 0, 1, Ok((0, 2))),
        (BundleType::DEFAULT, 1, 0, Ok((1, 2))),
        (BundleType::DEFAULT, 3, 2, Ok((3, 2))),
        (BundleType::DEFAULT, 2, 5, Ok((2, 5))),
        (required, 0, 0, Ok((1, 2))),
        (required, 0, 3, Ok((1, 3))),
        (required, 2, 1, Ok((2, 2))),
        (BundleType::Coinbase, 0, 0, Ok((0, 0))),
        (BundleType::Coinbase, 0, 1, Ok((0, 1))),
        (
            BundleType::Coinbase,
            1,
            1,
            Err(Error::BundleTypeNotSatisfiable),
        ),
    ];
    for (bundle_type, spends, outputs, expected) in table {
        let got = bundle_type
            .num_spends(spends)
            .and_then(|s| Ok((s, bundle_type.num_outputs(spends, outputs)?)));
        assert_eq!(got, expected, "{bundle_type:?} {spends} {outputs}");
    }
}

#[test]
fn change_padding_and_shuffle() {
    let w = wallet(1, 100_000);
    let expsk = w.key.expanded_spending_key();
    let recipient = wallet(2, 0).address;

    let mut builder = Builder::new(w.anchor);
    assert_eq!(builder.padding(BundleType::DEFAULT), Ok((0, 0)));
    builder
        .add_spend(expsk, &w.note, &w.path, &random(1))
        .unwrap();
    assert_eq!(builder.padding(BundleType::DEFAULT), Ok((0, 2)));
    assert_eq!(
        builder.padding(BundleType::Coinbase),
        Err(Error::BundleTypeNotSatisfiable)
    );
    builder
        .add_output(None, &recipient, 60_000, None, &random(2))
        .unwrap();
    assert_eq!(builder.value_balance(), 40_000);

    // the change is what is left once 10 000 leave the pool
    let ovk = Some(expsk.ovk());
    assert_eq!(
        builder.add_change(ovk, &w.address, 40_001, None, &random(3)),
        Err(Error::InsufficientFunds)
    );
    assert_eq!(builder.n_outputs(), 1);
    let change = builder
        .add_change(ovk, &w.address, 10_000, None, &random(3))
        .unwrap()
        .unwrap();
    assert_eq!((change.value(), *change.recipient()), (30_000, w.address));
    assert_eq!(builder.value_balance(), 10_000);
    // nothing is left: no output
    assert_eq!(
        builder.add_change(ovk, &w.address, 10_000, None, &random(4)),
        Ok(None)
    );
    assert_eq!(builder.n_outputs(), 2);

    // two outputs already: nothing to pad, unless a spend is added by hand
    assert_eq!(builder.padding_random_len(BundleType::DEFAULT), Ok(0));
    builder.pad(BundleType::DEFAULT, &[]).unwrap();
    assert_eq!(
        builder.pad(BundleType::DEFAULT, &[0; 8]),
        Err(Error::RandomLength)
    );
    builder.add_dummy_spend(&random(5)).unwrap();
    builder.add_dummy_spend(&random(6)).unwrap();
    builder.add_dummy_output(&random(7)).unwrap();
    assert_eq!((builder.n_spends(), builder.n_outputs()), (3, 3));
    // dummies are worth nothing, and do not clash with one another
    assert_eq!(builder.value_balance(), 10_000);
    assert_ne!(builder.spends[1].nullifier, builder.spends[2].nullifier);
    assert_eq!(builder.spends[1].circuit.value, 0);
    assert_eq!(builder.outputs[2].circuit.value, 0);
    // a dummy spend has a path that leads nowhere, and the builder's anchor
    let dummy = &builder.spends[1].circuit;
    assert_eq!(dummy.anchor.to_bytes(), w.anchor);
    assert_eq!(dummy.auth_path.len(), 32);
    assert!(dummy.auth_path.iter().all(|(_, right)| !right));
    assert_ne!(dummy.auth_path[0].0, dummy.auth_path[1].0);

    // shuffling moves everything to where the metadata says
    let nullifiers: Vec<_> = builder.spends.iter().map(|s| s.nullifier).collect();
    let cmus: Vec<_> = builder.outputs.iter().map(|o| o.description.cmu).collect();
    assert_eq!(builder.shuffle_random_len(), 48);
    assert_eq!(builder.shuffle(&[0; 47]), Err(Error::RandomLength));
    assert_eq!(builder.shuffle(&[0; 56]), Err(Error::RandomLength));
    let mut moved = false;
    for tag in 20..28 {
        let before: Vec<_> = builder.spends.iter().map(|s| s.nullifier).collect();
        let before_cmus: Vec<_> = builder.outputs.iter().map(|o| o.description.cmu).collect();
        let meta = builder.shuffle(&random::<48>(tag)).unwrap();
        let mut seen = [false; 3];
        for n in 0..3 {
            let spend = meta.spend_index(n).unwrap();
            let output = meta.output_index(n).unwrap();
            assert_eq!(builder.spends[spend].nullifier, before[n]);
            assert_eq!(builder.outputs[output].description.cmu, before_cmus[n]);
            seen[spend] = true;
            moved |= spend != n || output != n;
        }
        assert_eq!(seen, [true; 3]);
        assert_eq!((meta.spend_index(3), meta.output_index(3)), (None, None));
    }
    assert!(moved);
    let mut sorted: Vec<_> = builder.spends.iter().map(|s| s.nullifier).collect();
    sorted.sort();
    let mut expected = nullifiers.clone();
    expected.sort();
    assert_eq!(sorted, expected);
    assert_eq!(builder.outputs.len(), cmus.len());
    assert_eq!(builder.value_balance(), 10_000);
    // the real spend is still the only one with a position
    assert_eq!(
        builder
            .spends
            .iter()
            .filter(|s| s.position.is_some())
            .count(),
        1
    );

    // a bundle nobody asked for: one dummy spend, two dummy outputs
    let required = BundleType::Transactional {
        bundle_required: true,
    };
    let mut builder = Builder::new(w.anchor);
    let len = builder.padding_random_len(required).unwrap();
    assert_eq!(len, DUMMY_SPEND_RANDOM_SIZE + 2 * DUMMY_OUTPUT_RANDOM_SIZE);
    builder.pad(required, &random::<1056>(8)[..len]).unwrap();
    assert_eq!((builder.n_spends(), builder.n_outputs()), (1, 2));
    assert_eq!(builder.value_balance(), 0);
    assert_eq!(builder.padding(required), Ok((0, 0)));
    // a coinbase bundle is left alone
    let mut builder = Builder::new([0; 32]);
    builder
        .add_output(None, &recipient, 5, None, &random(9))
        .unwrap();
    assert_eq!(builder.padding(BundleType::Coinbase), Ok((0, 0)));
    assert_eq!(builder.padding(BundleType::DEFAULT), Ok((0, 1)));
    let len = builder.padding_random_len(BundleType::DEFAULT).unwrap();
    builder
        .pad(BundleType::DEFAULT, &random::<1056>(10)[..len])
        .unwrap();
    assert_eq!((builder.n_spends(), builder.n_outputs()), (0, 2));
    assert_eq!(builder.value_balance(), -5);
}

/// The shuffle reaches every permutation, about equally often.
#[test]
fn shuffle_is_uniform() {
    let mut counts = std::collections::BTreeMap::new();
    for i in 0..600u32 {
        let random: [u8; 32] =
            crate::sapling::prf::blake2b(b"outscript_test__", &[&i.to_le_bytes()]);
        let mut items = [0u8, 1, 2, 3];
        let indices = shuffle_items(&mut items, random.as_chunks::<8>().0);
        for (was, now) in indices.iter().enumerate() {
            assert_eq!(items[*now] as usize, was);
        }
        *counts.entry(items).or_insert(0u32) += 1;
    }
    assert_eq!(counts.len(), 24);
    // 25 expected each
    assert!(
        counts.values().all(|&n| (8..=50).contains(&n)),
        "{counts:?}"
    );
    assert!(shuffle_items::<u8>(&mut [], &[]).is_empty());
    assert_eq!(shuffle_items(&mut [7u8], &[[0xff; 8]]), [0]);
}

/// The two-step signing of a bundle whose spend authorizing keys are held
/// elsewhere, on a bundle put together by hand (its proofs are not made:
/// the signatures do not depend on them).
#[test]
fn external_signatures() {
    use crate::sapling::bundle::BundleRef;
    use crate::sapling::redjubjub::sign_spend as device_sign;

    // three spends: the first signed by the builder, the others elsewhere
    let asks = [Fr::from_u64(1111), Fr::from_u64(2222), Fr::from_u64(3333)];
    let alphas = [Fr::from_u64(7), Fr::from_u64(8), Fr::from_u64(9)];
    let rcvs = [Fr::from_u64(100), Fr::from_u64(200), Fr::from_u64(300)];
    let values = [5u64, 6, 7];
    let mut spends = Vec::new();
    let mut signing_keys = Vec::new();
    for i in 0..3 {
        let ak = verification_key(SigType::SpendAuth, &asks[i]);
        spends.push(SpendDescription {
            cv: value_commitment(values[i], &rcvs[i]).to_bytes(),
            nullifier: [i as u8; 32],
            rk: randomized_spend_key(&ak, &alphas[i]).to_bytes(),
            zkproof: [0; 192],
            spend_auth_sig: Signature([0; 64]),
        });
        signing_keys.push(SigningKey {
            ask: (i == 0).then_some(asks[i]),
            alpha: alphas[i],
            ak,
        });
    }
    let unauthorized = UnauthorizedBundle {
        bundle: Bundle {
            spends,
            outputs: Vec::new(),
            value_balance: 18,
            anchor: [0; 32],
            binding_sig: Signature([0; 64]),
        },
        signing_keys,
        bsk: binding_signing_key(&rcvs, []),
    };
    assert_eq!(unauthorized.external_spends().collect::<Vec<_>>(), [1, 2]);
    assert_eq!(unauthorized.signing_parts(3), None);
    let parts = unauthorized.signing_parts(1).unwrap();
    assert_eq!(parts.alpha, alphas[1]);
    assert_eq!(parts.rk, unauthorized.bundle().spends[1].rk);
    assert_eq!(parts.ak, verification_key(SigType::SpendAuth, &asks[1]));

    let sighash = [0x42; 32];
    let sig_random = random::<320>(1);
    assert_eq!(unauthorized.signature_random_len(), 320);
    // one step is not enough, and the randomness must be all there
    assert_eq!(
        clone_unauthorized(&unauthorized).sign(&sighash, &sig_random),
        Err(Error::MissingSignatures)
    );
    assert_eq!(
        clone_unauthorized(&unauthorized)
            .prepare(&sighash, &sig_random[..240])
            .unwrap_err(),
        Error::RandomLength
    );
    let prepared = unauthorized.prepare(&sighash, &sig_random).unwrap();
    assert_eq!(prepared.sighash(), &sighash);
    assert_eq!(prepared.missing().collect::<Vec<_>>(), [1, 2]);
    assert!(!prepared.is_complete());
    assert!(format!("{prepared:?}").contains("missing: 2"));
    assert_eq!(prepared.signing_parts(0), None);
    assert_eq!(prepared.signing_parts(1), Some(parts));
    assert_eq!(prepared.clone().finalize(), Err(Error::MissingSignatures));
    // what the builder could sign is signed
    let own = prepared.bundle().spends[0];
    assert!(verify_spend(&own.rk, &sighash, &own.spend_auth_sig).is_ok());
    assert_eq!(
        prepared.bundle().spends[1].spend_auth_sig,
        Signature([0; 64])
    );

    // the devices sign with rsk = ask + alpha
    let sign = |i: usize, sighash: &[u8; 32]| {
        let parts = prepared.signing_parts(i).unwrap();
        device_sign(&asks[i], &parts.alpha, sighash, &random(40 + i as u8))
    };
    let (sig1, sig2) = (sign(1, &sighash), sign(2, &sighash));
    let verified = |partial: PartiallyAuthorized| {
        let bundle = partial.finalize().unwrap();
        let bytes = bundle.serialize().unwrap();
        BundleRef::parse(&bytes).unwrap().verify(&sighash).unwrap();
        bundle
    };

    // by index
    let mut partial = prepared.clone();
    let invalid = Err(Error::InvalidExternalSignature);
    let duplicate = Err(Error::DuplicateSignature);
    assert_eq!(partial.append_signature(1, &sig2), invalid);
    assert_eq!(partial.append_signature(1, &sign(1, &[0x43; 32])), invalid);
    assert_eq!(partial.append_signature(1, &Signature([0; 64])), invalid);
    assert_eq!(partial.missing().count(), 2);
    assert_eq!(partial.append_signature(1, &sig1), Ok(()));
    assert_eq!(partial.append_signature(1, &sig1), duplicate);
    assert_eq!(partial.append_signature(0, &sig1), duplicate);
    assert_eq!(partial.append_signature(3, &sig1), duplicate);
    assert_eq!(partial.missing().collect::<Vec<_>>(), [2]);
    // with the key itself, when it is at hand
    assert_eq!(
        partial.sign_spend(2, &asks[1], &random(50)),
        Err(Error::WrongKey)
    );
    assert_eq!(partial.sign_spend(1, &asks[1], &random(50)), duplicate);
    assert_eq!(partial.sign_spend(2, &asks[2], &random(50)), Ok(()));
    assert!(partial.is_complete());
    let by_index = verified(partial);
    assert_eq!(by_index.spends[1].spend_auth_sig, sig1);

    // in any order, each going to the spend it is for
    let mut partial = prepared.clone();
    assert_eq!(partial.append_signatures(&[sig2, sig1]), Ok(()));
    let matched = verified(partial);
    assert_eq!(matched.spends[1].spend_auth_sig, sig1);
    assert_eq!(matched.spends[2].spend_auth_sig, sig2);
    assert_eq!(matched.binding_sig, by_index.binding_sig);

    // all or nothing
    let mut partial = prepared.clone();
    let other = sign(2, &sighash);
    assert_eq!(
        partial.append_signatures(&[sig1, Signature([1; 64])]),
        invalid
    );
    assert_eq!(partial.append_signatures(&[sig2, other]), duplicate);
    assert_eq!(
        partial.append_signatures(&[sig1, by_index.spends[0].spend_auth_sig]),
        invalid
    );
    assert_eq!(partial.missing().count(), 2);
    assert_eq!(partial.append_signatures(&[]), Ok(()));
    assert_eq!(partial.append_signatures(&[sig2]), Ok(()));
    assert_eq!(partial.append_signatures(&[sig2]), invalid);
    assert_eq!(partial.append_signatures(&[sig1]), Ok(()));
    verified(partial);
}

/// Everything the builder can do at once, with the real parameters: a spend
/// whose key is held elsewhere, a dummy spend, an output, the change, a
/// dummy output, a shuffle, and the two-step signing; then a bundle of
/// dummies alone. Both verify in full.
///
/// With `SAPLING_TX_DUMP_EXTERNAL` and `SAPLING_TX_DUMP_DUMMY` set to paths,
/// the raw transactions are written there in hex, to check them with other
/// implementations.
#[cfg(feature = "std")]
#[test]
#[ignore = "needs the Sapling parameters"]
fn padded_and_externally_signed_transactions() {
    use crate::sapling::bundle::BundleRef;
    use crate::sapling::note_encryption::Zip212Enforcement;
    use crate::sapling::prover::{
        OutputVerifyingKey, SpendVerifyingKey, tests::load_params, verify_bundle,
        verify_bundle_random_len,
    };
    use crate::zcashtx::{SIGHASH_ALL, ZcashTx, branch};

    let (spend_params, output_params) = load_params();
    let spend_vk = SpendVerifyingKey::mainnet();
    let output_vk = OutputVerifyingKey::mainnet();
    let w = wallet(1, 100_000);
    let expsk = w.key.expanded_spending_key();
    // all the builder sees of the spending key
    let proof_key = expsk.proof_generation_key();
    let fvk = expsk.full_viewing_key();
    let recipient = wallet(2, 0);

    let mut builder = Builder::new(w.anchor);
    builder
        .add_spend_with_proof_key(&proof_key, &w.note, &w.path, &random(60))
        .unwrap();
    let sent = builder
        .add_output(
            Some(fvk.ovk()),
            &recipient.address,
            60_000,
            None,
            &random(61),
        )
        .unwrap();
    let change = builder
        .add_change(Some(fvk.ovk()), &w.address, 10_000, None, &random(62))
        .unwrap()
        .unwrap();
    builder.add_dummy_spend(&random(63)).unwrap();
    builder.add_dummy_output(&random(64)).unwrap();
    builder.pad(BundleType::DEFAULT, &[]).unwrap();
    assert_eq!(builder.shuffle_random_len(), 40);
    // a shuffle that moves the real spend
    let meta = (65u8..)
        .find(|&tag| {
            let mut probe = Builder::new(w.anchor);
            probe.add_dummy_spend(&random(63)).unwrap();
            probe.add_dummy_spend(&random(63)).unwrap();
            let meta = probe.shuffle(&random::<16>(tag)).unwrap();
            meta.spend_index(0) == Some(1)
        })
        .map(|tag| {
            let mut bytes = random::<40>(tag);
            let outputs = random::<24>(tag + 100);
            bytes[16..].copy_from_slice(&outputs);
            builder.shuffle(&bytes).unwrap()
        })
        .unwrap();
    let real = meta.spend_index(0).unwrap();
    assert_eq!(real, 1);
    let unauthorized = builder
        .build(Some(&spend_params), Some(&output_params))
        .unwrap();
    assert_eq!(unauthorized.external_spends().collect::<Vec<_>>(), [real]);

    let unsigned_bytes = unauthorized.to_bytes().unwrap();
    let tx = ZcashTx {
        consensus_branch_id: branch::NU6,
        expiry_height: 2_800_000,
        sapling: &unsigned_bytes,
        ..ZcashTx::default()
    };
    let sighash = tx.sighash(None, SIGHASH_ALL, &[]).unwrap();
    let mut partial = unauthorized.prepare(&sighash, &random::<240>(70)).unwrap();
    assert_eq!(partial.missing().collect::<Vec<_>>(), [real]);
    // the holder of ask signs the signature hash
    let parts = partial.signing_parts(real).unwrap();
    assert_eq!(parts.ak, proof_key.ak);
    let signature =
        crate::sapling::redjubjub::sign_spend(expsk.ask(), &parts.alpha, &sighash, &random(71));
    partial.append_signature(real, &signature).unwrap();
    let sapling = partial.finalize().unwrap().serialize().unwrap();
    let raw = ZcashTx {
        sapling: &sapling,
        ..tx
    }
    .serialize();
    if let Some(path) = std::env::var_os("SAPLING_TX_DUMP_EXTERNAL") {
        std::fs::write(path, hex::encode(&raw)).unwrap();
    }

    let parsed = ZcashTx::parse_into(&raw, &mut [], &mut []).unwrap();
    assert_eq!(parsed.sighash(None, SIGHASH_ALL, &[]).unwrap(), sighash);
    let bundle = BundleRef::parse(parsed.sapling).unwrap();
    assert_eq!((bundle.n_spends(), bundle.n_outputs()), (2, 3));
    assert_eq!(bundle.value_balance(), 10_000);
    let len = verify_bundle_random_len(&bundle);
    verify_bundle(
        &bundle,
        &sighash,
        &spend_vk,
        &output_vk,
        &random::<160>(72)[..len],
    )
    .unwrap();
    bundle.verify(&sighash).unwrap();
    // the real spend reveals the note's nullifier, wherever it went
    assert_eq!(
        *bundle.spend(real).unwrap().nullifier,
        w.note.nullifier(fvk.nk(), w.path.position)
    );
    // the outputs are where the metadata says, and the dummy is nobody's
    let ivks = [
        fvk.ivk(),
        recipient
            .key
            .expanded_spending_key()
            .full_viewing_key()
            .ivk(),
    ];
    let mut found = Vec::new();
    bundle.try_note_decryption_batch(&ivks, Zip212Enforcement::On, |output, ivk, note, _| {
        found.push((output, ivk, note));
    });
    found.sort_by_key(|(_, ivk, _)| *ivk);
    assert_eq!(
        found,
        [
            (meta.output_index(1).unwrap(), 0, change),
            (meta.output_index(0).unwrap(), 1, sent),
        ]
    );

    // a bundle of dummies alone
    let required = BundleType::Transactional {
        bundle_required: true,
    };
    let mut builder = Builder::new(w.anchor);
    let len = builder.padding_random_len(required).unwrap();
    builder.pad(required, &random::<1056>(80)[..len]).unwrap();
    let unauthorized = builder
        .build(Some(&spend_params), Some(&output_params))
        .unwrap();
    assert_eq!(unauthorized.external_spends().count(), 0);
    let unsigned_bytes = unauthorized.to_bytes().unwrap();
    let tx = ZcashTx {
        consensus_branch_id: branch::NU6,
        expiry_height: 2_800_000,
        sapling: &unsigned_bytes,
        ..ZcashTx::default()
    };
    let sighash = tx.sighash(None, SIGHASH_ALL, &[]).unwrap();
    let sapling = unauthorized
        .sign(&sighash, &random::<160>(81))
        .unwrap()
        .serialize()
        .unwrap();
    let raw = ZcashTx {
        sapling: &sapling,
        ..tx
    }
    .serialize();
    if let Some(path) = std::env::var_os("SAPLING_TX_DUMP_DUMMY") {
        std::fs::write(path, hex::encode(&raw)).unwrap();
    }
    let bundle = BundleRef::parse(&sapling).unwrap();
    assert_eq!((bundle.n_spends(), bundle.n_outputs()), (1, 2));
    assert_eq!(bundle.value_balance(), 0);
    let len = verify_bundle_random_len(&bundle);
    verify_bundle(
        &bundle,
        &sighash,
        &spend_vk,
        &output_vk,
        &random::<160>(82)[..len],
    )
    .unwrap();
}
