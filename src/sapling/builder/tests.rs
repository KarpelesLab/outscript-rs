//! The builder's checks, and (ignored by default: it needs the parameter
//! files, see `prover/tests.rs`) a complete shielded transaction.

use super::*;
use crate::sapling::bundle::BundleRef;
use crate::sapling::keys::Diversifier;
use crate::sapling::note_encryption::{
    Zip212Enforcement, try_note_decryption, try_output_recovery_with_ovk,
};
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

/// Signing with the wrong amount of randomness, on a copy.
#[cfg(feature = "std")]
fn wallet_clone_sign(
    unauthorized: &UnauthorizedBundle,
    sighash: &[u8; 32],
) -> Result<Bundle, Error> {
    let copy = UnauthorizedBundle {
        bundle: unauthorized.bundle().clone(),
        signing_keys: unauthorized
            .signing_keys
            .iter()
            .map(|k| SigningKey {
                ask: k.ask,
                alpha: k.alpha,
            })
            .collect(),
        bsk: unauthorized.bsk,
    };
    copy.sign(sighash, &[0; 80])
}
