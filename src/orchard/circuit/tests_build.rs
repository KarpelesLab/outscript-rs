//! End-to-end tests: build, prove, sign and verify whole bundles.

use alloc::format;

use super::*;
use crate::orchard::builder::{BuildError, Builder, NO_MEMO};
use crate::orchard::bundle::{BundleRef, Flags};
use crate::orchard::keys::{Scope, SpendingKey};
use crate::orchard::note::{Note, Nullifier};
use crate::orchard::note_encryption::try_note_decryption;
use crate::orchard::tree;
use crate::zcashtx::{SIGHASH_ALL, ZcashTx};

/// Deterministic test bytes.
fn seed<const N: usize>(tag: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = tag.wrapping_mul(31).wrapping_add(i as u8).wrapping_mul(167) ^ tag;
    }
    out
}

/// Builds a bundle spending one note (5 ZEC, in a small tree), proves and
/// signs it; checks the proof, the signatures and the note decryption.
/// With `OUTSCRIPT_DUMP_DIR` set the bundle and its sighash are written
/// there for the reference check (`checkbundle <name> <sighash>
/// @built_bundle_<name>.hex` in the scratch project verifies the proof and
/// the signatures with the `orchard` crate).
fn build_and_check(version: CircuitVersion, name: &str) {
    let sk = SpendingKey::from_bytes(seed(1)).unwrap();
    let fvk = sk.to_fvk();
    let sender = fvk.address_at(0u32, Scope::External);
    let other = SpendingKey::from_bytes(seed(2)).unwrap().to_fvk();
    let recipient = other.address_at(7u32, Scope::External);

    // The note to spend, at position 2 of a tree of four notes.
    let rho = Nullifier::from_fp(Fp::from_uniform_bytes(&seed(3)));
    let note = Note::from_parts(sender, 500_000_000, rho, seed(4)).unwrap();
    let leaves = [
        Fp::from_u64(11),
        Fp::from_u64(22),
        note.cmx().to_fp(),
        Fp::from_u64(44),
    ];
    let anchor = tree::root(&leaves).unwrap();
    let path = tree::witness(&leaves, 2).unwrap();

    let restricted = version.supports_cross_address_restriction();
    let mut builder = Builder::new(version, Flags::ENABLED, anchor);
    assert_eq!(
        builder.add_spend(&other, note, path),
        Err(BuildError::WrongKey)
    );
    assert_eq!(
        builder.add_spend(&fvk, note, tree::witness(&leaves, 1).unwrap()),
        Err(BuildError::AnchorMismatch)
    );
    builder.add_spend(&fvk, note, path).unwrap();
    let fee = 10_000;
    let ovk = Some(fvk.to_ovk(Scope::External));
    if restricted {
        // from NU6.3 the Orchard pool only lets value out, or back to the
        // address it comes from
        let mut bad = builder.clone();
        bad.add_output(ovk, recipient, 1, NO_MEMO).unwrap();
        builder
            .add_output(ovk, sender, 200_000_000, NO_MEMO)
            .unwrap();
        assert_eq!(builder.value_balance(), Ok(300_000_000));
        let pk = ProvingKey::build(version);
        assert!(matches!(
            bad.build(&pk, &seed(9)),
            Err(BuildError::CrossAddressDisabled)
        ));
    } else {
        builder
            .add_output(ovk, recipient, 300_000_000, NO_MEMO)
            .unwrap();
        builder
            .add_output(None, sender, 200_000_000 - fee, NO_MEMO)
            .unwrap();
        assert_eq!(builder.value_balance(), Ok(fee as i64));
    }

    let t = std::time::Instant::now();
    let pk = ProvingKey::build(version);
    std::eprintln!("{version:?}: proving key in {:?}", t.elapsed());
    let t = std::time::Instant::now();
    let unauthorized = builder.build(&pk, &seed(5)).unwrap();
    let actions = unauthorized.bundle().actions.len();
    std::eprintln!(
        "{version:?}: {actions} actions built and proven in {:?}",
        t.elapsed()
    );
    assert_eq!(actions, 2);
    assert_eq!(unauthorized.bundle().proof.len(), proof_size(actions));

    // The transaction the bundle goes in gives the sighash.
    let unsigned = unauthorized.bundle().to_bytes();
    let tx = ZcashTx {
        expiry_height: 3_000_000,
        orchard: &unsigned,
        ..ZcashTx::default()
    };
    let sighash = tx.sighash(None, SIGHASH_ALL, &[]).unwrap();
    // Signed elsewhere, the bundle is as good.
    // (From NU6.3 the note kept is created by an action of its own, which
    // spends a note of value zero of the wallet: two actions to sign.)
    let requests = unauthorized.spend_auth_requests();
    assert_eq!(requests.len(), if restricted { 2 } else { 1 });
    let external: Vec<(usize, [u8; 64])> = requests
        .iter()
        .map(|request| {
            let signature = sk
                .to_ask()
                .randomize(&request.alpha)
                .sign(&seed(7), &sighash);
            (request.index, signature.to_bytes())
        })
        .collect();
    let signed = unauthorized
        .authorize(&sighash, &[], &external, &seed(6))
        .unwrap()
        .to_bytes();
    let signed = BundleRef::parse(&signed).unwrap().unwrap();
    assert_eq!(signed.verify_signatures(&sighash), Ok(()));

    let bundle = unauthorized
        .apply_signatures(&sighash, &[sk.to_ask()], &seed(6))
        .unwrap();
    let bytes = bundle.to_bytes();
    // signing does not change the sighash
    let tx = ZcashTx {
        orchard: &bytes,
        ..tx
    };
    assert_eq!(tx.sighash(None, SIGHASH_ALL, &[]).unwrap(), sighash);
    let raw = tx.serialize();
    let parsed = ZcashTx::parse_into(&raw, &mut [], &mut []).unwrap();
    assert_eq!(parsed.orchard, &bytes[..]);

    let parsed = BundleRef::parse(&bytes).unwrap().unwrap();
    assert_eq!(parsed.verify_signatures(&sighash), Ok(()));
    let t = std::time::Instant::now();
    let vk = VerifyingKey::embedded(version);
    std::eprintln!("{version:?}: embedded verifying key in {:?}", t.elapsed());
    let t = std::time::Instant::now();
    assert_eq!(parsed.verify_proof(&vk), Ok(()));
    std::eprintln!("{version:?}: proof verified in {:?}", t.elapsed());
    assert_eq!(parsed.verify_proof(&pk.verifying_key()), Ok(()));
    for other in CircuitVersion::ALL {
        if other != version {
            assert!(parsed.verify_proof(&VerifyingKey::embedded(other)).is_err());
        }
    }

    // The recipients can read their notes.
    let mut found = 0u64;
    for action in parsed.actions() {
        for ivk in [fvk.to_ivk(Scope::External), other.to_ivk(Scope::External)] {
            if let Some((note, _)) =
                try_note_decryption(&ivk, &action.output(), &action.enc_ciphertext)
            {
                found += note.value();
            }
        }
    }
    let expected = if restricted {
        200_000_000
    } else {
        500_000_000 - fee
    };
    assert_eq!(found, expected);

    #[cfg(feature = "std")]
    if let Ok(dir) = std::env::var("OUTSCRIPT_DUMP_DIR") {
        std::fs::write(
            format!("{dir}/built_bundle_{name}.hex"),
            hex::encode(&bytes),
        )
        .unwrap();
        std::fs::write(
            format!("{dir}/built_sighash_{name}.hex"),
            hex::encode(sighash),
        )
        .unwrap();
    }
}

#[test]
#[ignore = "slow in the test profile"]
fn build_prove_sign_verify_fixed() {
    build_and_check(CircuitVersion::FixedPostNu6_2, "fixed");
}

#[test]
#[ignore = "slow in the test profile"]
fn build_prove_sign_verify_post_nu6_3() {
    build_and_check(CircuitVersion::PostNu6_3, "nu63");
}

#[test]
#[ignore = "slow in the test profile"]
fn build_prove_sign_verify_insecure() {
    build_and_check(CircuitVersion::InsecurePreNu6_2, "insecure");
}

/// The proving key and the proof of a bundle are the same on one thread
/// and on many; prints how long each takes.
#[cfg(feature = "std")]
#[test]
#[ignore = "slow in the test profile"]
fn threads_do_not_change_the_bundle() {
    use crate::orchard::halo2::{max_threads, set_max_threads};
    let _guard = crate::orchard::par::TEST_THREADS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let version = CircuitVersion::FixedPostNu6_2;
    let sk = SpendingKey::from_bytes(seed(1)).unwrap();
    let fvk = sk.to_fvk();
    let sender = fvk.address_at(0u32, Scope::External);
    let rho = Nullifier::from_fp(Fp::from_uniform_bytes(&seed(3)));
    let note = Note::from_parts(sender, 500_000_000, rho, seed(4)).unwrap();
    let leaves = [note.cmx().to_fp()];
    let anchor = tree::root(&leaves).unwrap();
    let path = tree::witness(&leaves, 0).unwrap();
    let run = |threads: usize| {
        set_max_threads(threads);
        let t = std::time::Instant::now();
        let pk = ProvingKey::build(version);
        let keygen = t.elapsed();
        let mut builder = Builder::new(version, Flags::ENABLED, anchor);
        builder.add_spend(&fvk, note, path).unwrap();
        builder
            .add_output(None, sender, 400_000_000, NO_MEMO)
            .unwrap();
        let t = std::time::Instant::now();
        let bundle = builder.build(&pk, &seed(5)).unwrap().bundle().to_bytes();
        std::eprintln!(
            "{} thread(s): proving key in {keygen:?}, 2 actions built and proven in {:?}",
            max_threads(),
            t.elapsed()
        );
        let key = format!("{:?}", pk.verifying_key().halo2().pinned());
        (key, bundle)
    };
    let single = run(1);
    for threads in [2, 5, 0] {
        assert!(run(threads) == single, "{threads} threads");
    }
    let parsed = BundleRef::parse(&single.1).unwrap().unwrap();
    assert_eq!(
        parsed.verify_proof(&VerifyingKey::embedded(version)),
        Ok(())
    );
}
