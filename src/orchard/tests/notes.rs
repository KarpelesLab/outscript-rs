use super::{arr, vectors};
use crate::orchard::bundle::{ACTION_SIZE, Action, BundleRef, Flags};
use crate::orchard::keys::*;
use crate::orchard::note_encryption::*;
use crate::orchard::tree::{self, Frontier, MerklePath};
use crate::orchard::{Error, Fp, Fq, Note, Nullifier, ValueCommitment, constants, value};

#[test]
fn note_encryption_vectors() {
    let tvs = vectors(include_str!("../testdata/orchard_note_encryption.json"));
    assert_eq!(tvs.len(), 10);
    for tv in tvs {
        // incoming_viewing_key, ovk, default_d, default_pk_d, v, rseed, memo,
        // cv_net, rho, cmx, esk, ephemeral_key, shared_secret, k_enc, p_enc,
        // c_enc, ock, op, c_out
        let ivk = IncomingViewingKey::from_bytes(&arr(&tv[0])).unwrap();
        let ovk = OutgoingViewingKey::from_bytes(arr(&tv[1]));
        let mut raw = [0u8; 43];
        raw[..11].copy_from_slice(&arr::<11>(&tv[2]));
        raw[11..].copy_from_slice(&arr::<32>(&tv[3]));
        let recipient = Address::from_raw_address_bytes(&raw).unwrap();
        assert_eq!(ivk.address(recipient.diversifier()), recipient);
        let value = tv[4].as_u64().unwrap();
        let rseed: [u8; 32] = arr(&tv[5]);
        let memo: [u8; MEMO_SIZE] = arr(&tv[6]);
        let cv: [u8; 32] = arr(&tv[7]);
        let rho: [u8; 32] = arr(&tv[8]);
        let cmx: [u8; 32] = arr(&tv[9]);
        let ephemeral_key: [u8; 32] = arr(&tv[11]);
        let c_enc: [u8; ENC_CIPHERTEXT_SIZE] = arr(&tv[15]);
        let c_out: [u8; OUT_CIPHERTEXT_SIZE] = arr(&tv[18]);

        let note = Note::from_parts(
            recipient,
            value,
            Nullifier::from_bytes(&rho).unwrap(),
            rseed,
        )
        .unwrap();
        assert_eq!(note.cmx().to_bytes(), cmx);
        assert_eq!(note.esk().to_bytes(), arr::<32>(&tv[10]));

        // encryption reproduces the vector
        let encrypted = encrypt_note(&note, &memo);
        assert_eq!(encrypted.ephemeral_key, ephemeral_key);
        assert_eq!(encrypted.enc_ciphertext, c_enc);
        let cv_typed = ValueCommitment::from_bytes(&cv).unwrap();
        assert_eq!(
            encrypt_outgoing(&note, &ovk, &cv_typed, &ephemeral_key),
            c_out
        );

        // and every way of decrypting recovers the note
        let output = ActionOutput {
            nullifier: &rho,
            cmx: &cmx,
            ephemeral_key: &ephemeral_key,
        };
        let (got, got_memo) = try_note_decryption(&ivk, &output, &c_enc).unwrap();
        assert_eq!(got, note);
        assert_eq!(got_memo, memo);
        let compact: [u8; COMPACT_NOTE_SIZE] = c_enc[..COMPACT_NOTE_SIZE].try_into().unwrap();
        assert_eq!(
            try_compact_note_decryption(&ivk, &output, &compact),
            Some(note)
        );
        let (got, got_memo) =
            try_output_recovery_with_ovk(&ovk, &cv, &output, &c_enc, &c_out).unwrap();
        assert_eq!(got, note);
        assert_eq!(got_memo, memo);

        // a different key, a different action or a damaged ciphertext fail
        let mut other = arr::<64>(&tv[0]);
        other[32] ^= 1;
        let other_ivk = IncomingViewingKey::from_bytes(&other).unwrap();
        assert!(try_note_decryption(&other_ivk, &output, &c_enc).is_none());
        assert!(try_compact_note_decryption(&other_ivk, &output, &compact).is_none());
        let other_ovk = OutgoingViewingKey::from_bytes([1; 32]);
        assert!(try_output_recovery_with_ovk(&other_ovk, &cv, &output, &c_enc, &c_out).is_none());
        let mut bad = c_enc;
        bad[100] ^= 1;
        assert!(try_note_decryption(&ivk, &output, &bad).is_none());
        assert!(try_output_recovery_with_ovk(&ovk, &cv, &output, &bad, &c_out).is_none());
        let mut bad_compact = compact;
        bad_compact[15] ^= 1;
        assert!(try_compact_note_decryption(&ivk, &output, &bad_compact).is_none());
        for field in 0..3 {
            let mut fields = [rho, cmx, ephemeral_key];
            fields[field][0] ^= 1;
            let wrong = ActionOutput {
                nullifier: &fields[0],
                cmx: &fields[1],
                ephemeral_key: &fields[2],
            };
            assert!(try_note_decryption(&ivk, &wrong, &c_enc).is_none());
            assert!(try_compact_note_decryption(&ivk, &wrong, &compact).is_none());
            assert!(try_output_recovery_with_ovk(&ovk, &cv, &wrong, &c_enc, &c_out).is_none());
        }
        // garbage in the public fields does not panic
        let junk = [0xffu8; 32];
        let wrong = ActionOutput {
            nullifier: &junk,
            cmx: &junk,
            ephemeral_key: &junk,
        };
        assert!(try_note_decryption(&ivk, &wrong, &c_enc).is_none());
        let zero = [0u8; 32];
        let wrong = ActionOutput {
            nullifier: &rho,
            cmx: &cmx,
            ephemeral_key: &zero,
        };
        assert!(try_note_decryption(&ivk, &wrong, &c_enc).is_none());
    }
}

#[test]
fn unrecoverable_outgoing_ciphertext() {
    let mut random = [0u8; 96];
    for (i, b) in random.iter_mut().enumerate() {
        *b = i as u8;
    }
    let out = encrypt_outgoing_unrecoverable(&random);
    assert_ne!(out[..64], random[32..]);
    assert_ne!(out, encrypt_outgoing_unrecoverable(&[3; 96]));
}

#[test]
fn empty_roots_vectors() {
    let tvs = vectors(include_str!("../testdata/orchard_empty_roots.json"));
    let roots = tvs[0][0].as_array().unwrap();
    assert_eq!(roots.len(), 33);
    for (level, expected) in roots.iter().enumerate() {
        assert_eq!(tree::empty_root(level).to_bytes(), arr::<32>(expected));
        assert_eq!(constants::EMPTY_ROOTS[level], tree::empty_root(level));
    }
    assert_eq!(tree::empty_root(0), tree::UNCOMMITTED);
    for level in 0..32 {
        let below = tree::empty_root(level);
        assert_eq!(
            tree::merkle_crh(level, &below, &below),
            tree::empty_root(level + 1)
        );
    }
    assert_eq!(Frontier::new().root(), tree::empty_root(32));
    #[cfg(feature = "alloc")]
    assert_eq!(tree::root(&[]), Some(tree::empty_root(32)));
}

#[test]
fn merkle_tree_vectors() {
    let tvs = vectors(include_str!("../testdata/orchard_merkle_tree.json"));
    assert_eq!(tvs.len(), 16);
    let field = |v: &serde_json::Value| Fp::from_bytes(&arr(v)).unwrap();
    let mut frontier = Frontier::new();
    for (appended, tv) in tvs.iter().enumerate() {
        // the 16 leaves of a tree of depth 4, the paths of each, its root
        let leaves: Vec<Fp> = tv[0].as_array().unwrap().iter().map(field).collect();
        let paths = tv[1].as_array().unwrap();
        let small_root = field(&tv[2]);
        assert_eq!(leaves.len(), 16);
        // the full tree has the depth 4 tree as its leftmost subtree
        let mut root = small_root;
        for level in 4..32 {
            root = tree::merkle_crh(level, &root, &tree::empty_root(level));
        }
        #[cfg_attr(not(feature = "alloc"), allow(unused_variables))]
        let committed = &leaves[..appended + 1];
        assert!(
            leaves[appended + 1..]
                .iter()
                .all(|l| *l == tree::UNCOMMITTED)
        );
        #[cfg(feature = "alloc")]
        {
            assert_eq!(tree::root(committed), Some(root));
            assert_eq!(tree::root(&leaves), Some(root));
        }
        assert_eq!(frontier.append(leaves[appended]), Ok(appended as u32));
        assert_eq!(frontier.size(), appended as u64 + 1);
        assert_eq!(frontier.root(), root);
        for (position, expected) in paths.iter().enumerate() {
            let expected: Vec<Fp> = expected.as_array().unwrap().iter().map(field).collect();
            assert_eq!(expected.len(), 4);
            // the path of the vector, completed with empty subtrees
            let mut auth_path = [Fp::ZERO; 32];
            for (level, sibling) in auth_path.iter_mut().enumerate() {
                *sibling = match expected.get(level) {
                    Some(e) => *e,
                    None => tree::empty_root(level),
                };
            }
            let path = MerklePath::from_parts(position as u32, auth_path);
            assert_eq!(path.root(leaves[position]), root);
            assert_eq!(path.position(), position as u32);
            assert_eq!(path.auth_path(), &auth_path);
            #[cfg(feature = "alloc")]
            {
                assert_eq!(tree::witness(&leaves, position as u32), Some(path));
                if position <= appended {
                    assert_eq!(tree::witness(committed, position as u32), Some(path));
                } else {
                    assert!(tree::witness(committed, position as u32).is_none());
                }
            }
        }
    }
}

/// The spec's own check value for `MerkleCRH` (also asserted by the
/// reference test vector generator).
#[test]
fn merkle_crh_known_value() {
    let rev = |s: &str| -> [u8; 32] {
        let mut b: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
        b.reverse();
        // the generator hashes the low 255 bits
        b[31] &= 0x7f;
        b
    };
    let left = rev("87a086ae7d2252d58729b30263fb7b66308bf94ef59a76c9c86e7ea016536505");
    let right = rev("a75b84a125b2353da7e8d96ee2a15efe4de23df9601b9d9564ba59de57130406");
    let left = Fp::from_bytes(&left).unwrap();
    let right = Fp::from_bytes(&right).unwrap();
    // the generator asserts merkle_crh(MERKLE_DEPTH - 1 - 25, left, right)
    // with l = MERKLE_DEPTH - 1 - layer = 25
    let mut parent = Fp::ZERO;
    for digit in
        "626278560043615083774572461435172561667439770708282630516615972307985967801".bytes()
    {
        parent = parent * Fp::from_u64(10) + Fp::from_u64((digit - b'0') as u64);
    }
    assert_eq!(tree::merkle_crh(25, &left, &right), parent);
    assert_ne!(tree::merkle_crh(26, &left, &right), parent);
}

fn sample_bundle(actions: usize, sighash: &[u8; 32]) -> Vec<u8> {
    let sk = SpendingKey::from_bytes([11; 32]).unwrap();
    let ask = sk.to_ask();
    let fvk = sk.to_fvk();
    let recipient = fvk.address_at(0u32, Scope::External);
    let mut data = vec![actions as u8];
    let mut sigs = Vec::new();
    let mut rcvs = Vec::new();
    for i in 0..actions {
        let rho = Nullifier::from_fp(Fp::from_u64(1000 + i as u64));
        let note = Note::from_parts(recipient, 50_000, rho, [i as u8 + 1; 32]).unwrap();
        let rcv = Fq::from_u64(77 + i as u64);
        // each action spends nothing and outputs 50000
        let cv = ValueCommitment::derive(-50_000, &rcv);
        rcvs.push(rcv);
        let alpha = Fq::from_u64(5 + i as u64);
        let encrypted = encrypt_note(&note, &[0xf6; MEMO_SIZE]);
        let action = Action {
            cv: cv.to_bytes(),
            nullifier: rho.to_bytes(),
            rk: fvk.ak().randomize(&alpha).to_bytes(),
            cmx: note.cmx().to_bytes(),
            ephemeral_key: encrypted.ephemeral_key,
            enc_ciphertext: encrypted.enc_ciphertext,
            out_ciphertext: encrypt_outgoing(
                &note,
                &fvk.to_ovk(Scope::External),
                &cv,
                &encrypted.ephemeral_key,
            ),
            spend_auth_sig: ask
                .randomize(&alpha)
                .sign(&[i as u8; 80], sighash)
                .to_bytes(),
        };
        data.extend_from_slice(&action.to_bytes());
        sigs.extend_from_slice(&action.spend_auth_sig);
    }
    data.push(Flags::ENABLED.to_byte());
    data.extend_from_slice(&(-50_000i64 * actions as i64).to_le_bytes());
    data.extend_from_slice(&tree::empty_root(32).to_bytes());
    data.extend_from_slice(&[0xfd, 0x00, 0x01]);
    data.extend_from_slice(&[0xab; 256]);
    data.extend_from_slice(&sigs);
    let bsk = value::binding_signing_key(rcvs.iter());
    data.extend_from_slice(&bsk.sign(&[0x99; 80], sighash).to_bytes());
    data
}

#[test]
fn bundle_roundtrip_and_signatures() {
    let sighash = [0x42; 32];
    let data = sample_bundle(3, &sighash);
    let bundle = BundleRef::parse(&data).unwrap().unwrap();
    assert_eq!(bundle.action_count(), 3);
    assert_eq!(bundle.actions().len(), 3);
    assert_eq!(bundle.flags(), Flags::ENABLED);
    assert!(bundle.flags().spends_enabled() && bundle.flags().outputs_enabled());
    assert_eq!(bundle.value_balance(), -150_000);
    assert_eq!(bundle.anchor(), &tree::empty_root(32).to_bytes());
    assert_eq!(bundle.proof(), &[0xab; 256][..]);
    assert_eq!(bundle.serialized_len(), data.len());
    let mut out = vec![0u8; data.len()];
    assert_eq!(bundle.write_to_slice(&mut out), Ok(data.len()));
    assert_eq!(out, data);
    assert_eq!(
        bundle.write_to_slice(&mut out[..data.len() - 1]),
        Err(Error::BufferTooSmall)
    );
    assert!(bundle.action(3).is_none());

    // signatures
    assert_eq!(bundle.verify_signatures(&sighash), Ok(()));
    assert_eq!(
        bundle.verify_signatures(&[0x43; 32]),
        Err(Error::InvalidSignature)
    );

    // the notes are found by their owner and recoverable by the sender
    let fvk = SpendingKey::from_bytes([11; 32]).unwrap().to_fvk();
    let ivk = fvk.to_ivk(Scope::External);
    for action in bundle.actions() {
        let (note, memo) =
            try_note_decryption(&ivk, &action.output(), &action.enc_ciphertext).unwrap();
        assert_eq!(note.value(), 50_000);
        assert_eq!(memo, [0xf6; MEMO_SIZE]);
        assert!(
            try_note_decryption(
                &fvk.to_ivk(Scope::Internal),
                &action.output(),
                &action.enc_ciphertext
            )
            .is_none()
        );
        let recovered = try_output_recovery_with_ovk(
            &fvk.to_ovk(Scope::External),
            &action.cv,
            &action.output(),
            &action.enc_ciphertext,
            &action.out_ciphertext,
        )
        .unwrap();
        assert_eq!(recovered.0, note);
        assert!(action.value_commitment().is_some());
        assert!(action.validating_key().is_some());
    }

    #[cfg(feature = "alloc")]
    owned_bundle(&data, &sighash);
}

#[cfg(feature = "alloc")]
fn owned_bundle(data: &[u8], sighash: &[u8; 32]) {
    let bundle = BundleRef::parse(data).unwrap().unwrap();
    let owned = bundle.to_owned();
    assert_eq!(owned.to_bytes(), data);
    assert_eq!(
        crate::orchard::bundle::Bundle::parse(data),
        Ok(Some(owned.clone()))
    );
    let mut tampered = owned.clone();
    tampered.value_balance += 1;
    let bytes = tampered.to_bytes();
    let view = BundleRef::parse(&bytes).unwrap().unwrap();
    assert_eq!(
        view.verify_signatures(sighash),
        Err(Error::InvalidSignature)
    );
    let mut empty = owned;
    empty.actions.clear();
    assert_eq!(empty.to_bytes(), [0]);

    // the transaction layer accepts the same bytes
    let tx = crate::zcashtx::ZcashTx {
        orchard: data,
        ..Default::default()
    };
    let serialized = tx.serialize();
    assert!(serialized.ends_with(data));
    assert!(tx.txid().is_ok());
}

#[test]
fn bundle_parsing_is_strict_and_panic_free() {
    assert_eq!(BundleRef::parse(&[]), Ok(None));
    assert_eq!(BundleRef::parse(&[0]), Ok(None));
    assert_eq!(BundleRef::parse(&[0, 0]), Err(Error::TrailingData));
    let data = sample_bundle(1, &[1; 32]);
    assert_eq!(data.len(), 1 + ACTION_SIZE + 41 + 3 + 256 + 64 + 64);
    for len in 1..data.len() {
        assert_eq!(
            BundleRef::parse(&data[..len]),
            Err(Error::UnexpectedEof),
            "{len}"
        );
    }
    let mut long = data.clone();
    long.push(0);
    assert_eq!(BundleRef::parse(&long), Err(Error::TrailingData));
    let mut rest = &long[..];
    assert!(BundleRef::read(&mut rest).unwrap().is_some());
    assert_eq!(rest, [0]);
    // unknown flag bits
    let mut bad = data.clone();
    bad[1 + ACTION_SIZE] = 0b100;
    assert_eq!(BundleRef::parse(&bad), Err(Error::InvalidFlags));
    assert!(Flags::from_byte(4).is_none());
    assert_eq!(Flags::from_parts(true, false).to_byte(), 1);
    assert_eq!(Flags::from_parts(false, true).to_byte(), 2);
    // a non-canonical action count, absurd counts
    let mut bad = vec![0xfd, 0x01, 0x00];
    bad.extend_from_slice(&data[1..]);
    assert_eq!(BundleRef::parse(&bad), Err(Error::NonCanonical));
    assert_eq!(
        BundleRef::parse(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        Err(Error::TooLarge)
    );
    assert_eq!(
        BundleRef::parse(&[0xfe, 0xff, 0xff, 0xff, 0xff]),
        Err(Error::UnexpectedEof)
    );
    // points that do not decode fail verification without panicking
    let mut bad = data.clone();
    bad[1..33].fill(0xff);
    let view = BundleRef::parse(&bad).unwrap().unwrap();
    assert_eq!(
        view.binding_validating_key().unwrap_err(),
        Error::InvalidEncoding
    );
    assert!(view.verify_signatures(&[1; 32]).is_err());
    let mut bad = data;
    bad[65..97].fill(0xff);
    let view = BundleRef::parse(&bad).unwrap().unwrap();
    assert_eq!(
        view.verify_signatures(&[1; 32]),
        Err(Error::InvalidEncoding)
    );
}
