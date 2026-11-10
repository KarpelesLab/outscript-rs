use super::{arr, vectors};
use crate::orchard::keys::*;
use crate::orchard::redpallas::{Binding, Signature, SigningKey, SpendAuth, VerificationKey};
use crate::orchard::{Error, Fp, Fq, Note, Nullifier, value};

#[test]
fn key_components_vectors() {
    let tvs = vectors(include_str!("../testdata/orchard_key_components.json"));
    assert_eq!(tvs.len(), 10);
    for tv in tvs {
        // sk, ask, ak, nk, rivk, ivk, ovk, dk, default_d, default_pk_d,
        // internal_rivk, internal_ivk, internal_ovk, internal_dk,
        // note_v, note_rho, note_rseed, note_cmx, note_nf
        let sk = SpendingKey::from_bytes(arr(&tv[0])).unwrap();
        assert_eq!(sk.to_bytes(), &arr::<32>(&tv[0]));
        let ask = sk.to_ask();
        assert_eq!(ask.to_scalar().to_bytes(), arr::<32>(&tv[1]));
        let fvk = sk.to_fvk();
        assert_eq!(ask.to_ak(), *fvk.ak());
        assert_eq!(fvk.ak().to_bytes(), arr::<32>(&tv[2]));
        assert_eq!(fvk.nk().to_bytes(), arr::<32>(&tv[3]));
        assert_eq!(fvk.rivk(Scope::External).to_bytes(), arr::<32>(&tv[4]));
        let ivk = fvk.to_ivk(Scope::External);
        assert_eq!(ivk.ivk().to_bytes(), arr::<32>(&tv[5]));
        assert_eq!(fvk.to_ovk(Scope::External).to_bytes(), &arr::<32>(&tv[6]));
        assert_eq!(ivk.dk().to_bytes(), &arr::<32>(&tv[7]));
        let address = fvk.address_at(0u32, Scope::External);
        assert_eq!(address.diversifier().to_bytes(), &arr::<11>(&tv[8]));
        assert_eq!(address.pk_d().to_bytes(), arr::<32>(&tv[9]));
        assert_eq!(fvk.rivk(Scope::Internal).to_bytes(), arr::<32>(&tv[10]));
        let internal = fvk.to_ivk(Scope::Internal);
        assert_eq!(internal.ivk().to_bytes(), arr::<32>(&tv[11]));
        assert_eq!(fvk.to_ovk(Scope::Internal).to_bytes(), &arr::<32>(&tv[12]));
        assert_eq!(internal.dk().to_bytes(), &arr::<32>(&tv[13]));

        // encodings round-trip
        assert_eq!(FullViewingKey::from_bytes(&fvk.to_bytes()), Ok(fvk));
        assert_eq!(IncomingViewingKey::from_bytes(&ivk.to_bytes()), Ok(ivk));
        let raw = address.to_raw_address_bytes();
        assert_eq!(Address::from_raw_address_bytes(&raw), Ok(address));
        assert_eq!(
            ivk.diversifier_index(&address),
            Some(DiversifierIndex::from(0u32))
        );
        assert_eq!(internal.diversifier_index(&address), None);
        assert_eq!(fvk.scope_for_address(&address), Some(Scope::External));
        let change = fvk.address_at(7u32, Scope::Internal);
        assert_eq!(fvk.scope_for_address(&change), Some(Scope::Internal));
        assert_eq!(
            internal.diversifier_index(&change).unwrap().to_u128(),
            7u128
        );

        // the note of the vector
        let rho = Nullifier::from_bytes(&arr(&tv[15])).unwrap();
        let note = Note::from_parts(address, tv[14].as_u64().unwrap(), rho, arr(&tv[16])).unwrap();
        assert_eq!(note.cmx().to_bytes(), arr::<32>(&tv[17]));
        assert_eq!(note.nullifier(&fvk).to_bytes(), arr::<32>(&tv[18]));
    }
}

#[test]
fn zip32_vectors() {
    let tvs = vectors(include_str!("../testdata/orchard_zip32.json"));
    assert_eq!(tvs.len(), 4);
    let seed: Vec<u8> = (0..32).collect();
    let mut key = ExtendedSpendingKey::master(&seed).unwrap();
    for (depth, tv) in tvs.iter().enumerate() {
        // sk, c, xsk, fp
        if depth > 0 {
            key = key.derive_child(depth as u32).unwrap();
        }
        assert_eq!(key.depth() as usize, depth);
        assert_eq!(key.spending_key().to_bytes(), &arr::<32>(&tv[0]));
        assert_eq!(key.chain_code(), &arr::<32>(&tv[1]));
        assert_eq!(key.to_bytes(), arr::<73>(&tv[2]));
        let fvk = key.spending_key().to_fvk();
        assert_eq!(fvk.fingerprint(), arr::<32>(&tv[3]));
        assert_eq!(
            ExtendedSpendingKey::from_bytes(&key.to_bytes()),
            Ok(key.clone())
        );
        let path: Vec<u32> = (1..=depth as u32).collect();
        assert_eq!(
            ExtendedSpendingKey::from_path(&seed, &path),
            Ok(key.clone())
        );
    }
    assert_eq!(
        key.derive_child(1 << 31).unwrap_err(),
        Error::InvalidChildIndex
    );
    assert_eq!(
        ExtendedSpendingKey::master(&seed[..31]).unwrap_err(),
        Error::InvalidSeedLength
    );
    assert_eq!(
        ExtendedSpendingKey::master(&[0u8; 253]).unwrap_err(),
        Error::InvalidSeedLength
    );
    let account = SpendingKey::from_zip32_seed(&seed, 133, 0).unwrap();
    let by_path = ExtendedSpendingKey::from_path(&seed, &[32, 133, 0]).unwrap();
    assert_eq!(account.to_bytes(), by_path.spending_key().to_bytes());
    // a master key cannot claim a parent
    let mut bytes = ExtendedSpendingKey::master(&seed).unwrap().to_bytes();
    bytes[1] = 1;
    assert!(ExtendedSpendingKey::from_bytes(&bytes).is_err());
}

#[test]
fn key_encodings_reject_invalid_input() {
    let sk = SpendingKey::from_bytes([7; 32]).unwrap();
    let fvk = sk.to_fvk();
    let good = fvk.to_bytes();
    // ak with its sign bit set, ak = identity, non-canonical nk and rivk
    let mut bad = good;
    bad[31] |= 0x80;
    assert_eq!(
        FullViewingKey::from_bytes(&bad),
        Err(Error::InvalidFullViewingKey)
    );
    let mut bad = good;
    bad[..32].fill(0);
    assert!(FullViewingKey::from_bytes(&bad).is_err());
    let mut bad = good;
    bad[32..64].fill(0xff);
    assert!(FullViewingKey::from_bytes(&bad).is_err());
    let mut bad = good;
    bad[64..].fill(0xff);
    assert!(FullViewingKey::from_bytes(&bad).is_err());

    let ivk = fvk.to_ivk(Scope::External).to_bytes();
    let mut bad = ivk;
    bad[32..].fill(0);
    assert_eq!(
        IncomingViewingKey::from_bytes(&bad),
        Err(Error::InvalidIncomingViewingKey)
    );
    bad[32..].fill(0xff);
    assert!(IncomingViewingKey::from_bytes(&bad).is_err());

    let address = fvk.address_at(3u64, Scope::External).to_raw_address_bytes();
    let mut bad = address;
    bad[11..].fill(0);
    assert_eq!(
        Address::from_raw_address_bytes(&bad),
        Err(Error::InvalidAddress)
    );
    bad[11..].fill(0xff);
    assert!(Address::from_raw_address_bytes(&bad).is_err());

    assert!(DiversifierIndex::from_u128(1 << 88).is_none());
    let max = DiversifierIndex::from_u128((1 << 88) - 1).unwrap();
    assert_eq!(max.to_bytes(), &[0xff; 11]);
    // FF1 is a permutation: every index decrypts back
    let dk = *fvk.to_ivk(Scope::External).dk();
    for index in [0u128, 1, 0xdead_beef, (1 << 88) - 1, 1 << 44, (1 << 44) - 1] {
        let index = DiversifierIndex::from_u128(index).unwrap();
        assert_eq!(dk.diversifier_index(&dk.get(index)), index);
    }
    assert_eq!(format!("{sk:?}"), "SpendingKey(..)");
}

#[test]
fn redpallas_sign_and_verify() {
    let sk = SpendingKey::from_bytes([42; 32]).unwrap();
    let ask = sk.to_ask();
    let ak = ask.to_ak();
    let msg = [9u8; 32];
    let random = [0x5a; 80];

    // a spend authorization signature under a randomized key
    let alpha = Fq::from_u64(0x1234_5678_9abc);
    let rsk = ask.randomize(&alpha);
    let rk = ak.randomize(&alpha);
    assert_eq!(rsk.verification_key(), rk);
    let sig = rsk.sign(&random, &msg);
    assert_eq!(rk.verify(&msg, &sig), Ok(()));
    assert_eq!(rk.verify(&[8u8; 32], &sig), Err(Error::InvalidSignature));
    let plain: SigningKey<SpendAuth> = SigningKey::from_scalar(ask.to_scalar());
    assert_eq!(plain.randomize(&alpha).to_bytes(), rsk.to_bytes());
    assert_eq!(
        plain.verification_key().verify(&msg, &sig),
        Err(Error::InvalidSignature)
    );
    assert_eq!(plain.verification_key().randomize(&alpha), rk);
    // the signature is randomized
    let other = rsk.sign(&[0xa5; 80], &msg);
    assert_ne!(sig, other);
    assert_eq!(rk.verify(&msg, &other), Ok(()));

    // encodings
    let bytes = sig.to_bytes();
    assert_eq!(Signature::<SpendAuth>::from_bytes(&bytes), sig);
    let vk = VerificationKey::<SpendAuth>::from_bytes(&rk.to_bytes()).unwrap();
    assert_eq!(vk, rk);
    assert_eq!(vk.to_point(), rk.to_point());
    let mut bad = bytes;
    bad[40] ^= 1;
    assert!(rk.verify(&msg, &Signature::from_bytes(&bad)).is_err());
    // a non-canonical S, a non-canonical R
    let mut bad = bytes;
    bad[32..].fill(0xff);
    assert!(rk.verify(&msg, &Signature::from_bytes(&bad)).is_err());
    let mut bad = bytes;
    bad[..32].fill(0xff);
    assert!(rk.verify(&msg, &Signature::from_bytes(&bad)).is_err());
    assert!(SigningKey::<SpendAuth>::from_bytes(&[0xff; 32]).is_none());
    assert!(VerificationKey::<Binding>::from_bytes(&[0xff; 32]).is_none());

    // a binding signature: two actions whose values balance
    let (rcv1, rcv2) = (Fq::from_u64(111), Fq::from_u64(222).neg());
    let cv1 = value::ValueCommitment::derive(5_000, &rcv1);
    let cv2 = value::ValueCommitment::derive(-3_000, &rcv2);
    let bsk = value::binding_signing_key([&rcv1, &rcv2]);
    let bvk = value::binding_validating_key([&cv1, &cv2], 2_000);
    assert_eq!(bsk.verification_key(), bvk);
    let sig = bsk.sign(&random, &msg);
    assert_eq!(bvk.verify(&msg, &sig), Ok(()));
    let wrong = value::binding_validating_key([&cv1, &cv2], 2_001);
    assert!(wrong.verify(&msg, &sig).is_err());
    assert_eq!(
        value::ValueCommitment::from_bytes(&cv1.to_bytes()),
        Some(cv1)
    );
    // commitments are homomorphic
    let sum = value::ValueCommitment::derive(2_000, &(rcv1 + rcv2));
    assert_eq!(
        (cv1.to_point().to_point() + cv2.to_point()).to_affine(),
        sum.to_point()
    );
    let _ = Fp::ZERO;
}

/// Signatures of both kinds verified together.
#[cfg(feature = "alloc")]
#[test]
fn redpallas_batch_verification() {
    use crate::orchard::redpallas::BatchVerifier;
    let random = [0x77; 64];
    let msgs: [[u8; 32]; 3] = [[1; 32], [2; 32], [3; 32]];
    let spend: Vec<_> = (0u8..3)
        .map(|i| {
            let ask = SpendingKey::from_bytes([40 + i; 32]).unwrap().to_ask();
            let rsk = ask.randomize(&Fq::from_u64(1000 + i as u64));
            let sig = rsk.sign(&[i; 80], &msgs[i as usize]);
            (rsk.verification_key(), sig)
        })
        .collect();
    let bsk: SigningKey<Binding> = SigningKey::from_scalar(Fq::from_u64(0xdead_beef));
    let binding = (bsk.verification_key(), bsk.sign(&[9; 80], &msgs[0]));

    let batch = |skip: Option<usize>| {
        let mut batch = BatchVerifier::new();
        for (i, (vk, sig)) in spend.iter().enumerate() {
            if skip != Some(i) {
                batch.queue(vk, &msgs[i], sig);
            }
        }
        batch.queue(&binding.0, &msgs[0], &binding.1);
        batch
    };
    assert!(BatchVerifier::new().is_empty());
    assert_eq!(BatchVerifier::new().verify(&random), Ok(()));
    assert_eq!(batch(None).len(), 4);
    assert_eq!(batch(None).verify(&random), Ok(()));
    assert_eq!(batch(None).verify(&[0; 64]), Ok(()));
    for i in 0..3 {
        // one signature over another message, by another key, altered
        let mut b = batch(Some(i));
        b.queue(&spend[i].0, &msgs[(i + 1) % 3], &spend[i].1);
        assert_eq!(b.verify(&random), Err(Error::InvalidSignature));
        let mut b = batch(Some(i));
        b.queue(&spend[(i + 1) % 3].0, &msgs[i], &spend[i].1);
        assert_eq!(b.verify(&random), Err(Error::InvalidSignature));
        for at in [3, 40] {
            let mut bytes = spend[i].1.to_bytes();
            bytes[at] ^= 4;
            let mut b = batch(Some(i));
            b.queue(&spend[i].0, &msgs[i], &Signature::from_bytes(&bytes));
            assert_eq!(b.verify(&random), Err(Error::InvalidSignature));
        }
        // not canonically encoded
        let mut bytes = spend[i].1.to_bytes();
        bytes[32..].fill(0xff);
        let mut b = batch(Some(i));
        b.queue(&spend[i].0, &msgs[i], &Signature::from_bytes(&bytes));
        assert_eq!(b.len(), 4);
        assert_eq!(b.verify(&random), Err(Error::InvalidSignature));
    }
    // a signature of one kind does not pass for the other
    let as_binding: VerificationKey<Binding> =
        VerificationKey::from_bytes(&spend[0].0.to_bytes()).unwrap();
    let mut b = BatchVerifier::new();
    b.queue(
        &as_binding,
        &msgs[0],
        &Signature::from_bytes(&spend[0].1.to_bytes()),
    );
    assert_eq!(b.verify(&random), Err(Error::InvalidSignature));
    // two wrong signatures whose errors would cancel out with equal
    // coefficients: swapped between two keys
    let mut b = BatchVerifier::new();
    b.queue(&spend[0].0, &msgs[0], &spend[1].1);
    b.queue(&spend[1].0, &msgs[1], &spend[0].1);
    assert_eq!(b.verify(&random), Err(Error::InvalidSignature));
}
