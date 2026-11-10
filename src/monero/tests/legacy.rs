//! Tests of the verification of the old formats — version 1 ring
//! signatures, MLSAG, Borromean range proofs, the original Bulletproofs —
//! and of `Transaction::verify`, against real mainnet transactions and
//! their rings (`testdata/mainnet_txs.txt`).

use std::vec::Vec;

use super::with_alloc::mainnet_txs;
use super::*;

/// The transaction `name` of the fixtures and its rings.
fn real(name: &str) -> (Transaction, Vec<Vec<RingMember>>) {
    let mut txs = mainnet_txs();
    let real = txs.remove(name).unwrap_or_else(|| panic!("{name}"));
    assert!(!real.rings.is_empty(), "{name}");
    (Transaction::parse(&real.bytes).unwrap(), real.rings)
}

/// A point of order 8.
const TORSION: &str = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a";

/// A version 1 transaction: its ring signatures hold, and are bound to the
/// prefix, the ring and the key image.
#[test]
fn v1_ring_signatures() {
    let (tx, rings) = real("v1");
    assert_eq!(tx.prefix.version, 1);
    assert_eq!(tx.verify_ring_signatures(&rings), Ok(true));
    assert_eq!(tx.verify_balance(), Ok(true));
    assert_eq!(tx.verify_range_proof(), Err(Error::Unsupported));
    assert_eq!(tx.verify(&rings), Ok(true));

    // The primitive, input by input.
    let message = tx.prefix.hash();
    for ((input, ring), signatures) in tx.prefix.inputs.iter().zip(&rings).zip(&tx.signatures) {
        let keys: Vec<[u8; 32]> = ring.iter().map(|member| member.key).collect();
        let key_image = input.key_image().unwrap();
        assert!(check_ring_signature(&message, key_image, &keys, signatures));
        assert!(!check_ring_signature(
            &[0u8; 32], key_image, &keys, signatures
        ));
        assert!(!check_ring_signature(&message, &keys[0], &keys, signatures));
        assert!(!check_ring_signature(
            &message,
            key_image,
            &keys[1..],
            &signatures[1..]
        ));
        assert!(!check_ring_signature(
            &message,
            key_image,
            &keys[1..],
            signatures
        ));
        let mut swapped = keys.clone();
        swapped.swap(0, 1);
        assert!(!check_ring_signature(
            &message, key_image, &swapped, signatures
        ));
        for byte in [0usize, 31, 32, 63] {
            let mut bad = signatures.clone();
            bad[1][byte] ^= 1;
            assert!(!check_ring_signature(&message, key_image, &keys, &bad));
        }
        // A challenge or response that is not reduced, a key that is not a
        // point.
        let mut bad = signatures.clone();
        bad[0][..32].copy_from_slice(&[0xff; 32]);
        assert!(!check_ring_signature(&message, key_image, &keys, &bad));
        let mut bad = keys.clone();
        bad[0] = [0xff; 32];
        assert!(!check_ring_signature(&message, key_image, &bad, signatures));
        assert!(!check_ring_signature(
            &message,
            &[0xff; 32],
            &keys,
            signatures
        ));
    }

    // Through the transaction.
    let mut bad = rings.clone();
    bad[1].swap(0, 1);
    assert_eq!(tx.verify_ring_signatures(&bad), Ok(false));
    assert_eq!(tx.verify(&bad), Ok(false));
    let mut bad = rings.clone();
    bad[0].pop();
    assert_eq!(tx.verify(&bad), Err(Error::InvalidRing));
    assert_eq!(tx.verify(&rings[..1]), Err(Error::InvalidRing));
    let mut changed = tx.clone();
    changed.prefix.unlock_time += 1;
    assert_eq!(changed.verify(&rings), Ok(false));
    let mut changed = tx.clone();
    changed.signatures[0][0][0] ^= 1;
    assert_eq!(changed.verify(&rings), Ok(false));
    let mut changed = tx.clone();
    changed.signatures.pop();
    assert_eq!(changed.verify(&rings), Err(Error::InvalidTransaction));
    // Outputs worth more than the inputs.
    let mut changed = tx.clone();
    changed.prefix.outputs[0].amount = u64::MAX / 2;
    assert_eq!(changed.fee(), None);
    assert_eq!(changed.verify_balance(), Ok(false));
    assert_eq!(changed.verify(&rings), Ok(false));
}

/// Key images that consensus refuses: the identity, and anything with a
/// torsion component.
#[test]
fn key_image_subgroup() {
    use super::super::legacy_sig::key_image_point;
    let (tx, _) = real("v1");
    let good = *tx.prefix.inputs[0].key_image().unwrap();
    assert!(key_image_point(&good).is_some());
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(key_image_point(&identity).is_none());
    assert!(key_image_point(&h32(TORSION)).is_none());
    assert!(key_image_point(&[0xff; 32]).is_none());
    let torsion = EdwardsPoint::decompress(&h32(TORSION)).unwrap();
    assert_eq!(torsion.mul_by_cofactor(), EdwardsPoint::identity());
    let mixed = EdwardsPoint::decompress(&good).unwrap().add(&torsion);
    assert!(key_image_point(&mixed.compress()).is_none());
}

/// RingCT type 1: one MLSAG over all the inputs, which also carries the
/// balance, and a Borromean range proof per output.
#[test]
fn rct_full() {
    let (tx, rings) = real("rct1");
    assert_eq!(tx.rct.rct_type, RCT_TYPE_FULL);
    assert_eq!(tx.rct.mlsags.len(), 1);
    assert_eq!(tx.verify_balance(), Err(Error::Unsupported));
    assert_eq!(tx.verify_ring_signatures(&rings), Ok(true));
    assert_eq!(tx.verify_range_proof(), Ok(true));
    assert_eq!(tx.verify(&rings), Ok(true));

    let message = tx.signature_hash();
    let key_images: Vec<[u8; 32]> = tx
        .prefix
        .inputs
        .iter()
        .map(|input| *input.key_image().unwrap())
        .collect();
    let mlsag = &tx.rct.mlsags[0];
    let (out_pk, fee) = (&tx.rct.out_pk, tx.rct.fee);
    assert!(mlsag.verify_full(&message, &rings, &key_images, out_pk, fee));
    // The balance: another fee, an output commitment missing.
    assert!(!mlsag.verify_full(&message, &rings, &key_images, out_pk, fee + 1));
    assert!(!mlsag.verify_full(&message, &rings, &key_images, &out_pk[1..], fee));
    // The message, the ring, the key image, the signature.
    assert!(!mlsag.verify_full(&[1u8; 32], &rings, &key_images, out_pk, fee));
    let mut bad = rings.clone();
    bad[0][1].commitment = bad[0][0].commitment;
    assert!(!mlsag.verify_full(&message, &bad, &key_images, out_pk, fee));
    let mut bad = rings.clone();
    bad[0].swap(0, 2);
    assert!(!mlsag.verify_full(&message, &bad, &key_images, out_pk, fee));
    let mut bad = rings.clone();
    bad[0].pop();
    assert!(!mlsag.verify_full(&message, &bad, &key_images, out_pk, fee));
    assert!(!mlsag.verify_full(&message, &rings, &[key_images[0]; 2], out_pk, fee));
    assert!(!mlsag.verify_full(&message, &rings, &[rings[0][0].key], out_pk, fee));
    assert!(!mlsag.verify_full(&message, &rings, &[h32(TORSION)], out_pk, fee));
    assert!(!mlsag.verify_full(&message, &[], &[], out_pk, fee));
    let tamper = |edit: &dyn Fn(&mut Mlsag)| {
        let mut bad = mlsag.clone();
        edit(&mut bad);
        assert!(!bad.verify_full(&message, &rings, &key_images, out_pk, fee));
    };
    tamper(&|m| m.cc[0] ^= 1);
    tamper(&|m| m.cc = [0; 32]);
    tamper(&|m| m.cc = [0xff; 32]);
    tamper(&|m| m.ss[0][0][0] ^= 1);
    tamper(&|m| m.ss[2][1][0] ^= 1);
    tamper(&|m| m.ss[1][1] = [0xff; 32]);
    tamper(&|m| m.ss.swap(0, 1));
    tamper(&|m| {
        m.ss.pop();
    });
    tamper(&|m| {
        m.ss[0].pop();
    });

    // Through the transaction: the fee is part of the signed message and of
    // the balance.
    let mut changed = tx.clone();
    changed.rct.fee += 1;
    assert_eq!(changed.verify(&rings), Ok(false));
    let mut changed = tx.clone();
    changed.rct.mlsags.clear();
    assert_eq!(changed.verify(&rings), Err(Error::InvalidTransaction));
}

/// The Borromean range proofs of real outputs.
#[test]
fn borromean_range_proofs() {
    let (tx, _) = real("rct1");
    assert_eq!(tx.rct.range_sigs.len(), tx.prefix.outputs.len());
    let proof = &tx.rct.range_sigs[0];
    let commitment = &tx.rct.out_pk[0];
    assert_eq!(proof.0.len(), BORROMEAN_PROOF_LEN);
    assert!(proof.verify(commitment));
    assert!(borromean_verify(&proof.0, commitment));
    // Another commitment.
    assert!(!proof.verify(&tx.rct.out_pk[1]));
    assert!(!proof.verify(&[0xff; 32]));
    // Any part changed: s0, s1, ee, the bit commitments.
    for position in [
        0usize,
        31,
        63 * 32,
        64 * 32 + 5,
        127 * 32,
        128 * 32,
        129 * 32 + 1,
    ] {
        let mut bad = proof.clone();
        bad.0[position] ^= 1;
        assert!(!bad.verify(commitment), "{position}");
    }
    // Two bit commitments swapped: the sum is the same, the proof is not.
    let mut bad = proof.clone();
    let (a, b) = (129 * 32, 130 * 32);
    for i in 0..32 {
        bad.0.swap(a + i, b + i);
    }
    assert!(!bad.verify(commitment));
    // ee not reduced; a bit commitment that is not a point; a wrong length.
    let mut bad = proof.clone();
    bad.0[128 * 32..129 * 32].copy_from_slice(&[0xff; 32]);
    assert!(!bad.verify(commitment));
    let mut bad = proof.clone();
    bad.0[192 * 32..].copy_from_slice(&[0xff; 32]);
    assert!(!bad.verify(commitment));
    assert!(!borromean_verify(&proof.0[1..], commitment));
    assert!(!borromean_verify(&[], commitment));

    // Through the transaction.
    let mut changed = tx.clone();
    changed.rct.range_sigs.swap(0, 1);
    assert_eq!(changed.verify_range_proof(), Ok(false));
    let mut changed = tx.clone();
    changed.rct.range_sigs.pop();
    assert_eq!(changed.verify_range_proof(), Err(Error::InvalidTransaction));
}

/// RingCT type 2: an MLSAG per input over the keys and the commitments
/// less the pseudo-output.
#[test]
fn rct_simple() {
    let (tx, rings) = real("rct2");
    assert_eq!(tx.rct.rct_type, RCT_TYPE_SIMPLE);
    assert_eq!(tx.rct.mlsags.len(), tx.prefix.inputs.len());
    assert!(tx.prefix.inputs.len() >= 2);
    assert_eq!(tx.verify_balance(), Ok(true));
    assert_eq!(tx.verify_ring_signatures(&rings), Ok(true));
    assert_eq!(tx.verify_range_proof(), Ok(true));
    assert_eq!(tx.verify(&rings), Ok(true));

    let message = tx.signature_hash();
    for (i, mlsag) in tx.rct.mlsags.iter().enumerate() {
        let key_image = tx.prefix.inputs[i].key_image().unwrap();
        let pseudo_out = &tx.rct.pseudo_outs[i];
        let ring = &rings[i];
        assert!(mlsag.verify_simple(&message, ring, key_image, pseudo_out));
        let other = (i + 1) % rings.len();
        assert!(!mlsag.verify_simple(&[2u8; 32], ring, key_image, pseudo_out));
        assert!(!mlsag.verify_simple(&message, &rings[other], key_image, pseudo_out));
        assert!(!mlsag.verify_simple(&message, ring, &ring[0].key, pseudo_out));
        assert!(!mlsag.verify_simple(&message, ring, &h32(TORSION), pseudo_out));
        assert!(!mlsag.verify_simple(&message, ring, key_image, &tx.rct.pseudo_outs[other]));
        assert!(!mlsag.verify_simple(&message, ring, key_image, &[0xff; 32]));
        assert!(!mlsag.verify_simple(&message, &ring[1..], key_image, pseudo_out));
        assert!(!mlsag.verify_simple(&message, &[], key_image, pseudo_out));
        let mut bad = ring.clone();
        bad[1].commitment = bad[0].commitment;
        assert!(!mlsag.verify_simple(&message, &bad, key_image, pseudo_out));
        let mut bad = mlsag.clone();
        bad.ss[1][1][0] ^= 1;
        assert!(!bad.verify_simple(&message, ring, key_image, pseudo_out));
        let mut bad = mlsag.clone();
        bad.ss[0].push([0; 32]);
        assert!(!bad.verify_simple(&message, ring, key_image, pseudo_out));
    }

    // Through the transaction.
    let mut swapped = rings.clone();
    swapped.swap(0, 1);
    assert_eq!(tx.verify(&swapped), Ok(false));
    let mut changed = tx.clone();
    changed.rct.fee += 1;
    assert_eq!(changed.verify_balance(), Ok(false));
    assert_eq!(changed.verify(&rings), Ok(false));
    let mut changed = tx.clone();
    changed.rct.pseudo_outs.swap(0, 1);
    assert_eq!(changed.verify_balance(), Ok(true));
    assert_eq!(changed.verify(&rings), Ok(false));
    let mut changed = tx.clone();
    changed.rct.range_sigs[1].0[0] ^= 1;
    assert_eq!(changed.verify_range_proof(), Ok(false));
    assert_eq!(changed.verify(&rings), Ok(false));
}

/// The original Bulletproofs of real transactions, of each of the RingCT
/// types that carry them and of every size the fixtures have.
#[test]
fn bulletproofs_original() {
    let generators = BulletproofGenerators::new(4);
    assert_eq!(generators.max_outputs(), 4);
    let mut sizes = Vec::new();
    for name in BULLETPROOF_TXS {
        let (tx, rings) = real(name);
        assert_eq!(tx.rct.bulletproofs.len(), 1, "{name}");
        let proof = &tx.rct.bulletproofs[0];
        let commitments = &tx.rct.out_pk;
        sizes.push((tx.rct.rct_type, commitments.len()));
        assert!(proof.verify(commitments), "{name}");
        assert_eq!(tx.verify_range_proof(), Ok(true), "{name}");
        assert_eq!(tx.verify(&rings), Ok(true), "{name}");
        if commitments.len() > 4 {
            assert!(!proof.verify_with(&generators, commitments), "{name}");
            continue;
        }
        assert!(proof.verify_with(&generators, commitments), "{name}");

        if commitments.len() > 1 {
            let mut bad = commitments.clone();
            bad.swap(0, 1);
            assert!(!proof.verify_with(&generators, &bad), "{name}");
            assert!(!proof.verify_with(&generators, &commitments[1..]));
        }
        let mut bad = commitments.clone();
        bad[0] = [0xff; 32];
        assert!(!proof.verify_with(&generators, &bad), "{name}");
        let tamper = |edit: &dyn Fn(&mut Bulletproof)| {
            let mut bad = proof.clone();
            edit(&mut bad);
            assert!(!bad.verify_with(&generators, commitments), "{name}");
        };
        tamper(&|p| p.a = p.s);
        tamper(&|p| p.s = p.a);
        tamper(&|p| p.t1 = p.t2);
        tamper(&|p| p.t2 = p.t1);
        tamper(&|p| p.taux[0] ^= 1);
        tamper(&|p| p.mu[0] ^= 1);
        tamper(&|p| p.aa[0] ^= 1);
        tamper(&|p| p.b[0] ^= 1);
        tamper(&|p| p.t[0] ^= 1);
        tamper(&|p| p.l.swap(0, 1));
        tamper(&|p| p.r.swap(2, 3));
        tamper(&|p| core::mem::swap(&mut p.l, &mut p.r));
        tamper(&|p| {
            p.l.pop();
            p.r.pop();
        });
        tamper(&|p| {
            p.l.push(p.a);
            p.r.push(p.a);
        });
        // Not a point, not a reduced scalar.
        tamper(&|p| p.t1 = [0xff; 32]);
        tamper(&|p| p.l[0] = [0xff; 32]);
        for field in 0..5 {
            tamper(&|p| {
                *[&mut p.taux, &mut p.mu, &mut p.aa, &mut p.b, &mut p.t][field] = [0xff; 32]
            });
        }

        // Through the transaction: the proof is part of the signed message.
        let mut changed = tx.clone();
        changed.rct.bulletproofs[0].mu[0] ^= 1;
        assert_eq!(changed.verify_range_proof(), Ok(false));
        assert_eq!(changed.verify_ring_signatures(&rings), Ok(false));
        let mut changed = tx.clone();
        changed.rct.bulletproofs.clear();
        assert_eq!(changed.verify(&rings), Err(Error::InvalidTransaction));
    }
    sizes.sort();
    sizes.dedup();
    assert_eq!(sizes, BULLETPROOF_SIZES);

    let (tx, _) = real("rct4");
    let proof = &tx.rct.bulletproofs[0];
    assert!(!proof.verify(&[]));
    assert!(!proof.verify(&[H; 17]));
    let small = BulletproofGenerators::new(1);
    assert!(!proof.verify_with(&small, &tx.rct.out_pk));
}

/// The real transactions with an original Bulletproof.
const BULLETPROOF_TXS: [&str; 3] = ["rct3", "rct4", "rct5"];
/// Their RingCT types and numbers of outputs.
const BULLETPROOF_SIZES: [(u8, usize); 3] = [(3, 2), (4, 2), (5, 2)];

/// Batches: many proofs in one multi-scalar multiplication.
#[test]
fn range_proof_batches() {
    let mut rng = test_rng(21);
    let mut zeros = |_: &mut [u8]| {};

    // The original Bulletproofs.
    let txs: Vec<Transaction> = BULLETPROOF_TXS.iter().map(|name| real(name).0).collect();
    let generators = BulletproofGenerators::new(16);
    let mut batch: Vec<(&Bulletproof, &[[u8; 32]])> = txs
        .iter()
        .map(|tx| (&tx.rct.bulletproofs[0], &tx.rct.out_pk[..]))
        .collect();
    assert_eq!(
        Bulletproof::verify_batch(&generators, &batch, &mut rng),
        Ok(true)
    );
    assert_eq!(
        Bulletproof::verify_batch(&generators, &[], &mut rng),
        Ok(true)
    );
    assert_eq!(
        Bulletproof::verify_batch(&generators, &batch[..1], &mut rng),
        Ok(true)
    );
    assert_eq!(
        Bulletproof::verify_batch(&generators, &batch, &mut zeros),
        Err(Error::BadRandomness)
    );
    // One bad proof spoils the batch, wherever it is and whichever of its
    // two equations it breaks.
    for position in 0..batch.len() {
        for edit in 0..3 {
            let mut bad = batch[position].0.clone();
            match edit {
                0 => bad.taux[0] ^= 1,
                1 => bad.mu[0] ^= 1,
                _ => bad.l.swap(0, 1),
            }
            let mut spoiled = batch.clone();
            spoiled[position].0 = &bad;
            assert_eq!(
                Bulletproof::verify_batch(&generators, &spoiled, &mut rng),
                Ok(false),
                "{position} {edit}"
            );
        }
    }
    // Proofs with each other's commitments.
    let commitments = batch[0].1;
    batch[0].1 = batch[1].1;
    batch[1].1 = commitments;
    assert_eq!(
        Bulletproof::verify_batch(&generators, &batch, &mut rng),
        Ok(false)
    );
    // Generators too few.
    let small = BulletproofGenerators::new(1);
    batch.swap(0, 1);
    assert_eq!(
        Bulletproof::verify_batch(&small, &batch[..1], &mut rng),
        Ok(false)
    );

    // Bulletproofs+, of two to twelve outputs.
    let names = [
        "rct6_1in_2out",
        "rct6_2in_2out_additional_keys",
        "rct6_1in_3out",
        "rct6_1in_8out",
        "rct6_1in_12out_additional_keys",
    ];
    let all = mainnet_txs();
    let txs: Vec<Transaction> = names
        .iter()
        .map(|name| Transaction::parse(&all[*name].bytes).unwrap())
        .collect();
    let generators = BulletproofPlusGenerators::new(16);
    let batch: Vec<(&BulletproofPlus, &[[u8; 32]])> = txs
        .iter()
        .map(|tx| (&tx.rct.bulletproofs_plus[0], &tx.rct.out_pk[..]))
        .collect();
    assert_eq!(
        BulletproofPlus::verify_batch(&generators, &batch, &mut rng),
        Ok(true)
    );
    assert_eq!(
        BulletproofPlus::verify_batch(&generators, &[], &mut rng),
        Ok(true)
    );
    assert_eq!(
        BulletproofPlus::verify_batch(&generators, &batch, &mut zeros),
        Err(Error::BadRandomness)
    );
    for position in 0..batch.len() {
        let mut bad = batch[position].0.clone();
        bad.d1[0] ^= 1;
        let mut spoiled = batch.clone();
        spoiled[position].0 = &bad;
        assert_eq!(
            BulletproofPlus::verify_batch(&generators, &spoiled, &mut rng),
            Ok(false),
            "{position}"
        );
    }
    let mut mixed = batch.clone();
    mixed[0].1 = batch[1].1;
    mixed[1].1 = batch[0].1;
    assert_eq!(
        BulletproofPlus::verify_batch(&generators, &mixed, &mut rng),
        Ok(false)
    );
    let small = BulletproofPlusGenerators::new(4);
    assert_eq!(
        BulletproofPlus::verify_batch(&small, &batch, &mut rng),
        Ok(false)
    );
    assert_eq!(
        BulletproofPlus::verify_batch(&small, &batch[..3], &mut rng),
        Ok(true)
    );
}

/// `Transaction::verify` across the formats: what it refuses.
#[test]
fn transaction_verify() {
    let all = mainnet_txs();
    // A coinbase transaction is not for this.
    let coinbase = Transaction::parse(&all["coinbase"].bytes).unwrap();
    assert_eq!(coinbase.verify(&[]), Err(Error::Unsupported));
    assert_eq!(
        coinbase.verify_ring_signatures(&[]),
        Err(Error::Unsupported)
    );
    assert_eq!(coinbase.verify_range_proof(), Err(Error::Unsupported));
    assert_eq!(coinbase.verify_balance(), Err(Error::Unsupported));

    for name in ["rct3", "rct4", "rct5", "rct6_1in_2out"] {
        let (tx, rings) = real(name);
        assert_eq!(tx.verify(&rings), Ok(true), "{name}");
        assert_eq!(tx.verify(&[]), Err(Error::InvalidRing), "{name}");
        // The balance.
        let mut changed = tx.clone();
        changed.rct.fee += 1;
        assert_eq!(changed.verify(&rings), Ok(false), "{name}");
        let mut changed = tx.clone();
        changed.rct.out_pk.swap(0, 1);
        assert_eq!(changed.verify_balance(), Ok(true));
        assert_eq!(changed.verify(&rings), Ok(false), "{name}");
        // The ring.
        let mut bad = rings.clone();
        bad[0][2].key = bad[0][3].key;
        assert_eq!(tx.verify(&bad), Ok(false), "{name}");
        // The key image.
        let mut changed = tx.clone();
        if let Input::ToKey { key_image, .. } = &mut changed.prefix.inputs[0] {
            *key_image = h32(TORSION);
        }
        assert_eq!(changed.verify(&rings), Ok(false), "{name}");
        // The shape.
        let mut changed = tx.clone();
        changed.rct.pseudo_outs.pop();
        assert_eq!(changed.verify(&rings), Err(Error::InvalidTransaction));
        let mut changed = tx.clone();
        changed.rct.out_pk[0] = [0xff; 32];
        assert!(matches!(changed.verify(&rings), Err(Error::CryptoNote(_))));
        let mut changed = tx.clone();
        changed.rct.rct_type = 9;
        assert_eq!(changed.verify(&rings), Err(Error::Unsupported));
        let mut changed = tx.clone();
        changed.prefix.inputs.clear();
        assert_eq!(changed.verify(&[]), Err(Error::InvalidTransaction));
    }
}
