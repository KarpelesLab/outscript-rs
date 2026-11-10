//! Tests of what needs a heap: transactions, range proofs, construction.

use std::collections::BTreeMap;
use std::string::String;
use std::vec::Vec;

use super::*;

const MAINNET: &str = include_str!("../testdata/mainnet_txs.txt");

pub(super) struct RealTx {
    pub(super) txid: [u8; 32],
    pub(super) bytes: Vec<u8>,
    pub(super) rings: Vec<Vec<RingMember>>,
}

pub(super) fn mainnet_txs() -> BTreeMap<String, RealTx> {
    let mut txs = BTreeMap::new();
    for line in MAINNET.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f.first().copied() {
            Some("tx") => {
                txs.insert(
                    String::from(f[1]),
                    RealTx {
                        txid: h32(f[3]),
                        bytes: hex::decode(f[4]).unwrap(),
                        rings: Vec::new(),
                    },
                );
            }
            Some("ring") => {
                let ring = f[3..]
                    .iter()
                    .map(|member| {
                        let (key, commitment) = member.split_once(':').unwrap();
                        RingMember {
                            key: h32(key),
                            commitment: h32(commitment),
                        }
                    })
                    .collect();
                let tx = txs.get_mut(f[1]).unwrap();
                assert_eq!(tx.rings.len(), f[2].parse::<usize>().unwrap());
                tx.rings.push(ring);
            }
            _ => assert!(line.starts_with('#'), "{line}"),
        }
    }
    txs
}

/// Every real transaction parses, serializes back to the same bytes and
/// hashes to its id.
#[test]
fn mainnet_round_trip_and_txid() {
    let txs = mainnet_txs();
    assert_eq!(txs.len(), 12);
    let mut types = Vec::new();
    for (name, real) in &txs {
        let tx = Transaction::parse(&real.bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(tx.serialize(), real.bytes, "{name}");
        assert_eq!(tx.hash(), real.txid, "{name}");
        types.push((tx.prefix.version, tx.rct.rct_type));

        let prefix_bytes = tx.prefix.serialize();
        assert_eq!(prefix_bytes, real.bytes[..prefix_bytes.len()]);
        assert_eq!(TransactionPrefix::parse(&prefix_bytes).unwrap(), tx.prefix);
        assert_eq!(tx.prefix.hash(), cn_fast_hash(&prefix_bytes));

        // The pruned form, as a daemon serves it for scanning.
        let pruned_bytes = tx.serialize_pruned();
        assert_eq!(pruned_bytes, real.bytes[..pruned_bytes.len()]);
        let pruned = Transaction::parse_pruned(&pruned_bytes).unwrap();
        assert_eq!(pruned.prefix, tx.prefix);
        assert_eq!(pruned.rct.out_pk, tx.rct.out_pk);
        assert_eq!(pruned.rct.ecdh_info, tx.rct.ecdh_info);
        assert_eq!(pruned.serialize_pruned(), pruned_bytes);
        match tx.prunable_hash() {
            Some(prunable_hash) => {
                assert_eq!(
                    pruned.hash_with_prunable_hash(&prunable_hash),
                    Some(real.txid)
                );
                let prunable = &real.bytes[pruned_bytes.len()..];
                if tx.rct.rct_type != RCT_TYPE_NULL {
                    assert_eq!(prunable_hash, cn_fast_hash(prunable));
                    assert!(Transaction::parse_pruned(&real.bytes).is_err());
                } else {
                    assert!(prunable.is_empty());
                    assert_eq!(prunable_hash, [0u8; 32]);
                }
            }
            None => {
                assert_eq!(tx.prefix.version, 1);
                assert_eq!(pruned.hash_with_prunable_hash(&[0u8; 32]), None);
            }
        }

        // Shape.
        let inputs = tx.prefix.inputs.len();
        let outputs = tx.prefix.outputs.len();
        if tx.prefix.version == 1 {
            assert_eq!(tx.signatures.len(), inputs);
            assert!(tx.fee().unwrap() > 0);
        } else if tx.rct.rct_type == RCT_TYPE_NULL {
            assert!(matches!(tx.prefix.inputs[0], Input::Gen { .. }));
            assert_eq!(tx.prefix.inputs[0].ring_size(), 0);
            assert_eq!(tx.prefix.inputs[0].key_image(), None);
            assert_eq!(tx.prefix.inputs[0].absolute_offsets(), None);
            assert_eq!(
                output_commitment(&tx, 0),
                Some(zero_commit(tx.prefix.outputs[0].amount))
            );
            assert_eq!(tx.verify_balance(), Err(Error::Unsupported));
        } else {
            assert_eq!(tx.rct.out_pk.len(), outputs);
            assert_eq!(tx.rct.ecdh_info.len(), outputs);
            assert_eq!(output_commitment(&tx, 0), Some(tx.rct.out_pk[0]));
            assert_eq!(output_commitment(&tx, outputs), None);
            assert_eq!(tx.fee(), Some(tx.rct.fee));
            if tx.rct.rct_type != RCT_TYPE_FULL {
                assert_eq!(tx.rct.pseudo_outs.len(), inputs);
                // The amounts balance.
                assert_eq!(tx.verify_balance(), Ok(true), "{name}");
            }
            for input in &tx.prefix.inputs {
                let absolute = input.absolute_offsets().unwrap();
                let Input::ToKey { key_offsets, .. } = input else {
                    panic!()
                };
                assert_eq!(relative_offsets(&absolute).unwrap(), *key_offsets);
            }
        }
        // The transaction public key is there.
        assert!(tx_public_key(&tx.prefix.extra).is_some(), "{name}");
        if name.contains("additional_keys") {
            assert_eq!(additional_public_keys(&tx.prefix.extra).len(), outputs * 32);
            assert!(additional_public_key(&tx.prefix.extra, outputs, outputs - 1).is_some());
        }
        if tx.rct.rct_type == RCT_TYPE_BULLETPROOF_PLUS {
            assert!(tx.prefix.outputs.iter().all(|o| o.view_tag.is_some()));
            assert_eq!(tx.rct.clsags.len(), inputs);
            assert_eq!(tx.rct.bulletproofs_plus.len(), 1);
        }
    }
    types.sort();
    types.dedup();
    assert_eq!(
        types,
        [
            (1, 0),
            (2, 0),
            (2, 1),
            (2, 2),
            (2, 3),
            (2, 4),
            (2, 5),
            (2, 6)
        ]
    );
}

/// The Bulletproofs+ of real transactions verify against their output
/// commitments, and stop verifying when anything changes.
#[test]
fn mainnet_bulletproofs_plus() {
    let txs = mainnet_txs();
    let generators = BulletproofPlusGenerators::new(4);
    for name in ["rct6_1in_2out", "rct6_1in_3out"] {
        let tx = Transaction::parse(&txs[name].bytes).unwrap();
        assert_eq!(tx.verify_range_proof(), Ok(true), "{name}");
        let proof = &tx.rct.bulletproofs_plus[0];
        let commitments = &tx.rct.out_pk;
        assert!(proof.verify_with(&generators, commitments));

        let mut bad = commitments.clone();
        bad.swap(0, 1);
        assert!(!proof.verify_with(&generators, &bad), "{name}");
        assert!(!proof.verify_with(&generators, &commitments[1..]));
        let tamper = |edit: &dyn Fn(&mut BulletproofPlus)| {
            let mut bad = proof.clone();
            edit(&mut bad);
            assert!(!bad.verify_with(&generators, commitments), "{name}");
        };
        tamper(&|p| p.a = p.b);
        tamper(&|p| p.a1 = p.b);
        tamper(&|p| p.b = p.a);
        tamper(&|p| p.r1[0] ^= 1);
        tamper(&|p| p.s1[0] ^= 1);
        tamper(&|p| p.d1[0] ^= 1);
        tamper(&|p| p.l.swap(0, 1));
        tamper(&|p| p.r.swap(2, 3));
        tamper(&|p| {
            p.l.pop();
            p.r.pop();
        });
        // Not a point, not a reduced scalar.
        tamper(&|p| p.a = [0xff; 32]);
        tamper(&|p| p.d1 = [0xff; 32]);
    }
    // Generators too few for the proof.
    let tx = Transaction::parse(&txs["rct6_1in_3out"].bytes).unwrap();
    let small = BulletproofPlusGenerators::new(2);
    assert_eq!(small.max_outputs(), 2);
    assert!(!tx.rct.bulletproofs_plus[0].verify_with(&small, &tx.rct.out_pk));
    // No commitments, or too many.
    assert!(!tx.rct.bulletproofs_plus[0].verify(&[]));
    assert!(!tx.rct.bulletproofs_plus[0].verify(&[H; 17]));
}

/// The larger aggregations (8 and 16 commitments).
#[test]
fn mainnet_bulletproofs_plus_large() {
    let txs = mainnet_txs();
    for name in ["rct6_1in_8out", "rct6_1in_12out_additional_keys"] {
        let tx = Transaction::parse(&txs[name].bytes).unwrap();
        assert_eq!(tx.verify_range_proof(), Ok(true), "{name}");
    }
}

/// The CLSAG signatures of real transactions verify against their rings.
#[test]
fn mainnet_clsag() {
    let txs = mainnet_txs();
    for name in ["rct6_1in_2out", "rct6_2in_2out_additional_keys"] {
        let real = &txs[name];
        let tx = Transaction::parse(&real.bytes).unwrap();
        assert_eq!(real.rings.len(), tx.prefix.inputs.len());
        assert_eq!(tx.verify_ring_signatures(&real.rings), Ok(true), "{name}");

        // A ring member changed, or the rings swapped or cut.
        let mut bad = real.rings.clone();
        bad[0][3].commitment = bad[0][4].commitment;
        assert_eq!(tx.verify_ring_signatures(&bad), Ok(false), "{name}");
        let mut bad = real.rings.clone();
        bad[0].pop();
        assert_eq!(tx.verify_ring_signatures(&bad), Err(Error::InvalidRing));
        assert_eq!(tx.verify_ring_signatures(&[]), Err(Error::InvalidRing));
        // Another message: a changed transaction.
        let mut changed = tx.clone();
        changed.prefix.unlock_time += 1;
        assert_eq!(changed.verify_ring_signatures(&real.rings), Ok(false));
        let mut changed = tx.clone();
        changed.rct.bulletproofs_plus[0].r1[0] ^= 1;
        assert_eq!(changed.verify_ring_signatures(&real.rings), Ok(false));
    }
    // The CLSAG of the previous RingCT type is the same signature; only the
    // range proof differs, and the message covers it.
    let real = &txs["rct5"];
    let tx = Transaction::parse(&real.bytes).unwrap();
    assert_eq!(tx.verify_ring_signatures(&real.rings), Ok(true));
    let message = tx.signature_hash();
    for (i, clsag) in tx.rct.clsags.iter().enumerate() {
        let key_image = tx.prefix.inputs[i].key_image().unwrap();
        assert!(clsag.verify(&message, &real.rings[i], key_image, &tx.rct.pseudo_outs[i]));
    }
}

/// Every real transaction with its rings verifies in full, whatever its
/// format.
#[test]
fn mainnet_verify_all_formats() {
    let txs = mainnet_txs();
    let mut seen = Vec::new();
    for (name, real) in &txs {
        if real.rings.is_empty() {
            continue;
        }
        let tx = Transaction::parse(&real.bytes).unwrap();
        assert_eq!(tx.verify(&real.rings), Ok(true), "{name}");
        seen.push((tx.prefix.version, tx.rct.rct_type));
    }
    seen.sort();
    seen.dedup();
    assert_eq!(
        seen,
        [(1, 0), (2, 1), (2, 2), (2, 3), (2, 4), (2, 5), (2, 6)]
    );
}

/// Parsing never panics on, and rejects, truncated and corrupted
/// transactions.
#[test]
fn parse_rejections() {
    let txs = mainnet_txs();
    for (name, real) in &txs {
        let bytes = &real.bytes;
        // Every truncation fails; so does trailing data.
        let step = (bytes.len() / 200).max(1);
        for cut in (0..bytes.len()).step_by(step) {
            assert!(Transaction::parse(&bytes[..cut]).is_err(), "{name} {cut}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(Transaction::parse(&longer), Err(Error::TrailingData));
        // Flipping any of the first bytes must not panic.
        for i in 0..bytes.len().min(300) {
            for bit in [0x01u8, 0x80, 0xff] {
                let mut bad = bytes.clone();
                bad[i] ^= bit;
                if let Ok(tx) = Transaction::parse(&bad) {
                    let _ = tx.hash();
                    let _ = tx.signature_hash();
                    let _ = tx.fee();
                    let _ = tx.verify_balance();
                }
            }
        }
    }
    // Versions, and counts larger than the data.
    assert_eq!(
        Transaction::parse(&[0, 0, 0, 0, 0]),
        Err(Error::Unsupported)
    );
    assert_eq!(
        Transaction::parse(&[3, 0, 0, 0, 0]),
        Err(Error::Unsupported)
    );
    assert_eq!(
        Transaction::parse(&[2, 0, 0xff, 0xff, 0xff, 0xff, 0x0f]),
        Err(Error::UnexpectedEof)
    );
    // An unknown input type, output type and RingCT type.
    assert_eq!(
        Transaction::parse(&[2, 0, 1, 0x00, 0]),
        Err(Error::Unsupported)
    );
    let mut tx = Transaction::parse(&txs["coinbase"].bytes).unwrap();
    tx.rct.rct_type = 7;
    assert_eq!(Transaction::parse(&tx.serialize()), Err(Error::Unsupported));
    let coinbase = &txs["coinbase"].bytes;
    let output_tag = coinbase.iter().position(|b| *b == 0x03).unwrap();
    let mut bad = coinbase.clone();
    bad[output_tag] = 0x01;
    assert!(Transaction::parse(&bad).is_err());

    assert_eq!(relative_offsets(&[5, 5]), Err(Error::InvalidRing));
    assert_eq!(relative_offsets(&[5, 4]), Err(Error::InvalidRing));
    assert_eq!(relative_offsets(&[0, 4, 9]).unwrap(), [0, 4, 5]);
    assert_eq!(relative_offsets(&[]).unwrap(), [0u64; 0]);
    let overflow = Input::ToKey {
        amount: 0,
        key_offsets: std::vec![u64::MAX, 1],
        key_image: [0; 32],
    };
    assert_eq!(overflow.absolute_offsets(), None);
}

/// Our proofs verify, for every number of commitments up to four (more in
/// the release-only test), and are bound to their commitments.
#[test]
fn bulletproofs_plus_prove() {
    let mut rng = test_rng(11);
    let generators = BulletproofPlusGenerators::new(4);
    let amounts = [0u64, u64::MAX, 1_000_000_000_000, 42];
    let all_masks: Vec<[u8; 32]> = (0..4)
        .map(|_| random_scalar(&mut rng).unwrap().to_bytes())
        .collect();
    let masks = &all_masks;
    for count in 1..=4usize {
        let (amounts, masks) = (&amounts[..count], &all_masks[..count]);
        let proof = BulletproofPlus::prove_with(&generators, amounts, masks, &mut rng).unwrap();
        let commitments: Vec<[u8; 32]> = amounts
            .iter()
            .zip(masks)
            .map(|(amount, mask)| commit(*amount, mask).unwrap())
            .collect();
        assert_eq!(
            proof.l.len(),
            6 + count.next_power_of_two().trailing_zeros() as usize
        );
        assert!(proof.verify_with(&generators, &commitments), "{count}");
        if count <= 2 {
            assert!(proof.verify(&commitments));
        }

        // A commitment to another amount or with another mask.
        let mut bad = commitments.clone();
        bad[count - 1] = commit(amounts[count - 1] ^ 1, &masks[count - 1]).unwrap();
        assert!(!proof.verify_with(&generators, &bad), "{count}");
        let mut bad = commitments.clone();
        bad[0] = commit(amounts[0], &all_masks[count % 3 + 1]).unwrap();
        assert!(!proof.verify_with(&generators, &bad), "{count}");
    }

    // Bad input.
    let prove = |amounts: &[u64], masks: &[[u8; 32]]| {
        BulletproofPlus::prove_with(&generators, amounts, masks, &mut test_rng(1)).map(|_| ())
    };
    assert_eq!(prove(&[], &[]), Err(Error::InvalidProof));
    assert_eq!(prove(&[1, 2], &masks[..1]), Err(Error::InvalidProof));
    assert_eq!(prove(&[1; 5], &[masks[0]; 5]), Err(Error::InvalidProof));
    assert_eq!(prove(&[1; 17], &[masks[0]; 17]), Err(Error::InvalidProof));
    assert!(matches!(
        prove(&[1], &[[0xff; 32]]),
        Err(Error::CryptoNote(_))
    ));
    assert_eq!(
        BulletproofPlus::prove_with(&generators, &[1], &masks[..1], &mut |_: &mut [u8]| {})
            .unwrap_err(),
        Error::BadRandomness
    );
}

/// Proofs over eight and sixteen commitments. Proving these takes a few
/// seconds without optimisation: run with `--release`, or `--ignored`.
#[test]
#[cfg_attr(debug_assertions, ignore)]
fn bulletproofs_plus_prove_large() {
    let mut rng = test_rng(12);
    let generators = BulletproofPlusGenerators::new(16);
    for count in [5usize, 16] {
        let amounts: Vec<u64> = (0..count as u64).map(|i| i * 1_000_003).collect();
        let masks: Vec<[u8; 32]> = (0..count)
            .map(|_| random_scalar(&mut rng).unwrap().to_bytes())
            .collect();
        let proof = BulletproofPlus::prove_with(&generators, &amounts, &masks, &mut rng).unwrap();
        let commitments: Vec<[u8; 32]> = amounts
            .iter()
            .zip(&masks)
            .map(|(amount, mask)| commit(*amount, mask).unwrap())
            .collect();
        assert!(proof.verify_with(&generators, &commitments), "{count}");
    }
}

/// The scanning vectors of `monero-rs`: transactions with the keys of their
/// recipient, and the amounts and one-time keys the recipient's wallet finds
/// in them — RingCT outputs, a coinbase output, view tags (one of them a
/// false positive on an output that is not the wallet's), and outputs to
/// subaddresses through additional transaction keys.
#[test]
fn scan_vectors() {
    let mut count = 0;
    for line in include_str!("../testdata/monero_rs_scan.txt").lines() {
        if line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let name = f[0];
        let account = AccountKeys::from_secret_keys(&h32(f[2]), &h32(f[1])).unwrap();
        let tx = Transaction::parse(&hex::decode(f[3]).unwrap()).unwrap();
        // The ids under which public daemons know these transactions (the
        // coinbase one is the id the vectors' wallet printed).
        let txid = match name {
            "ringct" => "4c9c4f6b3d298c5ffa31139929b34ae53d727adf3de70ed2b8c32835d4513e25",
            "coinbase" => "50ad877c2f126c9278dc4b043774bceb995c80bc2fa11de10a0f8379a856422e",
            "view_tag_false_positive" => {
                "a76998eed792c703da7287b9286541a9f281cd634b814c9b8588fbcc0a0f760d"
            }
            "view_tag" => "99eed466ab48df521c658669f517b4408564a0902c67b9f533f53e558a2d416d",
            "additional_keys" => "b9cc1b04d38f15d5c2c807b5ca143be731461db1a77386b49052869f6118e0d0",
            _ => panic!("{name}"),
        };
        assert_eq!(tx.hash(), h32(txid), "{name}");

        // The subaddresses the vectors' wallet looked for.
        let mut table = Vec::new();
        for major in 0..2 {
            for minor in 0..3 {
                let index = SubaddressIndex::new(major, minor);
                table.push((account.view_keys().subaddress_spend_public(index), index));
            }
        }
        let mut lookup = |key: &[u8; 32]| {
            table
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, index)| *index)
        };

        let owned = account
            .view_keys()
            .scan_transaction(&tx, &mut lookup)
            .unwrap();
        let expected = &f[4..];
        assert_eq!(owned.len(), expected.len(), "{name}");
        for (output, expected) in owned.iter().zip(expected) {
            let e: Vec<&str> = expected.split(':').collect();
            assert_eq!(output.amount, e[0].parse::<u64>().unwrap(), "{name}");
            assert_eq!(output.key, h32(e[2]), "{name}");
            let (secret, image) = account
                .output_key_image(
                    &output.derivation,
                    output.index as u64,
                    output.subaddress,
                    &output.key,
                )
                .unwrap();
            assert_eq!(*secret, h32(e[1]), "{name}");
            assert_eq!(
                image,
                crate::cryptonote::generate_key_image(&output.key, &secret).unwrap()
            );
            // The amount and the mask open the output's commitment.
            assert_eq!(
                commit(output.amount, &output.mask).unwrap(),
                output_commitment(&tx, output.index).unwrap(),
                "{name}"
            );
        }

        match name {
            "coinbase" => assert_eq!(tx.rct.rct_type, RCT_TYPE_NULL),
            "view_tag_false_positive" => {
                // The other output's view tag matches too, by chance.
                let other = 1 - owned[0].index;
                let derivation = account
                    .view_keys()
                    .key_derivation(&tx_public_key(&tx.prefix.extra).unwrap())
                    .unwrap();
                assert_eq!(
                    Some(derive_view_tag(&derivation, other as u64)),
                    tx.prefix.outputs[other].view_tag
                );
            }
            "additional_keys" => {
                assert_eq!(
                    additional_public_keys(&tx.prefix.extra).len(),
                    tx.prefix.outputs.len() * 32
                );
                assert!(owned.iter().all(|output| !output.subaddress.is_main()));
            }
            _ => {}
        }
        count += 1;
    }
    assert_eq!(count, 5);
}
