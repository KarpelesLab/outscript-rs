//! Tests of transaction construction: what is built verifies as a node
//! would check it, and the recipients find and can spend their outputs.

use std::vec::Vec;

use super::*;
use crate::crypto::Zeroizing;

/// A spendable output of `amount` in a ring of `ring_size`, at `real_index`.
fn fake_input(
    rng: &mut dyn FnMut(&mut [u8]),
    amount: u64,
    ring_size: usize,
    real_index: usize,
) -> TransactionInput {
    let secret = random_scalar(rng).unwrap();
    let mask = random_scalar(rng).unwrap();
    let mut ring = Vec::new();
    for i in 0..ring_size {
        ring.push(if i == real_index {
            RingMember {
                key: EdwardsPoint::mul_base(&secret).compress(),
                commitment: commit(amount, &mask.to_bytes()).unwrap(),
            }
        } else {
            RingMember {
                key: EdwardsPoint::mul_base(&random_scalar(rng).unwrap()).compress(),
                commitment: EdwardsPoint::mul_base(&random_scalar(rng).unwrap()).compress(),
            }
        });
    }
    TransactionInput {
        ring,
        global_indices: (0..ring_size as u64).map(|i| 1000 + i * 37).collect(),
        real_index,
        secret_key: Zeroizing::new(secret.to_bytes()),
        amount,
        mask: Zeroizing::new(mask.to_bytes()),
    }
}

/// Checks everything a node would about a built transaction's proofs, and
/// that it survives serialization.
fn check_built(built: &BuiltTransaction, inputs: &[TransactionInput]) -> Transaction {
    let tx = &built.transaction;
    let bytes = tx.serialize();
    let parsed = Transaction::parse(&bytes).unwrap();
    assert_eq!(parsed, *tx);
    assert_eq!(parsed.hash(), tx.hash());
    assert_eq!(tx.prefix.version, 2);
    assert_eq!(tx.rct.rct_type, RCT_TYPE_BULLETPROOF_PLUS);
    assert_eq!(tx.verify_balance(), Ok(true));
    assert_eq!(tx.verify_range_proof(), Ok(true));

    // The inputs are sorted by key image, decreasing; find each one's ring.
    let images: Vec<[u8; 32]> = tx
        .prefix
        .inputs
        .iter()
        .map(|input| *input.key_image().unwrap())
        .collect();
    assert!(images.windows(2).all(|pair| pair[0] > pair[1]));
    let rings: Vec<Vec<RingMember>> = images
        .iter()
        .map(|image| {
            let input = inputs
                .iter()
                .find(|input| {
                    let key = &input.ring[input.real_index].key;
                    crate::cryptonote::generate_key_image(key, &input.secret_key).unwrap() == *image
                })
                .unwrap();
            input.ring.clone()
        })
        .collect();
    assert_eq!(tx.verify_ring_signatures(&rings), Ok(true));
    for (ring, tx_input) in rings.iter().zip(&tx.prefix.inputs) {
        assert_eq!(tx_input.ring_size(), ring.len());
        assert_eq!(tx_input.absolute_offsets().unwrap()[1], 1037);
    }
    // The transaction public key is the first entry of the extra field.
    assert!(matches!(
        parse_extra(&tx.prefix.extra).next(),
        Some(Ok(ExtraField::PublicKey(_)))
    ));
    assert!(parse_extra(&tx.prefix.extra).all(|field| field.is_ok()));
    assert!(
        tx.prefix
            .outputs
            .iter()
            .all(|o| o.view_tag.is_some() && o.amount == 0)
    );
    parsed
}

/// A standard payment with change: two outputs, a dummy payment id, and
/// both sides find their output.
#[test]
fn standard_payment() {
    let mut rng = test_rng(21);
    let sender = AccountKeys::from_seed(&[1; 32]).unwrap();
    let recipient = AccountKeys::from_seed(&[2; 32]).unwrap();
    let inputs = [
        fake_input(&mut rng, 3_000_000_000, 4, 2),
        fake_input(&mut rng, 2_000_000_000, 4, 0),
    ];
    let mut builder = TransactionBuilder::new();
    for input in &inputs {
        builder.input(input.clone());
    }
    builder
        .destination(recipient.address(Network::Mainnet), 4_200_000_000)
        .change(sender.address(Network::Mainnet), sender.view_secret())
        .fee(100_000_000)
        .unlock_time(0);
    let built = builder.build(&mut rng).unwrap();
    let tx = check_built(&built, &inputs);
    assert_eq!(tx.prefix.inputs.len(), 2);
    assert_eq!(tx.prefix.outputs.len(), 2);
    assert_eq!(tx.rct.fee, 100_000_000);
    assert!(built.additional_secret_keys.is_empty());
    assert_eq!(additional_public_keys(&tx.prefix.extra).len(), 0);

    // R = r * G.
    assert_eq!(
        tx_public_key(&tx.prefix.extra).unwrap(),
        secret_key_to_public_key(&built.tx_secret_key).unwrap()
    );
    // 01 || R || 02 09 01 || id
    assert_eq!(tx.prefix.extra.len(), 33 + 11);
    assert!(matches!(
        payment_id(&tx.prefix.extra),
        Some(PaymentId::Encrypted(_))
    ));

    let got = recipient
        .view_keys()
        .scan_transaction(&tx, &mut |_| None)
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].amount, 4_200_000_000);
    assert_eq!(got[0].subaddress, SubaddressIndex::MAIN);
    // The dummy payment id decrypts to zero.
    assert_eq!(got[0].payment_id, Some([0u8; 8]));
    assert_eq!(got[0].commitment, tx.rct.out_pk[got[0].index]);
    assert_eq!(
        commit(got[0].amount, &got[0].mask).unwrap(),
        got[0].commitment
    );
    assert_eq!(built.output_order[got[0].index], 0);

    let change = sender
        .view_keys()
        .scan_transaction(&tx, &mut |_| None)
        .unwrap();
    assert_eq!(change.len(), 1);
    assert_eq!(change[0].amount, 700_000_000);
    assert_eq!(built.output_order[change[0].index], 1);
    assert_ne!(change[0].index, got[0].index);

    // A stranger finds nothing.
    let stranger = AccountKeys::from_seed(&[3; 32]).unwrap();
    assert!(
        stranger
            .view_keys()
            .scan_transaction(&tx, &mut |_| None)
            .unwrap()
            .is_empty()
    );

    // The recipient can spend what it received.
    let (secret, _image) = recipient
        .output_key_image(
            &got[0].derivation,
            got[0].index as u64,
            got[0].subaddress,
            &got[0].key,
        )
        .unwrap();
    let respend = TransactionInput {
        ring: std::vec![
            RingMember {
                key: got[0].key,
                commitment: got[0].commitment
            },
            inputs[0].ring[0],
        ],
        global_indices: std::vec![7, 9],
        real_index: 0,
        secret_key: secret,
        amount: got[0].amount,
        mask: got[0].mask.clone(),
    };
    let mut builder = TransactionBuilder::new();
    builder
        .input(respend.clone())
        .destination(sender.address(Network::Mainnet), 4_000_000_000)
        .destination(stranger.address(Network::Mainnet), 150_000_000)
        .fee(50_000_000)
        .shuffle_outputs(false);
    let built = builder.build(&mut rng).unwrap();
    let tx = &built.transaction;
    assert_eq!(tx.verify_balance(), Ok(true));
    assert_eq!(tx.verify_range_proof(), Ok(true));
    assert_eq!(
        tx.verify_ring_signatures(core::slice::from_ref(&respend.ring)),
        Ok(true)
    );
    assert_eq!(built.output_order, [0, 1]);
    // Two recipients and no change: no single view key to encrypt a dummy
    // payment id for, as in the reference.
    assert_eq!(payment_id(&tx.prefix.extra), None);
    let got = stranger
        .view_keys()
        .scan_transaction(tx, &mut |_| None)
        .unwrap();
    assert_eq!(
        (got.len(), got[0].index, got[0].amount),
        (1, 1, 150_000_000)
    );
}

/// A payment to a single subaddress: the transaction key is `r * D`.
#[test]
fn subaddress_payment() {
    let mut rng = test_rng(22);
    let sender = AccountKeys::from_seed(&[1; 32]).unwrap();
    let recipient = AccountKeys::from_seed(&[2; 32]).unwrap();
    let index = SubaddressIndex::new(0, 5);
    let sub = recipient.subaddress(Network::Mainnet, index);
    assert!(sub.is_subaddress());
    let inputs = [fake_input(&mut rng, 1_000_000_000, 3, 1)];
    let mut builder = TransactionBuilder::new();
    builder
        .input(inputs[0].clone())
        .destination(sub, 900_000_000)
        .change(sender.address(Network::Mainnet), sender.view_secret())
        .fee(20_000_000);
    let built = builder.build(&mut rng).unwrap();
    let tx = check_built(&built, &inputs);

    let r = crate::cryptonote::scalar_from_bytes(&built.tx_secret_key).unwrap();
    let d = EdwardsPoint::decompress(&sub.spend_public).unwrap();
    assert_eq!(
        tx_public_key(&tx.prefix.extra).unwrap(),
        d.mul(&r).compress()
    );
    assert!(built.additional_secret_keys.is_empty());

    let mut lookup = |key: &[u8; 32]| (*key == sub.spend_public).then_some(index);
    let got = recipient
        .view_keys()
        .scan_transaction(&tx, &mut lookup)
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].amount, got[0].subaddress), (900_000_000, index));
    assert_eq!(got[0].payment_id, Some([0u8; 8]));
    // Without the table the output is not recognised.
    assert!(
        recipient
            .view_keys()
            .scan_transaction(&tx, &mut |_| None)
            .unwrap()
            .is_empty()
    );
    // The one-time secret key includes the subaddress offset.
    let (secret, _) = recipient
        .output_key_image(&got[0].derivation, got[0].index as u64, index, &got[0].key)
        .unwrap();
    assert_eq!(secret_key_to_public_key(&secret).unwrap(), got[0].key);

    // The change comes back although R is not r * G.
    let change = sender
        .view_keys()
        .scan_transaction(&tx, &mut |_| None)
        .unwrap();
    assert_eq!(change.len(), 1);
    assert_eq!(change[0].amount, 80_000_000);
}

/// Several recipients, subaddresses among them: every output has its own
/// public key.
#[test]
fn additional_keys() {
    let mut rng = test_rng(23);
    let sender = AccountKeys::from_seed(&[1; 32]).unwrap();
    let alice = AccountKeys::from_seed(&[2; 32]).unwrap();
    let bob = AccountKeys::from_seed(&[3; 32]).unwrap();
    let alice_index = SubaddressIndex::new(3, 1);
    let alice_sub = alice.subaddress(Network::Mainnet, alice_index);
    let sender_index = SubaddressIndex::new(1, 0);
    let sender_sub = sender.subaddress(Network::Mainnet, sender_index);
    let inputs = [fake_input(&mut rng, 10_000_000_000, 2, 0)];
    let mut builder = TransactionBuilder::new();
    builder
        .input(inputs[0].clone())
        .destination(alice_sub, 1_000_000_000)
        .destination(bob.address(Network::Mainnet), 2_000_000_000)
        .destination(alice.address(Network::Mainnet), 3_000_000_000)
        // The change goes to a subaddress of the sender.
        .change(sender_sub, sender.view_secret())
        .fee(1_000_000);
    let built = builder.build(&mut rng).unwrap();
    let tx = check_built(&built, &inputs);
    assert_eq!(tx.prefix.outputs.len(), 4);
    assert_eq!(built.additional_secret_keys.len(), 4);
    assert_eq!(additional_public_keys(&tx.prefix.extra).len(), 4 * 32);
    // R = r * G, then the additional keys; no payment id with four outputs.
    assert_eq!(
        tx_public_key(&tx.prefix.extra).unwrap(),
        secret_key_to_public_key(&built.tx_secret_key).unwrap()
    );
    assert_eq!(tx.prefix.extra[33], TX_EXTRA_TAG_ADDITIONAL_PUBKEYS);
    assert_eq!(tx.prefix.extra.len(), 33 + 2 + 4 * 32);
    assert_eq!(payment_id(&tx.prefix.extra), None);

    let mut alice_lookup = |key: &[u8; 32]| (*key == alice_sub.spend_public).then_some(alice_index);
    let mut got = alice
        .view_keys()
        .scan_transaction(&tx, &mut alice_lookup)
        .unwrap();
    got.sort_by_key(|o| o.amount);
    assert_eq!(got.len(), 2);
    assert_eq!(
        (got[0].amount, got[0].subaddress),
        (1_000_000_000, alice_index)
    );
    assert_eq!(
        (got[1].amount, got[1].subaddress),
        (3_000_000_000, SubaddressIndex::MAIN)
    );
    assert_eq!(got[0].payment_id, None);

    let got = bob
        .view_keys()
        .scan_transaction(&tx, &mut |_| None)
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].amount, 2_000_000_000);

    let mut sender_lookup =
        |key: &[u8; 32]| (*key == sender_sub.spend_public).then_some(sender_index);
    let change = sender
        .view_keys()
        .scan_transaction(&tx, &mut sender_lookup)
        .unwrap();
    assert_eq!(change.len(), 1);
    assert_eq!(
        (change[0].amount, change[0].subaddress),
        (3_999_000_000, sender_index)
    );
    let (secret, _) = sender
        .output_key_image(
            &change[0].derivation,
            change[0].index as u64,
            sender_index,
            &change[0].key,
        )
        .unwrap();
    assert_eq!(secret_key_to_public_key(&secret).unwrap(), change[0].key);
}

/// An integrated address: its payment id reaches the recipient, encrypted.
#[test]
fn integrated_payment() {
    let mut rng = test_rng(24);
    let sender = AccountKeys::from_seed(&[1; 32]).unwrap();
    let recipient = AccountKeys::from_seed(&[2; 32]).unwrap();
    let id = [9, 8, 7, 6, 5, 4, 3, 2];
    let integrated = recipient
        .address(Network::Mainnet)
        .with_payment_id(id)
        .unwrap();
    let inputs = [fake_input(&mut rng, 1_000_000_000, 2, 1)];
    let mut builder = TransactionBuilder::new();
    builder
        .input(inputs[0].clone())
        .destination(integrated, 1_000_000_000 - 7)
        .change(sender.address(Network::Mainnet), sender.view_secret())
        .fee(7);
    let built = builder.build(&mut rng).unwrap();
    let tx = check_built(&built, &inputs);
    let Some(PaymentId::Encrypted(encrypted)) = payment_id(&tx.prefix.extra) else {
        panic!("no payment id");
    };
    assert_ne!(encrypted, id);
    let got = recipient
        .view_keys()
        .scan_transaction(&tx, &mut |_| None)
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].payment_id, Some(id));
    // A zero change output is still made.
    let change = sender
        .view_keys()
        .scan_transaction(&tx, &mut |_| None)
        .unwrap();
    assert_eq!((change.len(), change[0].amount), (1, 0));

    // Two payment ids, or one with two recipients.
    let other = AccountKeys::from_seed(&[4; 32]).unwrap();
    let mut two_ids = TransactionBuilder::new();
    two_ids
        .input(inputs[0].clone())
        .destination(integrated, 5)
        .destination(integrated, 5)
        .change(sender.address(Network::Mainnet), sender.view_secret());
    assert_eq!(two_ids.build(&mut rng).unwrap_err(), Error::InvalidAddress);
    let mut two_recipients = TransactionBuilder::new();
    two_recipients
        .input(inputs[0].clone())
        .destination(integrated, 5)
        .destination(other.address(Network::Mainnet), 5)
        .change(sender.address(Network::Mainnet), sender.view_secret());
    assert_eq!(
        two_recipients.build(&mut rng).unwrap_err(),
        Error::InvalidAddress
    );
}

#[test]
fn rejections() {
    let mut rng = test_rng(25);
    let sender = AccountKeys::from_seed(&[1; 32]).unwrap();
    let recipient = AccountKeys::from_seed(&[2; 32]).unwrap();
    let to = recipient.address(Network::Mainnet);
    let home = sender.address(Network::Mainnet);
    let input = fake_input(&mut rng, 1000, 2, 0);
    let build = |edit: &dyn Fn(&mut TransactionBuilder)| {
        let mut builder = TransactionBuilder::new();
        edit(&mut builder);
        builder.build(&mut test_rng(1)).map(|_| ()).unwrap_err()
    };

    // No inputs; one output; amounts that do not add up; overflow.
    assert_eq!(
        build(&|b| {
            b.destination(to, 0).change(home, sender.view_secret());
        }),
        Error::InvalidAmounts
    );
    assert_eq!(
        build(&|b| {
            b.input(input.clone()).destination(to, 1000);
        }),
        Error::InvalidAmounts
    );
    assert_eq!(
        build(&|b| {
            b.input(input.clone())
                .destination(to, 500)
                .destination(home, 400);
        }),
        Error::InvalidAmounts
    );
    assert_eq!(
        build(&|b| {
            b.input(input.clone())
                .destination(to, 900)
                .change(home, sender.view_secret())
                .fee(101);
        }),
        Error::InvalidAmounts
    );
    assert_eq!(
        build(&|b| {
            b.input(input.clone())
                .destination(to, u64::MAX)
                .destination(to, 2)
                .change(home, sender.view_secret());
        }),
        Error::InvalidAmounts
    );
    // Seventeen outputs.
    assert_eq!(
        build(&|b| {
            b.input(input.clone()).change(home, sender.view_secret());
            for _ in 0..16 {
                b.destination(to, 1);
            }
        }),
        Error::InvalidAmounts
    );

    // Rings.
    let with = |edit: &dyn Fn(&mut TransactionInput)| {
        let mut bad = input.clone();
        edit(&mut bad);
        build(&|b| {
            b.input(bad.clone())
                .destination(to, 10)
                .change(home, sender.view_secret());
        })
    };
    assert_eq!(with(&|i| i.real_index = 2), Error::InvalidRing);
    assert_eq!(
        with(&|i| i.global_indices = std::vec![5]),
        Error::InvalidRing
    );
    assert_eq!(
        with(&|i| i.global_indices = std::vec![5, 5]),
        Error::InvalidRing
    );
    assert_eq!(
        with(&|i| i.global_indices = std::vec![6, 5]),
        Error::InvalidRing
    );
    assert_eq!(with(&|i| i.real_index = 1), Error::KeyMismatch);
    assert_eq!(with(&|i| i.amount = 999), Error::CommitmentMismatch);
    assert_eq!(
        with(&|i| i.mask = i.secret_key.clone()),
        Error::CommitmentMismatch
    );
    assert!(matches!(
        with(&|i| *i.secret_key = [0xff; 32]),
        Error::CryptoNote(_)
    ));
    // The same output twice.
    assert_eq!(
        build(&|b| {
            b.input(input.clone())
                .input(input.clone())
                .destination(to, 10)
                .change(home, sender.view_secret());
        }),
        Error::InvalidRing
    );
    // A dead random source.
    let mut builder = TransactionBuilder::new();
    builder
        .input(input.clone())
        .destination(to, 10)
        .change(home, sender.view_secret());
    assert_eq!(
        builder.build(&mut |_: &mut [u8]| {}).unwrap_err(),
        Error::BadRandomness
    );
    // Nothing secret in the Debug output.
    let debug = std::format!("{builder:?} {input:?}");
    assert!(!debug.contains("secret") && !debug.contains("mask"));
}
