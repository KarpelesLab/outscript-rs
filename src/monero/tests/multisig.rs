//! Tests for multisig.
//!
//! - `testdata/wallet2_multisig_kex_*.txt`: key exchanges between
//!   `monero-wallet-rpc` 0.18.5.4 wallets and this crate, one participant
//!   being this crate's: its spend key, the threshold, the address the
//!   reference wallets arrived at, and the messages of the reference wallets,
//!   round by round.
//! - `testdata/wallet2_multisig_*.hex`: from the 2-of-3 account of
//!   `wallet2_multisig_kex_2of3.txt`, on a regtest chain: the output export
//!   and the multisig info of the two reference wallets, and a transaction
//!   one of them proposed, after it imported the info this crate exported
//!   for the nonces of `testdata/multisig_nonces.hex`. Signed by this crate,
//!   it was submitted by the reference wallet and mined.

use super::super::*;
use super::test_rng;
use crate::cryptonote::{
    derivation_to_scalar, derive_public_key, generate_key_derivation, sc_reduce32,
    secret_key_to_public_key,
};

fn h32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).unwrap();
    out
}

fn fixture(text: &str) -> Vec<u8> {
    hex::decode(text.trim()).unwrap()
}

fn address_text(address: &Address) -> String {
    let mut text = [0u8; MAX_ADDRESS_LEN];
    let n = address.encode_to_slice(&mut text).unwrap();
    core::str::from_utf8(&text[..n]).unwrap().to_string()
}

/// Replays this crate's side of a recorded key exchange.
fn replay(text: &str) -> MultisigAccount {
    let mut rng = test_rng(31);
    let mut spend = [0u8; 32];
    let mut threshold = 0;
    let mut address = "";
    let mut rounds: Vec<Vec<&str>> = Vec::new();
    for line in text.lines() {
        let Some((name, value)) = line.trim().split_once(' ') else {
            continue;
        };
        match name {
            "spend" => spend = h32(value),
            "threshold" => threshold = value.parse().unwrap(),
            "address" => address = value,
            _ => {
                let round: usize = name.strip_prefix("round").unwrap().parse().unwrap();
                rounds.resize(round.max(rounds.len()), Vec::new());
                rounds[round - 1].push(value);
            }
        }
    }
    let mut kex = MultisigKex::new(&AccountKeys::from_spend_secret(&spend).unwrap()).unwrap();
    kex.first_message(&mut rng).unwrap();
    for (i, messages) in rounds.iter().enumerate() {
        assert!(!kex.is_ready());
        assert!(kex.clone().finish().is_err());
        if i == 0 {
            // A message of a later round, or an exchange not started, is
            // refused, and leaves the state as it was.
            if let Some(later) = rounds.get(1) {
                assert_eq!(
                    kex.start(threshold, later, &mut rng).unwrap_err(),
                    Error::InvalidMultisig
                );
            }
            assert_eq!(
                kex.update(messages, &mut rng).unwrap_err(),
                Error::InvalidMultisig
            );
            kex.start(threshold, messages, &mut rng).unwrap();
            assert_eq!(
                kex.start(threshold, messages, &mut rng).unwrap_err(),
                Error::InvalidMultisig
            );
        } else {
            // The messages of another round, or not all of them, do not do.
            assert_eq!(
                kex.update(&rounds[i - 1], &mut rng).unwrap_err(),
                Error::InvalidMultisig
            );
            if messages.len() > 1 {
                assert_eq!(
                    kex.update(&messages[1..], &mut rng).unwrap_err(),
                    Error::InvalidMultisig
                );
            }
            kex.update(messages, &mut rng).unwrap();
        }
    }
    assert!(kex.is_ready());
    assert_eq!(
        kex.update(rounds.last().unwrap(), &mut rng).unwrap_err(),
        Error::InvalidMultisig
    );
    let signer = *kex.signer_public();
    let account = kex.finish().unwrap();
    assert_eq!(address_text(&account.address(Network::Mainnet)), address);
    assert_eq!(account.threshold(), threshold);
    assert_eq!(account.signers().len(), rounds[0].len() + 1);
    assert!(account.signers().contains(&signer));
    assert_eq!(account.signer_public(), signer);
    account
}

#[test]
fn key_exchange_with_reference_wallets() {
    // N-of-N: one share. 2-of-3: two. 2-of-4: three. 3-of-4: three.
    for (text, shares) in [
        (include_str!("../testdata/wallet2_multisig_kex_2of2.txt"), 1),
        (include_str!("../testdata/wallet2_multisig_kex_2of3.txt"), 2),
        (include_str!("../testdata/wallet2_multisig_kex_2of4.txt"), 3),
        (include_str!("../testdata/wallet2_multisig_kex_3of4.txt"), 3),
    ] {
        let account = replay(text);
        assert_eq!(account.multisig_secrets().len(), shares);
        // The parts make the same account again.
        let signers = account.signers().to_vec();
        let secrets: Vec<[u8; 32]> = account.multisig_secrets().copied().collect();
        let again = MultisigAccount::from_parts(
            account.threshold(),
            &signers,
            account.base_secret(),
            &secrets,
            account.view_keys(),
        )
        .unwrap();
        assert_eq!(again.signer_public(), account.signer_public());
        assert_eq!(
            again.address(Network::Mainnet),
            account.address(Network::Mainnet)
        );
        // Not without this participant among the signers.
        let others: Vec<[u8; 32]> = signers
            .iter()
            .copied()
            .filter(|signer| *signer != account.signer_public())
            .collect();
        assert_eq!(
            MultisigAccount::from_parts(
                account.threshold(),
                &others,
                account.base_secret(),
                &secrets,
                account.view_keys(),
            )
            .unwrap_err(),
            Error::InvalidMultisig
        );
    }
}

#[test]
fn key_exchange_messages_are_checked() {
    let mut rng = test_rng(32);
    let alice = MultisigKex::new(&AccountKeys::from_seed(&[1u8; 32]).unwrap()).unwrap();
    let mut bob = MultisigKex::new(&AccountKeys::from_seed(&[2u8; 32]).unwrap()).unwrap();
    let message = alice.first_message(&mut rng).unwrap();
    // A changed character breaks the signature or the encoding.
    for at in [13, 40, message.len() - 1] {
        let mut bytes = message.clone().into_bytes();
        bytes[at] = if bytes[at] == b'2' { b'3' } else { b'2' };
        let changed = String::from_utf8(bytes).unwrap();
        assert_eq!(
            bob.start(2, &[&changed], &mut rng).unwrap_err(),
            Error::InvalidMultisig
        );
    }
    for bad in ["", "MultisigxV2R1", "MultisigV1abc", "MultisigxV2Rn1111"] {
        assert_eq!(
            bob.start(2, &[bad], &mut rng).unwrap_err(),
            Error::InvalidMultisig
        );
    }
    // The threshold must fit; a participant counts once; one's own first
    // message is ignored.
    assert_eq!(
        bob.start(3, &[&message], &mut rng).unwrap_err(),
        Error::InvalidMultisig
    );
    assert_eq!(
        bob.start(0, &[&message], &mut rng).unwrap_err(),
        Error::InvalidMultisig
    );
    assert_eq!(
        bob.start(2, &[&message, &message], &mut rng).unwrap_err(),
        Error::InvalidMultisig
    );
    let own = bob.first_message(&mut rng).unwrap();
    assert_eq!(
        bob.start(2, &[&own], &mut rng).unwrap_err(),
        Error::InvalidMultisig
    );
    bob.start(2, &[&own, &message], &mut rng).unwrap();
}

/// A group of this crate's participants, after their key exchange.
fn group(threshold: u32, count: u8, rng: &mut dyn FnMut(&mut [u8])) -> Vec<MultisigAccount> {
    let mut participants: Vec<MultisigKex> = (0..count)
        .map(|i| MultisigKex::new(&AccountKeys::from_seed(&[40 + i; 32]).unwrap()).unwrap())
        .collect();
    let mut messages: Vec<String> = participants
        .iter()
        .map(|kex| kex.first_message(rng).unwrap())
        .collect();
    let mut first = true;
    while !participants.iter().all(|kex| kex.is_ready()) {
        let mut next = Vec::new();
        for (i, kex) in participants.iter_mut().enumerate() {
            let others: Vec<&str> = messages
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, message)| message.as_str())
                .collect();
            next.push(if first {
                kex.start(threshold, &others, rng).unwrap()
            } else {
                kex.update(&others, rng).unwrap()
            });
        }
        messages = next;
        first = false;
    }
    participants
        .into_iter()
        .map(|kex| kex.finish().unwrap())
        .collect()
}

/// An output paid to `address`, with a ring around it, as a source and as
/// the wallet's record of it.
fn funded(address: &Address, amount: u64, seed: u8, position: u64) -> (TxSource, ExportedOutput) {
    let r = sc_reduce32(&[seed; 32]);
    let tx_public = secret_key_to_public_key(&r).unwrap();
    let derivation = generate_key_derivation(&address.view_public, &r).unwrap();
    let key = derive_public_key(&derivation, 0, &address.spend_public).unwrap();
    let mask = commitment_mask(&derivation_to_scalar(&derivation, 0));
    let mut ring = Vec::new();
    for i in 0..5u64 {
        let mut bytes = [seed; 32];
        bytes[0] = i as u8;
        bytes[1] = 0x77;
        ring.push((
            1000 * position + 10 * i,
            RingMember {
                key: secret_key_to_public_key(&sc_reduce32(&bytes)).unwrap(),
                commitment: commit(i + 1, &sc_reduce32(&bytes)).unwrap(),
            },
        ));
    }
    let real = (seed % 5) as usize;
    ring[real].1 = RingMember {
        key,
        commitment: commit(amount, &mask).unwrap(),
    };
    let global_output_index = ring[real].0;
    (
        TxSource {
            outputs: ring,
            real_output: real as u64,
            real_out_tx_key: tx_public,
            real_out_additional_tx_keys: Vec::new(),
            real_output_in_tx_index: 0,
            amount,
            rct: true,
            mask: *mask,
            multisig_klrki: [0u8; 128],
        },
        ExportedOutput {
            public_key: key,
            internal_output_index: 0,
            global_output_index,
            tx_public_key: tx_public,
            flags: ExportedOutput::FLAG_RCT,
            amount,
            additional_tx_keys: Vec::new(),
            subaddress: SubaddressIndex::MAIN,
        },
    )
}

fn destination(address: &Address, amount: u64) -> TxDestination {
    TxDestination {
        original: String::new(),
        amount,
        spend_public: address.spend_public,
        view_public: address.view_public,
        is_subaddress: address.is_subaddress(),
        is_integrated: false,
    }
}

/// What a wallet of the account would prepare: both outputs spent, a
/// payment and the change.
fn construction(
    account: &MultisigAccount,
    recipient: &Address,
) -> (TxConstructionData, Vec<ExportedOutput>) {
    let address = account.address(Network::Mainnet);
    let (source_a, output_a) = funded(&address, 5_000_000_000_000, 11, 1);
    let (source_b, output_b) = funded(&address, 3_000_000_000_000, 12, 2);
    let payment = destination(recipient, 6_000_000_000_000);
    let change = destination(&address, 1_999_000_000_000);
    (
        TxConstructionData {
            sources: vec![source_a, source_b],
            change: change.clone(),
            splitted_destinations: vec![payment.clone(), change],
            selected_transfers: vec![0, 1],
            extra: Vec::new(),
            unlock_time: 0,
            use_rct: true,
            use_view_tags: true,
            range_proof_type: 3,
            bp_version: 4,
            destinations: vec![payment],
            subaddress_account: 0,
            subaddress_indices: vec![0],
        },
        vec![output_a, output_b],
    )
}

fn rings(tx: &PendingTx) -> Vec<Vec<RingMember>> {
    // The sources, in the order of the inputs.
    tx.transaction
        .prefix
        .inputs
        .iter()
        .map(|input| {
            let source = tx
                .construction_data
                .sources
                .iter()
                .find(|source| source.multisig_klrki[96..] == input.key_image().unwrap()[..])
                .unwrap();
            source.outputs.iter().map(|(_, member)| *member).collect()
        })
        .collect()
}

#[test]
fn two_of_three_among_ourselves() {
    let mut rng = test_rng(33);
    let accounts = group(2, 3, &mut rng);
    let (alice, bob, carol) = (&accounts[0], &accounts[1], &accounts[2]);
    assert_eq!(
        alice.address(Network::Mainnet),
        bob.address(Network::Mainnet)
    );
    assert_eq!(
        alice.address(Network::Mainnet),
        carol.address(Network::Mainnet)
    );
    let recipient = AccountKeys::from_seed(&[60u8; 32]).unwrap();
    let (data, outputs) = construction(alice, &recipient.address(Network::Mainnet));

    let (alice_info, _) = alice.export_info(&outputs, &mut rng).unwrap();
    let (bob_info, mut bob_nonces) = bob.export_info(&outputs, &mut rng).unwrap();
    let (carol_info, mut carol_nonces) = carol.export_info(&outputs, &mut rng).unwrap();
    // 2-of-3: two shares each, and two nonces per signature a participant
    // may be asked for.
    assert_eq!(bob_info.outputs[0].partial_key_images.len(), 2);
    assert_eq!(bob_info.outputs[0].nonces.len(), 4);

    // Everybody arrives at the same key images, from any other participant.
    for (i, output) in outputs.iter().enumerate() {
        let image = alice
            .key_image(output, &[&bob_info.outputs[i], &carol_info.outputs[i]])
            .unwrap();
        assert_eq!(
            alice.key_image(output, &[&bob_info.outputs[i]]).unwrap(),
            image
        );
        assert_eq!(
            bob.key_image(output, &[&carol_info.outputs[i]]).unwrap(),
            image
        );
        assert_eq!(
            carol.key_image(output, &[&alice_info.outputs[i]]).unwrap(),
            image
        );
    }

    // Alice proposes, for Bob or Carol to complete.
    let proposal = alice
        .propose(
            &data,
            &outputs,
            &[bob_info.clone(), carol_info.clone()],
            &mut rng,
        )
        .unwrap();
    assert!(!proposal.is_complete(2));
    assert_eq!(proposal.signers, vec![alice.signer_public()]);
    let pending = &proposal.transactions[0];
    assert_eq!(pending.multisig_signatures.len(), 2);
    assert_eq!(pending.fee, 1_000_000_000);
    assert_eq!(pending.transaction.verify_balance(), Ok(true));
    assert_eq!(pending.transaction.verify_range_proof(), Ok(true));
    assert_eq!(
        pending.transaction.verify_ring_signatures(&rings(pending)),
        Ok(false)
    );

    // The nonces survive storage.
    let mut stored = MultisigNonces::from_bytes(&bob_nonces.to_bytes()).unwrap();
    assert!(MultisigNonces::from_bytes(&bob_nonces.to_bytes()[1..]).is_err());

    let by_bob = bob.sign(&proposal, &outputs, &mut bob_nonces).unwrap();
    assert!(by_bob.is_complete(2));
    let done = &by_bob.transactions[0];
    assert_eq!(done.transaction.verify(&rings(done)), Ok(true));
    // The payment arrives, and the change comes back.
    let found = recipient
        .view_keys()
        .scan_transaction(&done.transaction, &mut |_| None)
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].amount, 6_000_000_000_000);
    let found = alice
        .view_keys()
        .scan_transaction(&done.transaction, &mut |_| None)
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].amount, 1_999_000_000_000);

    // Carol can complete it as well, with the other attempt.
    let by_carol = carol.sign(&proposal, &outputs, &mut carol_nonces).unwrap();
    let other = &by_carol.transactions[0];
    assert_eq!(other.transaction.verify(&rings(other)), Ok(true));
    assert_ne!(other.transaction.hash(), done.transaction.hash());
    assert_eq!(other.transaction.prefix, done.transaction.prefix);

    // A nonce signs once: Bob's are gone, and the copy stored before
    // signing still has them, which is why it must not be kept.
    assert_eq!(
        bob.sign(&proposal, &outputs, &mut bob_nonces).unwrap_err(),
        Error::MultisigInfoNeeded
    );
    assert!(bob.sign(&proposal, &outputs, &mut stored).is_ok());
    assert_eq!(
        bob.sign(&proposal, &outputs, &mut stored).unwrap_err(),
        Error::MultisigInfoNeeded
    );
    // Nobody signs twice, or a complete set.
    let (_, mut alice_nonces) = alice.export_info(&outputs, &mut rng).unwrap();
    assert_eq!(
        alice
            .sign(&proposal, &outputs, &mut alice_nonces)
            .unwrap_err(),
        Error::InvalidMultisig
    );
    assert_eq!(
        carol
            .sign(&by_bob, &outputs, &mut carol_nonces)
            .unwrap_err(),
        Error::InvalidMultisig
    );

    // What is signed is what the construction data says: a set whose
    // transaction pays someone else, or another amount, is refused.
    let (_, fresh) = bob.export_info(&outputs, &mut rng).unwrap();
    let thief = AccountKeys::from_seed(&[61u8; 32])
        .unwrap()
        .address(Network::Mainnet);
    let mut forged = proposal.clone();
    for destination in &mut forged.transactions[0]
        .construction_data
        .splitted_destinations
    {
        if destination.spend_public == recipient.address(Network::Mainnet).spend_public {
            destination.spend_public = thief.spend_public;
            destination.view_public = thief.view_public;
        }
    }
    assert_eq!(
        bob.sign(&forged, &outputs, &mut fresh.clone()).unwrap_err(),
        Error::InvalidMultisig
    );
    let mut forged = proposal.clone();
    forged.transactions[0]
        .construction_data
        .splitted_destinations[0]
        .amount += 1;
    assert!(bob.sign(&forged, &outputs, &mut fresh.clone()).is_err());
    let mut forged = proposal.clone();
    forged.transactions[0].multisig_tx_key_entropy[0] ^= 1;
    assert_eq!(
        bob.sign(&forged, &outputs, &mut fresh.clone()).unwrap_err(),
        Error::InvalidMultisig
    );
    // The change may only go back to the account.
    let mut diverted = data.clone();
    diverted.change.spend_public = thief.spend_public;
    diverted.change.view_public = thief.view_public;
    diverted.splitted_destinations[1] = diverted.change.clone();
    assert_eq!(
        alice
            .propose(
                &diverted,
                &outputs,
                core::slice::from_ref(&bob_info),
                &mut rng
            )
            .unwrap_err(),
        Error::InvalidAddress
    );
    // It takes the info of enough of the others, from this account.
    assert_eq!(
        alice.propose(&data, &outputs, &[], &mut rng).unwrap_err(),
        Error::MultisigInfoNeeded
    );
    assert_eq!(
        alice
            .propose(&data, &outputs, &[alice_info], &mut rng)
            .unwrap_err(),
        Error::InvalidMultisig
    );
    let mut short = bob_info.clone();
    short.outputs.truncate(1);
    assert_eq!(
        alice
            .propose(&data, &outputs, &[short], &mut rng)
            .unwrap_err(),
        Error::MultisigInfoNeeded
    );
}

#[test]
fn three_of_three_among_ourselves() {
    let mut rng = test_rng(34);
    let accounts = group(3, 3, &mut rng);
    let (alice, bob, carol) = (&accounts[0], &accounts[1], &accounts[2]);
    let recipient = AccountKeys::from_seed(&[60u8; 32]).unwrap();
    // To a subaddress: the transaction key is made with its spend key.
    let (data, outputs) = construction(
        alice,
        &recipient.subaddress(Network::Mainnet, SubaddressIndex::new(0, 3)),
    );
    let (bob_info, mut bob_nonces) = bob.export_info(&outputs, &mut rng).unwrap();
    let (carol_info, mut carol_nonces) = carol.export_info(&outputs, &mut rng).unwrap();
    assert_eq!(bob_info.outputs[0].partial_key_images.len(), 1);
    assert_eq!(bob_info.outputs[0].nonces.len(), 2);
    // With one of the others only, nothing can be proposed.
    assert_eq!(
        alice
            .propose(&data, &outputs, core::slice::from_ref(&bob_info), &mut rng)
            .unwrap_err(),
        Error::MultisigInfoNeeded
    );
    let proposal = alice
        .propose(&data, &outputs, &[carol_info, bob_info], &mut rng)
        .unwrap();
    assert_eq!(proposal.transactions[0].multisig_signatures.len(), 1);
    let by_bob = bob.sign(&proposal, &outputs, &mut bob_nonces).unwrap();
    assert!(!by_bob.is_complete(3));
    let pending = &by_bob.transactions[0];
    assert_eq!(
        pending.transaction.verify_ring_signatures(&rings(pending)),
        Ok(false)
    );
    let by_carol = carol.sign(&by_bob, &outputs, &mut carol_nonces).unwrap();
    assert!(by_carol.is_complete(3));
    let done = &by_carol.transactions[0];
    assert_eq!(done.transaction.verify(&rings(done)), Ok(true));
    let mut lookup = |spend: &[u8; 32]| {
        let index = SubaddressIndex::new(0, 3);
        (recipient.view_keys().subaddress_spend_public(index) == *spend).then_some(index)
    };
    let found = recipient
        .view_keys()
        .scan_transaction(&done.transaction, &mut lookup)
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].amount, 6_000_000_000_000);
}

#[test]
fn co_signing_with_reference_wallets() {
    let mut rng = test_rng(35);
    let account = replay(include_str!("../testdata/wallet2_multisig_kex_2of3.txt"));
    let cipher = account.cipher().unwrap();
    let outputs = OutputExport::from_file(
        &cipher,
        &fixture(include_str!("../testdata/wallet2_multisig_outputs.hex")),
    )
    .unwrap()
    .outputs;
    assert_eq!(outputs.len(), 3);

    // The info of the two reference wallets.
    let file = fixture(include_str!("../testdata/wallet2_multisig_info_1.hex"));
    let info_1 = MultisigInfo::from_file(&cipher, &file).unwrap();
    let info_2 = MultisigInfo::from_file(
        &cipher,
        &fixture(include_str!("../testdata/wallet2_multisig_info_2.hex")),
    )
    .unwrap();
    for info in [&info_1, &info_2] {
        assert_eq!(info.spend_public, *account.view_keys().spend_public());
        assert_eq!(info.view_public, account.view_keys().view_public());
        assert!(account.signers().contains(&info.signer));
        assert_ne!(info.signer, account.signer_public());
        assert_eq!(info.outputs.len(), 3);
        for output in &info.outputs {
            assert_eq!(output.nonces.len(), 4);
            assert_eq!(output.partial_key_images.len(), 2);
        }
    }
    let again = info_1.to_file(&cipher, &mut rng).unwrap();
    assert_eq!(MultisigInfo::from_file(&cipher, &again).unwrap(), info_1);
    assert_eq!(
        *cipher.decrypt(&again[MULTISIG_INFO_MAGIC.len()..]).unwrap(),
        *cipher.decrypt(&file[MULTISIG_INFO_MAGIC.len()..]).unwrap()
    );

    // The transaction the first reference wallet proposed.
    let file = fixture(include_str!("../testdata/wallet2_multisig_tx.hex"));
    let set = MultisigTxSet::from_file(&cipher, &file).unwrap();
    assert_eq!(set.signers, vec![info_1.signer]);
    assert_eq!(set.transactions.len(), 1);
    let pending = &set.transactions[0];
    assert_eq!(pending.transaction.prefix.inputs.len(), 2);
    // One attempt with the other reference wallet, one with us.
    assert_eq!(pending.multisig_signatures.len(), 2);
    assert_eq!(pending.destinations[0].amount, 25_000_000_000_000);
    let again = set.to_file(&cipher, &mut rng).unwrap();
    assert_eq!(
        *cipher
            .decrypt(&again[MULTISIG_TX_SET_MAGIC.len()..])
            .unwrap(),
        *cipher
            .decrypt(&file[MULTISIG_TX_SET_MAGIC.len()..])
            .unwrap()
    );

    // The key images of the outputs it spends are the ones we compute, from
    // the shares of either reference wallet.
    for (input, transfer) in pending
        .transaction
        .prefix
        .inputs
        .iter()
        .zip(&pending.selected_transfers)
    {
        let i = *transfer as usize;
        let image = account
            .key_image(&outputs[i], &[&info_1.outputs[i], &info_2.outputs[i]])
            .unwrap();
        assert_eq!(input.key_image(), Some(&image));
        assert_eq!(
            account
                .key_image(&outputs[i], &[&info_2.outputs[i]])
                .unwrap(),
            image
        );
    }

    // Our signature completes it: the transaction that was mined.
    let mut nonces =
        MultisigNonces::from_bytes(&fixture(include_str!("../testdata/multisig_nonces.hex")))
            .unwrap();
    let signed = account.sign(&set, &outputs, &mut nonces).unwrap();
    assert!(signed.is_complete(2));
    assert_eq!(signed.signers.len(), 2);
    let done = &signed.transactions[0];
    assert_eq!(done.transaction.verify(&rings(done)), Ok(true));
    assert_eq!(
        hex::encode(done.transaction.hash()),
        "db87f9d3cd2a064b669c21950a0c40cd5e76f072f1cf81ecba3cb68c386d24ff"
    );
    let read =
        MultisigTxSet::from_file(&cipher, &signed.to_file(&cipher, &mut rng).unwrap()).unwrap();
    assert_eq!(read.transactions[0].transaction, done.transaction);
    assert_eq!(read.signers, signed.signers);
    // The nonces are used up.
    assert_eq!(
        account.sign(&set, &outputs, &mut nonces).unwrap_err(),
        Error::MultisigInfoNeeded
    );

    // Proposing from the same data, with the reference wallets' info: one
    // attempt for each of them.
    let mut data = pending.construction_data.clone();
    // A set lists the outputs spent in the order of the inputs; a proposal
    // takes them in the order of the sources.
    data.selected_transfers = data
        .sources
        .iter()
        .map(|source| {
            let key = source.outputs[source.real_output as usize].1.key;
            outputs.iter().position(|o| o.public_key == key).unwrap() as u64
        })
        .collect();
    let proposal = account
        .propose(&data, &outputs, &[info_1, info_2], &mut rng)
        .unwrap();
    let ours = &proposal.transactions[0];
    assert_eq!(ours.multisig_signatures.len(), 2);
    assert_eq!(ours.fee, pending.fee);
    assert_eq!(ours.key_images, pending.key_images);
    assert_eq!(ours.selected_transfers, pending.selected_transfers);
    assert_eq!(ours.transaction.verify_balance(), Ok(true));
    assert_eq!(ours.transaction.verify_range_proof(), Ok(true));
    assert_eq!(
        ours.construction_data.extra.len(),
        pending.construction_data.extra.len()
    );
}
