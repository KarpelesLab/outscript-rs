//! Blocks of Zano's main network, the reward of an oversized one, the stake
//! kernel of the first proof-of-stake blocks, and what a daemon serves a
//! wallet: decoys and a block template.
//!
//! The fixtures were dumped from a daemon with `testdata/zano_fetch.py`
//! and picked with the tools of `chain.rs`: the ids, sizes and
//! difficulties quoted here are the daemon's.

use super::super::*;
use super::chain::{TransferPlan, owned_outputs, transfer_from_daemon_data};
use super::h32;
use crate::prelude::*;

/// A reply of `getrandom_outs3`, as the daemon sent it: 36 confidential
/// outputs asked by global index, the two of the first transaction of
/// block 3 904 059 last.
const RANDOM_OUTS_REPLY: &[u8] = include_bytes!("../testdata/daemon/random_outs3_reply.bin");

/// A block template the daemon made (`getblocktemplate`) for the address of
/// the wallet of the tests, on top of block 3 904 085.
const BLOCK_TEMPLATE: &[u8] = include_bytes!("../testdata/daemon/block_template.bin");

#[test]
fn json_binary_strings() {
    assert_eq!(
        json_binary_string(br#"a\"b\\c\/d\b\f\n\r\t\u0000\u001f\u007F"#).unwrap(),
        b"a\"b\\c/d\x08\x0c\n\r\t\x00\x1f\x7f"
    );
    // Bytes that are not UTF-8 come as they are.
    assert_eq!(
        json_binary_string(&[0xff, 0x80, b'\\', b'n', 0xc3]).unwrap(),
        [0xff, 0x80, b'\n', 0xc3]
    );
    assert_eq!(json_binary_string(b"").unwrap(), b"");
    for bad in [
        &br#"\x"#[..],
        br#"\"#,
        br#"\u00"#,
        br#"\u0100"#,
        br#"\u00zz"#,
        br#"a"b"#,
    ] {
        assert_eq!(json_binary_string(bad), Err(Error::InvalidEncoding));
    }
}

/// A reply with one entry per given `(global index, flags)`.
fn made_up_reply(entries: &[(u64, u64)]) -> Vec<u8> {
    let mut blob = Vec::new();
    for (index, flags) in entries {
        blob.extend_from_slice(&index.to_le_bytes());
        for key in 0..4u8 {
            blob.extend_from_slice(&[key + 0x61; 32]);
        }
        blob.extend_from_slice(&flags.to_le_bytes());
    }
    let mut reply =
        br#"{ "id": 0, "jsonrpc": "2.0", "result": { "outs": [{ "amount": 0, "outs": ""#.to_vec();
    for byte in blob {
        match byte {
            b'"' | b'\\' => reply.extend_from_slice(&[b'\\', byte]),
            0..0x20 => reply.extend_from_slice(format!("\\u{byte:04x}").as_bytes()),
            byte => reply.push(byte),
        }
    }
    reply.extend_from_slice(b"\" }, { \"amount\": 1000 }], \"status\": \"OK\" } }\r\n");
    reply
}

#[test]
fn random_outs_replies() {
    let reply = made_up_reply(&[
        (7, 0),
        (0x0102_0304_0506_0708, RANDOM_OUT_FLAG_COINBASE),
        (0, RANDOM_OUT_FLAG_NOT_ALLOWED),
    ]);
    let parsed = parse_random_outs_reply(&reply).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!((parsed[0].amount, parsed[0].outs.len()), (0, 3));
    // An amount the daemon had nothing for: epee leaves the field out.
    assert_eq!((parsed[1].amount, parsed[1].outs.len()), (1000, 0));
    let outs = &parsed[0].outs;
    assert_eq!(outs[0].member.global_index, 7);
    assert_eq!(outs[0].member.stealth_address, [0x61; 32]);
    assert_eq!(outs[0].member.concealing_point, [0x62; 32]);
    assert_eq!(outs[0].member.amount_commitment, [0x63; 32]);
    assert_eq!(outs[0].member.blinded_asset_id, [0x64; 32]);
    assert_eq!(outs[1].member.global_index, 0x0102_0304_0506_0708);
    assert_eq!(outs[1].flags, RANDOM_OUT_FLAG_COINBASE);
    assert!(outs[0].is_allowed() && outs[1].is_allowed() && !outs[2].is_allowed());

    // The result alone, without the envelope.
    let start = reply.windows(8).position(|w| w == b"\"result\"").unwrap() + 9;
    let inner = &reply[start..reply.len() - 4];
    assert_eq!(parse_random_outs_reply(inner).unwrap(), parsed);

    // Cut anywhere, changed anywhere: an error or other outputs, no panic.
    for cut in 0..reply.len() - 3 {
        assert!(parse_random_outs_reply(&reply[..cut]).is_err(), "{cut}");
    }
    for at in 0..reply.len() {
        let mut changed = reply.clone();
        changed[at] ^= 0x5c;
        let _ = parse_random_outs_reply(&changed);
    }

    assert_eq!(decode_random_outs(&[0; 143]), Err(Error::InvalidEncoding));
    assert_eq!(decode_random_outs(&[]).unwrap(), []);
    for (text, error) in [
        (
            &br#"{"outs":[],"status":"BUSY"}"#[..],
            Error::InvalidEncoding,
        ),
        (br#"{"outs":[]}"#, Error::InvalidEncoding),
        (br#"{"status":"OK"}"#, Error::InvalidEncoding),
        (
            br#"{"outs":[{"outs":""}],"status":"OK"}"#,
            Error::InvalidEncoding,
        ),
        (
            br#"{"outs":[{"amount":0,"outs":7}],"status":"OK"}"#,
            Error::InvalidEncoding,
        ),
        (
            br#"{"outs":[{"amount":0,"outs":"abc"}],"status":"OK"}"#,
            Error::InvalidEncoding,
        ),
        (br#"{"outs":[],"status":"OK"} x"#, Error::TrailingData),
        (br#"{"outs":[,],"status":"OK"}"#, Error::InvalidEncoding),
        (br#"{"outs":[],"status":"OK""#, Error::UnexpectedEof),
        (b"", Error::UnexpectedEof),
    ] {
        assert_eq!(parse_random_outs_reply(text), Err(error), "{text:?}");
    }
    assert_eq!(
        parse_random_outs_reply(br#"{"outs":[],"status":"OK"}"#).unwrap(),
        []
    );
    // Nesting is bounded.
    let deep = [b'['; 4000];
    assert_eq!(parse_random_outs_reply(&deep), Err(Error::TooDeep));
}

#[test]
fn tree_hashes() {
    let hash = |n: u8| crate::cryptonote::cn_fast_hash(&[n]);
    let pair = |a: [u8; 32], b: [u8; 32]| crate::cryptonote::cn_fast_hash_parts(&[&a, &b]);
    let h: Vec<[u8; 32]> = (0..9).map(hash).collect();
    assert_eq!(tree_hash(&[]), [0; 32]);
    assert_eq!(tree_hash(&h[..1]), h[0]);
    assert_eq!(tree_hash(&h[..2]), pair(h[0], h[1]));
    // Three: the last two are paired first.
    assert_eq!(tree_hash(&h[..3]), pair(h[0], pair(h[1], h[2])));
    assert_eq!(tree_hash(&h[..4]), pair(pair(h[0], h[1]), pair(h[2], h[3])));
    assert_eq!(
        tree_hash(&h[..5]),
        pair(pair(h[0], h[1]), pair(h[2], pair(h[3], h[4])))
    );
    assert_eq!(
        tree_hash(&h[..9]),
        pair(
            pair(pair(h[0], h[1]), pair(h[2], h[3])),
            pair(pair(h[4], h[5]), pair(h[6], pair(h[7], h[8])))
        )
    );
}

#[test]
fn rewards_and_medians() {
    assert_eq!(block_reward(0, 0, 0), Some(PREMINE_AMOUNT));
    assert_eq!(block_reward(1, 0, 0), Some(BLOCK_REWARD));
    assert_eq!(block_reward(1, 0, 125_000), Some(BLOCK_REWARD));
    assert!(block_reward(1, 0, 125_001).unwrap() < BLOCK_REWARD);
    assert!(matches!(block_reward(1, 0, 249_999), Some(1..16_000_000)));
    // Nothing left at twice the median: the chain refuses such a block.
    assert_eq!(block_reward(1, 0, 250_000), None);
    assert_eq!(block_reward(1, 0, 250_001), None);
    // A larger median moves the zone.
    assert_eq!(block_reward(1, 200_000, 200_000), Some(BLOCK_REWARD));
    assert_eq!(
        block_reward(1, 200_000, 300_000),
        Some(BLOCK_REWARD / 4 * 3)
    );
    assert_eq!(block_reward(1, u64::MAX, u64::MAX), Some(BLOCK_REWARD));
    assert_eq!(block_reward(1, 1 << 40, (1 << 40) + 1), None);

    assert_eq!(median_block_size(&mut []), 0);
    assert_eq!(median_block_size(&mut [5]), 5);
    assert_eq!(median_block_size(&mut [9, 1]), 5);
    assert_eq!(median_block_size(&mut [9, 1, 4]), 4);
    assert_eq!(median_block_size(&mut [9, 1, 4, 6]), 5);
}

#[test]
fn hashes_against_difficulties() {
    // The hash is a big-endian number: 2^255 meets a difficulty of 1 only.
    let mut half = [0u8; 32];
    half[0] = 0x80;
    assert!(check_hash(&half, 0) && check_hash(&half, 1) && !check_hash(&half, 2));
    assert!(check_hash(&[0xff; 32], 1) && !check_hash(&[0xff; 32], 2));
    assert!(check_hash(&[0; 32], u128::MAX));
    // 2^128 - 1 times 2^128 - 1 fits; 2^128 times 2^128 does not.
    let mut low = [0u8; 32];
    low[16..].fill(0xff);
    assert!(check_hash(&low, u128::MAX));
    let mut over = [0u8; 32];
    over[15] = 1;
    assert!(check_hash(&over, u128::MAX));
    let mut two = over;
    two[15] = 2;
    assert!(!check_hash(&two, 1 << 127));
    assert!(check_hash(&two, (1 << 127) - 1));
}

/// The decoys of a real reply.
fn real_decoys() -> Vec<RandomOut> {
    let mut reply = parse_random_outs_reply(RANDOM_OUTS_REPLY).unwrap();
    assert_eq!(reply.len(), 1);
    assert_eq!(reply[0].amount, 0);
    reply.remove(0).outs
}

#[test]
fn random_outs_of_a_daemon() {
    let outs = real_decoys();
    // One entry per index asked, in the order asked.
    let asked: [u64; 36] = [
        555950, 927252, 1157635, 1699100, 1790466, 1991957, 2394310, 2400634, 2646611, 3565204,
        3770903, 4658278, 5303976, 5309676, 5310606, 5314428, 5316153, 5325000, 5335110, 5337689,
        5354234, 5354468, 5358370, 5360066, 5361043, 5361881, 5362606, 5363582, 5371294, 5383076,
        5383612, 5385333, 5389030, 5389147, 5389477, 5389478,
    ];
    assert_eq!(outs.len(), asked.len());
    let mut allowed = 0;
    for (out, index) in outs.iter().zip(asked) {
        if !out.is_allowed() {
            // A refused entry is all zeros but for its flag.
            assert_eq!(out.member, RingMember::default());
            continue;
        }
        allowed += 1;
        assert_eq!(out.member.global_index, index);
        // Every key is a point, and on the wire times 1/8 like the keys of
        // an output: the blinded asset id of a native output is H / 8.
        for key in [
            &out.member.stealth_address,
            &out.member.concealing_point,
            &out.member.amount_commitment,
            &out.member.blinded_asset_id,
        ] {
            assert!(crate::cryptonote::check_key(key));
        }
    }
    assert!(allowed >= 32, "{allowed}");

    // The last two are the outputs of the first transaction of a block
    // that is among the fixtures: the daemon gives what the block holds.
    let block = Block::from_bytes(include_bytes!("../testdata/mainnet/block_3904059.bin")).unwrap();
    for (out, on_chain) in outs[34..].iter().zip(&block.miner_tx.vout) {
        let on_chain = on_chain.zarcanum_out().unwrap();
        assert_eq!(out.flags, RANDOM_OUT_FLAG_COINBASE);
        assert_eq!(out.member.stealth_address, on_chain.stealth_address);
        assert_eq!(out.member.concealing_point, on_chain.concealing_point);
        assert_eq!(out.member.amount_commitment, on_chain.amount_commitment);
        assert_eq!(out.member.blinded_asset_id, on_chain.blinded_asset_id);
    }
    // Outputs of other transactions are not flagged.
    assert!(outs.iter().any(|out| out.is_allowed() && out.flags == 0));

    // The reply is not UTF-8: a JSON library does not read it.
    assert!(String::from_utf8(RANDOM_OUTS_REPLY.to_vec()).is_err());
    // Cut anywhere it is an error, not a panic.
    for cut in (0..RANDOM_OUTS_REPLY.len() - 8).step_by(7) {
        assert!(parse_random_outs_reply(&RANDOM_OUTS_REPLY[..cut]).is_err());
    }
}

/// What the daemon said of the template with it (`miner_tx_tgc`): the
/// amounts of the outputs of its first transaction and the blinding masks
/// of their commitments, and the key pair of the transaction.
const TEMPLATE_OUTS: [(u64, &str); 2] = [
    (
        328_000_000_000,
        "e9466e2d0436eff1f0e2f7c0596903e61e1344a5a66594bd865213582acfe001",
    ),
    (
        672_000_000_000,
        "b788f608d6e810d5aaa2fff293b93fc4c0161a94e40f9617ea2f5d70049b7607",
    ),
];
const TEMPLATE_TX_KEY: (&str, &str) = (
    "17d96f3caccc3ecacf112509e708a8a4b960f4980a3cb4af946508198ba589e8",
    "c4b6095cf3d23f2db6c97a59e238ef323bc4221ca0a9869489e10329320baa01",
);

/// A block template of the daemon: it parses and serializes back, and the
/// wallet it pays finds in its first transaction the amounts and the
/// blinding masks the daemon says it put there.
#[test]
fn block_template_of_a_daemon() {
    let block = Block::from_bytes(BLOCK_TEMPLATE).unwrap();
    assert_eq!(block.to_bytes(), BLOCK_TEMPLATE);
    assert_eq!(block.height(), Some(3_904_086));
    assert_eq!(
        block.header.prev_id,
        h32("20c500b3241a67e204a4f9875959ab29bc2284bc014b9593f74b5d5d4d004dab")
    );
    assert_eq!(
        (
            block.header.major_version,
            block.header.nonce,
            block.header.flags
        ),
        (3, 0, 0)
    );
    assert!(!block.is_pos() && block.tx_hashes.is_empty());
    assert_eq!(block.stake_key_image(), None);
    // No other transaction: the tree hash is the id of the first.
    assert_eq!(block.tx_tree_hash(), block.miner_tx.prefix_hash());

    let tx = &block.miner_tx;
    // The daemon is a build that knows hard fork 6 without hard fork 7.
    assert_eq!((tx.version, tx.hardfork_id), (4, HARDFORK_06));
    assert_eq!(tx.tx_pub_key(), Some(h32(TEMPLATE_TX_KEY.0)));
    assert_eq!(
        crate::cryptonote::secret_key_to_public_key(&h32(TEMPLATE_TX_KEY.1)).unwrap(),
        h32(TEMPLATE_TX_KEY.0)
    );
    assert!(tx.verify_coinbase_proofs(BLOCK_REWARD));
    assert!(!tx.verify_coinbase_proofs(BLOCK_REWARD + 1));

    let wallet = super::wallet();
    let found = wallet.scan_tx(tx).unwrap();
    assert_eq!(found.outputs.len(), 2);
    for (out, (amount, mask)) in found.outputs.iter().zip(TEMPLATE_OUTS) {
        assert_eq!(out.amount, amount);
        assert_eq!(out.amount_blinding_mask, h32(mask));
        assert!(out.is_native);
        assert_eq!(out.asset_id_blinding_mask, [0; 32]);
    }
    assert_eq!(found.output_payment_ids, [0, 0]);
    // The sender's side of the same derivation.
    let derivation = crate::cryptonote::generate_key_derivation(
        wallet.view_public_key(),
        &h32(TEMPLATE_TX_KEY.1),
    )
    .unwrap();
    assert_eq!(
        *wallet.key_derivation(&h32(TEMPLATE_TX_KEY.0)).unwrap(),
        derivation
    );
    // One hint per output: that of the derivation — both outputs have the
    // same — and a random one (`add_random_derivation_hints_and_put_them_to_tx`).
    let mine = derivation_hint(&derivation).to_le_bytes();
    let hints: Vec<&Vec<u8>> = tx
        .extra
        .iter()
        .filter_map(|entry| match entry {
            Variant::DerivationHint(hint) => Some(hint),
            _ => None,
        })
        .collect();
    assert_eq!(hints.len(), 2);
    assert_eq!(hints.iter().filter(|hint| ***hint == mine).count(), 1);
    // Someone else finds nothing.
    let stranger = Wallet::generate(&mut super::stream(5), 0).unwrap();
    assert!(!stranger.scan_tx(tx).unwrap().found());

    for cut in (0..BLOCK_TEMPLATE.len()).step_by(11) {
        assert!(Block::from_bytes(&BLOCK_TEMPLATE[..cut]).is_err());
    }
}

/// Everything short of the network: the outputs the wallet scans in the
/// template of the daemon are spent in rings made of the decoys of the
/// daemon's reply, as `tool_build_transfer` does with a dump.
#[test]
fn transfer_from_what_a_daemon_serves() {
    let wallet = super::wallet();
    let block = Block::from_bytes(BLOCK_TEMPLATE).unwrap();
    // The template is not in the chain: the global indices its outputs
    // would have are made up.
    let owned = owned_outputs(
        &wallet,
        "template",
        &block.miner_tx,
        &[5_389_600, 5_389_601],
    );
    assert_eq!(owned.len(), 2);
    let decoys = real_decoys();
    let recipient = Wallet::generate(&mut super::stream(77), 0).unwrap();
    let mut plan = TransferPlan {
        destination: recipient.address(),
        amount: 700_000_000_000,
        fee: 10_000_000_000,
        version: 4,
        hardfork_id: HARDFORK_07,
        ring_size: 16,
    };
    let tx =
        transfer_from_daemon_data(&wallet, &mut super::stream(1), &owned, &decoys, &plan).unwrap();
    // Both outputs were needed.
    assert_eq!((tx.version, tx.hardfork_id, tx.vin.len()), (4, 7, 2));
    let Variant::ZcInput(input) = &tx.vin[0] else {
        panic!()
    };
    assert_eq!(input.key_offsets.len(), 16);
    let paid = recipient.scan_tx(&tx).unwrap();
    assert_eq!(paid.outputs.len(), 1);
    assert_eq!(paid.outputs[0].amount, 700_000_000_000);
    let change = wallet.scan_tx(&tx).unwrap();
    assert_eq!(change.outputs.len(), 1);
    assert_eq!(change.outputs[0].amount, 290_000_000_000);

    // One output is enough for less, and for the chain of hard fork 6.
    plan.amount = 100_000_000_000;
    plan.hardfork_id = HARDFORK_06;
    let tx =
        transfer_from_daemon_data(&wallet, &mut super::stream(2), &owned, &decoys, &plan).unwrap();
    assert_eq!((tx.hardfork_id, tx.vin.len()), (6, 1));

    // Not more than there is, nor without decoys enough.
    plan.amount = 1_000_000_000_000;
    assert!(
        transfer_from_daemon_data(&wallet, &mut super::stream(3), &owned, &decoys, &plan).is_err()
    );
    plan.amount = 700_000_000_000;
    assert!(
        transfer_from_daemon_data(&wallet, &mut super::stream(3), &owned, &decoys[..20], &plan)
            .is_err()
    );
}
