//! Blocks of Zano's main network, the reward of an oversized one, the stake
//! kernel of the first proof-of-stake blocks, and what a daemon serves a
//! wallet: decoys and a block template.
//!
//! The fixtures were dumped from a daemon with `testdata/zano_fetch.py`
//! and picked with the tools of `chain.rs`: the ids, sizes and
//! difficulties quoted here are the daemon's.

use super::super::*;
use super::chain::{
    TransferPlan, owned_outputs, rings_from_binary, transfer_from_daemon_data,
    zarcanum_without_kernel,
};
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

/// A block of the main network, as the daemon describes it.
struct BlockFixture {
    height: u64,
    id: &'static str,
    pos: bool,
    /// The number of transactions, the first one included.
    txs: usize,
    major_version: u8,
    bytes: &'static [u8],
}

macro_rules! block {
    ($height:literal, $id:literal, $pos:literal, $txs:literal, $major:literal) => {
        BlockFixture {
            height: $height,
            id: $id,
            pos: $pos,
            txs: $txs,
            major_version: $major,
            bytes: include_bytes!(concat!("../testdata/mainnet/block_", $height, ".bin")),
        }
    };
}

/// Blocks from before and after each change of format. Those above
/// 3 833 000 are of the chain builds below 600 follow (hard fork 6 without
/// hard fork 7).
const BLOCKS: &[BlockFixture] = &[
    block!(
        0,
        "cc608f59f8080e2fbfe3c8c80eb6e6a953d47cf2d6aebd345bada3a1cab99852",
        false,
        1,
        1
    ),
    block!(
        1,
        "901214ab938219f5b33b547008607aee14d29950a34834a2e9973b96269bd0b0",
        false,
        1,
        0
    ),
    block!(
        52,
        "bc5c5abcb33054dbd39e15b72206f27c104738c2c30cfd7581b3246ba1fee47a",
        true,
        1,
        1
    ),
    block!(
        578,
        "08a30e6733e32019c3d738616303fd16d2b9b1969f582d2c4ff16296be1dabee",
        true,
        3,
        1
    ),
    block!(
        2555001,
        "b329dd2f7a8985fc0e85d985eb333c604d16eed49c7616088af7116a9120d45a",
        false,
        6,
        3
    ),
    block!(
        3076401,
        "8d93e0a7ab93b367dea44862f27ee9ca044649db84a9f44bf095d2eebc133b2d",
        true,
        1,
        3
    ),
    block!(
        3833001,
        "be9116ccd30367cfdf03d854e3ea532f6130645c61d284c30c6ba908b448803d",
        false,
        19,
        3
    ),
    block!(
        3833002,
        "b67a2a4974dc70a1abc7b173b9e9843e6d5c15dea5c5e53a75814c95110a988d",
        true,
        16,
        3
    ),
    block!(
        3904059,
        "29c230e1dcc6cd0e12c2615cce67005e7ef1d20501d672cc4b7d528a336cdbcf",
        false,
        1,
        3
    ),
];

fn block(height: u64) -> (&'static BlockFixture, Block) {
    let fixture = BLOCKS.iter().find(|b| b.height == height).unwrap();
    (fixture, Block::from_bytes(fixture.bytes).unwrap())
}

/// Every block parses, serializes back to the same bytes and hashes to the
/// id the daemon gives it: the header, the tree hash of one to nineteen
/// transactions and their count.
#[test]
fn block_ids() {
    for fixture in BLOCKS {
        let block = Block::from_bytes(fixture.bytes).unwrap();
        let at = fixture.height;
        assert_eq!(block.to_bytes(), fixture.bytes, "{at}");
        assert_eq!(hex::encode(block.id()), fixture.id, "{at}");
        assert_eq!(block.height(), Some(fixture.height));
        assert_eq!(block.is_pos(), fixture.pos, "{at}");
        assert_eq!(block.stake_key_image().is_some(), fixture.pos, "{at}");
        assert_eq!(block.tx_hashes.len() + 1, fixture.txs, "{at}");
        assert_eq!(block.header.major_version, fixture.major_version, "{at}");
        assert_eq!(block.header.flags, u8::from(fixture.pos), "{at}");
        // A proof-of-stake block has no nonce, and a timestamp on the
        // 15-second grid of the kernels.
        if fixture.pos {
            assert_eq!((block.header.nonce, block.header.timestamp % 15), (0, 0));
        }
        assert_eq!(
            BlockHeader::from_bytes(&block.header.to_bytes()),
            Ok(block.header)
        );
        // The first transaction is of the version of the height.
        let (version, _) = mainnet_tx_version(fixture.height);
        assert_eq!(block.miner_tx.version, version, "{at}");
        // The id covers everything.
        let mut other = block.clone();
        other.header.timestamp += 1;
        assert_ne!(other.id(), block.id());
        let mut other = block.clone();
        other.miner_tx.extra.push(Variant::Padding(Vec::new()));
        assert_ne!(other.id(), block.id());
        if let Some(last) = block.tx_hashes.len().checked_sub(1) {
            let mut other = block.clone();
            other.tx_hashes[last][31] ^= 1;
            assert_ne!(other.id(), block.id());
            let mut other = block.clone();
            other.tx_hashes.swap(0, last);
            assert_eq!(other.id() == block.id(), last == 0);
        }
        // Truncated anywhere, it is an error and not a panic.
        for cut in (0..fixture.bytes.len()).step_by(13) {
            assert!(Block::from_bytes(&fixture.bytes[..cut]).is_err());
        }
        let mut longer = fixture.bytes.to_vec();
        longer.push(0);
        assert_eq!(Block::from_bytes(&longer), Err(Error::TrailingData));
    }
    // A major version above the last one is refused, as the reference does.
    let mut bytes = BLOCKS[0].bytes.to_vec();
    bytes[0] = BLOCK_MAJOR_VERSION_MAX + 1;
    assert_eq!(Block::from_bytes(&bytes), Err(Error::UnsupportedVersion));
}

/// The first blocks: the premine, then one coin a block.
#[test]
fn first_blocks() {
    let (_, genesis) = block(0);
    assert_eq!(genesis.header.prev_id, [0; 32]);
    let premine = VerifyContext::new(&[]).block_reward(PREMINE_AMOUNT);
    assert_eq!(genesis.miner_tx.verify(&premine), Ok(()));
    assert_eq!(block_reward(0, 0, 1293), Some(PREMINE_AMOUNT));

    let (_, first) = block(1);
    assert_eq!(first.header.prev_id, genesis.id());
    let coin = VerifyContext::new(&[]).block_reward(BLOCK_REWARD);
    assert_eq!(first.miner_tx.verify(&coin), Ok(()));
    assert_eq!(first.miner_tx.verify(&premine), Err(VerifyError::Balance));
}

/// The ring of one transparent output.
fn bare_ring(stealth_address: &str) -> [ClsagGgxInput; 1] {
    [ClsagGgxInput {
        stealth_address: h32(stealth_address),
        ..Default::default()
    }]
}

/// The stakes of blocks from before hard fork 4: the first one of the
/// chain, whose stake modifier has `POS_STARTER_KERNEL_HASH`, and one of
/// when the difficulty had become what it takes to mean something. The
/// stake modifiers come from following the chain from its first block
/// (`tool_chain`), the difficulties are the daemon's.
#[test]
fn stake_kernels() {
    // Block 52, on top of the proof-of-work block 51.
    let (fixture, first) = block(52);
    let ring = bare_ring("a465473449150fd70fd1a655a4edeade31ef207c54cb9a17b650f824452a168e");
    let mut stake = StakeContext {
        block_id: h32(fixture.id),
        timestamp: first.header.timestamp,
        last_pow_id: h32("af05b814c75e10872afc0345108e830884bc4c32091db783505abe3dac9929cf"),
        last_pos_kernel_id: POS_STARTER_KERNEL_HASH,
        pos_difficulty: 1,
        ring: Vec::new(),
    };
    let rings: [&[ClsagGgxInput]; 1] = [&ring];
    let context = VerifyContext::new(&rings).block_reward(BLOCK_REWARD);
    assert_eq!(first.miner_tx.verify(&context.stake(&stake)), Ok(()));
    // With the difficulty of the first days any kernel does.
    stake.timestamp += 15;
    assert_eq!(first.miner_tx.verify(&context.stake(&stake)), Ok(()));

    // Block 578, with two other transactions whose fees it collects.
    let (fixture, block) = block(578);
    let ring = bare_ring("3bb78ad0bedf2d34a0e9f02f8ad66f988e18351fbd90b9b39437bf9fa43deb79");
    let stake = StakeContext {
        block_id: h32(fixture.id),
        timestamp: block.header.timestamp,
        last_pow_id: h32("622ede8d79f93d7867dab8d38295aced30455b1a58f3d6d36bd1acecd9ea404a"),
        last_pos_kernel_id: h32("0019593a4ff89b71339e87e5e2454292a9eb6c995d71994f6814fed11f7ee9bc"),
        pos_difficulty: 39_872_877_294_655_451,
        ring: Vec::new(),
    };
    let rings: [&[ClsagGgxInput]; 1] = [&ring];
    let context = VerifyContext::new(&rings).block_reward(BLOCK_REWARD + 200_000);
    let tx = &block.miner_tx;
    assert_eq!(tx.verify(&context.stake(&stake)), Ok(()));
    let Variant::ToKey(input) = &tx.vin[1] else {
        panic!()
    };
    let key_image = block.stake_key_image().unwrap();
    assert_eq!(*key_image, input.k_image);
    assert!(stake.check_bare_kernel(key_image, input.amount));
    // The difficulty a stake of this amount has to meet: one kernel in
    // thousands does.
    let target = stake.pos_difficulty / u128::from(input.amount);
    assert!(target > 1000, "{target}");
    // Its kernel hash is small, as the difficulty wants it; it is the
    // second half of the stake modifier of the next proof-of-stake block.
    let kernel = stake.kernel_hash(key_image);
    assert_eq!(
        kernel,
        h32("00010819e79d625afce9f6cc4cfa5ede65200285b1a0845dfdc6be64879db9bb")
    );
    assert!(check_hash(&kernel, target) && !check_hash(&kernel, target * 4096));

    // Another timestamp, another modifier or a larger difficulty: another
    // kernel, which does not meet it.
    let broken = |change: &dyn Fn(&mut StakeContext)| {
        let mut other = stake.clone();
        change(&mut other);
        tx.verify(&context.stake(&other)) == Err(VerifyError::Stake)
    };
    assert!(broken(&|s| s.timestamp += 15));
    assert!(broken(&|s| s.timestamp -= 15));
    assert!(broken(&|s| s.last_pow_id[0] ^= 1));
    assert!(broken(&|s| s.last_pos_kernel_id[31] ^= 1));
    assert!(broken(&|s| s.pos_difficulty *= 4096));
    assert!(!stake.check_bare_kernel(key_image, 0));
    // The signature is over the block id.
    let mut other = stake.clone();
    other.block_id[0] ^= 1;
    assert_eq!(
        tx.verify(&context.stake(&other)),
        Err(VerifyError::InputSignature(1))
    );
    // Without a difficulty the kernel is not looked at.
    let mut unchecked = stake.clone();
    unchecked.pos_difficulty = 0;
    unchecked.timestamp += 15;
    assert_eq!(tx.verify(&context.stake(&unchecked)), Ok(()));
    // The fees are part of what the block creates.
    let without_fees = VerifyContext::new(&rings).block_reward(BLOCK_REWARD);
    assert_eq!(
        tx.verify(&without_fees.stake(&stake)),
        Err(VerifyError::Balance)
    );
}

/// The first blocks after hard forks 4, 5 and 6: fees are burnt, and the
/// stake is hidden.
#[test]
fn zarcanum_blocks() {
    // Proof of work: the reward and nothing else, whatever the fees.
    for height in [2_555_001, 3_833_001, 3_904_059] {
        let (_, block) = block(height);
        assert!(
            block.miner_tx.verify_coinbase_proofs(BLOCK_REWARD),
            "{height}"
        );
        assert!(
            !block
                .miner_tx
                .verify_coinbase_proofs(BLOCK_REWARD + 50_000_000_000)
        );
        let reward = VerifyContext::new(&[]).block_reward(BLOCK_REWARD);
        assert_eq!(block.miner_tx.verify(&reward), Ok(()), "{height}");
    }
    // From hard fork 6 on the first transaction states the size the reward
    // is computed from.
    let (_, block_v4) = block(3_833_001);
    assert_eq!(
        block_v4.miner_tx.extra.first(),
        Some(&Variant::CoinbaseBlockCumulativeSize(93_480))
    );
    assert_eq!(block_reward(3_833_001, 0, 93_480), Some(BLOCK_REWARD));

    // Proof of stake: the proofs of the first transaction, with the reward.
    for height in [3_076_401, 3_833_002] {
        let (_, block) = block(height);
        assert!(
            block.miner_tx.verify_coinbase_proofs(BLOCK_REWARD),
            "{height}"
        );
        assert!(!block.miner_tx.verify_coinbase_proofs(BLOCK_REWARD - 1));
        assert!(matches!(
            block.miner_tx.signatures.as_slice(),
            [Variant::ZarcanumSig(_)]
        ));
    }
    // And of the stake proof what does not take the kernel hash of the
    // proof-of-stake block before (which this daemon does not serve): the
    // range proof and the ring signature over the block id.
    let (fixture, block) = block(3_833_002);
    let ring =
        rings_from_binary(include_bytes!("../testdata/mainnet/block_3833002.rings")).remove(0);
    assert_eq!(ring.len(), 16);
    let id = h32(fixture.id);
    assert!(zarcanum_without_kernel(&block.miner_tx, &id, &ring));
    let mut other_id = id;
    other_id[0] ^= 1;
    assert!(!zarcanum_without_kernel(&block.miner_tx, &other_id, &ring));
    let mut other_ring = ring.clone();
    other_ring.swap(3, 4);
    assert!(!zarcanum_without_kernel(&block.miner_tx, &id, &other_ring));
    // The whole proof needs the stake context.
    let reward = VerifyContext::new(&[]).block_reward(BLOCK_REWARD);
    assert_eq!(
        block.miner_tx.verify(&reward),
        Err(VerifyError::MissingStakeContext)
    );
}
