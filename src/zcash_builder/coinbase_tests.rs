//! Coinbase transactions against the main network.
//!
//! `testdata/mainnet_coinbases.json` holds the coinbase transactions of 29
//! blocks of the main network, from the activation of NU5 (height
//! 1 687 104) to height 3 560 137, with the total of the fees the other
//! transactions of each block pay (transactions, heights and fees from a
//! public explorer, `api.mainnet.cipherscan.app`). They are on both sides
//! of every change of rule since NU5: an address period of the Canopy
//! funding streams, the second halving and NU6 (the lockbox), NU6.1 (with
//! its lockbox disbursement), NU6.3 (version 6) and NU7 (a third of the
//! subsidy, 40% of the fees). Some are version 4 transactions, which
//! miners made until NU7; two have an Ironwood bundle, which
//! `zcash_primitives` 0.31.0 and `orchard` 0.16.0 parsed and verified in
//! full (proof and signatures) by a program outside this repository.
//!
//! Each is checked against what `zcashtx::subsidy` computes from its
//! height and fees, and every version 5 and 6 one without shielded outputs
//! is built again from its parts, to the same bytes and the same id.

use super::*;
use crate::zcashtx::subsidy::{self, Recipient};
use crate::zcashtx::{branch, coinbase_script_height};

/// A coinbase transaction of the fixture, taken apart.
struct Coinbase {
    height: u32,
    fees: u64,
    txid: [u8; 32],
    raw: Vec<u8>,
    /// 4, 5 or 6.
    version: u32,
    branch_id: u32,
    expiry_height: u32,
    script_sig: Vec<u8>,
    sequence: u32,
    outputs: Vec<(u64, Vec<u8>)>,
    /// The value its shielded outputs take, and the Ironwood bundle.
    shielded: u64,
    ironwood: Vec<u8>,
}

fn rows() -> Vec<Coinbase> {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("testdata/mainnet_coinbases.json")).unwrap();
    rows.as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let raw = hex::decode(row["raw"].as_str().unwrap()).unwrap();
            let mut coinbase = Coinbase {
                height: row["height"].as_u64().unwrap() as u32,
                fees: row["fees"].as_u64().unwrap(),
                txid: hex::decode(row["txid"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                version: u32::from_le_bytes(raw[..4].try_into().unwrap()) & 0x7fff_ffff,
                branch_id: 0,
                expiry_height: 0,
                script_sig: Vec::new(),
                sequence: 0,
                outputs: Vec::new(),
                shielded: 0,
                ironwood: Vec::new(),
                raw,
            };
            if coinbase.version == 4 {
                parse_v4(&mut coinbase);
            } else {
                parse_v5(&mut coinbase);
            }
            coinbase
        })
        .collect()
}

fn parse_v5(coinbase: &mut Coinbase) {
    let mut inputs = [ZcashTxIn::default(); 1];
    let mut outputs = [ZcashTxOut::default(); 16];
    let tx = ZcashTx::parse_into(&coinbase.raw, &mut inputs, &mut outputs).unwrap();
    assert!(tx.is_coinbase());
    assert_eq!(tx.txid().unwrap(), coinbase.txid);
    assert_eq!(tx.coinbase_height(), Some(coinbase.height));
    coinbase.branch_id = tx.consensus_branch_id;
    coinbase.expiry_height = tx.expiry_height;
    assert_eq!(tx.lock_time, 0);
    coinbase.script_sig = tx.inputs[0].script_sig.to_vec();
    coinbase.sequence = tx.inputs[0].sequence;
    coinbase.outputs = tx
        .outputs
        .iter()
        .map(|output| (output.amount, output.script.to_vec()))
        .collect();
    // no fixture has a Sapling or an Orchard bundle
    assert!(tx.sapling.len() <= 2);
    assert!(tx.orchard.len() <= 1);
    coinbase.ironwood = tx.ironwood.to_vec();
    #[cfg(feature = "zcash-orchard")]
    if let Some(bundle) = tx.ironwood_bundle().unwrap() {
        assert!(bundle.value_balance() < 0);
        coinbase.shielded = (-bundle.value_balance()) as u64;
    }
}

/// A version 4 transaction with transparent parts only.
fn parse_v4(coinbase: &mut Coinbase) {
    let raw = &coinbase.raw;
    assert_eq!(raw[..8], [0x04, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89]);
    assert_eq!(raw[8], 1);
    assert_eq!(raw[9..45], [[0u8; 32].as_slice(), &[0xff; 4]].concat()[..]);
    let n = raw[45] as usize;
    coinbase.script_sig = raw[46..46 + n].to_vec();
    let mut at = 46 + n;
    coinbase.sequence = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
    at += 4;
    let count = raw[at];
    at += 1;
    for _ in 0..count {
        let amount = u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
        let len = raw[at + 8] as usize;
        coinbase
            .outputs
            .push((amount, raw[at + 9..at + 9 + len].to_vec()));
        at += 9 + len;
    }
    // the lock time, which some miners do not leave at zero
    coinbase.expiry_height = u32::from_le_bytes(raw[at + 4..at + 8].try_into().unwrap());
    // no value balance, Sapling spend, Sapling output or JoinSplit
    assert_eq!(raw[at + 8..], [0; 11]);
}

fn script_of(address: &str) -> Vec<u8> {
    crate::zcash::decode_zcash_address("zcash", address)
        .unwrap()
        .script
        .to_vec()
}

/// Every coinbase has the height, the expiry height, the funding stream
/// outputs and the total value the rules give for its block.
#[test]
fn mainnet_coinbases_follow_the_rules() {
    let rows = rows();
    assert_eq!(rows.len(), 29);
    let mut versions = [0; 7];
    let mut recipients = Vec::new();
    for coinbase in &rows {
        let height = coinbase.height;
        versions[coinbase.version as usize] += 1;
        assert_eq!(
            coinbase_script_height(&coinbase.script_sig).map(|(h, _)| h),
            Some(height)
        );
        assert_eq!(coinbase.expiry_height, height, "{height}");
        let branch_id = match height {
            h if h < subsidy::NU5_ACTIVATION_HEIGHT => unreachable!(),
            h if h < subsidy::NU6_ACTIVATION_HEIGHT => branch::NU5,
            h if h < subsidy::NU6_1_ACTIVATION_HEIGHT => branch::NU6,
            // NU6.2 is between NU6.1 and NU6.3: the fixture tells it
            h if h < subsidy::NU6_3_ACTIVATION_HEIGHT => coinbase.branch_id,
            h if h < subsidy::NU7_ACTIVATION_HEIGHT => branch::NU6_3,
            _ => branch::NU7,
        };
        if coinbase.version > 4 {
            assert_eq!(coinbase.branch_id, branch_id, "{height}");
            assert!(matches!(
                coinbase.branch_id,
                branch::NU5
                    | branch::NU6
                    | branch::NU6_1
                    | branch::NU6_2
                    | branch::NU6_3
                    | branch::NU7
            ));
            // version 6 from NU6.3 only (and version 5 still)
            assert!(coinbase.version == 5 || height >= subsidy::NU6_3_ACTIVATION_HEIGHT);
        }

        // the funding streams: an output each, of its amount to its address
        let streams = subsidy::funding_streams(height).unwrap();
        for stream in streams.as_slice() {
            let Recipient::Address(address) = stream.recipient else {
                continue;
            };
            if !recipients.contains(&address) {
                recipients.push(address);
            }
            let output = (stream.amount, script_of(address));
            assert!(
                coinbase.outputs.contains(&output),
                "{height} {}",
                stream.name
            );
        }
        if let Some(disbursement) = subsidy::lockbox_disbursement(height) {
            let output = (disbursement.amount, script_of(disbursement.address));
            let found = coinbase.outputs.iter().filter(|o| **o == output).count();
            assert_eq!(found, disbursement.outputs);
        }

        // the total: the subsidy and the miner's fees, less the lockbox
        let transparent: u64 = coinbase.outputs.iter().map(|output| output.0).sum();
        let total = subsidy::coinbase_output_total(height, coinbase.fees).unwrap();
        if coinbase.ironwood.len() <= 1 {
            assert_eq!(transparent, total, "{height}");
        } else if cfg!(feature = "zcash-orchard") {
            assert_eq!(transparent + coinbase.shielded, total, "{height}");
        }
        let subsidy_value = subsidy::block_subsidy(height).unwrap();
        assert_eq!(
            total,
            subsidy_value + subsidy::miner_fees(height, coinbase.fees) - streams.lockbox_total()
                + subsidy::lockbox_disbursement(height).map_or(0, |d| 10 * d.amount)
        );
    }
    // versions 4, 5 and 6, and every recipient but the one of ZIP 2008,
    // which no block pays yet: eight addresses of the first stream, ZF,
    // MG, and ZCG
    assert!(versions[4] > 5 && versions[5] > 5 && versions[6] > 5);
    assert_eq!(recipients.len(), 8 + 3);
    // the fees matter on both sides of NU7
    assert!(
        rows.iter()
            .any(|c| c.fees % 10 != 0 && c.height < subsidy::NU7_ACTIVATION_HEIGHT)
    );
    assert!(
        rows.iter()
            .any(|c| c.fees > 0 && c.height >= subsidy::NU7_ACTIVATION_HEIGHT)
    );
}

/// The version 5 and 6 coinbases without shielded outputs, built again
/// from their height, the miner's bytes, their sequence number and their
/// outputs: the same bytes, which hash to the id the chain has.
#[test]
fn mainnet_coinbases_rebuilt() {
    let (mut rebuilt, mut v5_from_nu6_3) = (0, 0);
    for coinbase in rows() {
        if coinbase.version == 4 || coinbase.ironwood.len() > 1 {
            continue;
        }
        let (height, extra) = coinbase_script_height(&coinbase.script_sig).unwrap();
        let mut builder = Builder::new_coinbase(coinbase.branch_id, height, extra).unwrap();
        assert!(builder.is_coinbase());
        if coinbase.version == 5 {
            // a miner still making version 5 transactions under NU6.3
            v5_from_nu6_3 += (builder.tx_version() == TxVersion::V6) as usize;
            builder.set_tx_version(TxVersion::V5);
        } else {
            assert_eq!(builder.tx_version(), TxVersion::V6);
        }
        builder.set_coinbase_sequence(coinbase.sequence).unwrap();
        for (amount, script) in &coinbase.outputs {
            builder.add_transparent_output(*amount, script).unwrap();
        }
        let total = subsidy::coinbase_output_total(height, coinbase.fees).unwrap();
        assert_eq!(builder.created_value(), Ok(total));
        assert_eq!(builder.fee(), Err(Error::Coinbase));
        // a wrong total is refused, and the transaction is not an ordinary
        // one
        let wrong = Builder::new_coinbase(coinbase.branch_id, height, extra).unwrap();
        assert_eq!(
            wrong.build_coinbase(&Provers::new(), total, &[0; 64]),
            Err(Error::FeeMismatch {
                stated: total,
                actual: 0
            })
        );
        let tx = builder
            .build_coinbase(&Provers::new(), total, &[0; 64])
            .unwrap();
        assert_eq!(tx.raw, coinbase.raw, "{height}");
        assert_eq!(tx.txid, coinbase.txid, "{height}");
        // without transparent inputs the shielded signature hash is the id
        let mut id = tx.txid;
        id.reverse();
        assert_eq!(tx.shielded_sighash, id);
        rebuilt += 1;
    }
    // fourteen of the fixture are version 5 or 6 and transparent only
    assert_eq!((rebuilt, v5_from_nu6_3), (14, 1));
}

/// What a coinbase builder refuses.
#[test]
fn coinbase_checks() {
    let key = SecpPrivateKey::from_bytes(&[7; 32]).unwrap();
    let script = p2pkh_script(&hash160(&key.public_key().serialize_compressed()));
    let coin = ZcashTxOut {
        amount: 5,
        script: &script,
    };
    assert_eq!(
        Builder::new_coinbase(branch::NU7, 0, &[]).err(),
        Some(Error::Tx(crate::Error::InvalidData))
    );
    assert_eq!(
        Builder::new_coinbase(branch::NU7, 3_600_000, &[0; 97]).err(),
        Some(Error::Tx(crate::Error::TooLarge))
    );
    assert!(Builder::new_coinbase(branch::NU7, 3_600_000, &[0; 96]).is_ok());

    let mut builder = Builder::new_coinbase(branch::NU7, 3_600_000, b"miner").unwrap();
    assert_eq!(
        builder.add_transparent_input(&key, [1; 32], 0, 0, coin),
        Err(Error::Coinbase)
    );
    assert_eq!(
        builder.add_transparent_input_external(107, SIGHASH_ALL, [1; 32], 0, 0, coin),
        Err(Error::Coinbase)
    );
    assert_eq!(
        builder.fund(FeeRule::Zip317, Change::Transparent(&script)),
        Err(Error::Coinbase)
    );
    assert_eq!(builder.created_value(), Ok(0));
    builder.add_transparent_output(100, &script).unwrap();
    assert_eq!(builder.created_value(), Ok(100));
    // a coinbase is one logical action of input, and its outputs
    assert_eq!(builder.logical_actions(), 1);
    let build = |builder: Builder<'_>| builder.build(&Provers::new(), 0, &[0; 64]);
    assert_eq!(
        build(Builder::new_coinbase(branch::NU7, 3_600_000, b"miner").unwrap()),
        Err(Error::Coinbase)
    );
    let tx = builder
        .build_coinbase(&Provers::new(), 100, &[0; 64])
        .unwrap();
    let mut inputs = [ZcashTxIn::default(); 1];
    let mut outputs = [ZcashTxOut::default(); 1];
    let parsed = ZcashTx::parse_into(&tx.raw, &mut inputs, &mut outputs).unwrap();
    assert!(parsed.is_coinbase());
    assert_eq!(parsed.coinbase_height(), Some(3_600_000));
    assert_eq!(parsed.expiry_height, 3_600_000);
    assert_eq!(parsed.version, TxVersion::V6);
    assert_eq!(parsed.inputs[0].sequence, u32::MAX);
    assert_eq!(parsed.inputs[0].script_sig, b"\x03\x80\xee\x36miner");

    // an ordinary builder is not a coinbase one
    let mut ordinary = Builder::new(branch::NU7, 3_600_040, 0);
    assert!(!ordinary.is_coinbase());
    assert_eq!(ordinary.set_coinbase_sequence(0), Err(Error::Coinbase));
    assert_eq!(ordinary.created_value(), Err(Error::Coinbase));
    ordinary.add_transparent_output(1, &script).unwrap();
    assert_eq!(
        ordinary.build_coinbase(&Provers::new(), 1, &[0; 64]),
        Err(Error::Coinbase)
    );
}

/// The coinbase script: the encodings of the heights.
#[test]
fn coinbase_scripts() {
    use crate::zcashtx::{coinbase_height_prefix, coinbase_script_sig_to_slice};
    let script = |height: u32, extra: &[u8]| {
        let mut out = [0u8; 100];
        coinbase_script_sig_to_slice(height, extra, &mut out).map(|n| out[..n].to_vec())
    };
    // the protocol specification: 0x50 + height up to 16, then the fewest
    // bytes of a signed little-endian number, with their length
    assert_eq!(script(1, &[]), Ok(vec![0x51, 0x00]));
    assert_eq!(script(16, &[]), Ok(vec![0x60, 0x00]));
    assert_eq!(script(16, &[9]), Ok(vec![0x60, 9]));
    assert_eq!(script(17, &[]), Ok(vec![0x01, 0x11]));
    assert_eq!(script(127, &[]), Ok(vec![0x01, 0x7f]));
    assert_eq!(script(128, &[]), Ok(vec![0x02, 0x80, 0x00]));
    assert_eq!(script(255, &[]), Ok(vec![0x02, 0xff, 0x00]));
    assert_eq!(script(256, &[]), Ok(vec![0x02, 0x00, 0x01]));
    assert_eq!(script(32_767, &[]), Ok(vec![0x02, 0xff, 0x7f]));
    assert_eq!(script(32_768, &[]), Ok(vec![0x03, 0x00, 0x80, 0x00]));
    assert_eq!(script(8_388_607, &[]), Ok(vec![0x03, 0xff, 0xff, 0x7f]));
    assert_eq!(
        script(8_388_608, &[]),
        Ok(vec![0x04, 0x00, 0x00, 0x80, 0x00])
    );
    assert_eq!(
        script(u32::MAX, &[]),
        Ok(vec![0x05, 0xff, 0xff, 0xff, 0xff, 0x00])
    );
    // as the chain has them (heights 1 687 104 and 3 560 136)
    assert_eq!(
        script(1_687_104, &[0]),
        Ok(vec![0x03, 0x40, 0xbe, 0x19, 0x00])
    );
    assert_eq!(
        script(3_560_136, &[0x04, 0xf0, 0x9f, 0xa6, 0x93]),
        Ok(hex::decode("03c8523604f09fa693").unwrap())
    );
    assert_eq!(script(0, &[]), Err(crate::Error::InvalidData));
    assert_eq!(script(17, &[0; 98]).map(|s| s.len()), Ok(100));
    assert_eq!(script(17, &[0; 99]), Err(crate::Error::TooLarge));
    assert_eq!(
        coinbase_script_sig_to_slice(17, &[], &mut [0u8; 1]),
        Err(crate::Error::BufferTooSmall)
    );
    assert_eq!(coinbase_height_prefix(0), None);
    // and back, for every length of encoding; only the shortest is one
    for height in [
        1,
        2,
        16,
        17,
        127,
        128,
        255,
        256,
        32_767,
        32_768,
        65_535,
        65_536,
        8_388_607,
        8_388_608,
        16_777_215,
        16_777_216,
        0x7fff_ffff,
        0x8000_0000,
        u32::MAX,
    ] {
        let s = script(height, b"x").unwrap();
        let (h, rest) = coinbase_script_height(&s).unwrap();
        assert_eq!((h, rest), (height, &b"x"[..]), "{height}");
    }
    for bad in [
        &[][..],
        &[0x51],
        &[0x00, 0x00],
        &[0x01, 0x10],
        &[0x02, 0x11, 0x00],
        &[0x02, 0x80],
        &[0x01, 0x80, 0x00],
        &[0x06, 1, 2, 3, 4, 5, 6],
        &[0x05, 0xff, 0xff, 0xff, 0xff, 0x01],
        &[0x4c, 0x01, 0x11],
        &[0x61, 0x00],
    ] {
        assert_eq!(coinbase_script_height(bad), None, "{bad:?}");
    }
    assert_eq!(coinbase_script_height(&[0x01; 101]), None);
}

/// The Ironwood outputs of the two shielded coinbases of the fixture are
/// decrypted with the all-zero outgoing viewing key, as consensus requires
/// they can be: notes of the Ironwood version, worth what the bundle
/// takes, in bundles that disable spends and are not padded.
#[cfg(feature = "zcash-orchard")]
#[test]
fn mainnet_shielded_coinbases_open_with_the_zero_key() {
    use crate::orchard::bundle::BundleRef;
    use crate::orchard::keys::OutgoingViewingKey;
    use crate::orchard::note::NoteVersion;
    use crate::orchard::note_encryption::try_output_recovery_with_ovk_versioned;
    let ovk = OutgoingViewingKey::from_bytes([0; 32]);
    let mut seen = Vec::new();
    for coinbase in rows() {
        if coinbase.ironwood.len() <= 1 {
            continue;
        }
        let bundle = BundleRef::parse_ironwood(&coinbase.ironwood)
            .unwrap()
            .unwrap();
        let flags = bundle.flags();
        assert!(!flags.spends_enabled() && flags.outputs_enabled());
        assert!(flags.cross_address_enabled());
        let mut total = 0;
        for action in bundle.actions() {
            let recover = |version| {
                try_output_recovery_with_ovk_versioned(
                    version,
                    &ovk,
                    &action.cv,
                    &action.output(),
                    &action.enc_ciphertext,
                    &action.out_ciphertext,
                )
            };
            // the note plaintext lead byte must be 0x03 (ZIP 258)
            assert!(recover(NoteVersion::V2).is_none());
            let (note, _) = recover(NoteVersion::V3).expect("opens with the zero key");
            assert_eq!(note.version(), NoteVersion::V3);
            total += note.value();
        }
        assert_eq!(total, coinbase.shielded);
        assert_eq!(bundle.value_balance(), -(total as i64));
        seen.push((coinbase.height, bundle.action_count(), total));
    }
    assert_eq!(
        seen,
        [(3_543_404, 1, 125_271_960), (3_560_137, 2, 41_680_668)]
    );
}
