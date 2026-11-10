//! Version 6 transactions (ZIP 229) against the main network and the
//! reference implementation.
//!
//! `testdata/mainnet_v6.json` indexes nine transactions of the main
//! network, mined under NU6.3 (from height 3 428 143) and NU7 (from
//! 3 543 405): `testdata/mainnet_tx_*.hex` and, for two that the Orchard
//! tests already had, `../orchard/testdata/mainnet_tx_*.hex`. Between them
//! they have every part a version 6 transaction can have: a coinbase,
//! transparent inputs and outputs, Sapling spends and outputs, an Orchard
//! bundle, Ironwood bundles of one and two actions; one is a version 5
//! transaction mined under NU7.
//!
//! The raw transactions, their ids and heights are those of a public
//! explorer (`api.mainnet.cipherscan.app`), and the outputs their
//! transparent inputs spend were read from the transactions that made
//! them. The other expected values (the authorizing data commitment, the
//! signature hash of the shielded parts and of each transparent input)
//! are what `zcash_primitives` 0.31.0 computes, by a program outside this
//! repository which also had that crate, `sapling-crypto` 0.9.0 and
//! `orchard` 0.16.0 parse each transaction, serialize it back to the same
//! bytes, and verify every signature and every proof in it: all valid.

use crate::crypto::secp256k1::{SecpPublicKey, parse_der_signature};
use crate::hash::hash160;
use crate::prelude::*;
use crate::pushbytes::parse_push_bytes;
use crate::zcashtx::*;
use crate::{Error, PubKey, generate_script};

/// A transaction of the index.
struct Row {
    raw: Vec<u8>,
    txid: [u8; 32],
    version: TxVersion,
    branch: u32,
    coinbase: bool,
    /// The outputs the transparent inputs spend: amount and scriptPubKey.
    prevouts: Vec<(u64, Vec<u8>)>,
    auth_digest: [u8; 32],
    shielded_sighash: [u8; 32],
    input_sighashes: Vec<[u8; 32]>,
    /// For each transparent input, its signature hash for the hash types
    /// ALL, NONE, SINGLE, then the same with ANYONECANPAY (`None` where
    /// SINGLE has no output to sign).
    input_sighashes_by_type: Vec<Vec<Option<[u8; 32]>>>,
    n_inputs: usize,
    n_outputs: usize,
    /// Spends, outputs and value balance.
    sapling: Option<(usize, usize, i64)>,
    /// Actions, flags and value balance.
    orchard: Option<(usize, u8, i64)>,
    ironwood: Option<(usize, u8, i64)>,
}

fn raw_hex(txid: &str) -> &'static str {
    match &txid[..8] {
        "33813831" => include_str!("testdata/mainnet_tx_33813831.hex"),
        "e39eab2b" => include_str!("../orchard/testdata/mainnet_tx_e39eab2b.hex"),
        "cce28826" => include_str!("testdata/mainnet_tx_cce28826.hex"),
        "57d7d945" => include_str!("testdata/mainnet_tx_57d7d945.hex"),
        "2b39d3da" => include_str!("testdata/mainnet_tx_2b39d3da.hex"),
        "a4f6190d" => include_str!("testdata/mainnet_tx_a4f6190d.hex"),
        "2be7cf25" => include_str!("../orchard/testdata/mainnet_tx_2be7cf25.hex"),
        "cb69d2f5" => include_str!("testdata/mainnet_tx_cb69d2f5.hex"),
        "fa1979af" => include_str!("testdata/mainnet_tx_fa1979af.hex"),
        other => panic!("no fixture {other}"),
    }
}

fn hex32(v: &serde_json::Value) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(v.as_str().unwrap(), &mut out).unwrap();
    out
}

fn rows() -> Vec<Row> {
    let index: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("testdata/mainnet_v6.json")).unwrap();
    let count = |v: &serde_json::Value| v.as_u64().unwrap() as usize;
    let pool = |v: &serde_json::Value| {
        v.as_object().map(|o| {
            (
                count(&o["actions"]),
                o["flags"].as_u64().unwrap() as u8,
                o["value_balance"].as_i64().unwrap(),
            )
        })
    };
    index
        .iter()
        .map(|row| {
            let txid = row["txid"].as_str().unwrap();
            let height = row["height"].as_u64().unwrap();
            // the upgrade in force at the height (ZIPs 258 and 259)
            let branch = match row["upgrade"].as_str().unwrap() {
                "Nu6_3" => {
                    assert!((3_428_143..3_543_405).contains(&height));
                    branch::NU6_3
                }
                "Nu7" => {
                    assert!(height >= 3_543_405);
                    branch::NU7
                }
                other => panic!("{other}"),
            };
            Row {
                raw: hex::decode(raw_hex(txid).trim()).unwrap(),
                txid: hex32(&row["txid"]),
                version: match row["version"].as_u64().unwrap() {
                    5 => TxVersion::V5,
                    6 => TxVersion::V6,
                    other => panic!("{other}"),
                },
                branch,
                coinbase: row["coinbase"].as_bool().unwrap(),
                prevouts: row["prevouts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| {
                        (
                            p[0].as_u64().unwrap(),
                            hex::decode(p[1].as_str().unwrap()).unwrap(),
                        )
                    })
                    .collect(),
                auth_digest: hex32(&row["auth_digest"]),
                shielded_sighash: hex32(&row["shielded_sighash"]),
                input_sighashes: row["input_sighashes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(hex32)
                    .collect(),
                input_sighashes_by_type: row["input_sighashes_by_type"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|types| {
                        let types = types.as_array().unwrap();
                        assert_eq!(types.len(), 6);
                        types.iter().map(|h| h.as_str().map(|_| hex32(h))).collect()
                    })
                    .collect(),
                n_inputs: count(&row["inputs"]),
                n_outputs: count(&row["outputs"]),
                sapling: row["sapling"].as_object().map(|o| {
                    (
                        count(&o["spends"]),
                        count(&o["outputs"]),
                        o["value_balance"].as_i64().unwrap(),
                    )
                }),
                orchard: pool(&row["orchard"]),
                ironwood: pool(&row["ironwood"]),
            }
        })
        .collect()
}

fn parse<'a>(
    raw: &'a [u8],
    inputs: &'a mut [ZcashTxIn<'a>],
    outputs: &'a mut [ZcashTxOut<'a>],
) -> ZcashTx<'a> {
    ZcashTx::parse_into(raw, inputs, outputs).unwrap()
}

/// Every transaction of the index: the round trip, the id of the chain,
/// the digests of the reference, and every signature under them.
#[test]
fn mainnet_transactions() {
    let rows = rows();
    assert_eq!(rows.len(), 9);
    for row in &rows {
        let name = hex::encode(&row.txid[..4]);
        let mut inputs = [ZcashTxIn::default(); 2];
        let mut outputs = [ZcashTxOut::default(); 4];
        assert_eq!(tx_format(&row.raw).unwrap().tx_version(), Some(row.version));
        let tx = parse(&row.raw, &mut inputs, &mut outputs);
        assert_eq!(tx.version, row.version, "{name}");
        assert_eq!(tx.consensus_branch_id, row.branch, "{name}");
        assert_eq!(tx.version.valid_in_branch(row.branch), Some(true));
        assert_eq!(
            (tx.inputs.len(), tx.outputs.len()),
            (row.n_inputs, row.n_outputs)
        );
        assert_eq!(tx.serialize(), row.raw, "{name}");
        assert_eq!(tx.serialized_len(), row.raw.len());
        assert_eq!(tx.txid().unwrap(), row.txid, "{name}");
        assert_eq!(tx.auth_digest().unwrap(), row.auth_digest, "{name}");

        let prevouts: Vec<ZcashTxOut<'_>> = row
            .prevouts
            .iter()
            .map(|(amount, script)| ZcashTxOut {
                amount: *amount,
                script,
            })
            .collect();
        let shielded = tx.sighash(None, SIGHASH_ALL, &prevouts).unwrap();
        assert_eq!(shielded, row.shielded_sighash, "{name}");
        let mut id = row.txid;
        id.reverse();
        // with nothing transparent spent, that is the id
        assert_eq!(shielded == id, row.prevouts.is_empty(), "{name}");
        if row.coinbase {
            assert_eq!(tx.inputs[0].txid, [0; 32]);
            assert_eq!(tx.inputs[0].vout, u32::MAX);
        } else {
            assert_eq!(row.prevouts.len(), row.n_inputs);
        }

        // the transparent inputs: P2PKH, signed with SIGHASH_ALL
        for (i, expected) in row.input_sighashes.iter().enumerate() {
            let sighash = tx.sighash(Some(i), SIGHASH_ALL, &prevouts).unwrap();
            assert_eq!(&sighash, expected, "{name} input {i}");
            let script_sig = tx.inputs[i].script_sig;
            let (sig, n) = parse_push_bytes(script_sig).unwrap();
            let (pubkey, m) = parse_push_bytes(&script_sig[n..]).unwrap();
            assert_eq!(n + m, script_sig.len());
            let script = &row.prevouts[i].1;
            assert_eq!(script.len(), 25);
            assert_eq!(script[3..23], hash160(pubkey));
            let (hash_type, der) = sig.split_last().unwrap();
            assert_eq!(*hash_type, SIGHASH_ALL);
            let (r, s) = parse_der_signature(der).unwrap();
            let public = SecpPublicKey::from_sec1(pubkey).unwrap();
            assert!(public.verify(&sighash, &r, &s), "{name} input {i}");
            assert!(!public.verify(&shielded, &r, &s));

            // the digests of the other hash types
            let types = [
                SIGHASH_ALL,
                SIGHASH_NONE,
                SIGHASH_SINGLE,
                SIGHASH_ALL | SIGHASH_ANYONECANPAY,
                SIGHASH_NONE | SIGHASH_ANYONECANPAY,
                SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
            ];
            let by_type = &row.input_sighashes_by_type[i];
            assert_eq!(by_type[0], Some(sighash));
            let mut seen = Vec::new();
            for (hash_type, expected) in types.into_iter().zip(by_type) {
                let digest = tx.sighash(Some(i), hash_type, &prevouts);
                match expected {
                    Some(expected) => assert_eq!(digest, Ok(*expected), "{name} {hash_type:#x}"),
                    // SINGLE without an output at the index of the input
                    None => assert_eq!(digest, Err(Error::OutputIndex)),
                }
                // each type has its digest
                if digest.is_ok() {
                    assert!(!seen.contains(&digest));
                    seen.push(digest);
                }
            }
        }
        assert_eq!(row.input_sighashes_by_type.len(), row.input_sighashes.len());

        shielded_parts(row, &tx, &shielded, &name);

        // the fee these pay is the conventional one (those with
        // transparent inputs or without any transparent part: the others
        // keep or take transparent value this test does not follow)
        let pools = row.sapling.map_or(0, |s| s.2)
            + row.orchard.map_or(0, |o| o.2)
            + row.ironwood.map_or(0, |o| o.2);
        let spent: u64 = row.prevouts.iter().map(|p| p.0).sum();
        let created: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        let fee = spent as i64 + pools - created as i64;
        if !row.coinbase {
            assert!(fee >= 0, "{name}");
            if row.sapling.is_some() || row.ironwood.is_some() {
                assert_eq!(tx.conventional_fee(), Ok(fee as u64), "{name}");
            }
        }
    }
}

/// The bundles of a transaction: their shape, and their signatures and
/// proofs as far as the features built allow.
#[allow(unused_variables)]
fn shielded_parts(row: &Row, tx: &ZcashTx<'_>, sighash: &[u8; 32], name: &str) {
    assert_eq!(tx.sapling.is_empty(), row.sapling.is_none(), "{name}");
    assert_eq!(tx.orchard.is_empty(), row.orchard.is_none(), "{name}");
    assert_eq!(tx.ironwood.is_empty(), row.ironwood.is_none(), "{name}");
    #[cfg(feature = "zcash-sapling")]
    {
        let bundle = tx.sapling_bundle().unwrap();
        let (spends, outputs, balance) = row.sapling.unwrap_or((0, 0, 0));
        assert_eq!((bundle.n_spends(), bundle.n_outputs()), (spends, outputs));
        assert_eq!(bundle.value_balance(), balance);
        if row.sapling.is_some() {
            assert_eq!(bundle.verify(sighash), Ok(()), "{name}");
            assert!(bundle.verify(&[0x55; 32]).is_err());
            #[cfg(all(feature = "std", feature = "zcash-sapling-prover"))]
            {
                use crate::sapling::prover::{
                    OutputVerifyingKey, SpendVerifyingKey, verify_bundle_proofs,
                };
                verify_bundle_proofs(
                    &bundle,
                    &SpendVerifyingKey::mainnet(),
                    &OutputVerifyingKey::mainnet(),
                )
                .unwrap();
            }
        }
    }
    #[cfg(feature = "zcash-orchard")]
    {
        use crate::orchard::bundle::Flags;
        let bundles = [
            (tx.orchard_bundle().unwrap(), row.orchard),
            (tx.ironwood_bundle().unwrap(), row.ironwood),
        ];
        for (pool, (bundle, expected)) in bundles.into_iter().enumerate() {
            assert_eq!(bundle.is_some(), expected.is_some(), "{name}");
            let (Some(bundle), Some((actions, flags, balance))) = (bundle, expected) else {
                continue;
            };
            assert_eq!(bundle.action_count(), actions);
            assert_eq!(bundle.flags().to_byte(), flags);
            assert_eq!(bundle.value_balance(), balance);
            // Orchard actions are restricted from NU6.3; the Ironwood
            // bundles of the chain are not
            assert_eq!(bundle.flags().cross_address_enabled(), pool == 1);
            assert_eq!(
                bundle.flags(),
                [Flags::ENABLED, Flags::IRONWOOD_ENABLED][pool]
            );
            // from NU6.3 no value enters the Orchard pool
            assert!(pool == 1 || balance >= 0);
            assert_eq!(bundle.verify_signatures(sighash), Ok(()), "{name}");
            assert!(bundle.verify_signatures(&[0x55; 32]).is_err());
            #[cfg(feature = "zcash-orchard-prover")]
            {
                use crate::orchard::circuit::{CircuitVersion, VerifyingKey};
                assert_eq!(
                    CircuitVersion::for_branch_id(row.branch),
                    Some(CircuitVersion::PostNu6_3)
                );
                for vk in VerifyingKey::embedded_all() {
                    assert_eq!(
                        bundle.verify_proof(&vk).is_ok(),
                        vk.version() == CircuitVersion::PostNu6_3,
                        "{name} {:?}",
                        vk.version()
                    );
                }
            }
        }
    }
}

/// The notes of the Ironwood pool are of the plaintext version of ZIP
/// 2005, which no key of this test can read: what can be checked of the
/// chain is that the bundles are told apart by their place alone.
#[cfg(feature = "zcash-orchard")]
#[test]
fn pools_are_told_apart_by_place() {
    use crate::orchard::bundle::BundleRef;
    for row in rows() {
        let mut inputs = [ZcashTxIn::default(); 2];
        let mut outputs = [ZcashTxOut::default(); 4];
        let tx = parse(&row.raw, &mut inputs, &mut outputs);
        if row.ironwood.is_some() {
            // an Ironwood bundle of the chain is not an Orchard one
            assert_eq!(
                BundleRef::parse(tx.ironwood).err(),
                Some(crate::orchard::Error::InvalidFlags)
            );
            // and swapping the bundles is another transaction, or none
            let swapped = ZcashTx {
                orchard: tx.ironwood,
                ironwood: tx.orchard,
                ..tx
            };
            assert_eq!(swapped.txid(), Err(Error::InvalidData));
        }
        if row.orchard.is_some() && row.version == TxVersion::V6 {
            let moved = ZcashTx {
                orchard: &[],
                ironwood: tx.orchard,
                ..tx
            };
            assert_ne!(moved.txid().unwrap(), row.txid);
            assert!(moved.ironwood_bundle().unwrap().is_some());
        }
    }
}

/// The empty version 6 transaction of the tests of `zcash_primitives`
/// 0.31.0 (`nu7_v6_encoding_and_digests_are_feature_independent`), whose
/// digest its authors computed independently.
#[test]
fn empty_v6_transaction() {
    let encoded = hex::decode("0600008098b684d8d90a19770000000001000000000000000000").unwrap();
    let mut digest = [0u8; 32];
    hex::decode_to_slice(
        "78296c68a370c2e1f058d997c81c7b011c4562c52fc5ca2994ad59cd179fbe9e",
        &mut digest,
    )
    .unwrap();
    let tx = ZcashTx {
        version: TxVersion::V6,
        consensus_branch_id: branch::NU7,
        expiry_height: 1,
        ..Default::default()
    };
    assert_eq!(tx.serialize(), encoded);
    assert_eq!(tx.sighash(None, SIGHASH_ALL, &[]).unwrap(), digest);
    digest.reverse();
    assert_eq!(tx.txid().unwrap(), digest);
    let parsed = ZcashTx::parse_into(&encoded, &mut [], &mut []).unwrap();
    assert_eq!(parsed.version, TxVersion::V6);
    assert_eq!(parsed.txid().unwrap(), digest);
    assert!(parsed.ironwood.is_empty());
    // the same fields in version 5 are another transaction
    let v5 = ZcashTx {
        version: TxVersion::V5,
        ..tx
    };
    assert_eq!(v5.serialized_len(), encoded.len() - 1);
    assert_ne!(v5.txid().unwrap(), digest);
}

/// The authorizing data commitments of the version 5 transactions of the
/// ZIP-244 test vectors (`zcash-test-vectors`, `zip_0244.json`).
#[test]
fn v5_auth_digests() {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../../testdata/zip_0244.json")).unwrap();
    assert_eq!(rows.len(), 12);
    for row in &rows[2..] {
        let raw = hex::decode(row[0].as_str().unwrap()).unwrap();
        let mut inputs = [ZcashTxIn::default(); 8];
        let mut outputs = [ZcashTxOut::default(); 8];
        let tx = ZcashTx::parse_into(&raw, &mut inputs, &mut outputs).unwrap();
        assert_eq!(tx.version, TxVersion::V5);
        assert_eq!(tx.auth_digest().unwrap(), hex32(&row[2]));
        // as a version 6 transaction it would have another
        let v6 = ZcashTx {
            version: TxVersion::V6,
            ..tx
        };
        assert_ne!(v6.auth_digest().unwrap(), hex32(&row[2]));
    }
}

#[test]
fn versions_and_formats() {
    // what wallets use, and what consensus accepts (ZIPs 229, 258, 259;
    // `TxVersion::{suggested_for_branch, valid_in_branch}` of the reference)
    let table = [
        (branch::NU5, TxVersion::V5, false),
        (branch::NU6, TxVersion::V5, false),
        (branch::NU6_1, TxVersion::V5, false),
        (branch::NU6_2, TxVersion::V5, false),
        (branch::NU6_3, TxVersion::V6, true),
        (branch::NU7, TxVersion::V6, true),
    ];
    for (branch_id, suggested, v6) in table {
        assert_eq!(TxVersion::for_branch_id(branch_id), Some(suggested));
        assert_eq!(TxVersion::V5.valid_in_branch(branch_id), Some(true));
        assert_eq!(TxVersion::V6.valid_in_branch(branch_id), Some(v6));
    }
    // Canopy, and a branch that does not exist
    for unknown in [0xe9ff_75a6, 0x1234_5678] {
        assert_eq!(TxVersion::for_branch_id(unknown), None);
        assert_eq!(TxVersion::V5.valid_in_branch(unknown), None);
    }
    assert_eq!(branch::NU7, 0x7719_0ad9);
    assert_eq!(TxVersion::default(), TxVersion::V5);
    assert_eq!(ZcashTx::default().version, TxVersion::V5);
    assert_eq!(TxVersion::V6.header(), 0x8000_0006);
    assert_eq!(TxVersion::V6.version_group_id(), 0xd884_b698);

    // formats by header
    let header = |version: u32, group: u32| {
        let mut bytes = version.to_le_bytes().to_vec();
        bytes.extend_from_slice(&group.to_le_bytes());
        bytes
    };
    assert_eq!(
        tx_format(&header(0x8000_0006, 0xd884_b698)),
        Ok(TxFormat::V6)
    );
    assert_eq!(
        tx_format(&header(0x8000_0005, 0x26a7_270a)),
        Ok(TxFormat::V5)
    );
    assert_eq!(
        tx_format(&header(0x8000_0004, 0x892f_2085)),
        Ok(TxFormat::V4)
    );
    assert_eq!(
        tx_format(&header(0x8000_0003, 0x03c4_8270)),
        Ok(TxFormat::V3)
    );
    assert_eq!(tx_format(&[2, 0, 0, 0]), Ok(TxFormat::Legacy(2)));
    assert_eq!(TxFormat::V4.tx_version(), None);
    assert_eq!(TxFormat::V6.tx_version(), Some(TxVersion::V6));
    // a version with the group id of another, no version, too short
    for bad in [
        header(0x8000_0006, 0x26a7_270a),
        header(0x8000_0005, 0xd884_b698),
        header(0x8000_0007, 0xd884_b698),
        header(0, 0),
    ] {
        assert_eq!(tx_format(&bad), Err(Error::UnsupportedTxType));
        assert_eq!(
            ZcashTx::parse_into(&bad, &mut [], &mut []).map(|_| ()),
            Err(Error::UnsupportedTxType)
        );
    }
    assert_eq!(tx_format(&[6, 0, 0]), Err(Error::UnexpectedEof));
    assert_eq!(tx_format(&[6, 0, 0, 0x80, 1]), Err(Error::UnexpectedEof));

    // a real version 4 transaction is told, and left to the Sapling module
    let v4 =
        hex::decode(include_str!("../sapling/testdata/mainnet_v4_sapling_tx.hex").trim()).unwrap();
    assert_eq!(tx_format(&v4), Ok(TxFormat::V4));
    assert_eq!(
        ZcashTx::parse_into(&v4, &mut [], &mut []).map(|_| ()),
        Err(Error::UnsupportedTxType)
    );
}

/// The parser on what is not a transaction: truncations and extensions of
/// a real one, and its counts and flags tampered with.
#[test]
fn malformed_v6() {
    let rows = rows();
    let parse = |raw: &[u8]| {
        let mut inputs = [ZcashTxIn::default(); 2];
        let mut outputs = [ZcashTxOut::default(); 4];
        ZcashTx::parse_into(raw, &mut inputs, &mut outputs).map(|_| ())
    };
    for row in &rows {
        // every proper prefix is an error (most are too short; cutting at
        // the Ironwood count leaves a version 6 transaction without it)
        let step = (row.raw.len() / 300).max(1);
        for len in (0..row.raw.len()).step_by(step) {
            assert!(parse(&row.raw[..len]).is_err(), "{len}");
        }
        assert_eq!(
            parse(&row.raw[..row.raw.len() - 1]),
            Err(Error::UnexpectedEof)
        );
        let mut long = row.raw.clone();
        long.push(0);
        assert_eq!(parse(&long), Err(Error::TrailingData));
    }

    // the transparent-only transaction: its last three bytes are the
    // empty Sapling (two counts), Orchard and Ironwood bundles
    let small = rows.iter().find(|r| r.txid[0] == 0xcb).unwrap();
    let n = small.raw.len();
    assert_eq!(small.raw[n - 4..], [0, 0, 0, 0]);
    // as a version 5 transaction, it has one byte too many
    let mut v5 = small.raw.clone();
    v5[..8].copy_from_slice(&[5, 0, 0, 0x80, 0x0a, 0x27, 0xa7, 0x26]);
    assert_eq!(parse(&v5), Err(Error::TrailingData));
    assert_eq!(parse(&v5[..n - 1]), Ok(()));
    // counts must be in their shortest form
    let mut padded = small.raw[..n - 1].to_vec();
    padded.extend_from_slice(&[0xfd, 0, 0]);
    assert_eq!(parse(&padded), Err(Error::NonCanonical));
    // a count without its actions
    let mut claims = small.raw[..n - 1].to_vec();
    claims.push(1);
    assert_eq!(parse(&claims), Err(Error::UnexpectedEof));
    claims.extend_from_slice(&[0xff; 9]);
    assert_eq!(parse(&claims), Err(Error::UnexpectedEof));

    // flags: the Orchard bundle has two, in version 6 too; the Ironwood
    // bundle three; a value balance is within the money supply
    let both = rows
        .iter()
        .find(|r| r.txid[0] == 0x2b && r.txid[1] == 0xe7)
        .unwrap();
    let mut inputs = [ZcashTxIn::default(); 2];
    let mut outputs = [ZcashTxOut::default(); 4];
    let tx = ZcashTx::parse_into(&both.raw, &mut inputs, &mut outputs).unwrap();
    let orchard_at = both.raw.len() - tx.ironwood.len() - tx.orchard.len();
    let ironwood_at = both.raw.len() - tx.ironwood.len();
    let orchard_flags = orchard_at + 1 + 2 * 820;
    let ironwood_flags = ironwood_at + 1 + 820;
    assert_eq!(both.raw[orchard_flags], 0b011);
    assert_eq!(both.raw[ironwood_flags], 0b111);
    let tamper = |at: usize, value: u8| {
        let mut raw = both.raw.clone();
        raw[at] = value;
        parse(&raw)
    };
    assert_eq!(tamper(orchard_flags, 0b111), Err(Error::InvalidData));
    assert_eq!(tamper(orchard_flags, 0b1011), Err(Error::InvalidData));
    assert_eq!(tamper(ironwood_flags, 0b1111), Err(Error::InvalidData));
    assert_eq!(tamper(ironwood_flags, 0x87), Err(Error::InvalidData));
    // (flags a parser accepts: the proof would not verify)
    assert_eq!(tamper(ironwood_flags, 0b011), Ok(()));
    assert_eq!(tamper(orchard_flags, 0b001), Ok(()));
    for at in [orchard_flags, ironwood_flags] {
        // the value balance follows the flags: 2^63 - 1 and -2^63
        assert_eq!(tamper(at + 8, 0x7f), Err(Error::InvalidAmount));
        assert_eq!(tamper(at + 8, 0x80), Err(Error::InvalidAmount));
    }

    // a version 5 transaction has no Ironwood bundle
    let stray = ZcashTx {
        version: TxVersion::V5,
        ..tx
    };
    assert_eq!(stray.txid(), Err(Error::InvalidData));
    assert_eq!(stray.auth_digest(), Err(Error::InvalidData));
    assert_eq!(
        stray.sighash(None, SIGHASH_ALL, &[]),
        Err(Error::InvalidData)
    );
    assert_eq!(stray.logical_actions(), Err(Error::InvalidData));
    #[cfg(feature = "zcash-orchard")]
    assert_eq!(stray.ironwood_bundle(), Err(Error::InvalidData));
    // and its serialization none
    assert_eq!(stray.serialized_len(), both.raw.len() - tx.ironwood.len());
}

/// What the move of the anchors does (ZIP 229): in version 6 an anchor is
/// authorizing data, which the transaction id and the signature hashes do
/// not cover; in version 5 it is covered by all.
#[test]
fn anchors_are_authorizing_data_in_v6() {
    let rows = rows();
    for row in rows.iter().filter(|r| r.version == TxVersion::V6) {
        let mut inputs = [ZcashTxIn::default(); 2];
        let mut outputs = [ZcashTxOut::default(); 4];
        let tx = parse(&row.raw, &mut inputs, &mut outputs);
        let mut changed = 0;
        // the id of the same fields as a version 5 transaction, which
        // exists when there is no Ironwood bundle
        let as_v5 = |tx: ZcashTx<'_>| {
            ZcashTx {
                version: TxVersion::V5,
                ..tx
            }
            .txid()
        };
        let v5_id = as_v5(tx);
        assert_eq!(v5_id.is_ok(), row.ironwood.is_none());
        let mut check = |tx: ZcashTx<'_>| {
            assert_eq!(tx.txid().unwrap(), row.txid);
            assert_ne!(tx.auth_digest().unwrap(), row.auth_digest);
            // in version 5 the anchor is in the id
            if let Ok(id) = v5_id {
                assert_ne!(as_v5(tx).unwrap(), id);
            }
            changed += 1;
        };
        if let Some((spends, outputs, _)) = row.sapling.filter(|s| s.0 > 0) {
            // the anchor follows the descriptions and the value balance
            let at = 1 + spends * 96 + 1 + outputs * 756 + 8;
            let mut sapling = tx.sapling.to_vec();
            sapling[at] ^= 1;
            check(ZcashTx {
                sapling: &sapling,
                ..tx
            });
        }
        if let Some((actions, _, _)) = row.orchard {
            let mut orchard = tx.orchard.to_vec();
            orchard[1 + actions * 820 + 9] ^= 1;
            check(ZcashTx {
                orchard: &orchard,
                ..tx
            });
        }
        if let Some((actions, _, _)) = row.ironwood {
            let mut ironwood = tx.ironwood.to_vec();
            ironwood[1 + actions * 820 + 9] ^= 1;
            check(ZcashTx {
                ironwood: &ironwood,
                ..tx
            });
        }
        let anchors = row.sapling.is_some_and(|s| s.0 > 0) as usize
            + row.orchard.is_some() as usize
            + row.ironwood.is_some() as usize;
        assert_eq!(changed, anchors);
    }
}

/// Signing the transparent input of a version 6 transaction: the
/// signature is over the version 6 digests.
#[test]
fn sign_v6() {
    let key = crate::crypto::secp256k1::SecpPrivateKey::from_bytes(&[7u8; 32]).unwrap();
    let mine = generate_script(&PubKey::Secp256k1(key.public_key()), "p2pkh").unwrap();
    let inputs = [ZcashTxIn {
        txid: [0x11; 32],
        vout: 1,
        sequence: u32::MAX,
        ..Default::default()
    }];
    let outputs = [ZcashTxOut {
        amount: 90_000,
        script: &mine,
    }];
    let prevouts = [ZcashTxOut {
        amount: 100_000,
        script: &mine,
    }];
    let v6 = ZcashTx {
        version: TxVersion::V6,
        consensus_branch_id: branch::NU7,
        expiry_height: 3_600_000,
        inputs: &inputs,
        outputs: &outputs,
        ..Default::default()
    };
    let v5 = ZcashTx {
        version: TxVersion::V5,
        ..v6
    };
    let raw = v6.sign(&[&key], &prevouts).unwrap();
    assert_eq!(raw[..8], [6, 0, 0, 0x80, 0x98, 0xb6, 0x84, 0xd8]);
    // it ends with four empty bundles, one more than in version 5
    assert_eq!(v6.serialized_len(), v5.serialized_len() + 1);
    assert_eq!(raw[raw.len() - 5..], [0xac, 0, 0, 0, 0]);
    let mut ins = [ZcashTxIn::default(); 1];
    let mut outs = [ZcashTxOut::default(); 1];
    let parsed = ZcashTx::parse_into(&raw, &mut ins, &mut outs).unwrap();
    assert_eq!(parsed.version, TxVersion::V6);
    assert_eq!(parsed.txid().unwrap(), v6.txid().unwrap());
    assert_ne!(parsed.txid().unwrap(), v5.txid().unwrap());
    let sighash = parsed.sighash(Some(0), SIGHASH_ALL, &prevouts).unwrap();
    assert_ne!(
        sighash,
        v5.sighash(Some(0), SIGHASH_ALL, &prevouts).unwrap()
    );
    let (sig, n) = parse_push_bytes(parsed.inputs[0].script_sig).unwrap();
    let (pubkey, _) = parse_push_bytes(&parsed.inputs[0].script_sig[n..]).unwrap();
    let (r, s) = parse_der_signature(&sig[..sig.len() - 1]).unwrap();
    assert!(
        SecpPublicKey::from_sec1(pubkey)
            .unwrap()
            .verify(&sighash, &r, &s)
    );
    assert_eq!(parsed.conventional_fee(), Ok(10_000));
}
