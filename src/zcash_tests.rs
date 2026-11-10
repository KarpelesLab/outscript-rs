//! ZIP-244 known answers (`zcash-test-vectors/test-vectors/json/zip_0244.json`)
//! for [`zcashtx`](crate::zcashtx): transaction ids and every signature
//! digest of ten random v5 transactions, each carrying Sapling or Orchard
//! bundles alongside its transparent parts. Plus a signing round trip.

use crate::crypto::secp256k1::{SecpPrivateKey, parse_der_signature};
use crate::prelude::*;
use crate::pushbytes::parse_push_bytes;
use crate::zcashtx::*;
use crate::{Error, PubKey, generate_script};

struct Vector {
    tx: Vec<u8>,
    txid: [u8; 32],
    amounts: Vec<u64>,
    script_pubkeys: Vec<Vec<u8>>,
    transparent_input: Option<usize>,
    sighash_shielded: [u8; 32],
    /// By hash type: ALL, NONE, SINGLE, then the same with ANYONECANPAY.
    sighashes: [Option<[u8; 32]>; 6],
}

fn vectors() -> Vec<Vector> {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../testdata/zip_0244.json")).unwrap();
    let hex32 = |v: &serde_json::Value| -> Option<[u8; 32]> {
        let s = v.as_str()?;
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).unwrap();
        Some(out)
    };
    rows[2..]
        .iter()
        .map(|row| {
            let f = row.as_array().unwrap();
            Vector {
                tx: hex::decode(f[0].as_str().unwrap()).unwrap(),
                txid: hex32(&f[1]).unwrap(),
                amounts: f[3]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| a.as_u64().unwrap())
                    .collect(),
                script_pubkeys: f[4]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| hex::decode(s.as_str().unwrap()).unwrap())
                    .collect(),
                transparent_input: f[5].as_u64().map(|i| i as usize),
                sighash_shielded: hex32(&f[6]).unwrap(),
                sighashes: [
                    hex32(&f[7]),
                    hex32(&f[8]),
                    hex32(&f[9]),
                    hex32(&f[10]),
                    hex32(&f[11]),
                    hex32(&f[12]),
                ],
            }
        })
        .collect()
}

#[test]
fn zip244_vectors() {
    let vectors = vectors();
    assert_eq!(vectors.len(), 10);
    let mut with_input = 0;
    for (i, v) in vectors.iter().enumerate() {
        let mut inputs = [ZcashTxIn::default(); 8];
        let mut outputs = [ZcashTxOut::default(); 8];
        let tx = ZcashTx::parse_into(&v.tx, &mut inputs, &mut outputs).unwrap();
        assert_eq!(tx.consensus_branch_id, branch::NU5);
        assert_eq!(tx.serialize(), v.tx, "vector {i}: serialization");
        assert_eq!(tx.serialized_len(), v.tx.len());

        let mut txid = tx.txid().unwrap();
        txid.reverse();
        assert_eq!(txid, v.txid, "vector {i}: txid");

        let prevouts: Vec<ZcashTxOut<'_>> = v
            .amounts
            .iter()
            .zip(&v.script_pubkeys)
            .map(|(&amount, script)| ZcashTxOut { amount, script })
            .collect();
        // coinbase transactions spend nothing, and have no amounts
        let expected_prevouts = if v.amounts.is_empty() {
            0
        } else {
            tx.inputs.len()
        };
        assert_eq!(prevouts.len(), expected_prevouts);
        assert_eq!(
            tx.sighash(None, SIGHASH_ALL, &prevouts).unwrap(),
            v.sighash_shielded,
            "vector {i}: shielded sighash"
        );

        let Some(index) = v.transparent_input else {
            // no transparent input to sign for: none, or a coinbase
            if tx.inputs.is_empty() {
                assert_eq!(
                    tx.sighash(Some(0), SIGHASH_ALL, &prevouts),
                    Err(Error::InputIndex)
                );
            } else {
                assert_eq!(tx.inputs[0].txid, [0; 32]);
                assert_eq!(tx.inputs[0].vout, u32::MAX);
            }
            continue;
        };
        with_input += 1;
        let hash_types = [
            SIGHASH_ALL,
            SIGHASH_NONE,
            SIGHASH_SINGLE,
            SIGHASH_ALL | SIGHASH_ANYONECANPAY,
            SIGHASH_NONE | SIGHASH_ANYONECANPAY,
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        ];
        for (hash_type, expected) in hash_types.into_iter().zip(v.sighashes) {
            let got = tx.sighash(Some(index), hash_type, &prevouts);
            match expected {
                Some(expected) => {
                    assert_eq!(got, Ok(expected), "vector {i}: hash type {hash_type:#x}")
                }
                // SINGLE with no output at the input's index is not allowed
                None => assert_eq!(got, Err(Error::OutputIndex), "vector {i}: {hash_type:#x}"),
            }
            if hash_type & SIGHASH_ANYONECANPAY != 0 && expected.is_some() {
                // only the spent output of this input matters
                assert_eq!(tx.sighash(Some(index), hash_type, &prevouts[..=index]), got);
                let mut other = prevouts.clone();
                for (j, prevout) in other.iter_mut().enumerate() {
                    if j != index {
                        prevout.amount += 1;
                    }
                }
                assert_eq!(tx.sighash(Some(index), hash_type, &other), got);
            }
        }
        assert_eq!(
            tx.sighash(Some(index), SIGHASH_ALL, &prevouts[..prevouts.len() - 1]),
            Err(Error::PrevOutCount)
        );
        assert_eq!(
            tx.sighash(Some(index), 0, &prevouts),
            Err(Error::UnsupportedSighash)
        );
        assert_eq!(
            tx.sighash(Some(index), 0x04, &prevouts),
            Err(Error::UnsupportedSighash)
        );
        assert_eq!(
            tx.sighash(None, SIGHASH_NONE, &prevouts),
            Err(Error::UnsupportedSighash)
        );
        assert_eq!(
            tx.sighash(Some(tx.inputs.len()), SIGHASH_ALL, &prevouts),
            Err(Error::InputIndex)
        );
    }
    assert_eq!(with_input, 6);
}

#[test]
fn parse_rejects_malformed() {
    let v = &vectors()[4];
    let mut inputs = [ZcashTxIn::default(); 8];
    let mut outputs = [ZcashTxOut::default(); 8];
    let parse = |data: &[u8]| {
        let mut inputs = [ZcashTxIn::default(); 8];
        let mut outputs = [ZcashTxOut::default(); 8];
        ZcashTx::parse_into(data, &mut inputs, &mut outputs).map(|tx| tx.serialized_len())
    };
    for cut in [0, 4, 19, 20, 21, 60, v.tx.len() / 2, v.tx.len() - 1] {
        assert_eq!(
            parse(&v.tx[..cut]),
            Err(Error::UnexpectedEof),
            "cut at {cut}"
        );
    }
    let mut extended = v.tx.clone();
    extended.push(0);
    assert_eq!(parse(&extended), Err(Error::TrailingData));
    let mut v4 = v.tx.clone();
    v4[0] = 4;
    assert_eq!(parse(&v4), Err(Error::UnsupportedTxType));
    assert_eq!(
        ZcashTx::parse_into(&v.tx, &mut inputs[..1], &mut outputs).map(|_| ()),
        Err(Error::TooLarge)
    );
    // a bundle that does not add up is caught when digesting too
    let tx = ZcashTx::parse_into(&v.tx, &mut inputs, &mut outputs).unwrap();
    let cut = ZcashTx {
        orchard: &tx.orchard[..tx.orchard.len() - 1],
        ..tx
    };
    assert_eq!(cut.txid(), Err(Error::UnexpectedEof));
    let mut longer = tx.orchard.to_vec();
    longer.push(0);
    let long = ZcashTx {
        orchard: &longer,
        ..tx
    };
    assert_eq!(long.txid(), Err(Error::TrailingData));
}

/// The empty bundles hash as the reference does, and are what `Default` and
/// explicit empty bytes both stand for.
#[test]
fn empty_bundles() {
    let inputs = [ZcashTxIn {
        txid: [0x11; 32],
        vout: 1,
        ..Default::default()
    }];
    let outputs = [ZcashTxOut {
        amount: 5,
        script: &[0x51],
    }];
    let tx = ZcashTx {
        consensus_branch_id: branch::NU6,
        inputs: &inputs,
        outputs: &outputs,
        ..Default::default()
    };
    let explicit = ZcashTx {
        sapling: &[0, 0],
        orchard: &[0],
        ..tx
    };
    assert_eq!(tx.serialize(), explicit.serialize());
    assert_eq!(tx.txid(), explicit.txid());
    assert_eq!(tx.serialize().len(), 20 + 1 + 41 + 1 + 10 + 3);
    let mut inputs = [ZcashTxIn::default(); 2];
    let mut outputs = [ZcashTxOut::default(); 2];
    let raw = tx.serialize();
    let parsed = ZcashTx::parse_into(&raw, &mut inputs, &mut outputs).unwrap();
    assert!(parsed.sapling.is_empty() && parsed.orchard.is_empty());
    assert_eq!(parsed.txid(), tx.txid());
}

#[test]
fn signs_p2pkh_inputs() {
    let keys: Vec<SecpPrivateKey> = (1u8..=3)
        .map(|k| SecpPrivateKey::from_bytes(&[k; 32]).unwrap())
        .collect();
    let scripts: Vec<Vec<u8>> = keys
        .iter()
        .map(|k| {
            generate_script(&PubKey::Secp256k1(k.public_key()), "p2pkh")
                .unwrap()
                .to_vec()
        })
        .collect();
    // the third input is an uncompressed-key P2PKH output
    let uncompressed = keys[2].public_key().serialize_uncompressed();
    let mut uncompressed_script = vec![0x76, 0xa9, 0x14];
    uncompressed_script.extend_from_slice(&crate::hash::hash160(&uncompressed));
    uncompressed_script.extend_from_slice(&[0x88, 0xac]);

    let inputs: Vec<ZcashTxIn<'_>> = (0..3)
        .map(|i| ZcashTxIn {
            txid: [i as u8; 32],
            vout: i as u32,
            script_sig: &[],
            sequence: 0xffff_fffe,
        })
        .collect();
    let outputs = [ZcashTxOut {
        amount: 250_000,
        script: &scripts[0],
    }];
    let tx = ZcashTx {
        consensus_branch_id: branch::NU6_1,
        expiry_height: 3_200_040,
        inputs: &inputs,
        outputs: &outputs,
        ..Default::default()
    };
    let prevouts = [
        ZcashTxOut {
            amount: 100_000,
            script: &scripts[0],
        },
        ZcashTxOut {
            amount: 100_000,
            script: &scripts[1],
        },
        ZcashTxOut {
            amount: 60_000,
            script: &uncompressed_script,
        },
    ];
    let key_refs: Vec<&SecpPrivateKey> = keys.iter().collect();
    let signed = tx.sign(&key_refs, &prevouts).unwrap();
    assert!(signed.len() <= tx.signed_len_bound());
    let mut buf = vec![0u8; tx.signed_len_bound()];
    let n = tx.sign_to_slice(&key_refs, &prevouts, &mut buf).unwrap();
    assert_eq!(&buf[..n], &signed[..]);
    assert_eq!(
        tx.sign_to_slice(&key_refs, &prevouts, &mut buf[..n - 1]),
        Err(Error::BufferTooSmall)
    );

    // each scriptSig verifies against the sighash it was made for
    let mut parsed_inputs = [ZcashTxIn::default(); 3];
    let mut parsed_outputs = [ZcashTxOut::default(); 1];
    let parsed = ZcashTx::parse_into(&signed, &mut parsed_inputs, &mut parsed_outputs).unwrap();
    assert_eq!(parsed.expiry_height, 3_200_040);
    assert_eq!(parsed.consensus_branch_id, branch::NU6_1);
    for (i, input) in parsed.inputs.iter().enumerate() {
        let (sig, n) = parse_push_bytes(input.script_sig).unwrap();
        let (pubkey, m) = parse_push_bytes(&input.script_sig[n..]).unwrap();
        assert_eq!(n + m, input.script_sig.len());
        assert_eq!(pubkey.len(), if i == 2 { 65 } else { 33 });
        assert_eq!(*sig.last().unwrap(), SIGHASH_ALL);
        let (r, s) = parse_der_signature(&sig[..sig.len() - 1]).unwrap();
        let sighash = tx.sighash(Some(i), SIGHASH_ALL, &prevouts).unwrap();
        assert!(keys[i].public_key().verify(&sighash, &r, &s), "input {i}");
        // the scriptSigs do not change the id
        assert_eq!(parsed.txid(), tx.txid());
    }

    // the wrong key, a non-P2PKH output, the wrong number of keys
    let mut script_sig = [0u8; MAX_SCRIPT_SIG_LEN];
    assert_eq!(
        tx.sign_input_to_slice(0, &keys[1], SIGHASH_ALL, &prevouts, &mut script_sig),
        Err(Error::KeyNotInvolved)
    );
    let p2sh = [ZcashTxOut {
        amount: 1,
        script: &[
            0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87,
        ],
    }];
    assert_eq!(
        tx.sign_input_to_slice(0, &keys[0], SIGHASH_ALL, &p2sh, &mut script_sig),
        Err(Error::UnsupportedScript)
    );
    assert_eq!(
        tx.sign_input_to_slice(0, &keys[0], SIGHASH_ALL, &prevouts, &mut script_sig[..50]),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(tx.sign(&key_refs[..2], &prevouts), Err(Error::KeyCount));
    assert_eq!(tx.sign(&key_refs, &prevouts[..2]), Err(Error::PrevOutCount));
}

/// Where the compact sizes of a serialized transaction are, and where its
/// bundles start, from its parsed form.
struct Layout {
    compact_sizes: Vec<usize>,
    sapling: usize,
    orchard: usize,
}

fn layout(raw: &[u8], tx: &ZcashTx<'_>) -> Layout {
    let size = |n: usize| crate::BtcVarInt(n as u64).len();
    let mut at = vec![20];
    let mut pos = 20 + size(tx.inputs.len());
    for input in tx.inputs {
        at.push(pos + 36);
        pos += 36 + size(input.script_sig.len()) + input.script_sig.len() + 4;
    }
    at.push(pos);
    pos += size(tx.outputs.len());
    for output in tx.outputs {
        at.push(pos + 8);
        pos += 8 + size(output.script.len()) + output.script.len();
    }
    let sapling = pos;
    let orchard = raw.len() - tx.orchard.len().max(1);
    assert_eq!(orchard - sapling, tx.sapling.len().max(2));
    // nSpendsSapling, nOutputsSapling
    at.push(sapling);
    let n_spends = raw[sapling] as usize;
    assert!(n_spends < 0xfd);
    at.push(sapling + 1 + n_spends * 96);
    // nActionsOrchard and the length of the proof
    at.push(orchard);
    let n_actions = raw[orchard] as usize;
    assert!(n_actions < 0xfd);
    if n_actions > 0 {
        at.push(orchard + 1 + n_actions * 820 + 41);
    }
    Layout {
        compact_sizes: at,
        sapling,
        orchard,
    }
}

/// The transaction with the compact size at `at` in a longer form.
fn widen(raw: &[u8], at: usize) -> Vec<u8> {
    let mut out = raw[..at].to_vec();
    match raw[at] {
        0xfd => {
            out.push(0xfe);
            out.extend_from_slice(&raw[at + 1..at + 3]);
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(&raw[at + 3..]);
        }
        n => {
            assert!(n < 0xfd);
            out.extend_from_slice(&[0xfd, n, 0]);
            out.extend_from_slice(&raw[at + 1..]);
        }
    }
    out
}

/// Every compact size must be in its shortest form: a transaction would
/// otherwise have several encodings with one id, and the typed bundle
/// parsers, which are strict, would not find the bundles where this parser
/// does.
#[test]
fn parse_rejects_non_canonical_compact_sizes() {
    let mut checked = 0;
    for (i, v) in vectors().iter().enumerate() {
        let mut inputs = [ZcashTxIn::default(); 8];
        let mut outputs = [ZcashTxOut::default(); 8];
        let tx = ZcashTx::parse_into(&v.tx, &mut inputs, &mut outputs).unwrap();
        for at in layout(&v.tx, &tx).compact_sizes {
            let wide = widen(&v.tx, at);
            // with lenient compact sizes this is the same transaction
            let lenient = crate::BtcVarInt::decode(&wide[at..]).unwrap();
            let strict = crate::BtcVarInt::decode(&v.tx[at..]).unwrap();
            assert_eq!(lenient.0, strict.0);
            let mut inputs = [ZcashTxIn::default(); 8];
            let mut outputs = [ZcashTxOut::default(); 8];
            assert_eq!(
                ZcashTx::parse_into(&wide, &mut inputs, &mut outputs).map(|_| ()),
                Err(Error::NonCanonical),
                "vector {i}: compact size at {at}"
            );
            checked += 1;
        }
    }
    assert!(checked > 60);

    // the digests read the bundles with the same rule
    let tx = ZcashTx {
        sapling: &[0xfd, 0, 0, 0],
        ..Default::default()
    };
    assert_eq!(tx.txid(), Err(Error::NonCanonical));
    assert_eq!(tx.sighash(None, SIGHASH_ALL, &[]), Err(Error::NonCanonical));
    let tx = ZcashTx {
        orchard: &[0xfe, 0, 0, 0, 0],
        ..Default::default()
    };
    assert_eq!(tx.txid(), Err(Error::NonCanonical));
    assert_eq!(tx.logical_actions(), Err(Error::NonCanonical));
    // 2^32 and up takes nine bytes, less does not
    let tx = ZcashTx {
        orchard: &[0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0],
        ..Default::default()
    };
    assert_eq!(tx.txid(), Err(Error::NonCanonical));
}

/// What consensus fixes of a bundle's fields is checked when parsing, as
/// the typed parsers do.
#[test]
fn parse_rejects_invalid_bundle_fields() {
    let vectors = vectors();
    let mut seen = (false, false);
    for v in &vectors {
        let mut inputs = [ZcashTxIn::default(); 8];
        let mut outputs = [ZcashTxOut::default(); 8];
        let tx = ZcashTx::parse_into(&v.tx, &mut inputs, &mut outputs).unwrap();
        let l = layout(&v.tx, &tx);
        let parse = |data: &[u8]| {
            let mut inputs = [ZcashTxIn::default(); 8];
            let mut outputs = [ZcashTxOut::default(); 8];
            ZcashTx::parse_into(data, &mut inputs, &mut outputs).map(|_| ())
        };
        if !tx.orchard.is_empty() {
            // a reserved flag bit
            let n = v.tx[l.orchard] as usize;
            let mut bad = v.tx.clone();
            bad[l.orchard + 1 + n * 820] |= 4;
            assert_eq!(parse(&bad), Err(Error::InvalidData));
            let cut = ZcashTx {
                orchard: &bad[l.orchard..],
                ..tx
            };
            assert_eq!(cut.txid(), Err(Error::InvalidData));
            seen.0 = true;
        }
        if !tx.sapling.is_empty() {
            // a value balance above the money supply
            let (n_spends, n_outputs) = {
                let n = v.tx[l.sapling] as usize;
                (n, v.tx[l.sapling + 1 + n * 96] as usize)
            };
            let at = l.sapling + 2 + n_spends * 96 + n_outputs * 756;
            let mut bad = v.tx.clone();
            bad[at..at + 8].copy_from_slice(&(21_000_000i64 * 100_000_000 + 1).to_le_bytes());
            assert_eq!(parse(&bad), Err(Error::InvalidAmount));
            bad[at..at + 8].copy_from_slice(&(-21_000_000i64 * 100_000_000).to_le_bytes());
            assert_eq!(parse(&bad), Ok(()));
            seen.1 = true;
        }
    }
    assert_eq!(seen, (true, true));
}

/// The typed views see the bundles exactly where the transaction parser
/// put them.
#[cfg(any(feature = "zcash-sapling", feature = "zcash-orchard"))]
#[test]
fn typed_bundle_views_agree() {
    let mut seen = (0, 0);
    for (i, v) in vectors().iter().enumerate() {
        let mut inputs = [ZcashTxIn::default(); 8];
        let mut outputs = [ZcashTxOut::default(); 8];
        let tx = ZcashTx::parse_into(&v.tx, &mut inputs, &mut outputs).unwrap();
        #[cfg(feature = "zcash-sapling")]
        {
            let bundle = tx.sapling_bundle().unwrap();
            assert_eq!(bundle.is_empty(), tx.sapling.is_empty(), "vector {i}");
            if !bundle.is_empty() {
                assert_eq!(
                    crate::sapling::bundle::bundle_len(bundle.n_spends(), bundle.n_outputs()),
                    tx.sapling.len()
                );
                assert_eq!(bundle.to_bundle().serialize().unwrap(), tx.sapling);
                seen.0 += 1;
            }
            // a view of anything else than the whole bundle is refused
            if let Some((_, short)) = tx.sapling.split_last() {
                let cut = ZcashTx {
                    sapling: short,
                    ..tx
                };
                assert!(cut.sapling_bundle().is_err());
            }
        }
        #[cfg(feature = "zcash-orchard")]
        {
            let bundle = tx.orchard_bundle().unwrap();
            assert_eq!(bundle.is_none(), tx.orchard.is_empty(), "vector {i}");
            if let Some(bundle) = bundle {
                assert_eq!(bundle.serialized_len(), tx.orchard.len());
                assert_eq!(bundle.to_owned().to_bytes(), tx.orchard);
                seen.1 += 1;
                let cut = ZcashTx {
                    orchard: &tx.orchard[..tx.orchard.len() - 1],
                    ..tx
                };
                assert!(cut.orchard_bundle().is_err());
            }
        }
    }
    #[cfg(feature = "zcash-sapling")]
    assert!(seen.0 > 0);
    #[cfg(feature = "zcash-orchard")]
    assert!(seen.1 > 0);
    let _ = seen;

    // no bundle at all
    let tx = ZcashTx::default();
    #[cfg(feature = "zcash-sapling")]
    assert!(tx.sapling_bundle().unwrap().is_empty());
    #[cfg(feature = "zcash-orchard")]
    assert!(tx.orchard_bundle().unwrap().is_none());
    let _ = tx;
}

/// ZIP-317: the conventional fee of given sizes and counts, and of parsed
/// transactions.
#[test]
fn zip317_conventional_fee() {
    use crate::zcashtx::zip317::{conventional_fee, logical_actions};
    assert_eq!(conventional_fee(0), 10_000);
    assert_eq!(conventional_fee(2), 10_000);
    assert_eq!(conventional_fee(3), 15_000);
    // one P2PKH input and two outputs: within the grace window
    assert_eq!(logical_actions(148, 68, 0, 0, 0), 2);
    // sizes round up, the larger side counts
    assert_eq!(logical_actions(151, 34, 0, 0, 0), 2);
    assert_eq!(logical_actions(150, 35, 0, 0, 0), 2);
    assert_eq!(logical_actions(450, 34, 0, 0, 0), 3);
    // Sapling counts its larger side, Orchard its actions
    assert_eq!(logical_actions(0, 0, 1, 3, 2), 5);
    assert_eq!(logical_actions(300, 34, 3, 1, 4), 9);
    assert_eq!(conventional_fee(u64::MAX), u64::MAX);

    assert_eq!(ZcashTx::default().conventional_fee(), Ok(10_000));
    for v in vectors() {
        let mut inputs = [ZcashTxIn::default(); 8];
        let mut outputs = [ZcashTxOut::default(); 8];
        let tx = ZcashTx::parse_into(&v.tx, &mut inputs, &mut outputs).unwrap();
        let l = layout(&v.tx, &tx);
        let n_spends = v.tx[l.sapling] as u64;
        let n_outputs = v.tx[l.sapling + 1 + n_spends as usize * 96] as u64;
        let n_actions = v.tx[l.orchard] as u64;
        let actions = tx.logical_actions().unwrap();
        assert!(actions >= n_spends.max(n_outputs) + n_actions);
        assert!(actions >= tx.inputs.len().max(tx.outputs.len()) as u64);
        assert_eq!(tx.conventional_fee().unwrap(), 5000 * actions.max(2));
    }
}
