//! Tests of what needs a heap: serialization, proofs, signing, scanning.

use std::vec::Vec;

use super::super::epee::{EpeeSection, EpeeValue};
use super::super::*;
use super::{h32, stream, vectors, wallet};
use crate::cryptonote::{EdwardsPoint, Scalar, cn_fast_hash, point_from_bytes, scalar_from_bytes};

const SIGNED: &[u8] = include_bytes!("../testdata/zano_tx_signed3.bin");
const COINBASE_V3: &[u8] = include_bytes!("../testdata/coinbase_v3.bin");
const TRANSFER_V3: &[u8] = include_bytes!("../testdata/transfer_v3.bin");
const GO_BUILT_TRANSFER: &[u8] = include_bytes!("../testdata/go_built_transfer.bin");

fn keys(bytes: &[u8]) -> Vec<[u8; 32]> {
    assert_eq!(bytes.len() % 32, 0);
    bytes.as_chunks::<32>().0.to_vec()
}

fn point(hex: &str) -> EdwardsPoint {
    point_from_bytes(&h32(hex)).unwrap()
}

fn scalar(hex: &str) -> Scalar {
    scalar_from_bytes(&h32(hex)).unwrap()
}

fn div8(p: &EdwardsPoint) -> [u8; 32] {
    p.mul(&scalar_1div8()).compress()
}

fn names(items: &[Variant]) -> Vec<&'static str> {
    items.iter().map(Variant::name).collect()
}

/// The ring of a source, as the signature sees it.
fn ring_of(source: &TxSource) -> Vec<ClsagGgxInput> {
    source
        .outputs
        .iter()
        .map(|o| ClsagGgxInput {
            stealth_address: o.stealth_address,
            amount_commitment: o.amount_commitment,
            blinded_asset_id: o.blinded_asset_id,
        })
        .collect()
}

/// Verifies every input of `tx` against the source of `ftp` it spends
/// (matched by ring offsets), and the transaction-wide proofs.
fn verify_all(tx: &Transaction, ftp: &FinalizeTxParam) -> bool {
    let mut ok = tx.verify_proofs();
    for (index, vin) in tx.vin.iter().enumerate() {
        let Variant::ZcInput(input) = vin else {
            return false;
        };
        let mut absolute = Vec::new();
        let mut sum = 0u64;
        for offset in &input.key_offsets {
            let Variant::Uint64(offset) = offset else {
                return false;
            };
            sum += offset;
            absolute.push(Variant::Uint64(sum));
        }
        let source = ftp
            .sources
            .iter()
            .find(|s| {
                s.outputs
                    .iter()
                    .map(|o| &o.out_reference)
                    .eq(absolute.iter())
            })
            .expect("no source for the input");
        ok &= tx.verify_input(index, &ring_of(source));
    }
    ok
}

/// zanolib's `TestParseOnChainBlobs`, with its `vectors.json`.
#[test]
fn on_chain_transactions() {
    let tx = Transaction::from_bytes(COINBASE_V3).unwrap();
    assert_eq!(tx.to_bytes(), COINBASE_V3);
    assert_eq!(tx.version, TRANSACTION_VERSION_POST_HF5);
    assert_eq!(
        tx.prefix_hash(),
        h32("5412e0a8a4d8eb4394eeea4ec6b821c5b920f21d6c7903d3bfa4692994efea00")
    );
    assert!(matches!(tx.vin[..], [Variant::Gen { height: 3714400 }]));
    assert_eq!(
        names(&tx.extra),
        [
            "pub_key",
            "user_data",
            "extra_padding",
            "derivation_hint",
            "derivation_hint",
            "unlock_time"
        ]
    );
    assert_eq!(names(&tx.vout), ["tx_out_zarcanum", "tx_out_zarcanum"]);
    assert_eq!(tx.fee(), None);
    // Not a confidential-input transaction.
    assert!(!tx.verify_proofs());

    let tx = Transaction::from_bytes(TRANSFER_V3).unwrap();
    assert_eq!(tx.to_bytes(), TRANSFER_V3);
    assert_eq!(tx.version, TRANSACTION_VERSION_POST_HF5);
    assert_eq!(
        tx.prefix_hash(),
        h32("0d1dc9acc18202344a69e1a62ead03e3ae1d5fd7a316c9a6172db57accaf8d00")
    );
    assert_eq!(
        names(&tx.extra),
        [
            "pub_key",
            "etc_tx_flags16",
            "derivation_hint",
            "derivation_hint",
            "zarcanum_tx_data_v1"
        ]
    );
    assert_eq!(names(&tx.vout), ["tx_out_zarcanum", "tx_out_zarcanum"]);
    assert!(tx.fee().is_some() && tx.tx_pub_key().is_some());
    assert_eq!(cn_fast_hash(&tx.prefix_bytes()), tx.prefix_hash());

    // A mainnet transaction made by Zano itself: its surjection, range and
    // balance proofs verify, and stop verifying once touched.
    assert!(tx.verify_proofs());
    let mut bad = tx.clone();
    let Some(Variant::OutZarcanum(out)) = bad.vout.first_mut() else {
        panic!("no output");
    };
    out.encrypted_amount ^= 1;
    // (the encrypted amount is in the prefix: the proofs sign another id)
    assert!(!bad.verify_proofs());
    for field in 0..3 {
        let mut bad = tx.clone();
        match &mut bad.proofs[field] {
            Variant::AssetSurjectionProof(p) => p.bge_proofs[1].z[0] ^= 1,
            Variant::OutsRangeProof(p) if field == 1 => p.bpp.delta[0] ^= 1,
            Variant::BalanceProof(p) => p.dss.y0[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(!bad.verify_proofs(), "proof {field}");
    }
    let mut bad = tx.clone();
    let Variant::OutsRangeProof(p) = &mut bad.proofs[1] else {
        panic!()
    };
    p.aggregation_proof.y1s[0][0] ^= 1;
    assert!(!bad.verify_proofs());

    // The scanning parser stops before the signatures.
    let scan = Transaction::from_bytes_for_scan(TRANSFER_V3).unwrap();
    assert_eq!(scan.prefix_hash(), tx.prefix_hash());
    assert!(scan.signatures.is_empty() && scan.proofs.is_empty());
    assert_eq!(scan.attachment, tx.attachment);
    // It does not mind what follows the attachments.
    let prefix_len = tx.prefix_bytes().len() + 1;
    let mut cut = TRANSFER_V3[..prefix_len].to_vec();
    cut.extend_from_slice(&[0xee; 5]);
    assert_eq!(Transaction::from_bytes_for_scan(&cut).unwrap(), scan);
    assert!(Transaction::from_bytes(&cut).is_err());
}

/// Truncations and corruptions of real data never panic.
#[test]
fn parsing_is_total() {
    let w = wallet();
    let mut plain = SIGNED.to_vec();
    chacha8_crypt(w.view_secret_key(), &mut plain);
    for data in [COINBASE_V3, TRANSFER_V3] {
        for len in 0..data.len() {
            assert!(Transaction::from_bytes(&data[..len]).is_err(), "{len}");
            let _ = Transaction::from_bytes_for_scan(&data[..len]);
        }
        let mut extended = data.to_vec();
        extended.push(0);
        assert_eq!(Transaction::from_bytes(&extended), Err(Error::TrailingData));
    }
    for len in (0..plain.len()).step_by(7) {
        assert!(FinalizedTx::from_bytes(&plain[..len]).is_err());
        let _ = FinalizeTxParam::from_bytes(&plain[..len]);
    }
    // Every byte of a transaction flipped, one at a time.
    let mut data = TRANSFER_V3.to_vec();
    for i in 0..data.len().min(600) {
        data[i] ^= 0xff;
        let _ = Transaction::from_bytes(&data);
        data[i] ^= 0xff;
    }
    // Counts far beyond the data.
    for data in [
        &[3, 0xff, 0xff, 0xff, 0xff, 0x0f][..],
        &[
            3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        ],
        &[3, 1, 37, 0xff, 0xff, 0x7f],
        &[3, 1, 99, 0],
    ] {
        assert!(Transaction::from_bytes(data).is_err());
    }
    assert_eq!(
        Transaction::from_bytes(&[3, 1, 99, 0]),
        Err(Error::UnsupportedVariant(99))
    );
    // The wrong key gives garbage, not a panic.
    assert!(FinalizedTx::decrypt(SIGNED, &[7; 32]).is_err());
    assert!(FinalizeTxParam::decrypt(SIGNED, &[7; 32]).is_err());
}

/// The varint: zanolib's `VarintAppendUint64` writes 128 as the single byte
/// 0x80; Zano writes 0x80 0x01, as this module does.
#[test]
fn varint_128() {
    let comment = Variant::Comment(std::vec![0x55; 128]);
    let tx = Transaction {
        version: 2,
        extra: std::vec![comment],
        ..Default::default()
    };
    let bytes = tx.to_bytes();
    assert_eq!(&bytes[..6], [2, 0, 1, 7, 0x80, 0x01]);
    assert_eq!(Transaction::from_bytes(&bytes).unwrap(), tx);
    for value in [0u64, 127, 128, 129, 16383, 16384, u64::MAX] {
        let tx = Transaction {
            version: 2,
            extra: std::vec![Variant::UnlockTime(value)],
            ..Default::default()
        };
        assert_eq!(Transaction::from_bytes(&tx.to_bytes()).unwrap(), tx);
    }
}

/// Every variant survives a round trip.
#[test]
fn variants_round_trip() {
    let key = |n: u8| [n; 32];
    let addr = AccountPublicAddr {
        spend_key: key(1),
        view_key: key(2),
        flags: 1,
    };
    let offsets = std::vec![
        Variant::Uint64(77),
        Variant::RefById(RefById { hash: key(3), n: 9 })
    ];
    let details = std::vec![
        Variant::SignedParts(SignedParts {
            n_outs: 300,
            n_extras: 2
        }),
        Variant::ExtraAttachmentInfo(ExtraAttachmentInfo {
            sz: 70000,
            hsh: key(4),
            cnt: 3
        }),
    ];
    let tx = Transaction {
        version: 3,
        hardfork_id: 5,
        vin: std::vec![
            Variant::Gen { height: 1 << 40 },
            Variant::ToKey(TxInToKey {
                amount: 1000,
                key_offsets: offsets.clone(),
                k_image: key(5),
                etc_details: details.clone(),
            }),
            Variant::ZcInput(TxInZcInput {
                key_offsets: offsets,
                key_image: key(6),
                etc_details: details,
            }),
        ],
        extra: std::vec![
            Variant::Comment(b"hello".to_vec()),
            Variant::CryptoChecksum(TxCryptoChecksum {
                encrypted_key_derivation: key(7),
                derivation_hash: 0xdead_beef
            }),
            Variant::DerivationHint(std::vec![1, 2]),
            Variant::ServiceAttachment(TxServiceAttachment {
                service_id: b"P".to_vec(),
                instruction: b"i".to_vec(),
                body: std::vec![0; 300],
                security: std::vec![key(8), key(9)],
                flags: TX_SERVICE_ATTACHMENT_ENCRYPT_BODY,
            }),
            Variant::UnlockTime(5),
            Variant::ExpirationTime(6),
            Variant::Flags(7),
            Variant::UserData(std::vec![1]),
            Variant::Padding(std::vec![0; 4]),
            Variant::PubKey(key(10)),
            Variant::EtcTxFlags16(0x1234),
            Variant::DeriveXor(0x4321),
            Variant::EtcTxTime(1_700_000_000),
            Variant::Uint32(0x0102_0304),
            Variant::Payer(addr),
            Variant::Receiver(addr),
            Variant::ZarcanumTxDataV1 {
                fee: 10_000_000_000
            },
        ],
        vout: std::vec![Variant::OutZarcanum(TxOutZarcanum {
            stealth_address: key(11),
            concealing_point: key(12),
            amount_commitment: key(13),
            blinded_asset_id: key(14),
            encrypted_amount: u64::MAX - 1,
            mix_attr: 1,
        })],
        attachment: std::vec![Variant::Comment(Vec::new())],
        signatures: std::vec![Variant::ZcSig(ZcSig {
            pseudo_out_amount_commitment: key(15),
            pseudo_out_blinded_asset_id: key(16),
            clsag_ggx: ClsagGgxSig {
                c: key(17),
                r_g: std::vec![key(18), key(19)],
                r_x: std::vec![key(20), key(21)],
                k1: key(22),
                k2: key(23),
            },
        })],
        proofs: std::vec![
            Variant::AssetSurjectionProof(ZcAssetSurjectionProof {
                bge_proofs: std::vec![BgeProof {
                    a: key(24),
                    b: key(25),
                    pk: std::vec![key(26)],
                    f: std::vec![key(27), key(28), key(29)],
                    y: key(30),
                    z: key(31),
                }],
            }),
            Variant::OutsRangeProof(ZcOutsRangeProof {
                bpp: BppSignature {
                    lv: std::vec![key(32)],
                    rv: std::vec![key(33)],
                    a0: key(34),
                    a: key(35),
                    b: key(36),
                    r: key(37),
                    s: key(38),
                    delta: key(39),
                },
                aggregation_proof: UgAggProof {
                    amount_commitments_for_rp_aggregation: std::vec![key(40)],
                    y0s: std::vec![key(41)],
                    y1s: std::vec![key(42)],
                    c: key(43),
                },
            }),
            Variant::BalanceProof(ZcBalanceProof {
                dss: DoubleSchnorrSig {
                    c: key(44),
                    y0: key(45),
                    y1: key(46),
                },
            }),
        ],
    };
    let bytes = tx.to_bytes();
    assert_eq!(Transaction::from_bytes(&bytes).unwrap(), tx);
    // The hardfork id is in the prefix from version 3 on only.
    let mut v2 = tx.clone();
    v2.version = 2;
    assert_eq!(v2.to_bytes().len() + 1, bytes.len());
    assert_eq!(v2.prefix_bytes().len() + 1, tx.prefix_bytes().len());
    for item in tx.vin.iter().chain(&tx.extra).chain(&tx.proofs) {
        assert!(!item.name().is_empty());
    }
    let tags: Vec<u8> = tx.extra.iter().map(Variant::tag).collect();
    assert_eq!(
        tags,
        [
            7, 10, 11, 12, 14, 15, 16, 19, 21, 22, 23, 24, 27, 28, 31, 32, 39
        ]
    );
    assert_eq!(tx.fee(), Some(10_000_000_000));
    assert_eq!(tx.tx_pub_key(), Some(key(10)));
    // A boolean must be 0 or 1.
    let mut ftp = FinalizeTxParam::default().to_bytes();
    assert_eq!(
        FinalizeTxParam::from_bytes(&ftp).unwrap(),
        FinalizeTxParam::default()
    );
    ftp[8 + 2 + 65 + 1] = 2;
    assert_eq!(
        FinalizeTxParam::from_bytes(&ftp),
        Err(Error::InvalidEncoding)
    );
}

/// zanolib's `epee` round trip, and the format's corners.
#[test]
fn epee_round_trip() {
    let mut dist = EpeeSection::new();
    dist.set("amount", EpeeValue::Uint(0)).set(
        "global_offsets",
        EpeeValue::UintArray(std::vec![1, 3, 5928, 2811]),
    );
    let mut root = EpeeSection::new();
    root.set("amounts", EpeeValue::SectionArray(std::vec![dist.clone()]))
        .set("height_upper_limit", EpeeValue::Uint(2_555_000))
        .set("use_forced_mix_outs", EpeeValue::Bool(false))
        .set("coinbase_percents", EpeeValue::Uint(15))
        .set(
            "blob",
            EpeeValue::Bytes(std::vec![0x00, 0x01, 0xff, 0xc3, 0xa9]),
        )
        .set("nested", EpeeValue::Section(dist))
        .set("flags", EpeeValue::BoolArray(std::vec![true, false]))
        .set(
            "names",
            EpeeValue::BytesArray(std::vec![b"a".to_vec(), std::vec![7; 100]]),
        )
        .set("long", EpeeValue::Bytes(std::vec![9; 20000]));
    let bytes = root.to_bytes().unwrap();
    assert_eq!(
        bytes[..9],
        [0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01]
    );
    let got = EpeeSection::from_bytes(&bytes).unwrap();
    assert_eq!(got, root);
    assert_eq!(got.uint("height_upper_limit"), Some(2_555_000));
    assert_eq!(got.uint("coinbase_percents"), Some(15));
    assert_eq!(got.bool("use_forced_mix_outs"), Some(false));
    assert_eq!(got.bytes("blob"), Some(&[0x00, 0x01, 0xff, 0xc3, 0xa9][..]));
    let sections = got.sections("amounts").unwrap();
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].uint("amount"), Some(0));
    assert_eq!(
        sections[0].uints("global_offsets"),
        Some(&[1, 3, 5928, 2811][..])
    );
    assert_eq!(got.section("nested"), Some(&sections[0]));
    assert_eq!(got.uint("blob"), None);
    assert_eq!(got.get("missing"), None);
    assert_eq!(got.entries().count(), 9);
    assert_eq!(got.entries().next().unwrap().0, "amounts");

    // Setting again replaces in place.
    let mut s = EpeeSection::new();
    s.set("a", EpeeValue::Uint(1)).set("b", EpeeValue::Uint(2));
    s.set("a", EpeeValue::Bool(true));
    assert_eq!(s.entries().map(|(n, _)| n).collect::<Vec<_>>(), ["a", "b"]);
    assert_eq!(s.bool("a"), Some(true));
    assert!(
        s.set(&"n".repeat(256), EpeeValue::Uint(0))
            .to_bytes()
            .is_err()
    );

    // Narrow and signed integers widen; a double keeps its bits.
    let mut doc = bytes[..9].to_vec();
    doc.extend_from_slice(&[4 << 2]);
    doc.extend_from_slice(&[1, b'a', 8, 0xfe]);
    doc.extend_from_slice(&[1, b'b', 3, 0x34, 0x12]);
    doc.extend_from_slice(&[1, b'c', 2, 1, 0, 0, 0]);
    doc.extend_from_slice(&[1, b'd', 0x80 | 7, 2 << 2, 1, 0, 2, 0]);
    let got = EpeeSection::from_bytes(&doc).unwrap();
    assert_eq!(got.uint("a"), Some(0xfe));
    assert_eq!(got.uint("b"), Some(0x1234));
    assert_eq!(got.uint("c"), Some(1));
    assert_eq!(got.uints("d"), Some(&[1, 2][..]));

    // Malformed documents.
    assert_eq!(EpeeSection::from_bytes(&[]), Err(Error::UnexpectedEof));
    assert_eq!(
        EpeeSection::from_bytes(&[0; 9]),
        Err(Error::InvalidEncoding)
    );
    let mut bad = doc.clone();
    bad.push(0);
    assert_eq!(EpeeSection::from_bytes(&bad), Err(Error::TrailingData));
    for len in 0..bytes.len().min(400) {
        assert!(EpeeSection::from_bytes(&bytes[..len]).is_err());
    }
    // An unknown type, and a count far beyond the data.
    let mut bad = bytes[..9].to_vec();
    bad.extend_from_slice(&[1 << 2, 1, b'a', 14, 0]);
    assert_eq!(EpeeSection::from_bytes(&bad), Err(Error::InvalidEncoding));
    let mut bad = bytes[..9].to_vec();
    bad.extend_from_slice(&[1 << 2, 1, b'a', 0x80 | 12, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(EpeeSection::from_bytes(&bad), Err(Error::UnexpectedEof));
    // Nesting without end.
    let mut deep = bytes[..9].to_vec();
    for _ in 0..100 {
        deep.extend_from_slice(&[1 << 2, 1, b'a', 12]);
    }
    deep.push(0);
    assert_eq!(EpeeSection::from_bytes(&deep), Err(Error::TooDeep));
}

/// The transaction Zano's own wallet signed (zanolib's fixture): it parses,
/// re-encrypts to the same bytes, and every signature and proof in it
/// verifies.
#[test]
fn zano_signed_fixture() {
    let w = wallet();
    let fin = w.parse_finalized(SIGNED).unwrap();
    assert_eq!(fin.encrypt(w.view_secret_key()), SIGNED);
    assert_eq!(
        cn_fast_hash(&fin.tx.to_bytes()),
        h32(vectors("fixture_tx")[0][1])
    );
    let v = &vectors("fixture_ftp")[0];
    assert_eq!(cn_fast_hash(&fin.ftp.to_bytes()), h32(v[1]));
    assert_eq!(
        cn_fast_hash(&fin.ftp.encrypt(w.view_secret_key())),
        h32(v[2])
    );
    assert_eq!(
        w.parse_ftp(&fin.ftp.encrypt(w.view_secret_key())).unwrap(),
        fin.ftp
    );

    assert_eq!(
        fin.tx.prefix_hash(),
        h32("6205ab25f5f18a6124835a2c951ea7a862f806fbfaad9e33307e432739e07554")
    );
    assert_eq!(fin.tx.version, 2);
    assert_eq!((fin.tx.vin.len(), fin.tx.vout.len()), (4, 2));
    assert_eq!(fin.tx.fee(), Some(10_000_000_000));
    assert_eq!(fin.tx_id, [0; 32]);
    assert_eq!(fin.derivation, [0; 32]);
    assert_eq!(
        fin.one_time_key,
        h32("955f1e1fc3262ba2f307b64e60a960e18ff1072300dbf297114739fabb000204")
    );
    assert_eq!(fin.ftp.spend_pub_key, *w.spend_public_key());
    assert_eq!(fin.ftp.selected_transfers, [0, 1, 3, 2]);
    assert!(fin.ftp.shuffle);
    assert_eq!((fin.ftp.tx_version, fin.ftp.tx_hardfork_id), (2, 4));
    let amounts: Vec<u64> = fin.ftp.sources.iter().map(|s| s.amount).collect();
    assert_eq!(
        amounts,
        [
            900_000_000_000,
            790_000_000_000,
            680_000_000_000,
            100_000_000_000
        ]
    );
    assert!(
        fin.ftp
            .sources
            .iter()
            .all(|s| s.outputs.len() == 16 && s.is_zc())
    );
    let dests: Vec<u64> = fin
        .ftp
        .prepared_destinations
        .iter()
        .map(|d| d.amount)
        .collect();
    assert_eq!(dests, [1_790_000_000_000, 670_000_000_000]);

    // Zano's signatures and proofs, checked by this module's verifiers.
    assert!(verify_all(&fin.tx, &fin.ftp));
    // A ring signature does not verify over another ring, nor once touched.
    let ring0 = ring_of(&fin.ftp.sources[0]);
    let ring1 = ring_of(&fin.ftp.sources[1]);
    let good = (0..4).filter(|i| fin.tx.verify_input(*i, &ring0)).count();
    assert_eq!(good, 1);
    let index = (0..4).find(|i| fin.tx.verify_input(*i, &ring0)).unwrap();
    assert!(!fin.tx.verify_input(index, &ring1));
    assert!(!fin.tx.verify_input(index, &ring0[..15]));
    assert!(!fin.tx.verify_input(9, &ring0));
    let mut bad = fin.tx.clone();
    let Variant::ZcSig(sig) = &mut bad.signatures[index] else {
        panic!()
    };
    sig.clsag_ggx.r_x[7][0] ^= 1;
    assert!(!bad.verify_input(index, &ring0));
}

/// Signing zanolib's fixture with the same one-time key and the same
/// "random" bytes gives, byte for byte, the transaction zanolib signs.
#[test]
fn sign_matches_zanolib() {
    let w = wallet();
    let fin = w.parse_finalized(SIGNED).unwrap();
    let signed = w
        .sign(&mut stream(0), &fin.ftp, Some(&fin.one_time_key))
        .unwrap();
    let v = &vectors("sign")[0];
    assert_eq!(signed.tx.prefix_hash(), h32(v[3]));
    assert_eq!(cn_fast_hash(&signed.tx.to_bytes()), h32(v[1]));
    assert_eq!(
        cn_fast_hash(&signed.encrypt(w.view_secret_key())),
        h32(v[2])
    );
    assert_eq!(signed.ftp, fin.ftp);
    assert_eq!(signed.one_time_key, fin.one_time_key);

    // The inputs are those Zano's wallet made (key images, by increasing
    // order), and the outputs too: both depend only on the keys.
    assert_eq!(signed.tx.vin, fin.tx.vin);
    assert_eq!(signed.tx.vout, fin.tx.vout);
    // And it verifies.
    assert!(verify_all(&signed.tx, &fin.ftp));

    // The full wallet and its view-only half find the same outputs in it.
    let view = w.export_view(0).load().unwrap();
    let found = view.scan_tx(&signed.tx).unwrap();
    assert_eq!(found, w.scan_tx(&signed.tx).unwrap());
    assert!(found.found());
    assert_eq!(found.tx_pub_key, signed.tx.tx_pub_key());
    assert_eq!(found.payment_id, None);
    let scans = vectors("scan");
    assert_eq!(found.outputs.len(), scans.len());
    for (out, v) in found.outputs.iter().zip(&scans) {
        assert_eq!(out.output_index, v[1].parse::<u64>().unwrap());
        assert_eq!(out.amount, v[2].parse::<u64>().unwrap());
        assert_eq!(out.asset_id, h32(v[3]));
        assert!(out.is_native);
        assert_eq!(out.stealth_address, h32(v[5]));
        assert_eq!(out.amount_blinding_mask, h32(v[6]));
        assert_eq!(out.asset_id_blinding_mask, h32(v[7]));
    }
    // Another wallet finds nothing.
    let other = Wallet::generate(&mut stream(5), 0).unwrap();
    assert!(!other.scan_tx(&signed.tx).unwrap().found());

    // The payment id zanolib attached and encrypted.
    let v = &vectors("payment_id")[0];
    let mut tx = signed.tx.clone();
    tx.attachment
        .push(Variant::ServiceAttachment(TxServiceAttachment {
            service_id: PAYMENT_ID_SERVICE_ID.as_bytes().to_vec(),
            body: hex::decode(v[2]).unwrap(),
            flags: TX_SERVICE_ATTACHMENT_ENCRYPT_BODY,
            ..Default::default()
        }));
    let found = view.scan_tx(&tx).unwrap();
    assert_eq!(found.payment_id, Some(hex::decode(v[3]).unwrap()));
    assert_eq!(found.outputs.len(), 2);
    // Without a transaction public key there is nothing to find.
    tx.extra.retain(|e| !matches!(e, Variant::PubKey(_)));
    assert_eq!(view.scan_tx(&tx).unwrap(), ScanResult::default());

    // A view-only wallet cannot sign by itself, but can with a signer.
    assert_eq!(
        view.sign(&mut stream(0), &fin.ftp, None).unwrap_err(),
        Error::ViewOnly
    );
    let signer = LocalInputSigner::new(w.spend_secret_key().unwrap()).unwrap();
    let delegated = view
        .sign_with(&mut stream(0), &fin.ftp, Some(&fin.one_time_key), &signer)
        .unwrap();
    assert_eq!(delegated, signed);
}

#[test]
fn sign_errors() {
    let w = wallet();
    let fin = w.parse_finalized(SIGNED).unwrap();
    let key = Some(&fin.one_time_key);
    let sign = |ftp: &FinalizeTxParam| w.sign(&mut stream(0), ftp, key).unwrap_err();

    let other = Wallet::generate(&mut stream(5), 0).unwrap();
    assert_eq!(
        other.sign(&mut stream(0), &fin.ftp, key).unwrap_err(),
        Error::KeyMismatch
    );
    let mut ftp = fin.ftp.clone();
    ftp.tx_version = 1;
    assert_eq!(sign(&ftp), Error::UnsupportedVersion);
    let mut ftp = fin.ftp.clone();
    ftp.sources.clear();
    assert_eq!(sign(&ftp), Error::InvalidRing);
    let mut ftp = fin.ftp.clone();
    ftp.prepared_destinations[0].amount += 700_000_000_000;
    assert_eq!(sign(&ftp), Error::InsufficientFunds);
    let mut ftp = fin.ftp.clone();
    ftp.prepared_destinations[0].amount += 10_000_000_000;
    assert_eq!(sign(&ftp), Error::MissingFee);
    let mut ftp = fin.ftp.clone();
    ftp.prepared_destinations[0].asset_id = POINT_U;
    assert_eq!(sign(&ftp), Error::Unbalanced);
    let mut ftp = fin.ftp.clone();
    ftp.prepared_destinations[0].addr.clear();
    assert_eq!(sign(&ftp), Error::Unsupported);
    let mut ftp = fin.ftp.clone();
    ftp.sources[0].real_output = 16;
    assert_eq!(sign(&ftp), Error::InvalidRing);
    let mut ftp = fin.ftp.clone();
    ftp.sources[0].real_output ^= 1;
    assert_eq!(sign(&ftp), Error::KeyMismatch);
    let mut ftp = fin.ftp.clone();
    ftp.sources[0].real_out_in_tx_index += 1;
    assert_eq!(sign(&ftp), Error::KeyMismatch);
    let mut ftp = fin.ftp.clone();
    ftp.sources[1].outputs.swap(0, 1);
    assert_eq!(sign(&ftp), Error::InvalidRing);
    let mut ftp = fin.ftp.clone();
    ftp.sources[1].outputs[2].out_reference = Variant::RefById(RefById::default());
    assert_eq!(sign(&ftp), Error::Unsupported);
    let mut ftp = fin.ftp.clone();
    ftp.sources[2].real_out_asset_id_blinding_mask = [0; 32];
    assert_eq!(sign(&ftp), Error::Unsupported);
    // A wrong blinding mask does not open the output.
    let mut ftp = fin.ftp.clone();
    ftp.sources[3].real_out_amount_blinding_mask[0] ^= 1;
    assert_eq!(sign(&ftp), Error::SecretMismatch);
    let mut ftp = fin.ftp.clone();
    ftp.sources[3].amount += 1;
    assert_eq!(sign(&ftp), Error::SecretMismatch);
    // A one-time key that is not a scalar.
    assert!(w.sign(&mut stream(0), &fin.ftp, Some(&[0xff; 32])).is_err());
}

/// A transfer built from scanned outputs: zanolib's verifies here, and this
/// module's verifies too (zanolib draws the transaction key itself, so the
/// two cannot be compared byte for byte).
#[test]
fn build_transfer() {
    let w = wallet();
    let fin = w.parse_finalized(SIGNED).unwrap();

    let inputs: Vec<TransferInput> = fin
        .ftp
        .sources
        .iter()
        .map(|source| {
            let global = |entry: &TxSourceOutputEntry| match entry.out_reference {
                Variant::Uint64(index) => index,
                _ => panic!("not a global index"),
            };
            TransferInput {
                amount: source.amount,
                asset_id: NATIVE_COIN_ASSET_ID,
                amount_blinding_mask: source.real_out_amount_blinding_mask,
                asset_id_blinding_mask: source.real_out_asset_id_blinding_mask,
                real_out_tx_key: source.real_out_tx_key,
                real_out_index: source.real_out_in_tx_index,
                real_global_index: global(&source.outputs[source.real_output as usize]),
                // Reversed: the builder sorts.
                ring: source
                    .outputs
                    .iter()
                    .rev()
                    .map(|o| RingMember {
                        global_index: global(o),
                        stealth_address: o.stealth_address,
                        concealing_point: o.concealing_point,
                        amount_commitment: o.amount_commitment,
                        blinded_asset_id: o.blinded_asset_id,
                    })
                    .collect(),
            }
        })
        .collect();
    let recipient: Address = super::ADDRESSES[4].0.parse().unwrap();
    let fee = 10_000_000_000;
    let dests = [
        TransferDest {
            address: recipient,
            asset_id: NATIVE_COIN_ASSET_ID,
            amount: 1_234_567_890_123,
        },
        TransferDest {
            address: w.address(),
            asset_id: NATIVE_COIN_ASSET_ID,
            amount: 2_470_000_000_000 - 1_234_567_890_123 - fee,
        },
    ];

    // The transaction zanolib built from the same inputs and destinations.
    let go = Transaction::from_bytes(GO_BUILT_TRANSFER).unwrap();
    assert_eq!((go.version, go.hardfork_id, go.fee()), (3, 5, Some(fee)));
    assert!(verify_all(&go, &fin.ftp));
    let found = w.scan_tx(&go).unwrap();
    assert_eq!(found.outputs.len(), 1);
    assert_eq!(
        (found.outputs[0].output_index, found.outputs[0].amount),
        (1, dests[1].amount)
    );

    // And this module's.
    let ftp = w.transfer_params(&inputs, &dests, 3, 5).unwrap();
    for (built, original) in ftp.sources.iter().zip(&fin.ftp.sources) {
        assert_eq!(built.outputs, original.outputs);
        assert_eq!(built.real_output, original.real_output);
        assert_eq!(built.asset_id, Some(NATIVE_COIN_ASSET_ID));
    }
    let built = w
        .build_transfer(&mut stream(99), &inputs, &dests, 3, 5)
        .unwrap();
    let tx = Transaction::from_bytes(&built.tx.to_bytes()).unwrap();
    assert_eq!((tx.version, tx.hardfork_id, tx.fee()), (3, 5, Some(fee)));
    assert!(verify_all(&tx, &fin.ftp));
    // Same inputs, so the same key images as zanolib's.
    assert_eq!(tx.vin, go.vin);
    let Variant::OutZarcanum(out) = &tx.vout[0] else {
        panic!()
    };
    // An output to an auditable address is not to be mixed.
    assert_eq!(out.mix_attr, 1);
    let found = w.scan_tx(&tx).unwrap();
    assert_eq!(found.outputs.len(), 1);
    assert_eq!(found.outputs[0].amount, dests[1].amount);

    // Errors.
    let view = Wallet::view_only(w.view_secret_key(), w.spend_public_key(), 0).unwrap();
    let mut rng = stream(1);
    assert_eq!(
        view.build_transfer(&mut rng, &inputs, &dests, 3, 5)
            .unwrap_err(),
        Error::ViewOnly
    );
    assert_eq!(
        w.build_transfer(&mut rng, &[], &dests, 3, 5).unwrap_err(),
        Error::InvalidRing
    );
    let mut bad = inputs[0].clone();
    bad.ring.clear();
    assert_eq!(
        w.transfer_params(&[bad], &dests, 3, 5).unwrap_err(),
        Error::InvalidRing
    );
    let mut bad = inputs[0].clone();
    bad.ring[3] = bad.ring[4];
    assert_eq!(
        w.transfer_params(&[bad], &dests, 3, 5).unwrap_err(),
        Error::InvalidRing
    );
    let mut bad = inputs[0].clone();
    bad.real_global_index += 1_000_000;
    assert_eq!(
        w.transfer_params(&[bad], &dests, 3, 5).unwrap_err(),
        Error::InvalidRing
    );
    let mut bad = inputs[0].clone();
    bad.ring[0].concealing_point = [2; 32];
    assert!(w.transfer_params(&[bad], &dests, 3, 5).is_err());
}

/// CLSAG-GGX: the signature zanolib makes from the same secrets and nonces.
#[test]
fn clsag_matches_zanolib() {
    let v = &vectors("clsag")[0];
    let m = h32(v[1]);
    let ring: Vec<ClsagGgxInput> = keys(&hex::decode(v[2]).unwrap())
        .as_chunks::<3>()
        .0
        .iter()
        .map(|c| ClsagGgxInput {
            stealth_address: c[0],
            amount_commitment: c[1],
            blinded_asset_id: c[2],
        })
        .collect();
    assert_eq!(ring.len(), 5);
    let key_image = point(v[3]);
    let (pseudo_amount, pseudo_asset) = (point(v[4]), point(v[5]));
    let secrets = [scalar(v[6]), scalar(v[7]), scalar(v[8])];
    let want = hex::decode(v[9]).unwrap();

    // zanolib drew 20 scalars (64 bytes each) before signing.
    let sign = |ring: &[ClsagGgxInput], secrets: &[Scalar; 3], index: usize| {
        generate_clsag_ggx(
            &mut stream(20 * 64),
            &m,
            ring,
            &key_image,
            &pseudo_amount,
            &pseudo_asset,
            &secrets[0],
            &secrets[1],
            &secrets[2],
            index,
        )
    };
    let sig = sign(&ring, &secrets, 3).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&sig.c);
    for part in [&sig.r_g, &sig.r_x] {
        bytes.push(part.len() as u8);
        bytes.extend(part.iter().flatten());
    }
    bytes.extend_from_slice(&sig.k1);
    bytes.extend_from_slice(&sig.k2);
    assert_eq!(bytes, want);

    let (pa, pb, ki) = (div8(&pseudo_amount), div8(&pseudo_asset), h32(v[3]));
    assert!(verify_clsag_ggx(&m, &ring, &pa, &pb, &ki, &sig));
    // Another message, ring, pseudo-output or key image does not verify.
    assert!(!verify_clsag_ggx(&[1; 32], &ring, &pa, &pb, &ki, &sig));
    assert!(!verify_clsag_ggx(&m, &ring, &pb, &pa, &ki, &sig));
    assert!(!verify_clsag_ggx(&m, &ring, &pa, &pb, &POINT_X, &sig));
    let mut other = ring.clone();
    other.swap(0, 1);
    assert!(!verify_clsag_ggx(&m, &other, &pa, &pb, &ki, &sig));
    assert!(!verify_clsag_ggx(&m, &ring[..4], &pa, &pb, &ki, &sig));
    assert!(!verify_clsag_ggx(&m, &[], &pa, &pb, &ki, &sig));
    for field in 0..5 {
        let mut bad = sig.clone();
        match field {
            0 => bad.c[0] ^= 1,
            1 => bad.r_g[4][0] ^= 1,
            2 => bad.r_x[0][0] ^= 1,
            3 => bad.k1 = bad.k2,
            _ => bad.k2 = POINT_G,
        }
        assert!(!verify_clsag_ggx(&m, &ring, &pa, &pb, &ki, &bad), "{field}");
    }
    // A key image outside the prime-order subgroup is refused: the point of
    // order two, (0, -1).
    let mut order2 = [0xff; 32];
    order2[0] = 0xec;
    order2[31] = 0x7f;
    assert!(point_from_bytes(&order2).is_ok());
    assert!(!verify_clsag_ggx(&m, &ring, &pa, &pb, &order2, &sig));

    // Wrong secrets, index or ring are refused.
    let swapped = [secrets[1].clone(), secrets[0].clone(), secrets[2].clone()];
    assert_eq!(sign(&ring, &swapped, 3).unwrap_err(), Error::SecretMismatch);
    assert_eq!(sign(&ring, &secrets, 2).unwrap_err(), Error::SecretMismatch);
    assert_eq!(sign(&ring, &secrets, 5).unwrap_err(), Error::InvalidRing);
    assert_eq!(sign(&[], &secrets, 0).unwrap_err(), Error::InvalidRing);

    // The real member first: the ring closes on itself.
    let mut first = ring.clone();
    first.swap(0, 3);
    let sig = sign(&first, &secrets, 0).unwrap();
    assert!(verify_clsag_ggx(&m, &first, &pa, &pb, &ki, &sig));
    let sig = sign(&first[..1], &secrets, 0).unwrap();
    assert!(verify_clsag_ggx(&m, &first[..1], &pa, &pb, &ki, &sig));
}

fn bge_bytes(proof: &BgeProof) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&proof.a);
    bytes.extend_from_slice(&proof.b);
    for part in [&proof.pk, &proof.f] {
        bytes.push(part.len() as u8);
        bytes.extend(part.iter().flatten());
    }
    bytes.extend_from_slice(&proof.y);
    bytes.extend_from_slice(&proof.z);
    bytes
}

fn bge_from_bytes(bytes: &[u8]) -> BgeProof {
    let tx = [&[2, 0, 0, 0, 0, 0, 1, 46, 1][..], bytes].concat();
    match Transaction::from_bytes(&tx).unwrap().proofs.pop() {
        Some(Variant::AssetSurjectionProof(mut p)) => p.bge_proofs.pop().unwrap(),
        _ => panic!("not a surjection proof"),
    }
}

/// The one-out-of-many proof: byte for byte zanolib's for rings of up to 4
/// members. For larger rings zanolib indexes its matrix wrongly, and makes
/// proofs that do not verify.
#[test]
fn bge_matches_zanolib() {
    for v in vectors("bge") {
        let (size, index): (usize, usize) = (v[1].parse().unwrap(), v[2].parse().unwrap());
        let context = h32(v[3]);
        let ring_bytes = keys(&hex::decode(v[4]).unwrap());
        let ring: Vec<EdwardsPoint> = ring_bytes
            .iter()
            .map(|k| point_from_bytes(k).unwrap())
            .collect();
        assert_eq!(ring.len(), size);
        let secret = scalar(v[5]);
        let go = hex::decode(v[6]).unwrap();

        // zanolib drew the secret and one scalar per ring member first.
        let start = size as u64 * 1000 + (1 + size as u64) * 64;
        let proof =
            generate_bge_proof(&mut stream(start), &context, &ring, &secret, index).unwrap();
        let ring_1div8: Vec<[u8; 32]> = ring.iter().map(div8).collect();
        assert!(
            verify_bge_proof(&context, &ring_1div8, &proof),
            "size {size}"
        );
        let go_proof = bge_from_bytes(&go);
        if size <= 4 {
            assert_eq!(bge_bytes(&proof), go, "size {size}");
            assert_eq!((proof.pk.len(), proof.f.len()), (1, 3));
        } else {
            assert_eq!(go_proof.pk.len(), proof.pk.len());
            assert!(
                !verify_bge_proof(&context, &ring_1div8, &go_proof),
                "size {size}"
            );
        }

        // Anything changed, and it no longer verifies.
        assert!(!verify_bge_proof(&[9; 32], &ring_1div8, &proof));
        let mut other = ring_1div8.clone();
        other[index] = POINT_X;
        assert!(!verify_bge_proof(&context, &other, &proof));
        for field in 0..6 {
            let mut bad = proof.clone();
            match field {
                0 => bad.a = bad.b,
                1 => bad.b = POINT_H,
                2 => bad.pk[0] = POINT_U,
                3 => bad.f[1][0] ^= 1,
                4 => bad.y[0] ^= 1,
                _ => bad.z[0] ^= 1,
            }
            assert!(
                !verify_bge_proof(&context, &ring_1div8, &bad),
                "{size} {field}"
            );
        }
        let mut bad = proof.clone();
        bad.f.pop();
        assert!(!verify_bge_proof(&context, &ring_1div8, &bad));
        assert!(!verify_bge_proof(&context, &[], &proof));

        // A wrong secret or index is refused.
        let mut rng = stream(0);
        assert_eq!(
            generate_bge_proof(&mut rng, &context, &ring, &Scalar::ONE, index).unwrap_err(),
            Error::SecretMismatch
        );
        assert_eq!(
            generate_bge_proof(&mut rng, &context, &ring, &secret, size).unwrap_err(),
            Error::InvalidRing
        );
    }
    let mut rng = stream(0);
    assert_eq!(
        generate_bge_proof(&mut rng, &[0; 32], &[], &Scalar::ONE, 0).unwrap_err(),
        Error::InvalidRing
    );
    let big = std::vec![generator_x(); BGE_MAX_RING_SIZE + 1];
    assert_eq!(
        generate_bge_proof(&mut rng, &[0; 32], &big, &Scalar::ONE, 0).unwrap_err(),
        Error::InvalidRing
    );
}

fn bpp_bytes(sig: &BppSignature) -> Vec<u8> {
    let mut tx = Transaction {
        version: 2,
        ..Default::default()
    };
    tx.proofs.push(Variant::OutsRangeProof(ZcOutsRangeProof {
        bpp: sig.clone(),
        ..Default::default()
    }));
    let bytes = tx.to_bytes();
    // version, five empty sequences but the last (one item), the tag; and
    // the empty aggregation proof at the end.
    bytes[8..bytes.len() - 35].to_vec()
}

fn agg_bytes(proof: &UgAggProof) -> Vec<u8> {
    let mut bytes = Vec::new();
    for part in [
        &proof.amount_commitments_for_rp_aggregation,
        &proof.y0s,
        &proof.y1s,
    ] {
        bytes.push(part.len() as u8);
        bytes.extend(part.iter().flatten());
    }
    bytes.extend_from_slice(&proof.c);
    bytes
}

/// The range proof and its aggregation proof: byte for byte zanolib's for
/// one and two outputs. For three, zanolib's `d` vector is wrong and its
/// proof does not verify; this module's does.
#[test]
fn range_proofs_match_zanolib() {
    for v in vectors("range") {
        let n: usize = v[1].parse().unwrap();
        let context = h32(v[2]);
        let input = keys(&hex::decode(v[3]).unwrap());
        let (go_agg, go_bpp) = (hex::decode(v[4]).unwrap(), hex::decode(v[5]).unwrap());

        let mut amounts = Vec::new();
        let mut amount_scalars = Vec::new();
        let mut masks = Vec::new();
        let mut asset_ids = Vec::new();
        let mut commitments = Vec::new();
        for item in input.as_chunks::<3>().0.iter() {
            let amount = u64::from_le_bytes(item[0][..8].try_into().unwrap());
            assert_eq!(item[0][8..], [0; 24]);
            let mask = scalar_from_bytes(&item[1]).unwrap();
            let asset_id = point_from_bytes(&item[2]).unwrap();
            let amount_scalar = crate::cryptonote::scalar_from_u64(amount);
            commitments.push(
                asset_id
                    .mul(&amount_scalar)
                    .add(&EdwardsPoint::mul_base(&mask)),
            );
            amounts.push(amount);
            amount_scalars.push(amount_scalar);
            masks.push(mask);
            asset_ids.push(asset_id);
        }
        assert_eq!(amounts.len(), n);

        // zanolib drew two scalars per output before the y' masks.
        let mut rng = stream(n as u64 * 7777 + n as u64 * 2 * 64);
        let mut y_primes = Vec::new();
        let mut rp_commitments = Vec::new();
        for amount in &amount_scalars {
            let mut wide = [0u8; 64];
            rng(&mut wide);
            let y_prime = Scalar::from_bytes_mod_order(&wide);
            rp_commitments.push(
                generator_u()
                    .mul(amount)
                    .add(&EdwardsPoint::mul_base(&y_prime)),
            );
            y_primes.push(y_prime);
        }
        let agg = generate_vector_ug_aggregation_proof(
            &mut rng,
            &context,
            &amount_scalars,
            &masks,
            &y_primes,
            &commitments,
            &rp_commitments,
            &asset_ids,
        )
        .unwrap();
        assert_eq!(agg_bytes(&agg), go_agg, "{n} outputs");
        let rp_1div8 = &agg.amount_commitments_for_rp_aggregation;
        let bpp = generate_bpp(&mut rng, &amounts, &y_primes, rp_1div8).unwrap();
        assert_eq!(
            bpp.lv.len(),
            6 + n.next_power_of_two().trailing_zeros() as usize
        );
        assert!(verify_bpp(&bpp, rp_1div8), "{n} outputs");
        if n <= 2 {
            assert_eq!(bpp_bytes(&bpp), go_bpp, "{n} outputs");
        } else {
            // zanolib's proof for three outputs: same shape, but invalid.
            let mut tx = std::vec![2, 0, 0, 0, 0, 0, 1, 47];
            tx.extend_from_slice(&go_bpp);
            tx.extend_from_slice(&[0; 35]);
            let Some(Variant::OutsRangeProof(go)) =
                Transaction::from_bytes(&tx).unwrap().proofs.pop()
            else {
                panic!()
            };
            assert_eq!(go.bpp.a0, bpp.a0);
            assert_ne!(go.bpp, bpp);
            assert!(!verify_bpp(&go.bpp, rp_1div8));
        }

        let commitments_1div8: Vec<[u8; 32]> = commitments.iter().map(div8).collect();
        let asset_ids_1div8: Vec<[u8; 32]> = asset_ids.iter().map(div8).collect();
        let verify_agg = |context: &[u8; 32], c: &[[u8; 32]], a: &[[u8; 32]], p: &UgAggProof| {
            verify_vector_ug_aggregation_proof(context, c, a, p)
        };
        assert!(verify_agg(
            &context,
            &commitments_1div8,
            &asset_ids_1div8,
            &agg
        ));
        assert!(!verify_agg(
            &[1; 32],
            &commitments_1div8,
            &asset_ids_1div8,
            &agg
        ));
        assert!(!verify_agg(
            &context,
            &asset_ids_1div8,
            &commitments_1div8,
            &agg
        ));
        assert!(!verify_agg(&context, &[], &[], &agg));
        for field in 0..4 {
            let mut bad = agg.clone();
            match field {
                0 => bad.amount_commitments_for_rp_aggregation[0] = POINT_U,
                1 => bad.y0s[0][0] ^= 1,
                2 => bad.y1s[n - 1][0] ^= 1,
                _ => bad.c[0] ^= 1,
            }
            assert!(!verify_agg(
                &context,
                &commitments_1div8,
                &asset_ids_1div8,
                &bad
            ));
        }

        // The range proof is about these commitments and no others.
        if n == 2 {
            let mut other = rp_1div8.clone();
            other.swap(0, 1);
            assert!(!verify_bpp(&bpp, &other));
            assert!(!verify_bpp(&bpp, &rp_1div8[..1]));
            for field in 0..8 {
                let mut bad = bpp.clone();
                match field {
                    0 => bad.lv[3] = bad.rv[3],
                    1 => bad.rv[0] = POINT_G,
                    2 => bad.a0 = bad.a,
                    3 => bad.a = bad.b,
                    4 => bad.b = POINT_H,
                    5 => bad.r[0] ^= 1,
                    6 => bad.s[0] ^= 1,
                    _ => bad.delta[0] ^= 1,
                }
                assert!(!verify_bpp(&bpp_clone_check(&bad), rp_1div8), "{field}");
            }
            let mut bad = bpp.clone();
            bad.lv.pop();
            assert!(!verify_bpp(&bad, rp_1div8));
            // A response that is not a reduced scalar.
            let mut bad = bpp.clone();
            bad.r = [0xff; 32];
            assert!(!verify_bpp(&bad, rp_1div8));
        }

        // The secrets must open the commitments.
        let mut wrong = masks.clone();
        wrong[0] = Scalar::ONE;
        assert_eq!(
            generate_vector_ug_aggregation_proof(
                &mut rng,
                &context,
                &amount_scalars,
                &wrong,
                &y_primes,
                &commitments,
                &rp_commitments,
                &asset_ids,
            )
            .unwrap_err(),
            Error::SecretMismatch
        );
    }

    let mut rng = stream(0);
    assert_eq!(
        generate_bpp(&mut rng, &[], &[], &[]).unwrap_err(),
        Error::TooLarge
    );
    assert_eq!(
        generate_bpp(&mut rng, &[1], &[], &[POINT_G]).unwrap_err(),
        Error::TooLarge
    );
    assert_eq!(
        generate_bpp(
            &mut rng,
            &[0; BPP_MAX_VALUES + 1],
            &std::vec![Scalar::ONE; BPP_MAX_VALUES + 1],
            &[POINT_G; BPP_MAX_VALUES + 1]
        )
        .unwrap_err(),
        Error::TooLarge
    );
    assert_eq!(
        generate_vector_ug_aggregation_proof(&mut rng, &[0; 32], &[], &[], &[], &[], &[], &[])
            .unwrap_err(),
        Error::TooLarge
    );
}

/// Round-trips a proof through its serialization.
fn bpp_clone_check(sig: &BppSignature) -> BppSignature {
    let mut tx = std::vec![2, 0, 0, 0, 0, 0, 1, 47];
    tx.extend_from_slice(&bpp_bytes(sig));
    tx.extend_from_slice(&[0; 35]);
    match Transaction::from_bytes(&tx).unwrap().proofs.pop() {
        Some(Variant::OutsRangeProof(p)) => p.bpp,
        _ => panic!(),
    }
}

#[test]
fn bpp_generators() {
    for (name, select_h, index) in [
        ("bpp_gen_0", false, 0),
        ("bpp_gen_0h", true, 0),
        ("bpp_gen_77h", true, 77),
    ] {
        assert_eq!(
            super::super::bpp::generator(select_h, index).compress(),
            h32(vectors(name)[0][1])
        );
    }
}

#[test]
fn double_schnorr_matches_zanolib() {
    let v = &vectors("dss")[0];
    let m = h32(v[1]);
    let (a, b) = (scalar(v[2]), scalar(v[3]));
    let a_pt = generator_x().mul(&a);
    let b_pt = EdwardsPoint::mul_base(&b);
    // zanolib drew the two secrets first.
    let sig = generate_double_schnorr_sig(
        &mut stream(31337 + 128),
        SchnorrGenerator::X,
        &m,
        &a_pt,
        &a,
        &b_pt,
        &b,
    )
    .unwrap();
    let bytes = [sig.c, sig.y0, sig.y1].concat();
    assert_eq!(bytes, hex::decode(v[4]).unwrap());

    let b_bytes = b_pt.compress();
    assert!(verify_double_schnorr_sig(
        SchnorrGenerator::X,
        &m,
        &a_pt,
        &b_bytes,
        &sig
    ));
    assert!(!verify_double_schnorr_sig(
        SchnorrGenerator::G,
        &m,
        &a_pt,
        &b_bytes,
        &sig
    ));
    assert!(!verify_double_schnorr_sig(
        SchnorrGenerator::X,
        &[0; 32],
        &a_pt,
        &b_bytes,
        &sig
    ));
    assert!(!verify_double_schnorr_sig(
        SchnorrGenerator::X,
        &m,
        &b_pt,
        &b_bytes,
        &sig
    ));
    assert!(!verify_double_schnorr_sig(
        SchnorrGenerator::X,
        &m,
        &a_pt,
        &POINT_U,
        &sig
    ));
    for field in 0..3 {
        let mut bad = sig;
        match field {
            0 => bad.c[0] ^= 1,
            1 => bad.y0[0] ^= 1,
            _ => bad.y1 = [0xff; 32],
        }
        assert!(!verify_double_schnorr_sig(
            SchnorrGenerator::X,
            &m,
            &a_pt,
            &b_bytes,
            &bad
        ));
    }

    // Both secrets over G.
    let a_g = EdwardsPoint::mul_base(&a);
    let mut rng = stream(1);
    let sig = generate_double_schnorr_sig(&mut rng, SchnorrGenerator::G, &m, &a_g, &a, &b_pt, &b)
        .unwrap();
    assert!(verify_double_schnorr_sig(
        SchnorrGenerator::G,
        &m,
        &a_g,
        &b_bytes,
        &sig
    ));
    assert!(!verify_double_schnorr_sig(
        SchnorrGenerator::X,
        &m,
        &a_g,
        &b_bytes,
        &sig
    ));
    assert_eq!(
        generate_double_schnorr_sig(&mut rng, SchnorrGenerator::X, &m, &a_g, &a, &b_pt, &b)
            .unwrap_err(),
        Error::SecretMismatch
    );
}

/// zanolib's view wallet tests.
#[test]
fn view_wallet_data() {
    let w = Wallet::generate(&mut stream(11), 0).unwrap();
    let data = w.export_view(12345);
    let json = serde_json::to_string(&data).unwrap();
    assert!(json.contains("\"view_secret_key\"") && !json.contains("\"flags\""));
    let back: ViewWalletData = serde_json::from_str(&json).unwrap();
    assert_eq!(back, data);
    assert_eq!(back.start_height, 12345);
    let view = back.load().unwrap();
    assert!(view.is_view_only());
    assert_eq!(view.address(), w.address());
    assert_eq!(view.spend_public_key(), w.spend_public_key());
    assert_eq!(view.view_secret_key(), w.view_secret_key());

    // The JSON zanolib writes: the address and the view secret are enough.
    let json = std::format!(
        r#"{{"address":"{}","view_secret_key":"{}","start_height":100}}"#,
        w.address(),
        hex::encode(w.view_secret_key())
    );
    let data: ViewWalletData = serde_json::from_str(&json).unwrap();
    assert_eq!(data.load().unwrap().address(), w.address());

    // An auditable wallet keeps its flags, through the address too.
    let audit = Wallet::generate(&mut stream(12), ADDRESS_FLAG_AUDITABLE).unwrap();
    let mut data = audit.export_view(0);
    assert!(
        serde_json::to_string(&data)
            .unwrap()
            .contains("\"flags\":1")
    );
    assert!(data.load().unwrap().is_auditable());
    data.spend_public_key = None;
    data.flags = 0;
    assert_eq!(data.load().unwrap().address(), audit.address());

    // Mismatches and malformed input.
    let other = Wallet::generate(&mut stream(13), 0).unwrap();
    let mut bad = w.export_view(0);
    bad.view_secret_key = hex::encode(other.view_secret_key());
    assert_eq!(bad.load().unwrap_err(), Error::KeyMismatch);
    bad.view_public_key = None;
    assert_eq!(bad.load().unwrap_err(), Error::AddressMismatch);
    let mut bad = w.export_view(0);
    bad.address = None;
    bad.spend_public_key = None;
    assert_eq!(bad.load().unwrap_err(), Error::KeyMismatch);
    let mut bad = w.export_view(0);
    bad.view_secret_key = "zz".into();
    assert_eq!(bad.load().unwrap_err(), Error::InvalidHex);
    let mut bad = w.export_view(0);
    bad.spend_public_key = Some("abcd".into());
    assert_eq!(bad.load().unwrap_err(), Error::InvalidHex);
    let mut bad = w.export_view(0);
    bad.address = Some("nonsense".into());
    assert!(bad.load().is_err());
}
