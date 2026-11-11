//! Tests against Zano's C++ itself.
//!
//! `testdata/zano_harness.cpp` (not compiled here; `cxx_harness_build.txt`
//! tells how it was built) links the reference's libraries and
//!
//! - printed `testdata/cxx_vectors.txt`: the key derivation and the cipher
//!   of the payload encryption of hard fork 6, what `encrypt_payload_items`
//!   makes of a version 4 and of a version 3 transaction and what
//!   `decrypt_payload_items` reads back, and the wallet blobs of the three
//!   layouts with the values of their fields;
//! - signed, as `wallet2::sign_transfer` does, the unsigned transactions
//!   this module makes for the scenarios below
//!   (`testdata/cxx/*.signed.bin`);
//! - validated, as the daemon does short of the chain, those transactions
//!   and the ones this module signs for the same scenarios, and scanned
//!   them as the wallet does (`testdata/cxx_sign_vectors.txt`).
//!
//! Signing here is deterministic, so the test holds this module to the
//! exact blobs the C++ accepted.

use std::string::{String, ToString};
use std::vec::Vec;

use super::super::crypto::{OutputSecrets, random_scalar};
use super::super::keccak::keccak;
use super::super::payload;
use super::super::*;
use super::{h32, stream};
use crate::cryptonote::{EdwardsPoint, cn_fast_hash, point_from_bytes, scalar_from_bytes};

const VECTORS: &str = include_str!("../testdata/cxx_vectors.txt");
const SIGN_VECTORS: &str = include_str!("../testdata/cxx_sign_vectors.txt");

/// The fields of the lines of `text` whose first fields are `names`.
fn lines(text: &'static str, names: &[&str]) -> Vec<Vec<&'static str>> {
    let found: Vec<Vec<&str>> = text
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|fields| fields.len() >= names.len() && fields[..names.len()] == *names)
        .map(|fields| fields[names.len()..].to_vec())
        .collect();
    assert!(!found.is_empty(), "no vector {names:?}");
    found
}

fn line(text: &'static str, names: &[&str]) -> Vec<&'static str> {
    let mut found = lines(text, names);
    assert_eq!(found.len(), 1, "{names:?}");
    found.remove(0)
}

/// Hex, with `-` for nothing.
fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        Vec::new()
    } else {
        hex::decode(s).unwrap()
    }
}

fn tohex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "-".to_string()
    } else {
        hex::encode(bytes)
    }
}

/// The Keccak sponge of capacity 640 bits, the key and nonce it gives, and
/// ChaCha20.
#[test]
fn hf6_primitives() {
    let vectors = lines(VECTORS, &["key_iv"]);
    assert_eq!(vectors.len(), 3);
    for v in vectors {
        let (domain, data, index) = (unhex(v[0]), unhex(v[1]), v[2].parse::<u64>().unwrap());
        let mut input = domain.clone();
        input.extend_from_slice(&data);
        input.extend_from_slice(&index.to_le_bytes());
        let mut out = [0u8; 40];
        keccak(&input, &mut out);
        assert_eq!(hex::encode(out), [v[3], v[4]].concat());
        if let Ok(data) = <[u8; 32]>::try_from(&data[..]) {
            let domain: [u8; 32] = domain.try_into().unwrap();
            let (key, iv) = chacha20_generate_key_and_iv(&domain, &data, index);
            assert_eq!(hex::encode(&key[..]), v[3]);
            assert_eq!(hex::encode(iv.to_le_bytes()), v[4]);
        }
    }
    // Out of range: nothing is written.
    let mut none = [7u8; 65];
    keccak(b"", &mut none);
    assert_eq!(none, [7u8; 65]);
    keccak(b"", &mut []);
    // Keccak-256 is the same sponge.
    let mut out = [0u8; 32];
    for len in [0usize, 1, 135, 136, 137, 300] {
        let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
        keccak(&data, &mut out);
        assert_eq!(out, cn_fast_hash(&data), "{len}");
    }

    let vectors = lines(VECTORS, &["chacha20"]);
    assert_eq!(vectors.len(), 4);
    for v in vectors {
        let nonce: [u8; 8] = unhex(v[1]).try_into().unwrap();
        let mut data = unhex(v[2]);
        chacha20(&h32(v[0]), &nonce, &mut data);
        assert_eq!(hex::encode(&data), v[3]);
        chacha20(&h32(v[0]), &nonce, &mut data);
        assert_eq!(hex::encode(&data), v[2]);
    }

    let v = line(VECTORS, &["sender_derivation"]);
    let mut data = h32(v[2]);
    payload::crypt_derivation_for_sender(
        &scalar_from_bytes(&h32(v[1])).unwrap(),
        &point_from_bytes(&h32(v[0])).unwrap(),
        &mut data,
    );
    assert_eq!(data, h32(v[3]));
}

/// The entries the harness prints of decrypted items, in its words.
fn dump_items(items: &[Variant]) -> Vec<String> {
    let dump: Vec<String> = items
        .iter()
        .filter_map(|item| match item {
            Variant::Comment(c) => Some(["c:", &tohex(c)].concat()),
            Variant::ServiceAttachment(a) => Some(
                [
                    "a:",
                    &tohex(&a.service_id),
                    ":",
                    &tohex(&a.body),
                    ":",
                    &a.flags.to_string(),
                    ":",
                    &a.security.len().to_string(),
                ]
                .concat(),
            ),
            Variant::Payer(a) => Some(["p:", &hex::encode(a.spend_key)].concat()),
            Variant::Receiver(a) => Some(["r:", &hex::encode(a.spend_key)].concat()),
            _ => None,
        })
        .collect();
    if dump.is_empty() {
        ["-".to_string()].to_vec()
    } else {
        dump
    }
}

/// `encrypt_payload_items` and `decrypt_payload_items`, for a version 4 and
/// a version 3 transaction: the same bytes as the reference, read back by
/// the recipient, by the sender and by a view-only recipient.
#[test]
fn payload_encryption_matches_reference() {
    for name in ["payload_v4", "payload_v3"] {
        let v = line(VECTORS, &[name]);
        let sender = Wallet::from_spend_secret(&h32(v[0]), 0).unwrap();
        let receiver = Wallet::from_spend_secret(&h32(v[2]), 0).unwrap();
        assert_eq!(*sender.view_secret_key(), h32(v[1]));
        assert_eq!(*receiver.view_secret_key(), h32(v[3]));
        let tx_secret = scalar_from_bytes(&h32(v[4])).unwrap();
        let tx_public = EdwardsPoint::mul_base(&tx_secret);
        let plain = Transaction::from_bytes(&unhex(v[6])).unwrap();
        assert_eq!(plain.to_bytes(), unhex(v[6]));

        let mut tx = plain.clone();
        let signer = LocalInputSigner::new(sender.spend_secret_key().unwrap()).unwrap();
        let derivation = payload::encrypt_payload_items(
            &mut tx,
            &tx_secret,
            &tx_public,
            &AccountPublicAddr::from(&receiver.address()),
            &signer,
        )
        .unwrap();
        assert_eq!(*derivation, h32(v[5]), "{name}");
        assert_eq!(hex::encode(tx.to_bytes()), v[7], "{name}");
        assert_ne!(tx, plain);

        let view_only = Wallet::view_only(
            receiver.view_secret_key(),
            receiver.spend_public_key(),
            receiver.flags(),
        )
        .unwrap();
        for (who, wallet, income) in [
            ("_income", &receiver, true),
            ("_outgoing", &sender, false),
            ("_watch", &view_only, true),
        ] {
            let expected = line(VECTORS, &[&[name, who].concat()]);
            assert_eq!(
                *wallet.payload_derivation(&tx, income).unwrap().unwrap(),
                *derivation
            );
            let items = wallet.decrypt_payload_items(&tx, income).unwrap();
            assert_eq!(dump_items(&items), expected, "{name}{who}");
        }
        // The recipient and the sender read every entry back as it was.
        let original: Vec<Variant> = plain
            .extra
            .iter()
            .chain(&plain.attachment)
            .cloned()
            .collect();
        let strip = |items: Vec<Variant>| -> Vec<Variant> {
            items
                .into_iter()
                .filter(|i| !matches!(i, Variant::CryptoChecksum(_)))
                .map(|mut item| {
                    // Encrypting adds keys to the attachments.
                    if let Variant::ServiceAttachment(a) = &mut item {
                        a.security.clear();
                    }
                    item
                })
                .collect()
        };
        assert_eq!(
            strip(receiver.decrypt_payload_items(&tx, true).unwrap()),
            original
        );
        assert_eq!(
            strip(sender.decrypt_payload_items(&tx, false).unwrap()),
            original
        );
        // Someone else gets the entries as they are, and a view-only
        // wallet nothing of what it sent.
        let other = Wallet::generate(&mut stream(3), 0).unwrap();
        assert!(other.payload_derivation(&tx, true).unwrap().is_none());
        assert!(other.payload_derivation(&tx, false).unwrap().is_none());
        assert!(view_only.payload_derivation(&tx, false).unwrap().is_none());
        let raw: Vec<Variant> = tx.extra.iter().chain(&tx.attachment).cloned().collect();
        assert_eq!(other.decrypt_payload_items(&tx, true).unwrap(), raw);
        let scanned = receiver.scan_tx(&tx).unwrap();
        let Some(Variant::ServiceAttachment(payment)) = original
            .iter()
            .find(|i| matches!(i, Variant::ServiceAttachment(a) if a.service_id == b"P"))
        else {
            panic!()
        };
        assert_eq!(scanned.payment_id.as_ref(), Some(&payment.body));
        let comments: Vec<&Variant> = original
            .iter()
            .filter(|i| matches!(i, Variant::Comment(_)))
            .collect();
        assert_eq!(scanned.comments.len(), comments.len());
        assert_eq!(Variant::Comment(scanned.comments[0].clone()), *comments[0]);
        let scanned = other.scan_tx(&tx).unwrap();
        assert_eq!((scanned.payment_id, scanned.comments.len()), (None, 0));

        // A signer without the spend key cannot encrypt.
        struct NoKey;
        impl InputSigner for NoKey {
            fn key_image(
                &self,
                _: &crate::cryptonote::Scalar,
                _: &EdwardsPoint,
            ) -> Result<EdwardsPoint, Error> {
                Err(Error::Unsupported)
            }
            fn sign_clsag(
                &self,
                _: &mut dyn FnMut(&mut [u8]),
                _: &crate::cryptonote::Scalar,
                _: &[u8; 32],
                _: &[ClsagGgxInput],
                _: &EdwardsPoint,
                _: &EdwardsPoint,
                _: &EdwardsPoint,
                _: &crate::cryptonote::Scalar,
                _: &crate::cryptonote::Scalar,
                _: usize,
            ) -> Result<ClsagGgxSig, Error> {
                Err(Error::Unsupported)
            }
        }
        let mut tx = plain.clone();
        assert_eq!(
            payload::encrypt_payload_items(
                &mut tx,
                &tx_secret,
                &tx_public,
                &AccountPublicAddr::from(&receiver.address()),
                &NoKey,
            )
            .unwrap_err(),
            Error::Unsupported
        );
    }
}

fn dump_ref(reference: &Variant) -> String {
    match reference {
        Variant::Uint64(index) => ["g", &index.to_string()].concat(),
        Variant::RefById(id) => ["r", &hex::encode(id.hash), ":", &id.n.to_string()].concat(),
        other => panic!("{other:?}"),
    }
}

fn dump_addr(out: &mut Vec<String>, addr: &AccountPublicAddr) {
    out.push(hex::encode(addr.spend_key));
    out.push(hex::encode(addr.view_key));
    out.push(addr.flags.to_string());
}

/// The fields of an unsigned transaction, as the harness prints them.
fn dump_ftp(out: &mut Vec<String>, f: &FinalizeTxParam) {
    let vec_hex = |items: &[Variant]| {
        let mut bytes = Vec::new();
        super::super::ser::write_vec(&mut bytes, items);
        hex::encode(bytes)
    };
    out.push(f.unlock_time.to_string());
    out.push(vec_hex(&f.extra));
    out.push(vec_hex(&f.attachments));
    dump_addr(out, &f.crypt_address);
    out.push(f.tx_outs_attr.to_string());
    out.push(u8::from(f.shuffle).to_string());
    out.push(f.flags.to_string());
    out.push(hex::encode(f.multisig_id));
    out.push(f.sources.len().to_string());
    for s in &f.sources {
        out.push(s.outputs.len().to_string());
        for e in &s.outputs {
            out.push(dump_ref(&e.out_reference));
            out.push(hex::encode(e.stealth_address));
            out.push(hex::encode(e.concealing_point));
            out.push(hex::encode(e.amount_commitment));
            out.push(hex::encode(e.blinded_asset_id));
        }
        out.push(s.real_output.to_string());
        out.push(hex::encode(s.real_out_tx_key));
        out.push(hex::encode(s.real_out_amount_blinding_mask));
        out.push(hex::encode(s.real_out_asset_id_blinding_mask));
        out.push(s.real_out_in_tx_index.to_string());
        out.push(s.amount.to_string());
        out.push(s.transfer_index.to_string());
        out.push(hex::encode(s.multisig_id));
        out.push(s.ms_sigs_count.to_string());
        out.push(s.ms_keys_count.to_string());
        out.push(u8::from(s.separately_signed_tx_complete).to_string());
        out.push(tohex(&s.htlc_origin));
        out.push(s.asset_id.map_or("-".to_string(), hex::encode));
    }
    out.push(f.selected_transfers.len().to_string());
    out.extend(f.selected_transfers.iter().map(u64::to_string));
    out.push(f.prepared_destinations.len().to_string());
    for d in &f.prepared_destinations {
        out.push(d.amount.to_string());
        out.push(d.addr.len().to_string());
        for a in &d.addr {
            dump_addr(out, a);
        }
        out.push(d.minimum_sigs.to_string());
        out.push(d.amount_to_provide.to_string());
        out.push(d.unlock_time.to_string());
        out.push(d.htlc_options.expiration.to_string());
        out.push(hex::encode(d.htlc_options.htlc_hash));
        out.push(hex::encode(d.asset_id));
        out.push(d.flags.to_string());
        out.push(if f.format == FtpFormat::Current {
            d.payment_id.to_string()
        } else {
            "-".to_string()
        });
    }
    out.push(f.expiration_time.to_string());
    out.push(hex::encode(f.spend_pub_key));
    out.push(f.tx_version.to_string());
    out.push(f.tx_hardfork_id.to_string());
    out.push(f.mode_separate_fee.to_string());
}

/// The wallet blobs of each layout, serialized by the reference from its
/// own structures (those of the releases that had the layout): they parse
/// to the same field values, and serialize back to the same bytes.
#[test]
fn wallet_blobs_match_reference() {
    for (name, format) in [
        ("a", FtpFormat::Legacy),
        ("b", FtpFormat::V2_1_8),
        ("c", FtpFormat::Current),
    ] {
        let v = line(VECTORS, &["ftp", name]);
        let (view, blob) = (h32(v[0]), unhex(v[1]));
        let ftp = FinalizeTxParam::decrypt(&blob, &view).unwrap();
        assert_eq!(ftp.format, format);
        let mut dump = Vec::new();
        dump_ftp(&mut dump, &ftp);
        assert_eq!(dump, v[2..], "ftp {name}");
        assert_eq!(ftp.encrypt(&view), blob);
        assert_eq!(FinalizeTxParam::from_bytes(&ftp.to_bytes()).unwrap(), ftp);
        // The sources hold a reference by id, a HTLC origin and a flag.
        assert!(matches!(
            ftp.sources[1].outputs[1].out_reference,
            Variant::RefById(_)
        ));
        assert!(ftp.sources[1].separately_signed_tx_complete);
        assert_eq!(ftp.prepared_destinations[2].addr.len(), 2);

        let v = line(VECTORS, &["fin", name]);
        let (view, blob) = (h32(v[0]), unhex(v[1]));
        let fin = FinalizedTx::decrypt(&blob, &view).unwrap();
        assert_eq!(fin.ftp, ftp);
        let mut dump = [
            hex::encode(fin.tx.to_bytes()),
            hex::encode(fin.tx_id),
            hex::encode(fin.one_time_key),
        ]
        .to_vec();
        dump.push(tohex(&fin.htlc_origin));
        dump.push(fin.outs_key_images.len().to_string());
        for image in &fin.outs_key_images {
            dump.push(image.out_index.to_string());
            dump.push(hex::encode(image.image));
        }
        dump.push(hex::encode(fin.derivation));
        dump.push(u8::from(fin.was_not_prepared).to_string());
        assert_eq!(dump, v[2..], "fin {name}");
        assert_eq!(fin.encrypt(&view), blob);
        assert!(fin.was_not_prepared && fin.outs_key_images.len() == 2);

        // Every truncation is an error, never a panic.
        let plain = ftp.to_bytes();
        for len in (0..plain.len()).step_by(7) {
            assert!(FinalizeTxParam::from_bytes(&plain[..len]).is_err());
        }
    }
    // A gateway origin, or a gateway address, is not signed here.
    let v = line(VECTORS, &["ftp", "c"]);
    let mut ftp = FinalizeTxParam::decrypt(&unhex(v[1]), &h32(v[0])).unwrap();
    ftp.sources.truncate(1);
    ftp.prepared_destinations.truncate(1);
    let plain = ftp.to_bytes();
    // Where a list starts: the first byte that differs once it is empty.
    let differs = |other: &FinalizeTxParam| {
        let other = other.to_bytes();
        let at = plain.iter().zip(&other).position(|(a, b)| a != b).unwrap();
        (at, plain.len() - other.len())
    };
    let mut without = ftp.clone();
    without.sources.clear();
    let (count, len) = differs(&without);
    let mut bad = plain.clone();
    // The gateway origin ends the source.
    bad[count + len] = 1;
    assert_eq!(FinalizeTxParam::from_bytes(&bad), Err(Error::Unsupported));
    let mut without = ftp.clone();
    without.prepared_destinations.clear();
    let (count, _) = differs(&without);
    let mut bad = plain.clone();
    // The count, the amount, the count of addresses, the tag.
    let tag = count + 1 + 8 + 1;
    assert_eq!(bad[tag], 72);
    bad[tag] = 22;
    assert_eq!(FinalizeTxParam::from_bytes(&bad), Err(Error::Unsupported));
    bad[tag] = 23;
    assert!(FinalizeTxParam::from_bytes(&bad).is_err());
}

/// A second asset: any point will do.
const ASSET: [u8; 32] = POINT_U;
const COIN: u64 = 1_000_000_000_000;

/// How the real output of a source shows its asset.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// Transparent (pre-Zarcanum): the amount in the open.
    Bare,
    /// Confidential, with the bare native asset id (as a coinbase output).
    Explicit,
    /// Confidential, with a blinded asset id.
    Blinded([u8; 32]),
}

/// A source the wallet can spend, with a ring of made-up decoys, in no
/// particular order.
fn make_source(
    w: &Wallet,
    rng: &mut dyn FnMut(&mut [u8]),
    amount: u64,
    kind: Kind,
    ring_size: u64,
    global_base: u64,
) -> TxSource {
    let inv8 = scalar_1div8();
    let tx_secret = random_scalar(rng);
    let tx_key = EdwardsPoint::mul_base(&tx_secret).compress();
    let index = global_base % 3;
    let derivation = w.key_derivation(&tx_key).unwrap();
    let secrets = OutputSecrets::derive(&derivation, index);
    let spend = point_from_bytes(w.spend_public_key()).unwrap();
    let view = point_from_bytes(w.view_public_key()).unwrap();
    let native = generator_h();
    let x = generator_x();
    let random_point =
        |rng: &mut dyn FnMut(&mut [u8])| EdwardsPoint::mul_base(&random_scalar(rng)).compress();

    let real_position = global_base % ring_size;
    let mut outputs = Vec::new();
    let mut masks = ([0u8; 32], [0u8; 32]);
    for j in 0..ring_size {
        let mut entry = TxSourceOutputEntry {
            out_reference: Variant::Uint64(global_base + 3 * j),
            stealth_address: random_point(rng),
            concealing_point: [0; 32],
            amount_commitment: [0; 32],
            blinded_asset_id: [0; 32],
        };
        if j == real_position {
            entry.stealth_address = EdwardsPoint::mul_base(&secrets.h).add(&spend).compress();
        }
        if kind != Kind::Bare {
            let (asset, mask) = match kind {
                Kind::Blinded(asset) if j == real_position => (
                    point_from_bytes(&asset).unwrap(),
                    secrets.asset_blinding_mask.clone(),
                ),
                Kind::Blinded(_) => (native, random_scalar(rng)),
                _ => (native, crate::cryptonote::Scalar::ZERO),
            };
            let blinded = asset.add(&x.mul(&mask));
            entry.blinded_asset_id = blinded.mul(&inv8).compress();
            entry.concealing_point = random_point(rng);
            entry.amount_commitment = random_point(rng);
            if j == real_position {
                let commitment = blinded
                    .mul(&super::super::crypto::scalar_u64(amount))
                    .add(&EdwardsPoint::mul_base(&secrets.amount_blinding_mask));
                entry.amount_commitment = commitment.mul(&inv8).compress();
                entry.concealing_point = view.mul(&secrets.concealing).compress();
                masks = (secrets.amount_blinding_mask.to_bytes(), mask.to_bytes());
            }
        }
        outputs.push(entry);
    }
    // Out of order: signing sorts the ring.
    outputs.rotate_left(1);
    let real_output = (real_position + ring_size - 1) % ring_size;
    TxSource {
        outputs,
        real_output,
        real_out_tx_key: tx_key,
        real_out_amount_blinding_mask: masks.0,
        real_out_asset_id_blinding_mask: masks.1,
        real_out_in_tx_index: index,
        amount,
        transfer_index: global_base,
        multisig_id: [0; 32],
        ms_sigs_count: 0,
        ms_keys_count: 0,
        separately_signed_tx_complete: false,
        htlc_origin: Vec::new(),
        asset_id: Some(match kind {
            Kind::Blinded(asset) => asset,
            _ => NATIVE_COIN_ASSET_ID,
        }),
        is_zc_input: false,
    }
}

fn dest(to: &Wallet, amount: u64, asset_id: [u8; 32], payment_id: u64) -> TxDest {
    TxDest {
        amount,
        addr: [AccountPublicAddr::from(&to.address())].to_vec(),
        asset_id,
        payment_id,
        ..Default::default()
    }
}

fn attachment(id: &[u8], body: &[u8], flags: u8) -> Variant {
    Variant::ServiceAttachment(TxServiceAttachment {
        service_id: id.to_vec(),
        body: body.to_vec(),
        flags,
        ..Default::default()
    })
}

/// An unsigned transaction with what signs it.
struct Scenario {
    name: &'static str,
    sender: Wallet,
    recipient: Wallet,
    ftp: FinalizeTxParam,
    one_time_key: [u8; 32],
}

impl Scenario {
    fn sign(&self) -> FinalizedTx {
        self.sender
            .sign(&mut stream(1000), &self.ftp, Some(&self.one_time_key))
            .unwrap()
    }
}

/// The transactions signed on both sides: every transaction version this
/// module signs, confidential and transparent inputs, the native coin and
/// another asset, payment ids and encrypted entries.
fn scenarios() -> Vec<Scenario> {
    let sender = || Wallet::generate(&mut stream(11), 0).unwrap();
    let recipient = || Wallet::generate(&mut stream(22), 0).unwrap();
    let mut rng = stream(33);
    let fee = COIN / 100;
    let base = |version: u64, hardfork: u64| FinalizeTxParam {
        crypt_address: AccountPublicAddr::from(&recipient().address()),
        spend_pub_key: *sender().spend_public_key(),
        tx_version: version,
        tx_hardfork_id: hardfork,
        selected_transfers: [1, 2].to_vec(),
        format: FtpFormat::Current,
        ..Default::default()
    };
    let key = || random_scalar(&mut stream(44)).to_bytes();
    let (s, r) = (sender(), recipient());
    let mut all = Vec::new();

    // Version 4: two assets, payment ids, a comment, a payment id
    // attachment and one that auditors must not read; shuffled outputs.
    let mut ftp = base(4, 7);
    ftp.shuffle = true;
    ftp.sources = [
        make_source(
            &s,
            &mut rng,
            5 * COIN,
            Kind::Blinded(NATIVE_COIN_ASSET_ID),
            4,
            1000,
        ),
        make_source(&s, &mut rng, 3 * COIN, Kind::Explicit, 4, 2000),
        make_source(&s, &mut rng, 700, Kind::Blinded(ASSET), 3, 3000),
    ]
    .to_vec();
    ftp.prepared_destinations = [
        dest(&r, 6 * COIN, NATIVE_COIN_ASSET_ID, 0x0102_0304_0506_0708),
        dest(&r, 500, ASSET, 77),
        dest(&s, 2 * COIN - fee, NATIVE_COIN_ASSET_ID, 0),
        dest(&s, 200, ASSET, 0),
    ]
    .to_vec();
    // `construct_tx` gives an attachment that has one key a key of its
    // own, in place of the one its sender would decrypt an isolated body
    // with: the sender only reads the one in the extra back.
    ftp.extra = [
        Variant::Comment(b"version four".to_vec()),
        attachment(
            b"J",
            b"for the two of us",
            TX_SERVICE_ATTACHMENT_ENCRYPT_BODY
                | TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE,
        ),
    ]
    .to_vec();
    ftp.attachments = [
        attachment(b"P", b"12345678", TX_SERVICE_ATTACHMENT_ENCRYPT_BODY),
        attachment(b"N", b"in the clear", 0),
        attachment(
            b"I",
            b"not for auditors",
            TX_SERVICE_ATTACHMENT_ENCRYPT_BODY
                | TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE,
        ),
    ]
    .to_vec();
    all.push(("v4_assets", ftp));

    // Version 4: a transparent input beside a confidential one.
    let mut ftp = base(4, 7);
    ftp.expiration_time = 1_900_000_000;
    ftp.sources = [
        make_source(&s, &mut rng, 4 * COIN, Kind::Bare, 3, 100),
        make_source(
            &s,
            &mut rng,
            2 * COIN,
            Kind::Blinded(NATIVE_COIN_ASSET_ID),
            5,
            5000,
        ),
    ]
    .to_vec();
    ftp.prepared_destinations = [
        dest(&r, 5 * COIN, NATIVE_COIN_ASSET_ID, 9),
        dest(&s, COIN - fee, NATIVE_COIN_ASSET_ID, 0),
    ]
    .to_vec();
    all.push(("v4_mixed", ftp));

    // Version 4: transparent inputs only.
    let mut ftp = base(4, 7);
    ftp.sources = [
        make_source(&s, &mut rng, 4 * COIN, Kind::Bare, 2, 200),
        make_source(&s, &mut rng, COIN, Kind::Bare, 1, 300),
    ]
    .to_vec();
    ftp.prepared_destinations = [
        dest(&r, 3 * COIN, NATIVE_COIN_ASSET_ID, 0),
        dest(&s, 2 * COIN - fee, NATIVE_COIN_ASSET_ID, 0),
    ]
    .to_vec();
    all.push(("v4_bare", ftp));

    // Version 3: a transparent input, another asset, and the entries
    // versions 2 and 3 encrypt.
    let mut ftp = base(3, 5);
    ftp.unlock_time = 12345;
    ftp.sources = [
        make_source(&s, &mut rng, 2 * COIN, Kind::Bare, 4, 400),
        make_source(
            &s,
            &mut rng,
            9 * COIN,
            Kind::Blinded(NATIVE_COIN_ASSET_ID),
            3,
            6000,
        ),
        make_source(&s, &mut rng, 1_000_000, Kind::Blinded(ASSET), 4, 7000),
    ]
    .to_vec();
    ftp.prepared_destinations = [
        dest(&r, 10 * COIN, NATIVE_COIN_ASSET_ID, 0),
        dest(&r, 1_000_000, ASSET, 0),
        dest(&s, COIN - fee, NATIVE_COIN_ASSET_ID, 0),
    ]
    .to_vec();
    ftp.extra = [
        Variant::Comment(b"version three".to_vec()),
        Variant::Payer(AccountPublicAddr::from(&s.address())),
        attachment(
            b"Q",
            b"with a proof",
            TX_SERVICE_ATTACHMENT_ENCRYPT_BODY | TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF,
        ),
        attachment(
            b"J",
            b"for the two of us",
            TX_SERVICE_ATTACHMENT_ENCRYPT_BODY
                | TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE
                | TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF,
        ),
    ]
    .to_vec();
    ftp.attachments = [
        attachment(
            b"P",
            b"abcdefgh",
            TX_SERVICE_ATTACHMENT_ENCRYPT_BODY | TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF,
        ),
        attachment(
            b"I",
            b"not for auditors",
            TX_SERVICE_ATTACHMENT_ENCRYPT_BODY
                | TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE,
        ),
    ]
    .to_vec();
    all.push(("v3_mixed", ftp));

    // Version 2: outputs that all show the native asset id, so that the
    // outputs do too.
    let mut ftp = base(2, 4);
    ftp.sources = [
        make_source(&s, &mut rng, 3 * COIN, Kind::Explicit, 3, 8000),
        make_source(&s, &mut rng, 2 * COIN, Kind::Explicit, 2, 9000),
    ]
    .to_vec();
    ftp.prepared_destinations = [
        dest(&r, 4 * COIN, NATIVE_COIN_ASSET_ID, 0),
        dest(&s, COIN - fee, NATIVE_COIN_ASSET_ID, 0),
        dest(&s, 0, NATIVE_COIN_ASSET_ID, 0),
    ]
    .to_vec();
    all.push(("v2_native", ftp));

    all.into_iter()
        .map(|(name, ftp)| Scenario {
            name,
            sender: sender(),
            recipient: recipient(),
            ftp,
            one_time_key: key(),
        })
        .collect()
}

/// The ring of a source in the order of the transaction.
fn sorted_ring(source: &TxSource) -> Vec<ClsagGgxInput> {
    let mut outputs = source.outputs.clone();
    outputs.sort_by_key(|o| match o.out_reference {
        Variant::Uint64(index) => index,
        _ => panic!(),
    });
    outputs
        .iter()
        .map(|o| ClsagGgxInput {
            stealth_address: o.stealth_address,
            amount_commitment: o.amount_commitment,
            blinded_asset_id: o.blinded_asset_id,
        })
        .collect()
}

/// Verifies a signed transaction whole: each input against the ring of
/// the source with its key offsets, and the proofs.
fn verify(fin: &FinalizedTx) -> bool {
    let offsets = |source: &TxSource| -> Vec<u64> {
        let mut indices: Vec<u64> = source
            .outputs
            .iter()
            .map(|o| match o.out_reference {
                Variant::Uint64(index) => index,
                _ => panic!(),
            })
            .collect();
        indices.sort_unstable();
        let mut previous = 0;
        indices
            .into_iter()
            .map(|index| {
                let offset = index - previous;
                previous = index;
                offset
            })
            .collect()
    };
    let mut rings = Vec::new();
    for vin in &fin.tx.vin {
        let key_offsets = match vin {
            Variant::ZcInput(input) => &input.key_offsets,
            Variant::ToKey(input) => &input.key_offsets,
            _ => return false,
        };
        let key_offsets: Vec<u64> = key_offsets
            .iter()
            .map(|o| match o {
                Variant::Uint64(offset) => *offset,
                _ => panic!(),
            })
            .collect();
        let Some(source) = fin.ftp.sources.iter().find(|s| offsets(s) == key_offsets) else {
            return false;
        };
        rings.push(sorted_ring(source));
    }
    let rings: Vec<&[ClsagGgxInput]> = rings.iter().map(Vec::as_slice).collect();
    fin.tx.verify(&VerifyContext::new(&rings)).is_ok()
}

/// What the harness prints of the outputs an account finds.
fn dump_outs(wallet: &Wallet, tx: &Transaction) -> Vec<String> {
    let found = wallet.scan_tx(tx).unwrap();
    let mut out = ["1".to_string()].to_vec();
    for (o, payment_id) in found.outputs.iter().zip(&found.output_payment_ids) {
        out.push(
            [
                o.output_index.to_string(),
                o.amount.to_string(),
                hex::encode(o.asset_id),
                payment_id.to_string(),
            ]
            .join(":"),
        );
    }
    out
}

/// Checks a signed transaction against what the reference said of it.
fn check_against_reference(scenario: &Scenario, who: &str, fin: &FinalizedTx) {
    let name = scenario.name;
    let v = line(SIGN_VECTORS, &[name, who, "check"]);
    let expected = [
        ["tx=", &hex::encode(fin.tx.prefix_hash())].concat(),
        ["version=", &fin.tx.version.to_string()].concat(),
        "semantic=1".to_string(),
        "inputs=1".to_string(),
        "range=1".to_string(),
        "balance=1".to_string(),
        "surjection=1".to_string(),
        "id=1".to_string(),
        "key=1".to_string(),
        ["fee=", &fin.tx.fee().unwrap().to_string()].concat(),
    ];
    assert_eq!(v, expected, "{name} {who}");
    assert_eq!(fin.tx_id, fin.tx.prefix_hash());
    assert_eq!(
        EdwardsPoint::mul_base(&scalar_from_bytes(&fin.one_time_key).unwrap()).compress(),
        fin.tx.tx_pub_key().unwrap()
    );
    for (account, wallet) in [(0, &scenario.sender), (1, &scenario.recipient)] {
        let account = account.to_string();
        let outs = line(SIGN_VECTORS, &[name, who, "outs", &account]);
        assert_eq!(dump_outs(wallet, &fin.tx), outs, "{name} {who} outs");
        let items = line(SIGN_VECTORS, &[name, who, "items", &account]);
        let decrypted = wallet
            .decrypt_payload_items(&fin.tx, account != "0")
            .unwrap();
        assert_eq!(dump_items(&decrypted), items, "{name} {who} items");
    }
    // The key images of the change are those of the outputs the sender
    // finds.
    let own: Vec<u64> = scenario
        .sender
        .scan_tx(&fin.tx)
        .unwrap()
        .outputs
        .iter()
        .map(|o| o.output_index)
        .collect();
    let images: Vec<u64> = fin.outs_key_images.iter().map(|k| k.out_index).collect();
    assert_eq!(images, own, "{name} {who}");
    assert!(!own.is_empty());
}

/// Both ways: what this module signs is what the reference accepted, byte
/// for byte; and what the reference signed from the same unsigned
/// transactions parses, verifies and scans here as it does there.
///
/// Signing is slow without optimizations: the default run signs the
/// scenarios named in `sign`, and checks what the reference signed for all
/// of them.
fn signing_matches_reference(sign: &[&str]) {
    const SIGNED: [(&str, &[u8]); 5] = [
        (
            "v4_assets",
            include_bytes!("../testdata/cxx/v4_assets.signed.bin"),
        ),
        (
            "v4_mixed",
            include_bytes!("../testdata/cxx/v4_mixed.signed.bin"),
        ),
        (
            "v4_bare",
            include_bytes!("../testdata/cxx/v4_bare.signed.bin"),
        ),
        (
            "v3_mixed",
            include_bytes!("../testdata/cxx/v3_mixed.signed.bin"),
        ),
        (
            "v2_native",
            include_bytes!("../testdata/cxx/v2_native.signed.bin"),
        ),
    ];
    let scenarios = scenarios();
    assert_eq!(scenarios.len(), SIGNED.len());
    for (scenario, (name, cxx_blob)) in scenarios.iter().zip(SIGNED) {
        assert_eq!(scenario.name, name);
        let view = scenario.sender.view_secret_key();

        // Signed there, accepted here.
        let fin = scenario.sender.parse_finalized(cxx_blob).unwrap();
        assert_eq!(fin.encrypt(view), cxx_blob, "{name}");
        assert_eq!(fin.ftp, scenario.ftp, "{name}");
        let accepted = line(SIGN_VECTORS, &[name, "cxx", "ACCEPTED"]);
        assert_eq!(hex::encode(cn_fast_hash(&fin.to_bytes())), accepted[0]);
        check_against_reference(scenario, "cxx", &fin);
        if !sign.contains(&name) {
            continue;
        }
        assert!(verify(&fin), "{name}");

        // Signed here, accepted there.
        let signed = scenario.sign();
        let accepted = line(SIGN_VECTORS, &[name, "rust", "ACCEPTED"]);
        assert_eq!(
            hex::encode(cn_fast_hash(&signed.to_bytes())),
            accepted[0],
            "{name}: not the blob the reference accepted"
        );
        assert_eq!(
            scenario
                .sender
                .parse_finalized(&signed.encrypt(view))
                .unwrap(),
            signed
        );
        check_against_reference(scenario, "rust", &signed);

        // The two transactions are built alike: only what is random
        // differs.
        let shape = |tx: &Transaction| {
            let names = |items: &[Variant]| -> Vec<&str> {
                items
                    .iter()
                    .map(Variant::name)
                    .filter(|name| *name != "derivation_hint")
                    .collect()
            };
            (
                tx.version,
                tx.hardfork_id,
                names(&tx.vin),
                names(&tx.extra),
                names(&tx.vout),
                names(&tx.attachment),
                names(&tx.signatures),
                names(&tx.proofs),
                tx.fee(),
            )
        };
        assert_eq!(shape(&signed.tx), shape(&fin.tx), "{name}");
        let key_images = |tx: &Transaction| -> Vec<[u8; 32]> {
            tx.vin.iter().map(|i| *i.key_image().unwrap()).collect()
        };
        assert_eq!(key_images(&signed.tx), key_images(&fin.tx), "{name}");
        assert_eq!(fin.tx.vin, signed.tx.vin, "{name}");
        // What the harness refuses fails here too.
        if name == "v4_mixed" {
            assert!(verify(&signed));
            let mut bad = fin.clone();
            bad.tx.vout.swap(0, 1);
            assert!(!verify(&bad));
        }
    }
}

#[test]
fn signing_matches_reference_quick() {
    signing_matches_reference(&["v4_mixed"]);
}

#[test]
#[ignore = "slow without optimizations"]
fn signing_matches_reference_all() {
    signing_matches_reference(&["v4_assets", "v4_mixed", "v4_bare", "v3_mixed", "v2_native"]);
}

/// Writes what the harness needs to regenerate the fixtures: for each
/// scenario the unsigned blob, the blob this module signs and the keys.
/// Set `OUTSCRIPT_ZANO_CXX_DIR` to a directory and run with `--ignored`.
#[test]
#[ignore = "exports blobs for testdata/zano_harness.cpp"]
fn export_for_harness() {
    let Some(dir) = std::env::var_os("OUTSCRIPT_ZANO_CXX_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    for scenario in scenarios() {
        let view = scenario.sender.view_secret_key();
        let file = |suffix: &str| dir.join([scenario.name, suffix].concat());
        std::fs::write(file(".unsigned.bin"), scenario.ftp.encrypt(view)).unwrap();
        let signed = scenario.sign();
        std::fs::write(file(".rust_signed.bin"), signed.encrypt(view)).unwrap();
        // What the harness must refuse: an output swapped after signing,
        // and a fee that is not the one proven.
        let mut bad = signed.clone();
        bad.tx.vout.swap(0, 1);
        bad.tx_id = bad.tx.prefix_hash();
        std::fs::write(file(".bad_outs.bin"), bad.encrypt(view)).unwrap();
        let mut bad = signed.clone();
        for entry in &mut bad.tx.extra {
            if let Variant::ZarcanumTxDataV1 { fee } = entry {
                *fee += 1;
            }
        }
        bad.tx_id = bad.tx.prefix_hash();
        std::fs::write(file(".bad_fee.bin"), bad.encrypt(view)).unwrap();
        let keys = [
            hex::encode(view),
            hex::encode(scenario.sender.spend_secret_key().unwrap()),
            hex::encode(scenario.recipient.view_secret_key()),
            hex::encode(scenario.recipient.spend_secret_key().unwrap()),
        ]
        .join(" ");
        std::fs::write(file(".keys"), keys).unwrap();
    }
}
