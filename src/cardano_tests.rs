//! Tests for Cardano addresses and transactions, ported from `cardano_test.go`
//! and `cardanotx_test.go`.

use crate::Error;
use crate::cardano::{
    cardano_base_address, cardano_enterprise_address, cardano_key_hash, cardano_reward_address,
    parse_cardano_address,
};
use crate::cardano_derive::{
    CardanoExtendedKey, cardano_harden as harden, cardano_icarus_master_key,
};
use crate::cardanotx::{CardanoAsset, CardanoInput, CardanoOutput, CardanoSigner, CardanoTx};
use crate::cbor::split_array_items;
use crate::crypto::ed25519;
use crate::hash::blake2b_256;
use crate::script::Script;

// Raw 32-byte Ed25519 public keys decoded from the CIP-19 reference bech32 keys
// addr_vk1w0l2sr2... and stake_vk1px4j0r2...
const CIP19_ADDR_VK: &str = "73fea80d424276ad0978d4fe5310e8bc2d485f5f6bb3bf87612989f112ad5a7d";
const CIP19_STAKE_VK: &str = "09ab278d49b7b86a055185c474c4942281ddfa05a54684c7e8a6f230625aee57";

fn payment_hash() -> [u8; 28] {
    cardano_key_hash(&hex::decode(CIP19_ADDR_VK).unwrap())
}
fn stake_hash() -> [u8; 28] {
    cardano_key_hash(&hex::decode(CIP19_STAKE_VK).unwrap())
}

#[test]
fn cip19_address_vectors() {
    let p = payment_hash();
    let s = stake_hash();

    assert_eq!(
        cardano_base_address(&p, &s, "cardano").unwrap(),
        "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
    );
    assert_eq!(
        cardano_enterprise_address(&p, "cardano").unwrap(),
        "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"
    );
    assert_eq!(
        cardano_reward_address(&s, "cardano").unwrap(),
        "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
    );
    assert_eq!(
        cardano_base_address(&p, &s, "cardano-testnet").unwrap(),
        "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae"
    );
    assert_eq!(
        cardano_reward_address(&s, "cardano-testnet").unwrap(),
        "stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn"
    );
}

#[test]
fn cardano_from_pubkey() {
    let payment_key = hex::decode(CIP19_ADDR_VK).unwrap();
    let s = Script::new(crate::pubkey::PubKey::Ed25519(
        payment_key.clone().try_into().unwrap(),
    ));

    // default (mainnet) enterprise address via the format
    assert_eq!(
        s.address("cardano", &[]).unwrap(),
        "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"
    );

    // testnet enterprise: validate via parse round-trip (same payment hash, net 0)
    let got_test = s.address("cardano", &["cardano-testnet"]).unwrap();
    let out = parse_cardano_address(&got_test).unwrap();
    assert_eq!(
        hex::encode(out.hash().unwrap()),
        "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
    );
}

#[test]
fn cardano_parse_round_trip() {
    let addrs = [
        "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x",
        "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8",
        "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw",
        "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae",
        "stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn",
    ];
    for a in addrs {
        let out = parse_cardano_address(a).unwrap();
        assert_eq!(out.address(&[]).unwrap(), a, "round-trip mismatch for {a}");
    }
}

#[test]
fn cardano_real_tx_body_hash() {
    // A Cardano transaction id is blake2b-256 of the body's exact CBOR bytes.
    // Mainnet tx b94c3185280a4217d5ab922619f74d768e0a7189f653c644c4f2aaccc7498217.
    const WANT_TXID: &str = "b94c3185280a4217d5ab922619f74d768e0a7189f653c644c4f2aaccc7498217";
    let raw = include_str!("../testdata/cardano_mainnet_tx.hex");
    let buf = hex::decode(raw.trim()).unwrap();
    let arr = split_array_items(&buf).unwrap();
    assert_eq!(arr.len(), 4);
    assert_eq!(hex::encode(blake2b_256(&arr[0])), WANT_TXID);
}

fn addr_bytes(addr: &str) -> Vec<u8> {
    parse_cardano_address(addr).unwrap().bytes().to_vec()
}

fn sample_tx() -> CardanoTx {
    let txid =
        hex::decode("5c32d3c670337ad0ef69e5bf8cbd26cee7a736ee0fba41e63ec071671c1a6376").unwrap();
    CardanoTx {
        inputs: vec![CardanoInput { txid, index: 0 }],
        outputs: vec![
            CardanoOutput {
                address: addr_bytes("addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"),
                amount: 1_000_000,
                assets: vec![],
            },
            CardanoOutput {
                address: addr_bytes(
                    "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x",
                ),
                amount: 8_500_000,
                assets: vec![],
            },
        ],
        fee: 170_000,
        ttl: 41_000_000,
        witnesses: vec![],
        parsed: None,
    }
}

#[test]
fn cardano_tx_sign_and_verify() {
    let mut tx = sample_tx();
    let seed = [0x42u8; 32];
    let pub_key = ed25519::public_from_seed(&seed);

    let digest = tx.sign_bytes().unwrap();
    assert_eq!(digest.len(), 32);

    tx.sign(&[seed]).unwrap();
    assert_eq!(tx.witnesses.len(), 1);
    let w = &tx.witnesses[0];
    assert_eq!(w.vkey, pub_key.to_vec());
    assert!(ed25519::verify(
        &pub_key,
        &digest,
        &w.signature.clone().try_into().unwrap()
    ));
    tx.verify().unwrap();

    // Hash() must equal the signing digest (the transaction id).
    assert_eq!(tx.hash().unwrap(), digest);
}

#[test]
fn cardano_tx_round_trip() {
    let mut tx = sample_tx();
    tx.sign(&[[0x07u8; 32]]).unwrap();

    let enc = tx.to_bytes().unwrap();
    let arr = split_array_items(&enc).unwrap();
    assert_eq!(arr.len(), 4);
    // txid must be blake2b-256 of the embedded body bytes
    assert_eq!(blake2b_256(&arr[0]), tx.hash().unwrap());

    let decoded = CardanoTx::from_bytes(&enc).unwrap();
    assert_eq!(decoded.fee, tx.fee);
    assert_eq!(decoded.ttl, tx.ttl);
    assert_eq!(decoded.inputs.len(), tx.inputs.len());
    assert_eq!(decoded.outputs.len(), tx.outputs.len());
    for (a, b) in decoded.inputs.iter().zip(&tx.inputs) {
        assert_eq!(a.txid, b.txid);
        assert_eq!(a.index, b.index);
    }
    for (a, b) in decoded.outputs.iter().zip(&tx.outputs) {
        assert_eq!(a.address, b.address);
        assert_eq!(a.amount, b.amount);
    }
    assert_eq!(decoded.witnesses.len(), 1);
    assert_eq!(decoded.witnesses[0].signature, tx.witnesses[0].signature);

    // re-marshaling the decoded transaction must be byte-identical (deterministic)
    assert_eq!(decoded.to_bytes().unwrap(), enc);
}

#[test]
fn cardano_tx_multiasset() {
    let txid =
        hex::decode("5c32d3c670337ad0ef69e5bf8cbd26cee7a736ee0fba41e63ec071671c1a6376").unwrap();
    let policy = hex::decode("00000000000000000000000000000000000000000000000000000000").unwrap();
    let tx = CardanoTx {
        inputs: vec![CardanoInput { txid, index: 1 }],
        outputs: vec![CardanoOutput {
            address: addr_bytes("addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"),
            amount: 2_000_000,
            assets: vec![CardanoAsset {
                policy_id: policy.clone(),
                asset_name: b"TOKEN".to_vec(),
                amount: 42,
            }],
        }],
        fee: 180_000,
        ttl: 0,
        witnesses: vec![],
        parsed: None,
    };
    let enc = tx.to_bytes().unwrap();
    let decoded = CardanoTx::from_bytes(&enc).unwrap();
    assert_eq!(decoded.outputs.len(), 1);
    assert_eq!(decoded.outputs[0].assets.len(), 1);
    let a = &decoded.outputs[0].assets[0];
    assert_eq!(a.policy_id, policy);
    assert_eq!(a.asset_name, b"TOKEN");
    assert_eq!(a.amount, 42);
    assert_eq!(decoded.outputs[0].amount, 2_000_000);
}

#[test]
fn cardano_asset_amount_overflow() {
    // Aggregating two duplicate (policy, asset name) entries whose amounts
    // overflow u64 must error rather than silently wrapping.
    let txid =
        hex::decode("5c32d3c670337ad0ef69e5bf8cbd26cee7a736ee0fba41e63ec071671c1a6376").unwrap();
    let policy = hex::decode("00000000000000000000000000000000000000000000000000000000").unwrap();
    let tx = CardanoTx {
        inputs: vec![CardanoInput { txid, index: 1 }],
        outputs: vec![CardanoOutput {
            address: addr_bytes("addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"),
            amount: 2_000_000,
            assets: vec![
                CardanoAsset {
                    policy_id: policy.clone(),
                    asset_name: b"TOKEN".to_vec(),
                    amount: u64::MAX,
                },
                CardanoAsset {
                    policy_id: policy,
                    asset_name: b"TOKEN".to_vec(),
                    amount: 1,
                },
            ],
        }],
        fee: 180_000,
        ttl: 0,
        witnesses: vec![],
        parsed: None,
    };
    assert!(tx.to_bytes().is_err());
    assert!(tx.body_bytes().is_err());
}

#[test]
fn cardano_parse_hrp_mismatch() {
    // checksum-valid addresses whose HRP disagrees with the header byte must be
    // rejected (network confusion).
    let bad = [
        // "stake" HRP wrapping an enterprise (payment) header (0x61)
        "stake1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzersuzp9l4",
        // "addr" (mainnet) HRP with a testnet enterprise header (0x60)
        "addr1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers6g8jlq",
        // "addr" (mainnet) HRP with a testnet base header (0x00)
        "addr1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n9a3vl7ljgpcrf6e0p5lrzxyq034l8e5d3gemafc3ey5q9syj92",
    ];
    for a in bad {
        assert!(
            parse_cardano_address(a).is_err(),
            "expected {a} to be rejected"
        );
    }

    // all four legitimate prefixes must still parse
    let good = [
        "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8",
        "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae",
        "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw",
        "stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn",
    ];
    for a in good {
        assert!(parse_cardano_address(a).is_ok(), "expected {a} to parse");
    }
}

// --- BIP32-Ed25519 / CIP-1852 HD derivation ---

/// Mimics standard Ed25519 secret-key expansion (RFC 8032): SHA-512 of the seed,
/// lower half clamped into the scalar, upper half the nonce.
fn expand_seed(seed: &[u8; 32]) -> [u8; 64] {
    let mut h = purecrypto::hash::sha512(seed);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;
    h
}

#[test]
fn cardano_extended_key_matches_stdlib() {
    // For a key expanded from a seed the standard way, both public key and
    // signatures are byte-identical to standard Ed25519.
    for i in 0u8..8 {
        let seed = [i + 1; 32];
        let std_pub = ed25519::public_from_seed(&seed);

        let ek = CardanoExtendedKey::new(&expand_seed(&seed)).unwrap();
        assert_eq!(ek.public_key(), std_pub, "seed {i}: public key mismatch");

        for msg in [&b""[..], &b"cardano"[..], &[0xABu8; 32][..]] {
            let got = ek.sign(msg);
            assert_eq!(
                got,
                ed25519::sign(&seed, msg),
                "seed {i}: signature mismatch"
            );
            assert!(ed25519::verify(&std_pub, msg, &got));
        }
    }
}

#[test]
fn cardano_extended_key_derived_scalar() {
    // A scalar not in freshly-clamped form (as after child derivation) still
    // produces a valid Ed25519 signature.
    let mut secret = expand_seed(&[0x11; 32]);
    let mut carry = 0i32;
    for (i, b) in secret.iter_mut().enumerate().take(28) {
        let v = *b as i32 + (((8 * 0x1234) >> ((i % 4) * 8)) & 0xff) + carry;
        *b = (v & 0xff) as u8;
        carry = v >> 8;
    }
    secret[0] &= 248;
    secret[31] &= 63;
    secret[31] |= 64;

    let ek = CardanoExtendedKey::new(&secret).unwrap();
    let pub_key = ek.public_key();
    let msg = b"derived-key transaction body hash";
    let sig = ek.sign(msg);
    assert!(ed25519::verify(&pub_key, msg, &sig));
}

#[test]
fn cardano_extended_key_bad_length() {
    assert!(CardanoExtendedKey::new(&[0u8; 63]).is_err());
}

#[test]
fn cardano_tx_sign_with_extended_key() {
    let mut tx = sample_tx();
    let ek = CardanoExtendedKey::new(&expand_seed(&[0x55; 32])).unwrap();

    let digest = tx.sign_bytes().unwrap();
    tx.sign_with(&[&ek]).unwrap();
    assert_eq!(tx.witnesses.len(), 1);
    let w = &tx.witnesses[0];
    assert_eq!(w.vkey, ek.cardano_public_key());
    assert!(ed25519::verify(
        &ek.public_key(),
        &digest,
        &w.signature.clone().try_into().unwrap()
    ));

    let enc = tx.to_bytes().unwrap();
    let decoded = CardanoTx::from_bytes(&enc).unwrap();
    assert_eq!(decoded.witnesses.len(), 1);
    assert_eq!(decoded.witnesses[0].signature, w.signature);
}

// Authoritative V2 derivation vectors from typed-io/rust-ed25519-bip32 (used by
// cardano-serialization-lib): parent key D1, its hardened child at 0x80000000
// (D1_H0), and D1_H0's signature over "Hello World".
const D1: &str = "f8a29231ee38d6c5bf715d5bac21c750577aa3798b22d79d65bf97d6fadea15adcd1ee1abdf78bd4be64731a12deb94d3671784112eb6f364b871851fd1c9a247384db9ad6003bbd08b3b1ddc0d07a597293ff85e961bf252b331262eddfad0d";
const D1_H0: &str = "60d399da83ef80d8d4f8d223239efdc2b8fef387e1b5219137ffb4e8fbdea15adc9366b7d003af37c11396de9a83734e30e05e851efa32745c9cd7b42712c890608763770eddf77248ab652984b21b849760d1da74a6f5bd633ce41adceef07a";
const D1_H0_SIG: &str = "90194d57cde4fdadd01eb7cf161780c277e129fc7135b97779a3268837e4cd2e9444b9bb91c0e84d23bba870df3c4bda91a110ef735638fa7a34ea2046d4be04";

#[test]
fn cardano_derive_hardened_vector() {
    let parent = CardanoExtendedKey::new(&hex::decode(D1).unwrap()).unwrap();
    let child = parent.derive_child(0x8000_0000).unwrap();
    assert_eq!(hex::encode(&*child.bytes()), D1_H0);
}

#[test]
fn cardano_derived_key_signs_vector() {
    let ek = CardanoExtendedKey::new(&hex::decode(D1_H0).unwrap()[..64]).unwrap();
    let sig = ek.sign(b"Hello World");
    assert_eq!(hex::encode(sig), D1_H0_SIG);
}

#[test]
fn cardano_icarus_end_to_end() {
    // cardano-serialization-lib vectors for the recovery phrase "test walk nut
    // penalty hip pave soap entry language right filter choice".
    let entropy = hex::decode("df9ed25ed146bf43336a5d7cf7395994").unwrap();
    let master = cardano_icarus_master_key(&entropy, &[]).unwrap();

    let spend = master
        .derive_path(&[harden(1852), harden(1815), harden(0), 0, 0])
        .unwrap();
    let stake = master
        .derive_path(&[harden(1852), harden(1815), harden(0), 2, 0])
        .unwrap();

    let spend_hash = cardano_key_hash(&spend.public_key());
    let stake_hash = cardano_key_hash(&stake.public_key());

    // the spend key is the same one used in the CIP-19 address tests
    assert_eq!(
        hex::encode(spend_hash),
        "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
    );

    assert_eq!(
        cardano_enterprise_address(&spend_hash, "cardano").unwrap(),
        "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"
    );
    assert_eq!(
        cardano_enterprise_address(&spend_hash, "cardano-testnet").unwrap(),
        "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz"
    );
    assert_eq!(
        cardano_base_address(&spend_hash, &stake_hash, "cardano").unwrap(),
        "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwqfjkjv7"
    );
    assert_eq!(
        cardano_base_address(&spend_hash, &stake_hash, "cardano-testnet").unwrap(),
        "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
    );
}

#[test]
fn cardano_public_derivation_matches_private() {
    let entropy = hex::decode("df9ed25ed146bf43336a5d7cf7395994").unwrap();
    let master = cardano_icarus_master_key(&entropy, &[]).unwrap();

    // account/role level (m/1852'/1815'/0'/0), still private so we hold an xpub
    let role = master
        .derive_path(&[harden(1852), harden(1815), harden(0), 0])
        .unwrap();
    let xpub = role.extended_public_key().unwrap();

    for idx in [0u32, 1, 5, 100] {
        let priv_child = role.derive_child(idx).unwrap();
        let pub_child = xpub.derive_child(idx).unwrap();
        assert_eq!(
            priv_child.public_key(),
            pub_child.public_key(),
            "index {idx}: public-path pubkey != private-path pubkey"
        );
    }

    // hardened public derivation must be rejected
    assert!(xpub.derive_child(harden(0)).is_err());
}

#[test]
fn extended_key_zeroizes() {
    use crate::crypto::{Zeroize, ZeroizeOnDrop};
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<crate::CardanoExtendedKey>();

    let root = cardano_icarus_master_key(&[0x42; 16], b"").unwrap();
    let mut key = root.derive_path(&[crate::cardano_harden(1852), 0]).unwrap();
    let copy = key.clone();
    let xprv = key.bytes();
    assert_eq!(xprv.len(), 96);
    assert!(xprv.iter().any(|&b| b != 0));

    key.zeroize();
    // scalar and nonce are gone, and so is the chain code
    assert_eq!(key.bytes().len(), 64);
    assert!(key.bytes().iter().all(|&b| b == 0));
    assert!(key.chain_code().is_none());
    assert_eq!(key.public_key(), [0u8; 32]);
    // a clone is independent
    assert_eq!(*copy.bytes(), *xprv);
}

/// A transaction as another implementation may write it: body fields out of
/// order, a fee that is not in shortest form, withdrawals (5) and a validity
/// start (8), an output with a datum hash, a native script next to the vkey
/// witnesses, a false validity flag and auxiliary data. Returns the
/// transaction and its body.
fn foreign_tx(witness_set: &str) -> (Vec<u8>, Vec<u8>) {
    let body = [
        "a6",
        // 2: fee 170000, as a 64-bit integer
        "02",
        "1b0000000000029810",
        // 0: inputs
        "00",
        "81825820",
        "5c32d3c670337ad0ef69e5bf8cbd26cee7a736ee0fba41e63ec071671c1a6376",
        "00",
        // 8: validity interval start
        "08",
        "1a02000000",
        // 1: outputs, the one with a datum hash
        "01",
        "8183",
        "581d",
        "6194991315c92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e",
        "1a000f4240",
        "5820",
        "1111111111111111111111111111111111111111111111111111111111111111",
        // 5: withdrawals {reward account: 5000000}
        "05",
        "a1581d",
        "e1337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251",
        "1a004c4b40",
        // 3: ttl 41000000, as a 64-bit integer
        "03",
        "1b0000000002719c40",
    ]
    .concat();
    let body = hex::decode(body).unwrap();
    let mut tx = vec![0x84];
    tx.extend_from_slice(&body);
    tx.extend_from_slice(&hex::decode(witness_set).unwrap());
    tx.push(0xf4); // validity flag
    tx.extend_from_slice(&hex::decode("a1016474657374").unwrap()); // {1: "test"}
    (tx, body)
}

/// A witness set with only a native script: {1: [[0, h'22..']]}.
const SCRIPT_WITNESS: &str = "a101818200581c\
     22222222222222222222222222222222222222222222222222222222";

#[test]
fn cardano_parsed_tx_keeps_original_body() {
    let (raw, body) = foreign_tx(SCRIPT_WITNESS);
    let mut tx = CardanoTx::from_bytes(&raw).unwrap();
    assert_eq!(tx.fee, 170_000);
    assert_eq!(tx.ttl, 41_000_000);
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.outputs[0].amount, 1_000_000);
    assert!(tx.witnesses.is_empty());
    let parsed = tx.parsed.as_ref().unwrap();
    assert_eq!(parsed.body(), &body[..]);
    // what the fields do not show
    assert_eq!(parsed.extra_body_keys(), &[8, 5]);
    assert!(parsed.has_extra_witnesses());

    // the id is the hash of the bytes that were given
    let txid = blake2b_256(&body);
    assert_eq!(tx.body_bytes().unwrap(), body);
    assert_eq!(tx.hash().unwrap(), txid);
    assert_eq!(tx.sign_bytes().unwrap(), txid);
    // and not that of the fields encoded anew
    let rebuilt = CardanoTx {
        parsed: None,
        ..tx.clone()
    };
    assert_ne!(rebuilt.hash().unwrap(), txid);

    // nothing is lost on the way back
    assert_eq!(tx.to_bytes().unwrap(), raw);

    // signing signs that id, and keeps everything else as it was
    let seed = [0x42u8; 32];
    tx.sign(&[seed]).unwrap();
    tx.verify().unwrap();
    let signature: [u8; 64] = tx.witnesses[0].signature.clone().try_into().unwrap();
    assert!(ed25519::verify(
        &ed25519::public_from_seed(&seed),
        &txid,
        &signature
    ));
    let signed = tx.to_bytes().unwrap();
    let items = split_array_items(&signed).unwrap();
    assert_eq!(items.len(), 4);
    assert_eq!(items[0], body);
    // {0: [[vkey, signature]], 1: [[0, h'22..']]}
    let mut witness_set = hex::decode("a20081825820").unwrap();
    witness_set.extend_from_slice(&tx.witnesses[0].vkey);
    witness_set.extend_from_slice(&[0x58, 0x40]);
    witness_set.extend_from_slice(&signature);
    witness_set.extend_from_slice(&hex::decode(SCRIPT_WITNESS).unwrap()[1..]);
    assert_eq!(items[1], witness_set);
    assert_eq!(items[2], [0xf4]);
    assert_eq!(items[3], hex::decode("a1016474657374").unwrap());

    let again = CardanoTx::from_bytes(&signed).unwrap();
    assert_eq!(again.hash().unwrap(), txid);
    assert_eq!(again.witnesses.len(), 1);
    again.verify().unwrap();
    assert_eq!(again.parsed, tx.parsed);
    assert_eq!(again.to_bytes().unwrap(), signed);
}

/// The fields of a parsed transaction are a view of its body: changing them
/// does not make another transaction be signed in its name.
#[test]
fn cardano_parsed_tx_fields_must_match_body() {
    let (raw, _) = foreign_tx(SCRIPT_WITNESS);
    let tx = CardanoTx::from_bytes(&raw).unwrap();
    let edits: [fn(&mut CardanoTx); 5] = [
        |tx| tx.fee += 1,
        |tx| tx.ttl = 0,
        |tx| tx.outputs[0].amount -= 1,
        |tx| tx.outputs[0].address[1] ^= 1,
        |tx| tx.inputs[0].index = 1,
    ];
    for edit in edits {
        let mut edited = tx.clone();
        edit(&mut edited);
        assert_eq!(edited.body_bytes().err(), Some(Error::UnsupportedField));
        assert_eq!(edited.hash().err(), Some(Error::UnsupportedField));
        assert_eq!(edited.verify().err(), Some(Error::UnsupportedField));
        assert_eq!(edited.to_bytes().err(), Some(Error::UnsupportedField));
        assert_eq!(edited.sign(&[[1; 32]]).err(), Some(Error::UnsupportedField));
        assert!(edited.witnesses.is_empty());

        // letting go of the original bytes makes it a transaction of its
        // fields alone
        edited.parsed = None;
        let bytes = edited.to_bytes().unwrap();
        let rebuilt = CardanoTx::from_bytes(&bytes).unwrap();
        assert!(
            rebuilt
                .parsed
                .as_ref()
                .unwrap()
                .extra_body_keys()
                .is_empty()
        );
        assert_eq!(rebuilt.hash().unwrap(), edited.hash().unwrap());
    }
}

#[test]
fn cardano_parse_rejects_ambiguous() {
    let (raw, body) = foreign_tx(SCRIPT_WITNESS);
    let with_body = |body: &[u8]| {
        let mut tx = vec![0x84];
        tx.extend_from_slice(body);
        tx.extend_from_slice(&raw[1 + body.len()..]);
        CardanoTx::from_bytes(&tx).map(|_| ())
    };
    with_body(&body).unwrap();

    // a second fee, or a second of a field that is not modelled
    for extra in ["0200", "0500", "0800"] {
        let mut dup = body.clone();
        dup[0] += 1;
        dup.extend_from_slice(&hex::decode(extra).unwrap());
        assert_eq!(with_body(&dup), Err(Error::DuplicateKey), "{extra}");
    }
    // the same key in another width is the same key
    let mut dup = body.clone();
    dup[0] += 1;
    dup.extend_from_slice(&[0x18, 0x02, 0x00]);
    assert_eq!(with_body(&dup), Err(Error::DuplicateKey));
    // a key that is not an unsigned integer
    let mut text_key = body.clone();
    text_key[0] += 1;
    text_key.extend_from_slice(&[0x61, 0x61, 0x00]);
    assert_eq!(with_body(&text_key), Err(Error::InvalidData));
    // a body with more or fewer entries than it says
    let mut short = body.clone();
    short[0] += 1;
    assert!(with_body(&short).is_err());
    let mut long = body.clone();
    long[0] -= 1;
    assert!(with_body(&long).is_err());

    // duplicate vkey witness lists
    let (dup, _) = foreign_tx("a200800080");
    assert_eq!(
        CardanoTx::from_bytes(&dup).map(|_| ()),
        Err(Error::DuplicateKey)
    );
    // a witness set that is not a map
    let (not_map, _) = foreign_tx("80");
    assert_eq!(
        CardanoTx::from_bytes(&not_map).map(|_| ()),
        Err(Error::InvalidData)
    );

    // trailing bytes
    let mut trailing = raw.clone();
    trailing.push(0x00);
    assert_eq!(
        CardanoTx::from_bytes(&trailing).map(|_| ()),
        Err(Error::TrailingData)
    );
    // items past the auxiliary data
    let mut five = raw.clone();
    five[0] = 0x85;
    five.push(0xf6);
    assert_eq!(
        CardanoTx::from_bytes(&five).map(|_| ()),
        Err(Error::InvalidData)
    );
    assert_eq!(
        CardanoTx::from_bytes(&raw[..raw.len() - 1]).map(|_| ()),
        Err(Error::Cbor(crate::cbor::Error::UnexpectedEof))
    );
}

/// Set-tagged (#6.258) inputs and vkey witnesses, as written since Conway,
/// parse and keep their tag.
#[test]
fn cardano_parse_tagged_sets() {
    let mut tx = sample_tx();
    tx.sign(&[[0x07u8; 32]]).unwrap();
    let plain = tx.to_bytes().unwrap();
    let items = split_array_items(&plain).unwrap();

    // tag the inputs: a3 00 <inputs> ... -> a3 00 d9 0102 <inputs> ...
    let mut body = items[0][..2].to_vec();
    body.extend_from_slice(&[0xd9, 0x01, 0x02]);
    body.extend_from_slice(&items[0][2..]);
    // and the vkey witnesses: a1 00 <vkeys>
    let mut witness_set = items[1][..2].to_vec();
    witness_set.extend_from_slice(&[0xd9, 0x01, 0x02]);
    witness_set.extend_from_slice(&items[1][2..]);
    let mut tagged = vec![0x84];
    tagged.extend_from_slice(&body);
    tagged.extend_from_slice(&witness_set);
    tagged.extend_from_slice(&[0xf5, 0xf6]);

    let mut parsed = CardanoTx::from_bytes(&tagged).unwrap();
    assert_eq!(parsed.inputs, tx.inputs);
    assert_eq!(parsed.outputs, tx.outputs);
    assert_eq!(parsed.witnesses.len(), 1);
    assert_eq!(parsed.hash().unwrap(), blake2b_256(&body));
    assert_ne!(parsed.hash().unwrap(), tx.hash().unwrap());
    // the witness was made for the untagged body
    assert_eq!(parsed.verify().err(), Some(Error::SignatureVerification(0)));
    assert_eq!(parsed.to_bytes().unwrap(), tagged);

    parsed.witnesses.clear();
    parsed.sign(&[[0x07u8; 32]]).unwrap();
    parsed.verify().unwrap();
    let signed = parsed.to_bytes().unwrap();
    assert_eq!(signed.len(), tagged.len());
    assert_eq!(&signed[..1 + body.len() + 5], &tagged[..1 + body.len() + 5]);
}

/// A real transaction, with fields and witnesses this crate does not model,
/// keeps its id and every byte.
#[test]
fn cardano_real_tx_round_trip() {
    const WANT_TXID: &str = "b94c3185280a4217d5ab922619f74d768e0a7189f653c644c4f2aaccc7498217";
    let raw = hex::decode(include_str!("../testdata/cardano_mainnet_tx.hex").trim()).unwrap();
    let tx = CardanoTx::from_bytes(&raw).unwrap();
    assert_eq!(hex::encode(tx.hash().unwrap()), WANT_TXID);
    assert!(!tx.parsed.as_ref().unwrap().extra_body_keys().is_empty());
    tx.verify().unwrap();
    assert_eq!(tx.to_bytes().unwrap(), raw);
}
