//! Tests for the Zano module.
//!
//! `testdata/go_vectors.txt` was produced by the Go library
//! `KarpelesLab/zanolib`, with a deterministic byte stream in place of its
//! random source (see [`stream`]); the binary fixtures are zanolib's own:
//! two mainnet transactions and a transaction signed by Zano's wallet.
//!
//! `testdata/zanolib_crypto_vectors.txt` is a sample (every eighth line,
//! plus every failure case and the edge cases) of the vector tables in
//! zanolib's `zanocrypto/*_test.go` — themselves lines of the reference
//! implementation's `tests/crypto/tests.txt`. The whole tables (1940
//! vectors) pass too; they are not committed for their size.

use super::*;
use crate::cryptonote::{EdwardsPoint, Scalar, hash_to_ec, scalar_from_bytes};

#[cfg(feature = "alloc")]
mod assets;
#[cfg(feature = "alloc")]
mod chain;
#[cfg(feature = "alloc")]
mod full;
#[cfg(feature = "alloc")]
mod mainnet;
#[cfg(feature = "alloc")]
mod proofs;

pub(super) const VECTORS: &str = include_str!("testdata/go_vectors.txt");

const CRYPTO_VECTORS: &str = include_str!("testdata/zanolib_crypto_vectors.txt");

/// The spend secret of the wallet of zanolib's fixtures.
pub(super) const SPEND_SECRET: &str =
    "d3604ff3032bbd10c072f8a768e9c2bdab9ef94fb2ed51b81b379289afa09209";

pub(super) fn h32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).unwrap_or_else(|e| panic!("bad hex {s:?}: {e}"));
    out
}

/// The fields of the vector lines that start with `name`.
pub(super) fn vectors(name: &str) -> std::vec::Vec<std::vec::Vec<&'static str>> {
    let found: std::vec::Vec<_> = VECTORS
        .lines()
        .map(|line| line.split_whitespace().collect::<std::vec::Vec<_>>())
        .filter(|fields| fields.first() == Some(&name))
        .collect();
    assert!(!found.is_empty(), "no vector {name}");
    found
}

/// The deterministic "random" source the Go vectors were made with: byte
/// `n` is `(n * 197 + 13) % 251`, counting across calls from `start`.
pub(super) fn stream(start: u64) -> impl FnMut(&mut [u8]) {
    let mut n = start;
    move |buf: &mut [u8]| {
        for byte in buf {
            *byte = ((n * 197 + 13) % 251) as u8;
            n += 1;
        }
    }
}

pub(super) fn wallet() -> Wallet {
    Wallet::from_spend_secret(&h32(SPEND_SECRET), 0).unwrap()
}

const KEYS: (&str, &str) = (
    "9f5e1fa93630d4b281b18bb67a3db79e9622fc703cc3ad4a453a82e0a36d51fa",
    "a3f208c8f9ba49bab28eed62b35b0f6be0a297bcd85c2faa1eb1820527bcf7e3",
);

/// zanolib's `TestAddressParse` vectors: address, payment id, flags, kind.
const ADDRESSES: &[(&str, &str, u8, AddressType)] = &[
    (
        "ZxD5aoLDPTdcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp338Se7AxeH",
        "",
        0,
        AddressType::Standard,
    ),
    (
        "iZ2Zi6RmTWwcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp3iTqEsjvJoco1aLSZXS6T",
        "87440d0b9acc42f1",
        0,
        AddressType::Integrated,
    ),
    (
        "ZxD5aoLDPTdcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp3APrDvRoL5C",
        "",
        0xfe,
        AddressType::Standard,
    ),
    (
        "iZ4mBxubNfqcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp3iTrG7nU5rRCWmcozLaMoY95sAbo6",
        "3ba0527bcfb1fa93630d28eed6",
        0xfe,
        AddressType::IntegratedV2,
    ),
    (
        "aZxb9Et6FhP9AinRwcPqSqBKjckre7PgoZjK3q5YG2fUKHYWFZMWjB6YAEAdw4yDDUGEQ7CGEgbqhGRKeadGV1jLYcEJMEmqQFn",
        "",
        0x01,
        AddressType::Auditable,
    ),
    (
        "aiZXDondHWu9AinRwcPqSqBKjckre7PgoZjK3q5YG2fUKHYWFZMWjB6YAEAdw4yDDUGEQ7CGEgbqhGRKeadGV1jLYcEJM9xJH8EbjuRiMJgFmPRATsEV9",
        "3ba0527bcfb1fa93630d28eed6",
        0x01,
        AddressType::AuditableIntegrated,
    ),
];

#[test]
fn address_vectors() {
    for (text, payment_id, flags, kind) in ADDRESSES {
        let address = Address::parse(text).unwrap();
        assert_eq!(address.address_type(), *kind, "{text}");
        assert_eq!(*address.spend_key(), h32(KEYS.0));
        assert_eq!(*address.view_key(), h32(KEYS.1));
        assert_eq!(address.payment_id(), hex::decode(payment_id).unwrap());
        assert_eq!(address.flags(), *flags);
        assert_eq!(address.is_auditable(), flags & 1 == 1);

        let mut buf = [0u8; MAX_ADDRESS_LEN];
        let n = address.encode_to_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], text.as_bytes());
        assert_eq!(std::format!("{address}"), *text);
        assert_eq!(text.parse::<Address>().unwrap(), address);
        // A buffer one byte short is refused.
        assert_eq!(
            address.encode_to_slice(&mut buf[..n - 1]),
            Err(Error::CryptoNote(crate::cryptonote::Error::BufferTooSmall))
        );
    }
}

#[test]
fn address_kinds() {
    for kind in [
        AddressType::Standard,
        AddressType::Integrated,
        AddressType::IntegratedV2,
        AddressType::Auditable,
        AddressType::AuditableIntegrated,
    ] {
        assert_eq!(AddressType::from_prefix(kind.prefix()), Some(kind));
        assert!(!std::format!("{kind}").is_empty());
    }
    assert_eq!(AddressType::from_prefix(0x12), None);
    assert!(AddressType::Auditable.is_auditable() && AddressType::Auditable.has_flags());
    assert!(!AddressType::Integrated.has_flags() && AddressType::Integrated.is_integrated());
}

#[test]
fn address_payment_id() {
    let mut address = Address::parse(ADDRESSES[0].0).unwrap();
    // Standard <-> integrated.
    address
        .set_payment_id(&hex::decode(ADDRESSES[1].1).unwrap())
        .unwrap();
    assert_eq!(address.address_type(), AddressType::Integrated);
    assert_eq!(std::format!("{address}"), ADDRESSES[1].0);
    address.set_payment_id(&[]).unwrap();
    assert_eq!(address.address_type(), AddressType::Standard);
    assert_eq!(std::format!("{address}"), ADDRESSES[0].0);

    // With flags, the integrated kind is the one that carries them.
    let mut address = Address::parse(ADDRESSES[2].0).unwrap();
    address
        .set_payment_id(&hex::decode(ADDRESSES[3].1).unwrap())
        .unwrap();
    assert_eq!(std::format!("{address}"), ADDRESSES[3].0);
    address.set_payment_id(&[]).unwrap();
    assert_eq!(std::format!("{address}"), ADDRESSES[2].0);

    // Auditable <-> auditable integrated.
    let mut address = Address::parse(ADDRESSES[4].0).unwrap();
    address
        .set_payment_id(&hex::decode(ADDRESSES[5].1).unwrap())
        .unwrap();
    assert_eq!(std::format!("{address}"), ADDRESSES[5].0);
    address.set_payment_id(&[]).unwrap();
    assert_eq!(std::format!("{address}"), ADDRESSES[4].0);

    // The longest payment id round-trips; one more byte is refused.
    address.set_payment_id(&[0x5a; MAX_PAYMENT_ID_LEN]).unwrap();
    let text = std::format!("{address}");
    assert!(text.len() <= MAX_ADDRESS_LEN);
    assert_eq!(Address::parse(&text).unwrap(), address);
    assert_eq!(
        address.set_payment_id(&[0; MAX_PAYMENT_ID_LEN + 1]),
        Err(Error::PaymentIdTooLong)
    );
    assert_eq!(PaymentId::new(&[1, 2]).unwrap().as_bytes(), [1, 2]);
    assert!(PaymentId::default().is_empty());
}

#[test]
fn address_errors() {
    use crate::cryptonote::{Error as Cn, encode_address_to_slice};

    assert!(Address::parse("invalid").is_err());
    assert!(Address::parse("").is_err());
    // A flipped character breaks the checksum.
    let mut text = std::string::String::from(ADDRESSES[0].0);
    text.replace_range(10..11, "x");
    assert_eq!(
        Address::parse(&text),
        Err(Error::CryptoNote(Cn::BadChecksum))
    );
    // Far too long.
    assert_eq!(
        Address::parse(&"1".repeat(400)),
        Err(Error::InvalidAddressLength)
    );

    let frame = |prefix: u64, payload: &[u8]| {
        let mut buf = [0u8; 400];
        let n = encode_address_to_slice(prefix, payload, &mut buf).unwrap();
        std::string::String::from_utf8(buf[..n].to_vec()).unwrap()
    };
    // A Monero prefix.
    assert_eq!(
        Address::parse(&frame(18, &[1; 64])),
        Err(Error::UnknownAddressType)
    );
    // Too short for the keys; a standard address with more than flags; an
    // auditable address without flags or with a payment id.
    for (prefix, len) in [
        (0xc5, 63),
        (0xc5, 66),
        (0x98c8, 64),
        (0x98c8, 66),
        (0x36f8, 64),
    ] {
        assert_eq!(
            Address::parse(&frame(prefix, &std::vec![1u8; len])),
            Err(Error::InvalidAddressLength),
            "{prefix:x} {len}"
        );
    }
    assert_eq!(
        Address::parse(&frame(0x3678, &[1u8; 64 + 129])),
        Err(Error::PaymentIdTooLong)
    );
}

#[test]
fn wallet_keys() {
    // Values printed by zanolib for the same spend secret.
    let w = wallet();
    assert!(!w.is_view_only() && !w.is_auditable());
    assert_eq!(w.spend_secret_key(), Some(&h32(SPEND_SECRET)));
    assert_eq!(
        *w.spend_public_key(),
        h32("fae1e56916730ac218db4f0755f481fc502a984c2357bee9788d5082c13fa54c")
    );
    assert_eq!(
        *w.view_secret_key(),
        h32("f21239bd11256b0fb00e8ab2a7067903a0e27903054c4663b56e50eda821190f")
    );
    assert_eq!(
        *w.view_public_key(),
        h32("ee48fe0ed588254c6aec8c28a002d597a58045a37475d2fbf03b38250b2839c2")
    );
    assert_eq!(
        std::format!("{}", w.address()),
        "ZxDs9xR4tkr2oNLjqWdwXZNk2LorA8HX4Yw5xdyvp3u8Ued5UZZXeJB7EqrHE4V65wcj7awQtsMKrcHp1AQb8VFu1VmBz4fWS"
    );
    let audit = Wallet::from_spend_secret(&h32(SPEND_SECRET), ADDRESS_FLAG_AUDITABLE).unwrap();
    assert!(audit.is_auditable());
    assert_eq!(audit.address().address_type(), AddressType::Auditable);
    assert_eq!(
        std::format!("{}", audit.address()),
        "aZxbKZipb4yLF414WKuGTvhu2q2d47aMQFgF8mmjDXmJBeShUQCztz8PmnTj6za8Ky1UVotu3XTD5Li3RznA1Pgn7jErZH3uiaM"
    );

    // The secrets do not show in the debug output.
    let debug = std::format!("{w:?}");
    assert!(!debug.contains("d3604f") && !debug.contains("211, 96"));

    // A spend key that is not a reduced scalar.
    assert!(Wallet::from_spend_secret(&[0xff; 32], 0).is_err());
}

#[test]
fn wallet_view_only_and_generate() {
    let w = wallet();
    let view = Wallet::view_only(w.view_secret_key(), w.spend_public_key(), 0).unwrap();
    assert!(view.is_view_only());
    assert_eq!(view.spend_secret_key(), None);
    assert_eq!(view.address(), w.address());
    assert_eq!(view.view_public_key(), w.view_public_key());
    assert!(Wallet::view_only(&[0xff; 32], w.spend_public_key(), 0).is_err());
    // Not a point: y = 2 is not on the curve.
    let mut bad = [0u8; 32];
    bad[0] = 2;
    assert!(Wallet::view_only(w.view_secret_key(), &bad, 0).is_err());

    let generated = Wallet::generate(&mut stream(3), ADDRESS_FLAG_AUDITABLE).unwrap();
    assert!(generated.is_auditable() && !generated.is_view_only());
    assert_ne!(generated.address(), w.address());

    // A generated wallet takes 64 bytes and reduces them.
    let mut taken = 0;
    let mut rng = |buf: &mut [u8]| {
        taken += buf.len();
        buf.fill(0xff);
    };
    let generated = Wallet::generate(&mut rng, 0).unwrap();
    assert_eq!(taken, 64);
    let secret = *generated.spend_secret_key().unwrap();
    assert!(scalar_from_bytes(&secret).is_ok());
    assert_eq!(
        Wallet::from_spend_secret(&secret, 0).unwrap().address(),
        generated.address()
    );
}

#[test]
fn chacha8_vectors() {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let plain: std::vec::Vec<u8> = (0..200).map(|i| i as u8).collect();

    let want = hex::decode(vectors("chacha8")[0][1]).unwrap();
    let mut data = plain.clone();
    chacha8(&key, &[1, 2, 3, 4, 5, 6, 7, 8], &mut data);
    assert_eq!(data, want);
    chacha8(&key, &[1, 2, 3, 4, 5, 6, 7, 8], &mut data);
    assert_eq!(data, plain);

    let want = hex::decode(vectors("chacha8_crypt")[0][1]).unwrap();
    let mut data = plain[..100].to_vec();
    chacha8_crypt(&key, &mut data);
    assert_eq!(data, want);
    assert_eq!(
        *chacha8_generate_key(&key),
        crate::cryptonote::cn_fast_hash(&key)
    );

    // Whole blocks, a partial one and nothing at all agree with the stream.
    let mut whole = [0u8; 200];
    chacha8(&key, &[0; 8], &mut whole);
    for len in [0, 1, 63, 64, 65, 128, 199] {
        let mut part = std::vec![0u8; len];
        chacha8(&key, &[0; 8], &mut part);
        assert_eq!(part, whole[..len]);
    }
    assert_ne!(whole[..64], [0u8; 64]);
}

#[test]
fn generators() {
    // The constants are the points zanolib's precomputed tables hold; they
    // are also what Zano defines them to be.
    assert_eq!(EdwardsPoint::generator().compress(), POINT_G);
    assert_eq!(hash_to_ec(&POINT_G), POINT_H);
    assert_eq!(NATIVE_COIN_ASSET_ID, POINT_H);
    for (point, bytes) in [
        (generator_h(), POINT_H),
        (generator_h2(), POINT_H2),
        (generator_u(), POINT_U),
        (generator_x(), POINT_X),
    ] {
        assert_eq!(point.compress(), bytes);
        assert!(bool::from(point.is_torsion_free()));
        assert_ne!(point, EdwardsPoint::identity());
    }
    // H + G and H - G, as in zanolib's tables.
    assert_eq!(
        generator_h().add(&EdwardsPoint::generator()).compress(),
        h32("3c7db2eea377ff8ffa6d69020f18144cf5dc4813fc6c8a41abd6f00f1054d99c")
    );
    assert_eq!(
        generator_h().sub(&EdwardsPoint::generator()).compress(),
        h32("f62b2eb2ebe6c10f2e8da3dde2578a4dcfe6085e00c3ec8dfdf5be53f535641d")
    );

    let eight = crate::cryptonote::scalar_from_u64(8);
    assert_eq!(scalar_1div8().mul(&eight), Scalar::ONE);
}

#[test]
fn derivation_hints() {
    for v in vectors("hint") {
        assert_eq!(derivation_hint(&h32(v[1])), v[2].parse::<u16>().unwrap());
    }
}

#[test]
fn key_images() {
    // One line of zanolib's `TestKeyImage` (the rest run with `cryptonote`).
    let public = crate::cryptonote::point_from_bytes(&h32(
        "e46b60ebfe610b8ba761032018471e5719bb77ea1cd945475c4a4abe7224bfd0",
    ))
    .unwrap();
    let secret = scalar_from_bytes(&h32(
        "981d477fb18897fa1f784c89721a9d600bf283f06b89cb018a077f41dcefef0f",
    ))
    .unwrap();
    assert_eq!(
        key_image(&secret, &public).compress(),
        h32("a637203ec41eab772532d30420eac80612fce8e44f1758bc7e2cb1bdda815887")
    );
}

/// The outputs of the transaction zanolib signs from its fixture, which
/// both go to the wallet, scanned one at a time without a heap.
#[test]
fn scan_single_outputs() {
    let w = wallet();
    let view = Wallet::view_only(w.view_secret_key(), w.spend_public_key(), 0).unwrap();
    let tx_pub = h32(vectors("scan_txpub")[0][1]);
    let derivation = view.key_derivation(&tx_pub).unwrap();
    assert_eq!(*derivation, h32(vectors("payment_id")[0][1]));

    for v in vectors("scan") {
        let index: u64 = v[1].parse().unwrap();
        let output = TxOutZarcanum {
            stealth_address: h32(v[5]),
            concealing_point: h32(v[8]),
            amount_commitment: h32(v[9]),
            blinded_asset_id: h32(v[10]),
            encrypted_amount: v[11].parse().unwrap(),
            mix_attr: v[12].parse().unwrap(),
        };
        let found = view
            .scan_output(&derivation, index, &output)
            .unwrap()
            .unwrap();
        assert_eq!(found.output_index, index);
        assert_eq!(found.amount, v[2].parse::<u64>().unwrap());
        assert_eq!(found.asset_id, h32(v[3]));
        assert_eq!(found.is_native, v[4] == "true");
        assert!(found.is_native && found.asset_id == NATIVE_COIN_ASSET_ID);
        assert_eq!(found.stealth_address, h32(v[5]));
        assert_eq!(found.amount_blinding_mask, h32(v[6]));
        assert_eq!(found.asset_id_blinding_mask, h32(v[7]));

        // At another index, or for another wallet, it is someone else's.
        assert_eq!(view.scan_output(&derivation, index + 2, &output), Ok(None));
        let other = Wallet::from_spend_secret(&h32(KEYS_SECRET), 0).unwrap();
        let other_derivation = other.key_derivation(&tx_pub).unwrap();
        assert_eq!(
            other.scan_output(&other_derivation, index, &output),
            Ok(None)
        );

        // Ours, but tampered with.
        let mut bad = output;
        bad.encrypted_amount ^= 1;
        assert_eq!(
            view.scan_output(&derivation, index, &bad),
            Err(Error::MalformedOutput)
        );
        let mut bad = output;
        bad.concealing_point = bad.amount_commitment;
        assert_eq!(
            view.scan_output(&derivation, index, &bad),
            Err(Error::MalformedOutput)
        );
        let mut bad = output;
        bad.blinded_asset_id = [2; 32];
        assert!(view.scan_output(&derivation, index, &bad).is_err());
    }

    // The payment id zanolib encrypted for this transaction.
    let v = &vectors("payment_id")[0];
    let mut body = hex::decode(v[2]).unwrap();
    crypt_payment_id(&derivation, &mut body);
    assert_eq!(body, hex::decode(v[3]).unwrap());
    assert_eq!(body, b"payment-id-1234");

    assert!(view.key_derivation(&[2; 32]).is_err());
}

/// Some other wallet's spend secret.
const KEYS_SECRET: &str = "0100000000000000000000000000000000000000000000000000000000000000";

#[test]
fn errors_display() {
    for e in [
        Error::CryptoNote(crate::cryptonote::Error::BadChecksum),
        Error::UnknownAddressType,
        Error::UnsupportedVariant(99),
        Error::ViewOnly,
    ] {
        assert!(!std::format!("{e}").is_empty());
        let _: crate::Error = e.into();
    }
    assert_eq!(
        std::format!("{}", Error::UnsupportedVariant(99)),
        "unsupported variant tag 99"
    );
}

/// zanolib's `zanocrypto` vector tables: `TestHashToScalar`, `TestHashToEC`,
/// `TestHashToPoint`, `TestKeyImage`, `TestGenerateKeyDerivation`,
/// `TestDerivePublicKey` and `TestDeriveSecretKey`.
#[test]
fn zanolib_crypto_vectors() {
    use crate::cryptonote as cn;

    let mut count = 0;
    for line in CRYPTO_VECTORS.lines() {
        let f: std::vec::Vec<&str> = line.split_whitespace().collect();
        count += 1;
        match f[0] {
            "hash_to_scalar" => {
                let data = if f[1] == "x" {
                    std::vec::Vec::new()
                } else {
                    hex::decode(f[1]).unwrap()
                };
                assert_eq!(cn::hash_to_scalar(&data), h32(f[2]), "{line}");
            }
            "hash_to_ec" => assert_eq!(cn::hash_to_ec(&h32(f[1])), h32(f[2]), "{line}"),
            "hash_to_point" => assert_eq!(cn::hash_to_point(&h32(f[1])), h32(f[2]), "{line}"),
            "generate_key_image" => {
                let (public, secret) = (h32(f[1]), h32(f[2]));
                assert_eq!(cn::generate_key_image(&public, &secret).unwrap(), h32(f[3]));
                let image = key_image(
                    &scalar_from_bytes(&secret).unwrap(),
                    &cn::point_from_bytes(&public).unwrap(),
                );
                assert_eq!(image.compress(), h32(f[3]), "{line}");
            }
            "generate_key_derivation" => {
                let derivation = cn::generate_key_derivation(&h32(f[1]), &h32(f[2]));
                match f[3] {
                    "true" => assert_eq!(derivation.unwrap(), h32(f[4]), "{line}"),
                    _ => assert!(derivation.is_err(), "{line}"),
                }
            }
            "derive_public_key" => {
                let key = cn::derive_public_key(&h32(f[1]), f[2].parse().unwrap(), &h32(f[3]));
                match f[4] {
                    "true" => assert_eq!(key.unwrap(), h32(f[5]), "{line}"),
                    _ => assert!(key.is_err(), "{line}"),
                }
            }
            "derive_secret_key" => {
                let key = cn::derive_secret_key(&h32(f[1]), f[2].parse().unwrap(), &h32(f[3]));
                assert_eq!(*key.unwrap(), h32(f[4]), "{line}");
            }
            other => panic!("unknown vector {other}"),
        }
    }
    assert!(count >= 280);
}
