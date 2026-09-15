//! Known-answer tests for the heap-free API, run without `alloc` too. Vectors
//! mirror `address_tests.rs` and `cardano_tests.rs`.

use crate::crypto::ed25519::public_from_seed;
use crate::crypto::secp256k1::SecpPrivateKey;
use crate::pubkey::PubKey;
use crate::{address, cardano, generate_script};

fn arr32(s: &str) -> [u8; 32] {
    let mut a = [0u8; 32];
    hex::decode_to_slice(s, &mut a).unwrap();
    a
}

/// Generates `format` for `pk` and renders it for `network`, heap-free.
fn render(pk: &PubKey, format: &str, network: &str, want: &str) {
    let script = generate_script(pk, format).unwrap();
    let mut out = [0u8; address::MAX_ADDRESS_LEN];
    let n = address::encode_address_to_slice(format, &script, network, &mut out)
        .unwrap_or_else(|e| panic!("{format}/{network}: {e}"));
    assert_eq!(
        core::str::from_utf8(&out[..n]).unwrap(),
        want,
        "{format}/{network}"
    );
}

#[test]
fn secp256k1_addresses() {
    let sk = SecpPrivateKey::from_bytes(&arr32(
        "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf",
    ))
    .unwrap();
    let pk = PubKey::Secp256k1(sk.public_key());
    for (fmt, net, want) in [
        (
            "eth",
            "ethereum",
            "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7",
        ),
        ("p2pkh", "bitcoin", "1C2yfT2NNAPPHBqXQxxBPvguht2whJWRSi"),
        (
            "p2pkh",
            "bitcoincash",
            "bitcoincash:qpusjxtjrpkyf843mmfzk78yp5qfhhcq3yv38ma5lm",
        ),
        ("p2pkh", "litecoin", "LWFvvfLCSpdSXzXgb6wUfwkfv6QDipAzJc"),
        (
            "p2pkh",
            "electraproto",
            "PKd9pRRDR5saG2WHm3Gi4pfBKdCpm1YfY3",
        ),
        (
            "p2sh:p2pkh",
            "litecoin",
            "MNBNbudWqRT5MhorGVnpk7DDuMX5XCxKnR",
        ),
        (
            "p2wpkh",
            "bitcoin",
            "bc1q0yy3juscd3zfavw76g4h3eqdqzda7qyf58rj4m",
        ),
        (
            "p2wpkh",
            "litecoin",
            "ltc1q0yy3juscd3zfavw76g4h3eqdqzda7qyfsmekdt",
        ),
        (
            "p2wpkh",
            "electraproto",
            "ep1q0yy3juscd3zfavw76g4h3eqdqzda7qyf4r3klt",
        ),
        (
            "p2wsh:p2wpkh",
            "bitcoin",
            "bc1qwg7r0yn6t7ctfaplxuwvlu2yk8q6fd3xsvr3lkq5ud4ylsecczzqgq9ste",
        ),
    ] {
        render(&pk, fmt, net, want);
    }
}

#[test]
fn ed25519_addresses() {
    let massa = PubKey::Ed25519(public_from_seed(&arr32(
        "20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88",
    )));
    render(
        &massa,
        "massa",
        "massa",
        "AU16f3K8uWS8cSJaXb7oDzKUZRqt7392eFPtq2bBBop9PVbyXkMs",
    );

    let cardano_vk = arr32("73fea80d424276ad0978d4fe5310e8bc2d485f5f6bb3bf87612989f112ad5a7d");
    render(
        &PubKey::Ed25519(cardano_vk),
        "cardano",
        "",
        "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8",
    );
    let stake_vk = arr32("09ab278d49b7b86a055185c474c4942281ddfa05a54684c7e8a6f230625aee57");
    let mut out = [0u8; cardano::MAX_CARDANO_ADDRESS_LEN];
    let n = cardano::cardano_base_address_to_slice(
        &cardano::cardano_key_hash(&cardano_vk),
        &cardano::cardano_key_hash(&stake_vk),
        "cardano-testnet",
        &mut out,
    )
    .unwrap();
    assert_eq!(
        core::str::from_utf8(&out[..n]).unwrap(),
        "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae"
    );
}
