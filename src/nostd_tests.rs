//! Known-answer tests for the heap-free API, run without `alloc` too. Vectors
//! mirror `address_tests.rs` and `cardano_tests.rs`.

use crate::address::{DecodedAddress, Error};
use crate::crypto::ed25519::public_from_seed;
use crate::crypto::secp256k1::SecpPrivateKey;
use crate::pubkey::PubKey;
use crate::{
    address, base58, cardano, decode_bitcoin_based_address, decode_cardano_address,
    decode_evm_address, decode_massa_address, decode_solana_address, generate_script,
};

fn arr32(s: &str) -> [u8; 32] {
    let mut a = [0u8; 32];
    hex::decode_to_slice(s, &mut a).unwrap();
    a
}

/// Generates `format` for `pk`, renders it for `network`, then decodes the
/// address with `decode` and checks it pays to the same script — heap-free.
fn render(
    pk: &PubKey,
    format: &str,
    network: &str,
    want: &str,
    decode: impl Fn(&str) -> Result<DecodedAddress, Error>,
) {
    let script = generate_script(pk, format).unwrap();
    let mut out = [0u8; address::MAX_ADDRESS_LEN];
    let n = address::encode_address_to_slice(format, &script, network, &mut out)
        .unwrap_or_else(|e| panic!("{format}/{network}: {e}"));
    let addr = core::str::from_utf8(&out[..n]).unwrap();
    assert_eq!(addr, want, "{format}/{network}");
    let decoded = decode(addr).unwrap_or_else(|e| panic!("decode {addr}: {e}"));
    assert_eq!(decoded.script, script, "{addr}");
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
        render(&pk, fmt, net, want, |a| {
            if a.starts_with("0x") {
                decode_evm_address(a)
            } else if net == "electraproto" {
                decode_bitcoin_based_address(net, a)
            } else {
                decode_bitcoin_based_address("auto", a)
            }
        });
    }
}

#[test]
fn bitcoin_decode_details() {
    let tr = "bc1pgf6m46mr8c55veujxg3qvqxfektwmmpfrt5mhwtvwrzeacmm7xaqdndj5l";
    let d = decode_bitcoin_based_address("bitcoin", tr).unwrap();
    assert_eq!((d.format, d.networks), ("p2tr", &["bitcoin"][..]));
    let mut out = [0u8; address::MAX_ADDRESS_LEN];
    let n = address::encode_address_to_slice(d.format, &d.script, "bitcoin", &mut out).unwrap();
    assert_eq!(&out[..n], tr.as_bytes());

    let genesis = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    let d = decode_bitcoin_based_address("auto", genesis).unwrap();
    assert_eq!(d.networks, &["bitcoin", "bitcoin-cash"]);
    assert_eq!(
        decode_bitcoin_based_address("litecoin", genesis),
        Err(Error::UnsupportedVersion(0))
    );
    assert_eq!(
        decode_bitcoin_based_address("litecoin", tr),
        Err(Error::NetworkMismatch)
    );
    // prefix-less cashaddr
    let d =
        decode_bitcoin_based_address("auto", "qpusjxtjrpkyf843mmfzk78yp5qfhhcq3yv38ma5lm").unwrap();
    assert_eq!(d.networks, &["bitcoin-cash"]);
    for bad in ["", "1", "111", "1111111111", "bc1qqqqq"] {
        assert!(decode_bitcoin_based_address("auto", bad).is_err(), "{bad}");
    }

    assert_eq!(
        decode_evm_address("0x2aEb8ADD8337360E088B7D9ce4e857b9BE60f3a7"),
        Err(Error::BadChecksum)
    );
    assert!(decode_evm_address("0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7").is_ok());
    assert!(decode_evm_address("0x2aeb8add8337360e088b7d9ce4e857b9be60f3aZ").is_err());
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
        decode_massa_address,
    );

    // a Solana address is the plain base58 of the key
    let PubKey::Ed25519(key) = massa else {
        unreachable!()
    };
    let mut b58 = [0u8; 44];
    let n = base58::encode_to_slice(&key, &mut b58).unwrap();
    render(
        &massa,
        "solana",
        "solana",
        core::str::from_utf8(&b58[..n]).unwrap(),
        decode_solana_address,
    );

    let cardano_vk = arr32("73fea80d424276ad0978d4fe5310e8bc2d485f5f6bb3bf87612989f112ad5a7d");
    render(
        &PubKey::Ed25519(cardano_vk),
        "cardano",
        "",
        "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8",
        decode_cardano_address,
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
    let base = core::str::from_utf8(&out[..n]).unwrap();
    assert_eq!(
        base,
        "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae"
    );
    let d = decode_cardano_address(base).unwrap();
    assert_eq!((d.script.len(), d.networks), (57, &["cardano-testnet"][..]));
}
