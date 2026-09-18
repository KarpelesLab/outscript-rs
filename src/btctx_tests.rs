//! Ported known-answer tests from `btctx_test.go` and `p2tr_test.go`.

use crate::Error;
use crate::btctx::{BtcTx, BtcTxInput, BtcTxOutput, BtcTxSign};
use crate::crypto::secp256k1::{SecpPrivateKey, bip340_sign, bip340_verify, taproot_tweak};
use crate::script::Script;

fn key(hex_s: &str) -> SecpPrivateKey {
    let mut s = [0u8; 32];
    s.copy_from_slice(&hex::decode(hex_s).unwrap());
    SecpPrivateKey::from_bytes(&s).unwrap()
}

fn parse(hex_s: &str) -> BtcTx {
    BtcTx::from_bytes(&hex::decode(hex_s).unwrap()).unwrap()
}

#[test]
fn parse_txid() {
    let tx = parse(
        "0100000003362c10b042d48378b428d60c5c98d8b8aca7a03e1a2ca1048bfd469934bbda95010000008b483045022046c8bc9fb0e063e2fc8c6b1084afe6370461c16cbf67987d97df87827917d42d022100c807fa0ab95945a6e74c59838cc5f9e850714d8850cec4db1e7f3bcf71d5f5ef0141044450af01b4cc0d45207bddfb47911744d01f768d23686e9ac784162a5b3a15bc01e6653310bdd695d8c35d22e9bb457563f8de116ecafea27a0ec831e4a3e9feffffffffc19529a54ae15c67526cc5e20e535973c2d56ef35ff51bace5444388331c4813000000008b48304502201738185959373f04cc73dbbb1d061623d51dc40aac0220df56dabb9b80b72f49022100a7f76bde06369917c214ee2179e583fefb63c95bf876eb54d05dfdf0721ed772014104e6aa2cf108e1c650e12d8dd7ec0a36e478dad5a5d180585d25c30eb7c88c3df0c6f5fd41b3e70b019b777abd02d319bf724de184001b3d014cb740cb83ed21a6ffffffffbaae89b5d2e3ca78fd3f13cf0058784e7c089fb56e1e596d70adcfa486603967010000008b483045022055efbaddb4c67c1f1a46464c8f770aab03d6b513779ad48735d16d4c5b9907c2022100f469d50a5e5556fc2c932645f6927ac416aa65bc83d58b888b82c3220e1f0b73014104194b3f8aa08b96cae19b14bd6c32a92364bea3051cb9f018b03e3f09a57208ff058f4b41ebf96b9911066aef3be22391ac59175257af0984d1432acb8f2aefcaffffffff0340420f00000000001976a914c0fbb13eb10b57daa78b47660a4ffb79c29e2e6b88ac204e0000000000001976a9142cae94ffdc05f8214ccb2b697861c9c07e3948ee88ac1c2e0100000000001976a9146e03561cd4d6033456cc9036d409d2bf82721e9888ac00000000",
    );
    assert_eq!(
        hex::encode(tx.hash()),
        "38d4cfeb57d6685753b7a3b3534c3cb576c34ca7344cd4582f9613ebf0c2b02a"
    );
}

#[test]
fn parse_witness_txid() {
    let tx = parse(
        "0100000000010213206299feb17742091c3cb2ab45faa3aa87922d3c030cafb3f798850a2722bf0000000000feffffffa12f2424b9599898a1d30f06e1ce55eba7fabfeee82ae9356f07375806632ff3010000006b483045022100fcc8cf3014248e1a0d6dcddf03e80f7e591605ad0dbace27d2c0d87274f8cd66022053fcfff64f35f22a14deb657ac57f110084fb07bb917c3b42e7d033c54c7717b012102b9e4dcc33c9cc9cb5f42b96dddb3b475b067f3e21125f79e10c853e5ca8fba31feffffff02206f9800000000001976a9144841b9874d913c430048c78a7b18baebdbea440588ac8096980000000000160014e4873ef43eac347471dd94bc899c51b395a509a502483045022100dd8250f8b5c2035d8feefae530b10862a63030590a851183cb61b3672eb4f26e022057fe7bc8593f05416c185d829b574290fb8706423451ebd0a0ae50c276b87b43012102179862f40b85fa43487500f1d6b13c864b5eb0a83999738db0f7a6b91b2ec64f00db080000",
    );
    assert_eq!(
        hex::encode(tx.hash()),
        "99e7484eafb6e01622c395c8cae7cb9f8822aab6ba993696b39df8b60b0f4b11"
    );
}

const BIP143_TX: &str = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";

#[test]
fn p2pk_and_p2wpkh_bip143() {
    let key0 = key("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    let key1 = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");

    // script generation checks
    let s0 = Script::new(key0.public_key()).generate("p2pk").unwrap();
    assert_eq!(
        hex::encode(&s0),
        "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac"
    );
    let s1 = Script::new(key1.public_key()).generate("p2wpkh").unwrap();
    assert_eq!(
        hex::encode(&s1),
        "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"
    );

    let mut tx = parse(BIP143_TX);
    tx.sign(&[
        BtcTxSign::new(&key0, "p2pk"),
        BtcTxSign::new(&key1, "p2wpkh").amount(600000000),
    ])
    .unwrap();

    assert_eq!(
        hex::encode(&tx.inputs[0].script),
        "4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01"
    );
    assert_eq!(
        hex::encode(&tx.inputs[1].witnesses[0]),
        "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
    );

    let signed = "0100000000010".to_string()
        + "2fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01210"
        + "25476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";
    assert_eq!(hex::encode(tx.bytes()), signed);
}

#[test]
fn p2sh_p2wpkh() {
    let k = key("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf");
    let mut tx = parse(
        "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000",
    );
    tx.sign(&[BtcTxSign::new(&k, "p2sh:p2wpkh").amount(1000000000)])
        .unwrap();
    let expected = "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000";
    assert_eq!(hex::encode(tx.bytes()), expected);
}

#[test]
fn p2wsh_p2pkh_matches_p2wpkh_sig() {
    let key0 = key("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    let key1 = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
    let mut tx = parse(BIP143_TX);
    tx.sign(&[
        BtcTxSign::new(&key0, "p2pk"),
        BtcTxSign::new(&key1, "p2wsh:p2pkh").amount(600000000),
    ])
    .unwrap();
    assert_eq!(
        hex::encode(&tx.inputs[1].witnesses[0]),
        "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
    );
    assert_eq!(tx.inputs[1].witnesses.len(), 3);
    assert_eq!(
        hex::encode(&tx.inputs[1].witnesses[1]),
        "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
    );
    assert_eq!(
        hex::encode(&tx.inputs[1].witnesses[2]),
        "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"
    );
    assert!(tx.inputs[1].script.is_empty());
}

#[test]
fn p2wsh_p2pk() {
    let key0 = key("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    let key1 = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
    let mut tx = parse(BIP143_TX);
    tx.sign(&[
        BtcTxSign::new(&key0, "p2pk"),
        BtcTxSign::new(&key1, "p2wsh:p2pk").amount(600000000),
    ])
    .unwrap();
    assert_eq!(tx.inputs[1].witnesses.len(), 2);
    let expected_ws = Script::new(key1.public_key()).generate("p2pk").unwrap();
    assert_eq!(tx.inputs[1].witnesses[1], expected_ws);
}

#[test]
fn p2wsh_autodetect() {
    let key0 = key("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    let key1 = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
    let mut tx = parse(BIP143_TX);
    tx.inputs[1].script = Script::new(key1.public_key())
        .generate("p2wsh:p2pkh")
        .unwrap();
    tx.sign(&[
        BtcTxSign::new(&key0, "p2pk"),
        BtcTxSign::new(&key1, "p2wsh").amount(600000000),
    ])
    .unwrap();
    assert_eq!(
        hex::encode(&tx.inputs[1].witnesses[0]),
        "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
    );
    assert_eq!(tx.inputs[1].witnesses.len(), 3);
    assert!(tx.inputs[1].script.is_empty());
}

#[test]
fn compute_size_prefill_ge_signed() {
    let key0 = key("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    let key1 = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
    for scheme in [
        "p2wsh",
        "p2wsh:p2pk",
        "p2wsh:p2pkh",
        "p2wsh:p2puk",
        "p2wsh:p2pukh",
    ] {
        let mut est = parse(BIP143_TX);
        est.inputs[0].prefill("p2pk").unwrap();
        est.inputs[1].prefill(scheme).unwrap();
        let estimated = est.compute_size();

        let mut sig_tx = parse(BIP143_TX);
        let sign_scheme = if scheme == "p2wsh" {
            "p2wsh:p2pkh"
        } else {
            scheme
        };
        sig_tx
            .sign(&[
                BtcTxSign::new(&key0, "p2pk"),
                BtcTxSign::new(&key1, sign_scheme).amount(600000000),
            ])
            .unwrap();
        assert!(estimated >= sig_tx.compute_size(), "scheme {scheme}");
    }
}

#[test]
fn btc_output_json() {
    let v = BtcTxOutput {
        amount: crate::BtcAmount(123_456_700),
        n: 0,
        script: Vec::new(),
    };
    let j = serde_json::to_string(&v).unwrap();
    assert!(j.starts_with("{\"value\":1.23456700,"), "got {j}");

    let parsed: BtcTxOutput = serde_json::from_str("{\"value\":\"2.424242\"}").unwrap();
    assert_eq!(parsed.amount.0, 242_424_200);
}

#[test]
fn btc_tx_json_roundtrip() {
    let tx = parse(BIP143_TX);
    let j = serde_json::to_string(&tx).unwrap();
    let tx2: BtcTx = serde_json::from_str(&j).unwrap();
    assert_eq!(tx.bytes(), tx2.bytes());
}

// --- taproot ---

fn arr32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

#[test]
fn bip341_tweak_vector() {
    let internal = arr32("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
    let (tweaked, _) = taproot_tweak(&internal).unwrap();
    assert_eq!(
        hex::encode(tweaked),
        "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
    );
}

#[test]
fn p2tr_generate_and_address() {
    let k = key("0101010101010101010101010101010101010101010101010101010101010101");
    let s = Script::new(k.public_key());
    let script = s.generate("p2tr").unwrap();
    assert_eq!(script.len(), 34);
    assert_eq!(&script[..2], &[0x51, 0x20]);
    let addr = s.address("p2tr", &["bitcoin"]).unwrap();
    assert!(addr.starts_with("bc1p"));
    let out = crate::parse_bitcoin_based_address("bitcoin", &addr).unwrap();
    assert_eq!(out.bytes(), &script[..]);
}

#[test]
fn p2tr_sign_produces_valid_sig() {
    let k = key("0101010101010101010101010101010101010101010101010101010101010101");
    let s = Script::new(k.public_key());
    let script_pubkey = s.generate("p2tr").unwrap();

    let mut tx = BtcTx {
        version: 2,
        inputs: vec![BtcTxInput {
            sequence: 0xffffffff,
            ..Default::default()
        }],
        outputs: vec![BtcTxOutput {
            amount: crate::BtcAmount(90000),
            n: 0,
            script: script_pubkey.clone(),
        }],
        locktime: 0,
    };
    tx.sign(&[BtcTxSign::new(&k, "p2tr")
        .amount(100000)
        .prev_script(script_pubkey.clone())])
        .unwrap();

    assert_eq!(tx.inputs[0].witnesses.len(), 1);
    assert_eq!(tx.inputs[0].witnesses[0].len(), 64);

    let keys = [BtcTxSign {
        key: None,
        scheme: String::new(),
        amount: crate::BtcAmount(100000),
        sighash: 0,
        prev_script: script_pubkey.clone(),
        ..Default::default()
    }];
    let digest = tx.taproot_sighash(&keys, 0).unwrap();
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&script_pubkey[2..]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&tx.inputs[0].witnesses[0]);
    assert!(bip340_verify(&xonly, &digest, &sig));
}

#[test]
fn p2tr_external_signer() {
    // Simulate a TSS/HSM that holds the already-tweaked key.
    use crate::btctx::Signer;
    use crate::crypto::secp256k1::SecpPublicKey;

    let internal = key("0202020202020202020202020202020202020202020202020202020202020202");
    let pub_comp = internal.public_key().serialize_compressed();
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&pub_comp[1..]);
    let (tweaked_x, _) = taproot_tweak(&x_only).unwrap();

    // External signer that already knows its tweaked scalar.
    struct Ext {
        tweaked_secret: [u8; 32],
    }
    impl Signer for Ext {
        fn ecdsa_public_key(&self) -> Option<SecpPublicKey> {
            None
        }
        fn sign_taproot(&self, sighash: &[u8; 32]) -> Result<[u8; 64], crate::crypto::SignerError> {
            bip340_sign(&self.tweaked_secret, sighash, &[0u8; 32])
                .map_err(|_| crate::crypto::SignerError)
        }
    }

    // Compute the tweaked secret the way the library would internally.
    let tweaked_secret = compute_tweaked_secret(&internal);
    let signer = Ext { tweaked_secret };

    let mut script_pubkey = vec![0x51, 0x20];
    script_pubkey.extend_from_slice(&tweaked_x);

    let mut tx = BtcTx {
        version: 2,
        inputs: vec![BtcTxInput {
            sequence: 0xffffffff,
            ..Default::default()
        }],
        outputs: vec![BtcTxOutput {
            amount: crate::BtcAmount(90000),
            n: 0,
            script: script_pubkey.clone(),
        }],
        locktime: 0,
    };
    tx.sign(&[BtcTxSign::new(&signer, "p2tr")
        .amount(100000)
        .prev_script(script_pubkey.clone())])
        .unwrap();

    let keys = [BtcTxSign {
        key: None,
        scheme: String::new(),
        amount: crate::BtcAmount(100000),
        sighash: 0,
        prev_script: script_pubkey.clone(),
        ..Default::default()
    }];
    let digest = tx.taproot_sighash(&keys, 0).unwrap();
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&tx.inputs[0].witnesses[0]);
    assert!(bip340_verify(&tweaked_x, &digest, &sig));
}

#[test]
fn extract_and_verify_p2wpkh() {
    use crate::btctxparse::extract_btc_input_sig;
    use crate::crypto::secp256k1::parse_der_signature;

    let key0 = key("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    let key1 = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
    let mut tx = parse(BIP143_TX);
    tx.sign(&[
        BtcTxSign::new(&key0, "p2pk"),
        BtcTxSign::new(&key1, "p2wpkh").amount(600000000),
    ])
    .unwrap();

    let sigs = extract_btc_input_sig(&tx.inputs[1].script, &tx.inputs[1].witnesses).unwrap();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].scheme, "p2wpkh");
    assert_eq!(sigs[0].sighash_flag, 1);

    let digest = tx
        .input_sighash(1, &sigs[0], &[], crate::BtcAmount(600000000))
        .unwrap();

    let der = &tx.inputs[1].witnesses[0];
    let (r, s) = parse_der_signature(&der[..der.len() - 1]).unwrap();
    assert!(key1.public_key().verify(&digest, &r, &s));
}

#[test]
fn extract_and_verify_p2pkh() {
    use crate::btctxparse::extract_btc_input_sig;
    use crate::crypto::secp256k1::parse_der_signature;

    let k = key("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    let prev_script = Script::new(k.public_key()).generate("p2pkh").unwrap();

    let tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000001000000000 0ffffffff01a0860100000000001976a91400112233445566778899aabbccddeeff0011223388ac00000000"
        .replace(' ', "");
    let mut tx = parse(&tx_hex);
    tx.sign(&[BtcTxSign::new(&k, "p2pkh")]).unwrap();

    let sigs = extract_btc_input_sig(&tx.inputs[0].script, &tx.inputs[0].witnesses).unwrap();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].scheme, "p2pkh");

    let digest = tx
        .input_sighash(0, &sigs[0], &prev_script, crate::BtcAmount(0))
        .unwrap();
    let der = &{
        let (s, n) = crate::parse_push_bytes(&tx.inputs[0].script).unwrap();
        let _ = n;
        s.to_vec()
    };
    let (r, s) = parse_der_signature(&der[..der.len() - 1]).unwrap();
    assert!(k.public_key().verify(&digest, &r, &s));
}

// Helper mirroring the internal taproot scalar tweak, for the external-signer test.
fn compute_tweaked_secret(k: &SecpPrivateKey) -> [u8; 32] {
    use crate::crypto::secp256k1::tagged_hash;
    use num_bigint::BigUint;
    use num_traits::Num;

    let n = BigUint::from_str_radix(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap();
    let pub_comp = k.public_key().serialize_compressed();
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&pub_comp[1..]);
    let (_, parity) = taproot_tweak(&x_only).unwrap();

    // We don't have direct scalar access; recompute d from the known test key bytes.
    let d_bytes = arr32("0202020202020202020202020202020202020202020202020202020202020202");
    let mut d = BigUint::from_bytes_be(&d_bytes);
    if pub_comp[0] == 0x03 {
        d = (&n - (&d % &n)) % &n;
    }
    let t = BigUint::from_bytes_be(&tagged_hash("TapTweak", &[&x_only]));
    d = (&d + &t) % &n;
    if parity == 1 {
        d = (&n - (&d % &n)) % &n;
    }
    let db = d.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - db.len()..].copy_from_slice(&db);
    out
}

#[test]
fn parse_rejects_truncated_and_oversized_counts() {
    // version, segwit marker/flag, 1 input with empty script, 0 outputs
    let mut buf = hex::decode("010000000001").unwrap();
    buf.push(1); // input count
    buf.extend_from_slice(&[0u8; 36]); // txid + vout
    buf.push(0); // empty scriptSig
    buf.extend_from_slice(&[0xff; 4]); // sequence
    buf.push(0); // output count
    // a witness count of u64::MAX must fail on EOF, not attempt the allocation
    buf.push(0xff);
    buf.extend_from_slice(&[0xff; 8]);
    assert!(BtcTx::from_bytes(&buf).is_err());

    for len in 0..buf.len() {
        assert!(BtcTx::from_bytes(&buf[..len]).is_err());
    }
}

#[cfg(feature = "std")]
#[test]
fn read_from_matches_from_bytes() {
    let hex_s = "0100000001c19529a54ae15c67526cc5e20e535973c2d56ef35ff51bace5444388331c4813000000000000000000010000000000000000016a00000000";
    let raw = hex::decode(hex_s).unwrap();
    let mut tx = BtcTx::default();
    let n = tx.read_from(&mut &raw[..]).unwrap();
    assert_eq!(n as usize, raw.len());
    assert_eq!(tx.bytes(), raw);
    assert_eq!(BtcTx::from_bytes(&raw).unwrap().bytes(), raw);

    let err = BtcTx::default().read_from(&mut &raw[..10]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

/// The heap-free `RawTx` view must serialize and hash exactly like `BtcTx`,
/// with and without witness data.
#[test]
fn raw_tx_matches_btctx() {
    use crate::btcraw::{RawTx, RawTxIn, RawTxOut};

    let witness_tx = "0100000000010213206299feb17742091c3cb2ab45faa3aa87922d3c030cafb3f798850a2722bf0000000000feffffffa12f2424b9599898a1d30f06e1ce55eba7fabfeee82ae9356f07375806632ff3010000006b483045022100fcc8cf3014248e1a0d6dcddf03e80f7e591605ad0dbace27d2c0d87274f8cd66022053fcfff64f35f22a14deb657ac57f110084fb07bb917c3b42e7d033c54c7717b012102b9e4dcc33c9cc9cb5f42b96dddb3b475b067f3e21125f79e10c853e5ca8fba31feffffff02206f9800000000001976a9144841b9874d913c430048c78a7b18baebdbea440588ac8096980000000000160014e4873ef43eac347471dd94bc899c51b395a509a502483045022100dd8250f8b5c2035d8feefae530b10862a63030590a851183cb61b3672eb4f26e022057fe7bc8593f05416c185d829b574290fb8706423451ebd0a0ae50c276b87b43012102179862f40b85fa43487500f1d6b13c864b5eb0a83999738db0f7a6b91b2ec64f00db080000";
    for hex_tx in [witness_tx, BIP143_TX] {
        let tx = parse(hex_tx);
        let witnesses: Vec<Vec<&[u8]>> = tx
            .inputs
            .iter()
            .map(|i| i.witnesses.iter().map(Vec::as_slice).collect())
            .collect();
        let inputs: Vec<RawTxIn> = tx
            .inputs
            .iter()
            .zip(&witnesses)
            .map(|(i, w)| RawTxIn {
                txid: i.txid,
                vout: i.vout,
                script_sig: &i.script,
                sequence: i.sequence,
                witness: w,
            })
            .collect();
        let outputs: Vec<RawTxOut> = tx
            .outputs
            .iter()
            .map(|o| RawTxOut {
                amount: o.amount.0,
                script: &o.script,
            })
            .collect();
        let raw = RawTx {
            version: tx.version,
            inputs: &inputs,
            outputs: &outputs,
            locktime: tx.locktime,
        };
        let mut buf = vec![0u8; raw.serialized_len()];
        assert_eq!(raw.serialize_to_slice(&mut buf), Ok(buf.len()));
        assert_eq!(buf, tx.bytes());
        assert_eq!(hex::encode(&buf), hex_tx);
        assert_eq!(raw.txid(), tx.hash());
    }
}

/// Signing through the PSBT roles (create, update, sign, finalize, extract)
/// must produce exactly the transaction `BtcTx::sign` produces, for every
/// script type both support, including a PSBT signed by two parties in turn.
#[test]
fn psbt_workflow_matches_btctx_sign() {
    psbt_matches_btctx_sign(0);
}

/// The same, opted into the unified sighash through the PSBT sighash type.
#[test]
fn psbt_unified_matches_btctx_sign() {
    psbt_matches_btctx_sign(0x21); // ALL|UNIFIED
    psbt_matches_btctx_sign(0xa3); // SINGLE|ANYONECANPAY|UNIFIED
}

/// Signs one input of each scheme with `BtcTx::sign` and through a PSBT, with
/// sighash `hash_type` (0 for the default), and compares the results.
fn psbt_matches_btctx_sign(hash_type: u32) {
    use crate::psbt::Psbt;

    let k1 = key("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf");
    let k2 = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
    let prev_txid = arr32("0101010101010101010101010101010101010101010101010101010101010101");

    // a previous transaction paying `script` at output 0, for legacy inputs
    let prev_tx = |script: &[u8]| {
        let mut tx = BtcTx {
            version: 1,
            ..Default::default()
        };
        tx.inputs.push(BtcTxInput {
            txid: prev_txid,
            sequence: 0xffff_ffff,
            ..Default::default()
        });
        tx.outputs.push(BtcTxOutput {
            amount: crate::BtcAmount(90_000),
            n: 0,
            script: script.to_vec(),
        });
        tx
    };

    // (scheme, signing key, second key or None) — "2in" cases spend two
    // inputs with different keys and sign the PSBT in two passes
    let cases: &[(&str, &SecpPrivateKey)] = &[
        ("p2pk", &k1),
        ("p2pkh", &k1),
        ("p2pukh", &k1),
        ("p2wpkh", &k1),
        ("p2sh:p2wpkh", &k2),
        ("p2wsh:p2pkh", &k1),
        ("p2tr", &k2),
    ];
    for &(scheme, sk) in cases {
        let s = Script::new(sk.public_key());
        let spent_script = s.generate(scheme).unwrap();
        let prev = prev_tx(&spent_script);

        let mut tx = BtcTx {
            version: 2,
            locktime: 7,
            ..Default::default()
        };
        tx.inputs.push(BtcTxInput {
            txid: prev.hash(),
            vout: 0,
            sequence: 0xffff_fffd,
            ..Default::default()
        });
        tx.add_output("bc1q0yy3juscd3zfavw76g4h3eqdqzda7qyf58rj4m", 80_000)
            .unwrap();

        // reference: BtcTx::sign
        let mut reference = tx.clone();
        let sign_scheme = if scheme == "p2wsh:p2pkh" {
            "p2wsh:p2pkh"
        } else {
            scheme
        };
        reference
            .sign(&[BtcTxSign::new(sk, sign_scheme)
                .amount(90_000)
                .prev_script(spent_script.clone())
                .sighash(hash_type)])
            .unwrap();

        // PSBT: create, add UTXO and scripts, sign, finalize, extract
        let mut psbt = tx.to_psbt().unwrap();
        let p = Psbt::parse(&psbt).unwrap();
        psbt = if matches!(scheme, "p2pk" | "p2pkh" | "p2pukh") {
            p.set_input_record_to_vec(0, &[0x00], &prev.bytes())
                .unwrap()
        } else {
            p.set_witness_utxo_to_vec(0, 90_000, &spent_script).unwrap()
        };
        if scheme == "p2sh:p2wpkh" {
            let redeem = s.generate("p2wpkh").unwrap();
            psbt = Psbt::parse(&psbt)
                .unwrap()
                .set_input_record_to_vec(0, &[0x04], &redeem)
                .unwrap();
        }
        if scheme == "p2wsh:p2pkh" {
            let ws = s.generate("p2pkh").unwrap();
            psbt = Psbt::parse(&psbt)
                .unwrap()
                .set_input_record_to_vec(0, &[0x05], &ws)
                .unwrap();
        }
        if hash_type != 0 {
            psbt = Psbt::parse(&psbt)
                .unwrap()
                .set_input_record_to_vec(0, &[0x03], &hash_type.to_le_bytes())
                .unwrap();
        }

        // the other key is not involved
        let p = Psbt::parse(&psbt).unwrap();
        let other = if core::ptr::eq(sk, &k1) { &k2 } else { &k1 };
        assert_eq!(
            p.sign_input_to_vec(0, other),
            Err(crate::psbt::Error::KeyNotInvolved),
            "{scheme}"
        );
        let (signed, count) = p.sign_to_vec(other).unwrap();
        assert_eq!((count, signed.as_slice()), (0, psbt.as_slice()), "{scheme}");

        let (signed, count) = p.sign_to_vec(sk).unwrap();
        assert_eq!(count, 1, "{scheme}");
        let signed = Psbt::parse(&signed).unwrap();
        let (finalized, count) = signed.finalize_to_vec().unwrap();
        assert_eq!(count, 1, "{scheme}");
        let finalized = Psbt::parse(&finalized).unwrap();
        let raw = finalized.extract_tx_to_vec().unwrap();
        assert_eq!(
            hex::encode(&raw),
            hex::encode(reference.bytes()),
            "{scheme}"
        );

        // base64 round trip of the signed PSBT
        let text = signed.to_base64();
        assert_eq!(Psbt::decode_base64(&text).unwrap(), signed.as_bytes());
    }
}

/// Two parties sign different inputs (P2WPKH and P2TR) of one PSBT
/// independently; combining and finalizing yields the `BtcTx::sign` result.
#[test]
fn psbt_two_signers_combine() {
    use crate::psbt::Psbt;

    let k1 = key("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf");
    let k2 = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
    let spk1 = Script::new(k1.public_key()).generate("p2wpkh").unwrap();
    let spk2 = Script::new(k2.public_key()).generate("p2tr").unwrap();

    let mut tx = BtcTx {
        version: 2,
        ..Default::default()
    };
    for (i, fill) in [(0u32, 0x11u8), (1, 0x22)] {
        tx.inputs.push(BtcTxInput {
            txid: [fill; 32],
            vout: i,
            sequence: 0xffff_ffff,
            ..Default::default()
        });
    }
    tx.add_output("bc1q0yy3juscd3zfavw76g4h3eqdqzda7qyf58rj4m", 150_000)
        .unwrap();

    let mut reference = tx.clone();
    reference
        .sign(&[
            BtcTxSign::new(&k1, "p2wpkh")
                .amount(100_000)
                .prev_script(spk1.clone()),
            BtcTxSign::new(&k2, "p2tr")
                .amount(60_000)
                .prev_script(spk2.clone()),
        ])
        .unwrap();

    let base = tx.to_psbt().unwrap();
    let base = Psbt::parse(&base)
        .unwrap()
        .set_witness_utxo_to_vec(0, 100_000, &spk1)
        .unwrap();
    let base = Psbt::parse(&base)
        .unwrap()
        .set_witness_utxo_to_vec(1, 60_000, &spk2)
        .unwrap();
    let base = Psbt::parse(&base).unwrap();

    let (by1, n1) = base.sign_to_vec(&k1).unwrap();
    let (by2, n2) = base.sign_to_vec(&k2).unwrap();
    assert_eq!((n1, n2), (1, 1));
    let (by1, by2) = (Psbt::parse(&by1).unwrap(), Psbt::parse(&by2).unwrap());

    // a partially signed PSBT finalizes only the signed input
    let (partial, count) = by1.finalize_to_vec().unwrap();
    assert_eq!(count, 1);
    let partial = Psbt::parse(&partial).unwrap();
    assert!(!partial.is_finalized());
    assert_eq!(
        partial.extract_tx_to_vec(),
        Err(crate::psbt::Error::NotFinalized)
    );

    let combined = by1.combine_to_vec(&by2).unwrap();
    let (finalized, count) = Psbt::parse(&combined).unwrap().finalize_to_vec().unwrap();
    assert_eq!(count, 2);
    let raw = Psbt::parse(&finalized)
        .unwrap()
        .extract_tx_to_vec()
        .unwrap();
    assert_eq!(hex::encode(&raw), hex::encode(reference.bytes()));

    // the already-finalized input is left alone by later combining/finalizing
    let late = partial.combine_to_vec(&by2).unwrap();
    let (late_final, count) = Psbt::parse(&late).unwrap().finalize_to_vec().unwrap();
    assert_eq!(count, 1);
    let raw = Psbt::parse(&late_final)
        .unwrap()
        .extract_tx_to_vec()
        .unwrap();
    assert_eq!(hex::encode(&raw), hex::encode(reference.bytes()));
}

/// A taproot input with PSBT_IN_SIGHASH_TYPE = SIGHASH_ALL gets a 65-byte
/// signature that verifies against the output key over the SIGHASH_ALL
/// message.
#[test]
fn psbt_taproot_sighash_all() {
    use crate::btcraw::{RawTx, RawTxIn, RawTxOut};
    use crate::psbt::Psbt;

    let k = key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
    let spk = Script::new(k.public_key()).generate("p2tr").unwrap();
    let inputs = [RawTxIn {
        txid: [0x33; 32],
        vout: 0,
        sequence: 0xffff_ffff,
        ..Default::default()
    }];
    let outputs = [RawTxOut {
        amount: 1_000,
        script: &spk,
    }];
    let tx = RawTx {
        version: 2,
        inputs: &inputs,
        outputs: &outputs,
        locktime: 0,
    };
    let psbt = Psbt::create_to_vec(&tx).unwrap();
    let psbt = Psbt::parse(&psbt)
        .unwrap()
        .set_witness_utxo_to_vec(0, 5_000, &spk)
        .unwrap();
    let psbt = Psbt::parse(&psbt)
        .unwrap()
        .set_input_record_to_vec(0, &[0x03], &1u32.to_le_bytes())
        .unwrap();
    let (signed, n) = Psbt::parse(&psbt).unwrap().sign_to_vec(&k).unwrap();
    assert_eq!(n, 1);
    let signed = Psbt::parse(&signed).unwrap();
    let sig = signed.input(0).unwrap().tap_key_sig().unwrap();
    assert_eq!((sig.len(), sig[64]), (65, 0x01));

    let prevouts = [RawTxOut {
        amount: 5_000,
        script: &spk,
    }];
    let msg = tx
        .taproot_midstate(&prevouts)
        .unwrap()
        .key_spend_sighash_with_type(0, 1)
        .unwrap();
    let output_key: [u8; 32] = spk[2..].try_into().unwrap();
    assert!(bip340_verify(
        &output_key,
        &msg,
        sig[..64].try_into().unwrap()
    ));

    // SIGHASH_NONE commits to no outputs: a different digest, signed as such
    let none = Psbt::parse(&psbt)
        .unwrap()
        .set_input_record_to_vec(0, &[0x03], &2u32.to_le_bytes())
        .unwrap();
    let (signed, n) = Psbt::parse(&none).unwrap().sign_to_vec(&k).unwrap();
    assert_eq!(n, 1);
    let signed = Psbt::parse(&signed).unwrap();
    let sig = signed.input(0).unwrap().tap_key_sig().unwrap();
    assert_eq!((sig.len(), sig[64]), (65, 0x02));
    let mid = tx.taproot_midstate(&prevouts).unwrap();
    let none_msg = tx
        .taproot_sighash(&mid, &prevouts, 0, &crate::btcraw::TapSighash::new(0x02))
        .unwrap();
    assert_ne!(none_msg, msg);
    assert!(bip340_verify(
        &output_key,
        &none_msg,
        sig[..64].try_into().unwrap()
    ));

    // undefined sighash types are refused rather than mis-signed
    for bad in [0x04u32, 0x80, 0x84, 0x100] {
        let psbt = Psbt::parse(&psbt)
            .unwrap()
            .set_input_record_to_vec(0, &[0x03], &bad.to_le_bytes())
            .unwrap();
        assert_eq!(
            Psbt::parse(&psbt).unwrap().sign_to_vec(&k).err(),
            Some(crate::psbt::Error::UnsupportedSighash),
            "{bad:#x}"
        );
    }
}

/// The BIP-341 wallet test vectors for key-path spending: every hash type
/// (`DEFAULT`, `ALL`, `NONE`, `SINGLE` and their `ANYONECANPAY` forms), with
/// and without a script tree. Checks the sighash and the final signature.
#[test]
fn bip341_key_path_spending_vectors() {
    use crate::btcraw::{PrevOut, TapScriptPath, TapSighash};

    let json: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/bip341_wallet_vectors.json")).unwrap();
    let v = &json["keyPathSpending"][0];
    let tx =
        BtcTx::from_bytes(&hex::decode(v["given"]["rawUnsignedTx"].as_str().unwrap()).unwrap())
            .unwrap();
    let scripts: Vec<Vec<u8>> = v["given"]["utxosSpent"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| hex::decode(u["scriptPubKey"].as_str().unwrap()).unwrap())
        .collect();
    let prevouts: Vec<PrevOut<'_>> = v["given"]["utxosSpent"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&scripts)
        .map(|(u, script)| PrevOut {
            amount: u["amountSats"].as_u64().unwrap(),
            script,
        })
        .collect();

    let arr32 = |v: &serde_json::Value| -> [u8; 32] {
        let mut a = [0u8; 32];
        hex::decode_to_slice(v.as_str().unwrap(), &mut a).unwrap();
        a
    };
    let mut seen = Vec::new();
    tx.with_raw(|raw| {
        let mid = raw.taproot_midstate(&prevouts).unwrap();
        for spend in v["inputSpending"].as_array().unwrap() {
            let index = spend["given"]["txinIndex"].as_u64().unwrap() as usize;
            let hash_type = spend["given"]["hashType"].as_u64().unwrap() as u8;
            seen.push(hash_type);
            let sighash = raw
                .taproot_sighash(&mid, &prevouts, index, &TapSighash::new(hash_type))
                .unwrap();
            assert_eq!(
                sighash,
                arr32(&spend["intermediary"]["sigHash"]),
                "input {index}"
            );
            // the midstate-only shortcut agrees where it applies
            if hash_type <= 1 {
                assert_eq!(
                    mid.key_spend_sighash_with_type(index, hash_type).unwrap(),
                    sighash
                );
            }

            let key =
                SecpPrivateKey::from_bytes(&arr32(&spend["given"]["internalPrivkey"])).unwrap();
            assert_eq!(
                key.xonly_public_key(),
                arr32(&spend["intermediary"]["internalPubkey"])
            );
            let root = (!spend["given"]["merkleRoot"].is_null())
                .then(|| arr32(&spend["given"]["merkleRoot"]));
            let mut sig = key
                .sign_taproot_with_root(&sighash, root.as_ref())
                .unwrap()
                .to_vec();
            if hash_type != 0 {
                sig.push(hash_type);
            }
            assert_eq!(
                hex::encode(&sig),
                spend["expected"]["witness"][0].as_str().unwrap(),
                "input {index}"
            );
            // and it verifies under the tweaked output key
            let (output_key, _) =
                crate::taproot::taproot_tweak_with_root(&key.xonly_public_key(), root.as_ref())
                    .unwrap();
            assert_eq!(&prevouts[index].script[2..], &output_key);
            assert!(bip340_verify(
                &output_key,
                &sighash,
                sig[..64].try_into().unwrap()
            ));
        }

        // script path and annex change the digest; the legacy helper matches
        // the general one for a plain script-path spend
        let leaf_script = [0x51u8];
        let leaf = TapScriptPath::new(crate::taproot::tapleaf_hash(0xc0, &leaf_script));
        let key_path = raw
            .taproot_sighash(&mid, &prevouts, 0, &TapSighash::new(0))
            .unwrap();
        let script_path = raw
            .taproot_sighash(
                &mid,
                &prevouts,
                0,
                &TapSighash::new(0).with_script_path(leaf),
            )
            .unwrap();
        assert_ne!(key_path, script_path);
        assert_eq!(
            script_path,
            mid.script_path_sighash(0, &leaf_script).unwrap()
        );
        let with_codesep = TapSighash::new(0).with_script_path(leaf.with_codesep_pos(3));
        assert_ne!(
            raw.taproot_sighash(&mid, &prevouts, 0, &with_codesep)
                .unwrap(),
            script_path
        );
        let annex = [0x50u8, 1, 2];
        assert_ne!(
            raw.taproot_sighash(&mid, &prevouts, 0, &TapSighash::new(0).with_annex(&annex))
                .unwrap(),
            key_path
        );

        // rejections
        let err = |index, opts: TapSighash<'_>| raw.taproot_sighash(&mid, &prevouts, index, &opts);
        assert_eq!(
            err(0, TapSighash::new(0x04)),
            Err(Error::UnsupportedSighash)
        );
        assert_eq!(
            err(0, TapSighash::new(0x80)),
            Err(Error::UnsupportedSighash)
        );
        assert_eq!(
            err(0, TapSighash::new(0x84)),
            Err(Error::UnsupportedSighash)
        );
        assert_eq!(err(99, TapSighash::new(0)), Err(Error::InputIndex));
        assert_eq!(
            err(0, TapSighash::new(0).with_annex(&[0x51])),
            Err(Error::InvalidData)
        );
        // SIGHASH_SINGLE needs an output at the input's index (9 inputs, fewer outputs)
        assert!(raw.outputs.len() < raw.inputs.len());
        assert_eq!(
            err(raw.outputs.len(), TapSighash::new(0x03)),
            Err(Error::OutputIndex)
        );
        assert_eq!(
            raw.taproot_sighash(&mid, &prevouts[..1], 0, &TapSighash::new(0)),
            Err(Error::PrevOutCount)
        );
    });
    seen.sort_unstable();
    assert_eq!(seen, [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83]);
}

// --- taproot script trees through BtcTx ---

/// A taproot output with internal key `k1` committing to the tree
/// `[<k2> CHECKSIG, <k3> CHECKSIG]`, and a transaction spending it.
struct TapTreeFixture {
    tx: BtcTx,
    spk: Vec<u8>,
    root: [u8; 32],
    scripts: [Vec<u8>; 2],
    control_blocks: [Vec<u8>; 2],
}

fn tap_tree_fixture() -> TapTreeFixture {
    use crate::taproot::{
        MAX_CONTROL_BLOCK_LEN, TapLeaf, control_block_to_slice, p2tr_script_pubkey, tap_tree_root,
    };
    let leaf_of = |secret: u8| {
        let k = SecpPrivateKey::from_bytes(&[secret; 32]).unwrap();
        let mut s = vec![0x20];
        s.extend_from_slice(&k.xonly_public_key());
        s.push(0xac);
        s
    };
    let scripts = [leaf_of(2), leaf_of(3)];
    let leaves = [TapLeaf::new(1, &scripts[0]), TapLeaf::new(1, &scripts[1])];
    let internal = SecpPrivateKey::from_bytes(&[1; 32])
        .unwrap()
        .xonly_public_key();
    let root = tap_tree_root(&leaves).unwrap();
    let spk = p2tr_script_pubkey(&internal, Some(&root)).unwrap().to_vec();
    let control_blocks = [0, 1].map(|i| {
        let mut cb = [0u8; MAX_CONTROL_BLOCK_LEN];
        let n = control_block_to_slice(&internal, &leaves, i, &mut cb).unwrap();
        cb[..n].to_vec()
    });
    let tx = BtcTx {
        version: 2,
        inputs: vec![BtcTxInput {
            sequence: 0xffff_fffd,
            ..Default::default()
        }],
        outputs: vec![BtcTxOutput {
            amount: crate::BtcAmount(90_000),
            n: 0,
            script: spk.clone(),
        }],
        locktime: 0,
    };
    TapTreeFixture {
        tx,
        spk,
        root,
        scripts,
        control_blocks,
    }
}

#[test]
fn p2tr_key_path_over_script_tree() {
    use crate::btcraw::TapSighash;
    let TapTreeFixture {
        mut tx, spk, root, ..
    } = tap_tree_fixture();
    let k1 = SecpPrivateKey::from_bytes(&[1; 32]).unwrap();
    let output_key: [u8; 32] = spk[2..].try_into().unwrap();
    let probe = [BtcTxSign::without_key("p2tr")
        .amount(100_000)
        .prev_script(spk.clone())];

    // without the merkle root the signature is for another output key
    tx.sign(&[BtcTxSign::new(&k1, "p2tr")
        .amount(100_000)
        .prev_script(spk.clone())])
        .unwrap();
    let digest = tx.taproot_sighash(&probe, 0).unwrap();
    let sig: [u8; 64] = tx.inputs[0].witnesses[0][..].try_into().unwrap();
    assert!(!bip340_verify(&output_key, &digest, &sig));

    tx.sign(&[BtcTxSign::new(&k1, "p2tr")
        .amount(100_000)
        .prev_script(spk.clone())
        .tap_merkle_root(root)])
        .unwrap();
    assert_eq!(tx.inputs[0].witnesses.len(), 1);
    let sig: [u8; 64] = tx.inputs[0].witnesses[0][..].try_into().unwrap();
    assert!(bip340_verify(&output_key, &digest, &sig));

    // every BIP-341 hash type is signed as such and carries its type byte
    for hash_type in [0x01u8, 0x02, 0x03, 0x81, 0x82, 0x83] {
        tx.sign(&[BtcTxSign::new(&k1, "p2tr")
            .amount(100_000)
            .prev_script(spk.clone())
            .tap_merkle_root(root)
            .sighash(hash_type as u32)])
            .unwrap();
        let w = &tx.inputs[0].witnesses[0];
        assert_eq!((w.len(), w[64]), (65, hash_type));
        let digest = tx
            .taproot_sighash_with(&probe, 0, &TapSighash::new(hash_type))
            .unwrap();
        assert!(bip340_verify(
            &output_key,
            &digest,
            w[..64].try_into().unwrap()
        ));
    }
    for bad in [0x04u32, 0x80, 0x84, 0x1_00] {
        let r = tx.sign(&[BtcTxSign::new(&k1, "p2tr")
            .amount(100_000)
            .prev_script(spk.clone())
            .sighash(bad)]);
        assert_eq!(r, Err(Error::UnsupportedSighash), "{bad:#x}");
    }
}

#[test]
fn p2tr_script_path_spend() {
    use crate::btcraw::{TapScriptPath, TapSighash};
    use crate::taproot::{ControlBlock, tapleaf_hash};
    let TapTreeFixture {
        mut tx,
        spk,
        scripts,
        control_blocks,
        ..
    } = tap_tree_fixture();
    let output_key: [u8; 32] = spk[2..].try_into().unwrap();
    let probe = [BtcTxSign::without_key("p2tr")
        .amount(100_000)
        .prev_script(spk.clone())];

    for (i, secret) in [(0usize, 2u8), (1, 3)] {
        let k = SecpPrivateKey::from_bytes(&[secret; 32]).unwrap();
        tx.sign(&[BtcTxSign::new(&k, "p2tr")
            .amount(100_000)
            .prev_script(spk.clone())
            .tap_leaf(scripts[i].clone(), control_blocks[i].clone())])
            .unwrap();
        let w = &tx.inputs[0].witnesses;
        assert_eq!(w.len(), 3);
        assert_eq!((&w[1], &w[2]), (&scripts[i], &control_blocks[i]));
        assert!(
            ControlBlock::parse(&w[2])
                .unwrap()
                .verify(&w[1], &output_key)
        );
        let opts = TapSighash::new(0)
            .with_script_path(TapScriptPath::new(tapleaf_hash(0xc0, &scripts[i])));
        let digest = tx.taproot_sighash_with(&probe, 0, &opts).unwrap();
        // signed by the leaf key itself, untweaked
        assert!(bip340_verify(
            &k.xonly_public_key(),
            &digest,
            w[0][..].try_into().unwrap()
        ));
        // and the signed transaction still round-trips
        let bytes = tx.bytes();
        assert_eq!(BtcTx::from_bytes(&bytes).unwrap().bytes(), bytes);
    }

    let k2 = SecpPrivateKey::from_bytes(&[2; 32]).unwrap();
    let sign = |tx: &mut BtcTx, key: &SecpPrivateKey, script: Vec<u8>, cb: Vec<u8>| {
        tx.sign(&[BtcTxSign::new(key, "p2tr")
            .amount(100_000)
            .prev_script(spk.clone())
            .tap_leaf(script, cb)])
    };
    // the wrong key for the leaf
    let k3 = SecpPrivateKey::from_bytes(&[3; 32]).unwrap();
    assert_eq!(
        sign(&mut tx, &k3, scripts[0].clone(), control_blocks[0].clone()),
        Err(Error::KeyNotInvolved)
    );
    // a control block that does not prove this leaf for this output
    assert_eq!(
        sign(&mut tx, &k2, scripts[0].clone(), control_blocks[1].clone()),
        Err(Error::InvalidScript)
    );
    assert_eq!(
        sign(&mut tx, &k2, scripts[0].clone(), vec![0xc0; 10]),
        Err(Error::InvalidLength)
    );
    // only single-key leaves get their witness built
    assert_eq!(
        sign(&mut tx, &k2, vec![0x51], control_blocks[0].clone()),
        Err(Error::UnsupportedScript)
    );
}

// --- unified opt-in sighash ---

/// The unified sighash of input `index` of `tx`, spending `prevouts`.
fn unified_sighash(
    tx: &BtcTx,
    prevouts: &[crate::btcraw::PrevOut<'_>],
    index: usize,
    hash_type: u8,
    spend: &crate::btcraw::UnifiedSpend<'_>,
) -> Result<[u8; 32], Error> {
    tx.with_raw(|raw| {
        let mid = raw.taproot_midstate(prevouts)?;
        raw.unified_sighash(&mid, prevouts, index, hash_type, spend)
    })
}

/// The Bitcoin Knots unified sighash vectors (`src/test/data/unified_sighash.json`
/// at v29.4.1.knots20260508): scriptCode, raw transaction, input index, hash
/// type, script type, spent outputs, expected sighash. Tapscript vectors carry
/// the leaf script and use no annex and no `OP_CODESEPARATOR`.
#[test]
fn unified_sighash_vectors() {
    use crate::btcraw::{PrevOut, RawTxOut, TapScriptPath, UnifiedSpend};
    use crate::taproot::{TAPSCRIPT_LEAF_VERSION, tapleaf_hash};

    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/unified_sighash.json")).unwrap();
    let vectors = vectors.as_array().unwrap();
    let mut count = 0;
    for v in &vectors[1..] {
        let script_code = hex::decode(v[0].as_str().unwrap()).unwrap();
        let tx = parse(v[1].as_str().unwrap());
        let index = v[2].as_u64().unwrap() as usize;
        let hash_type = v[3].as_u64().unwrap() as u8;
        let spent: Vec<(u64, Vec<u8>)> = v[5]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| {
                let amount = o[0].as_u64().unwrap();
                (amount, hex::decode(o[1].as_str().unwrap()).unwrap())
            })
            .collect();
        let prevouts: Vec<PrevOut<'_>> = spent
            .iter()
            .map(|(amount, script)| RawTxOut {
                amount: *amount,
                script,
            })
            .collect();
        let spend = match v[4].as_u64().unwrap() {
            0 => UnifiedSpend::Legacy(&script_code),
            1 => UnifiedSpend::SegwitV0(&script_code),
            2 => UnifiedSpend::KEY_PATH,
            3 => UnifiedSpend::Taproot {
                annex: None,
                script_path: Some(TapScriptPath::new(tapleaf_hash(
                    TAPSCRIPT_LEAF_VERSION,
                    &script_code,
                ))),
            },
            t => panic!("script type {t}"),
        };
        let got = unified_sighash(&tx, &prevouts, index, hash_type, &spend).unwrap();
        assert_eq!(hex::encode(got), v[6].as_str().unwrap(), "vector {v}");
        count += 1;
    }
    assert_eq!(count, 166);
}

/// Annex and codeseparator commitments, which the Knots vectors leave at their
/// defaults. Expected values from `UnifiedSignatureHash` in Knots'
/// `test/functional/test_framework/script.py`.
#[test]
fn unified_sighash_annex_codesep() {
    use crate::btcraw::{RawTxOut, TapScriptPath, UnifiedSpend};
    use crate::taproot::{TAPSCRIPT_LEAF_VERSION, tapleaf_hash};

    let tx = parse(
        "01000000013412a79af62f112c6d1f07ae37b7dd832c16a9938ca13710c4aa7a86149e7e900100000000000000000260e5cc01000000001514b4d551c269e842436b426b506591e35a6eaa426b857d7c0100000000151427cc20ce3a0f64b433d81e4eecc43d1bc5fda29f00000000",
    );
    let spk = hex::decode("512054ffb854f30027cd78f146ff92904a4d008bcae625ccda02e63d32d1cbd29c13")
        .unwrap();
    let prevouts = [RawTxOut {
        amount: 26_954_754,
        script: &spk,
    }];
    let leaf = hex::decode("2067a20cd4a6079ec4187547c0f3bed18dec272baf2342876e7175fc15345af793ac")
        .unwrap();
    let annex = [0x50, 0xaa, 0xbb, 0xcc];
    let path = TapScriptPath::new(tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &leaf)).with_codesep_pos(7);
    let script = UnifiedSpend::Taproot {
        annex: Some(&annex),
        script_path: Some(path),
    };
    let key = UnifiedSpend::Taproot {
        annex: Some(&annex),
        script_path: None,
    };
    for (hash_type, spend, want) in [
        (
            0x21,
            script,
            "4840e8478ab8b57cc4b65e28abbfcdb0201b8ca6905fc8499579eecab07dc3ae",
        ),
        (
            0x21,
            key,
            "ff155493bb308bff9fbc9d05207e316daf3aaf9592d1acc96f40e965615126e4",
        ),
        (
            0xa3,
            script,
            "cd3c0c8b4d92816b088f579c6ccceaa719cd0070a2238047c8f5b8d2d75a6c04",
        ),
        (
            0xa3,
            key,
            "a060fcdb5e4b3a3acf1dcaf136e49ca0d6cbeca02a404d122371cdb0f1113c61",
        ),
    ] {
        let got = unified_sighash(&tx, &prevouts, 0, hash_type, &spend).unwrap();
        assert_eq!(hex::encode(got), want, "hash type {hash_type:#x}");
    }
}

#[test]
fn unified_sighash_rejects() {
    use crate::btcraw::{RawTxOut, UnifiedSpend};

    // two inputs, one output
    let mut tx = parse(BIP143_TX);
    tx.outputs.truncate(1);
    let spk = [0x51];
    let prevouts = [RawTxOut {
        amount: 1,
        script: &spk,
    }; 2];
    let legacy = UnifiedSpend::Legacy(&[]);
    let key = UnifiedSpend::KEY_PATH;
    let sighash =
        |index, hash_type, spend| unified_sighash(&tx, &prevouts, index, hash_type, spend);

    assert!(sighash(1, 0x21, &legacy).is_ok());
    // SINGLE needs an output at the input's index
    assert!(sighash(0, 0x23, &legacy).is_ok());
    assert_eq!(sighash(1, 0x23, &legacy), Err(Error::OutputIndex));
    assert_eq!(sighash(1, 0xa3, &key), Err(Error::OutputIndex));
    // the opt-in bit is required
    assert_eq!(sighash(0, 0x01, &legacy), Err(Error::UnsupportedSighash));
    assert_eq!(sighash(0, 0x01, &key), Err(Error::UnsupportedSighash));
    // bare, P2SH and segwit v0 commit to any byte; taproot to defined types only
    for t in [0x20, 0x24, 0x3f, 0x61, 0xff] {
        assert!(sighash(0, t, &legacy).is_ok(), "{t:#x}");
        assert_eq!(
            sighash(0, t, &key),
            Err(Error::UnsupportedSighash),
            "{t:#x}"
        );
    }
    let bad_annex = UnifiedSpend::Taproot {
        annex: Some(&[0x51]),
        script_path: None,
    };
    assert_eq!(sighash(0, 0x21, &bad_annex), Err(Error::InvalidData));
    assert_eq!(sighash(2, 0x21, &legacy), Err(Error::InputIndex));
    assert_eq!(
        tx.with_raw(|raw| {
            let mid = raw.taproot_midstate(&prevouts).unwrap();
            raw.unified_sighash(&mid, &prevouts[..1], 0, 0x21, &legacy)
        }),
        Err(Error::PrevOutCount)
    );
}

/// `BtcTx::sign` opts individual inputs into the unified sighash: their
/// signatures verify against it and carry its hash type, while the other
/// inputs keep their usual algorithm.
#[test]
fn sign_unified_mixed_inputs() {
    use crate::btcraw::UnifiedSpend;
    use crate::crypto::secp256k1::parse_der_signature;
    use crate::pushbytes::parse_push_bytes;

    let k = key("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf");
    let pk = k.public_key();
    let s = Script::new(pk.clone());
    let spk = |scheme| s.generate(scheme).unwrap();

    let mut tx = BtcTx {
        version: 2,
        locktime: 900_000,
        ..Default::default()
    };
    for i in 0..4u8 {
        tx.inputs.push(BtcTxInput {
            txid: [i + 1; 32],
            vout: i.into(),
            sequence: 0xffff_fffd,
            ..Default::default()
        });
    }
    tx.add_output("bc1q0yy3juscd3zfavw76g4h3eqdqzda7qyf58rj4m", 80_000)
        .unwrap();
    let entries = [
        ("p2pkh", 0x21, 10_000),              // ALL|UNIFIED
        ("p2wpkh", 0, 20_000),                // legacy BIP-143
        ("p2wsh:p2pkh", 0x82 | 0x20, 30_000), // NONE|ANYONECANPAY|UNIFIED
        ("p2tr", 0x22, 40_000),               // NONE|UNIFIED
    ];
    let keys: Vec<BtcTxSign> = entries
        .iter()
        .map(|&(scheme, sighash, amount)| {
            BtcTxSign::new(&k, scheme)
                .amount(amount)
                .prev_script(spk(scheme))
                .sighash(sighash)
        })
        .collect();
    tx.sign(&keys).unwrap();

    // input n's ECDSA signature verifies against `digest` and ends in `hash_type`
    let ecdsa_ok = |n: usize, digest: &[u8; 32], hash_type: u8| {
        let inp = &tx.inputs[n];
        let sig = match inp.witnesses.first() {
            Some(sig) => sig.as_slice(),
            None => parse_push_bytes(&inp.script).unwrap().0,
        };
        let (der, flag) = sig.split_at(sig.len() - 1);
        assert_eq!(flag, [hash_type], "input {n}");
        let (r, s) = parse_der_signature(der).unwrap();
        pk.verify(digest, &r, &s)
    };

    let p2pkh = spk("p2pkh");
    let digest = tx
        .unified_sighash(&keys, 0, 0x21, &UnifiedSpend::Legacy(&p2pkh))
        .unwrap();
    assert!(ecdsa_ok(0, &digest, 0x21));
    assert_ne!(digest, tx.legacy_sighash(0, &p2pkh, 0x21).unwrap());

    let pk_hash = crate::hash::hash160(&pk.serialize_compressed());
    let digest = tx.segwit_v0_midstate().sighash(
        &tx.inputs[1].raw(),
        &crate::btcraw::p2pkh_script_code(&pk_hash),
        20_000,
        1,
    );
    assert!(ecdsa_ok(1, &digest, 1));

    let digest = tx
        .unified_sighash(&keys, 2, 0xa2, &UnifiedSpend::SegwitV0(&p2pkh))
        .unwrap();
    assert!(ecdsa_ok(2, &digest, 0xa2));

    let wit = &tx.inputs[3].witnesses;
    assert_eq!((wit.len(), wit[0].len(), wit[0][64]), (1, 65, 0x22));
    let digest = tx
        .unified_sighash(&keys, 3, 0x22, &UnifiedSpend::KEY_PATH)
        .unwrap();
    let output_key: [u8; 32] = spk("p2tr")[2..].try_into().unwrap();
    assert!(bip340_verify(
        &output_key,
        &digest,
        wit[0][..64].try_into().unwrap()
    ));
}

#[test]
fn sign_unified_rejects() {
    let k = key("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf");
    let s = Script::new(k.public_key());
    let mut tx = BtcTx {
        version: 2,
        ..Default::default()
    };
    for i in 0..2u8 {
        tx.inputs.push(BtcTxInput {
            txid: [i + 1; 32],
            ..Default::default()
        });
    }
    tx.add_output("bc1q0yy3juscd3zfavw76g4h3eqdqzda7qyf58rj4m", 1_000)
        .unwrap();
    let entry = |scheme: &str, sighash| {
        BtcTxSign::new(&k, scheme)
            .amount(5_000)
            .prev_script(s.generate(scheme).unwrap())
            .sighash(sighash)
    };
    let sign = |keys: &[BtcTxSign]| tx.clone().sign(keys);

    assert!(sign(&[entry("p2wpkh", 0x21), entry("p2pkh", 0)]).is_ok());
    // every spent output is committed to
    let mut missing = entry("p2pkh", 0);
    missing.prev_script.clear();
    assert_eq!(
        sign(&[entry("p2wpkh", 0x21), missing]),
        Err(Error::MissingPrevScript(1))
    );
    // SINGLE needs an output at the input's index
    assert_eq!(
        sign(&[entry("p2wpkh", 0), entry("p2wpkh", 0x23)]),
        Err(Error::OutputIndex)
    );
    // taproot only takes the hash types BIP-341 defines
    assert_eq!(
        sign(&[entry("p2tr", 0x20), entry("p2tr", 0)]),
        Err(Error::UnsupportedSighash)
    );
    // the Bitcoin Cash fork id bit is not combined with it
    assert_eq!(
        sign(&[entry("p2pkh", 0x61), entry("p2pkh", 0)]),
        Err(Error::UnsupportedSighash)
    );
}

/// A tapscript spend opted into the unified sighash commits to the leaf as
/// script type 3.
#[test]
fn sign_unified_tapscript() {
    use crate::btcraw::{TapScriptPath, UnifiedSpend};
    use crate::taproot::{TAPSCRIPT_LEAF_VERSION, tapleaf_hash};
    let TapTreeFixture {
        mut tx,
        spk,
        scripts,
        control_blocks,
        ..
    } = tap_tree_fixture();
    let probe = [BtcTxSign::without_key("p2tr")
        .amount(100_000)
        .prev_script(spk.clone())];

    let k = SecpPrivateKey::from_bytes(&[2; 32]).unwrap();
    tx.sign(&[BtcTxSign::new(&k, "p2tr")
        .amount(100_000)
        .prev_script(spk.clone())
        .sighash(0x21)
        .tap_leaf(scripts[0].clone(), control_blocks[0].clone())])
        .unwrap();
    let w = &tx.inputs[0].witnesses;
    assert_eq!((w.len(), w[0].len(), w[0][64]), (3, 65, 0x21));
    let path = TapScriptPath::new(tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &scripts[0]));
    let spend = UnifiedSpend::Taproot {
        annex: None,
        script_path: Some(path),
    };
    let digest = tx.unified_sighash(&probe, 0, 0x21, &spend).unwrap();
    assert!(bip340_verify(
        &k.xonly_public_key(),
        &digest,
        w[0][..64].try_into().unwrap()
    ));
    // not the key-path message
    let key_path = tx
        .unified_sighash(&probe, 0, 0x21, &UnifiedSpend::KEY_PATH)
        .unwrap();
    assert_ne!(digest, key_path);
}
