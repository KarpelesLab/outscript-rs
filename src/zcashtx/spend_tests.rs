//! Spending transparent outputs other than P2PKH.
//!
//! `testdata/mainnet_multisig_*.hex` are two transactions of the main
//! network that spend an output of the 2-of-3 P2SH multisignature address
//! of ZIP 271 (`t3ev37Q2uL1sfTsiJQJiWJoFzQpDhmnUwYo`): a version 5 one
//! mined under NU6.1 at height 3 308 125, and a version 6 one mined under
//! NU6.3 at height 3 520 312 (raw transactions, heights and the spent
//! outputs from a public explorer, `api.mainnet.cipherscan.app`). The
//! signature digests expected of them are those `zcash_primitives` 0.31.0
//! computes, by a program outside this repository which also checked, with
//! the `secp256k1` crate, both signatures of each scriptSig against the
//! keys of the redeem script in the order `OP_CHECKMULTISIG` requires, and
//! the redeem script against the script hash of the output (the reference
//! crates have no script interpreter to run instead).
//!
//! With `ZCASH_TX_DUMP` set to a directory, the transactions built here
//! are written there (`<name>.hex` and `<name>.prevouts`), to check them
//! the same way.

use super::*;

fn key(n: u8) -> SecpPrivateKey {
    SecpPrivateKey::from_bytes(&[n; 32]).unwrap()
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

const SIX: [u8; 6] = [
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ALL | SIGHASH_ANYONECANPAY,
    SIGHASH_NONE | SIGHASH_ANYONECANPAY,
    SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
];

/// The scriptPubKey of the ZIP 271 address.
const ZIP271_SCRIPT: &str = "a914df3f053f9c73f96eb8502563f0566817e5c0b68087";

/// The pushes of a scriptSig of pushes.
fn pushes(mut script: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while !script.is_empty() {
        if script[0] == 0 {
            out.push(&script[..0]);
            script = &script[1..];
            continue;
        }
        let (data, used) = crate::pushbytes::parse_push_bytes(script).unwrap();
        out.push(data);
        script = &script[used..];
    }
    out
}

fn dump(name: &str, raw: &[u8], prevouts: &[ZcashTxOut<'_>]) {
    let Some(dir) = std::env::var_os("ZCASH_TX_DUMP") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::write(dir.join(format!("{name}.hex")), hex::encode(raw)).unwrap();
    let prevouts: Vec<String> = prevouts
        .iter()
        .map(|p| format!("{}:{}", p.amount, hex::encode(p.script)))
        .collect();
    std::fs::write(dir.join(format!("{name}.prevouts")), prevouts.join(" ")).unwrap();
}

/// Real spends of a 2-of-3 P2SH multisignature output, in both versions.
#[test]
fn mainnet_p2sh_multisig() {
    let script = hex::decode(ZIP271_SCRIPT).unwrap();
    type Case = (
        &'static str,
        &'static str,
        u64,
        TxVersion,
        u32,
        [Option<&'static str>; 6],
    );
    let cases: [Case; 2] = [
        (
            include_str!("testdata/mainnet_multisig_8a937240.hex"),
            "8a93724082fcc84bcd2c423c539214f1b3ec0802f11d25ec6021370a9e764c8a",
            743_822_950_000,
            TxVersion::V5,
            branch::NU6_1,
            [
                Some("09c12933959da84e57993f3f6382d63e228f9d0aef8704e7dbbf63f48e0c0bf2"),
                Some("d4db5c6f27ff279ddd58468c43e9950db61f2fffe62040e58d1e215d33babed4"),
                Some("ff2449b1469c7337306c237b591b03eb3f4a36e2a566a907851d0ea8c35ba548"),
                Some("11848f200a0aad64bab03814259a6165e1a1d2db3bed98842e25523621b75a78"),
                Some("a20a95ed5afece8bfbaa785e565d655b02c5c54436c60ef46f3d6319c93e3a16"),
                Some("d0af6f67d65252711f7d4614bf5c63fef315e9df950f75b3cc7589740c8e24d7"),
            ],
        ),
        (
            include_str!("testdata/mainnet_multisig_3ad0da85.hex"),
            "3ad0da85bea918406537ace183590377412675a413e7d127916076eb13094173",
            787_500_000_000,
            TxVersion::V6,
            branch::NU6_3,
            [
                Some("e55f8b3c915f9969b59e03048fdef4d45b5507ff62042c6806219bcf530598a4"),
                Some("4a7ed6e2798c26d7bf74a2cfe357957cd5277ca79a07caa01bb79df77d6800f2"),
                None,
                Some("4a3c44e9229085ce8da6b66269ec49bfccb72a9455df1b75ead023224178c56f"),
                Some("7791043e2a1c8a061c049dd8720ec06170f6ce36645a83f24502855c5ca22598"),
                None,
            ],
        ),
    ];
    for (raw, txid, amount, version, branch_id, sighashes) in cases {
        let raw = hex::decode(raw.trim()).unwrap();
        let mut inputs = [ZcashTxIn::default(); 1];
        let mut outputs = [ZcashTxOut::default(); 1];
        let tx = ZcashTx::parse_into(&raw, &mut inputs, &mut outputs).unwrap();
        assert_eq!(tx.version, version);
        assert_eq!(tx.consensus_branch_id, branch_id);
        assert_eq!(tx.txid().unwrap(), hex32(txid));
        let prevouts = [ZcashTxOut {
            amount,
            script: &script,
        }];
        for (hash_type, want) in SIX.into_iter().zip(sighashes) {
            match want {
                Some(want) => assert_eq!(
                    tx.sighash(Some(0), hash_type, &prevouts).unwrap(),
                    hex32(want)
                ),
                None => assert_eq!(
                    tx.sighash(Some(0), hash_type, &prevouts),
                    Err(Error::OutputIndex)
                ),
            }
        }

        // the scriptSig: OP_0, two signatures, the redeem script
        assert_eq!(tx.verify_input(0, &prevouts), Ok(()));
        let items = pushes(tx.inputs[0].script_sig);
        assert_eq!(items.len(), 4);
        assert!(items[0].is_empty());
        let redeem = items[3];
        assert_eq!(p2sh_script_of(redeem).unwrap()[..], script[..]);
        let ScriptKind::Multisig(multisig) = ScriptKind::of(redeem) else {
            panic!("not a multisignature script");
        };
        assert_eq!((multisig.required(), multisig.key_count()), (2, 3));
        let keys: Vec<&[u8]> = multisig.keys().collect();
        assert_eq!(Multisig::script(2, &keys).unwrap(), redeem);
        let signatures = [
            InputSignature::from_bytes(items[1]).unwrap(),
            InputSignature::from_bytes(items[2]).unwrap(),
        ];
        assert_eq!(signatures[0].hash_type(), SIGHASH_ALL);
        // each is the signature of one key, and of no other
        let signers: Vec<usize> = signatures
            .iter()
            .map(|signature| {
                let by: Vec<usize> = (0..3)
                    .filter(|k| {
                        tx.verify_input_signature(0, keys[*k], signature, &prevouts)
                            .is_ok()
                    })
                    .collect();
                assert_eq!(by.len(), 1);
                by[0]
            })
            .collect();
        assert!(signers[0] < signers[1]);

        // combined again, from any order, into the same scriptSig
        let mut out = [0u8; 400];
        for order in [[0, 1], [1, 0]] {
            let given = [signatures[order[0]], signatures[order[1]]];
            let n = tx
                .multisig_script_sig_to_slice(0, Some(redeem), &given, &prevouts, &mut out)
                .unwrap();
            assert_eq!(&out[..n], tx.inputs[0].script_sig);
        }
        let combine = |redeem: Option<&[u8]>, given: &[InputSignature], amount: u64| {
            let prevouts = [ZcashTxOut {
                amount,
                script: &script,
            }];
            tx.multisig_script_sig_to_slice(0, redeem, given, &prevouts, &mut [0u8; 400])
                .map(|_| ())
        };
        assert_eq!(
            combine(Some(redeem), &signatures[..1], amount),
            Err(Error::MissingSignatures)
        );
        assert_eq!(
            combine(Some(redeem), &[signatures[0], signatures[0]], amount),
            Err(Error::SignatureVerification(0))
        );
        assert_eq!(
            combine(None, &signatures, amount),
            Err(Error::MissingRedeemScript)
        );
        assert_eq!(
            combine(Some(&redeem[1..]), &signatures, amount),
            Err(Error::RedeemScriptMismatch)
        );
        // the digest commits to the amount spent
        assert_eq!(
            combine(Some(redeem), &signatures, amount + 1),
            Err(Error::SignatureVerification(0))
        );
        let wrong = [ZcashTxOut {
            amount: amount - 1,
            script: &script,
        }];
        assert_eq!(
            tx.verify_input(0, &wrong),
            Err(Error::SignatureVerification(0))
        );

        // signatures in the wrong order do not satisfy OP_CHECKMULTISIG
        let n =
            multisig_script_sig_to_slice(&[signatures[1], signatures[0]], Some(redeem), &mut out)
                .unwrap();
        let swapped = [ZcashTxIn {
            script_sig: &out[..n],
            ..tx.inputs[0]
        }];
        let bad = ZcashTx {
            inputs: &swapped,
            ..tx
        };
        assert_eq!(bad.txid().unwrap(), hex32(txid));
        assert_eq!(
            bad.verify_input(0, &prevouts),
            Err(Error::SignatureVerification(0))
        );
        // and the real scriptSig is accepted as one made elsewhere
        let spends = [InputSpend::new(InputSigner::ScriptSig(
            tx.inputs[0].script_sig,
        ))];
        assert_eq!(tx.sign_with(&spends, &prevouts).unwrap(), raw);
        let spends = [InputSpend::new(InputSigner::ScriptSig(&out[..n]))];
        assert_eq!(
            tx.sign_with(&spends, &prevouts),
            Err(Error::SignatureVerification(0))
        );
    }
}

/// The scripts of the outputs the built transactions spend.
struct Scripts {
    keys: [SecpPrivateKey; 3],
    redeem: Vec<u8>,
    p2sh: Vec<u8>,
    bare: Vec<u8>,
    p2pk: Vec<u8>,
    p2pkh: Vec<u8>,
}

fn scripts() -> Scripts {
    let keys = [key(1), key(2), key(3)];
    let publics: Vec<[u8; 33]> = keys
        .iter()
        .map(|k| k.public_key().serialize_compressed())
        .collect();
    let refs: Vec<&[u8]> = publics.iter().map(|k| &k[..]).collect();
    let redeem = Multisig::script(2, &refs).unwrap();
    let uncompressed = keys[1].public_key().serialize_uncompressed();
    let bare = Multisig::script(1, &[&publics[0], &uncompressed]).unwrap();
    let mut p2pk = vec![33];
    p2pk.extend_from_slice(&publics[2]);
    p2pk.push(0xac);
    Scripts {
        p2sh: p2sh_script_of(&redeem).unwrap().to_vec(),
        p2pkh: p2pkh_script(&hash160(&publics[0])).to_vec(),
        redeem,
        bare,
        p2pk,
        keys,
    }
}

#[test]
fn script_kinds() {
    let s = scripts();
    assert!(matches!(ScriptKind::of(&s.p2sh), ScriptKind::P2sh(_)));
    assert!(matches!(ScriptKind::of(&s.p2pkh), ScriptKind::P2pkh(_)));
    assert!(matches!(ScriptKind::of(&s.p2pk), ScriptKind::P2pk(k) if k.len() == 33));
    let ScriptKind::Multisig(m) = ScriptKind::of(&s.bare) else {
        panic!()
    };
    assert_eq!((m.required(), m.key_count()), (1, 2));
    assert_eq!(m.keys().map(|k| k.len()).collect::<Vec<_>>(), [33, 65]);
    assert_eq!(ScriptKind::of(&[]), ScriptKind::Other);
    assert_eq!(ScriptKind::of(&[0x6a]), ScriptKind::Other);
    // every truncation is refused, without panic
    for cut in 0..s.redeem.len() {
        assert_eq!(
            Multisig::parse(&s.redeem[..cut]),
            Err(Error::UnsupportedScript)
        );
        assert_eq!(
            Multisig::parse(&s.redeem[cut + 1..]),
            Err(Error::UnsupportedScript)
        );
    }
    let mut bad = s.redeem.clone();
    bad[0] = 0x54; // 4 of 3
    assert_eq!(Multisig::parse(&bad), Err(Error::UnsupportedScript));
    bad[0] = 0x50;
    assert_eq!(Multisig::parse(&bad), Err(Error::UnsupportedScript));
    let k = s.keys[0].public_key().serialize_compressed();
    assert_eq!(Multisig::script(0, &[&k]), Err(Error::KeyCount));
    assert_eq!(Multisig::script(2, &[&k]), Err(Error::KeyCount));
    assert_eq!(Multisig::script(1, &[&k[..]; 17]), Err(Error::KeyCount));
    assert_eq!(Multisig::script(1, &[&k[..32]]), Err(Error::InvalidKey));
    assert_eq!(Multisig::script(1, &[&[5u8; 33]]), Err(Error::InvalidKey));
    // sixteen keys make a script, but not a redeem script
    let big = Multisig::script(16, &[&k[..]; 16]).unwrap();
    assert_eq!(Multisig::parse(&big).unwrap().key_count(), 16);
    assert_eq!(p2sh_script_of(&big), Err(Error::TooLarge));
    assert!(p2sh_script_of(&Multisig::script(15, &[&k[..]; 15]).unwrap()).is_ok());

    assert!(InputSignature::from_bytes(&[]).is_err());
    let der = s.keys[0].sign_der(&[7; 32]);
    assert_eq!(
        InputSignature::from_der(der.as_bytes(), 0x04),
        Err(Error::UnsupportedSighash)
    );
    assert_eq!(
        InputSignature::from_der(der.as_bytes(), 0x00),
        Err(Error::UnsupportedSighash)
    );
    assert_eq!(
        InputSignature::from_der(&der.as_bytes()[1..], 0x01),
        Err(Error::InvalidSignature)
    );
    let sig = InputSignature::from_der(der.as_bytes(), 0x83).unwrap();
    assert_eq!(sig.hash_type(), 0x83);
    assert_eq!(sig.der(), der.as_bytes());
    assert_eq!(InputSignature::from_bytes(sig.as_bytes()), Ok(sig));
    for t in 0..=255u8 {
        assert_eq!(is_valid_sighash_type(t), SIX.contains(&t));
    }
}

/// Every kind of input, each with its own sighash type, in both versions:
/// signed here, verified, and signed again through signatures made
/// "elsewhere".
#[test]
fn every_kind_and_sighash_type() {
    let s = scripts();
    let scripts_of_inputs: [&[u8]; 6] = [&s.p2sh, &s.bare, &s.p2pk, &s.p2pkh, &s.p2sh, &s.p2sh];
    let inputs: Vec<ZcashTxIn<'_>> = (0..6)
        .map(|i| ZcashTxIn {
            txid: [0x20 + i as u8; 32],
            vout: i,
            script_sig: &[],
            sequence: 0xffff_fffe,
        })
        .collect();
    let prevouts: Vec<ZcashTxOut<'_>> = scripts_of_inputs
        .iter()
        .enumerate()
        .map(|(i, script)| ZcashTxOut {
            amount: 100_000 + i as u64,
            script,
        })
        .collect();
    let outputs: Vec<ZcashTxOut<'_>> = (0..6)
        .map(|i| ZcashTxOut {
            amount: 90_000 + i,
            script: &s.p2pkh,
        })
        .collect();
    let all = [&s.keys[0], &s.keys[1], &s.keys[2]];
    let last_two = [&s.keys[2], &s.keys[1]];
    let custom = |sighash: &[u8; 32], out: &mut [u8]| {
        // what `Multisig` does, by hand: keys 1 and 3
        let mut n = 1;
        out[0] = 0;
        for k in [&s.keys[0], &s.keys[2]] {
            let der = k.sign_der(sighash);
            let mut sig = der.as_bytes().to_vec();
            sig.push(SIX[5]);
            n += crate::pushbytes::push_bytes_to_slice(&sig, &mut out[n..]).unwrap();
        }
        n += crate::pushbytes::push_bytes_to_slice(&s.redeem, &mut out[n..]).unwrap();
        Ok(n)
    };
    for (version, branch_id) in [(TxVersion::V5, branch::NU6_2), (TxVersion::V6, branch::NU7)] {
        let tx = ZcashTx {
            version,
            consensus_branch_id: branch_id,
            expiry_height: 3_600_000,
            lock_time: 7,
            inputs: &inputs,
            outputs: &outputs,
            ..Default::default()
        };
        let spends = [
            InputSpend::new(InputSigner::Multisig {
                redeem_script: Some(&s.redeem),
                keys: &all,
            })
            .with_hash_type(SIX[0]),
            InputSpend::new(InputSigner::Multisig {
                redeem_script: None,
                keys: &last_two,
            })
            .with_hash_type(SIX[1]),
            InputSpend::new(InputSigner::Key(&s.keys[2])).with_hash_type(SIX[2]),
            InputSpend::new(InputSigner::Key(&s.keys[0])).with_hash_type(SIX[3]),
            InputSpend::new(InputSigner::Multisig {
                redeem_script: Some(&s.redeem),
                keys: &last_two,
            })
            .with_hash_type(SIX[4]),
            InputSpend::new(InputSigner::Custom {
                max_len: 300,
                build: &custom,
            })
            .with_hash_type(SIX[5]),
        ];
        let raw = tx.sign_with(&spends, &prevouts).unwrap();
        assert!(raw.len() <= tx.signed_len_bound_with(&spends));
        dump(&format!("transparent_kinds_{version:?}"), &raw, &prevouts);

        let mut parsed_inputs = [ZcashTxIn::default(); 6];
        let mut parsed_outputs = [ZcashTxOut::default(); 6];
        let parsed = ZcashTx::parse_into(&raw, &mut parsed_inputs, &mut parsed_outputs).unwrap();
        assert_eq!(parsed.txid(), tx.txid());
        assert_eq!(parsed.serialize(), raw);
        for (i, hash_type) in SIX.into_iter().enumerate() {
            assert_eq!(parsed.verify_input(i, &prevouts), Ok(()), "input {i}");
            let items = pushes(parsed.inputs[i].script_sig);
            let signature = items.iter().find(|item| item.len() > 60).unwrap();
            assert_eq!(*signature.last().unwrap(), hash_type);
        }
        // the first two keys signed input 0; keys 2 and 3 input 4
        let k: Vec<&[u8]> = Multisig::parse(&s.redeem).unwrap().keys().collect();
        let sig = |item: &[u8]| InputSignature::from_bytes(item).unwrap();
        let check = |i: usize, key: &[u8], item: &[u8]| {
            parsed.verify_input_signature(i, key, &sig(item), &prevouts)
        };
        let items = pushes(parsed.inputs[0].script_sig);
        assert_eq!(items.len(), 4);
        assert_eq!(check(0, k[0], items[1]), Ok(()));
        assert_eq!(check(0, k[1], items[2]), Ok(()));
        let items = pushes(parsed.inputs[4].script_sig);
        assert_eq!(check(4, k[1], items[1]), Ok(()));
        assert_eq!(check(4, k[2], items[2]), Ok(()));
        assert_eq!(
            check(4, k[0], items[2]),
            Err(Error::SignatureVerification(4))
        );
        assert_eq!(check(4, &k[0][1..], items[2]), Err(Error::InvalidKey));
        // the bare 1-of-2 is signed by its second key, the uncompressed one
        assert_eq!(pushes(parsed.inputs[1].script_sig).len(), 2);
        // a scriptSig of one input is not one of another
        let moved = [ZcashTxIn {
            script_sig: parsed.inputs[4].script_sig,
            ..parsed.inputs[0]
        }];
        let moved = ZcashTx {
            inputs: &moved,
            ..parsed
        };
        assert!(moved.verify_input(0, &prevouts[..1]).is_err());

        // the same transaction, from signatures made elsewhere: each
        // co-signer is given the digest and returns a DER signature
        let external = |i: usize, k: &SecpPrivateKey| {
            let sighash = tx.sighash(Some(i), SIX[i], &prevouts).unwrap();
            InputSignature::from_der(k.sign_der(&sighash).as_bytes(), SIX[i]).unwrap()
        };
        let multisig = |i: usize, redeem: Option<&[u8]>, given: &[InputSignature]| {
            let mut out = vec![0u8; 300];
            let n = tx
                .multisig_script_sig_to_slice(i, redeem, given, &prevouts, &mut out)
                .unwrap();
            out.truncate(n);
            out
        };
        let mut p2pk = vec![0u8; 80];
        let n = p2pk_script_sig_to_slice(&external(2, &s.keys[2]), &mut p2pk).unwrap();
        p2pk.truncate(n);
        let mut p2pkh = vec![0u8; MAX_SCRIPT_SIG_LEN];
        let n = p2pkh_script_sig_to_slice(
            &external(3, &s.keys[0]),
            &s.keys[0].public_key().serialize_compressed(),
            &mut p2pkh,
        )
        .unwrap();
        p2pkh.truncate(n);
        let script_sigs = [
            // any order, and one more than needed
            multisig(
                0,
                Some(&s.redeem),
                &[
                    external(0, &s.keys[2]),
                    external(0, &s.keys[1]),
                    external(0, &s.keys[0]),
                ],
            ),
            multisig(1, None, &[external(1, &s.keys[1])]),
            p2pk,
            p2pkh,
            multisig(
                4,
                Some(&s.redeem),
                &[external(4, &s.keys[2]), external(4, &s.keys[1])],
            ),
            multisig(
                5,
                Some(&s.redeem),
                &[external(5, &s.keys[0]), external(5, &s.keys[2])],
            ),
        ];
        let ready: Vec<InputSpend<'_>> = script_sigs
            .iter()
            .map(|script_sig| InputSpend::new(InputSigner::ScriptSig(script_sig)))
            .collect();
        // ECDSA here is deterministic: the very same transaction
        assert_eq!(tx.sign_with(&ready, &prevouts).unwrap(), raw);

        // what is refused
        let sign = |i: usize, spend: InputSpend<'_>| {
            tx.script_sig_to_slice(i, &spend, &prevouts, &mut [0u8; 400])
                .map(|_| ())
        };
        let multisig_spend = |redeem_script, keys| {
            InputSpend::new(InputSigner::Multisig {
                redeem_script,
                keys,
            })
        };
        let one = [&s.keys[0]];
        let (k8, k9) = (key(8), key(9));
        let strangers = [&k8, &k9];
        assert_eq!(
            sign(0, multisig_spend(Some(&s.redeem), &one)),
            Err(Error::MissingSignatures)
        );
        assert_eq!(
            sign(0, multisig_spend(Some(&s.redeem), &strangers)),
            Err(Error::MissingSignatures)
        );
        assert_eq!(
            sign(0, multisig_spend(None, &all)),
            Err(Error::MissingRedeemScript)
        );
        assert_eq!(
            sign(0, multisig_spend(Some(&s.bare), &all)),
            Err(Error::RedeemScriptMismatch)
        );
        assert_eq!(
            sign(1, multisig_spend(Some(&s.redeem), &all)),
            Err(Error::RedeemScriptMismatch)
        );
        assert_eq!(
            sign(3, multisig_spend(None, &all)),
            Err(Error::UnsupportedScript)
        );
        assert_eq!(
            sign(2, InputSpend::new(InputSigner::Key(&s.keys[0]))),
            Err(Error::KeyNotInvolved)
        );
        assert_eq!(
            sign(3, InputSpend::new(InputSigner::Key(&s.keys[1]))),
            Err(Error::KeyNotInvolved)
        );
        assert_eq!(
            sign(0, InputSpend::new(InputSigner::Key(&s.keys[0]))),
            Err(Error::UnsupportedScript)
        );
        assert_eq!(
            sign(
                2,
                InputSpend::new(InputSigner::Key(&s.keys[2])).with_hash_type(0x04)
            ),
            Err(Error::UnsupportedSighash)
        );
        // a scriptSig made elsewhere for another input, or of another form
        assert_eq!(
            sign(4, InputSpend::new(InputSigner::ScriptSig(&script_sigs[0]))),
            Err(Error::SignatureVerification(4))
        );
        assert_eq!(
            sign(3, InputSpend::new(InputSigner::ScriptSig(&script_sigs[2]))),
            Err(Error::InvalidScript)
        );
        assert_eq!(
            sign(
                5,
                InputSpend::new(InputSigner::Custom {
                    max_len: 10,
                    build: &|_, _| Ok(11)
                })
            ),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(
            sign(
                5,
                InputSpend::new(InputSigner::Custom {
                    max_len: 10,
                    build: &|_, _| Err(Error::Signer)
                })
            ),
            Err(Error::Signer)
        );
        assert_eq!(tx.sign_with(&spends[..5], &prevouts), Err(Error::KeyCount));
        // buffers too short never panic
        for len in [0, 10, 21, 60, raw.len() / 2, raw.len() - 1] {
            let mut short = vec![0u8; len];
            assert_eq!(
                tx.sign_with_to_slice(&ready, &prevouts, &mut short),
                Err(Error::BufferTooSmall),
                "{len}"
            );
        }
        let mut enough = vec![0u8; tx.signed_len_bound_with(&ready)];
        let n = tx
            .sign_with_to_slice(&ready, &prevouts, &mut enough)
            .unwrap();
        assert_eq!(enough[..n], raw[..]);
    }
}

/// A scriptSig of a script this module does not know is used as given.
#[test]
fn unknown_scripts_pass_through() {
    // OP_1: anyone can spend
    let script = [0x51u8];
    let p2sh = p2sh_script_of(&script).unwrap();
    let inputs = [ZcashTxIn {
        txid: [9; 32],
        vout: 0,
        script_sig: &[],
        sequence: u32::MAX,
    }];
    let outputs = [ZcashTxOut {
        amount: 1,
        script: &p2sh,
    }];
    let tx = ZcashTx {
        inputs: &inputs,
        outputs: &outputs,
        ..Default::default()
    };
    let prevouts = [ZcashTxOut {
        amount: 10_001,
        script: &p2sh,
    }];
    let script_sig = [1u8, 0x51];
    let spends = [InputSpend::new(InputSigner::ScriptSig(&script_sig))];
    let raw = tx.sign_with(&spends, &prevouts).unwrap();
    let mut i = [ZcashTxIn::default(); 1];
    let mut o = [ZcashTxOut::default(); 1];
    let parsed = ZcashTx::parse_into(&raw, &mut i, &mut o).unwrap();
    assert_eq!(parsed.inputs[0].script_sig, script_sig);
    assert_eq!(
        parsed.verify_input(0, &prevouts),
        Err(Error::UnsupportedScript)
    );
    // but the redeem script must still be the one of the output
    let spends = [InputSpend::new(InputSigner::ScriptSig(&[1u8, 0x52]))];
    assert_eq!(
        tx.sign_with(&spends, &prevouts),
        Err(Error::RedeemScriptMismatch)
    );
    // the existing P2PKH signer is unchanged
    let k = key(5);
    let script = p2pkh_script(&hash160(&k.public_key().serialize_compressed()));
    let prevouts = [ZcashTxOut {
        amount: 10_001,
        script: &script,
    }];
    let spends = [InputSpend::new(InputSigner::Key(&k))];
    assert_eq!(
        tx.sign_with(&spends, &prevouts).unwrap(),
        tx.sign(&[&k], &prevouts).unwrap()
    );
}
