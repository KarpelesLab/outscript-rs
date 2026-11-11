//! Transparent inputs of every kind, signatures made elsewhere, change
//! and fees decided by the builder, bundles that are not padded, and
//! shielded coinbase transactions.
//!
//! The transactions built here are dumped as those of `tests.rs` are
//! (`ZCASH_TX_DUMP`), with the keys that read them: `<name>.fvks` (Orchard
//! full viewing keys) and `<name>.sapling_ivks` (Sapling incoming viewing
//! keys). A program outside this repository had `zcash_primitives` 0.31.0,
//! `sapling-crypto` 0.9.0 and `orchard` 0.16.0 parse each of them,
//! serialize it back to the same bytes, verify every proof and signature,
//! decrypt the notes with the external and the internal incoming viewing
//! keys of each wallet (the change is read by the internal one alone),
//! and, for the coinbase transactions, recover every shielded output with
//! the all-zero outgoing viewing key.

use super::*;
use crate::zcashtx::{
    InputSignature, InputSigner, InputSpend, Multisig, SIGHASH_ANYONECANPAY, SIGHASH_NONE,
    SIGHASH_SINGLE, p2sh_script_of,
};

/// The scripts of a 2-of-3 multisignature of the keys 1, 2 and 3.
fn multisig() -> ([SecpPrivateKey; 3], Vec<u8>, Vec<u8>) {
    let keys = [key(1), key(2), key(3)];
    let publics: Vec<[u8; 33]> = keys
        .iter()
        .map(|k| k.public_key().serialize_compressed())
        .collect();
    let refs: Vec<&[u8]> = publics.iter().map(|k| &k[..]).collect();
    let redeem = Multisig::script(2, &refs).unwrap();
    let p2sh = p2sh_script_of(&redeem).unwrap().to_vec();
    (keys, redeem, p2sh)
}

/// The inputs of a built transaction verify, each for its kind.
fn verify_inputs(tx: &Transaction, coins: &[Coin], n_outputs: usize) {
    let mut inputs = vec![ZcashTxIn::default(); coins.len()];
    let mut outputs = vec![ZcashTxOut::default(); n_outputs];
    let parsed = ZcashTx::parse_into(&tx.raw, &mut inputs, &mut outputs).unwrap();
    assert_eq!(parsed.txid().unwrap(), tx.txid);
    let prevouts: Vec<ZcashTxOut<'_>> = coins
        .iter()
        .map(|coin| ZcashTxOut {
            amount: coin.amount,
            script: &coin.script,
        })
        .collect();
    for i in 0..coins.len() {
        assert_eq!(parsed.verify_input(i, &prevouts), Ok(()), "input {i}");
    }
    assert_eq!(
        parsed.sighash(None, SIGHASH_ALL, &prevouts).unwrap(),
        tx.shielded_sighash
    );
}

/// Multisignature, P2PK and P2PKH inputs, signed by the builder and
/// elsewhere, with every sighash type.
#[test]
fn transparent_inputs_of_every_kind() {
    let (keys, redeem, p2sh) = multisig();
    let k = key(4);
    let public = k.public_key().serialize_compressed();
    let mut p2pk = vec![33];
    p2pk.extend_from_slice(&public);
    p2pk.push(0xac);
    let coins = [
        Coin {
            amount: 100_000,
            script: p2sh.clone(),
        },
        Coin {
            amount: 50_000,
            script: p2pk.clone(),
        },
        Coin {
            amount: 60_000,
            script: p2pkh(&k),
        },
        Coin {
            amount: 70_000,
            script: p2sh.clone(),
        },
        Coin {
            amount: 80_000,
            script: p2pkh(&k),
        },
    ];
    let to = p2pkh(&key(5));
    let signers = [&keys[2], &keys[0]];
    let hash_types = [
        SIGHASH_ALL,
        SIGHASH_NONE,
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE,
    ];
    let prevout = |i: usize| ZcashTxOut {
        amount: coins[i].amount,
        script: &coins[i].script,
    };

    for (branch_id, name) in [
        (branch::NU6_2, "transparent_builder_v5"),
        (branch::NU7, "transparent_builder_v6"),
    ] {
        let mut builder = Builder::new(branch_id, 3_600_000, 0);
        // signed here: a multisignature and a P2PK output
        builder
            .add_transparent_input_with(
                InputSpend::new(InputSigner::Multisig {
                    redeem_script: Some(&redeem),
                    keys: &signers,
                })
                .with_hash_type(hash_types[0]),
                [0x41; 32],
                0,
                u32::MAX,
                prevout(0),
            )
            .unwrap();
        builder
            .add_transparent_input_with(
                InputSpend::new(InputSigner::Key(&k)).with_hash_type(hash_types[1]),
                [0x42; 32],
                1,
                u32::MAX,
                prevout(1),
            )
            .unwrap();
        builder
            .add_transparent_input_with(
                InputSpend::new(InputSigner::Key(&k)).with_hash_type(hash_types[2]),
                [0x43; 32],
                2,
                u32::MAX,
                prevout(2),
            )
            .unwrap();
        // signed elsewhere: a multisignature and a P2PKH output
        let multisig = Multisig::parse(&redeem).unwrap();
        builder
            .add_transparent_input_external(
                multisig.script_sig_len_bound(Some(redeem.len())),
                hash_types[3],
                [0x44; 32],
                3,
                u32::MAX,
                prevout(3),
            )
            .unwrap();
        builder
            .add_transparent_input_external(107, hash_types[4], [0x45; 32], 4, u32::MAX, prevout(4))
            .unwrap();
        for i in 0..5 {
            builder.add_transparent_output(60_000 + i, &to).unwrap();
        }
        // the multisignature inputs are 297 bytes at most: two actions
        // each; the five outputs are five
        assert_eq!(builder.logical_actions(), 2 + 1 + 1 + 2 + 1);
        let fee = builder.fee().unwrap();
        assert_eq!(fee, 360_000 - 300_010);

        // not all in one step
        let again = |b: &Builder<'_>| b.fee();
        assert_eq!(again(&builder), Ok(fee));
        let mut pending = builder
            .build_pending(&Provers::new(), fee, &random(1))
            .unwrap();
        assert_eq!(pending.input_count(), 5);
        assert_eq!(pending.unsigned_inputs().collect::<Vec<_>>(), [3, 4]);
        assert_eq!(pending.input_hash_type(3), Ok(hash_types[3]));
        assert_eq!(
            pending.input_hash_type(5),
            Err(Error::Tx(crate::Error::InputIndex))
        );

        // the co-signers of input 3: keys 2 and 3, the first for another
        // sighash type than the input was added with
        let digest = pending.input_sighash(3).unwrap();
        assert_ne!(digest, pending.input_sighash(4).unwrap());
        assert_ne!(digest, pending.shielded_sighash());
        let other_type = SIGHASH_NONE | SIGHASH_ANYONECANPAY;
        let other_digest = pending.input_sighash_for(3, other_type).unwrap();
        let sig = |k: &SecpPrivateKey, digest: &[u8; 32], hash_type: u8| {
            InputSignature::from_der(k.sign_der(digest).as_bytes(), hash_type).unwrap()
        };
        let cosigned = [
            sig(&keys[2], &digest, hash_types[3]),
            sig(&keys[1], &other_digest, other_type),
        ];
        // one signature is not enough, a stranger's is refused, and so is
        // a signature of another digest
        assert_eq!(
            pending.apply_multisig_signatures(3, Some(&redeem), &cosigned[..1]),
            Err(Error::Tx(crate::Error::MissingSignatures))
        );
        assert_eq!(
            pending.apply_multisig_signatures(
                3,
                Some(&redeem),
                &[cosigned[0], sig(&key(9), &digest, hash_types[3])]
            ),
            Err(Error::Tx(crate::Error::SignatureVerification(3)))
        );
        assert_eq!(
            pending.apply_multisig_signatures(
                3,
                Some(&redeem),
                &[cosigned[0], sig(&keys[1], &digest, other_type)]
            ),
            Err(Error::Tx(crate::Error::SignatureVerification(3)))
        );
        assert_eq!(
            pending.apply_multisig_signatures(3, None, &cosigned),
            Err(Error::Tx(crate::Error::MissingRedeemScript))
        );
        assert_eq!(pending.unsigned_inputs().collect::<Vec<_>>(), [3, 4]);
        pending
            .apply_multisig_signatures(3, Some(&redeem), &cosigned)
            .unwrap();
        assert_eq!(pending.unsigned_inputs().collect::<Vec<_>>(), [4]);

        // the hardware wallet of input 4
        let digest = pending.input_sighash(4).unwrap();
        let signature = sig(&k, &digest, hash_types[4]);
        assert_eq!(
            pending.apply_signature(4, &key(9).public_key().serialize_compressed(), &signature),
            Err(Error::Tx(crate::Error::KeyNotInvolved))
        );
        assert_eq!(
            pending.apply_signature(4, &public, &sig(&k, &digest, SIGHASH_ALL)),
            Err(Error::Tx(crate::Error::SignatureVerification(4)))
        );
        assert_eq!(
            pending.apply_signature(3, &public, &signature),
            Err(Error::Tx(crate::Error::UnsupportedScript))
        );
        assert_eq!(
            pending.apply_signature(7, &public, &signature),
            Err(Error::Tx(crate::Error::InputIndex))
        );
        pending.apply_signature(4, &public, &signature).unwrap();
        assert_eq!(pending.unsigned_inputs().count(), 0);

        let txid = pending.txid();
        let tx = pending.finish().unwrap();
        assert_eq!(tx.txid, txid);
        dump(name, &tx, &coins);
        verify_inputs(&tx, &coins, 5);

        // each input has the sighash type it was added with
        let mut inputs = [ZcashTxIn::default(); 5];
        let mut outputs = [ZcashTxOut::default(); 5];
        let parsed = ZcashTx::parse_into(&tx.raw, &mut inputs, &mut outputs).unwrap();
        // (of input 3, the first signature is that of the second key,
        // which chose its own type)
        let first_types = [
            hash_types[0],
            hash_types[1],
            hash_types[2],
            other_type,
            hash_types[4],
        ];
        for (i, hash_type) in first_types.into_iter().enumerate() {
            let script_sig = parsed.inputs[i].script_sig;
            // the first signature: after OP_0 in a multisignature
            let at = (script_sig[0] == 0) as usize;
            let len = script_sig[at] as usize;
            assert_eq!(script_sig[at + len], hash_type, "input {i}");
        }
        // the keys of the multisignature signed in the order of the script
        // whatever the order they were given in
        let prevouts: Vec<ZcashTxOut<'_>> = (0..5).map(prevout).collect();
        let script_sig = parsed.inputs[0].script_sig;
        let first = InputSignature::from_bytes(&script_sig[2..2 + script_sig[1] as usize]).unwrap();
        let public = keys[0].public_key().serialize_compressed();
        assert_eq!(
            parsed.verify_input_signature(0, &public, &first, &prevouts),
            Ok(())
        );
    }

    // an input signed elsewhere that nobody signed
    let mut builder = Builder::new(branch::NU7, 0, 0);
    builder
        .add_transparent_input_external(107, SIGHASH_ALL, [0x45; 32], 4, u32::MAX, prevout(4))
        .unwrap();
    builder.add_transparent_output(70_000, &to).unwrap();
    assert_eq!(
        builder.build(&Provers::new(), 10_000, &random(1)),
        Err(Error::MissingTransparentSignature(0))
    );

    // what the builder refuses when an input is added
    let mut builder = Builder::new(branch::NU7, 0, 0);
    let mut add = |signer, i: usize| {
        builder.add_transparent_input_with(InputSpend::new(signer), [1; 32], 0, 0, prevout(i))
    };
    let one = [&keys[0]];
    assert_eq!(
        add(InputSigner::Key(&k), 0),
        Err(Error::Tx(crate::Error::UnsupportedScript))
    );
    assert_eq!(
        add(InputSigner::Key(&keys[0]), 1),
        Err(Error::Tx(crate::Error::KeyNotInvolved))
    );
    assert_eq!(
        add(InputSigner::Key(&keys[0]), 2),
        Err(Error::Tx(crate::Error::KeyNotInvolved))
    );
    assert_eq!(
        add(
            InputSigner::Multisig {
                redeem_script: Some(&redeem),
                keys: &one
            },
            0
        ),
        Err(Error::Tx(crate::Error::MissingSignatures))
    );
    assert_eq!(
        add(
            InputSigner::Multisig {
                redeem_script: None,
                keys: &signers
            },
            0
        ),
        Err(Error::Tx(crate::Error::MissingRedeemScript))
    );
    assert_eq!(
        add(
            InputSigner::Multisig {
                redeem_script: Some(&redeem[1..]),
                keys: &signers
            },
            0
        ),
        Err(Error::Tx(crate::Error::RedeemScriptMismatch))
    );
    assert_eq!(
        add(
            InputSigner::Multisig {
                redeem_script: Some(&redeem),
                keys: &signers
            },
            2
        ),
        Err(Error::Tx(crate::Error::UnsupportedScript))
    );
    assert_eq!(
        builder.add_transparent_input_with(
            InputSpend::new(InputSigner::Key(&k)).with_hash_type(0x04),
            [1; 32],
            0,
            0,
            prevout(2)
        ),
        Err(Error::Tx(crate::Error::UnsupportedSighash))
    );
    assert_eq!(
        builder.add_transparent_input_external(10_001, SIGHASH_ALL, [1; 32], 0, 0, prevout(2)),
        Err(Error::Tx(crate::Error::TooLarge))
    );
    // SIGHASH_SINGLE without an output at the index of the input
    let mut builder = Builder::new(branch::NU7, 0, 0);
    builder
        .add_transparent_input_with(
            InputSpend::new(InputSigner::Key(&k)).with_hash_type(SIGHASH_SINGLE),
            [1; 32],
            0,
            0,
            prevout(2),
        )
        .unwrap();
    assert_eq!(
        builder.build(&Provers::new(), 60_000, &random(1)),
        Err(Error::Tx(crate::Error::OutputIndex))
    );
}

/// A custom scriptSig, and a scriptSig that needs no signature.
#[test]
fn custom_inputs() {
    // a hash lock: OP_SHA256 <hash> OP_EQUAL, behind P2SH
    let secret = b"open sesame";
    let mut redeem = vec![0xa8, 32];
    redeem.extend_from_slice(&crate::hash::sha256_once(secret));
    redeem.push(0x87);
    let p2sh = p2sh_script_of(&redeem).unwrap().to_vec();
    let coins = [
        Coin {
            amount: 40_000,
            script: p2sh.clone(),
        },
        Coin {
            amount: 40_000,
            script: p2sh.clone(),
        },
    ];
    let mut script_sig = vec![secret.len() as u8];
    script_sig.extend_from_slice(secret);
    script_sig.push(redeem.len() as u8);
    script_sig.extend_from_slice(&redeem);
    let seen = core::cell::Cell::new([0u8; 32]);
    let build = |digest: &[u8; 32], out: &mut [u8]| {
        seen.set(*digest);
        out[..script_sig.len()].copy_from_slice(&script_sig);
        Ok(script_sig.len())
    };
    let mut builder = Builder::new(branch::NU7, 0, 0);
    let prevout = ZcashTxOut {
        amount: 40_000,
        script: &p2sh,
    };
    builder
        .add_transparent_input_with(
            InputSpend::new(InputSigner::Custom {
                max_len: script_sig.len(),
                build: &build,
            })
            .with_hash_type(SIGHASH_NONE),
            [7; 32],
            0,
            u32::MAX,
            prevout,
        )
        .unwrap();
    builder
        .add_transparent_input_with(
            InputSpend::new(InputSigner::ScriptSig(&script_sig)),
            [7; 32],
            1,
            u32::MAX,
            prevout,
        )
        .unwrap();
    builder
        .add_transparent_output(70_000, &p2pkh(&key(5)))
        .unwrap();
    assert_eq!(builder.conventional_fee(), 10_000);
    let pending = builder
        .build_pending(&Provers::new(), 10_000, &random(1))
        .unwrap();
    let digest = pending.input_sighash(0).unwrap();
    assert_eq!(pending.unsigned_inputs().count(), 0);
    let tx = pending.finish().unwrap();
    // the function was given the digest of its input, for its type
    assert_eq!(seen.get(), digest);
    dump("transparent_custom", &tx, &coins);
    let mut inputs = [ZcashTxIn::default(); 2];
    let mut outputs = [ZcashTxOut::default(); 1];
    let parsed = ZcashTx::parse_into(&tx.raw, &mut inputs, &mut outputs).unwrap();
    assert_eq!(parsed.inputs[0].script_sig, script_sig);
    assert_eq!(parsed.inputs[1].script_sig, script_sig);

    // given later, the scriptSig must still spend the output
    let mut builder = Builder::new(branch::NU7, 0, 0);
    builder
        .add_transparent_input_external(script_sig.len(), SIGHASH_ALL, [7; 32], 0, 0, prevout)
        .unwrap();
    builder
        .add_transparent_output(30_000, &p2pkh(&key(5)))
        .unwrap();
    let mut pending = builder
        .build_pending(&Provers::new(), 10_000, &random(1))
        .unwrap();
    let mut wrong = script_sig.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert_eq!(
        pending.apply_script_sig(0, &wrong),
        Err(Error::Tx(crate::Error::RedeemScriptMismatch))
    );
    pending.apply_script_sig(0, &script_sig).unwrap();
    assert!(pending.finish().is_ok());
}

/// TEX addresses and the transparent receivers of unified addresses.
#[test]
fn tex_and_unified_outputs() {
    let k = key(4);
    let script = p2pkh(&k);
    let coin = ZcashTxOut {
        amount: 100_000,
        script: &script,
    };
    let (hash, network) =
        crate::zcash::decode_tex_address("auto", "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte")
            .unwrap();
    assert_eq!(network, "zcash");
    let mut builder = Builder::new(branch::NU7, 3_600_000, 0);
    builder
        .add_transparent_input(&k, [3; 32], 0, u32::MAX, coin)
        .unwrap();
    builder.add_tex_output(90_000, &hash).unwrap();
    let tx = builder.build(&Provers::new(), 10_000, &random(1)).unwrap();
    let mut inputs = [ZcashTxIn::default(); 1];
    let mut outputs = [ZcashTxOut::default(); 1];
    let parsed = ZcashTx::parse_into(&tx.raw, &mut inputs, &mut outputs).unwrap();
    // the script of t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC
    let t1 =
        crate::zcash::decode_zcash_address("zcash", "t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC").unwrap();
    assert_eq!(parsed.outputs[0].script, &t1.script[..]);
    assert_eq!(parsed.outputs[0].amount, 90_000);

    #[cfg(feature = "zcash-orchard")]
    {
        use crate::orchard::unified::UnifiedAddress;
        let mut builder = Builder::new(branch::NU7, 3_600_000, 0);
        builder
            .add_transparent_input(&k, [3; 32], 0, u32::MAX, coin)
            .unwrap();
        let p2pkh_ua = UnifiedAddress {
            p2pkh: Some(hash),
            orchard: Some([0; 43]),
            ..Default::default()
        };
        let p2sh_ua = UnifiedAddress {
            p2sh: Some([0x77; 20]),
            sapling: Some([0; 43]),
            ..Default::default()
        };
        let shielded_only = UnifiedAddress {
            orchard: Some([0; 43]),
            ..Default::default()
        };
        builder
            .add_unified_transparent_output(40_000, &p2pkh_ua)
            .unwrap();
        builder
            .add_unified_transparent_output(45_000, &p2sh_ua)
            .unwrap();
        assert_eq!(
            builder.add_unified_transparent_output(1, &shielded_only),
            Err(Error::NoTransparentReceiver)
        );
        let tx = builder.build(&Provers::new(), 15_000, &random(1)).unwrap();
        let mut outputs = [ZcashTxOut::default(); 2];
        let parsed = ZcashTx::parse_into(&tx.raw, &mut inputs, &mut outputs).unwrap();
        assert_eq!(parsed.outputs[0].script, &t1.script[..]);
        assert_eq!(
            parsed.outputs[1].script,
            crate::zcashtx::p2sh_script(&[0x77; 20])
        );
    }
}

/// The fee and the change the builder decides, for a transparent
/// transaction.
#[test]
fn funding_with_transparent_change() {
    let k = key(4);
    let script = p2pkh(&k);
    let to = p2pkh(&key(5));
    let change = p2pkh(&key(6));
    let new = |amounts: &[u64], sent: &[u64]| {
        let mut builder = Builder::new(branch::NU7, 3_600_000, 0);
        for (i, amount) in amounts.iter().enumerate() {
            let coin = ZcashTxOut {
                amount: *amount,
                script: &script,
            };
            builder
                .add_transparent_input(&k, [i as u8 + 1; 32], 0, u32::MAX, coin)
                .unwrap();
        }
        for amount in sent {
            builder.add_transparent_output(*amount, &to).unwrap();
        }
        builder
    };
    let zip317 =
        |builder: &mut Builder<'_>| builder.fund(FeeRule::Zip317, Change::Transparent(&change));

    // one input, one output and the change: two logical actions
    let mut builder = new(&[100_000], &[30_000]);
    assert_eq!(builder.conventional_fee(), 10_000);
    assert_eq!(
        zip317(&mut builder),
        Ok(Funding {
            fee: 10_000,
            change: 60_000
        })
    );
    assert_eq!(builder.fee(), Ok(10_000));
    let (tx, funding) = new(&[100_000], &[30_000])
        .fund_and_build(
            &Provers::new(),
            FeeRule::Zip317,
            Change::Transparent(&change),
            &random(1),
        )
        .unwrap();
    assert_eq!(funding.change, 60_000);
    let mut inputs = [ZcashTxIn::default(); 1];
    let mut outputs = [ZcashTxOut::default(); 2];
    let parsed = ZcashTx::parse_into(&tx.raw, &mut inputs, &mut outputs).unwrap();
    assert_eq!(parsed.outputs[1].amount, 60_000);
    assert_eq!(parsed.outputs[1].script, change);
    assert_eq!(parsed.conventional_fee(), Ok(10_000));
    assert_eq!(
        tx.raw,
        builder
            .build(&Provers::new(), 10_000, &random(1))
            .unwrap()
            .raw
    );

    // the change output is a third action: the fee is that of the
    // transaction with it, not of the transaction before
    let mut builder = new(&[100_000], &[30_000, 20_000]);
    assert_eq!(builder.conventional_fee(), 10_000);
    assert_eq!(
        zip317(&mut builder),
        Ok(Funding {
            fee: 15_000,
            change: 35_000
        })
    );
    assert_eq!(builder.conventional_fee(), 15_000);

    // exactly the fee: no change
    let mut builder = new(&[100_000], &[90_000]);
    assert_eq!(
        zip317(&mut builder),
        Ok(Funding {
            fee: 10_000,
            change: 0
        })
    );
    assert_eq!(builder.logical_actions(), 1);
    // less than the fee
    assert_eq!(
        zip317(&mut new(&[100_000], &[90_001])),
        Err(Error::InsufficientFunds)
    );
    assert_eq!(
        zip317(&mut new(&[100_000], &[100_001])),
        Err(Error::InsufficientFunds)
    );
    // more than the fee without change, not more than the fee with it:
    // what is left would not pay for its own output, and goes to the fee
    for left in [12_000, 15_000] {
        let mut builder = new(&[100_000], &[50_000, 50_000 - left]);
        assert_eq!(builder.conventional_fee(), 10_000);
        assert_eq!(
            zip317(&mut builder),
            Ok(Funding {
                fee: left,
                change: 0
            })
        );
        assert_eq!(builder.fee(), Ok(left));
    }
    let mut builder = new(&[100_000], &[50_000, 34_999]);
    assert_eq!(
        zip317(&mut builder),
        Ok(Funding {
            fee: 15_000,
            change: 1
        })
    );

    // a fee the caller fixes
    let mut builder = new(&[100_000, 100_000], &[30_000]);
    assert_eq!(
        builder.fund(FeeRule::Fixed(1_234), Change::Transparent(&change)),
        Ok(Funding {
            fee: 1_234,
            change: 168_766
        })
    );
    assert_eq!(
        new(&[100_000], &[99_000]).fund(FeeRule::Fixed(1_234), Change::Transparent(&change)),
        Err(Error::InsufficientFunds)
    );
    // an empty transaction has nothing to fund
    assert_eq!(zip317(&mut new(&[], &[])), Err(Error::InsufficientFunds));
}

#[cfg(feature = "zcash-orchard-prover")]
mod shielded {
    use super::super::orchard::{ironwood_wallet, verify_ironwood, verify_orchard, wallet};
    use super::*;
    use crate::orchard::builder::{BuildError, BundleType, NO_MEMO};
    use crate::orchard::bundle::Flags;
    use crate::orchard::circuit::ProvingKey;
    use crate::orchard::keys::{FullViewingKey, OutgoingViewingKey, Scope};
    use crate::orchard::note::NoteVersion;
    use crate::orchard::note_encryption::{
        try_note_decryption_versioned, try_output_recovery_with_ovk_versioned,
    };

    /// The values of the notes `fvk` reads in the bundle of a pool with
    /// its incoming viewing key of `scope`.
    fn read(raw: &[u8], ironwood: bool, fvk: &FullViewingKey, scope: Scope) -> Vec<u64> {
        let mut inputs = vec![ZcashTxIn::default(); 4];
        let mut outputs = vec![ZcashTxOut::default(); 4];
        let parsed = ZcashTx::parse_into(raw, &mut inputs, &mut outputs).unwrap();
        let (bundle, version) = if ironwood {
            (parsed.ironwood_bundle().unwrap(), NoteVersion::V3)
        } else {
            (parsed.orchard_bundle().unwrap(), NoteVersion::V2)
        };
        let Some(bundle) = bundle else {
            return Vec::new();
        };
        let ivk = fvk.to_ivk(scope);
        let mut values: Vec<u64> = bundle
            .actions()
            .filter_map(|action| {
                try_note_decryption_versioned(
                    version,
                    &ivk,
                    &action.output(),
                    &action.enc_ciphertext,
                )
            })
            .map(|(note, _)| note.value())
            .collect();
        values.sort();
        values
    }

    /// The fees the builder counts for change it would add, without
    /// proving anything.
    #[test]
    fn funding_counts_the_actions_of_the_change() {
        let w = wallet(1, 500_000);
        let iw = ironwood_wallet(1, 500_000);
        let to = p2pkh(&key(5));

        // the Orchard pool under NU7: the spend and the change do not
        // share an action
        let mut builder = Builder::new(branch::NU7, 3_600_000, 0);
        builder.set_orchard_anchor(w.anchor).unwrap();
        builder.add_orchard_spend(&w.sk, w.note, w.path).unwrap();
        builder.add_transparent_output(200_000, &to).unwrap();
        // the spend, padded to two actions, and the transparent output
        assert_eq!(builder.logical_actions(), 3);
        assert_eq!(
            builder.fund(FeeRule::Zip317, Change::Orchard(&w.sk)),
            Ok(Funding {
                fee: 15_000,
                change: 285_000
            })
        );
        assert_eq!(builder.logical_actions(), 3);
        assert_eq!(builder.orchard_balance(), Ok(215_000));
        // a second note kept is one more action
        builder.add_orchard_change(&w.sk, 5_000, NO_MEMO).unwrap();
        assert_eq!(builder.logical_actions(), 4);

        // before NU6.3 they do: the change takes the place of padding
        let mut builder = Builder::new(branch::NU6_2, 3_400_000, 0);
        builder.set_orchard_anchor(w.anchor).unwrap();
        builder.add_orchard_spend(&w.sk, w.note, w.path).unwrap();
        builder.add_transparent_output(200_000, &to).unwrap();
        assert_eq!(
            builder.fund(FeeRule::Zip317, Change::Orchard(&w.sk)),
            Ok(Funding {
                fee: 15_000,
                change: 285_000
            })
        );

        // the Orchard pool takes no value in from NU6.3: the change of a
        // transparent input cannot go there, and goes to Ironwood
        let k = key(4);
        let script = p2pkh(&k);
        let coin = ZcashTxOut {
            amount: 100_000,
            script: &script,
        };
        let mut builder = Builder::new(branch::NU7, 3_600_000, 0);
        builder
            .add_transparent_input(&k, [1; 32], 0, u32::MAX, coin)
            .unwrap();
        builder.add_transparent_output(30_000, &to).unwrap();
        builder.set_orchard_anchor(w.anchor).unwrap();
        builder.set_ironwood_anchor(iw.anchor).unwrap();
        assert_eq!(
            builder.fund(FeeRule::Zip317, Change::Orchard(&w.sk)),
            Err(Error::OrchardPoolClosed)
        );
        // an Ironwood bundle the change starts has two actions
        assert_eq!(builder.logical_actions(), 1);
        assert_eq!(
            builder.fund(FeeRule::Zip317, Change::Ironwood(&iw.fvk)),
            Ok(Funding {
                fee: 15_000,
                change: 55_000
            })
        );
        assert_eq!(builder.ironwood_balance(), Ok(-55_000));
        assert_eq!(builder.logical_actions(), 3);

        // not padded, it has one
        let mut builder = Builder::new(branch::NU7, 3_600_000, 0);
        builder
            .add_transparent_input(&k, [1; 32], 0, u32::MAX, coin)
            .unwrap();
        builder.set_ironwood_anchor(iw.anchor).unwrap();
        builder
            .set_ironwood_bundle_type(BundleType::UNPADDED)
            .unwrap();
        assert_eq!(
            builder.fund(FeeRule::Zip317, Change::Ironwood(&iw.fvk)),
            Ok(Funding {
                fee: 10_000,
                change: 90_000
            })
        );
        assert_eq!(builder.logical_actions(), 2);
        assert_eq!(
            builder.set_ironwood_bundle_type(BundleType::Coinbase),
            Err(Error::Coinbase)
        );
    }

    /// Spending from the Orchard pool under NU7 as ZIP 326 has it: a
    /// spend action, whose note of value zero nobody reads, and an output
    /// action for the change, at the internal address.
    #[test]
    #[ignore = "slow in the test profile"]
    fn orchard_change_nu7() {
        let w = wallet(1, 500_000);
        let to = p2pkh(&key(5));
        let mut builder = Builder::new(branch::NU7, 3_600_000, 0);
        builder.set_orchard_anchor(w.anchor).unwrap();
        builder.add_orchard_spend(&w.sk, w.note, w.path).unwrap();
        builder.add_transparent_output(200_000, &to).unwrap();
        let pk = ProvingKey::build(CircuitVersion::PostNu6_3);
        let (tx, funding) = builder
            .fund_and_build(
                &Provers::new().orchard(&pk),
                FeeRule::Zip317,
                Change::Orchard(&w.sk),
                &random(7),
            )
            .unwrap();
        assert_eq!(
            funding,
            Funding {
                fee: 15_000,
                change: 285_000
            }
        );
        dump("orchard_change_nu7", &tx, &[]);
        dump_fvks("orchard_change_nu7", &[&w.fvk]);
        let sighash = verify_transparent(&tx, &[], 1);
        // nothing for the external key, which `verify_orchard` reads with
        let found = verify_orchard(
            &tx.raw,
            0,
            1,
            &sighash,
            CircuitVersion::PostNu6_3,
            215_000,
            &[&w.fvk],
        );
        assert_eq!(found, 0);
        assert_eq!(read(&tx.raw, false, &w.fvk, Scope::External), [0u64; 0]);
        assert_eq!(read(&tx.raw, false, &w.fvk, Scope::Internal), [285_000]);
        let mut ins = [ZcashTxIn::default(); 1];
        let mut outs = [ZcashTxOut::default(); 1];
        let parsed = ZcashTx::parse_into(&tx.raw, &mut ins, &mut outs).unwrap();
        assert_eq!(parsed.conventional_fee(), Ok(15_000));
        let bundle = parsed.orchard_bundle().unwrap().unwrap();
        assert_eq!(bundle.action_count(), 2);
        assert_eq!(bundle.flags(), Flags::ENABLED);
        // the change is recovered with the internal outgoing viewing key
        let ovk = w.fvk.to_ovk(Scope::Internal);
        let recovered: Vec<u64> = bundle
            .actions()
            .filter_map(|action| {
                try_output_recovery_with_ovk_versioned(
                    NoteVersion::V2,
                    &ovk,
                    &action.cv,
                    &action.output(),
                    &action.enc_ciphertext,
                    &action.out_ciphertext,
                )
            })
            .map(|(note, _)| note.value())
            .collect();
        assert_eq!(recovered, [285_000]);
        // the nullifier of the note spent is one of the two revealed
        let nullifier = w.note.nullifier(&w.fvk).to_bytes();
        assert_eq!(
            bundle
                .actions()
                .filter(|a| a.nullifier == nullifier)
                .count(),
            1
        );
    }

    /// A payment from transparent funds to the Ironwood pool, with its
    /// change kept there, at the internal address.
    #[test]
    #[ignore = "slow in the test profile"]
    fn ironwood_change_nu7() {
        let w = ironwood_wallet(1, 0);
        let other = wallet(2, 0);
        let k = key(4);
        let coins = [Coin {
            amount: 100_000,
            script: p2pkh(&k),
        }];
        let mut builder = Builder::new(branch::NU7, 3_600_000, 0);
        let prevout = ZcashTxOut {
            amount: coins[0].amount,
            script: &coins[0].script,
        };
        builder
            .add_transparent_input(&k, [0x61; 32], 0, u32::MAX, prevout)
            .unwrap();
        builder.set_ironwood_anchor(w.anchor).unwrap();
        builder
            .add_ironwood_output(None, other.address, 50_000, NO_MEMO)
            .unwrap();
        let pk = ProvingKey::build(CircuitVersion::PostNu6_3);
        let (tx, funding) = builder
            .fund_and_build(
                &Provers::new().orchard(&pk),
                FeeRule::Zip317,
                Change::Ironwood(&w.fvk),
                &random(7),
            )
            .unwrap();
        // one transparent action, and the payment and the change
        assert_eq!(
            funding,
            Funding {
                fee: 15_000,
                change: 35_000
            }
        );
        dump("ironwood_change_nu7", &tx, &coins);
        dump_fvks("ironwood_change_nu7", &[&w.fvk, &other.fvk]);
        let sighash = verify_transparent(&tx, &coins, 0);
        let found = verify_ironwood(&tx.raw, 1, 0, &sighash, 2, -85_000, &[&w.fvk, &other.fvk]);
        assert_eq!(found, 50_000);
        assert_eq!(read(&tx.raw, true, &w.fvk, Scope::External), [0u64; 0]);
        assert_eq!(read(&tx.raw, true, &w.fvk, Scope::Internal), [35_000]);
        assert_eq!(read(&tx.raw, true, &other.fvk, Scope::External), [50_000]);
    }

    /// The migration of a note from the Orchard pool to the Ironwood
    /// pool, in bundles that are not padded: one action each.
    #[test]
    #[ignore = "slow in the test profile"]
    fn unpadded_migration_nu7() {
        let w = wallet(1, 500_000);
        let iw = ironwood_wallet(1, 0);
        let mut builder = Builder::new(branch::NU7, 3_600_000, 0);
        builder
            .set_orchard_bundle_type(BundleType::UNPADDED)
            .unwrap();
        builder
            .set_ironwood_bundle_type(BundleType::UNPADDED)
            .unwrap();
        builder.set_orchard_anchor(w.anchor).unwrap();
        builder.set_ironwood_anchor(iw.anchor).unwrap();
        builder.add_orchard_spend(&w.sk, w.note, w.path).unwrap();
        // one Orchard action; the Ironwood one is the change
        assert_eq!(builder.logical_actions(), 1);
        let pk = ProvingKey::build(CircuitVersion::PostNu6_3);
        let (tx, funding) = builder
            .fund_and_build(
                &Provers::new().orchard(&pk),
                FeeRule::Zip317,
                Change::Ironwood(&w.fvk),
                &random(7),
            )
            .unwrap();
        assert_eq!(
            funding,
            Funding {
                fee: 10_000,
                change: 490_000
            }
        );
        dump("unpadded_migration_nu7", &tx, &[]);
        dump_fvks("unpadded_migration_nu7", &[&w.fvk]);
        let sighash = verify_transparent(&tx, &[], 0);
        let found = verify_orchard(
            &tx.raw,
            0,
            0,
            &sighash,
            CircuitVersion::PostNu6_3,
            500_000,
            &[&w.fvk],
        );
        assert_eq!(found, 0);
        verify_ironwood(&tx.raw, 0, 0, &sighash, 1, -490_000, &[&w.fvk]);
        assert_eq!(read(&tx.raw, true, &w.fvk, Scope::Internal), [490_000]);
        let mut ins = [ZcashTxIn::default(); 1];
        let mut outs = [ZcashTxOut::default(); 1];
        let parsed = ZcashTx::parse_into(&tx.raw, &mut ins, &mut outs).unwrap();
        assert_eq!(parsed.orchard_bundle().unwrap().unwrap().action_count(), 1);
        assert_eq!(parsed.conventional_fee(), Ok(10_000));
    }

    /// The values of the notes of a coinbase bundle, which the all-zero
    /// outgoing viewing key recovers.
    fn coinbase_notes(raw: &[u8], ironwood: bool) -> Vec<u64> {
        let mut inputs = vec![ZcashTxIn::default(); 1];
        let mut outputs = vec![ZcashTxOut::default(); 4];
        let parsed = ZcashTx::parse_into(raw, &mut inputs, &mut outputs).unwrap();
        assert!(parsed.is_coinbase());
        let (bundle, version) = if ironwood {
            (parsed.ironwood_bundle().unwrap(), NoteVersion::V3)
        } else {
            (parsed.orchard_bundle().unwrap(), NoteVersion::V2)
        };
        let bundle = bundle.unwrap();
        assert!(!bundle.flags().spends_enabled());
        assert!(bundle.flags().outputs_enabled());
        assert_eq!(bundle.flags().cross_address_enabled(), ironwood);
        let ovk = OutgoingViewingKey::from_bytes([0; 32]);
        let mut values: Vec<u64> = bundle
            .actions()
            .map(|action| {
                let (note, _) = try_output_recovery_with_ovk_versioned(
                    version,
                    &ovk,
                    &action.cv,
                    &action.output(),
                    &action.enc_ciphertext,
                    &action.out_ciphertext,
                )
                .expect("opens with the zero key");
                note.value()
            })
            .collect();
        values.sort();
        values
    }

    /// A coinbase transaction of NU7 as the miners of the main network
    /// make them: the funding stream output, and the rest to the Ironwood
    /// pool, in a bundle of flags `0x06` that is not padded.
    #[test]
    #[ignore = "slow in the test profile"]
    fn ironwood_coinbase_nu7() {
        use crate::zcashtx::subsidy::{self, Recipient};
        let height = 3_560_137;
        let fees = 35_000;
        let miner = wallet(3, 0);
        let total = subsidy::coinbase_output_total(height, fees).unwrap();
        let streams = subsidy::funding_streams(height).unwrap();
        let mut builder = Builder::new_coinbase(branch::NU7, height, b"\x04test").unwrap();
        builder.set_ironwood_anchor(wallet(1, 1).anchor).unwrap();
        let mut left = total;
        for stream in streams.as_slice() {
            if let Recipient::Address(address) = stream.recipient {
                let script = crate::zcash::decode_zcash_address("zcash", address).unwrap();
                builder
                    .add_transparent_output(stream.amount, &script.script)
                    .unwrap();
                left -= stream.amount;
            }
        }
        // the key given is not used: a coinbase output opens for anyone
        let ovk = Some(miner.fvk.to_ovk(Scope::External));
        builder
            .add_ironwood_output(ovk, miner.address, left - 208_404, NO_MEMO)
            .unwrap();
        builder
            .add_ironwood_output(None, miner.address, 208_404, NO_MEMO)
            .unwrap();
        // the same value as the real coinbase of that block has
        assert_eq!(left, 41_680_668);
        assert_eq!(builder.created_value(), Ok(total));
        assert_eq!(
            builder.add_ironwood_spend(&miner.sk, miner.note, miner.path),
            Err(Error::Coinbase)
        );
        assert_eq!(
            builder.add_ironwood_change(&miner.fvk, 1, NO_MEMO),
            Err(Error::Coinbase)
        );
        // no Orchard action in a coinbase from NU6.3
        builder.set_orchard_anchor(miner.anchor).unwrap();
        assert_eq!(
            builder.add_orchard_output(None, miner.address, 1, NO_MEMO),
            Err(Error::OrchardPoolClosed)
        );
        // two actions, not padded: the input, and the output and the two
        // actions
        assert_eq!(builder.logical_actions(), 3);
        let pk = ProvingKey::build(CircuitVersion::PostNu6_3);
        let tx = builder
            .build_coinbase(&Provers::new().orchard(&pk), total, &random(7))
            .unwrap();
        dump("ironwood_coinbase_nu7", &tx, &[]);
        dump_fvks("ironwood_coinbase_nu7", &[&miner.fvk]);
        assert_eq!(coinbase_notes(&tx.raw, true), [208_404, 41_472_264]);
        assert_eq!(
            read(&tx.raw, true, &miner.fvk, Scope::External),
            [208_404, 41_472_264]
        );
        let mut ins = [ZcashTxIn::default(); 1];
        let mut outs = [ZcashTxOut::default(); 1];
        let parsed = ZcashTx::parse_into(&tx.raw, &mut ins, &mut outs).unwrap();
        assert_eq!(parsed.version, TxVersion::V6);
        assert_eq!(parsed.expiry_height, height);
        assert_eq!(parsed.coinbase_height(), Some(height));
        let bundle = parsed.ironwood_bundle().unwrap().unwrap();
        assert_eq!(bundle.action_count(), 2);
        assert_eq!(bundle.flags().to_byte(), 0x06);
        assert_eq!(bundle.value_balance(), -(left as i64));
        let mut id = tx.txid;
        id.reverse();
        assert_eq!(bundle.verify_signatures(&id), Ok(()));
        let vk = crate::orchard::circuit::VerifyingKey::embedded(CircuitVersion::PostNu6_3);
        assert_eq!(bundle.verify_proof(&vk), Ok(()));
    }

    /// A coinbase transaction with an Orchard output, as they could be
    /// before NU6.3: `enableSpendsOrchard = 0`, one action.
    #[test]
    #[ignore = "slow in the test profile"]
    fn orchard_coinbase_nu6_2() {
        let miner = wallet(3, 0);
        let mut builder = Builder::new_coinbase(branch::NU6_2, 3_420_000, &[]).unwrap();
        assert_eq!(builder.tx_version(), TxVersion::V5);
        builder.set_orchard_anchor(miner.anchor).unwrap();
        builder
            .add_orchard_output(None, miner.address, 137_500_000, NO_MEMO)
            .unwrap();
        assert_eq!(
            builder.add_orchard_spend(&miner.sk, miner.note, miner.path),
            Err(Error::Coinbase)
        );
        assert_eq!(
            builder.add_orchard_change(&miner.sk, 1, NO_MEMO),
            Err(Error::Coinbase)
        );
        assert_eq!(
            builder.set_orchard_bundle_type(BundleType::UNPADDED),
            Err(Error::Coinbase)
        );
        let pk = ProvingKey::build(CircuitVersion::FixedPostNu6_2);
        let tx = builder
            .build_coinbase(&Provers::new().orchard(&pk), 137_500_000, &random(7))
            .unwrap();
        dump("orchard_coinbase_nu6_2", &tx, &[]);
        dump_fvks("orchard_coinbase_nu6_2", &[&miner.fvk]);
        assert_eq!(coinbase_notes(&tx.raw, false), [137_500_000]);
        let mut ins = [ZcashTxIn::default(); 1];
        let mut outs = [ZcashTxOut::default(); 1];
        let parsed = ZcashTx::parse_into(&tx.raw, &mut ins, &mut outs).unwrap();
        let bundle = parsed.orchard_bundle().unwrap().unwrap();
        assert_eq!(bundle.action_count(), 1);
        assert_eq!(bundle.flags().to_byte(), 0x02);
        let vk = crate::orchard::circuit::VerifyingKey::embedded(CircuitVersion::FixedPostNu6_2);
        assert_eq!(bundle.verify_proof(&vk), Ok(()));

        // under NU7 the same is refused before anything is proven
        let mut builder = Builder::new_coinbase(branch::NU7, 3_600_000, &[]).unwrap();
        builder.set_orchard_anchor(miner.anchor).unwrap();
        assert_eq!(
            builder.add_orchard_output(None, miner.address, 1, NO_MEMO),
            Err(Error::OrchardPoolClosed)
        );
        let _ = BuildError::BundleTypeNotSatisfiable;
    }
}

/// Sapling: change at the internal address, and a coinbase output.
#[cfg(all(feature = "std", feature = "zcash-sapling-prover"))]
mod sapling_funding {
    use super::super::sapling::{verify_sapling, wallet};
    use super::*;
    use crate::sapling::keys::OutgoingViewingKey;
    use crate::sapling::note_encryption::{
        Zip212Enforcement, try_note_decryption, try_output_recovery_with_ovk,
    };

    fn dump_ivks(name: &str, ivks: &[[u8; 32]]) {
        let Some(dir) = std::env::var_os("ZCASH_TX_DUMP") else {
            return;
        };
        let keys: Vec<String> = ivks.iter().map(hex::encode).collect();
        let path = std::path::PathBuf::from(dir).join(format!("{name}.sapling_ivks"));
        std::fs::write(path, keys.join(",")).unwrap();
    }

    /// A Sapling note spent to a transparent output, the change going to
    /// the internal address of the account (ZIP 32), which the internal
    /// incoming viewing key reads and the external one does not.
    #[test]
    #[ignore = "needs the Sapling parameters"]
    fn sapling_change() {
        let (spend_params, output_params) = crate::sapling::prover::tests::load_params();
        let provers = Provers::new()
            .sapling_spend(&spend_params)
            .sapling_output(&output_params);
        let w = wallet(1, 200_000);
        let expsk = w.key.expanded_spending_key();
        let external = w.key.to_extended_full_viewing_key();
        let internal = external.internal().unwrap();
        let (_, change_address) = internal.default_address().unwrap();
        assert_ne!(change_address, w.address);
        let to = p2pkh(&key(5));

        let mut builder = Builder::new(branch::NU7, 3_600_000, 0);
        builder.set_sapling_anchor(w.anchor).unwrap();
        builder
            .add_sapling_spend(expsk, &w.note, &w.path, &random(10))
            .unwrap();
        builder.add_transparent_output(50_000, &to).unwrap();
        let change_random = random(11);
        let change = Change::Sapling {
            ovk: Some(internal.full_viewing_key().ovk()),
            to: &change_address,
            random: &change_random,
        };
        assert_eq!(std::format!("{change:?}"), "Sapling");
        let (tx, funding) = builder
            .fund_and_build(&provers, FeeRule::Zip317, change, &random(12))
            .unwrap();
        // the spend and the change are one action, the output another
        assert_eq!(
            funding,
            Funding {
                fee: 10_000,
                change: 140_000
            }
        );
        dump("sapling_change", &tx, &[]);
        dump_ivks(
            "sapling_change",
            &[external.ivk().to_bytes(), internal.ivk().to_bytes()],
        );
        let sighash = verify_transparent(&tx, &[], 1);
        verify_sapling(&tx.raw, 0, 1, &sighash, 60_000);
        let mut ins = [ZcashTxIn::default(); 1];
        let mut outs = [ZcashTxOut::default(); 1];
        let parsed = ZcashTx::parse_into(&tx.raw, &mut ins, &mut outs).unwrap();
        assert_eq!(parsed.conventional_fee(), Ok(10_000));
        let bundle = parsed.sapling_bundle().unwrap();
        assert_eq!((bundle.n_spends(), bundle.n_outputs()), (1, 1));
        let out = bundle.output(0).unwrap();
        let read = |ivk| {
            try_note_decryption(
                &ivk,
                out.ephemeral_key,
                out.cmu,
                out.enc_ciphertext,
                Zip212Enforcement::On,
            )
        };
        assert!(read(external.ivk()).is_none());
        let (note, _) = read(internal.ivk()).unwrap();
        assert_eq!(note.value(), 140_000);
    }

    /// A coinbase transaction with a Sapling output (ZIP 213): made with
    /// the all-zero outgoing viewing key whatever key is given.
    #[test]
    #[ignore = "needs the Sapling parameters"]
    fn sapling_coinbase() {
        let (spend_params, output_params) = crate::sapling::prover::tests::load_params();
        let provers = Provers::new()
            .sapling_spend(&spend_params)
            .sapling_output(&output_params);
        let miner = wallet(3, 5);
        let expsk = miner.key.expanded_spending_key();
        let mut builder = Builder::new_coinbase(branch::NU7, 3_600_000, &[]).unwrap();
        builder.set_sapling_anchor(miner.anchor).unwrap();
        assert_eq!(
            builder.add_sapling_spend(expsk, &miner.note, &miner.path, &random(10)),
            Err(Error::Coinbase)
        );
        let sent = builder
            .add_sapling_output(
                Some(expsk.ovk()),
                &miner.address,
                45_833_334,
                None,
                &random(11),
            )
            .unwrap();
        let tx = builder
            .build_coinbase(&provers, 45_833_334, &random(12))
            .unwrap();
        dump("sapling_coinbase", &tx, &[]);
        let mut id = tx.txid;
        id.reverse();
        verify_sapling(&tx.raw, 1, 0, &id, -45_833_334);
        let mut ins = [ZcashTxIn::default(); 1];
        let mut outs = [ZcashTxOut::default(); 1];
        let parsed = ZcashTx::parse_into(&tx.raw, &mut ins, &mut outs).unwrap();
        assert!(parsed.is_coinbase());
        let bundle = parsed.sapling_bundle().unwrap();
        assert_eq!((bundle.n_spends(), bundle.n_outputs()), (0, 1));
        let out = bundle.output(0).unwrap();
        let recover = |ovk: &OutgoingViewingKey| {
            try_output_recovery_with_ovk(
                ovk,
                out.cv,
                out.cmu,
                out.ephemeral_key,
                out.enc_ciphertext,
                out.out_ciphertext,
                Zip212Enforcement::On,
            )
        };
        assert!(recover(expsk.ovk()).is_none());
        let (note, _) = recover(&OutgoingViewingKey([0; 32])).unwrap();
        assert_eq!(note, sent);
    }
}
