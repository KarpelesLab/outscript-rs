//! The builder's checks, which run everywhere, and whole transactions
//! built, parsed back and verified in full, which are slow (ignored by
//! default: run them in release) and, for the Sapling parts, need the
//! parameter files (`ZCASH_PARAMS`, see `sapling/prover/tests.rs`).
//!
//! With `ZCASH_TX_DUMP` set to a directory, the transactions built are
//! written there (`<name>.hex`, with `<name>.prevouts` holding one
//! `amount:scriptPubKey` per transparent input, `<name>.txid`, and for
//! some `<name>.fvks`, the Orchard full viewing keys that read their
//! notes), to check them with other implementations.

use super::*;
use crate::crypto::secp256k1::{SecpPublicKey, parse_der_signature};
use crate::pushbytes::parse_push_bytes;
use crate::zcashtx::{TxFormat, branch, tx_format};
use crate::{PubKey, generate_script};

/// Deterministic stand-in for the caller's random generator.
fn random<const N: usize>(tag: u8) -> [u8; N] {
    let mut out = [0u8; N];
    Seed([tag; 64]).fill(0xff, &mut out);
    out
}

fn key(n: u8) -> SecpPrivateKey {
    SecpPrivateKey::from_bytes(&[n; 32]).unwrap()
}

fn p2pkh(key: &SecpPrivateKey) -> Vec<u8> {
    generate_script(&PubKey::Secp256k1(key.public_key()), "p2pkh")
        .unwrap()
        .to_vec()
}

/// What the test knows of a transparent input: what it spends.
struct Coin {
    amount: u64,
    script: Vec<u8>,
}

/// Parses a built transaction and checks all that concerns its transparent
/// parts and its digests: the id, the signature hashes and the signature
/// of every input. Returns the shielded signature hash.
fn verify_transparent(tx: &Transaction, coins: &[Coin], n_outputs: usize) -> [u8; 32] {
    let mut inputs = vec![ZcashTxIn::default(); coins.len()];
    let mut outputs = vec![ZcashTxOut::default(); n_outputs];
    // the buffers are exactly as long as the transaction needs
    if !coins.is_empty() {
        assert_eq!(
            ZcashTx::parse_into(&tx.raw, &mut inputs[1..], &mut outputs).map(|_| ()),
            Err(crate::Error::TooLarge)
        );
    }
    let parsed = ZcashTx::parse_into(&tx.raw, &mut inputs, &mut outputs).unwrap();
    assert_eq!(parsed.inputs.len(), coins.len());
    assert_eq!(parsed.outputs.len(), n_outputs);
    assert_eq!(parsed.serialize(), tx.raw);
    assert_eq!(parsed.txid().unwrap(), tx.txid);

    let prevouts: Vec<ZcashTxOut<'_>> = coins
        .iter()
        .map(|coin| ZcashTxOut {
            amount: coin.amount,
            script: &coin.script,
        })
        .collect();
    let shielded = parsed.sighash(None, SIGHASH_ALL, &prevouts).unwrap();
    assert_eq!(shielded, tx.shielded_sighash);
    if coins.is_empty() {
        let mut id = tx.txid;
        id.reverse();
        assert_eq!(shielded, id);
    }
    for (i, (input, coin)) in parsed.inputs.iter().zip(coins).enumerate() {
        let (sig, n) = parse_push_bytes(input.script_sig).unwrap();
        let (pubkey, m) = parse_push_bytes(&input.script_sig[n..]).unwrap();
        assert_eq!(n + m, input.script_sig.len());
        // the key is the one the spent output pays to
        assert_eq!(coin.script[3..23], hash160(pubkey));
        let (hash_type, der) = sig.split_last().unwrap();
        assert_eq!(*hash_type, SIGHASH_ALL);
        let (r, s) = parse_der_signature(der).unwrap();
        let sighash = parsed.sighash(Some(i), SIGHASH_ALL, &prevouts).unwrap();
        assert_ne!(sighash, shielded);
        let public = SecpPublicKey::from_sec1(pubkey).unwrap();
        assert!(public.verify(&sighash, &r, &s), "input {i}");
        // each input signs its own digest
        if i > 0 {
            let other = parsed.sighash(Some(0), SIGHASH_ALL, &prevouts).unwrap();
            assert!(!public.verify(&other, &r, &s));
        }
    }
    shielded
}

/// Writes a built transaction where `ZCASH_TX_DUMP` says.
fn dump(name: &str, tx: &Transaction, coins: &[Coin]) {
    let Some(dir) = std::env::var_os("ZCASH_TX_DUMP") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::write(dir.join(format!("{name}.hex")), hex::encode(&tx.raw)).unwrap();
    std::fs::write(dir.join(format!("{name}.txid")), hex::encode(tx.txid)).unwrap();
    std::fs::write(
        dir.join(format!("{name}.sighash")),
        hex::encode(tx.shielded_sighash),
    )
    .unwrap();
    let prevouts: Vec<String> = coins
        .iter()
        .map(|coin| format!("{}:{}", coin.amount, hex::encode(&coin.script)))
        .collect();
    std::fs::write(dir.join(format!("{name}.prevouts")), prevouts.join("\n")).unwrap();
}

/// Writes the Orchard full viewing keys that read the notes of a built
/// transaction where `ZCASH_TX_DUMP` says.
#[cfg(feature = "zcash-orchard-prover")]
fn dump_fvks(name: &str, fvks: &[&crate::orchard::keys::FullViewingKey]) {
    let Some(dir) = std::env::var_os("ZCASH_TX_DUMP") else {
        return;
    };
    let keys: Vec<String> = fvks.iter().map(|fvk| hex::encode(fvk.to_bytes())).collect();
    let path = std::path::PathBuf::from(dir).join(format!("{name}.fvks"));
    std::fs::write(path, keys.join(",")).unwrap();
}

/// The version of the transaction, by branch and by choice, and version 6
/// transactions without shielded parts.
#[test]
fn transaction_versions() {
    let k = key(1);
    let script = p2pkh(&k);
    let to = p2pkh(&key(9));
    let coins = [Coin {
        amount: 100_000,
        script: script.clone(),
    }];
    let build = |branch_id: u32, version: Option<TxVersion>| {
        let mut builder = Builder::new(branch_id, 3_600_000, 0);
        if let Some(version) = version {
            builder.set_tx_version(version);
        }
        let prevout = ZcashTxOut {
            amount: 100_000,
            script: &script,
        };
        builder
            .add_transparent_input(&k, [7; 32], 1, u32::MAX, prevout)
            .unwrap();
        builder.add_transparent_output(90_000, &to).unwrap();
        (
            builder.tx_version(),
            builder.build(&Provers::new(), 10_000, &random(1)),
        )
    };
    // the version wallets use under each upgrade
    for (branch_id, expected) in [
        (branch::NU5, TxVersion::V5),
        (branch::NU6, TxVersion::V5),
        (branch::NU6_1, TxVersion::V5),
        (branch::NU6_2, TxVersion::V5),
        (branch::NU6_3, TxVersion::V6),
        (branch::NU7, TxVersion::V6),
        (0x1234_5678, TxVersion::V5),
    ] {
        let (version, tx) = build(branch_id, None);
        assert_eq!(version, expected);
        let tx = tx.unwrap();
        assert_eq!(tx_format(&tx.raw).unwrap().tx_version(), Some(expected));
        verify_transparent(&tx, &coins, 1);
    }
    // version 5 stays valid from NU6.3; version 6 is not before
    for branch_id in [branch::NU6_3, branch::NU7] {
        let (version, v5) = build(branch_id, Some(TxVersion::V5));
        assert_eq!(version, TxVersion::V5);
        let v5 = v5.unwrap();
        assert_eq!(tx_format(&v5.raw), Ok(TxFormat::V5));
        verify_transparent(&v5, &coins, 1);
        let v6 = build(branch_id, Some(TxVersion::V6)).1.unwrap();
        assert_eq!(v6, build(branch_id, None).1.unwrap());
        assert_ne!(v6.txid, v5.txid);
        assert_eq!(v6.raw.len(), v5.raw.len() + 1);
    }
    for branch_id in [branch::NU5, branch::NU6_2] {
        assert_eq!(
            build(branch_id, Some(TxVersion::V6)).1,
            Err(Error::VersionNotActive)
        );
    }
    // a branch not known here: the caller's choice is taken
    let (_, tx) = build(0x1234_5678, Some(TxVersion::V6));
    assert_eq!(tx_format(&tx.unwrap().raw), Ok(TxFormat::V6));

    // the version 6 transaction is the one `ZcashTx::sign` makes
    let tx = build(branch::NU7, None).1.unwrap();
    dump("transparent_v6", &tx, &coins);
    let inputs = [ZcashTxIn {
        txid: [7; 32],
        vout: 1,
        script_sig: &[],
        sequence: u32::MAX,
    }];
    let outputs = [ZcashTxOut {
        amount: 90_000,
        script: &to,
    }];
    let plain = ZcashTx {
        version: TxVersion::V6,
        consensus_branch_id: branch::NU7,
        expiry_height: 3_600_000,
        inputs: &inputs,
        outputs: &outputs,
        ..Default::default()
    };
    let prevouts = [ZcashTxOut {
        amount: 100_000,
        script: &script,
    }];
    assert_eq!(plain.sign(&[&k], &prevouts).unwrap(), tx.raw);
    assert_eq!(plain.txid().unwrap(), tx.txid);
}

#[test]
fn transparent_transaction() {
    let keys = [key(1), key(2), key(3)];
    // the third coin pays to an uncompressed key
    let mut uncompressed = vec![0x76, 0xa9, 0x14];
    uncompressed.extend_from_slice(&hash160(&keys[2].public_key().serialize_uncompressed()));
    uncompressed.extend_from_slice(&[0x88, 0xac]);
    let coins = [
        Coin {
            amount: 100_000,
            script: p2pkh(&keys[0]),
        },
        Coin {
            amount: 100_000,
            script: p2pkh(&keys[1]),
        },
        Coin {
            amount: 60_000,
            script: uncompressed,
        },
    ];
    let to = p2pkh(&key(9));

    let mut builder = Builder::new(branch::NU6_1, 3_200_040, 0);
    assert_eq!(
        builder.clone_empty().build(&Provers::new(), 0, &random(0)),
        Err(Error::Empty)
    );
    for (i, (key, coin)) in keys.iter().zip(&coins).enumerate() {
        let prevout = ZcashTxOut {
            amount: coin.amount,
            script: &coin.script,
        };
        builder
            .add_transparent_input(key, [i as u8; 32], i as u32, 0xffff_fffe, prevout)
            .unwrap();
    }
    assert_eq!(builder.transparent_balance(), 260_000);
    assert_eq!(builder.fee(), Ok(260_000));
    // three inputs, one of them above the standard size
    assert_eq!(builder.logical_actions(), 4);
    builder.add_transparent_output(240_000, &to).unwrap();
    assert_eq!(builder.fee(), Ok(20_000));
    assert_eq!(builder.conventional_fee(), 20_000);

    // not the key of the coin, not a P2PKH coin, too much money
    let prevout = ZcashTxOut {
        amount: 5,
        script: &coins[0].script,
    };
    assert_eq!(
        builder.add_transparent_input(&keys[1], [9; 32], 0, 0, prevout),
        Err(Error::Tx(crate::Error::KeyNotInvolved))
    );
    let p2sh = ZcashTxOut {
        amount: 5,
        script: &[
            0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87,
        ],
    };
    assert_eq!(
        builder.add_transparent_input(&keys[0], [9; 32], 0, 0, p2sh),
        Err(Error::Tx(crate::Error::UnsupportedScript))
    );
    let rich = ZcashTxOut {
        amount: MAX_MONEY + 1,
        script: &coins[0].script,
    };
    assert_eq!(
        builder.add_transparent_input(&keys[0], [9; 32], 0, 0, rich),
        Err(Error::ValueOutOfRange)
    );
    assert_eq!(
        builder.add_transparent_output(MAX_MONEY + 1, &to),
        Err(Error::ValueOutOfRange)
    );
    assert_eq!(builder.fee(), Ok(20_000));

    // the fee is the caller's to state
    let rebuild = |fee: u64, extra: u64| {
        let mut b = Builder::new(branch::NU6_1, 3_200_040, 0);
        for (i, (key, coin)) in keys.iter().zip(&coins).enumerate() {
            let prevout = ZcashTxOut {
                amount: coin.amount,
                script: &coin.script,
            };
            b.add_transparent_input(key, [i as u8; 32], i as u32, 0xffff_fffe, prevout)
                .unwrap();
        }
        b.add_transparent_output(240_000 + extra, &to).unwrap();
        b.build(&Provers::new(), fee, &random(1))
    };
    assert_eq!(
        rebuild(10_000, 0),
        Err(Error::FeeMismatch {
            stated: 10_000,
            actual: 20_000
        })
    );
    assert_eq!(rebuild(0, 20_001), Err(Error::InsufficientFunds));
    assert_eq!(rebuild(0, 20_000).map(|tx| tx.raw.len() > 400), Ok(true));

    let tx = builder.build(&Provers::new(), 20_000, &random(1)).unwrap();
    assert_eq!(rebuild(20_000, 0).as_ref(), Ok(&tx));
    let shielded = verify_transparent(&tx, &coins, 1);
    assert_eq!(shielded, tx.shielded_sighash);
    dump("transparent", &tx, &coins);

    // it is the transaction `ZcashTx::sign` makes
    let inputs: Vec<ZcashTxIn<'_>> = (0..3)
        .map(|i| ZcashTxIn {
            txid: [i as u8; 32],
            vout: i as u32,
            script_sig: &[],
            sequence: 0xffff_fffe,
        })
        .collect();
    let outputs = [ZcashTxOut {
        amount: 240_000,
        script: &to,
    }];
    let plain = ZcashTx {
        consensus_branch_id: branch::NU6_1,
        expiry_height: 3_200_040,
        inputs: &inputs,
        outputs: &outputs,
        ..Default::default()
    };
    let prevouts: Vec<ZcashTxOut<'_>> = coins
        .iter()
        .map(|coin| ZcashTxOut {
            amount: coin.amount,
            script: &coin.script,
        })
        .collect();
    let key_refs: Vec<&SecpPrivateKey> = keys.iter().collect();
    assert_eq!(plain.sign(&key_refs, &prevouts).unwrap(), tx.raw);
    assert_eq!(plain.txid().unwrap(), tx.txid);

    // the signed transaction pays what ZIP-317 asks of it
    let mut ins = [ZcashTxIn::default(); 3];
    let mut outs = [ZcashTxOut::default(); 1];
    let parsed = ZcashTx::parse_into(&tx.raw, &mut ins, &mut outs).unwrap();
    assert_eq!(parsed.conventional_fee(), Ok(20_000));
}

impl Builder<'_> {
    /// A builder with the same header and nothing in it.
    fn clone_empty(&self) -> Builder<'static> {
        Builder::new(self.consensus_branch_id, self.expiry_height, self.lock_time)
    }
}

#[cfg(feature = "zcash-orchard-prover")]
mod orchard {
    use super::*;
    use crate::orchard::Fp;
    use crate::orchard::builder::{BuildError, NO_MEMO};
    use crate::orchard::circuit::{ProvingKey, VerifyingKey};
    use crate::orchard::keys::{Address, FullViewingKey, Scope, SpendingKey};
    use crate::orchard::note::{Note, Nullifier};
    use crate::orchard::note_encryption::try_note_decryption;
    use crate::orchard::tree::{self, MerklePath};

    /// An Orchard wallet with one note of `value` in a small tree.
    pub(super) struct Wallet {
        pub sk: SpendingKey,
        pub fvk: FullViewingKey,
        pub address: Address,
        pub note: Note,
        pub path: MerklePath,
        pub anchor: Fp,
    }

    pub(super) fn wallet(seed: u8, value: u64) -> Wallet {
        let sk = SpendingKey::from_bytes(random(seed)).unwrap();
        let fvk = sk.to_fvk();
        let address = fvk.address_at(0u32, Scope::External);
        let rho = Nullifier::from_fp(Fp::from_uniform_bytes(&random(seed.wrapping_add(100))));
        let note = Note::from_parts(address, value, rho, random(seed.wrapping_add(101))).unwrap();
        let leaves = [
            Fp::from_u64(11),
            Fp::from_u64(22),
            note.cmx().to_fp(),
            Fp::from_u64(44),
        ];
        Wallet {
            sk,
            fvk,
            address,
            note,
            path: tree::witness(&leaves, 2).unwrap(),
            anchor: tree::root(&leaves).unwrap(),
        }
    }

    /// Verifies the Orchard bundle of a serialized transaction in full,
    /// and returns the total value of the notes `fvks` can read in it.
    pub(super) fn verify_orchard(
        raw: &[u8],
        n_inputs: usize,
        n_outputs: usize,
        sighash: &[u8; 32],
        version: CircuitVersion,
        value_balance: i64,
        fvks: &[&FullViewingKey],
    ) -> u64 {
        let mut inputs = vec![ZcashTxIn::default(); n_inputs];
        let mut outputs = vec![ZcashTxOut::default(); n_outputs];
        let parsed = ZcashTx::parse_into(raw, &mut inputs, &mut outputs).unwrap();
        let bundle = parsed.orchard_bundle().unwrap().unwrap();
        assert_eq!(bundle.value_balance(), value_balance);
        assert_eq!(bundle.verify_signatures(sighash), Ok(()));
        assert!(bundle.verify_signatures(&[0x55; 32]).is_err());
        for (other, vk) in CircuitVersion::ALL.iter().zip(VerifyingKey::embedded_all()) {
            assert_eq!(bundle.verify_proof(&vk).is_ok(), *other == version);
        }
        let mut found = 0;
        for action in bundle.actions() {
            for fvk in fvks {
                let ivk = fvk.to_ivk(Scope::External);
                if let Some((note, _)) =
                    try_note_decryption(&ivk, &action.output(), &action.enc_ciphertext)
                {
                    found += note.value();
                }
            }
        }
        found
    }

    #[test]
    fn circuit_versions() {
        use CircuitVersion::*;
        assert_eq!(orchard_circuit_version(branch::NU5), Some(InsecurePreNu6_2));
        assert_eq!(orchard_circuit_version(branch::NU6), Some(InsecurePreNu6_2));
        assert_eq!(
            orchard_circuit_version(branch::NU6_1),
            Some(InsecurePreNu6_2)
        );
        assert_eq!(orchard_circuit_version(branch::NU6_2), Some(FixedPostNu6_2));
        assert_eq!(orchard_circuit_version(branch::NU6_3), Some(PostNu6_3));
        // NU7 keeps the circuit of NU6.3 (`zcash_protocol` 0.11.0)
        assert_eq!(orchard_circuit_version(branch::NU7), Some(PostNu6_3));
        // Canopy, anything else
        assert_eq!(orchard_circuit_version(0xe9ff_75a6), None);
        assert_eq!(orchard_circuit_version(0x1234_5678), None);
        assert_eq!(orchard_circuit_version(0), None);
    }

    #[test]
    fn orchard_checks() {
        let w = wallet(1, 500_000);
        let other = wallet(2, 0);

        // an unknown branch needs its circuit version, a bundle its anchor
        let mut builder = Builder::new(0x1234_5678, 0, 0);
        assert_eq!(builder.orchard_circuit_version(), None);
        assert_eq!(builder.tx_version(), TxVersion::V5);
        builder.set_orchard_anchor(w.anchor).unwrap();
        assert_eq!(
            builder.add_orchard_output(None, other.address, 1, NO_MEMO),
            Err(Error::UnknownCircuitVersion)
        );
        builder
            .set_orchard_circuit_version(CircuitVersion::PostNu6_3)
            .unwrap();
        builder.add_orchard_spend(&w.sk, w.note, w.path).unwrap();
        assert_eq!(
            builder.set_orchard_circuit_version(CircuitVersion::FixedPostNu6_2),
            Err(Error::AlreadyStarted)
        );
        assert_eq!(
            builder.set_orchard_anchor(w.anchor),
            Err(Error::AlreadyStarted)
        );

        let mut builder = Builder::new(branch::NU6_2, 0, 0);
        assert_eq!(
            builder.orchard_circuit_version(),
            Some(CircuitVersion::FixedPostNu6_2)
        );
        assert_eq!(
            builder.add_orchard_spend(&w.sk, w.note, w.path),
            Err(Error::MissingAnchor)
        );
        assert_eq!(
            builder.add_orchard_output(None, other.address, 1, NO_MEMO),
            Err(Error::MissingAnchor)
        );
        // nothing was started by the failures
        builder.set_orchard_anchor(other.anchor).unwrap();
        assert_eq!(
            builder.add_orchard_spend(&w.sk, w.note, w.path),
            Err(Error::Orchard(BuildError::AnchorMismatch))
        );
        builder.set_orchard_anchor(w.anchor).unwrap();
        assert_eq!(
            builder.add_orchard_spend(&other.sk, w.note, w.path),
            Err(Error::Orchard(BuildError::WrongKey))
        );
        assert_eq!(
            builder.add_orchard_output(None, other.address, MAX_MONEY + 1, NO_MEMO),
            Err(Error::ValueOutOfRange)
        );
        assert_eq!(builder.logical_actions(), 0);
        assert_eq!(builder.orchard_balance(), Ok(0));

        // value balances: positive out of the pool, negative into it
        builder.add_orchard_spend(&w.sk, w.note, w.path).unwrap();
        assert_eq!(builder.orchard_balance(), Ok(500_000));
        assert_eq!(builder.fee(), Ok(500_000));
        assert_eq!(builder.logical_actions(), 2);
        for _ in 0..3 {
            builder
                .add_orchard_output(None, other.address, 200_000, NO_MEMO)
                .unwrap();
        }
        assert_eq!(builder.orchard_balance(), Ok(-100_000));
        assert_eq!(builder.fee(), Err(Error::InsufficientFunds));
        assert_eq!(builder.logical_actions(), 3);
        assert_eq!(builder.conventional_fee(), 15_000);
        // a transparent coin pays for the difference and the fee
        let k = key(1);
        let script = p2pkh(&k);
        let prevout = ZcashTxOut {
            amount: 115_000,
            script: &script,
        };
        builder
            .add_transparent_input(&k, [1; 32], 0, u32::MAX, prevout)
            .unwrap();
        assert_eq!(builder.fee(), Ok(15_000));
        assert_eq!(builder.conventional_fee(), 20_000);
        assert_eq!(
            builder.build(&Provers::new(), 15_000, &random(3)),
            Err(Error::MissingProvingKey)
        );
    }

    /// A transaction moving value between the transparent and the Orchard
    /// pools, for the circuit version of `branch_id`: one transparent coin
    /// and one note in, one transparent output and one note out.
    fn orchard_transaction(branch_id: u32, name: &str) {
        orchard_transaction_as(branch_id, None, name)
    }

    /// The same, in the transaction version given rather than in the one
    /// of the branch.
    fn orchard_transaction_as(branch_id: u32, tx_version: Option<TxVersion>, name: &str) {
        let version = orchard_circuit_version(branch_id).unwrap();
        let restricted = version.supports_cross_address_restriction();
        let w = wallet(1, 500_000);
        let other = wallet(2, 0);
        let k = key(4);
        let coins = [Coin {
            amount: 100_000,
            script: p2pkh(&k),
        }];
        let to = p2pkh(&key(5));

        let mut builder = Builder::new(branch_id, 3_500_000, 0);
        if let Some(tx_version) = tx_version {
            builder.set_tx_version(tx_version);
        }
        let tx_version = builder.tx_version();
        assert_eq!(
            tx_version,
            tx_version_of(branch_id, tx_version),
            "{name}: the version of the branch unless chosen"
        );
        let prevout = ZcashTxOut {
            amount: coins[0].amount,
            script: &coins[0].script,
        };
        builder
            .add_transparent_input(&k, [0x21; 32], 3, u32::MAX, prevout)
            .unwrap();
        builder.set_orchard_anchor(w.anchor).unwrap();
        builder.add_orchard_spend(&w.sk, w.note, w.path).unwrap();
        let ovk = Some(w.fvk.to_ovk(Scope::External));
        // from NU6.3 a note only goes back to where the spent one was
        let (recipient, shielded, transparent) = if restricted {
            (w.address, 300_000, 285_000)
        } else {
            (other.address, 550_000, 35_000)
        };
        builder
            .add_orchard_output(ovk, recipient, shielded, NO_MEMO)
            .unwrap();
        builder.add_transparent_output(transparent, &to).unwrap();
        let balance = 500_000 - shielded as i64;
        assert_eq!(builder.orchard_balance(), Ok(balance));
        // one transparent action and two Orchard ones
        assert_eq!(builder.conventional_fee(), 15_000);
        assert_eq!(builder.fee(), Ok(15_000));

        let pk = ProvingKey::build(version);
        if restricted {
            // an output to another address cannot be paired
            let mut bad = Builder::new(branch_id, 0, 0);
            bad.set_orchard_anchor(w.anchor).unwrap();
            bad.add_orchard_spend(&w.sk, w.note, w.path).unwrap();
            bad.add_orchard_output(None, other.address, 490_000, NO_MEMO)
                .unwrap();
            assert_eq!(
                bad.build(&Provers::new().orchard(&pk), 10_000, &random(8)),
                Err(Error::Orchard(BuildError::CrossAddressDisabled))
            );
        } else {
            // the key of another circuit version is refused
            let wrong = ProvingKey::build(CircuitVersion::PostNu6_3);
            let mut bad = Builder::new(branch_id, 0, 0);
            bad.set_orchard_anchor(w.anchor).unwrap();
            bad.add_orchard_spend(&w.sk, w.note, w.path).unwrap();
            assert_eq!(
                bad.build(&Provers::new().orchard(&wrong), 500_000, &random(8)),
                Err(Error::Orchard(BuildError::WrongProvingKey))
            );
        }

        let start = std::time::Instant::now();
        let tx = builder
            .build(&Provers::new().orchard(&pk), 15_000, &random(7))
            .unwrap();
        std::eprintln!("{name}: built in {:?}", start.elapsed());
        dump(name, &tx, &coins);
        dump_fvks(name, &[&w.fvk, &other.fvk]);
        assert_eq!(tx_format(&tx.raw).unwrap().tx_version(), Some(tx_version));

        let sighash = verify_transparent(&tx, &coins, 1);
        let found = verify_orchard(
            &tx.raw,
            1,
            1,
            &sighash,
            version,
            balance,
            &[&w.fvk, &other.fvk],
        );
        assert_eq!(found, shielded);
        let mut ins = [ZcashTxIn::default(); 1];
        let mut outs = [ZcashTxOut::default(); 1];
        let parsed = ZcashTx::parse_into(&tx.raw, &mut ins, &mut outs).unwrap();
        assert!(parsed.sapling.is_empty());
        assert_eq!(parsed.orchard_bundle().unwrap().unwrap().action_count(), 2);
        assert_eq!(parsed.conventional_fee(), Ok(15_000));
        assert_eq!(parsed.outputs[0].amount, transparent);
    }

    #[test]
    #[ignore = "slow in the test profile"]
    fn orchard_transaction_nu5() {
        orchard_transaction(branch::NU5, "orchard_nu5");
    }

    #[test]
    #[ignore = "slow in the test profile"]
    fn orchard_transaction_nu6_2() {
        orchard_transaction(branch::NU6_2, "orchard_nu6_2");
    }

    #[test]
    #[ignore = "slow in the test profile"]
    fn orchard_transaction_nu6_3() {
        orchard_transaction(branch::NU6_3, "orchard_nu6_3");
    }

    /// Under NU7 as under NU6.3: a version 6 transaction.
    #[test]
    #[ignore = "slow in the test profile"]
    fn orchard_transaction_nu7() {
        orchard_transaction(branch::NU7, "orchard_nu7");
    }

    /// Version 5 stays valid under NU6.3 and NU7, and can be asked for.
    #[test]
    #[ignore = "slow in the test profile"]
    fn orchard_transaction_v5_from_nu6_3() {
        orchard_transaction_as(branch::NU6_3, Some(TxVersion::V5), "orchard_nu6_3_v5");
        orchard_transaction_as(branch::NU7, Some(TxVersion::V5), "orchard_nu7_v5");
    }

    /// The version a transaction of the test is expected in.
    fn tx_version_of(branch_id: u32, chosen: TxVersion) -> TxVersion {
        match (branch_id, chosen) {
            (branch::NU6_3 | branch::NU7, TxVersion::V5) => TxVersion::V5,
            (branch::NU6_3 | branch::NU7, TxVersion::V6) => TxVersion::V6,
            _ => TxVersion::V5,
        }
    }

    /// An Ironwood wallet: as [`wallet`], its note being one of the
    /// Ironwood pool, in the tree of that pool.
    pub(super) fn ironwood_wallet(seed: u8, value: u64) -> Wallet {
        use crate::orchard::note::NoteVersion;
        let sk = SpendingKey::from_bytes(random(seed)).unwrap();
        let fvk = sk.to_fvk();
        let address = fvk.address_at(0u32, Scope::External);
        let rho = Nullifier::from_fp(Fp::from_uniform_bytes(&random(seed.wrapping_add(110))));
        let note = Note::from_parts_versioned(
            address,
            value,
            rho,
            random(seed.wrapping_add(111)),
            NoteVersion::V3,
        )
        .unwrap();
        let leaves = [
            Fp::from_u64(55),
            note.cmx().to_fp(),
            Fp::from_u64(66),
            Fp::from_u64(77),
            Fp::from_u64(88),
        ];
        Wallet {
            sk,
            fvk,
            address,
            note,
            path: tree::witness(&leaves, 1).unwrap(),
            anchor: tree::root(&leaves).unwrap(),
        }
    }

    /// Verifies the Ironwood bundle of a serialized transaction in full,
    /// and returns the total value of the notes `fvks` can read in it.
    pub(super) fn verify_ironwood(
        raw: &[u8],
        n_inputs: usize,
        n_outputs: usize,
        sighash: &[u8; 32],
        actions: usize,
        value_balance: i64,
        fvks: &[&FullViewingKey],
    ) -> u64 {
        use crate::orchard::bundle::Flags;
        use crate::orchard::note::NoteVersion;
        use crate::orchard::note_encryption::try_note_decryption_versioned;
        let mut inputs = vec![ZcashTxIn::default(); n_inputs];
        let mut outputs = vec![ZcashTxOut::default(); n_outputs];
        let parsed = ZcashTx::parse_into(raw, &mut inputs, &mut outputs).unwrap();
        assert_eq!(parsed.version, TxVersion::V6);
        let bundle = parsed.ironwood_bundle().unwrap().unwrap();
        assert_eq!(bundle.action_count(), actions);
        assert_eq!(bundle.flags(), Flags::IRONWOOD_ENABLED);
        assert_eq!(bundle.value_balance(), value_balance);
        assert_eq!(bundle.verify_signatures(sighash), Ok(()));
        assert!(bundle.verify_signatures(&[0x55; 32]).is_err());
        for vk in VerifyingKey::embedded_all() {
            assert_eq!(
                bundle.verify_proof(&vk).is_ok(),
                vk.version() == CircuitVersion::PostNu6_3
            );
        }
        // read as an Orchard bundle (restricted), the proof is not valid
        let mut bytes = parsed.ironwood.to_vec();
        let flags = 1 + actions * crate::orchard::bundle::ACTION_SIZE;
        assert_eq!(bytes[flags], 0b111);
        bytes[flags] = 0b011;
        let restricted = crate::orchard::bundle::BundleRef::parse(&bytes)
            .unwrap()
            .unwrap();
        let vk = VerifyingKey::embedded(CircuitVersion::PostNu6_3);
        assert!(restricted.verify_proof(&vk).is_err());

        let mut found = 0;
        for action in bundle.actions() {
            for fvk in fvks {
                let ivk = fvk.to_ivk(Scope::External);
                let output = action.output();
                // the notes are of the Ironwood version, and of no other
                assert_eq!(
                    try_note_decryption(&ivk, &output, &action.enc_ciphertext),
                    None
                );
                if let Some((note, _)) = try_note_decryption_versioned(
                    NoteVersion::V3,
                    &ivk,
                    &output,
                    &action.enc_ciphertext,
                ) {
                    assert_eq!(note.version(), NoteVersion::V3);
                    found += note.value();
                }
            }
        }
        found
    }

    #[test]
    fn ironwood_checks() {
        let w = ironwood_wallet(1, 500_000);
        let other = wallet(2, 0);
        let orchard_note = wallet(1, 500_000);

        let mut builder = Builder::new(branch::NU7, 0, 0);
        assert_eq!(builder.tx_version(), TxVersion::V6);
        assert_eq!(
            builder.orchard_circuit_version(),
            Some(CircuitVersion::PostNu6_3)
        );
        // a bundle needs its anchor: that of the Ironwood tree
        assert_eq!(
            builder.add_ironwood_spend(&w.sk, w.note, w.path),
            Err(Error::MissingAnchor)
        );
        assert_eq!(
            builder.add_ironwood_output(None, other.address, 1, NO_MEMO),
            Err(Error::MissingAnchor)
        );
        builder.set_orchard_anchor(w.anchor).unwrap();
        assert_eq!(
            builder.add_ironwood_output(None, other.address, 1, NO_MEMO),
            Err(Error::MissingAnchor)
        );
        builder.set_ironwood_anchor(other.anchor).unwrap();
        assert_eq!(
            builder.add_ironwood_spend(&w.sk, w.note, w.path),
            Err(Error::Orchard(BuildError::AnchorMismatch))
        );
        builder.set_ironwood_anchor(w.anchor).unwrap();
        assert_eq!(
            builder.add_ironwood_spend(&other.sk, w.note, w.path),
            Err(Error::Orchard(BuildError::WrongKey))
        );
        assert_eq!(
            builder.add_ironwood_output(None, other.address, MAX_MONEY + 1, NO_MEMO),
            Err(Error::ValueOutOfRange)
        );
        // each pool has its notes
        assert_eq!(
            builder.add_ironwood_spend(&orchard_note.sk, orchard_note.note, orchard_note.path),
            Err(Error::Orchard(BuildError::WrongNoteVersion))
        );
        assert_eq!(
            builder.add_orchard_spend(&w.sk, w.note, w.path),
            Err(Error::Orchard(BuildError::WrongNoteVersion))
        );
        assert_eq!(builder.logical_actions(), 0);
        assert_eq!(builder.ironwood_balance(), Ok(0));

        builder.add_ironwood_spend(&w.sk, w.note, w.path).unwrap();
        assert_eq!(
            builder.set_ironwood_anchor(w.anchor),
            Err(Error::AlreadyStarted)
        );
        assert_eq!(builder.ironwood_balance(), Ok(500_000));
        assert_eq!(builder.orchard_balance(), Ok(0));
        assert_eq!(builder.fee(), Ok(500_000));
        assert_eq!(builder.logical_actions(), 2);
        // outputs go to any address
        for _ in 0..3 {
            builder
                .add_ironwood_output(None, other.address, 150_000, NO_MEMO)
                .unwrap();
        }
        assert_eq!(builder.ironwood_balance(), Ok(50_000));
        assert_eq!(builder.logical_actions(), 3);
        assert_eq!(builder.conventional_fee(), 15_000);
        // the Orchard actions count with them
        let ow = wallet(3, 70_000);
        builder.set_orchard_anchor(ow.anchor).unwrap();
        builder.add_orchard_spend(&ow.sk, ow.note, ow.path).unwrap();
        assert_eq!(builder.logical_actions(), 5);
        assert_eq!(builder.fee(), Ok(120_000));
        assert_eq!(
            builder.build(&Provers::new(), 120_000, &random(3)),
            Err(Error::MissingProvingKey)
        );

        // Ironwood parts need version 6, which needs NU6.3
        let ironwood_in = |branch_id: u32, version: Option<TxVersion>| {
            let mut builder = Builder::new(branch_id, 0, 0);
            if let Some(version) = version {
                builder.set_tx_version(version);
            }
            builder.set_ironwood_anchor(w.anchor).unwrap();
            builder.add_ironwood_spend(&w.sk, w.note, w.path).unwrap();
            builder.build(&Provers::new(), 500_000, &random(3))
        };
        assert_eq!(
            ironwood_in(branch::NU7, Some(TxVersion::V5)),
            Err(Error::IronwoodNeedsV6)
        );
        assert_eq!(
            ironwood_in(branch::NU6_3, Some(TxVersion::V5)),
            Err(Error::IronwoodNeedsV6)
        );
        assert_eq!(
            ironwood_in(branch::NU6_2, None),
            Err(Error::IronwoodNeedsV6)
        );
        assert_eq!(
            ironwood_in(branch::NU6_2, Some(TxVersion::V6)),
            Err(Error::VersionNotActive)
        );
        assert_eq!(
            ironwood_in(branch::NU6_3, None),
            Err(Error::MissingProvingKey)
        );

        // from NU6.3 the Orchard pool takes no value in, in any version
        let orchard_in = |branch_id: u32, version: TxVersion, output: u64| {
            let w = wallet(1, 500_000);
            let k = key(1);
            let script = p2pkh(&k);
            let mut builder = Builder::new(branch_id, 0, 0);
            builder.set_tx_version(version);
            let prevout = ZcashTxOut {
                amount: 100_000,
                script: &script,
            };
            builder
                .add_transparent_input(&k, [1; 32], 0, u32::MAX, prevout)
                .unwrap();
            builder.set_orchard_anchor(w.anchor).unwrap();
            builder.add_orchard_spend(&w.sk, w.note, w.path).unwrap();
            builder
                .add_orchard_output(None, w.address, output, NO_MEMO)
                .unwrap();
            let fee = 600_000 - output;
            builder.build(&Provers::new(), fee, &random(3))
        };
        for version in [TxVersion::V5, TxVersion::V6] {
            for branch_id in [branch::NU6_3, branch::NU7] {
                assert_eq!(
                    orchard_in(branch_id, version, 500_001),
                    Err(Error::OrchardPoolClosed)
                );
                assert_eq!(
                    orchard_in(branch_id, version, 500_000),
                    Err(Error::MissingProvingKey)
                );
            }
        }
        assert_eq!(
            orchard_in(branch::NU6_2, TxVersion::V5, 500_001),
            Err(Error::MissingProvingKey)
        );
    }

    /// A version 6 transaction between the transparent and the Ironwood
    /// pools: one transparent coin and one Ironwood note in, one
    /// transparent output and two Ironwood notes out, to another address
    /// and back.
    fn ironwood_transaction(branch_id: u32, name: &str) {
        let w = ironwood_wallet(1, 500_000);
        let other = wallet(2, 0);
        let k = key(4);
        let coins = [Coin {
            amount: 100_000,
            script: p2pkh(&k),
        }];
        let to = p2pkh(&key(5));

        let mut builder = Builder::new(branch_id, 3_600_000, 0);
        assert_eq!(builder.tx_version(), TxVersion::V6);
        let prevout = ZcashTxOut {
            amount: coins[0].amount,
            script: &coins[0].script,
        };
        builder
            .add_transparent_input(&k, [0x51; 32], 2, u32::MAX, prevout)
            .unwrap();
        builder.set_ironwood_anchor(w.anchor).unwrap();
        builder.add_ironwood_spend(&w.sk, w.note, w.path).unwrap();
        let ovk = Some(w.fvk.to_ovk(Scope::External));
        builder
            .add_ironwood_output(ovk, other.address, 450_000, NO_MEMO)
            .unwrap();
        builder
            .add_ironwood_output(ovk, w.address, 100_000, NO_MEMO)
            .unwrap();
        builder.add_transparent_output(35_000, &to).unwrap();
        assert_eq!(builder.ironwood_balance(), Ok(-50_000));
        assert_eq!(builder.orchard_balance(), Ok(0));
        // one transparent action and two Ironwood ones
        assert_eq!(builder.conventional_fee(), 15_000);
        assert_eq!(builder.fee(), Ok(15_000));

        // the key of another circuit version is refused
        let wrong = ProvingKey::build(CircuitVersion::FixedPostNu6_2);
        let mut bad = Builder::new(branch_id, 0, 0);
        bad.set_ironwood_anchor(w.anchor).unwrap();
        bad.add_ironwood_spend(&w.sk, w.note, w.path).unwrap();
        assert_eq!(
            bad.build(&Provers::new().orchard(&wrong), 500_000, &random(8)),
            Err(Error::Orchard(BuildError::WrongProvingKey))
        );

        let pk = ProvingKey::build(CircuitVersion::PostNu6_3);
        let start = std::time::Instant::now();
        let tx = builder
            .build(&Provers::new().orchard(&pk), 15_000, &random(7))
            .unwrap();
        std::eprintln!("{name}: built in {:?}", start.elapsed());
        dump(name, &tx, &coins);
        dump_fvks(name, &[&w.fvk, &other.fvk]);
        assert_eq!(tx_format(&tx.raw), Ok(TxFormat::V6));

        let sighash = verify_transparent(&tx, &coins, 1);
        let found = verify_ironwood(&tx.raw, 1, 1, &sighash, 2, -50_000, &[&w.fvk, &other.fvk]);
        assert_eq!(found, 550_000);
        let mut ins = [ZcashTxIn::default(); 1];
        let mut outs = [ZcashTxOut::default(); 1];
        let parsed = ZcashTx::parse_into(&tx.raw, &mut ins, &mut outs).unwrap();
        assert!(parsed.sapling.is_empty() && parsed.orchard.is_empty());
        assert_eq!(parsed.orchard_bundle(), Ok(None));
        assert_eq!(parsed.conventional_fee(), Ok(15_000));
        // the nullifier of the note spent is revealed
        let nullifier = w.note.nullifier(&w.fvk).to_bytes();
        let bundle = parsed.ironwood_bundle().unwrap().unwrap();
        assert!(bundle.actions().any(|a| a.nullifier == nullifier));
    }

    #[test]
    #[ignore = "slow in the test profile"]
    fn ironwood_transaction_nu6_3() {
        ironwood_transaction(branch::NU6_3, "ironwood_nu6_3");
    }

    #[test]
    #[ignore = "slow in the test profile"]
    fn ironwood_transaction_nu7() {
        ironwood_transaction(branch::NU7, "ironwood_nu7");
    }
}

#[cfg(feature = "zcash-sapling-prover")]
mod sapling {
    use super::*;
    use crate::sapling::Error as SaplingError;
    use crate::sapling::builder::Error as BuildError;
    use crate::sapling::field::Fq;
    use crate::sapling::keys::PaymentAddress;
    use crate::sapling::note::{Note, Rseed};
    use crate::sapling::tree::{Frontier, MerklePath};
    use crate::sapling::zip32::ExtendedSpendingKey;

    /// A Sapling wallet with one note of `value` in a tree with other
    /// commitments.
    pub(super) struct Wallet {
        pub key: ExtendedSpendingKey,
        pub address: PaymentAddress,
        pub note: Note,
        pub path: MerklePath,
        pub anchor: [u8; 32],
    }

    pub(super) fn wallet(seed: u8, value: u64) -> Wallet {
        let key = ExtendedSpendingKey::from_seed_account(&[seed; 32], 133, 0).unwrap();
        let (_, address) = key.default_address().unwrap();
        let note = Note::new(address, value, Rseed::AfterZip212(random(seed)));
        let mut frontier: Frontier = Frontier::new();
        for i in 0..3u64 {
            frontier.append(&Fq::from_u64(1000 + i).to_bytes()).unwrap();
        }
        let mut witness = frontier.append_witnessed(&note.cmu()).unwrap();
        for i in 0..2u64 {
            witness.append(&Fq::from_u64(2000 + i).to_bytes()).unwrap();
        }
        Wallet {
            key,
            address,
            note,
            path: witness.path(),
            anchor: witness.root(),
        }
    }

    #[test]
    fn sapling_checks() {
        let w = wallet(1, 200_000);
        let expsk = w.key.expanded_spending_key();

        let mut builder = Builder::new(branch::NU6_2, 0, 0);
        assert_eq!(
            builder.add_sapling_spend(expsk, &w.note, &w.path, &random(1)),
            Err(Error::MissingAnchor)
        );
        // a failed spend starts nothing: the anchor can still be set
        builder.set_sapling_anchor([0; 32]).unwrap();
        assert_eq!(
            builder.add_sapling_spend(expsk, &w.note, &w.path, &random(1)),
            Err(Error::Sapling(BuildError::Sapling(
                SaplingError::InvalidPath
            )))
        );
        builder.set_sapling_anchor(w.anchor).unwrap();
        builder
            .add_sapling_spend(expsk, &w.note, &w.path, &random(1))
            .unwrap();
        assert_eq!(
            builder.set_sapling_anchor(w.anchor),
            Err(Error::AlreadyStarted)
        );
        assert_eq!(
            builder.add_sapling_spend(expsk, &w.note, &w.path, &random(2)),
            Err(Error::Sapling(BuildError::DuplicateSpend))
        );

        // value balances: positive out of the pool, negative into it
        assert_eq!(builder.sapling_balance(), 200_000);
        assert_eq!(builder.fee(), Ok(200_000));
        assert_eq!(builder.logical_actions(), 1);
        let note = builder
            .add_sapling_output(None, &w.address, 150_000, None, &random(3))
            .unwrap();
        assert_eq!(note.value(), 150_000);
        builder
            .add_sapling_output(None, &w.address, 60_000, None, &random(4))
            .unwrap();
        assert_eq!(builder.sapling_balance(), -10_000);
        assert_eq!(builder.fee(), Err(Error::InsufficientFunds));
        assert_eq!(builder.logical_actions(), 2);
        let k = key(1);
        let script = p2pkh(&k);
        let prevout = ZcashTxOut {
            amount: 25_000,
            script: &script,
        };
        builder
            .add_transparent_input(&k, [1; 32], 0, u32::MAX, prevout)
            .unwrap();
        assert_eq!(builder.fee(), Ok(15_000));
        assert_eq!(builder.conventional_fee(), 15_000);
        // proofs need parameters
        assert_eq!(
            builder.build(&Provers::new(), 15_000, &random(5)),
            Err(Error::Sapling(BuildError::MissingParameters))
        );

        // outputs alone need no anchor, which then comes too late
        let mut builder = Builder::new(branch::NU6_2, 0, 0);
        builder
            .add_sapling_output(None, &w.address, 1, None, &random(3))
            .unwrap();
        assert_eq!(
            builder.set_sapling_anchor(w.anchor),
            Err(Error::AlreadyStarted)
        );
        assert_eq!(builder.sapling_balance(), -1);
    }

    /// Verifies the Sapling bundle of a serialized transaction in full.
    #[cfg(feature = "std")]
    pub(super) fn verify_sapling(
        raw: &[u8],
        n_inputs: usize,
        n_outputs: usize,
        sighash: &[u8; 32],
        value_balance: i64,
    ) {
        use crate::sapling::prover::{OutputVerifyingKey, SpendVerifyingKey, verify_bundle_proofs};
        let mut inputs = vec![ZcashTxIn::default(); n_inputs];
        let mut outputs = vec![ZcashTxOut::default(); n_outputs];
        let parsed = ZcashTx::parse_into(raw, &mut inputs, &mut outputs).unwrap();
        let bundle = parsed.sapling_bundle().unwrap();
        assert_eq!(bundle.value_balance(), value_balance);
        bundle.verify(sighash).unwrap();
        assert!(bundle.verify(&[0x55; 32]).is_err());
        verify_bundle_proofs(
            &bundle,
            &SpendVerifyingKey::mainnet(),
            &OutputVerifyingKey::mainnet(),
        )
        .unwrap();
    }

    /// A transaction between the transparent and the Sapling pools.
    #[cfg(feature = "std")]
    #[test]
    #[ignore = "needs the Sapling parameters"]
    fn sapling_transaction() {
        use crate::sapling::note_encryption::{Zip212Enforcement, try_note_decryption};
        let (spend_params, output_params) = crate::sapling::prover::tests::load_params();
        let provers = Provers::new()
            .sapling_spend(&spend_params)
            .sapling_output(&output_params);
        let w = wallet(1, 200_000);
        let expsk = w.key.expanded_spending_key();
        let recipient = wallet(2, 0);
        let k = key(4);
        let coins = [Coin {
            amount: 100_000,
            script: p2pkh(&k),
        }];
        let to = p2pkh(&key(5));

        let mut builder = Builder::new(branch::NU6_1, 3_300_000, 0);
        let prevout = ZcashTxOut {
            amount: coins[0].amount,
            script: &coins[0].script,
        };
        builder
            .add_transparent_input(&k, [0x31; 32], 0, u32::MAX, prevout)
            .unwrap();
        builder.set_sapling_anchor(w.anchor).unwrap();
        builder
            .add_sapling_spend(expsk, &w.note, &w.path, &random(10))
            .unwrap();
        let sent = builder
            .add_sapling_output(
                Some(expsk.ovk()),
                &recipient.address,
                250_000,
                None,
                &random(11),
            )
            .unwrap();
        builder.add_transparent_output(40_000, &to).unwrap();
        assert_eq!(builder.sapling_balance(), -50_000);
        assert_eq!(builder.conventional_fee(), 10_000);
        let tx = builder.build(&provers, 10_000, &random(12)).unwrap();
        dump("sapling", &tx, &coins);

        let sighash = verify_transparent(&tx, &coins, 1);
        verify_sapling(&tx.raw, 1, 1, &sighash, -50_000);
        let mut ins = [ZcashTxIn::default(); 1];
        let mut outs = [ZcashTxOut::default(); 1];
        let parsed = ZcashTx::parse_into(&tx.raw, &mut ins, &mut outs).unwrap();
        assert!(parsed.orchard.is_empty());
        assert_eq!(parsed.conventional_fee(), Ok(10_000));
        let bundle = parsed.sapling_bundle().unwrap();
        assert_eq!((bundle.n_spends(), bundle.n_outputs()), (1, 1));
        assert_eq!(bundle.anchor(), Some(&w.anchor));
        let out = bundle.output(0).unwrap();
        let ivk = recipient
            .key
            .expanded_spending_key()
            .proof_generation_key()
            .ivk();
        let (note, _) = try_note_decryption(
            &ivk,
            out.ephemeral_key,
            out.cmu,
            out.enc_ciphertext,
            Zip212Enforcement::On,
        )
        .unwrap();
        assert_eq!(note, sent);
    }
}

/// The whole of a version 6 transaction, under NU7: transparent coins, a
/// Sapling note, an Orchard note and an Ironwood note in; a transparent
/// output, a Sapling note, an Orchard note (back to its address) and two
/// Ironwood notes out. Built, parsed back, and every proof and signature
/// verified.
#[cfg(all(
    feature = "std",
    feature = "zcash-sapling-prover",
    feature = "zcash-orchard-prover"
))]
#[test]
#[ignore = "needs the Sapling parameters"]
fn full_transaction_v6() {
    use crate::orchard::builder::NO_MEMO;
    use crate::orchard::circuit::ProvingKey;
    use crate::orchard::keys::Scope;

    let branch_id = branch::NU7;
    let version = orchard_circuit_version(branch_id).unwrap();
    assert_eq!(version, CircuitVersion::PostNu6_3);
    let (spend_params, output_params) = crate::sapling::prover::tests::load_params();
    let pk = ProvingKey::build(version);
    let provers = Provers::new()
        .sapling_spend(&spend_params)
        .sapling_output(&output_params)
        .orchard(&pk);

    let keys = [key(4), key(6)];
    let coins = [
        Coin {
            amount: 100_000,
            script: p2pkh(&keys[0]),
        },
        Coin {
            amount: 30_000,
            script: p2pkh(&keys[1]),
        },
    ];
    let to = p2pkh(&key(5));
    let sw = sapling::wallet(1, 200_000);
    let s_recipient = sapling::wallet(2, 0);
    let expsk = sw.key.expanded_spending_key();
    let ow = orchard::wallet(1, 500_000);
    let iw = orchard::ironwood_wallet(3, 300_000);
    let i_recipient = orchard::wallet(2, 0);

    let mut builder = Builder::new(branch_id, 3_600_000, 0);
    assert_eq!(builder.tx_version(), TxVersion::V6);
    for (i, (key, coin)) in keys.iter().zip(&coins).enumerate() {
        let prevout = ZcashTxOut {
            amount: coin.amount,
            script: &coin.script,
        };
        builder
            .add_transparent_input(key, [0x61 + i as u8; 32], i as u32, u32::MAX, prevout)
            .unwrap();
    }
    builder.add_transparent_output(40_000, &to).unwrap();
    builder.set_sapling_anchor(sw.anchor).unwrap();
    builder
        .add_sapling_spend(expsk, &sw.note, &sw.path, &random(30))
        .unwrap();
    builder
        .add_sapling_output(
            Some(expsk.ovk()),
            &s_recipient.address,
            150_000,
            None,
            &random(31),
        )
        .unwrap();
    // the Orchard pool only empties: what stays goes back to its address
    builder.set_orchard_anchor(ow.anchor).unwrap();
    builder.add_orchard_spend(&ow.sk, ow.note, ow.path).unwrap();
    builder
        .add_orchard_output(
            Some(ow.fvk.to_ovk(Scope::External)),
            ow.address,
            100_000,
            NO_MEMO,
        )
        .unwrap();
    // and the rest moves to the Ironwood pool
    builder.set_ironwood_anchor(iw.anchor).unwrap();
    builder
        .add_ironwood_spend(&iw.sk, iw.note, iw.path)
        .unwrap();
    let ovk = Some(iw.fvk.to_ovk(Scope::External));
    builder
        .add_ironwood_output(ovk, i_recipient.address, 700_000, NO_MEMO)
        .unwrap();
    builder
        .add_ironwood_output(ovk, iw.address, 105_000, NO_MEMO)
        .unwrap();

    // the four pools: 90 000 out of the transparent one, 50 000 out of
    // Sapling, 400 000 out of Orchard, 505 000 into Ironwood, and the
    // rest is the fee
    assert_eq!(builder.transparent_balance(), 90_000);
    assert_eq!(builder.sapling_balance(), 50_000);
    assert_eq!(builder.orchard_balance(), Ok(400_000));
    assert_eq!(builder.ironwood_balance(), Ok(-505_000));
    assert_eq!(builder.fee(), Ok(35_000));
    // two transparent inputs, one Sapling spend, two Orchard actions and
    // two Ironwood ones
    assert_eq!(builder.logical_actions(), 7);
    assert_eq!(builder.conventional_fee(), 35_000);

    let start = std::time::Instant::now();
    let tx = builder.build(&provers, 35_000, &random(32)).unwrap();
    std::eprintln!("full version 6 transaction built in {:?}", start.elapsed());
    dump("full_v6", &tx, &coins);
    dump_fvks("full_v6", &[&ow.fvk, &iw.fvk, &i_recipient.fvk]);
    assert_eq!(tx_format(&tx.raw), Ok(TxFormat::V6));

    // every signature, every proof, and the digests they are over
    let sighash = verify_transparent(&tx, &coins, 1);
    sapling::verify_sapling(&tx.raw, 2, 1, &sighash, 50_000);
    let found = orchard::verify_orchard(
        &tx.raw,
        2,
        1,
        &sighash,
        version,
        400_000,
        &[&ow.fvk, &iw.fvk, &i_recipient.fvk],
    );
    assert_eq!(found, 100_000);
    let found = orchard::verify_ironwood(
        &tx.raw,
        2,
        1,
        &sighash,
        2,
        -505_000,
        &[&ow.fvk, &iw.fvk, &i_recipient.fvk],
    );
    assert_eq!(found, 805_000);

    let mut ins = [ZcashTxIn::default(); 2];
    let mut outs = [ZcashTxOut::default(); 1];
    let parsed = ZcashTx::parse_into(&tx.raw, &mut ins, &mut outs).unwrap();
    assert_eq!(parsed.version, TxVersion::V6);
    assert_eq!(parsed.consensus_branch_id, branch_id);
    assert_eq!(parsed.conventional_fee(), Ok(35_000));
    let prevouts: Vec<ZcashTxOut<'_>> = coins
        .iter()
        .map(|coin| ZcashTxOut {
            amount: coin.amount,
            script: &coin.script,
        })
        .collect();
    // the signatures are in neither digest, and in version 6 neither are
    // the anchors: another anchor is the same transaction, as far as its
    // id and its signatures go
    let reanchored = |bundle: &[u8], at: usize| {
        let mut bytes = bundle.to_vec();
        bytes[at] ^= 1;
        bytes
    };
    let sapling = reanchored(parsed.sapling, 1 + 96 + 1 + 756 + 8);
    let orchard = reanchored(parsed.orchard, 1 + 2 * 820 + 9);
    let ironwood = reanchored(parsed.ironwood, 1 + 2 * 820 + 9);
    let other = ZcashTx {
        sapling: &sapling,
        orchard: &orchard,
        ironwood: &ironwood,
        ..parsed
    };
    assert_eq!(other.txid().unwrap(), tx.txid);
    assert_eq!(
        other.sighash(None, SIGHASH_ALL, &prevouts).unwrap(),
        sighash
    );
    assert_ne!(other.auth_digest().unwrap(), parsed.auth_digest().unwrap());
    assert_eq!(other.sapling_bundle().unwrap().verify(&sighash), Ok(()));
    let vk = crate::orchard::circuit::VerifyingKey::embedded(version);
    for bundle in [other.orchard_bundle(), other.ironwood_bundle()] {
        let bundle = bundle.unwrap().unwrap();
        assert_eq!(bundle.verify_signatures(&sighash), Ok(()));
        // (the proofs are for the anchors they were made with)
        assert!(bundle.verify_proof(&vk).is_err());
    }
}

/// The whole of it: a transparent coin, a Sapling note and an Orchard
/// note in; a transparent output, a Sapling note and an Orchard note out.
/// Built, parsed back, and every proof and signature verified.
#[cfg(all(
    feature = "std",
    feature = "zcash-sapling-prover",
    feature = "zcash-orchard-prover"
))]
#[test]
#[ignore = "needs the Sapling parameters"]
fn full_transaction() {
    use crate::orchard::builder::NO_MEMO;
    use crate::orchard::circuit::ProvingKey;
    use crate::orchard::keys::Scope;
    use crate::sapling::note_encryption::{Zip212Enforcement, try_note_decryption};

    let branch_id = branch::NU6_2;
    let version = orchard_circuit_version(branch_id).unwrap();
    let (spend_params, output_params) = crate::sapling::prover::tests::load_params();
    let pk = ProvingKey::build(version);
    let provers = Provers::new()
        .sapling_spend(&spend_params)
        .sapling_output(&output_params)
        .orchard(&pk);

    let keys = [key(4), key(6)];
    let coins = [
        Coin {
            amount: 100_000,
            script: p2pkh(&keys[0]),
        },
        Coin {
            amount: 30_000,
            script: p2pkh(&keys[1]),
        },
    ];
    let to = p2pkh(&key(5));
    let sw = sapling::wallet(1, 200_000);
    let s_recipient = sapling::wallet(2, 0);
    let expsk = sw.key.expanded_spending_key();
    let ow = orchard::wallet(1, 500_000);
    let o_recipient = orchard::wallet(2, 0);

    let mut builder = Builder::new(branch_id, 3_400_000, 0);
    for (i, (key, coin)) in keys.iter().zip(&coins).enumerate() {
        let prevout = ZcashTxOut {
            amount: coin.amount,
            script: &coin.script,
        };
        builder
            .add_transparent_input(key, [0x41 + i as u8; 32], i as u32, u32::MAX, prevout)
            .unwrap();
    }
    builder.add_transparent_output(40_000, &to).unwrap();
    builder.set_sapling_anchor(sw.anchor).unwrap();
    builder
        .add_sapling_spend(expsk, &sw.note, &sw.path, &random(20))
        .unwrap();
    let mut memo = [0u8; 512];
    memo[..5].copy_from_slice(b"hello");
    let sent = builder
        .add_sapling_output(
            Some(expsk.ovk()),
            &s_recipient.address,
            150_000,
            Some(&memo),
            &random(21),
        )
        .unwrap();
    builder.set_orchard_anchor(ow.anchor).unwrap();
    builder.add_orchard_spend(&ow.sk, ow.note, ow.path).unwrap();
    builder
        .add_orchard_output(
            Some(ow.fvk.to_ovk(Scope::External)),
            o_recipient.address,
            615_000,
            NO_MEMO,
        )
        .unwrap();

    // the three pools: 90 000 out of the transparent one, 50 000 out of
    // Sapling, 115 000 into Orchard, and the rest is the fee
    assert_eq!(builder.transparent_balance(), 90_000);
    assert_eq!(builder.sapling_balance(), 50_000);
    assert_eq!(builder.orchard_balance(), Ok(-115_000));
    assert_eq!(builder.fee(), Ok(25_000));
    // two transparent inputs, one Sapling spend, two Orchard actions
    assert_eq!(builder.logical_actions(), 5);
    assert_eq!(builder.conventional_fee(), 25_000);

    let start = std::time::Instant::now();
    let tx = builder.build(&provers, 25_000, &random(22)).unwrap();
    std::eprintln!("full transaction built in {:?}", start.elapsed());
    dump("full", &tx, &coins);

    // every signature, every proof, and the digests they are over
    let sighash = verify_transparent(&tx, &coins, 1);
    sapling::verify_sapling(&tx.raw, 2, 1, &sighash, 50_000);
    let found = orchard::verify_orchard(
        &tx.raw,
        2,
        1,
        &sighash,
        version,
        -115_000,
        &[&ow.fvk, &o_recipient.fvk],
    );
    assert_eq!(found, 615_000);

    let mut ins = [ZcashTxIn::default(); 2];
    let mut outs = [ZcashTxOut::default(); 1];
    let parsed = ZcashTx::parse_into(&tx.raw, &mut ins, &mut outs).unwrap();
    assert_eq!(parsed.consensus_branch_id, branch_id);
    assert_eq!(parsed.expiry_height, 3_400_000);
    assert_eq!(parsed.conventional_fee(), Ok(25_000));
    // the signatures are in neither digest
    let prevouts: Vec<ZcashTxOut<'_>> = coins
        .iter()
        .map(|coin| ZcashTxOut {
            amount: coin.amount,
            script: &coin.script,
        })
        .collect();
    let mut stripped = parsed.sapling.to_vec();
    let n = stripped.len();
    stripped[n - 64..].fill(0);
    let unsigned = ZcashTx {
        sapling: &stripped,
        ..parsed
    };
    assert_eq!(unsigned.txid().unwrap(), tx.txid);
    assert_eq!(
        unsigned.sighash(None, SIGHASH_ALL, &prevouts).unwrap(),
        sighash
    );
    // but the bundle is not valid without them
    assert!(unsigned.sapling_bundle().unwrap().verify(&sighash).is_err());

    // the Sapling recipient reads its note
    let bundle = parsed.sapling_bundle().unwrap();
    assert_eq!((bundle.n_spends(), bundle.n_outputs()), (1, 1));
    let out = bundle.output(0).unwrap();
    let ivk = s_recipient
        .key
        .expanded_spending_key()
        .proof_generation_key()
        .ivk();
    let (note, got_memo) = try_note_decryption(
        &ivk,
        out.ephemeral_key,
        out.cmu,
        out.enc_ciphertext,
        Zip212Enforcement::On,
    )
    .unwrap();
    assert_eq!(note, sent);
    assert_eq!(got_memo, memo);
    // the nullifiers of the notes spent are revealed
    let nk = expsk.proof_generation_key().nk();
    assert_eq!(
        *bundle.spend(0).unwrap().nullifier,
        sw.note.nullifier(&nk, sw.path.position)
    );
    let actions = parsed.orchard_bundle().unwrap().unwrap();
    assert_eq!(actions.action_count(), 2);
    let nullifier = ow.note.nullifier(&ow.fvk).to_bytes();
    assert!(actions.actions().any(|a| a.nullifier == nullifier));
}
