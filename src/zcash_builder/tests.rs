//! The builder's checks, which run everywhere, and whole transactions
//! built, parsed back and verified in full, which are slow (ignored by
//! default: run them in release) and, for the Sapling parts, need the
//! parameter files (`ZCASH_PARAMS`, see `sapling/prover/tests.rs`).
//!
//! With `ZCASH_TX_DUMP` set to a directory, the transactions built are
//! written there (`<name>.hex`, with `<name>.prevouts` holding one
//! `amount:scriptPubKey` per transparent input and `<name>.txid`), to
//! check them with other implementations.

use super::*;
use crate::crypto::secp256k1::{SecpPublicKey, parse_der_signature};
use crate::pushbytes::parse_push_bytes;
use crate::zcashtx::branch;
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
        // NU7, Canopy, anything else
        assert_eq!(orchard_circuit_version(0x7719_0ad9), None);
        assert_eq!(orchard_circuit_version(0xe9ff_75a6), None);
        assert_eq!(orchard_circuit_version(0), None);
    }

    #[test]
    fn orchard_checks() {
        let w = wallet(1, 500_000);
        let other = wallet(2, 0);

        // an unknown branch needs its circuit version, a bundle its anchor
        let mut builder = Builder::new(0x7719_0ad9, 0, 0);
        assert_eq!(builder.orchard_circuit_version(), None);
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
