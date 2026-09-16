//! Bitcoin transactions: building, signing (legacy, segwit BIP-143, taproot
//! BIP-341/340), serialization and parsing. Port of `btctx.go` and
//! `btctx_p2tr.go`.

pub use crate::Error;

use crate::prelude::*;

#[cfg(feature = "std")]
use std::io::{self, Read};

use serde::de;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::address::parse_bitcoin_based_address;
use crate::btcamount::BtcAmount;
use crate::btcraw::{PrevOut, RawTx, RawTxIn, RawTxOut, SegwitV0Midstate, TaprootMidstate};
use crate::btcvarint::BtcVarInt;
use crate::crypto::SignerError;
use crate::crypto::secp256k1::DerSignature;
use crate::crypto::secp256k1::SecpPublicKey;
use crate::hash::{dsha256, hash160, sha256_once};
use crate::pubkey::PubKey;
use crate::pushbytes::push_bytes;
use crate::script::Script;

/// A signer capable of producing ECDSA and/or taproot signatures for a single
/// transaction input. Implemented by
/// [`crate::crypto::secp256k1::SecpPrivateKey`]; external signers (TSS, HSM,
/// MuSig2) can implement only [`Signer::sign_taproot`].
pub trait Signer {
    /// The public key used to derive scriptCode / witness pubkeys, if available.
    fn ecdsa_public_key(&self) -> Option<SecpPublicKey> {
        None
    }
    /// Produces a DER-encoded low-S ECDSA signature over the 32-byte digest.
    fn sign_ecdsa_der(&self, _digest: &[u8; 32]) -> Result<DerSignature, SignerError> {
        Err(SignerError)
    }
    /// Produces a 64-byte BIP-340 Schnorr signature over the 32-byte taproot
    /// sighash. For a raw key this applies the BIP-341 key-path tweak; external
    /// signers are expected to already hold the tweaked key.
    fn sign_taproot(&self, _sighash: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        Err(SignerError)
    }
}

impl Signer for crate::crypto::secp256k1::SecpPrivateKey {
    fn ecdsa_public_key(&self) -> Option<SecpPublicKey> {
        Some(self.public_key())
    }
    fn sign_ecdsa_der(&self, digest: &[u8; 32]) -> Result<DerSignature, SignerError> {
        Ok(self.sign_der(digest))
    }
    fn sign_taproot(&self, sighash: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        self.sign_taproot(sighash).map_err(|_| SignerError)
    }
}

/// A single transaction input.
#[derive(Debug, Clone, Default)]
pub struct BtcTxInput {
    /// Transaction id of the spent output, in display (big-endian) byte order.
    pub txid: [u8; 32],
    /// Index of the spent output.
    pub vout: u32,
    /// The scriptSig.
    pub script: Vec<u8>,
    /// The input sequence number.
    pub sequence: u32,
    /// The segwit witness stack.
    pub witnesses: Vec<Vec<u8>>,
}

/// A single transaction output.
#[derive(Debug, Clone, Default)]
pub struct BtcTxOutput {
    /// Output amount in satoshis.
    pub amount: BtcAmount,
    /// Output index (not serialized in the wire format).
    pub n: usize,
    /// The scriptPubKey.
    pub script: Vec<u8>,
}

/// A Bitcoin transaction.
#[derive(Debug, Clone, Default)]
pub struct BtcTx {
    /// Transaction version.
    pub version: u32,
    /// Inputs.
    pub inputs: Vec<BtcTxInput>,
    /// Outputs.
    pub outputs: Vec<BtcTxOutput>,
    /// Lock time.
    pub locktime: u32,
}

/// Signing parameters for a single transaction input.
pub struct BtcTxSign<'a> {
    /// The signer (required for signing; may be `None` for sighash-only use).
    pub key: Option<&'a dyn Signer>,
    /// Spend scheme, e.g. "p2pk", "p2wpkh", "p2wsh:p2pkh", "p2tr".
    pub scheme: String,
    /// Value of the input being spent (required for segwit and taproot).
    pub amount: BtcAmount,
    /// Sighash flag (0 defaults to SIGHASH_ALL for non-taproot).
    pub sighash: u32,
    /// scriptPubKey of the output being spent (required for taproot).
    pub prev_script: Vec<u8>,
}

impl<'a> BtcTxSign<'a> {
    /// Creates signing parameters with the given key and scheme.
    pub fn new(key: &'a dyn Signer, scheme: &str) -> Self {
        BtcTxSign {
            key: Some(key),
            scheme: scheme.to_string(),
            amount: BtcAmount(0),
            sighash: 0,
            prev_script: Vec::new(),
        }
    }
    /// Sets the input amount.
    pub fn amount(mut self, amount: u64) -> Self {
        self.amount = BtcAmount(amount);
        self
    }
    /// Sets the previous scriptPubKey (taproot).
    pub fn prev_script(mut self, script: Vec<u8>) -> Self {
        self.prev_script = script;
        self
    }
}

fn signer_pubkey_script(key: &dyn Signer, name: &str) -> Result<Vec<u8>, Error> {
    let pk = key.ecdsa_public_key().ok_or(Error::NoPublicKey)?;
    Script::new(PubKey::Secp256k1(pk)).generate(name)
}

impl BtcTx {
    /// Signs the transaction. Requires one signing entry per input.
    pub fn sign(&mut self, keys: &[BtcTxSign]) -> Result<(), Error> {
        if self.inputs.is_empty() || self.inputs.len() != keys.len() {
            return Err(Error::KeyCount);
        }

        let mut midstate: Option<SegwitV0Midstate> = None;
        let mut taproot_parts: Option<TaprootSighashParts> = None;

        for (n, k) in keys.iter().enumerate() {
            let mut sighash = k.sighash;
            if k.scheme != "p2tr" && sighash == 0 {
                sighash = 1; // SIGHASH_ALL
            }
            let key = k.key.ok_or(Error::MissingKey)?;

            match k.scheme.as_str() {
                "p2pk" => {
                    let script_code = signer_pubkey_script(key, "p2pk")?;
                    let digest = self.legacy_sighash(n, &script_code, sighash)?;
                    let mut sig: Vec<u8> = key.sign_ecdsa_der(&digest)?.into();
                    sig.push((sighash & 0xff) as u8);
                    self.inputs[n].script = push_bytes(&sig);
                }
                "p2pkh" | "p2pukh" => {
                    if sighash & 0x40 == 0x40 {
                        // bitcoin-cash forkid: same preimage as segwit
                        let mid = *midstate.get_or_insert_with(|| self.segwit_v0_midstate());
                        self.p2wpkh_sign(n, k, sighash, &mid)?;
                        continue;
                    }
                    let script_code = signer_pubkey_script(key, &k.scheme)?;
                    let digest = self.legacy_sighash(n, &script_code, sighash)?;
                    let mut sig: Vec<u8> = key.sign_ecdsa_der(&digest)?.into();
                    sig.push((sighash & 0xff) as u8);
                    let pubkey = if k.scheme == "p2pkh" {
                        signer_pubkey_script(key, "pubkey:comp")?
                    } else {
                        signer_pubkey_script(key, "pubkey:uncomp")?
                    };
                    let mut script = push_bytes(&sig);
                    script.extend_from_slice(&push_bytes(&pubkey));
                    self.inputs[n].script = script;
                }
                "p2wpkh" | "p2sh:p2wpkh" => {
                    let mid = *midstate.get_or_insert_with(|| self.segwit_v0_midstate());
                    self.p2wpkh_sign(n, k, sighash, &mid)?;
                }
                "p2wsh" | "p2wsh:p2pk" | "p2wsh:p2puk" | "p2wsh:p2pkh" | "p2wsh:p2pukh" => {
                    let mid = *midstate.get_or_insert_with(|| self.segwit_v0_midstate());
                    self.p2wsh_sign(n, k, sighash, &mid)?;
                }
                "p2tr" => {
                    if taproot_parts.is_none() {
                        taproot_parts = Some(self.taproot_sighash_parts_from_keys(keys)?);
                    }
                    let parts = taproot_parts.as_ref().unwrap();
                    self.p2tr_sign(n, k, parts)?;
                }
                _ => return Err(Error::UnsupportedScheme),
            }
        }
        Ok(())
    }

    fn p2wpkh_sign(
        &mut self,
        n: usize,
        k: &BtcTxSign,
        sighash: u32,
        mid: &SegwitV0Midstate,
    ) -> Result<(), Error> {
        let key = k.key.ok_or(Error::MissingKey)?;
        let pubkey = if k.scheme == "p2pukh" {
            signer_pubkey_script(key, "pubkey:uncomp")?
        } else {
            signer_pubkey_script(key, "pubkey:comp")?
        };
        let pk_hash = hash160(&pubkey);
        let script_code = p2pkh_script_code(&pk_hash);
        let digest = mid.sighash(&self.inputs[n].raw(), &script_code, k.amount.0, sighash);
        let mut sig: Vec<u8> = key.sign_ecdsa_der(&digest)?.into();
        sig.push((sighash & 0xff) as u8);

        match k.scheme.as_str() {
            "p2pkh" | "p2pukh" => {
                let mut script = push_bytes(&sig);
                script.extend_from_slice(&push_bytes(&pubkey));
                self.inputs[n].script = script;
            }
            "p2wpkh" => {
                self.inputs[n].witnesses = vec![sig, pubkey];
                self.inputs[n].script = Vec::new();
            }
            "p2sh:p2wpkh" => {
                self.inputs[n].witnesses = vec![sig, pubkey.clone()];
                let mut inner = vec![0u8];
                inner.extend_from_slice(&push_bytes(&pk_hash));
                self.inputs[n].script = push_bytes(&inner);
            }
            _ => {}
        }
        Ok(())
    }

    fn p2wsh_sign(
        &mut self,
        n: usize,
        k: &BtcTxSign,
        sighash: u32,
        mid: &SegwitV0Midstate,
    ) -> Result<(), Error> {
        let key = k.key.ok_or(Error::MissingKey)?;
        let (inner_scheme, witness_script): (&str, Vec<u8>) = if k.scheme == "p2wsh" {
            self.detect_p2wsh_inner(n, key)?
        } else {
            let inner = &k.scheme["p2wsh:".len()..];
            (inner, signer_pubkey_script(key, inner)?)
        };

        let digest = mid.sighash(&self.inputs[n].raw(), &witness_script, k.amount.0, sighash);
        let mut sig: Vec<u8> = key.sign_ecdsa_der(&digest)?.into();
        sig.push((sighash & 0xff) as u8);

        match inner_scheme {
            "p2pk" | "p2puk" => {
                self.inputs[n].witnesses = vec![sig, witness_script];
            }
            "p2pkh" => {
                let pubkey = signer_pubkey_script(key, "pubkey:comp")?;
                self.inputs[n].witnesses = vec![sig, pubkey, witness_script];
            }
            "p2pukh" => {
                let pubkey = signer_pubkey_script(key, "pubkey:uncomp")?;
                self.inputs[n].witnesses = vec![sig, pubkey, witness_script];
            }
            _ => return Err(Error::UnsupportedScheme),
        }
        self.inputs[n].script = Vec::new();
        Ok(())
    }

    fn detect_p2wsh_inner(
        &self,
        n: usize,
        key: &dyn Signer,
    ) -> Result<(&'static str, Vec<u8>), Error> {
        let candidates = ["p2pkh", "p2pk", "p2pukh", "p2puk"];
        let pk = key.ecdsa_public_key().ok_or(Error::NoPublicKey)?;
        let s = Script::new(PubKey::Secp256k1(pk));

        let sc = &self.inputs[n].script;
        let target_hash: Option<[u8; 32]> = if sc.len() == 34 && sc[0] == 0x00 && sc[1] == 0x20 {
            let mut h = [0u8; 32];
            h.copy_from_slice(&sc[2..34]);
            Some(h)
        } else {
            None
        };

        for inner in candidates {
            let ws = match s.generate(inner) {
                Ok(v) => v,
                Err(_) => continue,
            };
            match target_hash {
                Some(t) => {
                    if sha256_once(&ws) == t {
                        return Ok((inner, ws));
                    }
                }
                None => return Ok((inner, ws)),
            }
        }
        Err(Error::NoMatchingWitnessScript)
    }

    /// Runs `f` on a borrowed [`RawTx`] view of this transaction. Scripts and
    /// witnesses are left empty: the view only serves sighash computation.
    fn with_raw<R>(&self, f: impl FnOnce(&RawTx<'_>) -> R) -> R {
        let inputs: Vec<RawTxIn<'_>> = self.inputs.iter().map(BtcTxInput::raw).collect();
        let outputs: Vec<RawTxOut<'_>> = self
            .outputs
            .iter()
            .map(|o| RawTxOut {
                amount: o.amount.0,
                script: &o.script,
            })
            .collect();
        f(&RawTx {
            version: self.version,
            inputs: &inputs,
            outputs: &outputs,
            locktime: self.locktime,
        })
    }

    /// Creates a BIP-174 PSBT for this transaction, which must not carry any
    /// scriptSig or witness yet. Add UTXO and script information with the
    /// [`Psbt`](crate::psbt::Psbt) updater methods before signing.
    pub fn to_psbt(&self) -> Result<Vec<u8>, Error> {
        if self
            .inputs
            .iter()
            .any(|i| !i.script.is_empty() || !i.witnesses.is_empty())
        {
            return Err(Error::InvalidUnsignedTx);
        }
        self.with_raw(crate::psbt::Psbt::create_to_vec)
    }

    /// The BIP-143 hashes shared by every input.
    pub(crate) fn segwit_v0_midstate(&self) -> SegwitV0Midstate {
        self.with_raw(|raw| raw.segwit_v0_midstate())
    }

    /// Serializes the transaction (including witness data if present).
    pub fn bytes(&self) -> Vec<u8> {
        self.export_bytes(self.has_witness())
    }

    /// Alias for [`Self::bytes`], serializing the transaction to its wire form.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes()
    }

    /// Reports whether any input has witness data.
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|i| !i.witnesses.is_empty())
    }

    /// Removes all input scripts and witnesses (used during signing).
    pub fn clear_inputs(&mut self) {
        for inp in &mut self.inputs {
            inp.script.clear();
            inp.witnesses.clear();
        }
    }

    /// Adds an output for the given address, auto-detecting the network.
    pub fn add_output(&mut self, address: &str, amount: u64) -> Result<(), Error> {
        self.add_net_output("auto", address, amount)
    }

    /// Adds an output for the given address parsed for `network`.
    pub fn add_net_output(
        &mut self,
        network: &str,
        address: &str,
        amount: u64,
    ) -> Result<(), Error> {
        let addr = parse_bitcoin_based_address(network, address)?;
        let n = self.outputs.len();
        self.outputs.push(BtcTxOutput {
            amount: BtcAmount(amount),
            n,
            script: addr.bytes().to_vec(),
        });
        Ok(())
    }

    fn export_bytes(&self, wit: bool) -> Vec<u8> {
        let mut buf = self.version.to_le_bytes().to_vec();
        if wit {
            buf.push(0);
            buf.push(1);
        }
        buf.extend_from_slice(&BtcVarInt(self.inputs.len() as u64).bytes());
        for inp in &self.inputs {
            buf.extend_from_slice(&inp.bytes());
        }
        buf.extend_from_slice(&BtcVarInt(self.outputs.len() as u64).bytes());
        for o in &self.outputs {
            buf.extend_from_slice(&o.bytes());
        }
        if wit {
            for inp in &self.inputs {
                buf.extend_from_slice(&BtcVarInt(inp.witnesses.len() as u64).bytes());
                for w in &inp.witnesses {
                    buf.extend_from_slice(&BtcVarInt(w.len() as u64).bytes());
                    buf.extend_from_slice(w);
                }
            }
        }
        buf.extend_from_slice(&self.locktime.to_le_bytes());
        buf
    }

    /// Computes the transaction id (reversed double-SHA-256).
    pub fn hash(&self) -> [u8; 32] {
        let mut h = dsha256(&self.export_bytes(false));
        h.reverse();
        h
    }

    /// Estimates the (virtual) transaction size, accounting for segwit.
    pub fn compute_size(&self) -> usize {
        let mut ln = 4
            + BtcVarInt(self.inputs.len() as u64).len()
            + BtcVarInt(self.outputs.len() as u64).len()
            + 4;
        let mut witln = 0;
        for inp in &self.inputs {
            ln += inp.compute_size();
            witln += inp.compute_witness_size();
        }
        for o in &self.outputs {
            ln += o.compute_size();
        }
        if !self.has_witness() {
            return ln;
        }
        witln += 2; // marker, flag
        ln + witln.div_ceil(4)
    }

    /// Parses a transaction from bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<BtcTx, Error> {
        let mut tx = BtcTx::default();
        tx.read_source(&mut SliceSource(buf))
            .map_err(ReadError::into_error)?;
        Ok(tx)
    }

    /// Reads a transaction from `r`, returning the number of bytes consumed.
    #[cfg(feature = "std")]
    pub fn read_from<R: Read>(&mut self, r: &mut R) -> io::Result<u64> {
        self.read_source(&mut IoSource(r))
            .map_err(ReadError::into_io)
    }

    fn read_source<S: ByteSource>(&mut self, r: &mut S) -> Result<u64, ReadError> {
        let mut n = 0u64;
        self.version = read_u32le(r, &mut n)?;
        let mut in_cnt = read_varint(r, &mut n)?;
        let mut segwit = false;
        if in_cnt == 0 {
            segwit = true;
            read_u8(r, &mut n)?; // flag
            in_cnt = read_varint(r, &mut n)?;
        }
        if in_cnt > 10000 {
            return Err(ReadError::TooLarge);
        }
        self.inputs = Vec::with_capacity(in_cnt as usize);
        for _ in 0..in_cnt {
            let mut inp = BtcTxInput::default();
            inp.read_source(r, &mut n)?;
            self.inputs.push(inp);
        }
        let out_cnt = read_varint(r, &mut n)?;
        if out_cnt > 65536 {
            return Err(ReadError::TooLarge);
        }
        self.outputs = Vec::with_capacity(out_cnt as usize);
        for idx in 0..out_cnt {
            let mut o = BtcTxOutput {
                n: idx as usize,
                ..Default::default()
            };
            o.read_source(r, &mut n)?;
            self.outputs.push(o);
        }
        if segwit {
            for inp in &mut self.inputs {
                let wc = read_varint(r, &mut n)?;
                // Each witness item takes at least one byte, so cap the
                // up-front allocation.
                let mut ws = Vec::with_capacity(wc.min(10000) as usize);
                for _ in 0..wc {
                    ws.push(read_var_buf(r, &mut n)?);
                }
                inp.witnesses = ws;
            }
        }
        self.locktime = read_u32le(r, &mut n)?;
        Ok(n)
    }
}

impl BtcTxInput {
    fn compute_size(&self) -> usize {
        32 + 4 + BtcVarInt(self.script.len() as u64).len() + self.script.len() + 4
    }
    fn compute_witness_size(&self) -> usize {
        let mut ln = BtcVarInt(self.witnesses.len() as u64).len();
        for w in &self.witnesses {
            ln += BtcVarInt(w.len() as u64).len() + w.len();
        }
        ln
    }

    /// Serializes the input (txid + vout + script + sequence).
    pub fn bytes(&self) -> Vec<u8> {
        let mut txid = self.txid;
        txid.reverse();
        let mut buf = txid.to_vec();
        buf.extend_from_slice(&self.vout.to_le_bytes());
        buf.extend_from_slice(&BtcVarInt(self.script.len() as u64).bytes());
        buf.extend_from_slice(&self.script);
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf
    }

    /// The outpoint and sequence as a [`RawTxIn`] (without script or witness).
    pub(crate) fn raw(&self) -> RawTxIn<'_> {
        RawTxIn {
            txid: self.txid,
            vout: self.vout,
            sequence: self.sequence,
            ..Default::default()
        }
    }

    fn read_source<S: ByteSource>(&mut self, r: &mut S, n: &mut u64) -> Result<(), ReadError> {
        read_full(r, &mut self.txid, n)?;
        self.txid.reverse();
        self.vout = read_u32le(r, n)?;
        self.script = read_var_buf(r, n)?;
        self.sequence = read_u32le(r, n)?;
        Ok(())
    }

    /// Fills the input with placeholder data of the expected signature size for
    /// the given scheme (used for fee estimation).
    pub fn prefill(&mut self, scheme: &str) -> Result<(), Error> {
        // worst-case sizes used for fee estimation
        let empty_sig = vec![0u8; 72];
        let comp_key = vec![0u8; 33];
        let uncomp_key = vec![0u8; 65];
        let p2pk_script = vec![0u8; 35];
        let p2puk_script = vec![0u8; 67];
        let p2pkh_script = vec![0u8; 25];
        match scheme {
            "p2pk" => {
                self.script = push_bytes(&empty_sig);
                self.witnesses.clear();
            }
            "p2pkh" => {
                let mut s = push_bytes(&empty_sig);
                s.extend_from_slice(&push_bytes(&comp_key));
                self.script = s;
                self.witnesses.clear();
            }
            "p2pukh" => {
                let mut s = push_bytes(&empty_sig);
                s.extend_from_slice(&push_bytes(&uncomp_key));
                self.script = s;
                self.witnesses.clear();
            }
            "p2wpkh" => {
                self.script = Vec::new();
                self.witnesses = vec![empty_sig, comp_key];
            }
            "p2wsh:p2pk" => {
                self.script = Vec::new();
                self.witnesses = vec![empty_sig, p2pk_script];
            }
            "p2wsh:p2puk" => {
                self.script = Vec::new();
                self.witnesses = vec![empty_sig, p2puk_script];
            }
            "p2wsh" | "p2wsh:p2pkh" => {
                self.script = Vec::new();
                self.witnesses = vec![empty_sig, comp_key, p2pkh_script];
            }
            "p2wsh:p2pukh" => {
                self.script = Vec::new();
                self.witnesses = vec![empty_sig, uncomp_key, p2pkh_script];
            }
            "p2tr" => {
                self.script = Vec::new();
                self.witnesses = vec![vec![0u8; 64]];
            }
            _ => return Err(Error::UnsupportedScheme),
        }
        Ok(())
    }
}

impl BtcTxOutput {
    fn compute_size(&self) -> usize {
        8 + BtcVarInt(self.script.len() as u64).len() + self.script.len()
    }

    /// Serializes the output (amount + script).
    pub fn bytes(&self) -> Vec<u8> {
        let mut buf = self.amount.0.to_le_bytes().to_vec();
        buf.extend_from_slice(&BtcVarInt(self.script.len() as u64).bytes());
        buf.extend_from_slice(&self.script);
        buf
    }

    fn read_source<S: ByteSource>(&mut self, r: &mut S, n: &mut u64) -> Result<(), ReadError> {
        self.amount = BtcAmount(read_u64le(r, n)?);
        self.script = read_var_buf(r, n)?;
        Ok(())
    }
}

// --- taproot (BIP-341) sighash ---

/// Cached per-transaction BIP-341 sighash components.
pub type TaprootSighashParts = TaprootMidstate;

pub(crate) use crate::btcraw::p2pkh_script_code;

impl BtcTx {
    fn taproot_sighash_parts_from_keys(
        &self,
        keys: &[BtcTxSign],
    ) -> Result<TaprootSighashParts, Error> {
        if keys.len() != self.inputs.len() {
            return Err(Error::KeyCount);
        }
        let mut prevouts = Vec::with_capacity(keys.len());
        for (i, k) in keys.iter().enumerate() {
            if k.prev_script.is_empty() {
                return Err(Error::MissingPrevScript(i));
            }
            prevouts.push(PrevOut {
                amount: k.amount.0,
                script: &k.prev_script,
            });
        }
        self.with_raw(|raw| raw.taproot_midstate(&prevouts))
    }

    pub(crate) fn taproot_sighash_parts_raw(
        &self,
        prev_scripts: &[Vec<u8>],
        amounts: &[u64],
    ) -> Result<TaprootSighashParts, Error> {
        if prev_scripts.len() != self.inputs.len() || amounts.len() != self.inputs.len() {
            return Err(Error::PrevOutCount);
        }
        let mut prevouts = Vec::with_capacity(prev_scripts.len());
        for (i, (script, &amount)) in prev_scripts.iter().zip(amounts).enumerate() {
            if script.is_empty() {
                return Err(Error::MissingPrevScript(i));
            }
            prevouts.push(PrevOut { amount, script });
        }
        self.with_raw(|raw| raw.taproot_midstate(&prevouts))
    }

    /// Pre-segwit legacy sighash: clear inputs, substitute `script_code` at
    /// input `n`, serialize without witness, append the sighash flag (u32 LE),
    /// double-SHA256.
    pub(crate) fn legacy_sighash(
        &self,
        n: usize,
        script_code: &[u8],
        flag: u32,
    ) -> Result<[u8; 32], Error> {
        self.with_raw(|raw| raw.legacy_sighash(n, script_code, flag))
    }

    /// Computes the BIP-341 key-path SIGHASH_DEFAULT digest for input `idx`.
    /// Each entry in `keys` must have its `prev_script` and `amount` set.
    pub fn taproot_sighash(&self, keys: &[BtcTxSign], idx: usize) -> Result<[u8; 32], Error> {
        let parts = self.taproot_sighash_parts_from_keys(keys)?;
        parts.key_spend_sighash(idx)
    }

    fn p2tr_sign(
        &mut self,
        n: usize,
        k: &BtcTxSign,
        parts: &TaprootSighashParts,
    ) -> Result<(), Error> {
        if k.sighash != 0 && k.sighash != 1 {
            return Err(Error::UnsupportedSighash);
        }
        let sighash = parts.key_spend_sighash(n)?;
        let key = k.key.ok_or(Error::MissingKey)?;
        let sig = key.sign_taproot(&sighash)?;
        self.inputs[n].witnesses = vec![sig.to_vec()];
        self.inputs[n].script = Vec::new();
        Ok(())
    }
}

// --- read helpers ---

/// Errors from parsing a serialized transaction.
#[derive(Debug)]
enum ReadError {
    Eof,
    TooLarge,
    #[cfg(feature = "std")]
    Io(io::Error),
}

impl core::fmt::Display for ReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReadError::Eof => f.write_str("unexpected end of transaction data"),
            ReadError::TooLarge => f.write_str("transaction data exceeds the allowed maximum"),
            #[cfg(feature = "std")]
            ReadError::Io(e) => e.fmt(f),
        }
    }
}

impl ReadError {
    fn into_error(self) -> Error {
        match self {
            ReadError::Eof => Error::UnexpectedEof,
            ReadError::TooLarge => Error::TooLarge,
            #[cfg(feature = "std")]
            ReadError::Io(_) => Error::UnexpectedEof,
        }
    }

    #[cfg(feature = "std")]
    fn into_io(self) -> io::Error {
        match self {
            ReadError::Io(e) => e,
            ReadError::Eof => io::Error::from(io::ErrorKind::UnexpectedEof),
            other => io::Error::other(other.into_error()),
        }
    }
}

/// A source of bytes for transaction parsing: a slice, or (with `std`) any
/// [`Read`].
trait ByteSource {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ReadError>;
}

struct SliceSource<'a>(&'a [u8]);

impl ByteSource for SliceSource<'_> {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ReadError> {
        if self.0.len() < buf.len() {
            return Err(ReadError::Eof);
        }
        let (head, rest) = self.0.split_at(buf.len());
        buf.copy_from_slice(head);
        self.0 = rest;
        Ok(())
    }
}

#[cfg(feature = "std")]
struct IoSource<'r, R>(&'r mut R);

#[cfg(feature = "std")]
impl<R: Read> ByteSource for IoSource<'_, R> {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ReadError> {
        self.0.read_exact(buf).map_err(ReadError::Io)
    }
}

fn read_u8<S: ByteSource>(r: &mut S, n: &mut u64) -> Result<u8, ReadError> {
    let mut b = [0u8; 1];
    read_full(r, &mut b, n)?;
    Ok(b[0])
}
fn read_u32le<S: ByteSource>(r: &mut S, n: &mut u64) -> Result<u32, ReadError> {
    let mut b = [0u8; 4];
    read_full(r, &mut b, n)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64le<S: ByteSource>(r: &mut S, n: &mut u64) -> Result<u64, ReadError> {
    let mut b = [0u8; 8];
    read_full(r, &mut b, n)?;
    Ok(u64::from_le_bytes(b))
}
fn read_full<S: ByteSource>(r: &mut S, buf: &mut [u8], n: &mut u64) -> Result<(), ReadError> {
    r.read_exact(buf)?;
    *n += buf.len() as u64;
    Ok(())
}
fn read_varint<S: ByteSource>(r: &mut S, n: &mut u64) -> Result<u64, ReadError> {
    let mut buf = [0u8; 9];
    read_full(r, &mut buf[..1], n)?;
    let extra = match buf[0] {
        0xfd => 2,
        0xfe => 4,
        0xff => 8,
        _ => 0,
    };
    read_full(r, &mut buf[1..1 + extra], n)?;
    let (v, _) = BtcVarInt::decode(&buf).expect("buffer holds a full varint");
    Ok(v.0)
}
fn read_var_buf<S: ByteSource>(r: &mut S, n: &mut u64) -> Result<Vec<u8>, ReadError> {
    let ln = read_varint(r, n)?;
    if ln == 0 {
        return Ok(Vec::new());
    }
    if ln > 100000 {
        return Err(ReadError::TooLarge);
    }
    let mut buf = vec![0u8; ln as usize];
    read_full(r, &mut buf, n)?;
    Ok(buf)
}

// --- JSON (serde) ---

#[derive(Serialize)]
struct ScriptPubKeyJson {
    hex: String,
    #[serde(rename = "type")]
    typ: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<String>,
}

impl Serialize for BtcTxOutput {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut st = serializer.serialize_struct("BtcTxOutput", 3)?;
        st.serialize_field("value", &self.amount)?;
        st.serialize_field("n", &self.n)?;
        st.serialize_field(
            "scriptPubKey",
            &ScriptPubKeyJson {
                hex: hex::encode(&self.script),
                typ: String::new(),
                addresses: Vec::new(),
            },
        )?;
        st.end()
    }
}

#[derive(Deserialize)]
struct ScriptHexJson {
    #[serde(default)]
    hex: String,
}

#[derive(Deserialize)]
struct BtcTxOutputDe {
    #[serde(default)]
    value: BtcAmount,
    #[serde(default)]
    n: usize,
    #[serde(rename = "scriptPubKey", default)]
    script_pub_key: Option<ScriptHexJson>,
}

impl<'de> Deserialize<'de> for BtcTxOutput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let de = BtcTxOutputDe::deserialize(deserializer)?;
        let script = match de.script_pub_key {
            Some(s) if !s.hex.is_empty() => hex::decode(&s.hex).map_err(de::Error::custom)?,
            _ => Vec::new(),
        };
        Ok(BtcTxOutput {
            amount: de.value,
            n: de.n,
            script,
        })
    }
}

impl Serialize for BtcTxInput {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut st = serializer.serialize_struct("BtcTxInput", 5)?;
        st.serialize_field("txid", &hex::encode(self.txid))?;
        st.serialize_field("vout", &self.vout)?;
        st.serialize_field(
            "scriptSig",
            &ScriptHexOut {
                hex: hex::encode(&self.script),
            },
        )?;
        st.serialize_field("sequence", &self.sequence)?;
        let witnesses: Vec<String> = self.witnesses.iter().map(hex::encode).collect();
        if witnesses.is_empty() {
            st.skip_field("witnesses")?;
        } else {
            st.serialize_field("witnesses", &witnesses)?;
        }
        st.end()
    }
}

#[derive(Serialize)]
struct ScriptHexOut {
    hex: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct BtcTxInputDe {
    #[serde(default)]
    txid: String,
    #[serde(default)]
    vout: u32,
    #[serde(rename = "scriptSig", default)]
    script_sig: Option<ScriptHexJson>,
    #[serde(default)]
    sequence: u32,
    #[serde(default)]
    witnesses: Vec<String>,
}

impl<'de> Deserialize<'de> for BtcTxInput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let de = BtcTxInputDe::deserialize(deserializer)?;
        let mut txid = [0u8; 32];
        if !de.txid.is_empty() {
            let raw = hex::decode(&de.txid).map_err(de::Error::custom)?;
            if raw.len() != 32 {
                return Err(de::Error::custom("txid must be 32 bytes"));
            }
            txid.copy_from_slice(&raw);
        }
        let script = match de.script_sig {
            Some(s) if !s.hex.is_empty() => hex::decode(&s.hex).map_err(de::Error::custom)?,
            _ => Vec::new(),
        };
        let mut witnesses = Vec::with_capacity(de.witnesses.len());
        for w in de.witnesses {
            witnesses.push(hex::decode(&w).map_err(de::Error::custom)?);
        }
        Ok(BtcTxInput {
            txid,
            vout: de.vout,
            script,
            sequence: de.sequence,
            witnesses,
        })
    }
}

impl Serialize for BtcTx {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut st = serializer.serialize_struct("BtcTx", 4)?;
        st.serialize_field("version", &self.version)?;
        st.serialize_field("vin", &self.inputs)?;
        st.serialize_field("vout", &self.outputs)?;
        st.serialize_field("locktime", &self.locktime)?;
        st.end()
    }
}

#[derive(Deserialize)]
struct BtcTxDe {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    vin: Vec<BtcTxInput>,
    #[serde(default)]
    vout: Vec<BtcTxOutput>,
    #[serde(default)]
    locktime: u32,
}

impl<'de> Deserialize<'de> for BtcTx {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let de = BtcTxDe::deserialize(deserializer)?;
        Ok(BtcTx {
            version: de.version,
            inputs: de.vin,
            outputs: de.vout,
            locktime: de.locktime,
        })
    }
}
