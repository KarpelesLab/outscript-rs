//! Heap-free Bitcoin transaction signing: a borrowed transaction view
//! ([`RawTx`]) with streaming sighash computation (legacy, BIP-143 segwit v0,
//! BIP-341 taproot), serialization into a caller buffer, and txid.
//!
//! Signing an input is: compute its sighash, sign it (e.g.
//! [`SecpPrivateKey::sign_der`](crate::crypto::secp256k1::SecpPrivateKey::sign_der)
//! plus the sighash-type byte, or
//! [`SecpPrivateKey::sign_taproot`](crate::crypto::secp256k1::SecpPrivateKey::sign_taproot)),
//! place the result in that input's `script_sig`/`witness`, then serialize.
//!
//! Only whole-transaction commitments are supported: `SIGHASH_ALL` (including
//! the Bitcoin Cash `ALL|FORKID` flag, which shares the BIP-143 preimage) and
//! taproot `SIGHASH_DEFAULT`.

use purecrypto::hash::{Digest, Sha256};

use crate::btcvarint::BtcVarInt;
use crate::crypto::secp256k1::tagged_hash;
use crate::hash::sha256_once;
use crate::sink::{Counter, HashSink, Sink, SliceSink};

/// Errors from [`RawTx`] operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input index is out of range.
    InputIndex,
    /// The previous outputs do not match the inputs one to one.
    PrevOutCount,
    /// The output buffer is too small.
    BufferTooSmall,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::InputIndex => "input index out of range",
            Error::PrevOutCount => "previous outputs must match the inputs one to one",
            Error::BufferTooSmall => "transaction output buffer too small",
        })
    }
}

impl core::error::Error for Error {}

/// A transaction input.
#[derive(Debug, Clone, Copy, Default)]
pub struct RawTxIn<'a> {
    /// Id of the spent transaction, in display (big-endian) byte order.
    pub txid: [u8; 32],
    /// Index of the spent output.
    pub vout: u32,
    /// The scriptSig (empty for segwit spends and when computing sighashes).
    pub script_sig: &'a [u8],
    /// The sequence number.
    pub sequence: u32,
    /// The witness stack (empty for legacy spends).
    pub witness: &'a [&'a [u8]],
}

/// A transaction output.
#[derive(Debug, Clone, Copy, Default)]
pub struct RawTxOut<'a> {
    /// Amount in satoshis.
    pub amount: u64,
    /// The scriptPubKey.
    pub script: &'a [u8],
}

/// The output an input spends, as needed by taproot sighashes.
pub type PrevOut<'a> = RawTxOut<'a>;

/// A borrowed transaction.
#[derive(Debug, Clone, Copy, Default)]
pub struct RawTx<'a> {
    /// Transaction version.
    pub version: u32,
    /// Inputs.
    pub inputs: &'a [RawTxIn<'a>],
    /// Outputs.
    pub outputs: &'a [RawTxOut<'a>],
    /// Lock time.
    pub locktime: u32,
}

fn put_varint<S: Sink>(s: &mut S, v: usize) {
    let (buf, len) = BtcVarInt(v as u64).to_array();
    s.put(&buf[..len]);
}

fn put_outpoint<S: Sink>(s: &mut S, input: &RawTxIn<'_>) {
    let mut txid = input.txid;
    txid.reverse();
    s.put(&txid);
    s.put(&input.vout.to_le_bytes());
}

fn put_output<S: Sink>(s: &mut S, output: &RawTxOut<'_>) {
    s.put(&output.amount.to_le_bytes());
    put_varint(s, output.script.len());
    s.put(output.script);
}

/// Finishes a streamed double SHA-256.
fn dsha256_finish(h: HashSink<Sha256>) -> [u8; 32] {
    sha256_once(&h.0.finalize())
}

/// Double SHA-256 of whatever `f` writes.
fn dsha256_with(f: impl FnOnce(&mut HashSink<Sha256>)) -> [u8; 32] {
    let mut h = HashSink(Sha256::new());
    f(&mut h);
    dsha256_finish(h)
}

/// Single SHA-256 of whatever `f` writes.
fn sha256_with(f: impl FnOnce(&mut HashSink<Sha256>)) -> [u8; 32] {
    let mut h = HashSink(Sha256::new());
    f(&mut h);
    h.0.finalize()
}

impl<'a> RawTx<'a> {
    /// Reports whether any input carries witness data.
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|i| !i.witness.is_empty())
    }

    /// Serializes the transaction, substituting `script_override` as the
    /// scriptSig of every input (`None`: each input's own; `Some((n, s))`:
    /// `s` for input `n`, empty for the others).
    fn write<S: Sink>(&self, s: &mut S, witness: bool, script_override: Option<(usize, &[u8])>) {
        s.put(&self.version.to_le_bytes());
        if witness {
            s.put(&[0x00, 0x01]);
        }
        put_varint(s, self.inputs.len());
        for (i, input) in self.inputs.iter().enumerate() {
            let script = match script_override {
                None => input.script_sig,
                Some((n, script)) if n == i => script,
                Some(_) => &[],
            };
            put_outpoint(s, input);
            put_varint(s, script.len());
            s.put(script);
            s.put(&input.sequence.to_le_bytes());
        }
        put_varint(s, self.outputs.len());
        for output in self.outputs {
            put_output(s, output);
        }
        if witness {
            for input in self.inputs {
                put_varint(s, input.witness.len());
                for item in input.witness {
                    put_varint(s, item.len());
                    s.put(item);
                }
            }
        }
        s.put(&self.locktime.to_le_bytes());
    }

    /// The serialized length (with witness data if any input has some).
    pub fn serialized_len(&self) -> usize {
        let mut c = Counter::default();
        self.write(&mut c, self.has_witness(), None);
        c.0
    }

    /// Serializes the transaction into `out` (with witness data if any input
    /// has some), returning the number of bytes written.
    pub fn serialize_to_slice(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut s = SliceSink::new(out);
        self.write(&mut s, self.has_witness(), None);
        s.finish().ok_or(Error::BufferTooSmall)
    }

    /// The transaction id (double SHA-256 of the non-witness serialization, in
    /// display byte order).
    pub fn txid(&self) -> [u8; 32] {
        let mut h = dsha256_with(|s| self.write(s, false, None));
        h.reverse();
        h
    }

    /// The pre-segwit sighash of input `index`: the transaction with every
    /// scriptSig emptied except `script_code` at `index`, followed by the
    /// 4-byte `sighash_type`, double SHA-256'd.
    pub fn legacy_sighash(
        &self,
        index: usize,
        script_code: &[u8],
        sighash_type: u32,
    ) -> Result<[u8; 32], Error> {
        if index >= self.inputs.len() {
            return Err(Error::InputIndex);
        }
        Ok(dsha256_with(|s| {
            self.write(s, false, Some((index, script_code)));
            s.put(&sighash_type.to_le_bytes());
        }))
    }

    /// Precomputes the BIP-143 hashes shared by every input's sighash.
    pub fn segwit_v0_midstate(&self) -> SegwitV0Midstate {
        SegwitV0Midstate {
            version: self.version,
            locktime: self.locktime,
            hash_prevouts: dsha256_with(|s| self.inputs.iter().for_each(|i| put_outpoint(s, i))),
            hash_sequence: dsha256_with(|s| {
                self.inputs
                    .iter()
                    .for_each(|i| s.put(&i.sequence.to_le_bytes()))
            }),
            hash_outputs: dsha256_with(|s| self.outputs.iter().for_each(|o| put_output(s, o))),
        }
    }

    /// The BIP-143 (segwit v0) sighash of input `index`. Prefer
    /// [`segwit_v0_midstate`](Self::segwit_v0_midstate) when signing several
    /// inputs.
    pub fn segwit_v0_sighash(
        &self,
        index: usize,
        script_code: &[u8],
        amount: u64,
        sighash_type: u32,
    ) -> Result<[u8; 32], Error> {
        let input = self.inputs.get(index).ok_or(Error::InputIndex)?;
        Ok(self
            .segwit_v0_midstate()
            .sighash(input, script_code, amount, sighash_type))
    }

    /// Precomputes the BIP-341 hashes shared by every input's taproot sighash.
    /// `prevouts` are the outputs spent by each input, in order.
    pub fn taproot_midstate(&self, prevouts: &[PrevOut<'_>]) -> Result<TaprootMidstate, Error> {
        if prevouts.len() != self.inputs.len() {
            return Err(Error::PrevOutCount);
        }
        Ok(TaprootMidstate {
            version: self.version,
            locktime: self.locktime,
            input_count: self.inputs.len(),
            sha_prevouts: sha256_with(|s| self.inputs.iter().for_each(|i| put_outpoint(s, i))),
            sha_amounts: sha256_with(|s| {
                prevouts.iter().for_each(|p| s.put(&p.amount.to_le_bytes()))
            }),
            sha_scriptpubkeys: sha256_with(|s| {
                prevouts.iter().for_each(|p| {
                    put_varint(s, p.script.len());
                    s.put(p.script);
                })
            }),
            sha_sequences: sha256_with(|s| {
                self.inputs
                    .iter()
                    .for_each(|i| s.put(&i.sequence.to_le_bytes()))
            }),
            sha_outputs: sha256_with(|s| self.outputs.iter().for_each(|o| put_output(s, o))),
        })
    }
}

/// BIP-143 hashes shared by every input of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegwitV0Midstate {
    version: u32,
    locktime: u32,
    hash_prevouts: [u8; 32],
    hash_sequence: [u8; 32],
    hash_outputs: [u8; 32],
}

impl SegwitV0Midstate {
    /// The BIP-143 sighash for `input` (which must belong to the transaction
    /// this midstate was computed from), spending `amount` satoshis under
    /// `script_code` (for P2WPKH: the P2PKH script of the key hash; for P2WSH:
    /// the witness script).
    pub fn sighash(
        &self,
        input: &RawTxIn<'_>,
        script_code: &[u8],
        amount: u64,
        sighash_type: u32,
    ) -> [u8; 32] {
        dsha256_with(|s| {
            s.put(&self.version.to_le_bytes());
            s.put(&self.hash_prevouts);
            s.put(&self.hash_sequence);
            put_outpoint(s, input);
            put_varint(s, script_code.len());
            s.put(script_code);
            s.put(&amount.to_le_bytes());
            s.put(&input.sequence.to_le_bytes());
            s.put(&self.hash_outputs);
            s.put(&self.locktime.to_le_bytes());
            s.put(&sighash_type.to_le_bytes());
        })
    }
}

/// BIP-341 hashes shared by every input of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaprootMidstate {
    version: u32,
    locktime: u32,
    input_count: usize,
    sha_prevouts: [u8; 32],
    sha_amounts: [u8; 32],
    sha_scriptpubkeys: [u8; 32],
    sha_sequences: [u8; 32],
    sha_outputs: [u8; 32],
}

impl TaprootMidstate {
    fn common(&self, spend_type: u8, index: u32) -> [u8; 175] {
        let mut buf = [0u8; 175];
        buf[0] = 0x00; // epoch
        buf[1] = 0x00; // hash type: SIGHASH_DEFAULT
        buf[2..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..10].copy_from_slice(&self.locktime.to_le_bytes());
        buf[10..42].copy_from_slice(&self.sha_prevouts);
        buf[42..74].copy_from_slice(&self.sha_amounts);
        buf[74..106].copy_from_slice(&self.sha_scriptpubkeys);
        buf[106..138].copy_from_slice(&self.sha_sequences);
        buf[138..170].copy_from_slice(&self.sha_outputs);
        buf[170] = spend_type; // no annex
        buf[171..].copy_from_slice(&index.to_le_bytes());
        buf
    }

    fn check(&self, index: usize) -> Result<u32, Error> {
        if index >= self.input_count {
            return Err(Error::InputIndex);
        }
        Ok(index as u32)
    }

    /// The BIP-341 key-path `SIGHASH_DEFAULT` sighash of input `index`.
    pub fn key_spend_sighash(&self, index: usize) -> Result<[u8; 32], Error> {
        let common = self.common(0x00, self.check(index)?);
        Ok(tagged_hash("TapSighash", &[&common]))
    }

    /// The BIP-342 script-path `SIGHASH_DEFAULT` sighash of input `index` for a
    /// tapscript leaf (leaf version 0xc0, no code separator).
    pub fn script_path_sighash(&self, index: usize, leaf_script: &[u8]) -> Result<[u8; 32], Error> {
        let common = self.common(0x02, self.check(index)?);
        let (len_buf, len_len) = BtcVarInt(leaf_script.len() as u64).to_array();
        let tapleaf_hash = tagged_hash("TapLeaf", &[&[0xc0], &len_buf[..len_len], leaf_script]);
        Ok(tagged_hash(
            "TapSighash",
            &[
                &common,
                &tapleaf_hash,
                &[0x00],                       // key_version
                &0xffff_ffffu32.to_le_bytes(), // codesep position
            ],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arr32_le(hex_s: &str) -> [u8; 32] {
        // BIP-143 lists outpoint hashes in serialized (little-endian) order
        let mut a = [0u8; 32];
        hex::decode_to_slice(hex_s, &mut a).unwrap();
        a.reverse();
        a
    }

    /// BIP-143 "Native P2WPKH" example: sighash of the second input.
    #[test]
    fn bip143_native_p2wpkh() {
        let inputs = [
            RawTxIn {
                txid: arr32_le("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"),
                vout: 0,
                sequence: 0xffff_ffee,
                ..Default::default()
            },
            RawTxIn {
                txid: arr32_le("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"),
                vout: 1,
                sequence: 0xffff_ffff,
                ..Default::default()
            },
        ];
        let mut s0 = [0u8; 25];
        hex::decode_to_slice(
            "76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac",
            &mut s0,
        )
        .unwrap();
        let mut s1 = [0u8; 25];
        hex::decode_to_slice(
            "76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac",
            &mut s1,
        )
        .unwrap();
        let outputs = [
            RawTxOut {
                amount: 112_340_000,
                script: &s0,
            },
            RawTxOut {
                amount: 223_450_000,
                script: &s1,
            },
        ];
        let tx = RawTx {
            version: 1,
            inputs: &inputs,
            outputs: &outputs,
            locktime: 0x11,
        };
        let mut script_code = [0u8; 25];
        hex::decode_to_slice(
            "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac",
            &mut script_code,
        )
        .unwrap();
        let sighash = tx
            .segwit_v0_sighash(1, &script_code, 600_000_000, 1)
            .unwrap();
        let mut want = [0u8; 32];
        hex::decode_to_slice(
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670",
            &mut want,
        )
        .unwrap();
        assert_eq!(sighash, want);

        // unsigned serialization round-trips through the length and buffer APIs
        let mut buf = [0u8; 256];
        let n = tx.serialize_to_slice(&mut buf).unwrap();
        assert_eq!(n, tx.serialized_len());
        assert_eq!(
            tx.serialize_to_slice(&mut buf[..n - 1]),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(tx.segwit_v0_sighash(2, &[], 0, 1), Err(Error::InputIndex));
        assert_eq!(tx.legacy_sighash(2, &[], 1), Err(Error::InputIndex));
        assert_eq!(tx.taproot_midstate(&outputs[..1]), Err(Error::PrevOutCount));
    }
}
