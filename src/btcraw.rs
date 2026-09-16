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

pub use crate::Error;

use purecrypto::hash::{Digest, Sha256};

use crate::btcvarint::BtcVarInt;
use crate::crypto::secp256k1::tagged_hash;
use crate::hash::sha256_once;
use crate::sink::{Counter, HashSink, Sink, SliceSink};

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

/// The P2PKH script used as the BIP-143 scriptCode of a P2WPKH spend.
pub(crate) fn p2pkh_script_code(pk_hash: &[u8; 20]) -> [u8; 25] {
    let mut s = [0u8; 25];
    s[..3].copy_from_slice(&[0x76, 0xa9, 0x14]);
    s[3..23].copy_from_slice(pk_hash);
    s[23..].copy_from_slice(&[0x88, 0xac]);
    s
}

fn put_varint<S: Sink + ?Sized>(s: &mut S, v: usize) {
    let (buf, len) = BtcVarInt(v as u64).to_array();
    s.put(&buf[..len]);
}

fn put_outpoint<S: Sink + ?Sized>(s: &mut S, input: &RawTxIn<'_>) {
    let mut txid = input.txid;
    txid.reverse();
    s.put(&txid);
    s.put(&input.vout.to_le_bytes());
}

fn put_output<S: Sink + ?Sized>(s: &mut S, output: &RawTxOut<'_>) {
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

/// A transaction as seen by the sighash algorithms: only outpoints,
/// sequences, outputs, version and locktime matter. Implemented by [`RawTx`]
/// and by the PSBT unsigned-transaction view.
pub(crate) trait TxSource {
    fn version(&self) -> u32;
    fn locktime(&self) -> u32;
    fn input_count(&self) -> usize;
    /// Calls `f` with each input (scripts and witnesses are ignored).
    fn for_each_input(&self, f: &mut dyn FnMut(&RawTxIn<'_>));
    /// Calls `f` with each output.
    fn for_each_output(&self, f: &mut dyn FnMut(&RawTxOut<'_>));
}

impl TxSource for RawTx<'_> {
    fn version(&self) -> u32 {
        self.version
    }
    fn locktime(&self) -> u32 {
        self.locktime
    }
    fn input_count(&self) -> usize {
        self.inputs.len()
    }
    fn for_each_input(&self, f: &mut dyn FnMut(&RawTxIn<'_>)) {
        self.inputs.iter().for_each(f)
    }
    fn for_each_output(&self, f: &mut dyn FnMut(&RawTxOut<'_>)) {
        self.outputs.iter().for_each(f)
    }
}

fn output_count<T: TxSource + ?Sized>(tx: &T) -> usize {
    let mut n = 0;
    tx.for_each_output(&mut |_| n += 1);
    n
}

/// The legacy sighash of input `index` of `tx` (see [`RawTx::legacy_sighash`]).
pub(crate) fn legacy_sighash_of<T: TxSource + ?Sized>(
    tx: &T,
    index: usize,
    script_code: &[u8],
    sighash_type: u32,
) -> Result<[u8; 32], Error> {
    if index >= tx.input_count() {
        return Err(Error::InputIndex);
    }
    Ok(dsha256_with(|s| {
        s.put(&tx.version().to_le_bytes());
        put_varint(s, tx.input_count());
        let mut i = 0;
        tx.for_each_input(&mut |input| {
            let script = if i == index { script_code } else { &[] };
            put_outpoint(s, input);
            put_varint(s, script.len());
            s.put(script);
            s.put(&input.sequence.to_le_bytes());
            i += 1;
        });
        put_varint(s, output_count(tx));
        tx.for_each_output(&mut |o| put_output(s, o));
        s.put(&tx.locktime().to_le_bytes());
        s.put(&sighash_type.to_le_bytes());
    }))
}

/// The BIP-143 midstate of `tx` (see [`RawTx::segwit_v0_midstate`]).
pub(crate) fn segwit_v0_midstate_of<T: TxSource + ?Sized>(tx: &T) -> SegwitV0Midstate {
    let mut prevouts = HashSink(Sha256::new());
    let mut sequences = HashSink(Sha256::new());
    tx.for_each_input(&mut |i| {
        put_outpoint(&mut prevouts, i);
        sequences.put(&i.sequence.to_le_bytes());
    });
    SegwitV0Midstate {
        version: tx.version(),
        locktime: tx.locktime(),
        hash_prevouts: dsha256_finish(prevouts),
        hash_sequence: dsha256_finish(sequences),
        hash_outputs: dsha256_with(|s| tx.for_each_output(&mut |o| put_output(s, o))),
    }
}

/// The BIP-341 midstate of `tx` given the outputs its inputs spend, in order
/// (see [`RawTx::taproot_midstate`]).
pub(crate) fn taproot_midstate_of<'p, T: TxSource + ?Sized>(
    tx: &T,
    prevouts: impl Iterator<Item = PrevOut<'p>>,
) -> Result<TaprootMidstate, Error> {
    let mut amounts = HashSink(Sha256::new());
    let mut scripts = HashSink(Sha256::new());
    let mut count = 0;
    for p in prevouts {
        amounts.put(&p.amount.to_le_bytes());
        put_varint(&mut scripts, p.script.len());
        scripts.put(p.script);
        count += 1;
    }
    if count != tx.input_count() {
        return Err(Error::PrevOutCount);
    }
    let mut outpoints = HashSink(Sha256::new());
    let mut sequences = HashSink(Sha256::new());
    tx.for_each_input(&mut |i| {
        put_outpoint(&mut outpoints, i);
        sequences.put(&i.sequence.to_le_bytes());
    });
    Ok(TaprootMidstate {
        version: tx.version(),
        locktime: tx.locktime(),
        input_count: count,
        sha_prevouts: outpoints.0.finalize(),
        sha_amounts: amounts.0.finalize(),
        sha_scriptpubkeys: scripts.0.finalize(),
        sha_sequences: sequences.0.finalize(),
        sha_outputs: sha256_with(|s| tx.for_each_output(&mut |o| put_output(s, o))),
    })
}

impl<'a> RawTx<'a> {
    /// Reports whether any input carries witness data.
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|i| !i.witness.is_empty())
    }

    /// Serializes the transaction, with witness data if `witness`.
    fn write<S: Sink + ?Sized>(&self, s: &mut S, witness: bool) {
        s.put(&self.version.to_le_bytes());
        if witness {
            s.put(&[0x00, 0x01]);
        }
        put_varint(s, self.inputs.len());
        for input in self.inputs {
            put_outpoint(s, input);
            put_varint(s, input.script_sig.len());
            s.put(input.script_sig);
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

    /// Streams the serialization without witness data.
    pub(crate) fn write_unsigned(&self, s: &mut dyn Sink) {
        self.write(s, false)
    }

    /// The serialized length (with witness data if any input has some).
    pub fn serialized_len(&self) -> usize {
        let mut c = Counter::default();
        self.write(&mut c, self.has_witness());
        c.0
    }

    /// Serializes the transaction into `out` (with witness data if any input
    /// has some), returning the number of bytes written.
    pub fn serialize_to_slice(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut s = SliceSink::new(out);
        self.write(&mut s, self.has_witness());
        s.finish().ok_or(Error::BufferTooSmall)
    }

    /// The transaction id (double SHA-256 of the non-witness serialization, in
    /// display byte order).
    pub fn txid(&self) -> [u8; 32] {
        let mut h = dsha256_with(|s| self.write(s, false));
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
        legacy_sighash_of(self, index, script_code, sighash_type)
    }

    /// Precomputes the BIP-143 hashes shared by every input's sighash.
    pub fn segwit_v0_midstate(&self) -> SegwitV0Midstate {
        segwit_v0_midstate_of(self)
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
        taproot_midstate_of(self, prevouts.iter().copied())
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
    fn common(&self, hash_type: u8, spend_type: u8, index: u32) -> [u8; 175] {
        let mut buf = [0u8; 175];
        buf[0] = 0x00; // epoch
        buf[1] = hash_type;
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
        self.key_spend_sighash_with_type(index, 0x00)
    }

    /// The BIP-341 key-path sighash of input `index` for `SIGHASH_DEFAULT`
    /// (0x00) or `SIGHASH_ALL` (0x01), the two types committing to the whole
    /// transaction. A `SIGHASH_ALL` signature carries the type as a 65th byte.
    pub fn key_spend_sighash_with_type(
        &self,
        index: usize,
        hash_type: u8,
    ) -> Result<[u8; 32], Error> {
        if hash_type > 0x01 {
            return Err(Error::UnsupportedSighash);
        }
        let common = self.common(hash_type, 0x00, self.check(index)?);
        Ok(tagged_hash("TapSighash", &[&common]))
    }

    /// The BIP-342 script-path `SIGHASH_DEFAULT` sighash of input `index` for a
    /// tapscript leaf (leaf version 0xc0, no code separator).
    pub fn script_path_sighash(&self, index: usize, leaf_script: &[u8]) -> Result<[u8; 32], Error> {
        let common = self.common(0x00, 0x02, self.check(index)?);
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
