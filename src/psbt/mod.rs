//! Partially Signed Bitcoin Transactions (BIP-174, version 0), without
//! allocating.
//!
//! [`Psbt`] is a zero-copy, fully validated view over PSBT bytes. Every role
//! of the BIP-174 workflow writes a new PSBT into a caller buffer:
//!
//! - **Creator**: [`Psbt::create_to_slice`] from an unsigned [`RawTx`].
//! - **Updater**: [`Psbt::set_input_record`] and typed helpers such as
//!   [`Psbt::set_witness_utxo`] or [`Psbt::add_input_bip32_derivation`].
//! - **Signer**: [`Psbt::sign_to_slice`] / [`Psbt::sign_input_to_slice`] with
//!   any [`PsbtSigner`] (P2PKH, P2PK, bare and P2SH multisig, P2WPKH, P2WSH,
//!   their P2SH-nested forms, and P2TR key path).
//! - **Combiner**: [`Psbt::combine_to_slice`].
//! - **Finalizer**: [`Psbt::finalize_to_slice`].
//! - **Extractor**: [`Psbt::extract_tx_to_slice`].
//!
//! Output records are grouped by key type in ascending order, keeping their
//! existing order within a type, which reproduces the BIP-174 test vectors
//! byte for byte. Every output is re-parsed before being returned, so these
//! functions never produce an invalid PSBT. Base64 text goes through
//! [`Psbt::from_base64`] and [`Psbt::encode_base64_to_slice`].
//!
//! With `alloc`, each `*_to_slice` operation has a `*_to_vec` counterpart.

pub use crate::Error;

mod finalize;
mod sign;

pub use sign::{PsbtSigner, SignerError};

#[cfg(feature = "alloc")]
use crate::prelude::*;

use crate::base64;
use crate::btcraw::{RawTx, RawTxIn, RawTxOut, TxSource};
use crate::btcvarint::BtcVarInt;
use crate::crypto::secp256k1::SecpPublicKey;
use crate::hash::sha256_once;
use crate::sink::{Counter, HashSink, Sink, SliceSink};
use purecrypto::hash::{Digest, Sha256};

/// The 5-byte PSBT magic: `psbt` followed by `0xff`.
pub const MAGIC: [u8; 5] = *b"psbt\xff";

/// Key types of the global map.
pub mod global {
    /// The unsigned transaction.
    pub const UNSIGNED_TX: u64 = 0x00;
    /// An extended public key and its derivation path.
    pub const XPUB: u64 = 0x01;
    /// The PSBT version (only 0 is supported).
    pub const VERSION: u64 = 0xfb;
    /// Proprietary data.
    pub const PROPRIETARY: u64 = 0xfc;
}

/// Key types of input maps.
pub mod input {
    /// The full previous transaction.
    pub const NON_WITNESS_UTXO: u64 = 0x00;
    /// The spent output (amount and scriptPubKey).
    pub const WITNESS_UTXO: u64 = 0x01;
    /// An ECDSA signature, keyed by public key.
    pub const PARTIAL_SIG: u64 = 0x02;
    /// The sighash type to sign with.
    pub const SIGHASH_TYPE: u64 = 0x03;
    /// The P2SH redeem script.
    pub const REDEEM_SCRIPT: u64 = 0x04;
    /// The P2WSH witness script.
    pub const WITNESS_SCRIPT: u64 = 0x05;
    /// A public key's BIP-32 fingerprint and derivation path.
    pub const BIP32_DERIVATION: u64 = 0x06;
    /// The finalized scriptSig.
    pub const FINAL_SCRIPTSIG: u64 = 0x07;
    /// The finalized witness stack.
    pub const FINAL_SCRIPTWITNESS: u64 = 0x08;
    /// A RIPEMD-160 preimage.
    pub const RIPEMD160: u64 = 0x0a;
    /// A SHA-256 preimage.
    pub const SHA256: u64 = 0x0b;
    /// A HASH160 preimage.
    pub const HASH160: u64 = 0x0c;
    /// A HASH256 preimage.
    pub const HASH256: u64 = 0x0d;
    /// A taproot key-path signature.
    pub const TAP_KEY_SIG: u64 = 0x13;
    /// A taproot script-path signature.
    pub const TAP_SCRIPT_SIG: u64 = 0x14;
    /// A taproot leaf script and control block.
    pub const TAP_LEAF_SCRIPT: u64 = 0x15;
    /// A taproot key's leaf hashes and derivation path.
    pub const TAP_BIP32_DERIVATION: u64 = 0x16;
    /// The taproot internal key.
    pub const TAP_INTERNAL_KEY: u64 = 0x17;
    /// The taproot merkle root.
    pub const TAP_MERKLE_ROOT: u64 = 0x18;
    /// Proprietary data.
    pub const PROPRIETARY: u64 = 0xfc;
}

/// Key types of output maps.
pub mod output {
    /// The P2SH redeem script.
    pub const REDEEM_SCRIPT: u64 = 0x00;
    /// The P2WSH witness script.
    pub const WITNESS_SCRIPT: u64 = 0x01;
    /// A public key's BIP-32 fingerprint and derivation path.
    pub const BIP32_DERIVATION: u64 = 0x02;
    /// The taproot internal key.
    pub const TAP_INTERNAL_KEY: u64 = 0x05;
    /// The taproot script tree.
    pub const TAP_TREE: u64 = 0x06;
    /// A taproot key's leaf hashes and derivation path.
    pub const TAP_BIP32_DERIVATION: u64 = 0x07;
    /// Proprietary data.
    pub const PROPRIETARY: u64 = 0xfc;
}

// --- reading ---

#[derive(Clone)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::UnexpectedEof)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::UnexpectedEof)?;
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn varint(&mut self) -> Result<u64, Error> {
        let (v, n) = BtcVarInt::decode(&self.buf[self.pos.min(self.buf.len())..])
            .ok_or(Error::UnexpectedEof)?;
        if v.len() != n {
            return Err(Error::NonCanonical);
        }
        self.pos += n;
        Ok(v.0)
    }
    /// A length-prefixed byte string.
    fn var_bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = self.varint()?;
        self.take(usize::try_from(n).map_err(|_| Error::UnexpectedEof)?)
    }
}

pub(crate) fn put_varint(s: &mut dyn Sink, v: usize) {
    let (buf, len) = BtcVarInt(v as u64).to_array();
    s.put(&buf[..len]);
}

// --- transactions ---

/// Offsets of the parts of a serialized transaction.
#[derive(Debug, Clone, Copy)]
struct TxLayout {
    /// Offset of the input-count varint.
    inputs_at: usize,
    /// Offset of the output-count varint.
    outputs_at: usize,
    /// Offset just past the outputs (the witnesses or the locktime).
    outputs_end: usize,
    input_count: usize,
    output_count: usize,
    /// Every scriptSig is empty and there is no witness data.
    unsigned: bool,
}

impl TxLayout {
    /// Parses a complete transaction. `allow_witness` accepts the segwit
    /// serialization (as a non-witness UTXO may use).
    fn parse(bytes: &[u8], allow_witness: bool) -> Result<TxLayout, Error> {
        let mut r = Reader::new(bytes);
        r.u32()?;
        let mut inputs_at = r.pos;
        let mut input_count = r.varint()?;
        let mut segwit = false;
        let mut output_count = None;
        if input_count == 0 && allow_witness {
            match r.u8()? {
                // the "flag" was the output count of a 0-input transaction
                0 => output_count = Some(0),
                1 => {
                    segwit = true;
                    inputs_at = r.pos;
                    input_count = r.varint()?;
                }
                _ => return Err(Error::InvalidRecordValue),
            }
        }
        let mut unsigned = !segwit;
        for _ in 0..input_count {
            r.take(36)?;
            if !r.var_bytes()?.is_empty() {
                unsigned = false;
            }
            r.u32()?;
        }
        let outputs_at = r.pos;
        let output_count = match output_count {
            Some(n) => n,
            None => {
                let n = r.varint()?;
                for _ in 0..n {
                    r.u64()?;
                    r.var_bytes()?;
                }
                n
            }
        };
        let outputs_end = r.pos;
        if segwit {
            let mut any = false;
            for _ in 0..input_count {
                let items = r.varint()?;
                for _ in 0..items {
                    r.var_bytes()?;
                    any = true;
                }
                any |= items > 0;
            }
            if !any {
                // a witness marker with no witness data is not canonical
                return Err(Error::InvalidRecordValue);
            }
        }
        r.u32()?;
        if !r.is_empty() {
            return Err(Error::InvalidRecordValue);
        }
        Ok(TxLayout {
            inputs_at,
            outputs_at,
            outputs_end,
            input_count: input_count as usize,
            output_count: output_count as usize,
            unsigned,
        })
    }
}

/// The unsigned transaction of a PSBT.
#[derive(Debug, Clone, Copy)]
pub struct UnsignedTx<'a> {
    bytes: &'a [u8],
    layout: TxLayout,
}

/// Iterates the inputs of a validated transaction.
fn tx_inputs<'a>(bytes: &'a [u8], layout: &TxLayout) -> impl Iterator<Item = RawTxIn<'a>> + 'a {
    let mut r = Reader::new(bytes);
    r.pos = layout.inputs_at;
    let count = r.varint().unwrap_or(0);
    (0..count).map_while(move |_| {
        let mut txid: [u8; 32] = r.take(32).ok()?.try_into().ok()?;
        txid.reverse();
        let vout = r.u32().ok()?;
        let script_sig = r.var_bytes().ok()?;
        let sequence = r.u32().ok()?;
        Some(RawTxIn {
            txid,
            vout,
            script_sig,
            sequence,
            witness: &[],
        })
    })
}

/// Iterates the outputs of a validated transaction.
fn tx_outputs<'a>(bytes: &'a [u8], layout: &TxLayout) -> impl Iterator<Item = RawTxOut<'a>> + 'a {
    let mut r = Reader::new(bytes);
    r.pos = layout.outputs_at;
    (0..layout.output_count).map_while(move |i| {
        if i == 0 {
            r.varint().ok()?;
        }
        let amount = r.u64().ok()?;
        let script = r.var_bytes().ok()?;
        Some(RawTxOut { amount, script })
    })
}

/// The txid of a validated transaction (witness data excluded).
fn tx_txid(bytes: &[u8], layout: &TxLayout) -> [u8; 32] {
    let mut h = HashSink(Sha256::new());
    h.put(&bytes[..4]);
    h.put(&bytes[layout.inputs_at..layout.outputs_end]);
    h.put(&bytes[bytes.len() - 4..]);
    let mut id = sha256_once(&h.0.finalize());
    id.reverse();
    id
}

impl<'a> UnsignedTx<'a> {
    /// The serialized transaction.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// The transaction version.
    pub fn version(&self) -> u32 {
        u32::from_le_bytes(self.bytes[..4].try_into().unwrap())
    }
    /// The locktime.
    pub fn locktime(&self) -> u32 {
        u32::from_le_bytes(self.bytes[self.bytes.len() - 4..].try_into().unwrap())
    }
    /// The number of inputs.
    pub fn input_count(&self) -> usize {
        self.layout.input_count
    }
    /// The number of outputs.
    pub fn output_count(&self) -> usize {
        self.layout.output_count
    }
    /// The inputs (with empty scriptSigs and witnesses).
    pub fn inputs(&self) -> impl Iterator<Item = RawTxIn<'a>> + 'a {
        tx_inputs(self.bytes, &self.layout)
    }
    /// The outputs.
    pub fn outputs(&self) -> impl Iterator<Item = RawTxOut<'a>> + 'a {
        tx_outputs(self.bytes, &self.layout)
    }
    /// The txid of the transaction once finalized (scriptSigs and witnesses
    /// do not change it for segwit spends, but do for legacy ones).
    pub fn txid(&self) -> [u8; 32] {
        tx_txid(self.bytes, &self.layout)
    }
}

impl TxSource for UnsignedTx<'_> {
    fn version(&self) -> u32 {
        UnsignedTx::version(self)
    }
    fn locktime(&self) -> u32 {
        UnsignedTx::locktime(self)
    }
    fn input_count(&self) -> usize {
        self.layout.input_count
    }
    fn for_each_input(&self, f: &mut dyn FnMut(&RawTxIn<'_>)) {
        self.inputs().for_each(|i| f(&i))
    }
    fn for_each_output(&self, f: &mut dyn FnMut(&RawTxOut<'_>)) {
        self.outputs().for_each(|o| f(&o))
    }
}

// --- maps ---

/// A key-value record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    /// The full key: the compact-size key type followed by the key data.
    pub key: &'a [u8],
    /// The value.
    pub value: &'a [u8],
}

impl<'a> Record<'a> {
    /// The key type.
    pub fn key_type(&self) -> u64 {
        Reader::new(self.key).varint().unwrap_or(u64::MAX)
    }
    /// The key data following the key type.
    pub fn key_data(&self) -> &'a [u8] {
        let (_, n) = BtcVarInt::decode(self.key).unwrap_or((BtcVarInt(0), self.key.len()));
        &self.key[n..]
    }
}

/// A PSBT key-value map.
#[derive(Debug, Clone, Copy)]
pub struct Map<'a> {
    /// The encoded records, without the terminating 0x00.
    bytes: &'a [u8],
}

impl<'a> Map<'a> {
    /// Reads one map (including its terminator), checking only the framing.
    fn read(r: &mut Reader<'a>) -> Result<Map<'a>, Error> {
        let start = r.pos;
        loop {
            let at = r.pos;
            let key = r.var_bytes()?;
            if key.is_empty() {
                return Ok(Map {
                    bytes: &r.buf[start..at],
                });
            }
            Reader::new(key).varint()?;
            r.var_bytes()?;
        }
    }

    /// The records, in encoded order.
    pub fn records(&self) -> impl Iterator<Item = Record<'a>> + 'a {
        let mut r = Reader::new(self.bytes);
        core::iter::from_fn(move || {
            if r.is_empty() {
                return None;
            }
            let key = r.var_bytes().ok()?;
            let value = r.var_bytes().ok()?;
            Some(Record { key, value })
        })
    }

    /// The records of one key type.
    pub fn records_of(&self, key_type: u64) -> impl Iterator<Item = Record<'a>> + 'a {
        self.records().filter(move |r| r.key_type() == key_type)
    }

    /// The value of the record with the given full key.
    pub fn get(&self, key: &[u8]) -> Option<&'a [u8]> {
        self.records().find(|r| r.key == key).map(|r| r.value)
    }

    /// The value of the (key-data-less) record of `key_type`.
    pub fn get_type(&self, key_type: u64) -> Option<&'a [u8]> {
        self.records_of(key_type)
            .find(|r| r.key_data().is_empty())
            .map(|r| r.value)
    }

    fn contains_key(&self, key: &[u8]) -> bool {
        self.records().any(|r| r.key == key)
    }

    fn check_duplicates(&self) -> Result<(), Error> {
        for (i, a) in self.records().enumerate() {
            if self.records().skip(i + 1).any(|b| b.key == a.key) {
                return Err(Error::DuplicateKey);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MapKind {
    Global,
    Input,
    Output,
}

fn is_pubkey(data: &[u8]) -> bool {
    matches!(data.len(), 33 | 65) && SecpPublicKey::from_sec1(data).is_ok()
}

fn is_derivation_path(value: &[u8]) -> bool {
    value.len() >= 4 && value.len().is_multiple_of(4)
}

/// Checks a record's key data and value against BIP-174 for its map.
fn validate_record(kind: MapKind, rec: &Record<'_>) -> Result<(), Error> {
    let data = rec.key_data();
    let value = rec.value;
    let no_key_data = || {
        if data.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidRecordKey)
        }
    };
    let check = |ok: bool| {
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidRecordValue)
        }
    };
    match (kind, rec.key_type()) {
        (MapKind::Global, global::UNSIGNED_TX) => no_key_data(),
        (MapKind::Global, global::XPUB) => {
            if data.len() != 78 {
                return Err(Error::InvalidRecordKey);
            }
            check(is_derivation_path(value))
        }
        (MapKind::Global, global::VERSION) => {
            no_key_data()?;
            match value {
                [0, 0, 0, 0] => Ok(()),
                [_, _, _, _] => Err(Error::UnsupportedPsbtVersion),
                _ => Err(Error::InvalidRecordValue),
            }
        }
        // PSBTv2-only global fields
        (MapKind::Global, 0x02..=0x06) => Err(Error::InvalidRecordKey),
        (MapKind::Input, input::NON_WITNESS_UTXO) => {
            no_key_data()?;
            TxLayout::parse(value, true).map(|_| ())
        }
        (MapKind::Input, input::WITNESS_UTXO) => {
            no_key_data()?;
            let mut r = Reader::new(value);
            r.u64()?;
            r.var_bytes()?;
            check(r.is_empty())
        }
        (MapKind::Input, input::PARTIAL_SIG) => {
            if !is_pubkey(data) {
                return Err(Error::InvalidRecordKey);
            }
            check(!value.is_empty())
        }
        (MapKind::Input, input::SIGHASH_TYPE) => {
            no_key_data()?;
            check(value.len() == 4)
        }
        (MapKind::Input, input::REDEEM_SCRIPT | input::WITNESS_SCRIPT | input::FINAL_SCRIPTSIG) => {
            no_key_data()
        }
        (MapKind::Input, input::BIP32_DERIVATION) | (MapKind::Output, output::BIP32_DERIVATION) => {
            if !is_pubkey(data) {
                return Err(Error::InvalidRecordKey);
            }
            check(is_derivation_path(value))
        }
        (MapKind::Input, input::FINAL_SCRIPTWITNESS) => {
            no_key_data()?;
            let mut r = Reader::new(value);
            for _ in 0..r.varint()? {
                r.var_bytes()?;
            }
            check(r.is_empty())
        }
        (MapKind::Input, input::RIPEMD160 | input::HASH160) => {
            check(data.len() == 20).map_err(|_| Error::InvalidRecordKey)
        }
        (MapKind::Input, input::SHA256 | input::HASH256) => {
            check(data.len() == 32).map_err(|_| Error::InvalidRecordKey)
        }
        // PSBTv2-only input fields
        (MapKind::Input, 0x0e..=0x12) => Err(Error::InvalidRecordKey),
        (MapKind::Input, input::TAP_KEY_SIG) => {
            no_key_data()?;
            check(matches!(value.len(), 64 | 65))
        }
        (MapKind::Input, input::TAP_SCRIPT_SIG) => {
            if data.len() != 64 {
                return Err(Error::InvalidRecordKey);
            }
            check(matches!(value.len(), 64 | 65))
        }
        (MapKind::Input, input::TAP_LEAF_SCRIPT) => {
            if data.len() < 33 || !(data.len() - 33).is_multiple_of(32) {
                return Err(Error::InvalidRecordKey);
            }
            check(!value.is_empty())
        }
        (MapKind::Input, input::TAP_BIP32_DERIVATION)
        | (MapKind::Output, output::TAP_BIP32_DERIVATION) => {
            if data.len() != 32 {
                return Err(Error::InvalidRecordKey);
            }
            let mut r = Reader::new(value);
            let hashes = r.varint()?;
            r.take(
                usize::try_from(hashes)
                    .map_err(|_| Error::InvalidRecordValue)?
                    .saturating_mul(32),
            )?;
            check(is_derivation_path(&value[r.pos..]))
        }
        (MapKind::Input, input::TAP_INTERNAL_KEY | input::TAP_MERKLE_ROOT)
        | (MapKind::Output, output::TAP_INTERNAL_KEY) => {
            no_key_data()?;
            check(value.len() == 32)
        }
        (MapKind::Output, output::REDEEM_SCRIPT | output::WITNESS_SCRIPT | output::TAP_TREE) => {
            no_key_data()
        }
        // PSBTv2-only output fields
        (MapKind::Output, 0x03 | 0x04) => Err(Error::InvalidRecordKey),
        (_, 0xfc) => Reader::new(data)
            .var_bytes()
            .map(|_| ())
            .map_err(|_| Error::InvalidRecordKey),
        _ => Ok(()),
    }
}

fn validate_map(kind: MapKind, map: &Map<'_>) -> Result<(), Error> {
    map.check_duplicates()?;
    map.records().try_for_each(|r| validate_record(kind, &r))
}

// --- the PSBT ---

/// A validated, zero-copy view of a version-0 PSBT.
#[derive(Debug, Clone, Copy)]
pub struct Psbt<'a> {
    bytes: &'a [u8],
    global: Map<'a>,
    tx: UnsignedTx<'a>,
    /// Offset of the first input map.
    inputs_at: usize,
}

/// Writes one map (records and terminator) of a PSBT being rewritten.
pub(crate) type MapWriter<'f, 'a> =
    dyn FnMut(MapLoc, Map<'a>, &mut dyn Sink) -> Result<(), Error> + 'f;

/// Where a map sits in a PSBT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MapLoc {
    Global,
    Input(usize),
    Output(usize),
}

impl<'a> Psbt<'a> {
    /// Parses and fully validates a binary PSBT.
    pub fn parse(bytes: &'a [u8]) -> Result<Psbt<'a>, Error> {
        if bytes.get(..5) != Some(&MAGIC[..]) {
            return Err(Error::InvalidMagic);
        }
        let mut r = Reader::new(bytes);
        r.pos = 5;
        let global = Map::read(&mut r)?;
        validate_map(MapKind::Global, &global)?;
        let tx_bytes = global
            .get_type(global::UNSIGNED_TX)
            .ok_or(Error::MissingUnsignedTx)?;
        let layout = TxLayout::parse(tx_bytes, false).map_err(|_| Error::InvalidUnsignedTx)?;
        if !layout.unsigned {
            return Err(Error::InvalidUnsignedTx);
        }
        let inputs_at = r.pos;
        for _ in 0..layout.input_count {
            validate_map(MapKind::Input, &Map::read(&mut r)?)?;
        }
        for _ in 0..layout.output_count {
            validate_map(MapKind::Output, &Map::read(&mut r)?)?;
        }
        if !r.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(Psbt {
            bytes,
            global,
            tx: UnsignedTx {
                bytes: tx_bytes,
                layout,
            },
            inputs_at,
        })
    }

    /// Decodes a base64 PSBT into `buf` (
    /// [`base64::decoded_len_bound`]`(text.len())` bytes suffice) and parses it.
    pub fn from_base64(text: &str, buf: &'a mut [u8]) -> Result<Psbt<'a>, Error> {
        let n = base64::decode_to_slice(text, buf)?;
        let buf: &'a [u8] = buf;
        Psbt::parse(&buf[..n])
    }

    /// The binary PSBT.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The binary length.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Writes the base64 encoding into `out` ([`base64::encoded_len`]`(self.len())`
    /// bytes), returning the number of bytes written.
    pub fn encode_base64_to_slice(&self, out: &mut [u8]) -> Result<usize, Error> {
        Ok(base64::encode_to_slice(self.bytes, out)?)
    }

    /// The global map.
    pub fn global(&self) -> Map<'a> {
        self.global
    }

    /// The unsigned transaction.
    pub fn unsigned_tx(&self) -> UnsignedTx<'a> {
        self.tx
    }

    /// The input maps followed by the output maps.
    fn maps(&self) -> impl Iterator<Item = Map<'a>> + 'a {
        let mut r = Reader::new(self.bytes);
        r.pos = self.inputs_at;
        let count = self.tx.input_count() + self.tx.output_count();
        (0..count).map_while(move |_| Map::read(&mut r).ok())
    }

    /// The input maps.
    pub fn inputs(&self) -> impl Iterator<Item = PsbtInput<'a>> + 'a {
        self.maps().take(self.tx.input_count()).map(PsbtInput)
    }

    /// The output maps.
    pub fn outputs(&self) -> impl Iterator<Item = PsbtOutput<'a>> + 'a {
        self.maps().skip(self.tx.input_count()).map(PsbtOutput)
    }

    /// Input map `index`.
    pub fn input(&self, index: usize) -> Option<PsbtInput<'a>> {
        self.inputs().nth(index)
    }

    /// Output map `index`.
    pub fn output(&self, index: usize) -> Option<PsbtOutput<'a>> {
        self.outputs().nth(index)
    }

    /// Reports whether every input has a final scriptSig or witness.
    pub fn is_finalized(&self) -> bool {
        self.inputs().all(|i| i.is_finalized())
    }

    /// The output spent by input `index`, from its non-witness UTXO (checked
    /// against the outpoint's txid) or witness UTXO.
    pub fn utxo(&self, index: usize) -> Result<RawTxOut<'a>, Error> {
        let inp = self.input(index).ok_or(Error::InputIndex)?;
        let outpoint = self.tx.inputs().nth(index).ok_or(Error::InputIndex)?;
        if let Some(prev) = inp.map().get_type(input::NON_WITNESS_UTXO) {
            let layout = TxLayout::parse(prev, true)?;
            if tx_txid(prev, &layout) != outpoint.txid {
                return Err(Error::UtxoTxidMismatch);
            }
            return tx_outputs(prev, &layout)
                .nth(outpoint.vout as usize)
                .ok_or(Error::InvalidRecordValue);
        }
        inp.witness_utxo().ok_or(Error::MissingUtxo)
    }

    // --- writing ---

    /// Streams a PSBT with each map written by `f` (which must write the
    /// map's records and terminator, typically via [`write_map`]).
    fn write(&self, s: &mut dyn Sink, f: &mut MapWriter<'_, 'a>) -> Result<(), Error> {
        s.put(&MAGIC);
        f(MapLoc::Global, self.global, s)?;
        let n_in = self.tx.input_count();
        for (i, map) in self.maps().enumerate() {
            let loc = if i < n_in {
                MapLoc::Input(i)
            } else {
                MapLoc::Output(i - n_in)
            };
            f(loc, map, s)?;
        }
        Ok(())
    }

    /// Runs a writer into `out`, then validates the result.
    fn emit(&self, out: &mut [u8], f: &mut MapWriter<'_, 'a>) -> Result<usize, Error> {
        let mut sink = SliceSink::new(out);
        self.write(&mut sink, f)?;
        let n = sink.finish().ok_or(Error::BufferTooSmall)?;
        Psbt::parse(&out[..n])?;
        Ok(n)
    }

    /// Writes a copy of this PSBT with `edit` applied to one map.
    fn edit_map(&self, out: &mut [u8], at: MapLoc, edit: MapEdit<'_, 'a>) -> Result<usize, Error> {
        match at {
            MapLoc::Input(i) if i >= self.tx.input_count() => return Err(Error::InputIndex),
            MapLoc::Output(i) if i >= self.tx.output_count() => return Err(Error::OutputIndex),
            _ => {}
        }
        self.emit(out, &mut |loc, map, s| {
            if loc == at {
                write_map(s, map, &edit);
            } else {
                write_map(s, map, &MapEdit::none());
            }
            Ok(())
        })
    }

    // --- creator ---

    /// Writes a new PSBT for `tx`, whose scriptSigs and witnesses must be
    /// empty, into `out`. [`Psbt::create_len`] gives the exact size.
    pub fn create_to_slice(tx: &RawTx<'_>, out: &mut [u8]) -> Result<usize, Error> {
        let mut sink = SliceSink::new(out);
        create(tx, &mut sink)?;
        let n = sink.finish().ok_or(Error::BufferTooSmall)?;
        Psbt::parse(&out[..n])?;
        Ok(n)
    }

    /// The size of the PSBT [`Psbt::create_to_slice`] writes.
    pub fn create_len(tx: &RawTx<'_>) -> Result<usize, Error> {
        let mut c = Counter::default();
        create(tx, &mut c)?;
        Ok(c.0)
    }

    // --- updater ---

    /// Writes a copy with the record `key` (compact-size type followed by key
    /// data) of input `index` set to `value`, replacing any existing record
    /// with that key. At most `self.len() + key.len() + value.len() + 18`
    /// bytes are written.
    pub fn set_input_record(
        &self,
        index: usize,
        key: &[u8],
        value: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let add = [NewRecord {
            key_tail: &[],
            key,
            value: &value,
        }];
        self.edit_map(out, MapLoc::Input(index), MapEdit::add(&add))
    }

    /// Writes a copy with the record `key` removed from input `index`.
    pub fn remove_input_record(
        &self,
        index: usize,
        key: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let drop = |r: &Record<'_>| r.key != key;
        self.edit_map(out, MapLoc::Input(index), MapEdit::keep(&drop))
    }

    /// Writes a copy with the record `key` of output `index` set to `value`.
    pub fn set_output_record(
        &self,
        index: usize,
        key: &[u8],
        value: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let add = [NewRecord {
            key_tail: &[],
            key,
            value: &value,
        }];
        self.edit_map(out, MapLoc::Output(index), MapEdit::add(&add))
    }

    /// Writes a copy with the record `key` removed from output `index`.
    pub fn remove_output_record(
        &self,
        index: usize,
        key: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let drop = |r: &Record<'_>| r.key != key;
        self.edit_map(out, MapLoc::Output(index), MapEdit::keep(&drop))
    }

    /// Writes a copy with the global record `key` set to `value`.
    pub fn set_global_record(
        &self,
        key: &[u8],
        value: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let add = [NewRecord {
            key_tail: &[],
            key,
            value: &value,
        }];
        self.edit_map(out, MapLoc::Global, MapEdit::add(&add))
    }

    /// Writes a copy with input `index`'s witness UTXO set.
    pub fn set_witness_utxo(
        &self,
        index: usize,
        amount: u64,
        script_pubkey: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let value = WitnessUtxoValue {
            amount,
            script: script_pubkey,
        };
        let add = [NewRecord {
            key_tail: &[],
            key: &[input::WITNESS_UTXO as u8],
            value: &value,
        }];
        self.edit_map(out, MapLoc::Input(index), MapEdit::add(&add))
    }

    /// Writes a copy with input `index`'s non-witness UTXO (the full previous
    /// transaction) set.
    pub fn set_non_witness_utxo(
        &self,
        index: usize,
        prev_tx: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.set_input_record(index, &[input::NON_WITNESS_UTXO as u8], prev_tx, out)
    }

    /// Writes a copy with input `index`'s redeem script set.
    pub fn set_redeem_script(
        &self,
        index: usize,
        script: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.set_input_record(index, &[input::REDEEM_SCRIPT as u8], script, out)
    }

    /// Writes a copy with input `index`'s witness script set.
    pub fn set_witness_script(
        &self,
        index: usize,
        script: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.set_input_record(index, &[input::WITNESS_SCRIPT as u8], script, out)
    }

    /// Writes a copy with input `index`'s sighash type set.
    pub fn set_sighash_type(
        &self,
        index: usize,
        sighash_type: u32,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.set_input_record(
            index,
            &[input::SIGHASH_TYPE as u8],
            &sighash_type.to_le_bytes(),
            out,
        )
    }

    /// Writes a copy recording that `pubkey` (33 or 65 bytes) of input `index`
    /// derives from the master key with `fingerprint` along `path`.
    pub fn add_input_bip32_derivation(
        &self,
        index: usize,
        pubkey: &[u8],
        fingerprint: [u8; 4],
        path: &[u32],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut key = [0u8; 66];
        key[0] = input::BIP32_DERIVATION as u8;
        let key = key_with_data(&mut key, pubkey)?;
        let value = DerivationValue { fingerprint, path };
        let add = [NewRecord {
            key_tail: &[],
            key,
            value: &value,
        }];
        self.edit_map(out, MapLoc::Input(index), MapEdit::add(&add))
    }

    /// Writes a copy recording that `pubkey` (33 or 65 bytes) of output
    /// `index` derives from the master key with `fingerprint` along `path`.
    pub fn add_output_bip32_derivation(
        &self,
        index: usize,
        pubkey: &[u8],
        fingerprint: [u8; 4],
        path: &[u32],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut key = [0u8; 66];
        key[0] = output::BIP32_DERIVATION as u8;
        let key = key_with_data(&mut key, pubkey)?;
        let value = DerivationValue { fingerprint, path };
        let add = [NewRecord {
            key_tail: &[],
            key,
            value: &value,
        }];
        self.edit_map(out, MapLoc::Output(index), MapEdit::add(&add))
    }

    /// Writes a copy with input `index`'s taproot internal key set.
    pub fn set_tap_internal_key(
        &self,
        index: usize,
        key: &[u8; 32],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.set_input_record(index, &[input::TAP_INTERNAL_KEY as u8], key, out)
    }

    /// Writes a copy with input `index`'s taproot merkle root set: the root of
    /// the script tree its output commits to (see
    /// [`tap_tree_root`](crate::taproot::tap_tree_root)). Signers need it to
    /// sign the key path of such an output.
    pub fn set_tap_merkle_root(
        &self,
        index: usize,
        root: &[u8; 32],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.set_input_record(index, &[input::TAP_MERKLE_ROOT as u8], root, out)
    }

    /// Writes a copy with a taproot leaf script added to input `index`: the
    /// `script` with its `control_block` (see
    /// [`control_block_to_slice`](crate::taproot::control_block_to_slice)).
    /// Signers sign the leaves their key appears in, and the finalizer spends
    /// through a leaf that has enough signatures. At most
    /// `self.len() + control_block.len() + script.len() + 20` bytes are
    /// written.
    pub fn add_tap_leaf_script(
        &self,
        index: usize,
        control_block: &[u8],
        script: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let cb = crate::taproot::ControlBlock::parse(control_block)
            .map_err(|_| Error::InvalidRecordKey)?;
        let value = LeafScriptValue {
            script,
            leaf_version: cb.leaf_version,
        };
        let add = [NewRecord {
            key: &[input::TAP_LEAF_SCRIPT as u8],
            key_tail: control_block,
            value: &value,
        }];
        self.edit_map(out, MapLoc::Input(index), MapEdit::add(&add))
    }

    // --- combiner ---

    /// Writes the union of this PSBT and `other` (which must share the
    /// unsigned transaction) into `out`; records already present here win.
    /// `self.len() + other.len()` bytes always suffice.
    pub fn combine_to_slice(&self, other: &Psbt<'_>, out: &mut [u8]) -> Result<usize, Error> {
        if self.tx.bytes != other.tx.bytes {
            return Err(Error::TxMismatch);
        }
        let mut theirs = core::iter::once(other.global).chain(other.maps());
        self.emit(out, &mut |_, map, s| {
            let secondary = theirs.next().ok_or(Error::TxMismatch)?;
            write_map(
                s,
                map,
                &MapEdit {
                    secondary: Some(secondary),
                    ..MapEdit::none()
                },
            );
            Ok(())
        })
    }

    // --- extractor ---

    fn write_extracted(&self, s: &mut dyn Sink) -> Result<(), Error> {
        if !self.is_finalized() {
            return Err(Error::NotFinalized);
        }
        let tx = self.tx.bytes;
        let layout = &self.tx.layout;
        let has_witness = self.inputs().any(|i| i.final_script_witness().is_some());
        s.put(&tx[..4]);
        if has_witness {
            s.put(&[0x00, 0x01]);
        }
        put_varint(s, layout.input_count);
        let mut r = Reader::new(tx);
        r.pos = layout.inputs_at;
        r.varint()?;
        for inp in self.inputs() {
            s.put(r.take(36)?);
            r.var_bytes()?;
            let script_sig = inp.final_script_sig().unwrap_or(&[]);
            put_varint(s, script_sig.len());
            s.put(script_sig);
            s.put(r.take(4)?);
        }
        s.put(&tx[layout.outputs_at..layout.outputs_end]);
        if has_witness {
            for inp in self.inputs() {
                // the record value is already a serialized witness stack
                s.put(inp.final_script_witness().unwrap_or(&[0x00]));
            }
        }
        s.put(&tx[tx.len() - 4..]);
        Ok(())
    }

    /// Writes the final network transaction of a fully finalized PSBT into
    /// `out`. [`Psbt::extracted_tx_len`] gives the exact size.
    pub fn extract_tx_to_slice(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut sink = SliceSink::new(out);
        self.write_extracted(&mut sink)?;
        sink.finish().ok_or(Error::BufferTooSmall)
    }

    /// The size of the transaction [`Psbt::extract_tx_to_slice`] writes.
    pub fn extracted_tx_len(&self) -> Result<usize, Error> {
        let mut c = Counter::default();
        self.write_extracted(&mut c)?;
        Ok(c.0)
    }
}

fn create(tx: &RawTx<'_>, s: &mut dyn Sink) -> Result<(), Error> {
    if tx
        .inputs
        .iter()
        .any(|i| !i.script_sig.is_empty() || !i.witness.is_empty())
    {
        return Err(Error::InvalidUnsignedTx);
    }
    s.put(&MAGIC);
    put_varint(s, 1);
    s.put(&[global::UNSIGNED_TX as u8]);
    put_varint(s, tx.serialized_len());
    tx.write_unsigned(s);
    s.put(&[0x00]);
    for _ in 0..tx.inputs.len() + tx.outputs.len() {
        s.put(&[0x00]);
    }
    Ok(())
}

fn key_with_data<'k>(key: &'k mut [u8; 66], data: &[u8]) -> Result<&'k [u8], Error> {
    if !matches!(data.len(), 33 | 65) {
        return Err(Error::InvalidRecordKey);
    }
    key[1..=data.len()].copy_from_slice(data);
    Ok(&key[..=data.len()])
}

/// A typed view of an input map.
#[derive(Debug, Clone, Copy)]
pub struct PsbtInput<'a>(Map<'a>);

impl<'a> PsbtInput<'a> {
    /// The raw map.
    pub fn map(&self) -> Map<'a> {
        self.0
    }
    /// The full previous transaction, if present.
    pub fn non_witness_utxo(&self) -> Option<&'a [u8]> {
        self.0.get_type(input::NON_WITNESS_UTXO)
    }
    /// The witness UTXO, if present.
    pub fn witness_utxo(&self) -> Option<RawTxOut<'a>> {
        let mut r = Reader::new(self.0.get_type(input::WITNESS_UTXO)?);
        Some(RawTxOut {
            amount: r.u64().ok()?,
            script: r.var_bytes().ok()?,
        })
    }
    /// The partial signatures as `(pubkey, signature with sighash byte)`.
    pub fn partial_sigs(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        self.0
            .records_of(input::PARTIAL_SIG)
            .map(|r| (r.key_data(), r.value))
    }
    /// The partial signature for `pubkey`.
    pub fn partial_sig(&self, pubkey: &[u8]) -> Option<&'a [u8]> {
        self.partial_sigs()
            .find(|(k, _)| *k == pubkey)
            .map(|(_, v)| v)
    }
    /// The requested sighash type, if present.
    pub fn sighash_type(&self) -> Option<u32> {
        Some(u32::from_le_bytes(
            self.0.get_type(input::SIGHASH_TYPE)?.try_into().ok()?,
        ))
    }
    /// The redeem script, if present.
    pub fn redeem_script(&self) -> Option<&'a [u8]> {
        self.0.get_type(input::REDEEM_SCRIPT)
    }
    /// The witness script, if present.
    pub fn witness_script(&self) -> Option<&'a [u8]> {
        self.0.get_type(input::WITNESS_SCRIPT)
    }
    /// The final scriptSig, if finalized.
    pub fn final_script_sig(&self) -> Option<&'a [u8]> {
        self.0.get_type(input::FINAL_SCRIPTSIG)
    }
    /// The final witness as serialized (item count, then length-prefixed
    /// items), if finalized.
    pub fn final_script_witness(&self) -> Option<&'a [u8]> {
        self.0.get_type(input::FINAL_SCRIPTWITNESS)
    }
    /// The taproot key-path signature, if present.
    pub fn tap_key_sig(&self) -> Option<&'a [u8]> {
        self.0.get_type(input::TAP_KEY_SIG)
    }
    /// The taproot internal key, if present.
    pub fn tap_internal_key(&self) -> Option<[u8; 32]> {
        self.0.get_type(input::TAP_INTERNAL_KEY)?.try_into().ok()
    }
    /// The taproot merkle root, if present.
    pub fn tap_merkle_root(&self) -> Option<[u8; 32]> {
        self.0.get_type(input::TAP_MERKLE_ROOT)?.try_into().ok()
    }
    /// The taproot leaf scripts, each with its control block.
    pub fn tap_leaf_scripts(&self) -> impl Iterator<Item = TapLeafScript<'a>> + 'a {
        self.0.records_of(input::TAP_LEAF_SCRIPT).filter_map(|r| {
            let (&leaf_version, script) = r.value.split_last()?;
            Some(TapLeafScript {
                control_block: r.key_data(),
                script,
                leaf_version,
            })
        })
    }
    /// The taproot script-path signatures as `(x-only pubkey, leaf hash,
    /// signature)`; a non-default sighash type is the signature's 65th byte.
    pub fn tap_script_sigs(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8], &'a [u8])> + 'a {
        self.0.records_of(input::TAP_SCRIPT_SIG).filter_map(|r| {
            let (xonly, leaf_hash) = r.key_data().split_at_checked(32)?;
            Some((xonly, leaf_hash, r.value))
        })
    }
    /// The taproot script-path signature of `xonly_pubkey` for the leaf with
    /// `leaf_hash`.
    pub fn tap_script_sig(
        &self,
        xonly_pubkey: &[u8; 32],
        leaf_hash: &[u8; 32],
    ) -> Option<&'a [u8]> {
        self.tap_script_sigs()
            .find(|(k, l, _)| k == xonly_pubkey && l == leaf_hash)
            .map(|(_, _, sig)| sig)
    }
    /// Reports whether the input has a final scriptSig or witness.
    pub fn is_finalized(&self) -> bool {
        self.final_script_sig().is_some() || self.final_script_witness().is_some()
    }
}

/// A taproot leaf script of an input (`PSBT_IN_TAP_LEAF_SCRIPT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TapLeafScript<'a> {
    /// The control block proving the leaf (see
    /// [`ControlBlock`](crate::taproot::ControlBlock)).
    pub control_block: &'a [u8],
    /// The leaf script.
    pub script: &'a [u8],
    /// The leaf version.
    pub leaf_version: u8,
}

/// A typed view of an output map.
#[derive(Debug, Clone, Copy)]
pub struct PsbtOutput<'a>(Map<'a>);

impl<'a> PsbtOutput<'a> {
    /// The raw map.
    pub fn map(&self) -> Map<'a> {
        self.0
    }
    /// The redeem script, if present.
    pub fn redeem_script(&self) -> Option<&'a [u8]> {
        self.0.get_type(output::REDEEM_SCRIPT)
    }
    /// The witness script, if present.
    pub fn witness_script(&self) -> Option<&'a [u8]> {
        self.0.get_type(output::WITNESS_SCRIPT)
    }
    /// The taproot internal key, if present.
    pub fn tap_internal_key(&self) -> Option<[u8; 32]> {
        self.0.get_type(output::TAP_INTERNAL_KEY)?.try_into().ok()
    }
}

// --- map writing ---

/// A value that streams itself into a sink.
pub(crate) trait WriteValue {
    fn write_value(&self, s: &mut dyn Sink);
}

impl WriteValue for &[u8] {
    fn write_value(&self, s: &mut dyn Sink) {
        s.put(self)
    }
}

impl<const N: usize> WriteValue for [u8; N] {
    fn write_value(&self, s: &mut dyn Sink) {
        s.put(self)
    }
}

impl<const N: usize> WriteValue for crate::inline::InlineBytes<N> {
    fn write_value(&self, s: &mut dyn Sink) {
        s.put(self)
    }
}

/// A `PSBT_IN_TAP_LEAF_SCRIPT` value: the script, then its leaf version.
struct LeafScriptValue<'a> {
    script: &'a [u8],
    leaf_version: u8,
}

impl WriteValue for LeafScriptValue<'_> {
    fn write_value(&self, s: &mut dyn Sink) {
        s.put(self.script);
        s.put(&[self.leaf_version]);
    }
}

struct WitnessUtxoValue<'a> {
    amount: u64,
    script: &'a [u8],
}

impl WriteValue for WitnessUtxoValue<'_> {
    fn write_value(&self, s: &mut dyn Sink) {
        s.put(&self.amount.to_le_bytes());
        put_varint(s, self.script.len());
        s.put(self.script);
    }
}

struct DerivationValue<'a> {
    fingerprint: [u8; 4],
    path: &'a [u32],
}

impl WriteValue for DerivationValue<'_> {
    fn write_value(&self, s: &mut dyn Sink) {
        s.put(&self.fingerprint);
        for step in self.path {
            s.put(&step.to_le_bytes());
        }
    }
}

/// A record to add to a map. Its full key is `key` followed by `key_tail`,
/// so long key data (a taproot control block) need not be copied next to its
/// key type.
pub(crate) struct NewRecord<'x> {
    pub(crate) key: &'x [u8],
    pub(crate) key_tail: &'x [u8],
    pub(crate) value: &'x dyn WriteValue,
}

impl NewRecord<'_> {
    fn has_key(&self, key: &[u8]) -> bool {
        key.len() == self.key.len() + self.key_tail.len()
            && key.starts_with(self.key)
            && key.ends_with(self.key_tail)
    }
}

/// How to rewrite a map: keep a subset of its records, merge in records from
/// another map, and add (or replace) records.
pub(crate) struct MapEdit<'x, 'm> {
    pub(crate) keep: Option<&'x dyn Fn(&Record<'m>) -> bool>,
    pub(crate) secondary: Option<Map<'m>>,
    pub(crate) added: &'x [NewRecord<'x>],
}

impl<'x, 'm> MapEdit<'x, 'm> {
    pub(crate) fn none() -> Self {
        MapEdit {
            keep: None,
            secondary: None,
            added: &[],
        }
    }
    pub(crate) fn add(added: &'x [NewRecord<'x>]) -> Self {
        MapEdit {
            added,
            ..MapEdit::none()
        }
    }
    pub(crate) fn keep(keep: &'x dyn Fn(&Record<'m>) -> bool) -> Self {
        MapEdit {
            keep: Some(keep),
            ..MapEdit::none()
        }
    }
}

fn key_type_of(key: &[u8]) -> u64 {
    Reader::new(key).varint().unwrap_or(u64::MAX)
}

fn put_record(s: &mut dyn Sink, key: &[u8], value: &dyn WriteValue) {
    put_record_split(s, key, &[], value);
}

fn put_record_split(s: &mut dyn Sink, key: &[u8], key_tail: &[u8], value: &dyn WriteValue) {
    let mut c = Counter::default();
    value.write_value(&mut c);
    put_varint(s, key.len() + key_tail.len());
    s.put(key);
    s.put(key_tail);
    put_varint(s, c.0);
    value.write_value(s);
}

/// Writes `map` with `edit` applied, records grouped by ascending key type and
/// in their existing order within a type (kept records, then merged, then
/// added), followed by the terminator.
pub(crate) fn write_map<'m>(s: &mut dyn Sink, map: Map<'m>, edit: &MapEdit<'_, 'm>) {
    let added = |key: &[u8]| edit.added.iter().any(|a| a.has_key(key));
    let primary = |r: &Record<'m>| edit.keep.is_none_or(|k| k(r)) && !added(r.key);
    let secondary = |r: &Record<'m>| !map.contains_key(r.key) && !added(r.key);

    let mut last: Option<u64> = None;
    loop {
        let above = |t: u64| last.is_none_or(|l| t > l);
        let mut next: Option<u64> = None;
        let mut consider = |t: u64| {
            if above(t) && next.is_none_or(|n| t < n) {
                next = Some(t);
            }
        };
        map.records()
            .filter(|r| primary(r))
            .for_each(|r| consider(r.key_type()));
        if let Some(sec) = edit.secondary {
            sec.records()
                .filter(|r| secondary(r))
                .for_each(|r| consider(r.key_type()));
        }
        edit.added.iter().for_each(|a| consider(key_type_of(a.key)));
        let Some(t) = next else { break };

        for r in map.records().filter(|r| r.key_type() == t && primary(r)) {
            put_record(s, r.key, &r.value);
        }
        if let Some(sec) = edit.secondary {
            for r in sec.records().filter(|r| r.key_type() == t && secondary(r)) {
                put_record(s, r.key, &r.value);
            }
        }
        for a in edit.added.iter().filter(|a| key_type_of(a.key) == t) {
            put_record_split(s, a.key, a.key_tail, a.value);
        }
        last = Some(t);
    }
    s.put(&[0x00]);
}

// --- alloc conveniences ---

#[cfg(feature = "alloc")]
fn to_vec(len: usize, f: impl FnOnce(&mut [u8]) -> Result<usize, Error>) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; len];
    let n = f(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

#[cfg(feature = "alloc")]
impl Psbt<'_> {
    /// Decodes a base64 PSBT into bytes (parse them with [`Psbt::parse`]).
    pub fn decode_base64(text: &str) -> Result<Vec<u8>, Error> {
        let bytes = base64::decode(text)?;
        Psbt::parse(&bytes)?;
        Ok(bytes)
    }

    /// The base64 encoding.
    pub fn to_base64(&self) -> String {
        base64::encode(self.bytes)
    }

    /// [`Psbt::create_to_slice`] into a new vector.
    pub fn create_to_vec(tx: &RawTx<'_>) -> Result<Vec<u8>, Error> {
        to_vec(Psbt::create_len(tx)?, |out| Psbt::create_to_slice(tx, out))
    }

    /// [`Psbt::set_input_record`] into a new vector.
    pub fn set_input_record_to_vec(
        &self,
        index: usize,
        key: &[u8],
        value: &[u8],
    ) -> Result<Vec<u8>, Error> {
        to_vec(self.len() + key.len() + value.len() + 18, |out| {
            self.set_input_record(index, key, value, out)
        })
    }

    /// [`Psbt::set_output_record`] into a new vector.
    pub fn set_output_record_to_vec(
        &self,
        index: usize,
        key: &[u8],
        value: &[u8],
    ) -> Result<Vec<u8>, Error> {
        to_vec(self.len() + key.len() + value.len() + 18, |out| {
            self.set_output_record(index, key, value, out)
        })
    }

    /// [`Psbt::set_witness_utxo`] into a new vector.
    pub fn set_witness_utxo_to_vec(
        &self,
        index: usize,
        amount: u64,
        script_pubkey: &[u8],
    ) -> Result<Vec<u8>, Error> {
        to_vec(self.len() + script_pubkey.len() + 30, |out| {
            self.set_witness_utxo(index, amount, script_pubkey, out)
        })
    }

    /// [`Psbt::add_input_bip32_derivation`] into a new vector.
    pub fn add_input_bip32_derivation_to_vec(
        &self,
        index: usize,
        pubkey: &[u8],
        fingerprint: [u8; 4],
        path: &[u32],
    ) -> Result<Vec<u8>, Error> {
        to_vec(self.len() + 90 + 4 * path.len(), |out| {
            self.add_input_bip32_derivation(index, pubkey, fingerprint, path, out)
        })
    }

    /// [`Psbt::combine_to_slice`] into a new vector.
    pub fn combine_to_vec(&self, other: &Psbt<'_>) -> Result<Vec<u8>, Error> {
        to_vec(self.len() + other.len(), |out| {
            self.combine_to_slice(other, out)
        })
    }

    /// [`Psbt::extract_tx_to_slice`] into a new vector.
    pub fn extract_tx_to_vec(&self) -> Result<Vec<u8>, Error> {
        to_vec(self.extracted_tx_len()?, |out| {
            self.extract_tx_to_slice(out)
        })
    }
}

#[cfg(test)]
mod tests;
