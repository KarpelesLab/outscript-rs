//! Zcash v5 transactions (ZIP-225) with transparent inputs and outputs, and
//! their ZIP-244 transaction ids and signature digests.
//!
//! A [`ZcashTx`] borrows its transparent inputs and outputs, and the Sapling
//! and Orchard bundles as raw bytes: shielded proofs and signatures are not
//! produced here, but a transaction that carries them, built elsewhere, can
//! still have its transparent inputs signed and its id computed, as their
//! digests only hash the bundles' fields.
//!
//! The transparent parts follow Bitcoin: P2PKH outputs, ECDSA signatures with
//! a sighash type byte, and `push(sig) push(pubkey)` scriptSigs. What differs
//! is the header (version group and consensus branch ids, expiry height) and
//! the digests, which are personalized BLAKE2b-256 trees rather than double
//! SHA-256.
//!
//! Everything works without `alloc`, into caller buffers.
//!
//! ```
//! use outscript::crypto::secp256k1::SecpPrivateKey;
//! use outscript::zcashtx::{ZcashTx, ZcashTxIn, ZcashTxOut, branch};
//! use outscript::{generate_script, PubKey};
//!
//! let key = SecpPrivateKey::from_bytes(&[7u8; 32]).unwrap();
//! let mine = generate_script(&PubKey::Secp256k1(key.public_key()), "p2pkh").unwrap();
//!
//! let inputs = [ZcashTxIn { txid: [0x11; 32], vout: 1, ..Default::default() }];
//! let outputs = [ZcashTxOut { amount: 90_000, script: &mine }];
//! let tx = ZcashTx {
//!     consensus_branch_id: branch::NU6_1,
//!     expiry_height: 3_200_000,
//!     inputs: &inputs,
//!     outputs: &outputs,
//!     ..Default::default()
//! };
//! // the output each input spends: its amount and scriptPubKey
//! let prevouts = [ZcashTxOut { amount: 100_000, script: &mine }];
//! let mut raw = [0u8; 256];
//! let len = tx.sign_to_slice(&[&key], &prevouts, &mut raw).unwrap();
//! assert!(len > 150);
//! ```

pub use crate::Error;

use crate::btcvarint::BtcVarInt;
use crate::crypto::secp256k1::SecpPrivateKey;
use crate::hash::{Blake2bPersonal, hash160};
#[cfg(feature = "alloc")]
use crate::prelude::*;
use crate::pushbytes::push_bytes_to_slice;
use crate::sink::{Counter, Sink, SliceSink};

/// Consensus branch ids of the network upgrades that use v5 transactions,
/// for [`ZcashTx::consensus_branch_id`]. A transaction is only valid for the
/// upgrade in force when it is mined.
pub mod branch {
    /// NU5 (May 2022).
    pub const NU5: u32 = 0xc2d6_d0b4;
    /// NU6 (November 2024).
    pub const NU6: u32 = 0xc8e7_1055;
    /// NU6.1 (2025).
    pub const NU6_1: u32 = 0x4dec_4df0;
    /// NU6.2 (2026).
    pub const NU6_2: u32 = 0x5437_f330;
}

/// The version field of a v5 transaction: 5, with the overwintered bit.
pub const VERSION_V5: u32 = 0x8000_0005;
/// The version group id of v5 transactions.
pub const VERSION_GROUP_ID_V5: u32 = 0x26a7_270a;

/// Sign every input and output.
pub const SIGHASH_ALL: u8 = 0x01;
/// Sign every input and no output.
pub const SIGHASH_NONE: u8 = 0x02;
/// Sign every input and the output at the input's index.
pub const SIGHASH_SINGLE: u8 = 0x03;
/// Combined with the others: sign only this input.
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// A transparent input.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZcashTxIn<'a> {
    /// Id of the spent transaction, in display (big-endian) byte order.
    pub txid: [u8; 32],
    /// Index of the spent output.
    pub vout: u32,
    /// The scriptSig: empty until signed.
    pub script_sig: &'a [u8],
    /// The sequence number.
    pub sequence: u32,
}

/// A transparent output, and the output an input spends.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZcashTxOut<'a> {
    /// Amount in zatoshis.
    pub amount: u64,
    /// The scriptPubKey.
    pub script: &'a [u8],
}

/// A borrowed v5 transaction.
#[derive(Debug, Clone, Copy)]
pub struct ZcashTx<'a> {
    /// The [`branch`] id of the network upgrade the transaction is for.
    pub consensus_branch_id: u32,
    /// Lock time, as in Bitcoin.
    pub lock_time: u32,
    /// The block height from which the transaction is no longer valid, or 0
    /// for no expiry. Wallets typically set the current height plus 40.
    pub expiry_height: u32,
    /// Transparent inputs.
    pub inputs: &'a [ZcashTxIn<'a>],
    /// Transparent outputs.
    pub outputs: &'a [ZcashTxOut<'a>],
    /// The serialized Sapling bundle (ZIP-225 `nSpendsSapling` onwards), or
    /// empty for none.
    pub sapling: &'a [u8],
    /// The serialized Orchard bundle (ZIP-225 `nActionsOrchard` onwards), or
    /// empty for none.
    pub orchard: &'a [u8],
}

impl Default for ZcashTx<'_> {
    fn default() -> Self {
        ZcashTx {
            consensus_branch_id: branch::NU6_2,
            lock_time: 0,
            expiry_height: 0,
            inputs: &[],
            outputs: &[],
            sapling: &[],
            orchard: &[],
        }
    }
}

/// A personalized BLAKE2b-256 as a byte sink.
struct Digest(Blake2bPersonal);

impl Sink for Digest {
    fn put(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

/// BLAKE2b-256 of whatever `f` writes, personalized with `person`.
fn digest(person: &[u8], f: impl FnOnce(&mut Digest)) -> [u8; 32] {
    let mut d = Digest(Blake2bPersonal::new(32, person));
    f(&mut d);
    d.0.finalize_32()
}

fn put_varint<S: Sink + ?Sized>(s: &mut S, v: usize) {
    let (buf, len) = BtcVarInt(v as u64).to_array();
    s.put(&buf[..len]);
}

fn put_outpoint<S: Sink + ?Sized>(s: &mut S, input: &ZcashTxIn<'_>) {
    let mut txid = input.txid;
    txid.reverse();
    s.put(&txid);
    s.put(&input.vout.to_le_bytes());
}

fn put_output<S: Sink + ?Sized>(s: &mut S, output: &ZcashTxOut<'_>) {
    s.put(&output.amount.to_le_bytes());
    put_varint(s, output.script.len());
    s.put(output.script);
}

/// Reads a compact size and the fixed-size items it counts.
fn take_items<'a>(data: &mut &'a [u8], item_len: usize) -> Result<(usize, &'a [u8]), Error> {
    let (count, n) = BtcVarInt::decode(data).ok_or(Error::UnexpectedEof)?;
    let count = usize::try_from(count.0).map_err(|_| Error::TooLarge)?;
    let len = count.checked_mul(item_len).ok_or(Error::TooLarge)?;
    let items = data.get(n..n + len).ok_or(Error::UnexpectedEof)?;
    *data = &data[n + len..];
    Ok((count, items))
}

fn take<'a>(data: &mut &'a [u8], len: usize) -> Result<&'a [u8], Error> {
    let bytes = data.get(..len).ok_or(Error::UnexpectedEof)?;
    *data = &data[len..];
    Ok(bytes)
}

/// The fields of a Sapling bundle its digest covers.
struct Sapling<'a> {
    spends: &'a [u8],
    outputs: &'a [u8],
    value_balance: &'a [u8],
    anchor: &'a [u8],
}

const SAPLING_SPEND_LEN: usize = 96;
const SAPLING_OUTPUT_LEN: usize = 756;
const ORCHARD_ACTION_LEN: usize = 820;
const PROOF_LEN: usize = 192;
const SIG_LEN: usize = 64;

/// Splits a serialized Sapling bundle into its fields, checking its length.
fn parse_sapling(bundle: &[u8]) -> Result<Sapling<'_>, Error> {
    let data = &mut &*bundle;
    let (n_spends, spends) = take_items(data, SAPLING_SPEND_LEN)?;
    let (n_outputs, outputs) = take_items(data, SAPLING_OUTPUT_LEN)?;
    let (mut value_balance, mut anchor): (&[u8], &[u8]) = (&[], &[]);
    if n_spends + n_outputs > 0 {
        value_balance = take(data, 8)?;
        if n_spends > 0 {
            anchor = take(data, 32)?;
        }
        take(
            data,
            n_spends * (PROOF_LEN + SIG_LEN) + n_outputs * PROOF_LEN + SIG_LEN,
        )?;
    }
    if !data.is_empty() {
        return Err(Error::TrailingData);
    }
    Ok(Sapling {
        spends,
        outputs,
        value_balance,
        anchor,
    })
}

/// The fields of an Orchard bundle its digest covers.
struct Orchard<'a> {
    actions: &'a [u8],
    /// Flags, value balance and anchor, in serialization order.
    trailer: &'a [u8],
}

fn parse_orchard(bundle: &[u8]) -> Result<Orchard<'_>, Error> {
    let data = &mut &*bundle;
    let (n_actions, actions) = take_items(data, ORCHARD_ACTION_LEN)?;
    let mut trailer: &[u8] = &[];
    if n_actions > 0 {
        trailer = take(data, 1 + 8 + 32)?;
        take_items(data, 1)?; // the proof
        take(data, n_actions * SIG_LEN + SIG_LEN)?;
    }
    if !data.is_empty() {
        return Err(Error::TrailingData);
    }
    Ok(Orchard { actions, trailer })
}

/// The ZIP-244 digest of a Sapling bundle.
fn sapling_digest(bundle: &[u8]) -> Result<[u8; 32], Error> {
    let bundle = parse_sapling(bundle)?;
    Ok(digest(b"ZTxIdSaplingHash", |d| {
        if bundle.spends.is_empty() && bundle.outputs.is_empty() {
            return;
        }
        let spends = bundle.spends.as_chunks::<SAPLING_SPEND_LEN>().0;
        d.put(&digest(b"ZTxIdSSpendsHash", |d| {
            if bundle.spends.is_empty() {
                return;
            }
            d.put(&digest(b"ZTxIdSSpendCHash", |d| {
                for spend in spends {
                    d.put(&spend[32..64]); // nullifier
                }
            }));
            d.put(&digest(b"ZTxIdSSpendNHash", |d| {
                for spend in spends {
                    d.put(&spend[..32]); // cv
                    d.put(bundle.anchor);
                    d.put(&spend[64..]); // rk
                }
            }));
        }));
        let outputs = bundle.outputs.as_chunks::<SAPLING_OUTPUT_LEN>().0;
        d.put(&digest(b"ZTxIdSOutputHash", |d| {
            if bundle.outputs.is_empty() {
                return;
            }
            d.put(&digest(b"ZTxIdSOutC__Hash", |d| {
                for output in outputs {
                    d.put(&output[32..96]); // cmu, ephemeral key
                    d.put(&output[96..148]); // the compact part of the ciphertext
                }
            }));
            d.put(&digest(b"ZTxIdSOutM__Hash", |d| {
                for output in outputs {
                    d.put(&output[148..660]); // the memo
                }
            }));
            d.put(&digest(b"ZTxIdSOutN__Hash", |d| {
                for output in outputs {
                    d.put(&output[..32]); // cv
                    d.put(&output[660..]); // the rest of the ciphertext, out ciphertext
                }
            }));
        }));
        d.put(bundle.value_balance);
    }))
}

/// The ZIP-244 digest of an Orchard bundle.
fn orchard_digest(bundle: &[u8]) -> Result<[u8; 32], Error> {
    let bundle = parse_orchard(bundle)?;
    Ok(digest(b"ZTxIdOrchardHash", |d| {
        if bundle.actions.is_empty() {
            return;
        }
        let actions = bundle.actions.as_chunks::<ORCHARD_ACTION_LEN>().0;
        d.put(&digest(b"ZTxIdOrcActCHash", |d| {
            for action in actions {
                d.put(&action[32..64]); // nullifier
                d.put(&action[96..160]); // cmx, ephemeral key
                d.put(&action[160..212]); // the compact part of the ciphertext
            }
        }));
        d.put(&digest(b"ZTxIdOrcActMHash", |d| {
            for action in actions {
                d.put(&action[212..724]); // the memo
            }
        }));
        d.put(&digest(b"ZTxIdOrcActNHash", |d| {
            for action in actions {
                d.put(&action[..32]); // cv
                d.put(&action[64..96]); // rk
                d.put(&action[724..]); // the rest of the ciphertext, out ciphertext
            }
        }));
        d.put(bundle.trailer);
    }))
}

/// The empty bundles, as serialized.
const NO_SAPLING: &[u8] = &[0, 0];
const NO_ORCHARD: &[u8] = &[0];

/// The longest scriptSig [`ZcashTx::sign_input_to_slice`] writes: a DER
/// signature with its sighash byte and an uncompressed key, each pushed.
pub const MAX_SCRIPT_SIG_LEN: usize = 1 + 73 + 1 + 65;

impl<'a> ZcashTx<'a> {
    fn sapling(&self) -> &[u8] {
        if self.sapling.is_empty() {
            NO_SAPLING
        } else {
            self.sapling
        }
    }

    fn orchard(&self) -> &[u8] {
        if self.orchard.is_empty() {
            NO_ORCHARD
        } else {
            self.orchard
        }
    }

    fn write_header<S: Sink + ?Sized>(&self, s: &mut S) {
        s.put(&VERSION_V5.to_le_bytes());
        s.put(&VERSION_GROUP_ID_V5.to_le_bytes());
        s.put(&self.consensus_branch_id.to_le_bytes());
        s.put(&self.lock_time.to_le_bytes());
        s.put(&self.expiry_height.to_le_bytes());
    }

    fn write_input<S: Sink + ?Sized>(input: &ZcashTxIn<'_>, script_sig: &[u8], s: &mut S) {
        put_outpoint(s, input);
        put_varint(s, script_sig.len());
        s.put(script_sig);
        s.put(&input.sequence.to_le_bytes());
    }

    fn write_outputs_and_bundles<S: Sink + ?Sized>(&self, s: &mut S) {
        put_varint(s, self.outputs.len());
        for output in self.outputs {
            put_output(s, output);
        }
        s.put(self.sapling());
        s.put(self.orchard());
    }

    /// Writes the whole transaction to `s`.
    fn write<S: Sink + ?Sized>(&self, s: &mut S) {
        self.write_header(s);
        put_varint(s, self.inputs.len());
        for input in self.inputs {
            Self::write_input(input, input.script_sig, s);
        }
        self.write_outputs_and_bundles(s);
    }

    /// The serialized length.
    pub fn serialized_len(&self) -> usize {
        let mut c = Counter::default();
        self.write(&mut c);
        c.0
    }

    /// Serializes the transaction into `out`, returning the number of bytes
    /// written.
    pub fn serialize_to_slice(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut s = SliceSink::new(out);
        self.write(&mut s);
        s.finish().ok_or(Error::BufferTooSmall)
    }

    /// Serializes the transaction.
    #[cfg(feature = "alloc")]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.serialized_len()];
        self.serialize_to_slice(&mut out)
            .expect("buffer sized by serialized_len");
        out
    }

    /// Parses a serialized v5 transaction, placing its transparent inputs and
    /// outputs in the given buffers, which must be large enough
    /// ([`Error::TooLarge`] otherwise). The scriptSigs and bundles are
    /// borrowed from `data`.
    pub fn parse_into<'b>(
        data: &'a [u8],
        inputs: &'b mut [ZcashTxIn<'a>],
        outputs: &'b mut [ZcashTxOut<'a>],
    ) -> Result<ZcashTx<'b>, Error>
    where
        'a: 'b,
    {
        let rest = &mut &*data;
        let mut word = || -> Result<u32, Error> {
            let bytes = take(rest, 4)?;
            Ok(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
        };
        if word()? != VERSION_V5 {
            return Err(Error::UnsupportedTxType);
        }
        if word()? != VERSION_GROUP_ID_V5 {
            return Err(Error::UnsupportedTxType);
        }
        let consensus_branch_id = word()?;
        let lock_time = word()?;
        let expiry_height = word()?;

        let (n_inputs, _) = take_items(rest, 0)?;
        let inputs = inputs.get_mut(..n_inputs).ok_or(Error::TooLarge)?;
        for input in inputs.iter_mut() {
            let mut txid: [u8; 32] = take(rest, 32)?.try_into().expect("32 bytes");
            txid.reverse();
            let vout = u32::from_le_bytes(take(rest, 4)?.try_into().expect("4 bytes"));
            let (_, script_sig) = take_items(rest, 1)?;
            let sequence = u32::from_le_bytes(take(rest, 4)?.try_into().expect("4 bytes"));
            *input = ZcashTxIn {
                txid,
                vout,
                script_sig,
                sequence,
            };
        }
        let (n_outputs, _) = take_items(rest, 0)?;
        let outputs = outputs.get_mut(..n_outputs).ok_or(Error::TooLarge)?;
        for output in outputs.iter_mut() {
            let amount = u64::from_le_bytes(take(rest, 8)?.try_into().expect("8 bytes"));
            let (_, script) = take_items(rest, 1)?;
            *output = ZcashTxOut { amount, script };
        }

        // the bundles: parsed to find their ends, kept as bytes
        let sapling_start = data.len() - rest.len();
        let sapling = &mut &**rest;
        let (n_spends, _) = take_items(sapling, SAPLING_SPEND_LEN)?;
        let (n_outputs, _) = take_items(sapling, SAPLING_OUTPUT_LEN)?;
        if n_spends + n_outputs > 0 {
            take(sapling, 8 + if n_spends > 0 { 32 } else { 0 })?;
            take(
                sapling,
                n_spends * (PROOF_LEN + SIG_LEN) + n_outputs * PROOF_LEN + SIG_LEN,
            )?;
        }
        let sapling_end = data.len() - sapling.len();
        *rest = sapling;
        let orchard = &mut &**rest;
        let (n_actions, _) = take_items(orchard, ORCHARD_ACTION_LEN)?;
        if n_actions > 0 {
            take(orchard, 1 + 8 + 32)?;
            take_items(orchard, 1)?;
            take(orchard, n_actions * SIG_LEN + SIG_LEN)?;
        }
        let orchard_end = data.len() - orchard.len();
        if orchard_end != data.len() {
            return Err(Error::TrailingData);
        }
        let sapling = &data[sapling_start..sapling_end];
        let orchard = &data[sapling_end..orchard_end];
        Ok(ZcashTx {
            consensus_branch_id,
            lock_time,
            expiry_height,
            inputs,
            outputs,
            sapling: if sapling == NO_SAPLING { &[] } else { sapling },
            orchard: if orchard == NO_ORCHARD { &[] } else { orchard },
        })
    }

    /// Whether this is a coinbase transaction: one input spending nothing.
    fn is_coinbase(&self) -> bool {
        matches!(self.inputs, [input] if input.txid == [0; 32] && input.vout == u32::MAX)
    }

    fn header_digest(&self) -> [u8; 32] {
        digest(b"ZTxIdHeadersHash", |d| self.write_header(d))
    }

    fn prevouts_digest(&self) -> [u8; 32] {
        digest(b"ZTxIdPrevoutHash", |d| {
            for input in self.inputs {
                put_outpoint(d, input);
            }
        })
    }

    fn sequence_digest(&self) -> [u8; 32] {
        digest(b"ZTxIdSequencHash", |d| {
            for input in self.inputs {
                d.put(&input.sequence.to_le_bytes());
            }
        })
    }

    fn outputs_digest(&self, outputs: &[ZcashTxOut<'_>]) -> [u8; 32] {
        digest(b"ZTxIdOutputsHash", |d| {
            for output in outputs {
                put_output(d, output);
            }
        })
    }

    /// The transparent digest of the transaction id.
    fn transparent_digest(&self) -> [u8; 32] {
        digest(b"ZTxIdTranspaHash", |d| {
            if self.inputs.is_empty() && self.outputs.is_empty() {
                return;
            }
            d.put(&self.prevouts_digest());
            d.put(&self.sequence_digest());
            d.put(&self.outputs_digest(self.outputs));
        })
    }

    /// The transaction id, in display (big-endian) byte order.
    pub fn txid(&self) -> Result<[u8; 32], Error> {
        let mut id = self.tx_digest(self.transparent_digest())?;
        id.reverse();
        Ok(id)
    }

    /// The ZIP-244 digest tree with the given transparent digest.
    fn tx_digest(&self, transparent: [u8; 32]) -> Result<[u8; 32], Error> {
        let sapling = sapling_digest(self.sapling())?;
        let orchard = orchard_digest(self.orchard())?;
        let mut person = *b"ZcashTxHash_\0\0\0\0";
        person[12..].copy_from_slice(&self.consensus_branch_id.to_le_bytes());
        Ok(digest(&person, |d| {
            d.put(&self.header_digest());
            d.put(&transparent);
            d.put(&sapling);
            d.put(&orchard);
        }))
    }

    /// The ZIP-244 signature digest of transparent input `index` for
    /// `hash_type`, given the outputs the inputs spend: `prevouts[i]` is what
    /// `inputs[i]` spends. With [`SIGHASH_ANYONECANPAY`], only the spent
    /// output of `index` is needed and `prevouts` may stop there.
    ///
    /// A `None` index gives the digest that shielded spends and the binding
    /// signatures sign, which only exists for [`SIGHASH_ALL`] and still
    /// commits to every transparent input's spent output.
    pub fn sighash(
        &self,
        index: Option<usize>,
        hash_type: u8,
        prevouts: &[ZcashTxOut<'_>],
    ) -> Result<[u8; 32], Error> {
        let anyone_can_pay = hash_type & SIGHASH_ANYONECANPAY != 0;
        let base = hash_type & !SIGHASH_ANYONECANPAY;
        if !matches!(base, SIGHASH_ALL | SIGHASH_NONE | SIGHASH_SINGLE) {
            return Err(Error::UnsupportedSighash);
        }
        if let Some(index) = index {
            if index >= self.inputs.len() {
                return Err(Error::InputIndex);
            }
            if base == SIGHASH_SINGLE && index >= self.outputs.len() {
                return Err(Error::OutputIndex);
            }
        } else if hash_type != SIGHASH_ALL {
            return Err(Error::UnsupportedSighash);
        }
        // Nothing transparent is spent: the digest is the transaction id's.
        if self.inputs.is_empty() || self.is_coinbase() {
            return self.tx_digest(self.transparent_digest());
        }
        if index.is_some_and(|index| index >= prevouts.len())
            || !anyone_can_pay && prevouts.len() != self.inputs.len()
        {
            return Err(Error::PrevOutCount);
        }
        let transparent = digest(b"ZTxIdTranspaHash", |d| {
            d.put(&[hash_type]);
            d.put(&if anyone_can_pay {
                digest(b"ZTxIdPrevoutHash", |_| {})
            } else {
                self.prevouts_digest()
            });
            d.put(&digest(b"ZTxTrAmountsHash", |d| {
                if !anyone_can_pay {
                    for prevout in prevouts {
                        d.put(&prevout.amount.to_le_bytes());
                    }
                }
            }));
            d.put(&digest(b"ZTxTrScriptsHash", |d| {
                if !anyone_can_pay {
                    for prevout in prevouts {
                        put_varint(d, prevout.script.len());
                        d.put(prevout.script);
                    }
                }
            }));
            d.put(&if anyone_can_pay {
                digest(b"ZTxIdSequencHash", |_| {})
            } else {
                self.sequence_digest()
            });
            d.put(&match (base, index) {
                (SIGHASH_NONE, _) => self.outputs_digest(&[]),
                (SIGHASH_SINGLE, Some(index)) => {
                    self.outputs_digest(&self.outputs[index..index + 1])
                }
                _ => self.outputs_digest(self.outputs),
            });
            d.put(&digest(b"Zcash___TxInHash", |d| {
                if let Some(index) = index {
                    put_outpoint(d, &self.inputs[index]);
                    put_output(d, &prevouts[index]);
                    d.put(&self.inputs[index].sequence.to_le_bytes());
                }
            }));
        });
        self.tx_digest(transparent)
    }

    /// Signs transparent input `index`, which must spend a P2PKH output of
    /// `key`, writing its scriptSig into `out` (at most
    /// [`MAX_SCRIPT_SIG_LEN`] bytes). Returns the number of bytes written.
    pub fn sign_input_to_slice(
        &self,
        index: usize,
        key: &SecpPrivateKey,
        hash_type: u8,
        prevouts: &[ZcashTxOut<'_>],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let prevout = prevouts.get(index).ok_or(Error::PrevOutCount)?;
        let pk_hash: [u8; 20] = match prevout.script {
            [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => {
                hash.try_into().expect("20 bytes")
            }
            _ => return Err(Error::UnsupportedScript),
        };
        let public = key.public_key();
        let compressed = public.serialize_compressed();
        let uncompressed = public.serialize_uncompressed();
        let pubkey: &[u8] = if hash160(&compressed) == pk_hash {
            &compressed
        } else if hash160(&uncompressed) == pk_hash {
            &uncompressed
        } else {
            return Err(Error::KeyNotInvolved);
        };

        let sighash = self.sighash(Some(index), hash_type, prevouts)?;
        let der = key.sign_der(&sighash);
        let mut sig = [0u8; 73];
        sig[..der.len()].copy_from_slice(&der);
        sig[der.len()] = hash_type;
        let n = push_bytes_to_slice(&sig[..der.len() + 1], out).ok_or(Error::BufferTooSmall)?;
        let m = push_bytes_to_slice(pubkey, &mut out[n..]).ok_or(Error::BufferTooSmall)?;
        Ok(n + m)
    }

    /// An upper bound on the length of the signed transaction.
    pub fn signed_len_bound(&self) -> usize {
        let unsigned: usize = self.inputs.iter().map(|input| input.script_sig.len()).sum();
        self.serialized_len() - unsigned + self.inputs.len() * (MAX_SCRIPT_SIG_LEN + 2)
    }

    /// Signs every transparent input with [`SIGHASH_ALL`], one key per input
    /// in order, and writes the signed transaction into `out` (at most
    /// [`signed_len_bound`](Self::signed_len_bound) bytes). Returns the
    /// number of bytes written. The scriptSigs the inputs hold are ignored.
    pub fn sign_to_slice(
        &self,
        keys: &[&SecpPrivateKey],
        prevouts: &[ZcashTxOut<'_>],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if keys.len() != self.inputs.len() {
            return Err(Error::KeyCount);
        }
        let mut s = SliceSink::new(out);
        self.write_header(&mut s);
        put_varint(&mut s, self.inputs.len());
        for (index, (input, key)) in self.inputs.iter().zip(keys).enumerate() {
            let mut script_sig = [0u8; MAX_SCRIPT_SIG_LEN];
            let n = self.sign_input_to_slice(index, key, SIGHASH_ALL, prevouts, &mut script_sig)?;
            Self::write_input(input, &script_sig[..n], &mut s);
        }
        self.write_outputs_and_bundles(&mut s);
        s.finish().ok_or(Error::BufferTooSmall)
    }

    /// Signs every transparent input: see [`sign_to_slice`](Self::sign_to_slice).
    #[cfg(feature = "alloc")]
    pub fn sign(
        &self,
        keys: &[&SecpPrivateKey],
        prevouts: &[ZcashTxOut<'_>],
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; self.signed_len_bound()];
        let n = self.sign_to_slice(keys, prevouts, &mut out)?;
        out.truncate(n);
        Ok(out)
    }
}
