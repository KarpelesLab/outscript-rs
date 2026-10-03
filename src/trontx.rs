//! Tron transactions: protobuf-encoded, identified by the SHA-256 of their
//! `raw_data`, and signed with secp256k1 into 65-byte recoverable signatures.
//!
//! A [`TronTx`] holds the `Transaction.raw` fields of the Tron protocol
//! (reference block, expiration, timestamp, fee limit, memo) and its one
//! [`TronContract`]: a TRX transfer, a TRC-10 asset transfer, a smart-contract
//! call (TRC-20 transfers go through those, see [`trc20_transfer_data`]), or
//! any other contract as its raw protobuf parameter. It serializes the raw
//! data the way java-tron does (fields in ascending order, defaults omitted),
//! so the id matches the network's, computes that id, signs it, and wraps raw
//! data and signatures into the `Transaction` message nodes broadcast.
//!
//! The reverse direction is covered too: [`TronTx::parse`] reads the raw data
//! a node built (`raw_data_hex`) so a wallet can show what it is about to
//! sign, and [`sign_txid`] / [`transaction_to_slice`] sign and wrap raw data
//! without interpreting it at all.
//!
//! Everything works without `alloc`, into caller buffers.
//!
//! ```
//! use outscript::crypto::secp256k1::SecpPrivateKey;
//! use outscript::tron::{address_from_pubkey, address_from_str};
//! use outscript::trontx::{TronContract, TronTransfer, TronTx};
//!
//! let key = SecpPrivateKey::from_bytes(&[7u8; 32]).unwrap();
//! let transfer = TronTransfer {
//!     owner: address_from_pubkey(&key.public_key()),
//!     to: address_from_str("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").unwrap(),
//!     amount: 1_000_000, // sun: 1 TRX
//! };
//! let tx = TronTx {
//!     expiration: 1_791_005_213_610, // ms; nodes accept up to 24h ahead
//!     timestamp: 1_791_005_153_610,
//!     ..TronTx::new(TronContract::Transfer(transfer))
//! }
//! .with_ref_block(86_777_507, &[0x5c; 32]); // a recent block's height and id
//!
//! let sig = tx.sign(&key);
//! assert_eq!(tx.signer(&sig), Ok(transfer.owner));
//! let mut raw = [0u8; 256];
//! let len = tx.encode_signed_to_slice(&[sig], &mut raw).unwrap(); // broadcast these
//! assert_eq!(len, tx.signed_len(1));
//! ```

pub use crate::Error;

use purecrypto::hash::{Digest, Sha256};

use crate::crypto::secp256k1::{SecpPrivateKey, recover_public_key};
use crate::hash::sha256_once;
#[cfg(feature = "alloc")]
use crate::prelude::*;
use crate::sink::{Counter, HashSink, Sink, SliceSink};
use crate::tron::{TronAddress, address_from_pubkey};

/// A 65-byte recoverable signature: `r || s || v`, with `v` the recovery id
/// (0 or 1).
pub type TronSignature = [u8; 65];

// --- protobuf wire format ---

const WIRE_VARINT: u8 = 0;
const WIRE_BYTES: u8 = 2;

fn put_varint(s: &mut dyn Sink, mut v: u64) {
    let mut buf = [0u8; 10];
    let mut n = 0;
    while v >= 0x80 {
        buf[n] = (v as u8) | 0x80;
        v >>= 7;
        n += 1;
    }
    buf[n] = v as u8;
    s.put(&buf[..=n]);
}

fn varint_len(v: u64) -> usize {
    let mut c = Counter::default();
    put_varint(&mut c, v);
    c.0
}

fn put_tag(s: &mut dyn Sink, field: u32, wire: u8) {
    put_varint(s, (u64::from(field) << 3) | u64::from(wire));
}

/// An integer field; proto3 omits zero.
fn put_uint(s: &mut dyn Sink, field: u32, v: u64) {
    if v != 0 {
        put_tag(s, field, WIRE_VARINT);
        put_varint(s, v);
    }
}

/// A bytes or string field; proto3 omits empty.
fn put_bytes(s: &mut dyn Sink, field: u32, b: &[u8]) {
    if !b.is_empty() {
        put_tag(s, field, WIRE_BYTES);
        put_varint(s, b.len() as u64);
        s.put(b);
    }
}

/// A length-delimited field whose content `write` produces: an embedded
/// message (always written) or, with `omit_empty`, bytes.
fn put_delimited(s: &mut dyn Sink, field: u32, omit_empty: bool, write: impl Fn(&mut dyn Sink)) {
    let mut c = Counter::default();
    write(&mut c);
    if omit_empty && c.0 == 0 {
        return;
    }
    put_tag(s, field, WIRE_BYTES);
    put_varint(s, c.0 as u64);
    write(s);
}

/// Reads protobuf fields off a byte slice.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn varint(&mut self) -> Result<u64, Error> {
        let mut v = 0u64;
        for (i, &b) in self.0.iter().take(10).enumerate() {
            let bits = u64::from(b & 0x7f);
            // the tenth byte holds the last bit; anything more overflows
            if i == 9 && bits > 1 {
                return Err(Error::TooLarge);
            }
            v |= bits << (7 * i);
            if b & 0x80 == 0 {
                self.0 = &self.0[i + 1..];
                return Ok(v);
            }
        }
        Err(if self.0.len() < 10 {
            Error::UnexpectedEof
        } else {
            Error::TooLarge
        })
    }

    /// The next field's number and wire type, or `None` at the end.
    fn tag(&mut self) -> Result<Option<(u32, u8)>, Error> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let tag = self.varint()?;
        let field = tag >> 3;
        if field == 0 || field > u64::from(u32::MAX) {
            return Err(Error::InvalidData);
        }
        Ok(Some((field as u32, (tag & 7) as u8)))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let bytes = self.0.get(..len).ok_or(Error::UnexpectedEof)?;
        self.0 = &self.0[len..];
        Ok(bytes)
    }

    /// A length-delimited field's content.
    fn bytes(&mut self, wire: u8) -> Result<&'a [u8], Error> {
        if wire != WIRE_BYTES {
            return Err(Error::InvalidData);
        }
        let len = usize::try_from(self.varint()?).map_err(|_| Error::TooLarge)?;
        self.take(len)
    }

    /// A non-negative `int64` (or `int32`, `max` permitting) field.
    fn int(&mut self, wire: u8, max: u64) -> Result<u64, Error> {
        if wire != WIRE_VARINT {
            return Err(Error::InvalidData);
        }
        let v = self.varint()?;
        if v > max {
            return Err(Error::InvalidData);
        }
        Ok(v)
    }

    /// A 21-byte raw address.
    fn address(&mut self, wire: u8) -> Result<TronAddress, Error> {
        self.bytes(wire)?
            .try_into()
            .map_err(|_| Error::InvalidLength)
    }

    /// Skips a field's value.
    fn skip(&mut self, wire: u8) -> Result<(), Error> {
        match wire {
            WIRE_VARINT => self.varint().map(drop),
            1 => self.take(8).map(drop),
            WIRE_BYTES => self.bytes(wire).map(drop),
            5 => self.take(4).map(drop),
            _ => Err(Error::InvalidData),
        }
    }
}

const I64_MAX: u64 = i64::MAX as u64;
const I32_MAX: u64 = i32::MAX as u64;

// --- contracts ---

/// A native TRX transfer (`TransferContract`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TronTransfer {
    /// The sender, who signs.
    pub owner: TronAddress,
    /// The recipient.
    pub to: TronAddress,
    /// The amount in sun (a millionth of a TRX).
    pub amount: u64,
}

impl TronTransfer {
    /// The `Transaction.Contract.type` value.
    pub const CONTRACT_TYPE: u32 = 1;
    /// The `google.protobuf.Any` type URL.
    pub const TYPE_URL: &'static str = "type.googleapis.com/protocol.TransferContract";
}

/// A TRC-10 asset transfer (`TransferAssetContract`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TronTransferAsset<'a> {
    /// The asset id, as decimal ASCII digits (e.g. `b"1002000"`).
    pub asset_name: &'a [u8],
    /// The sender, who signs.
    pub owner: TronAddress,
    /// The recipient.
    pub to: TronAddress,
    /// The amount, in the asset's base units.
    pub amount: u64,
}

impl TronTransferAsset<'_> {
    /// The `Transaction.Contract.type` value.
    pub const CONTRACT_TYPE: u32 = 2;
    /// The `google.protobuf.Any` type URL.
    pub const TYPE_URL: &'static str = "type.googleapis.com/protocol.TransferAssetContract";
}

/// A smart-contract call (`TriggerSmartContract`), such as a TRC-20 transfer.
/// The transaction's `fee_limit` bounds the energy it may burn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TronTriggerSmartContract<'a> {
    /// The caller, who signs.
    pub owner: TronAddress,
    /// The contract called.
    pub contract: TronAddress,
    /// TRX sent along with the call, in sun.
    pub call_value: u64,
    /// The ABI-encoded call.
    pub data: &'a [u8],
    /// A TRC-10 amount sent along with the call (0 for none).
    pub call_token_value: u64,
    /// The TRC-10 asset of `call_token_value` (0 for none).
    pub token_id: u64,
}

impl<'a> TronTriggerSmartContract<'a> {
    /// The `Transaction.Contract.type` value.
    pub const CONTRACT_TYPE: u32 = 31;
    /// The `google.protobuf.Any` type URL.
    pub const TYPE_URL: &'static str = "type.googleapis.com/protocol.TriggerSmartContract";

    /// A call of `contract` with `data`, sending no TRX or TRC-10 along.
    pub fn new(owner: TronAddress, contract: TronAddress, data: &'a [u8]) -> Self {
        TronTriggerSmartContract {
            owner,
            contract,
            call_value: 0,
            data,
            call_token_value: 0,
            token_id: 0,
        }
    }
}

/// Any other contract, as its `Transaction.Contract.type`, type URL and
/// serialized parameter (the `google.protobuf.Any` value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TronOtherContract<'a> {
    /// The `Transaction.Contract.type` value.
    pub contract_type: u32,
    /// The `google.protobuf.Any` type URL, e.g.
    /// `type.googleapis.com/protocol.VoteWitnessContract`.
    pub type_url: &'a str,
    /// The serialized contract message.
    pub parameter: &'a [u8],
}

/// The one contract a Tron transaction carries.
///
/// Non-exhaustive: more contract types may get their own variant; today they
/// go through [`TronContract::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TronContract<'a> {
    /// A TRX transfer.
    Transfer(TronTransfer),
    /// A TRC-10 transfer.
    TransferAsset(TronTransferAsset<'a>),
    /// A smart-contract call.
    TriggerSmartContract(TronTriggerSmartContract<'a>),
    /// Any other contract, uninterpreted.
    Other(TronOtherContract<'a>),
}

impl<'a> TronContract<'a> {
    /// The `Transaction.Contract.type` value.
    pub fn contract_type(&self) -> u32 {
        match self {
            TronContract::Transfer(_) => TronTransfer::CONTRACT_TYPE,
            TronContract::TransferAsset(_) => TronTransferAsset::CONTRACT_TYPE,
            TronContract::TriggerSmartContract(_) => TronTriggerSmartContract::CONTRACT_TYPE,
            TronContract::Other(c) => c.contract_type,
        }
    }

    /// The `google.protobuf.Any` type URL.
    pub fn type_url(&self) -> &'a str {
        match self {
            TronContract::Transfer(_) => TronTransfer::TYPE_URL,
            TronContract::TransferAsset(_) => TronTransferAsset::TYPE_URL,
            TronContract::TriggerSmartContract(_) => TronTriggerSmartContract::TYPE_URL,
            TronContract::Other(c) => c.type_url,
        }
    }

    /// Writes the serialized contract message (the `Any` value).
    fn write_parameter(&self, s: &mut dyn Sink) {
        match self {
            TronContract::Transfer(c) => {
                put_bytes(s, 1, &c.owner);
                put_bytes(s, 2, &c.to);
                put_uint(s, 3, c.amount);
            }
            TronContract::TransferAsset(c) => {
                put_bytes(s, 1, c.asset_name);
                put_bytes(s, 2, &c.owner);
                put_bytes(s, 3, &c.to);
                put_uint(s, 4, c.amount);
            }
            TronContract::TriggerSmartContract(c) => {
                put_bytes(s, 1, &c.owner);
                put_bytes(s, 2, &c.contract);
                put_uint(s, 3, c.call_value);
                put_bytes(s, 4, c.data);
                put_uint(s, 5, c.call_token_value);
                put_uint(s, 6, c.token_id);
            }
            TronContract::Other(c) => s.put(c.parameter),
        }
    }

    /// Writes the `Transaction.Contract` message.
    fn write(&self, s: &mut dyn Sink, permission_id: u32) {
        put_uint(s, 1, u64::from(self.contract_type()));
        put_delimited(s, 2, false, |s| {
            // google.protobuf.Any
            put_bytes(s, 1, self.type_url().as_bytes());
            put_delimited(s, 2, true, |s| self.write_parameter(s));
        });
        put_uint(s, 5, u64::from(permission_id));
    }

    /// Interprets a contract whose type URL is known; others stay `Other`.
    fn parse(contract_type: u32, type_url: &'a str, parameter: &'a [u8]) -> Result<Self, Error> {
        let expected_type = match type_url {
            TronTransfer::TYPE_URL => TronTransfer::CONTRACT_TYPE,
            TronTransferAsset::TYPE_URL => TronTransferAsset::CONTRACT_TYPE,
            TronTriggerSmartContract::TYPE_URL => TronTriggerSmartContract::CONTRACT_TYPE,
            _ => {
                return Ok(TronContract::Other(TronOtherContract {
                    contract_type,
                    type_url,
                    parameter,
                }));
            }
        };
        if contract_type != expected_type {
            return Err(Error::InvalidData);
        }
        let mut r = Reader(parameter);
        let (mut owner, mut to) = (None, None);
        let (mut amount, mut call_value, mut call_token_value, mut token_id) = (0, 0, 0, 0);
        let (mut asset_name, mut data): (&[u8], &[u8]) = (&[], &[]);
        while let Some((field, wire)) = r.tag()? {
            match (expected_type, field) {
                (TronTransfer::CONTRACT_TYPE, 1) | (TronTransferAsset::CONTRACT_TYPE, 2) => {
                    owner = Some(r.address(wire)?)
                }
                (TronTransfer::CONTRACT_TYPE, 2) | (TronTransferAsset::CONTRACT_TYPE, 3) => {
                    to = Some(r.address(wire)?)
                }
                (TronTransfer::CONTRACT_TYPE, 3) | (TronTransferAsset::CONTRACT_TYPE, 4) => {
                    amount = r.int(wire, I64_MAX)?
                }
                (TronTransferAsset::CONTRACT_TYPE, 1) => asset_name = r.bytes(wire)?,
                (TronTriggerSmartContract::CONTRACT_TYPE, 1) => owner = Some(r.address(wire)?),
                (TronTriggerSmartContract::CONTRACT_TYPE, 2) => to = Some(r.address(wire)?),
                (TronTriggerSmartContract::CONTRACT_TYPE, 3) => {
                    call_value = r.int(wire, I64_MAX)?
                }
                (TronTriggerSmartContract::CONTRACT_TYPE, 4) => data = r.bytes(wire)?,
                (TronTriggerSmartContract::CONTRACT_TYPE, 5) => {
                    call_token_value = r.int(wire, I64_MAX)?
                }
                (TronTriggerSmartContract::CONTRACT_TYPE, 6) => token_id = r.int(wire, I64_MAX)?,
                _ => return Err(Error::UnsupportedField),
            }
        }
        let owner = owner.ok_or(Error::InvalidData)?;
        let to = to.ok_or(Error::InvalidData)?;
        Ok(match expected_type {
            TronTransfer::CONTRACT_TYPE => {
                TronContract::Transfer(TronTransfer { owner, to, amount })
            }
            TronTransferAsset::CONTRACT_TYPE => TronContract::TransferAsset(TronTransferAsset {
                asset_name,
                owner,
                to,
                amount,
            }),
            _ => TronContract::TriggerSmartContract(TronTriggerSmartContract {
                owner,
                contract: to,
                call_value,
                data,
                call_token_value,
                token_id,
            }),
        })
    }
}

/// The `transfer(address,uint256)` calldata of a TRC-20 transfer, for a
/// [`TronTriggerSmartContract`] of the token's contract. The recipient goes
/// in as its 20-byte account hash, without the address prefix.
pub fn trc20_transfer_data(to: &TronAddress, amount: u128) -> [u8; 68] {
    let mut data = [0u8; 68];
    data[..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    data[16..36].copy_from_slice(&to[1..]);
    data[52..].copy_from_slice(&amount.to_be_bytes());
    data
}

// --- transactions ---

/// A Tron transaction's `raw_data`: what is identified and signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TronTx<'a> {
    /// Bytes 6 and 7 of the reference block's height, big-endian.
    pub ref_block_bytes: [u8; 2],
    /// Bytes 8 to 15 of the reference block's id.
    pub ref_block_hash: [u8; 8],
    /// When the transaction expires, in milliseconds since the Unix epoch;
    /// at most 24 hours after the reference block.
    pub expiration: u64,
    /// When the transaction was created, in milliseconds since the Unix epoch.
    pub timestamp: u64,
    /// The most TRX (in sun) a smart-contract call may burn as energy; 0 for
    /// other contracts.
    pub fee_limit: u64,
    /// A memo (the `data` field), or empty.
    pub memo: &'a [u8],
    /// The contract.
    pub contract: TronContract<'a>,
    /// The permission the signers act under: 0 for the owner permission, 2
    /// and up for an active permission of a multi-signature account.
    pub permission_id: u32,
}

impl<'a> TronTx<'a> {
    /// A transaction carrying `contract`, with every other field zero or
    /// empty. Set at least the reference block ([`with_ref_block`](Self::with_ref_block))
    /// and the expiration.
    pub fn new(contract: TronContract<'a>) -> Self {
        TronTx {
            ref_block_bytes: [0; 2],
            ref_block_hash: [0; 8],
            expiration: 0,
            timestamp: 0,
            fee_limit: 0,
            memo: &[],
            contract,
            permission_id: 0,
        }
    }

    /// Sets the reference block from a recent block's height and id (the id
    /// starts with the height; the hash part follows).
    pub fn with_ref_block(mut self, height: u64, block_id: &[u8; 32]) -> Self {
        let height = height.to_be_bytes();
        self.ref_block_bytes = [height[6], height[7]];
        self.ref_block_hash.copy_from_slice(&block_id[8..16]);
        self
    }

    /// Writes the `raw_data` message.
    fn write_raw(&self, s: &mut dyn Sink) {
        put_bytes(s, 1, &self.ref_block_bytes);
        put_bytes(s, 4, &self.ref_block_hash);
        put_uint(s, 8, self.expiration);
        put_bytes(s, 10, self.memo);
        put_delimited(s, 11, false, |s| self.contract.write(s, self.permission_id));
        put_uint(s, 14, self.timestamp);
        put_uint(s, 18, self.fee_limit);
    }

    /// The length of the serialized `raw_data`.
    pub fn raw_data_len(&self) -> usize {
        let mut c = Counter::default();
        self.write_raw(&mut c);
        c.0
    }

    /// Serializes the `raw_data` into `out`, returning the number of bytes
    /// written.
    pub fn raw_data_to_slice(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut s = SliceSink::new(out);
        self.write_raw(&mut s);
        s.finish().ok_or(Error::BufferTooSmall)
    }

    /// Serializes the `raw_data`.
    #[cfg(feature = "alloc")]
    pub fn raw_data(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.raw_data_len()];
        self.raw_data_to_slice(&mut out)
            .expect("buffer sized by raw_data_len");
        out
    }

    /// The transaction id: SHA-256 of the `raw_data`. This is what is signed.
    pub fn txid(&self) -> [u8; 32] {
        let mut h = HashSink(Sha256::new());
        self.write_raw(&mut h);
        h.0.finalize()
    }

    /// Signs the transaction.
    pub fn sign(&self, key: &SecpPrivateKey) -> TronSignature {
        sign_txid(&self.txid(), key)
    }

    /// The address that produced `sig` for this transaction.
    pub fn signer(&self, sig: &TronSignature) -> Result<TronAddress, Error> {
        recover_signer(&self.txid(), sig)
    }

    /// The length of the `Transaction` message with `signatures` signatures.
    pub fn signed_len(&self, signatures: usize) -> usize {
        transaction_len(self.raw_data_len(), signatures)
    }

    /// Writes the `Transaction` message (`raw_data` and `sigs`), as nodes
    /// broadcast it, into `out`, returning the number of bytes written.
    pub fn encode_signed_to_slice(
        &self,
        sigs: &[TronSignature],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut s = SliceSink::new(out);
        put_delimited(&mut s, 1, false, |s| self.write_raw(s));
        for sig in sigs {
            put_bytes(&mut s, 2, sig);
        }
        s.finish().ok_or(Error::BufferTooSmall)
    }

    /// The `Transaction` message: see [`encode_signed_to_slice`](Self::encode_signed_to_slice).
    #[cfg(feature = "alloc")]
    pub fn encode_signed(&self, sigs: &[TronSignature]) -> Vec<u8> {
        let mut out = vec![0u8; self.signed_len(sigs.len())];
        self.encode_signed_to_slice(sigs, &mut out)
            .expect("buffer sized by signed_len");
        out
    }

    /// Parses a serialized `raw_data` (a node's `raw_data_hex`), borrowing
    /// the memo and the contract's variable parts from it.
    ///
    /// The transaction must be one this type can reproduce byte for byte, so
    /// that its id is preserved: fields the type does not model
    /// (`ref_block_num`, `auths`, `scripts`, a contract's `provider` or
    /// `ContractName`) fail with [`Error::UnsupportedField`], more than one
    /// contract with [`Error::InvalidData`], and an encoding that differs
    /// from the canonical one with [`Error::NonCanonical`].
    pub fn parse(raw_data: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader(raw_data);
        let (mut ref_block_bytes, mut ref_block_hash) = (None, None);
        let (mut expiration, mut timestamp, mut fee_limit) = (0, 0, 0);
        let mut memo: &[u8] = &[];
        let mut contract = None;
        while let Some((field, wire)) = r.tag()? {
            match field {
                1 => ref_block_bytes = Some(r.bytes(wire)?),
                4 => ref_block_hash = Some(r.bytes(wire)?),
                8 => expiration = r.int(wire, I64_MAX)?,
                10 => memo = r.bytes(wire)?,
                11 => {
                    if contract.is_some() {
                        return Err(Error::InvalidData);
                    }
                    contract = Some(Self::parse_contract(r.bytes(wire)?)?);
                }
                14 => timestamp = r.int(wire, I64_MAX)?,
                18 => fee_limit = r.int(wire, I64_MAX)?,
                _ => return Err(Error::UnsupportedField),
            }
        }
        let (contract, permission_id) = contract.ok_or(Error::InvalidData)?;
        let tx = TronTx {
            ref_block_bytes: ref_block_bytes
                .ok_or(Error::InvalidData)?
                .try_into()
                .map_err(|_| Error::InvalidLength)?,
            ref_block_hash: ref_block_hash
                .ok_or(Error::InvalidData)?
                .try_into()
                .map_err(|_| Error::InvalidLength)?,
            expiration,
            timestamp,
            fee_limit,
            memo,
            contract,
            permission_id,
        };
        if tx.txid() != sha256_once(raw_data) {
            return Err(Error::NonCanonical);
        }
        Ok(tx)
    }

    /// Parses a `Transaction.Contract` message into the contract and its
    /// permission id.
    fn parse_contract(data: &'a [u8]) -> Result<(TronContract<'a>, u32), Error> {
        let mut r = Reader(data);
        let (mut contract_type, mut permission_id) = (0, 0);
        let mut any = None;
        while let Some((field, wire)) = r.tag()? {
            match field {
                1 => contract_type = r.int(wire, I32_MAX)? as u32,
                2 => any = Some(r.bytes(wire)?),
                5 => permission_id = r.int(wire, I32_MAX)? as u32,
                _ => return Err(Error::UnsupportedField),
            }
        }
        let mut r = Reader(any.ok_or(Error::InvalidData)?);
        let (mut type_url, mut parameter): (&str, &[u8]) = ("", &[]);
        while let Some((field, wire)) = r.tag()? {
            match field {
                1 => {
                    type_url =
                        core::str::from_utf8(r.bytes(wire)?).map_err(|_| Error::InvalidData)?
                }
                2 => parameter = r.bytes(wire)?,
                _ => return Err(Error::UnsupportedField),
            }
        }
        Ok((
            TronContract::parse(contract_type, type_url, parameter)?,
            permission_id,
        ))
    }
}

/// Signs a transaction id (the SHA-256 of its `raw_data`).
pub fn sign_txid(txid: &[u8; 32], key: &SecpPrivateKey) -> TronSignature {
    let (r, s, recid) = key.sign_recoverable(txid);
    let mut sig = [0u8; 65];
    sig[..32].copy_from_slice(&r);
    sig[32..64].copy_from_slice(&s);
    sig[64] = recid;
    sig
}

/// The address that produced `sig` for the transaction with id `txid`. The
/// recovery id may also be given as `27 + recid`, as some signers do.
pub fn recover_signer(txid: &[u8; 32], sig: &TronSignature) -> Result<TronAddress, Error> {
    let recid = match sig[64] {
        v @ 0..=3 => v,
        v @ 27..=30 => v - 27,
        _ => return Err(Error::InvalidV),
    };
    let r: [u8; 32] = sig[..32].try_into().expect("32 bytes");
    let s: [u8; 32] = sig[32..64].try_into().expect("32 bytes");
    let pubkey = recover_public_key(&r, &s, recid, txid).map_err(|_| Error::Recovery)?;
    Ok(address_from_pubkey(&pubkey))
}

/// The length of the `Transaction` message wrapping `raw_data_len` bytes of
/// raw data and `signatures` signatures.
pub fn transaction_len(raw_data_len: usize, signatures: usize) -> usize {
    1 + varint_len(raw_data_len as u64) + raw_data_len + signatures * (2 + 65)
}

/// Writes the `Transaction` message (`raw_data` and `sigs`), as nodes
/// broadcast it, into `out`, returning the number of bytes written. For raw
/// data built elsewhere; [`TronTx::encode_signed_to_slice`] does the same
/// for a [`TronTx`].
pub fn transaction_to_slice(
    raw_data: &[u8],
    sigs: &[TronSignature],
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut s = SliceSink::new(out);
    put_delimited(&mut s, 1, false, |s| s.put(raw_data));
    for sig in sigs {
        put_bytes(&mut s, 2, sig);
    }
    s.finish().ok_or(Error::BufferTooSmall)
}

/// The `Transaction` message: see [`transaction_to_slice`].
#[cfg(feature = "alloc")]
pub fn transaction(raw_data: &[u8], sigs: &[TronSignature]) -> Vec<u8> {
    let mut out = vec![0u8; transaction_len(raw_data.len(), sigs.len())];
    transaction_to_slice(raw_data, sigs, &mut out).expect("buffer sized by transaction_len");
    out
}

/// Splits a `Transaction` message into its `raw_data` and its signatures,
/// which are copied into `sigs` ([`Error::TooLarge`] if there are more).
/// Returns the raw data and the number of signatures. Other fields (the
/// results a node attaches) are skipped.
pub fn parse_transaction<'a>(
    data: &'a [u8],
    sigs: &mut [TronSignature],
) -> Result<(&'a [u8], usize), Error> {
    let mut r = Reader(data);
    let mut raw_data = None;
    let mut count = 0;
    while let Some((field, wire)) = r.tag()? {
        match field {
            1 => {
                if raw_data.is_some() {
                    return Err(Error::InvalidData);
                }
                raw_data = Some(r.bytes(wire)?);
            }
            2 => {
                let sig = r.bytes(wire)?;
                let slot = sigs.get_mut(count).ok_or(Error::TooLarge)?;
                *slot = sig.try_into().map_err(|_| Error::InvalidSignature)?;
                count += 1;
            }
            _ => r.skip(wire)?,
        }
    }
    Ok((raw_data.ok_or(Error::InvalidData)?, count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tron::address_from_str;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        let mut a = [0u8; N];
        hex::decode_to_slice(s, &mut a).unwrap();
        a
    }

    fn key() -> SecpPrivateKey {
        SecpPrivateKey::from_bytes(&h(
            "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf",
        ))
        .unwrap()
    }

    /// Mainnet transactions from block 86777507 (2026-10-03): `raw_data_hex`,
    /// `txID` and `signature` as the node returned them.
    struct Vector {
        raw_data: &'static str,
        txid: &'static str,
        signature: &'static str,
        contract: TronContract<'static>,
        expiration: u64,
        timestamp: u64,
        fee_limit: u64,
    }

    fn vectors() -> [Vector; 3] {
        let addr = |hex| h::<21>(hex);
        [
            Vector {
                raw_data: "0a021ea02208aad8d0d99af16daf40aa87eb8190345a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a15414057457e23815c277b3b2c9c7ebf0300145e20ce1215411fe62596881a5a3e6a1abb2fd26611a62664c784180970cab2e7819034",
                txid: "c2b231b26f2657c417047ab49ff7bb59ebcc0a92b3583fd4fc89139f268aaba0",
                signature: "c1f9fd128fe145575b8bf66eadacdac6d80fcb479c5fb0f8f246578bf6b94f9356f534ae7432268b81c9333011c21089084f22aaeb55cd0afee6970a762adfdf01",
                contract: TronContract::Transfer(TronTransfer {
                    owner: addr("414057457e23815c277b3b2c9c7ebf0300145e20ce"),
                    to: addr("411fe62596881a5a3e6a1abb2fd26611a62664c784"),
                    amount: 9,
                }),
                expiration: 1_791_005_213_610,
                timestamp: 1_791_005_153_610,
                fee_limit: 0,
            },
            Vector {
                raw_data: "0a021e8d22083f4b4b92c1944c9040fea9f98190345aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a15415bbe102a79d3cd56aacfb2dbc72e88579de71042121541a614f803b6fd780986a42c78ec9c7f77e6ded13c2244a9059cbb000000000000000000000000f3bba0c676e77dde79933fbcbacd445b2c9af0ff0000000000000000000000000000000000000000000000000000000001c73ddc709e82e7819034900180e1eb17",
                txid: "6ecfb8332017b5f809e777ca7b6586119640183fe8c867f97db85d2c25beb36c",
                signature: "775916fd47a70c88f4c4694270b5b443566dbb2b00198359392343d7fdadbdbd4abe66f30e78d4e947d4fa43b84d26dd8a6d0aebb8145e99cbf3674574aff34200",
                contract: TronContract::TriggerSmartContract(TronTriggerSmartContract::new(
                    addr("415bbe102a79d3cd56aacfb2dbc72e88579de71042"),
                    addr("41a614f803b6fd780986a42c78ec9c7f77e6ded13c"),
                    &[
                        0xa9, 0x05, 0x9c, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf3, 0xbb,
                        0xa0, 0xc6, 0x76, 0xe7, 0x7d, 0xde, 0x79, 0x93, 0x3f, 0xbc, 0xba, 0xcd,
                        0x44, 0x5b, 0x2c, 0x9a, 0xf0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xc7, 0x3d, 0xdc,
                    ],
                )),
                expiration: 1_791_005_447_422,
                timestamp: 1_791_005_147_422,
                fee_limit: 50_000_000,
            },
            Vector {
                raw_data: "0a021e8f220821079d025b1450fa40f8f2ea8190345a77080212730a32747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e736665724173736574436f6e7472616374123d0a073130303531393012154190a231614832887d3dd33104e789ddaf45ad6c221a15417d6f5b645b60c66044a92b41c78e0e3844825694208094ebdc0370eab3e7819034",
                txid: "46b0d4734e690429df5431f95b11150124cb671f240c81149982b1a8b5c678b4",
                signature: "3efa874f03ef41b3490c581103c16f11b7ee21c87e3322db776b3f2d27b087ca0b5fe7dee730f318f57161c7b602c9176e59f3265e84c62919424e3296566a8e00",
                contract: TronContract::TransferAsset(TronTransferAsset {
                    asset_name: b"1005190",
                    owner: addr("4190a231614832887d3dd33104e789ddaf45ad6c22"),
                    to: addr("417d6f5b645b60c66044a92b41c78e0e3844825694"),
                    amount: 1_000_000_000,
                }),
                expiration: 1_791_005_211_000,
                timestamp: 1_791_005_153_770,
                fee_limit: 0,
            },
        ]
    }

    fn owner(c: &TronContract<'_>) -> TronAddress {
        match c {
            TronContract::Transfer(c) => c.owner,
            TronContract::TransferAsset(c) => c.owner,
            TronContract::TriggerSmartContract(c) => c.owner,
            TronContract::Other(_) => unreachable!(),
        }
    }

    #[test]
    fn mainnet_vectors() {
        for v in vectors() {
            let raw = hex::decode(v.raw_data).unwrap();
            let txid: [u8; 32] = h(v.txid);
            let sig: TronSignature = h(v.signature);

            let tx = TronTx::parse(&raw).unwrap();
            assert_eq!(tx.contract, v.contract);
            assert_eq!(
                (tx.expiration, tx.timestamp, tx.fee_limit, tx.permission_id),
                (v.expiration, v.timestamp, v.fee_limit, 0)
            );
            assert_eq!(&tx.ref_block_bytes, &raw[2..4]);
            assert_eq!(&tx.ref_block_hash, &raw[6..14]);
            assert!(tx.memo.is_empty());

            // reproduced byte for byte, hence the id
            let mut out = [0u8; 512];
            assert_eq!(tx.raw_data_len(), raw.len());
            let n = tx.raw_data_to_slice(&mut out).unwrap();
            assert_eq!(&out[..n], &raw[..]);
            assert_eq!(tx.txid(), txid);
            assert_eq!(
                tx.raw_data_to_slice(&mut out[..raw.len() - 1]),
                Err(Error::BufferTooSmall)
            );

            // the network's signature is the owner's
            assert_eq!(tx.signer(&sig), Ok(owner(&tx.contract)));
            assert_eq!(recover_signer(&txid, &sig), Ok(owner(&tx.contract)));

            // the broadcast message, and back
            let n = tx.encode_signed_to_slice(&[sig], &mut out).unwrap();
            assert_eq!(n, tx.signed_len(1));
            let mut m = [0u8; 512];
            let m_len = transaction_to_slice(&raw, &[sig], &mut m).unwrap();
            assert_eq!(&m[..m_len], &out[..n]);
            let mut sigs = [[0u8; 65]; 2];
            assert_eq!(parse_transaction(&out[..n], &mut sigs), Ok((&raw[..], 1)));
            assert_eq!(sigs[0], sig);
            assert_eq!(
                parse_transaction(&out[..n], &mut sigs[..0]),
                Err(Error::TooLarge)
            );
            assert_eq!(
                tx.encode_signed_to_slice(&[sig], &mut out[..n - 1]),
                Err(Error::BufferTooSmall)
            );
        }
    }

    /// Building the TRX transfer vector from its fields gives the same bytes.
    #[test]
    fn builds_transfer_vector() {
        let v = &vectors()[0];
        let tx = TronTx {
            ref_block_bytes: [0x1e, 0xa0],
            ref_block_hash: h("aad8d0d99af16daf"),
            expiration: v.expiration,
            timestamp: v.timestamp,
            ..TronTx::new(v.contract)
        };
        assert_eq!(hex::encode(tx.txid()), v.txid);
        let mut out = [0u8; 256];
        let n = tx.raw_data_to_slice(&mut out).unwrap();
        assert_eq!(hex::encode(&out[..n]), v.raw_data);

        // the same reference block from its height and id
        let mut block_id = [0u8; 32];
        block_id[..8].copy_from_slice(&0x052c_1ea0u64.to_be_bytes());
        block_id[8..16].copy_from_slice(&h::<8>("aad8d0d99af16daf"));
        let via_block = TronTx::new(v.contract).with_ref_block(0x052c_1ea0, &block_id);
        assert_eq!(
            (via_block.ref_block_bytes, via_block.ref_block_hash),
            (tx.ref_block_bytes, tx.ref_block_hash)
        );
    }

    /// The TRC-20 call data of the USDT transfer vector.
    #[test]
    fn trc20_data_matches_vector() {
        let TronContract::TriggerSmartContract(call) = vectors()[1].contract else {
            unreachable!()
        };
        let to = address_from_str("TYBwyJDsfFgt9toLTMuJuZCKrJG4ZCDNCB").unwrap();
        assert_eq!(&trc20_transfer_data(&to, 29_834_716)[..], call.data);
    }

    #[test]
    fn sign_and_recover() {
        let key = key();
        let me = address_from_pubkey(&key.public_key());
        let tx = TronTx {
            expiration: 1_791_005_213_610,
            timestamp: 1_791_005_153_610,
            memo: b"hello",
            permission_id: 2,
            ..TronTx::new(TronContract::Transfer(TronTransfer {
                owner: me,
                to: address_from_str("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").unwrap(),
                amount: 0, // omitted from the encoding
            }))
        }
        .with_ref_block(86_777_507, &[0x5c; 32]);
        let mut sig = tx.sign(&key);
        assert!(sig[64] <= 1);
        assert_eq!(tx.signer(&sig), Ok(me));
        sig[64] += 27;
        assert_eq!(tx.signer(&sig), Ok(me));
        sig[64] = 5;
        assert_eq!(tx.signer(&sig), Err(Error::InvalidV));
        sig[64] = 0;
        sig[0] ^= 1;
        assert_ne!(tx.signer(&sig), Ok(me));

        // memo and permission id survive a round trip
        let mut raw = [0u8; 256];
        let n = tx.raw_data_to_slice(&mut raw).unwrap();
        assert_eq!(TronTx::parse(&raw[..n]), Ok(tx));
    }

    #[test]
    fn other_contract_roundtrip() {
        let tx = TronTx {
            expiration: 1,
            ..TronTx::new(TronContract::Other(TronOtherContract {
                contract_type: 4,
                type_url: "type.googleapis.com/protocol.VoteWitnessContract",
                parameter: &[0x0a, 0x01, 0x41],
            }))
        }
        .with_ref_block(1, &[1; 32]);
        let mut raw = [0u8; 256];
        let n = tx.raw_data_to_slice(&mut raw).unwrap();
        assert_eq!(TronTx::parse(&raw[..n]), Ok(tx));
        assert_eq!(tx.contract.contract_type(), 4);
    }

    #[test]
    fn parse_rejects() {
        let raw = hex::decode(vectors()[0].raw_data).unwrap();
        let parse = |data: &[u8]| TronTx::parse(data).map(drop);
        assert_eq!(parse(&raw[..raw.len() - 1]), Err(Error::UnexpectedEof));
        assert_eq!(parse(&raw[..raw.len() - 8]), Err(Error::UnexpectedEof));
        assert_eq!(parse(&[]), Err(Error::InvalidData));
        // ref_block_num (field 3) is not modelled
        let mut with_num = raw.clone();
        with_num.extend_from_slice(&[0x18, 0x01]);
        assert_eq!(parse(&with_num), Err(Error::UnsupportedField));
        // an explicit zero expiration decodes but is not what we would write
        let mut zero = vec![0x40, 0x00];
        zero.extend_from_slice(&raw);
        assert_eq!(parse(&zero), Err(Error::NonCanonical));
        // two contracts (the contract field follows the 4+10+7 bytes of the
        // reference block and expiration)
        let contract = &raw[21..21 + 2 + 0x65];
        assert_eq!(&contract[..2], &[0x5a, 0x65]);
        let mut two = raw.clone();
        two.extend_from_slice(contract);
        assert_eq!(parse(&two), Err(Error::InvalidData));
        // the wrong wire type for a field
        let mut wire = raw.clone();
        wire[0] = 0x08;
        assert!(parse(&wire).is_err());
        // a bad address length inside the contract
        let mut short = raw.clone();
        let owner_len_at = 21 + 2 + 2 + 2 + 2 + 0x2d + 2 + 1;
        assert_eq!(
            &raw[owner_len_at - 1..owner_len_at + 2],
            &[0x0a, 0x15, 0x41]
        );
        short[owner_len_at] = 0x14;
        assert_eq!(parse(&short), Err(Error::InvalidLength));
        // a varint that overflows
        assert_eq!(
            parse(&[
                0x40, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
            ]),
            Err(Error::TooLarge)
        );
        // a negative amount, in a TransferContract parameter written as is
        let TronContract::Transfer(transfer) = vectors()[0].contract else {
            unreachable!()
        };
        let mut parameter = vec![0x0a, 0x15];
        parameter.extend_from_slice(&transfer.owner);
        parameter.extend_from_slice(&[0x12, 0x15]);
        parameter.extend_from_slice(&transfer.to);
        parameter.push(0x18);
        let amount_at = parameter.len();
        parameter.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        let as_is = |parameter: &[u8]| {
            let tx = TronTx {
                expiration: 1,
                ..TronTx::new(TronContract::Other(TronOtherContract {
                    contract_type: TronTransfer::CONTRACT_TYPE,
                    type_url: TronTransfer::TYPE_URL,
                    parameter,
                }))
            }
            .with_ref_block(1, &[1; 32]);
            let mut raw = [0u8; 256];
            let n = tx.raw_data_to_slice(&mut raw).unwrap();
            // the parsed contract borrows nothing from a TransferContract
            TronTx::parse(&raw[..n]).map(|tx| match tx.contract {
                TronContract::Transfer(c) => Some(c),
                _ => None,
            })
        };
        assert_eq!(as_is(&parameter), Err(Error::InvalidData));
        parameter.truncate(amount_at);
        parameter.push(9);
        assert_eq!(as_is(&parameter), Ok(Some(transfer)));
        // a type that does not match the type URL
        let mut mismatch = raw.clone();
        assert_eq!(&mismatch[23..25], &[0x08, 0x01]);
        mismatch[24] = 0x02;
        assert_eq!(parse(&mismatch), Err(Error::InvalidData));

        // the Transaction wrapper
        assert_eq!(
            parse_transaction(&[0x12, 0x01, 0x00], &mut [[0; 65]; 1]),
            Err(Error::InvalidSignature)
        );
        assert_eq!(parse_transaction(&[], &mut []), Err(Error::InvalidData));
        // a result (field 5) is skipped, a group (wire type 3) is not
        assert_eq!(
            parse_transaction(&[0x0a, 0x01, 0x00, 0x2a, 0x01, 0x00], &mut []),
            Ok((&[0u8][..], 0))
        );
        assert_eq!(
            parse_transaction(&[0x0a, 0x01, 0x00, 0x2b], &mut []),
            Err(Error::InvalidData)
        );
    }
}
