//! Transactions: the wire format, the hashes, and the checks of a RingCT
//! transaction's proofs.

use super::bulletproofs_plus::BulletproofPlus;
use super::clsag::{Clsag, RingMember};
use super::fee::weight_clawback;
use super::legacy_sig::{
    BORROMEAN_PROOF_LEN, borromean_verify, check_ring_signature, key_image_point,
};
use super::ringct::verify_balance;
use super::{Error, ringct};
use crate::cryptonote::{Hasher, cn_fast_hash, push_varint, read_varint};
use crate::prelude::*;

/// RingCT type of a transaction without RingCT data: a coinbase transaction.
pub const RCT_TYPE_NULL: u8 = 0;
/// RingCT type "full": one MLSAG over all inputs, Borromean range proofs
/// (2017).
pub const RCT_TYPE_FULL: u8 = 1;
/// RingCT type "simple": one MLSAG per input, Borromean range proofs (2017).
pub const RCT_TYPE_SIMPLE: u8 = 2;
/// RingCT type with the original Bulletproofs (2018).
pub const RCT_TYPE_BULLETPROOF: u8 = 3;
/// RingCT type with Bulletproofs and 8-byte encrypted amounts (2019).
pub const RCT_TYPE_BULLETPROOF2: u8 = 4;
/// RingCT type with CLSAG ring signatures and Bulletproofs (2020).
pub const RCT_TYPE_CLSAG: u8 = 5;
/// RingCT type with CLSAG ring signatures and Bulletproofs+ (2022): the
/// current one.
pub const RCT_TYPE_BULLETPROOF_PLUS: u8 = 6;

/// Input tag of a coinbase input.
const TXIN_GEN: u8 = 0xff;
/// Input tag of an input spending an output.
const TXIN_TO_KEY: u8 = 0x02;
/// Output tag of an output to a one-time key.
const TXOUT_TO_KEY: u8 = 0x02;
/// Output tag of an output to a one-time key with a view tag.
const TXOUT_TO_TAGGED_KEY: u8 = 0x03;

/// The size of a Borromean range proof.
const RANGE_SIG_LEN: usize = BORROMEAN_PROOF_LEN;

/// An input of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// The input of a coinbase transaction, which creates coins.
    Gen {
        /// The height of the block.
        height: u64,
    },
    /// An input that spends one of the outputs of its ring.
    ToKey {
        /// The amount: zero for a RingCT input, whose amount is hidden.
        amount: u64,
        /// The ring: the global indices of its outputs (among those of the
        /// same amount), the first as it is and each next one as the
        /// difference with the one before. See
        /// [`absolute_offsets`](Input::absolute_offsets).
        key_offsets: Vec<u64>,
        /// The key image of the output being spent.
        key_image: [u8; 32],
    },
}

impl Input {
    /// The global indices of the ring's outputs (the running sum of the
    /// relative `key_offsets`), or `None` for a coinbase input or if the sum
    /// overflows.
    pub fn absolute_offsets(&self) -> Option<Vec<u64>> {
        let Input::ToKey { key_offsets, .. } = self else {
            return None;
        };
        let mut sum = 0u64;
        key_offsets
            .iter()
            .map(|offset| {
                sum = sum.checked_add(*offset)?;
                Some(sum)
            })
            .collect()
    }

    /// The number of outputs in the ring (zero for a coinbase input).
    pub fn ring_size(&self) -> usize {
        match self {
            Input::Gen { .. } => 0,
            Input::ToKey { key_offsets, .. } => key_offsets.len(),
        }
    }

    /// The key image, for an input that spends an output.
    pub fn key_image(&self) -> Option<&[u8; 32]> {
        match self {
            Input::Gen { .. } => None,
            Input::ToKey { key_image, .. } => Some(key_image),
        }
    }
}

/// The relative `key_offsets` of a ring given by the global indices of its
/// outputs, which must be in increasing order.
///
/// Fails with [`Error::InvalidRing`] if they are not.
pub fn relative_offsets(absolute: &[u64]) -> Result<Vec<u64>, Error> {
    let mut previous = 0u64;
    absolute
        .iter()
        .enumerate()
        .map(|(i, index)| {
            let offset = index.checked_sub(previous).ok_or(Error::InvalidRing)?;
            if i != 0 && offset == 0 {
                return Err(Error::InvalidRing);
            }
            previous = *index;
            Ok(offset)
        })
        .collect()
}

/// An output of a transaction: `txout_to_key`, or `txout_to_tagged_key` when
/// it has a view tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Output {
    /// The amount: zero for a RingCT output, whose amount is hidden.
    pub amount: u64,
    /// The one-time public key.
    pub key: [u8; 32],
    /// The view tag ([`derive_view_tag`](super::derive_view_tag)), on
    /// outputs made since the 2022 network upgrade.
    pub view_tag: Option<u8>,
}

/// The part of a transaction that the signatures commit to through its hash.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransactionPrefix {
    /// The format version: 1 before RingCT, 2 since.
    pub version: u64,
    /// The height or time before which the outputs cannot be spent (zero for
    /// no lock beyond the standard ten blocks).
    pub unlock_time: u64,
    /// The inputs.
    pub inputs: Vec<Input>,
    /// The outputs.
    pub outputs: Vec<Output>,
    /// The extra field: see [`parse_extra`](super::parse_extra).
    pub extra: Vec<u8>,
}

/// The encrypted amount (and, in the old form, mask) of a RingCT output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdhInfo {
    /// The form of the RingCT types 1 to 3: the mask and the amount, each
    /// offset by a hash of the shared secret.
    Full {
        /// The encrypted mask.
        mask: [u8; 32],
        /// The encrypted amount.
        amount: [u8; 32],
    },
    /// The current form: the 8-byte amount XORed with a hash of the shared
    /// secret ([`encrypt_amount`](super::encrypt_amount)); the mask is
    /// derived from the shared secret.
    Compact([u8; 8]),
}

impl EcdhInfo {
    /// The 8-byte encrypted amount of the current form.
    pub fn compact(&self) -> Option<[u8; 8]> {
        match self {
            EcdhInfo::Compact(amount) => Some(*amount),
            EcdhInfo::Full { .. } => None,
        }
    }
}

/// A Borromean range proof of the RingCT types 1 and 2, kept as its 6176 raw
/// bytes (the 64 `s0`, the 64 `s1`, `ee`, then the 64 bit commitments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeSig(pub Vec<u8>);

impl RangeSig {
    /// Whether the proof holds for `commitment`, the commitment of the
    /// output it comes with: its amount is below 2^64
    /// ([`borromean_verify`]).
    pub fn verify(&self, commitment: &[u8; 32]) -> bool {
        borromean_verify(&self.0, commitment)
    }
}

/// An original Bulletproof range proof (RingCT types 3 to 5): one proof
/// that the amounts of all the outputs of a transaction are below 2^64.
/// Verified by `Bulletproof::verify`; there is no prover for it here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bulletproof {
    /// `A`.
    pub a: [u8; 32],
    /// `S`.
    pub s: [u8; 32],
    /// `T1`.
    pub t1: [u8; 32],
    /// `T2`.
    pub t2: [u8; 32],
    /// `taux`.
    pub taux: [u8; 32],
    /// `mu`.
    pub mu: [u8; 32],
    /// `L`: the left points of the inner-product rounds.
    pub l: Vec<[u8; 32]>,
    /// `R`: the right points of the inner-product rounds.
    pub r: Vec<[u8; 32]>,
    /// `a` (the scalar; `A` is the field [`a`](Self::a)).
    pub aa: [u8; 32],
    /// `b`.
    pub b: [u8; 32],
    /// `t`.
    pub t: [u8; 32],
}

/// An MLSAG ring signature (RingCT types 1 to 4). Verified by
/// [`verify_simple`](Self::verify_simple) (types 2 to 4, one signature per
/// input) and [`verify_full`](Self::verify_full) (type 1, one signature for
/// the transaction); there is no signer for it here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mlsag {
    /// The responses: one row per ring member.
    pub ss: Vec<Vec<[u8; 32]>>,
    /// The first challenge.
    pub cc: [u8; 32],
}

/// The RingCT data of a version 2 transaction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RctSignatures {
    /// The RingCT type: [`RCT_TYPE_NULL`] for a coinbase transaction (the
    /// other fields are then empty), [`RCT_TYPE_BULLETPROOF_PLUS`] for a
    /// current transaction.
    pub rct_type: u8,
    /// The fee, in atomic units.
    pub fee: u64,
    /// The encrypted amounts, one per output.
    pub ecdh_info: Vec<EcdhInfo>,
    /// The commitments to the amounts of the outputs.
    pub out_pk: Vec<[u8; 32]>,
    /// The pseudo-output commitments, one per input: commitments to the
    /// amounts of the outputs being spent, re-blinded. (They are serialized
    /// with the prunable data, or before it for [`RCT_TYPE_SIMPLE`]; absent
    /// for [`RCT_TYPE_FULL`].)
    pub pseudo_outs: Vec<[u8; 32]>,
    /// The Borromean range proofs (types 1 and 2).
    pub range_sigs: Vec<RangeSig>,
    /// The original Bulletproofs (types 3 to 5).
    pub bulletproofs: Vec<Bulletproof>,
    /// The Bulletproofs+ (type 6): one, aggregated over all outputs.
    pub bulletproofs_plus: Vec<BulletproofPlus>,
    /// The MLSAG ring signatures (types 1 to 4).
    pub mlsags: Vec<Mlsag>,
    /// The CLSAG ring signatures (types 5 and 6), one per input.
    pub clsags: Vec<Clsag>,
}

/// A transaction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Transaction {
    /// The prefix.
    pub prefix: TransactionPrefix,
    /// The ring signatures of a version 1 transaction: for each input, one
    /// 64-byte signature per ring member.
    pub signatures: Vec<Vec<[u8; 64]>>,
    /// The RingCT data of a version 2 transaction.
    pub rct: RctSignatures,
}

/// A cursor over untrusted bytes.
pub(super) struct Reader<'a> {
    pub(super) data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (head, tail) = self.data.split_at_checked(n).ok_or(Error::UnexpectedEof)?;
        self.data = tail;
        Ok(head)
    }

    pub(super) fn u8(&mut self) -> Result<u8, Error> {
        self.bytes(1)?.first().copied().ok_or(Error::UnexpectedEof)
    }

    pub(super) fn varint(&mut self) -> Result<u64, Error> {
        let (value, n) = read_varint(self.data)?;
        self.bytes(n)?;
        Ok(value)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        <[u8; N]>::try_from(self.bytes(N)?).map_err(|_| Error::UnexpectedEof)
    }

    pub(super) fn key(&mut self) -> Result<[u8; 32], Error> {
        self.array()
    }

    /// Checks that `count` elements of at least `min_len` bytes each can
    /// still follow, so that a count read from the data never drives an
    /// allocation larger than the data itself.
    pub(super) fn check_count(&self, count: u64, min_len: usize) -> Result<usize, Error> {
        let count = usize::try_from(count).map_err(|_| Error::UnexpectedEof)?;
        let need = count.checked_mul(min_len).ok_or(Error::UnexpectedEof)?;
        if need > self.data.len() {
            return Err(Error::UnexpectedEof);
        }
        Ok(count)
    }

    /// A varint count of elements of at least `min_len` bytes each.
    pub(super) fn count(&mut self, min_len: usize) -> Result<usize, Error> {
        let count = self.varint()?;
        self.check_count(count, min_len)
    }

    /// `count` keys.
    pub(super) fn keys(&mut self, count: usize) -> Result<Vec<[u8; 32]>, Error> {
        let count = self.check_count(count as u64, 32)?;
        (0..count).map(|_| self.key()).collect()
    }

    /// A vector of keys with its length.
    pub(super) fn key_vec(&mut self) -> Result<Vec<[u8; 32]>, Error> {
        let count = self.count(32)?;
        self.keys(count)
    }
}

fn push_keys(out: &mut Vec<u8>, keys: &[[u8; 32]]) {
    for key in keys {
        out.extend_from_slice(key);
    }
}

impl TransactionPrefix {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let version = r.varint()?;
        if version == 0 || version > 2 {
            return Err(Error::Unsupported);
        }
        let unlock_time = r.varint()?;

        let count = r.count(2)?;
        let mut inputs = Vec::with_capacity(count);
        for _ in 0..count {
            inputs.push(match r.u8()? {
                TXIN_GEN => Input::Gen {
                    height: r.varint()?,
                },
                TXIN_TO_KEY => {
                    let amount = r.varint()?;
                    let offsets = r.count(1)?;
                    let mut key_offsets = Vec::with_capacity(offsets);
                    for _ in 0..offsets {
                        key_offsets.push(r.varint()?);
                    }
                    Input::ToKey {
                        amount,
                        key_offsets,
                        key_image: r.key()?,
                    }
                }
                // txin_to_script and txin_to_scripthash were never used.
                _ => return Err(Error::Unsupported),
            });
        }

        let count = r.count(34)?;
        let mut outputs = Vec::with_capacity(count);
        for _ in 0..count {
            let amount = r.varint()?;
            outputs.push(match r.u8()? {
                TXOUT_TO_KEY => Output {
                    amount,
                    key: r.key()?,
                    view_tag: None,
                },
                TXOUT_TO_TAGGED_KEY => Output {
                    amount,
                    key: r.key()?,
                    view_tag: Some(r.u8()?),
                },
                // txout_to_script and txout_to_scripthash were never used.
                _ => return Err(Error::Unsupported),
            });
        }

        let len = r.count(1)?;
        let extra = r.bytes(len)?.to_vec();
        Ok(TransactionPrefix {
            version,
            unlock_time,
            inputs,
            outputs,
            extra,
        })
    }

    /// Decodes a transaction prefix, which must take up all of `data`.
    ///
    /// Fails as [`Transaction::parse`] does.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let mut r = Reader { data };
        let prefix = Self::read(&mut r)?;
        if !r.data.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(prefix)
    }

    /// Appends the serialized prefix to `out`.
    pub fn write(&self, out: &mut Vec<u8>) {
        push_varint(out, self.version);
        push_varint(out, self.unlock_time);
        push_varint(out, self.inputs.len() as u64);
        for input in &self.inputs {
            match input {
                Input::Gen { height } => {
                    out.push(TXIN_GEN);
                    push_varint(out, *height);
                }
                Input::ToKey {
                    amount,
                    key_offsets,
                    key_image,
                } => {
                    out.push(TXIN_TO_KEY);
                    push_varint(out, *amount);
                    push_varint(out, key_offsets.len() as u64);
                    for offset in key_offsets {
                        push_varint(out, *offset);
                    }
                    out.extend_from_slice(key_image);
                }
            }
        }
        push_varint(out, self.outputs.len() as u64);
        for output in &self.outputs {
            push_varint(out, output.amount);
            match output.view_tag {
                None => {
                    out.push(TXOUT_TO_KEY);
                    out.extend_from_slice(&output.key);
                }
                Some(tag) => {
                    out.push(TXOUT_TO_TAGGED_KEY);
                    out.extend_from_slice(&output.key);
                    out.push(tag);
                }
            }
        }
        push_varint(out, self.extra.len() as u64);
        out.extend_from_slice(&self.extra);
    }

    /// The serialized prefix.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    /// The hash of the prefix (`get_transaction_prefix_hash`): what a
    /// version 1 ring signature signs, and the first of the three hashes a
    /// RingCT signature commits to.
    pub fn hash(&self) -> [u8; 32] {
        cn_fast_hash(&self.serialize())
    }

    /// The ring size the RingCT data is laid out for: that of the first
    /// input.
    fn ring_size(&self) -> usize {
        self.inputs.first().map_or(0, |input| match input {
            Input::Gen { .. } => 1,
            Input::ToKey { key_offsets, .. } => key_offsets.len(),
        })
    }
}

fn is_known_rct_type(rct_type: u8) -> bool {
    rct_type <= RCT_TYPE_BULLETPROOF_PLUS
}

fn has_compact_amounts(rct_type: u8) -> bool {
    matches!(
        rct_type,
        RCT_TYPE_BULLETPROOF2 | RCT_TYPE_CLSAG | RCT_TYPE_BULLETPROOF_PLUS
    )
}

fn has_bulletproofs(rct_type: u8) -> bool {
    matches!(
        rct_type,
        RCT_TYPE_BULLETPROOF | RCT_TYPE_BULLETPROOF2 | RCT_TYPE_CLSAG
    )
}

fn has_clsags(rct_type: u8) -> bool {
    matches!(rct_type, RCT_TYPE_CLSAG | RCT_TYPE_BULLETPROOF_PLUS)
}

impl Bulletproof {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let proof = Bulletproof {
            a: r.key()?,
            s: r.key()?,
            t1: r.key()?,
            t2: r.key()?,
            taux: r.key()?,
            mu: r.key()?,
            l: r.key_vec()?,
            r: r.key_vec()?,
            aa: r.key()?,
            b: r.key()?,
            t: r.key()?,
        };
        if proof.l.is_empty() || proof.l.len() != proof.r.len() {
            return Err(Error::InvalidTransaction);
        }
        Ok(proof)
    }

    /// Decodes a proof as a transaction carries it (`A`, `S`, `T1`, `T2`,
    /// `taux`, `mu`, the counted `L` and `R`, then `a`, `b` and `t`), which
    /// must take up all of `data`.
    ///
    /// Fails with [`Error::UnexpectedEof`], [`Error::TrailingData`],
    /// [`Error::InvalidTransaction`] (no rounds, or not as many `L` as
    /// `R`) or [`Error::CryptoNote`] (a bad varint). The structure only is
    /// checked: see `Bulletproof::verify`.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let mut r = Reader { data };
        let proof = Self::read(&mut r)?;
        if !r.data.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(proof)
    }

    /// The serialized proof: what [`parse`](Self::parse) reads.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out, true);
        out
    }

    /// Appends the proof: with the lengths of `L` and `R` as serialized in a
    /// transaction, without them as hashed for the signatures.
    fn write(&self, out: &mut Vec<u8>, lengths: bool) {
        push_keys(out, &[self.a, self.s, self.t1, self.t2, self.taux, self.mu]);
        for keys in [&self.l, &self.r] {
            if lengths {
                push_varint(out, keys.len() as u64);
            }
            push_keys(out, keys);
        }
        push_keys(out, &[self.aa, self.b, self.t]);
    }
}

impl BulletproofPlus {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let proof = BulletproofPlus {
            a: r.key()?,
            a1: r.key()?,
            b: r.key()?,
            r1: r.key()?,
            s1: r.key()?,
            d1: r.key()?,
            l: r.key_vec()?,
            r: r.key_vec()?,
        };
        if proof.l.is_empty() || proof.l.len() != proof.r.len() {
            return Err(Error::InvalidTransaction);
        }
        Ok(proof)
    }

    /// Decodes a proof as a transaction carries it (`A`, `A1`, `B`, `r1`,
    /// `s1`, `d1`, then the counted `L` and `R`), which must take up all of
    /// `data`.
    ///
    /// Fails with [`Error::UnexpectedEof`], [`Error::TrailingData`],
    /// [`Error::InvalidTransaction`] (no rounds, or not as many `L` as
    /// `R`) or [`Error::CryptoNote`] (a bad varint). The structure only is
    /// checked: see [`verify`](Self::verify).
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let mut r = Reader { data };
        let proof = Self::read(&mut r)?;
        if !r.data.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(proof)
    }

    /// The serialized proof: what [`parse`](Self::parse) reads.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out, true);
        out
    }

    /// Appends the proof: with the lengths of `L` and `R` as serialized in a
    /// transaction, without them as hashed for the signatures.
    fn write(&self, out: &mut Vec<u8>, lengths: bool) {
        push_keys(out, &[self.a, self.a1, self.b, self.r1, self.s1, self.d1]);
        for keys in [&self.l, &self.r] {
            if lengths {
                push_varint(out, keys.len() as u64);
            }
            push_keys(out, keys);
        }
    }

    /// The number of amounts a proof with this many rounds covers, if its
    /// size is a possible one.
    fn max_amounts(&self) -> Option<usize> {
        let extra_rounds = self.l.len().checked_sub(6)?;
        if extra_rounds > 4 {
            return None;
        }
        Some(1usize << extra_rounds)
    }
}

impl RctSignatures {
    /// Reads the non-prunable part (`rctSigBase`).
    fn read_base(r: &mut Reader<'_>, inputs: usize, outputs: usize) -> Result<Self, Error> {
        let rct_type = r.u8()?;
        let mut rct = RctSignatures {
            rct_type,
            ..Default::default()
        };
        if rct_type == RCT_TYPE_NULL {
            return Ok(rct);
        }
        if !is_known_rct_type(rct_type) {
            return Err(Error::Unsupported);
        }
        rct.fee = r.varint()?;
        if rct_type == RCT_TYPE_SIMPLE {
            rct.pseudo_outs = r.keys(inputs)?;
        }
        let compact = has_compact_amounts(rct_type);
        let count = r.check_count(outputs as u64, if compact { 8 } else { 64 })?;
        rct.ecdh_info.reserve(count);
        for _ in 0..count {
            rct.ecdh_info.push(if compact {
                EcdhInfo::Compact(r.array()?)
            } else {
                EcdhInfo::Full {
                    mask: r.key()?,
                    amount: r.key()?,
                }
            });
        }
        rct.out_pk = r.keys(outputs)?;
        Ok(rct)
    }

    /// Reads the prunable part (`rctSigPrunable`).
    fn read_prunable(
        &mut self,
        r: &mut Reader<'_>,
        inputs: usize,
        outputs: usize,
        ring_size: usize,
    ) -> Result<(), Error> {
        let rct_type = self.rct_type;
        if rct_type == RCT_TYPE_BULLETPROOF_PLUS {
            let count = r.count(8 * 32)?;
            if count > outputs {
                return Err(Error::InvalidTransaction);
            }
            let mut covered = 0usize;
            for _ in 0..count {
                let proof = BulletproofPlus::read(r)?;
                let amounts = proof.max_amounts().ok_or(Error::InvalidTransaction)?;
                covered = covered.saturating_add(amounts);
                self.bulletproofs_plus.push(proof);
            }
            if covered < outputs {
                return Err(Error::InvalidTransaction);
            }
        } else if has_bulletproofs(rct_type) {
            let count = if rct_type == RCT_TYPE_BULLETPROOF {
                u64::from(u32::from_le_bytes(r.array()?))
            } else {
                r.varint()?
            };
            let count = r.check_count(count, 11 * 32)?;
            if count > outputs {
                return Err(Error::InvalidTransaction);
            }
            for _ in 0..count {
                self.bulletproofs.push(Bulletproof::read(r)?);
            }
        } else {
            let count = r.check_count(outputs as u64, RANGE_SIG_LEN)?;
            for _ in 0..count {
                self.range_sigs
                    .push(RangeSig(r.bytes(RANGE_SIG_LEN)?.to_vec()));
            }
        }

        if has_clsags(rct_type) {
            let count = r.check_count(inputs as u64, 64)?;
            for _ in 0..count {
                self.clsags.push(Clsag {
                    s: r.keys(ring_size)?,
                    c1: r.key()?,
                    d: r.key()?,
                });
            }
        } else {
            // One signature over all inputs for the "full" type, with a
            // column per input and one for the commitments; one signature
            // per input otherwise, with two columns.
            let (count, columns) = if rct_type == RCT_TYPE_FULL {
                (1, inputs.checked_add(1).ok_or(Error::UnexpectedEof)?)
            } else {
                (inputs, 2)
            };
            let count = r.check_count(count as u64, 32)?;
            for _ in 0..count {
                let row_len = columns.checked_mul(32).ok_or(Error::UnexpectedEof)?;
                let rows = r.check_count(ring_size as u64, row_len)?;
                let mut ss = Vec::with_capacity(rows);
                for _ in 0..rows {
                    ss.push(r.keys(columns)?);
                }
                self.mlsags.push(Mlsag { ss, cc: r.key()? });
            }
        }

        if rct_type != RCT_TYPE_FULL && rct_type != RCT_TYPE_SIMPLE {
            self.pseudo_outs = r.keys(inputs)?;
        }
        Ok(())
    }

    /// Appends the non-prunable part (`rctSigBase`).
    fn write_base(&self, out: &mut Vec<u8>) {
        out.push(self.rct_type);
        if self.rct_type == RCT_TYPE_NULL {
            return;
        }
        push_varint(out, self.fee);
        if self.rct_type == RCT_TYPE_SIMPLE {
            push_keys(out, &self.pseudo_outs);
        }
        for info in &self.ecdh_info {
            match info {
                EcdhInfo::Compact(amount) => out.extend_from_slice(amount),
                EcdhInfo::Full { mask, amount } => {
                    out.extend_from_slice(mask);
                    out.extend_from_slice(amount);
                }
            }
        }
        push_keys(out, &self.out_pk);
    }

    /// Appends the prunable part (`rctSigPrunable`).
    fn write_prunable(&self, out: &mut Vec<u8>) {
        let rct_type = self.rct_type;
        if rct_type == RCT_TYPE_NULL {
            return;
        }
        if rct_type == RCT_TYPE_BULLETPROOF_PLUS {
            push_varint(out, self.bulletproofs_plus.len() as u64);
            for proof in &self.bulletproofs_plus {
                proof.write(out, true);
            }
        } else if has_bulletproofs(rct_type) {
            if rct_type == RCT_TYPE_BULLETPROOF {
                let count = u32::try_from(self.bulletproofs.len()).unwrap_or(u32::MAX);
                out.extend_from_slice(&count.to_le_bytes());
            } else {
                push_varint(out, self.bulletproofs.len() as u64);
            }
            for proof in &self.bulletproofs {
                proof.write(out, true);
            }
        } else {
            for sig in &self.range_sigs {
                out.extend_from_slice(&sig.0);
            }
        }
        if has_clsags(rct_type) {
            for sig in &self.clsags {
                push_keys(out, &sig.s);
                out.extend_from_slice(&sig.c1);
                out.extend_from_slice(&sig.d);
            }
        } else {
            for sig in &self.mlsags {
                for row in &sig.ss {
                    push_keys(out, row);
                }
                out.extend_from_slice(&sig.cc);
            }
        }
        if rct_type != RCT_TYPE_FULL && rct_type != RCT_TYPE_SIMPLE {
            push_keys(out, &self.pseudo_outs);
        }
    }

    /// The range proofs as the signatures hash them: their keys, one after
    /// the other.
    fn write_proofs_for_hash(&self, out: &mut Vec<u8>) {
        for proof in &self.bulletproofs_plus {
            proof.write(out, false);
        }
        for proof in &self.bulletproofs {
            proof.write(out, false);
        }
        for sig in &self.range_sigs {
            out.extend_from_slice(&sig.0);
        }
    }
}

impl Transaction {
    /// Decodes a transaction, which must take up all of `data`.
    ///
    /// Version 1 transactions and every RingCT type up to
    /// [`RCT_TYPE_BULLETPROOF_PLUS`] are understood. Fails with
    /// [`Error::Unsupported`] for another version, RingCT type, or kind of
    /// input or output; [`Error::UnexpectedEof`], [`Error::TrailingData`],
    /// [`Error::InvalidTransaction`] or [`Error::CryptoNote`] (a bad varint)
    /// for malformed data. Parsing checks the structure only: keys,
    /// signatures and proofs are not validated.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let mut r = Reader { data };
        let tx = Self::read(&mut r)?;
        if !r.data.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(tx)
    }

    /// Decodes a transaction from the front of `r`.
    pub(super) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let prefix = TransactionPrefix::read(r)?;
        let mut tx = Transaction {
            prefix,
            ..Default::default()
        };
        if tx.prefix.version == 1 {
            for input in &tx.prefix.inputs {
                let count = r.check_count(input.ring_size() as u64, 64)?;
                let mut signatures = Vec::with_capacity(count);
                for _ in 0..count {
                    signatures.push(r.array()?);
                }
                tx.signatures.push(signatures);
            }
        } else {
            let inputs = tx.prefix.inputs.len();
            let outputs = tx.prefix.outputs.len();
            tx.rct = RctSignatures::read_base(r, inputs, outputs)?;
            if tx.rct.rct_type != RCT_TYPE_NULL {
                let ring_size = tx.prefix.ring_size();
                tx.rct.read_prunable(r, inputs, outputs, ring_size)?;
            }
        }
        Ok(tx)
    }

    /// Decodes a pruned transaction — the prefix and, for version 2, the
    /// non-prunable RingCT data — as daemons serve them for scanning (the
    /// `pruned_as_hex` of `get_transactions`). It must take up all of
    /// `data`.
    ///
    /// The signatures, the proofs and (for RingCT types 3 and up) the
    /// pseudo-outputs are left empty, so the result can be scanned but not
    /// verified, and its id takes
    /// [`hash_with_prunable_hash`](Self::hash_with_prunable_hash). Fails as
    /// [`parse`](Self::parse) does.
    pub fn parse_pruned(data: &[u8]) -> Result<Self, Error> {
        let mut r = Reader { data };
        let prefix = TransactionPrefix::read(&mut r)?;
        let mut tx = Transaction {
            prefix,
            ..Default::default()
        };
        if tx.prefix.version != 1 {
            let inputs = tx.prefix.inputs.len();
            let outputs = tx.prefix.outputs.len();
            tx.rct = RctSignatures::read_base(&mut r, inputs, outputs)?;
        }
        if !r.data.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(tx)
    }

    /// The serialized transaction without its prunable part: what
    /// [`parse_pruned`](Self::parse_pruned) reads.
    pub fn serialize_pruned(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.prefix.write(&mut out);
        if self.prefix.version != 1 {
            self.rct.write_base(&mut out);
        }
        out
    }

    /// The hash of the prunable RingCT data, the third of the hashes the id
    /// of a version 2 transaction is made of: `None` for a version 1
    /// transaction, zero for a coinbase transaction.
    pub fn prunable_hash(&self) -> Option<[u8; 32]> {
        if self.prefix.version == 1 {
            return None;
        }
        if self.rct.rct_type == RCT_TYPE_NULL {
            return Some([0u8; 32]);
        }
        let mut prunable = Vec::new();
        self.rct.write_prunable(&mut prunable);
        Some(cn_fast_hash(&prunable))
    }

    /// The id of a version 2 transaction from its pruned form and the hash
    /// of its prunable data (the `prunable_hash` a daemon returns next to a
    /// pruned transaction). `None` for a version 1 transaction, whose id is
    /// the hash of the whole transaction.
    pub fn hash_with_prunable_hash(&self, prunable_hash: &[u8; 32]) -> Option<[u8; 32]> {
        if self.prefix.version == 1 {
            return None;
        }
        let prunable_hash = if self.rct.rct_type == RCT_TYPE_NULL {
            &[0u8; 32]
        } else {
            prunable_hash
        };
        let mut h = Hasher::new();
        h.update(&self.prefix.hash());
        h.update(&self.base_hash());
        h.update(prunable_hash);
        Some(h.finalize())
    }

    /// The serialized transaction.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.prefix.write(&mut out);
        if self.prefix.version == 1 {
            for signature in self.signatures.iter().flatten() {
                out.extend_from_slice(signature);
            }
        } else {
            self.rct.write_base(&mut out);
            self.rct.write_prunable(&mut out);
        }
        out
    }

    /// The hash of the non-prunable RingCT data.
    fn base_hash(&self) -> [u8; 32] {
        let mut base = Vec::new();
        self.rct.write_base(&mut base);
        cn_fast_hash(&base)
    }

    /// The transaction id (`get_transaction_hash`).
    ///
    /// For a version 1 transaction it is the hash of the whole transaction;
    /// for a version 2 transaction, the hash of three hashes: that of the
    /// prefix, of the non-prunable RingCT data, and of the prunable RingCT
    /// data (zero for a coinbase transaction, which has none).
    pub fn hash(&self) -> [u8; 32] {
        match self.prunable_hash() {
            Some(prunable_hash) => self
                .hash_with_prunable_hash(&prunable_hash)
                .unwrap_or_default(),
            None => cn_fast_hash(&self.serialize()),
        }
    }

    /// The message the ring signatures of a RingCT transaction sign
    /// (`get_pre_mlsag_hash`): the hash of the prefix hash, the hash of the
    /// non-prunable RingCT data, and the hash of the range proofs.
    pub fn signature_hash(&self) -> [u8; 32] {
        let mut proofs = Vec::new();
        self.rct.write_proofs_for_hash(&mut proofs);
        let mut h = Hasher::new();
        h.update(&self.prefix.hash());
        h.update(&self.base_hash());
        h.update(&cn_fast_hash(&proofs));
        h.finalize()
    }

    /// The weight of the transaction, which fees and block limits are
    /// counted in (`get_transaction_weight`): its size in bytes, plus, when
    /// it has a Bulletproof or Bulletproof+ over more than two outputs, a
    /// clawback of most of what aggregating the range proofs saved (see
    /// [`estimate_tx_weight`](super::estimate_tx_weight)).
    pub fn weight(&self) -> u64 {
        let size = self.serialize().len() as u64;
        if self.prefix.version < 2 {
            return size;
        }
        let rct = &self.rct;
        let plus = rct.rct_type == RCT_TYPE_BULLETPROOF_PLUS;
        let rounds: Vec<usize> = if plus {
            rct.bulletproofs_plus.iter().map(|p| p.l.len()).collect()
        } else if has_bulletproofs(rct.rct_type) {
            rct.bulletproofs.iter().map(|p| p.l.len()).collect()
        } else {
            return size;
        };
        // The outputs the proofs are padded to.
        let mut padded = 0u64;
        for rounds in rounds {
            let extra = u32::try_from(rounds.saturating_sub(6)).unwrap_or(u32::MAX);
            padded = padded.saturating_add(1u64.checked_shl(extra).unwrap_or(u64::MAX));
        }
        size.saturating_add(weight_clawback(padded, plus))
    }

    /// The fee: what the RingCT data states for a version 2 transaction,
    /// the difference between the inputs and the outputs for a version 1
    /// transaction (`None` if that underflows or overflows).
    pub fn fee(&self) -> Option<u64> {
        if self.prefix.version != 1 {
            return Some(self.rct.fee);
        }
        let mut inputs = 0u64;
        for input in &self.prefix.inputs {
            match input {
                Input::ToKey { amount, .. } => inputs = inputs.checked_add(*amount)?,
                Input::Gen { .. } => return Some(0),
            }
        }
        let mut outputs = 0u64;
        for output in &self.prefix.outputs {
            outputs = outputs.checked_add(output.amount)?;
        }
        inputs.checked_sub(outputs)
    }

    /// Checks that the transaction has the parts its kind calls for, and
    /// returns its RingCT type (`None` for version 1).
    ///
    /// Fails with [`Error::Unsupported`] for a coinbase transaction, whose
    /// validity is a matter of the block it is in.
    fn check_shape(&self) -> Result<Option<u8>, Error> {
        let rct = &self.rct;
        let inputs = self.prefix.inputs.len();
        let outputs = self.prefix.outputs.len();
        let spends = self
            .prefix
            .inputs
            .iter()
            .all(|input| matches!(input, Input::ToKey { .. }));
        if !spends {
            return Err(Error::Unsupported);
        }
        if inputs == 0 {
            return Err(Error::InvalidTransaction);
        }
        if self.prefix.version == 1 {
            if self.signatures.len() != inputs {
                return Err(Error::InvalidTransaction);
            }
            return Ok(None);
        }
        let rct_type = rct.rct_type;
        if self.prefix.version != 2 || rct_type == RCT_TYPE_NULL || !is_known_rct_type(rct_type) {
            return Err(Error::Unsupported);
        }
        let ring_signatures = if has_clsags(rct_type) {
            rct.clsags.len()
        } else {
            rct.mlsags.len()
        };
        let range_proofs_fit = if rct_type == RCT_TYPE_BULLETPROOF_PLUS {
            rct.bulletproofs_plus.len() == 1
        } else if has_bulletproofs(rct_type) {
            rct.bulletproofs.len() == 1
        } else {
            rct.range_sigs.len() == outputs
        };
        let (expected_signatures, expected_pseudo_outs) = if rct_type == RCT_TYPE_FULL {
            (1, 0)
        } else {
            (inputs, inputs)
        };
        if outputs == 0
            || rct.out_pk.len() != outputs
            || rct.ecdh_info.len() != outputs
            || rct.pseudo_outs.len() != expected_pseudo_outs
            || ring_signatures != expected_signatures
            || !range_proofs_fit
        {
            return Err(Error::InvalidTransaction);
        }
        Ok(Some(rct_type))
    }

    /// Whether the amounts balance.
    ///
    /// For a version 2 transaction of a RingCT type with pseudo-outputs (2
    /// to 6): the pseudo-output commitments add up to the output commitments
    /// plus the fee ([`verify_balance`](super::verify_balance)). For a
    /// version 1 transaction, whose amounts are in the clear: the inputs
    /// cover the outputs (the difference is the [`fee`](Self::fee)).
    ///
    /// Fails with [`Error::Unsupported`] for anything else: a coinbase
    /// transaction, or RingCT type 1, where the balance is part of what the
    /// ring signature proves
    /// ([`verify_ring_signatures`](Self::verify_ring_signatures)).
    pub fn verify_balance(&self) -> Result<bool, Error> {
        let rct = &self.rct;
        if self.prefix.version == 1 {
            let spends = self
                .prefix
                .inputs
                .iter()
                .any(|input| matches!(input, Input::ToKey { .. }));
            if !spends {
                return Err(Error::Unsupported);
            }
            return Ok(self.fee().is_some());
        }
        if self.prefix.version != 2
            || rct.rct_type < RCT_TYPE_SIMPLE
            || !is_known_rct_type(rct.rct_type)
        {
            return Err(Error::Unsupported);
        }
        verify_balance(&rct.pseudo_outs, &rct.out_pk, rct.fee)
    }

    /// Whether the range proofs of the transaction hold for its output
    /// commitments: every output amount is below 2^64. That is one
    /// Borromean proof per output for RingCT types 1 and 2
    /// ([`RangeSig::verify`]), one original Bulletproof for types 3 to 5
    /// (`Bulletproof::verify`), one Bulletproof+ for type 6
    /// ([`BulletproofPlus::verify`]).
    ///
    /// To check the proofs of many transactions at once, give them and the
    /// transactions' `rct.out_pk` to [`BulletproofPlus::verify_batch`] (or
    /// `Bulletproof::verify_batch`).
    ///
    /// Fails with [`Error::Unsupported`] for a transaction without RingCT
    /// data (version 1, or coinbase), and [`Error::InvalidTransaction`] if
    /// it does not have the proofs its type calls for.
    pub fn verify_range_proof(&self) -> Result<bool, Error> {
        let Some(rct_type) = self.check_shape()? else {
            return Err(Error::Unsupported);
        };
        let rct = &self.rct;
        if rct_type == RCT_TYPE_BULLETPROOF_PLUS {
            let proof = rct.bulletproofs_plus.first();
            return Ok(proof.is_some_and(|proof| proof.verify(&rct.out_pk)));
        }
        if has_bulletproofs(rct_type) {
            let proof = rct.bulletproofs.first();
            return Ok(proof.is_some_and(|proof| proof.verify(&rct.out_pk)));
        }
        Ok(rct
            .range_sigs
            .iter()
            .zip(&rct.out_pk)
            .all(|(proof, commitment)| proof.verify(commitment)))
    }

    /// Whether the ring signatures of the transaction hold, given the
    /// members of each input's ring: `rings[i]` lists, in the order of the
    /// input's key offsets, the public key and the commitment of each output
    /// (as the daemon's `get_outs` returns them, for the input's amount —
    /// zero in a RingCT transaction — and absolute offsets).
    ///
    /// Every kind of signature the chain has seen is checked: the
    /// CryptoNote ring signatures of version 1 ([`check_ring_signature`];
    /// the commitments of the ring members are not used), MLSAG for RingCT
    /// types 1 to 4 ([`Mlsag::verify_full`], [`Mlsag::verify_simple`]) and
    /// CLSAG for types 5 and 6 ([`Clsag::verify`]). For type 1, this also
    /// shows that the amounts balance. Key images outside the prime-order
    /// subgroup are refused, as consensus does.
    ///
    /// Fails with [`Error::Unsupported`] for a coinbase transaction,
    /// [`Error::InvalidTransaction`] if the transaction does not have the
    /// signatures its type calls for, and [`Error::InvalidRing`] if the
    /// rings do not have the sizes the inputs say.
    pub fn verify_ring_signatures(&self, rings: &[Vec<RingMember>]) -> Result<bool, Error> {
        let rct_type = self.check_shape()?;
        if rings.len() != self.prefix.inputs.len() {
            return Err(Error::InvalidRing);
        }
        let mut key_images = Vec::with_capacity(rings.len());
        for (input, ring) in self.prefix.inputs.iter().zip(rings) {
            let Input::ToKey { key_image, .. } = input else {
                return Err(Error::Unsupported);
            };
            if ring.len() != input.ring_size() {
                return Err(Error::InvalidRing);
            }
            key_images.push(*key_image);
        }
        let rct = &self.rct;
        let Some(rct_type) = rct_type else {
            let message = self.prefix.hash();
            let inputs = key_images.iter().zip(rings).zip(&self.signatures);
            for ((key_image, ring), signatures) in inputs {
                let keys: Vec<[u8; 32]> = ring.iter().map(|member| member.key).collect();
                if key_image_point(key_image).is_none()
                    || !check_ring_signature(&message, key_image, &keys, signatures)
                {
                    return Ok(false);
                }
            }
            return Ok(true);
        };
        let message = self.signature_hash();
        if rct_type == RCT_TYPE_FULL {
            let signature = rct.mlsags.first().ok_or(Error::InvalidTransaction)?;
            return Ok(signature.verify_full(&message, rings, &key_images, &rct.out_pk, rct.fee));
        }
        let inputs = key_images.iter().zip(rings).zip(&rct.pseudo_outs);
        if has_clsags(rct_type) {
            for (((key_image, ring), pseudo_out), clsag) in inputs.zip(&rct.clsags) {
                if !clsag.verify(&message, ring, key_image, pseudo_out) {
                    return Ok(false);
                }
            }
        } else {
            for (((key_image, ring), pseudo_out), mlsag) in inputs.zip(&rct.mlsags) {
                if !mlsag.verify_simple(&message, ring, key_image, pseudo_out) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Whether the transaction's proofs hold, given the members of each
    /// input's ring (as for
    /// [`verify_ring_signatures`](Self::verify_ring_signatures)): the
    /// amounts balance, every output amount is in range, and every input is
    /// signed by the owner of one of its ring's outputs. Every format the
    /// chain has seen is understood: version 1 and RingCT types 1 to 6.
    ///
    /// This is the cryptography of a transaction, not all of consensus: the
    /// caller must still check that the ring members are the outputs the
    /// inputs' offsets name and are spendable, that the key images have not
    /// been seen before, and the rules of the block's era (ring sizes,
    /// input and output ordering, allowed versions and types, the unlock
    /// time, the minimum fee, sizes).
    ///
    /// The inexpensive checks come first. Fails with
    /// [`Error::Unsupported`] for a coinbase transaction,
    /// [`Error::InvalidTransaction`] for one whose parts do not fit
    /// together, [`Error::InvalidRing`] if the rings do not have the sizes
    /// the inputs say, and [`Error::CryptoNote`] for a commitment that is
    /// not a curve point.
    ///
    /// ```
    /// use outscript::monero::{RingMember, Transaction};
    /// # fn fetch() -> (Vec<u8>, Vec<Vec<RingMember>>) { (Vec::new(), Vec::new()) }
    /// // A transaction (`get_transactions`) and, for each input, the outputs
    /// // its ring refers to (`get_outs`).
    /// let (bytes, rings) = fetch();
    /// # if false {
    /// let tx = Transaction::parse(&bytes)?;
    /// assert!(tx.verify(&rings)?);
    /// # }
    /// # Ok::<(), outscript::monero::Error>(())
    /// ```
    pub fn verify(&self, rings: &[Vec<RingMember>]) -> Result<bool, Error> {
        let rct_type = self.check_shape()?;
        if rings.len() != self.prefix.inputs.len()
            || rings
                .iter()
                .zip(&self.prefix.inputs)
                .any(|(ring, input)| ring.len() != input.ring_size())
        {
            return Err(Error::InvalidRing);
        }
        // RingCT type 1 has no pseudo-outputs: its signature covers the
        // balance.
        if rct_type != Some(RCT_TYPE_FULL) && !self.verify_balance()? {
            return Ok(false);
        }
        if !self.verify_ring_signatures(rings)? {
            return Ok(false);
        }
        Ok(rct_type.is_none() || self.verify_range_proof()?)
    }
}

/// The commitment an output stands for in a ring: the one in the RingCT data
/// for a RingCT output, `G + amount * H` for the output `index` of a version
/// 2 coinbase transaction.
///
/// Returns `None` if the transaction has no such output, or is a version 1
/// transaction (whose outputs cannot be in a RingCT ring).
pub fn output_commitment(tx: &Transaction, index: usize) -> Option<[u8; 32]> {
    let output = tx.prefix.outputs.get(index)?;
    if tx.prefix.version < 2 {
        return None;
    }
    if tx.rct.rct_type == RCT_TYPE_NULL {
        return Some(ringct::zero_commit(output.amount));
    }
    tx.rct.out_pk.get(index).copied()
}
