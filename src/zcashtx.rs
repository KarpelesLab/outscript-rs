//! Zcash v5 (ZIP-225) and v6 (ZIP 229) transactions with transparent inputs
//! and outputs, and their ZIP-244 transaction ids, authorizing data
//! commitments and signature digests.
//!
//! A [`ZcashTx`] borrows its transparent inputs and outputs, and the
//! Sapling, Orchard and (in version 6) Ironwood bundles as raw bytes:
//! shielded proofs and signatures are not produced here, but a transaction
//! that carries them can still have its transparent inputs signed and its
//! id computed, as their digests only hash the bundles' fields. With the
//! `zcash-sapling` and `zcash-orchard` features, `ZcashTx::sapling_bundle`,
//! `ZcashTx::orchard_bundle` and `ZcashTx::ironwood_bundle` give the typed
//! views of the bundles, and (with `alloc`) the `zcash_builder` module
//! builds whole transactions, shielded parts included.
//!
//! Parsing is strict where consensus is: compact sizes must be in their
//! shortest form, the reserved flag bits of the Orchard and Ironwood
//! bundles must be zero, and the value balances within the money supply.
//!
//! # Transaction versions
//!
//! What follows is what the main network runs, as of November 2026, from
//! the ZIPs (`zcash/zips` at commit `4699a8d5`), the reference
//! implementation (`zcash_primitives` 0.31.0, `zcash_protocol` 0.11.0,
//! `orchard` 0.16.0) and the chain itself.
//!
//! - **Version 5** (ZIP 225, version group id `0x26A7270A`), from NU5:
//!   transparent, Sapling and Orchard parts. It stays valid under NU6.3
//!   and NU7 (ZIP 229: "Version 4, version 5, and version 6 transactions
//!   are all valid from NU6.3 activation onward"; ZIP 259: "version 5 and
//!   version 6 transactions remain valid"), and version 5 transactions
//!   are still mined under NU7. It cannot carry an Ironwood bundle.
//! - **Version 6** (ZIP 229, status Final; version group id
//!   `0xD884B698`), from NU6.3 (ZIP 258, Final: branch id `0x37A5165B`,
//!   main network height 3 428 143): the fields of version 5, followed by
//!   an **Ironwood bundle** encoded as the Orchard one. The Ironwood pool
//!   is a second value pool of the Orchard protocol, with its own note
//!   commitment tree, the same Action circuit, and notes of a new
//!   plaintext version (ZIP 2005). In its flags the third bit is
//!   `enableCrossAddress` (ZIP 2006); in the flags of the Orchard bundle
//!   that bit stays reserved and zero, in both versions.
//!
//!   The digests are those of ZIP 244 with two changes: an Ironwood
//!   digest is added last to the transaction id and to the authorizing
//!   data commitment, and the Sapling, Orchard and Ironwood anchors move
//!   from the former to the latter, with new personalizations for the
//!   nodes that change (`ZTxIdSSpendNH_v6`, `ZTxAuthSapliH_v6`,
//!   `ZTxIdOrchardH_v6`, `ZTxAuthOrchaH_v6`, and `ZTxIdIronwd_H_v6`,
//!   `ZTxIdIrnActCH_v6`, `ZTxIdIrnActMH_v6`, `ZTxIdIrnActNH_v6`,
//!   `ZTxAuthIrnwdH_v6`). The signature digests change only through
//!   these.
//! - **NU7** (ZIP 259, branch id `0x77190AD9`, main network height
//!   3 543 405; the ZIP is still marked Proposed in the repository, but
//!   the upgrade is active on the main network and in `zcash_protocol`)
//!   "introduces no new transaction format": versions 5 and 6 are
//!   unchanged under it, and version 4 becomes invalid (ZIP 2003).
//! - **Version 4** and earlier (Sapling to Canopy formats, valid until
//!   NU7) are not handled here: [`ZcashTx::parse_into`] rejects them with
//!   [`Error::UnsupportedTxType`], and [`tx_format`] tells the format of
//!   a serialized transaction from its header, so that a version 4 one
//!   can be given to `sapling::bundle::BundleV4Ref`.
//!
//! Not deployed, and not implemented here: the withdrawn version 6 format
//! of ZIPs 230 and 246 (ZSAs: burns, issuance), the `zip233Amount` and
//! explicit fee fields, memo bundles (ZIP 231), the extensible format of
//! ZIP 248 (Draft), and the version 7 of `zcash_protocol`
//! (`0x74616368`, behind an unstable build flag).
//!
//! From NU6.3 on, consensus also requires of every transaction, whatever
//! its version (ZIP 258): no Orchard action in a coinbase transaction, a
//! non-negative `valueBalanceOrchard` (no new value enters the Orchard
//! pool), and Orchard proofs for the cross-address restricted circuit.
//! These are rules about the chain, which the parser does not apply.
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

/// Consensus branch ids of the network upgrades that use v5 or v6
/// transactions, for [`ZcashTx::consensus_branch_id`]. A transaction is only
/// valid for the upgrade in force when it is mined.
pub mod branch {
    /// NU5 (May 2022).
    pub const NU5: u32 = 0xc2d6_d0b4;
    /// NU6 (November 2024).
    pub const NU6: u32 = 0xc8e7_1055;
    /// NU6.1 (2025).
    pub const NU6_1: u32 = 0x4dec_4df0;
    /// NU6.2 (2026).
    pub const NU6_2: u32 = 0x5437_f330;
    /// NU6.3 (2026, ZIP 258): the Ironwood pool and v6 transactions.
    pub const NU6_3: u32 = 0x37a5_165b;
    /// NU7 (2026, ZIP 259): no new transaction format.
    pub const NU7: u32 = 0x7719_0ad9;
}

/// The version field of a v5 transaction: 5, with the overwintered bit.
pub const VERSION_V5: u32 = 0x8000_0005;
/// The version group id of v5 transactions.
pub const VERSION_GROUP_ID_V5: u32 = 0x26a7_270a;
/// The version field of a v6 transaction: 6, with the overwintered bit.
pub const VERSION_V6: u32 = 0x8000_0006;
/// The version group id of v6 transactions (ZIP 229).
pub const VERSION_GROUP_ID_V6: u32 = 0xd884_b698;

/// The transaction formats [`ZcashTx`] handles.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TxVersion {
    /// Version 5 (ZIP 225): transparent, Sapling and Orchard parts.
    #[default]
    V5,
    /// Version 6 (ZIP 229, from NU6.3): those of version 5 and an Ironwood
    /// bundle, with the anchors moved from the transaction id to the
    /// authorizing data commitment.
    V6,
}

impl TxVersion {
    /// The header field: the version with the overwintered bit.
    pub const fn header(self) -> u32 {
        match self {
            TxVersion::V5 => VERSION_V5,
            TxVersion::V6 => VERSION_V6,
        }
    }

    /// The version group id.
    pub const fn version_group_id(self) -> u32 {
        match self {
            TxVersion::V5 => VERSION_GROUP_ID_V5,
            TxVersion::V6 => VERSION_GROUP_ID_V6,
        }
    }

    /// The version wallets use under a consensus branch, or `None` for a
    /// branch not known here (or older than NU5): version 5 from NU5 to
    /// NU6.2, version 6 for NU6.3 and NU7. This is
    /// `TxVersion::suggested_for_branch` of `zcash_primitives` 0.31.0.
    ///
    /// Consensus does not require version 6 under NU6.3 or NU7: version 5
    /// stays valid (see [`valid_in_branch`](Self::valid_in_branch)). But
    /// only version 6 can carry an Ironwood bundle, which is where
    /// shielded payments go from NU6.3.
    pub const fn for_branch_id(consensus_branch_id: u32) -> Option<Self> {
        match consensus_branch_id {
            branch::NU5 | branch::NU6 | branch::NU6_1 | branch::NU6_2 => Some(TxVersion::V5),
            branch::NU6_3 | branch::NU7 => Some(TxVersion::V6),
            _ => None,
        }
    }

    /// Whether consensus accepts this version under a consensus branch, or
    /// `None` for a branch not known here (or older than NU5): version 5
    /// from NU5 on, version 6 from NU6.3 on. This is
    /// `TxVersion::valid_in_branch` of `zcash_primitives` 0.31.0.
    pub const fn valid_in_branch(self, consensus_branch_id: u32) -> Option<bool> {
        match consensus_branch_id {
            branch::NU5 | branch::NU6 | branch::NU6_1 | branch::NU6_2 => {
                Some(matches!(self, TxVersion::V5))
            }
            branch::NU6_3 | branch::NU7 => Some(true),
            _ => None,
        }
    }
}

/// The format of a serialized transaction, as its header states it: see
/// [`tx_format`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxFormat {
    /// Before Overwinter: no version group id (versions 1 and 2, and what
    /// consensus then read as version 2).
    Legacy(u32),
    /// Version 3 (Overwinter).
    V3,
    /// Version 4 (Sapling to NU6.3; invalid from NU7): not parsed by
    /// [`ZcashTx`]. Its Sapling fields are read by
    /// `sapling::bundle::BundleV4Ref`.
    V4,
    /// Version 5: see [`TxVersion::V5`].
    V5,
    /// Version 6: see [`TxVersion::V6`].
    V6,
}

impl TxFormat {
    /// The version [`ZcashTx`] handles this format as, if it does.
    pub const fn tx_version(self) -> Option<TxVersion> {
        match self {
            TxFormat::V5 => Some(TxVersion::V5),
            TxFormat::V6 => Some(TxVersion::V6),
            _ => None,
        }
    }
}

/// Tells the format of a serialized transaction from its header (the
/// version, and for an overwintered transaction the version group id),
/// without reading further. [`Error::UnsupportedTxType`] for a header that
/// is none of the formats of the chain: a zero version, or a version and
/// group id that do not go together.
pub fn tx_format(data: &[u8]) -> Result<TxFormat, Error> {
    let word = |at: usize| -> Result<u32, Error> {
        let bytes = data.get(at..at + 4).ok_or(Error::UnexpectedEof)?;
        Ok(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
    };
    let header = word(0)?;
    if header >> 31 == 0 {
        return match header {
            0 => Err(Error::UnsupportedTxType),
            version => Ok(TxFormat::Legacy(version)),
        };
    }
    match (header, word(4)?) {
        (0x8000_0003, 0x03c4_8270) => Ok(TxFormat::V3),
        (0x8000_0004, 0x892f_2085) => Ok(TxFormat::V4),
        (VERSION_V5, VERSION_GROUP_ID_V5) => Ok(TxFormat::V5),
        (VERSION_V6, VERSION_GROUP_ID_V6) => Ok(TxFormat::V6),
        _ => Err(Error::UnsupportedTxType),
    }
}

/// Sign every input and output.
pub const SIGHASH_ALL: u8 = 0x01;
/// Sign every input and no output.
pub const SIGHASH_NONE: u8 = 0x02;
/// Sign every input and the output at the input's index.
pub const SIGHASH_SINGLE: u8 = 0x03;
/// Combined with the others: sign only this input.
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// The conventional fee of ZIP-317, which nodes require of the transactions
/// they relay and mine without restriction: proportional to the number of
/// *logical actions* of a transaction.
pub mod zip317 {
    /// The fee per logical action, in zatoshis.
    pub const MARGINAL_FEE: u64 = 5000;
    /// The number of logical actions every transaction pays for at least.
    pub const GRACE_ACTIONS: u64 = 2;
    /// The size in bytes that counts as one transparent input: that of a
    /// signed P2PKH input.
    pub const P2PKH_STANDARD_INPUT_SIZE: u64 = 150;
    /// The size in bytes that counts as one transparent output: that of a
    /// P2PKH output.
    pub const P2PKH_STANDARD_OUTPUT_SIZE: u64 = 34;

    /// The number of logical actions of a transaction whose serialized
    /// transparent inputs (as signed) and outputs take `tx_in_total_size`
    /// and `tx_out_total_size` bytes, the counts of entries not included,
    /// with the given numbers of Sapling spends, Sapling outputs and
    /// Orchard actions. The actions of the Ironwood bundle of a version 6
    /// transaction count as Orchard ones do (revision 1 of ZIP-317): give
    /// the sum of both as `orchard_actions`.
    pub const fn logical_actions(
        tx_in_total_size: u64,
        tx_out_total_size: u64,
        sapling_spends: u64,
        sapling_outputs: u64,
        orchard_actions: u64,
    ) -> u64 {
        let ins = tx_in_total_size.div_ceil(P2PKH_STANDARD_INPUT_SIZE);
        let outs = tx_out_total_size.div_ceil(P2PKH_STANDARD_OUTPUT_SIZE);
        let transparent = if ins > outs { ins } else { outs };
        let sapling = if sapling_spends > sapling_outputs {
            sapling_spends
        } else {
            sapling_outputs
        };
        transparent
            .saturating_add(sapling)
            .saturating_add(orchard_actions)
    }

    /// The conventional fee, in zatoshis, of a transaction of that many
    /// [`logical_actions`].
    pub const fn conventional_fee(logical_actions: u64) -> u64 {
        let actions = if logical_actions > GRACE_ACTIONS {
            logical_actions
        } else {
            GRACE_ACTIONS
        };
        MARGINAL_FEE.saturating_mul(actions)
    }
}

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

/// A borrowed v5 or v6 transaction.
#[derive(Debug, Clone, Copy)]
pub struct ZcashTx<'a> {
    /// The format of the transaction: version 5 by default.
    /// [`TxVersion::for_branch_id`] gives the one wallets use under a
    /// network upgrade.
    pub version: TxVersion,
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
    /// The serialized Ironwood bundle of a version 6 transaction (ZIP 229
    /// `nActionsIronwood` onwards), or empty for none. It must be empty in
    /// a version 5 transaction, which cannot carry one: its digests fail
    /// with [`Error::InvalidData`] otherwise, and its serialization leaves
    /// the bundle out.
    pub ironwood: &'a [u8],
}

impl Default for ZcashTx<'_> {
    fn default() -> Self {
        ZcashTx {
            version: TxVersion::V5,
            consensus_branch_id: branch::NU6_2,
            lock_time: 0,
            expiry_height: 0,
            inputs: &[],
            outputs: &[],
            sapling: &[],
            orchard: &[],
            ironwood: &[],
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

/// Reads the compact size at the front of `data`, without consuming it: its
/// value and the number of bytes it takes.
///
/// Only the shortest encoding of a value is accepted
/// ([`Error::NonCanonical`] otherwise), as the consensus rules require of
/// the v5 format and as the typed bundle parsers of the `sapling` and
/// `orchard` modules do: another encoding of the same transaction would
/// have the same id.
fn peek_compact_size(data: &[u8]) -> Result<(u64, usize), Error> {
    let (BtcVarInt(value), n) = BtcVarInt::decode(data).ok_or(Error::UnexpectedEof)?;
    let shortest = match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    };
    if n != shortest {
        return Err(Error::NonCanonical);
    }
    Ok((value, n))
}

/// Reads a compact size and the fixed-size items it counts.
fn take_items<'a>(data: &mut &'a [u8], item_len: usize) -> Result<(usize, &'a [u8]), Error> {
    let (count, n) = peek_compact_size(data)?;
    let count = usize::try_from(count).map_err(|_| Error::TooLarge)?;
    let len = count.checked_mul(item_len).ok_or(Error::TooLarge)?;
    // the count is whatever the data claims: `n + len` may not fit a usize
    let end = n.checked_add(len).ok_or(Error::TooLarge)?;
    let items = data.get(n..end).ok_or(Error::UnexpectedEof)?;
    *data = &data[end..];
    Ok((count, items))
}

fn take<'a>(data: &mut &'a [u8], len: usize) -> Result<&'a [u8], Error> {
    let bytes = data.get(..len).ok_or(Error::UnexpectedEof)?;
    *data = &data[len..];
    Ok(bytes)
}

/// The fields of a Sapling bundle its digests cover.
struct Sapling<'a> {
    spends: &'a [u8],
    outputs: &'a [u8],
    value_balance: &'a [u8],
    anchor: &'a [u8],
    /// The spend proofs, spend authorization signatures, output proofs and
    /// binding signature, in serialization order.
    auth: &'a [u8],
}

const SAPLING_SPEND_LEN: usize = 96;
const SAPLING_OUTPUT_LEN: usize = 756;
const ORCHARD_ACTION_LEN: usize = 820;
const PROOF_LEN: usize = 192;
const SIG_LEN: usize = 64;
/// The total supply in zatoshis, which bounds every amount and balance.
const MAX_MONEY: i64 = 21_000_000 * 100_000_000;

/// A value balance, which must be within the money supply.
fn value_balance(bytes: &[u8]) -> Result<i64, Error> {
    let balance = i64::from_le_bytes(bytes.try_into().map_err(|_| Error::InvalidLength)?);
    if !(-MAX_MONEY..=MAX_MONEY).contains(&balance) {
        return Err(Error::InvalidAmount);
    }
    Ok(balance)
}

/// Reads a serialized Sapling bundle (the same in v5 and v6) off the front
/// of `data`, split into its fields.
fn take_sapling<'a>(data: &mut &'a [u8]) -> Result<Sapling<'a>, Error> {
    let (n_spends, spends) = take_items(data, SAPLING_SPEND_LEN)?;
    let (n_outputs, outputs) = take_items(data, SAPLING_OUTPUT_LEN)?;
    let (mut balance, mut anchor, mut auth): (&[u8], &[u8], &[u8]) = (&[], &[], &[]);
    // the counts were just checked against the data: their sum fits
    if n_spends + n_outputs > 0 {
        balance = take(data, 8)?;
        value_balance(balance)?;
        if n_spends > 0 {
            anchor = take(data, 32)?;
        }
        auth = take(
            data,
            n_spends * (PROOF_LEN + SIG_LEN) + n_outputs * PROOF_LEN + SIG_LEN,
        )?;
    }
    Ok(Sapling {
        spends,
        outputs,
        value_balance: balance,
        anchor,
        auth,
    })
}

/// Splits a serialized Sapling bundle into its fields, checking its length.
fn parse_sapling(bundle: &[u8]) -> Result<Sapling<'_>, Error> {
    let data = &mut &*bundle;
    let sapling = take_sapling(data)?;
    if !data.is_empty() {
        return Err(Error::TrailingData);
    }
    Ok(sapling)
}

/// The fields of an Orchard or Ironwood bundle its digests cover.
struct Orchard<'a> {
    actions: &'a [u8],
    /// Flags and value balance, in serialization order.
    flags_balance: &'a [u8],
    anchor: &'a [u8],
    proof: &'a [u8],
    /// The spend authorization signatures and the binding signature.
    signatures: &'a [u8],
}

/// How the digests cover the bundle of a pool of the Orchard protocol in a
/// transaction version (ZIP 244, ZIP 229).
struct ActionPool {
    /// The flag bits that may be set.
    flags: u8,
    bundle: &'static [u8; 16],
    compact: &'static [u8; 16],
    memos: &'static [u8; 16],
    noncompact: &'static [u8; 16],
    auth: &'static [u8; 16],
    /// Whether the anchor is authorizing data (v6) or effecting data (v5).
    anchor_in_auth: bool,
}

const ORCHARD_V5: ActionPool = ActionPool {
    flags: 0b011,
    bundle: b"ZTxIdOrchardHash",
    compact: b"ZTxIdOrcActCHash",
    memos: b"ZTxIdOrcActMHash",
    noncompact: b"ZTxIdOrcActNHash",
    auth: b"ZTxAuthOrchaHash",
    anchor_in_auth: false,
};

/// In v6 the Orchard actions are hashed as in v5: only the nodes whose
/// content changes are renamed.
const ORCHARD_V6: ActionPool = ActionPool {
    bundle: b"ZTxIdOrchardH_v6",
    auth: b"ZTxAuthOrchaH_v6",
    anchor_in_auth: true,
    ..ORCHARD_V5
};

const IRONWOOD_V6: ActionPool = ActionPool {
    flags: 0b111,
    bundle: b"ZTxIdIronwd_H_v6",
    compact: b"ZTxIdIrnActCH_v6",
    memos: b"ZTxIdIrnActMH_v6",
    noncompact: b"ZTxIdIrnActNH_v6",
    auth: b"ZTxAuthIrnwdH_v6",
    anchor_in_auth: true,
};

/// Reads a serialized Orchard or Ironwood bundle off the front of `data`,
/// split into its fields. Only the flag bits of `flags` may be set.
fn take_orchard<'a>(data: &mut &'a [u8], flags: u8) -> Result<Orchard<'a>, Error> {
    let (n_actions, actions) = take_items(data, ORCHARD_ACTION_LEN)?;
    let (mut flags_balance, mut anchor, mut proof, mut signatures): (&[u8], &[u8], &[u8], &[u8]) =
        (&[], &[], &[], &[]);
    if n_actions > 0 {
        flags_balance = take(data, 1 + 8)?;
        // the other bits are reserved and must be zero
        if flags_balance[0] & !flags != 0 {
            return Err(Error::InvalidData);
        }
        value_balance(&flags_balance[1..])?;
        anchor = take(data, 32)?;
        proof = take_items(data, 1)?.1;
        signatures = take(data, n_actions * SIG_LEN + SIG_LEN)?;
    }
    Ok(Orchard {
        actions,
        flags_balance,
        anchor,
        proof,
        signatures,
    })
}

fn parse_orchard<'a>(bundle: &'a [u8], pool: &ActionPool) -> Result<Orchard<'a>, Error> {
    let data = &mut &*bundle;
    let orchard = take_orchard(data, pool.flags)?;
    if !data.is_empty() {
        return Err(Error::TrailingData);
    }
    Ok(orchard)
}

/// The ZIP-244 digest of a Sapling bundle, for the transaction id of a v5
/// transaction or (ZIP 229: without the anchor) of a v6 one.
fn sapling_digest(bundle: &[u8], version: TxVersion) -> Result<[u8; 32], Error> {
    let bundle = parse_sapling(bundle)?;
    let v6 = version == TxVersion::V6;
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
            let noncompact: &[u8; 16] = if v6 {
                b"ZTxIdSSpendNH_v6"
            } else {
                b"ZTxIdSSpendNHash"
            };
            d.put(&digest(noncompact, |d| {
                for spend in spends {
                    d.put(&spend[..32]); // cv
                    if !v6 {
                        d.put(bundle.anchor);
                    }
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

/// The digest of the authorizing data of a Sapling bundle: in v6, the
/// anchor (if there are spends) is part of it.
fn sapling_auth_digest(bundle: &[u8], version: TxVersion) -> Result<[u8; 32], Error> {
    let bundle = parse_sapling(bundle)?;
    let (person, anchor): (&[u8; 16], &[u8]) = match version {
        TxVersion::V5 => (b"ZTxAuthSapliHash", &[]),
        TxVersion::V6 => (b"ZTxAuthSapliH_v6", bundle.anchor),
    };
    Ok(digest(person, |d| {
        d.put(bundle.auth);
        d.put(anchor);
    }))
}

/// The ZIP-244 digest of an Orchard or Ironwood bundle, for the
/// transaction id.
fn orchard_digest(bundle: &[u8], pool: &ActionPool) -> Result<[u8; 32], Error> {
    let bundle = parse_orchard(bundle, pool)?;
    Ok(digest(pool.bundle, |d| {
        if bundle.actions.is_empty() {
            return;
        }
        let actions = bundle.actions.as_chunks::<ORCHARD_ACTION_LEN>().0;
        d.put(&digest(pool.compact, |d| {
            for action in actions {
                d.put(&action[32..64]); // nullifier
                d.put(&action[96..160]); // cmx, ephemeral key
                d.put(&action[160..212]); // the compact part of the ciphertext
            }
        }));
        d.put(&digest(pool.memos, |d| {
            for action in actions {
                d.put(&action[212..724]); // the memo
            }
        }));
        d.put(&digest(pool.noncompact, |d| {
            for action in actions {
                d.put(&action[..32]); // cv
                d.put(&action[64..96]); // rk
                d.put(&action[724..]); // the rest of the ciphertext, out ciphertext
            }
        }));
        d.put(bundle.flags_balance);
        if !pool.anchor_in_auth {
            d.put(bundle.anchor);
        }
    }))
}

/// The digest of the authorizing data of an Orchard or Ironwood bundle.
fn orchard_auth_digest(bundle: &[u8], pool: &ActionPool) -> Result<[u8; 32], Error> {
    let bundle = parse_orchard(bundle, pool)?;
    Ok(digest(pool.auth, |d| {
        d.put(bundle.proof);
        d.put(bundle.signatures);
        if pool.anchor_in_auth {
            d.put(bundle.anchor);
        }
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

    fn ironwood(&self) -> &[u8] {
        if self.ironwood.is_empty() {
            NO_ORCHARD
        } else {
            self.ironwood
        }
    }

    /// How the digests cover the Orchard bundle in this version.
    fn orchard_pool(&self) -> &'static ActionPool {
        match self.version {
            TxVersion::V5 => &ORCHARD_V5,
            TxVersion::V6 => &ORCHARD_V6,
        }
    }

    /// The Ironwood bundle of a v6 transaction, as serialized, or `None`
    /// for a v5 one, which must not have any.
    fn ironwood_of_v6(&self) -> Result<Option<&[u8]>, Error> {
        match self.version {
            TxVersion::V6 => Ok(Some(self.ironwood())),
            TxVersion::V5 if self.ironwood() == NO_ORCHARD => Ok(None),
            TxVersion::V5 => Err(Error::InvalidData),
        }
    }

    fn write_header<S: Sink + ?Sized>(&self, s: &mut S) {
        s.put(&self.version.header().to_le_bytes());
        s.put(&self.version.version_group_id().to_le_bytes());
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
        if self.version == TxVersion::V6 {
            s.put(self.ironwood());
        }
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

    /// Parses a serialized v5 or v6 transaction, placing its transparent
    /// inputs and outputs in the given buffers, which must be large enough
    /// ([`Error::TooLarge`] otherwise). The scriptSigs and bundles are
    /// borrowed from `data`.
    ///
    /// A transaction of another format (version 4 and earlier) is
    /// [`Error::UnsupportedTxType`]: see [`tx_format`].
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
        let version = match (word()?, word()?) {
            (VERSION_V5, VERSION_GROUP_ID_V5) => TxVersion::V5,
            (VERSION_V6, VERSION_GROUP_ID_V6) => TxVersion::V6,
            _ => return Err(Error::UnsupportedTxType),
        };
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

        // The bundles: parsed to find their ends, kept as bytes. What the
        // digests require of them is required here, so that a transaction
        // that parses has an id.
        let mut bundle = |read: &mut dyn FnMut(&mut &'a [u8]) -> Result<(), Error>| {
            let start = *rest;
            read(rest)?;
            Ok::<&'a [u8], Error>(&start[..start.len() - rest.len()])
        };
        let sapling = bundle(&mut |rest| take_sapling(rest).map(|_| ()))?;
        let orchard_flags = match version {
            TxVersion::V5 => ORCHARD_V5.flags,
            TxVersion::V6 => ORCHARD_V6.flags,
        };
        let orchard = bundle(&mut |rest| take_orchard(rest, orchard_flags).map(|_| ()))?;
        let ironwood = match version {
            TxVersion::V5 => NO_ORCHARD,
            TxVersion::V6 => bundle(&mut |rest| take_orchard(rest, IRONWOOD_V6.flags).map(|_| ()))?,
        };
        if !rest.is_empty() {
            return Err(Error::TrailingData);
        }
        // And what the typed views require, so that the bundles are where
        // every parser of this crate finds them.
        #[cfg(feature = "zcash-sapling")]
        crate::sapling::bundle::BundleRef::parse(sapling)?;
        #[cfg(feature = "zcash-orchard")]
        {
            crate::orchard::bundle::BundleRef::parse(orchard)?;
            crate::orchard::bundle::BundleRef::parse_ironwood(ironwood)?;
        }
        Ok(ZcashTx {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            inputs,
            outputs,
            sapling: if sapling == NO_SAPLING { &[] } else { sapling },
            orchard: if orchard == NO_ORCHARD { &[] } else { orchard },
            ironwood: if ironwood == NO_ORCHARD {
                &[]
            } else {
                ironwood
            },
        })
    }

    /// The typed view of the Sapling bundle (empty when there is none): its
    /// spends and outputs, and the verification of its signatures and
    /// proofs.
    ///
    /// For a transaction given by [`parse_into`](Self::parse_into) this
    /// cannot fail: the transaction parser and the typed one accept the
    /// same bundles, of the same length.
    #[cfg(feature = "zcash-sapling")]
    pub fn sapling_bundle(&self) -> Result<crate::sapling::bundle::BundleRef<'a>, Error> {
        Ok(crate::sapling::bundle::BundleRef::parse(self.sapling)?)
    }

    /// The typed view of the Orchard bundle, or `None` when there is none:
    /// its actions, and the verification of its signatures and proof.
    ///
    /// For a transaction given by [`parse_into`](Self::parse_into) this
    /// cannot fail: the transaction parser and the typed one accept the
    /// same bundles, of the same length.
    #[cfg(feature = "zcash-orchard")]
    pub fn orchard_bundle(&self) -> Result<Option<crate::orchard::bundle::BundleRef<'a>>, Error> {
        Ok(crate::orchard::bundle::BundleRef::parse(self.orchard)?)
    }

    /// The typed view of the Ironwood bundle of a version 6 transaction, or
    /// `None` when there is none: as
    /// [`orchard_bundle`](Self::orchard_bundle), the two pools sharing
    /// their encoding, signatures and circuit (the proof is verified with
    /// the key of the NU6.3 circuit).
    #[cfg(feature = "zcash-orchard")]
    pub fn ironwood_bundle(&self) -> Result<Option<crate::orchard::bundle::BundleRef<'a>>, Error> {
        if self.ironwood_of_v6()?.is_none() {
            return Ok(None);
        }
        Ok(crate::orchard::bundle::BundleRef::parse_ironwood(
            self.ironwood,
        )?)
    }

    /// The number of ZIP-317 logical actions of the transaction as it is
    /// (the transparent inputs count by their size, scriptSigs included:
    /// an unsigned transaction has fewer than it will once signed).
    pub fn logical_actions(&self) -> Result<u64, Error> {
        let mut ins = Counter::default();
        for input in self.inputs {
            Self::write_input(input, input.script_sig, &mut ins);
        }
        let mut outs = Counter::default();
        for output in self.outputs {
            put_output(&mut outs, output);
        }
        let sapling = parse_sapling(self.sapling())?;
        let orchard = parse_orchard(self.orchard(), self.orchard_pool())?;
        let ironwood = match self.ironwood_of_v6()? {
            Some(ironwood) => parse_orchard(ironwood, &IRONWOOD_V6)?.actions.len(),
            None => 0,
        };
        Ok(zip317::logical_actions(
            ins.0 as u64,
            outs.0 as u64,
            (sapling.spends.len() / SAPLING_SPEND_LEN) as u64,
            (sapling.outputs.len() / SAPLING_OUTPUT_LEN) as u64,
            ((orchard.actions.len() + ironwood) / ORCHARD_ACTION_LEN) as u64,
        ))
    }

    /// The ZIP-317 conventional fee of the transaction as it is, in
    /// zatoshis: see [`logical_actions`](Self::logical_actions).
    pub fn conventional_fee(&self) -> Result<u64, Error> {
        Ok(zip317::conventional_fee(self.logical_actions()?))
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

    /// The ZIP-244 digest tree with the given transparent digest: in v6
    /// (ZIP 229), with the Ironwood digest last.
    fn tx_digest(&self, transparent: [u8; 32]) -> Result<[u8; 32], Error> {
        let sapling = sapling_digest(self.sapling(), self.version)?;
        let orchard = orchard_digest(self.orchard(), self.orchard_pool())?;
        let ironwood = match self.ironwood_of_v6()? {
            Some(ironwood) => Some(orchard_digest(ironwood, &IRONWOOD_V6)?),
            None => None,
        };
        let mut person = *b"ZcashTxHash_\0\0\0\0";
        person[12..].copy_from_slice(&self.consensus_branch_id.to_le_bytes());
        Ok(digest(&person, |d| {
            d.put(&self.header_digest());
            d.put(&transparent);
            d.put(&sapling);
            d.put(&orchard);
            if let Some(ironwood) = &ironwood {
                d.put(ironwood);
            }
        }))
    }

    /// The authorizing data commitment of the transaction (ZIP 244, and
    /// ZIP 229 for version 6), in the byte order of the digest: what the
    /// `hashAuthDataRoot` of a block commits to, over the scriptSigs, the
    /// shielded proofs and signatures and, in version 6, the anchors and
    /// the Ironwood bundle.
    pub fn auth_digest(&self) -> Result<[u8; 32], Error> {
        let transparent = digest(b"ZTxAuthTransHash", |d| {
            for input in self.inputs {
                put_varint(d, input.script_sig.len());
                d.put(input.script_sig);
            }
        });
        let sapling = sapling_auth_digest(self.sapling(), self.version)?;
        let orchard = orchard_auth_digest(self.orchard(), self.orchard_pool())?;
        let ironwood = match self.ironwood_of_v6()? {
            Some(ironwood) => Some(orchard_auth_digest(ironwood, &IRONWOOD_V6)?),
            None => None,
        };
        let mut person = *b"ZTxAuthHash_\0\0\0\0";
        person[12..].copy_from_slice(&self.consensus_branch_id.to_le_bytes());
        Ok(digest(&person, |d| {
            d.put(&transparent);
            d.put(&sapling);
            d.put(&orchard);
            if let Some(ironwood) = &ironwood {
                d.put(ironwood);
            }
        }))
    }

    /// The ZIP-244 (version 6: ZIP 229) signature digest of transparent input `index` for
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A compact size is a claim: one that, added to its own length, does not
    /// fit a `usize` is an error and not an overflow.
    #[test]
    fn take_items_count_cannot_overflow() {
        let mut bytes = [0xffu8; 16];
        bytes[9..].fill(0);
        // 2^64-1 one-byte items
        let data = &mut &bytes[..];
        assert_eq!(take_items(data, 1), Err(Error::TooLarge));
        assert_eq!(data.len(), 16);
        // and counts whose byte length alone overflows
        assert_eq!(take_items(&mut &bytes[..], 96), Err(Error::TooLarge));
        // a count just past the data is an EOF
        let short = [0x08u8, 1, 2, 3, 4, 5, 6, 7];
        assert_eq!(take_items(&mut &short[..], 1), Err(Error::UnexpectedEof));
        let exact = [0x02u8, 1, 2, 3];
        let data = &mut &exact[..];
        assert_eq!(take_items(data, 1), Ok((2, &exact[1..3])));
        assert_eq!(*data, &exact[3..]);
    }
}
