//! Transactions: the structures of `currency_basic.h` this module handles
//! and their binary serialization.
//!
//! Points and scalars are kept as the 32 bytes that are on the wire; they are
//! decoded (and checked) where the cryptography uses them.

use crate::cryptonote::{cn_fast_hash, push_varint};
use crate::prelude::*;

use super::Error;
use super::scan::TxOutZarcanum;
use super::ser::{self, Reader, Wire, write_bytes, write_vec};

/// `TRANSACTION_VERSION_INITAL`.
pub const TRANSACTION_VERSION_INITIAL: u64 = 0;
/// `TRANSACTION_VERSION_PRE_HF4`.
pub const TRANSACTION_VERSION_PRE_HF4: u64 = 1;
/// `TRANSACTION_VERSION_POST_HF4`: confidential (Zarcanum) transactions.
pub const TRANSACTION_VERSION_POST_HF4: u64 = 2;
/// `TRANSACTION_VERSION_POST_HF5`: adds the hardfork id to the prefix.
pub const TRANSACTION_VERSION_POST_HF5: u64 = 3;

/// Implements [`Wire`] for a struct, field by field in declaration order.
macro_rules! wire_struct {
    (@read $r:ident, u8) => { $r.u8()? };
    (@read $r:ident, u32) => { $r.u32()? };
    (@read $r:ident, u64) => { $r.u64()? };
    (@read $r:ident, varint) => { $r.varint()? };
    (@read $r:ident, bool) => { $r.bool()? };
    (@read $r:ident, key) => { $r.key()? };
    (@read $r:ident, bytes) => { $r.bytes()? };
    (@read $r:ident, vec) => { $r.vec()? };
    (@read $r:ident, obj) => { Wire::read($r)? };
    (@write $out:ident, $v:expr, u8) => { $out.push($v) };
    (@write $out:ident, $v:expr, u32) => { $out.extend_from_slice(&$v.to_le_bytes()) };
    (@write $out:ident, $v:expr, u64) => { $out.extend_from_slice(&$v.to_le_bytes()) };
    (@write $out:ident, $v:expr, varint) => { push_varint($out, $v) };
    (@write $out:ident, $v:expr, bool) => { $out.push(u8::from($v)) };
    (@write $out:ident, $v:expr, key) => { $out.extend_from_slice(&$v) };
    (@write $out:ident, $v:expr, bytes) => { write_bytes($out, &$v) };
    (@write $out:ident, $v:expr, vec) => { write_vec($out, &$v) };
    (@write $out:ident, $v:expr, obj) => { $v.write($out) };
    ($ty:ty, min = $min:expr, { $($field:ident : $kind:tt),* $(,)? }) => {
        impl Wire for $ty {
            const MIN_SIZE: usize = $min;

            fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
                Ok(Self { $($field: wire_struct!(@read r, $kind)),* })
            }

            fn write(&self, out: &mut Vec<u8>) {
                $(wire_struct!(@write out, self.$field, $kind);)*
            }
        }
    };
}
pub(crate) use wire_struct;

/// The public keys and flags of an account (`account_public_address`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccountPublicAddr {
    /// The public spend key.
    pub spend_key: [u8; 32],
    /// The public view key.
    pub view_key: [u8; 32],
    /// The account flags
    /// ([`ADDRESS_FLAG_AUDITABLE`](super::ADDRESS_FLAG_AUDITABLE)).
    pub flags: u8,
}
wire_struct!(AccountPublicAddr, min = 65, { spend_key: key, view_key: key, flags: u8 });

impl From<&super::Address> for AccountPublicAddr {
    fn from(address: &super::Address) -> Self {
        AccountPublicAddr {
            spend_key: *address.spend_key(),
            view_key: *address.view_key(),
            flags: address.flags(),
        }
    }
}

/// A reference to an output by transaction and index (`ref_by_id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RefById {
    /// The hash of the transaction.
    pub hash: [u8; 32],
    /// The index of the output in it.
    pub n: u32,
}
wire_struct!(RefById, min = 36, { hash: key, n: u32 });

/// How many outputs and extra entries an input signs, in a separately signed
/// transaction (`signed_parts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignedParts {
    /// The number of outputs signed.
    pub n_outs: u64,
    /// The number of extra entries signed.
    pub n_extras: u64,
}
wire_struct!(SignedParts, min = 2, { n_outs: varint, n_extras: varint });

/// The size, hash and count of the attachments (`extra_attachment_info`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExtraAttachmentInfo {
    /// The size of the attachments.
    pub sz: u64,
    /// Their hash.
    pub hsh: [u8; 32],
    /// Their count.
    pub cnt: u64,
}
wire_struct!(ExtraAttachmentInfo, min = 34, { sz: varint, hsh: key, cnt: varint });

/// The key derivation encrypted for the sender, and a check value
/// (`tx_crypto_checksum`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxCryptoChecksum {
    /// The key derivation, encrypted with the sender's key.
    pub encrypted_key_derivation: [u8; 32],
    /// A 32-bit hash of the derivation.
    pub derivation_hash: u32,
}
wire_struct!(TxCryptoChecksum, min = 36, { encrypted_key_derivation: key, derivation_hash: u32 });

/// A service payload (`tx_service_attachment`). The payment id of an
/// integrated address travels as one, with the service id
/// [`PAYMENT_ID_SERVICE_ID`](super::PAYMENT_ID_SERVICE_ID).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxServiceAttachment {
    /// The service the payload is for.
    pub service_id: Vec<u8>,
    /// The instruction for the service.
    pub instruction: Vec<u8>,
    /// The payload.
    pub body: Vec<u8>,
    /// Public keys attached to the payload.
    pub security: Vec<[u8; 32]>,
    /// The `TX_SERVICE_ATTACHMENT_*` flags.
    pub flags: u8,
}
wire_struct!(TxServiceAttachment, min = 5, {
    service_id: bytes, instruction: bytes, body: bytes, security: vec, flags: u8
});

/// A transparent (pre-HF4) input (`txin_to_key`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxInToKey {
    /// The amount spent.
    pub amount: u64,
    /// The ring: [`Variant::Uint64`] offsets or [`Variant::RefById`].
    pub key_offsets: Vec<Variant>,
    /// The key image.
    pub k_image: [u8; 32],
    /// [`Variant::SignedParts`] and [`Variant::ExtraAttachmentInfo`] entries.
    pub etc_details: Vec<Variant>,
}
wire_struct!(TxInToKey, min = 35, {
    amount: varint, key_offsets: vec, k_image: key, etc_details: vec
});

/// A confidential input (`txin_zc_input`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxInZcInput {
    /// The ring: [`Variant::Uint64`] global indices, each relative to the
    /// previous one, or [`Variant::RefById`].
    pub key_offsets: Vec<Variant>,
    /// The key image.
    pub key_image: [u8; 32],
    /// [`Variant::SignedParts`] and [`Variant::ExtraAttachmentInfo`] entries.
    pub etc_details: Vec<Variant>,
}
wire_struct!(TxInZcInput, min = 34, { key_offsets: vec, key_image: key, etc_details: vec });

wire_struct!(TxOutZarcanum, min = 137, {
    stealth_address: key, concealing_point: key, amount_commitment: key,
    blinded_asset_id: key, encrypted_amount: u64, mix_attr: u8
});

/// A CLSAG-GGX ring signature (`CLSAG_GGX_signature_serialized`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClsagGgxSig {
    /// The challenge at ring position 0.
    pub c: [u8; 32],
    /// The responses for the `G` layers (0 and 1), one per ring member.
    pub r_g: Vec<[u8; 32]>,
    /// The responses for the `X` layer (2), one per ring member.
    pub r_x: Vec<[u8; 32]>,
    /// The auxiliary key image of layer 1, times `1/8`.
    pub k1: [u8; 32],
    /// The auxiliary key image of layer 2, times `1/8`.
    pub k2: [u8; 32],
}
wire_struct!(ClsagGgxSig, min = 98, { c: key, r_g: vec, r_x: vec, k1: key, k2: key });

/// The signature of a confidential input (`ZC_sig`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZcSig {
    /// The pseudo-output amount commitment, times `1/8`.
    pub pseudo_out_amount_commitment: [u8; 32],
    /// The pseudo-output blinded asset id, times `1/8`.
    pub pseudo_out_blinded_asset_id: [u8; 32],
    /// The ring signature.
    pub clsag_ggx: ClsagGgxSig,
}
wire_struct!(ZcSig, min = 162, {
    pseudo_out_amount_commitment: key, pseudo_out_blinded_asset_id: key, clsag_ggx: obj
});

/// A Bootle–Groth–Esgin one-out-of-many proof (`BGE_proof_s`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BgeProof {
    /// The commitment `A`, times `1/8`.
    pub a: [u8; 32],
    /// The commitment `B`, times `1/8`.
    pub b: [u8; 32],
    /// The `m` polynomial commitments, times `1/8`.
    pub pk: Vec<[u8; 32]>,
    /// The `m * (n - 1)` responses.
    pub f: Vec<[u8; 32]>,
    /// The response `y`.
    pub y: [u8; 32],
    /// The response `z`.
    pub z: [u8; 32],
}
wire_struct!(BgeProof, min = 130, { a: key, b: key, pk: vec, f: vec, y: key, z: key });

/// The proof that every output has the asset of some input
/// (`zc_asset_surjection_proof`): one [`BgeProof`] per output.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZcAssetSurjectionProof {
    /// One proof per output.
    pub bge_proofs: Vec<BgeProof>,
}
wire_struct!(ZcAssetSurjectionProof, min = 1, { bge_proofs: vec });

/// A Bulletproofs+ aggregated range proof (`bpp_signature_serialized`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BppSignature {
    /// The left points of the inner-product rounds, times `1/8`.
    pub lv: Vec<[u8; 32]>,
    /// The right points of the inner-product rounds, times `1/8`.
    pub rv: Vec<[u8; 32]>,
    /// The bit commitment `A0`, times `1/8`.
    pub a0: [u8; 32],
    /// The final-round point `A`, times `1/8`.
    pub a: [u8; 32],
    /// The final-round point `B`, times `1/8`.
    pub b: [u8; 32],
    /// The response `r`.
    pub r: [u8; 32],
    /// The response `s`.
    pub s: [u8; 32],
    /// The response `delta`.
    pub delta: [u8; 32],
}
wire_struct!(BppSignature, min = 194, {
    lv: vec, rv: vec, a0: key, a: key, b: key, r: key, s: key, delta: key
});

/// The proof that ties each output's amount commitment to a second
/// commitment to the same amount over `U`, which the range proof is about
/// (`vector_UG_aggregation_proof_serialized`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UgAggProof {
    /// `E' = amount * U + y' * G` for each output, times `1/8`.
    pub amount_commitments_for_rp_aggregation: Vec<[u8; 32]>,
    /// The first response of each output.
    pub y0s: Vec<[u8; 32]>,
    /// The second response of each output.
    pub y1s: Vec<[u8; 32]>,
    /// The common challenge.
    pub c: [u8; 32],
}
wire_struct!(UgAggProof, min = 35, {
    amount_commitments_for_rp_aggregation: vec, y0s: vec, y1s: vec, c: key
});

/// The range proof of the outputs (`zc_outs_range_proof`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZcOutsRangeProof {
    /// The range proof, over the commitments `amount * U + y' * G`.
    pub bpp: BppSignature,
    /// The link between those commitments and the outputs'.
    pub aggregation_proof: UgAggProof,
}
wire_struct!(ZcOutsRangeProof, min = 229, { bpp: obj, aggregation_proof: obj });

/// A Schnorr proof of two discrete logarithms at once
/// (`generic_double_schnorr_sig_s`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DoubleSchnorrSig {
    /// The challenge.
    pub c: [u8; 32],
    /// The response for the first secret.
    pub y0: [u8; 32],
    /// The response for the second secret.
    pub y1: [u8; 32],
}
wire_struct!(DoubleSchnorrSig, min = 96, { c: key, y0: key, y1: key });

/// The proof that inputs and outputs balance, and that the signer knows the
/// transaction secret key (`zc_balance_proof`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ZcBalanceProof {
    /// The double Schnorr proof.
    pub dss: DoubleSchnorrSig,
}
wire_struct!(ZcBalanceProof, min = 96, { dss: obj });

/// One alternative of the tagged unions (`boost::variant`) found in
/// transactions: inputs, outputs, extra and attachment entries, signatures
/// and proofs all share one tag space.
///
/// The binary format has no length in front of a variant, so data holding a
/// tag that is not listed here cannot be parsed
/// ([`Error::UnsupportedVariant`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Variant {
    /// Tag 0, `txin_gen`: the coinbase input, with the block height.
    Gen {
        /// The height of the block.
        height: u64,
    },
    /// Tag 1, `txin_to_key`.
    ToKey(TxInToKey),
    /// Tag 7, `tx_comment`.
    Comment(Vec<u8>),
    /// Tag 10, `tx_crypto_checksum`.
    CryptoChecksum(TxCryptoChecksum),
    /// Tag 11, `tx_derivation_hint`: a [`derivation_hint`](super::derivation_hint),
    /// as two little-endian bytes.
    DerivationHint(Vec<u8>),
    /// Tag 12, `tx_service_attachment`.
    ServiceAttachment(TxServiceAttachment),
    /// Tag 14, `etc_tx_details_unlock_time`.
    UnlockTime(u64),
    /// Tag 15, `etc_tx_details_expiration_time`.
    ExpirationTime(u64),
    /// Tag 16, `etc_tx_details_flags`.
    Flags(u64),
    /// Tag 17, `signed_parts`.
    SignedParts(SignedParts),
    /// Tag 18, `extra_attachment_info`.
    ExtraAttachmentInfo(ExtraAttachmentInfo),
    /// Tag 19, `extra_user_data`.
    UserData(Vec<u8>),
    /// Tag 21, `extra_padding`.
    Padding(Vec<u8>),
    /// Tag 22, a `crypto::public_key`: in the extra, the transaction public
    /// key.
    PubKey([u8; 32]),
    /// Tag 23, `etc_tx_flags16_t`.
    EtcTxFlags16(u16),
    /// Tag 24, a `uint16_t` (`derive_xor`).
    DeriveXor(u16),
    /// Tag 25, `ref_by_id`.
    RefById(RefById),
    /// Tag 26, a `uint64_t`: in a ring, a global output index.
    Uint64(u64),
    /// Tag 27, `etc_tx_time`.
    EtcTxTime(u64),
    /// Tag 28, a `uint32_t`.
    Uint32(u32),
    /// Tag 31, `tx_payer`.
    Payer(AccountPublicAddr),
    /// Tag 32, `tx_receiver`.
    Receiver(AccountPublicAddr),
    /// Tag 37, `txin_zc_input`.
    ZcInput(TxInZcInput),
    /// Tag 38, `tx_out_zarcanum`.
    OutZarcanum(TxOutZarcanum),
    /// Tag 39, `zarcanum_tx_data_v1`: the fee.
    ZarcanumTxDataV1 {
        /// The fee, in atomic units of the native coin.
        fee: u64,
    },
    /// Tag 43, `ZC_sig`.
    ZcSig(ZcSig),
    /// Tag 46, `zc_asset_surjection_proof`.
    AssetSurjectionProof(ZcAssetSurjectionProof),
    /// Tag 47, `zc_outs_range_proof`.
    OutsRangeProof(ZcOutsRangeProof),
    /// Tag 48, `zc_balance_proof`.
    BalanceProof(ZcBalanceProof),
}

impl Variant {
    /// The tag byte of this alternative.
    pub fn tag(&self) -> u8 {
        match self {
            Variant::Gen { .. } => 0,
            Variant::ToKey(_) => 1,
            Variant::Comment(_) => 7,
            Variant::CryptoChecksum(_) => 10,
            Variant::DerivationHint(_) => 11,
            Variant::ServiceAttachment(_) => 12,
            Variant::UnlockTime(_) => 14,
            Variant::ExpirationTime(_) => 15,
            Variant::Flags(_) => 16,
            Variant::SignedParts(_) => 17,
            Variant::ExtraAttachmentInfo(_) => 18,
            Variant::UserData(_) => 19,
            Variant::Padding(_) => 21,
            Variant::PubKey(_) => 22,
            Variant::EtcTxFlags16(_) => 23,
            Variant::DeriveXor(_) => 24,
            Variant::RefById(_) => 25,
            Variant::Uint64(_) => 26,
            Variant::EtcTxTime(_) => 27,
            Variant::Uint32(_) => 28,
            Variant::Payer(_) => 31,
            Variant::Receiver(_) => 32,
            Variant::ZcInput(_) => 37,
            Variant::OutZarcanum(_) => 38,
            Variant::ZarcanumTxDataV1 { .. } => 39,
            Variant::ZcSig(_) => 43,
            Variant::AssetSurjectionProof(_) => 46,
            Variant::OutsRangeProof(_) => 47,
            Variant::BalanceProof(_) => 48,
        }
    }

    /// The name Zano's JSON gives this alternative.
    pub fn name(&self) -> &'static str {
        match self {
            Variant::Gen { .. } => "gen",
            Variant::ToKey(_) => "key",
            Variant::Comment(_) => "comment",
            Variant::CryptoChecksum(_) => "checksum",
            Variant::DerivationHint(_) => "derivation_hint",
            Variant::ServiceAttachment(_) => "attachment",
            Variant::UnlockTime(_) => "unlock_time",
            Variant::ExpirationTime(_) => "expiration_time",
            Variant::Flags(_) => "flags",
            Variant::SignedParts(_) => "signed_outs",
            Variant::ExtraAttachmentInfo(_) => "extra_attach_info",
            Variant::UserData(_) => "user_data",
            Variant::Padding(_) => "extra_padding",
            Variant::PubKey(_) => "pub_key",
            Variant::EtcTxFlags16(_) => "etc_tx_flags16",
            Variant::DeriveXor(_) => "derive_xor",
            Variant::RefById(_) => "ref_by_id",
            Variant::Uint64(_) => "uint64_t",
            Variant::EtcTxTime(_) => "etc_tx_time",
            Variant::Uint32(_) => "uint32_t",
            Variant::Payer(_) => "payer2",
            Variant::Receiver(_) => "receiver2",
            Variant::ZcInput(_) => "txin_zc_input",
            Variant::OutZarcanum(_) => "tx_out_zarcanum",
            Variant::ZarcanumTxDataV1 { .. } => "zarcanum_tx_data_v1",
            Variant::ZcSig(_) => "ZC_sig",
            Variant::AssetSurjectionProof(_) => "zc_asset_surjection_proof",
            Variant::OutsRangeProof(_) => "zc_outs_range_proof",
            Variant::BalanceProof(_) => "zc_balance_proof",
        }
    }
}

impl Wire for Variant {
    // A tag and at least one byte.
    const MIN_SIZE: usize = 2;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(match r.u8()? {
            0 => Variant::Gen {
                height: r.varint()?,
            },
            1 => Variant::ToKey(Wire::read(r)?),
            7 => Variant::Comment(r.bytes()?),
            10 => Variant::CryptoChecksum(Wire::read(r)?),
            11 => Variant::DerivationHint(r.bytes()?),
            12 => Variant::ServiceAttachment(Wire::read(r)?),
            14 => Variant::UnlockTime(r.varint()?),
            15 => Variant::ExpirationTime(r.varint()?),
            16 => Variant::Flags(r.varint()?),
            17 => Variant::SignedParts(Wire::read(r)?),
            18 => Variant::ExtraAttachmentInfo(Wire::read(r)?),
            19 => Variant::UserData(r.bytes()?),
            21 => Variant::Padding(r.bytes()?),
            22 => Variant::PubKey(r.key()?),
            23 => Variant::EtcTxFlags16(r.u16()?),
            24 => Variant::DeriveXor(r.u16()?),
            25 => Variant::RefById(Wire::read(r)?),
            26 => Variant::Uint64(r.u64()?),
            27 => Variant::EtcTxTime(r.varint()?),
            28 => Variant::Uint32(r.u32()?),
            31 => Variant::Payer(Wire::read(r)?),
            32 => Variant::Receiver(Wire::read(r)?),
            37 => Variant::ZcInput(Wire::read(r)?),
            38 => Variant::OutZarcanum(Wire::read(r)?),
            39 => Variant::ZarcanumTxDataV1 { fee: r.u64()? },
            43 => Variant::ZcSig(Wire::read(r)?),
            46 => Variant::AssetSurjectionProof(Wire::read(r)?),
            47 => Variant::OutsRangeProof(Wire::read(r)?),
            48 => Variant::BalanceProof(Wire::read(r)?),
            tag => return Err(Error::UnsupportedVariant(tag)),
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        match self {
            Variant::Gen { height: v }
            | Variant::UnlockTime(v)
            | Variant::ExpirationTime(v)
            | Variant::Flags(v)
            | Variant::EtcTxTime(v) => push_varint(out, *v),
            Variant::ToKey(v) => v.write(out),
            Variant::Comment(v)
            | Variant::DerivationHint(v)
            | Variant::UserData(v)
            | Variant::Padding(v) => write_bytes(out, v),
            Variant::CryptoChecksum(v) => v.write(out),
            Variant::ServiceAttachment(v) => v.write(out),
            Variant::SignedParts(v) => v.write(out),
            Variant::ExtraAttachmentInfo(v) => v.write(out),
            Variant::PubKey(v) => out.extend_from_slice(v),
            Variant::EtcTxFlags16(v) | Variant::DeriveXor(v) => {
                out.extend_from_slice(&v.to_le_bytes());
            }
            Variant::RefById(v) => v.write(out),
            Variant::Uint64(v) | Variant::ZarcanumTxDataV1 { fee: v } => {
                out.extend_from_slice(&v.to_le_bytes());
            }
            Variant::Uint32(v) => out.extend_from_slice(&v.to_le_bytes()),
            Variant::Payer(v) | Variant::Receiver(v) => v.write(out),
            Variant::ZcInput(v) => v.write(out),
            Variant::OutZarcanum(v) => v.write(out),
            Variant::ZcSig(v) => v.write(out),
            Variant::AssetSurjectionProof(v) => v.write(out),
            Variant::OutsRangeProof(v) => v.write(out),
            Variant::BalanceProof(v) => v.write(out),
        }
    }
}

/// A transaction.
///
/// The prefix — version, inputs, extra, outputs and, from version 3 on, the
/// hardfork id — is what the transaction id hashes; attachments, signatures
/// and proofs follow it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Transaction {
    /// The version (`TRANSACTION_VERSION_*`).
    pub version: u64,
    /// The inputs: [`Variant::Gen`], [`Variant::ToKey`] or
    /// [`Variant::ZcInput`].
    pub vin: Vec<Variant>,
    /// The extra entries (transaction public key, hints, fee, ...).
    pub extra: Vec<Variant>,
    /// The outputs: [`Variant::OutZarcanum`].
    pub vout: Vec<Variant>,
    /// The hardfork id, serialized (as part of the prefix) only from
    /// [`TRANSACTION_VERSION_POST_HF5`] on.
    pub hardfork_id: u8,
    /// The attachments.
    pub attachment: Vec<Variant>,
    /// One signature per input: [`Variant::ZcSig`].
    pub signatures: Vec<Variant>,
    /// The transaction-wide proofs.
    pub proofs: Vec<Variant>,
}

impl Transaction {
    fn read_prefix(r: &mut Reader<'_>) -> Result<Self, Error> {
        let version = r.varint()?;
        let vin = r.vec()?;
        let extra = r.vec()?;
        let vout = r.vec()?;
        let hardfork_id = if version >= TRANSACTION_VERSION_POST_HF5 {
            r.u8()?
        } else {
            0
        };
        Ok(Transaction {
            version,
            vin,
            extra,
            vout,
            hardfork_id,
            ..Default::default()
        })
    }

    fn write_prefix(&self, out: &mut Vec<u8>) {
        push_varint(out, self.version);
        write_vec(out, &self.vin);
        write_vec(out, &self.extra);
        write_vec(out, &self.vout);
        if self.version >= TRANSACTION_VERSION_POST_HF5 {
            out.push(self.hardfork_id);
        }
    }

    /// Parses a transaction, which must take the whole of `data`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        ser::from_bytes(data)
    }

    /// Parses only what scanning needs: the prefix and the attachments,
    /// which come before the signatures and proofs. Whatever follows is not
    /// looked at, so a transaction whose signatures use variants this module
    /// does not know (a proof-of-stake `zarcanum_sig`, ...) can still be
    /// scanned. `signatures` and `proofs` are left empty.
    pub fn from_bytes_for_scan(data: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(data);
        let mut tx = Self::read_prefix(&mut r)?;
        tx.attachment = r.vec()?;
        Ok(tx)
    }

    /// Serializes the transaction.
    pub fn to_bytes(&self) -> Vec<u8> {
        ser::to_bytes(self)
    }

    /// Serializes the prefix.
    pub fn prefix_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_prefix(&mut out);
        out
    }

    /// The transaction id: the Keccak-256 hash of the prefix.
    pub fn prefix_hash(&self) -> [u8; 32] {
        cn_fast_hash(&self.prefix_bytes())
    }

    /// The fee, from the [`Variant::ZarcanumTxDataV1`] extra entry.
    pub fn fee(&self) -> Option<u64> {
        self.extra.iter().find_map(|e| match e {
            Variant::ZarcanumTxDataV1 { fee } => Some(*fee),
            _ => None,
        })
    }

    /// The transaction public key, from the [`Variant::PubKey`] extra entry.
    pub fn tx_pub_key(&self) -> Option<[u8; 32]> {
        self.extra.iter().find_map(|e| match e {
            Variant::PubKey(key) => Some(*key),
            _ => None,
        })
    }
}

impl Wire for Transaction {
    const MIN_SIZE: usize = 7;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let mut tx = Self::read_prefix(r)?;
        tx.attachment = r.vec()?;
        tx.signatures = r.vec()?;
        tx.proofs = r.vec()?;
        Ok(tx)
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.write_prefix(out);
        write_vec(out, &self.attachment);
        write_vec(out, &self.signatures);
        write_vec(out, &self.proofs);
    }
}
