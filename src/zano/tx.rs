//! Transactions: the structures of `currency_basic.h` this module handles
//! and their binary serialization.
//!
//! Points and scalars are kept as the 32 bytes that are on the wire; they are
//! decoded (and checked) where the cryptography uses them.

use crate::cryptonote::{cn_fast_hash, push_varint};
use crate::prelude::*;

use super::Error;
use super::scan::TxOutZarcanum;
use super::ser::{self, Reader, Wire, write_bytes, write_varints, write_vec};
use super::tx_ext::{
    AccountPublicAddrOld, AssetDescriptorOperation, AssetOperationProof, AssetOwnershipProof,
    AssetOwnershipProofEth, ExtraAliasEntry, ExtraAliasEntryOld, GatewayAddressOperation,
    GatewaySignature, NlsagSig, TxInGateway, TxInMultisig, TxOutBare, TxOutGateway, TxOutMultisig,
    TxOutToKey, TxOutZarcanumHf6, ZarcanumSig, ZcGwBalanceProof,
};

/// `TRANSACTION_VERSION_INITAL`.
pub const TRANSACTION_VERSION_INITIAL: u64 = 0;
/// `TRANSACTION_VERSION_PRE_HF4`.
pub const TRANSACTION_VERSION_PRE_HF4: u64 = 1;
/// `TRANSACTION_VERSION_POST_HF4`: confidential (Zarcanum) transactions.
pub const TRANSACTION_VERSION_POST_HF4: u64 = 2;
/// `TRANSACTION_VERSION_POST_HF5`: adds the hardfork id to the prefix.
pub const TRANSACTION_VERSION_POST_HF5: u64 = 3;
/// `TRANSACTION_VERSION_POST_HF6`: outputs carry an encrypted payment id.
pub const TRANSACTION_VERSION_POST_HF6: u64 = 4;

/// Hard fork 4 (Zarcanum): confidential transactions.
pub const HARDFORK_04_ZARCANUM: u8 = 4;
/// Hard fork 5.
pub const HARDFORK_05: u8 = 5;
/// Hard fork 6.
pub const HARDFORK_06: u8 = 6;
/// Hard fork 7.
pub const HARDFORK_07: u8 = 7;

/// The heights after which the hard forks of the main network are active
/// (`ZANO_HARDFORK_0x_AFTER_HEIGHT`), indexed by hard fork id: hard fork `n`
/// rules apply to blocks above `MAINNET_HARDFORK_HEIGHTS[n]`.
///
/// Hard forks 6 and 7 share a height: the gateway types hard fork 6
/// introduced never were valid on the main network.
pub const MAINNET_HARDFORK_HEIGHTS: [u64; 8] = [
    0, 194_624, 999_999, 1_082_577, 2_555_000, 3_076_400, 3_833_000, 3_833_000,
];

/// The id of the most recent hard fork active for a block at `height` of
/// the main network (`get_the_most_recent_hardfork_id_for_height`).
pub fn mainnet_hardfork_id(height: u64) -> u8 {
    let mut id = 0u8;
    for (n, after) in MAINNET_HARDFORK_HEIGHTS.iter().enumerate().skip(1) {
        if height > *after {
            id = n as u8;
        }
    }
    id
}

/// The transaction version to build for a block at `height` of the main
/// network, with the hard fork id to put in it
/// (`get_tx_version_and_hardfork_id`): version 1 up to block 2 555 000,
/// 2 up to 3 076 400, 3 up to 3 833 000 and 4 above.
pub fn mainnet_tx_version(height: u64) -> (u64, u8) {
    let id = mainnet_hardfork_id(height);
    (tx_version_for_hardfork(id), id)
}

/// The transaction version of a hard fork.
pub fn tx_version_for_hardfork(hardfork_id: u8) -> u64 {
    match hardfork_id {
        ..HARDFORK_04_ZARCANUM => TRANSACTION_VERSION_PRE_HF4,
        HARDFORK_04_ZARCANUM => TRANSACTION_VERSION_POST_HF4,
        HARDFORK_05 => TRANSACTION_VERSION_POST_HF5,
        _ => TRANSACTION_VERSION_POST_HF6,
    }
}

/// Implements [`Wire`] for a struct, field by field in declaration order.
macro_rules! wire_struct {
    (@read $r:ident, u8) => { $r.u8()? };
    (@read $r:ident, varints) => { $r.varints()? };
    (@read $r:ident, opt) => { $r.opt()? };
    (@write $out:ident, $v:expr, varints) => { write_varints($out, &$v) };
    (@write $out:ident, $v:expr, opt) => { write_opt($out, &$v) };
    (@read $r:ident, u16) => { $r.u16()? };
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

impl Wire for RefById {
    const MIN_SIZE: usize = 33;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(RefById {
            hash: r.key()?,
            // A varint, unlike in zanolib.
            n: u32::try_from(r.varint()?).map_err(|_| Error::InvalidEncoding)?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.hash);
        push_varint(out, u64::from(self.n));
    }
}

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

/// Declares [`Variant`]: each alternative with its tag, its JSON name and
/// how its payload is serialized.
macro_rules! variants {
    (@read $r:ident, $variant:ident, unit) => { Variant::$variant };
    (@read $r:ident, $variant:ident, boxed) => { Variant::$variant(Box::new(Wire::read($r)?)) };
    (@read $r:ident, $variant:ident, $kind:tt) => { Variant::$variant(wire_struct!(@read $r, $kind)) };
    ($( $(#[$doc:meta])* $tag:literal $name:literal $variant:ident $( ( $ty:ty ) )? : $kind:tt, )*) => {
        /// One alternative of the tagged unions (`boost::variant`) found in
        /// transactions: inputs, outputs, extra and attachment entries,
        /// signatures and proofs all share one tag space.
        ///
        /// The binary format has no length in front of a variant, so data
        /// holding a tag that is not listed here cannot be parsed
        /// ([`Error::UnsupportedVariant`]). Parsing accepts any alternative
        /// in any container; the reference only accepts some in each.
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum Variant {
            /// Tag 0, `txin_gen`: the coinbase input, with the block height.
            Gen {
                /// The height of the block.
                height: u64,
            },
            /// Tag 39, `zarcanum_tx_data_v1`: the fee.
            ZarcanumTxDataV1 {
                /// The fee, in atomic units of the native coin.
                fee: u64,
            },
            $( $(#[$doc])* $variant $( ( $ty ) )?, )*
        }

        impl Variant {
            /// The tag byte of this alternative.
            pub fn tag(&self) -> u8 {
                match self {
                    Variant::Gen { .. } => 0,
                    Variant::ZarcanumTxDataV1 { .. } => 39,
                    $( variants!(@pat $variant $( $ty )?) => $tag, )*
                }
            }

            /// The name Zano's JSON gives this alternative.
            pub fn name(&self) -> &'static str {
                match self {
                    Variant::Gen { .. } => "gen",
                    Variant::ZarcanumTxDataV1 { .. } => "zarcanum_tx_data_v1",
                    $( variants!(@pat $variant $( $ty )?) => $name, )*
                }
            }

            fn read_tagged(tag: u8, r: &mut Reader<'_>) -> Result<Self, Error> {
                Ok(match tag {
                    0 => Variant::Gen { height: r.varint()? },
                    39 => Variant::ZarcanumTxDataV1 { fee: r.u64()? },
                    $( $tag => variants!(@read r, $variant, $kind), )*
                    tag => return Err(Error::UnsupportedVariant(tag)),
                })
            }

            fn write_payload(&self, out: &mut Vec<u8>) {
                match self {
                    Variant::Gen { height } => push_varint(out, *height),
                    Variant::ZarcanumTxDataV1 { fee } => out.extend_from_slice(&fee.to_le_bytes()),
                    $( variants!(@arm $variant $( $ty )?, v) => { variants!(@w out, v, $kind) } )*
                }
            }
        }
    };
    (@pat $variant:ident) => { Variant::$variant };
    (@pat $variant:ident $ty:ty) => { Variant::$variant(_) };
    (@arm $variant:ident, $v:ident) => { Variant::$variant };
    (@arm $variant:ident $ty:ty, $v:ident) => { Variant::$variant($v) };
    (@w $out:ident, $v:ident, unit) => { () };
    (@w $out:ident, $v:ident, boxed) => { $v.write($out) };
    (@w $out:ident, $v:ident, obj) => { $v.write($out) };
    (@w $out:ident, $v:ident, bytes) => { write_bytes($out, $v) };
    (@w $out:ident, $v:ident, vec) => { write_vec($out, $v) };
    (@w $out:ident, $v:ident, varints) => { write_varints($out, $v) };
    (@w $out:ident, $v:ident, key) => { $out.extend_from_slice($v) };
    (@w $out:ident, $v:ident, varint) => { push_varint($out, *$v) };
    (@w $out:ident, $v:ident, u16) => { $out.extend_from_slice(&$v.to_le_bytes()) };
    (@w $out:ident, $v:ident, u32) => { $out.extend_from_slice(&$v.to_le_bytes()) };
    (@w $out:ident, $v:ident, u64) => { $out.extend_from_slice(&$v.to_le_bytes()) };
}

variants! {
    /// Tag 1, `txin_to_key`.
    1 "key" ToKey(TxInToKey): obj,
    /// Tag 2, `txin_multisig`.
    2 "multisig" InMultisig(TxInMultisig): obj,
    /// Tag 3, `txout_to_key`: the target of a [`TxOutBare`].
    3 "key" ToKeyTarget(TxOutToKey): obj,
    /// Tag 4, `txout_multisig`: the target of a [`TxOutBare`].
    4 "multisig" MultisigTarget(TxOutMultisig): obj,
    /// Tag 7, `tx_comment`.
    7 "comment" Comment(Vec<u8>): bytes,
    /// Tag 8, `tx_payer_old`.
    8 "payer" PayerOld(AccountPublicAddrOld): obj,
    /// Tag 9, a `std::string`.
    9 "string" String(Vec<u8>): bytes,
    /// Tag 10, `tx_crypto_checksum`.
    10 "checksum" CryptoChecksum(TxCryptoChecksum): obj,
    /// Tag 11, `tx_derivation_hint`: a
    /// [`derivation_hint`](super::derivation_hint), as two little-endian
    /// bytes.
    11 "derivation_hint" DerivationHint(Vec<u8>): bytes,
    /// Tag 12, `tx_service_attachment`.
    12 "attachment" ServiceAttachment(TxServiceAttachment): obj,
    /// Tag 14, `etc_tx_details_unlock_time`.
    14 "unlock_time" UnlockTime(u64): varint,
    /// Tag 15, `etc_tx_details_expiration_time`.
    15 "expiration_time" ExpirationTime(u64): varint,
    /// Tag 16, `etc_tx_details_flags`.
    16 "flags" Flags(u64): varint,
    /// Tag 17, `signed_parts`.
    17 "signed_outs" SignedParts(SignedParts): obj,
    /// Tag 18, `extra_attachment_info`.
    18 "extra_attach_info" ExtraAttachmentInfo(ExtraAttachmentInfo): obj,
    /// Tag 19, `extra_user_data`.
    19 "user_data" UserData(Vec<u8>): bytes,
    /// Tag 20, `extra_alias_entry_old`.
    20 "alias_entry" AliasEntryOld(ExtraAliasEntryOld): obj,
    /// Tag 21, `extra_padding`.
    21 "extra_padding" Padding(Vec<u8>): bytes,
    /// Tag 22, a `crypto::public_key`: in the extra, the transaction public
    /// key.
    22 "pub_key" PubKey([u8; 32]): key,
    /// Tag 23, `etc_tx_flags16_t`.
    23 "etc_tx_flags16" EtcTxFlags16(u16): u16,
    /// Tag 24, a `uint16_t` (`derive_xor`).
    24 "derive_xor" DeriveXor(u16): u16,
    /// Tag 25, `ref_by_id`.
    25 "ref_by_id" RefById(RefById): obj,
    /// Tag 26, a `uint64_t`: in a ring, a global output index.
    26 "uint64_t" Uint64(u64): u64,
    /// Tag 27, `etc_tx_time`.
    27 "etc_tx_time" EtcTxTime(u64): varint,
    /// Tag 28, a `uint32_t`.
    28 "uint32_t" Uint32(u32): u32,
    /// Tag 29, `tx_receiver_old`.
    29 "payer" ReceiverOld(AccountPublicAddrOld): obj,
    /// Tag 30, `etc_tx_details_unlock_time2`: one unlock time per output.
    30 "unlock_time2" UnlockTime2(Vec<u64>): varints,
    /// Tag 31, `tx_payer`.
    31 "payer2" Payer(AccountPublicAddr): obj,
    /// Tag 32, `tx_receiver`.
    32 "receiver2" Receiver(AccountPublicAddr): obj,
    /// Tag 33, `extra_alias_entry`.
    33 "alias_entry2" AliasEntry(ExtraAliasEntry): obj,
    /// Tag 36, `tx_out_bare`: a transparent output.
    36 "tx_out_bare" OutBare(TxOutBare): obj,
    /// Tag 37, `txin_zc_input`.
    37 "txin_zc_input" ZcInput(TxInZcInput): obj,
    /// Tag 38, `tx_out_zarcanum_v1`: the confidential output of
    /// transactions of version 2 and 3.
    38 "tx_out_zarcanum_v1" OutZarcanum(TxOutZarcanum): obj,
    /// Tag 42, `NLSAG_sig`: the ring signature of a transparent input.
    42 "NLSAG_sig" Nlsag(NlsagSig): obj,
    /// Tag 43, `ZC_sig`.
    43 "ZC_sig" ZcSig(ZcSig): obj,
    /// Tag 44, `void_sig`.
    44 "void_sig" VoidSig: unit,
    /// Tag 45, `zarcanum_sig`: the signature of the stake input of a
    /// proof-of-stake block.
    45 "zarcanum_sig" ZarcanumSig(Box<ZarcanumSig>): boxed,
    /// Tag 46, `zc_asset_surjection_proof`.
    46 "zc_asset_surjection_proof" AssetSurjectionProof(ZcAssetSurjectionProof): obj,
    /// Tag 47, `zc_outs_range_proof`.
    47 "zc_outs_range_proof" OutsRangeProof(ZcOutsRangeProof): obj,
    /// Tag 48, `zc_balance_proof`.
    48 "zc_balance_proof" BalanceProof(ZcBalanceProof): obj,
    /// Tag 49, `asset_descriptor_operation`.
    49 "asset_descriptor_base" AssetOperation(Box<AssetDescriptorOperation>): boxed,
    /// Tag 50, `asset_operation_proof`.
    50 "asset_operation_proof" AssetOperationProof(AssetOperationProof): obj,
    /// Tag 51, `asset_operation_ownership_proof`.
    51 "asset_operation_ownership_proof" AssetOwnershipProof(AssetOwnershipProof): obj,
    /// Tag 52, `asset_operation_ownership_proof_eth`.
    52 "asset_operation_ownership_proof_eth" AssetOwnershipProofEth(AssetOwnershipProofEth): obj,
    /// Tag 62, `dummy`: a reserved entry.
    62 "dummy" Dummy: unit,
    /// Tag 63, `tx_out_zarcanum`: the confidential output of transactions
    /// of version 4.
    63 "tx_out_zarcanum" OutZarcanumHf6(TxOutZarcanumHf6): obj,
    /// Tag 65, `txin_gateway`.
    65 "txin_gateway" InGateway(TxInGateway): obj,
    /// Tag 66, `tx_out_gateway`.
    66 "tx_out_gateway" OutGateway(TxOutGateway): obj,
    /// Tag 67, `gateway_sig`.
    67 "gateway_signature" GatewaySig(GatewaySignature): obj,
    /// Tag 73, `gateway_address_descriptor_operation`.
    73 "gateway_address_descriptor_operation" GatewayAddressOperation(Box<GatewayAddressOperation>): boxed,
    /// Tag 76, `gateway_address_ownership_proof`.
    76 "gateway_address_ownership_proof" GatewayAddressOwnershipProof(GatewaySignature): obj,
    /// Tag 77, `zc_gw_balance_proof`.
    77 "zc_gw_balance_proof" GwBalanceProof(ZcGwBalanceProof): obj,
    /// Tag 78, `etc_coinbase_block_cumulative_size`.
    78 "etc_coinbase_block_cumulative_size" CoinbaseBlockCumulativeSize(u64): varint,
}

impl Variant {
    /// The confidential output this alternative holds, without the payment
    /// id of a version 4 output: [`Variant::OutZarcanum`] or
    /// [`Variant::OutZarcanumHf6`].
    pub fn zarcanum_out(&self) -> Option<TxOutZarcanum> {
        match self {
            Variant::OutZarcanum(out) => Some(*out),
            Variant::OutZarcanumHf6(out) => Some(out.base()),
            _ => None,
        }
    }

    /// The key image of an input: [`Variant::ToKey`] or [`Variant::ZcInput`].
    pub fn key_image(&self) -> Option<&[u8; 32]> {
        match self {
            Variant::ToKey(input) => Some(&input.k_image),
            Variant::ZcInput(input) => Some(&input.key_image),
            _ => None,
        }
    }
}

impl Wire for Variant {
    // A tag; `void_sig` and `dummy` have nothing after it.
    const MIN_SIZE: usize = 1;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let tag = r.u8()?;
        r.enter()?;
        let variant = Self::read_tagged(tag, r);
        r.leave();
        variant
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        self.write_payload(out);
    }
}

/// A transaction.
///
/// The prefix — version, inputs, extra, outputs and, from version 3 on, the
/// hardfork id — is what the transaction id hashes; attachments, signatures
/// and proofs follow it.
///
/// Versions 0 and 1 (before hard fork 4) have another layout: outputs come
/// before the extra and are all [`Variant::OutBare`], signatures come
/// before the attachments and are all [`Variant::Nlsag`], neither with a
/// tag, and there are no proofs. A value of such a version holding anything
/// else does not serialize to a valid transaction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Transaction {
    /// The version (`TRANSACTION_VERSION_*`).
    pub version: u64,
    /// The inputs: [`Variant::Gen`], [`Variant::ToKey`],
    /// [`Variant::InMultisig`], [`Variant::ZcInput`] or
    /// [`Variant::InGateway`].
    pub vin: Vec<Variant>,
    /// The extra entries (transaction public key, hints, fee, ...).
    pub extra: Vec<Variant>,
    /// The outputs: [`Variant::OutBare`], [`Variant::OutZarcanum`]
    /// (versions 2 and 3), [`Variant::OutZarcanumHf6`] (version 4) or
    /// [`Variant::OutGateway`].
    pub vout: Vec<Variant>,
    /// The hardfork id, serialized (as part of the prefix) only from
    /// [`TRANSACTION_VERSION_POST_HF5`] on.
    pub hardfork_id: u8,
    /// The attachments.
    pub attachment: Vec<Variant>,
    /// One signature per input: [`Variant::Nlsag`], [`Variant::ZcSig`],
    /// [`Variant::ZarcanumSig`], [`Variant::VoidSig`] or
    /// [`Variant::GatewaySig`].
    pub signatures: Vec<Variant>,
    /// The transaction-wide proofs.
    pub proofs: Vec<Variant>,
}

/// The outputs of a version 0 or 1 transaction: bare outputs without tags.
fn read_bare_outs(r: &mut Reader<'_>) -> Result<Vec<Variant>, Error> {
    Ok(r.vec::<TxOutBare>()?
        .into_iter()
        .map(Variant::OutBare)
        .collect())
}

/// The signatures of a version 0 or 1 transaction: ring signatures without
/// tags.
fn read_bare_sigs(r: &mut Reader<'_>) -> Result<Vec<Variant>, Error> {
    Ok(r.vec::<NlsagSig>()?
        .into_iter()
        .map(Variant::Nlsag)
        .collect())
}

/// Writes variants without their tags (the layout of versions 0 and 1).
fn write_untagged(out: &mut Vec<u8>, items: &[Variant]) {
    push_varint(out, items.len() as u64);
    for item in items {
        item.write_payload(out);
    }
}

impl Transaction {
    /// Whether the transaction has the layout of versions 0 and 1.
    fn is_pre_hf4(&self) -> bool {
        self.version <= TRANSACTION_VERSION_PRE_HF4
    }

    fn read_prefix(r: &mut Reader<'_>) -> Result<Self, Error> {
        let version = r.varint()?;
        if version > TRANSACTION_VERSION_POST_HF6 {
            return Err(Error::UnsupportedVersion);
        }
        let mut tx = Transaction {
            version,
            vin: r.vec()?,
            ..Default::default()
        };
        if tx.is_pre_hf4() {
            tx.vout = read_bare_outs(r)?;
            tx.extra = r.vec()?;
            return Ok(tx);
        }
        tx.extra = r.vec()?;
        tx.vout = r.vec()?;
        if version >= TRANSACTION_VERSION_POST_HF5 {
            tx.hardfork_id = r.u8()?;
        }
        Ok(tx)
    }

    fn write_prefix(&self, out: &mut Vec<u8>) {
        push_varint(out, self.version);
        write_vec(out, &self.vin);
        if self.is_pre_hf4() {
            write_untagged(out, &self.vout);
            write_vec(out, &self.extra);
            return;
        }
        write_vec(out, &self.extra);
        write_vec(out, &self.vout);
        if self.version >= TRANSACTION_VERSION_POST_HF5 {
            out.push(self.hardfork_id);
        }
    }

    /// Parses a transaction, which must take the whole of `data`.
    ///
    /// Fails with [`Error::UnsupportedVersion`] for a version above 4.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        ser::from_bytes(data)
    }

    /// Parses only what scanning needs: the prefix and the attachments.
    /// Whatever follows is not looked at; `signatures` and `proofs` are
    /// left empty (for versions 0 and 1 the signatures come first and are
    /// parsed).
    pub fn from_bytes_for_scan(data: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(data);
        let mut tx = Self::read_prefix(&mut r)?;
        if tx.is_pre_hf4() {
            tx.signatures = read_bare_sigs(&mut r)?;
        }
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

    /// The fee declared in the extra: the sum of the
    /// [`Variant::ZarcanumTxDataV1`] entries, `None` without any (coinbase
    /// transactions, and versions 0 and 1, whose fee is what the inputs
    /// exceed the outputs by: see [`bare_fee`](Self::bare_fee)).
    pub fn fee(&self) -> Option<u64> {
        let mut fees = self.extra.iter().filter_map(|e| match e {
            Variant::ZarcanumTxDataV1 { fee } => Some(*fee),
            _ => None,
        });
        let first = fees.next()?;
        fees.try_fold(first, |acc, fee| acc.checked_add(fee))
    }

    /// The fee of a transaction of version 0 or 1: its transparent inputs
    /// minus its outputs. `None` if they overflow or the outputs exceed
    /// the inputs.
    pub fn bare_fee(&self) -> Option<u64> {
        let inputs = self.vin.iter().try_fold(0u64, |acc, input| match input {
            Variant::ToKey(input) => acc.checked_add(input.amount),
            Variant::InMultisig(input) => acc.checked_add(input.amount),
            _ => Some(acc),
        })?;
        let outputs = self.vout.iter().try_fold(0u64, |acc, out| match out {
            Variant::OutBare(out) => acc.checked_add(out.amount),
            _ => Some(acc),
        })?;
        inputs.checked_sub(outputs)
    }

    /// The transaction public key, from the [`Variant::PubKey`] extra entry.
    pub fn tx_pub_key(&self) -> Option<[u8; 32]> {
        self.extra.iter().find_map(|e| match e {
            Variant::PubKey(key) => Some(*key),
            _ => None,
        })
    }

    /// The transaction flags (`TX_FLAG_*`), from the [`Variant::Flags`]
    /// extra entry; zero without one.
    pub fn flags(&self) -> u64 {
        self.extra
            .iter()
            .find_map(|e| match e {
                Variant::Flags(flags) => Some(*flags),
                _ => None,
            })
            .unwrap_or(0)
    }

    /// The asset operation of the transaction, if it has one.
    pub fn asset_operation(&self) -> Option<&AssetDescriptorOperation> {
        self.extra.iter().find_map(|e| match e {
            Variant::AssetOperation(operation) => Some(&**operation),
            _ => None,
        })
    }

    /// Whether this is the first transaction of a block: its first input is
    /// a [`Variant::Gen`] (`is_coinbase`).
    pub fn is_coinbase(&self) -> bool {
        matches!(self.vin.first(), Some(Variant::Gen { .. }))
    }

    /// Whether this is the first transaction of a proof-of-stake block: a
    /// [`Variant::Gen`] and the stake input (`is_pos_miner_tx`).
    pub fn is_pos_coinbase(&self) -> bool {
        matches!(
            self.vin.as_slice(),
            [Variant::Gen { .. }, Variant::ToKey(_) | Variant::ZcInput(_)]
        )
    }
}

/// `TX_FLAG_SIGNATURE_MODE_SEPARATE`: each input signs the part of the
/// transaction that existed when it was added, so that several parties can
/// build one transaction.
pub const TX_FLAG_SIGNATURE_MODE_SEPARATE: u64 = 1;

impl Wire for Transaction {
    const MIN_SIZE: usize = 6;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let mut tx = Self::read_prefix(r)?;
        if tx.is_pre_hf4() {
            tx.signatures = read_bare_sigs(r)?;
            tx.attachment = r.vec()?;
            return Ok(tx);
        }
        tx.attachment = r.vec()?;
        tx.signatures = r.vec()?;
        tx.proofs = r.vec()?;
        Ok(tx)
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.write_prefix(out);
        if self.is_pre_hf4() {
            write_untagged(out, &self.signatures);
            write_vec(out, &self.attachment);
            return;
        }
        write_vec(out, &self.attachment);
        write_vec(out, &self.signatures);
        write_vec(out, &self.proofs);
    }
}
