//! The structures of `currency_basic.h` besides the ones a plain
//! confidential transfer uses: the pre-Zarcanum (transparent) inputs,
//! outputs and signatures, the proof-of-stake signature, asset operations
//! with their proofs, aliases, and the gateway types of hard fork 6.

use crate::cryptonote::push_varint;
use crate::prelude::*;

use super::Error;
use super::ser::{Reader, Wire, write_bytes, write_opt, write_vec};
use super::tx::{AccountPublicAddr, Variant, wire_struct};

/// Reads the version of a structure that only has a version 0.
fn version0(r: &mut Reader<'_>) -> Result<(), Error> {
    r.version(0).map(|_| ())
}

/// A multisig input (`txin_multisig`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxInMultisig {
    /// The amount spent.
    pub amount: u64,
    /// The id of the multisig output.
    pub multisig_out_id: [u8; 32],
    /// The number of signatures of the input.
    pub sigs_count: u64,
    /// [`Variant::SignedParts`] and [`Variant::ExtraAttachmentInfo`] entries.
    pub etc_details: Vec<Variant>,
}
wire_struct!(TxInMultisig, min = 35, {
    amount: varint, multisig_out_id: key, sigs_count: varint, etc_details: vec
});

/// The target of a transparent output paid to one key (`txout_to_key`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxOutToKey {
    /// The one-time public key.
    pub key: [u8; 32],
    /// The mixing attribute (`0`: any ring, `1`: must not be mixed, more:
    /// the least ring size).
    pub mix_attr: u8,
}
wire_struct!(TxOutToKey, min = 33, { key: key, mix_attr: u8 });

/// The target of a transparent multisig output (`txout_multisig`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxOutMultisig {
    /// The signatures needed to spend the output.
    pub minimum_sigs: u64,
    /// The keys of the participants.
    pub keys: Vec<[u8; 32]>,
}
wire_struct!(TxOutMultisig, min = 2, { minimum_sigs: varint, keys: vec });

/// A transparent (pre-Zarcanum) output (`tx_out_bare`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutBare {
    /// The amount.
    pub amount: u64,
    /// The target: [`Variant::ToKeyTarget`] or [`Variant::MultisigTarget`].
    pub target: Box<Variant>,
}

impl Wire for TxOutBare {
    const MIN_SIZE: usize = 3;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(TxOutBare {
            amount: r.varint()?,
            target: Box::new(Variant::read(r)?),
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_varint(out, self.amount);
        self.target.write(out);
    }
}

/// The public keys of an account without flags
/// (`account_public_address_old`), as transactions before hard fork 2 have
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccountPublicAddrOld {
    /// The public spend key.
    pub spend_key: [u8; 32],
    /// The public view key.
    pub view_key: [u8; 32],
}
wire_struct!(AccountPublicAddrOld, min = 64, { spend_key: key, view_key: key });

/// An alias registration or update, before hard fork 2
/// (`extra_alias_entry_old`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExtraAliasEntryOld {
    /// The alias.
    pub alias: Vec<u8>,
    /// The address it stands for.
    pub address: AccountPublicAddrOld,
    /// A comment.
    pub text_comment: Vec<u8>,
    /// The secret view key of the address, if its owner publishes it (at
    /// most one).
    pub view_key: Vec<[u8; 32]>,
    /// The signature of an update (at most one).
    pub sign: Vec<[u8; 64]>,
}
wire_struct!(ExtraAliasEntryOld, min = 68, {
    alias: bytes, address: obj, text_comment: bytes, view_key: vec, sign: vec
});

/// An alias registration or update (`extra_alias_entry`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExtraAliasEntry {
    /// The alias.
    pub alias: Vec<u8>,
    /// The address it stands for.
    pub address: AccountPublicAddr,
    /// A comment.
    pub text_comment: Vec<u8>,
    /// The secret view key of the address, if its owner publishes it (at
    /// most one).
    pub view_key: Vec<[u8; 32]>,
    /// The signature of an update (at most one).
    pub sign: Vec<[u8; 64]>,
}
wire_struct!(ExtraAliasEntry, min = 69, {
    alias: bytes, address: obj, text_comment: bytes, view_key: vec, sign: vec
});

/// The ring signature of a transparent input (`NLSAG_sig`): one CryptoNote
/// signature per ring member — or, for a multisig input, per participant.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NlsagSig {
    /// The signatures: `c` then `r`, 32 bytes each.
    pub s: Vec<[u8; 64]>,
}
wire_struct!(NlsagSig, min = 1, { s: vec });

/// A Bulletproofs+ range proof with a double-blinded commitment
/// (`bppe_signature_serialized`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BppeSignature {
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
    /// The response `delta_1`.
    pub delta_1: [u8; 32],
    /// The response `delta_2`.
    pub delta_2: [u8; 32],
}
wire_struct!(BppeSignature, min = 226, {
    lv: vec, rv: vec, a0: key, a: key, b: key, r: key, s: key, delta_1: key, delta_2: key
});

/// A CLSAG-GGXXG ring signature (`CLSAG_GGXXG_signature_serialized`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClsagGgxxgSig {
    /// The challenge at ring position 0.
    pub c: [u8; 32],
    /// The responses for the `G` layers (0, 1 and 4), one per ring member.
    pub r_g: Vec<[u8; 32]>,
    /// The responses for the `X` layers (2 and 3), one per ring member.
    pub r_x: Vec<[u8; 32]>,
    /// The auxiliary key image of layer 1, times `1/8`.
    pub k1: [u8; 32],
    /// The auxiliary key image of layer 2, times `1/8`.
    pub k2: [u8; 32],
    /// The auxiliary key image of layer 3, times `1/8`.
    pub k3: [u8; 32],
    /// The auxiliary key image of layer 4, times `1/8`.
    pub k4: [u8; 32],
}
wire_struct!(ClsagGgxxgSig, min = 162, {
    c: key, r_g: vec, r_x: vec, k1: key, k2: key, k3: key, k4: key
});

/// The signature of the stake input of a proof-of-stake block
/// (`zarcanum_sig`): the Zarcanum proof that the hidden stake amount meets
/// the difficulty, and the ring signature of the stake.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZarcanumSig {
    /// The scalar `d`.
    pub d: [u8; 32],
    /// The commitment `C`, times `1/8`.
    pub c_point: [u8; 32],
    /// The commitment `C'`, times `1/8`.
    pub c_prime: [u8; 32],
    /// The commitment `E`, times `1/8`.
    pub e: [u8; 32],
    /// The challenge shared by the three proofs below.
    pub c: [u8; 32],
    /// First response of the proof that `C + C'` is a combination of `X` and
    /// `H + G`.
    pub y0: [u8; 32],
    /// Second response of that proof.
    pub y1: [u8; 32],
    /// First response of the proof that `C - C'` is a combination of `X` and
    /// `H - G`.
    pub y2: [u8; 32],
    /// Second response of that proof.
    pub y3: [u8; 32],
    /// The response of the Schnorr proof.
    pub y4: [u8; 32],
    /// The range proof of `E`.
    pub e_range_proof: BppeSignature,
    /// The pseudo-output amount commitment, times `1/8`.
    pub pseudo_out_amount_commitment: [u8; 32],
    /// The ring signature.
    pub clsag_ggxxg: ClsagGgxxgSig,
}
wire_struct!(ZarcanumSig, min = 740, {
    d: key, c_point: key, c_prime: key, e: key, c: key, y0: key, y1: key, y2: key,
    y3: key, y4: key, e_range_proof: obj, pseudo_out_amount_commitment: key,
    clsag_ggxxg: obj
});

/// `asset_descriptor_base::version` of hard fork 4.
pub const ASSET_DESCRIPTOR_BASE_HF4_VER: u8 = 0;
/// `asset_descriptor_base::version` from hard fork 5 on.
pub const ASSET_DESCRIPTOR_BASE_HF5_VER: u8 = 2;
/// `asset_descriptor_operation::version` of hard fork 4.
pub const ASSET_DESCRIPTOR_OPERATION_HF4_VER: u8 = 1;
/// `asset_descriptor_operation::version` from hard fork 5 on.
pub const ASSET_DESCRIPTOR_OPERATION_HF5_VER: u8 = 2;

/// `asset_descriptor_operation::operation_type`: registers a new asset and
/// emits its first coins.
pub const ASSET_DESCRIPTOR_OPERATION_REGISTER: u8 = 1;
/// Operation type: emits more coins of an asset.
pub const ASSET_DESCRIPTOR_OPERATION_EMIT: u8 = 2;
/// Operation type: changes the descriptor of an asset (its owner, its meta
/// information).
pub const ASSET_DESCRIPTOR_OPERATION_UPDATE: u8 = 3;
/// Operation type: burns coins of an asset in the open.
pub const ASSET_DESCRIPTOR_OPERATION_PUBLIC_BURN: u8 = 4;

/// The description of an asset (`asset_descriptor_base`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AssetDescriptorBase {
    /// The most coins that can ever exist.
    pub total_max_supply: u64,
    /// The coins emitted so far.
    pub current_supply: u64,
    /// The number of decimals.
    pub decimal_point: u8,
    /// The ticker.
    pub ticker: Vec<u8>,
    /// The full name.
    pub full_name: Vec<u8>,
    /// Free-form information (JSON by convention).
    pub meta_info: Vec<u8>,
    /// The key of the owner, who may emit and update. Zero when the owner
    /// is an Ethereum key.
    pub owner: [u8; 32],
    /// Reserved.
    pub hidden_supply: bool,
    /// The version of the structure: it tells which of the fields below are
    /// serialized.
    pub version: u8,
    /// From version 1: the compressed secp256k1 key of the owner, if the
    /// asset is controlled by an Ethereum key.
    pub owner_eth_pub_key: Option<[u8; 33]>,
    /// From version 2: reserved entries ([`Variant::Dummy`]).
    pub etc: Vec<Variant>,
}

impl Wire for AssetDescriptorBase {
    const MIN_SIZE: usize = 54;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let version = r.version(ASSET_DESCRIPTOR_BASE_HF5_VER)?;
        let mut adb = AssetDescriptorBase {
            total_max_supply: r.u64()?,
            current_supply: r.u64()?,
            decimal_point: r.u8()?,
            ticker: r.bytes()?,
            full_name: r.bytes()?,
            meta_info: r.bytes()?,
            owner: r.key()?,
            hidden_supply: r.bool()?,
            version,
            ..Default::default()
        };
        if version >= 1 {
            adb.owner_eth_pub_key = r.opt()?;
        }
        if version >= 2 {
            adb.etc = r.vec()?;
        }
        Ok(adb)
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_varint(out, u64::from(self.version));
        out.extend_from_slice(&self.total_max_supply.to_le_bytes());
        out.extend_from_slice(&self.current_supply.to_le_bytes());
        out.push(self.decimal_point);
        write_bytes(out, &self.ticker);
        write_bytes(out, &self.full_name);
        write_bytes(out, &self.meta_info);
        out.extend_from_slice(&self.owner);
        out.push(u8::from(self.hidden_supply));
        if self.version >= 1 {
            write_opt(out, &self.owner_eth_pub_key);
        }
        if self.version >= 2 {
            write_vec(out, &self.etc);
        }
    }
}

/// An operation on an asset, in the extra of a transaction
/// (`asset_descriptor_operation`).
///
/// Versions 0 and 1 (hard fork 4) always carry a descriptor and an amount
/// commitment on the wire, and neither amount nor salt; they are read into
/// the same optional fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AssetDescriptorOperation {
    /// The operation (`ASSET_DESCRIPTOR_OPERATION_*`).
    pub operation_type: u8,
    /// The version of the structure.
    pub version: u8,
    /// The commitment `amount * asset_id + mask * G` to the amount emitted
    /// or burnt, times `1/8` (register, emit, burn).
    pub amount_commitment: Option<[u8; 32]>,
    /// The asset operated on (emit, update, burn).
    pub asset_id: Option<[u8; 32]>,
    /// The descriptor (register, update; always there before version 2).
    pub descriptor: Option<AssetDescriptorBase>,
    /// From version 2: the amount emitted or burnt.
    pub amount: Option<u64>,
    /// From version 2: a salt for the asset id of a registration.
    pub asset_id_salt: Option<u32>,
    /// From version 2: reserved entries ([`Variant::Dummy`]).
    pub etc: Vec<Variant>,
}

impl Wire for AssetDescriptorOperation {
    const MIN_SIZE: usize = 8;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let version = r.version(ASSET_DESCRIPTOR_OPERATION_HF5_VER)?;
        if version < ASSET_DESCRIPTOR_OPERATION_HF5_VER {
            // asset_descriptor_operation_v1
            return Ok(AssetDescriptorOperation {
                version,
                operation_type: r.u8()?,
                descriptor: Some(Wire::read(r)?),
                amount_commitment: Some(r.key()?),
                asset_id: r.opt()?,
                ..Default::default()
            });
        }
        Ok(AssetDescriptorOperation {
            version,
            operation_type: r.u8()?,
            amount_commitment: r.opt()?,
            asset_id: r.opt()?,
            descriptor: r.opt()?,
            amount: r.opt()?,
            asset_id_salt: r.opt()?,
            etc: r.vec()?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_varint(out, u64::from(self.version));
        out.push(self.operation_type);
        if self.version < ASSET_DESCRIPTOR_OPERATION_HF5_VER {
            match &self.descriptor {
                Some(descriptor) => descriptor.write(out),
                None => AssetDescriptorBase::default().write(out),
            }
            out.extend_from_slice(&self.amount_commitment.unwrap_or_default());
            write_opt(out, &self.asset_id);
            return;
        }
        write_opt(out, &self.amount_commitment);
        write_opt(out, &self.asset_id);
        write_opt(out, &self.descriptor);
        write_opt(out, &self.amount);
        write_opt(out, &self.asset_id_salt);
        write_vec(out, &self.etc);
    }
}

/// A proof of knowing how a point is a combination of two generators
/// (`linear_composition_proof_s`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinearCompositionProof {
    /// The challenge.
    pub c: [u8; 32],
    /// The response for the first generator.
    pub y0: [u8; 32],
    /// The response for the second generator.
    pub y1: [u8; 32],
}
wire_struct!(LinearCompositionProof, min = 96, { c: key, y0: key, y1: key });

/// The proof that the amount commitment of an asset operation commits to
/// its declared amount (`asset_operation_proof`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AssetOperationProof {
    /// For a hidden supply (not in use): the commitment is a combination of
    /// the asset id and `G`.
    pub amount_commitment_composition_proof: Option<LinearCompositionProof>,
    /// For an open supply: a signature of the transaction id with the key
    /// `8 * commitment - amount * asset_id`, which only a multiple of `G`
    /// can make.
    pub amount_commitment_g_proof: Option<[u8; 64]>,
}

impl Wire for AssetOperationProof {
    const MIN_SIZE: usize = 3;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        version0(r)?;
        Ok(AssetOperationProof {
            amount_commitment_composition_proof: r.opt()?,
            amount_commitment_g_proof: r.opt()?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(0);
        write_opt(out, &self.amount_commitment_composition_proof);
        write_opt(out, &self.amount_commitment_g_proof);
    }
}

/// A Schnorr signature with its challenge (`generic_schnorr_sig_s`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SchnorrSig {
    /// The challenge.
    pub c: [u8; 32],
    /// The response.
    pub y: [u8; 32],
}
wire_struct!(SchnorrSig, min = 64, { c: key, y: key });

/// The signature of an asset operation by the asset's owner
/// (`asset_operation_ownership_proof`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AssetOwnershipProof {
    /// The signature of the transaction id with the owner's key.
    pub gss: SchnorrSig,
}

impl Wire for AssetOwnershipProof {
    const MIN_SIZE: usize = 65;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        version0(r)?;
        Ok(AssetOwnershipProof {
            gss: Wire::read(r)?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(0);
        self.gss.write(out);
    }
}

/// The signature of an asset operation by an owner that is an Ethereum key
/// (`asset_operation_ownership_proof_eth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetOwnershipProofEth {
    /// The secp256k1 ECDSA signature of the transaction id: `r` then `s`.
    pub eth_sig: [u8; 64],
}

impl Wire for AssetOwnershipProofEth {
    const MIN_SIZE: usize = 65;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        version0(r)?;
        Ok(AssetOwnershipProofEth {
            eth_sig: r.array()?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(0);
        out.extend_from_slice(&self.eth_sig);
    }
}

/// A confidential output from hard fork 6 on (`tx_out_zarcanum`): a
/// [`TxOutZarcanum`](super::TxOutZarcanum) with an encrypted payment id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxOutZarcanumHf6 {
    /// The one-time public key of the output.
    pub stealth_address: [u8; 32],
    /// The concealing point `Q`, times `1/8`.
    pub concealing_point: [u8; 32],
    /// The amount commitment `amount * T + y * G`, times `1/8`.
    pub amount_commitment: [u8; 32],
    /// The blinded asset id `T = asset_id + s * X`, times `1/8`.
    pub blinded_asset_id: [u8; 32],
    /// The amount, XORed with a mask only the two parties can derive.
    pub encrypted_amount: u64,
    /// The payment id of the output (zero for none), XORed with another
    /// such mask.
    pub encrypted_payment_id: u64,
    /// The mixing attribute.
    pub mix_attr: u8,
}

impl TxOutZarcanumHf6 {
    /// The output without its payment id: what scanning and the proofs
    /// work on.
    pub fn base(&self) -> super::TxOutZarcanum {
        super::TxOutZarcanum {
            stealth_address: self.stealth_address,
            concealing_point: self.concealing_point,
            amount_commitment: self.amount_commitment,
            blinded_asset_id: self.blinded_asset_id,
            encrypted_amount: self.encrypted_amount,
            mix_attr: self.mix_attr,
        }
    }
}

impl Wire for TxOutZarcanumHf6 {
    const MIN_SIZE: usize = 146;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        version0(r)?;
        Ok(TxOutZarcanumHf6 {
            stealth_address: r.key()?,
            concealing_point: r.key()?,
            amount_commitment: r.key()?,
            blinded_asset_id: r.key()?,
            encrypted_amount: r.u64()?,
            encrypted_payment_id: r.u64()?,
            mix_attr: r.u8()?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(0);
        out.extend_from_slice(&self.stealth_address);
        out.extend_from_slice(&self.concealing_point);
        out.extend_from_slice(&self.amount_commitment);
        out.extend_from_slice(&self.blinded_asset_id);
        out.extend_from_slice(&self.encrypted_amount.to_le_bytes());
        out.extend_from_slice(&self.encrypted_payment_id.to_le_bytes());
        out.push(self.mix_attr);
    }
}

/// An input that spends from a gateway address (`txin_gateway`). Hard fork
/// 6 only: the main network never accepted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxInGateway {
    /// The gateway address.
    pub gateway_addr: [u8; 32],
    /// The asset id, times `1/8`.
    pub asset_id: [u8; 32],
    /// The amount.
    pub amount: u64,
    /// The trailing version field (the structure serializes it twice).
    pub version: u64,
}

impl Wire for TxInGateway {
    const MIN_SIZE: usize = 67;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        version0(r)?;
        Ok(TxInGateway {
            gateway_addr: r.key()?,
            asset_id: r.key()?,
            amount: r.varint()?,
            version: r.varint()?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(0);
        out.extend_from_slice(&self.gateway_addr);
        out.extend_from_slice(&self.asset_id);
        push_varint(out, self.amount);
        push_varint(out, self.version);
    }
}

/// An output paid to a gateway address, in the open (`tx_out_gateway`).
/// Hard fork 6 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxOutGateway {
    /// The gateway address.
    pub gateway_addr: [u8; 32],
    /// The asset id, times `1/8`.
    pub asset_id: [u8; 32],
    /// The amount.
    pub amount: u64,
    /// The payment id.
    pub payment_id: u64,
}

impl Wire for TxOutGateway {
    const MIN_SIZE: usize = 74;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        version0(r)?;
        Ok(TxOutGateway {
            gateway_addr: r.key()?,
            asset_id: r.key()?,
            amount: r.varint()?,
            payment_id: r.u64()?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(0);
        out.extend_from_slice(&self.gateway_addr);
        out.extend_from_slice(&self.asset_id);
        push_varint(out, self.amount);
        out.extend_from_slice(&self.payment_id.to_le_bytes());
    }
}

/// A signature by the owner of a gateway address (`gateway_signature_v`,
/// `gateway_owner_signature_v`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewaySignature {
    /// Tag 70: a Schnorr signature with a Zano key.
    Schnorr(SchnorrSig),
    /// Tag 71: a secp256k1 ECDSA signature.
    Eth([u8; 64]),
    /// Tag 68: an Ed25519 signature.
    Eddsa([u8; 64]),
}

impl Default for GatewaySignature {
    fn default() -> Self {
        GatewaySignature::Schnorr(SchnorrSig::default())
    }
}

impl Wire for GatewaySignature {
    // A version, a tag and 64 bytes.
    const MIN_SIZE: usize = 66;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        version0(r)?;
        Ok(match r.u8()? {
            70 => GatewaySignature::Schnorr(Wire::read(r)?),
            71 => GatewaySignature::Eth(r.array()?),
            68 => GatewaySignature::Eddsa(r.array()?),
            tag => return Err(Error::UnsupportedVariant(tag)),
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(0);
        match self {
            GatewaySignature::Schnorr(sig) => {
                out.push(70);
                sig.write(out);
            }
            GatewaySignature::Eth(sig) => {
                out.push(71);
                out.extend_from_slice(sig);
            }
            GatewaySignature::Eddsa(sig) => {
                out.push(68);
                out.extend_from_slice(sig);
            }
        }
    }
}

/// The key that controls a gateway address (`gateway_owner_key_v`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayOwnerKey {
    /// Tag 22: a Zano public key.
    Zano([u8; 32]),
    /// Tag 60: a compressed secp256k1 public key.
    Eth([u8; 33]),
    /// Tag 69: an Ed25519 public key.
    Eddsa([u8; 32]),
}

impl Default for GatewayOwnerKey {
    fn default() -> Self {
        GatewayOwnerKey::Zano([0u8; 32])
    }
}

/// The description of a gateway address (`gateway_address_descriptor_base`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GatewayAddressDescriptor {
    /// The key of the owner.
    pub owner_key: GatewayOwnerKey,
    /// Reserved entries ([`Variant::Dummy`]).
    pub etc: Vec<Variant>,
    /// Free-form information.
    pub meta_info: Vec<u8>,
}

impl Wire for GatewayAddressDescriptor {
    const MIN_SIZE: usize = 36;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        version0(r)?;
        let owner_key = match r.u8()? {
            22 => GatewayOwnerKey::Zano(r.key()?),
            60 => GatewayOwnerKey::Eth(r.array()?),
            69 => GatewayOwnerKey::Eddsa(r.key()?),
            tag => return Err(Error::UnsupportedVariant(tag)),
        };
        Ok(GatewayAddressDescriptor {
            owner_key,
            etc: r.vec()?,
            meta_info: r.bytes()?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(0);
        match &self.owner_key {
            GatewayOwnerKey::Zano(key) => {
                out.push(22);
                out.extend_from_slice(key);
            }
            GatewayOwnerKey::Eth(key) => {
                out.push(60);
                out.extend_from_slice(key);
            }
            GatewayOwnerKey::Eddsa(key) => {
                out.push(69);
                out.extend_from_slice(key);
            }
        }
        write_vec(out, &self.etc);
        write_bytes(out, &self.meta_info);
    }
}

/// The registration or the update of a gateway address
/// (`gateway_address_descriptor_operation`). Hard fork 6 only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayAddressOperation {
    /// Tag 74: registers an address.
    Register {
        /// The public view key of the address (not multiplied by `1/8`).
        view_pub_key: [u8; 32],
        /// Its descriptor.
        descriptor: GatewayAddressDescriptor,
    },
    /// Tag 75: replaces the descriptor of an address.
    Update {
        /// The address.
        address_id: [u8; 32],
        /// Its new descriptor.
        descriptor: GatewayAddressDescriptor,
    },
}

impl Wire for GatewayAddressOperation {
    const MIN_SIZE: usize = 71;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        version0(r)?;
        let tag = r.u8()?;
        if tag != 74 && tag != 75 {
            return Err(Error::UnsupportedVariant(tag));
        }
        version0(r)?;
        let key = r.key()?;
        let descriptor = Wire::read(r)?;
        Ok(if tag == 74 {
            GatewayAddressOperation::Register {
                view_pub_key: key,
                descriptor,
            }
        } else {
            GatewayAddressOperation::Update {
                address_id: key,
                descriptor,
            }
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        let (tag, key, descriptor) = match self {
            GatewayAddressOperation::Register {
                view_pub_key,
                descriptor,
            } => (74, view_pub_key, descriptor),
            GatewayAddressOperation::Update {
                address_id,
                descriptor,
            } => (75, address_id, descriptor),
        };
        out.extend_from_slice(&[0, tag, 0]);
        out.extend_from_slice(key);
        descriptor.write(out);
    }
}

/// The balance proof of a transaction without confidential inputs that has
/// non-native assets (`zc_gw_balance_proof`): a proof that the balance is a
/// combination of `G` and `X`, with a Schnorr proof of the transaction
/// secret key. Hard fork 6 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ZcGwBalanceProof {
    /// The challenge.
    pub c: [u8; 32],
    /// The response for `G`.
    pub y0: [u8; 32],
    /// The response for `X`.
    pub y1: [u8; 32],
    /// The response for the transaction key.
    pub y2: [u8; 32],
}
wire_struct!(ZcGwBalanceProof, min = 128, { c: key, y0: key, y1: key, y2: key });
