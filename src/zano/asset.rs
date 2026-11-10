//! Assets: the derivation of an asset id from its descriptor, and the
//! proofs an asset operation comes with.

use crate::cryptonote::{EdwardsPoint, Hasher, cn_fast_hash, point_from_hash};

use super::crypto::{self, mul_vartime, scalar_u64};
use super::nlsag::verify_schnorr_sig;
use super::tx::{Transaction, Variant};
use super::tx_ext::{
    ASSET_DESCRIPTOR_OPERATION_EMIT, ASSET_DESCRIPTOR_OPERATION_HF5_VER,
    ASSET_DESCRIPTOR_OPERATION_PUBLIC_BURN, ASSET_DESCRIPTOR_OPERATION_REGISTER,
    ASSET_DESCRIPTOR_OPERATION_UPDATE, AssetDescriptorBase, AssetDescriptorOperation,
    AssetOperationProof,
};
use super::verify::VerifyError;

const HDS_ASSET_ID: &[u8; 32] = b"ZANO_HDS_ASSET_ID______________\0";
/// `CRYPTO_HASH_ASSET_ID_ITERATIONS`.
const ASSET_ID_ITERATIONS: u64 = 1024;

/// The 32 bytes of a `u64` as a scalar.
fn scalar_bytes(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&value.to_le_bytes());
    out
}

impl AssetDescriptorBase {
    /// The id of the asset this descriptor registers, with the optional
    /// salt of the registration (`get_or_calculate_asset_id`): a point
    /// hashed from the ticker, the names, the maximum supply, the decimals
    /// and the owner — not from the current supply.
    pub fn asset_id(&self, salt: Option<u32>) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(HDS_ASSET_ID);
        hasher.update(&cn_fast_hash(&self.ticker));
        hasher.update(&cn_fast_hash(&self.full_name));
        hasher.update(&cn_fast_hash(&self.meta_info));
        hasher.update(&scalar_bytes(self.total_max_supply));
        hasher.update(&scalar_bytes(u64::from(self.decimal_point)));
        hasher.update(&self.owner);
        if let Some(key) = &self.owner_eth_pub_key {
            // Two 32-byte items hold the 33 bytes of the key.
            let mut items = [0u8; 64];
            items[..33].copy_from_slice(key);
            hasher.update(&items);
        }
        if let Some(salt) = salt {
            hasher.update(&scalar_bytes(u64::from(salt)));
        }
        let mut hash = hasher.finalize();
        for i in 0..ASSET_ID_ITERATIONS {
            let mut hasher = Hasher::new();
            hasher.update(HDS_ASSET_ID);
            hasher.update(&hash);
            hasher.update(&i.to_le_bytes());
            hash = hasher.finalize();
        }
        point_from_hash(&hash).compress()
    }
}

impl AssetDescriptorOperation {
    /// The id of the asset the operation is about
    /// (`get_or_calculate_asset_id`): the one it names, or for a
    /// registration the one its descriptor derives
    /// ([`AssetDescriptorBase::asset_id`], a thousand hashes). `None` if the
    /// field it needs is missing or the operation type is unknown.
    pub fn target_asset_id(&self) -> Option<[u8; 32]> {
        match self.operation_type {
            ASSET_DESCRIPTOR_OPERATION_EMIT
            | ASSET_DESCRIPTOR_OPERATION_UPDATE
            | ASSET_DESCRIPTOR_OPERATION_PUBLIC_BURN => self.asset_id,
            ASSET_DESCRIPTOR_OPERATION_REGISTER => {
                Some(self.descriptor.as_ref()?.asset_id(self.asset_id_salt))
            }
            _ => None,
        }
    }

    /// Whether the operation creates coins: a registration or an emission
    /// (`is_asset_emitting_transaction`).
    pub fn is_emitting(&self) -> bool {
        matches!(
            self.operation_type,
            ASSET_DESCRIPTOR_OPERATION_REGISTER | ASSET_DESCRIPTOR_OPERATION_EMIT
        )
    }
}

/// Half the order of secp256k1, big-endian: a signature with a larger `s`
/// is not accepted (as libsecp256k1 does not).
#[cfg(feature = "secp256k1")]
const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Verifies the signature of `m` by a compressed secp256k1 key
/// (`verify_eth_signature`): plain ECDSA over the 32 bytes, with a low `s`.
#[cfg(feature = "secp256k1")]
pub fn verify_eth_signature(m: &[u8; 32], public: &[u8; 33], sig: &[u8; 64]) -> bool {
    use purecrypto::ec::secp256k1::ecdsa::{Secp256k1EcdsaPublicKey, Secp256k1EcdsaSignature};

    let Some((_, s)) = sig.split_first_chunk::<32>() else {
        return false;
    };
    if s > SECP256K1_HALF_ORDER.as_slice() {
        return false;
    }
    let Ok(key) = Secp256k1EcdsaPublicKey::from_sec1(public) else {
        return false;
    };
    key.verify_prehash(m, &Secp256k1EcdsaSignature::from_bytes(sig))
        .is_ok()
}

impl Transaction {
    /// Verifies the asset operation of the transaction, if it has one
    /// (`validate_asset_operation`, for what a transaction shows by
    /// itself):
    ///
    /// - for a registration, an emission and a burn, the proof that the
    ///   amount commitment commits to the declared amount of the asset;
    /// - for an emission and an update, the signature of the asset's owner.
    ///
    /// `previous` is the descriptor of the asset before this operation, as
    /// the chain has it: it gives the owner, and for operations of hard
    /// fork 4 (version below 2) the supply the amount is relative to. It is
    /// not needed for a registration. Without it, an emission, an update or
    /// a version 1 burn fails with [`VerifyError::MissingAssetDescriptor`].
    ///
    /// What depends on the chain alone is not checked: that the asset is
    /// (not) registered yet, the supply limits, the fields an update may
    /// change.
    pub fn verify_asset_operation(
        &self,
        previous: Option<&AssetDescriptorBase>,
    ) -> Result<(), VerifyError> {
        let Some(ado) = self.asset_operation() else {
            return Ok(());
        };
        let tx_id = self.prefix_hash();
        let asset_id = ado.target_asset_id().ok_or(VerifyError::Malformed)?;
        let hf5 = ado.version >= ASSET_DESCRIPTOR_OPERATION_HF5_VER;
        let needs_previous = || previous.ok_or(VerifyError::MissingAssetDescriptor);
        // The supply before and after, for the operations of hard fork 4.
        let supplies = || -> Result<(u64, u64), VerifyError> {
            let descriptor = ado.descriptor.as_ref().ok_or(VerifyError::Malformed)?;
            Ok((needs_previous()?.current_supply, descriptor.current_supply))
        };

        let amount = match ado.operation_type {
            ASSET_DESCRIPTOR_OPERATION_REGISTER => {
                let descriptor = ado.descriptor.as_ref().ok_or(VerifyError::Malformed)?;
                if hf5 && ado.amount != Some(descriptor.current_supply) {
                    return Err(VerifyError::AssetOperation);
                }
                Some(descriptor.current_supply)
            }
            ASSET_DESCRIPTOR_OPERATION_EMIT => {
                verify_ownership(self, &tx_id, needs_previous()?)?;
                if hf5 {
                    Some(ado.amount.ok_or(VerifyError::Malformed)?)
                } else {
                    let (before, after) = supplies()?;
                    Some(
                        after
                            .checked_sub(before)
                            .filter(|emitted| *emitted != 0)
                            .ok_or(VerifyError::AssetOperation)?,
                    )
                }
            }
            ASSET_DESCRIPTOR_OPERATION_UPDATE => {
                verify_ownership(self, &tx_id, needs_previous()?)?;
                None
            }
            ASSET_DESCRIPTOR_OPERATION_PUBLIC_BURN => {
                if hf5 {
                    Some(ado.amount.ok_or(VerifyError::Malformed)?)
                } else {
                    let (before, after) = supplies()?;
                    Some(
                        before
                            .checked_sub(after)
                            .filter(|burnt| *burnt != 0)
                            .ok_or(VerifyError::AssetOperation)?,
                    )
                }
            }
            _ => return Err(VerifyError::Malformed),
        };
        let Some(amount) = amount else {
            return Ok(());
        };

        // validate_asset_operation_amount_commitment
        let mut proofs = self.proofs.iter().filter_map(|p| match p {
            Variant::AssetOperationProof(proof) => Some(proof),
            _ => None,
        });
        let (Some(proof), None) = (proofs.next(), proofs.next()) else {
            return Err(VerifyError::Malformed);
        };
        if ado.descriptor.as_ref().is_some_and(|d| d.hidden_supply) {
            return Err(VerifyError::Unsupported);
        }
        let AssetOperationProof {
            amount_commitment_g_proof: Some(g_proof),
            ..
        } = proof
        else {
            return Err(VerifyError::Malformed);
        };
        let commitment = ado.amount_commitment.ok_or(VerifyError::Malformed)?;
        let point = |bytes: &[u8; 32]| crypto::point(bytes).map_err(|_| VerifyError::Malformed);
        // A = 8 * commitment - amount * asset_id must be a multiple of G.
        let a: EdwardsPoint = point(&commitment)?
            .mul_by_cofactor()
            .sub(&mul_vartime(&scalar_u64(amount), &point(&asset_id)?));
        if crate::cryptonote::check_signature(&tx_id, &a.compress(), g_proof) {
            Ok(())
        } else {
            Err(VerifyError::AssetOperation)
        }
    }
}

/// `validate_ado_ownership`: the owner of the asset signed the transaction.
fn verify_ownership(
    tx: &Transaction,
    tx_id: &[u8; 32],
    previous: &AssetDescriptorBase,
) -> Result<(), VerifyError> {
    if let Some(eth_key) = &previous.owner_eth_pub_key {
        if previous.owner != [0u8; 32] {
            return Err(VerifyError::AssetOwnership);
        }
        let sig = tx
            .proofs
            .iter()
            .find_map(|p| match p {
                Variant::AssetOwnershipProofEth(proof) => Some(&proof.eth_sig),
                _ => None,
            })
            .ok_or(VerifyError::Malformed)?;
        #[cfg(feature = "secp256k1")]
        {
            return if verify_eth_signature(tx_id, eth_key, sig) {
                Ok(())
            } else {
                Err(VerifyError::AssetOwnership)
            };
        }
        #[cfg(not(feature = "secp256k1"))]
        {
            let _ = (eth_key, sig);
            return Err(VerifyError::Unsupported);
        }
    }
    let proof = tx
        .proofs
        .iter()
        .find_map(|p| match p {
            Variant::AssetOwnershipProof(proof) => Some(proof),
            _ => None,
        })
        .ok_or(VerifyError::Malformed)?;
    if verify_schnorr_sig(tx_id, &previous.owner, &proof.gss) {
        Ok(())
    } else {
        Err(VerifyError::AssetOwnership)
    }
}
