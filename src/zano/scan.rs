//! Finding and decoding the outputs paid to a wallet, with the view key
//! only.

use purecrypto::zeroize::Zeroizing;

use crate::cryptonote::{EdwardsPoint, Scalar};

#[cfg(feature = "alloc")]
use crate::prelude::*;

use super::chacha8::chacha8_crypt;
use super::crypto::{self, NATIVE_COIN_ASSET_ID, OutputSecrets};
use super::{Error, Wallet};

/// A confidential (Zarcanum, post-HF4) transaction output
/// (`tx_out_zarcanum`). The points are stored multiplied by `1/8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxOutZarcanum {
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
    /// The mixing attribute (`1`: must not be mixed, as for outputs to an
    /// auditable address).
    pub mix_attr: u8,
}

/// An output found to belong to the wallet, with what is needed to spend it
/// later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivedOutput {
    /// The index of the output in its transaction.
    pub output_index: u64,
    /// The amount, in atomic units of the asset.
    pub amount: u64,
    /// The asset id, unblinded.
    pub asset_id: [u8; 32],
    /// Whether the asset is the native coin.
    pub is_native: bool,
    /// The one-time public key of the output.
    pub stealth_address: [u8; 32],
    /// The blinding mask of the amount commitment.
    pub amount_blinding_mask: [u8; 32],
    /// The blinding mask of the asset id (zero for a bare native id).
    pub asset_id_blinding_mask: [u8; 32],
}

impl Wallet {
    /// The key derivation `8 * view_secret * tx_public_key` the wallet shares
    /// with the sender of a transaction (`generate_key_derivation`). The
    /// result is secret.
    ///
    /// Fails with [`Error::CryptoNote`] (`InvalidPoint`) if `tx_public_key`
    /// is not a point.
    pub fn key_derivation(&self, tx_public_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
        let tx_public = crypto::point(tx_public_key)?;
        let view = self.view_scalar()?;
        Ok(Zeroizing::new(
            tx_public.mul(&view).mul_by_cofactor().compress(),
        ))
    }

    /// Tests whether output `index` of a transaction belongs to the wallet,
    /// given the transaction's [`key_derivation`](Self::key_derivation), and
    /// decodes it if so.
    ///
    /// Returns `Ok(None)` for an output of someone else. An output with the
    /// wallet's stealth address whose commitments do not match what the
    /// sender should have built is malformed: [`Error::MalformedOutput`]
    /// (or `InvalidPoint` if a point does not decode).
    pub fn scan_output(
        &self,
        derivation: &[u8; 32],
        index: u64,
        output: &TxOutZarcanum,
    ) -> Result<Option<ReceivedOutput>, Error> {
        let secrets = OutputSecrets::derive(derivation, index);
        // P' = h * G + spend_public: the definitive ownership test.
        let spend_public = crypto::point(self.spend_public_key())?;
        let stealth = EdwardsPoint::mul_base(&secrets.h).add(&spend_public);
        if stealth.compress() != output.stealth_address {
            return Ok(None);
        }

        let amount = output.encrypted_amount ^ secrets.amount_mask;
        let blinded_asset_id = crypto::point(&output.blinded_asset_id)?.mul_by_cofactor();
        // A' = amount * T + y * G must be the amount commitment.
        let commitment = blinded_asset_id
            .mul(&crypto::scalar_u64(amount))
            .add(&EdwardsPoint::mul_base(&secrets.amount_blinding_mask));
        let expected = crypto::point(&output.amount_commitment)?.mul_by_cofactor();
        if commitment != expected {
            return Err(Error::MalformedOutput);
        }
        // Q' = Hs(domain, h) * view_public must be the concealing point.
        let view_public = crypto::point(self.view_public_key())?;
        if view_public.mul(&secrets.concealing).compress() != output.concealing_point {
            return Err(Error::MalformedOutput);
        }

        let native = crypto::generator_h();
        let (asset_id, mask) = if blinded_asset_id == native {
            // A bare native asset id (as in coinbase outputs).
            (native, Scalar::ZERO)
        } else {
            let asset_id =
                blinded_asset_id.sub(&crypto::generator_x().mul(&secrets.asset_blinding_mask));
            (asset_id, secrets.asset_blinding_mask.clone())
        };
        let asset_id = asset_id.compress();
        Ok(Some(ReceivedOutput {
            output_index: index,
            amount,
            asset_id,
            is_native: asset_id == NATIVE_COIN_ASSET_ID,
            stealth_address: output.stealth_address,
            amount_blinding_mask: secrets.amount_blinding_mask.to_bytes(),
            asset_id_blinding_mask: mask.to_bytes(),
        }))
    }
}

/// Decrypts in place the body of a payment-id service attachment
/// (`service_id` [`PAYMENT_ID_SERVICE_ID`] with the
/// [`TX_SERVICE_ATTACHMENT_ENCRYPT_BODY`] flag), with the transaction's
/// [`key_derivation`](Wallet::key_derivation). The same call encrypts.
pub fn crypt_payment_id(derivation: &[u8; 32], body: &mut [u8]) {
    chacha8_crypt(derivation, body);
}

/// The `service_id` of the service attachment that carries the payment id of
/// an integrated address (`BC_PAYMENT_ID_SERVICE_ID`).
pub const PAYMENT_ID_SERVICE_ID: &str = "P";
/// Service attachment flag: the body is ChaCha8-encrypted.
pub const TX_SERVICE_ATTACHMENT_ENCRYPT_BODY: u8 = 1 << 0;
/// Service attachment flag: the body is deflated.
pub const TX_SERVICE_ATTACHMENT_DEFLATE_BODY: u8 = 1 << 1;
/// Service attachment flag: the body is encrypted so that auditors of an
/// auditable wallet cannot read it.
pub const TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE: u8 = 1 << 2;
/// Service attachment flag: a proof is attached to the encrypted body.
pub const TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF: u8 = 1 << 3;

impl Wallet {
    /// Tests whether the transparent (pre-Zarcanum) output `index` of a
    /// transaction, paid to the one-time key `key`, belongs to the wallet,
    /// given the transaction's [`key_derivation`](Self::key_derivation).
    ///
    /// The amount of such an output is in the open; the output found has
    /// the native asset id and zero blinding masks.
    pub fn scan_bare_output(
        &self,
        derivation: &[u8; 32],
        index: u64,
        amount: u64,
        key: &[u8; 32],
    ) -> Result<Option<ReceivedOutput>, Error> {
        let secrets = OutputSecrets::derive(derivation, index);
        let spend_public = crypto::point(self.spend_public_key())?;
        if EdwardsPoint::mul_base(&secrets.h)
            .add(&spend_public)
            .compress()
            != *key
        {
            return Ok(None);
        }
        Ok(Some(ReceivedOutput {
            output_index: index,
            amount,
            asset_id: NATIVE_COIN_ASSET_ID,
            is_native: true,
            stealth_address: *key,
            amount_blinding_mask: [0u8; 32],
            asset_id_blinding_mask: [0u8; 32],
        }))
    }
}

/// Decrypts the payment id of output `index` of a version 4 transaction
/// (`tx_out_zarcanum::encrypted_payment_id`), given the transaction's
/// [`key_derivation`](Wallet::key_derivation): zero means no payment id.
/// The same call encrypts.
///
/// The result is only meaningful for an output of the wallet the
/// derivation is of.
pub fn crypt_output_payment_id(derivation: &[u8; 32], index: u64, payment_id: u64) -> u64 {
    payment_id ^ OutputSecrets::derive(derivation, index).payment_id_mask
}

/// What a transaction pays to a wallet.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanResult {
    /// The transaction public key, if the transaction has one.
    pub tx_pub_key: Option<[u8; 32]>,
    /// The outputs that belong to the wallet.
    pub outputs: Vec<ReceivedOutput>,
    /// The payment id the sender attached (decrypted), if any: the body of
    /// the payment id attachment or, for a version 4 transaction without
    /// one, the eight bytes of the first non-zero payment id of the
    /// wallet's outputs.
    pub payment_id: Option<Vec<u8>>,
    /// For each of `outputs`, its own payment id (version 4 outputs carry
    /// one each); zero for none.
    pub output_payment_ids: Vec<u64>,
}

#[cfg(feature = "alloc")]
impl ScanResult {
    /// Whether any output of the transaction belongs to the wallet.
    pub fn found(&self) -> bool {
        !self.outputs.is_empty()
    }
}

#[cfg(feature = "alloc")]
impl Wallet {
    /// Finds the outputs of `tx` that belong to the wallet, decoding the
    /// amount and asset of each — and, for the outputs of a version 4
    /// transaction, its payment id — and recovers the payment id if the
    /// transaction carries one (`lookup_acc_outs`). Only the view key is
    /// used.
    ///
    /// A transaction without a public key, or with nothing for the wallet,
    /// gives an empty result. Confidential outputs and transparent outputs
    /// to one key are looked at; multisig and gateway outputs are not.
    ///
    /// The payment id attachment of a version 4 transaction is encrypted
    /// in a way this module does not implement: it is returned as it is.
    pub fn scan_tx(&self, tx: &super::Transaction) -> Result<ScanResult, Error> {
        use super::tx::{TRANSACTION_VERSION_POST_HF6, Variant};

        let mut result = ScanResult::default();
        let Some(tx_pub_key) = tx.tx_pub_key() else {
            return Ok(result);
        };
        result.tx_pub_key = Some(tx_pub_key);
        let derivation = self.key_derivation(&tx_pub_key)?;

        for (index, out) in tx.vout.iter().enumerate() {
            let index = u64::try_from(index).map_err(|_| Error::TooLarge)?;
            let (found, payment_id) = match out {
                Variant::OutZarcanum(out) => (self.scan_output(&derivation, index, out)?, 0),
                Variant::OutZarcanumHf6(out) => (
                    self.scan_output(&derivation, index, &out.base())?,
                    crypt_output_payment_id(&derivation, index, out.encrypted_payment_id),
                ),
                Variant::OutBare(out) => match &*out.target {
                    Variant::ToKeyTarget(target) => (
                        self.scan_bare_output(&derivation, index, out.amount, &target.key)?,
                        0,
                    ),
                    _ => continue,
                },
                _ => continue,
            };
            if let Some(found) = found {
                result.outputs.push(found);
                result.output_payment_ids.push(payment_id);
            }
        }

        let attachment = tx
            .extra
            .iter()
            .chain(&tx.attachment)
            .find_map(|item| match item {
                Variant::ServiceAttachment(a)
                    if a.service_id == PAYMENT_ID_SERVICE_ID.as_bytes() =>
                {
                    Some(a)
                }
                _ => None,
            });
        if let Some(attachment) = attachment {
            let mut body = attachment.body.clone();
            if attachment.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY != 0
                && tx.version < TRANSACTION_VERSION_POST_HF6
            {
                crypt_payment_id(&derivation, &mut body);
            }
            result.payment_id = Some(body);
        } else if let Some(id) = result.output_payment_ids.iter().find(|id| **id != 0) {
            result.payment_id = Some(id.to_le_bytes().to_vec());
        }
        Ok(result)
    }
}
