//! Offline signing: building the transaction an unsigned-transaction blob
//! describes, with its ring signatures and proofs (`construct_tx`, for
//! transactions that spend confidential and transparent outputs into
//! confidential outputs).

use purecrypto::zeroize::Zeroizing;

use crate::cryptonote::{EdwardsPoint, Scalar, cn_fast_hash, derivation_to_scalar};
use crate::prelude::*;

use super::bge::generate_bge_proof;
use super::bpp::generate_bpp;
use super::chacha8::chacha8_crypt;
use super::clsag::{ClsagGgxInput, generate_clsag_ggx};
use super::crypto::{
    self, NATIVE_COIN_ASSET_ID, OutputSecrets, derivation_hint, generator_h, generator_u,
    generator_x, mul_vartime, random_scalar, scalar_1div8, scalar_u64,
};
use super::ftp::{
    FinalizeTxParam, FinalizedTx, FtpFormat, KeyImageIndex, TX_DEST_FLAG_EXPLICIT_NATIVE_ASSET_ID,
    TxDest, TxSource, TxSourceOutputEntry,
};
use super::nlsag::generate_ring_signature;
use super::scan::{
    TX_SERVICE_ATTACHMENT_DEFLATE_BODY, TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF,
    TX_SERVICE_ATTACHMENT_ENCRYPT_BODY, TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE,
    TxOutZarcanum,
};
use super::schnorr::{
    SchnorrGenerator, generate_double_schnorr_sig, generate_vector_ug_aggregation_proof,
};
use super::ser::{Reader, Wire, write_vec};
use super::tx::{
    ClsagGgxSig, ExtraAttachmentInfo, TRANSACTION_VERSION_POST_HF4, TRANSACTION_VERSION_POST_HF5,
    TRANSACTION_VERSION_POST_HF6, TX_FLAG_SIGNATURE_MODE_SEPARATE, Transaction, TxCryptoChecksum,
    TxInToKey, TxInZcInput, Variant, ZcAssetSurjectionProof, ZcBalanceProof, ZcOutsRangeProof,
    ZcSig,
};
use super::tx_ext::{NlsagSig, TxOutZarcanumHf6};
use super::{ADDRESS_FLAG_AUDITABLE, Error, Wallet};

/// The mixing attribute of an output that must not be mixed
/// (`CURRENCY_TO_KEY_OUT_FORCED_NO_MIX`).
const MIX_ATTR_FORCED_NO_MIX: u8 = 1;
/// `CURRENCY_TX_MAX_ALLOWED_INPUTS`.
const MAX_INPUTS: usize = 256;
/// `CURRENCY_TX_MAX_ALLOWED_OUTS`.
const MAX_OUTPUTS: usize = 32;

/// The operations of signing that need the secret spend key.
///
/// The secret key of an output is `hi + x`, with `hi = Hs(8 * v * R, index)`
/// a scalar anyone holding the view key can compute, and `x` the secret
/// spend key. [`LocalInputSigner`] holds `x`; another implementation can
/// keep it elsewhere (a device, a threshold of parties) and let a view-only
/// wallet drive the signing through [`Wallet::sign_with`].
pub trait InputSigner {
    /// The key image `(hi + x) * Hp(stealth_address)` of the output with
    /// this one-time public key.
    fn key_image(&self, hi: &Scalar, stealth_address: &EdwardsPoint)
    -> Result<EdwardsPoint, Error>;

    /// The CLSAG-GGX signature of a confidential input:
    /// [`generate_clsag_ggx`] with `hi + x` as the first secret.
    #[allow(clippy::too_many_arguments)]
    fn sign_clsag(
        &self,
        rng: &mut dyn FnMut(&mut [u8]),
        hi: &Scalar,
        m: &[u8; 32],
        ring: &[ClsagGgxInput],
        key_image: &EdwardsPoint,
        pseudo_out_amount_commitment: &EdwardsPoint,
        pseudo_out_blinded_asset_id: &EdwardsPoint,
        secret_1_f: &Scalar,
        secret_2_t: &Scalar,
        secret_index: usize,
    ) -> Result<ClsagGgxSig, Error>;

    /// The ring signature of a transparent (pre-Zarcanum) input:
    /// [`generate_ring_signature`] with the secret `hi + x`.
    ///
    /// The default fails with [`Error::Unsupported`]: a signer that does
    /// not implement it cannot spend transparent outputs.
    fn sign_ring(
        &self,
        rng: &mut dyn FnMut(&mut [u8]),
        hi: &Scalar,
        m: &[u8; 32],
        ring: &[[u8; 32]],
        key_image: &EdwardsPoint,
        secret_index: usize,
    ) -> Result<NlsagSig, Error> {
        let _ = (rng, hi, m, ring, key_image, secret_index);
        Err(Error::Unsupported)
    }

    /// Encrypts `data` in place under the secret spend key (ChaCha8 with
    /// the hash of the key, `chacha_crypt_legacy`): how the key derivation
    /// of encrypted attachments is kept for the sender in the transaction.
    ///
    /// The default fails with [`Error::Unsupported`]: a signer that does
    /// not implement it cannot sign a transaction that has entries to
    /// encrypt.
    fn crypt_for_sender(&self, data: &mut [u8]) -> Result<(), Error> {
        let _ = data;
        Err(Error::Unsupported)
    }
}

/// An [`InputSigner`] that holds the secret spend key. The key is wiped when
/// the signer is dropped.
pub struct LocalInputSigner {
    spend_secret: Scalar,
}

impl LocalInputSigner {
    /// A signer for this secret spend key; `InvalidScalar` if it is not a
    /// reduced scalar.
    pub fn new(spend_secret: &[u8; 32]) -> Result<Self, Error> {
        Ok(LocalInputSigner {
            spend_secret: crypto::scalar(spend_secret)?,
        })
    }
}

impl InputSigner for LocalInputSigner {
    fn key_image(
        &self,
        hi: &Scalar,
        stealth_address: &EdwardsPoint,
    ) -> Result<EdwardsPoint, Error> {
        Ok(crypto::key_image(
            &hi.add(&self.spend_secret),
            stealth_address,
        ))
    }

    fn sign_clsag(
        &self,
        rng: &mut dyn FnMut(&mut [u8]),
        hi: &Scalar,
        m: &[u8; 32],
        ring: &[ClsagGgxInput],
        key_image: &EdwardsPoint,
        pseudo_out_amount_commitment: &EdwardsPoint,
        pseudo_out_blinded_asset_id: &EdwardsPoint,
        secret_1_f: &Scalar,
        secret_2_t: &Scalar,
        secret_index: usize,
    ) -> Result<ClsagGgxSig, Error> {
        generate_clsag_ggx(
            rng,
            m,
            ring,
            key_image,
            pseudo_out_amount_commitment,
            pseudo_out_blinded_asset_id,
            &hi.add(&self.spend_secret),
            secret_1_f,
            secret_2_t,
            secret_index,
        )
    }

    fn sign_ring(
        &self,
        rng: &mut dyn FnMut(&mut [u8]),
        hi: &Scalar,
        m: &[u8; 32],
        ring: &[[u8; 32]],
        key_image: &EdwardsPoint,
        secret_index: usize,
    ) -> Result<NlsagSig, Error> {
        generate_ring_signature(
            rng,
            m,
            ring,
            key_image,
            &hi.add(&self.spend_secret),
            secret_index,
        )
    }

    fn crypt_for_sender(&self, data: &mut [u8]) -> Result<(), Error> {
        let key = Zeroizing::new(self.spend_secret.to_bytes());
        chacha8_crypt(&key, data);
        Ok(())
    }
}

/// What signing knows about an input.
struct Input<'a> {
    source: &'a TxSource,
    /// The ring, sorted as it goes into the transaction.
    ring: Vec<TxSourceOutputEntry>,
    /// The position of the real output in `ring`.
    real_index: usize,
    /// `Hs(8 * v * R, index)`.
    hi: Scalar,
    key_image: EdwardsPoint,
    /// The input as it goes into the transaction.
    vin: Variant,
    /// The asset id of the output spent.
    asset_id: EdwardsPoint,
}

/// What signing knows about an output (`tx_generation_context`, per output).
struct Output {
    amount: u64,
    asset_id: EdwardsPoint,
    /// `T = asset_id + s * X`.
    blinded_asset_id: EdwardsPoint,
    /// `E = amount * T + y * G`.
    amount_commitment: EdwardsPoint,
    asset_blinding_mask: Scalar,
    amount_blinding_mask: Scalar,
}

/// The sum of amounts; [`Error::TooLarge`] if it overflows.
fn sum(mut amounts: impl Iterator<Item = u64>) -> Result<u64, Error> {
    amounts.try_fold(0u64, |acc, v| acc.checked_add(v).ok_or(Error::TooLarge))
}

/// Checks that every non-native asset has equal inputs and outputs, and
/// returns the fee: the native surplus.
fn balance(inputs: &[Input<'_>], dests: &[TxDest]) -> Result<u64, Error> {
    let input_ids: Vec<[u8; 32]> = inputs.iter().map(|i| i.asset_id.compress()).collect();
    let total_in = |id: &[u8; 32]| {
        sum(inputs
            .iter()
            .zip(&input_ids)
            .filter(|(_, input_id)| *input_id == id)
            .map(|(input, _)| input.source.amount))
    };
    let total_out =
        |id: &[u8; 32]| sum(dests.iter().filter(|d| d.asset_id == *id).map(|d| d.amount));

    for id in input_ids.iter().chain(dests.iter().map(|d| &d.asset_id)) {
        if *id != NATIVE_COIN_ASSET_ID && total_in(id)? != total_out(id)? {
            return Err(Error::Unbalanced);
        }
    }
    total_in(&NATIVE_COIN_ASSET_ID)?
        .checked_sub(total_out(&NATIVE_COIN_ASSET_ID)?)
        .ok_or(Error::InsufficientFunds)
}

/// The ring of a source as it goes into the transaction
/// (`prepare_outputs_entries_for_key_offsets`): by increasing global index,
/// references by id last, with the new position of the real output. The
/// references stay absolute.
fn sorted_ring(source: &TxSource) -> Result<(Vec<TxSourceOutputEntry>, usize), Error> {
    let real_index = usize::try_from(source.real_output).map_err(|_| Error::InvalidRing)?;
    let real = source.outputs.get(real_index).ok_or(Error::InvalidRing)?;
    let mut ring = source.outputs.clone();
    for entry in &ring {
        if !matches!(
            entry.out_reference,
            Variant::Uint64(_) | Variant::RefById(_)
        ) {
            return Err(Error::Unsupported);
        }
    }
    // A stable sort: references by id keep their order.
    ring.sort_by_key(|entry| match entry.out_reference {
        Variant::Uint64(index) => (0u8, index),
        _ => (1, 0),
    });
    let position = ring
        .iter()
        .position(|entry| entry.out_reference == real.out_reference)
        .ok_or(Error::InvalidRing)?;
    Ok((ring, position))
}

/// The references of a sorted ring, global indices relative to the previous
/// one. A repeated global index is an error.
fn key_offsets(ring: &[TxSourceOutputEntry]) -> Result<Vec<Variant>, Error> {
    let mut offsets = Vec::with_capacity(ring.len());
    let mut previous = None;
    for entry in ring {
        match &entry.out_reference {
            Variant::Uint64(index) => {
                let offset = match previous {
                    None => *index,
                    Some(previous) => index
                        .checked_sub(previous)
                        .filter(|offset| *offset != 0)
                        .ok_or(Error::InvalidRing)?,
                };
                previous = Some(*index);
                offsets.push(Variant::Uint64(offset));
            }
            other => offsets.push(other.clone()),
        }
    }
    Ok(offsets)
}

/// Replaces the entry of the same kind in `extra`, or adds it
/// (`update_or_add_field_to_extra`).
fn update_or_add(extra: &mut Vec<Variant>, entry: Variant) {
    let same = extra
        .iter_mut()
        .find(|e| core::mem::discriminant(*e) == core::mem::discriminant(&entry));
    match same {
        Some(slot) => *slot = entry,
        None => extra.push(entry),
    }
}

/// Encrypts a value through its serialization, which is the layout of the
/// structure the reference encrypts in memory.
fn crypt_wire<T: Wire>(value: &mut T, derivation: &[u8; 32]) -> Result<(), Error> {
    let mut bytes = Vec::new();
    value.write(&mut bytes);
    chacha8_crypt(derivation, &mut bytes);
    *value = T::read(&mut Reader::new(&bytes))?;
    Ok(())
}

/// Encrypts in place what `encrypt_attach_visitor_legacy` encrypts of one
/// extra or attachment entry (transactions of version 2 and 3); whether it
/// did.
fn encrypt_legacy_item(item: &mut Variant, derivation: &[u8; 32]) -> Result<bool, Error> {
    match item {
        Variant::Comment(comment) => chacha8_crypt(derivation, comment),
        Variant::Payer(addr) | Variant::Receiver(addr) => crypt_wire(addr, derivation)?,
        Variant::PayerOld(addr) | Variant::ReceiverOld(addr) => crypt_wire(addr, derivation)?,
        Variant::ServiceAttachment(attachment) => {
            if attachment.flags & TX_SERVICE_ATTACHMENT_DEFLATE_BODY != 0 {
                // No deflate here.
                return Err(Error::Unsupported);
            }
            if attachment.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY == 0 {
                return Ok(false);
            }
            if attachment.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE != 0 {
                return Err(Error::Unsupported);
            }
            let proof =
                (attachment.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF != 0).then(|| {
                    let mut salted = attachment.body.clone();
                    salted.extend_from_slice(&cn_fast_hash(derivation));
                    cn_fast_hash(&salted)
                });
            chacha8_crypt(derivation, &mut attachment.body);
            attachment.security.extend(proof);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Whether `encrypt_payload_items_visitor` (version 4) would change this
/// entry.
fn needs_hf6_encryption(item: &Variant) -> bool {
    match item {
        Variant::Comment(_) => true,
        Variant::ServiceAttachment(attachment) => {
            attachment.flags
                & (TX_SERVICE_ATTACHMENT_ENCRYPT_BODY | TX_SERVICE_ATTACHMENT_DEFLATE_BODY)
                != 0
        }
        _ => false,
    }
}

/// A uniform index below `bound` (which is not zero), by rejection.
fn random_below(rng: &mut dyn FnMut(&mut [u8]), bound: usize) -> usize {
    let bound = bound as u64;
    let zone = u64::MAX - (u64::MAX % bound);
    // A broken `rng` that only gives large values ends after a few tries.
    for _ in 0..64 {
        let mut bytes = [0u8; 8];
        rng(&mut bytes);
        let value = u64::from_le_bytes(bytes);
        if value < zone {
            return (value % bound) as usize;
        }
    }
    0
}

impl Wallet {
    /// Builds and signs the transaction `ftp` describes
    /// (`wallet2::sign_transfer`, `construct_tx`).
    ///
    /// `one_time_key` is the transaction secret key, a reduced scalar; with
    /// `None`, it is drawn from `rng` first. `rng` then supplies the order
    /// of the outputs (if `ftp.shuffle`), the padding hints, the blinding
    /// masks of the pseudo-outputs and the nonces of the signatures and
    /// proofs: it must fill its buffer from a cryptographically secure
    /// source, and never repeat.
    ///
    /// Transactions of version 2 to 4 are built, as `construct_tx` builds
    /// them:
    ///
    /// - inputs are confidential outputs (CLSAG-GGX) or transparent
    ///   pre-Zarcanum ones (ring signature), each ring sorted by global
    ///   index, the inputs sorted by kind and key image;
    /// - outputs are confidential, in the order of
    ///   `ftp.prepared_destinations` or shuffled; version 4 outputs carry
    ///   the destination's payment id. An output shows the bare native
    ///   asset id when its destination asks for it
    ///   ([`TX_DEST_FLAG_EXPLICIT_NATIVE_ASSET_ID`]) or when every ring
    ///   member of every input does;
    /// - the extra entries and attachments of `ftp` are copied, with the
    ///   unlock time, flags and expiration time; in versions 2 and 3,
    ///   comments, payer and receiver entries and service attachments
    ///   flagged for it are encrypted for `ftp.crypt_address`.
    ///
    /// The fee is the native coin surplus of the inputs over the outputs;
    /// every other asset must balance exactly.
    ///
    /// Not built ([`Error::Unsupported`]): multisig, HTLC and gateway
    /// inputs, outputs to several keys or to the null address, the
    /// separate signature mode, asset operations, entries that need
    /// deflate or the auditable-isolated encryption, and, in version 4,
    /// any entry to encrypt.
    ///
    /// Fails with [`Error::ViewOnly`] without a secret spend key, and with
    /// the errors of [`sign_with`](Self::sign_with).
    pub fn sign(
        &self,
        rng: &mut dyn FnMut(&mut [u8]),
        ftp: &FinalizeTxParam,
        one_time_key: Option<&[u8; 32]>,
    ) -> Result<FinalizedTx, Error> {
        let signer = LocalInputSigner {
            spend_secret: self.spend_scalar()?,
        };
        self.sign_with(rng, ftp, one_time_key, &signer)
    }

    /// [`sign`](Self::sign), with the operations that need the secret spend
    /// key delegated to `signer`: a view-only wallet can drive it.
    ///
    /// Fails with:
    /// - [`Error::KeyMismatch`] if `ftp` was prepared for another spend key,
    ///   or a source's real output is not this wallet's;
    /// - [`Error::UnsupportedVersion`], [`Error::Unsupported`] (see
    ///   [`sign`](Self::sign));
    /// - [`Error::InvalidRing`] (no sources, a real output outside its ring,
    ///   a repeated global index);
    /// - [`Error::Unbalanced`], [`Error::InsufficientFunds`],
    ///   [`Error::MissingFee`] (the native inputs equal the native outputs:
    ///   a transaction needs a fee), [`Error::TooLarge`] (more outputs than
    ///   a range proof covers, more inputs than a surjection proof does);
    /// - [`Error::SecretMismatch`] if a blinding mask does not open its
    ///   output;
    /// - `InvalidPoint`/`InvalidScalar` for malformed keys.
    pub fn sign_with(
        &self,
        rng: &mut dyn FnMut(&mut [u8]),
        ftp: &FinalizeTxParam,
        one_time_key: Option<&[u8; 32]>,
        signer: &dyn InputSigner,
    ) -> Result<FinalizedTx, Error> {
        if ftp.spend_pub_key != *self.spend_public_key() {
            return Err(Error::KeyMismatch);
        }
        if !matches!(
            ftp.tx_version,
            TRANSACTION_VERSION_POST_HF4
                | TRANSACTION_VERSION_POST_HF5
                | TRANSACTION_VERSION_POST_HF6
        ) {
            return Err(Error::UnsupportedVersion);
        }
        let hf6 = ftp.tx_version >= TRANSACTION_VERSION_POST_HF6;
        if ftp.sources.is_empty() || ftp.prepared_destinations.is_empty() {
            return Err(Error::InvalidRing);
        }
        if ftp.sources.len() > MAX_INPUTS || ftp.prepared_destinations.len() > MAX_OUTPUTS {
            return Err(Error::TooLarge);
        }
        let has_asset_operation = ftp
            .extra
            .iter()
            .any(|e| matches!(e, Variant::AssetOperation(_)));
        if u64::from(ftp.flags) & TX_FLAG_SIGNATURE_MODE_SEPARATE != 0 || has_asset_operation {
            return Err(Error::Unsupported);
        }

        let mut tx = Transaction {
            version: ftp.tx_version,
            extra: ftp.extra.clone(),
            ..Default::default()
        };
        if ftp.tx_version >= TRANSACTION_VERSION_POST_HF5 {
            tx.hardfork_id = u8::try_from(ftp.tx_hardfork_id).map_err(|_| Error::TooLarge)?;
        }
        if ftp.unlock_time != 0 {
            update_or_add(&mut tx.extra, Variant::UnlockTime(ftp.unlock_time));
        }
        if ftp.flags != 0 {
            update_or_add(&mut tx.extra, Variant::Flags(u64::from(ftp.flags)));
        }
        if ftp.expiration_time != 0 {
            update_or_add(&mut tx.extra, Variant::ExpirationTime(ftp.expiration_time));
        }

        // Inputs: the ring as offsets, and the key image.
        let spend_public = crypto::point(self.spend_public_key())?;
        let x_gen = generator_x();
        let native = generator_h();
        let mut inputs = Vec::with_capacity(ftp.sources.len());
        // Whether every ring member of every input shows the native asset
        // id: then the outputs must show it too.
        let mut all_inputs_native = true;
        for source in &ftp.sources {
            if source.is_multisig() || !source.htlc_origin.is_empty() {
                return Err(Error::Unsupported);
            }
            let (ring, real_index) = sorted_ring(source)?;
            let real = ring.get(real_index).ok_or(Error::InvalidRing)?;

            let derivation = self.key_derivation(&source.real_out_tx_key)?;
            let hi_bytes = Zeroizing::new(derivation_to_scalar(
                &derivation,
                source.real_out_in_tx_index,
            ));
            let hi = crypto::scalar(&hi_bytes)?;
            let stealth = EdwardsPoint::mul_base(&hi).add(&spend_public);
            if stealth.compress() != real.stealth_address {
                return Err(Error::KeyMismatch);
            }
            let key_image = signer.key_image(&hi, &stealth)?;
            let offsets = key_offsets(&ring)?;

            let (vin, asset_id) = if source.is_zc() {
                // T_i = H_i + r_i * X is the real output's: that tells H_i,
                // which must be the asset id the source names, if it does.
                let real_blinded = crypto::point(&real.blinded_asset_id)?.mul_by_cofactor();
                let mask = crypto::scalar(&source.real_out_asset_id_blinding_mask)?;
                let unblinded = real_blinded.sub(&x_gen.mul(&mask));
                if let Some(id) = &source.asset_id
                    && crypto::point(id)? != unblinded
                {
                    return Err(Error::SecretMismatch);
                }
                for member in &ring {
                    if crypto::point(&member.blinded_asset_id)?.mul_by_cofactor() != native {
                        all_inputs_native = false;
                    }
                }
                let vin = Variant::ZcInput(TxInZcInput {
                    key_offsets: offsets,
                    key_image: key_image.compress(),
                    etc_details: Vec::new(),
                });
                (vin, unblinded)
            } else {
                if source.asset_id.is_some_and(|id| id != NATIVE_COIN_ASSET_ID) {
                    return Err(Error::Unsupported);
                }
                let vin = Variant::ToKey(TxInToKey {
                    amount: source.amount,
                    key_offsets: offsets,
                    k_image: key_image.compress(),
                    etc_details: Vec::new(),
                });
                (vin, native)
            };
            inputs.push(Input {
                source,
                ring,
                real_index,
                hi,
                key_image,
                vin,
                asset_id,
            });
        }
        let fee = balance(&inputs, &ftp.prepared_destinations)?;

        let tx_secret = match one_time_key {
            Some(key) => crypto::scalar(key)?,
            None => random_scalar(rng),
        };
        let tx_public = EdwardsPoint::mul_base(&tx_secret);
        tx.extra.push(Variant::PubKey(tx_public.compress()));
        update_or_add(&mut tx.extra, Variant::EtcTxFlags16(0));

        // Attachments, and the entries to encrypt for the recipient.
        tx.attachment = ftp.attachments.clone();
        // d = 8 * r * V of the address attachments are encrypted for; zero
        // if it has no usable view key.
        let crypt_derivation = Zeroizing::new(
            crypto::point(&ftp.crypt_address.view_key)
                .map(|view| view.mul(&tx_secret).mul_by_cofactor().compress())
                .unwrap_or_default(),
        );
        if hf6 {
            if tx
                .extra
                .iter()
                .chain(&tx.attachment)
                .any(needs_hf6_encryption)
            {
                return Err(Error::Unsupported);
            }
        } else {
            let mut in_attachments = false;
            for item in &mut tx.attachment {
                in_attachments |= encrypt_legacy_item(item, &crypt_derivation)?;
            }
            let mut in_extra = false;
            for item in &mut tx.extra {
                in_extra |= encrypt_legacy_item(item, &crypt_derivation)?;
            }
            if in_attachments || in_extra {
                let mut encrypted_key_derivation = *crypt_derivation;
                signer.crypt_for_sender(&mut encrypted_key_derivation)?;
                let hash = cn_fast_hash(&crypt_derivation[..]);
                let checksum = Variant::CryptoChecksum(TxCryptoChecksum {
                    encrypted_key_derivation,
                    derivation_hash: u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]),
                });
                if in_extra {
                    tx.extra.push(checksum);
                } else {
                    tx.attachment.push(checksum);
                }
            }
        }

        // Outputs, shuffled if asked.
        let mut dests: Vec<&TxDest> = ftp.prepared_destinations.iter().collect();
        if ftp.shuffle {
            for i in (1..dests.len()).rev() {
                dests.swap(i, random_below(rng, i + 1));
            }
        }
        let inv8 = scalar_1div8();
        let mut outputs = Vec::with_capacity(dests.len());
        // The hints the transaction came with, and those of its outputs.
        let existing_hints: Vec<Vec<u8>> = tx
            .extra
            .iter()
            .filter_map(|e| match e {
                Variant::DerivationHint(hint) => Some(hint.clone()),
                _ => None,
            })
            .collect();
        let mut hints: Vec<u16> = Vec::new();
        for (index, dst) in dests.iter().enumerate() {
            let [addr] = dst.addr.as_slice() else {
                return Err(Error::Unsupported);
            };
            if addr.spend_key == [0u8; 32] && addr.view_key == [0u8; 32] {
                // A burn.
                return Err(Error::Unsupported);
            }
            let explicit_native =
                dst.flags & TX_DEST_FLAG_EXPLICIT_NATIVE_ASSET_ID != 0 || all_inputs_native;
            if explicit_native && dst.asset_id != NATIVE_COIN_ASSET_ID {
                return Err(Error::Unbalanced);
            }
            let view_public = crypto::point(&addr.view_key)?;
            let dst_spend_public = crypto::point(&addr.spend_key)?;
            // d = 8 * r * V
            let derivation =
                Zeroizing::new(view_public.mul(&tx_secret).mul_by_cofactor().compress());
            let hint = derivation_hint(&derivation);
            if !hints.contains(&hint) {
                hints.push(hint);
            }
            let index = u64::try_from(index).map_err(|_| Error::TooLarge)?;
            let secrets = OutputSecrets::derive(&derivation, index);

            let asset_id = crypto::point(&dst.asset_id)?;
            let asset_blinding_mask = if explicit_native {
                Scalar::ZERO
            } else {
                secrets.asset_blinding_mask.clone()
            };
            let blinded_asset_id = asset_id.add(&x_gen.mul(&asset_blinding_mask));
            let amount_commitment = blinded_asset_id
                .mul(&scalar_u64(dst.amount))
                .add(&EdwardsPoint::mul_base(&secrets.amount_blinding_mask));
            let out = TxOutZarcanum {
                stealth_address: EdwardsPoint::mul_base(&secrets.h)
                    .add(&dst_spend_public)
                    .compress(),
                concealing_point: view_public.mul(&secrets.concealing).compress(),
                amount_commitment: amount_commitment.mul(&inv8).compress(),
                blinded_asset_id: blinded_asset_id.mul(&inv8).compress(),
                encrypted_amount: dst.amount ^ secrets.amount_mask,
                mix_attr: if addr.flags & ADDRESS_FLAG_AUDITABLE != 0 {
                    MIX_ATTR_FORCED_NO_MIX
                } else {
                    ftp.tx_outs_attr
                },
            };
            tx.vout.push(if hf6 {
                Variant::OutZarcanumHf6(TxOutZarcanumHf6 {
                    stealth_address: out.stealth_address,
                    concealing_point: out.concealing_point,
                    amount_commitment: out.amount_commitment,
                    blinded_asset_id: out.blinded_asset_id,
                    encrypted_amount: out.encrypted_amount,
                    encrypted_payment_id: dst.payment_id ^ secrets.payment_id_mask,
                    mix_attr: out.mix_attr,
                })
            } else {
                Variant::OutZarcanum(out)
            });
            outputs.push(Output {
                amount: dst.amount,
                asset_id,
                blinded_asset_id,
                amount_commitment,
                asset_blinding_mask,
                amount_blinding_mask: secrets.amount_blinding_mask.clone(),
            });
        }

        // One hint per output: random ones make up for shared derivations
        // (`add_random_derivation_hints_and_put_them_to_tx`).
        let wanted = tx
            .vout
            .len()
            .checked_sub(existing_hints.len())
            .ok_or(Error::Unsupported)?;
        let mut attempts = 0u32;
        while hints.len() < wanted {
            let mut random = [0u8; 2];
            rng(&mut random);
            // Offset by the count, so that a constant `rng` still ends.
            let hint = u16::from_le_bytes(random).wrapping_add(hints.len() as u16);
            attempts += 1;
            if attempts > 4096 {
                return Err(Error::TooLarge);
            }
            if !hints.contains(&hint) && !existing_hints.contains(&hint.to_le_bytes().to_vec()) {
                hints.push(hint);
            }
        }
        hints.sort_unstable();
        for hint in hints {
            tx.extra
                .push(Variant::DerivationHint(hint.to_le_bytes().to_vec()));
        }

        // A service attachment with one key gets a key derived for it.
        let own_view = crypto::point(self.view_public_key())?;
        let own_derivation = Zeroizing::new(own_view.mul(&tx_secret).mul_by_cofactor().compress());
        let mut service_attachments = 0u64;
        for item in &mut tx.attachment {
            let Variant::ServiceAttachment(attachment) = item else {
                continue;
            };
            match attachment.security.as_mut_slice() {
                [] => {}
                [key] => {
                    *key = crate::cryptonote::derive_public_key(
                        &own_derivation,
                        service_attachments,
                        self.spend_public_key(),
                    )?;
                }
                _ => return Err(Error::Unsupported),
            }
            service_attachments += 1;
        }

        // Inputs go by kind, then by increasing key image (`less_txin_v`).
        inputs.sort_by_key(|input| (input.vin.tag(), input.key_image.compress()));
        for input in &inputs {
            tx.vin.push(input.vin.clone());
        }
        if fee == 0 {
            return Err(Error::MissingFee);
        }
        if tx
            .extra
            .iter()
            .any(|e| matches!(e, Variant::ZarcanumTxDataV1 { .. }))
        {
            return Err(Error::Unsupported);
        }
        tx.extra.push(Variant::ZarcanumTxDataV1 { fee });

        // The attachments are final: the extra tells their size and hash.
        if !tx.attachment.is_empty() {
            let mut bytes = Vec::new();
            write_vec(&mut bytes, &tx.attachment);
            tx.extra
                .push(Variant::ExtraAttachmentInfo(ExtraAttachmentInfo {
                    sz: bytes.len() as u64,
                    hsh: cn_fast_hash(&bytes),
                    cnt: tx.attachment.len() as u64,
                }));
        }

        // The prefix is final: sign it.
        let tx_id = tx.prefix_hash();

        let amount_blinding_masks_sum = outputs
            .iter()
            .fold(Scalar::ZERO, |acc, o| acc.add(&o.amount_blinding_mask));
        // sum(s_j * e_j)
        let asset_mask_x_amount_sum = outputs.iter().fold(Scalar::ZERO, |acc, o| {
            acc.add(&o.asset_blinding_mask.mul(&scalar_u64(o.amount)))
        });
        let mut pseudo_out_amount_masks_sum = Scalar::ZERO;
        // sum(r_i * a_i)
        let mut real_in_asset_mask_x_amount_sum = Scalar::ZERO;
        let mut pseudo_out_amount_commitments_sum = EdwardsPoint::identity();
        // Per confidential input: T^p_i, the asset id H_i, and r_i + r'_i.
        let mut pseudo_outs = Vec::with_capacity(inputs.len());
        let mut bare_inputs_sum = 0u64;

        let zc_count = inputs.iter().filter(|i| i.source.is_zc()).count();
        let mut zc_signed = 0usize;
        for input in &inputs {
            let source = input.source;
            if !source.is_zc() {
                bare_inputs_sum = bare_inputs_sum
                    .checked_add(source.amount)
                    .ok_or(Error::TooLarge)?;
                let keys: Vec<[u8; 32]> = input.ring.iter().map(|m| m.stealth_address).collect();
                tx.signatures.push(Variant::Nlsag(signer.sign_ring(
                    rng,
                    &input.hi,
                    &tx_id,
                    &keys,
                    &input.key_image,
                    input.real_index,
                )?));
                continue;
            }
            zc_signed += 1;
            let real_amount_mask = crypto::scalar(&source.real_out_amount_blinding_mask)?;
            let real_asset_mask = crypto::scalar(&source.real_out_asset_id_blinding_mask)?;
            let amount = scalar_u64(source.amount);
            // T_i = H_i + r_i * X
            let source_blinded_asset_id = input.asset_id.add(&x_gen.mul(&real_asset_mask));

            // The last pseudo-output's mask makes the G components of the
            // balance equation cancel out.
            let pseudo_amount_mask = if zc_signed == zc_count {
                amount_blinding_masks_sum.sub(&pseudo_out_amount_masks_sum)
            } else {
                let mask = random_scalar(rng);
                pseudo_out_amount_masks_sum = pseudo_out_amount_masks_sum.add(&mask);
                mask
            };
            let pseudo_asset_mask = random_scalar(rng);
            // T^p_i = T_i + r'_i * X
            let pseudo_blinded_asset_id =
                source_blinded_asset_id.add(&x_gen.mul(&pseudo_asset_mask));
            // A^p_i = a_i * T_i + f'_i * G
            let pseudo_amount_commitment = source_blinded_asset_id
                .mul(&amount)
                .add(&EdwardsPoint::mul_base(&pseudo_amount_mask));

            real_in_asset_mask_x_amount_sum =
                real_in_asset_mask_x_amount_sum.add(&real_asset_mask.mul(&amount));
            pseudo_out_amount_commitments_sum =
                pseudo_out_amount_commitments_sum.add(&pseudo_amount_commitment);

            let ring: Vec<ClsagGgxInput> = input
                .ring
                .iter()
                .map(|out| ClsagGgxInput {
                    stealth_address: out.stealth_address,
                    amount_commitment: out.amount_commitment,
                    blinded_asset_id: out.blinded_asset_id,
                })
                .collect();
            let clsag_ggx = signer.sign_clsag(
                rng,
                &input.hi,
                &tx_id,
                &ring,
                &input.key_image,
                &pseudo_amount_commitment,
                &pseudo_blinded_asset_id,
                &real_amount_mask.sub(&pseudo_amount_mask),
                &pseudo_asset_mask.negate(),
                input.real_index,
            )?;
            tx.signatures.push(Variant::ZcSig(ZcSig {
                pseudo_out_amount_commitment: pseudo_amount_commitment.mul(&inv8).compress(),
                pseudo_out_blinded_asset_id: pseudo_blinded_asset_id.mul(&inv8).compress(),
                clsag_ggx,
            }));
            pseudo_outs.push((
                pseudo_blinded_asset_id,
                input.asset_id,
                pseudo_asset_mask.add(&real_asset_mask),
            ));
        }
        let has_bare_inputs = zc_count != inputs.len();

        // Asset surjection: each output has the asset of some input. The
        // native coin of transparent inputs is a ring member of its own:
        // the last one up to version 3, the first one from version 4 on,
        // and the first member with the output's asset is the one proven.
        // Without confidential inputs every output shows the native asset
        // id; the proof is then empty, and version 4 has none.
        if zc_count != 0 {
            let native_member = has_bare_inputs.then_some((native, native, Scalar::ZERO));
            let mut members: Vec<(EdwardsPoint, EdwardsPoint, Scalar)> = Vec::new();
            if hf6 {
                members.extend(native_member.clone());
            }
            members.append(&mut pseudo_outs);
            if !hf6 {
                members.extend(native_member);
            }
            let mut surjection = ZcAssetSurjectionProof::default();
            for output in &outputs {
                // T^p_i - T'_j = (r_i + r'_i - s_j) * X for an input of the
                // same asset.
                let ring: Vec<EdwardsPoint> = members
                    .iter()
                    .map(|(blinded, _, _)| blinded.sub(&output.blinded_asset_id))
                    .collect();
                let (secret_index, (_, _, mask)) = members
                    .iter()
                    .enumerate()
                    .find(|(_, (_, asset_id, _))| *asset_id == output.asset_id)
                    .ok_or(Error::Unbalanced)?;
                let secret = mask.sub(&output.asset_blinding_mask);
                surjection.bge_proofs.push(generate_bge_proof(
                    rng,
                    &tx_id,
                    &ring,
                    &secret,
                    secret_index,
                )?);
            }
            tx.proofs.push(Variant::AssetSurjectionProof(surjection));
        } else if !hf6 {
            tx.proofs.push(Variant::AssetSurjectionProof(
                ZcAssetSurjectionProof::default(),
            ));
        }

        // Range proof: each amount is below 2^64.
        let u_gen = generator_u();
        let mut y_primes = Vec::with_capacity(outputs.len());
        let mut rp_commitments = Vec::with_capacity(outputs.len());
        for output in &outputs {
            // E'_j = e_j * U + y'_j * G
            let y_prime = random_scalar(rng);
            rp_commitments.push(
                u_gen
                    .mul(&scalar_u64(output.amount))
                    .add(&EdwardsPoint::mul_base(&y_prime)),
            );
            y_primes.push(y_prime);
        }
        let amounts: Vec<u64> = outputs.iter().map(|o| o.amount).collect();
        let amount_scalars: Vec<Scalar> = amounts.iter().map(|a| scalar_u64(*a)).collect();
        let amount_masks: Vec<Scalar> = outputs
            .iter()
            .map(|o| o.amount_blinding_mask.clone())
            .collect();
        let commitments: Vec<EdwardsPoint> = outputs.iter().map(|o| o.amount_commitment).collect();
        let blinded_asset_ids: Vec<EdwardsPoint> =
            outputs.iter().map(|o| o.blinded_asset_id).collect();
        let aggregation_proof = generate_vector_ug_aggregation_proof(
            rng,
            &tx_id,
            &amount_scalars,
            &amount_masks,
            &y_primes,
            &commitments,
            &rp_commitments,
            &blinded_asset_ids,
        )?;
        let bpp = generate_bpp(
            rng,
            &amounts,
            &y_primes,
            &aggregation_proof.amount_commitments_for_rp_aggregation,
        )?;
        tx.proofs.push(Variant::OutsRangeProof(ZcOutsRangeProof {
            bpp,
            aggregation_proof,
        }));

        // Balance: what is left of inputs minus outputs minus fee is a
        // multiple of X (of G without confidential inputs), and the signer
        // knows the transaction secret key.
        let amount_commitments_sum = commitments
            .iter()
            .fold(EdwardsPoint::identity(), |acc, c| acc.add(c));
        let native_surplus = scalar_u64(bare_inputs_sum).sub(&scalar_u64(fee));
        let commitment_to_zero = mul_vartime(&native_surplus, &native)
            .add(&pseudo_out_amount_commitments_sum)
            .sub(&amount_commitments_sum);
        let (generator, secret) = if zc_count != 0 {
            (
                SchnorrGenerator::X,
                real_in_asset_mask_x_amount_sum.sub(&asset_mask_x_amount_sum),
            )
        } else {
            (SchnorrGenerator::G, amount_blinding_masks_sum.negate())
        };
        let dss = generate_double_schnorr_sig(
            rng,
            generator,
            &tx_id,
            &commitment_to_zero,
            &secret,
            &tx_public,
            &tx_secret,
        )?;
        tx.proofs
            .push(Variant::BalanceProof(ZcBalanceProof { dss }));

        // What the wallet that prepared the transaction needs back
        // (`sign_transfer`): the key images of the outputs that are its own.
        // A wallet of the legacy format left the id and the derivation
        // zero, and no key images.
        let mut finalized = FinalizedTx {
            tx,
            tx_id: [0u8; 32],
            one_time_key: tx_secret.to_bytes(),
            ftp: ftp.clone(),
            htlc_origin: Vec::new(),
            outs_key_images: Vec::new(),
            derivation: [0u8; 32],
            was_not_prepared: false,
        };
        if ftp.format == FtpFormat::Current {
            finalized.tx_id = tx_id;
            finalized.derivation = *crypt_derivation;
            for (index, out) in finalized.tx.vout.iter().enumerate() {
                let index = index as u64;
                let Some(out) = out.zarcanum_out() else {
                    continue;
                };
                let hi_bytes = Zeroizing::new(derivation_to_scalar(&own_derivation, index));
                let hi = crypto::scalar(&hi_bytes)?;
                let stealth = EdwardsPoint::mul_base(&hi).add(&spend_public);
                if stealth.compress() == out.stealth_address {
                    finalized.outs_key_images.push(KeyImageIndex {
                        out_index: index,
                        image: signer.key_image(&hi, &stealth)?.compress(),
                    });
                }
            }
        }
        Ok(finalized)
    }
}
