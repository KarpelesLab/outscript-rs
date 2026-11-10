//! Offline signing: building the transaction an unsigned-transaction blob
//! describes, with its ring signatures and proofs (`construct_tx`, for
//! transactions that spend and create confidential outputs only).

use purecrypto::zeroize::Zeroizing;

use crate::cryptonote::{EdwardsPoint, Scalar, derivation_to_scalar};
use crate::prelude::*;

use super::bge::{generate_bge_proof, verify_bge_proof};
use super::bpp::{generate_bpp, verify_bpp};
use super::clsag::{ClsagGgxInput, generate_clsag_ggx, verify_clsag_ggx};
use super::crypto::{
    self, NATIVE_COIN_ASSET_ID, OutputSecrets, derivation_hint, generator_h, generator_u,
    generator_x, mul_vartime, random_scalar, scalar_1div8, scalar_u64,
};
use super::ftp::{FinalizeTxParam, FinalizedTx, TxSource};
use super::scan::TxOutZarcanum;
use super::schnorr::{
    SchnorrGenerator, generate_double_schnorr_sig, generate_vector_ug_aggregation_proof,
    verify_double_schnorr_sig, verify_vector_ug_aggregation_proof,
};
use super::tx::{
    ClsagGgxSig, TRANSACTION_VERSION_POST_HF4, TRANSACTION_VERSION_POST_HF5, Transaction,
    TxInZcInput, Variant, ZcAssetSurjectionProof, ZcBalanceProof, ZcOutsRangeProof, ZcSig,
};
use super::{ADDRESS_FLAG_AUDITABLE, Error, Wallet};

/// The mixing attribute of an output that must not be mixed
/// (`CURRENCY_TO_KEY_OUT_FORCED_NO_MIX`).
const MIX_ATTR_FORCED_NO_MIX: u8 = 1;

/// The two operations of signing an input that need the secret spend key:
/// the key image and the ring signature.
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

    /// The CLSAG-GGX signature of an input: [`generate_clsag_ggx`] with
    /// `hi + x` as the first secret.
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
}

/// What signing knows about an input.
struct Input<'a> {
    source: &'a TxSource,
    /// `Hs(8 * v * R, index)`.
    hi: Scalar,
    key_image: EdwardsPoint,
    key_image_bytes: [u8; 32],
    vin: TxInZcInput,
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

/// Whether an unblinded asset id is the native coin's; an unset one counts
/// as native.
fn is_native(asset_id: Option<&[u8; 32]>) -> bool {
    asset_id.is_none_or(|id| *id == NATIVE_COIN_ASSET_ID)
}

/// The sum of amounts; [`Error::TooLarge`] if it overflows.
fn sum(mut amounts: impl Iterator<Item = u64>) -> Result<u64, Error> {
    amounts.try_fold(0u64, |acc, v| acc.checked_add(v).ok_or(Error::TooLarge))
}

/// Checks that every non-native asset has equal inputs and outputs, and
/// returns the fee: the native surplus.
fn balance(ftp: &FinalizeTxParam) -> Result<u64, Error> {
    let sources = &ftp.sources;
    let dests = &ftp.prepared_destinations;
    let native_in = sum(sources
        .iter()
        .filter(|s| is_native(s.asset_id.as_ref()))
        .map(|s| s.amount))?;
    let native_out = sum(dests
        .iter()
        .filter(|d| is_native(Some(&d.asset_id)))
        .map(|d| d.amount))?;

    let source_assets = sources.iter().filter_map(|s| s.asset_id.as_ref());
    for id in source_assets.chain(dests.iter().map(|d| &d.asset_id)) {
        if is_native(Some(id)) {
            continue;
        }
        let asset_in = sum(sources
            .iter()
            .filter(|s| s.asset_id.as_ref() == Some(id))
            .map(|s| s.amount))?;
        let asset_out = sum(dests.iter().filter(|d| d.asset_id == *id).map(|d| d.amount))?;
        if asset_in != asset_out {
            return Err(Error::Unbalanced);
        }
    }
    native_in
        .checked_sub(native_out)
        .ok_or(Error::InsufficientFunds)
}

impl Wallet {
    /// Builds and signs the transaction `ftp` describes
    /// (`wallet2::sign_transfer`).
    ///
    /// `one_time_key` is the transaction secret key, a reduced scalar; with
    /// `None`, it is drawn from `rng` first. `rng` then supplies the padding
    /// hints, the blinding masks of the pseudo-outputs and the nonces of the
    /// signatures and proofs: it must fill its buffer from a
    /// cryptographically secure source, and never repeat.
    ///
    /// Only transactions of version 2 and 3 that spend confidential outputs
    /// into confidential outputs are supported. The outputs are created in
    /// the order of `ftp.prepared_destinations` (the `shuffle` flag is not
    /// acted on), and the extra entries and attachments of `ftp` are not
    /// copied: review them before signing a blob that has any.
    ///
    /// The fee is the native coin surplus of the inputs over the outputs;
    /// every other asset must balance exactly.
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
    /// - [`Error::UnsupportedVersion`], [`Error::Unsupported`] (a source
    ///   that is not a confidential output or is referenced by id, a
    ///   destination without exactly one address);
    /// - [`Error::InvalidRing`] (no sources, a real output outside its ring,
    ///   global indices not increasing);
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
            TRANSACTION_VERSION_POST_HF4 | TRANSACTION_VERSION_POST_HF5
        ) {
            return Err(Error::UnsupportedVersion);
        }
        if ftp.sources.is_empty() || ftp.prepared_destinations.is_empty() {
            return Err(Error::InvalidRing);
        }
        let fee = balance(ftp)?;

        let tx_secret = match one_time_key {
            Some(key) => crypto::scalar(key)?,
            None => random_scalar(rng),
        };
        let tx_public = EdwardsPoint::mul_base(&tx_secret);
        let mut tx = Transaction {
            version: ftp.tx_version,
            ..Default::default()
        };
        if ftp.tx_version >= TRANSACTION_VERSION_POST_HF5 {
            tx.hardfork_id = u8::try_from(ftp.tx_hardfork_id).map_err(|_| Error::TooLarge)?;
        }
        tx.extra.push(Variant::PubKey(tx_public.compress()));
        tx.extra.push(Variant::EtcTxFlags16(0));

        // Inputs: the ring as offsets, and the key image.
        let spend_public = crypto::point(self.spend_public_key())?;
        let mut inputs = Vec::with_capacity(ftp.sources.len());
        for source in &ftp.sources {
            if !source.is_zc() {
                return Err(Error::Unsupported);
            }
            let real_index = usize::try_from(source.real_output).map_err(|_| Error::InvalidRing)?;
            let real = source.outputs.get(real_index).ok_or(Error::InvalidRing)?;
            let mut vin = TxInZcInput::default();
            let mut previous = 0u64;
            for (n, out) in source.outputs.iter().enumerate() {
                let Variant::Uint64(global_index) = out.out_reference else {
                    return Err(Error::Unsupported);
                };
                // Indices are relative to the previous one, and increase.
                let offset = global_index
                    .checked_sub(previous)
                    .filter(|offset| n == 0 || *offset != 0)
                    .ok_or(Error::InvalidRing)?;
                previous = global_index;
                vin.key_offsets.push(Variant::Uint64(offset));
            }

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
            let key_image_bytes = key_image.compress();
            vin.key_image = key_image_bytes;
            inputs.push(Input {
                source,
                hi,
                key_image,
                key_image_bytes,
                vin,
            });
        }

        // Outputs.
        let inv8 = scalar_1div8();
        let x_gen = generator_x();
        let mut outputs = Vec::with_capacity(ftp.prepared_destinations.len());
        let mut hints: Vec<u16> = Vec::new();
        for (index, dst) in ftp.prepared_destinations.iter().enumerate() {
            let [addr] = dst.addr.as_slice() else {
                return Err(Error::Unsupported);
            };
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
            let blinded_asset_id = asset_id.add(&x_gen.mul(&secrets.asset_blinding_mask));
            let amount_commitment = blinded_asset_id
                .mul(&scalar_u64(dst.amount))
                .add(&EdwardsPoint::mul_base(&secrets.amount_blinding_mask));
            tx.vout.push(Variant::OutZarcanum(TxOutZarcanum {
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
            }));
            outputs.push(Output {
                amount: dst.amount,
                asset_id,
                blinded_asset_id,
                amount_commitment,
                asset_blinding_mask: secrets.asset_blinding_mask.clone(),
                amount_blinding_mask: secrets.amount_blinding_mask.clone(),
            });
        }

        // One hint per output: random ones make up for shared derivations.
        while hints.len() < tx.vout.len() {
            let mut random = [0u8; 2];
            rng(&mut random);
            // Offset by the count, so that a constant `rng` still ends.
            let hint = u16::from_le_bytes(random).wrapping_add(hints.len() as u16);
            if !hints.contains(&hint) {
                hints.push(hint);
            }
        }
        hints.sort_unstable();
        for hint in hints {
            tx.extra
                .push(Variant::DerivationHint(hint.to_le_bytes().to_vec()));
        }

        // Inputs go by increasing key image.
        inputs.sort_by_key(|input| input.key_image_bytes);
        for input in &inputs {
            tx.vin.push(Variant::ZcInput(input.vin.clone()));
        }
        if fee == 0 {
            return Err(Error::MissingFee);
        }
        tx.extra.push(Variant::ZarcanumTxDataV1 { fee });

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
        // Per input: T^p_i, the asset id H_i, and r_i + r'_i.
        let mut pseudo_outs = Vec::with_capacity(inputs.len());

        let default_asset_id = outputs.first().map(|o| o.asset_id);
        let last = inputs.len().saturating_sub(1);
        for (n, input) in inputs.iter().enumerate() {
            let source = input.source;
            let asset_id = match &source.asset_id {
                Some(id) => crypto::point(id)?,
                None => default_asset_id.ok_or(Error::InvalidRing)?,
            };
            let real_amount_mask = crypto::scalar(&source.real_out_amount_blinding_mask)?;
            let real_asset_mask = crypto::scalar(&source.real_out_asset_id_blinding_mask)?;
            let amount = scalar_u64(source.amount);
            // T_i = H_i + r_i * X
            let source_blinded_asset_id = asset_id.add(&x_gen.mul(&real_asset_mask));

            // The last pseudo-output's mask makes the G components of the
            // balance equation cancel out.
            let pseudo_amount_mask = if n == last {
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

            let ring: Vec<ClsagGgxInput> = source
                .outputs
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
                usize::try_from(source.real_output).map_err(|_| Error::InvalidRing)?,
            )?;
            tx.signatures.push(Variant::ZcSig(ZcSig {
                pseudo_out_amount_commitment: pseudo_amount_commitment.mul(&inv8).compress(),
                pseudo_out_blinded_asset_id: pseudo_blinded_asset_id.mul(&inv8).compress(),
                clsag_ggx,
            }));
            pseudo_outs.push((
                pseudo_blinded_asset_id,
                asset_id,
                pseudo_asset_mask.add(&real_asset_mask),
            ));
        }

        // Asset surjection: each output has the asset of some input.
        let mut surjection = ZcAssetSurjectionProof::default();
        for output in &outputs {
            // T^p_i - T'_j = (r_i + r'_i - s_j) * X for an input of the same
            // asset.
            let ring: Vec<EdwardsPoint> = pseudo_outs
                .iter()
                .map(|(blinded, _, _)| blinded.sub(&output.blinded_asset_id))
                .collect();
            let (secret_index, (_, _, mask)) = pseudo_outs
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
        // multiple of X, and the signer knows the transaction secret key.
        let amount_commitments_sum = commitments
            .iter()
            .fold(EdwardsPoint::identity(), |acc, c| acc.add(c));
        let commitment_to_zero = pseudo_out_amount_commitments_sum
            .sub(&amount_commitments_sum)
            .sub(&mul_vartime(&scalar_u64(fee), &generator_h()));
        let secret_x = real_in_asset_mask_x_amount_sum.sub(&asset_mask_x_amount_sum);
        let dss = generate_double_schnorr_sig(
            rng,
            SchnorrGenerator::X,
            &tx_id,
            &commitment_to_zero,
            &secret_x,
            &tx_public,
            &tx_secret,
        )?;
        tx.proofs
            .push(Variant::BalanceProof(ZcBalanceProof { dss }));

        Ok(FinalizedTx {
            tx,
            tx_id: [0u8; 32],
            one_time_key: tx_secret.to_bytes(),
            ftp: ftp.clone(),
            htlc_origin: Vec::new(),
            outs_key_images: Vec::new(),
            derivation: [0u8; 32],
            was_not_prepared: false,
        })
    }
}

/// The inputs' pseudo-outputs and the Zarcanum outputs of a transaction
/// whose inputs are all confidential.
fn zc_parts(tx: &Transaction) -> Option<(Vec<&ZcSig>, Vec<&TxOutZarcanum>)> {
    let sigs: Vec<&ZcSig> = tx
        .signatures
        .iter()
        .map(|s| match s {
            Variant::ZcSig(sig) => Some(sig),
            _ => None,
        })
        .collect::<Option<_>>()?;
    let outs: Vec<&TxOutZarcanum> = tx
        .vout
        .iter()
        .map(|o| match o {
            Variant::OutZarcanum(out) => Some(out),
            _ => None,
        })
        .collect::<Option<_>>()?;
    let all_zc = tx.vin.iter().all(|i| matches!(i, Variant::ZcInput(_)));
    (all_zc && !sigs.is_empty() && sigs.len() == tx.vin.len() && !outs.is_empty())
        .then_some((sigs, outs))
}

impl Transaction {
    /// Verifies the transaction-wide proofs of a transaction (version 2 or
    /// 3) whose inputs are all confidential: the asset surjection proof,
    /// the range proof with its aggregation proof, and the balance proof.
    ///
    /// The ring signatures of the inputs are *not* covered — they need the
    /// outputs the rings refer to: see
    /// [`verify_input`](Self::verify_input). Returns `false` for any other
    /// kind of transaction. Variable-time.
    pub fn verify_proofs(&self) -> bool {
        self.verify_proofs_inner().unwrap_or(false)
    }

    fn verify_proofs_inner(&self) -> Option<bool> {
        if !matches!(
            self.version,
            TRANSACTION_VERSION_POST_HF4 | TRANSACTION_VERSION_POST_HF5
        ) {
            return None;
        }
        let (sigs, outs) = zc_parts(self)?;
        let [
            Variant::AssetSurjectionProof(surjection),
            Variant::OutsRangeProof(range),
            Variant::BalanceProof(balance),
        ] = self.proofs.as_slice()
        else {
            return None;
        };
        let tx_id = self.prefix_hash();
        let inv8 = scalar_1div8();
        let point8 = |bytes: &[u8; 32]| Some(crypto::point(bytes).ok()?.mul_by_cofactor());

        // Asset surjection.
        if surjection.bge_proofs.len() != outs.len() {
            return Some(false);
        }
        let mut pseudo_asset_ids = Vec::with_capacity(sigs.len());
        for sig in &sigs {
            pseudo_asset_ids.push(point8(&sig.pseudo_out_blinded_asset_id)?);
        }
        for (out, proof) in outs.iter().zip(&surjection.bge_proofs) {
            let blinded = point8(&out.blinded_asset_id)?;
            let ring: Vec<[u8; 32]> = pseudo_asset_ids
                .iter()
                .map(|p| mul_vartime(&inv8, &p.sub(&blinded)).compress())
                .collect();
            if !verify_bge_proof(&tx_id, &ring, proof) {
                return Some(false);
            }
        }

        // Range.
        let amount_commitments: Vec<[u8; 32]> = outs.iter().map(|o| o.amount_commitment).collect();
        let blinded_asset_ids: Vec<[u8; 32]> = outs.iter().map(|o| o.blinded_asset_id).collect();
        if !verify_vector_ug_aggregation_proof(
            &tx_id,
            &amount_commitments,
            &blinded_asset_ids,
            &range.aggregation_proof,
        ) || !verify_bpp(
            &range.bpp,
            &range
                .aggregation_proof
                .amount_commitments_for_rp_aggregation,
        ) {
            return Some(false);
        }

        // Balance: sum(A^p) - sum(E) - fee * H is a multiple of X.
        let fee = self.fee()?;
        let mut commitment_to_zero = mul_vartime(&scalar_u64(fee), &generator_h()).negate();
        for sig in &sigs {
            commitment_to_zero =
                commitment_to_zero.add(&point8(&sig.pseudo_out_amount_commitment)?);
        }
        for out in &outs {
            commitment_to_zero = commitment_to_zero.sub(&point8(&out.amount_commitment)?);
        }
        Some(verify_double_schnorr_sig(
            SchnorrGenerator::X,
            &tx_id,
            &commitment_to_zero,
            &self.tx_pub_key()?,
            &balance.dss,
        ))
    }

    /// Verifies the ring signature of the confidential input `index`, given
    /// the outputs its ring refers to, in ring order. Variable-time.
    pub fn verify_input(&self, index: usize, ring: &[ClsagGgxInput]) -> bool {
        let (Some(Variant::ZcInput(input)), Some(Variant::ZcSig(sig))) =
            (self.vin.get(index), self.signatures.get(index))
        else {
            return false;
        };
        verify_clsag_ggx(
            &self.prefix_hash(),
            ring,
            &sig.pseudo_out_amount_commitment,
            &sig.pseudo_out_blinded_asset_id,
            &input.key_image,
            &sig.clsag_ggx,
        )
    }
}
