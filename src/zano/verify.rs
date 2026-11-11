//! Verification of a whole transaction: the signatures of its inputs, the
//! asset surjection, range and balance proofs, and the proofs of an asset
//! operation, as the reference checks them (`check_tx_balance`,
//! `verify_asset_surjection_proof`, `collect_rangeproofs_data_from_tx`,
//! `check_tx_input`, `validate_asset_operation`, `validate_pos_block`).

use crate::cryptonote::{EdwardsPoint, Scalar};
use crate::prelude::*;

use super::TxOutZarcanum;
use super::bge::verify_bge_proof;
use super::bpp::verify_bpp;
use super::clsag::{ClsagGgxInput, verify_clsag_ggx};
use super::crypto::{self, generator_h, mul_vartime, scalar_1div8, scalar_u64};
use super::nlsag::verify_ring_signature;
use super::schnorr::{
    SchnorrGenerator, verify_double_schnorr_sig, verify_vector_ug_aggregation_proof,
};
use super::tx::{
    TRANSACTION_VERSION_POST_HF6, TRANSACTION_VERSION_PRE_HF4, TX_FLAG_SIGNATURE_MODE_SEPARATE,
    Transaction, Variant, ZcAssetSurjectionProof, ZcBalanceProof, ZcOutsRangeProof,
};
use super::tx_ext::{ASSET_DESCRIPTOR_OPERATION_PUBLIC_BURN, AssetDescriptorBase};
use super::zarcanum::{StakeContext, verify_zarcanum_proof};

/// Why a transaction does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// The transaction is not built as its version requires: a signature
    /// or a proof is missing or of the wrong kind, counts do not match, a
    /// point or a scalar does not decode.
    Malformed,
    /// The transaction uses something this module does not verify: a
    /// multisig or gateway input, a gateway output, the separate signature
    /// mode, a hidden asset supply, an asset owned by an Ethereum key
    /// without the `secp256k1` feature.
    Unsupported,
    /// The inputs are not in the order hard fork 4 requires.
    InputsNotSorted,
    /// No ring was given for this input, or one of the wrong size.
    MissingRing(usize),
    /// The signature of this input is not valid.
    InputSignature(usize),
    /// The asset surjection proof is not valid, or an output that must
    /// carry the bare native asset id does not.
    AssetSurjection,
    /// The range proof of the outputs is not valid.
    RangeProof,
    /// Inputs and outputs do not balance.
    Balance,
    /// The amount commitment of the asset operation is not proven.
    AssetOperation,
    /// The owner of the asset did not sign its operation.
    AssetOwnership,
    /// An asset operation needs the asset's previous descriptor.
    MissingAssetDescriptor,
    /// The coinbase of a proof-of-stake block needs a [`StakeContext`].
    MissingStakeContext,
    /// The stake proof of a proof-of-stake block is not valid.
    Stake,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::Malformed => f.write_str("malformed transaction"),
            VerifyError::Unsupported => f.write_str("unsupported transaction feature"),
            VerifyError::InputsNotSorted => f.write_str("inputs are not sorted"),
            VerifyError::MissingRing(n) => write!(f, "no usable ring for input {n}"),
            VerifyError::InputSignature(n) => write!(f, "invalid signature of input {n}"),
            VerifyError::AssetSurjection => f.write_str("invalid asset surjection proof"),
            VerifyError::RangeProof => f.write_str("invalid range proof"),
            VerifyError::Balance => f.write_str("invalid balance proof"),
            VerifyError::AssetOperation => f.write_str("invalid asset operation proof"),
            VerifyError::AssetOwnership => f.write_str("invalid asset ownership proof"),
            VerifyError::MissingAssetDescriptor => {
                f.write_str("the asset's previous descriptor is needed")
            }
            VerifyError::MissingStakeContext => f.write_str("the stake context is needed"),
            VerifyError::Stake => f.write_str("invalid stake proof"),
        }
    }
}

impl core::error::Error for VerifyError {}

/// What [`Transaction::verify`] needs from the chain.
///
/// ```
/// use outscript::zano::VerifyContext;
///
/// // A coinbase transaction of a proof-of-work block has no rings.
/// let context = VerifyContext::new(&[]).block_reward(1_000_000_000_000);
/// # let _ = context;
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyContext<'a> {
    rings: &'a [&'a [ClsagGgxInput]],
    block_reward: u64,
    asset_descriptor: Option<&'a AssetDescriptorBase>,
    stake: Option<&'a StakeContext>,
}

impl<'a> VerifyContext<'a> {
    /// A context with the rings of the inputs: for each input that has a
    /// key image (transparent or confidential), in input order, the outputs
    /// its `key_offsets` refer to, in ring order. For a transparent input
    /// only the stealth addresses are used.
    ///
    /// The confidential stake input of a proof-of-stake block is the
    /// exception: its ring, which needs the concealing points too, is in
    /// the [`StakeContext`], and it has no entry here.
    pub fn new(rings: &'a [&'a [ClsagGgxInput]]) -> Self {
        VerifyContext {
            rings,
            ..Default::default()
        }
    }

    /// For the first transaction of a block: what it may create — the
    /// block reward, plus, before hard fork 4, the fees of the block.
    pub fn block_reward(mut self, block_reward: u64) -> Self {
        self.block_reward = block_reward;
        self
    }

    /// For an asset operation: the descriptor of the asset before it (see
    /// [`Transaction::verify_asset_operation`]).
    pub fn asset_descriptor(mut self, descriptor: &'a AssetDescriptorBase) -> Self {
        self.asset_descriptor = Some(descriptor);
        self
    }

    /// For the first transaction of a proof-of-stake block: what its stake
    /// proof is about.
    pub fn stake(mut self, stake: &'a StakeContext) -> Self {
        self.stake = Some(stake);
        self
    }
}

/// `(1/8) * H`: the blinded asset id of an output with the bare native
/// asset id (`native_coin_asset_id_1div8`).
fn native_asset_id_1div8() -> [u8; 32] {
    mul_vartime(&scalar_1div8(), &generator_h()).compress()
}

fn point8(bytes: &[u8; 32]) -> Result<EdwardsPoint, VerifyError> {
    Ok(crypto::point(bytes)
        .map_err(|_| VerifyError::Malformed)?
        .mul_by_cofactor())
}

/// Where an input sorts (`less_txin_v`): by kind, then by key image (or
/// what stands for it).
fn input_order(input: &Variant) -> Option<(u8, [u8; 32])> {
    let key = match input {
        Variant::Gen { height } => {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&height.to_be_bytes());
            key
        }
        Variant::ToKey(input) => input.k_image,
        Variant::InMultisig(input) => input.multisig_out_id,
        Variant::ZcInput(input) => input.key_image,
        Variant::InGateway(input) => input.gateway_addr,
        _ => return None,
    };
    Some((input.tag(), key))
}

/// The confidential outputs of a transaction, with their count.
fn zarcanum_outs(tx: &Transaction) -> Vec<TxOutZarcanum> {
    tx.vout.iter().filter_map(Variant::zarcanum_out).collect()
}

fn single<'a, T>(
    items: &'a [Variant],
    pick: impl Fn(&'a Variant) -> Option<&'a T>,
) -> Result<Option<&'a T>, VerifyError> {
    let mut found = items.iter().filter_map(pick);
    match (found.next(), found.next()) {
        (first, None) => Ok(first),
        _ => Err(VerifyError::Malformed),
    }
}

impl Transaction {
    /// Verifies the transaction-wide proofs of a transaction of version 2
    /// to 4 that is not the first of a block: the asset surjection proof,
    /// the range proof with its aggregation proof, and the balance proof.
    ///
    /// The signatures of the inputs are *not* covered — they need the
    /// outputs the rings refer to: see [`verify`](Self::verify) and
    /// [`verify_input`](Self::verify_input). Variable-time.
    pub fn verify_proofs(&self) -> bool {
        self.check_proofs(0).is_ok()
    }

    /// [`verify_proofs`](Self::verify_proofs) (with a zero `block_reward`)
    /// or [`verify_coinbase_proofs`](Self::verify_coinbase_proofs), telling
    /// which proof fails.
    pub fn try_verify_proofs(&self, block_reward: u64) -> Result<(), VerifyError> {
        self.check_proofs(block_reward)
    }

    /// [`verify_proofs`](Self::verify_proofs) for the first transaction of
    /// a block, which creates `block_reward` (the base reward of the block:
    /// from hard fork 4 on, fees are burnt).
    pub fn verify_coinbase_proofs(&self, block_reward: u64) -> bool {
        self.is_coinbase() && self.check_proofs(block_reward).is_ok()
    }

    /// Verifies the signature of the input `index` that has a key image,
    /// given the outputs its ring refers to, in ring order: the CLSAG-GGX
    /// signature of a confidential input, or the ring signature of a
    /// transparent one (which only uses the stealth addresses of `ring`).
    ///
    /// The stake input of a proof-of-stake block is not covered: see
    /// [`verify`](Self::verify). Variable-time.
    pub fn verify_input(&self, index: usize, ring: &[ClsagGgxInput]) -> bool {
        self.flags() & TX_FLAG_SIGNATURE_MODE_SEPARATE == 0
            && self
                .check_input(index, ring, &self.prefix_hash(), None)
                .is_ok()
    }

    /// Verifies everything about the transaction that does not need more
    /// of the chain than `context` holds:
    ///
    /// - the order of the inputs (from version 2 on);
    /// - the signature of every input, against the rings of `context`;
    /// - for versions 0 and 1, that the transparent amounts balance;
    /// - from version 2 on, the asset surjection, range and balance proofs
    ///   ([`verify_proofs`](Self::verify_proofs)), and the proofs of an
    ///   asset operation
    ///   ([`verify_asset_operation`](Self::verify_asset_operation));
    /// - for the first transaction of a proof-of-stake block, the stake
    ///   proof: the Zarcanum proof from hard fork 4 on; before, the
    ///   signature of the stake over the block id and, if the
    ///   [`StakeContext`] has a difficulty, the kernel of the stake against
    ///   it.
    ///
    /// What is *not* checked is what only the chain knows: that the rings
    /// are the outputs the inputs refer to, that the key images are unspent,
    /// unlock times, mixing attributes, the minimum fee and the size limits,
    /// and which entries a hard fork allows.
    ///
    /// Each proof is verified on its own; nothing is batched across
    /// transactions. Variable-time.
    pub fn verify(&self, context: &VerifyContext<'_>) -> Result<(), VerifyError> {
        if self.flags() & TX_FLAG_SIGNATURE_MODE_SEPARATE != 0 {
            return Err(VerifyError::Unsupported);
        }
        let tx_id = self.prefix_hash();
        let pre_hf4 = self.version <= TRANSACTION_VERSION_PRE_HF4;

        if !pre_hf4 {
            let mut previous = None;
            for input in &self.vin {
                let order = input_order(input).ok_or(VerifyError::Malformed)?;
                if previous.is_some_and(|previous| order < previous) {
                    return Err(VerifyError::InputsNotSorted);
                }
                previous = Some(order);
            }
        }

        // The coinbase input has no signature; every other input has one.
        let signed = self
            .vin
            .iter()
            .filter(|input| !matches!(input, Variant::Gen { .. }))
            .count();
        if self.signatures.len() != signed {
            return Err(VerifyError::Malformed);
        }
        let mut rings = context.rings.iter();
        for (index, input) in self.vin.iter().enumerate() {
            if matches!(input, Variant::Gen { .. }) {
                continue;
            }
            // The ring of a Zarcanum stake comes with the stake context.
            let zarcanum_stake =
                index == 1 && self.is_pos_coinbase() && matches!(input, Variant::ZcInput(_));
            let ring = if zarcanum_stake {
                &[][..]
            } else {
                rings.next().ok_or(VerifyError::MissingRing(index))?
            };
            self.check_input(index, ring, &tx_id, context.stake)?;
        }

        if pre_hf4 {
            return self.check_bare_balance(context.block_reward);
        }
        self.check_proofs(context.block_reward)?;
        self.verify_asset_operation(context.asset_descriptor)
    }

    /// The signature of input `index`.
    fn check_input(
        &self,
        index: usize,
        ring: &[ClsagGgxInput],
        tx_id: &[u8; 32],
        stake: Option<&StakeContext>,
    ) -> Result<(), VerifyError> {
        let input = self.vin.get(index).ok_or(VerifyError::Malformed)?;
        // Signatures skip the coinbase input.
        let skipped = self
            .vin
            .iter()
            .take(index)
            .filter(|input| matches!(input, Variant::Gen { .. }))
            .count();
        let sig = self
            .signatures
            .get(index - skipped)
            .ok_or(VerifyError::Malformed)?;
        let is_stake = self.is_pos_coinbase() && index == 1;
        let ok = match (input, sig) {
            (Variant::ToKey(input), Variant::Nlsag(sig)) => {
                if ring.len() != input.key_offsets.len() {
                    return Err(VerifyError::MissingRing(index));
                }
                // The stake of a proof-of-stake block signs the block id.
                let message = if is_stake {
                    &stake.ok_or(VerifyError::MissingStakeContext)?.block_id
                } else {
                    tx_id
                };
                let keys: Vec<[u8; 32]> = ring.iter().map(|m| m.stealth_address).collect();
                let signed = verify_ring_signature(message, &keys, &input.k_image, sig);
                // The kernel of the stake against the difficulty, if the
                // context has one.
                if let Some(stake) = stake.filter(|s| is_stake && signed && s.pos_difficulty != 0)
                    && !stake.check_bare_kernel(&input.k_image, input.amount)
                {
                    return Err(VerifyError::Stake);
                }
                signed
            }
            (Variant::ZcInput(input), Variant::ZcSig(sig)) => {
                if ring.len() != input.key_offsets.len() {
                    return Err(VerifyError::MissingRing(index));
                }
                verify_clsag_ggx(
                    tx_id,
                    ring,
                    &sig.pseudo_out_amount_commitment,
                    &sig.pseudo_out_blinded_asset_id,
                    &input.key_image,
                    &sig.clsag_ggx,
                )
            }
            (Variant::ZcInput(input), Variant::ZarcanumSig(sig)) if is_stake => {
                let stake = stake.ok_or(VerifyError::MissingStakeContext)?;
                if stake.ring.len() != input.key_offsets.len() {
                    return Err(VerifyError::MissingRing(index));
                }
                return if verify_zarcanum_proof(stake, &input.key_image, sig) {
                    Ok(())
                } else {
                    Err(VerifyError::Stake)
                };
            }
            (Variant::InMultisig(_) | Variant::InGateway(_), _) => {
                return Err(VerifyError::Unsupported);
            }
            _ => return Err(VerifyError::Malformed),
        };
        if ok {
            Ok(())
        } else {
            Err(VerifyError::InputSignature(index))
        }
    }

    /// `check_tx_bare_balance`, for versions 0 and 1.
    fn check_bare_balance(&self, block_reward: u64) -> Result<(), VerifyError> {
        let surplus = self.bare_fee();
        let ok = if self.is_coinbase() {
            // inputs + reward == outputs
            let inputs = self.vin.iter().try_fold(0u64, |acc, input| match input {
                Variant::ToKey(input) => acc.checked_add(input.amount),
                _ => Some(acc),
            });
            let outputs = self.vout.iter().try_fold(0u64, |acc, out| match out {
                Variant::OutBare(out) => acc.checked_add(out.amount),
                _ => None,
            });
            inputs.and_then(|inputs| inputs.checked_add(block_reward)) == outputs
                && outputs.is_some()
        } else {
            surplus.is_some() && self.vout.iter().all(|o| matches!(o, Variant::OutBare(_)))
        };
        if ok {
            Ok(())
        } else {
            Err(VerifyError::Balance)
        }
    }

    /// The transaction-wide proofs of a transaction of version 2 to 4.
    pub(crate) fn check_proofs(&self, block_reward: u64) -> Result<(), VerifyError> {
        if self.version <= TRANSACTION_VERSION_PRE_HF4
            || self.version > TRANSACTION_VERSION_POST_HF6
            || self.flags() & TX_FLAG_SIGNATURE_MODE_SEPARATE != 0
        {
            return Err(VerifyError::Unsupported);
        }
        if block_reward != 0 && !self.is_coinbase() {
            return Err(VerifyError::Malformed);
        }
        for input in &self.vin {
            match input {
                Variant::Gen { .. } | Variant::ToKey(_) | Variant::ZcInput(_) => {}
                Variant::InMultisig(_) | Variant::InGateway(_) => {
                    return Err(VerifyError::Unsupported);
                }
                _ => return Err(VerifyError::Malformed),
            }
        }
        for out in &self.vout {
            match out {
                Variant::OutZarcanum(_) | Variant::OutZarcanumHf6(_) => {}
                Variant::OutGateway(_) => return Err(VerifyError::Unsupported),
                _ => return Err(VerifyError::Malformed),
            }
        }
        let tx_id = self.prefix_hash();
        let outs = zarcanum_outs(self);
        self.check_surjection(&tx_id, &outs)?;
        self.check_range(&tx_id, &outs)?;
        self.check_balance(&tx_id, &outs, block_reward)
    }

    /// `verify_asset_surjection_proof`: every output has the asset of some
    /// input, of the native coin if a transparent input brings some, or of
    /// the asset the transaction emits.
    fn check_surjection(
        &self,
        tx_id: &[u8; 32],
        outs: &[TxOutZarcanum],
    ) -> Result<(), VerifyError> {
        let hf6 = self.version >= TRANSACTION_VERSION_POST_HF6;
        let has_zc = self.vin.iter().any(|i| matches!(i, Variant::ZcInput(_)));
        let has_bare = self.vin.iter().any(|i| !matches!(i, Variant::ZcInput(_)));
        if !has_zc {
            // Only native coins come in: they must go out in the open.
            let native = native_asset_id_1div8();
            return if outs.iter().all(|out| out.blinded_asset_id == native) {
                Ok(())
            } else {
                Err(VerifyError::AssetSurjection)
            };
        }
        if hf6 && outs.is_empty() {
            return Ok(());
        }

        let pseudo_outs = self.signatures.iter().filter_map(|sig| match sig {
            Variant::ZcSig(sig) => Some(&sig.pseudo_out_blinded_asset_id),
            _ => None,
        });
        let native = has_bare.then(generator_h);
        let mut ring = Vec::new();
        // From hard fork 6 on the native member comes first.
        if hf6 {
            ring.extend(native);
        }
        for pseudo_out in pseudo_outs {
            ring.push(point8(pseudo_out)?);
        }
        if !hf6 {
            ring.extend(native);
        }
        if let Some(ado) = self.asset_operation().filter(|ado| ado.is_emitting()) {
            let asset_id = ado.target_asset_id().ok_or(VerifyError::Malformed)?;
            ring.push(crypto::point(&asset_id).map_err(|_| VerifyError::Malformed)?);
        }

        let proof: &ZcAssetSurjectionProof = single(&self.proofs, |p| match p {
            Variant::AssetSurjectionProof(proof) => Some(proof),
            _ => None,
        })?
        .ok_or(VerifyError::Malformed)?;
        if proof.bge_proofs.len() != outs.len() {
            return Err(VerifyError::Malformed);
        }
        let inv8 = scalar_1div8();
        for (out, bge) in outs.iter().zip(&proof.bge_proofs) {
            let blinded = point8(&out.blinded_asset_id)?;
            let ring: Vec<[u8; 32]> = ring
                .iter()
                .map(|member| mul_vartime(&inv8, &member.sub(&blinded)).compress())
                .collect();
            if !verify_bge_proof(tx_id, &ring, bge) {
                return Err(VerifyError::AssetSurjection);
            }
        }
        Ok(())
    }

    /// `collect_rangeproofs_data_from_tx` and
    /// `verify_multiple_zc_outs_range_proofs`.
    fn check_range(&self, tx_id: &[u8; 32], outs: &[TxOutZarcanum]) -> Result<(), VerifyError> {
        let proof: Option<&ZcOutsRangeProof> = single(&self.proofs, |p| match p {
            Variant::OutsRangeProof(proof) => Some(proof),
            _ => None,
        })?;
        let Some(proof) = proof else {
            // Only a transaction without confidential outputs, which hard
            // fork 6 made possible, has no range proof.
            return if outs.is_empty() && self.version >= TRANSACTION_VERSION_POST_HF6 {
                Ok(())
            } else {
                Err(VerifyError::Malformed)
            };
        };
        if proof
            .aggregation_proof
            .amount_commitments_for_rp_aggregation
            .len()
            != outs.len()
            || outs.is_empty()
        {
            return Err(VerifyError::Malformed);
        }
        let amount_commitments: Vec<[u8; 32]> = outs.iter().map(|o| o.amount_commitment).collect();
        let blinded_asset_ids: Vec<[u8; 32]> = outs.iter().map(|o| o.blinded_asset_id).collect();
        if verify_vector_ug_aggregation_proof(
            tx_id,
            &amount_commitments,
            &blinded_asset_ids,
            &proof.aggregation_proof,
        ) && verify_bpp(
            &proof.bpp,
            &proof
                .aggregation_proof
                .amount_commitments_for_rp_aggregation,
        ) {
            Ok(())
        } else {
            Err(VerifyError::RangeProof)
        }
    }

    /// `check_tx_balance`: what comes in minus what goes out, the fee
    /// included, is a multiple of `X` (with confidential inputs) or of `G`
    /// (without), and the signer knows the transaction secret key.
    fn check_balance(
        &self,
        tx_id: &[u8; 32],
        outs: &[TxOutZarcanum],
        block_reward: u64,
    ) -> Result<(), VerifyError> {
        let malformed = |_| VerifyError::Malformed;
        let mut bare_inputs = block_reward;
        let mut zc_inputs = 0usize;
        for input in &self.vin {
            match input {
                Variant::ToKey(input) => {
                    bare_inputs = bare_inputs
                        .checked_add(input.amount)
                        .ok_or(VerifyError::Balance)?;
                }
                Variant::ZcInput(_) => zc_inputs += 1,
                _ => {}
            }
        }
        // The first transaction of a block declares no fee; any other must.
        let fee = if self.is_coinbase() {
            0
        } else {
            self.fee().ok_or(VerifyError::Malformed)?
        };
        if block_reward != 0 && fee != 0 {
            return Err(VerifyError::Malformed);
        }

        // Sums of points that are on the wire times 1/8.
        let mut inputs_sum = EdwardsPoint::identity();
        let mut outs_sum = EdwardsPoint::identity();
        for out in outs {
            outs_sum = outs_sum.add(&crypto::point(&out.amount_commitment).map_err(malformed)?);
        }
        if let Some(ado) = self.asset_operation()
            && (ado.is_emitting() || ado.operation_type == ASSET_DESCRIPTOR_OPERATION_PUBLIC_BURN)
        {
            let commitment = ado.amount_commitment.ok_or(VerifyError::Malformed)?;
            let commitment = crypto::point(&commitment).map_err(malformed)?;
            if ado.is_emitting() {
                inputs_sum = inputs_sum.add(&commitment);
            } else {
                outs_sum = outs_sum.add(&commitment);
            }
        }
        let mut zc_sigs = 0usize;
        for sig in &self.signatures {
            let pseudo_out = match sig {
                Variant::ZcSig(sig) => &sig.pseudo_out_amount_commitment,
                Variant::ZarcanumSig(sig) => &sig.pseudo_out_amount_commitment,
                _ => continue,
            };
            inputs_sum = inputs_sum.add(&crypto::point(pseudo_out).map_err(malformed)?);
            zc_sigs += 1;
        }
        if zc_sigs != zc_inputs {
            return Err(VerifyError::Malformed);
        }

        let native: Scalar = scalar_u64(bare_inputs).sub(&scalar_u64(fee));
        let commitment_to_zero =
            mul_vartime(&native, &generator_h()).add(&inputs_sum.sub(&outs_sum).mul_by_cofactor());
        let proof: &ZcBalanceProof = single(&self.proofs, |p| match p {
            Variant::BalanceProof(proof) => Some(proof),
            _ => None,
        })?
        .ok_or(VerifyError::Malformed)?;
        let generator = if zc_inputs > 0 {
            SchnorrGenerator::X
        } else {
            SchnorrGenerator::G
        };
        let tx_pub_key = self.tx_pub_key().ok_or(VerifyError::Malformed)?;
        if verify_double_schnorr_sig(
            generator,
            tx_id,
            &commitment_to_zero,
            &tx_pub_key,
            &proof.dss,
        ) {
            Ok(())
        } else {
            Err(VerifyError::Balance)
        }
    }
}
