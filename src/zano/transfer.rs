//! Building a transfer from scanned outputs, without a view-only
//! `simplewallet` in the loop.

use purecrypto::zeroize::Zeroize;

use crate::prelude::*;

use super::ftp::{FinalizeTxParam, FinalizedTx, TxDest, TxSource, TxSourceOutputEntry};
use super::tx::{AccountPublicAddr, TRANSACTION_VERSION_POST_HF6, Variant, mainnet_tx_version};
use super::{Address, Error, Wallet, crypto};

/// One output of an input's ring — the real output or a decoy — as the
/// daemon returns it: by its chain-wide global index, with its points as
/// they are on chain (times `1/8`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RingMember {
    /// The global index of the output.
    pub global_index: u64,
    /// Its one-time public key.
    pub stealth_address: [u8; 32],
    /// Its concealing point.
    pub concealing_point: [u8; 32],
    /// Its amount commitment.
    pub amount_commitment: [u8; 32],
    /// Its blinded asset id.
    pub blinded_asset_id: [u8; 32],
}

/// An output to spend: what [`Wallet::scan_tx`] recovered about it, where it
/// is, and a ring of decoys that includes it.
///
/// The blinding masks are wiped when the value is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferInput {
    /// The amount of the output.
    pub amount: u64,
    /// Its asset id, unblinded.
    pub asset_id: [u8; 32],
    /// The blinding mask of its amount commitment.
    pub amount_blinding_mask: [u8; 32],
    /// The blinding mask of its asset id.
    pub asset_id_blinding_mask: [u8; 32],
    /// The public key of the transaction that created it.
    pub real_out_tx_key: [u8; 32],
    /// Its index in that transaction.
    pub real_out_index: u64,
    /// Its global index.
    pub real_global_index: u64,
    /// The ring: decoys and the real output, in any order.
    pub ring: Vec<RingMember>,
}

impl Drop for TransferInput {
    fn drop(&mut self) {
        self.amount_blinding_mask.zeroize();
        self.asset_id_blinding_mask.zeroize();
    }
}

impl TransferInput {
    /// The source entry for this input: the ring sorted by global index,
    /// with the real output located in it.
    fn to_source(&self) -> Result<TxSource, Error> {
        let mut ring = self.ring.clone();
        ring.sort_by_key(|member| member.global_index);
        if ring.is_empty()
            || ring
                .windows(2)
                .any(|w| matches!(w, [a, b] if a.global_index == b.global_index))
        {
            return Err(Error::InvalidRing);
        }
        let real_output = ring
            .iter()
            .position(|member| member.global_index == self.real_global_index)
            .ok_or(Error::InvalidRing)?;

        let mut outputs = Vec::with_capacity(ring.len());
        for member in &ring {
            for point in [
                &member.stealth_address,
                &member.concealing_point,
                &member.amount_commitment,
                &member.blinded_asset_id,
            ] {
                crypto::point(point)?;
            }
            outputs.push(TxSourceOutputEntry {
                out_reference: Variant::Uint64(member.global_index),
                stealth_address: member.stealth_address,
                concealing_point: member.concealing_point,
                amount_commitment: member.amount_commitment,
                blinded_asset_id: member.blinded_asset_id,
            });
        }
        crypto::point(&self.real_out_tx_key)?;
        crypto::point(&self.asset_id)?;

        Ok(TxSource {
            outputs,
            real_output: real_output as u64,
            real_out_tx_key: self.real_out_tx_key,
            real_out_amount_blinding_mask: self.amount_blinding_mask,
            real_out_asset_id_blinding_mask: self.asset_id_blinding_mask,
            real_out_in_tx_index: self.real_out_index,
            amount: self.amount,
            transfer_index: 0,
            multisig_id: [0; 32],
            ms_sigs_count: 0,
            ms_keys_count: 0,
            separately_signed_tx_complete: false,
            htlc_origin: Vec::new(),
            asset_id: Some(self.asset_id),
            is_zc_input: self.amount_blinding_mask != [0u8; 32]
                || self.asset_id_blinding_mask != [0u8; 32],
        })
    }
}

/// An output to create: `amount` of `asset_id` to `address`.
///
/// The payment id of an integrated address goes into the output of a
/// version 4 transaction, if it is of eight bytes at most
/// ([`Error::PaymentIdTooLong`] otherwise); it is not attached to a
/// transaction of version 2 or 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferDest {
    /// The recipient.
    pub address: Address,
    /// The asset id, unblinded
    /// ([`NATIVE_COIN_ASSET_ID`](super::NATIVE_COIN_ASSET_ID) for ZANO).
    pub asset_id: [u8; 32],
    /// The amount.
    pub amount: u64,
}

impl Wallet {
    /// The unsigned transaction that spends `inputs` into `dests`, ready
    /// for [`sign`](Self::sign).
    ///
    /// The fee is implicit: the native coin surplus of the inputs over the
    /// outputs. Every other asset must balance exactly, so change needs a
    /// destination of its own.
    ///
    /// Fails with [`Error::InvalidRing`] (no inputs, an empty ring, a
    /// repeated global index, the real output missing from its ring) and
    /// `InvalidPoint` for a malformed ring member, key or asset id.
    pub fn transfer_params(
        &self,
        inputs: &[TransferInput],
        dests: &[TransferDest],
        version: u64,
        hardfork_id: u64,
    ) -> Result<FinalizeTxParam, Error> {
        if inputs.is_empty() {
            return Err(Error::InvalidRing);
        }
        let mut ftp = FinalizeTxParam {
            spend_pub_key: *self.spend_public_key(),
            tx_version: version,
            tx_hardfork_id: hardfork_id,
            ..Default::default()
        };
        for input in inputs {
            ftp.sources.push(input.to_source()?);
        }
        for dest in dests {
            crypto::point(&dest.asset_id)?;
            // The payment id of an integrated address goes into a version 4
            // output, as the eight bytes `convert_payment_id` makes of it.
            let mut payment_id = 0u64;
            let id = dest.address.payment_id();
            if version >= TRANSACTION_VERSION_POST_HF6 && !id.is_empty() {
                let mut bytes = [0u8; 8];
                let start = 8usize
                    .checked_sub(id.len())
                    .ok_or(Error::PaymentIdTooLong)?;
                bytes[start..].copy_from_slice(id);
                payment_id = u64::from_le_bytes(bytes);
            }
            ftp.prepared_destinations.push(TxDest {
                amount: dest.amount,
                addr: vec![AccountPublicAddr::from(&dest.address)],
                asset_id: dest.asset_id,
                payment_id,
                ..Default::default()
            });
        }
        Ok(ftp)
    }

    /// [`build_transfer`](Self::build_transfer) with the transaction
    /// version and the hardfork id of a block at `height` of the main
    /// network ([`mainnet_tx_version`]): the height the transaction is
    /// expected to be included at, in practice the current one.
    pub fn build_transfer_at_height(
        &self,
        rng: &mut dyn FnMut(&mut [u8]),
        inputs: &[TransferInput],
        dests: &[TransferDest],
        height: u64,
    ) -> Result<FinalizedTx, Error> {
        let (version, hardfork_id) = mainnet_tx_version(height);
        self.build_transfer(rng, inputs, dests, version, u64::from(hardfork_id))
    }

    /// Builds and signs a transfer of `inputs` to `dests`
    /// ([`transfer_params`](Self::transfer_params), then
    /// [`sign`](Self::sign) with a transaction key drawn from `rng`).
    ///
    /// Fails with [`Error::ViewOnly`] without a secret spend key, and the
    /// errors of the two steps.
    pub fn build_transfer(
        &self,
        rng: &mut dyn FnMut(&mut [u8]),
        inputs: &[TransferInput],
        dests: &[TransferDest],
        version: u64,
        hardfork_id: u64,
    ) -> Result<FinalizedTx, Error> {
        if self.is_view_only() {
            return Err(Error::ViewOnly);
        }
        let ftp = self.transfer_params(inputs, dests, version, hardfork_id)?;
        self.sign(rng, &ftp, None)
    }
}
