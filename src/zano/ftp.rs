//! The blobs a view-only `simplewallet` and an offline signer exchange: the
//! unsigned transaction (`finalize_tx_param`) and the signed one
//! (`finalized_tx`).
//!
//! Both are the binary serialization of the structure, encrypted with
//! ChaCha8 under a key derived from the secret view key. The format is not
//! versioned and follows the wallet's C++ structures: it matches Zano
//! 2.1.0.382 to 2.1.19.477.

use purecrypto::zeroize::{Zeroize, Zeroizing};

use crate::cryptonote::push_varint;
use crate::prelude::*;

use super::Error;
use super::chacha8::chacha8_crypt;
use super::ser::{self, Reader, Wire, write_bytes, write_vec};
use super::tx::{AccountPublicAddr, Transaction, Variant, wire_struct};

/// One member of the ring of a source (`tx_source_entry::output_entry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSourceOutputEntry {
    /// The output: its global index ([`Variant::Uint64`]) or a
    /// [`Variant::RefById`].
    pub out_reference: Variant,
    /// The one-time public key of the output.
    pub stealth_address: [u8; 32],
    /// Its concealing point, times `1/8`.
    pub concealing_point: [u8; 32],
    /// Its amount commitment, times `1/8`.
    pub amount_commitment: [u8; 32],
    /// Its blinded asset id, times `1/8`.
    pub blinded_asset_id: [u8; 32],
}
wire_struct!(TxSourceOutputEntry, min = 130, {
    out_reference: obj, stealth_address: key, concealing_point: key,
    amount_commitment: key, blinded_asset_id: key
});

/// An output to spend, with its ring (`tx_source_entry`).
///
/// The blinding masks are secret; they are wiped when the source is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSource {
    /// The ring: the real output and its decoys, by increasing global index.
    pub outputs: Vec<TxSourceOutputEntry>,
    /// The position of the real output in `outputs`.
    pub real_output: u64,
    /// The public key of the transaction that created the real output.
    pub real_out_tx_key: [u8; 32],
    /// The blinding mask of the real output's amount commitment.
    pub real_out_amount_blinding_mask: [u8; 32],
    /// The blinding mask of the real output's asset id.
    pub real_out_asset_id_blinding_mask: [u8; 32],
    /// The index of the real output in its transaction.
    pub real_out_in_tx_index: u64,
    /// The amount of the real output.
    pub amount: u64,
    /// The wallet's index of the transfer.
    pub transfer_index: u64,
    /// For a multisig input, the id of the multisig output.
    pub multisig_id: [u8; 32],
    /// For a multisig input, the number of signatures.
    pub ms_sigs_count: u64,
    /// For a multisig input, the number of keys.
    pub ms_keys_count: u64,
    /// Whether a separately signed transaction is complete.
    pub separately_signed_tx_complete: bool,
    /// For an HTLC input, its origin.
    pub htlc_origin: Vec<u8>,
    /// The asset id of the real output, unblinded. It is not part of the
    /// blob: a source parsed from one has `None`, which stands for the asset
    /// of the first destination when signing, and for the native coin when
    /// working out the fee.
    pub asset_id: Option<[u8; 32]>,
    /// Whether the source is a confidential (Zarcanum) output. Not part of
    /// the blob either: a parsed source counts as one when its asset
    /// blinding mask is not zero.
    pub is_zc_input: bool,
}

impl TxSource {
    /// Whether this source is a confidential output.
    pub fn is_zc(&self) -> bool {
        self.is_zc_input || self.real_out_asset_id_blinding_mask != [0u8; 32]
    }
}

impl Drop for TxSource {
    fn drop(&mut self) {
        self.real_out_amount_blinding_mask.zeroize();
        self.real_out_asset_id_blinding_mask.zeroize();
    }
}

impl Wire for TxSource {
    const MIN_SIZE: usize = 211;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(TxSource {
            outputs: r.vec()?,
            real_output: r.u64()?,
            real_out_tx_key: r.key()?,
            real_out_amount_blinding_mask: r.key()?,
            real_out_asset_id_blinding_mask: r.key()?,
            real_out_in_tx_index: r.u64()?,
            amount: r.u64()?,
            transfer_index: r.u64()?,
            multisig_id: r.key()?,
            ms_sigs_count: r.u64()?,
            ms_keys_count: r.u64()?,
            separately_signed_tx_complete: r.bool()?,
            htlc_origin: r.bytes()?,
            asset_id: None,
            is_zc_input: false,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        write_vec(out, &self.outputs);
        out.extend_from_slice(&self.real_output.to_le_bytes());
        out.extend_from_slice(&self.real_out_tx_key);
        out.extend_from_slice(&self.real_out_amount_blinding_mask);
        out.extend_from_slice(&self.real_out_asset_id_blinding_mask);
        out.extend_from_slice(&self.real_out_in_tx_index.to_le_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.transfer_index.to_le_bytes());
        out.extend_from_slice(&self.multisig_id);
        out.extend_from_slice(&self.ms_sigs_count.to_le_bytes());
        out.extend_from_slice(&self.ms_keys_count.to_le_bytes());
        out.push(u8::from(self.separately_signed_tx_complete));
        write_bytes(out, &self.htlc_origin);
    }
}

/// The HTLC options of a destination (`destination_option_htlc_out`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxDestHtlcOut {
    /// The expiration of the contract.
    pub expiration: u64,
    /// The hash that locks it.
    pub htlc_hash: [u8; 32],
}
wire_struct!(TxDestHtlcOut, min = 40, { expiration: u64, htlc_hash: key });

/// An output to create (`tx_destination_entry`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxDest {
    /// The amount.
    pub amount: u64,
    /// The recipient: one address (several would make a multisig output,
    /// which this module does not build).
    pub addr: Vec<AccountPublicAddr>,
    /// For a multisig output, the signatures required.
    pub minimum_sigs: u64,
    /// The amount provided by the initial creator of a partially created
    /// transaction.
    pub amount_to_provide: u64,
    /// The unlock time of the output.
    pub unlock_time: u64,
    /// The HTLC options.
    pub htlc_options: TxDestHtlcOut,
    /// The asset id, unblinded.
    pub asset_id: [u8; 32],
    /// The `tx_destination_entry_flags`.
    pub flags: u64,
}
wire_struct!(TxDest, min = 105, {
    amount: u64, addr: vec, minimum_sigs: u64, amount_to_provide: u64, unlock_time: u64,
    htlc_options: obj, asset_id: key, flags: u64
});

/// A varint, as an element of a sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct VarintItem(u64);

impl Wire for VarintItem {
    const MIN_SIZE: usize = 1;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(VarintItem(r.varint()?))
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_varint(out, self.0);
    }
}

/// An unsigned transaction: what a view-only wallet hands to the signer
/// (`finalize_tx_param`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FinalizeTxParam {
    /// The unlock time of the transaction.
    pub unlock_time: u64,
    /// Extra entries to put in the transaction.
    pub extra: Vec<Variant>,
    /// Attachments to put in the transaction.
    pub attachments: Vec<Variant>,
    /// The address attachments are encrypted for.
    pub crypt_address: AccountPublicAddr,
    /// The mixing attribute of the outputs.
    pub tx_outs_attr: u8,
    /// Whether to shuffle the outputs.
    pub shuffle: bool,
    /// The transaction flags.
    pub flags: u8,
    /// For a multisig transaction, the id of the multisig output.
    pub multisig_id: [u8; 32],
    /// The outputs to spend.
    pub sources: Vec<TxSource>,
    /// The wallet's indices of the transfers spent.
    pub selected_transfers: Vec<u64>,
    /// The outputs to create.
    pub prepared_destinations: Vec<TxDest>,
    /// The expiration time of the transaction.
    pub expiration_time: u64,
    /// The public spend key of the wallet that prepared the transaction.
    pub spend_pub_key: [u8; 32],
    /// The transaction version to build.
    pub tx_version: u64,
    /// The hardfork id to put in a version 3 transaction.
    pub tx_hardfork_id: u64,
    /// The fee mode of a separately signed transaction.
    pub mode_separate_fee: u64,
}

impl Wire for FinalizeTxParam {
    const MIN_SIZE: usize = 180;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(FinalizeTxParam {
            unlock_time: r.u64()?,
            extra: r.vec()?,
            attachments: r.vec()?,
            crypt_address: Wire::read(r)?,
            tx_outs_attr: r.u8()?,
            shuffle: r.bool()?,
            flags: r.u8()?,
            multisig_id: r.key()?,
            sources: r.vec()?,
            selected_transfers: r.vec::<VarintItem>()?.into_iter().map(|v| v.0).collect(),
            prepared_destinations: r.vec()?,
            expiration_time: r.u64()?,
            spend_pub_key: r.key()?,
            tx_version: r.u64()?,
            tx_hardfork_id: r.u64()?,
            mode_separate_fee: r.u64()?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.unlock_time.to_le_bytes());
        write_vec(out, &self.extra);
        write_vec(out, &self.attachments);
        self.crypt_address.write(out);
        out.push(self.tx_outs_attr);
        out.push(u8::from(self.shuffle));
        out.push(self.flags);
        out.extend_from_slice(&self.multisig_id);
        write_vec(out, &self.sources);
        push_varint(out, self.selected_transfers.len() as u64);
        for index in &self.selected_transfers {
            push_varint(out, *index);
        }
        write_vec(out, &self.prepared_destinations);
        out.extend_from_slice(&self.expiration_time.to_le_bytes());
        out.extend_from_slice(&self.spend_pub_key);
        out.extend_from_slice(&self.tx_version.to_le_bytes());
        out.extend_from_slice(&self.tx_hardfork_id.to_le_bytes());
        out.extend_from_slice(&self.mode_separate_fee.to_le_bytes());
    }
}

/// Decrypts a wallet blob, or encrypts one.
fn crypt(blob: &[u8], view_secret_key: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut data = Zeroizing::new(blob.to_vec());
    chacha8_crypt(view_secret_key, &mut data);
    data
}

impl FinalizeTxParam {
    /// Parses the plain serialization, which must take the whole of `data`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        ser::from_bytes(data)
    }

    /// The plain serialization. It holds secrets (the blinding masks).
    pub fn to_bytes(&self) -> Vec<u8> {
        ser::to_bytes(self)
    }

    /// Decrypts and parses an unsigned transaction blob with the wallet's
    /// secret view key.
    ///
    /// A wrong key gives garbage, which fails to parse (most often with
    /// [`Error::UnexpectedEof`] or [`Error::UnsupportedVariant`]).
    pub fn decrypt(blob: &[u8], view_secret_key: &[u8; 32]) -> Result<Self, Error> {
        Self::from_bytes(&crypt(blob, view_secret_key))
    }

    /// Serializes and encrypts with the wallet's secret view key.
    pub fn encrypt(&self, view_secret_key: &[u8; 32]) -> Vec<u8> {
        let plain = Zeroizing::new(self.to_bytes());
        crypt(&plain, view_secret_key).to_vec()
    }
}

/// An output index with its key image (`finalized_tx::outs_key_images`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyImageIndex {
    /// The index of the output.
    pub out_index: u64,
    /// Its key image.
    pub image: [u8; 32],
}
wire_struct!(KeyImageIndex, min = 40, { out_index: u64, image: key });

/// A signed transaction with what the wallet that prepared it needs to
/// account for it (`finalized_tx`).
///
/// The one-time secret key is wiped when the value is dropped.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FinalizedTx {
    /// The transaction.
    pub tx: Transaction,
    /// The transaction id. The offline signer leaves it zero, as Zano does.
    pub tx_id: [u8; 32],
    /// The one-time secret key of the transaction.
    pub one_time_key: [u8; 32],
    /// The parameters the transaction was built from.
    pub ftp: FinalizeTxParam,
    /// For an HTLC transaction, its origin.
    pub htlc_origin: Vec<u8>,
    /// The key images of the change outputs.
    pub outs_key_images: Vec<KeyImageIndex>,
    /// The key derivation. The offline signer leaves it zero, as Zano does.
    pub derivation: [u8; 32],
    /// Whether the transaction was not prepared, for a legitimate reason.
    pub was_not_prepared: bool,
}
wire_struct!(FinalizedTx, min = 290, {
    tx: obj, tx_id: key, one_time_key: key, ftp: obj, htlc_origin: bytes,
    outs_key_images: vec, derivation: key, was_not_prepared: bool
});

impl Drop for FinalizedTx {
    fn drop(&mut self) {
        self.one_time_key.zeroize();
    }
}

impl FinalizedTx {
    /// Parses the plain serialization, which must take the whole of `data`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        ser::from_bytes(data)
    }

    /// The plain serialization. It holds secrets.
    pub fn to_bytes(&self) -> Vec<u8> {
        ser::to_bytes(self)
    }

    /// Decrypts and parses a signed transaction blob with the wallet's
    /// secret view key.
    pub fn decrypt(blob: &[u8], view_secret_key: &[u8; 32]) -> Result<Self, Error> {
        Self::from_bytes(&crypt(blob, view_secret_key))
    }

    /// Serializes and encrypts with the wallet's secret view key: the blob
    /// the view-only wallet broadcasts.
    pub fn encrypt(&self, view_secret_key: &[u8; 32]) -> Vec<u8> {
        let plain = Zeroizing::new(self.to_bytes());
        crypt(&plain, view_secret_key).to_vec()
    }
}

impl super::Wallet {
    /// Decrypts and parses an unsigned transaction blob made by this
    /// wallet's view-only counterpart ([`FinalizeTxParam::decrypt`]).
    pub fn parse_ftp(&self, blob: &[u8]) -> Result<FinalizeTxParam, Error> {
        FinalizeTxParam::decrypt(blob, self.view_secret_key())
    }

    /// Decrypts and parses a signed transaction blob
    /// ([`FinalizedTx::decrypt`]).
    pub fn parse_finalized(&self, blob: &[u8]) -> Result<FinalizedTx, Error> {
        FinalizedTx::decrypt(blob, self.view_secret_key())
    }
}
