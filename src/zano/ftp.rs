//! The blobs a view-only `simplewallet` and an offline signer exchange: the
//! unsigned transaction (`finalize_tx_param`) and the signed one
//! (`finalized_tx`).
//!
//! Both are the binary serialization of the structure, encrypted with
//! ChaCha8 under a key derived from the secret view key. The format is not
//! versioned and follows the wallet's C++ structures, which changed twice
//! ([`FtpFormat`]).
//!
//! The three layouts are checked against Zano's own serialization of
//! those structures, and signing against its `construct_tx` and its
//! verifiers (`testdata/zano_harness.cpp`).

use purecrypto::zeroize::{Zeroize, Zeroizing};

use crate::cryptonote::push_varint;
use crate::prelude::*;

use super::Error;
use super::chacha8::chacha8_crypt;
use super::ser::{Reader, Wire, write_bytes, write_varints, write_vec};
use super::tx::{
    AccountPublicAddr, TX_FLAG_SIGNATURE_MODE_SEPARATE, Transaction, Variant, wire_struct,
};

/// Which release of Zano's wallet a blob is laid out for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FtpFormat {
    /// Zano 2.0 and 2.1.0.382 to 2.1.7.424: sources do not name their
    /// asset, and the signer leaves the transaction id, the derivation and
    /// the key images of the signed blob empty.
    Legacy,
    /// Zano 2.1.8.428 to 2.1.19.477 (hard fork 5): sources carry their
    /// asset id, and the signer fills the signed blob in.
    V2_1_8,
    /// Zano 2.2 (hard forks 6 and 7): sources also carry a gateway origin,
    /// destinations a payment id and tagged addresses.
    #[default]
    Current,
}

impl FtpFormat {
    /// The layouts, in the order parsing tries them: the largest first.
    const ALL: [FtpFormat; 3] = [FtpFormat::Current, FtpFormat::V2_1_8, FtpFormat::Legacy];
}

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
    /// The ring: the real output and its decoys.
    pub outputs: Vec<TxSourceOutputEntry>,
    /// The position of the real output in `outputs`.
    pub real_output: u64,
    /// The public key of the transaction that created the real output.
    pub real_out_tx_key: [u8; 32],
    /// The blinding mask of the real output's amount commitment (zero for a
    /// transparent output).
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
    /// The asset id of the real output, unblinded. A source parsed from a
    /// [`FtpFormat::Legacy`] blob, which does not carry it, has `None`, which stands for the asset of the first destination when
    /// signing, and for the native coin when working out the fee.
    pub asset_id: Option<[u8; 32]>,
    /// Whether the source is a confidential (Zarcanum) output. Not part of
    /// the blob: a parsed source counts as one when a blinding mask is not
    /// zero.
    pub is_zc_input: bool,
}

impl TxSource {
    /// Whether this source is a confidential output (`is_zc`: its amount
    /// blinding mask is not zero).
    pub fn is_zc(&self) -> bool {
        self.is_zc_input
            || self.real_out_amount_blinding_mask != [0u8; 32]
            || self.real_out_asset_id_blinding_mask != [0u8; 32]
    }

    /// Whether this source is a multisig output (`is_multisig`).
    pub fn is_multisig(&self) -> bool {
        self.ms_sigs_count > 0
    }

    fn read(r: &mut Reader<'_>, format: FtpFormat) -> Result<Self, Error> {
        let mut source = TxSource {
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
        };
        if format != FtpFormat::Legacy {
            source.asset_id = Some(r.key()?);
        }
        if format == FtpFormat::Current {
            // A source that spends from a gateway address (hard fork 6
            // only) cannot be signed here.
            if r.key()? != [0u8; 32] {
                return Err(Error::Unsupported);
            }
        }
        Ok(source)
    }

    fn write(&self, out: &mut Vec<u8>, format: FtpFormat) {
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
        if format != FtpFormat::Legacy {
            out.extend_from_slice(&self.asset_id.unwrap_or(super::NATIVE_COIN_ASSET_ID));
        }
        if format == FtpFormat::Current {
            out.extend_from_slice(&[0u8; 32]);
        }
    }
}

impl Drop for TxSource {
    fn drop(&mut self) {
        self.real_out_amount_blinding_mask.zeroize();
        self.real_out_asset_id_blinding_mask.zeroize();
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

/// `tdef_explicit_native_asset_id`: the output shows the native asset id
/// unblinded. Only for the native coin.
pub const TX_DEST_FLAG_EXPLICIT_NATIVE_ASSET_ID: u64 = 1;
/// `tdef_explicit_amount_to_provide`.
pub const TX_DEST_FLAG_EXPLICIT_AMOUNT_TO_PROVIDE: u64 = 2;
/// `tdef_zero_amount_blinding_mask`: the amount commitment is not blinded
/// (used to burn native coins; only acted on for an output to the null
/// address, which this module does not build).
pub const TX_DEST_FLAG_ZERO_AMOUNT_BLINDING_MASK: u64 = 4;

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
    /// The `tx_destination_entry_flags` (`TX_DEST_FLAG_*`).
    pub flags: u64,
    /// The payment id of the output (version 4 transactions; zero for
    /// none). Only in a [`FtpFormat::Current`] blob.
    pub payment_id: u64,
}

impl TxDest {
    fn read(r: &mut Reader<'_>, format: FtpFormat) -> Result<Self, Error> {
        let amount = r.u64()?;
        let addr = match format {
            FtpFormat::Legacy | FtpFormat::V2_1_8 => r.vec()?,
            FtpFormat::Current => {
                // address_v: a tagged account address, or a gateway address
                // (hard fork 6 only), which cannot be paid here.
                let n = r.count(AccountPublicAddr::MIN_SIZE + 1)?;
                let mut addr = Vec::with_capacity(n.min(16));
                for _ in 0..n {
                    match r.u8()? {
                        72 => addr.push(Wire::read(r)?),
                        22 => return Err(Error::Unsupported),
                        tag => return Err(Error::UnsupportedVariant(tag)),
                    }
                }
                addr
            }
        };
        Ok(TxDest {
            amount,
            addr,
            minimum_sigs: r.u64()?,
            amount_to_provide: r.u64()?,
            unlock_time: r.u64()?,
            htlc_options: Wire::read(r)?,
            asset_id: r.key()?,
            flags: r.u64()?,
            payment_id: match format {
                FtpFormat::Legacy | FtpFormat::V2_1_8 => 0,
                FtpFormat::Current => r.u64()?,
            },
        })
    }

    fn write(&self, out: &mut Vec<u8>, format: FtpFormat) {
        out.extend_from_slice(&self.amount.to_le_bytes());
        match format {
            FtpFormat::Legacy | FtpFormat::V2_1_8 => write_vec(out, &self.addr),
            FtpFormat::Current => {
                push_varint(out, self.addr.len() as u64);
                for addr in &self.addr {
                    out.push(72);
                    addr.write(out);
                }
            }
        }
        out.extend_from_slice(&self.minimum_sigs.to_le_bytes());
        out.extend_from_slice(&self.amount_to_provide.to_le_bytes());
        out.extend_from_slice(&self.unlock_time.to_le_bytes());
        self.htlc_options.write(out);
        out.extend_from_slice(&self.asset_id);
        out.extend_from_slice(&self.flags.to_le_bytes());
        if format == FtpFormat::Current {
            out.extend_from_slice(&self.payment_id.to_le_bytes());
        }
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
    /// The transaction flags (`TX_FLAG_*`).
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
    /// The hardfork id to put in a transaction of version 3 and above.
    pub tx_hardfork_id: u64,
    /// The fee of a separately signed transaction.
    pub mode_separate_fee: u64,
    /// The layout of the blob this was parsed from, and that
    /// [`to_bytes`](Self::to_bytes) writes.
    pub format: FtpFormat,
}

impl FinalizeTxParam {
    fn read(r: &mut Reader<'_>, format: FtpFormat) -> Result<Self, Error> {
        let unlock_time = r.u64()?;
        let extra = r.vec()?;
        let attachments = r.vec()?;
        let crypt_address = Wire::read(r)?;
        let tx_outs_attr = r.u8()?;
        let shuffle = r.bool()?;
        let flags = r.u8()?;
        let multisig_id = r.key()?;
        // The sizes are those of the legacy layout, the smaller ones.
        let n = r.count(211)?;
        let mut sources = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            sources.push(TxSource::read(r, format)?);
        }
        let selected_transfers = r.varints()?;
        let n = r.count(105)?;
        let mut prepared_destinations = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            prepared_destinations.push(TxDest::read(r, format)?);
        }
        let ftp = FinalizeTxParam {
            unlock_time,
            extra,
            attachments,
            crypt_address,
            tx_outs_attr,
            shuffle,
            flags,
            multisig_id,
            sources,
            selected_transfers,
            prepared_destinations,
            expiration_time: r.u64()?,
            spend_pub_key: r.key()?,
            tx_version: r.u64()?,
            tx_hardfork_id: r.u64()?,
            mode_separate_fee: r.u64()?,
            format,
        };
        // A separately signed transaction comes with the state of its
        // construction, which this module neither reads nor continues.
        if u64::from(ftp.flags) & TX_FLAG_SIGNATURE_MODE_SEPARATE != 0 {
            return Err(Error::Unsupported);
        }
        Ok(ftp)
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
        push_varint(out, self.sources.len() as u64);
        for source in &self.sources {
            source.write(out, self.format);
        }
        write_varints(out, &self.selected_transfers);
        push_varint(out, self.prepared_destinations.len() as u64);
        for dest in &self.prepared_destinations {
            dest.write(out, self.format);
        }
        out.extend_from_slice(&self.expiration_time.to_le_bytes());
        out.extend_from_slice(&self.spend_pub_key);
        out.extend_from_slice(&self.tx_version.to_le_bytes());
        out.extend_from_slice(&self.tx_hardfork_id.to_le_bytes());
        out.extend_from_slice(&self.mode_separate_fee.to_le_bytes());
    }
}

/// Parses `data` as a whole with `read`, in the first layout that fits:
/// the current one, then the older ones.
fn parse<T>(
    data: &[u8],
    read: impl Fn(&mut Reader<'_>, FtpFormat) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut first = None;
    let mut last = Error::UnexpectedEof;
    for format in FtpFormat::ALL {
        let mut r = Reader::new(data);
        match read(&mut r, format).and_then(|value| r.finish().map(|()| value)) {
            Ok(value) => return Ok(value),
            Err(error) => {
                first.get_or_insert(error);
                last = error;
            }
        }
    }
    // What this module cannot sign is reported as such, rather than as
    // whatever the other layouts make of the bytes.
    Err(match first {
        Some(Error::Unsupported) => Error::Unsupported,
        _ => last,
    })
}

/// Decrypts a wallet blob, or encrypts one.
fn crypt(blob: &[u8], view_secret_key: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut data = Zeroizing::new(blob.to_vec());
    chacha8_crypt(view_secret_key, &mut data);
    data
}

impl FinalizeTxParam {
    /// Parses the plain serialization, which must take the whole of `data`:
    /// in the current layout or, failing that, in the older ones
    /// ([`format`](Self::format) tells which).
    ///
    /// Fails with [`Error::Unsupported`] for a blob with a gateway source
    /// or destination, or of a separately signed transaction.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        parse(data, Self::read)
    }

    /// The plain serialization, in the layout of
    /// [`format`](Self::format). It holds secrets (the blinding masks).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
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
    /// The transaction id.
    pub tx_id: [u8; 32],
    /// The one-time secret key of the transaction.
    pub one_time_key: [u8; 32],
    /// The parameters the transaction was built from.
    pub ftp: FinalizeTxParam,
    /// For an HTLC transaction, its origin.
    pub htlc_origin: Vec<u8>,
    /// The key images of the outputs that come back to the wallet (change).
    pub outs_key_images: Vec<KeyImageIndex>,
    /// The key derivation attachments are encrypted with.
    pub derivation: [u8; 32],
    /// Whether the transaction was not prepared, for a legitimate reason.
    pub was_not_prepared: bool,
}

impl Drop for FinalizedTx {
    fn drop(&mut self) {
        self.one_time_key.zeroize();
    }
}

impl FinalizedTx {
    fn read(r: &mut Reader<'_>, format: FtpFormat) -> Result<Self, Error> {
        Ok(FinalizedTx {
            tx: Wire::read(r)?,
            tx_id: r.key()?,
            one_time_key: r.key()?,
            ftp: FinalizeTxParam::read(r, format)?,
            htlc_origin: r.bytes()?,
            outs_key_images: r.vec()?,
            derivation: r.key()?,
            was_not_prepared: r.bool()?,
        })
    }

    /// Parses the plain serialization, which must take the whole of `data`
    /// (in any layout, as [`FinalizeTxParam::from_bytes`]).
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        parse(data, Self::read)
    }

    /// The plain serialization, in the layout of its `ftp`. It holds
    /// secrets.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.tx.write(&mut out);
        out.extend_from_slice(&self.tx_id);
        out.extend_from_slice(&self.one_time_key);
        self.ftp.write(&mut out);
        write_bytes(&mut out, &self.htlc_origin);
        write_vec(&mut out, &self.outs_key_images);
        out.extend_from_slice(&self.derivation);
        out.push(u8::from(self.was_not_prepared));
        out
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
