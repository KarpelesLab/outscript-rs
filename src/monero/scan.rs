//! Recognising and opening the outputs of an account: view tags, subaddress
//! lookup, amounts, payment ids, one-time secret keys and key images.

use purecrypto::zeroize::Zeroizing;

use super::Error;
use super::keys::{AccountKeys, SubaddressIndex, ViewKeys, subaddress_secret_key};
use super::ringct::commit_point;
use crate::cryptonote::{
    EdwardsPoint, Hasher, MAX_VARINT_LEN, cn_fast_hash_parts, derivation_to_scalar,
    generate_key_derivation, generate_key_image, point_from_bytes, scalar_from_bytes,
    scalar_from_u64, write_varint,
};

#[cfg(feature = "alloc")]
use super::tx::Transaction;
#[cfg(feature = "alloc")]
use super::{extra, ringct::zero_commit};
#[cfg(feature = "alloc")]
use crate::prelude::*;

/// `derive_view_tag`: the first byte of
/// `cn_fast_hash("view_tag" || derivation || varint(output_index))`.
///
/// An output carries the tag so that a wallet can discard 255 outputs out of
/// 256 before doing any curve arithmetic on them.
pub fn derive_view_tag(derivation: &[u8; 32], output_index: u64) -> u8 {
    let mut index = [0u8; MAX_VARINT_LEN];
    let n = write_varint(output_index, &mut index).unwrap_or(0);
    let hash = Zeroizing::new(cn_fast_hash_parts(&[
        b"view_tag",
        derivation,
        index.get(..n).unwrap_or(&[]),
    ]));
    hash[0]
}

/// `derive_subaddress_public_key`: `output_key - Hs(derivation ||
/// varint(output_index)) * G`, the public spend key an output was sent to if
/// `derivation` is the right one — to be compared with the account's spend
/// key or looked up among its subaddresses.
///
/// Fails with [`Error::CryptoNote`] if `output_key` is not a curve point.
pub fn derive_subaddress_public_key(
    output_key: &[u8; 32],
    derivation: &[u8; 32],
    output_index: u64,
) -> Result<[u8; 32], Error> {
    let key = point_from_bytes(output_key)?;
    let scalar = Zeroizing::new(derivation_to_scalar(derivation, output_index));
    let scalar = scalar_from_bytes(&scalar)?;
    Ok(key.sub(&EdwardsPoint::mul_base(&scalar)).compress())
}

/// `genCommitmentMask`: the blinding factor
/// `Hs("commitment_mask" || shared_scalar)` of an output's commitment, with
/// `shared_scalar` the output's
/// [`derivation_to_scalar`].
pub fn commitment_mask(shared_scalar: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut h = Hasher::new();
    h.update(b"commitment_mask");
    h.update(shared_scalar);
    Zeroizing::new(h.finalize_scalar())
}

/// The 8 bytes an amount is XORed with: the start of
/// `cn_fast_hash("amount" || shared_scalar)`.
fn amount_key(shared_scalar: &[u8; 32]) -> Zeroizing<[u8; 8]> {
    let hash = Zeroizing::new(cn_fast_hash_parts(&[b"amount", shared_scalar]));
    let mut key = Zeroizing::new([0u8; 8]);
    for (k, h) in key.iter_mut().zip(hash.iter()) {
        *k = *h;
    }
    key
}

/// Encrypts an amount for the recipient of an output (`ecdhEncode`, the
/// 8-byte form): the little-endian amount XORed with the start of
/// `cn_fast_hash("amount" || shared_scalar)`.
pub fn encrypt_amount(shared_scalar: &[u8; 32], amount: u64) -> [u8; 8] {
    let key = amount_key(shared_scalar);
    let mut out = amount.to_le_bytes();
    for (o, k) in out.iter_mut().zip(key.iter()) {
        *o ^= *k;
    }
    out
}

/// Decrypts an amount encrypted by [`encrypt_amount`] (`ecdhDecode`).
pub fn decrypt_amount(shared_scalar: &[u8; 32], encrypted: &[u8; 8]) -> u64 {
    u64::from_le_bytes(encrypt_amount(
        shared_scalar,
        u64::from_le_bytes(*encrypted),
    ))
}

/// Encrypts or decrypts (the operation is its own inverse) the 8-byte payment
/// id of a transaction: XOR with the start of
/// `cn_fast_hash(derivation || 0x8d)`.
///
/// `derivation` is the key derivation between the transaction key and the
/// recipient's view key: [`generate_key_derivation`] of the recipient's
/// public view key and the transaction secret key for the sender, of the
/// transaction public key and the secret view key for the recipient.
pub fn encrypt_payment_id(derivation: &[u8; 32], payment_id: &[u8; 8]) -> [u8; 8] {
    let hash = Zeroizing::new(cn_fast_hash_parts(&[derivation, &[0x8d]]));
    let mut out = *payment_id;
    for (o, h) in out.iter_mut().zip(hash.iter()) {
        *o ^= *h;
    }
    out
}

/// The amount and commitment mask of an output, as its owner recovers them.
#[derive(Clone)]
pub struct OutputAmount {
    /// The amount, in atomic units.
    pub amount: u64,
    /// The blinding factor of the commitment.
    pub mask: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for OutputAmount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OutputAmount")
    }
}

/// Opens the amount of a RingCT output: decrypts `encrypted_amount`, derives
/// the mask, and checks them against the output's `commitment`.
///
/// `derivation` is the key derivation the output was recognised with. Fails
/// with [`Error::CommitmentMismatch`] if `mask * G + amount * H` is not the
/// commitment: the sender did not follow the protocol and the output cannot
/// be spent.
pub fn decode_amount(
    derivation: &[u8; 32],
    output_index: u64,
    encrypted_amount: &[u8; 8],
    commitment: &[u8; 32],
) -> Result<OutputAmount, Error> {
    let shared = Zeroizing::new(derivation_to_scalar(derivation, output_index));
    let amount = decrypt_amount(&shared, encrypted_amount);
    let mask = commitment_mask(&shared);
    let point = commit_point(&scalar_from_u64(amount), &scalar_from_bytes(&mask)?);
    if point.compress() != *commitment {
        return Err(Error::CommitmentMismatch);
    }
    Ok(OutputAmount { amount, mask })
}

impl ViewKeys {
    /// The key derivation `8 * view_secret * tx_public` between this account
    /// and a transaction public key (or one of the per-output keys).
    ///
    /// Fails with [`Error::CryptoNote`] if `tx_public` is not a curve point.
    pub fn key_derivation(&self, tx_public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
        Ok(Zeroizing::new(generate_key_derivation(
            tx_public,
            self.view_secret(),
        )?))
    }

    /// Whether the output `output_index` of a transaction belongs to this
    /// account, given the key `derivation` to try, and to which subaddress.
    ///
    /// With a `view_tag` (outputs made since the 2022 network upgrade carry
    /// one), an output whose tag does not match is discarded at the cost of
    /// one hash. Otherwise the spend key the output would have been sent to
    /// is computed ([`derive_subaddress_public_key`]); the main address is
    /// recognised directly, and `lookup` is asked about any other key: it
    /// returns the index of the subaddress with that public spend key
    /// ([`ViewKeys::subaddress_spend_public`]), typically from a table of the
    /// subaddresses the wallet has handed out. Pass `&mut |_| None` to watch
    /// the main address only.
    ///
    /// Fails with [`Error::CryptoNote`] if `output_key` is not a curve
    /// point.
    pub fn check_output(
        &self,
        derivation: &[u8; 32],
        output_index: u64,
        output_key: &[u8; 32],
        view_tag: Option<u8>,
        lookup: &mut dyn FnMut(&[u8; 32]) -> Option<SubaddressIndex>,
    ) -> Result<Option<SubaddressIndex>, Error> {
        if let Some(tag) = view_tag
            && derive_view_tag(derivation, output_index) != tag
        {
            return Ok(None);
        }
        let spend = derive_subaddress_public_key(output_key, derivation, output_index)?;
        if spend == *self.spend_public() {
            return Ok(Some(SubaddressIndex::MAIN));
        }
        Ok(lookup(&spend))
    }

    /// Decrypts the 8-byte payment id of a transaction with the public key
    /// `tx_public`.
    ///
    /// Fails with [`Error::CryptoNote`] if `tx_public` is not a curve point.
    pub fn decrypt_payment_id(
        &self,
        tx_public: &[u8; 32],
        encrypted: &[u8; 8],
    ) -> Result<[u8; 8], Error> {
        Ok(encrypt_payment_id(
            &*self.key_derivation(tx_public)?,
            encrypted,
        ))
    }
}

impl AccountKeys {
    /// The one-time secret key of an output this account owns:
    /// `Hs(derivation || varint(output_index)) + b`, plus the subaddress
    /// offset `m` for an output received on a subaddress.
    pub fn output_secret_key(
        &self,
        derivation: &[u8; 32],
        output_index: u64,
        subaddress: SubaddressIndex,
    ) -> Result<Zeroizing<[u8; 32]>, Error> {
        let shared = Zeroizing::new(derivation_to_scalar(derivation, output_index));
        let mut secret = scalar_from_bytes(&shared)?.add(&scalar_from_bytes(self.spend_secret())?);
        if !subaddress.is_main() {
            let m = subaddress_secret_key(self.view_secret(), subaddress);
            secret = secret.add(&scalar_from_bytes(&m)?);
        }
        Ok(Zeroizing::new(secret.to_bytes()))
    }

    /// The one-time secret key and the key image of the output with the
    /// public key `output_key`, which this account owns.
    ///
    /// Fails with [`Error::KeyMismatch`] if the secret key derived from
    /// `derivation`, `output_index` and `subaddress` is not that of
    /// `output_key` (the output is not this account's, or not on that
    /// subaddress).
    pub fn output_key_image(
        &self,
        derivation: &[u8; 32],
        output_index: u64,
        subaddress: SubaddressIndex,
        output_key: &[u8; 32],
    ) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), Error> {
        let secret = self.output_secret_key(derivation, output_index, subaddress)?;
        if EdwardsPoint::mul_base(&scalar_from_bytes(&secret)?).compress() != *output_key {
            return Err(Error::KeyMismatch);
        }
        let image = generate_key_image(output_key, &secret)?;
        Ok((secret, image))
    }
}

/// An output of a transaction that belongs to the scanning account.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct OwnedOutput {
    /// The index of the output in the transaction.
    pub index: usize,
    /// The subaddress it was received on (`(0, 0)` for the main address).
    pub subaddress: SubaddressIndex,
    /// The one-time public key of the output.
    pub key: [u8; 32],
    /// The amount, in atomic units.
    pub amount: u64,
    /// The blinding factor of the commitment (1 for an output whose amount
    /// is in the clear).
    pub mask: Zeroizing<[u8; 32]>,
    /// The commitment to the amount.
    pub commitment: [u8; 32],
    /// The key derivation the output was recognised with: what
    /// [`AccountKeys::output_key_image`] needs to spend it.
    pub derivation: Zeroizing<[u8; 32]>,
    /// The decrypted 8-byte payment id of the transaction, if it has one.
    /// Every transaction with two outputs carries one, usually zero.
    pub payment_id: Option<[u8; 8]>,
}

#[cfg(feature = "alloc")]
impl core::fmt::Debug for OwnedOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnedOutput")
            .field("index", &self.index)
            .field("subaddress", &self.subaddress)
            .field("key", &self.key)
            .field("amount", &self.amount)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "alloc")]
impl ViewKeys {
    /// Finds the outputs of `tx` that belong to this account, with their
    /// amounts.
    ///
    /// Each output is tried against the transaction public keys of the extra
    /// field and against its own additional key, if any, as in
    /// [`check_output`](Self::check_output); `lookup` is the subaddress
    /// table described there. An output whose encrypted amount does not open
    /// its commitment is skipped: it cannot be spent.
    ///
    /// Fails with [`Error::Unsupported`] for a transaction whose amounts
    /// this cannot read (the pre-2019 32-byte encrypted amounts).
    pub fn scan_transaction(
        &self,
        tx: &Transaction,
        lookup: &mut dyn FnMut(&[u8; 32]) -> Option<SubaddressIndex>,
    ) -> Result<Vec<OwnedOutput>, Error> {
        let extra_bytes = &tx.prefix.extra;
        let outputs = &tx.prefix.outputs;
        let mut owned = Vec::new();
        let mut payment_id = None;
        if let (Some(extra::PaymentId::Encrypted(id)), Some(tx_public)) = (
            extra::payment_id(extra_bytes),
            extra::tx_public_key(extra_bytes),
        ) && let Ok(id) = self.decrypt_payment_id(&tx_public, &id)
        {
            payment_id = Some(id);
        }

        for (index, output) in outputs.iter().enumerate() {
            let output_index = index as u64;
            let additional = extra::additional_public_key(extra_bytes, outputs.len(), index);
            let candidates = extra::tx_public_keys(extra_bytes).chain(additional);
            for tx_public in candidates {
                // A transaction key that is not a point matches nothing.
                let Ok(derivation) = self.key_derivation(&tx_public) else {
                    continue;
                };
                let Ok(Some(subaddress)) = self.check_output(
                    &derivation,
                    output_index,
                    &output.key,
                    output.view_tag,
                    lookup,
                ) else {
                    continue;
                };
                let (amount, mask, commitment) = if tx.prefix.version < 2 || tx.rct.rct_type == 0 {
                    // The amount is in the clear; a coinbase output of a
                    // version 2 transaction stands in rings with the
                    // commitment G + amount * H.
                    let mut one = [0u8; 32];
                    one[0] = 1;
                    (
                        output.amount,
                        Zeroizing::new(one),
                        zero_commit(output.amount),
                    )
                } else {
                    let (Some(commitment), Some(encrypted)) =
                        (tx.rct.out_pk.get(index), tx.rct.ecdh_info.get(index))
                    else {
                        return Err(Error::InvalidTransaction);
                    };
                    let encrypted = encrypted.compact().ok_or(Error::Unsupported)?;
                    match decode_amount(&derivation, output_index, &encrypted, commitment) {
                        Ok(opened) => (opened.amount, opened.mask, *commitment),
                        Err(_) => continue,
                    }
                };
                owned.push(OwnedOutput {
                    index,
                    subaddress,
                    key: output.key,
                    amount,
                    mask,
                    commitment,
                    derivation,
                    payment_id,
                });
                break;
            }
        }
        Ok(owned)
    }
}
