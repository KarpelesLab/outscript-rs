//! What a transaction encrypts for its recipient: comments, the bodies of
//! the service attachments flagged for it and, before hard fork 6, the
//! payer and receiver entries (`encrypt_payload_items`,
//! `decrypt_payload_items`).
//!
//! Two schemes, by transaction version:
//!
//! - versions 2 and 3: ChaCha8 under the Keccak-256 hash of the key
//!   derivation `8 * r * V`, with a zero nonce, for every entry
//!   (`chacha_crypt_legacy`);
//! - version 4 (hard fork 6): ChaCha20 under a key and a nonce derived from
//!   the key derivation by a Keccak sponge
//!   ([`chacha20_generate_key_and_iv`]); the nonce counts the entries
//!   encrypted, the extra first and the attachments after.
//!
//! In both, a [`TxCryptoChecksum`] entry tells a recipient whether the
//! derivation is its own, and keeps the derivation for the sender,
//! encrypted under the secret spend key.

use purecrypto::zeroize::Zeroizing;

use crate::cryptonote::{EdwardsPoint, Scalar, cn_fast_hash};
use crate::prelude::*;

use super::chacha8::{chacha8_crypt, chacha20, chacha20_generate_key_and_iv};
use super::crypto;
use super::scan::{
    TX_SERVICE_ATTACHMENT_DEFLATE_BODY, TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF,
    TX_SERVICE_ATTACHMENT_ENCRYPT_BODY, TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE,
};
use super::ser::{Reader, Wire};
use super::sign::InputSigner;
use super::tx::{
    AccountPublicAddr, TRANSACTION_VERSION_POST_HF6, Transaction, TxCryptoChecksum,
    TxServiceAttachment, Variant,
};
use super::{Error, Wallet};

/// `CRYPTO_HDS_CHACHA_TX_PAYLOAD_ITEMS`.
const HDS_PAYLOAD_ITEMS: &[u8; 32] = b"ZANO_HDS_CHACHA_TX_PAYLOAD_ITEM\0";
/// `CRYPTO_HDS_CHACHA_TX_PI_ISOLATE_AUDITABLE`.
const HDS_ISOLATE_AUDITABLE: &[u8; 32] = b"ZANO_HDS_CHACHA_TX_PI_ISLT_AUDT\0";
/// `CRYPTO_HDS_CHACHA_TX_PAYLOAD_SENDER_DER`.
const HDS_SENDER_DERIVATION: &[u8; 32] = b"ZANO_HDS_CHACHA_TX_PI_SENDR_DER\0";

/// The check value of a key derivation: the first four bytes of its hash.
fn derivation_hash(derivation: &[u8; 32]) -> u32 {
    let hash = cn_fast_hash(derivation);
    u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]])
}

/// `8 * secret * public`, compressed (`generate_key_derivation`).
fn derivation(public: &EdwardsPoint, secret: &Scalar) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(public.mul(secret).mul_by_cofactor().compress())
}

/// Encrypts, or decrypts, the key derivation a version 4 transaction keeps
/// for its sender (`encrypt_decrypt_key_derivation_for_sender`): ChaCha20
/// under the key and nonce derived from `8 * spend_secret * tx_public`.
pub(crate) fn crypt_derivation_for_sender(
    spend_secret: &Scalar,
    tx_public: &EdwardsPoint,
    data: &mut [u8; 32],
) {
    let shared = derivation(tx_public, spend_secret);
    let (key, iv) = chacha20_generate_key_and_iv(HDS_SENDER_DERIVATION, &shared, 0);
    chacha20(&key, &iv.to_le_bytes(), data);
}

/// Encrypts, or decrypts, the key derivation of an auditable-isolated
/// attachment of a version 4 transaction for its sender: ChaCha20 under a
/// key derived from the secret spend key, with the nonce of the entry.
pub(crate) fn crypt_isolated_for_sender(spend_secret: &Scalar, nonce: u64, data: &mut [u8; 32]) {
    let secret = Zeroizing::new(spend_secret.to_bytes());
    let (key, _) = chacha20_generate_key_and_iv(HDS_ISOLATE_AUDITABLE, &secret, 0);
    chacha20(&key, &nonce.to_le_bytes(), data);
}

/// The proof of a version 2 or 3 attachment flagged
/// [`TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF`]: the hash of the plain body
/// followed by the hash of the derivation it is encrypted with.
fn legacy_proof(body: &[u8], derivation: &[u8; 32]) -> [u8; 32] {
    let mut salted = Zeroizing::new(body.to_vec());
    salted.extend_from_slice(&cn_fast_hash(derivation));
    cn_fast_hash(&salted)
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

/// What encrypting needs beside the entries.
struct Sender<'a> {
    /// `8 * r * V`, for the address the transaction encrypts for.
    derivation: &'a [u8; 32],
    tx_secret: &'a Scalar,
    crypt_address: &'a AccountPublicAddr,
    signer: &'a dyn InputSigner,
}

impl Sender<'_> {
    /// `8 * r * S`: the key of an auditable-isolated attachment, which the
    /// view key of the recipient does not give.
    fn isolated_derivation(&self) -> Result<Zeroizing<[u8; 32]>, Error> {
        if self.crypt_address.spend_key == [0u8; 32] {
            return Err(Error::Unsupported);
        }
        let spend = crypto::point(&self.crypt_address.spend_key)?;
        Ok(derivation(&spend, self.tx_secret))
    }
}

/// Encrypts in place what `encrypt_attach_visitor_legacy` encrypts of one
/// extra or attachment entry (transactions of version 2 and 3); whether it
/// did.
fn encrypt_legacy_item(item: &mut Variant, sender: &Sender<'_>) -> Result<bool, Error> {
    match item {
        Variant::Comment(comment) => chacha8_crypt(sender.derivation, comment),
        Variant::Payer(addr) | Variant::Receiver(addr) => crypt_wire(addr, sender.derivation)?,
        Variant::PayerOld(addr) | Variant::ReceiverOld(addr) => {
            crypt_wire(addr, sender.derivation)?;
        }
        Variant::ServiceAttachment(attachment) => {
            if attachment.flags & TX_SERVICE_ATTACHMENT_DEFLATE_BODY != 0 {
                // No deflate here.
                return Err(Error::Unsupported);
            }
            if attachment.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY == 0 {
                return Ok(false);
            }
            let mut local = Zeroizing::new(*sender.derivation);
            let mut for_sender = None;
            if attachment.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE != 0 {
                local = sender.isolated_derivation()?;
                let mut encrypted = *local;
                sender.signer.crypt_for_sender(&mut encrypted)?;
                for_sender = Some(encrypted);
            }
            let proof = (attachment.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF != 0)
                .then(|| legacy_proof(&attachment.body, &local));
            chacha8_crypt(&local, &mut attachment.body);
            attachment.security.extend(for_sender);
            attachment.security.extend(proof);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// The cipher of the entries of a version 4 transaction: one key, and a
/// nonce that counts the entries.
struct Hf6Cipher {
    key: Zeroizing<[u8; 32]>,
    iv: u64,
}

impl Hf6Cipher {
    fn new(derivation: &[u8; 32]) -> Self {
        let (key, iv) = chacha20_generate_key_and_iv(HDS_PAYLOAD_ITEMS, derivation, 0);
        Hf6Cipher { key, iv }
    }

    /// Encrypts or decrypts one entry, and moves on to the next nonce.
    fn crypt(&mut self, data: &mut [u8]) {
        chacha20(&self.key, &self.iv.to_le_bytes(), data);
        self.next();
    }

    fn next(&mut self) {
        self.iv = self.iv.wrapping_add(1);
    }
}

/// Encrypts or decrypts the body of an auditable-isolated attachment of a
/// version 4 transaction, under its own derivation and the nonce of the
/// entry.
fn crypt_isolated_body(derivation: &[u8; 32], nonce: u64, data: &mut [u8]) {
    let (key, _) = chacha20_generate_key_and_iv(HDS_ISOLATE_AUDITABLE, derivation, 0);
    chacha20(&key, &nonce.to_le_bytes(), data);
}

/// Encrypts in place what `encrypt_payload_items_visitor` encrypts of one
/// extra or attachment entry (transactions of version 4); whether it did.
fn encrypt_hf6_item(
    item: &mut Variant,
    cipher: &mut Hf6Cipher,
    sender: &Sender<'_>,
) -> Result<bool, Error> {
    match item {
        Variant::Comment(comment) => cipher.crypt(comment),
        Variant::ServiceAttachment(attachment) => {
            if attachment.flags & TX_SERVICE_ATTACHMENT_DEFLATE_BODY != 0 {
                // No deflate here.
                return Err(Error::Unsupported);
            }
            if attachment.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY == 0 {
                return Ok(false);
            }
            if attachment.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE != 0 {
                let local = sender.isolated_derivation()?;
                crypt_isolated_body(&local, cipher.iv, &mut attachment.body);
                let mut encrypted = *local;
                sender
                    .signer
                    .crypt_isolated_for_sender(cipher.iv, &mut encrypted)?;
                cipher.next();
                attachment.security.push(encrypted);
            } else {
                cipher.crypt(&mut attachment.body);
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Encrypts the entries of `tx` that are to be (`encrypt_payload_items`),
/// for `crypt_address` and with the transaction secret key, and adds the
/// [`TxCryptoChecksum`] if anything was encrypted. Returns the key
/// derivation `8 * r * V` (zero if the address has no usable view key).
pub(crate) fn encrypt_payload_items(
    tx: &mut Transaction,
    tx_secret: &Scalar,
    tx_public: &EdwardsPoint,
    crypt_address: &AccountPublicAddr,
    signer: &dyn InputSigner,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let shared = crypto::point(&crypt_address.view_key)
        .map(|view| derivation(&view, tx_secret))
        .unwrap_or_default();
    let sender = Sender {
        derivation: &shared,
        tx_secret,
        crypt_address,
        signer,
    };
    let hf6 = tx.version >= TRANSACTION_VERSION_POST_HF6;
    let mut in_extra = false;
    let mut in_attachments = false;
    if hf6 {
        // The order matters: the nonce counts across both containers.
        let mut cipher = Hf6Cipher::new(&shared);
        for item in &mut tx.extra {
            in_extra |= encrypt_hf6_item(item, &mut cipher, &sender)?;
        }
        for item in &mut tx.attachment {
            in_attachments |= encrypt_hf6_item(item, &mut cipher, &sender)?;
        }
    } else {
        for item in &mut tx.attachment {
            in_attachments |= encrypt_legacy_item(item, &sender)?;
        }
        for item in &mut tx.extra {
            in_extra |= encrypt_legacy_item(item, &sender)?;
        }
    }
    if in_extra || in_attachments {
        let mut encrypted_key_derivation = *shared;
        if hf6 {
            signer.crypt_derivation_for_sender(tx_public, &mut encrypted_key_derivation)?;
        } else {
            signer.crypt_for_sender(&mut encrypted_key_derivation)?;
        }
        let checksum = Variant::CryptoChecksum(TxCryptoChecksum {
            encrypted_key_derivation,
            derivation_hash: derivation_hash(&shared),
        });
        if in_extra {
            tx.extra.push(checksum);
        } else {
            tx.attachment.push(checksum);
        }
    }
    Ok(shared)
}

/// Who decrypts.
struct Receiver<'a> {
    derivation: &'a [u8; 32],
    income: bool,
    /// The secret spend key, if the wallet has it.
    spend_secret: Option<&'a Scalar>,
    tx_public: &'a EdwardsPoint,
}

/// The entry a version 2 or 3 transaction encrypted as `item`
/// (`decrypt_attach_visitor_legacy`), or `None` for one this wallet cannot
/// read.
fn decrypt_legacy_item(item: &Variant, receiver: &Receiver<'_>) -> Result<Option<Variant>, Error> {
    let mut item = item.clone();
    match &mut item {
        Variant::Comment(comment) => chacha8_crypt(receiver.derivation, comment),
        Variant::Payer(addr) | Variant::Receiver(addr) => crypt_wire(addr, receiver.derivation)?,
        Variant::PayerOld(addr) | Variant::ReceiverOld(addr) => {
            crypt_wire(addr, receiver.derivation)?;
        }
        Variant::ServiceAttachment(attachment) => {
            if attachment.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY == 0 {
                return Ok(Some(item));
            }
            let mut local = Zeroizing::new(*receiver.derivation);
            if attachment.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE != 0 {
                let Some(spend_secret) = receiver.spend_secret else {
                    return Ok(None);
                };
                if receiver.income {
                    local = derivation(receiver.tx_public, spend_secret);
                } else {
                    let Some(first) = attachment.security.first() else {
                        return Ok(None);
                    };
                    *local = *first;
                    let key = Zeroizing::new(spend_secret.to_bytes());
                    chacha8_crypt(&key, &mut local[..]);
                }
            }
            chacha8_crypt(&local, &mut attachment.body);
            // The proof is over the body before it was deflated, which is
            // not undone here.
            if attachment.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF != 0
                && attachment.flags & TX_SERVICE_ATTACHMENT_DEFLATE_BODY == 0
                && attachment.security.last() != Some(&legacy_proof(&attachment.body, &local))
            {
                return Ok(None);
            }
        }
        _ => {}
    }
    Ok(Some(item))
}

/// The entry a version 4 transaction encrypted as `item`
/// (`decrypt_payload_items_visitor`), or `None` for one this wallet cannot
/// read.
fn decrypt_hf6_item(
    item: &Variant,
    cipher: &mut Hf6Cipher,
    receiver: &Receiver<'_>,
) -> Option<Variant> {
    let mut item = item.clone();
    match &mut item {
        Variant::Comment(comment) => cipher.crypt(comment),
        Variant::ServiceAttachment(attachment)
            if attachment.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY != 0 =>
        {
            if attachment.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE == 0 {
                cipher.crypt(&mut attachment.body);
            } else {
                let nonce = cipher.iv;
                cipher.next();
                let spend_secret = receiver.spend_secret?;
                let local = if receiver.income {
                    derivation(receiver.tx_public, spend_secret)
                } else {
                    let mut local = Zeroizing::new(*attachment.security.first()?);
                    crypt_isolated_for_sender(spend_secret, nonce, &mut local);
                    local
                };
                crypt_isolated_body(&local, nonce, &mut attachment.body);
            }
        }
        _ => {}
    }
    Some(item)
}

/// The [`TxCryptoChecksum`] of a transaction: the first of its extra or,
/// failing that, of its attachments.
fn crypto_checksum(tx: &Transaction) -> Option<&TxCryptoChecksum> {
    let first = |items: &[Variant]| {
        items
            .iter()
            .position(|item| matches!(item, Variant::CryptoChecksum(_)))
    };
    let item = match first(&tx.extra) {
        Some(index) => tx.extra.get(index),
        None => first(&tx.attachment).and_then(|index| tx.attachment.get(index)),
    };
    match item {
        Some(Variant::CryptoChecksum(checksum)) => Some(checksum),
        _ => None,
    }
}

impl Wallet {
    /// The key derivation the encrypted entries of `tx` are encrypted with
    /// (`get_encryption_key_derivation`), or `None` if this wallet cannot
    /// tell it. The result is secret.
    ///
    /// For a transaction received (`income`), it is the wallet's own
    /// [`key_derivation`](Self::key_derivation), unless the
    /// [`TxCryptoChecksum`] of the transaction says the entries were
    /// encrypted for someone else. For a transaction sent, it is read from
    /// that entry with the secret spend key: `None` without the entry,
    /// without the key (a view-only wallet), or if the transaction is of
    /// another wallet.
    ///
    /// Fails with `InvalidPoint` if the transaction public key is not a
    /// point.
    pub fn payload_derivation(
        &self,
        tx: &Transaction,
        income: bool,
    ) -> Result<Option<Zeroizing<[u8; 32]>>, Error> {
        let Some(tx_pub_key) = tx.tx_pub_key() else {
            return Ok(None);
        };
        let checksum = crypto_checksum(tx);
        let shared = if income {
            self.key_derivation(&tx_pub_key)?
        } else {
            let (Some(checksum), Ok(spend_secret)) = (checksum, self.spend_scalar()) else {
                return Ok(None);
            };
            let mut shared = Zeroizing::new(checksum.encrypted_key_derivation);
            if tx.version >= TRANSACTION_VERSION_POST_HF6 {
                let tx_public = crypto::point(&tx_pub_key)?;
                crypt_derivation_for_sender(&spend_secret, &tx_public, &mut shared);
            } else {
                let key = Zeroizing::new(spend_secret.to_bytes());
                chacha8_crypt(&key, &mut shared[..]);
            }
            shared
        };
        if checksum.is_some_and(|c| c.derivation_hash != derivation_hash(&shared)) {
            return Ok(None);
        }
        Ok(Some(shared))
    }

    /// The extra entries of `tx`, then its attachments, with what was
    /// encrypted for this wallet decrypted (`decrypt_payload_items`):
    /// comments, the bodies of service attachments flagged
    /// [`TX_SERVICE_ATTACHMENT_ENCRYPT_BODY`] and, in transactions of
    /// version 2 and 3, payer and receiver entries.
    ///
    /// `income` tells a transaction received from one this wallet sent;
    /// see [`payload_derivation`](Self::payload_derivation). Without a
    /// derivation the entries come back as they are, still encrypted.
    ///
    /// An entry this wallet cannot read is left out: an attachment flagged
    /// [`TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE`] without the
    /// secret spend key and, in versions 2 and 3, one whose proof
    /// ([`TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF`]) does not match. A body
    /// flagged [`TX_SERVICE_ATTACHMENT_DEFLATE_BODY`] is decrypted but not
    /// inflated.
    ///
    /// The decryption is not authenticated: entries encrypted with another
    /// key, in a transaction without a [`TxCryptoChecksum`], decrypt to
    /// garbage.
    pub fn decrypt_payload_items(
        &self,
        tx: &Transaction,
        income: bool,
    ) -> Result<Vec<Variant>, Error> {
        let items = tx.extra.iter().chain(&tx.attachment);
        let (Some(shared), Some(tx_pub_key)) =
            (self.payload_derivation(tx, income)?, tx.tx_pub_key())
        else {
            return Ok(items.cloned().collect());
        };
        let spend_secret = self.spend_scalar().ok();
        let receiver = Receiver {
            derivation: &shared,
            income,
            spend_secret: spend_secret.as_ref(),
            tx_public: &crypto::point(&tx_pub_key)?,
        };
        let mut decrypted = Vec::with_capacity(tx.extra.len() + tx.attachment.len());
        if tx.version >= TRANSACTION_VERSION_POST_HF6 {
            let mut cipher = Hf6Cipher::new(&shared);
            for item in items {
                decrypted.extend(decrypt_hf6_item(item, &mut cipher, &receiver));
            }
        } else {
            for item in items {
                decrypted.extend(decrypt_legacy_item(item, &receiver)?);
            }
        }
        Ok(decrypted)
    }
}

/// The body of the payment id attachment among decrypted entries.
pub(crate) fn payment_id_attachment(items: &[Variant]) -> Option<&TxServiceAttachment> {
    items.iter().find_map(|item| match item {
        Variant::ServiceAttachment(a)
            if a.service_id == super::PAYMENT_ID_SERVICE_ID.as_bytes() =>
        {
            Some(a)
        }
        _ => None,
    })
}
