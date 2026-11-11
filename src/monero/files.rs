//! The files the reference wallet (`monero-wallet-cli`, `wallet2`) exchanges
//! between a view-only wallet and the offline wallet that holds the spend
//! key: exported outputs, signed key images, and unsigned and signed
//! transaction sets.
//!
//! All of them are a magic string followed by a payload encrypted with a key
//! derived from the secret view key ([`WalletCipher`]), so that both wallets
//! of an account can read them and nobody else.

use purecrypto::zeroize::{Zeroize, Zeroizing};

use super::address::{Address, Network};
use super::build::{TransactionBuilder, TransactionInput};
use super::clsag::RingMember;
use super::extra::{ExtraField, PaymentId, parse_extra};
use super::keys::{AccountKeys, SubaddressIndex};
use super::legacy_sig::check_ring_signature;
use super::slow_hash::cn_slow_hash;
use super::tx::{Reader, Transaction};
use super::{Error, random_secret};
use crate::cryptonote::{
    EdwardsPoint, Hasher, check_signature, cn_fast_hash, generate_key_derivation,
    generate_key_image, generate_signature, point_from_bytes, point_from_hash, push_varint,
    scalar_from_bytes, secret_key_to_public_key,
};
use crate::prelude::*;

/// The magic of a key image export (`export_key_images`).
pub const KEY_IMAGE_EXPORT_MAGIC: &[u8] = b"Monero key image export\x03";
/// The magic of an output export (`export_outputs`).
pub const OUTPUT_EXPORT_MAGIC: &[u8] = b"Monero output export\x04";
/// The magic of an unsigned transaction set (`unsigned_monero_tx`).
pub const UNSIGNED_TX_SET_MAGIC: &[u8] = b"Monero unsigned tx set\x05";
/// The magic of a signed transaction set (`signed_monero_tx`).
pub const SIGNED_TX_SET_MAGIC: &[u8] = b"Monero signed tx set\x05";

/// The magic of a multisig transaction set (`multisig_monero_tx`).
pub const MULTISIG_TX_SET_MAGIC: &[u8] = b"Monero multisig unsigned tx set\x01";
/// The magic of a multisig info export (`export_multisig_info`).
pub const MULTISIG_INFO_MAGIC: &[u8] = b"Monero multisig export\x01";

/// The size of the nonce in front of an encrypted payload.
const IV_LEN: usize = 8;
/// The size of the signature at its end.
const SIGNATURE_LEN: usize = 64;

/// ChaCha20 as Monero uses it (`crypto::chacha20`): Bernstein's original,
/// with a 64-bit nonce and a 64-bit block counter starting at zero. XORs the
/// key stream into `data`.
fn chacha20(key: &[u8; 32], iv: &[u8; IV_LEN], data: &mut [u8]) {
    let word = |bytes: &[u8]| {
        let mut le = [0u8; 4];
        le.copy_from_slice(bytes);
        u32::from_le_bytes(le)
    };
    let mut state = Zeroizing::new([0u32; 16]);
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (slot, bytes) in state[4..12].iter_mut().zip(key.as_chunks::<4>().0) {
        *slot = word(bytes);
    }
    state[14] = word(&iv[..4]);
    state[15] = word(&iv[4..]);
    let mut counter = 0u64;
    for chunk in data.chunks_mut(64) {
        state[12] = counter as u32;
        state[13] = (counter >> 32) as u32;
        counter = counter.wrapping_add(1);
        let mut x = Zeroizing::new(*state);
        for _ in 0..10 {
            let mut quarter = |a: usize, b: usize, c: usize, d: usize| {
                x[a] = x[a].wrapping_add(x[b]);
                x[d] = (x[d] ^ x[a]).rotate_left(16);
                x[c] = x[c].wrapping_add(x[d]);
                x[b] = (x[b] ^ x[c]).rotate_left(12);
                x[a] = x[a].wrapping_add(x[b]);
                x[d] = (x[d] ^ x[a]).rotate_left(8);
                x[c] = x[c].wrapping_add(x[d]);
                x[b] = (x[b] ^ x[c]).rotate_left(7);
            };
            quarter(0, 4, 8, 12);
            quarter(1, 5, 9, 13);
            quarter(2, 6, 10, 14);
            quarter(3, 7, 11, 15);
            quarter(0, 5, 10, 15);
            quarter(1, 6, 11, 12);
            quarter(2, 7, 8, 13);
            quarter(3, 4, 9, 14);
        }
        let mut stream = Zeroizing::new([0u8; 64]);
        for (i, bytes) in stream.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            *bytes = x[i].wrapping_add(state[i]).to_le_bytes();
        }
        for (byte, key) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= key;
        }
    }
}

/// The encryption the two wallets of an account — the view-only one and the
/// one with the spend key — share: `wallet2::encrypt_with_view_secret_key`.
///
/// The key is `cn_slow_hash` ([`cn_slow_hash`]) of the secret view key
/// (`crypto::generate_chacha_key`), the cipher ChaCha20 with a random 8-byte
/// nonce in front of the ciphertext, and the whole is signed with the view
/// key, the signature at the end.
///
/// Deriving the key takes one `cn_slow_hash` — 2 MiB and a fraction of a
/// second — so make one of these and keep it. The view key and the derived
/// key are wiped when it is dropped.
///
/// ```
/// use outscript::monero::{AccountKeys, WalletCipher};
/// # use outscript::cryptonote::cn_fast_hash;
/// # let mut state = [7u8; 32];
/// # let mut rng = |out: &mut [u8]| {
/// #     for chunk in out.chunks_mut(32) {
/// #         state = cn_fast_hash(&state);
/// #         chunk.copy_from_slice(&state[..chunk.len()]);
/// #     }
/// # };
///
/// let account = AccountKeys::from_seed(&[5u8; 32])?;
/// let cipher = WalletCipher::new(account.view_secret())?;
/// // `rng` fills its argument with cryptographically secure random bytes.
/// let sealed = cipher.encrypt(b"between the two wallets", &mut rng)?;
/// assert_eq!(&**cipher.decrypt(&sealed)?, b"between the two wallets");
/// # Ok::<(), outscript::monero::Error>(())
/// ```
#[derive(Clone)]
pub struct WalletCipher {
    key: Zeroizing<[u8; 32]>,
    view_secret: Zeroizing<[u8; 32]>,
    view_public: [u8; 32],
}

impl core::fmt::Debug for WalletCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WalletCipher")
            .field("view_public", &self.view_public)
            .finish_non_exhaustive()
    }
}

impl WalletCipher {
    /// The cipher of the account with the secret view key `view_secret`, as
    /// a wallet with the default settings derives it.
    ///
    /// Fails with [`Error::CryptoNote`] if `view_secret` is not a reduced
    /// scalar.
    pub fn new(view_secret: &[u8; 32]) -> Result<Self, Error> {
        Self::with_kdf_rounds(view_secret, 1)
    }

    /// The same for a wallet opened with `--kdf-rounds`: the hash is
    /// iterated `kdf_rounds` times (at least once).
    pub fn with_kdf_rounds(view_secret: &[u8; 32], kdf_rounds: u64) -> Result<Self, Error> {
        let view_public = secret_key_to_public_key(view_secret)?;
        let mut key = Zeroizing::new(cn_slow_hash(view_secret));
        for _ in 1..kdf_rounds {
            *key = cn_slow_hash(&*key);
        }
        Ok(WalletCipher {
            key,
            view_secret: Zeroizing::new(*view_secret),
            view_public,
        })
    }

    /// Encrypts and signs `plaintext`: the nonce, the ciphertext, the
    /// signature.
    ///
    /// `rng` fills its argument with cryptographically secure random bytes:
    /// the nonce and the nonce of the signature come from it, and neither may
    /// repeat. Fails with [`Error::BadRandomness`] if it yields only zeros.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Vec<u8>, Error> {
        let mut iv = [0u8; IV_LEN];
        rng(&mut iv);
        let mut out = Vec::with_capacity(IV_LEN + plaintext.len() + SIGNATURE_LEN);
        out.extend_from_slice(&iv);
        out.extend_from_slice(plaintext);
        if let Some(body) = out.get_mut(IV_LEN..) {
            chacha20(&self.key, &iv, body);
        }
        let hash = cn_fast_hash(&out);
        let nonce = random_secret(rng)?;
        let signature = generate_signature(&hash, &self.view_public, &self.view_secret, &nonce)?;
        out.extend_from_slice(&signature);
        Ok(out)
    }

    /// Checks the signature of `ciphertext` and decrypts it.
    ///
    /// Fails with [`Error::InvalidFile`] if it is too short to be one and
    /// [`Error::AuthenticationFailed`] if the signature is not that of this
    /// account's view key over this data (another account's file, or a
    /// damaged one).
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let signed_len = ciphertext
            .len()
            .checked_sub(SIGNATURE_LEN)
            .filter(|len| *len >= IV_LEN)
            .ok_or(Error::InvalidFile)?;
        let (signed, signature) = ciphertext.split_at(signed_len);
        let signature = <[u8; 64]>::try_from(signature).map_err(|_| Error::InvalidFile)?;
        if !check_signature(&cn_fast_hash(signed), &self.view_public, &signature) {
            return Err(Error::AuthenticationFailed);
        }
        let (iv, body) = signed.split_at(IV_LEN);
        let iv = <[u8; IV_LEN]>::try_from(iv).map_err(|_| Error::InvalidFile)?;
        let mut plaintext = Zeroizing::new(body.to_vec());
        chacha20(&self.key, &iv, &mut plaintext);
        Ok(plaintext)
    }

    /// Decrypts a file that starts with `magic`.
    pub(super) fn open(&self, magic: &[u8], file: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let ciphertext = file.strip_prefix(magic).ok_or(Error::InvalidFile)?;
        self.decrypt(ciphertext)
    }

    /// Makes a file that starts with `magic`.
    pub(super) fn seal(
        &self,
        magic: &[u8],
        plaintext: &[u8],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Vec<u8>, Error> {
        let mut out = magic.to_vec();
        out.extend_from_slice(&self.encrypt(plaintext, rng)?);
        Ok(out)
    }
}

/// A key image with the proof that it is the one of an output: what the
/// wallet with the spend key gives the view-only wallet, so that it can tell
/// which outputs are spent (`export_key_images`).
///
/// The proof is a ring signature with the output's one-time key as its only
/// ring member, over the key image itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedKeyImage {
    /// The key image.
    pub key_image: [u8; 32],
    /// The signature: the challenge, then the response.
    pub signature: [u8; 64],
}

impl SignedKeyImage {
    /// Computes and signs the key image of the output with the one-time
    /// public key `output_key` and secret key `output_secret`
    /// ([`AccountKeys::output_secret_key`]).
    ///
    /// `rng` fills its argument with cryptographically secure random bytes:
    /// the nonce of the signature comes from it, so it must never repeat or
    /// be predictable. Fails with [`Error::KeyMismatch`] if the secret key
    /// is not that of `output_key`, [`Error::CryptoNote`] if it is not a
    /// reduced scalar, and [`Error::BadRandomness`] if `rng` yields only
    /// zeros.
    ///
    /// ```
    /// use outscript::monero::SignedKeyImage;
    /// # use outscript::cryptonote::{cn_fast_hash, sc_reduce32, secret_key_to_public_key};
    /// # let mut state = [7u8; 32];
    /// # let mut rng = |out: &mut [u8]| {
    /// #     for chunk in out.chunks_mut(32) {
    /// #         state = cn_fast_hash(&state);
    /// #         chunk.copy_from_slice(&state[..chunk.len()]);
    /// #     }
    /// # };
    ///
    /// let output_secret = sc_reduce32(&[1u8; 32]);
    /// let output_key = secret_key_to_public_key(&output_secret)?;
    /// let signed = SignedKeyImage::sign(&output_key, &output_secret, &mut rng)?;
    /// assert!(signed.verify(&output_key));
    /// assert!(!signed.verify(&secret_key_to_public_key(&sc_reduce32(&[2u8; 32]))?));
    /// # Ok::<(), outscript::monero::Error>(())
    /// ```
    pub fn sign(
        output_key: &[u8; 32],
        output_secret: &[u8; 32],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Self, Error> {
        let x = scalar_from_bytes(output_secret)?;
        if EdwardsPoint::mul_base(&x).compress() != *output_key {
            return Err(Error::KeyMismatch);
        }
        let key_image = generate_key_image(output_key, output_secret)?;
        let k = super::random_scalar(rng)?;
        let a = EdwardsPoint::mul_base(&k).compress();
        let b = point_from_hash(output_key).mul(&k).compress();
        let mut h = Hasher::new();
        h.update(&key_image);
        h.update(&a);
        h.update(&b);
        let c = h.finalize_to_scalar();
        let r = k.sub(&c.mul(&x));
        let mut signature = [0u8; 64];
        let (sig_c, sig_r) = signature.split_at_mut(32);
        sig_c.copy_from_slice(&c.to_bytes());
        sig_r.copy_from_slice(&r.to_bytes());
        Ok(SignedKeyImage {
            key_image,
            signature,
        })
    }

    /// Whether this is the key image of the output with the one-time public
    /// key `output_key`, as `wallet2::import_key_images` checks: the key
    /// image is in the prime-order subgroup and the signature is valid.
    /// Variable-time: everything here is public.
    pub fn verify(&self, output_key: &[u8; 32]) -> bool {
        let Ok(image) = point_from_bytes(&self.key_image) else {
            return false;
        };
        image != EdwardsPoint::identity()
            && bool::from(image.is_torsion_free())
            && check_ring_signature(
                &self.key_image,
                &self.key_image,
                &[*output_key],
                &[self.signature],
            )
    }
}

/// The key images of an account's outputs, as `export_key_images` writes
/// them and `import_key_images` reads them.
///
/// ```
/// use outscript::monero::{AccountKeys, KeyImageExport, SignedKeyImage, WalletCipher};
/// # use outscript::cryptonote::{cn_fast_hash, sc_reduce32, secret_key_to_public_key};
/// # let mut state = [7u8; 32];
/// # let mut rng = |out: &mut [u8]| {
/// #     for chunk in out.chunks_mut(32) {
/// #         state = cn_fast_hash(&state);
/// #         chunk.copy_from_slice(&state[..chunk.len()]);
/// #     }
/// # };
///
/// let account = AccountKeys::from_seed(&[5u8; 32])?;
/// let cipher = WalletCipher::new(account.view_secret())?;
/// # let output_secret = sc_reduce32(&[1u8; 32]);
/// # let output_key = secret_key_to_public_key(&output_secret)?;
/// // One entry per output of the wallet, in the wallet's order.
/// let export = KeyImageExport {
///     offset: 0,
///     spend_public: *account.spend_public(),
///     view_public: account.view_public(),
///     key_images: vec![SignedKeyImage::sign(&output_key, &output_secret, &mut rng)?],
/// };
/// let file = export.to_file(&cipher, &mut rng)?;
/// assert_eq!(KeyImageExport::from_file(&cipher, &file)?, export);
/// # Ok::<(), outscript::monero::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyImageExport {
    /// The position, among the outputs of the wallet, of the output the
    /// first key image is for.
    pub offset: u32,
    /// The public spend key of the account.
    pub spend_public: [u8; 32],
    /// The public view key of the account.
    pub view_public: [u8; 32],
    /// The key images, one per output from `offset` on.
    pub key_images: Vec<SignedKeyImage>,
}

impl KeyImageExport {
    /// Reads a key image file.
    ///
    /// Fails with [`Error::InvalidFile`] if it is not one,
    /// [`Error::AuthenticationFailed`] if it was not made with this view
    /// key. The signatures of the key images are not checked here: that
    /// takes the outputs ([`SignedKeyImage::verify`]).
    pub fn from_file(cipher: &WalletCipher, file: &[u8]) -> Result<Self, Error> {
        let data = cipher.open(KEY_IMAGE_EXPORT_MAGIC, file)?;
        let mut r = Reader { data: &data };
        let offset = u32::from_le_bytes(r.array().map_err(|_| Error::InvalidFile)?);
        let spend_public = r.key().map_err(|_| Error::InvalidFile)?;
        let view_public = r.key().map_err(|_| Error::InvalidFile)?;
        let (records, rest) = r.data.as_chunks::<96>();
        if !rest.is_empty() {
            return Err(Error::InvalidFile);
        }
        let mut key_images = Vec::with_capacity(records.len());
        for record in records {
            let (key_image, signature) = record.split_at(32);
            key_images.push(SignedKeyImage {
                key_image: <[u8; 32]>::try_from(key_image).map_err(|_| Error::InvalidFile)?,
                signature: <[u8; 64]>::try_from(signature).map_err(|_| Error::InvalidFile)?,
            });
        }
        Ok(KeyImageExport {
            offset,
            spend_public,
            view_public,
            key_images,
        })
    }

    /// Writes the key image file. `rng` is as for
    /// [`WalletCipher::encrypt`].
    pub fn to_file(
        &self,
        cipher: &WalletCipher,
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Vec<u8>, Error> {
        let mut data = Vec::with_capacity(68 + 96 * self.key_images.len());
        data.extend_from_slice(&self.offset.to_le_bytes());
        data.extend_from_slice(&self.spend_public);
        data.extend_from_slice(&self.view_public);
        for entry in &self.key_images {
            data.extend_from_slice(&entry.key_image);
            data.extend_from_slice(&entry.signature);
        }
        cipher.seal(KEY_IMAGE_EXPORT_MAGIC, &data, rng)
    }
}

// --- the binary archive ---

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

pub(super) fn put_keys(out: &mut Vec<u8>, keys: &[[u8; 32]]) {
    push_varint(out, keys.len() as u64);
    for key in keys {
        out.extend_from_slice(key);
    }
}

impl Reader<'_> {
    fn u64_le(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn u32_le(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn flag(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidFile),
        }
    }

    fn varint_u32(&mut self) -> Result<u32, Error> {
        u32::try_from(self.varint()?).map_err(|_| Error::InvalidFile)
    }

    /// A string or a vector of bytes.
    fn blob(&mut self) -> Result<Vec<u8>, Error> {
        let len = self.count(1)?;
        Ok(self.bytes(len)?.to_vec())
    }

    /// The count in front of a pair or a tuple, which must be `expected`.
    fn arity(&mut self, expected: u64) -> Result<(), Error> {
        if self.varint()? != expected {
            return Err(Error::InvalidFile);
        }
        Ok(())
    }
}

/// An output of the wallet as the view-only wallet describes it to the
/// offline one (`exported_transfer_details`): what it takes to compute the
/// key image and to spend it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedOutput {
    /// The one-time public key of the output.
    pub public_key: [u8; 32],
    /// The index of the output in its transaction.
    pub internal_output_index: u64,
    /// Its global index (among RingCT outputs, or among the outputs of its
    /// amount).
    pub global_output_index: u64,
    /// The public key of its transaction.
    pub tx_public_key: [u8; 32],
    /// The flags: see the `FLAG_` constants.
    pub flags: u8,
    /// The amount, in atomic units.
    pub amount: u64,
    /// The additional public keys of its transaction, if any.
    pub additional_tx_keys: Vec<[u8; 32]>,
    /// The subaddress it was received on.
    pub subaddress: SubaddressIndex,
}

impl ExportedOutput {
    /// The output is spent.
    pub const FLAG_SPENT: u8 = 1;
    /// The output is frozen.
    pub const FLAG_FROZEN: u8 = 1 << 1;
    /// The output is a RingCT one.
    pub const FLAG_RCT: u8 = 1 << 2;
    /// The exporting wallet knows its key image.
    pub const FLAG_KEY_IMAGE_KNOWN: u8 = 1 << 3;
    /// The exporting wallet asks for its key image.
    pub const FLAG_KEY_IMAGE_REQUEST: u8 = 1 << 4;
    /// The key image the exporting wallet has is a partial one (multisig).
    pub const FLAG_KEY_IMAGE_PARTIAL: u8 = 1 << 5;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        if r.varint()? != 1 {
            return Err(Error::Unsupported);
        }
        Ok(ExportedOutput {
            public_key: r.key()?,
            internal_output_index: r.varint()?,
            global_output_index: r.varint()?,
            tx_public_key: r.key()?,
            flags: r.u8()?,
            amount: r.varint()?,
            additional_tx_keys: r.key_vec()?,
            subaddress: SubaddressIndex::new(r.varint_u32()?, r.varint_u32()?),
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_varint(out, 1);
        out.extend_from_slice(&self.public_key);
        push_varint(out, self.internal_output_index);
        push_varint(out, self.global_output_index);
        out.extend_from_slice(&self.tx_public_key);
        out.push(self.flags);
        push_varint(out, self.amount);
        put_keys(out, &self.additional_tx_keys);
        push_varint(out, self.subaddress.major as u64);
        push_varint(out, self.subaddress.minor as u64);
    }

    /// The one-time secret key and the key image of the output, for the
    /// account that owns it.
    ///
    /// The description comes from the view-only wallet and is not trusted:
    /// the secret key derived from it is checked against the output's
    /// public key. Fails with [`Error::KeyMismatch`] if they do not match
    /// (the output is not this account's, or not as described) and
    /// [`Error::CryptoNote`] if a key is not a curve point.
    pub fn key_image(
        &self,
        account: &AccountKeys,
    ) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), Error> {
        output_secret(
            account,
            &self.public_key,
            &self.tx_public_key,
            &self.additional_tx_keys,
            self.internal_output_index,
            self.subaddress,
        )
    }

    /// The key image with its proof, for a key image export:
    /// [`key_image`](Self::key_image), then [`SignedKeyImage::sign`].
    pub fn signed_key_image(
        &self,
        account: &AccountKeys,
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<SignedKeyImage, Error> {
        let (secret, _) = self.key_image(account)?;
        SignedKeyImage::sign(&self.public_key, &secret, rng)
    }
}

/// The one-time secret key and key image of an output, trying the
/// transaction public key and then the output's additional key
/// (`generate_key_image_helper`).
pub(super) fn output_secret(
    account: &AccountKeys,
    output_key: &[u8; 32],
    tx_public_key: &[u8; 32],
    additional_tx_keys: &[[u8; 32]],
    output_index: u64,
    subaddress: SubaddressIndex,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), Error> {
    let additional = usize::try_from(output_index)
        .ok()
        .and_then(|index| additional_tx_keys.get(index));
    let mut result = Err(Error::KeyMismatch);
    for tx_key in core::iter::once(tx_public_key).chain(additional) {
        // A key that is not a point cannot be the one: try the next.
        let Ok(derivation) = generate_key_derivation(tx_key, account.view_secret()) else {
            continue;
        };
        let derivation = Zeroizing::new(derivation);
        result = account.output_key_image(&derivation, output_index, subaddress, output_key);
        if result.is_ok() {
            break;
        }
    }
    result
}

fn read_outputs(r: &mut Reader<'_>) -> Result<(u64, u64, Vec<ExportedOutput>), Error> {
    r.arity(3)?;
    let offset = r.varint()?;
    let total = r.varint()?;
    // An output takes at least 71 bytes.
    let count = r.count(71)?;
    let mut outputs = Vec::with_capacity(count);
    for _ in 0..count {
        outputs.push(ExportedOutput::read(r)?);
    }
    Ok((offset, total, outputs))
}

fn write_outputs(out: &mut Vec<u8>, offset: u64, total: u64, outputs: &[ExportedOutput]) {
    push_varint(out, 3);
    push_varint(out, offset);
    push_varint(out, total);
    push_varint(out, outputs.len() as u64);
    for output in outputs {
        output.write(out);
    }
}

/// Maps the errors of reading a payload that was authenticated: whatever is
/// wrong with it, it is not a file this crate reads.
pub(super) fn archive<T>(result: Result<T, Error>) -> Result<T, Error> {
    result.map_err(|e| match e {
        Error::Unsupported => Error::Unsupported,
        Error::InvalidMultisig => Error::InvalidMultisig,
        _ => Error::InvalidFile,
    })
}

/// The outputs of an account, as the view-only wallet exports them
/// (`export_outputs`) for the offline wallet to import (`import_outputs`).
///
/// ```
/// use outscript::monero::{AccountKeys, OutputExport, WalletCipher};
/// # use outscript::cryptonote::cn_fast_hash;
/// # let mut state = [7u8; 32];
/// # let mut rng = |out: &mut [u8]| {
/// #     for chunk in out.chunks_mut(32) {
/// #         state = cn_fast_hash(&state);
/// #         chunk.copy_from_slice(&state[..chunk.len()]);
/// #     }
/// # };
///
/// let account = AccountKeys::from_seed(&[5u8; 32])?;
/// let cipher = WalletCipher::new(account.view_secret())?;
/// let export = OutputExport {
///     spend_public: *account.spend_public(),
///     view_public: account.view_public(),
///     offset: 0,
///     total: 0,
///     outputs: Vec::new(),
/// };
/// let file = export.to_file(&cipher, &mut rng)?;
/// assert_eq!(OutputExport::from_file(&cipher, &file)?, export);
/// # Ok::<(), outscript::monero::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputExport {
    /// The public spend key of the account.
    pub spend_public: [u8; 32],
    /// The public view key of the account.
    pub view_public: [u8; 32],
    /// The position, among the outputs of the wallet, of the first output
    /// here.
    pub offset: u64,
    /// The number of outputs the wallet has.
    pub total: u64,
    /// The outputs, from `offset` on.
    pub outputs: Vec<ExportedOutput>,
}

impl OutputExport {
    /// Reads an output export — the file `export_outputs` writes, or the
    /// `outputs_data_hex` of the wallet RPC once decoded.
    ///
    /// Only the current layout (the one of the magic's version 4, with
    /// `exported_transfer_details`) is read. Fails with
    /// [`Error::InvalidFile`] if it is not one,
    /// [`Error::AuthenticationFailed`] if it was not made with this view
    /// key, and [`Error::Unsupported`] for an older layout.
    pub fn from_file(cipher: &WalletCipher, file: &[u8]) -> Result<Self, Error> {
        let data = cipher.open(OUTPUT_EXPORT_MAGIC, file)?;
        let mut r = Reader { data: &data };
        let spend_public = archive(r.key())?;
        let view_public = archive(r.key())?;
        let (offset, total, outputs) = archive(read_outputs(&mut r))?;
        if !r.data.is_empty() {
            return Err(Error::InvalidFile);
        }
        Ok(OutputExport {
            spend_public,
            view_public,
            offset,
            total,
            outputs,
        })
    }

    /// Writes the output export. `rng` is as for [`WalletCipher::encrypt`].
    pub fn to_file(
        &self,
        cipher: &WalletCipher,
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.spend_public);
        data.extend_from_slice(&self.view_public);
        write_outputs(&mut data, self.offset, self.total, &self.outputs);
        cipher.seal(OUTPUT_EXPORT_MAGIC, &data, rng)
    }

    /// The key image export that answers this output export: the key image
    /// of every output here, signed, for the view-only wallet to import.
    ///
    /// `rng` is as for [`SignedKeyImage::sign`]. Fails as
    /// [`ExportedOutput::key_image`] does, and with [`Error::InvalidFile`]
    /// if the offset does not fit the key image file.
    pub fn key_images(
        &self,
        account: &AccountKeys,
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<KeyImageExport, Error> {
        let mut key_images = Vec::with_capacity(self.outputs.len());
        for output in &self.outputs {
            key_images.push(output.signed_key_image(account, rng)?);
        }
        Ok(KeyImageExport {
            offset: u32::try_from(self.offset).map_err(|_| Error::InvalidFile)?,
            spend_public: *account.spend_public(),
            view_public: account.view_public(),
            key_images,
        })
    }
}

/// A destination of a transaction to sign (`tx_destination_entry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxDestination {
    /// The address as the user gave it, if the wallet kept it.
    pub original: String,
    /// The amount, in atomic units.
    pub amount: u64,
    /// The public spend key of the address.
    pub spend_public: [u8; 32],
    /// The public view key of the address.
    pub view_public: [u8; 32],
    /// Whether the address is a subaddress.
    pub is_subaddress: bool,
    /// Whether the address was an integrated one.
    pub is_integrated: bool,
}

impl TxDestination {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(TxDestination {
            original: String::from_utf8(r.blob()?).map_err(|_| Error::InvalidFile)?,
            amount: r.varint()?,
            spend_public: r.key()?,
            view_public: r.key()?,
            is_subaddress: r.flag()?,
            is_integrated: r.flag()?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        put_bytes(out, self.original.as_bytes());
        push_varint(out, self.amount);
        out.extend_from_slice(&self.spend_public);
        out.extend_from_slice(&self.view_public);
        out.push(self.is_subaddress as u8);
        out.push(self.is_integrated as u8);
    }

    fn read_vec(r: &mut Reader<'_>) -> Result<Vec<Self>, Error> {
        // A destination takes at least 68 bytes.
        let count = r.count(68)?;
        (0..count).map(|_| Self::read(r)).collect()
    }

    fn write_vec(out: &mut Vec<u8>, destinations: &[Self]) {
        push_varint(out, destinations.len() as u64);
        for destination in destinations {
            destination.write(out);
        }
    }

    /// The address, on `network`: a standard address or a subaddress (the
    /// payment id of an integrated address is in the extra field of the
    /// construction data, not here).
    pub fn address(&self, network: Network) -> Address {
        if self.is_subaddress {
            Address::subaddress(network, self.spend_public, self.view_public)
        } else {
            Address::standard(network, self.spend_public, self.view_public)
        }
    }

    pub(super) fn same_address(&self, other: &Self) -> bool {
        self.spend_public == other.spend_public && self.view_public == other.view_public
    }
}

/// An output to spend, with its ring, as the view-only wallet prepared it
/// (`tx_source_entry`).
#[derive(Clone, PartialEq, Eq)]
pub struct TxSource {
    /// The ring: the global index of each member, and the member.
    pub outputs: Vec<(u64, RingMember)>,
    /// The position of the output being spent in the ring.
    pub real_output: u64,
    /// The public key of the transaction that made it.
    pub real_out_tx_key: [u8; 32],
    /// The additional public keys of that transaction.
    pub real_out_additional_tx_keys: Vec<[u8; 32]>,
    /// The index of the output in that transaction.
    pub real_output_in_tx_index: u64,
    /// Its amount.
    pub amount: u64,
    /// Whether it is a RingCT output.
    pub rct: bool,
    /// The mask of its commitment (1 for an output that is not RingCT).
    pub mask: [u8; 32],
    /// The multisig data (`k`, `L`, `R` and the key image), all zero in a
    /// transaction that is not a multisig one.
    pub multisig_klrki: [u8; 128],
}

impl core::fmt::Debug for TxSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxSource")
            .field("outputs", &self.outputs)
            .field("real_output", &self.real_output)
            .field("amount", &self.amount)
            .finish_non_exhaustive()
    }
}

impl TxSource {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        // A ring member takes at least 66 bytes.
        let count = r.count(66)?;
        let mut outputs = Vec::with_capacity(count);
        for _ in 0..count {
            r.arity(2)?;
            let index = r.varint()?;
            outputs.push((
                index,
                RingMember {
                    key: r.key()?,
                    commitment: r.key()?,
                },
            ));
        }
        let source = TxSource {
            outputs,
            real_output: r.u64_le()?,
            real_out_tx_key: r.key()?,
            real_out_additional_tx_keys: r.key_vec()?,
            real_output_in_tx_index: r.u64_le()?,
            amount: r.u64_le()?,
            rct: r.flag()?,
            mask: r.key()?,
            multisig_klrki: r.array()?,
        };
        if source.real_output >= source.outputs.len() as u64 {
            return Err(Error::InvalidFile);
        }
        Ok(source)
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_varint(out, self.outputs.len() as u64);
        for (index, member) in &self.outputs {
            push_varint(out, 2);
            push_varint(out, *index);
            out.extend_from_slice(&member.key);
            out.extend_from_slice(&member.commitment);
        }
        put_u64(out, self.real_output);
        out.extend_from_slice(&self.real_out_tx_key);
        put_keys(out, &self.real_out_additional_tx_keys);
        put_u64(out, self.real_output_in_tx_index);
        put_u64(out, self.amount);
        out.push(self.rct as u8);
        out.extend_from_slice(&self.mask);
        out.extend_from_slice(&self.multisig_klrki);
    }

    /// The ring member being spent.
    pub(super) fn real(&self) -> Result<&RingMember, Error> {
        usize::try_from(self.real_output)
            .ok()
            .and_then(|index| self.outputs.get(index))
            .map(|(_, member)| member)
            .ok_or(Error::InvalidRing)
    }
}

/// What it takes to build one transaction (`tx_construction_data`): the
/// outputs to spend with their rings, and where the money goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxConstructionData {
    /// The outputs to spend.
    pub sources: Vec<TxSource>,
    /// The change: its address and amount.
    pub change: TxDestination,
    /// The outputs to make, the change among them.
    pub splitted_destinations: Vec<TxDestination>,
    /// The positions of the outputs to spend among the outputs of the
    /// wallet.
    pub selected_transfers: Vec<u64>,
    /// The extra field to start from: the payment id, not yet encrypted, if
    /// there is one.
    pub extra: Vec<u8>,
    /// The unlock time.
    pub unlock_time: u64,
    /// Whether to make a RingCT transaction.
    pub use_rct: bool,
    /// Whether the outputs get view tags.
    pub use_view_tags: bool,
    /// The kind of range proof (`rct::RangeProofType`; 3 is the padded
    /// Bulletproof all current transactions have).
    pub range_proof_type: u64,
    /// The version of the Bulletproofs (4 is Bulletproofs+ with CLSAG and
    /// view tags, RingCT type 6).
    pub bp_version: u64,
    /// The destinations as the user gave them, without the change.
    pub destinations: Vec<TxDestination>,
    /// The account (major subaddress index) the transaction spends from.
    pub subaddress_account: u32,
    /// The minor subaddress indices it spends from.
    pub subaddress_indices: Vec<u32>,
}

impl TxConstructionData {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        // A source takes at least 250 bytes.
        let count = r.count(250)?;
        let mut sources = Vec::with_capacity(count);
        for _ in 0..count {
            sources.push(TxSource::read(r)?);
        }
        let change = TxDestination::read(r)?;
        let splitted_destinations = TxDestination::read_vec(r)?;
        let count = r.count(1)?;
        let mut selected_transfers = Vec::with_capacity(count);
        for _ in 0..count {
            selected_transfers.push(r.varint()?);
        }
        let extra = r.blob()?;
        let unlock_time = r.u64_le()?;
        let flags = r.u8()?;
        if r.varint()? != 0 {
            return Err(Error::Unsupported);
        }
        let range_proof_type = r.varint()?;
        let bp_version = r.varint()?;
        let destinations = TxDestination::read_vec(r)?;
        let subaddress_account = r.u32_le()?;
        let count = r.count(1)?;
        let mut subaddress_indices = Vec::with_capacity(count);
        for _ in 0..count {
            subaddress_indices.push(r.varint_u32()?);
        }
        Ok(TxConstructionData {
            sources,
            change,
            splitted_destinations,
            selected_transfers,
            extra,
            unlock_time,
            use_rct: flags & 1 != 0,
            use_view_tags: flags & 2 != 0,
            range_proof_type,
            bp_version,
            destinations,
            subaddress_account,
            subaddress_indices,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_varint(out, self.sources.len() as u64);
        for source in &self.sources {
            source.write(out);
        }
        self.change.write(out);
        TxDestination::write_vec(out, &self.splitted_destinations);
        push_varint(out, self.selected_transfers.len() as u64);
        for index in &self.selected_transfers {
            push_varint(out, *index);
        }
        put_bytes(out, &self.extra);
        put_u64(out, self.unlock_time);
        out.push((self.use_rct as u8) | ((self.use_view_tags as u8) << 1));
        push_varint(out, 0);
        push_varint(out, self.range_proof_type);
        push_varint(out, self.bp_version);
        TxDestination::write_vec(out, &self.destinations);
        out.extend_from_slice(&self.subaddress_account.to_le_bytes());
        push_varint(out, self.subaddress_indices.len() as u64);
        for index in &self.subaddress_indices {
            push_varint(out, *index as u64);
        }
    }

    /// The fee the transaction pays: what the sources hold less what the
    /// outputs get. `None` if that does not add up.
    pub fn fee(&self) -> Option<u64> {
        let mut total = 0u64;
        for source in &self.sources {
            total = total.checked_add(source.amount)?;
        }
        for destination in &self.splitted_destinations {
            total = total.checked_sub(destination.amount)?;
        }
        Some(total)
    }

    /// The payment id in the extra field, which may hold nothing else that
    /// matters: the transaction public keys are replaced when signing.
    pub(super) fn payment_id(&self) -> Result<Option<[u8; 8]>, Error> {
        let mut found = None;
        for field in parse_extra(&self.extra) {
            match field.map_err(|_| Error::InvalidExtra)? {
                ExtraField::PublicKey(_) | ExtraField::AdditionalPublicKeys(_) => {}
                ExtraField::Nonce(nonce) => match PaymentId::from_nonce(nonce) {
                    Some(PaymentId::Encrypted(id)) if found.is_none() => found = Some(id),
                    _ => return Err(Error::Unsupported),
                },
                _ => return Err(Error::Unsupported),
            }
        }
        Ok(found)
    }
}

/// The transactions a view-only wallet prepared for the offline wallet to
/// sign (`unsigned_tx_set`, the file `unsigned_monero_tx`), with the outputs
/// the view-only wallet has no key image for yet.
///
/// What the offline side does with it — see [`sign`](Self::sign):
///
/// ```no_run
/// use outscript::monero::{AccountKeys, OutputExport, UnsignedTxSet, WalletCipher};
/// # fn files() -> (Vec<u8>, Vec<u8>) { unimplemented!() }
/// # let mut rng = |_: &mut [u8]| {};
///
/// let account = AccountKeys::from_seed(&[5u8; 32])?;
/// let cipher = WalletCipher::new(account.view_secret())?;
/// // From the view-only wallet: `export_outputs all` and `transfer`.
/// let (outputs_file, unsigned_file) = files();
/// let outputs = OutputExport::from_file(&cipher, &outputs_file)?;
/// let unsigned = UnsignedTxSet::from_file(&cipher, &unsigned_file)?;
/// // Show the user what is about to be signed.
/// for tx in &unsigned.transactions {
///     for destination in &tx.destinations {
///         println!("{} to {}", destination.amount, destination.original);
///     }
///     println!("fee {:?}", tx.fee());
/// }
/// let signed = unsigned.sign(&account, &outputs.outputs, &mut rng)?;
/// // For the view-only wallet to `submit_transfer`.
/// let signed_file = signed.to_file(&cipher, &mut rng)?;
/// # Ok::<(), outscript::monero::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedTxSet {
    /// The transactions to sign.
    pub transactions: Vec<TxConstructionData>,
    /// The position, among the outputs of the wallet, of the first of
    /// `outputs`.
    pub offset: u64,
    /// The number of outputs the wallet has.
    pub total: u64,
    /// The outputs the view-only wallet has no key image for, from `offset`
    /// on: none if it has them all.
    pub outputs: Vec<ExportedOutput>,
}

impl UnsignedTxSet {
    /// Reads an unsigned transaction set — the file `unsigned_monero_tx`,
    /// or the `unsigned_txset` of the wallet RPC once decoded.
    ///
    /// Only the current layout (version 2 of the set, in the files with the
    /// magic's version 5) is read. Fails with [`Error::InvalidFile`] if it
    /// is not one, [`Error::AuthenticationFailed`] if it was not made with
    /// this view key, and [`Error::Unsupported`] for an older layout.
    pub fn from_file(cipher: &WalletCipher, file: &[u8]) -> Result<Self, Error> {
        let data = cipher.open(UNSIGNED_TX_SET_MAGIC, file)?;
        let mut r = Reader { data: &data };
        archive(Self::read(&mut r))
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        if r.varint()? != 2 {
            return Err(Error::Unsupported);
        }
        let count = r.count(1)?;
        let mut transactions = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            transactions.push(TxConstructionData::read(r)?);
        }
        let (offset, total, outputs) = read_outputs(r)?;
        if !r.data.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(UnsignedTxSet {
            transactions,
            offset,
            total,
            outputs,
        })
    }

    /// Writes the unsigned transaction set. `rng` is as for
    /// [`WalletCipher::encrypt`].
    pub fn to_file(
        &self,
        cipher: &WalletCipher,
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();
        push_varint(&mut data, 2);
        push_varint(&mut data, self.transactions.len() as u64);
        for tx in &self.transactions {
            tx.write(&mut data);
        }
        write_outputs(&mut data, self.offset, self.total, &self.outputs);
        cipher.seal(UNSIGNED_TX_SET_MAGIC, &data, rng)
    }

    /// Signs the transactions, as `sign_transfer` of the reference wallet
    /// does, giving the set to hand back to the view-only wallet.
    ///
    /// `known_outputs` are the outputs of the wallet from the first one on,
    /// as a full output export lists them (`export_outputs all`,
    /// [`OutputExport`] with the offset 0): the set itself only describes
    /// the outputs the view-only wallet has no key image for, and the
    /// signed set must carry the key image of every output up to the last
    /// one spent. Those of the set take precedence where both describe an
    /// output. Nothing in either is trusted: every secret key derived from
    /// them is checked against the public key it is for.
    ///
    /// The transactions are built as [`TransactionBuilder`] builds them
    /// (version 2, RingCT type 6); a set asking for anything else is
    /// refused. **Signing spends the money**: check the destinations, the
    /// amounts and the fee of every transaction of the set first. What is
    /// enforced here is only that the change goes back to the account the
    /// transaction spends from.
    ///
    /// `rng` fills its argument with cryptographically secure random bytes;
    /// it is as critical as for [`TransactionBuilder::build`].
    ///
    /// Fails with:
    /// - [`Error::Unsupported`] for a set that asks for another transaction
    ///   format, a non-zero unlock time, or an extra field with anything but
    ///   an 8-byte payment id;
    /// - [`Error::MissingOutputs`] if an output to spend is described neither
    ///   in the set nor in `known_outputs`, or the two leave a gap;
    /// - [`Error::InvalidAddress`] if the change does not go to the first
    ///   address of the account the transaction spends from;
    /// - [`Error::KeyMismatch`] if an output is not this account's;
    /// - and as [`TransactionBuilder::build`] does.
    pub fn sign(
        &self,
        account: &AccountKeys,
        known_outputs: &[ExportedOutput],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<SignedTxSet, Error> {
        // The outputs of the wallet, from the first one on.
        let offset = usize::try_from(self.offset).map_err(|_| Error::MissingOutputs)?;
        let mut outputs: Vec<&ExportedOutput> = known_outputs.iter().take(offset).collect();
        if outputs.len() < offset {
            return Err(Error::MissingOutputs);
        }
        outputs.extend(self.outputs.iter());
        if let Some(rest) = known_outputs.get(outputs.len()..) {
            outputs.extend(rest.iter());
        }

        let mut transactions = Vec::with_capacity(self.transactions.len());
        let mut tx_key_images = Vec::new();
        let mut last_spent = 0usize;
        for data in &self.transactions {
            let (pending, owned) = sign_one(data, account, &outputs, rng)?;
            for index in &data.selected_transfers {
                let index = usize::try_from(*index).map_err(|_| Error::MissingOutputs)?;
                last_spent = last_spent.max(index.saturating_add(1));
            }
            tx_key_images.extend(owned);
            transactions.push(pending);
        }
        if outputs.len() < last_spent {
            return Err(Error::MissingOutputs);
        }
        let mut key_images = Vec::with_capacity(outputs.len());
        for output in &outputs {
            key_images.push(output.key_image(account)?.1);
        }
        Ok(SignedTxSet {
            transactions,
            key_images,
            tx_key_images,
        })
    }
}

/// The identity of the group, which stands for "no key" where the reference
/// wallet withholds one.
const NO_KEY: [u8; 32] = {
    let mut key = [0u8; 32];
    key[0] = 1;
    key
};

/// Signs one transaction of a set. Returns it with the key images of the
/// outputs it sends back to the account.
#[allow(clippy::type_complexity)]
fn sign_one(
    data: &TxConstructionData,
    account: &AccountKeys,
    outputs: &[&ExportedOutput],
    rng: &mut dyn FnMut(&mut [u8]),
) -> Result<(PendingTx, Vec<([u8; 32], [u8; 32])>), Error> {
    if data.unlock_time != 0
        || !data.use_rct
        || !data.use_view_tags
        || data.range_proof_type != 3
        || data.bp_version != 4
    {
        return Err(Error::Unsupported);
    }
    let fee = data.fee().ok_or(Error::InvalidAmounts)?;
    let payment_id = data.payment_id()?;

    // The change must come back to the account being spent from.
    let network = Network::Mainnet;
    let change_index = SubaddressIndex::new(data.subaddress_account, 0);
    let own = account.subaddress(network, change_index);
    let pays_change = data
        .splitted_destinations
        .iter()
        .any(|destination| destination.amount > 0 && destination.same_address(&data.change));
    if (data.change.amount > 0 || pays_change)
        && (data.change.spend_public != own.spend_public
            || data.change.view_public != own.view_public)
    {
        return Err(Error::InvalidAddress);
    }

    let mut builder = TransactionBuilder::new();
    // The sources with their key images, to put them in the order of the
    // inputs of the transaction afterwards.
    let mut sources = Vec::with_capacity(data.sources.len());
    for source in &data.sources {
        let real = source.real()?;
        let described = outputs
            .iter()
            .find(|output| output.public_key == real.key)
            .map(|output| output.subaddress);
        // An output nobody described can still be one of the main address.
        let subaddress = described.unwrap_or(SubaddressIndex::MAIN);
        let (secret_key, key_image) = output_secret(
            account,
            &real.key,
            &source.real_out_tx_key,
            &source.real_out_additional_tx_keys,
            source.real_output_in_tx_index,
            subaddress,
        )
        .map_err(|e| match (e, described) {
            (Error::KeyMismatch, None) => Error::MissingOutputs,
            (e, _) => e,
        })?;
        builder.input(TransactionInput {
            ring: source.outputs.iter().map(|(_, member)| *member).collect(),
            global_indices: source.outputs.iter().map(|(index, _)| *index).collect(),
            real_index: usize::try_from(source.real_output).map_err(|_| Error::InvalidRing)?,
            secret_key,
            amount: source.amount,
            mask: Zeroizing::new(source.mask),
        });
        sources.push((key_image, source.clone()));
    }
    for destination in &data.splitted_destinations {
        builder.destination(destination.address(network), destination.amount);
    }
    builder
        .change_among_destinations(data.change.address(network), account.view_secret())
        .fee(fee);
    if let Some(id) = payment_id {
        builder.payment_id(id);
    }
    let built = builder.build(rng)?;
    let tx = built.transaction;

    // The key images of the outputs that come back to the account.
    let view = account.view_keys();
    let change_spend = view.subaddress_spend_public(change_index);
    let mut lookup = |spend: &[u8; 32]| {
        if *spend == change_spend {
            return Some(change_index);
        }
        outputs
            .iter()
            .map(|output| output.subaddress)
            .find(|index| !index.is_main() && view.subaddress_spend_public(*index) == *spend)
    };
    let mut owned = Vec::new();
    for output in view.scan_transaction(&tx, &mut lookup)? {
        let (_, key_image) = account.output_key_image(
            &output.derivation,
            output.index as u64,
            output.subaddress,
            &output.key,
        )?;
        owned.push((output.key, key_image));
    }

    // As the reference wallet leaves them: the sources in the order of the
    // inputs, the destinations in the order of the outputs.
    sources.sort_by_key(|source| core::cmp::Reverse(source.0));
    let mut construction_data = data.clone();
    construction_data.sources = sources.into_iter().map(|(_, source)| source).collect();
    construction_data.splitted_destinations = built
        .output_order
        .iter()
        .filter_map(|index| data.splitted_destinations.get(*index).cloned())
        .collect();
    let mut key_images = String::new();
    for input in &tx.prefix.inputs {
        if let Some(key_image) = input.key_image() {
            key_images.push('<');
            key_images.push_str(&hex::encode(key_image));
            key_images.push_str("> ");
        }
    }
    Ok((
        PendingTx {
            transaction: tx,
            dust: 0,
            fee,
            dust_added_to_fee: false,
            change: data.change.clone(),
            selected_transfers: data.selected_transfers.clone(),
            key_images,
            tx_secret_key: built.tx_secret_key,
            additional_tx_secret_keys: built.additional_secret_keys,
            destinations: data.destinations.clone(),
            construction_data,
            multisig_signatures: Vec::new(),
            multisig_tx_key_entropy: [0u8; 32],
        },
        owned,
    ))
}

/// A signed transaction with what the wallet records about it
/// (`pending_tx`).
#[derive(Clone)]
pub struct PendingTx {
    /// The signed transaction.
    pub transaction: Transaction,
    /// The dust, which current transactions do not have.
    pub dust: u64,
    /// The fee.
    pub fee: u64,
    /// Whether the dust went to the fee.
    pub dust_added_to_fee: bool,
    /// The change.
    pub change: TxDestination,
    /// The positions of the outputs spent among the outputs of the wallet.
    pub selected_transfers: Vec<u64>,
    /// The key images of the inputs, as the reference wallet prints them:
    /// each in hexadecimal between angle brackets, followed by a space.
    pub key_images: String,
    /// The transaction secret key. [`SignedTxSet::to_file`] does not write
    /// it: like the reference wallet, it keeps it from the view-only wallet.
    pub tx_secret_key: Zeroizing<[u8; 32]>,
    /// The per-output secret keys, when the transaction has additional
    /// public keys. Not written either.
    pub additional_tx_secret_keys: Vec<Zeroizing<[u8; 32]>>,
    /// The destinations as the user gave them.
    pub destinations: Vec<TxDestination>,
    /// What the transaction was built from, the sources in the order of its
    /// inputs and the destinations in the order of its outputs.
    pub construction_data: TxConstructionData,
    /// The signing attempts of a multisig transaction, one per group of
    /// signers that can complete it; none otherwise.
    pub multisig_signatures: Vec<MultisigSignature>,
    /// The entropy of the transaction key of a multisig transaction; zero
    /// otherwise.
    pub multisig_tx_key_entropy: [u8; 32],
}

impl core::fmt::Debug for PendingTx {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingTx")
            .field("transaction", &self.transaction)
            .field("fee", &self.fee)
            .finish_non_exhaustive()
    }
}

impl PendingTx {
    pub(super) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        if r.varint()? != 1 {
            return Err(Error::Unsupported);
        }
        let transaction = Transaction::read(r)?;
        let dust = r.u64_le()?;
        let fee = r.u64_le()?;
        let dust_added_to_fee = r.flag()?;
        let change = TxDestination::read(r)?;
        let count = r.count(1)?;
        let mut selected_transfers = Vec::with_capacity(count);
        for _ in 0..count {
            selected_transfers.push(r.varint()?);
        }
        let key_images = String::from_utf8(r.blob()?).map_err(|_| Error::InvalidFile)?;
        let tx_secret_key = Zeroizing::new(r.key()?);
        let additional_tx_secret_keys = r.key_vec()?.into_iter().map(Zeroizing::new).collect();
        let destinations = TxDestination::read_vec(r)?;
        let construction_data = TxConstructionData::read(r)?;
        // A signing attempt takes at least 55 bytes.
        let count = r.count(55)?;
        let mut multisig_signatures = Vec::with_capacity(count);
        for _ in 0..count {
            multisig_signatures.push(MultisigSignature::read(r)?);
        }
        let multisig_tx_key_entropy = r.key()?;
        Ok(PendingTx {
            transaction,
            dust,
            fee,
            dust_added_to_fee,
            change,
            selected_transfers,
            key_images,
            tx_secret_key,
            additional_tx_secret_keys,
            destinations,
            construction_data,
            multisig_signatures,
            multisig_tx_key_entropy,
        })
    }

    /// Writes the transaction, without its secret keys unless
    /// `with_secrets`.
    pub(super) fn write(&self, out: &mut Vec<u8>, with_secrets: bool) {
        push_varint(out, 1);
        out.extend_from_slice(&self.transaction.serialize());
        put_u64(out, self.dust);
        put_u64(out, self.fee);
        out.push(self.dust_added_to_fee as u8);
        self.change.write(out);
        push_varint(out, self.selected_transfers.len() as u64);
        for index in &self.selected_transfers {
            push_varint(out, *index);
        }
        put_bytes(out, self.key_images.as_bytes());
        if with_secrets {
            out.extend_from_slice(&*self.tx_secret_key);
            push_varint(out, self.additional_tx_secret_keys.len() as u64);
            for key in &self.additional_tx_secret_keys {
                out.extend_from_slice(&**key);
            }
        } else {
            out.extend_from_slice(&NO_KEY);
            push_varint(out, 0);
        }
        TxDestination::write_vec(out, &self.destinations);
        self.construction_data.write(out);
        push_varint(out, self.multisig_signatures.len() as u64);
        for signature in &self.multisig_signatures {
            signature.write(out);
        }
        out.extend_from_slice(&self.multisig_tx_key_entropy);
    }
}

/// The signed transactions the offline wallet hands back
/// (`signed_tx_set`, the file `signed_monero_tx`), with the key images the
/// view-only wallet needs to follow what is spent.
#[derive(Debug, Clone)]
pub struct SignedTxSet {
    /// The signed transactions.
    pub transactions: Vec<PendingTx>,
    /// The key image of every output of the wallet, from the first one on.
    pub key_images: Vec<[u8; 32]>,
    /// For each output of the transactions that comes back to the account,
    /// its one-time public key and its key image.
    pub tx_key_images: Vec<([u8; 32], [u8; 32])>,
}

impl SignedTxSet {
    /// Reads a signed transaction set — the file `signed_monero_tx`, or the
    /// `signed_txset` of the wallet RPC once decoded.
    ///
    /// Fails as [`UnsignedTxSet::from_file`] does.
    pub fn from_file(cipher: &WalletCipher, file: &[u8]) -> Result<Self, Error> {
        let data = cipher.open(SIGNED_TX_SET_MAGIC, file)?;
        let mut r = Reader { data: &data };
        archive(Self::read(&mut r))
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        if r.varint()? != 0 {
            return Err(Error::Unsupported);
        }
        let count = r.count(1)?;
        let mut transactions = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            transactions.push(PendingTx::read(r)?);
        }
        let key_images = r.key_vec()?;
        let count = r.count(65)?;
        let mut tx_key_images = Vec::with_capacity(count);
        for _ in 0..count {
            r.arity(2)?;
            tx_key_images.push((r.key()?, r.key()?));
        }
        if !r.data.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(SignedTxSet {
            transactions,
            key_images,
            tx_key_images,
        })
    }

    /// Writes the signed transaction set for the view-only wallet
    /// (`submit_transfer`). As the reference wallet does, it leaves the
    /// transaction secret keys out: they stay in
    /// [`PendingTx::tx_secret_key`]. `rng` is as for
    /// [`WalletCipher::encrypt`].
    pub fn to_file(
        &self,
        cipher: &WalletCipher,
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Vec<u8>, Error> {
        let mut data = Zeroizing::new(Vec::new());
        push_varint(&mut data, 0);
        push_varint(&mut data, self.transactions.len() as u64);
        for tx in &self.transactions {
            tx.write(&mut data, false);
        }
        put_keys(&mut data, &self.key_images);
        push_varint(&mut data, self.tx_key_images.len() as u64);
        for (key, image) in &self.tx_key_images {
            push_varint(&mut data, 2);
            data.extend_from_slice(key);
            data.extend_from_slice(image);
        }
        let file = cipher.seal(SIGNED_TX_SET_MAGIC, &data, rng);
        data.zeroize();
        file
    }
}

/// One signing attempt of a multisig transaction (`multisig_sig`): the
/// aggregate nonces of a group of signers that can complete it, and the
/// responses as far as they have signed.
///
/// With more signers available than the threshold, the proposer does not
/// know who will sign, and makes one attempt per group, each leaving out
/// (`ignore`) the signers that are not of the group.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MultisigSignature {
    /// The signers that are not part of this attempt.
    pub ignore: Vec<[u8; 32]>,
    /// The public nonces (`L`) of the other signers this attempt uses: how
    /// each of them finds the secret nonces to sign with.
    pub used_l: Vec<[u8; 32]>,
    /// The public keys of the shares of the spend key signed with so far.
    pub signing_keys: Vec<[u8; 32]>,
    /// Left from the format of older versions: unused.
    pub legacy_c: Vec<[u8; 32]>,
    /// Left from the format of older versions: unused.
    pub legacy_mu_p: Vec<[u8; 32]>,
    /// For each input, the aggregate nonces on `G`, one per component.
    pub total_alpha_g: Vec<Vec<[u8; 32]>>,
    /// For each input, the aggregate nonces on the hash of the output key.
    pub total_alpha_h: Vec<Vec<[u8; 32]>>,
    /// For each input, the first challenge of its ring signature.
    pub c_0: Vec<[u8; 32]>,
    /// For each input, the response of the output being spent, as far as
    /// the signers have contributed.
    pub s: Vec<[u8; 32]>,
}

/// The size of an empty `rct::rctSig`, which a signing attempt carries
/// since older versions and no longer uses.
const EMPTY_RCT_SIG_LEN: usize = 44;

impl MultisigSignature {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        if r.varint()? != 1 {
            return Err(Error::Unsupported);
        }
        if r.bytes(EMPTY_RCT_SIG_LEN)?.iter().any(|byte| *byte != 0) {
            return Err(Error::Unsupported);
        }
        let ignore = r.key_vec()?;
        let used_l = r.key_vec()?;
        let signing_keys = r.key_vec()?;
        let legacy_c = r.key_vec()?;
        let legacy_mu_p = r.key_vec()?;
        let matrix = |r: &mut Reader<'_>| -> Result<Vec<Vec<[u8; 32]>>, Error> {
            let count = r.count(1)?;
            (0..count).map(|_| r.key_vec()).collect()
        };
        Ok(MultisigSignature {
            ignore,
            used_l,
            signing_keys,
            legacy_c,
            legacy_mu_p,
            total_alpha_g: matrix(r)?,
            total_alpha_h: matrix(r)?,
            c_0: r.key_vec()?,
            s: r.key_vec()?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_varint(out, 1);
        out.extend_from_slice(&[0u8; EMPTY_RCT_SIG_LEN]);
        put_keys(out, &self.ignore);
        put_keys(out, &self.used_l);
        put_keys(out, &self.signing_keys);
        put_keys(out, &self.legacy_c);
        put_keys(out, &self.legacy_mu_p);
        for matrix in [&self.total_alpha_g, &self.total_alpha_h] {
            push_varint(out, matrix.len() as u64);
            for row in matrix {
                put_keys(out, row);
            }
        }
        put_keys(out, &self.c_0);
        put_keys(out, &self.s);
    }
}

/// The transactions the participants of a multisig account sign in turn
/// (`multisig_tx_set`, the file `multisig_monero_tx`): each with the signing
/// attempts it can be completed by, and who has signed so far.
///
/// Once as many participants as the threshold have signed, the
/// transactions are complete and anyone can send them
/// (`submit_multisig`).
#[derive(Debug, Clone)]
pub struct MultisigTxSet {
    /// The transactions.
    pub transactions: Vec<PendingTx>,
    /// The participants that have signed, by the keys that identify them
    /// ([`MultisigAccount::signer_public`](super::MultisigAccount::signer_public)).
    pub signers: Vec<[u8; 32]>,
}

impl MultisigTxSet {
    /// Reads a multisig transaction set — the file `multisig_monero_tx`, or
    /// the `multisig_txset` or `tx_data_hex` of the wallet RPC once decoded.
    /// The cipher is that of the multisig account
    /// ([`MultisigAccount::cipher`](super::MultisigAccount::cipher)).
    ///
    /// Fails with [`Error::InvalidFile`] if it is not one,
    /// [`Error::AuthenticationFailed`] if it was not made with this view
    /// key, and [`Error::Unsupported`] for an older layout.
    pub fn from_file(cipher: &WalletCipher, file: &[u8]) -> Result<Self, Error> {
        let data = cipher.open(MULTISIG_TX_SET_MAGIC, file)?;
        let mut r = Reader { data: &data };
        archive(Self::read(&mut r))
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let count = r.count(1)?;
        let mut transactions = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            transactions.push(PendingTx::read(r)?);
        }
        let signers = r.key_vec()?;
        if !r.data.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(MultisigTxSet {
            transactions,
            signers,
        })
    }

    /// Writes the multisig transaction set, for the next participant to
    /// sign or for anyone to submit. Unlike a signed transaction set, it
    /// carries the transaction secret keys: every signer needs them to check
    /// what it signs. `rng` is as for [`WalletCipher::encrypt`].
    pub fn to_file(
        &self,
        cipher: &WalletCipher,
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Vec<u8>, Error> {
        let mut data = Zeroizing::new(Vec::new());
        push_varint(&mut data, self.transactions.len() as u64);
        for tx in &self.transactions {
            tx.write(&mut data, true);
        }
        put_keys(&mut data, &self.signers);
        let file = cipher.seal(MULTISIG_TX_SET_MAGIC, &data, rng);
        data.zeroize();
        file
    }
}
