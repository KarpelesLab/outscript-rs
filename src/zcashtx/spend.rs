//! Spending transparent outputs: P2PKH, P2PK, multisignature scripts (bare
//! or behind P2SH) and anything else through a caller-supplied scriptSig.
//!
//! Under ZIP 244 the signature digest of a transparent input commits to the
//! scriptPubKey of the output it spends, never to a redeem script (there is
//! no `scriptCode` in the digests of version 5 and 6 transactions): the
//! digest of a P2SH input is [`ZcashTx::sighash`] with the P2SH
//! scriptPubKey as the spent output, whatever the redeem script is. A
//! signature made for one script behind a P2SH output is therefore the same
//! for any other, and only the scriptSig differs.
//!
//! # Signatures made elsewhere
//!
//! A hardware wallet or a co-signer is given the digest of its input
//! ([`ZcashTx::sighash`]) and returns a DER signature, to which the sighash
//! type byte is appended ([`InputSignature::from_der`]). The signatures are
//! checked against their keys ([`ZcashTx::verify_input_signature`]) and
//! assembled into the scriptSig: [`p2pkh_script_sig_to_slice`],
//! [`p2pk_script_sig_to_slice`], or, for a multisignature,
//! [`ZcashTx::multisig_script_sig_to_slice`], which takes the signatures of
//! the co-signers in any order, drops those it has no use for, and writes
//! `OP_0 <signatures in the order of their keys> [<redeem script>]`.
//! [`ZcashTx::verify_input`] checks a finished scriptSig of these forms.

use super::{
    MAX_SCRIPT_SIG_LEN, SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE, ZcashTx,
    ZcashTxOut, put_varint,
};
use crate::Error;
use crate::btcvarint::BtcVarInt;
use crate::crypto::secp256k1::{DerSignature, SecpPrivateKey, SecpPublicKey};
use crate::hash::hash160;
#[cfg(feature = "alloc")]
use crate::prelude::*;
use crate::pushbytes::{parse_push_bytes, push_bytes_len, push_bytes_to_slice};
use crate::sink::{Sink, SliceSink};

/// The longest scriptSig consensus accepts, in bytes (`MAX_SCRIPT_SIZE`).
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// The longest redeem script a P2SH output can have, in bytes: the largest
/// item a script can push (`MAX_SCRIPT_ELEMENT_SIZE`).
pub const MAX_REDEEM_SCRIPT_SIZE: usize = 520;

/// The most keys a multisignature script handled here has: `OP_16` is the
/// largest count that is a single opcode. Behind P2SH, the limit of
/// [`MAX_REDEEM_SCRIPT_SIZE`] leaves room for fifteen compressed keys.
pub const MAX_MULTISIG_KEYS: usize = 16;

/// The longest signature of an input: a DER signature and its sighash byte.
pub const MAX_INPUT_SIGNATURE_LEN: usize = 73;

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKMULTISIG: u8 = 0xae;

/// Whether `hash_type` is one of the six sighash types of ZIP 244.
pub const fn is_valid_sighash_type(hash_type: u8) -> bool {
    matches!(
        hash_type & !SIGHASH_ANYONECANPAY,
        SIGHASH_ALL | SIGHASH_NONE | SIGHASH_SINGLE
    )
}

/// The signature of a transparent input as it goes in a scriptSig: a DER
/// ECDSA signature followed by its sighash type byte.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InputSignature {
    bytes: [u8; MAX_INPUT_SIGNATURE_LEN],
    len: u8,
}

impl core::fmt::Debug for InputSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("InputSignature")
            .field(&self.as_bytes())
            .finish()
    }
}

impl InputSignature {
    /// A DER signature (as a signer returns it, without sighash byte) made
    /// for the sighash type `hash_type`.
    ///
    /// The encoding must be strict DER, with `r` and `s` in range
    /// ([`Error::InvalidSignature`]), and the type one of the six of
    /// ZIP 244 ([`Error::UnsupportedSighash`]). `s` is not required to be
    /// low, as consensus does not require it, but nodes only relay
    /// transactions whose signatures have a low `s`
    /// ([`DerSignature::from_rs_low_s`] makes one from any `(r, s)`).
    pub fn from_der(der: &[u8], hash_type: u8) -> Result<Self, Error> {
        if !is_valid_sighash_type(hash_type) {
            return Err(Error::UnsupportedSighash);
        }
        let der = DerSignature::from_der(der).map_err(|_| Error::InvalidSignature)?;
        Ok(Self::new(&der, hash_type))
    }

    /// The signature as found in a scriptSig: DER followed by the sighash
    /// type byte. See [`from_der`](Self::from_der) for what is checked.
    pub fn from_bytes(signature: &[u8]) -> Result<Self, Error> {
        let (hash_type, der) = signature.split_last().ok_or(Error::InvalidSignature)?;
        Self::from_der(der, *hash_type)
    }

    fn new(der: &DerSignature, hash_type: u8) -> Self {
        let der = der.as_bytes();
        let mut bytes = [0u8; MAX_INPUT_SIGNATURE_LEN];
        bytes[..der.len()].copy_from_slice(der);
        bytes[der.len()] = hash_type;
        InputSignature {
            bytes,
            len: der.len() as u8 + 1,
        }
    }

    /// The signature and its sighash type byte, as pushed in a scriptSig.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The DER signature, without the sighash type byte.
    pub fn der(&self) -> &[u8] {
        &self.bytes[..self.len as usize - 1]
    }

    /// The sighash type the signature was made for.
    pub fn hash_type(&self) -> u8 {
        self.bytes[self.len as usize - 1]
    }
}

/// The scriptPubKey of a P2PKH output to the key hash `hash`.
pub const fn p2pkh_script(hash: &[u8; 20]) -> [u8; 25] {
    let mut script = [0u8; 25];
    script[0] = 0x76; // OP_DUP
    script[1] = 0xa9; // OP_HASH160
    script[2] = 0x14;
    let mut i = 0;
    while i < 20 {
        script[3 + i] = hash[i];
        i += 1;
    }
    script[23] = 0x88; // OP_EQUALVERIFY
    script[24] = OP_CHECKSIG;
    script
}

/// The scriptPubKey of a P2SH output to the script hash `hash`.
pub const fn p2sh_script(hash: &[u8; 20]) -> [u8; 23] {
    let mut script = [0u8; 23];
    script[0] = 0xa9; // OP_HASH160
    script[1] = 0x14;
    let mut i = 0;
    while i < 20 {
        script[2 + i] = hash[i];
        i += 1;
    }
    script[22] = 0x87; // OP_EQUAL
    script
}

/// The scriptPubKey of the P2SH output that `redeem_script` spends, or
/// [`Error::TooLarge`] for a script too long to ever be pushed
/// ([`MAX_REDEEM_SCRIPT_SIZE`]).
pub fn p2sh_script_of(redeem_script: &[u8]) -> Result<[u8; 23], Error> {
    if redeem_script.len() > MAX_REDEEM_SCRIPT_SIZE {
        return Err(Error::TooLarge);
    }
    Ok(p2sh_script(&hash160(redeem_script)))
}

/// What a scriptPubKey (or a redeem script) is, as far as this module can
/// spend it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptKind<'a> {
    /// Pay to the hash of a public key.
    P2pkh(&'a [u8; 20]),
    /// Pay to the hash of a redeem script.
    P2sh(&'a [u8; 20]),
    /// Pay to a public key, in its compressed or uncompressed encoding:
    /// `<key> OP_CHECKSIG`.
    P2pk(&'a [u8]),
    /// A multisignature script.
    Multisig(Multisig<'a>),
    /// Anything else.
    Other,
}

impl<'a> ScriptKind<'a> {
    /// Classifies `script`.
    pub fn of(script: &'a [u8]) -> Self {
        match script {
            [0x76, 0xa9, 0x14, hash @ .., 0x88, OP_CHECKSIG] if hash.len() == 20 => {
                ScriptKind::P2pkh(hash.try_into().expect("20 bytes"))
            }
            [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => {
                ScriptKind::P2sh(hash.try_into().expect("20 bytes"))
            }
            [33, key @ .., OP_CHECKSIG] if key.len() == 33 && is_key_encoding(key) => {
                ScriptKind::P2pk(key)
            }
            [65, key @ .., OP_CHECKSIG] if key.len() == 65 && is_key_encoding(key) => {
                ScriptKind::P2pk(key)
            }
            _ => match Multisig::parse(script) {
                Ok(multisig) => ScriptKind::Multisig(multisig),
                Err(_) => ScriptKind::Other,
            },
        }
    }
}

/// Whether `key` has the length and prefix of a SEC1 public key.
fn is_key_encoding(key: &[u8]) -> bool {
    matches!((key.len(), key.first()), (33, Some(2 | 3)) | (65, Some(4)))
}

/// A standard multisignature script, `OP_m <key 1> … <key n> OP_n
/// OP_CHECKMULTISIG`: a scriptPubKey (a *bare* multisignature) or, far more
/// often, the redeem script of a P2SH output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Multisig<'a> {
    required: u8,
    count: u8,
    /// The pushes of the keys.
    keys: &'a [u8],
}

impl<'a> Multisig<'a> {
    /// Parses a multisignature script: between 1 and
    /// [`MAX_MULTISIG_KEYS`] keys in their compressed or uncompressed
    /// encoding, of which at least one and at most all must sign.
    /// [`Error::UnsupportedScript`] for anything else.
    pub fn parse(script: &'a [u8]) -> Result<Self, Error> {
        let bad = Error::UnsupportedScript;
        let [m, keys @ .., n, OP_CHECKMULTISIG] = script else {
            return Err(bad);
        };
        let small = |op: u8| (OP_1..OP_1 + MAX_MULTISIG_KEYS as u8).contains(&op);
        if !small(*m) || !small(*n) {
            return Err(bad);
        }
        let (required, count) = (m - OP_1 + 1, n - OP_1 + 1);
        if required > count {
            return Err(bad);
        }
        let mut rest = keys;
        for _ in 0..count {
            let (&len, tail) = rest.split_first().ok_or(bad)?;
            let key = tail.get(..len as usize).ok_or(bad)?;
            if !is_key_encoding(key) {
                return Err(bad);
            }
            rest = &tail[len as usize..];
        }
        if !rest.is_empty() {
            return Err(bad);
        }
        Ok(Multisig {
            required,
            count,
            keys,
        })
    }

    /// The number of signatures the script requires.
    pub fn required(&self) -> usize {
        self.required as usize
    }

    /// The number of keys of the script.
    pub fn key_count(&self) -> usize {
        self.count as usize
    }

    /// The public keys, as encoded in the script, in its order (which is the
    /// order their signatures must have).
    pub fn keys(&self) -> impl ExactSizeIterator<Item = &'a [u8]> + Clone + 'a {
        let mut rest = self.keys;
        (0..self.count).map(move |_| {
            // the pushes were checked when parsing
            let len = rest[0] as usize;
            let key = &rest[1..1 + len];
            rest = &rest[1 + len..];
            key
        })
    }

    /// The length of the script of `keys`, if they have the lengths of
    /// public keys.
    #[cfg(feature = "alloc")]
    fn script_len(keys: &[&[u8]]) -> usize {
        3 + keys.iter().map(|key| 1 + key.len()).sum::<usize>()
    }

    /// Writes the script requiring `required` signatures of `keys` (SEC1
    /// public keys, compressed or not, in the order given) into `out`, and
    /// returns its length.
    ///
    /// [`Error::InvalidKey`] for a key that is not an encoding of a public
    /// key, [`Error::KeyCount`] unless `1 <= required <= keys.len() <=`
    /// [`MAX_MULTISIG_KEYS`]. A script meant as a redeem script must also
    /// fit [`MAX_REDEEM_SCRIPT_SIZE`], which [`p2sh_script_of`] checks.
    pub fn write_script(required: usize, keys: &[&[u8]], out: &mut [u8]) -> Result<usize, Error> {
        if required == 0 || required > keys.len() || keys.len() > MAX_MULTISIG_KEYS {
            return Err(Error::KeyCount);
        }
        if keys
            .iter()
            .any(|key| !is_key_encoding(key) || SecpPublicKey::from_sec1(key).is_err())
        {
            return Err(Error::InvalidKey);
        }
        let mut s = SliceSink::new(out);
        s.put(&[OP_1 + required as u8 - 1]);
        for key in keys {
            s.put(&[key.len() as u8]);
            s.put(key);
        }
        s.put(&[OP_1 + keys.len() as u8 - 1, OP_CHECKMULTISIG]);
        s.finish().ok_or(Error::BufferTooSmall)
    }

    /// The script requiring `required` signatures of `keys`: see
    /// [`write_script`](Self::write_script).
    #[cfg(feature = "alloc")]
    pub fn script(required: usize, keys: &[&[u8]]) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; Self::script_len(keys)];
        let n = Self::write_script(required, keys, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// The longest scriptSig spending this script: `OP_0`, the required
    /// signatures, and the script itself when it is a redeem script.
    pub fn script_sig_len_bound(&self, script_len: Option<usize>) -> usize {
        1 + self.required() * (1 + MAX_INPUT_SIGNATURE_LEN) + script_len.map_or(0, push_bytes_len)
    }
}

/// Writes the scriptSig of a P2PKH input, `<signature> <public key>`, into
/// `out` (at most [`MAX_SCRIPT_SIG_LEN`] bytes), and returns its length.
/// Nothing is verified: see [`ZcashTx::verify_input_signature`].
pub fn p2pkh_script_sig_to_slice(
    signature: &InputSignature,
    public_key: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if !is_key_encoding(public_key) {
        return Err(Error::InvalidKey);
    }
    let n = push_bytes_to_slice(signature.as_bytes(), out).ok_or(Error::BufferTooSmall)?;
    let m = push_bytes_to_slice(public_key, &mut out[n..]).ok_or(Error::BufferTooSmall)?;
    Ok(n + m)
}

/// Writes the scriptSig of a P2PK input, `<signature>`, into `out`, and
/// returns its length. Nothing is verified.
pub fn p2pk_script_sig_to_slice(
    signature: &InputSignature,
    out: &mut [u8],
) -> Result<usize, Error> {
    push_bytes_to_slice(signature.as_bytes(), out).ok_or(Error::BufferTooSmall)
}

/// Writes the scriptSig of a multisignature input into `out`, and returns
/// its length: `OP_0` (the item `OP_CHECKMULTISIG` pops and ignores), the
/// `signatures`, which must be in the order of their keys in the script,
/// and `redeem_script` when the output spent is a P2SH one. Nothing is
/// verified: [`ZcashTx::multisig_script_sig_to_slice`] orders and checks
/// the signatures.
pub fn multisig_script_sig_to_slice(
    signatures: &[InputSignature],
    redeem_script: Option<&[u8]>,
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut n = 1;
    *out.first_mut().ok_or(Error::BufferTooSmall)? = OP_0;
    for signature in signatures {
        n += push_bytes_to_slice(signature.as_bytes(), &mut out[n..])
            .ok_or(Error::BufferTooSmall)?;
    }
    if let Some(script) = redeem_script {
        if script.len() > MAX_REDEEM_SCRIPT_SIZE {
            return Err(Error::TooLarge);
        }
        n += push_bytes_to_slice(script, &mut out[n..]).ok_or(Error::BufferTooSmall)?;
    }
    Ok(n)
}

/// The data pushes of a scriptSig, which may hold nothing else.
struct Pushes<'a>(&'a [u8]);

impl<'a> Iterator for Pushes<'a> {
    type Item = Result<&'a [u8], Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let (&op, tail) = self.0.split_first()?;
        if op == OP_0 {
            self.0 = tail;
            return Some(Ok(&[]));
        }
        if op > 0x4e {
            self.0 = &[];
            return Some(Err(Error::UnsupportedScript));
        }
        match parse_push_bytes(self.0) {
            Some((data, used)) => {
                self.0 = &self.0[used..];
                Some(Ok(data))
            }
            None => {
                self.0 = &[];
                Some(Err(Error::InvalidScript))
            }
        }
    }
}

/// A function making the scriptSig of an input from its signature digest:
/// see [`InputSigner::Custom`].
pub type ScriptSigBuilder<'a> = dyn Fn(&[u8; 32], &mut [u8]) -> Result<usize, Error> + 'a;

/// How the scriptSig of a transparent input is made: see
/// [`ZcashTx::sign_with_to_slice`].
#[derive(Clone, Copy)]
pub enum InputSigner<'a> {
    /// With the private key of a P2PKH or P2PK output.
    Key(&'a SecpPrivateKey),
    /// With private keys of a multisignature script: the output itself (a
    /// bare multisignature, `redeem_script` being `None`), or the redeem
    /// script of a P2SH output. At least as many keys as the script
    /// requires must be given, in any order; the first that are keys of the
    /// script, in the order of the script, sign.
    Multisig {
        /// The redeem script of a P2SH output.
        redeem_script: Option<&'a [u8]>,
        /// The private keys.
        keys: &'a [&'a SecpPrivateKey],
    },
    /// With a finished scriptSig, made elsewhere: from signatures of the
    /// digest [`ZcashTx::sighash`] gives, assembled by the functions of this
    /// module or by the caller. A scriptSig of a form this module knows
    /// ([`ZcashTx::verify_input`]) is verified; any other is used as it is.
    ScriptSig(&'a [u8]),
    /// With a function that is given the signature digest of the input (for
    /// the sighash type of the [`InputSpend`]) and writes the scriptSig into
    /// the buffer it is handed, returning its length: for any script this
    /// module does not know. The buffer has at least `max_len` bytes, and
    /// the scriptSig is not verified.
    Custom {
        /// The most bytes the function writes.
        max_len: usize,
        /// The function.
        build: &'a ScriptSigBuilder<'a>,
    },
}

impl core::fmt::Debug for InputSigner<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            InputSigner::Key(_) => "Key",
            InputSigner::Multisig { .. } => "Multisig",
            InputSigner::ScriptSig(_) => "ScriptSig",
            InputSigner::Custom { .. } => "Custom",
        })
    }
}

/// How a transparent input is signed: by what, and for which sighash type.
#[derive(Debug, Clone, Copy)]
pub struct InputSpend<'a> {
    /// What makes the scriptSig.
    pub signer: InputSigner<'a>,
    /// The sighash type of the signatures made here: one of
    /// [`SIGHASH_ALL`], [`SIGHASH_NONE`] and [`SIGHASH_SINGLE`], alone or
    /// with [`SIGHASH_ANYONECANPAY`]. Not used with
    /// [`InputSigner::ScriptSig`], whose signatures state their own.
    pub hash_type: u8,
}

impl<'a> InputSpend<'a> {
    /// A spend signing everything ([`SIGHASH_ALL`]).
    pub const fn new(signer: InputSigner<'a>) -> Self {
        InputSpend {
            signer,
            hash_type: SIGHASH_ALL,
        }
    }

    /// The same spend for another sighash type.
    pub const fn with_hash_type(mut self, hash_type: u8) -> Self {
        self.hash_type = hash_type;
        self
    }

    /// The most bytes the scriptSig can take.
    pub fn script_sig_len_bound(&self) -> usize {
        match self.signer {
            InputSigner::Key(_) => MAX_SCRIPT_SIG_LEN,
            InputSigner::Multisig {
                redeem_script,
                keys,
            } => {
                1 + keys.len().min(MAX_MULTISIG_KEYS) * (1 + MAX_INPUT_SIGNATURE_LEN)
                    + redeem_script.map_or(0, |script| push_bytes_len(script.len()))
            }
            InputSigner::ScriptSig(script_sig) => script_sig.len(),
            InputSigner::Custom { max_len, .. } => max_len,
        }
    }
}

/// The digests of an input for the sighash types met so far.
struct Sighashes<'t, 'a, 'p> {
    tx: &'t ZcashTx<'a>,
    index: usize,
    prevouts: &'p [ZcashTxOut<'p>],
    known: [Option<[u8; 32]>; 6],
}

impl<'t, 'a, 'p> Sighashes<'t, 'a, 'p> {
    fn new(tx: &'t ZcashTx<'a>, index: usize, prevouts: &'p [ZcashTxOut<'p>]) -> Self {
        Sighashes {
            tx,
            index,
            prevouts,
            known: [None; 6],
        }
    }

    fn get(&mut self, hash_type: u8) -> Result<[u8; 32], Error> {
        if !is_valid_sighash_type(hash_type) {
            return Err(Error::UnsupportedSighash);
        }
        let slot = (hash_type & 3) as usize - 1 + 3 * (hash_type >> 7) as usize;
        if let Some(hash) = self.known[slot] {
            return Ok(hash);
        }
        let hash = self
            .tx
            .sighash(Some(self.index), hash_type, self.prevouts)?;
        self.known[slot] = Some(hash);
        Ok(hash)
    }

    /// Whether `signature` is one of `key` for this input.
    fn verifies(&mut self, key: &[u8], signature: &InputSignature) -> Result<bool, Error> {
        let Ok(key) = SecpPublicKey::from_sec1(key) else {
            return Ok(false);
        };
        let hash = self.get(signature.hash_type())?;
        let der = DerSignature::from_der(signature.der()).map_err(|_| Error::InvalidSignature)?;
        let (r, s) = der.to_rs();
        Ok(key.verify(&hash, &r, &s))
    }
}

impl<'a> ZcashTx<'a> {
    /// The output that input `index` spends.
    fn prevout<'p>(
        &self,
        index: usize,
        prevouts: &'p [ZcashTxOut<'p>],
    ) -> Result<&'p ZcashTxOut<'p>, Error> {
        if index >= self.inputs.len() {
            return Err(Error::InputIndex);
        }
        prevouts.get(index).ok_or(Error::PrevOutCount)
    }

    /// Signs the digest of transparent input `index` for `hash_type` with
    /// `key`, whatever the script of the output spent: the signature of one
    /// co-signer of a multisignature, or of the key of any other script.
    /// See [`sighash`](Self::sighash) for `prevouts`.
    pub fn sign_input_signature(
        &self,
        index: usize,
        key: &SecpPrivateKey,
        hash_type: u8,
        prevouts: &[ZcashTxOut<'_>],
    ) -> Result<InputSignature, Error> {
        let sighash = self.sighash(Some(index), hash_type, prevouts)?;
        Ok(InputSignature::new(&key.sign_der(&sighash), hash_type))
    }

    /// Checks that `signature` is a signature by `public_key` (in SEC1
    /// encoding) of the digest of transparent input `index` for the sighash
    /// type the signature states: [`Error::SignatureVerification`] with the
    /// index of the input otherwise, [`Error::InvalidKey`] for a key that
    /// is not one.
    pub fn verify_input_signature(
        &self,
        index: usize,
        public_key: &[u8],
        signature: &InputSignature,
        prevouts: &[ZcashTxOut<'_>],
    ) -> Result<(), Error> {
        if SecpPublicKey::from_sec1(public_key).is_err() {
            return Err(Error::InvalidKey);
        }
        match Sighashes::new(self, index, prevouts).verifies(public_key, signature)? {
            true => Ok(()),
            false => Err(Error::SignatureVerification(index)),
        }
    }

    /// The multisignature script that input `index` spends: the output
    /// itself, or the redeem script of a P2SH output.
    fn multisig_of<'s>(
        prevout: &ZcashTxOut<'s>,
        redeem_script: Option<&'s [u8]>,
    ) -> Result<Multisig<'s>, Error> {
        match (ScriptKind::of(prevout.script), redeem_script) {
            (ScriptKind::P2sh(hash), Some(script)) => {
                if script.len() > MAX_REDEEM_SCRIPT_SIZE || hash160(script) != *hash {
                    return Err(Error::RedeemScriptMismatch);
                }
                Multisig::parse(script)
            }
            (ScriptKind::P2sh(_), None) => Err(Error::MissingRedeemScript),
            (ScriptKind::Multisig(multisig), None) => Ok(multisig),
            (ScriptKind::Multisig(_), Some(_)) => Err(Error::RedeemScriptMismatch),
            _ => Err(Error::UnsupportedScript),
        }
    }

    /// Combines the signatures of the co-signers of multisignature input
    /// `index` into its scriptSig, written into `out`; returns its length.
    ///
    /// The output spent is a P2SH output whose redeem script is
    /// `redeem_script` ([`Error::MissingRedeemScript`] without one,
    /// [`Error::RedeemScriptMismatch`] if it is not the script of the
    /// output), or, with `None`, a bare multisignature. `signatures` are in
    /// any order, each for its own sighash type; every one must be a
    /// signature of a key of the script
    /// ([`Error::SignatureVerification`] with the index of the input
    /// otherwise), no two of the same key, and there must be as many as the
    /// script requires ([`Error::MissingSignatures`]). Signatures beyond
    /// that number are left out, those of the first keys of the script
    /// being kept.
    pub fn multisig_script_sig_to_slice(
        &self,
        index: usize,
        redeem_script: Option<&[u8]>,
        signatures: &[InputSignature],
        prevouts: &[ZcashTxOut<'_>],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let prevout = self.prevout(index, prevouts)?;
        let multisig = Self::multisig_of(prevout, redeem_script)?;
        if signatures.len() > MAX_MULTISIG_KEYS {
            return Err(Error::SignatureVerification(index));
        }
        let mut sighashes = Sighashes::new(self, index, prevouts);
        // which signature each key made
        let mut used = [false; MAX_MULTISIG_KEYS];
        let mut ordered = [None; MAX_MULTISIG_KEYS];
        let mut found = 0;
        for (slot, key) in ordered.iter_mut().zip(multisig.keys()) {
            for (i, signature) in signatures.iter().enumerate() {
                if !used[i] && sighashes.verifies(key, signature)? {
                    used[i] = true;
                    *slot = Some(*signature);
                    found += 1;
                    break;
                }
            }
        }
        if used[..signatures.len()].iter().any(|used| !used) {
            return Err(Error::SignatureVerification(index));
        }
        if found < multisig.required() {
            return Err(Error::MissingSignatures);
        }
        let mut kept = [InputSignature {
            bytes: [0; MAX_INPUT_SIGNATURE_LEN],
            len: 1,
        }; MAX_MULTISIG_KEYS];
        let mut n = 0;
        for signature in ordered.iter().flatten().take(multisig.required()) {
            kept[n] = *signature;
            n += 1;
        }
        multisig_script_sig_to_slice(&kept[..n], redeem_script, out)
    }

    /// Verifies the scriptSig of transparent input `index` against the
    /// output it spends, for the forms this module makes: P2PKH, P2PK, bare
    /// multisignature, and P2SH whose redeem script is a multisignature, a
    /// P2PKH or a P2PK script. This is what the script interpreter would
    /// conclude for these forms, not an interpreter: any other script is
    /// [`Error::UnsupportedScript`].
    ///
    /// Fails with [`Error::SignatureVerification`] (and the index) for a
    /// signature that does not verify, [`Error::RedeemScriptMismatch`] for
    /// a redeem script that is not the one of the output,
    /// [`Error::KeyNotInvolved`] for a public key that is not the one of a
    /// P2PKH output, and [`Error::InvalidScript`] or
    /// [`Error::InvalidSignature`] for a scriptSig that is not of the form
    /// the output needs.
    pub fn verify_input(&self, index: usize, prevouts: &[ZcashTxOut<'_>]) -> Result<(), Error> {
        let prevout = self.prevout(index, prevouts)?;
        let script_sig = self.inputs[index].script_sig;
        let mut sighashes = Sighashes::new(self, index, prevouts);
        match ScriptKind::of(prevout.script) {
            ScriptKind::P2sh(hash) => {
                // the last push is the redeem script, which the others feed
                let mut last: Option<(&[u8], usize)> = None;
                let mut offset = 0;
                let mut pushes = Pushes(script_sig);
                while let Some(push) = pushes.next() {
                    last = Some((push?, offset));
                    offset = script_sig.len() - pushes.0.len();
                }
                let (redeem, start) = last.ok_or(Error::InvalidScript)?;
                if hash160(redeem) != *hash {
                    return Err(Error::RedeemScriptMismatch);
                }
                if matches!(ScriptKind::of(redeem), ScriptKind::P2sh(_)) {
                    return Err(Error::UnsupportedScript);
                }
                Self::verify_script(&mut sighashes, redeem, &script_sig[..start])
            }
            _ => Self::verify_script(&mut sighashes, prevout.script, script_sig),
        }
    }

    /// Verifies the pushes `script_sig` against `script`, which is not a
    /// P2SH script.
    fn verify_script(
        sighashes: &mut Sighashes<'_, '_, '_>,
        script: &[u8],
        script_sig: &[u8],
    ) -> Result<(), Error> {
        let failed = Error::SignatureVerification(sighashes.index);
        let mut pushes = Pushes(script_sig);
        let mut next = || pushes.next().ok_or(Error::InvalidScript)?;
        match ScriptKind::of(script) {
            ScriptKind::P2pkh(hash) => {
                let signature = InputSignature::from_bytes(next()?)?;
                let key = next()?;
                if pushes.next().is_some() {
                    return Err(Error::InvalidScript);
                }
                if hash160(key) != *hash {
                    return Err(Error::KeyNotInvolved);
                }
                match sighashes.verifies(key, &signature)? {
                    true => Ok(()),
                    false => Err(failed),
                }
            }
            ScriptKind::P2pk(key) => {
                let signature = InputSignature::from_bytes(next()?)?;
                if pushes.next().is_some() {
                    return Err(Error::InvalidScript);
                }
                match sighashes.verifies(key, &signature)? {
                    true => Ok(()),
                    false => Err(failed),
                }
            }
            ScriptKind::Multisig(multisig) => {
                // the item OP_CHECKMULTISIG pops and ignores
                next()?;
                // as the opcode does: each signature must be of a key after
                // the key of the signature before it
                let mut keys = multisig.keys();
                for _ in 0..multisig.required() {
                    let signature = InputSignature::from_bytes(next()?)?;
                    loop {
                        let key = keys.next().ok_or(failed)?;
                        if sighashes.verifies(key, &signature)? {
                            break;
                        }
                    }
                }
                match pushes.next() {
                    None => Ok(()),
                    Some(_) => Err(Error::InvalidScript),
                }
            }
            ScriptKind::P2sh(_) | ScriptKind::Other => Err(Error::UnsupportedScript),
        }
    }

    /// Makes the scriptSig of transparent input `index` as `spend` says,
    /// into `out` (at most [`InputSpend::script_sig_len_bound`] bytes), and
    /// returns its length.
    ///
    /// With a key: the output spent must be a P2PKH output of the key
    /// ([`Error::KeyNotInvolved`] otherwise) or a P2PK output of it. With
    /// multisignature keys: [`Error::MissingSignatures`] if fewer keys of
    /// the script are given than it requires. With a scriptSig: see
    /// [`InputSigner::ScriptSig`].
    pub fn script_sig_to_slice(
        &self,
        index: usize,
        spend: &InputSpend<'_>,
        prevouts: &[ZcashTxOut<'_>],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let prevout = self.prevout(index, prevouts)?;
        let n = match spend.signer {
            InputSigner::Key(key) => match ScriptKind::of(prevout.script) {
                ScriptKind::P2pkh(_) => {
                    return self.sign_input_to_slice(index, key, spend.hash_type, prevouts, out);
                }
                ScriptKind::P2pk(public) => {
                    let ours = key.public_key();
                    if public != ours.serialize_compressed()
                        && public != ours.serialize_uncompressed()
                    {
                        return Err(Error::KeyNotInvolved);
                    }
                    let signature =
                        self.sign_input_signature(index, key, spend.hash_type, prevouts)?;
                    p2pk_script_sig_to_slice(&signature, out)?
                }
                _ => return Err(Error::UnsupportedScript),
            },
            InputSigner::Multisig {
                redeem_script,
                keys,
            } => {
                let multisig = Self::multisig_of(prevout, redeem_script)?;
                let mut signatures = [InputSignature {
                    bytes: [0; MAX_INPUT_SIGNATURE_LEN],
                    len: 1,
                }; MAX_MULTISIG_KEYS];
                let mut n = 0;
                for public in multisig.keys() {
                    if n == multisig.required() {
                        break;
                    }
                    let signer = keys.iter().find(|key| {
                        let ours = key.public_key();
                        public == ours.serialize_compressed()
                            || public == ours.serialize_uncompressed()
                    });
                    if let Some(key) = signer {
                        signatures[n] =
                            self.sign_input_signature(index, key, spend.hash_type, prevouts)?;
                        n += 1;
                    }
                }
                if n < multisig.required() {
                    return Err(Error::MissingSignatures);
                }
                multisig_script_sig_to_slice(&signatures[..n], redeem_script, out)?
            }
            InputSigner::ScriptSig(script_sig) => {
                self.verify_script_sig(index, script_sig, prevouts)?;
                out.get_mut(..script_sig.len())
                    .ok_or(Error::BufferTooSmall)?
                    .copy_from_slice(script_sig);
                script_sig.len()
            }
            InputSigner::Custom { max_len, build } => {
                let sighash = self.sighash(Some(index), spend.hash_type, prevouts)?;
                let buffer = out.get_mut(..max_len).ok_or(Error::BufferTooSmall)?;
                let n = build(&sighash, buffer)?;
                if n > max_len {
                    return Err(Error::BufferTooSmall);
                }
                n
            }
        };
        if n > MAX_SCRIPT_SIZE {
            return Err(Error::TooLarge);
        }
        Ok(n)
    }

    /// Verifies `script_sig` as the scriptSig of input `index`, if it is of
    /// a form [`verify_input`](Self::verify_input) knows; a scriptSig for
    /// a script it does not know is accepted unverified.
    fn verify_script_sig(
        &self,
        index: usize,
        script_sig: &[u8],
        prevouts: &[ZcashTxOut<'_>],
    ) -> Result<(), Error> {
        let prevout = self.prevout(index, prevouts)?;
        let mut sighashes = Sighashes::new(self, index, prevouts);
        let (script, pushes) = match ScriptKind::of(prevout.script) {
            ScriptKind::P2sh(hash) => {
                let mut last: Option<(&[u8], usize)> = None;
                let mut offset = 0;
                let mut pushes = Pushes(script_sig);
                while let Some(push) = pushes.next() {
                    let Ok(push) = push else {
                        // not only pushes: a script this module does not know
                        return Ok(());
                    };
                    last = Some((push, offset));
                    offset = script_sig.len() - pushes.0.len();
                }
                let (redeem, start) = last.ok_or(Error::InvalidScript)?;
                if hash160(redeem) != *hash {
                    return Err(Error::RedeemScriptMismatch);
                }
                (redeem, &script_sig[..start])
            }
            _ => (prevout.script, script_sig),
        };
        match ScriptKind::of(script) {
            ScriptKind::P2sh(_) | ScriptKind::Other => Ok(()),
            _ => Self::verify_script(&mut sighashes, script, pushes),
        }
    }

    /// An upper bound on the length of the transaction signed as `spends`
    /// say.
    pub fn signed_len_bound_with(&self, spends: &[InputSpend<'_>]) -> usize {
        let unsigned: usize = self.inputs.iter().map(|input| input.script_sig.len()).sum();
        let signed: usize = spends
            .iter()
            .map(|spend| spend.script_sig_len_bound() + 8)
            .sum();
        self.serialized_len() - unsigned + signed
    }

    /// Signs every transparent input as `spends` say, one per input in
    /// order ([`Error::KeyCount`] otherwise), and writes the signed
    /// transaction into `out` (at most
    /// [`signed_len_bound_with`](Self::signed_len_bound_with) bytes).
    /// Returns the number of bytes written. The scriptSigs the inputs hold
    /// are ignored. See [`script_sig_to_slice`](Self::script_sig_to_slice)
    /// for what each kind of spend requires.
    pub fn sign_with_to_slice(
        &self,
        spends: &[InputSpend<'_>],
        prevouts: &[ZcashTxOut<'_>],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if spends.len() != self.inputs.len() {
            return Err(Error::KeyCount);
        }
        let mut pos = {
            let mut s = SliceSink::new(out);
            self.write_header(&mut s);
            put_varint(&mut s, self.inputs.len());
            s.finish().ok_or(Error::BufferTooSmall)?
        };
        for (index, (input, spend)) in self.inputs.iter().zip(spends).enumerate() {
            // outpoint, then the scriptSig after room for the longest
            // encoding of its length, moved back once that is known
            const ROOM: usize = 3;
            let start = pos + 36;
            let buffer = out.get_mut(start + ROOM..).ok_or(Error::BufferTooSmall)?;
            let n = self.script_sig_to_slice(index, spend, prevouts, buffer)?;
            let (len, len_len) = BtcVarInt(n as u64).to_array();
            if len_len > ROOM {
                return Err(Error::TooLarge);
            }
            out.copy_within(start + ROOM..start + ROOM + n, start + len_len);
            out[start..start + len_len].copy_from_slice(&len[..len_len]);
            let mut s = SliceSink::new(&mut out[pos..start]);
            super::put_outpoint(&mut s, input);
            let end = start + len_len + n;
            out.get_mut(end..end + 4)
                .ok_or(Error::BufferTooSmall)?
                .copy_from_slice(&input.sequence.to_le_bytes());
            pos = end + 4;
        }
        let mut s = SliceSink::new(&mut out[pos..]);
        self.write_outputs_and_bundles(&mut s);
        Ok(pos + s.finish().ok_or(Error::BufferTooSmall)?)
    }

    /// Signs every transparent input as `spends` say: see
    /// [`sign_with_to_slice`](Self::sign_with_to_slice).
    #[cfg(feature = "alloc")]
    pub fn sign_with(
        &self,
        spends: &[InputSpend<'_>],
        prevouts: &[ZcashTxOut<'_>],
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; self.signed_len_bound_with(spends)];
        let n = self.sign_with_to_slice(spends, prevouts, &mut out)?;
        out.truncate(n);
        Ok(out)
    }
}
