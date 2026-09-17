//! secp256k1 keys, ECDSA (RFC6979 deterministic, low-S, DER + recoverable) and
//! BIP-340 Schnorr / BIP-341 taproot, built on `purecrypto`'s hazmat secp256k1
//! scalar/point arithmetic.
//!
//! The ECDSA path uses the standard RFC6979 deterministic nonce, low-S
//! normalization, and recovery-code semantics, so signatures are reproducible
//! and interoperable with other conforming implementations.

use purecrypto::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use purecrypto::hash::{Digest, HmacSha256, Sha256, sha256};
use purecrypto::zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "alloc")]
use crate::prelude::*;

/// secp256k1 group order n (big-endian).
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// secp256k1 field prime p (big-endian).
const FIELD_PRIME: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

/// (n-1)/2, the low-S threshold (big-endian 32 bytes).
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

fn is_over_half_order(s_be: &[u8; 32]) -> bool {
    // Equal-length big-endian comparison is numeric comparison.
    s_be[..] > HALF_ORDER[..]
}

/// Errors from secp256k1 operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A secret key, scalar or coordinate was out of range.
    InvalidKey,
    /// A point or encoding was malformed.
    Malformed,
    /// Public-key recovery failed.
    Recovery,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidKey => f.write_str("invalid secp256k1 key"),
            Error::Malformed => f.write_str("malformed secp256k1 data"),
            Error::Recovery => f.write_str("secp256k1 public-key recovery failed"),
        }
    }
}
impl core::error::Error for Error {}

// ---------------------------------------------------------------------------
// HMAC-SHA256 helper
// ---------------------------------------------------------------------------

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new(key);
    for p in parts {
        mac.update(p);
    }
    mac.finalize()
}

/// RFC6979 deterministic nonce generation (HMAC-SHA256), matching
/// `KarpelesLab/secp256k1`'s `NonceRFC6979` with `extra`/`version` unset.
/// `extra_iterations` selects the (extra_iterations+1)-th valid candidate.
fn generate_k(priv_be: &[u8; 32], hash: &[u8; 32], extra_iterations: u32) -> Scalar {
    // The key material and the whole HMAC-DRBG state (K, V) determine the
    // nonce, and the nonce reveals the private key: wipe all of it on return.
    let mut key = Zeroizing::new([0u8; 64]);
    key[..32].copy_from_slice(priv_be);
    key[32..].copy_from_slice(hash);

    let mut v = Zeroizing::new([1u8; 32]);
    let mut k = Zeroizing::new([0u8; 32]);

    *k = hmac(&k[..], &[&v[..], &[0x00], &key[..]]);
    *v = hmac(&k[..], &[&v[..]]);
    *k = hmac(&k[..], &[&v[..], &[0x01], &key[..]]);
    *v = hmac(&k[..], &[&v[..]]);

    let mut generated: u32 = 0;
    loop {
        *v = hmac(&k[..], &[&v[..]]);
        if let Ok(cand) = Scalar::from_bytes_be(&v)
            && !bool::from(cand.is_zero())
        {
            generated += 1;
            if generated > extra_iterations {
                return cand;
            }
        }
        *k = hmac(&k[..], &[&v[..], &[0x00]]);
        *v = hmac(&k[..], &[&v[..]]);
    }
}

// ---------------------------------------------------------------------------
// Public key
// ---------------------------------------------------------------------------

/// A secp256k1 public key.
#[derive(Clone)]
pub struct SecpPublicKey {
    point: AffinePoint,
}

impl SecpPublicKey {
    /// Parses a SEC1-encoded public key (compressed 0x02/0x03 or uncompressed 0x04).
    pub fn from_sec1(bytes: &[u8]) -> Result<SecpPublicKey, Error> {
        let point = AffinePoint::from_sec1(bytes).map_err(|_| Error::Malformed)?;
        Ok(SecpPublicKey { point })
    }

    /// Returns the 33-byte compressed SEC1 encoding.
    pub fn serialize_compressed(&self) -> [u8; 33] {
        self.point.to_sec1_compressed()
    }

    /// Returns the 65-byte uncompressed SEC1 encoding.
    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        self.point.to_sec1_uncompressed()
    }

    /// Returns the 32-byte x-only public key (compressed key without prefix).
    pub fn x_only(&self) -> [u8; 32] {
        self.point.x_bytes()
    }

    /// Verifies a low-level ECDSA signature `(r, s)` over `hash`.
    pub fn verify(&self, hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> bool {
        let r = match Scalar::from_bytes_be(r) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let s = match Scalar::from_bytes_be(s) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if bool::from(r.is_zero()) || bool::from(s.is_zero()) {
            return false;
        }
        let e = Scalar::from_bytes_be_reduce(hash);
        let w = s.invert();
        let u1 = e.mul(&w);
        let u2 = r.mul(&w);
        let big_r = ProjectivePoint::mul_generator(&u1).add(&self.point.to_projective().mul(&u2));
        let big_r = match big_r.to_affine() {
            Some(p) => p,
            None => return false,
        };
        // r' = R.x mod n
        let x = big_r.x_bytes();
        let r_prime = match Scalar::from_bytes_be(&x) {
            Ok(v) => v,
            Err(_) => Scalar::from_bytes_be_reduce(&x),
        };
        bool::from(r_prime.ct_eq(&r))
    }
}

// ---------------------------------------------------------------------------
// Private key
// ---------------------------------------------------------------------------

/// A secp256k1 private key.
///
/// The secret scalar is wiped when the key is dropped ([`ZeroizeOnDrop`]), and
/// [`Zeroize::zeroize`] scrubs it earlier on demand. A zeroized key holds the
/// invalid scalar 0 and must not be used again. Each [`Clone`] is an
/// independent copy that wipes itself; the bytes passed to
/// [`from_bytes`](Self::from_bytes) stay the caller's to wipe.
#[derive(Clone)]
pub struct SecpPrivateKey {
    d: Scalar,
    d_be: [u8; 32],
}

impl Zeroize for SecpPrivateKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
        self.d_be.zeroize();
    }
}

impl Drop for SecpPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecpPrivateKey {}

impl SecpPrivateKey {
    /// Creates a private key from a 32-byte big-endian secret scalar. Returns
    /// an error if the scalar is zero or >= n.
    pub fn from_bytes(secret: &[u8; 32]) -> Result<SecpPrivateKey, Error> {
        let d = Scalar::from_bytes_be(secret).map_err(|_| Error::InvalidKey)?;
        if bool::from(d.is_zero()) {
            return Err(Error::InvalidKey);
        }
        Ok(SecpPrivateKey { d, d_be: *secret })
    }

    /// Derives the public key.
    pub fn public_key(&self) -> SecpPublicKey {
        let point = ProjectivePoint::mul_generator(&self.d)
            .to_affine()
            .expect("d in [1,n-1] so d*G is not identity");
        SecpPublicKey { point }
    }

    /// Low-level RFC6979 ECDSA signing of a 32-byte digest. Returns
    /// `(r, s, recovery_id)` with `s` in low-S form and `recovery_id` in 0..=3.
    pub fn sign_recoverable(&self, hash: &[u8; 32]) -> ([u8; 32], [u8; 32], u8) {
        for iteration in 0u32.. {
            let k = generate_k(&self.d_be, hash, iteration);
            let big_r = ProjectivePoint::mul_generator(&k)
                .to_affine()
                .expect("k != 0 so k*G is not identity");
            let x = big_r.x_bytes();
            let (r, overflow) = match Scalar::from_bytes_be(&x) {
                Ok(v) => (v, 0u8),
                Err(_) => (Scalar::from_bytes_be_reduce(&x), 1u8),
            };
            if bool::from(r.is_zero()) {
                continue;
            }
            let y_odd = big_r.y_bytes()[31] & 1;
            let mut recid = (overflow << 1) | y_odd;

            let e = Scalar::from_bytes_be_reduce(hash);
            let kinv = k.invert();
            let mut s = self.d.mul(&r).add(&e).mul(&kinv);
            if bool::from(s.is_zero()) {
                continue;
            }
            let s_be = s.to_bytes_be();
            if is_over_half_order(&s_be) {
                s = s.negate();
                recid ^= 1;
            }
            return (r.to_bytes_be(), s.to_bytes_be(), recid);
        }
        unreachable!()
    }

    /// RFC6979 ECDSA signing of a 32-byte digest, returning a DER-encoded
    /// signature with low-S (as used for Bitcoin).
    pub fn sign_der(&self, hash: &[u8; 32]) -> DerSignature {
        let (r, s, _) = self.sign_recoverable(hash);
        der_encode(&r, &s)
    }

    /// The 32-byte x-only public key (BIP-340), as used for taproot internal
    /// keys and tapscript `OP_CHECKSIG`.
    pub fn xonly_public_key(&self) -> [u8; 32] {
        let comp = self.public_key().serialize_compressed();
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(&comp[1..]);
        x_only
    }

    /// BIP-341 key-path taproot signing: applies the taproot tweak to this key
    /// (empty merkle root) and produces a 64-byte BIP-340 Schnorr signature
    /// over `sighash`. Uses deterministic (zero) auxiliary randomness.
    pub fn sign_taproot(&self, sighash: &[u8; 32]) -> Result<[u8; 64], Error> {
        self.sign_taproot_with_root(sighash, None)
    }

    /// BIP-341 key-path taproot signing for an output that commits to a
    /// script tree: like [`sign_taproot`](Self::sign_taproot), with the tweak
    /// taken over `merkle_root` (`None` for a key-path-only output).
    pub fn sign_taproot_with_root(
        &self,
        sighash: &[u8; 32],
        merkle_root: Option<&[u8; 32]>,
    ) -> Result<[u8; 64], Error> {
        let pub_bytes = self.public_key().serialize_compressed();
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(&pub_bytes[1..]);
        let (_, parity, tweak) = taproot_tweak_full(&x_only, merkle_root)?;

        // d' = d if internal P.y even else n-d
        let mut d = if pub_bytes[0] == 0x03 {
            self.d.negate()
        } else {
            self.d.clone()
        };
        let t = Scalar::from_bytes_be(&tweak).map_err(|_| Error::InvalidKey)?;
        d = d.add(&t);
        if parity == 1 {
            d = d.negate();
        }
        bip340_sign_scalar(&d, sighash, &[0u8; 32])
    }

    /// BIP-340 Schnorr signing with this key as is (no taproot tweak), as
    /// needed for a tapscript `OP_CHECKSIG` against
    /// [`xonly_public_key`](Self::xonly_public_key). Uses deterministic (zero)
    /// auxiliary randomness.
    pub fn sign_schnorr(&self, msg: &[u8; 32]) -> Result<[u8; 64], Error> {
        bip340_sign_scalar(&self.d, msg, &[0u8; 32])
    }
}

// ---------------------------------------------------------------------------
// DER encoding
// ---------------------------------------------------------------------------

/// A DER-encoded ECDSA signature (at most 72 bytes), stored inline.
///
/// Dereferences to the encoded bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DerSignature {
    buf: [u8; 72],
    len: u8,
}

impl DerSignature {
    /// The encoded signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}

impl core::ops::Deref for DerSignature {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for DerSignature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::fmt::Debug for DerSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DerSignature(")?;
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

#[cfg(feature = "alloc")]
impl From<DerSignature> for Vec<u8> {
    fn from(sig: DerSignature) -> Vec<u8> {
        sig.as_bytes().to_vec()
    }
}

fn canon_int(value_be: &[u8; 32]) -> ([u8; 33], usize) {
    // Prepend a 0x00 then strip leading 0x00 bytes while the next byte's high
    // bit is clear (keeps the DER integer positive and minimally encoded).
    let mut buf = [0u8; 33];
    buf[1..].copy_from_slice(value_be);
    let mut start = 0;
    while start < 32 && buf[start] == 0x00 && buf[start + 1] & 0x80 == 0 {
        start += 1;
    }
    (buf, start)
}

fn der_encode(r_be: &[u8; 32], s_be: &[u8; 32]) -> DerSignature {
    let (r_buf, r_start) = canon_int(r_be);
    let (s_buf, s_start) = canon_int(s_be);
    let r = &r_buf[r_start..];
    let s = &s_buf[s_start..];
    // total length of the whole signature (mirrors Go: 6 + len(r) + len(s)).
    let total = 6 + r.len() + s.len();
    let mut buf = [0u8; 72];
    buf[0] = 0x30;
    buf[1] = (total - 2) as u8;
    buf[2] = 0x02;
    buf[3] = r.len() as u8;
    buf[4..4 + r.len()].copy_from_slice(r);
    let s_off = 4 + r.len();
    buf[s_off] = 0x02;
    buf[s_off + 1] = s.len() as u8;
    buf[s_off + 2..total].copy_from_slice(s);
    DerSignature {
        buf,
        len: total as u8,
    }
}

/// Parses a DER-encoded ECDSA signature into 32-byte big-endian `(r, s)`.
pub fn parse_der_signature(sig: &[u8]) -> Result<([u8; 32], [u8; 32]), Error> {
    if sig.len() < 8 || sig.len() > 72 {
        return Err(Error::Malformed);
    }
    if sig[0] != 0x30 {
        return Err(Error::Malformed);
    }
    if sig[1] as usize != sig.len() - 2 {
        return Err(Error::Malformed);
    }
    if sig[2] != 0x02 {
        return Err(Error::Malformed);
    }
    let r_len = sig[3] as usize;
    let s_type_off = 4 + r_len;
    if s_type_off + 1 >= sig.len() || sig[s_type_off] != 0x02 {
        return Err(Error::Malformed);
    }
    let s_len = sig[s_type_off + 1] as usize;
    let s_off = s_type_off + 2;
    if s_off + s_len != sig.len() {
        return Err(Error::Malformed);
    }
    let r = normalize_32(&sig[4..4 + r_len])?;
    let s = normalize_32(&sig[s_off..s_off + s_len])?;
    Ok((r, s))
}

fn normalize_32(b: &[u8]) -> Result<[u8; 32], Error> {
    let mut start = 0;
    while start < b.len() && b[start] == 0x00 {
        start += 1;
    }
    let trimmed = &b[start..];
    if trimmed.len() > 32 {
        return Err(Error::Malformed);
    }
    let mut out = [0u8; 32];
    out[32 - trimmed.len()..].copy_from_slice(trimmed);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

/// Recovers the public key from an ECDSA signature `(r, s)`, recovery id, and
/// 32-byte message digest.
pub fn recover_public_key(
    r_be: &[u8; 32],
    s_be: &[u8; 32],
    recid: u8,
    hash: &[u8; 32],
) -> Result<SecpPublicKey, Error> {
    if recid > 3 {
        return Err(Error::Recovery);
    }
    let r = Scalar::from_bytes_be(r_be).map_err(|_| Error::Recovery)?;
    let s = Scalar::from_bytes_be(s_be).map_err(|_| Error::Recovery)?;
    if bool::from(r.is_zero()) || bool::from(s.is_zero()) {
        return Err(Error::Recovery);
    }

    // Determine the x coordinate of R (possibly r + n).
    let x_bytes = if recid & 0x02 != 0 {
        // r + n must not overflow 256 bits and must stay below p.
        let (x, carry) = add_be(r_be, &ORDER);
        if carry || x[..] >= FIELD_PRIME[..] {
            return Err(Error::Recovery);
        }
        x
    } else {
        *r_be
    };

    // Lift x to a point with the requested y parity using SEC1 decompression.
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02 | (recid & 1);
    compressed[1..].copy_from_slice(&x_bytes);
    let big_x = AffinePoint::from_sec1(&compressed).map_err(|_| Error::Recovery)?;

    let e = Scalar::from_bytes_be_reduce(hash);
    let w = r.invert();
    let u1 = e.mul(&w).negate();
    let u2 = s.mul(&w);
    let q = ProjectivePoint::mul_generator(&u1).add(&big_x.to_projective().mul(&u2));
    if bool::from(q.is_identity()) {
        return Err(Error::Recovery);
    }
    let point = q.to_affine().ok_or(Error::Recovery)?;
    Ok(SecpPublicKey { point })
}

/// Big-endian 256-bit addition, returning the sum and the carry-out.
fn add_be(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], bool) {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let v = a[i] as u16 + b[i] as u16 + carry;
        out[i] = v as u8;
        carry = v >> 8;
    }
    (out, carry != 0)
}

// ---------------------------------------------------------------------------
// BIP-340 Schnorr / BIP-341 taproot
// ---------------------------------------------------------------------------

/// Computes a BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
pub fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let th = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(&th);
    h.update(&th);
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

fn taproot_tweak_full(
    internal_xonly: &[u8; 32],
    merkle_root: Option<&[u8; 32]>,
) -> Result<([u8; 32], u8, [u8; 32]), Error> {
    // lift_x: even-Y point with this x coordinate.
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(internal_xonly);
    let p_point = AffinePoint::from_sec1(&compressed).map_err(|_| Error::Malformed)?;

    // t = tagged_hash("TapTweak", P.x || merkle_root), with no root for a
    // key-path-only output
    let t_bytes = match merkle_root {
        Some(root) => tagged_hash("TapTweak", &[internal_xonly, root]),
        None => tagged_hash("TapTweak", &[internal_xonly]),
    };
    let t = Scalar::from_bytes_be(&t_bytes).map_err(|_| Error::InvalidKey)?;

    let q = p_point
        .to_projective()
        .add(&ProjectivePoint::mul_generator(&t));
    let qa = q.to_affine().ok_or(Error::Malformed)?;
    let tweaked = qa.x_bytes();
    let parity = qa.y_bytes()[31] & 1;
    Ok((tweaked, parity, t_bytes))
}

/// Applies the BIP-341 key-path-only taproot tweak (empty merkle root) to a
/// 32-byte x-only internal public key, returning the tweaked x-only output key
/// and the parity (0 if Q.y even, 1 if odd).
pub fn taproot_tweak(internal_xonly: &[u8; 32]) -> Result<([u8; 32], u8), Error> {
    taproot_tweak_with_root(internal_xonly, None)
}

/// Applies the BIP-341 taproot tweak to a 32-byte x-only internal public key,
/// committing to the script tree with the given `merkle_root` (`None` for a
/// key-path-only output, as in [`taproot_tweak`]). Returns the tweaked x-only
/// output key and its parity (0 if Q.y is even, 1 if odd), which a script-path
/// control block records.
pub fn taproot_tweak_with_root(
    internal_xonly: &[u8; 32],
    merkle_root: Option<&[u8; 32]>,
) -> Result<([u8; 32], u8), Error> {
    let (xonly, parity, _) = taproot_tweak_full(internal_xonly, merkle_root)?;
    Ok((xonly, parity))
}

fn bip340_sign_scalar(d0: &Scalar, msg: &[u8; 32], aux: &[u8; 32]) -> Result<[u8; 64], Error> {
    if bool::from(d0.is_zero()) {
        return Err(Error::InvalidKey);
    }
    // P = d0*G; if P.y odd, d = n - d0.
    let p_point = ProjectivePoint::mul_generator(d0)
        .to_affine()
        .ok_or(Error::InvalidKey)?;
    let p_y_odd = p_point.y_bytes()[31] & 1 == 1;
    let d = if p_y_odd { d0.negate() } else { d0.clone() };
    let px = p_point.x_bytes();

    // t = d XOR tagged_hash("BIP0340/aux", aux)
    let aux_hash = tagged_hash("BIP0340/aux", &[aux]);
    // (the key bytes, the masked key and the nonce seed are all wiped on return)
    let d_bytes = Zeroizing::new(d.to_bytes_be());
    let mut t = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        t[i] = d_bytes[i] ^ aux_hash[i];
    }

    // rand = tagged_hash("BIP0340/nonce", t || P.x || msg)
    let rand = Zeroizing::new(tagged_hash("BIP0340/nonce", &[&t[..], &px, msg]));
    let mut k = Scalar::from_bytes_be_reduce(&rand);
    if bool::from(k.is_zero()) {
        return Err(Error::InvalidKey);
    }

    // R = k*G; if R.y odd, k = n - k.
    let big_r = ProjectivePoint::mul_generator(&k)
        .to_affine()
        .ok_or(Error::InvalidKey)?;
    if big_r.y_bytes()[31] & 1 == 1 {
        k = k.negate();
    }
    let rx = big_r.x_bytes();

    // e = int(tagged_hash("BIP0340/challenge", R.x || P.x || msg)) mod n
    let e_bytes = tagged_hash("BIP0340/challenge", &[&rx, &px, msg]);
    let e = Scalar::from_bytes_be_reduce(&e_bytes);

    // s = k + e*d
    let s = k.add(&e.mul(&d));
    let s_bytes = s.to_bytes_be();

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&rx);
    sig[32..].copy_from_slice(&s_bytes);
    Ok(sig)
}

/// BIP-340 Schnorr signature over a 32-byte message using a 32-byte secret key,
/// with the given 32-byte auxiliary randomness (pass zeros for deterministic).
pub fn bip340_sign(secret: &[u8; 32], msg: &[u8; 32], aux: &[u8; 32]) -> Result<[u8; 64], Error> {
    let d0 = Scalar::from_bytes_be(secret).map_err(|_| Error::InvalidKey)?;
    bip340_sign_scalar(&d0, msg, aux)
}

/// Verifies a 64-byte BIP-340 Schnorr signature over `msg` against a 32-byte
/// x-only public key.
pub fn bip340_verify(xonly_pub: &[u8; 32], msg: &[u8; 32], sig: &[u8; 64]) -> bool {
    // P = lift_x(xonly_pub) (even Y).
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(xonly_pub);
    let p_point = match AffinePoint::from_sec1(&compressed) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let mut rx = [0u8; 32];
    rx.copy_from_slice(&sig[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);
    let s = match Scalar::from_bytes_be(&s_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // e = tagged_hash("BIP0340/challenge", rx || P.x || msg) mod n
    let e_bytes = tagged_hash("BIP0340/challenge", &[&rx, xonly_pub, msg]);
    let e = Scalar::from_bytes_be_reduce(&e_bytes);

    // R = s*G - e*P
    let r_point = ProjectivePoint::mul_generator(&s).add(&p_point.to_projective().mul(&e.negate()));
    let r_affine = match r_point.to_affine() {
        Some(p) => p,
        None => return false,
    };
    // R.y must be even and R.x == rx.
    if r_affine.y_bytes()[31] & 1 != 0 {
        return false;
    }
    r_affine.x_bytes() == rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_zeroizes() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecpPrivateKey>();

        let mut key = SecpPrivateKey::from_bytes(&[0x11; 32]).unwrap();
        let copy = key.clone();
        let sig = key.sign_der(&[7u8; 32]);
        key.zeroize();
        assert_eq!(key.d_be, [0u8; 32]);
        assert!(bool::from(key.d.is_zero()));
        // a clone is independent, and signing is unchanged by the wiping of
        // its temporaries
        assert_eq!(copy.d_be, [0x11; 32]);
        assert_eq!(copy.sign_der(&[7u8; 32]), sig);
    }

    #[test]
    fn recovery_with_overflowed_r() {
        // recid bit 1 set means R.x = r + n; r + n >= p must be rejected
        // rather than wrapping. r = p - n is the smallest such value.
        let r = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40, 0x2d, 0xa1, 0x72,
            0x2f, 0xc9, 0xba, 0xee,
        ];
        assert_eq!(add_be(&r, &ORDER), (FIELD_PRIME, false));
        let s = [0x01u8; 32];
        let msg = [0u8; 32];
        assert!(recover_public_key(&r, &s, 2, &msg).is_err());
        let (sum, carry) = add_be(&[0u8; 32], &ORDER);
        assert_eq!((sum, carry), (ORDER, false));
    }

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn arr32(s: &str) -> [u8; 32] {
        let v = h(s);
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn pubkey_compressed_uncompressed() {
        // From the Go outscript address test (priv eb696a...).
        let sk = SecpPrivateKey::from_bytes(&arr32(
            "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf",
        ))
        .unwrap();
        let pk = sk.public_key();
        let comp = hex::encode(pk.serialize_compressed());
        // Must start with 02/03 and be 33 bytes.
        assert_eq!(comp.len(), 66);
        assert!(comp.starts_with("02") || comp.starts_with("03"));
        // Uncompressed begins with 04.
        assert!(hex::encode(pk.serialize_uncompressed()).starts_with("04"));
    }

    #[test]
    fn ecdsa_rfc6979_deterministic_and_verify() {
        let sk = SecpPrivateKey::from_bytes(&arr32(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ))
        .unwrap();
        let msg = super::sha256(b"Satoshi Nakamoto");
        let (r1, s1, _) = sk.sign_recoverable(&msg);
        let (r2, s2, _) = sk.sign_recoverable(&msg);
        assert_eq!(r1, r2);
        assert_eq!(s1, s2);
        assert!(sk.public_key().verify(&msg, &r1, &s1));
        // low-S
        assert!(!is_over_half_order(&s1));
    }

    #[test]
    fn ecdsa_recovery_roundtrip() {
        let sk = SecpPrivateKey::from_bytes(&arr32(
            "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf",
        ))
        .unwrap();
        let msg = super::sha256(b"recover me");
        let (r, s, recid) = sk.sign_recoverable(&msg);
        let rec = recover_public_key(&r, &s, recid, &msg).unwrap();
        assert_eq!(
            rec.serialize_compressed(),
            sk.public_key().serialize_compressed()
        );
    }

    #[test]
    fn der_roundtrip() {
        let sk = SecpPrivateKey::from_bytes(&arr32(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ))
        .unwrap();
        let msg = super::sha256(b"der");
        let der = sk.sign_der(&msg);
        let (r, s) = parse_der_signature(&der).unwrap();
        assert!(sk.public_key().verify(&msg, &r, &s));
    }

    #[test]
    fn rfc6979_known_nonce() {
        // Canonical secp256k1 + SHA-256 RFC6979 vector (message "sample").
        let d = arr32("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let hash = super::sha256(b"sample");
        let k = generate_k(&d, &hash, 0);
        assert_eq!(
            hex::encode(k.to_bytes_be()),
            "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60"
        );
    }

    #[test]
    fn bip340_test_vector_0() {
        // BIP-340 test vector index 0.
        let secret = arr32("0000000000000000000000000000000000000000000000000000000000000003");
        let msg = arr32("0000000000000000000000000000000000000000000000000000000000000000");
        let aux = arr32("0000000000000000000000000000000000000000000000000000000000000000");
        let sig = bip340_sign(&secret, &msg, &aux).unwrap();
        let expected = "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0";
        assert_eq!(hex::encode(sig).to_uppercase(), expected);
    }
}
