//! Keys: public keys, the sender/receiver shared secret ("key derivation"),
//! one-time output keys, key images and the plain Schnorr signature.
//!
//! Names and semantics follow `crypto.cpp` of the CryptoNote reference
//! implementation (as kept by Monero and Zano).

use purecrypto::zeroize::Zeroizing;

use super::{
    EdwardsPoint, Error, Hasher, Scalar, cn_fast_hash, point_from_bytes, point_from_hash,
    scalar_from_bytes, scalar_reduce, write_varint,
};

/// `secret_key_to_public_key`: the public key `secret * G`.
///
/// Fails with [`Error::InvalidScalar`] if `secret` is not a reduced scalar.
pub fn secret_key_to_public_key(secret: &[u8; 32]) -> Result<[u8; 32], Error> {
    Ok(EdwardsPoint::mul_base(&scalar_from_bytes(secret)?).compress())
}

/// `check_key`: whether `public` is the canonical encoding of a curve point.
///
/// As in the reference, a point outside the prime-order subgroup passes.
pub fn check_key(public: &[u8; 32]) -> bool {
    point_from_bytes(public).is_ok()
}

/// `generate_key_derivation`: the shared secret `8 * secret * public`.
///
/// The sender computes it from the recipient's public view key and the
/// transaction secret key, the recipient from the transaction public key and
/// the secret view key. The result is a secret both share: wipe it when done.
///
/// Fails with [`Error::InvalidPoint`] if `public` is not a valid point and
/// [`Error::InvalidScalar`] if `secret` is not a reduced scalar.
pub fn generate_key_derivation(public: &[u8; 32], secret: &[u8; 32]) -> Result<[u8; 32], Error> {
    let point = point_from_bytes(public)?;
    let secret = scalar_from_bytes(secret)?;
    Ok(point.mul(&secret).mul_by_cofactor().compress())
}

/// `Hs(derivation || varint(output_index))` as a scalar.
fn derivation_scalar(derivation: &[u8; 32], output_index: u64) -> Scalar {
    let mut index = [0u8; super::MAX_VARINT_LEN];
    // A `MAX_VARINT_LEN` buffer always fits.
    let n = write_varint(output_index, &mut index).unwrap_or(0);
    let mut h = Hasher::new();
    h.update(derivation);
    h.update(index.get(..n).unwrap_or(&[]));
    h.finalize_to_scalar()
}

/// `derivation_to_scalar`: `Hs(derivation || varint(output_index))`, the
/// scalar that ties a key derivation to one output of the transaction.
///
/// The result is secret: wipe it when done.
pub fn derivation_to_scalar(derivation: &[u8; 32], output_index: u64) -> [u8; 32] {
    derivation_scalar(derivation, output_index).to_bytes()
}

/// `derive_public_key`: the one-time public key of an output,
/// `Hs(derivation || varint(output_index)) * G + base`, with `base` the
/// recipient's public spend key.
///
/// Fails with [`Error::InvalidPoint`] if `base` is not a valid point.
pub fn derive_public_key(
    derivation: &[u8; 32],
    output_index: u64,
    base: &[u8; 32],
) -> Result<[u8; 32], Error> {
    let base = point_from_bytes(base)?;
    let scalar = derivation_scalar(derivation, output_index);
    Ok(EdwardsPoint::mul_base(&scalar).add(&base).compress())
}

/// `derive_secret_key`: the one-time secret key of an output,
/// `Hs(derivation || varint(output_index)) + base`, with `base` the
/// recipient's secret spend key. It is the secret key of
/// [`derive_public_key`]'s result.
///
/// Fails with [`Error::InvalidScalar`] if `base` is not a reduced scalar.
pub fn derive_secret_key(
    derivation: &[u8; 32],
    output_index: u64,
    base: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let base = scalar_from_bytes(base)?;
    let scalar = derivation_scalar(derivation, output_index);
    Ok(Zeroizing::new(scalar.add(&base).to_bytes()))
}

/// `generate_key_image`: the key image `secret * Hp(public)` of a one-time
/// key pair, which marks its output as spent without revealing which output
/// it is.
///
/// Fails with [`Error::InvalidScalar`] if `secret` is not a reduced scalar.
/// `public` is only hashed, so it is not checked to be `secret * G`.
pub fn generate_key_image(public: &[u8; 32], secret: &[u8; 32]) -> Result<[u8; 32], Error> {
    let secret = scalar_from_bytes(secret)?;
    Ok(point_from_hash(public).mul(&secret).compress())
}

/// The secret view key that goes with a secret spend key in a deterministic
/// wallet: `cn_fast_hash(spend_secret)` reduced modulo the group order
/// (Monero's `generate_keys` over the hash of the spend key, Zano's
/// `dependent_key`).
pub fn derive_view_secret_key(spend_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hash = Zeroizing::new(cn_fast_hash(spend_secret));
    Zeroizing::new(scalar_reduce(&hash).to_bytes())
}

/// The challenge `Hs(prefix_hash || public || commitment)`.
fn challenge(prefix_hash: &[u8; 32], public: &[u8; 32], commitment: &[u8; 32]) -> Scalar {
    let mut h = Hasher::new();
    h.update(prefix_hash);
    h.update(public);
    h.update(commitment);
    h.finalize_to_scalar()
}

/// `generate_signature`: the plain CryptoNote Schnorr signature of
/// `prefix_hash` by the key pair (`public`, `secret`), as `c || r` with
/// `c = Hs(prefix_hash || public || k * G)` and `r = k - c * secret`.
///
/// This crate has no random number generator, so the caller supplies the
/// nonce: 32 bytes from a cryptographically secure source, **fresh for every
/// signature and kept secret** (two signatures sharing a nonce reveal the
/// secret key). The bytes are reduced modulo the group order to give `k`, so
/// a reduced scalar is used as it is.
///
/// Fails with [`Error::InvalidScalar`] if `secret` is not a reduced scalar,
/// [`Error::KeyMismatch`] if `public` is not `secret * G`, and
/// [`Error::InvalidNonce`] in the (practically unreachable) case where `k`,
/// `c` or `r` is zero — the reference draws a new nonce there.
pub fn generate_signature(
    prefix_hash: &[u8; 32],
    public: &[u8; 32],
    secret: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<[u8; 64], Error> {
    let secret = scalar_from_bytes(secret)?;
    if EdwardsPoint::mul_base(&secret).compress() != *public {
        return Err(Error::KeyMismatch);
    }
    let k = scalar_reduce(nonce);
    if k == Scalar::ZERO {
        return Err(Error::InvalidNonce);
    }
    let commitment = EdwardsPoint::mul_base(&k).compress();
    let c = challenge(prefix_hash, public, &commitment);
    let r = k.sub(&c.mul(&secret));
    if c == Scalar::ZERO || r == Scalar::ZERO {
        return Err(Error::InvalidNonce);
    }
    let mut sig = [0u8; 64];
    let (sig_c, sig_r) = sig.split_at_mut(32);
    sig_c.copy_from_slice(&c.to_bytes());
    sig_r.copy_from_slice(&r.to_bytes());
    Ok(sig)
}

/// `check_signature`: verifies a signature made by [`generate_signature`].
///
/// Follows Monero's rules: `public` must be a valid point, `c` and `r`
/// reduced scalars, `c` non-zero, and the recomputed commitment
/// `c * public + r * G` must not be the identity. Variable-time.
pub fn check_signature(prefix_hash: &[u8; 32], public: &[u8; 32], signature: &[u8; 64]) -> bool {
    let (sig_c, sig_r) = signature.split_at(32);
    let (Ok(sig_c), Ok(sig_r)) = (<&[u8; 32]>::try_from(sig_c), <&[u8; 32]>::try_from(sig_r))
    else {
        return false;
    };
    let (Ok(point), Ok(c), Ok(r)) = (
        point_from_bytes(public),
        scalar_from_bytes(sig_c),
        scalar_from_bytes(sig_r),
    ) else {
        return false;
    };
    if c == Scalar::ZERO {
        return false;
    }
    let commitment = EdwardsPoint::double_scalar_mul_base_vartime(&c, &point, &r).compress();
    if commitment == EdwardsPoint::identity().compress() {
        return false;
    }
    challenge(prefix_hash, public, &commitment) == c
}
