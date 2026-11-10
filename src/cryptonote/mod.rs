//! Primitives shared by the CryptoNote family of chains (Monero, Zano, ...).
//!
//! Everything here is chain-independent and works without a heap: values go
//! in and out as `[u8; 32]` (scalars little-endian, points compressed as in
//! RFC 8032), and the codecs write into caller buffers. The `alloc` feature
//! only adds `String`/`Vec` conveniences.
//!
//! - **Hashing**: [`cn_fast_hash`] (Keccak-256 with the original Keccak
//!   padding), [`hash_to_scalar`] (`Hs`: the hash reduced modulo the group
//!   order), the streaming [`Hasher`], and [`hash_to_ec`] (`Hp`) on top of
//!   the [`hash_to_point`] map — Monero's `ge_fromfe_frombytes_vartime`, which
//!   is *not* RFC 9380's Elligator 2 encoding.
//! - **Keys**: [`secret_key_to_public_key`], [`generate_key_derivation`],
//!   [`derivation_to_scalar`], [`derive_public_key`], [`derive_secret_key`],
//!   [`generate_key_image`], [`derive_view_secret_key`], and the plain
//!   CryptoNote Schnorr signature ([`generate_signature`],
//!   [`check_signature`]).
//! - **Codecs**: the varint ([`read_varint`], [`write_varint`]), the
//!   block-wise [`base58`], and the address framing
//!   `base58(varint(prefix) || payload || keccak[..4])`
//!   ([`encode_address_to_slice`], [`decode_address_to_slice`]).
//!
//! For constructions that need the group itself (ring signatures, range
//! proofs, ...), the typed layer exposes `purecrypto`'s [`Scalar`],
//! [`EdwardsPoint`] and [`FieldElement`] with the conversions CryptoNote uses:
//! [`scalar_from_bytes`], [`scalar_reduce`], [`point_from_bytes`],
//! [`scalar_from_hash`], [`point_from_hash`] and [`map_to_point`].
//!
//! # Secrets
//!
//! Functions that take a secret key wipe the secret-derived values they
//! create, and return derived secret keys in a
//! [`Zeroizing`](crate::crypto::Zeroizing) buffer. The scalar arithmetic and
//! the scalar multiplications by a secret are `purecrypto`'s constant-time
//! ones. Hashing to a point and signature verification are variable-time, and
//! only ever see public values. Key bytes passed in by reference stay yours to
//! wipe.
//!
//! # Untrusted input
//!
//! Decoding is canonical and never panics: a varint must be minimal and fit
//! in 64 bits, a base58 block must not overflow its byte count, a scalar must
//! be reduced and a point must be a canonical encoding of a curve point.
//! Points are *not* checked for membership in the prime-order subgroup, as
//! in the reference implementations; where that matters, multiply by the
//! cofactor or test [`EdwardsPoint::is_torsion_free`].

mod address;
pub mod base58;
mod hash;
mod keys;
mod point;
mod varint;

#[cfg(test)]
mod tests;

pub use purecrypto::ec::edwards25519::hazmat::{EdwardsPoint, FieldElement, Scalar};

pub use address::{
    ADDRESS_CHECKSUM_LEN, address_decoded_len, address_encoded_len, decode_address_to_slice,
    encode_address_to_slice,
};
#[cfg(feature = "alloc")]
pub use address::{decode_address, encode_address};
pub use hash::{
    Hasher, cn_fast_hash, cn_fast_hash_parts, hash_to_scalar, hash_to_scalar_parts, sc_check,
    sc_reduce32, scalar_from_bytes, scalar_from_hash, scalar_from_u64, scalar_reduce,
};
pub use keys::{
    check_key, check_signature, derivation_to_scalar, derive_public_key, derive_secret_key,
    derive_view_secret_key, generate_key_derivation, generate_key_image, generate_signature,
    secret_key_to_public_key,
};
pub use point::{hash_to_ec, hash_to_point, map_to_point, point_from_bytes, point_from_hash};
#[cfg(feature = "alloc")]
pub use varint::push_varint;
pub use varint::{MAX_VARINT_LEN, read_varint, varint_len, write_varint};

/// Errors from the CryptoNote primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The data ended in the middle of a varint.
    UnexpectedEof,
    /// A varint is not minimally encoded.
    NonCanonical,
    /// A varint does not fit in 64 bits, or a base58 block encodes a value
    /// too large for the bytes it stands for.
    Overflow,
    /// The output buffer is too small for the result.
    BufferTooSmall,
    /// A base58 string has a length no encoding produces, or an address is
    /// too short to hold a prefix and a checksum.
    InvalidLength,
    /// A character is not in the base58 alphabet.
    InvalidCharacter,
    /// The address checksum does not verify.
    BadChecksum,
    /// The bytes are not the canonical encoding of a curve point.
    InvalidPoint,
    /// The bytes are not a reduced scalar (a valid secret key).
    InvalidScalar,
    /// The public key does not belong to the secret key.
    KeyMismatch,
    /// The signing nonce is unusable (it, the challenge or the response is
    /// zero): sign again with a fresh nonce.
    InvalidNonce,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::UnexpectedEof => "unexpected end of varint",
            Error::NonCanonical => "non-canonical varint",
            Error::Overflow => "value overflows its encoding",
            Error::BufferTooSmall => "output buffer too small",
            Error::InvalidLength => "invalid length",
            Error::InvalidCharacter => "invalid base58 character",
            Error::BadChecksum => "bad address checksum",
            Error::InvalidPoint => "invalid curve point",
            Error::InvalidScalar => "invalid scalar",
            Error::KeyMismatch => "public key does not match the secret key",
            Error::InvalidNonce => "unusable signing nonce",
        })
    }
}

impl core::error::Error for Error {}
