//! Keccak-256 (`cn_fast_hash`) and hashing to a scalar (`Hs`).

use purecrypto::hash::{Digest, Keccak256};
use purecrypto::zeroize::Zeroizing;

use super::{Error, Scalar};

/// `cn_fast_hash`: Keccak-256 with the original Keccak padding (the one
/// Ethereum uses, not SHA3-256).
pub fn cn_fast_hash(data: &[u8]) -> [u8; 32] {
    purecrypto::hash::keccak256(data)
}

/// [`cn_fast_hash`] of the concatenation of `parts`.
pub fn cn_fast_hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hasher::new();
    for part in parts {
        h.update(part);
    }
    h.finalize()
}

/// A streaming [`cn_fast_hash`], for data that is not in one piece.
///
/// The state is wiped when the hasher is dropped.
#[derive(Clone)]
pub struct Hasher(Keccak256);

impl Hasher {
    /// A hasher with nothing absorbed.
    pub fn new() -> Self {
        Hasher(Keccak256::new())
    }

    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The hash of everything absorbed.
    pub fn finalize(self) -> [u8; 32] {
        self.0.clone().finalize()
    }

    /// The hash of everything absorbed, reduced to a scalar: the streaming
    /// form of [`hash_to_scalar`].
    pub fn finalize_scalar(self) -> [u8; 32] {
        sc_reduce32(&self.finalize())
    }

    /// The hash of everything absorbed, reduced to a [`Scalar`].
    pub fn finalize_to_scalar(self) -> Scalar {
        scalar_reduce(&self.finalize())
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        Digest::zeroize(&mut self.0);
    }
}

impl core::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Hasher")
    }
}

/// Decodes a scalar, which must be reduced (below the group order `l`):
/// `sc_check`, the test a secret key has to pass.
///
/// Fails with [`Error::InvalidScalar`] otherwise.
pub fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar, Error> {
    Scalar::from_bytes_canonical(bytes).ok_or(Error::InvalidScalar)
}

/// Reduces a 256-bit little-endian integer modulo the group order `l`
/// (`sc_reduce32`).
pub fn scalar_reduce(bytes: &[u8; 32]) -> Scalar {
    let mut wide = Zeroizing::new([0u8; 64]);
    for (w, b) in wide.iter_mut().zip(bytes) {
        *w = *b;
    }
    Scalar::from_bytes_mod_order(&wide)
}

/// The scalar `value`.
pub fn scalar_from_u64(value: u64) -> Scalar {
    let mut wide = [0u8; 64];
    for (w, b) in wide.iter_mut().zip(value.to_le_bytes()) {
        *w = b;
    }
    Scalar::from_bytes_mod_order(&wide)
}

/// `Hs`: [`cn_fast_hash`] of the concatenation of `parts`, reduced modulo the
/// group order, as a [`Scalar`].
pub fn scalar_from_hash(parts: &[&[u8]]) -> Scalar {
    let mut h = Hasher::new();
    for part in parts {
        h.update(part);
    }
    h.finalize_to_scalar()
}

/// `sc_reduce32`: reduces a 256-bit little-endian integer modulo the group
/// order `l`, returning the canonical 32-byte scalar.
///
/// The result is as secret as the input: wipe it if the input was.
pub fn sc_reduce32(bytes: &[u8; 32]) -> [u8; 32] {
    scalar_reduce(bytes).to_bytes()
}

/// `sc_check`: whether `bytes` is a reduced scalar (below the group order).
pub fn sc_check(bytes: &[u8; 32]) -> bool {
    Scalar::from_bytes_canonical(bytes).is_some()
}

/// `hash_to_scalar` (`Hs`): [`cn_fast_hash`] of `data`, reduced modulo the
/// group order.
pub fn hash_to_scalar(data: &[u8]) -> [u8; 32] {
    sc_reduce32(&cn_fast_hash(data))
}

/// [`hash_to_scalar`] of the concatenation of `parts`.
pub fn hash_to_scalar_parts(parts: &[&[u8]]) -> [u8; 32] {
    scalar_from_hash(parts).to_bytes()
}
