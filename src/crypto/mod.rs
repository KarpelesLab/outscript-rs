//! Cryptographic primitives used by outscript, built on `purecrypto`.

/// Secret wiping, re-exported from `purecrypto`: [`Zeroize`] to scrub a value
/// in place, [`Zeroizing`] to scrub a buffer when it goes out of scope, and the
/// [`ZeroizeOnDrop`] marker carried by this crate's key types.
///
/// Wiping is hygiene, not a guarantee: it cannot reach copies the compiler
/// made in registers or on the stack, or bytes a caller still holds.
pub use purecrypto::zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "ed25519")]
pub mod ed25519;
#[cfg(feature = "secp256k1")]
pub mod secp256k1;

/// The error an external signer reports when it cannot produce a signature
/// (unsupported algorithm, user rejection, device failure, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignerError;

impl core::fmt::Display for SignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("signer failed")
    }
}

impl core::error::Error for SignerError {}
