//! Cryptographic primitives used by outscript, built on `purecrypto`.

pub mod ed25519;
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
