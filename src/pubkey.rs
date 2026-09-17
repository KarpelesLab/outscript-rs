//! Public-key abstraction used by [`crate::script`].
//!
//! A small enum over the key types outscript understands, used to extract the
//! raw bytes for a requested public-key format.

#[cfg(feature = "alloc")]
use crate::prelude::*;

#[cfg(feature = "secp256k1")]
use crate::crypto::secp256k1::SecpPublicKey;

/// A public key understood by outscript: either secp256k1 or Ed25519.
///
/// Each variant exists only with its curve feature (`secp256k1`, enabled by
/// the `bitcoin` and `evm` chains; `ed25519`, enabled by `solana`, `cardano`
/// and `massa`).
///
/// Non-exhaustive: more key/curve types may be added as new chains are
/// supported.
#[derive(Clone)]
#[non_exhaustive]
pub enum PubKey {
    /// A secp256k1 public key (Bitcoin, EVM, ...).
    #[cfg(feature = "secp256k1")]
    Secp256k1(SecpPublicKey),
    /// A raw 32-byte Ed25519 public key (Solana, Cardano, Massa).
    #[cfg(feature = "ed25519")]
    Ed25519([u8; 32]),
}

#[cfg(feature = "alloc")]
impl PubKey {
    /// Returns the public-key bytes for the requested internal format name
    /// (`pubkey:comp`, `pubkey:uncomp`, `pubkey:ed25519`).
    pub fn bytes_for(&self, typ: &str) -> Result<Vec<u8>, crate::script::Error> {
        if !matches!(typ, "pubkey:ed25519" | "pubkey:comp" | "pubkey:uncomp") {
            return Err(crate::script::Error::UnknownFormat);
        }
        crate::script::generate_script(self, typ).map(Vec::from)
    }
}

#[cfg(feature = "secp256k1")]
impl From<SecpPublicKey> for PubKey {
    fn from(k: SecpPublicKey) -> Self {
        PubKey::Secp256k1(k)
    }
}
