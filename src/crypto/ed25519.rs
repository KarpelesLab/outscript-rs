//! Ed25519 helpers over `purecrypto::ec::ed25519`, plus the on-curve check used
//! by Solana program-derived addresses.

use purecrypto::ec::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use purecrypto::ec::edwards25519::hazmat::EdwardsPoint;

/// Derives the 32-byte raw Ed25519 public key from a 32-byte seed.
pub fn public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    Ed25519PrivateKey::from_bytes(*seed).public_key().to_bytes()
}

/// Signs a message with a 32-byte seed, returning a 64-byte signature.
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    Ed25519PrivateKey::from_bytes(*seed).sign(message).to_bytes()
}

/// Verifies a 64-byte Ed25519 signature over `message` for the given 32-byte
/// public key.
pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let pk = Ed25519PublicKey::from_bytes(*public);
    let sig = Ed25519Signature::from_bytes(*signature);
    pk.verify(message, &sig).is_ok()
}

/// Reports whether a 32-byte value decodes to a valid point on the Ed25519
/// curve. Used to reject Solana PDAs that would have a corresponding private
/// key.
pub fn is_on_curve(point: &[u8; 32]) -> bool {
    EdwardsPoint::decompress(point).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let seed = [7u8; 32];
        let pk = public_from_seed(&seed);
        let sig = sign(&seed, b"hello solana");
        assert!(verify(&pk, b"hello solana", &sig));
        assert!(!verify(&pk, b"tampered", &sig));
    }

    #[test]
    fn rfc8032_vector_1() {
        // RFC 8032 §7.1 test vector 1.
        let seed_v =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_v);
        let pk = public_from_seed(&seed);
        assert_eq!(
            hex::encode(pk),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = sign(&seed, b"");
        assert_eq!(
            hex::encode(sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn on_curve() {
        // A valid public key is on the curve.
        let pk = public_from_seed(&[1u8; 32]);
        assert!(is_on_curve(&pk));
    }
}
