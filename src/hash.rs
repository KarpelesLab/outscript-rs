//! Hashing helpers built on `purecrypto::hash`.
//!
//! Mirrors the chained-hash behaviour of the Go code's `gobottle.Hash`, which
//! applies a sequence of hash functions where each function consumes the output
//! of the previous one (e.g. HASH160 = RIPEMD160(SHA256(x))).

use purecrypto::hash::{Blake3, keccak256, ripemd160, sha256};

/// A single hash function usable in a [`hash_chain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFn {
    /// SHA-256.
    Sha256,
    /// RIPEMD-160.
    Ripemd160,
    /// Keccak-256 (Ethereum legacy keccak, not SHA3-256).
    Keccak256,
    /// BLAKE3 with 32-byte output (used for Massa).
    Blake3,
    /// Ethereum public-key hash (keccak-256 over the body with the SEC1 prefix
    /// byte stripped, returning the last 20 bytes). Terminal in a chain.
    EtherHash,
}

impl HashFn {
    fn apply(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashFn::Sha256 => sha256(data).to_vec(),
            HashFn::Ripemd160 => ripemd160(data).to_vec(),
            HashFn::Keccak256 => keccak256(data).to_vec(),
            HashFn::Blake3 => Blake3::hash(data).to_vec(),
            HashFn::EtherHash => ether_hash(data).to_vec(),
        }
    }
}

/// Applies a sequence of hash functions, chaining the output of one into the
/// input of the next. Equivalent to the Go `gobottle.Hash(data, fns...)`.
pub fn hash_chain(data: &[u8], fns: &[HashFn]) -> Vec<u8> {
    let mut cur = data.to_vec();
    for f in fns {
        cur = f.apply(&cur);
    }
    cur
}

/// SHA-256 one-shot.
pub fn sha256_once(data: &[u8]) -> [u8; 32] {
    sha256(data)
}

/// Double SHA-256: SHA256(SHA256(data)).
pub fn dsha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// HASH160: RIPEMD160(SHA256(data)).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

/// Keccak-256 (legacy keccak, as used by Ethereum).
pub fn keccak256_once(data: &[u8]) -> [u8; 32] {
    keccak256(data)
}

/// BLAKE3 with 32-byte output (used for Massa addresses).
pub fn blake3_256(data: &[u8]) -> [u8; 32] {
    Blake3::hash(data)
}

/// The Ethereum public-key hash used by the `eth` format.
///
/// Mirrors the Go `etherHash`: keccak-256 over the public key bytes with the
/// leading byte (the SEC1 `0x04` uncompressed prefix) stripped, returning the
/// last 20 bytes of the digest.
pub fn ether_hash(uncompressed_pubkey: &[u8]) -> [u8; 20] {
    let body = if uncompressed_pubkey.is_empty() {
        uncompressed_pubkey
    } else {
        &uncompressed_pubkey[1..]
    };
    let h = keccak256(body);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[12..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash160() {
        // HASH160 of empty string.
        let h = hash160(b"");
        assert_eq!(hex::encode(h), "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
    }

    #[test]
    fn test_dsha256() {
        let h = dsha256(b"hello");
        assert_eq!(
            hex::encode(h),
            "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
        );
    }

    #[test]
    fn test_hash_chain_matches_helpers() {
        let data = b"the quick brown fox";
        assert_eq!(
            hash_chain(data, &[HashFn::Sha256, HashFn::Sha256]),
            dsha256(data).to_vec()
        );
        assert_eq!(
            hash_chain(data, &[HashFn::Sha256, HashFn::Ripemd160]),
            hash160(data).to_vec()
        );
    }
}
