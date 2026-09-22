//! Hashing helpers built on `purecrypto::hash`.
//!
//! Supports chained hashing, where a sequence of hash functions is applied so
//! that each function consumes the output of the previous one (e.g.
//! HASH160 = RIPEMD160(SHA256(x))).

use purecrypto::hash::{Blake2bMac, Blake3, blake2b256, keccak256, ripemd160, sha256};

#[cfg(feature = "alloc")]
use crate::prelude::*;

#[cfg(feature = "alloc")]
/// A single hash step usable in a [`hash_chain`]: maps input bytes to output
/// bytes.
///
/// This is a plain function pointer, not an enum, so adding a hash needs no
/// change here — any `fn(&[u8]) -> Vec<u8>` works, whether one of the chainable
/// helpers below ([`sha256_vec`], [`ripemd160_vec`], …) or a user-defined one.
pub type HashFn = fn(&[u8]) -> Vec<u8>;

#[cfg(feature = "alloc")]
/// SHA-256, as a chainable [`HashFn`].
pub fn sha256_vec(data: &[u8]) -> Vec<u8> {
    sha256(data).to_vec()
}
#[cfg(feature = "alloc")]
/// RIPEMD-160, as a chainable [`HashFn`].
pub fn ripemd160_vec(data: &[u8]) -> Vec<u8> {
    ripemd160(data).to_vec()
}
#[cfg(feature = "alloc")]
/// Keccak-256 (Ethereum legacy keccak, not SHA3-256), as a chainable [`HashFn`].
pub fn keccak256_vec(data: &[u8]) -> Vec<u8> {
    keccak256(data).to_vec()
}
#[cfg(feature = "alloc")]
/// BLAKE3 with 32-byte output (used for Massa), as a chainable [`HashFn`].
pub fn blake3_vec(data: &[u8]) -> Vec<u8> {
    Blake3::hash(data).to_vec()
}
#[cfg(feature = "alloc")]
/// BLAKE2b-224 (used for Cardano key credentials), as a chainable [`HashFn`].
pub fn blake2b224_vec(data: &[u8]) -> Vec<u8> {
    blake2b224(data).to_vec()
}
#[cfg(feature = "alloc")]
/// The Ethereum public-key hash (keccak-256 over the body with the SEC1 prefix
/// byte stripped, last 20 bytes), as a chainable [`HashFn`]. Terminal in a chain.
pub fn ether_hash_vec(data: &[u8]) -> Vec<u8> {
    ether_hash(data).to_vec()
}

#[cfg(feature = "alloc")]
/// Applies a sequence of hash functions, chaining the output of one into the
/// input of the next.
pub fn hash_chain(data: &[u8], fns: &[HashFn]) -> Vec<u8> {
    let mut cur = data.to_vec();
    for f in fns {
        cur = f(&cur);
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

/// BLAKE2b with a 224-bit (28-byte) digest, used to derive Cardano key
/// credentials from public keys.
pub fn blake2b224(data: &[u8]) -> [u8; 28] {
    let mut h = Blake2bMac::new_unkeyed(28);
    h.update(data);
    let mut out = [0u8; 28];
    h.finalize_into(&mut out);
    out
}

/// BLAKE2b with a 256-bit (32-byte) digest, used as the Cardano transaction id
/// and signing digest.
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    blake2b256(data)
}

/// The Ethereum public-key hash used by the `eth` format.
///
/// Keccak-256 over the public key bytes with the leading byte (the SEC1 `0x04`
/// uncompressed prefix) stripped, returning the last 20 bytes of the digest.
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

    #[cfg(feature = "alloc")]
    #[test]
    fn test_hash_chain_matches_helpers() {
        let data = b"the quick brown fox";
        assert_eq!(
            hash_chain(data, &[sha256_vec, sha256_vec]),
            dsha256(data).to_vec()
        );
        assert_eq!(
            hash_chain(data, &[sha256_vec, ripemd160_vec]),
            hash160(data).to_vec()
        );
    }
}

/// BLAKE2b with a personalization string, as Zcash uses throughout (ZIP-243,
/// ZIP-244): the same hash, keyed apart by a 16-byte domain tag so that a
/// digest computed for one purpose is never valid for another.
///
/// `purecrypto` exposes BLAKE2b without its parameter block, so this is a
/// self-contained implementation of RFC 7693 §3 with `fanout = depth = 1`,
/// no key and no salt.
#[derive(Clone)]
pub struct Blake2bPersonal {
    h: [u64; 8],
    /// Bytes hashed so far, not counting what `buf` holds.
    counter: u128,
    buf: [u8; 128],
    buf_len: usize,
    out_len: usize,
}

const BLAKE2B_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const BLAKE2B_SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

impl Blake2bPersonal {
    /// Starts a hash of `out_len` bytes (1 to 64) personalized with `person`
    /// (at most 16 bytes, padded with zeros).
    pub fn new(out_len: usize, person: &[u8]) -> Self {
        assert!((1..=64).contains(&out_len), "BLAKE2b output length");
        assert!(person.len() <= 16, "BLAKE2b personalization length");
        let mut p = [0u8; 16];
        p[..person.len()].copy_from_slice(person);
        let mut h = BLAKE2B_IV;
        // parameter block: digest length, no key, fanout 1, depth 1, and the
        // personalization in its last two words
        h[0] ^= out_len as u64 | 1 << 16 | 1 << 24;
        h[6] ^= u64::from_le_bytes(p[..8].try_into().expect("8 bytes"));
        h[7] ^= u64::from_le_bytes(p[8..].try_into().expect("8 bytes"));
        Blake2bPersonal {
            h,
            counter: 0,
            buf: [0; 128],
            buf_len: 0,
            out_len,
        }
    }

    /// Feeds `data` into the hash.
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            // A full buffer is only compressed once more data follows, as the
            // last block is compressed with the final flag set.
            if self.buf_len == 128 {
                self.counter += 128;
                self.compress(false);
                self.buf_len = 0;
            }
            let n = data.len().min(128 - self.buf_len);
            self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
            self.buf_len += n;
            data = &data[n..];
        }
    }

    /// Finishes the hash into `out`, which must be `out_len` bytes.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        assert_eq!(out.len(), self.out_len, "BLAKE2b output buffer");
        self.counter += self.buf_len as u128;
        self.buf[self.buf_len..].fill(0);
        self.compress(true);
        for (dst, word) in out.chunks_mut(8).zip(self.h) {
            dst.copy_from_slice(&word.to_le_bytes()[..dst.len()]);
        }
    }

    /// Finishes a 32-byte hash.
    pub fn finalize_32(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.finalize_into(&mut out);
        out
    }

    fn compress(&mut self, last: bool) {
        let mut m = [0u64; 16];
        for (word, bytes) in m.iter_mut().zip(self.buf.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*bytes);
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&BLAKE2B_IV);
        v[12] ^= self.counter as u64;
        v[13] ^= (self.counter >> 64) as u64;
        if last {
            v[14] = !v[14];
        }
        for round in 0..12 {
            let s = &BLAKE2B_SIGMA[round % 10];
            let mut g = |a: usize, b: usize, c: usize, d: usize, x: u64, y: u64| {
                v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
                v[d] = (v[d] ^ v[a]).rotate_right(32);
                v[c] = v[c].wrapping_add(v[d]);
                v[b] = (v[b] ^ v[c]).rotate_right(24);
                v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
                v[d] = (v[d] ^ v[a]).rotate_right(16);
                v[c] = v[c].wrapping_add(v[d]);
                v[b] = (v[b] ^ v[c]).rotate_right(63);
            };
            g(0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for (h, (x, y)) in self.h.iter_mut().zip(v[..8].iter().zip(&v[8..])) {
            *h ^= x ^ y;
        }
    }
}

/// BLAKE2b-256 of `data` personalized with `person`: see [`Blake2bPersonal`].
pub fn blake2b_256_personal(person: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Blake2bPersonal::new(32, person);
    h.update(data);
    h.finalize_32()
}

#[cfg(test)]
mod blake2b_tests {
    use super::*;

    /// Known answers from Python's `hashlib.blake2b(digest_size, person)`.
    #[test]
    fn personalized_vectors() {
        let cases: [(&[u8], &[u8], usize, &str); 4] = [
            (
                b"",
                b"ZTxIdSaplingHash",
                32,
                "6f2fc8f98feafd94e74a0df4bed74391ee0b5a69945e4ced8ca8a095206f00ae",
            ),
            (
                b"",
                b"ZTxIdOrchardHash",
                32,
                "9fbe4ed13b0c08e671c11a3407d84e1117cd45028a2eee1b9feae78b48a6e2c1",
            ),
            (
                b"abc",
                b"ZcashTxHash_\xb4\xd0\xd6\xc2",
                32,
                "f31905091acfbfa30c3639202669c9fc839085bee60804d5bf1e948e5c5a6f57",
            ),
            (
                b"abc",
                b"",
                64,
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
            ),
        ];
        for (msg, person, len, want) in cases {
            let mut h = Blake2bPersonal::new(len, person);
            h.update(msg);
            let mut out = [0u8; 64];
            h.finalize_into(&mut out[..len]);
            assert_eq!(hex::encode(&out[..len]), want, "{person:?} {msg:?}");
        }

        // longer messages, fed in pieces of every size
        let long: Vec<u8> = (0..=255u8).cycle().take(768).collect();
        let want = "ac4e137dd99fb2aaa1ecba93dcbd88c06db3003aada88779db42eb96de5628df";
        for piece in [1usize, 7, 64, 127, 128, 129, 300, 768] {
            let mut h = Blake2bPersonal::new(32, b"ZTxIdPrevoutHash");
            for chunk in long.chunks(piece) {
                h.update(chunk);
            }
            assert_eq!(hex::encode(h.finalize_32()), want, "pieces of {piece}");
        }
        let two_hundred: Vec<u8> = (0..200u8).collect();
        assert_eq!(
            hex::encode(blake2b_256_personal(b"Zcash___TxInHash", &two_hundred)),
            "480a1713c02efeb491d6da63e42af404344c25ae7260c22ddda0ff542f0330c1"
        );
        // exactly one block, and a one-byte personalization
        assert_eq!(
            hex::encode(blake2b_256_personal(b"p", &[b'x'; 128])),
            "3b032241e30eaac1929aff2f4fe2c62c088df48f19a3e39e5120e1baa5924732"
        );
        // agrees with purecrypto without personalization
        assert_eq!(blake2b_256_personal(b"", b"hello"), blake2b_256(b"hello"));
    }
}
