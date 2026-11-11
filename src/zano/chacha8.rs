//! Bernstein's original ChaCha (64-bit block counter, 64-bit nonce): with 8
//! rounds, the stream cipher Zano uses for wallet blobs and, before hard
//! fork 6, for what a transaction encrypts; with 20 rounds, the one hard
//! fork 6 encrypts the payload of a transaction with.

use purecrypto::zeroize::{Zeroize, Zeroizing};

use crate::cryptonote::cn_fast_hash;

use super::keccak::keccak;

/// `"expand 32-byte k"` as four little-endian words.
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// The ChaCha8 key Zano derives from a 32-byte secret (a view secret key or a
/// key derivation): its Keccak-256 hash (`generate_chacha8_key`).
pub fn chacha8_generate_key(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(cn_fast_hash(seed))
}

#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// Applies the ChaCha8 keystream for `key` and `nonce` to `data` in place,
/// starting at block 0. Encryption and decryption are the same operation.
pub fn chacha8(key: &[u8; 32], nonce: &[u8; 8], data: &mut [u8]) {
    chacha(4, key, nonce, data);
}

/// Applies the ChaCha20 keystream for `key` and `nonce` to `data` in place,
/// starting at block 0 (`crypto::chacha20`: the original ChaCha20, with a
/// 64-bit nonce, not the one of RFC 8439). Encryption and decryption are
/// the same operation.
pub fn chacha20(key: &[u8; 32], nonce: &[u8; 8], data: &mut [u8]) {
    chacha(10, key, nonce, data);
}

/// The ChaCha20 key and nonce hard fork 6 derives from a secret
/// (`chacha_generate_key_and_iv`): the first 40 bytes of a Keccak sponge
/// of capacity 640 bits over `domain || data || index`, `domain` being one
/// of the 32-byte `CRYPTO_HDS_CHACHA_*` strings (31 characters and a zero).
///
/// The nonce is used as a little-endian counter: one value per entry
/// encrypted.
pub fn chacha20_generate_key_and_iv(
    domain: &[u8; 32],
    data: &[u8; 32],
    index: u64,
) -> (Zeroizing<[u8; 32]>, u64) {
    let mut input = Zeroizing::new([0u8; 72]);
    let (head, tail) = input.split_at_mut(32);
    head.copy_from_slice(domain);
    let (middle, tail) = tail.split_at_mut(32);
    middle.copy_from_slice(data);
    tail.copy_from_slice(&index.to_le_bytes());
    let mut out = Zeroizing::new([0u8; 40]);
    keccak(&input[..], &mut out[..]);
    let mut key = Zeroizing::new([0u8; 32]);
    let mut iv = [0u8; 8];
    let (k, n) = out.split_at(32);
    key.copy_from_slice(k);
    iv.copy_from_slice(n);
    (key, u64::from_le_bytes(iv))
}

/// ChaCha with `double_rounds` double rounds.
fn chacha(double_rounds: usize, key: &[u8; 32], nonce: &[u8; 8], data: &mut [u8]) {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&SIGMA);
    for (word, chunk) in state[4..12].iter_mut().zip(key.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }
    // state[12..14] is the 64-bit block counter, starting at zero.
    for (word, chunk) in state[14..16].iter_mut().zip(nonce.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }

    for block in data.chunks_mut(64) {
        let mut x = state;
        for _ in 0..double_rounds {
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 1, 5, 9, 13);
            quarter_round(&mut x, 2, 6, 10, 14);
            quarter_round(&mut x, 3, 7, 11, 15);
            quarter_round(&mut x, 0, 5, 10, 15);
            quarter_round(&mut x, 1, 6, 11, 12);
            quarter_round(&mut x, 2, 7, 8, 13);
            quarter_round(&mut x, 3, 4, 9, 14);
        }
        let mut keystream = [0u8; 64];
        let words = keystream.as_chunks_mut::<4>().0;
        for ((out, word), init) in words.iter_mut().zip(&x).zip(&state) {
            *out = word.wrapping_add(*init).to_le_bytes();
        }
        for (byte, k) in block.iter_mut().zip(&keystream) {
            *byte ^= k;
        }
        keystream.zeroize();
        x.zeroize();

        state[12] = state[12].wrapping_add(1);
        if state[12] == 0 {
            state[13] = state[13].wrapping_add(1);
        }
    }
    state.zeroize();
}

/// Encrypts or decrypts `data` in place the way Zano protects wallet blobs
/// and payment ids: ChaCha8 keyed by [`chacha8_generate_key`]`(secret)` with
/// an all-zero nonce.
pub fn chacha8_crypt(secret: &[u8; 32], data: &mut [u8]) {
    let key = chacha8_generate_key(secret);
    chacha8(&key, &[0u8; 8], data);
}
