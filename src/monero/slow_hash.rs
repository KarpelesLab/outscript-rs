//! `cn_slow_hash`, variant 0: the original CryptoNight, which the reference
//! wallet still uses as its key derivation function
//! (`crypto::generate_chacha_key`) for the wallet files and for everything it
//! exports encrypted — key images, outputs, transaction sets.
//!
//! The hash fills a 2 MiB scratchpad from the Keccak state of the input with
//! AES rounds, walks it half a million times, folds it back into the state
//! and finishes with one of four hash functions — BLAKE-256, Grøstl-256,
//! JH-256 or Skein-512-256 — picked by the state. `purecrypto` has none of
//! the four, and its AES and Keccak are not exposed at the level this needs
//! (single rounds, the bare permutation), so all of it is here.

mod blake256;
mod groestl;
mod jh;
mod skein;

pub(crate) use blake256::blake256;
pub(crate) use groestl::groestl256;
pub(crate) use jh::jh256;
pub(crate) use skein::skein512_256;

#[cfg(feature = "alloc")]
use crate::prelude::*;
#[cfg(feature = "alloc")]
use purecrypto::zeroize::{Zeroize, Zeroizing};

/// The AES S-box.
pub(crate) const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Multiplication by `x` in the AES field.
pub(crate) const fn xtime(a: u8) -> u8 {
    (a << 1) ^ (((a >> 7) & 1) * 0x1b)
}

/// The AES round table: `SubBytes` and `MixColumns` of a byte in row 0, as a
/// little-endian column. The tables of the other rows are rotations of it.
#[cfg(feature = "alloc")]
const T0: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = SBOX[i];
        let s2 = xtime(s);
        let s3 = s2 ^ s;
        table[i] = (s2 as u32) | ((s as u32) << 8) | ((s as u32) << 16) | ((s3 as u32) << 24);
        i += 1;
    }
    table
};

/// One AES round (`SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`) on a
/// block held as four little-endian columns.
#[cfg(feature = "alloc")]
#[inline]
fn aes_round(x: &[u32; 4], key: &[u32; 4]) -> [u32; 4] {
    let mut out = [0u32; 4];
    for (j, o) in out.iter_mut().enumerate() {
        *o = T0[(x[j] & 0xff) as usize]
            ^ T0[((x[(j + 1) & 3] >> 8) & 0xff) as usize].rotate_left(8)
            ^ T0[((x[(j + 2) & 3] >> 16) & 0xff) as usize].rotate_left(16)
            ^ T0[(x[(j + 3) & 3] >> 24) as usize].rotate_left(24)
            ^ key[j];
    }
    out
}

/// The first ten round keys of the AES-256 key schedule of `key`.
#[cfg(feature = "alloc")]
fn expand_key(key: &[u8]) -> Zeroizing<[[u32; 4]; 10]> {
    let sub = |w: u32| {
        (SBOX[(w & 0xff) as usize] as u32)
            | ((SBOX[((w >> 8) & 0xff) as usize] as u32) << 8)
            | ((SBOX[((w >> 16) & 0xff) as usize] as u32) << 16)
            | ((SBOX[(w >> 24) as usize] as u32) << 24)
    };
    let mut w = Zeroizing::new([0u32; 40]);
    for (word, bytes) in w.iter_mut().zip(key.as_chunks::<4>().0).take(8) {
        *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    let mut rcon = 1u32;
    for i in 8..40 {
        let mut temp = w[i - 1];
        if i % 8 == 0 {
            temp = sub(temp.rotate_right(8)) ^ rcon;
            rcon <<= 1;
        } else if i % 8 == 4 {
            temp = sub(temp);
        }
        w[i] = w[i - 8] ^ temp;
    }
    let mut keys = Zeroizing::new([[0u32; 4]; 10]);
    for (key, words) in keys.iter_mut().zip(w.as_chunks::<4>().0) {
        key.copy_from_slice(words);
    }
    keys
}

/// The ten rounds the scratchpad is filled and folded with.
#[cfg(feature = "alloc")]
#[inline]
fn pseudo_round(block: &mut [u32; 4], keys: &[[u32; 4]; 10]) {
    for key in keys {
        *block = aes_round(block, key);
    }
}

const KECCAK_RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
const KECCAK_ROT: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const KECCAK_PIL: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f\[1600\] permutation.
pub(crate) fn keccak_f(st: &mut [u64; 25]) {
    for rc in KECCAK_RC {
        let mut bc = [0u64; 5];
        for (i, b) in bc.iter_mut().enumerate() {
            *b = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for j in (0..25).step_by(5) {
                st[j + i] ^= t;
            }
        }
        let mut t = st[1];
        for (j, rot) in KECCAK_PIL.iter().zip(KECCAK_ROT) {
            let next = st[*j];
            st[*j] = t.rotate_left(rot);
            t = next;
        }
        for j in (0..25).step_by(5) {
            let mut row = [0u64; 5];
            row.copy_from_slice(&st[j..j + 5]);
            for i in 0..5 {
                st[j + i] ^= !row[(i + 1) % 5] & row[(i + 2) % 5];
            }
        }
        st[0] ^= rc;
    }
}

/// `keccak1600`: the whole 1600-bit state after absorbing `data` (rate 136
/// bytes, the original Keccak padding). Its first 32 bytes are
/// [`cn_fast_hash`](crate::cryptonote::cn_fast_hash).
pub(crate) fn keccak1600(data: &[u8]) -> [u64; 25] {
    const RATE: usize = 136;
    let mut st = [0u64; 25];
    let absorb = |st: &mut [u64; 25], block: &[u8]| {
        for (word, bytes) in st.iter_mut().zip(block.as_chunks::<8>().0) {
            let mut le = [0u8; 8];
            le.copy_from_slice(bytes);
            *word ^= u64::from_le_bytes(le);
        }
        keccak_f(st);
    };
    let (chunks, rest) = data.as_chunks::<RATE>();
    for block in chunks {
        absorb(&mut st, block);
    }
    let mut last = [0u8; RATE];
    last[..rest.len()].copy_from_slice(rest);
    last[rest.len()] = 0x01;
    last[RATE - 1] |= 0x80;
    absorb(&mut st, &last);
    purecrypto::zeroize::Zeroize::zeroize(&mut last);
    st
}

/// The bytes of a Keccak state.
pub(crate) fn state_bytes(st: &[u64; 25]) -> [u8; 200] {
    let mut out = [0u8; 200];
    for (bytes, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(st) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// The size of the scratchpad, in 16-byte blocks (2 MiB).
#[cfg(feature = "alloc")]
const BLOCKS: usize = 1 << 17;
/// The number of steps of the walk over the scratchpad.
#[cfg(feature = "alloc")]
const ITERATIONS: usize = 1 << 19;

/// `cn_slow_hash` of `data`, variant 0 (the original CryptoNight, as of
/// 2014): the proof of work of the first four years of the chain and, still,
/// the key derivation function of the reference wallet.
///
/// It takes 2 MiB of memory and of the order of a hundred milliseconds
/// (several seconds without compiler optimizations). The scratchpad is wiped
/// afterwards. By construction the memory it reads depends on the input, so
/// it is not constant-time in the cache-timing sense — nor is the reference
/// implementation.
///
/// ```
/// use outscript::monero::cn_slow_hash;
///
/// // The first line of Monero's `tests/hash/tests-slow.txt`.
/// let hash = cn_slow_hash(b"de omnibus dubitandum");
/// assert_eq!(hash[..4], [0x2f, 0x8e, 0x3d, 0xf4]);
/// ```
#[cfg(feature = "alloc")]
pub fn cn_slow_hash(data: &[u8]) -> [u8; 32] {
    let mut state = Zeroizing::new(keccak1600(data));
    let mut bytes = Zeroizing::new(state_bytes(&state));
    let block_at = |bytes: &[u8; 200], offset: usize| -> [u32; 4] {
        let mut block = [0u32; 4];
        for (word, b) in block
            .iter_mut()
            .zip(bytes[offset..offset + 16].as_chunks::<4>().0)
        {
            *word = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        }
        block
    };
    let init_text = |bytes: &[u8; 200]| -> [[u32; 4]; 8] {
        let mut text = [[0u32; 4]; 8];
        for (i, block) in text.iter_mut().enumerate() {
            *block = block_at(bytes, 64 + 16 * i);
        }
        text
    };

    // Fill the scratchpad.
    let keys = expand_key(&bytes[..32]);
    let mut text = Zeroizing::new(init_text(&bytes));
    let mut pad: Zeroizing<Vec<[u32; 4]>> = Zeroizing::new(Vec::with_capacity(BLOCKS));
    for _ in 0..BLOCKS / 8 {
        for block in text.iter_mut() {
            pseudo_round(block, &keys);
        }
        pad.extend_from_slice(&*text);
    }

    // Walk it.
    let xor = |a: &[u32; 4], b: &[u32; 4]| [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]];
    let lo = |x: &[u32; 4]| (x[0] as u64) | ((x[1] as u64) << 32);
    let hi = |x: &[u32; 4]| (x[2] as u64) | ((x[3] as u64) << 32);
    let join = |l: u64, h: u64| [l as u32, (l >> 32) as u32, h as u32, (h >> 32) as u32];
    let index = |x: &[u32; 4]| ((x[0] >> 4) as usize) & (BLOCKS - 1);
    let mut a = xor(&block_at(&bytes, 0), &block_at(&bytes, 32));
    let mut b = xor(&block_at(&bytes, 16), &block_at(&bytes, 48));
    for _ in 0..ITERATIONS {
        let j = index(&a);
        let c = aes_round(&pad[j], &a);
        pad[j] = xor(&b, &c);
        let j = index(&c);
        let d = pad[j];
        let product = (lo(&c) as u128) * (lo(&d) as u128);
        let sum = join(
            lo(&a).wrapping_add((product >> 64) as u64),
            hi(&a).wrapping_add(product as u64),
        );
        pad[j] = sum;
        a = xor(&sum, &d);
        b = c;
    }
    a.zeroize();
    b.zeroize();

    // Fold it back into the state.
    let keys = expand_key(&bytes[32..64]);
    let mut text = Zeroizing::new(init_text(&bytes));
    for chunk in pad.as_chunks::<8>().0 {
        for (block, scratch) in text.iter_mut().zip(chunk) {
            *block = xor(block, scratch);
            pseudo_round(block, &keys);
        }
    }
    for (i, block) in text.iter().enumerate() {
        for (j, word) in block.iter().enumerate() {
            let at = 64 + 16 * i + 4 * j;
            bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
        }
    }
    for (word, b) in state.iter_mut().zip(bytes.as_chunks::<8>().0) {
        let mut le = [0u8; 8];
        le.copy_from_slice(b);
        *word = u64::from_le_bytes(le);
    }
    keccak_f(&mut state);
    let bytes = Zeroizing::new(state_bytes(&state));
    match bytes[0] & 3 {
        0 => blake256(&*bytes),
        1 => groestl256(&*bytes),
        2 => jh256(&*bytes),
        _ => skein512_256(&*bytes),
    }
}
