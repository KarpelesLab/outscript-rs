//! BLAKE-256 (the SHA-3 finalist of Aumasson, Henzen, Meier and Phan, with 14
//! rounds), as `hash_extra_blake`.

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const C: [u32; 16] = [
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
];

const SIGMA: [[usize; 16]; 10] = [
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

/// The compression function: `counter` is the number of message bits hashed
/// up to and including this block (zero for a block of padding only).
fn compress(h: &mut [u32; 8], block: &[u8; 64], counter: u64) {
    let mut m = [0u32; 16];
    for (word, bytes) in m.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    let t0 = counter as u32;
    let t1 = (counter >> 32) as u32;
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..12].copy_from_slice(&C[..4]);
    v[12] = t0 ^ C[4];
    v[13] = t0 ^ C[5];
    v[14] = t1 ^ C[6];
    v[15] = t1 ^ C[7];
    for round in 0..14 {
        let s = &SIGMA[round % 10];
        let mut g = |a: usize, b: usize, c: usize, d: usize, i: usize| {
            v[a] = v[a]
                .wrapping_add(v[b])
                .wrapping_add(m[s[2 * i]] ^ C[s[2 * i + 1]]);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(12);
            v[a] = v[a]
                .wrapping_add(v[b])
                .wrapping_add(m[s[2 * i + 1]] ^ C[s[2 * i]]);
            v[d] = (v[d] ^ v[a]).rotate_right(8);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(7);
        };
        g(0, 4, 8, 12, 0);
        g(1, 5, 9, 13, 1);
        g(2, 6, 10, 14, 2);
        g(3, 7, 11, 15, 3);
        g(0, 5, 10, 15, 4);
        g(1, 6, 11, 12, 5);
        g(2, 7, 8, 13, 6);
        g(3, 4, 9, 14, 7);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE-256 of `data`.
pub(crate) fn blake256(data: &[u8]) -> [u8; 32] {
    let mut h = IV;
    let mut counter = 0u64;
    let (chunks, rest) = data.as_chunks::<64>();
    for chunk in chunks {
        let mut block = [0u8; 64];
        block.copy_from_slice(chunk);
        counter += 512;
        compress(&mut h, &block, counter);
    }
    let bits = (data.len() as u64) * 8;
    let mut block = [0u8; 64];
    block[..rest.len()].copy_from_slice(rest);
    block[rest.len()] = 0x80;
    if rest.len() > 55 {
        // The length does not fit: it goes in a block of its own.
        compress(&mut h, &block, bits);
        block = [0u8; 64];
        counter = 0;
    } else if rest.is_empty() {
        counter = 0;
    } else {
        counter = bits;
    }
    block[55] |= 0x01;
    block[56..].copy_from_slice(&bits.to_be_bytes());
    compress(&mut h, &block, counter);
    let mut out = [0u8; 32];
    for (bytes, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    out
}
