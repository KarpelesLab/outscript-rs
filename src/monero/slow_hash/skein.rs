//! Skein-512-256 (the SHA-3 finalist of Ferguson, Lucks, Schneier, Whiting,
//! Bellare, Kohno, Callas and Walker, version 1.3), as `hash_extra_skein`:
//! the 512-bit state with a 256-bit output.

/// The chaining value after the configuration block of a 256-bit output.
const IV: [u64; 8] = [
    0xccd044a12fdb3e13,
    0xe83590301a79a9eb,
    0x55aea0614f816e6f,
    0x2a2767a4ae9b94db,
    0xec06025e74dd7683,
    0xe7a436cdc4746251,
    0xc36fbaf9393ad185,
    0x3eedba1833edfc13,
];

const KS_PARITY: u64 = 0x1bd11bdaa9fc1a22;
const T1_FIRST: u64 = 1 << 62;
const T1_FINAL: u64 = 1 << 63;
const T1_MSG: u64 = 48 << 56;
const T1_OUT: u64 = 63 << 56;

/// The rotations of the eight rounds of a cycle.
const ROTATIONS: [[u32; 4]; 8] = [
    [46, 36, 19, 37],
    [33, 27, 14, 42],
    [17, 49, 36, 39],
    [44, 9, 54, 56],
    [39, 30, 34, 24],
    [13, 50, 10, 17],
    [25, 29, 39, 43],
    [8, 35, 56, 22],
];

/// The word pairs mixed in each of the four rounds between key injections.
const PAIRS: [[(usize, usize); 4]; 4] = [
    [(0, 1), (2, 3), (4, 5), (6, 7)],
    [(2, 1), (4, 7), (6, 5), (0, 3)],
    [(4, 1), (6, 3), (0, 5), (2, 7)],
    [(6, 1), (0, 7), (2, 5), (4, 3)],
];

/// One block of UBI: Threefish-512 keyed with the chaining value, with the
/// tweak `(t0, t1)`, on `block`, fed forward.
fn process(h: &mut [u64; 8], block: &[u8; 64], t0: u64, t1: u64) {
    let mut w = [0u64; 8];
    for (word, bytes) in w.iter_mut().zip(block.as_chunks::<8>().0) {
        let mut le = [0u8; 8];
        le.copy_from_slice(bytes);
        *word = u64::from_le_bytes(le);
    }
    let mut ks = [0u64; 9];
    ks[..8].copy_from_slice(h);
    ks[8] = h.iter().fold(KS_PARITY, |acc, word| acc ^ word);
    let ts = [t0, t1, t0 ^ t1];
    let inject = |x: &mut [u64; 8], s: usize| {
        for (i, word) in x.iter_mut().enumerate() {
            *word = word.wrapping_add(ks[(s + i) % 9]);
        }
        x[5] = x[5].wrapping_add(ts[s % 3]);
        x[6] = x[6].wrapping_add(ts[(s + 1) % 3]);
        x[7] = x[7].wrapping_add(s as u64);
    };
    let mut x = w;
    inject(&mut x, 0);
    for round in 0..72 {
        for ((a, b), rotation) in PAIRS[round % 4].iter().zip(ROTATIONS[round % 8]) {
            x[*a] = x[*a].wrapping_add(x[*b]);
            x[*b] = x[*b].rotate_left(rotation) ^ x[*a];
        }
        if round % 4 == 3 {
            inject(&mut x, round / 4 + 1);
        }
    }
    for i in 0..8 {
        h[i] = x[i] ^ w[i];
    }
}

/// Skein-512-256 of `data`.
pub(crate) fn skein512_256(data: &[u8]) -> [u8; 32] {
    let mut h = IV;
    let mut t1 = T1_FIRST | T1_MSG;
    let mut done = 0u64;
    // Every block but the last; the last one, even when full (or empty), is
    // processed with the final flag.
    let mut rest = data;
    while rest.len() > 64 {
        let (chunk, tail) = rest.split_at(64);
        let mut block = [0u8; 64];
        block.copy_from_slice(chunk);
        done += 64;
        process(&mut h, &block, done, t1);
        t1 &= !T1_FIRST;
        rest = tail;
    }
    let mut block = [0u8; 64];
    block[..rest.len()].copy_from_slice(rest);
    done += rest.len() as u64;
    process(&mut h, &block, done, t1 | T1_FINAL);
    // The output: the counter block 0.
    process(&mut h, &[0u8; 64], 8, T1_FIRST | T1_OUT | T1_FINAL);
    let mut out = [0u8; 32];
    for (bytes, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(h) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    out
}
