//! The Keccak sponge with the rates Zano uses beside Keccak-256: hard fork
//! 6 derives a ChaCha20 key and nonce as 40 bytes of Keccak with a
//! capacity of 640 bits (`keccak()` of `crypto/keccak.c`, whose rate
//! follows the output length), which `purecrypto` does not offer.

use purecrypto::zeroize::Zeroize;

/// The round constants of Keccak-f[1600].
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];
/// The rotation of each lane, in the order rho and pi visit them.
const ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
/// The lane each step of rho and pi writes.
const PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The permutation Keccak-f[1600].
fn keccak_f(st: &mut [u64; 25]) {
    for rc in RC {
        // Theta.
        let mut bc = [0u64; 5];
        for (i, column) in bc.iter_mut().enumerate() {
            *column = (0..5).fold(0, |acc, row| acc ^ st[i + 5 * row]);
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for row in 0..5 {
                st[i + 5 * row] ^= t;
            }
        }
        // Rho and pi.
        let mut t = st[1];
        for (lane, rotation) in PILN.into_iter().zip(ROTC) {
            let next = st[lane];
            st[lane] = t.rotate_left(rotation);
            t = next;
        }
        // Chi.
        for row in st.as_chunks_mut::<5>().0 {
            let copy = *row;
            for (i, lane) in row.iter_mut().enumerate() {
                *lane ^= !copy[(i + 1) % 5] & copy[(i + 2) % 5];
            }
        }
        // Iota.
        st[0] ^= rc;
    }
}

/// XORs a block of the rate into the state.
fn absorb(st: &mut [u64; 25], block: &[u8]) {
    for (lane, bytes) in st.iter_mut().zip(block.as_chunks::<8>().0) {
        *lane ^= u64::from_le_bytes(*bytes);
    }
}

/// Keccak with the original padding (`0x01 ... 0x80`), a capacity of twice
/// the output and a single squeeze: `keccak(in, inlen, md, mdlen)` of
/// Zano's `crypto/keccak.c`.
///
/// `out` holds from 1 to 64 bytes (a rate of 198 down to 72 bytes); it is
/// left untouched otherwise.
pub(crate) fn keccak(input: &[u8], out: &mut [u8]) {
    if out.is_empty() || out.len() > 64 {
        return;
    }
    // The reference XORs whole lanes: the rate rounded down to one.
    let rate = 200 - 2 * out.len();
    let lanes = rate / 8;
    let mut st = [0u64; 25];
    let mut blocks = input.chunks_exact(rate);
    for block in &mut blocks {
        absorb(&mut st, &block[..lanes * 8]);
        keccak_f(&mut st);
    }
    let rest = blocks.remainder();
    let mut last = [0u8; 200];
    if let Some(head) = last.get_mut(..rest.len()) {
        head.copy_from_slice(rest);
    }
    if let Some(byte) = last.get_mut(rest.len()) {
        *byte = 1;
    }
    if let Some(byte) = last.get_mut(rate - 1) {
        *byte |= 0x80;
    }
    absorb(&mut st, &last[..lanes * 8]);
    keccak_f(&mut st);

    let mut bytes = [0u8; 200];
    for (chunk, lane) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(&st) {
        *chunk = lane.to_le_bytes();
    }
    if let Some(head) = bytes.get(..out.len()) {
        out.copy_from_slice(head);
    }
    st.zeroize();
    last.zeroize();
    bytes.zeroize();
}
