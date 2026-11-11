//! Grøstl-256 (the SHA-3 finalist of Gauravaram, Knudsen, Matusiewicz,
//! Mendel, Rechberger, Schläffer and Thomsen), as `hash_extra_groestl`.

use super::{SBOX, xtime};

/// The state: eight columns of eight bytes, `state[column][row]`, the
/// message bytes filling it column by column.
type State = [[u8; 8]; 8];

const SHIFT_P: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
const SHIFT_Q: [usize; 8] = [1, 3, 5, 7, 0, 2, 4, 6];

/// The permutation `P` (`q` false) or `Q` (`q` true).
fn permute(state: &mut State, q: bool) {
    let shift = if q { &SHIFT_Q } else { &SHIFT_P };
    for round in 0..10u8 {
        // AddRoundConstant.
        for (column, bytes) in state.iter_mut().enumerate() {
            let constant = ((column as u8) << 4) ^ round;
            if q {
                for byte in bytes.iter_mut() {
                    *byte ^= 0xff;
                }
                bytes[7] ^= constant;
            } else {
                bytes[0] ^= constant;
            }
        }
        // SubBytes and ShiftBytes.
        let mut shifted = [[0u8; 8]; 8];
        for (column, bytes) in shifted.iter_mut().enumerate() {
            for (row, byte) in bytes.iter_mut().enumerate() {
                *byte = SBOX[state[(column + shift[row]) % 8][row] as usize];
            }
        }
        // MixBytes: the circulant matrix (02, 02, 03, 04, 05, 03, 05, 07).
        for (column, bytes) in state.iter_mut().enumerate() {
            let a = &shifted[column];
            for (row, byte) in bytes.iter_mut().enumerate() {
                let at = |k: usize| a[(row + k) % 8];
                let x2 = |v: u8| xtime(v);
                let x4 = |v: u8| xtime(xtime(v));
                *byte = x2(at(0))
                    ^ x2(at(1))
                    ^ (x2(at(2)) ^ at(2))
                    ^ x4(at(3))
                    ^ (x4(at(4)) ^ at(4))
                    ^ (x2(at(5)) ^ at(5))
                    ^ (x4(at(6)) ^ at(6))
                    ^ (x4(at(7)) ^ x2(at(7)) ^ at(7));
            }
        }
    }
}

fn compress(h: &mut State, block: &[u8; 64]) {
    let mut p = *h;
    let mut q = [[0u8; 8]; 8];
    for column in 0..8 {
        for row in 0..8 {
            let byte = block[column * 8 + row];
            p[column][row] ^= byte;
            q[column][row] = byte;
        }
    }
    permute(&mut p, false);
    permute(&mut q, true);
    for column in 0..8 {
        for row in 0..8 {
            h[column][row] ^= p[column][row] ^ q[column][row];
        }
    }
}

/// Grøstl-256 of `data`.
pub(crate) fn groestl256(data: &[u8]) -> [u8; 32] {
    // The initial value is the output length in bits, 256, big-endian at the
    // end of the state.
    let mut h = [[0u8; 8]; 8];
    h[7][6] = 0x01;
    let mut blocks = 0u64;
    let (chunks, rest) = data.as_chunks::<64>();
    for chunk in chunks {
        let mut block = [0u8; 64];
        block.copy_from_slice(chunk);
        compress(&mut h, &block);
        blocks += 1;
    }
    let mut block = [0u8; 64];
    block[..rest.len()].copy_from_slice(rest);
    block[rest.len()] = 0x80;
    if rest.len() > 55 {
        compress(&mut h, &block);
        blocks += 1;
        block = [0u8; 64];
    }
    blocks += 1;
    block[56..].copy_from_slice(&blocks.to_be_bytes());
    compress(&mut h, &block);
    // The output transformation: P(h) ^ h, truncated to its last 32 bytes.
    let mut p = h;
    permute(&mut p, false);
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let column = 4 + i / 8;
        let row = i % 8;
        *byte = p[column][row] ^ h[column][row];
    }
    out
}
