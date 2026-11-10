//! The Poseidon hash Orchard derives nullifiers with: the `P128Pow5T3`
//! instance (width 3, rate 2, S-box `x^5`, 8 full and 56 partial rounds) over
//! the Pallas base field.

use super::fields::Fp;

mod constants;

/// The width of the permutation.
pub const WIDTH: usize = 3;
/// The rate of the sponge.
pub const RATE: usize = 2;
/// The number of full rounds (half before, half after the partial rounds).
pub const FULL_ROUNDS: usize = 8;
/// The number of partial rounds.
pub const PARTIAL_ROUNDS: usize = 56;

/// The round constants, one row of three per round.
pub const ROUND_CONSTANTS: [[Fp; WIDTH]; FULL_ROUNDS + PARTIAL_ROUNDS] = {
    let mut out = [[Fp::ZERO; WIDTH]; FULL_ROUNDS + PARTIAL_ROUNDS];
    let mut i = 0;
    while i < out.len() {
        let mut j = 0;
        while j < WIDTH {
            out[i][j] = Fp::from_raw(constants::ROUND_CONSTANTS_RAW[i][j]);
            j += 1;
        }
        i += 1;
    }
    out
};

/// The MDS matrix, by rows.
pub const MDS: [[Fp; WIDTH]; WIDTH] = {
    let mut out = [[Fp::ZERO; WIDTH]; WIDTH];
    let mut i = 0;
    while i < WIDTH {
        let mut j = 0;
        while j < WIDTH {
            out[i][j] = Fp::from_raw(constants::MDS_RAW[i][j]);
            j += 1;
        }
        i += 1;
    }
    out
};

#[inline]
fn sbox(x: Fp) -> Fp {
    x.square().square() * x
}

/// Applies the Poseidon permutation to `state`.
pub fn permute(state: &mut [Fp; WIDTH]) {
    let half = FULL_ROUNDS / 2;
    for (round, constants) in ROUND_CONSTANTS.iter().enumerate() {
        for (s, c) in state.iter_mut().zip(constants) {
            *s += *c;
        }
        if round < half || round >= half + PARTIAL_ROUNDS {
            for s in state.iter_mut() {
                *s = sbox(*s);
            }
        } else {
            state[0] = sbox(state[0]);
        }
        let mut next = [Fp::ZERO; WIDTH];
        for (n, row) in next.iter_mut().zip(&MDS) {
            *n = row[0] * state[0] + row[1] * state[1] + row[2] * state[2];
        }
        *state = next;
    }
}

/// The Poseidon hash of two field elements (a sponge of rate 2 over
/// [`permute`] with the constant-length domain of length 2).
pub fn hash(a: Fp, b: Fp) -> Fp {
    // the capacity element encodes the input length: 2 * 2^64
    let mut state = [a, b, Fp::from_u128(2 << 64)];
    permute(&mut state);
    state[0]
}

/// The Grain LFSR in self-shrinking mode the Poseidon paper generates its
/// constants with.
struct Grain {
    state: [bool; 80],
    next_bit: usize,
}

impl Grain {
    fn new(t: u16, r_f: u16, r_p: u16) -> Self {
        let mut state = [true; 80];
        let mut set_bits = |offset: usize, len: usize, value: u16| {
            for i in 0..len {
                state[offset + len - 1 - i] = (value >> i) & 1 != 0;
            }
        };
        set_bits(0, 2, 1); // prime field
        set_bits(2, 4, 0); // x^alpha S-box
        set_bits(6, 12, Fp::NUM_BITS as u16);
        set_bits(18, 12, t);
        set_bits(30, 10, r_f);
        set_bits(40, 10, r_p);
        let mut grain = Grain {
            state,
            next_bit: 80,
        };
        // discard the first 160 bits
        for _ in 0..20 {
            grain.load_next_8_bits();
            grain.next_bit = 80;
        }
        grain
    }

    fn load_next_8_bits(&mut self) {
        let s = &self.state;
        let mut new_bits = [false; 8];
        for (i, bit) in new_bits.iter_mut().enumerate() {
            *bit = s[i + 62] ^ s[i + 51] ^ s[i + 38] ^ s[i + 23] ^ s[i + 13] ^ s[i];
        }
        self.state.rotate_left(8);
        self.next_bit -= 8;
        self.state[self.next_bit..self.next_bit + 8].copy_from_slice(&new_bits);
    }

    fn raw_bit(&mut self) -> bool {
        if self.next_bit == 80 {
            self.load_next_8_bits();
        }
        let bit = self.state[self.next_bit];
        self.next_bit += 1;
        bit
    }

    /// The next bit of the shrunk stream: pairs of bits whose first is 0
    /// are skipped.
    fn bit(&mut self) -> bool {
        while !self.raw_bit() {
            self.raw_bit();
        }
        self.raw_bit()
    }

    /// 255 bits, most significant first, as a little-endian integer.
    fn bits(&mut self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        for i in (0..Fp::NUM_BITS as usize).rev() {
            if self.bit() {
                bytes[i / 8] |= 1 << (i % 8);
            }
        }
        bytes
    }

    fn field_element(&mut self) -> Fp {
        loop {
            let bytes = self.bits();
            if let Some(f) = Fp::from_bytes(bytes[..32].try_into().expect("32 bytes")) {
                return f;
            }
        }
    }

    fn field_element_without_rejection(&mut self) -> Fp {
        Fp::from_uniform_bytes(&self.bits())
    }
}

/// Recomputes the round constants, the MDS matrix and its inverse with the
/// Grain LFSR procedure of the Poseidon paper (as `halo2_poseidon` does).
/// [`ROUND_CONSTANTS`] and [`MDS`] are the precomputed result.
#[allow(clippy::type_complexity)]
pub fn generate_constants() -> (
    [[Fp; WIDTH]; FULL_ROUNDS + PARTIAL_ROUNDS],
    [[Fp; WIDTH]; WIDTH],
    [[Fp; WIDTH]; WIDTH],
) {
    let mut grain = Grain::new(WIDTH as u16, FULL_ROUNDS as u16, PARTIAL_ROUNDS as u16);
    let mut round_constants = [[Fp::ZERO; WIDTH]; FULL_ROUNDS + PARTIAL_ROUNDS];
    for row in round_constants.iter_mut() {
        for c in row.iter_mut() {
            *c = grain.field_element();
        }
    }
    // a Cauchy matrix from the first 2 * WIDTH distinct elements
    let (xs, ys) = loop {
        let mut vals = [Fp::ZERO; 2 * WIDTH];
        for v in vals.iter_mut() {
            *v = grain.field_element_without_rejection();
        }
        let distinct = (0..vals.len()).all(|i| (0..i).all(|j| vals[i] != vals[j]));
        if distinct {
            let xs: [Fp; WIDTH] = vals[..WIDTH].try_into().expect("WIDTH elements");
            let ys: [Fp; WIDTH] = vals[WIDTH..].try_into().expect("WIDTH elements");
            break (xs, ys);
        }
    };
    let mut mds = [[Fp::ZERO; WIDTH]; WIDTH];
    for (row, x) in mds.iter_mut().zip(&xs) {
        for (m, y) in row.iter_mut().zip(&ys) {
            *m = (*x + *y).invert_or_zero();
        }
    }
    // the inverse of a Cauchy matrix, by Lagrange polynomials
    let l = |xs: &[Fp; WIDTH], j: usize, x: Fp| {
        let mut acc = Fp::ONE;
        for (m, x_m) in xs.iter().enumerate() {
            if m != j {
                acc = acc * (x - *x_m) * (xs[j] - *x_m).invert_or_zero();
            }
        }
        acc
    };
    let neg_ys = ys.map(|y| -y);
    let mut mds_inv = [[Fp::ZERO; WIDTH]; WIDTH];
    for (i, row) in mds_inv.iter_mut().enumerate() {
        for (j, m) in row.iter_mut().enumerate() {
            *m = (xs[j] - neg_ys[i]) * l(&xs, j, neg_ys[i]) * l(&neg_ys, i, xs[j]);
        }
    }
    (round_constants, mds, mds_inv)
}
