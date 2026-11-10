//! The BLAKE2s gadget, with the 32-bit words and the batched equality
//! constraints it is built from (`bellman`'s `blake2s`, `uint32` and
//! `multieq` gadgets).

use super::gadgets::{AllocatedBit, Boolean, FQ_CAPACITY};
use crate::prelude::*;
use crate::sapling::field::Fq;
use crate::sapling::groth16::{ConstraintSystem, LinearCombination, SynthesisError};

/// Batches equalities between small integers into as few constraints as
/// possible, by packing them side by side into one field element.
struct MultiEq<'a, CS: ConstraintSystem> {
    cs: &'a mut CS,
    bits_used: usize,
    lhs: LinearCombination,
    rhs: LinearCombination,
}

impl<'a, CS: ConstraintSystem> MultiEq<'a, CS> {
    fn new(cs: &'a mut CS) -> Self {
        MultiEq {
            cs,
            bits_used: 0,
            lhs: LinearCombination::zero(),
            rhs: LinearCombination::zero(),
        }
    }

    fn accumulate(&mut self) {
        let lhs = core::mem::take(&mut self.lhs);
        let rhs = core::mem::take(&mut self.rhs);
        self.cs.enforce(|_| lhs, |lc| lc + CS::one(), |_| rhs);
        self.bits_used = 0;
    }

    /// Enforces `lhs = rhs`, both below `2^num_bits`.
    fn enforce_equal(&mut self, num_bits: usize, lhs: &LinearCombination, rhs: &LinearCombination) {
        if FQ_CAPACITY <= self.bits_used + num_bits {
            self.accumulate();
        }
        let mut coeff = Fq::ONE;
        for _ in 0..self.bits_used {
            coeff = coeff.double();
        }
        self.lhs = core::mem::take(&mut self.lhs) + (coeff, lhs);
        self.rhs = core::mem::take(&mut self.rhs) + (coeff, rhs);
        self.bits_used += num_bits;
    }

    /// Flushes the pending equalities.
    fn finish(mut self) {
        if self.bits_used > 0 {
            self.accumulate();
        }
    }
}

/// A 32-bit word as booleans, least significant first.
#[derive(Clone)]
struct UInt32 {
    bits: [Boolean; 32],
    value: u32,
}

impl UInt32 {
    fn constant(value: u32) -> Self {
        UInt32 {
            bits: core::array::from_fn(|i| Boolean::Constant((value >> i) & 1 == 1)),
            value,
        }
    }

    fn from_bits(bits: [Boolean; 32]) -> Self {
        let value = bits
            .iter()
            .rev()
            .fold(0u32, |acc, b| (acc << 1) | u32::from(b.get_value()));
        UInt32 { bits, value }
    }

    fn rotr(&self, by: usize) -> Self {
        UInt32 {
            bits: core::array::from_fn(|i| self.bits[(i + by) % 32]),
            value: self.value.rotate_right(by as u32),
        }
    }

    fn xor<CS: ConstraintSystem>(&self, cs: &mut CS, other: &Self) -> Result<Self, SynthesisError> {
        let mut bits = [Boolean::Constant(false); 32];
        for (out, (a, b)) in bits.iter_mut().zip(self.bits.iter().zip(&other.bits)) {
            *out = Boolean::xor(cs, a, b)?;
        }
        Ok(UInt32 {
            bits,
            value: self.value ^ other.value,
        })
    }

    /// The sum of the operands modulo `2^32`.
    fn addmany<CS: ConstraintSystem>(
        cs: &mut MultiEq<'_, CS>,
        operands: &[&Self],
    ) -> Result<Self, SynthesisError> {
        let mut max_value = (operands.len() as u64) * u64::from(u32::MAX);
        let mut result_value = 0u64;
        let mut lc = LinearCombination::zero();
        let mut all_constants = true;
        for op in operands {
            result_value += u64::from(op.value);
            let mut coeff = Fq::ONE;
            for bit in &op.bits {
                lc = lc + &bit.lc(CS::one(), coeff);
                all_constants &= bit.is_constant();
                coeff = coeff.double();
            }
        }
        let modular_value = result_value as u32;
        if all_constants {
            return Ok(UInt32::constant(modular_value));
        }

        let mut result_bits = [Boolean::Constant(false); 32];
        let mut result_lc = LinearCombination::zero();
        let mut coeff = Fq::ONE;
        let mut i = 0;
        while max_value != 0 {
            let b = AllocatedBit::alloc(cs.cs, (result_value >> i) & 1 == 1)?;
            result_lc = result_lc + (coeff, b.get_variable());
            if let Some(slot) = result_bits.get_mut(i) {
                *slot = b.into();
            }
            max_value >>= 1;
            i += 1;
            coeff = coeff.double();
        }
        cs.enforce_equal(i, &lc, &result_lc);
        Ok(UInt32 {
            bits: result_bits,
            value: modular_value,
        })
    }
}

const R1: usize = 16;
const R2: usize = 12;
const R3: usize = 8;
const R4: usize = 7;

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

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

fn mixing_g<CS: ConstraintSystem>(
    cs: &mut MultiEq<'_, CS>,
    v: &mut [UInt32; 16],
    (a, b, c, d): (usize, usize, usize, usize),
    x: &UInt32,
    y: &UInt32,
) -> Result<(), SynthesisError> {
    v[a] = UInt32::addmany(cs, &[&v[a], &v[b], x])?;
    v[d] = v[d].xor(cs.cs, &v[a])?.rotr(R1);
    v[c] = UInt32::addmany(cs, &[&v[c], &v[d]])?;
    v[b] = v[b].xor(cs.cs, &v[c])?.rotr(R2);
    v[a] = UInt32::addmany(cs, &[&v[a], &v[b], y])?;
    v[d] = v[d].xor(cs.cs, &v[a])?.rotr(R3);
    v[c] = UInt32::addmany(cs, &[&v[c], &v[d]])?;
    v[b] = v[b].xor(cs.cs, &v[c])?.rotr(R4);
    Ok(())
}

fn blake2s_compression<CS: ConstraintSystem>(
    cs: &mut CS,
    h: &mut [UInt32; 8],
    m: &[UInt32; 16],
    t: u64,
    f: bool,
) -> Result<(), SynthesisError> {
    let mut v: [UInt32; 16] = core::array::from_fn(|i| {
        if i < 8 {
            h[i].clone()
        } else {
            UInt32::constant(IV[i - 8])
        }
    });
    v[12] = v[12].xor(cs, &UInt32::constant(t as u32))?;
    v[13] = v[13].xor(cs, &UInt32::constant((t >> 32) as u32))?;
    if f {
        v[14] = v[14].xor(cs, &UInt32::constant(u32::MAX))?;
    }

    {
        let mut cs = MultiEq::new(cs);
        for s in &SIGMA {
            mixing_g(&mut cs, &mut v, (0, 4, 8, 12), &m[s[0]], &m[s[1]])?;
            mixing_g(&mut cs, &mut v, (1, 5, 9, 13), &m[s[2]], &m[s[3]])?;
            mixing_g(&mut cs, &mut v, (2, 6, 10, 14), &m[s[4]], &m[s[5]])?;
            mixing_g(&mut cs, &mut v, (3, 7, 11, 15), &m[s[6]], &m[s[7]])?;
            mixing_g(&mut cs, &mut v, (0, 5, 10, 15), &m[s[8]], &m[s[9]])?;
            mixing_g(&mut cs, &mut v, (1, 6, 11, 12), &m[s[10]], &m[s[11]])?;
            mixing_g(&mut cs, &mut v, (2, 7, 8, 13), &m[s[12]], &m[s[13]])?;
            mixing_g(&mut cs, &mut v, (3, 4, 9, 14), &m[s[14]], &m[s[15]])?;
        }
        cs.finish();
    }

    for i in 0..8 {
        h[i] = h[i].xor(cs, &v[i])?;
        h[i] = h[i].xor(cs, &v[i + 8])?;
    }
    Ok(())
}

/// BLAKE2s-256 of `input` (a whole number of bytes, each bit least
/// significant first) with the given personalization: the 256 output bits.
pub(super) fn blake2s<CS: ConstraintSystem>(
    cs: &mut CS,
    input: &[Boolean],
    personalization: &[u8; 8],
) -> Result<Vec<Boolean>, SynthesisError> {
    debug_assert!(input.len().is_multiple_of(8));
    let person = |i: usize| {
        u32::from_le_bytes([
            personalization[i],
            personalization[i + 1],
            personalization[i + 2],
            personalization[i + 3],
        ])
    };
    let mut h: [UInt32; 8] = core::array::from_fn(|i| {
        UInt32::constant(match i {
            0 => IV[0] ^ 0x0101_0000 ^ 32,
            6 => IV[6] ^ person(0),
            7 => IV[7] ^ person(4),
            _ => IV[i],
        })
    });

    let block = |bits: &[Boolean]| -> [UInt32; 16] {
        core::array::from_fn(|w| {
            UInt32::from_bits(core::array::from_fn(|i| {
                bits.get(32 * w + i)
                    .copied()
                    .unwrap_or(Boolean::Constant(false))
            }))
        })
    };
    let mut blocks: Vec<[UInt32; 16]> = input.chunks(512).map(block).collect();
    if blocks.is_empty() {
        blocks.push(block(&[]));
    }

    let last = blocks.len() - 1;
    for (i, block) in blocks.iter().enumerate() {
        if i < last {
            blake2s_compression(cs, &mut h, block, (i as u64 + 1) * 64, false)?;
        } else {
            blake2s_compression(cs, &mut h, block, (input.len() / 8) as u64, true)?;
        }
    }
    Ok(h.iter().flat_map(|w| w.bits).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sapling::groth16::TestConstraintSystem;

    #[test]
    fn matches_the_hash() {
        for len in [0usize, 1, 32, 64, 65, 128] {
            let data: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37) ^ 0x5a).collect();
            let mut cs = TestConstraintSystem::new();
            let bits: Vec<Boolean> = crate::sapling::pedersen::bits_le(&data)
                .map(|b| AllocatedBit::alloc(&mut cs, b).map(Boolean::from))
                .collect::<Result<_, _>>()
                .unwrap();
            let out = blake2s(&mut cs, &bits, b"Zcash_nf").unwrap();
            assert!(cs.is_satisfied());
            let expected = crate::sapling::prf::blake2s_256(b"Zcash_nf", &[&data]);
            let expected: Vec<bool> = crate::sapling::pedersen::bits_le(&expected).collect();
            let got: Vec<bool> = out.iter().map(Boolean::get_value).collect();
            assert_eq!(got, expected, "{len}");
        }
    }

    /// The reference gadget's test pins 21518 constraints for a 512-bit
    /// input, the allocation of the input bits included.
    #[test]
    fn constraint_count() {
        let mut cs = TestConstraintSystem::new();
        let bits: Vec<Boolean> = (0..512)
            .map(|i| AllocatedBit::alloc(&mut cs, i % 3 == 0).map(Boolean::from))
            .collect::<Result<_, _>>()
            .unwrap();
        blake2s(&mut cs, &bits, b"12345678").unwrap();
        assert!(cs.is_satisfied());
        assert_eq!(cs.constraints.len(), 21518);
    }
}
