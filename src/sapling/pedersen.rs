//! Pedersen hashes and commitments (protocol specification §5.4.1.7,
//! §5.4.8.2 and §5.4.8.3).
//!
//! A Pedersen hash splits its input into segments of 63 three-bit chunks.
//! Chunk `j` of a segment encodes as `(1 - 2·s2)·(1 + s0 + 2·s1)·2^(4j)`,
//! the encodings of a segment sum to a scalar, and each segment's scalar
//! multiplies its own generator
//! ([`pedersen_hash_generator`](super::generators::pedersen_hash_generator)).
//!
//! Inputs are bit sequences, given as iterators of `bool`: [`bits_le`] turns
//! bytes into the little-endian bit order the specification uses
//! throughout.

use super::field::{Fq, Fr};
use super::generators::{
    NOTE_COMMITMENT_RANDOMNESS_BASE, NULLIFIER_POSITION_BASE, PEDERSEN_HASH_CHUNKS_PER_GENERATOR,
    VALUE_COMMITMENT_RANDOMNESS_BASE, VALUE_COMMITMENT_VALUE_BASE, pedersen_hash_generator,
};
use super::jubjub::Point;
use purecrypto::ct::{Choice, ConditionallySelectable};

/// The bits of `bytes`, least significant bit of each byte first
/// (`LEOS2BSP`).
pub fn bits_le(bytes: &[u8]) -> impl Iterator<Item = bool> + Clone + '_ {
    bytes
        .iter()
        .flat_map(|&byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
}

/// The low `n` bits of `value`, least significant first (`I2LEBSP_n`).
pub fn bits_le_u64(value: u64, n: u32) -> impl Iterator<Item = bool> + Clone {
    (0..n).map(move |i| i < 64 && (value >> i) & 1 == 1)
}

/// The encoding `(1 - 2·s2)·(1 + s0 + 2·s1)` of one three-bit chunk: a
/// non-zero integer in `-4..=4`.
pub const fn encode_chunk(s0: bool, s1: bool, s2: bool) -> i8 {
    let magnitude = 1 + s0 as i8 + 2 * s1 as i8;
    if s2 { -magnitude } else { magnitude }
}

/// The scalar `⟨M_i⟩` of one segment: the sum of its chunk encodings, chunk
/// `j` scaled by `2^(4j)`. Consumes up to 63 chunks (189 bits) from `bits`,
/// padding the last chunk with zeros, and returns `None` once `bits` is
/// exhausted.
pub fn encode_segment(bits: &mut impl Iterator<Item = bool>) -> Option<Fr> {
    let mut acc = Fr::ZERO;
    let mut cur = Fr::ONE;
    let mut any = false;
    for _ in 0..PEDERSEN_HASH_CHUNKS_PER_GENERATOR {
        let Some(s0) = bits.next() else { break };
        any = true;
        let s1 = bits.next().unwrap_or(false);
        let s2 = bits.next().unwrap_or(false);
        // branch-free: the input may be the content of a note
        let two = cur.double();
        let mut term = cur;
        term.conditional_assign(&two, Choice::from(u8::from(s0)));
        let with_s1 = term + two;
        term.conditional_assign(&with_s1, Choice::from(u8::from(s1)));
        let negated = -term;
        term.conditional_assign(&negated, Choice::from(u8::from(s2)));
        acc += term;
        cur = two.double().double().double();
    }
    any.then_some(acc)
}

/// `PedersenHashToPoint("Zcash_PH", M)`: the sum over the segments of `M` of
/// `[⟨M_i⟩] I_i`. The hash of the empty sequence is the identity.
pub fn pedersen_hash_to_point(bits: impl IntoIterator<Item = bool>) -> Point {
    let mut bits = bits.into_iter();
    let mut result = Point::IDENTITY;
    let mut segment = 0u32;
    while let Some(scalar) = encode_segment(&mut bits) {
        result += pedersen_hash_generator(segment).mul(&scalar);
        segment += 1;
    }
    result
}

/// `PedersenHash("Zcash_PH", M)`: the `u` coordinate of
/// [`pedersen_hash_to_point`].
pub fn pedersen_hash(bits: impl IntoIterator<Item = bool>) -> Fq {
    pedersen_hash_to_point(bits).to_affine().u()
}

/// `MixingPedersenHash(P, x) = P + [x] J`, which binds a note commitment to
/// its position in the tree.
pub fn mixing_pedersen_hash(p: &Point, x: &Fr) -> Point {
    p.add(&NULLIFIER_POSITION_BASE.to_point().mul(x))
}

/// `WindowedPedersenCommit_r(s) = PedersenHashToPoint("Zcash_PH", s) + [r]
/// FindGroupHash("Zcash_PH", "r")`.
pub fn windowed_pedersen_commit(bits: impl IntoIterator<Item = bool>, r: &Fr) -> Point {
    pedersen_hash_to_point(bits).add(&NOTE_COMMITMENT_RANDOMNESS_BASE.to_point().mul(r))
}

/// `HomomorphicPedersenCommit_rcv("Zcash_cv", v) = [v] V + [rcv] R`, with
/// the value given as a scalar (see [`Fr::from_i64`] for value balances).
pub fn homomorphic_pedersen_commit(value: &Fr, rcv: &Fr) -> Point {
    VALUE_COMMITMENT_VALUE_BASE
        .to_point()
        .mul(value)
        .add(&VALUE_COMMITMENT_RANDOMNESS_BASE.to_point().mul(rcv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sapling::test_vectors::rows;

    #[test]
    fn chunk_encoding() {
        assert_eq!(encode_chunk(false, false, false), 1);
        assert_eq!(encode_chunk(true, false, false), 2);
        assert_eq!(encode_chunk(false, true, false), 3);
        assert_eq!(encode_chunk(true, true, false), 4);
        assert_eq!(encode_chunk(true, true, true), -4);
        assert_eq!(encode_chunk(false, false, true), -1);
        // a segment is the sum of its chunks, scaled
        let bits = [true, false, true, false, true, false, true, true];
        let expect = Fr::from_i64(i64::from(encode_chunk(true, false, true)))
            + Fr::from_i64(i64::from(encode_chunk(false, true, false)) * 16)
            + Fr::from_i64(i64::from(encode_chunk(true, true, false)) * 256);
        let mut iter = bits.into_iter();
        assert_eq!(encode_segment(&mut iter), Some(expect));
        assert_eq!(encode_segment(&mut iter), None);
        assert_eq!(pedersen_hash_to_point([]), Point::IDENTITY);
    }

    #[test]
    fn bit_orders() {
        let bits: Vec<bool> = bits_le(&[0x01, 0x80]).collect();
        assert_eq!(bits.len(), 16);
        assert!(bits[0] && bits[15]);
        assert_eq!(bits.iter().filter(|b| **b).count(), 2);
        let bits: Vec<bool> = bits_le_u64(0b101, 6).collect();
        assert_eq!(bits, [true, false, true, false, false, false]);
    }

    /// The Pedersen hash vectors of `sapling-crypto` (generated by
    /// zcash-test-vectors' `sapling_pedersen.py`).
    #[test]
    fn pedersen_hash_vectors() {
        let vectors = rows(include_str!("testdata/pedersen_hash.json"));
        assert!(vectors.len() > 20);
        for v in &vectors {
            let bits = v[1].as_str().unwrap().bytes().map(|b| b == b'1');
            let p = pedersen_hash_to_point(bits).to_affine();
            let be = |f: Fq| {
                let mut bytes = f.to_bytes();
                bytes.reverse();
                hex::encode(bytes)
            };
            assert_eq!(be(p.u()), v[2].as_str().unwrap());
            assert_eq!(be(p.v()), v[3].as_str().unwrap());
        }
    }
}
