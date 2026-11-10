//! Utility gadgets (port of `halo2_gadgets::utilities`).
//!
//! Specialized to the Pallas base field. The trait layer of the reference
//! (`Var`, `UtilitiesInstructions`, `LookupRangeCheck`) is gone: a circuit
//! variable is an [`AssignedCell`], and [`load_private`] is a function.

use alloc::vec::Vec;
use core::ops::Range;

#[cfg(test)]
use crate::orchard::halo2::Error;
use crate::orchard::halo2::Value;
use crate::orchard::halo2::circuit::AssignedCell;
#[cfg(test)]
use crate::orchard::halo2::circuit::Layouter;
use crate::orchard::halo2::plonk::Expression;
#[cfg(test)]
use crate::orchard::halo2::plonk::{Advice, Column};
use crate::orchard::{Fp, Fq};

pub(crate) mod cond_swap;
pub(crate) mod decompose_running_sum;
pub(crate) mod lookup_range_check;

/// The number of bits of an element of the Pallas base field
/// (`pallas::Base::NUM_BITS`).
const FIELD_NUM_BITS: usize = 255;

/// A type that has a value at either keygen or proving time.
pub(crate) trait FieldValue {
    /// Returns the value of this type.
    fn value(&self) -> Value<&Fp>;
}

impl FieldValue for Value<Fp> {
    fn value(&self) -> Value<&Fp> {
        self.as_ref()
    }
}

impl FieldValue for AssignedCell<Fp> {
    fn value(&self) -> Value<&Fp> {
        self.value()
    }
}

/// A field whose elements have a canonical little-endian bit
/// representation (stands for `ff::PrimeFieldBits`).
pub(crate) trait FieldBits {
    /// Bit `i` (0 being the least significant) of the canonical integer
    /// value; `false` beyond the size of the field.
    fn le_bit(&self, i: usize) -> bool;
}

impl FieldBits for Fp {
    fn le_bit(&self, i: usize) -> bool {
        self.bit(i)
    }
}

impl FieldBits for Fq {
    fn le_bit(&self, i: usize) -> bool {
        self.bit(i)
    }
}

/// Load a variable (`UtilitiesInstructions::load_private`): one region
/// holding `value` in `column` at offset 0.
#[cfg(test)]
pub(crate) fn load_private(
    layouter: &mut Layouter<'_>,
    column: Column<Advice>,
    value: Value<Fp>,
) -> Result<AssignedCell<Fp>, Error> {
    layouter.assign_region(|mut region| region.assign_advice(column, 0, || value))
}

/// A type representing a range-constrained field element.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RangeConstrained<T: FieldValue> {
    inner: T,
    num_bits: usize,
}

impl<T: FieldValue> RangeConstrained<T> {
    /// Returns the range-constrained inner type.
    pub(crate) fn inner(&self) -> &T {
        &self.inner
    }

    /// Returns the number of bits to which this cell is constrained.
    pub(crate) fn num_bits(&self) -> usize {
        self.num_bits
    }
}

impl RangeConstrained<Value<Fp>> {
    /// Constructs a `RangeConstrained<Value<Fp>>` as a bitrange of the given
    /// value.
    pub(crate) fn bitrange_of(value: Value<&Fp>, bitrange: Range<usize>) -> Self {
        let num_bits = bitrange.len();
        Self {
            inner: value.map(|value| bitrange_subset(value, bitrange)),
            num_bits,
        }
    }
}

impl RangeConstrained<AssignedCell<Fp>> {
    /// Constructs a `RangeConstrained<AssignedCell<Fp>>` without verifying
    /// that the cell is correctly range constrained.
    pub(crate) fn unsound_unchecked(cell: AssignedCell<Fp>, num_bits: usize) -> Self {
        Self {
            inner: cell,
            num_bits,
        }
    }

    /// Extracts the range-constrained value from this range-constrained
    /// cell.
    pub(crate) fn value(&self) -> RangeConstrained<Value<Fp>> {
        RangeConstrained {
            inner: self.inner.value().copied(),
            num_bits: self.num_bits,
        }
    }
}

/// Checks that an expression is either 1 or 0.
pub(crate) fn bool_check(value: Expression) -> Expression {
    range_check(value, 2)
}

/// If `a` then `b`, else `c`. Returns (a * b) + (1 - a) * c.
///
/// `a` must be a boolean-constrained expression.
pub(crate) fn ternary(a: Expression, b: Expression, c: Expression) -> Expression {
    let one_minus_a = Expression::Constant(Fp::ONE) - a.clone();
    a * b + one_minus_a * c
}

/// Takes a specified subsequence of the little-endian bit representation of
/// a field element. The bits are numbered from 0 for the LSB.
///
/// # Panics
/// Panics if the range ends beyond the 255 bits of a field element.
pub(crate) fn bitrange_subset(field_elem: &Fp, bitrange: Range<usize>) -> Fp {
    // A subsequence of length NUM_BITS is allowed, because the bits are
    // those of the canonical representation.
    assert!(bitrange.end <= FIELD_NUM_BITS);

    bitrange.rev().fold(Fp::ZERO, |acc, i| {
        if field_elem.bit(i) {
            acc.double() + Fp::ONE
        } else {
            acc.double()
        }
    })
}

/// Check that an expression is in the small range [0..range),
/// i.e. 0 ≤ word < range.
pub(crate) fn range_check(word: Expression, range: usize) -> Expression {
    (1..range).fold(word.clone(), |acc, i| {
        acc * (Expression::Constant(Fp::from_u64(i as u64)) - word.clone())
    })
}

/// Decompose a word `alpha` into `window_num_bits` bits (little-endian).
/// For a window size of `w`, this returns [k_0, ..., k_n] where each `k_i`
/// is a `w`-bit value, and `scalar = k_0 + k_1 * w + k_n * w^n`.
///
/// # Panics
/// Panics if the window size is larger than 8 bits.
pub(crate) fn decompose_word<F: FieldBits>(
    word: &F,
    word_num_bits: usize,
    window_num_bits: usize,
) -> Vec<u8> {
    assert!(window_num_bits <= 8);

    // Pad bits to multiple of window_num_bits
    let padding = (window_num_bits - (word_num_bits % window_num_bits)) % window_num_bits;
    let bits: Vec<bool> = (0..word_num_bits)
        .map(|i| word.le_bit(i))
        .chain(core::iter::repeat_n(false, padding))
        .collect();
    assert_eq!(bits.len(), word_num_bits + padding);

    bits.chunks_exact(window_num_bits)
        .map(|chunk| chunk.iter().rev().fold(0, |acc, b| (acc << 1) + (*b as u8)))
        .collect()
}

/// The u64 integer represented by an L-bit little-endian bitstring.
///
/// # Panics
/// Panics if the bitstring is longer than 64 bits.
pub(crate) fn lebs2ip<const L: usize>(bits: &[bool; L]) -> u64 {
    assert!(L <= 64);
    bits.iter()
        .enumerate()
        .fold(0u64, |acc, (i, b)| acc + if *b { 1 << i } else { 0 })
}

/// The sequence of bits representing a u64 in little-endian order.
///
/// # Panics
/// Panics if the expected length of the sequence `NUM_BITS` exceeds 64.
pub(crate) fn i2lebsp<const NUM_BITS: usize>(int: u64) -> [bool; NUM_BITS] {
    assert!(NUM_BITS <= 64);
    core::array::from_fn(|mask| (int & (1 << mask)) != 0)
}

/// Helpers of the tests of this module and its children: dumps of a
/// constraint system and of a synthesized circuit in the text format of the
/// reference dumper, and their digests.
///
/// The expected digests in the tests were produced by running the gadgets of
/// `halo2_gadgets` 0.6.0 on `halo2_proofs` 0.4.1 in the same test circuits
/// (with the `V1` floor planner), in the scratch project
/// `/tmp/claude-1000/sp/ref-utilities/` (`cargo run`): for each circuit it
/// prints the BLAKE2b-256 digest of `format!("{:?}", cs.pinned())` after
/// `configure`, and that of the layout text below, obtained from a
/// recording `Assignment` backend.
#[cfg(test)]
pub(crate) mod test_dump {
    use alloc::format;
    use alloc::string::String;

    use crate::orchard::Fp;
    use crate::orchard::halo2::circuit::Circuit;
    use crate::orchard::halo2::dev::MockProver;
    use crate::orchard::halo2::plonk::{
        Any, Column, ConstraintSystem, Hex, PinnedConstraintSystem,
    };

    /// `<length>:<BLAKE2b-256 in hex>` of a dump.
    pub(crate) fn digest(s: &str) -> String {
        format!(
            "{}:{}",
            s.len(),
            hex::encode(purecrypto::hash::blake2b256(s.as_bytes()))
        )
    }

    /// The digest of the pinned constraint system of a circuit, before
    /// selector compression.
    pub(crate) fn pinned_digest<C: Circuit>(circuit: &C) -> String {
        let mut cs = ConstraintSystem::default();
        circuit.configure(&mut cs);
        digest(&format!("{:?}", PinnedConstraintSystem(&cs)))
    }

    fn column(c: &Column<Any>) -> String {
        format!("{:?} {}", c.column_type(), c.index())
    }

    /// The layout of a synthesized circuit: the rows each selector is
    /// enabled on, the nonzero fixed and advice cells, and the copy
    /// constraints in the order they were made.
    pub(crate) fn layout(prover: &MockProver) -> String {
        let mut out = String::new();
        for (i, rows) in prover.selectors.iter().enumerate() {
            for (row, on) in rows.iter().enumerate() {
                if *on {
                    out.push_str(&format!("selector {i} {row}\n"));
                }
            }
        }
        for (name, columns) in [("fixed", &prover.fixed), ("advice", &prover.advice)] {
            for (i, cells) in columns.iter().enumerate() {
                for (row, v) in cells.iter().enumerate() {
                    if *v != Fp::ZERO {
                        out.push_str(&format!("{name} {i} {row} {:?}\n", Hex(v)));
                    }
                }
            }
        }
        for ((lc, lr), (rc, rr)) in prover.copies.iter() {
            out.push_str(&format!("copy {} {lr} {} {rr}\n", column(lc), column(rc)));
        }
        out
    }

    /// The digest of the layout of a circuit synthesized on `2^k` rows.
    pub(crate) fn layout_digest<C: Circuit>(k: u32, circuit: &C) -> String {
        let prover = MockProver::run(k, circuit, alloc::vec![]).unwrap();
        digest(&layout(&prover))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::test_dump::{layout_digest, pinned_digest};
    use super::*;
    use crate::orchard::halo2::circuit::Circuit;
    use crate::orchard::halo2::dev::MockProver;
    use crate::orchard::halo2::plonk::{ConstraintSystem, Constraints, Rotation, Selector};

    /// The `test_range_check` circuit of the reference.
    struct MyCircuit<const RANGE: usize>(u8);

    #[derive(Clone)]
    struct Config {
        selector: Selector,
        advice: Column<Advice>,
    }

    impl<const RANGE: usize> Circuit for MyCircuit<RANGE> {
        type Config = Config;

        fn without_witnesses(&self) -> Self {
            MyCircuit(self.0)
        }

        fn configure(&self, meta: &mut ConstraintSystem) -> Config {
            let selector = meta.selector();
            let advice = meta.advice_column();

            meta.create_gate("range check", |meta| {
                let selector = meta.query_selector(selector);
                let advice = meta.query_advice(advice, Rotation::cur());

                Constraints::with_selector(selector, Some(range_check(advice, RANGE)))
            });

            Config { selector, advice }
        }

        fn synthesize(&self, config: Config, layouter: &mut Layouter<'_>) -> Result<(), Error> {
            layouter.assign_region(|mut region| {
                config.selector.enable(&mut region, 0)?;
                region.assign_advice(config.advice, 0, || {
                    Value::known(Fp::from_u64(self.0 as u64))
                })?;
                Ok(())
            })
        }
    }

    #[test]
    fn test_range_check() {
        for i in 0..8 {
            let circuit: MyCircuit<8> = MyCircuit(i);
            let prover = MockProver::run(3, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
        {
            let circuit: MyCircuit<8> = MyCircuit(8);
            let prover = MockProver::run(3, &circuit, vec![]).unwrap();
            assert!(prover.verify().unwrap_err().contains("gate 'range check'"));
        }
    }

    /// The gate and the layout are those of the reference (see
    /// [`test_dump`]).
    #[test]
    fn range_check_matches_reference() {
        let circuit: MyCircuit<8> = MyCircuit(5);
        assert_eq!(
            pinned_digest(&circuit),
            "1608:6d33ea08b9ac0513eea302dfc453ec35b308ac9e6a2445abc448c0c1faff67b9"
        );
        assert_eq!(
            layout_digest(3, &circuit),
            "91:fdd70f106db024ce172cda2f3943cea87fea4df82d7633db2ea7202ebb7a6ca2"
        );
    }

    /// A gate of `bool_check` and `ternary` expressions, compared with the
    /// reference.
    struct ExprCircuit;

    impl Circuit for ExprCircuit {
        type Config = ();

        fn without_witnesses(&self) -> Self {
            ExprCircuit
        }

        fn configure(&self, meta: &mut ConstraintSystem) {
            let advices = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];
            meta.create_gate("exprs", |meta| {
                let a = meta.query_advice(advices[0], Rotation::cur());
                let b = meta.query_advice(advices[1], Rotation::cur());
                let c = meta.query_advice(advices[2], Rotation::next());
                vec![bool_check(a.clone()), ternary(a, b, c)]
            });
        }

        fn synthesize(&self, _: (), _: &mut Layouter<'_>) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn expressions_match_reference() {
        assert_eq!(
            pinned_digest(&ExprCircuit),
            "1059:81f0a4c7f66f6ea72db5db6205d5d21634a641e8fc7ed18cee1721e49779e28a"
        );
    }

    /// A few field elements covering the whole range of bit lengths.
    fn samples() -> Vec<Fp> {
        let mut out = vec![Fp::ZERO, Fp::ONE, -Fp::ONE, Fp::from_u64(u64::MAX)];
        let mut x = Fp::from_u64(0x1234_5678_9abc_def1);
        for _ in 0..8 {
            x = x.square() + Fp::from_u64(7);
            out.push(x);
        }
        out
    }

    #[test]
    #[allow(clippy::single_range_in_vec_init)]
    fn test_bitrange_subset() {
        for field_elem in samples() {
            // Subset full range.
            assert_eq!(field_elem, bitrange_subset(&field_elem, 0..FIELD_NUM_BITS));
            // Subset zero bits.
            assert_eq!(Fp::ZERO, bitrange_subset(&field_elem, 0..0));

            // Decompose the field element into pieces using consecutive
            // ranges, and check that we recover the original.
            let decompose = |ranges: &[Range<usize>]| {
                assert_eq!(ranges[0].start, 0);
                assert_eq!(ranges.last().unwrap().end, FIELD_NUM_BITS);
                let mut sum = Fp::ZERO;
                let mut next = 0;
                for range in ranges {
                    assert_eq!(range.start, next);
                    next = range.end;
                    // 2^start
                    let mut shift = Fp::ONE;
                    for _ in 0..range.start {
                        shift = shift.double();
                    }
                    sum += bitrange_subset(&field_elem, range.clone()) * shift;
                }
                assert_eq!(field_elem, sum);
            };
            decompose(&[0..255]);
            decompose(&[0..1, 1..255]);
            decompose(&[0..254, 254..255]);
            decompose(&[0..127, 127..255]);
            decompose(&[0..128, 128..255]);
            decompose(&[0..50, 50..100, 100..150, 150..200, 200..255]);
        }
    }

    #[test]
    fn test_decompose_word() {
        let mut scalars = vec![Fq::ZERO, Fq::ONE, -Fq::ONE];
        let mut x = Fq::from_u64(0xfedc_ba98_7654_3211);
        for _ in 0..6 {
            x = x.square() + Fq::from_u64(3);
            scalars.push(x);
        }
        for scalar in scalars {
            for window_num_bits in 1usize..9 {
                // Get decomposition into `window_num_bits` bits
                let decomposed = decompose_word(&scalar, 255, window_num_bits);
                assert_eq!(decomposed.len(), 255usize.div_ceil(window_num_bits));

                // Flatten bits
                let bits: Vec<bool> = decomposed
                    .iter()
                    .flat_map(|window| {
                        (0..window_num_bits).map(move |mask| (window >> mask) & 1 == 1)
                    })
                    .collect();

                // Ensure this decomposition contains 256 or fewer set bits.
                assert!(!bits.iter().skip(32 * 8).any(|b| *b));

                // Check that original scalar is recovered from decomposition
                let mut bytes = [0u8; 32];
                for (i, bit) in bits.iter().enumerate().take(256) {
                    bytes[i / 8] |= (*bit as u8) << (i % 8);
                }
                assert_eq!(bytes, scalar.to_bytes());
            }
        }
    }

    #[test]
    fn lebs2ip_round_trip() {
        for int in [0, 1, 0x0123_4567_89ab_cdef, 0xFFFF_FFFF_FFFF_FFFF] {
            assert_eq!(lebs2ip::<64>(&i2lebsp(int)), int);
        }
        assert_eq!(lebs2ip::<10>(&i2lebsp(0x2a5)), 0x2a5);
        assert_eq!(lebs2ip::<4>(&i2lebsp(0x2a5)), 5);
    }

    #[test]
    fn i2lebsp_round_trip() {
        let mut bitstring = [false; 64];
        for (i, b) in bitstring.iter_mut().enumerate() {
            *b = (i * i + i / 3) % 3 == 1;
        }
        assert_eq!(i2lebsp::<64>(lebs2ip::<64>(&bitstring)), bitstring);
        assert_eq!(i2lebsp(lebs2ip(&[false; 64])), [false; 64]);
        assert_eq!(i2lebsp(lebs2ip(&[true; 64])), [true; 64]);
        let empty: [bool; 0] = [];
        assert_eq!(i2lebsp(lebs2ip(&empty)), empty);
    }
}
