//! RingCT basics: the second generator `H`, Pedersen commitments, and the
//! multi-scalar multiplication the proofs are built on.

use purecrypto::ct::Choice;
use purecrypto::zeroize::Zeroize;

use super::Error;
use crate::cryptonote::{
    EdwardsPoint, FieldElement, Scalar, point_from_bytes, scalar_from_bytes, scalar_from_u64,
};

/// The generator `H` of amounts in a Pedersen commitment
/// `mask * G + amount * H`: `8 * decompress(cn_fast_hash(G))`.
pub const H: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

/// `1 / 8` modulo the group order: proofs store their points divided by the
/// cofactor, so that the verifier's multiplication by 8 clears any torsion.
const INV_EIGHT: [u8; 32] = [
    0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
];

/// The point `H`.
pub(crate) fn h_point() -> EdwardsPoint {
    // The constant is a valid point (checked by the tests).
    EdwardsPoint::decompress(&H).unwrap_or_else(EdwardsPoint::identity)
}

/// The scalar `1 / 8`.
pub(crate) fn inv_eight() -> Scalar {
    Scalar::from_bytes_canonical(&INV_EIGHT).unwrap_or(Scalar::ONE)
}

/// The Pedersen commitment `mask * G + amount * H` to `amount`, blinded by
/// `mask` (`rct::commit`). Constant-time in both.
///
/// Fails with [`Error::CryptoNote`] if `mask` is not a reduced scalar.
pub fn commit(amount: u64, mask: &[u8; 32]) -> Result<[u8; 32], Error> {
    Ok(commit_point(&scalar_from_u64(amount), &scalar_from_bytes(mask)?).compress())
}

/// `mask * G + amount * H`, constant-time.
pub(crate) fn commit_point(amount: &Scalar, mask: &Scalar) -> EdwardsPoint {
    EdwardsPoint::mul_base(mask).add(&h_point().mul(amount))
}

/// The commitment `G + amount * H` to a public `amount`, with the mask 1
/// (`rct::zeroCommit`): what stands for the commitment of an output whose
/// amount is in the clear, such as a coinbase output. Variable-time.
pub fn zero_commit(amount: u64) -> [u8; 32] {
    EdwardsPoint::double_scalar_mul_base_vartime(&scalar_from_u64(amount), &h_point(), &Scalar::ONE)
        .compress()
}

/// Whether the commitments balance: the sum of `inputs` (the pseudo-output
/// commitments of a transaction) equals the sum of `outputs` plus
/// `fee * H`. Variable-time, for public data.
///
/// Fails with [`Error::CryptoNote`] if one of them is not a curve point.
pub fn verify_balance(inputs: &[[u8; 32]], outputs: &[[u8; 32]], fee: u64) -> Result<bool, Error> {
    let mut sum = EdwardsPoint::identity();
    for commitment in inputs {
        sum = sum.add(&point_from_bytes(commitment)?);
    }
    for commitment in outputs {
        sum = sum.sub(&point_from_bytes(commitment)?);
    }
    let fee = EdwardsPoint::double_scalar_mul_base_vartime(
        &scalar_from_u64(fee),
        &h_point(),
        &Scalar::ZERO,
    );
    Ok(sum == fee)
}

/// `a` if `choice` is set, otherwise `b`, without branching on `choice`.
#[cfg(feature = "alloc")]
pub(crate) fn select_point(a: &EdwardsPoint, b: &EdwardsPoint, choice: Choice) -> EdwardsPoint {
    let (a, b) = (a.to_extended(), b.to_extended());
    let mut out = [FieldElement::ZERO; 4];
    for ((o, a), b) in out.iter_mut().zip(&a).zip(&b) {
        *o = FieldElement::conditional_select(a, b, choice);
    }
    // The coordinates are those of one of two valid points.
    EdwardsPoint::from_extended(&out).unwrap_or_else(EdwardsPoint::identity)
}

/// Scratch space of [`multiexp`] for one point: its multiples
/// `0 * P .. 15 * P` and the bytes of its scalar.
#[derive(Clone)]
pub(crate) struct Table {
    multiples: [EdwardsPoint; 16],
    scalar: [u8; 32],
}

impl Table {
    /// An empty table, to be filled by [`multiexp`].
    pub(crate) fn new() -> Table {
        Table {
            multiples: [EdwardsPoint::identity(); 16],
            scalar: [0u8; 32],
        }
    }

    /// The 4-bit window `index` of the scalar (0 is the least significant).
    fn nibble(&self, index: usize) -> u8 {
        let byte = self.scalar.get(index / 2).copied().unwrap_or(0);
        (byte >> ((index % 2) * 4)) & 0x0f
    }
}

/// The multi-scalar multiplication `sum(scalars[i] * points[i])` (Straus's
/// method with 4-bit windows; the points share the doublings in groups of
/// `tables.len()`, which must not be zero).
///
/// With `constant_time`, every window adds a table entry picked without
/// branching or indexing on the scalar, for secret scalars; without, zero
/// windows are skipped and the entries are indexed directly, which is only
/// fit for public scalars. The scratch space is wiped before returning.
pub(crate) fn multiexp(
    scalars: &[Scalar],
    points: &[EdwardsPoint],
    tables: &mut [Table],
    constant_time: bool,
) -> EdwardsPoint {
    let group = tables.len().max(1);
    let mut total = EdwardsPoint::identity();
    for (scalars, points) in scalars.chunks(group).zip(points.chunks(group)) {
        let mut used = 0usize;
        for ((table, point), scalar) in tables.iter_mut().zip(points).zip(scalars) {
            let mut multiple = EdwardsPoint::identity();
            for entry in table.multiples.iter_mut() {
                *entry = multiple;
                multiple = multiple.add(point);
            }
            table.scalar = scalar.to_bytes();
            used += 1;
        }
        let tables = tables.get(..used).unwrap_or(&[]);
        total = total.add(&straus(tables, constant_time));
    }
    for table in tables.iter_mut() {
        table.scalar.zeroize();
    }
    total
}

/// One group of [`multiexp`].
fn straus(tables: &[Table], constant_time: bool) -> EdwardsPoint {
    let mut acc = EdwardsPoint::identity();
    let mut started = constant_time;
    // 64 windows of 4 bits, most significant first.
    for window in (0..64usize).rev() {
        if started {
            acc = acc.double().double().double().double();
        }
        for table in tables {
            let digit = table.nibble(window);
            if constant_time {
                let mut entry = [FieldElement::ZERO; 4];
                for (i, candidate) in table.multiples.iter().enumerate() {
                    // i < 16
                    let equal = ct_eq_u8(i as u8, digit);
                    for (e, c) in entry.iter_mut().zip(&candidate.to_extended()) {
                        *e = FieldElement::conditional_select(c, e, equal);
                    }
                }
                // Exactly one candidate matched: the coordinates are its own.
                if let Some(entry) = EdwardsPoint::from_extended(&entry) {
                    acc = acc.add(&entry);
                }
            } else if digit != 0
                && let Some(entry) = table.multiples.get(usize::from(digit))
            {
                acc = acc.add(entry);
                started = true;
            }
        }
    }
    acc
}

/// Whether two bytes are equal, without branching.
fn ct_eq_u8(a: u8, b: u8) -> Choice {
    let x = u32::from(a ^ b);
    // x is in 0..=255: x - 1 borrows into the high bits only for x = 0.
    Choice::from(((x.wrapping_sub(1) >> 8) & 1) as u8)
}
