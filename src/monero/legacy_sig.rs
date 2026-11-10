//! Verification of the signatures and range proofs of the old transaction
//! formats: the CryptoNote ring signature of version 1 transactions
//! (`crypto::check_ring_signature`) and the Borromean range proof of RingCT
//! types 1 and 2 (`rct::verRange`). With `alloc`, the MLSAG ring signature
//! of RingCT types 1 to 4 (`rct::MLSAG_Ver`).
//!
//! Nothing here signs: these formats can no longer be put on the chain.

use super::ringct::{Table, h_point, multiexp};
use crate::cryptonote::{
    EdwardsPoint, Hasher, Scalar, point_from_bytes, point_from_hash, scalar_from_bytes,
    scalar_from_u64, scalar_reduce,
};

#[cfg(feature = "alloc")]
use super::Error;
#[cfg(feature = "alloc")]
use super::clsag::RingMember;
#[cfg(feature = "alloc")]
use super::tx::Mlsag;
#[cfg(feature = "alloc")]
use crate::prelude::*;

/// The size of a Borromean range proof: 64 pairs of scalars, a scalar, and
/// 64 commitments.
pub const BORROMEAN_PROOF_LEN: usize = (64 + 64 + 1 + 64) * 32;

/// `c * P + s * Q`, variable-time.
fn double_mul(c: &Scalar, p: &EdwardsPoint, s: &Scalar, q: &EdwardsPoint) -> EdwardsPoint {
    let mut tables = [Table::new(), Table::new()];
    multiexp(&[c.clone(), s.clone()], &[*p, *q], &mut tables, false)
}

/// Verifies the ring signature of an input of a version 1 transaction
/// (`crypto::check_ring_signature`).
///
/// `prefix_hash` is the hash of the transaction prefix
/// (`TransactionPrefix::hash`), `key_image` the input's key image, `ring`
/// the one-time public keys of the outputs the input refers to, in the
/// order of its key offsets, and `signatures` the input's signatures, one
/// per ring member (each the challenge `c` then the response `r`).
///
/// As the reference function, this does not check that the key image is in
/// the prime-order subgroup, which consensus requires separately (a key
/// image with a torsion component would allow spending an output more than
/// once): `Transaction::verify` does. Variable-time: everything here is
/// public.
///
/// ```
/// use outscript::monero::check_ring_signature;
/// // No ring, no signature.
/// assert!(!check_ring_signature(&[0u8; 32], &[1u8; 32], &[], &[]));
/// ```
pub fn check_ring_signature(
    prefix_hash: &[u8; 32],
    key_image: &[u8; 32],
    ring: &[[u8; 32]],
    signatures: &[[u8; 64]],
) -> bool {
    if ring.is_empty() || ring.len() != signatures.len() {
        return false;
    }
    let Ok(image) = point_from_bytes(key_image) else {
        return false;
    };
    let mut h = Hasher::new();
    h.update(prefix_hash);
    let mut sum = Scalar::ZERO;
    for (key, signature) in ring.iter().zip(signatures) {
        let (c, r) = signature.split_at(32);
        let (Ok(c), Ok(r)) = (<[u8; 32]>::try_from(c), <[u8; 32]>::try_from(r)) else {
            return false;
        };
        let (Ok(c), Ok(r), Ok(public)) = (
            scalar_from_bytes(&c),
            scalar_from_bytes(&r),
            point_from_bytes(key),
        ) else {
            return false;
        };
        // a = c * P + r * G, b = r * Hp(P) + c * I
        let a = EdwardsPoint::double_scalar_mul_base_vartime(&c, &public, &r);
        let b = double_mul(&r, &point_from_hash(key), &c, &image);
        h.update(&a.compress());
        h.update(&b.compress());
        sum = sum.add(&c);
    }
    h.finalize_to_scalar() == sum
}

/// The scalar ref10's `slide` — the signed sliding-window recoding Monero's
/// variable-time double-scalar multiplication starts with — stands for,
/// given 32 bytes that need not be a reduced scalar.
///
/// For anything below 2^255 that is the value itself. Above, `slide` loses
/// the carry out of its top digit, and Monero has verified some Borromean
/// proofs of the chain's history with such scalars: the recoding is redone
/// here so that they verify the same.
pub(super) fn slide_scalar(bytes: &[u8; 32]) -> Scalar {
    if bytes[31] & 0x80 == 0 {
        return scalar_reduce(bytes);
    }
    let mut r = [0i8; 256];
    for (i, digit) in r.iter_mut().enumerate() {
        let byte = bytes.get(i >> 3).copied().unwrap_or(0);
        *digit = ((byte >> (i & 7)) & 1) as i8;
    }
    for i in 0..256usize {
        let Some(mut current) = r.get(i).copied() else {
            break;
        };
        if current == 0 {
            continue;
        }
        for b in 1..=6usize {
            let Some(next) = r.get(i + b).copied() else {
                break;
            };
            if next == 0 {
                continue;
            }
            // next is 0 or 1 here, and b at most 6: no overflow.
            let carry = i16::from(next) << b;
            let value = i16::from(current);
            if value + carry <= 15 {
                current = (value + carry) as i8;
                if let Some(slot) = r.get_mut(i + b) {
                    *slot = 0;
                }
            } else if value - carry >= -15 {
                current = (value - carry) as i8;
                for slot in r.iter_mut().skip(i + b) {
                    if *slot == 0 {
                        *slot = 1;
                        break;
                    }
                    *slot = 0;
                }
            } else {
                break;
            }
        }
        if let Some(slot) = r.get_mut(i) {
            *slot = current;
        }
    }
    // The value of the digits, by Horner's rule.
    let mut value = Scalar::ZERO;
    for digit in r.iter().rev() {
        value = value.add(&value);
        let magnitude = scalar_from_u64(u64::from(digit.unsigned_abs()));
        value = if *digit < 0 {
            value.sub(&magnitude)
        } else {
            value.add(&magnitude)
        };
    }
    value
}

/// Verifies a Borromean range proof (`rct::verRange`): that `commitment`
/// hides an amount below 2^64.
///
/// `proof` is the proof as a transaction of RingCT type 1 or 2 carries it
/// (`RangeSig`): [`BORROMEAN_PROOF_LEN`] bytes — the 64 `s0`, the 64 `s1`,
/// `ee`, then the 64 commitments to the bits of the amount. Any other
/// length fails. Variable-time: everything here is public.
///
/// ```
/// use outscript::monero::{BORROMEAN_PROOF_LEN, borromean_verify};
/// assert_eq!(BORROMEAN_PROOF_LEN, 6176);
/// assert!(!borromean_verify(&[0u8; BORROMEAN_PROOF_LEN], &[0u8; 32]));
/// ```
pub fn borromean_verify(proof: &[u8], commitment: &[u8; 32]) -> bool {
    if proof.len() != BORROMEAN_PROOF_LEN {
        return false;
    }
    let (chunks, _) = proof.as_chunks::<32>();
    let (Some(s0), Some(s1), Some(ee_bytes), Some(bits)) = (
        chunks.get(..64),
        chunks.get(64..128),
        chunks.get(128),
        chunks.get(129..193),
    ) else {
        return false;
    };
    let Ok(ee) = scalar_from_bytes(ee_bytes) else {
        return false;
    };
    // The commitments to the bits add up to the commitment.
    let mut sum = EdwardsPoint::identity();
    for bit in bits {
        let Ok(bit) = point_from_bytes(bit) else {
            return false;
        };
        sum = sum.add(&bit);
    }
    if sum.compress() != *commitment {
        return false;
    }
    let mut power = h_point();
    let mut h = Hasher::new();
    for ((s0, s1), bit) in s0.iter().zip(s1).zip(bits) {
        // The commitment to bit i is either to 0 or to 2^i: a ring signature
        // over the commitment and the commitment less 2^i * H shows that the
        // prover knows the mask of one of them.
        let Ok(bit) = point_from_bytes(bit) else {
            return false;
        };
        let ll = EdwardsPoint::double_scalar_mul_base_vartime(&ee, &bit, &slide_scalar(s0));
        let mut hash = Hasher::new();
        hash.update(&ll.compress());
        let lv = EdwardsPoint::double_scalar_mul_base_vartime(
            &hash.finalize_to_scalar(),
            &bit.sub(&power),
            &slide_scalar(s1),
        );
        h.update(&lv.compress());
        power = power.double();
    }
    // The signatures close.
    h.finalize_scalar() == *ee_bytes
}

/// The key image as a point, if it is one consensus accepts: not the
/// identity, and in the prime-order subgroup.
#[cfg(feature = "alloc")]
pub(crate) fn key_image_point(key_image: &[u8; 32]) -> Option<EdwardsPoint> {
    let image = point_from_bytes(key_image).ok()?;
    (image != EdwardsPoint::identity() && bool::from(image.is_torsion_free())).then_some(image)
}

#[cfg(feature = "alloc")]
impl Mlsag {
    /// Verifies the signature over a matrix of keys (`rct::MLSAG_Ver`):
    /// `matrix[i]` is the row of ring member `i`, whose first
    /// `key_images.len()` keys are one-time keys with a key image each, the
    /// rest being commitments to zero for one of the members.
    fn verify_matrix(
        &self,
        message: &[u8; 32],
        matrix: &[Vec<EdwardsPoint>],
        key_images: &[[u8; 32]],
    ) -> Result<bool, Error> {
        let rows = key_images.len();
        let Some(columns) = matrix.first().map(Vec::len) else {
            return Ok(false);
        };
        if matrix.len() < 2 || rows == 0 || rows > columns || self.ss.len() != matrix.len() {
            return Ok(false);
        }
        let mut images = Vec::with_capacity(rows);
        for key_image in key_images {
            let Some(image) = key_image_point(key_image) else {
                return Ok(false);
            };
            images.push(image);
        }
        let first = scalar_from_bytes(&self.cc)?;
        if first == Scalar::ZERO {
            return Ok(false);
        }
        let mut c = first.clone();
        for (member, responses) in matrix.iter().zip(&self.ss) {
            if member.len() != columns || responses.len() != columns {
                return Ok(false);
            }
            let mut h = Hasher::new();
            h.update(message);
            for (j, (key, s)) in member.iter().zip(responses).enumerate() {
                let s = scalar_from_bytes(s)?;
                let key_bytes = key.compress();
                // L = c * P + s * G
                let l = EdwardsPoint::double_scalar_mul_base_vartime(&c, key, &s);
                h.update(&key_bytes);
                h.update(&l.compress());
                if let Some(image) = images.get(j) {
                    // R = s * Hp(P) + c * I
                    let r = double_mul(&s, &point_from_hash(&key_bytes), &c, image);
                    h.update(&r.compress());
                }
            }
            c = h.finalize_to_scalar();
        }
        Ok(c == first)
    }

    /// Verifies the signature of one input of a transaction of RingCT type
    /// 2, 3 or 4 (`rct::verRctMGSimple`).
    ///
    /// `message` is the transaction's signature hash
    /// (`Transaction::signature_hash`), `ring` the outputs the input refers
    /// to, in the order of its key offsets, `key_image` its key image and
    /// `pseudo_out` its pseudo-output commitment.
    ///
    /// The key image must be in the prime-order subgroup, as consensus
    /// requires. Variable-time: everything here is public.
    pub fn verify_simple(
        &self,
        message: &[u8; 32],
        ring: &[RingMember],
        key_image: &[u8; 32],
        pseudo_out: &[u8; 32],
    ) -> bool {
        let matrix = || -> Result<Vec<Vec<EdwardsPoint>>, Error> {
            let pseudo_out = point_from_bytes(pseudo_out)?;
            ring.iter()
                .map(|member| {
                    Ok(vec![
                        point_from_bytes(&member.key)?,
                        point_from_bytes(&member.commitment)?.sub(&pseudo_out),
                    ])
                })
                .collect()
        };
        matrix()
            .and_then(|matrix| {
                self.verify_matrix(message, &matrix, core::slice::from_ref(key_image))
            })
            .unwrap_or(false)
    }

    /// Verifies the signature of a transaction of RingCT type 1
    /// (`rct::verRctMG`): one signature for all the inputs, which also shows
    /// that the amounts balance.
    ///
    /// `message` is the transaction's signature hash, `rings[i]` the
    /// outputs input `i` refers to, in the order of its key offsets (all
    /// rings have the same size), `key_images[i]` its key image;
    /// `out_commitments` are the commitments of the transaction's outputs
    /// and `fee` its fee.
    ///
    /// The key images must be in the prime-order subgroup, as consensus
    /// requires. Variable-time: everything here is public.
    pub fn verify_full(
        &self,
        message: &[u8; 32],
        rings: &[Vec<RingMember>],
        key_images: &[[u8; 32]],
        out_commitments: &[[u8; 32]],
        fee: u64,
    ) -> bool {
        let matrix = || -> Result<Option<Vec<Vec<EdwardsPoint>>>, Error> {
            let Some(ring_size) = rings.first().map(Vec::len) else {
                return Ok(None);
            };
            if rings.len() != key_images.len() || rings.iter().any(|ring| ring.len() != ring_size) {
                return Ok(None);
            }
            // What the inputs' commitments must exceed by nothing: the
            // outputs and the fee.
            let mut spent = EdwardsPoint::double_scalar_mul_base_vartime(
                &scalar_from_u64(fee),
                &h_point(),
                &Scalar::ZERO,
            );
            for commitment in out_commitments {
                spent = spent.add(&point_from_bytes(commitment)?);
            }
            let mut matrix = Vec::with_capacity(ring_size);
            for i in 0..ring_size {
                let mut row = Vec::with_capacity(rings.len() + 1);
                let mut commitments = EdwardsPoint::identity();
                for member in rings.iter().filter_map(|ring| ring.get(i)) {
                    row.push(point_from_bytes(&member.key)?);
                    commitments = commitments.add(&point_from_bytes(&member.commitment)?);
                }
                row.push(commitments.sub(&spent));
                matrix.push(row);
            }
            Ok(Some(matrix))
        };
        match matrix() {
            Ok(Some(matrix)) => self
                .verify_matrix(message, &matrix, key_images)
                .unwrap_or(false),
            _ => false,
        }
    }
}
