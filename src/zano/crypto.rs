//! Zano's generators, domain-separated hashes and the small helpers the rest
//! of the module shares. Nothing here needs a heap.

use purecrypto::zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "alloc")]
use crate::cryptonote::Hasher;
use crate::cryptonote::{
    self, EdwardsPoint, Scalar, derivation_to_scalar, point_from_bytes, scalar_from_bytes,
    scalar_from_hash, scalar_from_u64,
};

use super::Error;

/// The basepoint `G` of edwards25519 (`c_point_G`).
pub const POINT_G: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];
/// The generator `H = Hp(G)` (`c_point_H`), which is also the asset id of the
/// native coin.
pub const POINT_H: [u8; 32] = [
    0xd6, 0x32, 0x9b, 0x5b, 0x1f, 0x7c, 0x08, 0x05, 0xb5, 0xc3, 0x45, 0xf4, 0x95, 0x75, 0x54, 0x00,
    0x2a, 0x2f, 0x55, 0x78, 0x45, 0xf6, 0x4d, 0x76, 0x45, 0xda, 0xe0, 0xe0, 0x51, 0xa6, 0x49, 0x8a,
];
/// The generator `H2` (`c_point_H2`).
pub const POINT_H2: [u8; 32] = [
    0x90, 0xe6, 0xa6, 0x24, 0xd9, 0xc6, 0x6c, 0x0a, 0xfe, 0x4d, 0x5e, 0x0d, 0x7c, 0xe9, 0x90, 0x73,
    0x80, 0xce, 0x95, 0x86, 0xf4, 0xfb, 0x00, 0xb1, 0x3f, 0xd9, 0x5b, 0xbf, 0x37, 0x50, 0x64, 0x67,
];
/// The generator `U` (`c_point_U`).
pub const POINT_U: [u8; 32] = [
    0xd0, 0x26, 0x8e, 0x41, 0x9f, 0x56, 0x17, 0x5b, 0x91, 0xc2, 0x43, 0xdf, 0x3b, 0xf2, 0x5a, 0xd4,
    0x2f, 0x43, 0xa7, 0xf0, 0x18, 0xf5, 0x80, 0xe3, 0x1c, 0xc6, 0x0b, 0x7d, 0x90, 0x4a, 0xc9, 0xa1,
];
/// The generator `X` (`c_point_X`).
pub const POINT_X: [u8; 32] = [
    0x3a, 0x25, 0xbc, 0xdb, 0x43, 0xf5, 0xd2, 0xc9, 0xdd, 0x06, 0x3d, 0xc3, 0x9a, 0x9e, 0x09, 0x87,
    0xba, 0xfc, 0x6f, 0xcf, 0x2d, 0xf1, 0xbc, 0x76, 0x32, 0x2d, 0x75, 0x88, 0x4a, 0x4a, 0x38, 0x20,
];
/// The asset id of the native coin (ZANO): the generator [`POINT_H`].
pub const NATIVE_COIN_ASSET_ID: [u8; 32] = POINT_H;

/// `1/8` modulo the group order (`c_scalar_1div8`).
const SCALAR_1DIV8: [u8; 32] = [
    0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
];

pub(crate) const HDS_OUT_AMOUNT_MASK: &[u8; 32] = b"ZANO_HDS_OUT_AMOUNT_MASK_______\0";
pub(crate) const HDS_OUT_AMOUNT_BLINDING_MASK: &[u8; 32] = b"ZANO_HDS_OUT_AMOUNT_BLIND_MASK_\0";
pub(crate) const HDS_OUT_ASSET_BLINDING_MASK: &[u8; 32] = b"ZANO_HDS_OUT_ASSET_BLIND_MASK__\0";
pub(crate) const HDS_OUT_CONCEALING_POINT: &[u8; 32] = b"ZANO_HDS_OUT_CONCEALING_POINT__\0";

/// Decodes one of the constants above.
fn constant(bytes: &[u8; 32]) -> EdwardsPoint {
    // The constants are valid points (checked by the tests).
    EdwardsPoint::decompress(bytes).unwrap_or_else(EdwardsPoint::identity)
}

/// The generator [`POINT_H`], the native coin's asset id.
pub fn generator_h() -> EdwardsPoint {
    constant(&POINT_H)
}

/// The generator [`POINT_H2`].
pub fn generator_h2() -> EdwardsPoint {
    constant(&POINT_H2)
}

/// The generator [`POINT_U`].
pub fn generator_u() -> EdwardsPoint {
    constant(&POINT_U)
}

/// The generator [`POINT_X`].
pub fn generator_x() -> EdwardsPoint {
    constant(&POINT_X)
}

/// `1/8` modulo the group order: on-chain points are stored multiplied by
/// it, so that the multiplication by 8 every verifier does lands in the
/// prime-order subgroup.
pub fn scalar_1div8() -> Scalar {
    Scalar::from_bytes_canonical(&SCALAR_1DIV8).unwrap_or(Scalar::ZERO)
}

/// Decodes a point, with this module's error.
pub(crate) fn point(bytes: &[u8; 32]) -> Result<EdwardsPoint, Error> {
    Ok(point_from_bytes(bytes)?)
}

/// Decodes a reduced scalar, with this module's error.
pub(crate) fn scalar(bytes: &[u8; 32]) -> Result<Scalar, Error> {
    Ok(scalar_from_bytes(bytes)?)
}

/// `scalar * point` in variable time, for public values only.
#[cfg(feature = "alloc")]
pub(crate) fn mul_vartime(scalar: &Scalar, point: &EdwardsPoint) -> EdwardsPoint {
    EdwardsPoint::double_scalar_mul_base_vartime(scalar, point, &Scalar::ZERO)
}

/// The `width` bits of a little-endian scalar starting at bit `position`
/// (`width <= 16`).
#[cfg(feature = "alloc")]
fn scalar_bits(bytes: &[u8; 32], position: usize, width: usize) -> usize {
    let mut value = 0usize;
    for (n, index) in (position / 8..32).take(3).enumerate() {
        value |= usize::from(bytes[index]) << (8 * n);
    }
    (value >> (position % 8)) & ((1 << width) - 1)
}

/// The sum of `scalar * point` over `terms`, in variable time: for public
/// values only.
///
/// A few terms share one run of doublings (Straus, four bits at a time);
/// many go through buckets (Pippenger).
#[cfg(feature = "alloc")]
pub(crate) fn msm_vartime(terms: &[(Scalar, EdwardsPoint)]) -> EdwardsPoint {
    use crate::prelude::*;

    let scalars: Vec<[u8; 32]> = terms.iter().map(|(s, _)| s.to_bytes()).collect();
    let mut acc = EdwardsPoint::identity();
    if terms.len() < 24 {
        // tables[i][d - 1] = d * point_i, for d in 1..16.
        let tables: Vec<[EdwardsPoint; 15]> = terms
            .iter()
            .map(|(_, point)| {
                let mut table = [*point; 15];
                for d in 1..15 {
                    table[d] = table[d - 1].add(point);
                }
                table
            })
            .collect();
        for window in (0..64).rev() {
            for _ in 0..4 {
                acc = acc.double();
            }
            for (scalar, table) in scalars.iter().zip(&tables) {
                if let Some(multiple) = scalar_bits(scalar, window * 4, 4)
                    .checked_sub(1)
                    .and_then(|d| table.get(d))
                {
                    acc = acc.add(multiple);
                }
            }
        }
        return acc;
    }

    let width = match terms.len() {
        ..96 => 5,
        96..400 => 6,
        400..1200 => 8,
        _ => 9,
    };
    let mut buckets = vec![EdwardsPoint::identity(); (1 << width) - 1];
    for window in (0..253usize.div_ceil(width)).rev() {
        for _ in 0..width {
            acc = acc.double();
        }
        buckets.fill(EdwardsPoint::identity());
        for (scalar, (_, point)) in scalars.iter().zip(terms) {
            if let Some(bucket) = scalar_bits(scalar, window * width, width)
                .checked_sub(1)
                .and_then(|d| buckets.get_mut(d))
            {
                *bucket = bucket.add(point);
            }
        }
        // sum(d * bucket_d), as a sum of running sums from the top.
        let mut running = EdwardsPoint::identity();
        let mut sum = EdwardsPoint::identity();
        for bucket in buckets.iter().rev() {
            running = running.add(bucket);
            sum = sum.add(&running);
        }
        acc = acc.add(&sum);
    }
    acc
}

/// A uniformly random scalar: 64 bytes from `rng`, reduced modulo the group
/// order (`scalar_t::make_random`, zanolib's `RandomScalar`).
pub(crate) fn random_scalar(rng: &mut dyn FnMut(&mut [u8])) -> Scalar {
    let mut wide = Zeroizing::new([0u8; 64]);
    rng(&mut wide[..]);
    Scalar::from_bytes_mod_order(&wide)
}

/// `Hs(domain || h)`: one of the per-output scalars derived from the output
/// scalar `h`.
pub(crate) fn output_scalar(domain: &[u8; 32], h: &[u8; 32]) -> Scalar {
    scalar_from_hash(&[domain, h])
}

/// The secrets one output shares between its sender and its recipient, all
/// derived from `h = Hs(8 * r * V || varint(index))`.
pub(crate) struct OutputSecrets {
    /// `h` itself: the stealth address is `h * G + spend_public`.
    pub h: Scalar,
    /// The eight bytes the amount is XORed with.
    pub amount_mask: u64,
    /// The blinding mask `y` of the amount commitment.
    pub amount_blinding_mask: Scalar,
    /// The blinding mask `s` of the asset id (unused for a bare native id).
    pub asset_blinding_mask: Scalar,
    /// The multiplier of the view public key that gives the concealing point.
    pub concealing: Scalar,
}

impl OutputSecrets {
    /// The secrets of output `index` under the key `derivation`.
    pub(crate) fn derive(derivation: &[u8; 32], index: u64) -> Self {
        let mut h = derivation_to_scalar(derivation, index);
        let mut mask = output_scalar(HDS_OUT_AMOUNT_MASK, &h).to_bytes();
        let mut low = [0u8; 8];
        low.copy_from_slice(&mask[..8]);
        let secrets = OutputSecrets {
            // `h` is a reduced scalar by construction.
            h: Scalar::from_bytes_canonical(&h).unwrap_or(Scalar::ZERO),
            amount_mask: u64::from_le_bytes(low),
            amount_blinding_mask: output_scalar(HDS_OUT_AMOUNT_BLINDING_MASK, &h),
            asset_blinding_mask: output_scalar(HDS_OUT_ASSET_BLINDING_MASK, &h),
            concealing: output_scalar(HDS_OUT_CONCEALING_POINT, &h),
        };
        h.zeroize();
        mask.zeroize();
        low.zeroize();
        secrets
    }
}

/// The 16-bit hint a sender stores in the transaction for each recipient key
/// derivation, so that a wallet can skip transactions that are not for it:
/// the BLAKE2b-256 hash of the derivation, folded by XOR into 16 bits
/// (`get_derivation_hint`).
pub fn derivation_hint(derivation: &[u8; 32]) -> u16 {
    let hash = purecrypto::hash::blake2b256(derivation);
    hash.as_chunks::<2>()
        .0
        .iter()
        .fold(0u16, |acc, pair| acc ^ u16::from_le_bytes(*pair))
}

/// The key image `secret * Hp(public)` of a one-time key pair, as a point
/// (`generate_key_image`).
pub fn key_image(secret: &Scalar, public: &EdwardsPoint) -> EdwardsPoint {
    cryptonote::point_from_hash(&public.compress()).mul(secret)
}

/// A Keccak transcript that absorbs scalars and points and squeezes scalars
/// (`hash_helper_t::hs_t`).
#[cfg(feature = "alloc")]
pub(crate) struct Transcript(Hasher);

#[cfg(feature = "alloc")]
impl Transcript {
    pub(crate) fn new() -> Self {
        Transcript(Hasher::new())
    }

    pub(crate) fn bytes(&mut self, bytes: &[u8; 32]) -> &mut Self {
        self.0.update(bytes);
        self
    }

    pub(crate) fn scalar(&mut self, scalar: &Scalar) -> &mut Self {
        self.0.update(&scalar.to_bytes());
        self
    }

    pub(crate) fn point(&mut self, point: &EdwardsPoint) -> &mut Self {
        self.0.update(&point.compress());
        self
    }

    /// The scalar for what was absorbed so far, keeping the state.
    pub(crate) fn peek_scalar(&self) -> Scalar {
        self.0.clone().finalize_to_scalar()
    }

    /// The scalar for what was absorbed, starting over.
    pub(crate) fn take_scalar(&mut self) -> Scalar {
        core::mem::take(&mut self.0).finalize_to_scalar()
    }

    /// The unreduced hash of what was absorbed, starting over.
    pub(crate) fn take_hash(&mut self) -> [u8; 32] {
        core::mem::take(&mut self.0).finalize()
    }
}

/// The scalar `value`.
pub(crate) fn scalar_u64(value: u64) -> Scalar {
    scalar_from_u64(value)
}
