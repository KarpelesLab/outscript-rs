//! Points: decoding, and hashing to the curve (`Hp`).
//!
//! The map is a port of Monero's `ge_fromfe_frombytes_vartime`
//! (`crypto-ops.c`), an Elligator-2-style map with its own conventions (the
//! non-residue `2`, its own choice of square roots, the input read as a
//! 256-bit integer). It is not RFC 9380's `hash_to_curve`, and the two give
//! different points.

use super::{EdwardsPoint, Error, FieldElement, cn_fast_hash};

/// `-A`, with `A = 486662` the Montgomery coefficient of curve25519.
const FE_MA: [u8; 32] = [
    0xe7, 0x92, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
/// `-A^2`.
const FE_MA2: [u8; 32] = [
    0xc9, 0xe3, 0x3d, 0xdb, 0xc8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
/// `sqrt(-2 * A * (A + 2))`.
const FE_FFFB1: [u8; 32] = [
    0xee, 0x41, 0x1c, 0x32, 0x75, 0x69, 0xa7, 0x22, 0x8d, 0x73, 0x2a, 0xb9, 0xa8, 0x04, 0x94, 0xd1,
    0xe3, 0x19, 0xfb, 0x41, 0x37, 0xc5, 0xa9, 0x20, 0x17, 0x1b, 0xd6, 0xda, 0xef, 0xfb, 0x71, 0x7e,
];
/// `sqrt(2 * A * (A + 2))`.
const FE_FFFB2: [u8; 32] = [
    0xe0, 0x9a, 0x7c, 0x60, 0x83, 0x64, 0xde, 0xd2, 0xdf, 0xf7, 0x56, 0x04, 0x46, 0x03, 0xde, 0x51,
    0xbe, 0x5f, 0x16, 0xc0, 0xb7, 0x51, 0xd4, 0x91, 0xf6, 0x2c, 0x5a, 0x04, 0x0a, 0x1e, 0x06, 0x4d,
];
/// `sqrt(-sqrt(-1) * A * (A + 2))`.
const FE_FFFB3: [u8; 32] = [
    0x66, 0x2c, 0x30, 0x17, 0x87, 0x7d, 0x1b, 0x58, 0x29, 0x42, 0x96, 0xa5, 0x4e, 0xff, 0x24, 0x40,
    0xed, 0xa2, 0x0d, 0x3f, 0x40, 0x46, 0x95, 0xb8, 0xef, 0x08, 0xc2, 0x14, 0x0d, 0x11, 0x4a, 0x67,
];
/// `sqrt(sqrt(-1) * A * (A + 2))`.
const FE_FFFB4: [u8; 32] = [
    0x86, 0x91, 0xb3, 0xb6, 0x03, 0x19, 0x3d, 0x85, 0x49, 0x4a, 0x3f, 0xa1, 0x08, 0xfc, 0x46, 0xee,
    0x2e, 0x43, 0xf7, 0x7e, 0x88, 0xf4, 0xc0, 0x26, 0xf9, 0xdb, 0x67, 0x10, 0x03, 0xf3, 0x43, 0x1a,
];

/// Decodes a compressed point (`ge_frombytes_vartime`).
///
/// The encoding must be canonical (`y` below the field prime, no `-0` for
/// `x`) and on the curve, or this fails with [`Error::InvalidPoint`]. The
/// point may lie outside the prime-order subgroup.
pub fn point_from_bytes(bytes: &[u8; 32]) -> Result<EdwardsPoint, Error> {
    EdwardsPoint::decompress(bytes).ok_or(Error::InvalidPoint)
}

/// The field element `n`, for a small `n`.
fn fe_small(n: u8) -> FieldElement {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    FieldElement::from_bytes(&bytes)
}

/// `n` squarings of `x`.
fn square_n(x: &FieldElement, n: usize) -> FieldElement {
    let mut r = *x;
    for _ in 0..n {
        r = r.square();
    }
    r
}

/// `z^((p - 5) / 8) = z^(2^252 - 3)` (ref10's `fe_pow22523`).
fn pow22523(z: &FieldElement) -> FieldElement {
    let z2 = z.square();
    let z9 = square_n(&z2, 2).mul(z);
    let z11 = z2.mul(&z9);
    // 2^5 - 1
    let a = z11.square().mul(&z9);
    // 2^10 - 1
    let b = square_n(&a, 5).mul(&a);
    // 2^20 - 1
    let c = square_n(&b, 10).mul(&b);
    // 2^40 - 1
    let d = square_n(&c, 20).mul(&c);
    // 2^50 - 1
    let e = square_n(&d, 10).mul(&b);
    // 2^100 - 1
    let f = square_n(&e, 50).mul(&e);
    // 2^200 - 1
    let g = square_n(&f, 100).mul(&f);
    // 2^250 - 1
    let h = square_n(&g, 50).mul(&e);
    // 2^252 - 3
    square_n(&h, 2).mul(z)
}

/// `(u / v)^((p + 3) / 8)`, computed as `u * v^3 * (u * v^7)^((p - 5) / 8)`
/// (`fe_divpowm1`).
fn div_pow_m1(u: &FieldElement, v: &FieldElement) -> FieldElement {
    let v3 = v.square().mul(v);
    let uv7 = v3.square().mul(v).mul(u);
    pow22523(&uv7).mul(&v3).mul(u)
}

fn is_zero(x: &FieldElement) -> bool {
    bool::from(x.is_zero())
}

/// The map from a 32-byte hash to a curve point, without the multiplication
/// by the cofactor: `ge_fromfe_frombytes_vartime`.
///
/// The result is on the curve but generally not in the prime-order subgroup:
/// use [`point_from_hash`] for `Hp`. Variable-time, for public input.
pub fn map_to_point(hash: &[u8; 32]) -> EdwardsPoint {
    // The 32 bytes are read as a 256-bit integer, top bit included, and
    // reduced: 2^255 = 19 modulo p.
    let mut u = FieldElement::from_bytes(hash);
    if hash[31] & 0x80 != 0 {
        u = u.add(&fe_small(19));
    }

    let ma = FieldElement::from_bytes(&FE_MA);
    // v = 2 * u^2, w = 2 * u^2 + 1
    let v = u.square().mul(&fe_small(2));
    let w = v.add(&FieldElement::ONE);
    // x = w^2 - 2 * A^2 * u^2
    let x = w.square().add(&FieldElement::from_bytes(&FE_MA2).mul(&v));
    // rx = (w / x)^((p + 3) / 8)
    let mut rx = div_pow_m1(&w, &x);
    let x = rx.square().mul(&x);

    let (z, negative) = if !is_zero(&w.sub(&x)) {
        if !is_zero(&w.add(&x)) {
            // w / x is not a square: the other candidate, on the twist side.
            let x = x.mul(&FieldElement::SQRT_M1);
            let fffb = if !is_zero(&w.sub(&x)) {
                FE_FFFB3
            } else {
                FE_FFFB4
            };
            rx = rx.mul(&FieldElement::from_bytes(&fffb));
            (ma, true)
        } else {
            rx = rx.mul(&FieldElement::from_bytes(&FE_FFFB1)).mul(&u);
            (ma.mul(&v), false)
        }
    } else {
        rx = rx.mul(&FieldElement::from_bytes(&FE_FFFB2)).mul(&u);
        (ma.mul(&v), false)
    };

    if bool::from(rx.is_negative()) != negative {
        rx = rx.negate();
    }
    // The projective point (X : Y : Z).
    let rz = z.add(&w);
    let ry = z.sub(&w);
    let rx = rx.mul(&rz);

    // Z is never zero (it would take a Montgomery point with u = -1, and
    // curve25519 has none), so the affine point exists and is on the curve.
    let zinv = rz.invert();
    EdwardsPoint::from_affine(&rx.mul(&zinv), &ry.mul(&zinv)).unwrap_or_else(EdwardsPoint::identity)
}

/// `hash_to_point`: [`map_to_point`], compressed.
pub fn hash_to_point(hash: &[u8; 32]) -> [u8; 32] {
    map_to_point(hash).compress()
}

/// `Hp`: hashes `data` to a point of the prime-order subgroup,
/// `8 * map_to_point(cn_fast_hash(data))`.
///
/// Variable-time, for public input (`data` is a public key wherever
/// CryptoNote uses this).
pub fn point_from_hash(data: &[u8]) -> EdwardsPoint {
    map_to_point(&cn_fast_hash(data)).mul_by_cofactor()
}

/// `hash_to_ec` (`Hp`): [`point_from_hash`], compressed.
pub fn hash_to_ec(data: &[u8]) -> [u8; 32] {
    point_from_hash(data).compress()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constants are what their names say.
    #[test]
    fn constants() {
        let fe = |n: u32| {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&n.to_le_bytes());
            FieldElement::from_bytes(&b)
        };
        let a = fe(486662);
        let a_a2 = a.mul(&fe(486664));
        let sqrt_m1 = FieldElement::SQRT_M1;
        let c = |bytes: &[u8; 32]| FieldElement::from_bytes_canonical(bytes).unwrap();

        assert_eq!(sqrt_m1.square(), FieldElement::ONE.negate());
        assert_eq!(c(&FE_MA), a.negate());
        assert_eq!(c(&FE_MA2), a.square().negate());
        assert_eq!(c(&FE_FFFB1).square(), fe(2).mul(&a_a2).negate());
        assert_eq!(c(&FE_FFFB2).square(), fe(2).mul(&a_a2));
        assert_eq!(c(&FE_FFFB3).square(), sqrt_m1.mul(&a_a2).negate());
        assert_eq!(c(&FE_FFFB4).square(), sqrt_m1.mul(&a_a2));
    }

    /// `pow22523` and `div_pow_m1` against their definitions.
    #[test]
    fn powers() {
        let x = FieldElement::from_bytes(&[7u8; 32]);
        let y = FieldElement::from_bytes(&[9u8; 32]);
        // x^(2^252 - 3), by square and multiply.
        let mut want = FieldElement::ONE;
        for bit in (0..252).rev() {
            want = want.square();
            // 2^252 - 3 = 0b111...101: every bit set but bit 1.
            if bit != 1 {
                want = want.mul(&x);
            }
        }
        assert_eq!(pow22523(&x), want);
        // (x / y)^((p + 3) / 8) = (x / y) * (x / y)^((p - 5) / 8).
        let q = x.mul(&y.invert());
        assert_eq!(div_pow_m1(&x, &y), pow22523(&q).mul(&q));
        assert_eq!(div_pow_m1(&x, &FieldElement::ZERO), FieldElement::ZERO);
    }
}
