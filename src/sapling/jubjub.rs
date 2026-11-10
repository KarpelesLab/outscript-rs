//! The Jubjub curve: the twisted Edwards curve `-u² + v² = 1 + d·u²·v²` over
//! [`Fq`] with `d = -10240/10241`, of order `8·r` (protocol specification
//! §5.4.9.3).
//!
//! [`Point`] holds any point of the curve in extended coordinates;
//! [`AffinePoint`] is the `(u, v)` form used for constants and tables. The
//! addition law is complete, so no input needs special treatment.
//! [`Point::mul`] runs in constant time and is the one to use with secret
//! scalars; [`Point::mul_vartime`] is for public ones.

use super::field::{Fq, Fr};
use purecrypto::ct::{Choice, ConditionallySelectable, ConstantTimeEq};

/// The curve parameter `d = -10240/10241`.
pub const D: Fq = Fq::from_raw([
    0x0106_5fd6_d634_3eb1,
    0x292d_7f6d_3757_9d26,
    0xf5fd_9207_e6bd_7fd4,
    0x2a93_18e7_4bfa_2b48,
]);

/// `2·d`.
pub const D2: Fq = D.double();

/// The cofactor of the prime-order subgroup.
pub const COFACTOR: u64 = 8;

/// A point of Jubjub in affine coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffinePoint {
    u: Fq,
    v: Fq,
}

impl AffinePoint {
    /// The neutral element `(0, 1)`.
    pub const IDENTITY: AffinePoint = AffinePoint {
        u: Fq::ZERO,
        v: Fq::ONE,
    };

    /// The point with the given coordinates, which the caller guarantees to
    /// satisfy the curve equation (see [`is_on_curve`](Self::is_on_curve)).
    pub const fn from_raw_unchecked(u: Fq, v: Fq) -> AffinePoint {
        AffinePoint { u, v }
    }

    /// The point with the given coordinates, if it is on the curve.
    pub fn new(u: Fq, v: Fq) -> Option<AffinePoint> {
        let p = AffinePoint { u, v };
        p.is_on_curve().then_some(p)
    }

    /// The `u` coordinate.
    pub const fn u(&self) -> Fq {
        self.u
    }

    /// The `v` coordinate.
    pub const fn v(&self) -> Fq {
        self.v
    }

    /// Whether the coordinates satisfy `-u² + v² = 1 + d·u²·v²`.
    pub fn is_on_curve(&self) -> bool {
        let u2 = self.u.square();
        let v2 = self.v.square();
        v2 - u2 == Fq::ONE + D * u2 * v2
    }

    /// The same point in extended coordinates.
    pub const fn to_point(&self) -> Point {
        Point {
            u: self.u,
            v: self.v,
            z: Fq::ONE,
            t: self.u.const_mul(&self.v),
        }
    }

    /// The compressed encoding `repr_J`: `v` in little-endian order with the
    /// parity of `u` in the top bit.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = self.v.to_bytes();
        bytes[31] |= u8::from(self.u.is_odd()) << 7;
        bytes
    }

    /// Decodes a compressed point (`abst_J`), accepting canonical encodings
    /// only as ZIP-216 requires: `v` must be reduced, and the sign bit must
    /// be clear when `u` is zero.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<AffinePoint> {
        let sign = bytes[31] >> 7 == 1;
        let mut v_bytes = *bytes;
        v_bytes[31] &= 0x7f;
        let v = Fq::from_bytes(&v_bytes)?;
        let v2 = v.square();
        // d is not a square and -1 is, so the denominator is never zero
        let u2 = (v2 - Fq::ONE) * (Fq::ONE + D * v2).invert()?;
        let mut u = u2.sqrt()?;
        if u.is_odd() != sign {
            u = -u;
        }
        if u.is_zero() && sign {
            return None;
        }
        Some(AffinePoint { u, v })
    }
}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        AffinePoint {
            u: Fq::conditional_select(&a.u, &b.u, choice),
            v: Fq::conditional_select(&a.v, &b.v, choice),
        }
    }
}

/// A point of Jubjub in extended twisted Edwards coordinates
/// `(U : V : Z : T)` with `u = U/Z`, `v = V/Z` and `T = U·V/Z`.
///
/// The point may be anywhere on the curve, including the small-order
/// subgroup: see [`is_torsion_free`](Self::is_torsion_free),
/// [`is_small_order`](Self::is_small_order) and
/// [`mul_by_cofactor`](Self::mul_by_cofactor).
#[derive(Clone, Copy, Debug)]
pub struct Point {
    u: Fq,
    v: Fq,
    z: Fq,
    t: Fq,
}

impl Point {
    /// The neutral element.
    pub const IDENTITY: Point = AffinePoint::IDENTITY.to_point();

    /// Converts to affine coordinates (one field inversion).
    pub fn to_affine(&self) -> AffinePoint {
        // Z is never zero for a point of the curve
        let zinv = self.z.invert().unwrap_or(Fq::ZERO);
        AffinePoint {
            u: self.u * zinv,
            v: self.v * zinv,
        }
    }

    /// Converts a batch of points to affine coordinates with one inversion
    /// (Montgomery's trick). `out` must be as long as `points`.
    pub fn batch_to_affine(points: &[Point], out: &mut [AffinePoint]) {
        assert_eq!(points.len(), out.len(), "batch_to_affine output length");
        let mut acc = Fq::ONE;
        for (p, o) in points.iter().zip(out.iter_mut()) {
            // stash the running product of the earlier Z coordinates
            o.u = acc;
            acc *= p.z;
        }
        let mut inv = acc.invert().unwrap_or(Fq::ZERO);
        for (p, o) in points.iter().zip(out.iter_mut()).rev() {
            let zinv = inv * o.u;
            inv *= p.z;
            *o = AffinePoint {
                u: p.u * zinv,
                v: p.v * zinv,
            };
        }
    }

    /// The compressed encoding (see [`AffinePoint::to_bytes`]).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.to_affine().to_bytes()
    }

    /// Decodes a compressed point (see [`AffinePoint::from_bytes`]). The
    /// result may have a small-order component.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Point> {
        AffinePoint::from_bytes(bytes).map(|p| p.to_point())
    }

    /// Decodes a compressed point of the prime-order subgroup (which
    /// includes the identity), rejecting everything else.
    pub fn from_bytes_prime_order(bytes: &[u8; 32]) -> Option<Point> {
        Point::from_bytes(bytes).filter(Point::is_torsion_free)
    }

    /// The sum of two points (complete: valid for every pair of inputs).
    pub const fn add(&self, rhs: &Point) -> Point {
        // add-2008-hwcd-3 for a = -1
        let a = self.v.const_sub(&self.u).const_mul(&rhs.v.const_sub(&rhs.u));
        let b = self.v.const_add(&self.u).const_mul(&rhs.v.const_add(&rhs.u));
        let c = self.t.const_mul(&D2).const_mul(&rhs.t);
        let d = self.z.double().const_mul(&rhs.z);
        let e = b.const_sub(&a);
        let f = d.const_sub(&c);
        let g = d.const_add(&c);
        let h = b.const_add(&a);
        Point {
            u: e.const_mul(&f),
            v: g.const_mul(&h),
            z: f.const_mul(&g),
            t: e.const_mul(&h),
        }
    }

    /// `2·self`.
    pub const fn double(&self) -> Point {
        // dbl-2008-hwcd for a = -1
        let a = self.u.square();
        let b = self.v.square();
        let c = self.z.square().double();
        let d = a.const_neg();
        let e = self.u.const_add(&self.v).square().const_sub(&a).const_sub(&b);
        let g = d.const_add(&b);
        let f = g.const_sub(&c);
        let h = d.const_sub(&b);
        Point {
            u: e.const_mul(&f),
            v: g.const_mul(&h),
            z: f.const_mul(&g),
            t: e.const_mul(&h),
        }
    }

    /// `-self`.
    pub const fn negate(&self) -> Point {
        Point {
            u: self.u.const_neg(),
            v: self.v,
            z: self.z,
            t: self.t.const_neg(),
        }
    }

    /// `[8]·self`, which lands in the prime-order subgroup.
    pub const fn mul_by_cofactor(&self) -> Point {
        self.double().double().double()
    }

    /// `[scalar]·self` in constant time: a fixed 4-bit window over all 64
    /// nibbles of the scalar, with a constant-time table lookup.
    pub fn mul(&self, scalar: &Fr) -> Point {
        let mut table = [Point::IDENTITY; 16];
        for i in 1..16 {
            table[i] = table[i - 1].add(self);
        }
        let bytes = scalar.to_bytes();
        let mut acc = Point::IDENTITY;
        for byte in bytes.iter().rev() {
            for nibble in [byte >> 4, byte & 15] {
                acc = acc.double().double().double().double();
                let mut entry = Point::IDENTITY;
                for (i, candidate) in table.iter().enumerate() {
                    entry.conditional_assign(candidate, (i as u8).ct_eq(&nibble));
                }
                acc = acc.add(&entry);
            }
        }
        acc
    }

    /// `[scalar]·self` with a 4-bit window that skips zero digits: the
    /// running time reveals the scalar, so this is for public scalars only.
    pub fn mul_vartime(&self, scalar: &Fr) -> Point {
        let limbs = scalar.to_raw();
        let mut table = [*self; 15];
        for i in 1..15 {
            table[i] = table[i - 1].add(self);
        }
        let mut acc = Point::IDENTITY;
        let mut started = false;
        for i in (0..64).rev() {
            if started {
                acc = acc.double().double().double().double();
            }
            let nibble = ((limbs[i / 16] >> (4 * (i % 16))) & 15) as usize;
            if nibble != 0 {
                acc = acc.add(&table[nibble - 1]);
                started = true;
            }
        }
        acc
    }

    fn mul_limbs_vartime(&self, limbs: &[u64; 4]) -> Point {
        let mut acc = Point::IDENTITY;
        for i in (0..256).rev() {
            acc = acc.double();
            if (limbs[i / 64] >> (i % 64)) & 1 == 1 {
                acc = acc.add(self);
            }
        }
        acc
    }

    /// Whether this is the neutral element.
    pub fn is_identity(&self) -> bool {
        bool::from(self.ct_eq(&Point::IDENTITY))
    }

    /// Whether the order of this point divides 8 (the identity included).
    pub fn is_small_order(&self) -> bool {
        self.mul_by_cofactor().is_identity()
    }

    /// Whether this point is in the prime-order subgroup (the identity
    /// included). Not constant time.
    pub fn is_torsion_free(&self) -> bool {
        self.mul_limbs_vartime(&Fr::MODULUS).is_identity()
    }

    /// Whether this is a point of order exactly `r`: in the prime-order
    /// subgroup and not the identity.
    pub fn is_prime_order(&self) -> bool {
        self.is_torsion_free() && !self.is_identity()
    }
}

impl ConstantTimeEq for Point {
    fn ct_eq(&self, other: &Self) -> Choice {
        (self.u * other.z).ct_eq(&(other.u * self.z))
            & (self.v * other.z).ct_eq(&(other.v * self.z))
    }
}

impl ConditionallySelectable for Point {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Point {
            u: Fq::conditional_select(&a.u, &b.u, choice),
            v: Fq::conditional_select(&a.v, &b.v, choice),
            z: Fq::conditional_select(&a.z, &b.z, choice),
            t: Fq::conditional_select(&a.t, &b.t, choice),
        }
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Point {}

impl Default for Point {
    fn default() -> Self {
        Point::IDENTITY
    }
}

impl From<AffinePoint> for Point {
    fn from(p: AffinePoint) -> Point {
        p.to_point()
    }
}

impl core::ops::Add for Point {
    type Output = Point;
    fn add(self, rhs: Point) -> Point {
        Point::add(&self, &rhs)
    }
}

impl core::ops::Sub for Point {
    type Output = Point;
    fn sub(self, rhs: Point) -> Point {
        Point::add(&self, &rhs.negate())
    }
}

impl core::ops::Neg for Point {
    type Output = Point;
    fn neg(self) -> Point {
        self.negate()
    }
}

impl core::ops::AddAssign for Point {
    fn add_assign(&mut self, rhs: Point) {
        *self = Point::add(self, &rhs);
    }
}

impl core::ops::Mul<Fr> for Point {
    type Output = Point;
    /// Constant-time scalar multiplication: see [`Point::mul`].
    fn mul(self, rhs: Fr) -> Point {
        Point::mul(&self, &rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(hex_bytes: &str) -> Point {
        let bytes: [u8; 32] = hex::decode(hex_bytes).unwrap().try_into().unwrap();
        Point::from_bytes(&bytes).expect("a point")
    }

    /// The spending key base, from `sapling_generators.json`.
    const G: &str = "30b5f2aaad325630bcdddbce4d67656d05fd1cc2d037bb5375b6e96d9e01a1d7";

    #[test]
    fn curve_constants() {
        assert_eq!(D * Fq::from_u64(10241), -Fq::from_u64(10240));
        assert!(AffinePoint::IDENTITY.is_on_curve());
        // d is not a square, which is what makes the addition law complete
        assert!(D.sqrt().is_none());
    }

    #[test]
    fn group_law() {
        let g = point(G);
        assert!(g.to_affine().is_on_curve());
        assert_eq!(hex::encode(g.to_bytes()), G);
        assert!(g.is_prime_order());
        assert!(!g.is_small_order());
        let o = Point::IDENTITY;
        assert_eq!(g + o, g);
        assert_eq!(o + o, o);
        assert_eq!(g - g, o);
        assert_eq!(g.double(), g + g);
        assert_eq!(o.double(), o);
        let g3 = g.double() + g;
        assert_eq!(g3, g + g.double());
        assert_eq!((g3 + g) + g.double(), g3 + (g + g.double()));
        assert!(g3.to_affine().is_on_curve());
        // scalar multiplication, both ways
        for k in [0u64, 1, 2, 3, 15, 16, 17, 0xdead_beef_0bad_f00d] {
            let s = Fr::from_u64(k);
            let mut expect = o;
            for i in (0..64).rev() {
                expect = expect.double();
                if (k >> i) & 1 == 1 {
                    expect += g;
                }
            }
            assert_eq!(g.mul(&s), expect);
            assert_eq!(g.mul_vartime(&s), expect);
        }
        let big = -Fr::from_u64(3);
        assert_eq!(g.mul(&big), -g3);
        assert_eq!(g.mul_vartime(&big), -g3);
        assert_eq!(g * (Fr::from_u64(77) * big), (g * Fr::from_u64(77)) * big);
        assert_eq!(g.mul_by_cofactor(), g * Fr::from_u64(8));
    }

    #[test]
    fn small_order_points() {
        // (0, -1) has order 2
        let two = AffinePoint::new(Fq::ZERO, -Fq::ONE).unwrap().to_point();
        assert!(!two.is_identity());
        assert_eq!(two.double(), Point::IDENTITY);
        assert!(two.is_small_order());
        assert!(!two.is_torsion_free());
        assert!(!two.is_prime_order());
        assert!(Point::IDENTITY.is_torsion_free());
        assert!(!Point::IDENTITY.is_prime_order());
        let mixed = point(G) + two;
        assert!(!mixed.is_small_order());
        assert!(!mixed.is_torsion_free());
        assert_eq!(mixed.mul_by_cofactor(), point(G).mul_by_cofactor());
        assert!(Point::from_bytes_prime_order(&mixed.to_bytes()).is_none());
        assert!(Point::from_bytes_prime_order(&point(G).to_bytes()).is_some());
        assert_eq!(Point::from_bytes(&mixed.to_bytes()), Some(mixed));
    }

    #[test]
    fn zip_216_canonical_encodings() {
        // the identity and the point of order two
        let mut id = [0u8; 32];
        id[0] = 1;
        assert_eq!(Point::from_bytes(&id), Some(Point::IDENTITY));
        let minus_one = (-Fq::ONE).to_bytes();
        assert!(Point::from_bytes(&minus_one).is_some());
        // the same with the sign bit set: the two non-canonical encodings
        id[31] |= 0x80;
        assert!(Point::from_bytes(&id).is_none());
        let mut bad = minus_one;
        bad[31] |= 0x80;
        assert!(Point::from_bytes(&bad).is_none());
        // v not reduced: q + 1 would otherwise decode as v = 1
        let mut q_plus_1 = [0u8; 32];
        for (chunk, limb) in q_plus_1.chunks_mut(8).zip(Fq::MODULUS) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        q_plus_1[0] += 1;
        assert!(Point::from_bytes(&q_plus_1).is_none());
        // a v with no matching u
        let mut count = 0;
        for i in 0u8..20 {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            if let Some(p) = AffinePoint::from_bytes(&bytes) {
                assert!(p.is_on_curve());
                assert_eq!(p.to_bytes(), bytes);
                count += 1;
            }
        }
        assert!(count > 3 && count < 17);
    }

    #[test]
    fn batch_normalization() {
        let g = point(G);
        let points = [g, g.double(), Point::IDENTITY, g.double().double() + g];
        let mut out = [AffinePoint::IDENTITY; 4];
        Point::batch_to_affine(&points, &mut out);
        for (p, a) in points.iter().zip(out) {
            assert_eq!(p.to_affine(), a);
        }
    }
}
