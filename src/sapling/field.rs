//! The two prime fields of Jubjub: its base field [`Fq`] (the scalar field of
//! BLS12-381, in which Sapling's circuits are written) and its scalar field
//! [`Fr`] (the order of the prime-order subgroup).
//!
//! Both are 255-bit and 252-bit primes held as four 64-bit limbs in
//! Montgomery form. Addition, subtraction, multiplication and inversion run
//! in constant time; the functions whose name ends in `_vartime`, and
//! [`Fq::sqrt`], do not and are meant for public values.
//!
//! `purecrypto` has a BLS12-381 scalar field, but only behind its `bls`
//! feature (which needs an allocator), without inversion or square roots and
//! without `const` constructors, so the arithmetic lives here.

use purecrypto::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use purecrypto::zeroize::DefaultIsZeroes;

const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let r = a as u128 + b as u128 + carry as u128;
    (r as u64, (r >> 64) as u64)
}

/// `a - b - borrow`, where the borrow in and out is either 0 or all ones.
const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let r = (a as u128).wrapping_sub(b as u128 + (borrow >> 63) as u128);
    (r as u64, (r >> 64) as u64)
}

/// `a + b * c + carry`.
const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let r = a as u128 + (b as u128 * c as u128) + carry as u128;
    (r as u64, (r >> 64) as u64)
}

const fn add_limbs(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let (r0, c) = adc(a[0], b[0], 0);
    let (r1, c) = adc(a[1], b[1], c);
    let (r2, c) = adc(a[2], b[2], c);
    let (r3, c) = adc(a[3], b[3], c);
    ([r0, r1, r2, r3], c)
}

/// `a - b` and a borrow that is all ones when `a < b`.
const fn sub_limbs(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let (r0, c) = sbb(a[0], b[0], 0);
    let (r1, c) = sbb(a[1], b[1], c);
    let (r2, c) = sbb(a[2], b[2], c);
    let (r3, c) = sbb(a[3], b[3], c);
    ([r0, r1, r2, r3], c)
}

/// `b` where `mask` is all ones, `a` where it is zero.
const fn select_limbs(a: &[u64; 4], b: &[u64; 4], mask: u64) -> [u64; 4] {
    [
        (a[0] & !mask) | (b[0] & mask),
        (a[1] & !mask) | (b[1] & mask),
        (a[2] & !mask) | (b[2] & mask),
        (a[3] & !mask) | (b[3] & mask),
    ]
}

/// Reduces `value + carry * 2^256`, known to be below `2m`, modulo `m`.
const fn reduce_once(value: &[u64; 4], carry: u64, m: &[u64; 4]) -> [u64; 4] {
    let (d, borrow) = sub_limbs(value, m);
    // the subtraction underflows as a whole only without a carry in
    let keep = borrow & carry.wrapping_sub(1);
    select_limbs(&d, value, keep)
}

const fn add_mod(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
    let (s, c) = add_limbs(a, b);
    reduce_once(&s, c, m)
}

const fn sub_mod(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
    let (d, borrow) = sub_limbs(a, b);
    let masked = [m[0] & borrow, m[1] & borrow, m[2] & borrow, m[3] & borrow];
    add_limbs(&d, &masked).0
}

/// `-m^-1 mod 2^64` for an odd `m`.
const fn mont_inv(m0: u64) -> u64 {
    let mut inv = 1u64;
    let mut i = 0;
    while i < 63 {
        inv = inv.wrapping_mul(inv);
        inv = inv.wrapping_mul(m0);
        i += 1;
    }
    inv.wrapping_neg()
}

/// Montgomery multiplication: `a * b / 2^256 mod m`. One operand may be any
/// 256-bit value as long as the other is reduced.
const fn mont_mul(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4], inv: u64) -> [u64; 4] {
    let mut t = [0u64; 8];
    let mut i = 0;
    while i < 4 {
        let mut carry = 0;
        let mut j = 0;
        while j < 4 {
            let (lo, c) = mac(t[i + j], a[i], b[j], carry);
            t[i + j] = lo;
            carry = c;
            j += 1;
        }
        t[i + 4] = carry;
        i += 1;
    }
    let mut carry2 = 0;
    let mut i = 0;
    while i < 4 {
        let k = t[i].wrapping_mul(inv);
        let mut carry = 0;
        let mut j = 0;
        while j < 4 {
            let (lo, c) = mac(t[i + j], k, m[j], carry);
            t[i + j] = lo;
            carry = c;
            j += 1;
        }
        let (s, c) = adc(t[i + 4], carry2, carry);
        t[i + 4] = s;
        carry2 = c;
        i += 1;
    }
    reduce_once(&[t[4], t[5], t[6], t[7]], carry2, m)
}

/// `2^bits mod m`.
const fn pow2_mod(bits: usize, m: &[u64; 4]) -> [u64; 4] {
    let mut r = [1, 0, 0, 0];
    let mut i = 0;
    while i < bits {
        r = add_mod(&r, &r, m);
        i += 1;
    }
    r
}

/// `base^exp` in Montgomery form, by square-and-multiply over the bits of
/// `exp`: the sequence of operations depends on the exponent only.
const fn mont_pow(
    base: &[u64; 4],
    exp: &[u64; 4],
    one: &[u64; 4],
    m: &[u64; 4],
    inv: u64,
) -> [u64; 4] {
    let mut r = *one;
    let mut i = 256;
    while i > 0 {
        i -= 1;
        r = mont_mul(&r, &r, m, inv);
        if (exp[i / 64] >> (i % 64)) & 1 == 1 {
            r = mont_mul(&r, base, m, inv);
        }
    }
    r
}

const fn limbs_from_le(bytes: &[u8; 32]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut i = 0;
    while i < 32 {
        r[i / 8] |= (bytes[i] as u64) << (8 * (i % 8));
        i += 1;
    }
    r
}

const fn limbs_to_le(limbs: &[u64; 4]) -> [u8; 32] {
    let mut r = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        r[i] = (limbs[i / 8] >> (8 * (i % 8))) as u8;
        i += 1;
    }
    r
}

/// `limbs >> bits` for `bits < 64`.
const fn shr_limbs(limbs: &[u64; 4], bits: u32) -> [u64; 4] {
    if bits == 0 {
        return *limbs;
    }
    [
        limbs[0] >> bits | limbs[1] << (64 - bits),
        limbs[1] >> bits | limbs[2] << (64 - bits),
        limbs[2] >> bits | limbs[3] << (64 - bits),
        limbs[3] >> bits,
    ]
}

macro_rules! define_field {
    ($(#[$meta:meta])* $name:ident, $modulus:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Default)]
        pub struct $name([u64; 4]);

        impl $name {
            /// The modulus, as little-endian 64-bit limbs.
            pub const MODULUS: [u64; 4] = $modulus;
            const INV: u64 = mont_inv(Self::MODULUS[0]);
            const R: [u64; 4] = pow2_mod(256, &Self::MODULUS);
            const R2: [u64; 4] = pow2_mod(512, &Self::MODULUS);
            const R3: [u64; 4] = mont_mul(&Self::R2, &Self::R2, &Self::MODULUS, Self::INV);
            const MODULUS_MINUS_2: [u64; 4] =
                sub_limbs(&Self::MODULUS, &[2, 0, 0, 0]).0;

            /// The additive identity.
            pub const ZERO: Self = Self([0; 4]);
            /// The multiplicative identity.
            pub const ONE: Self = Self(Self::R);

            /// The element with the given little-endian limbs, reduced
            /// modulo the field order.
            pub const fn from_raw(limbs: [u64; 4]) -> Self {
                Self(mont_mul(&limbs, &Self::R2, &Self::MODULUS, Self::INV))
            }

            /// The element `v`.
            pub const fn from_u64(v: u64) -> Self {
                Self::from_raw([v, 0, 0, 0])
            }

            /// The canonical little-endian limbs of this element.
            pub const fn to_raw(&self) -> [u64; 4] {
                mont_mul(&self.0, &[1, 0, 0, 0], &Self::MODULUS, Self::INV)
            }

            /// Decodes a little-endian 32-byte encoding, rejecting values
            /// that are not below the field order.
            pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
                let limbs = limbs_from_le(bytes);
                let (_, borrow) = sub_limbs(&limbs, &Self::MODULUS);
                // only whether the encoding is canonical is revealed
                (borrow != 0).then(|| Self::from_raw(limbs))
            }

            /// Reduces a little-endian 32-byte integer modulo the field
            /// order.
            pub const fn from_bytes_reduced(bytes: &[u8; 32]) -> Self {
                Self::from_raw(limbs_from_le(bytes))
            }

            /// Reduces a little-endian 64-byte integer modulo the field
            /// order.
            pub const fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
                let mut lo = [0u8; 32];
                let mut hi = [0u8; 32];
                let mut i = 0;
                while i < 32 {
                    lo[i] = bytes[i];
                    hi[i] = bytes[32 + i];
                    i += 1;
                }
                let lo = mont_mul(&limbs_from_le(&lo), &Self::R2, &Self::MODULUS, Self::INV);
                let hi = mont_mul(&limbs_from_le(&hi), &Self::R3, &Self::MODULUS, Self::INV);
                Self(add_mod(&lo, &hi, &Self::MODULUS))
            }

            /// The canonical little-endian 32-byte encoding.
            pub const fn to_bytes(&self) -> [u8; 32] {
                limbs_to_le(&self.to_raw())
            }

            /// `self + rhs`, usable in constants.
            pub const fn const_add(&self, rhs: &Self) -> Self {
                Self(add_mod(&self.0, &rhs.0, &Self::MODULUS))
            }

            /// `self - rhs`, usable in constants.
            pub const fn const_sub(&self, rhs: &Self) -> Self {
                Self(sub_mod(&self.0, &rhs.0, &Self::MODULUS))
            }

            /// `self * rhs`, usable in constants.
            pub const fn const_mul(&self, rhs: &Self) -> Self {
                Self(mont_mul(&self.0, &rhs.0, &Self::MODULUS, Self::INV))
            }

            /// `-self`, usable in constants.
            pub const fn const_neg(&self) -> Self {
                Self(sub_mod(&[0; 4], &self.0, &Self::MODULUS))
            }

            /// `2 * self`.
            pub const fn double(&self) -> Self {
                self.const_add(self)
            }

            /// `self * self`.
            pub const fn square(&self) -> Self {
                self.const_mul(self)
            }

            /// `self^exp` for an exponent given as little-endian limbs. The
            /// running time depends on the exponent, not on `self`.
            pub const fn pow_vartime(&self, exp: &[u64; 4]) -> Self {
                Self(mont_pow(&self.0, exp, &Self::R, &Self::MODULUS, Self::INV))
            }

            /// The multiplicative inverse, or `None` for zero. Constant time
            /// in the value (Fermat's little theorem).
            pub fn invert(&self) -> Option<Self> {
                let inv = self.pow_vartime(&Self::MODULUS_MINUS_2);
                (!self.is_zero()).then_some(inv)
            }

            /// Whether this is zero.
            pub fn is_zero(&self) -> bool {
                bool::from(self.ct_eq(&Self::ZERO))
            }

            /// Whether the canonical representative is odd.
            pub const fn is_odd(&self) -> bool {
                self.to_raw()[0] & 1 == 1
            }
        }

        impl ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> Choice {
                // Montgomery representatives are kept fully reduced
                self.0.ct_eq(&other.0)
            }
        }

        impl ConditionallySelectable for $name {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                Self(<[u64; 4]>::conditional_select(&a.0, &b.0, choice))
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                bool::from(self.ct_eq(other))
            }
        }

        impl Eq for $name {}

        impl DefaultIsZeroes for $name {}

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(0x"))?;
                for byte in self.to_bytes().iter().rev() {
                    write!(f, "{byte:02x}")?;
                }
                f.write_str(")")
            }
        }

        impl core::ops::Add for $name {
            type Output = Self;
            fn add(self, rhs: Self) -> Self {
                self.const_add(&rhs)
            }
        }

        impl core::ops::Sub for $name {
            type Output = Self;
            fn sub(self, rhs: Self) -> Self {
                self.const_sub(&rhs)
            }
        }

        impl core::ops::Mul for $name {
            type Output = Self;
            fn mul(self, rhs: Self) -> Self {
                self.const_mul(&rhs)
            }
        }

        impl core::ops::Neg for $name {
            type Output = Self;
            fn neg(self) -> Self {
                self.const_neg()
            }
        }

        impl core::ops::AddAssign for $name {
            fn add_assign(&mut self, rhs: Self) {
                *self = *self + rhs;
            }
        }

        impl core::ops::SubAssign for $name {
            fn sub_assign(&mut self, rhs: Self) {
                *self = *self - rhs;
            }
        }

        impl core::ops::MulAssign for $name {
            fn mul_assign(&mut self, rhs: Self) {
                *self = *self * rhs;
            }
        }
    };
}

define_field!(
    /// An element of the Jubjub base field: the integers modulo
    /// `q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`,
    /// which is also the scalar field of BLS12-381 (so the field Sapling's
    /// Groth16 circuits compute in).
    Fq,
    [
        0xffff_ffff_0000_0001,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ]
);

define_field!(
    /// A Jubjub scalar: an integer modulo the order of the prime-order
    /// subgroup,
    /// `r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7`.
    Fr,
    [
        0xd097_0e5e_d6f7_2cb7,
        0xa668_2093_ccc8_1082,
        0x0667_3b01_0134_3b00,
        0x0e7d_b4ea_6533_afa9,
    ]
);

impl Fq {
    /// `q - 1 = 2^S * T` with `T` odd.
    pub const S: u32 = 32;
    const T: [u64; 4] = shr_limbs(&Self::MODULUS, 32);
    const T_MINUS_1_OVER_2: [u64; 4] = shr_limbs(&Self::T, 1);

    /// A generator of the multiplicative group (7), as BLS12-381 defines it.
    pub const MULTIPLICATIVE_GENERATOR: Fq = Fq::from_u64(7);

    /// A primitive `2^32`-th root of unity: the generator raised to `T`.
    pub const ROOT_OF_UNITY: Fq = Fq::MULTIPLICATIVE_GENERATOR.pow_vartime(&Self::T);

    /// A square root, or `None` for a non-residue (Tonelli–Shanks). Which of
    /// the two roots is returned is unspecified. Not constant time: this is
    /// used to decompress points, which are public.
    pub fn sqrt(&self) -> Option<Fq> {
        if self.is_zero() {
            return Some(Fq::ZERO);
        }
        let w = self.pow_vartime(&Self::T_MINUS_1_OVER_2);
        let mut r = *self * w; // self^((T + 1) / 2)
        let mut t = r * w; // self^T
        let mut c = Self::ROOT_OF_UNITY;
        let mut m = Self::S;
        while t != Fq::ONE {
            let mut i = 1;
            let mut t2i = t.square();
            while t2i != Fq::ONE {
                t2i = t2i.square();
                i += 1;
                if i >= m {
                    return None;
                }
            }
            for _ in 0..m - i - 1 {
                c = c.square();
            }
            r *= c;
            c = c.square();
            t *= c;
            m = i;
        }
        (r.square() == *self).then_some(r)
    }
}

impl Fr {
    /// The number of bits of the modulus.
    pub const NUM_BITS: u32 = 252;

    /// The scalar for a signed 64-bit integer (a value balance).
    pub fn from_i64(v: i64) -> Fr {
        let abs = Fr::from_u64(v.unsigned_abs());
        if v < 0 { -abs } else { abs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A few elements exercising carries.
    fn samples<F>(from: impl Fn([u64; 4]) -> F) -> [F; 5] {
        [
            from([0, 0, 0, 0]),
            from([1, 0, 0, 0]),
            from([u64::MAX, u64::MAX, u64::MAX, u64::MAX]),
            from([0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210, 7, 0x0123]),
            from([0xdead_beef, u64::MAX, 0, 0x7fff_ffff_ffff_ffff]),
        ]
    }

    macro_rules! field_laws {
        ($name:ident, $f:ident) => {
            #[test]
            fn $name() {
                let m1 = $f::from_raw(sub_limbs(&$f::MODULUS, &[1, 0, 0, 0]).0);
                assert_eq!(m1 + $f::ONE, $f::ZERO);
                assert_eq!(-$f::ONE, m1);
                assert_eq!($f::from_raw($f::MODULUS), $f::ZERO);
                assert_eq!(m1 * m1, $f::ONE);
                assert_eq!($f::ONE.to_raw(), [1, 0, 0, 0]);
                assert!($f::ZERO.invert().is_none());
                let xs = samples($f::from_raw);
                for a in xs {
                    assert_eq!($f::from_bytes(&a.to_bytes()), Some(a));
                    assert_eq!(a - a, $f::ZERO);
                    assert_eq!(a + (-a), $f::ZERO);
                    assert_eq!(a.double(), a + a);
                    assert_eq!(a.square(), a * a);
                    if let Some(inv) = a.invert() {
                        assert_eq!(a * inv, $f::ONE);
                    } else {
                        assert!(a.is_zero());
                    }
                    for b in xs {
                        assert_eq!(a + b, b + a);
                        assert_eq!(a * b, b * a);
                        assert_eq!((a - b) + b, a);
                        for c in xs {
                            assert_eq!((a + b) * c, a * c + b * c);
                            assert_eq!((a * b) * c, a * (b * c));
                        }
                    }
                }
                // the modulus and above are not canonical encodings
                assert!($f::from_bytes(&limbs_to_le(&$f::MODULUS)).is_none());
                assert!($f::from_bytes(&[0xff; 32]).is_none());
                assert_eq!($f::from_bytes(&m1.to_bytes()), Some(m1));
                // wide reduction: 2^256 * hi + lo
                let mut wide = [0u8; 64];
                wide[..32].copy_from_slice(&xs[3].to_bytes());
                wide[32..].copy_from_slice(&xs[4].to_bytes());
                let two_256 = $f::from_raw([0, 0, 1, 0]).square();
                assert_eq!($f::from_bytes_wide(&wide), xs[3] + xs[4] * two_256);
                assert_eq!($f::from_bytes_wide(&[0xff; 64]), two_256.square() - $f::ONE);
            }
        };
    }

    field_laws!(fq_laws, Fq);
    field_laws!(fr_laws, Fr);

    #[test]
    fn moduli_match_the_specification() {
        // q_J and r_J in decimal, from the protocol specification §5.4.9.3
        fn decimal<F: Copy + core::ops::Mul<Output = F> + core::ops::Add<Output = F>>(
            s: &str,
            from: impl Fn(u64) -> F,
        ) -> F {
            s.bytes().fold(from(0), |acc, d| {
                acc * from(10) + from(u64::from(d - b'0'))
            })
        }
        // q - 1 and r - 1, which are representable
        assert_eq!(
            decimal(
                "52435875175126190479447740508185965837690552500527637822603658699938581184512",
                Fq::from_u64
            ),
            -Fq::ONE
        );
        assert_eq!(
            decimal(
                "6554484396890773809930967563523245729705921265872317281365359162392183254198",
                Fr::from_u64
            ),
            -Fr::ONE
        );
        // and the same digits, computed in the other field, are not -1
        assert_ne!(
            decimal(
                "6554484396890773809930967563523245729705921265872317281365359162392183254198",
                Fq::from_u64
            ),
            -Fq::ONE
        );
    }

    #[test]
    fn square_roots() {
        // the root of unity has order exactly 2^32
        let mut x = Fq::ROOT_OF_UNITY;
        for _ in 0..31 {
            x = x.square();
        }
        assert_eq!(x, -Fq::ONE);
        let a = -samples(Fq::from_raw)[3];
        for v in [a, Fq::from_u64(4), Fq::ROOT_OF_UNITY, Fq::ZERO, Fq::ONE] {
            let sq = v.square();
            let root = sq.sqrt().expect("a square");
            assert!(root == v || root == -v);
        }
        // 7 generates the multiplicative group, so it is not a square
        assert!(Fq::MULTIPLICATIVE_GENERATOR.sqrt().is_none());
        assert!((Fq::MULTIPLICATIVE_GENERATOR * Fq::from_u64(9)).sqrt().is_none());
    }

    #[test]
    fn signed_scalars() {
        assert_eq!(Fr::from_i64(-5) + Fr::from_u64(5), Fr::ZERO);
        assert_eq!(Fr::from_i64(i64::MIN) + Fr::from_u64(1 << 63), Fr::ZERO);
        assert_eq!(Fr::from_i64(i64::MAX), Fr::from_u64(i64::MAX as u64));
    }
}
