//! The two prime fields of the Pasta curve cycle.
//!
//! [`Fp`] is the base field of Pallas and the scalar field of Vesta; [`Fq`] is
//! the scalar field of Pallas and the base field of Vesta. Both moduli are
//! 255 bits long and of the form `t * 2^32 + 1`, which gives each field a
//! multiplicative subgroup of order `2^32` (the evaluation domains a Halo 2
//! prover runs its FFTs over).
//!
//! Elements are kept in Montgomery form on four 64-bit limbs. Arithmetic has no
//! secret-dependent branches or memory accesses; the functions whose name ends
//! in `_vartime` are the exception and say so.

use purecrypto::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use purecrypto::zeroize::Zeroize;

/// `a + b + carry`, as (sum, carry).
#[inline(always)]
const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let r = a as u128 + b as u128 + carry as u128;
    (r as u64, (r >> 64) as u64)
}

/// `a - b - borrow`, as (difference, borrow), the borrow being 0 or all ones.
#[inline(always)]
const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let r = (a as u128).wrapping_sub(b as u128 + (borrow >> 63) as u128);
    (r as u64, (r >> 64) as u64)
}

/// `a + b * c + carry`, as (low, high).
#[inline(always)]
const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let r = a as u128 + (b as u128 * c as u128) + carry as u128;
    (r as u64, (r >> 64) as u64)
}

/// `a - m` when `a >= m`, else `a`; `a` must be below `2m`.
#[inline(always)]
const fn sub_cond(a: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
    let (d0, b) = sbb(a[0], m[0], 0);
    let (d1, b) = sbb(a[1], m[1], b);
    let (d2, b) = sbb(a[2], m[2], b);
    let (d3, b) = sbb(a[3], m[3], b);
    // a borrow means a < m: keep a
    [
        d0 ^ ((a[0] ^ d0) & b),
        d1 ^ ((a[1] ^ d1) & b),
        d2 ^ ((a[2] ^ d2) & b),
        d3 ^ ((a[3] ^ d3) & b),
    ]
}

#[inline(always)]
const fn add_mod(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
    // both below m < 2^255: the sum fits
    let (s0, c) = adc(a[0], b[0], 0);
    let (s1, c) = adc(a[1], b[1], c);
    let (s2, c) = adc(a[2], b[2], c);
    let (s3, _) = adc(a[3], b[3], c);
    sub_cond(&[s0, s1, s2, s3], m)
}

#[inline(always)]
const fn sub_mod(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
    let (d0, w) = sbb(a[0], b[0], 0);
    let (d1, w) = sbb(a[1], b[1], w);
    let (d2, w) = sbb(a[2], b[2], w);
    let (d3, w) = sbb(a[3], b[3], w);
    let (d0, c) = adc(d0, m[0] & w, 0);
    let (d1, c) = adc(d1, m[1] & w, c);
    let (d2, c) = adc(d2, m[2] & w, c);
    let (d3, _) = adc(d3, m[3] & w, c);
    [d0, d1, d2, d3]
}

/// Montgomery reduction of an 8-limb value below `m * 2^256`.
#[inline(always)]
const fn mont_reduce(t: &[u64; 8], m: &[u64; 4], inv: u64) -> [u64; 4] {
    let k = t[0].wrapping_mul(inv);
    let (_, carry) = mac(t[0], k, m[0], 0);
    let (r1, carry) = mac(t[1], k, m[1], carry);
    let (r2, carry) = mac(t[2], k, m[2], carry);
    let (r3, carry) = mac(t[3], k, m[3], carry);
    let (r4, carry2) = adc(t[4], 0, carry);

    let k = r1.wrapping_mul(inv);
    let (_, carry) = mac(r1, k, m[0], 0);
    let (r2, carry) = mac(r2, k, m[1], carry);
    let (r3, carry) = mac(r3, k, m[2], carry);
    let (r4, carry) = mac(r4, k, m[3], carry);
    let (r5, carry2) = adc(t[5], carry2, carry);

    let k = r2.wrapping_mul(inv);
    let (_, carry) = mac(r2, k, m[0], 0);
    let (r3, carry) = mac(r3, k, m[1], carry);
    let (r4, carry) = mac(r4, k, m[2], carry);
    let (r5, carry) = mac(r5, k, m[3], carry);
    let (r6, carry2) = adc(t[6], carry2, carry);

    let k = r3.wrapping_mul(inv);
    let (_, carry) = mac(r3, k, m[0], 0);
    let (r4, carry) = mac(r4, k, m[1], carry);
    let (r5, carry) = mac(r5, k, m[2], carry);
    let (r6, carry) = mac(r6, k, m[3], carry);
    let (r7, _) = adc(t[7], carry2, carry);

    sub_cond(&[r4, r5, r6, r7], m)
}

#[inline(always)]
const fn mont_mul(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4], inv: u64) -> [u64; 4] {
    let (r0, carry) = mac(0, a[0], b[0], 0);
    let (r1, carry) = mac(0, a[0], b[1], carry);
    let (r2, carry) = mac(0, a[0], b[2], carry);
    let (r3, r4) = mac(0, a[0], b[3], carry);

    let (r1, carry) = mac(r1, a[1], b[0], 0);
    let (r2, carry) = mac(r2, a[1], b[1], carry);
    let (r3, carry) = mac(r3, a[1], b[2], carry);
    let (r4, r5) = mac(r4, a[1], b[3], carry);

    let (r2, carry) = mac(r2, a[2], b[0], 0);
    let (r3, carry) = mac(r3, a[2], b[1], carry);
    let (r4, carry) = mac(r4, a[2], b[2], carry);
    let (r5, r6) = mac(r5, a[2], b[3], carry);

    let (r3, carry) = mac(r3, a[3], b[0], 0);
    let (r4, carry) = mac(r4, a[3], b[1], carry);
    let (r5, carry) = mac(r5, a[3], b[2], carry);
    let (r6, r7) = mac(r6, a[3], b[3], carry);

    mont_reduce(&[r0, r1, r2, r3, r4, r5, r6, r7], m, inv)
}

/// `-m^-1 mod 2^64` for an odd `m`.
const fn neg_inv64(m0: u64) -> u64 {
    let mut inv = 1u64;
    let mut i = 0;
    while i < 63 {
        inv = inv.wrapping_mul(inv);
        inv = inv.wrapping_mul(m0);
        i += 1;
    }
    inv.wrapping_neg()
}

/// `2^n mod m`.
const fn two_pow_mod(n: usize, m: &[u64; 4]) -> [u64; 4] {
    let mut x = [1u64, 0, 0, 0];
    let mut i = 0;
    while i < n {
        x = add_mod(&x, &x, m);
        i += 1;
    }
    x
}

/// `a >> n` for `n < 64`.
const fn shr(a: &[u64; 4], n: u32) -> [u64; 4] {
    [
        a[0] >> n | a[1] << (64 - n),
        a[1] >> n | a[2] << (64 - n),
        a[2] >> n | a[3] << (64 - n),
        a[3] >> n,
    ]
}

macro_rules! pasta_field {
    (
        $(#[$meta:meta])*
        $name:ident, modulus = $modulus:expr, zeta = $zeta:expr
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Default)]
        pub struct $name([u64; 4]);

        impl $name {
            /// The modulus, as little-endian 64-bit limbs.
            pub const MODULUS: [u64; 4] = $modulus;
            /// Bits needed to represent the modulus.
            pub const NUM_BITS: u32 = 255;
            /// The largest bit length every value of which is an element.
            pub const CAPACITY: u32 = 254;
            /// The 2-adicity of the field: `MODULUS - 1 = t * 2^S` with `t`
            /// odd.
            pub const S: u32 = 32;

            const INV: u64 = neg_inv64(Self::MODULUS[0]);
            const R: [u64; 4] = two_pow_mod(256, &Self::MODULUS);
            const R2: [u64; 4] = two_pow_mod(512, &Self::MODULUS);
            const R3: [u64; 4] =
                mont_mul(&Self::R2, &Self::R2, &Self::MODULUS, Self::INV);
            /// `t`, the odd part of `MODULUS - 1`.
            const T: [u64; 4] = shr(&Self::MODULUS, 32);
            /// `(t - 1) / 2`.
            const T_MINUS1_OVER2: [u64; 4] = shr(&Self::T, 1);
            const MODULUS_MINUS_2: [u64; 4] = [
                Self::MODULUS[0] - 2,
                Self::MODULUS[1],
                Self::MODULUS[2],
                Self::MODULUS[3],
            ];

            /// The additive identity.
            pub const ZERO: Self = Self([0; 4]);
            /// The multiplicative identity.
            pub const ONE: Self = Self(Self::R);
            /// A generator of the multiplicative group (5), which is also a
            /// quadratic non-residue.
            pub const MULTIPLICATIVE_GENERATOR: Self = Self::from_raw([5, 0, 0, 0]);
            /// A primitive `2^S`-th root of unity:
            /// `MULTIPLICATIVE_GENERATOR^t`.
            pub const ROOT_OF_UNITY: Self =
                Self::MULTIPLICATIVE_GENERATOR.pow_const(&Self::T);
            /// The inverse of [`ROOT_OF_UNITY`](Self::ROOT_OF_UNITY).
            pub const ROOT_OF_UNITY_INV: Self =
                Self::ROOT_OF_UNITY.pow_const(&[0xffff_ffff, 0, 0, 0]);
            /// `MULTIPLICATIVE_GENERATOR^(2^S)`, a generator of the subgroup
            /// of order `t`; its powers are the coset shifts of a Halo 2
            /// permutation argument.
            pub const DELTA: Self =
                Self::MULTIPLICATIVE_GENERATOR.pow_const(&[1 << 32, 0, 0, 0]);
            /// The inverse of two.
            pub const TWO_INV: Self = Self::from_raw([2, 0, 0, 0]).invert_const();
            /// A primitive cube root of unity (the one `pasta_curves` fixes),
            /// which gives the curve endomorphism `(x, y) -> (ZETA * x, y)`.
            pub const ZETA: Self = Self::from_raw($zeta);

            /// `ROOT_OF_UNITY^((t + 1) / 2)` and `ROOT_OF_UNITY^t`: what
            /// turns the square-root state of `a` into that of
            /// `ROOT_OF_UNITY * a`.
            const SQRT_C1: Self = Self::ROOT_OF_UNITY
                .pow_const(&Self::T_MINUS1_OVER2)
                .mul_const(&Self::ROOT_OF_UNITY);
            const SQRT_C2: Self = Self::ROOT_OF_UNITY.pow_const(&Self::T);

            /// The element congruent to the integer given as little-endian
            /// limbs (any 256-bit value; it is reduced).
            pub const fn from_raw(limbs: [u64; 4]) -> Self {
                Self(mont_mul(&limbs, &Self::R2, &Self::MODULUS, Self::INV))
            }

            /// The element for a small integer.
            pub const fn from_u64(v: u64) -> Self {
                Self::from_raw([v, 0, 0, 0])
            }

            /// The element for a 128-bit integer.
            pub const fn from_u128(v: u128) -> Self {
                Self::from_raw([v as u64, (v >> 64) as u64, 0, 0])
            }

            /// The element whose Montgomery form (`value * 2^256 mod
            /// MODULUS`, little-endian limbs) is given, without any check:
            /// the limbs must be below the modulus. This is for tables of
            /// precomputed constants, see
            /// [`to_montgomery`](Self::to_montgomery).
            pub const fn from_montgomery_unchecked(limbs: [u64; 4]) -> Self {
                Self(limbs)
            }

            /// The Montgomery form of this element, the inverse of
            /// [`from_montgomery_unchecked`](Self::from_montgomery_unchecked).
            pub const fn to_montgomery(&self) -> [u64; 4] {
                self.0
            }

            /// The canonical integer value, as little-endian limbs.
            pub const fn to_raw(&self) -> [u64; 4] {
                mont_reduce(
                    &[self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0],
                    &Self::MODULUS,
                    Self::INV,
                )
            }

            /// Decodes the canonical 32-byte little-endian encoding, or
            /// `None` if the value is not below the modulus.
            pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
                let limbs = le_limbs(bytes);
                let (_, b) = sbb(limbs[0], Self::MODULUS[0], 0);
                let (_, b) = sbb(limbs[1], Self::MODULUS[1], b);
                let (_, b) = sbb(limbs[2], Self::MODULUS[2], b);
                let (_, b) = sbb(limbs[3], Self::MODULUS[3], b);
                // a borrow means the value is below the modulus
                if bool::from(Choice::from((b & 1) as u8)) {
                    Some(Self::from_raw(limbs))
                } else {
                    None
                }
            }

            /// Interprets 32 little-endian bytes as an integer and reduces
            /// it.
            pub fn from_bytes_reduced(bytes: &[u8; 32]) -> Self {
                Self::from_raw(le_limbs(bytes))
            }

            /// Interprets 64 little-endian bytes as an integer and reduces
            /// it (`ToBase` / `ToScalar` of the protocol specification; the
            /// result is uniform when the bytes are).
            pub fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
                let lo = le_limbs(bytes[..32].try_into().expect("32 bytes"));
                let hi = le_limbs(bytes[32..].try_into().expect("32 bytes"));
                let lo = Self(mont_mul(&lo, &Self::R2, &Self::MODULUS, Self::INV));
                let hi = Self(mont_mul(&hi, &Self::R3, &Self::MODULUS, Self::INV));
                lo.add(&hi)
            }

            /// The canonical 32-byte little-endian encoding.
            pub fn to_bytes(&self) -> [u8; 32] {
                let limbs = self.to_raw();
                let mut out = [0u8; 32];
                for (chunk, limb) in out.as_chunks_mut::<8>().0.iter_mut().zip(limbs) {
                    *chunk = limb.to_le_bytes();
                }
                out
            }

            /// `self + rhs`.
            #[inline]
            pub const fn add(&self, rhs: &Self) -> Self {
                Self(add_mod(&self.0, &rhs.0, &Self::MODULUS))
            }

            /// `self - rhs`.
            #[inline]
            pub const fn sub(&self, rhs: &Self) -> Self {
                Self(sub_mod(&self.0, &rhs.0, &Self::MODULUS))
            }

            /// `-self`.
            #[inline]
            pub const fn neg(&self) -> Self {
                Self(sub_mod(&[0; 4], &self.0, &Self::MODULUS))
            }

            /// `2 * self`.
            #[inline]
            pub const fn double(&self) -> Self {
                self.add(self)
            }

            /// `self * rhs`.
            #[inline]
            pub const fn mul_const(&self, rhs: &Self) -> Self {
                Self(mont_mul(&self.0, &rhs.0, &Self::MODULUS, Self::INV))
            }

            /// `self * self`.
            #[inline]
            pub const fn square(&self) -> Self {
                self.mul_const(self)
            }

            /// `self^exp` for a public exponent given as little-endian
            /// limbs, usable in constants. The running time depends on the
            /// exponent (not on `self`).
            pub const fn pow_const(&self, exp: &[u64; 4]) -> Self {
                let mut acc = Self::ONE;
                let mut i = 256;
                while i > 0 {
                    i -= 1;
                    acc = acc.square();
                    if (exp[i / 64] >> (i % 64)) & 1 == 1 {
                        acc = acc.mul_const(self);
                    }
                }
                acc
            }

            /// `self^exp` for a public exponent; the running time depends
            /// on the exponent (not on `self`).
            pub fn pow_vartime(&self, exp: &[u64; 4]) -> Self {
                // 4-bit fixed windows over the public exponent
                let mut table = [Self::ONE; 16];
                for i in 1..16 {
                    table[i] = table[i - 1].mul_const(self);
                }
                let mut acc = Self::ONE;
                let mut started = false;
                for i in (0..64).rev() {
                    let nibble = ((exp[i / 16] >> (4 * (i % 16))) & 0xf) as usize;
                    if started {
                        acc = acc.square().square().square().square();
                    }
                    if nibble != 0 {
                        acc = acc.mul_const(&table[nibble]);
                        started = true;
                    }
                }
                acc
            }

            /// `self^exp` in time independent of both.
            pub fn pow(&self, exp: &[u64; 4]) -> Self {
                let mut acc = Self::ONE;
                for i in (0..256).rev() {
                    acc = acc.square();
                    let bit = Choice::from(((exp[i / 64] >> (i % 64)) & 1) as u8);
                    acc = Self::conditional_select(&acc.mul_const(self), &acc, bit);
                }
                acc
            }

            const fn invert_const(&self) -> Self {
                self.pow_const(&Self::MODULUS_MINUS_2)
            }

            /// The multiplicative inverse, with zero mapped to zero
            /// (`inv0`).
            pub fn invert_or_zero(&self) -> Self {
                self.pow_vartime(&Self::MODULUS_MINUS_2)
            }

            /// The multiplicative inverse, or `None` for zero.
            pub fn invert(&self) -> Option<Self> {
                if bool::from(self.is_zero()) {
                    None
                } else {
                    Some(self.invert_or_zero())
                }
            }

            /// Inverts every element of `elems` in place with a single field
            /// inversion (Montgomery's trick), leaving zeros as zeros.
            /// `scratch` must be at least as long as `elems`.
            ///
            /// # Panics
            /// Panics if `scratch` is shorter than `elems`.
            pub fn batch_invert(elems: &mut [Self], scratch: &mut [Self]) {
                assert!(scratch.len() >= elems.len(), "scratch too short");
                let mut acc = Self::ONE;
                for (e, s) in elems.iter().zip(scratch.iter_mut()) {
                    *s = acc;
                    acc = Self::conditional_select(&acc, &acc.mul_const(e), e.is_zero());
                }
                let mut inv = acc.invert_or_zero();
                for (e, s) in elems.iter_mut().zip(scratch.iter()).rev() {
                    let zero = e.is_zero();
                    let out = inv.mul_const(s);
                    inv = Self::conditional_select(&inv, &inv.mul_const(e), zero);
                    *e = Self::conditional_select(e, &out, zero);
                }
            }

            /// A square root of `self` when it has one; otherwise a square
            /// root of `ROOT_OF_UNITY * self`. The flag tells which (set for
            /// a square, zero included).
            pub fn sqrt_alt(&self) -> (Choice, Self) {
                // Tonelli-Shanks: x^2 = a * b throughout, b being driven to 1
                let w = self.pow_vartime(&Self::T_MINUS1_OVER2);
                let mut x = self.mul_const(&w);
                let mut b = x.mul_const(&w);
                let mut l = b;
                for _ in 0..Self::S - 1 {
                    l = l.square();
                }
                let is_square = l.ct_eq(&Self::ONE) | self.is_zero();
                x = Self::conditional_select(&x, &x.mul_const(&Self::SQRT_C1), is_square);
                b = Self::conditional_select(&b, &b.mul_const(&Self::SQRT_C2), is_square);
                let mut z = Self::ROOT_OF_UNITY;
                for i in (0..Self::S - 1).rev() {
                    let mut t = b;
                    for _ in 0..i {
                        t = t.square();
                    }
                    let fix = !t.ct_eq(&Self::ONE);
                    let zz = z.square();
                    x = Self::conditional_select(&x.mul_const(&z), &x, fix);
                    b = Self::conditional_select(&b.mul_const(&zz), &b, fix);
                    z = zz;
                }
                (is_square, x)
            }

            /// A square root (either one), or `None` if there is none.
            pub fn sqrt(&self) -> Option<Self> {
                let (is_square, root) = self.sqrt_alt();
                if bool::from(is_square) { Some(root) } else { None }
            }

            /// Whether this is zero.
            #[inline]
            pub fn is_zero(&self) -> Choice {
                (self.0[0] | self.0[1] | self.0[2] | self.0[3]).ct_eq(&0)
            }

            /// Whether the canonical integer value is odd.
            #[inline]
            pub fn is_odd(&self) -> Choice {
                Choice::from((self.to_raw()[0] & 1) as u8)
            }

            /// Bit `i` (0 being the least significant) of the canonical
            /// integer value.
            pub fn bit(&self, i: usize) -> bool {
                i < 256 && (self.to_raw()[i / 64] >> (i % 64)) & 1 == 1
            }
        }

        impl ConstantTimeEq for $name {
            #[inline]
            fn ct_eq(&self, other: &Self) -> Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl ConditionallySelectable for $name {
            /// `a` when `choice` is set, else `b`.
            #[inline]
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                Self([
                    u64::conditional_select(&a.0[0], &b.0[0], choice),
                    u64::conditional_select(&a.0[1], &b.0[1], choice),
                    u64::conditional_select(&a.0[2], &b.0[2], choice),
                    u64::conditional_select(&a.0[3], &b.0[3], choice),
                ])
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                bool::from(self.ct_eq(other))
            }
        }

        impl Eq for $name {}

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let l = self.to_raw();
                write!(
                    f,
                    concat!(stringify!($name), "(0x{:016x}{:016x}{:016x}{:016x})"),
                    l[3], l[2], l[1], l[0]
                )
            }
        }

        impl From<u64> for $name {
            fn from(v: u64) -> Self {
                Self::from_u64(v)
            }
        }

        impl core::ops::Add for $name {
            type Output = Self;
            #[inline]
            fn add(self, rhs: Self) -> Self {
                $name::add(&self, &rhs)
            }
        }

        impl core::ops::Sub for $name {
            type Output = Self;
            #[inline]
            fn sub(self, rhs: Self) -> Self {
                $name::sub(&self, &rhs)
            }
        }

        impl core::ops::Mul for $name {
            type Output = Self;
            #[inline]
            fn mul(self, rhs: Self) -> Self {
                self.mul_const(&rhs)
            }
        }

        impl core::ops::Neg for $name {
            type Output = Self;
            #[inline]
            fn neg(self) -> Self {
                $name::neg(&self)
            }
        }

        impl core::ops::AddAssign for $name {
            #[inline]
            fn add_assign(&mut self, rhs: Self) {
                *self = $name::add(self, &rhs);
            }
        }

        impl core::ops::SubAssign for $name {
            #[inline]
            fn sub_assign(&mut self, rhs: Self) {
                *self = $name::sub(self, &rhs);
            }
        }

        impl core::ops::MulAssign for $name {
            #[inline]
            fn mul_assign(&mut self, rhs: Self) {
                *self = self.mul_const(&rhs);
            }
        }
    };
}

fn le_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*chunk);
    }
    limbs
}

pasta_field! {
    /// An element of the Pallas base field (the Vesta scalar field), of
    /// modulus
    /// `p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`.
    ///
    /// This is the field Orchard's note commitments, nullifiers and Merkle
    /// tree live in, and the field an Orchard circuit is arithmetized over.
    Fp,
    modulus = [
        0x992d_30ed_0000_0001,
        0x2246_98fc_094c_f91b,
        0x0000_0000_0000_0000,
        0x4000_0000_0000_0000,
    ],
    zeta = [
        0x1dad_5ebd_fdfe_4ab9,
        0x1d1f_8bd2_37ad_3149,
        0x2caa_d5dc_57aa_b1b0,
        0x12cc_ca83_4acd_ba71,
    ]
}

pasta_field! {
    /// An element of the Pallas scalar field (the Vesta base field), of
    /// modulus
    /// `q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001`.
    ///
    /// Orchard's secret scalars (`ask`, `rivk`, `rcm`, `rcv`, `esk`) are
    /// elements of this field.
    Fq,
    modulus = [
        0x8c46_eb21_0000_0001,
        0x2246_98fc_0994_a8dd,
        0x0000_0000_0000_0000,
        0x4000_0000_0000_0000,
    ],
    zeta = [
        0x2aa9_d2e0_50aa_0e4f,
        0x0fed_467d_47c0_33af,
        0x511d_b4d8_1cf7_0f5a,
        0x0681_9a58_283e_528e,
    ]
}

impl Fq {
    /// The scalar with the same integer value as a base field element (the
    /// base field modulus is the smaller of the two, so no reduction takes
    /// place).
    pub fn from_fp(v: &Fp) -> Self {
        Self::from_raw(v.to_raw())
    }
}

impl Fp {
    /// The base field element congruent to the integer value of a scalar
    /// (reduced modulo the base field modulus, which only changes the few
    /// values above it).
    pub fn from_fq_reduced(v: &Fq) -> Self {
        Self::from_raw(v.to_raw())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random elements for the algebraic checks.
    fn sample<const N: usize>(seed: u64) -> [[u8; 64]; N] {
        let mut out = [[0u8; 64]; N];
        let mut s = seed;
        for bytes in out.iter_mut() {
            for b in bytes.iter_mut() {
                s = s
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (s >> 56) as u8;
            }
        }
        out
    }

    #[test]
    fn constants_match_pasta_curves() {
        // values from pasta_curves' fields/fp.rs and fields/fq.rs
        assert_eq!(Fp::INV, 0x992d30ecffffffff);
        assert_eq!(
            Fp::R,
            [
                0x34786d38fffffffd,
                0x992c350be41914ad,
                0xffffffffffffffff,
                0x3fffffffffffffff
            ]
        );
        assert_eq!(
            Fp::R2,
            [
                0x8c78ecb30000000f,
                0xd7d30dbd8b0de0e7,
                0x7797a99bc3c95d18,
                0x096d41af7b9cb714
            ]
        );
        assert_eq!(
            Fp::R3,
            [
                0xf185a5993a9e10f9,
                0xf6a68f3b6ac5b1d1,
                0xdf8d1014353fd42c,
                0x2ae309222d2d9910
            ]
        );
        assert_eq!(
            Fp::ROOT_OF_UNITY.to_raw(),
            [
                0xbdad6fabd87ea32f,
                0xea322bf2b7bb7584,
                0x362120830561f81a,
                0x2bce74deac30ebda
            ]
        );
        assert_eq!(
            Fp::ROOT_OF_UNITY_INV.to_raw(),
            [
                0xf0b87c7db2ce91f6,
                0x84a0a1d8859f066f,
                0xb4ed8e647196dad1,
                0x2cd5282c53116b5c
            ]
        );
        assert_eq!(
            Fp::DELTA.to_raw(),
            [
                0x6a6ccd20dd7b9ba2,
                0xf5e4f3f13eee5636,
                0xbd455b7112a5049d,
                0x0a757d0f0006ab6c
            ]
        );
        assert_eq!(
            Fp::TWO_INV.to_raw(),
            [
                0xcc96987680000001,
                0x11234c7e04a67c8d,
                0x0000000000000000,
                0x2000000000000000
            ]
        );
        assert_eq!(
            Fp::T_MINUS1_OVER2,
            [
                0x04a6_7c8d_cc96_9876,
                0x0000_0000_1123_4c7e,
                0x0000_0000_0000_0000,
                0x0000_0000_2000_0000
            ]
        );
        assert_eq!(
            Fq::ROOT_OF_UNITY.to_raw(),
            [
                0xa70e2c1102b6d05f,
                0x9bb97ea3c106f049,
                0x9e5c4dfd492ae26e,
                0x2de6a9b8746d3f58
            ]
        );
        assert_eq!(
            Fq::ROOT_OF_UNITY_INV.to_raw(),
            [
                0x57eecda0a84b6836,
                0x4ad38b9084b8a80c,
                0xf4c8f353124086c1,
                0x2235e1a7415bf936
            ]
        );
        assert_eq!(
            Fq::DELTA.to_raw(),
            [
                0x8494392472d1683c,
                0xe3ac3376541d1140,
                0x06f0a88e7f7949f8,
                0x2237d54423724166
            ]
        );
    }

    macro_rules! field_tests {
        ($name:ident, $f:ident) => {
            #[test]
            fn $name() {
                let one = $f::ONE;
                assert_eq!(one.to_raw(), [1, 0, 0, 0]);
                assert_eq!($f::ZERO.to_bytes(), [0u8; 32]);
                // roots of unity
                assert_eq!($f::ROOT_OF_UNITY * $f::ROOT_OF_UNITY_INV, one);
                let mut r = $f::ROOT_OF_UNITY;
                for _ in 0..31 {
                    r = r.square();
                }
                assert_eq!(r, -one);
                assert_eq!($f::ZETA.square() * $f::ZETA, one);
                assert_ne!($f::ZETA, one);
                assert_eq!($f::TWO_INV.double(), one);
                assert!($f::MULTIPLICATIVE_GENERATOR.sqrt().is_none());
                // the modulus is not canonical, the modulus minus one is
                let mut m = [0u8; 32];
                for (chunk, limb) in m.as_chunks_mut::<8>().0.iter_mut().zip($f::MODULUS) {
                    *chunk = limb.to_le_bytes();
                }
                assert!($f::from_bytes(&m).is_none());
                assert_eq!($f::from_bytes_reduced(&m), $f::ZERO);
                assert!($f::from_bytes(&[0xff; 32]).is_none());
                m[0] -= 1;
                assert_eq!($f::from_bytes(&m), Some(-one));
                assert_eq!((-one).to_bytes(), m);

                let samples = sample::<24>(0x1234_5678);
                let mut prev = $f::from_u64(7);
                for bytes in samples.iter() {
                    let a = $f::from_uniform_bytes(bytes);
                    let b = prev;
                    prev = a;
                    assert_eq!($f::from_bytes(&a.to_bytes()), Some(a));
                    assert_eq!(a + b - b, a);
                    assert_eq!(a - a, $f::ZERO);
                    assert_eq!(a + (-a), $f::ZERO);
                    assert_eq!(a.double(), a + a);
                    assert_eq!(a * b, b * a);
                    assert_eq!((a + b) * a, a.square() + b * a);
                    assert_eq!(a * a.invert().unwrap(), one);
                    assert_eq!(a.pow(&$f::MODULUS_MINUS_2), a.invert_or_zero());
                    assert_eq!(a.pow_const(&[5, 0, 0, 0]), a.square().square() * a);
                    let sq = a.square();
                    let (is_square, root) = sq.sqrt_alt();
                    assert!(bool::from(is_square));
                    assert!(root == a || root == -a);
                    let non = sq * $f::MULTIPLICATIVE_GENERATOR;
                    let (is_square, root) = non.sqrt_alt();
                    assert!(!bool::from(is_square));
                    assert_eq!(root.square(), non * $f::ROOT_OF_UNITY);
                    assert!(non.sqrt().is_none());
                    // wide reduction agrees with the two halves
                    let lo = $f::from_bytes_reduced(bytes[..32].try_into().unwrap());
                    let hi = $f::from_bytes_reduced(bytes[32..].try_into().unwrap());
                    let two_256 = $f::from_raw([0, 0, 0, 1 << 63]).double();
                    assert_eq!(a, lo + hi * two_256);
                    assert_eq!(a.is_odd().unwrap_u8(), a.to_bytes()[0] & 1);
                    assert_eq!(a.bit(3), a.to_bytes()[0] & 8 != 0);
                }
                assert!($f::ZERO.invert().is_none());
                assert_eq!($f::ZERO.sqrt(), Some($f::ZERO));

                let mut elems = [$f::ZERO; 6];
                for (i, e) in elems.iter_mut().enumerate() {
                    *e = $f::from_u64(i as u64 * 3);
                }
                let orig = elems;
                let mut scratch = [$f::ZERO; 6];
                $f::batch_invert(&mut elems, &mut scratch);
                for (e, o) in elems.iter().zip(orig) {
                    assert_eq!(*e, o.invert_or_zero());
                }
            }
        };
    }

    field_tests!(fp_arithmetic, Fp);
    field_tests!(fq_arithmetic, Fq);

    #[test]
    fn field_conversions() {
        let x = Fp::from_u64(0xdead_beef);
        assert_eq!(Fq::from_fp(&x).to_raw(), x.to_raw());
        // q - 1 is above p: it wraps around
        let big = -Fq::ONE;
        let wrapped = Fp::from_fq_reduced(&big);
        assert_ne!(wrapped.to_raw(), big.to_raw());
    }
}
