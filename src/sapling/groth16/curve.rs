//! Variable-time BLS12-381 arithmetic for the prover's multi-scalar
//! multiplications.
//!
//! The constant-time groups of `purecrypto::bls` use complete projective
//! formulas, which is the right default but costs about twice what a
//! multi-scalar multiplication over affine bases needs. This module has the
//! short Weierstrass arithmetic the prover's inner loops use instead: affine
//! bases, Jacobian accumulators, mixed addition and a bucket (Pippenger)
//! multi-scalar multiplication. Its running time depends on the points and
//! scalars, as it does in every Groth16 prover: see the note on side
//! channels in the [module documentation](super).

use crate::prelude::*;
use purecrypto::bls::{Fp, Fp2, G1, G2};

/// The field a curve is defined over: `Fp` for `G1`, `Fp2` for `G2`.
pub(crate) trait CurveField: Copy + PartialEq + Send + Sync {
    /// The additive identity.
    const ZERO: Self;
    /// The multiplicative identity.
    const ONE: Self;
    /// `self + rhs`.
    fn add(&self, rhs: &Self) -> Self;
    /// `self - rhs`.
    fn sub(&self, rhs: &Self) -> Self;
    /// `self · rhs`.
    fn mul(&self, rhs: &Self) -> Self;
    /// `self²`.
    fn square(&self) -> Self;
    /// `2·self`.
    fn double(&self) -> Self;
    /// Whether the element is zero.
    fn is_zero(&self) -> bool;
    /// The inverse, `None` for zero.
    fn invert(&self) -> Option<Self>;
    /// The coefficient `b` of the curve `y² = x³ + b` over this field.
    fn curve_b() -> Self;
}

impl CurveField for Fp {
    const ZERO: Self = Fp::ZERO;
    const ONE: Self = Fp::ONE;
    #[inline]
    fn add(&self, rhs: &Self) -> Self {
        Fp::add(self, rhs)
    }
    #[inline]
    fn sub(&self, rhs: &Self) -> Self {
        Fp::sub(self, rhs)
    }
    #[inline]
    fn mul(&self, rhs: &Self) -> Self {
        Fp::mul(self, rhs)
    }
    #[inline]
    fn square(&self) -> Self {
        Fp::square(self)
    }
    #[inline]
    fn double(&self) -> Self {
        Fp::double(self)
    }
    #[inline]
    fn is_zero(&self) -> bool {
        bool::from(Fp::is_zero(self))
    }
    fn invert(&self) -> Option<Self> {
        Fp::invert(self).into_option()
    }
    fn curve_b() -> Self {
        // 4
        Fp::ONE.double().double()
    }
}

impl CurveField for Fp2 {
    const ZERO: Self = Fp2::ZERO;
    const ONE: Self = Fp2::ONE;
    #[inline]
    fn add(&self, rhs: &Self) -> Self {
        Fp2::add(self, rhs)
    }
    #[inline]
    fn sub(&self, rhs: &Self) -> Self {
        Fp2::sub(self, rhs)
    }
    #[inline]
    fn mul(&self, rhs: &Self) -> Self {
        Fp2::mul(self, rhs)
    }
    #[inline]
    fn square(&self) -> Self {
        Fp2::square(self)
    }
    #[inline]
    fn double(&self) -> Self {
        Fp2::double(self)
    }
    #[inline]
    fn is_zero(&self) -> bool {
        bool::from(Fp2::is_zero(self))
    }
    fn invert(&self) -> Option<Self> {
        Fp2::invert(self).into_option()
    }
    fn curve_b() -> Self {
        // 4·(1 + u)
        let four = Fp::ONE.double().double();
        Fp2::new(four, four)
    }
}

/// A point other than the identity, in affine coordinates.
#[derive(Clone, Copy, PartialEq)]
pub(crate) struct Affine<F> {
    pub(crate) x: F,
    pub(crate) y: F,
}

impl<F: CurveField> Affine<F> {
    /// Whether the coordinates satisfy `y² = x³ + b`.
    pub(crate) fn is_on_curve(&self) -> bool {
        self.y.square() == self.x.square().mul(&self.x).add(&F::curve_b())
    }
}

/// A point in Jacobian coordinates (`x = X/Z²`, `y = Y/Z³`); `Z = 0` is the
/// identity.
#[derive(Clone, Copy)]
pub(crate) struct Jacobian<F> {
    x: F,
    y: F,
    z: F,
}

impl<F: CurveField> Jacobian<F> {
    /// The identity.
    pub(crate) const IDENTITY: Self = Jacobian {
        x: F::ZERO,
        y: F::ONE,
        z: F::ZERO,
    };

    /// Whether this is the identity.
    pub(crate) fn is_identity(&self) -> bool {
        self.z.is_zero()
    }

    /// `2·self`.
    pub(crate) fn double(&self) -> Self {
        if self.is_identity() {
            return *self;
        }
        // dbl-2009-l
        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();
        let d = self.x.add(&b).square().sub(&a).sub(&c).double();
        let e = a.double().add(&a);
        let f = e.square();
        let x3 = f.sub(&d.double());
        let y3 = e.mul(&d.sub(&x3)).sub(&c.double().double().double());
        let z3 = self.y.mul(&self.z).double();
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `self + rhs` for an affine `rhs`.
    pub(crate) fn add_affine(&self, rhs: &Affine<F>) -> Self {
        if self.is_identity() {
            return Jacobian {
                x: rhs.x,
                y: rhs.y,
                z: F::ONE,
            };
        }
        // madd-2007-bl
        let z1z1 = self.z.square();
        let u2 = rhs.x.mul(&z1z1);
        let s2 = rhs.y.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&self.x);
        let rr = s2.sub(&self.y);
        if h.is_zero() {
            return if rr.is_zero() {
                self.double()
            } else {
                Self::IDENTITY
            };
        }
        let hh = h.square();
        let i = hh.double().double();
        let j = h.mul(&i);
        let r = rr.double();
        let v = self.x.mul(&i);
        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&self.y.mul(&j).double());
        let z3 = self.z.add(&h).square().sub(&z1z1).sub(&hh);
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `self + rhs`.
    pub(crate) fn add(&self, rhs: &Self) -> Self {
        if self.is_identity() {
            return *rhs;
        }
        if rhs.is_identity() {
            return *self;
        }
        // add-2007-bl
        let z1z1 = self.z.square();
        let z2z2 = rhs.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = rhs.x.mul(&z1z1);
        let s1 = self.y.mul(&rhs.z).mul(&z2z2);
        let s2 = rhs.y.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&u1);
        let rr = s2.sub(&s1);
        if h.is_zero() {
            return if rr.is_zero() {
                self.double()
            } else {
                Self::IDENTITY
            };
        }
        let i = h.double().square();
        let j = h.mul(&i);
        let r = rr.double();
        let v = u1.mul(&i);
        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j).double());
        let z3 = self.z.add(&rhs.z).square().sub(&z1z1).sub(&z2z2).mul(&h);
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// The affine coordinates, `None` for the identity.
    pub(crate) fn to_affine(self) -> Option<Affine<F>> {
        let zinv = self.z.invert()?;
        let zinv2 = zinv.square();
        Some(Affine {
            x: self.x.mul(&zinv2),
            y: self.y.mul(&zinv2).mul(&zinv),
        })
    }
}

impl Jacobian<Fp> {
    /// Converts to the constant-time group type, checking the curve equation
    /// and subgroup membership; `None` when the check fails (which sums of
    /// valid parameters never do).
    pub(crate) fn to_g1(self) -> Option<G1> {
        match self.to_affine() {
            None => Some(G1::IDENTITY),
            Some(p) => G1::from_affine(p.x, p.y).ok(),
        }
    }
}

impl Jacobian<Fp2> {
    /// Converts to the constant-time group type, checking the curve equation
    /// and subgroup membership.
    pub(crate) fn to_g2(self) -> Option<G2> {
        match self.to_affine() {
            None => Some(G2::IDENTITY),
            Some(p) => G2::from_affine(p.x, p.y).ok(),
        }
    }
}

/// The `width` bits of `scalar` (little-endian limbs) starting at bit
/// `start`.
#[inline]
fn window(scalar: &[u64; 4], start: usize, width: usize) -> usize {
    let limb = start / 64;
    let shift = start % 64;
    if limb >= 4 {
        return 0;
    }
    let mut v = scalar[limb] >> shift;
    if shift + width > 64 && limb + 1 < 4 {
        v |= scalar[limb + 1] << (64 - shift);
    }
    (v & ((1u64 << width) - 1)) as usize
}

/// The bucket width for `n` terms: about `ln n`.
fn window_width(n: usize) -> usize {
    if n < 32 {
        3
    } else {
        // ln n ≈ 0.69·log2 n
        ((n.ilog2() as usize * 69) / 100 + 2).min(16)
    }
}

/// `Σ scalars[i]·bases[i]` on one thread. The slices have the same length;
/// the scalars are canonical little-endian limbs below `2^255`.
fn msm_serial<F: CurveField>(bases: &[Affine<F>], scalars: &[[u64; 4]]) -> Jacobian<F> {
    // scalars 0 and 1 are frequent in a witness (every boolean): they skip
    // the buckets
    let mut ones = Jacobian::IDENTITY;
    let mut general: Vec<(&Affine<F>, &[u64; 4])> = Vec::new();
    for (base, scalar) in bases.iter().zip(scalars) {
        match scalar {
            [0, 0, 0, 0] => {}
            [1, 0, 0, 0] => ones = ones.add_affine(base),
            _ => general.push((base, scalar)),
        }
    }
    if general.is_empty() {
        return ones;
    }
    let c = window_width(general.len());
    let mut buckets = vec![Jacobian::<F>::IDENTITY; (1 << c) - 1];
    let windows = 255usize.div_ceil(c);
    let mut acc = Jacobian::IDENTITY;
    for w in (0..windows).rev() {
        for _ in 0..c {
            acc = acc.double();
        }
        for bucket in buckets.iter_mut() {
            *bucket = Jacobian::IDENTITY;
        }
        for (base, scalar) in &general {
            let digit = window(scalar, w * c, c);
            if digit != 0 {
                buckets[digit - 1] = buckets[digit - 1].add_affine(base);
            }
        }
        // Σ (i + 1)·bucket[i] by a running sum from the top
        let mut running = Jacobian::IDENTITY;
        let mut sum = Jacobian::IDENTITY;
        for bucket in buckets.iter().rev() {
            running = running.add(bucket);
            sum = sum.add(&running);
        }
        acc = acc.add(&sum);
    }
    acc.add(&ones)
}

/// `Σ scalars[i]·bases[i]`, in variable time. The slices have the same
/// length; the scalars are canonical little-endian limbs. With `std` the
/// work is split over the available cores.
pub(crate) fn msm<F: CurveField>(bases: &[Affine<F>], scalars: &[[u64; 4]]) -> Jacobian<F> {
    debug_assert_eq!(bases.len(), scalars.len());
    #[cfg(feature = "std")]
    {
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
        if threads > 1 && bases.len() >= 256 {
            let chunk = bases.len().div_ceil(threads);
            return std::thread::scope(|scope| {
                let handles: Vec<_> = bases
                    .chunks(chunk)
                    .zip(scalars.chunks(chunk))
                    .map(|(b, s)| scope.spawn(move || msm_serial(b, s)))
                    .collect();
                let mut acc = Jacobian::IDENTITY;
                for handle in handles {
                    match handle.join() {
                        Ok(part) => acc = acc.add(&part),
                        Err(panic) => std::panic::resume_unwind(panic),
                    }
                }
                acc
            });
        }
    }
    msm_serial(bases, scalars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::bls::Fr;

    fn g1_affine(p: &G1) -> Affine<Fp> {
        let (x, y) = p.to_affine().unwrap();
        Affine { x, y }
    }

    fn g2_affine(p: &G2) -> Affine<Fp2> {
        let (x, y) = p.to_affine().unwrap();
        Affine { x, y }
    }

    fn fr(limbs: &[u64; 4]) -> Fr {
        let mut be = [0u8; 32];
        for (i, limb) in limbs.iter().enumerate() {
            be[32 - 8 * (i + 1)..32 - 8 * i].copy_from_slice(&limb.to_be_bytes());
        }
        Fr::from_bytes(&be).unwrap()
    }

    fn scalars(n: usize) -> Vec<[u64; 4]> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        (0..n)
            .map(|i| match i % 7 {
                0 => [0, 0, 0, 0],
                1 => [1, 0, 0, 0],
                2 => [next(), 0, 0, 0],
                _ => [next(), next(), next(), next() >> 2],
            })
            .collect()
    }

    #[test]
    fn group_law_matches_purecrypto() {
        let g = G1::generator();
        let a = g.double().add(&g);
        let b = a.double().double().add(&g);
        let ja = Jacobian::IDENTITY.add_affine(&g1_affine(&a));
        let jb = Jacobian::IDENTITY.add_affine(&g1_affine(&b));
        assert!(g1_affine(&a).is_on_curve());
        assert_eq!(ja.add(&jb).to_g1().unwrap(), a.add(&b));
        assert_eq!(ja.add(&ja).to_g1().unwrap(), a.double());
        assert_eq!(ja.add_affine(&g1_affine(&a)).to_g1().unwrap(), a.double());
        assert_eq!(
            ja.add_affine(&g1_affine(&a.neg())).to_g1().unwrap(),
            G1::IDENTITY
        );
        assert_eq!(ja.double().add(&jb).to_g1().unwrap(), a.double().add(&b));

        let h = G2::generator();
        let c = h.double().add(&h);
        let jc = Jacobian::IDENTITY.add_affine(&g2_affine(&c));
        assert!(g2_affine(&c).is_on_curve());
        assert_eq!(jc.double().add(&jc).to_g2().unwrap(), c.double().add(&c));
        assert_eq!(
            jc.double().add_affine(&g2_affine(&h)).to_g2().unwrap(),
            c.double().add(&h)
        );
    }

    #[test]
    fn msm_matches_naive() {
        for n in [0usize, 1, 5, 40, 300] {
            let scalars = scalars(n);
            let mut p = G1::generator();
            let mut q = G2::generator();
            let mut bases1 = Vec::new();
            let mut bases2 = Vec::new();
            let mut expected1 = G1::IDENTITY;
            let mut expected2 = G2::IDENTITY;
            for s in &scalars {
                bases1.push(g1_affine(&p));
                expected1 = expected1.add(&p.mul(&fr(s)));
                p = p.double().add(&G1::generator());
                if n <= 40 {
                    bases2.push(g2_affine(&q));
                    expected2 = expected2.add(&q.mul(&fr(s)));
                    q = q.double().add(&G2::generator());
                }
            }
            assert_eq!(msm(&bases1, &scalars).to_g1().unwrap(), expected1);
            assert_eq!(msm_serial(&bases1, &scalars).to_g1().unwrap(), expected1);
            if n <= 40 {
                assert_eq!(msm(&bases2, &scalars).to_g2().unwrap(), expected2);
            }
        }
    }
}
