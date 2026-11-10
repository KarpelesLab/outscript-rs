//! Polynomials over [`Fp`]: fast Fourier transforms and the evaluation
//! domains of `halo2_proofs` (the `2^k` roots of unity the circuit lives on
//! and the larger coset the quotient polynomial is computed on).

use alloc::vec;
use alloc::vec::Vec;

use super::plonk::Rotation;
use crate::orchard::{Fp, vesta};

/// Something a radix-2 FFT with [`Fp`] twiddle factors can run over: field
/// elements, or curve points (to move commitment generators to the Lagrange
/// basis).
pub(crate) trait FftGroup: Copy {
    /// `self + rhs`.
    fn group_add(&self, rhs: &Self) -> Self;
    /// `self - rhs`.
    fn group_sub(&self, rhs: &Self) -> Self;
    /// `self * by`.
    fn group_scale(&self, by: &Fp) -> Self;
}

impl FftGroup for Fp {
    #[inline]
    fn group_add(&self, rhs: &Self) -> Self {
        *self + *rhs
    }
    #[inline]
    fn group_sub(&self, rhs: &Self) -> Self {
        *self - *rhs
    }
    #[inline]
    fn group_scale(&self, by: &Fp) -> Self {
        *self * *by
    }
}

impl FftGroup for vesta::Point {
    fn group_add(&self, rhs: &Self) -> Self {
        self.add(rhs)
    }
    fn group_sub(&self, rhs: &Self) -> Self {
        self.sub(rhs)
    }
    fn group_scale(&self, by: &Fp) -> Self {
        self.mul_vartime(by)
    }
}

/// In-place FFT of `a` (of length `2^log_n`): `a[i]` becomes
/// `sum_j a[j] * omega^(i*j)`, for `omega` a primitive `2^log_n`-th root of
/// unity.
pub(crate) fn fft<G: FftGroup>(a: &mut [G], omega: Fp, log_n: u32) {
    let n = a.len();
    assert_eq!(n, 1 << log_n);
    if log_n == 0 {
        return;
    }
    for k in 0..n {
        let rk = k.reverse_bits() >> (usize::BITS - log_n);
        if k < rk {
            a.swap(rk, k);
        }
    }
    // The powers of omega, used at every level with a stride.
    let mut twiddles = Vec::with_capacity(n / 2);
    let mut w = Fp::ONE;
    for _ in 0..n / 2 {
        twiddles.push(w);
        w *= omega;
    }
    let mut m = 1;
    for _ in 0..log_n {
        let stride = n / (2 * m);
        for chunk in a.chunks_mut(2 * m) {
            let (lo, hi) = chunk.split_at_mut(m);
            // The first twiddle is one.
            let t = hi[0];
            hi[0] = lo[0].group_sub(&t);
            lo[0] = lo[0].group_add(&t);
            for j in 1..m {
                let t = hi[j].group_scale(&twiddles[j * stride]);
                hi[j] = lo[j].group_sub(&t);
                lo[j] = lo[j].group_add(&t);
            }
        }
        m *= 2;
    }
}

/// `2^exp` as a field element.
fn pow2(exp: u32) -> Fp {
    Fp::from_u64(2).pow_vartime(&[exp as u64, 0, 0, 0])
}

/// The value of a polynomial (coefficients, lowest first) at a point.
pub(crate) fn eval_polynomial(poly: &[Fp], point: Fp) -> Fp {
    poly.iter()
        .rev()
        .fold(Fp::ZERO, |acc, coeff| acc * point + *coeff)
}

/// The inner product of two vectors.
pub(crate) fn compute_inner_product(a: &[Fp], b: &[Fp]) -> Fp {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .fold(Fp::ZERO, |acc, (a, b)| acc + *a * *b)
}

/// The quotient of `a(X)` by `X - b` (its remainder, `a(b)`, is dropped);
/// one coefficient shorter than `a`.
pub(crate) fn kate_division(a: &[Fp], b: Fp) -> Vec<Fp> {
    let mut q = vec![Fp::ZERO; a.len() - 1];
    let mut tmp = Fp::ZERO;
    for (q, r) in q.iter_mut().rev().zip(a.iter().rev()) {
        let lead = *r + tmp;
        *q = lead;
        tmp = lead * b;
    }
    q
}

/// The coefficients of the polynomial of degree below `points.len()` taking
/// the values `evals` at the (distinct) `points`.
pub(crate) fn lagrange_interpolate(points: &[Fp], evals: &[Fp]) -> Vec<Fp> {
    assert_eq!(points.len(), evals.len());
    let n = points.len();
    let mut result = vec![Fp::ZERO; n];
    for j in 0..n {
        // The numerator polynomial prod_{k != j} (X - x_k) and its
        // denominator.
        let mut num = Vec::with_capacity(n);
        num.push(Fp::ONE);
        let mut denom = Fp::ONE;
        for k in 0..n {
            if k == j {
                continue;
            }
            denom *= points[j] - points[k];
            // multiply num by (X - x_k)
            num.push(Fp::ZERO);
            for i in (0..num.len()).rev() {
                let lower = if i > 0 { num[i - 1] } else { Fp::ZERO };
                num[i] = lower - num[i] * points[k];
            }
        }
        let scale = evals[j] * denom.invert_or_zero();
        for (r, c) in result.iter_mut().zip(num.iter()) {
            *r += *c * scale;
        }
    }
    result
}

/// The evaluation domain of a circuit of `2^k` rows whose constraints have
/// degree at most `j`: the `2^k`-th roots of unity, and for the quotient
/// polynomial the coset `ZETA * <extended_omega>` of `2^extended_k` points.
#[derive(Clone, Debug)]
pub(crate) struct EvaluationDomain {
    pub(crate) n: usize,
    pub(crate) k: u32,
    pub(crate) extended_k: u32,
    pub(crate) omega: Fp,
    pub(crate) omega_inv: Fp,
    extended_omega: Fp,
    extended_omega_inv: Fp,
    quotient_poly_degree: usize,
    ifft_divisor: Fp,
    extended_ifft_divisor: Fp,
    /// The inverses of the vanishing polynomial `X^n - 1` on the coset
    /// (periodic).
    t_evaluations: Vec<Fp>,
    barycentric_weight: Fp,
}

impl EvaluationDomain {
    /// The domain for constraints of degree `j` on `2^k` rows.
    pub(crate) fn new(j: u32, k: u32) -> Self {
        // quotient_poly_degree * params.n - 1 is the degree of the quotient
        // polynomial
        let quotient_poly_degree = (j - 1) as usize;
        let n = 1usize << k;
        let mut extended_k = k;
        while (1usize << extended_k) < (n * quotient_poly_degree) {
            extended_k += 1;
        }
        assert!(extended_k <= Fp::S);

        let mut extended_omega = Fp::ROOT_OF_UNITY;
        for _ in extended_k..Fp::S {
            extended_omega = extended_omega.square();
        }
        let mut omega = extended_omega;
        for _ in k..extended_k {
            omega = omega.square();
        }

        // The coset evaluations of X^n - 1 repeat with period
        // 2^(extended_k - k).
        let mut t_evaluations = Vec::with_capacity(1 << (extended_k - k));
        let orig = Fp::ZETA.pow_vartime(&[n as u64, 0, 0, 0]);
        let step = extended_omega.pow_vartime(&[n as u64, 0, 0, 0]);
        let mut cur = orig;
        for _ in 0..(1usize << (extended_k - k)) {
            t_evaluations.push((cur - Fp::ONE).invert_or_zero());
            cur *= step;
        }

        EvaluationDomain {
            n,
            k,
            extended_k,
            omega,
            omega_inv: omega.invert_or_zero(),
            extended_omega,
            extended_omega_inv: extended_omega.invert_or_zero(),
            quotient_poly_degree,
            ifft_divisor: pow2(k).invert_or_zero(),
            extended_ifft_divisor: pow2(extended_k).invert_or_zero(),
            t_evaluations,
            barycentric_weight: Fp::from_u64(n as u64).invert_or_zero(),
        }
    }

    /// The number of points of the extended domain.
    pub(crate) fn extended_len(&self) -> usize {
        1 << self.extended_k
    }

    /// The number of `n`-coefficient pieces of the quotient polynomial.
    pub(crate) fn quotient_poly_degree(&self) -> usize {
        self.quotient_poly_degree
    }

    /// From the values on the domain to coefficients.
    pub(crate) fn lagrange_to_coeff(&self, mut a: Vec<Fp>) -> Vec<Fp> {
        assert_eq!(a.len(), self.n);
        fft(&mut a, self.omega_inv, self.k);
        for v in a.iter_mut() {
            *v *= self.ifft_divisor;
        }
        a
    }

    /// From coefficients to the values on the domain.
    pub(crate) fn coeff_to_lagrange(&self, mut a: Vec<Fp>) -> Vec<Fp> {
        assert_eq!(a.len(), self.n);
        fft(&mut a, self.omega, self.k);
        a
    }

    /// From coefficients (at most `n * quotient_poly_degree` of them) to
    /// the values on the extended coset.
    pub(crate) fn coeff_to_extended(&self, mut a: Vec<Fp>) -> Vec<Fp> {
        assert!(a.len() <= self.extended_len());
        self.distribute_powers_zeta(&mut a, true);
        a.resize(self.extended_len(), Fp::ZERO);
        fft(&mut a, self.extended_omega, self.extended_k);
        a
    }

    /// From the values on the extended coset to the first
    /// `n * quotient_poly_degree` coefficients.
    pub(crate) fn extended_to_coeff(&self, mut a: Vec<Fp>) -> Vec<Fp> {
        assert_eq!(a.len(), self.extended_len());
        fft(&mut a, self.extended_omega_inv, self.extended_k);
        for v in a.iter_mut() {
            *v *= self.extended_ifft_divisor;
        }
        self.distribute_powers_zeta(&mut a, false);
        a.truncate(self.n * self.quotient_poly_degree);
        a
    }

    /// Divides values on the extended coset by the vanishing polynomial of
    /// the domain.
    pub(crate) fn divide_by_vanishing_poly(&self, a: &mut [Fp]) {
        assert_eq!(a.len(), self.extended_len());
        let period = self.t_evaluations.len();
        for (i, h) in a.iter_mut().enumerate() {
            *h *= self.t_evaluations[i % period];
        }
    }

    /// Multiplies coefficient `i` by `ZETA^i` (or its inverse): moves a
    /// polynomial to or from the coset. `ZETA` has order three.
    fn distribute_powers_zeta(&self, a: &mut [Fp], into_coset: bool) {
        let zeta = Fp::ZETA;
        let zeta_sq = zeta.square();
        let coset_powers = if into_coset {
            [zeta, zeta_sq]
        } else {
            [zeta_sq, zeta]
        };
        for (i, a) in a.iter_mut().enumerate() {
            match i % 3 {
                1 => *a *= coset_powers[0],
                2 => *a *= coset_powers[1],
                _ => {}
            }
        }
    }

    /// `value * omega^rotation`.
    pub(crate) fn rotate_omega(&self, value: Fp, rotation: Rotation) -> Fp {
        let e = [rotation.0.unsigned_abs() as u64, 0, 0, 0];
        if rotation.0 >= 0 {
            value * self.omega.pow_vartime(&e)
        } else {
            value * self.omega_inv.pow_vartime(&e)
        }
    }

    /// The Lagrange basis polynomials `l_i(x)` for `i` in `rotations`, given
    /// `xn = x^n`.
    pub(crate) fn l_i_range(
        &self,
        x: Fp,
        xn: Fp,
        rotations: core::ops::RangeInclusive<i32>,
    ) -> Vec<Fp> {
        let common = (xn - Fp::ONE) * self.barycentric_weight;
        rotations
            .map(|rotation| {
                let rotation = Rotation(rotation);
                let inv = (x - self.rotate_omega(Fp::ONE, rotation)).invert_or_zero();
                self.rotate_omega(inv * common, rotation)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poly(n: usize, seed: u64) -> Vec<Fp> {
        (0..n as u64)
            .map(|i| Fp::from_u64(seed.wrapping_mul(i + 7).wrapping_add(i * i)).square())
            .collect()
    }

    #[test]
    fn fft_and_domain_roundtrips() {
        let domain = EvaluationDomain::new(4, 3);
        assert_eq!(domain.extended_k, 5);
        let coeffs = poly(8, 3);
        let x = domain.omega.pow_vartime(&[5, 0, 0, 0]);
        let evals = domain.coeff_to_lagrange(coeffs.clone());
        assert_eq!(evals[5], eval_polynomial(&coeffs, x));
        assert_eq!(domain.lagrange_to_coeff(evals), coeffs);
        // the extended coset is ZETA * extended_omega^i
        let ext = domain.coeff_to_extended(coeffs.clone());
        let pt = Fp::ZETA * domain.extended_omega.pow_vartime(&[7, 0, 0, 0]);
        assert_eq!(ext[7], eval_polynomial(&coeffs, pt));
        let mut back = domain.extended_to_coeff(ext);
        back.truncate(8);
        assert_eq!(back, coeffs);
    }

    #[test]
    fn vanishing_division() {
        // (X^n - 1) * q, divided on the coset, gives q back
        let domain = EvaluationDomain::new(3, 3);
        let q = poly(8, 11);
        let mut prod = vec![Fp::ZERO; 16];
        for (i, c) in q.iter().enumerate() {
            prod[i] -= *c;
            prod[i + 8] += *c;
        }
        let mut ext = domain.coeff_to_extended(prod);
        domain.divide_by_vanishing_poly(&mut ext);
        let mut back = domain.extended_to_coeff(ext);
        back.truncate(8);
        assert_eq!(back, q);
    }

    #[test]
    fn lagrange_basis_and_interpolation() {
        let domain = EvaluationDomain::new(3, 3);
        let x = Fp::from_u64(123456789);
        let xn = x.pow_vartime(&[8, 0, 0, 0]);
        let l = domain.l_i_range(x, xn, -7..=7);
        for i in 0..8usize {
            let mut li = vec![Fp::ZERO; 8];
            li[i] = Fp::ONE;
            let li = domain.lagrange_to_coeff(li);
            assert_eq!(eval_polynomial(&li, x), l[7 + i]);
            if i >= 1 {
                assert_eq!(eval_polynomial(&li, x), l[i - 1]);
            }
        }
        let points = [Fp::from_u64(3), Fp::from_u64(5), Fp::from_u64(11)];
        let p = poly(3, 5);
        let evals: Vec<Fp> = points.iter().map(|x| eval_polynomial(&p, *x)).collect();
        assert_eq!(lagrange_interpolate(&points, &evals), p);
        // division by (X - b)
        let a = poly(6, 9);
        let b = Fp::from_u64(77);
        let q = kate_division(&a, b);
        let z = Fp::from_u64(1234);
        assert_eq!(
            eval_polynomial(&q, z) * (z - b) + eval_polynomial(&a, b),
            eval_polynomial(&a, z)
        );
    }
}
