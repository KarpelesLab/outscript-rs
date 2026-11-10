//! Constants required for the ECC chip (port of
//! `halo2_gadgets::ecc::chip::constants`).

use alloc::vec;
use alloc::vec::Vec;

use crate::orchard::{Fp, pallas};

/// Window size for fixed-base scalar multiplication
pub(crate) const FIXED_BASE_WINDOW_SIZE: usize = 3;

/// $2^{`FIXED_BASE_WINDOW_SIZE`}$
pub(crate) const H: usize = 1 << FIXED_BASE_WINDOW_SIZE;

/// Number of windows for a full-width scalar
pub(crate) const NUM_WINDOWS: usize = 255usize.div_ceil(FIXED_BASE_WINDOW_SIZE);

/// Number of windows for a short signed scalar
pub(crate) const NUM_WINDOWS_SHORT: usize = L_SCALAR_SHORT.div_ceil(FIXED_BASE_WINDOW_SIZE);

/// $\ell_\mathsf{value}$
/// Number of bits in an unsigned short scalar.
pub(crate) const L_SCALAR_SHORT: usize = 64;

/// The Pallas scalar field modulus is $q = 2^{254} + \mathsf{t_q}$.
/// <https://github.com/zcash/pasta>
pub(crate) const T_Q: u128 = 45560315531506369815346746415080538113;

/// The Pallas base field modulus is $p = 2^{254} + \mathsf{t_p}$.
/// <https://github.com/zcash/pasta>
pub(crate) const T_P: u128 = 45560315531419706090280762371685220353;

/// For each fixed base, we calculate its scalar multiples in three-bit
/// windows. Each window will have $2^3 = 8$ points. The tables are computed
/// as described in [the Orchard book](https://zcash.github.io/orchard/design/circuit/gadgets/ecc/fixed-base-scalar-mul.html#load-fixed-base).
///
/// Window `w < num_windows - 1` holds `[(k + 2) * 8^w]B` for `k` in `0..8`,
/// the last one `[k * 8^w - sum_{j < w} 2^{3j + 1}]B`. They are built with
/// additions only and normalized together.
pub(crate) fn compute_window_table(
    base: pallas::Affine,
    num_windows: usize,
) -> Vec<[pallas::Affine; H]> {
    let mut points: Vec<pallas::Point> = Vec::with_capacity(num_windows * H);

    // [8^w]B
    let mut b = base.to_point();
    // sum_{j < w} [2^{3j + 1}]B
    let mut sum = pallas::Point::IDENTITY;

    // Generate window table entries for all windows but the last.
    // For these first `num_windows - 1` windows, we compute the multiple
    // [(k+2)*(2^3)^w]B. Here, w ranges from [0..`num_windows - 1`)
    for _ in 0..(num_windows - 1) {
        let two_b = b.double();
        sum = sum.add(&two_b);
        let mut acc = two_b;
        for _ in 0..H {
            points.push(acc);
            acc = acc.add(&b);
        }
        b = two_b.double().double();
    }

    // Generate window table entries for the last window, w = `num_windows -
    // 1`. For the last window, we compute [k * (2^3)^w - sum]B, where sum is
    // defined as sum = \sum_{j = 0}^{`num_windows - 2`} 2^{3j+1}
    let mut acc = sum.neg();
    for _ in 0..H {
        points.push(acc);
        acc = acc.add(&b);
    }

    let mut affine = vec![pallas::Affine::IDENTITY; points.len()];
    pallas::Point::batch_normalize(&points, &mut affine);
    affine.as_chunks::<H>().0.to_vec()
}

/// The coefficients (lowest degree first) of the `H` Lagrange basis
/// polynomials over the points `0..H`.
fn lagrange_basis() -> [[Fp; H]; H] {
    core::array::from_fn(|j| {
        // prod_{m != j} (X - m) / (j - m)
        let mut poly = [Fp::ZERO; H];
        poly[0] = Fp::ONE;
        let mut denom = Fp::ONE;
        let mut degree = 0;
        for m in 0..H {
            if m == j {
                continue;
            }
            let m_f = Fp::from_u64(m as u64);
            // poly *= (X - m)
            degree += 1;
            for i in (0..=degree).rev() {
                let shifted = if i > 0 { poly[i - 1] } else { Fp::ZERO };
                poly[i] = shifted - poly[i] * m_f;
            }
            denom *= Fp::from_u64(j as u64) - m_f;
        }
        let denom_inv = denom.invert_or_zero();
        poly.map(|c| c * denom_inv)
    })
}

/// The coefficients of the polynomials interpolating, for each window of a
/// table, the x-coordinates of its points over `0..H`.
pub(crate) fn lagrange_coeffs_of_table(window_table: &[[pallas::Affine; H]]) -> Vec<[Fp; H]> {
    let basis = lagrange_basis();
    window_table
        .iter()
        .map(|window_points| {
            let mut coeffs = [Fp::ZERO; H];
            for (point, basis_poly) in window_points.iter().zip(basis.iter()) {
                let x = point.x();
                for (coeff, b) in coeffs.iter_mut().zip(basis_poly.iter()) {
                    *coeff += x * *b;
                }
            }
            coeffs
        })
        .collect()
}

/// For each window, we interpolate the $x$-coordinate.
/// Here, we pre-compute and store the coefficients of the interpolation
/// polynomial.
#[cfg(test)]
pub(crate) fn compute_lagrange_coeffs(base: pallas::Affine, num_windows: usize) -> Vec<[Fp; H]> {
    lagrange_coeffs_of_table(&compute_window_table(base, num_windows))
}

/// The `u` value of a point of a window table: the square root of `y + z`
/// with `y` the y-coordinate of the point and `z` the value of its window.
/// The root is the one [`Fp::sqrt`] returns, which is the one stored in the
/// tables of the reference (checked for every Orchard base in
/// `fixed_bases::tests`).
///
/// # Panics
/// Panics if `y + z` is not a square (`z` is not the value of the window).
pub(crate) fn fixed_u(y: Fp, z: u64) -> Fp {
    (y + Fp::from_u64(z))
        .sqrt()
        .expect("y + z is a square for the points of the window")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchard::Fq;

    /// 8^w
    fn h_pow(w: usize) -> Fq {
        (0..w).fold(Fq::ONE, |acc, _| acc * Fq::from_u64(H as u64))
    }

    /// The scalar of entry `k` of window `w`, as defined in the reference.
    fn window_scalar(w: usize, k: usize, num_windows: usize) -> Fq {
        if w < num_windows - 1 {
            Fq::from_u64(k as u64 + 2) * h_pow(w)
        } else {
            let sum = (0..(num_windows - 1)).fold(Fq::ZERO, |acc, j| {
                acc + (0..(FIXED_BASE_WINDOW_SIZE * j + 1)).fold(Fq::ONE, |acc, _| acc.double())
            });
            Fq::from_u64(k as u64) * h_pow(w) - sum
        }
    }

    fn evaluate(x: u8, coeffs: &[Fp]) -> Fp {
        let x = Fp::from_u64(x as u64);
        coeffs
            .iter()
            .rev()
            .cloned()
            .reduce(|acc, coeff| acc * x + coeff)
            .unwrap_or(Fp::ZERO)
    }

    /// `test_lagrange_coeffs` of the reference, which also checks the window
    /// table against its definition by scalar multiplications.
    fn test_lagrange_coeffs(base: pallas::Affine, num_windows: usize) {
        let table = compute_window_table(base, num_windows);
        let lagrange_coeffs = compute_lagrange_coeffs(base, num_windows);
        assert_eq!(table.len(), num_windows);
        assert_eq!(lagrange_coeffs.len(), num_windows);
        for (w, coeffs) in lagrange_coeffs.iter().enumerate() {
            for bits in 0..(H as u8) {
                let point = base
                    .to_point()
                    .mul_vartime(&window_scalar(w, bits as usize, num_windows))
                    .to_affine();
                assert_eq!(point.x(), table[w][bits as usize].x());
                assert_eq!(point.y(), table[w][bits as usize].y());
                assert_eq!(point.x(), evaluate(bits, coeffs));
            }
        }
    }

    #[test]
    fn lagrange_coeffs() {
        let base = pallas::Point::GENERATOR
            .mul_vartime(&Fq::from_u64(0x1234_5678_9abc_def1))
            .to_affine();
        test_lagrange_coeffs(base, NUM_WINDOWS_SHORT);
    }

    #[test]
    fn lagrange_coeffs_full() {
        test_lagrange_coeffs(crate::orchard::constants::NULLIFIER_K, NUM_WINDOWS);
    }
}
