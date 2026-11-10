//! The polynomial commitment scheme of `halo2_proofs` on Vesta: Pedersen
//! vector commitments to the coefficients of a polynomial, opened with an
//! inner product argument.

use alloc::vec;
use alloc::vec::Vec;

use purecrypto::hash::Blake2bMac;

use super::Error;
use super::poly::{compute_inner_product, eval_polynomial, fft_par};
use super::transcript::{TranscriptRead, TranscriptWrite};
use crate::orchard::par;
use crate::orchard::{Fp, vesta};

/// The public parameters of the commitment scheme for polynomials of
/// degree below `2^k`: generators with no known discrete logarithm
/// relations, derived by hashing to the curve (there is no trusted setup).
#[derive(Clone, Debug)]
pub struct Params {
    pub(crate) k: u32,
    pub(crate) n: usize,
    /// The generators committing to coefficients.
    pub(crate) g: Vec<vesta::Affine>,
    /// The generators committing to the values on the evaluation domain
    /// (the first `g_lagrange.len()` of them; all `n` unless the parameters
    /// were built for verification only).
    pub(crate) g_lagrange: Vec<vesta::Affine>,
    /// The blinding generator.
    pub(crate) w: vesta::Affine,
    /// The generator binding the claimed evaluation in an opening.
    pub(crate) u: vesta::Affine,
}

/// The inverse of the `2^k`-th root of unity.
fn omega_inv(k: u32) -> Fp {
    let mut alpha_inv = Fp::ROOT_OF_UNITY_INV;
    for _ in k..Fp::S {
        alpha_inv = alpha_inv.square();
    }
    alpha_inv
}

impl Params {
    /// The generators alone (`Halo2-Parameters` hashed to Vesta, as
    /// `halo2_proofs::poly::commitment::Params::new`).
    fn generators(k: u32) -> Self {
        assert!(k < 32);
        let n = 1usize << k;
        let hash = |msg: &[u8]| vesta::Point::hash_to_curve(b"Halo2-Parameters", msg);
        let g_projective: Vec<vesta::Point> = par::map_range(n, |i| {
            let mut message = [0u8; 5];
            message[1..5].copy_from_slice(&(i as u32).to_le_bytes());
            hash(&message)
        });
        let mut g = vec![vesta::Affine::IDENTITY; n];
        vesta::Point::batch_normalize(&g_projective, &mut g);
        Params {
            k,
            n,
            g,
            g_lagrange: Vec::new(),
            w: hash(&[1]).to_affine(),
            u: hash(&[2]).to_affine(),
        }
    }

    /// The parameters for polynomials of degree below `2^k`, for proving,
    /// key generation and verification.
    ///
    /// # Panics
    /// Panics if `k` is 32 or more.
    pub fn new(k: u32) -> Self {
        let mut params = Self::generators(k);
        // The Lagrange basis generators are the inverse FFT of the
        // generators.
        let mut g_lagrange: Vec<vesta::Point> = params.g.iter().map(|g| g.to_point()).collect();
        fft_par(&mut g_lagrange, omega_inv(k), k);
        let minv = Fp::TWO_INV.pow_vartime(&[k as u64, 0, 0, 0]);
        par::chunks_mut(&mut g_lagrange, 8, 1, |_, chunk| {
            for g in chunk.iter_mut() {
                *g = g.mul_vartime(&minv);
            }
        });
        params.g_lagrange = vec![vesta::Affine::IDENTITY; params.n];
        vesta::Point::batch_normalize(&g_lagrange, &mut params.g_lagrange);
        params
    }

    /// The parameters for verification only, with the Lagrange basis
    /// generators of the first `instance_rows` rows (those the public
    /// inputs are committed with). Much cheaper than [`Params::new`].
    ///
    /// # Panics
    /// Panics if `k` is 32 or more, or `instance_rows` above `2^k`.
    pub fn for_verifier(k: u32, instance_rows: usize) -> Self {
        let mut params = Self::generators(k);
        assert!(instance_rows <= params.n);
        let omega_inv = omega_inv(k);
        let minv = Fp::TWO_INV.pow_vartime(&[k as u64, 0, 0, 0]);
        let mut row_root = Fp::ONE;
        for _ in 0..instance_rows {
            // g_lagrange[i] = 1/n * sum_j omega^(-i*j) g[j]
            let mut scalars = Vec::with_capacity(params.n);
            let mut cur = minv;
            for _ in 0..params.n {
                scalars.push(cur);
                cur *= row_root;
            }
            params
                .g_lagrange
                .push(vesta::Point::msm_vartime(&scalars, &params.g).to_affine());
            row_root *= omega_inv;
        }
        params
    }

    /// The parameters for verification only, given the first Lagrange
    /// basis generators (as [`Params::for_verifier`] computes them).
    pub(crate) fn with_lagrange(k: u32, g_lagrange: Vec<vesta::Affine>) -> Self {
        let mut params = Self::generators(k);
        params.g_lagrange = g_lagrange;
        params
    }

    /// The size parameter `k`.
    pub fn k(&self) -> u32 {
        self.k
    }

    /// Commits to a polynomial given by at most `n` coefficients, with
    /// blinding factor `r`.
    pub(crate) fn commit(&self, poly: &[Fp], r: Fp) -> vesta::Point {
        assert!(poly.len() <= self.n);
        vesta::Point::msm_vartime(poly, &self.g).add(&self.w.to_point().mul_vartime(&r))
    }

    /// [`Params::commit`], splitting the work over the threads there are.
    pub(crate) fn commit_par(&self, poly: &[Fp], r: Fp) -> vesta::Point {
        assert!(poly.len() <= self.n);
        par::msm(poly, &self.g).add(&self.w.to_point().mul_vartime(&r))
    }

    /// Commits to a polynomial given by its values on the first
    /// `poly.len()` rows of the domain (zero on the others), with blinding
    /// factor `r`.
    ///
    /// # Panics
    /// Panics if the parameters lack the Lagrange generators of these rows.
    pub(crate) fn commit_lagrange(&self, poly: &[Fp], r: Fp) -> vesta::Point {
        assert!(poly.len() <= self.g_lagrange.len());
        vesta::Point::msm_vartime(poly, &self.g_lagrange).add(&self.w.to_point().mul_vartime(&r))
    }
}

/// A multi-scalar multiplication the verifier accumulates and evaluates
/// once: scalars for the fixed generators, and other terms.
#[derive(Clone, Debug)]
pub(crate) struct Msm {
    g_scalars: Option<Vec<Fp>>,
    w_scalar: Option<Fp>,
    u_scalar: Option<Fp>,
    other: Vec<(Fp, vesta::Affine)>,
}

impl Msm {
    /// An empty sum.
    pub(crate) fn new() -> Self {
        Msm {
            g_scalars: None,
            w_scalar: None,
            u_scalar: None,
            other: Vec::new(),
        }
    }

    /// Adds another sum to this one.
    pub(crate) fn add_msm(&mut self, other: &Self) {
        self.other.extend_from_slice(&other.other);
        if let Some(g_scalars) = &other.g_scalars {
            self.add_to_g_scalars(g_scalars);
        }
        if let Some(w_scalar) = other.w_scalar {
            self.add_to_w_scalar(w_scalar);
        }
        if let Some(u_scalar) = other.u_scalar {
            self.add_to_u_scalar(u_scalar);
        }
    }

    /// Adds `[scalar] point`.
    pub(crate) fn append_term(&mut self, scalar: Fp, point: vesta::Affine) {
        if !bool::from(point.is_identity()) {
            self.other.push((scalar, point));
        }
    }

    /// Adds `[constant] g[0]`.
    pub(crate) fn add_constant_term(&mut self, constant: Fp, n: usize) {
        let g_scalars = self.g_scalars.get_or_insert_with(|| vec![Fp::ZERO; n]);
        g_scalars[0] += constant;
    }

    /// Adds `sum [scalars[i]] g[i]`.
    pub(crate) fn add_to_g_scalars(&mut self, scalars: &[Fp]) {
        match &mut self.g_scalars {
            Some(g_scalars) => {
                for (g_scalar, scalar) in g_scalars.iter_mut().zip(scalars.iter()) {
                    *g_scalar += *scalar;
                }
            }
            None => self.g_scalars = Some(scalars.to_vec()),
        }
    }

    /// Adds `[scalar] w`.
    pub(crate) fn add_to_w_scalar(&mut self, scalar: Fp) {
        self.w_scalar = Some(self.w_scalar.map_or(scalar, |a| a + scalar));
    }

    /// Adds `[scalar] u`.
    pub(crate) fn add_to_u_scalar(&mut self, scalar: Fp) {
        self.u_scalar = Some(self.u_scalar.map_or(scalar, |a| a + scalar));
    }

    /// Multiplies the whole sum by `factor`.
    pub(crate) fn scale(&mut self, factor: Fp) {
        if let Some(g_scalars) = &mut self.g_scalars {
            for g_scalar in g_scalars {
                *g_scalar *= factor;
            }
        }
        for other in self.other.iter_mut() {
            other.0 *= factor;
        }
        self.w_scalar = self.w_scalar.map(|a| a * factor);
        self.u_scalar = self.u_scalar.map(|a| a * factor);
    }

    /// Whether the sum is the identity.
    pub(crate) fn eval(self, params: &Params) -> bool {
        let mut scalars: Vec<Fp> = self.other.iter().map(|(s, _)| *s).collect();
        let mut bases: Vec<vesta::Affine> = self.other.iter().map(|(_, p)| *p).collect();
        if let Some(w_scalar) = self.w_scalar {
            scalars.push(w_scalar);
            bases.push(params.w);
        }
        if let Some(u_scalar) = self.u_scalar {
            scalars.push(u_scalar);
            bases.push(params.u);
        }
        if let Some(g_scalars) = &self.g_scalars {
            scalars.extend_from_slice(g_scalars);
            bases.extend_from_slice(&params.g);
        }
        bool::from(par::msm(&scalars, &bases).is_identity())
    }
}

/// A source of field elements for the blinding factors of a proof: BLAKE2b
/// in counter mode over a caller-supplied seed.
pub(crate) struct ProverRng {
    seed: [u8; 64],
    counter: u64,
}

impl ProverRng {
    /// A generator over 64 fresh uniformly random bytes.
    pub(crate) fn new(seed: &[u8; 64]) -> Self {
        ProverRng {
            seed: *seed,
            counter: 0,
        }
    }

    /// The next uniformly random field element.
    pub(crate) fn next(&mut self) -> Fp {
        let mut h = Blake2bMac::try_new_with_salt_personal(&[], 64, &[], b"outscript_h2_rng")
            .expect("valid BLAKE2b parameters");
        h.update(&self.seed);
        h.update(&self.counter.to_le_bytes());
        self.counter += 1;
        let mut out = [0u8; 64];
        h.finalize_into(&mut out);
        let r = Fp::from_uniform_bytes(&out);
        purecrypto::zeroize::Zeroize::zeroize(&mut out);
        r
    }
}

impl Drop for ProverRng {
    fn drop(&mut self) {
        purecrypto::zeroize::Zeroize::zeroize(&mut self.seed);
    }
}

/// The fewest generators folded on several threads.
const FOLD_MIN_LEN: usize = 16;

/// Creates an opening proof: `p_poly` (committed with blinding `p_blind`)
/// evaluates at `x_3` to a value the verifier already knows.
pub(crate) fn create_proof(
    params: &Params,
    rng: &mut ProverRng,
    transcript: &mut TranscriptWrite,
    p_poly: &[Fp],
    p_blind: Fp,
    x_3: Fp,
) -> Result<(), Error> {
    assert_eq!(p_poly.len(), params.n);

    // A random polynomial with a root at x_3, to blind the opening.
    let mut s_poly: Vec<Fp> = (0..params.n).map(|_| rng.next()).collect();
    let s_at_x3 = eval_polynomial(&s_poly, x_3);
    s_poly[0] -= s_at_x3;
    let s_poly_blind = rng.next();
    let s_poly_commitment = params.commit_par(&s_poly, s_poly_blind).to_affine();
    transcript.write_point(&s_poly_commitment)?;

    let xi = transcript.squeeze_challenge();
    let z = transcript.squeeze_challenge();

    // P' = P - [v] G_0 + [xi] S
    let mut p_prime: Vec<Fp> = s_poly
        .iter()
        .zip(p_poly.iter())
        .map(|(s, p)| *s * xi + *p)
        .collect();
    let v = eval_polynomial(&p_prime, x_3);
    p_prime[0] -= v;
    let p_prime_blind = s_poly_blind * xi + p_blind;

    // The synthetic blinding factor of the final commitment.
    let mut f = p_prime_blind;

    // b = (1, x_3, x_3^2, ...)
    let mut b = Vec::with_capacity(params.n);
    let mut cur = Fp::ONE;
    for _ in 0..params.n {
        b.push(cur);
        cur *= x_3;
    }

    let mut g_prime = params.g.clone();
    let u = params.u.to_point();
    let w = params.w.to_point();

    for j in 0..params.k {
        let half = 1usize << (params.k - j - 1);

        let l_j = par::msm(&p_prime[half..], &g_prime[0..half]);
        let r_j = par::msm(&p_prime[0..half], &g_prime[half..]);
        let value_l_j = compute_inner_product(&p_prime[half..], &b[0..half]);
        let value_r_j = compute_inner_product(&p_prime[0..half], &b[half..]);
        let l_j_randomness = rng.next();
        let r_j_randomness = rng.next();
        let l_j = l_j
            .add(&u.mul_vartime(&(value_l_j * z)))
            .add(&w.mul_vartime(&l_j_randomness))
            .to_affine();
        let r_j = r_j
            .add(&u.mul_vartime(&(value_r_j * z)))
            .add(&w.mul_vartime(&r_j_randomness))
            .to_affine();
        transcript.write_point(&l_j)?;
        transcript.write_point(&r_j)?;

        let u_j = transcript.squeeze_challenge();
        let u_j_inv = u_j.invert().ok_or(Error::Synthesis)?;

        // Fold the vectors.
        for i in 0..half {
            p_prime[i] = p_prime[i] + p_prime[i + half] * u_j_inv;
            b[i] = b[i] + b[i + half] * u_j;
        }
        let fold = |i: usize| {
            g_prime[i]
                .to_point()
                .add(&g_prime[i + half].to_point().mul_vartime(&u_j))
        };
        let folded: Vec<vesta::Point> = if half >= FOLD_MIN_LEN {
            par::map_range(half, fold)
        } else {
            (0..half).map(fold).collect()
        };
        p_prime.truncate(half);
        b.truncate(half);
        g_prime.truncate(half);
        vesta::Point::batch_normalize(&folded, &mut g_prime);

        f += l_j_randomness * u_j_inv;
        f += r_j_randomness * u_j;
    }

    // The final opening: c and the blinding factor.
    transcript.write_scalar(&p_prime[0]);
    transcript.write_scalar(&f);
    Ok(())
}

/// Checks an opening proof: adds to `msm` the terms that sum to the
/// identity if and only if the commitment `msm` held on entry opens to `v`
/// at `x`.
pub(crate) fn verify_proof(
    params: &Params,
    mut msm: Msm,
    transcript: &mut TranscriptRead<'_>,
    x: Fp,
    v: Fp,
) -> Result<Msm, Error> {
    let k = params.k as usize;

    // P' = P - [v] G_0 + [xi] S
    msm.add_constant_term(-v, params.n);
    let s_poly_commitment = transcript.read_point()?;
    let xi = transcript.squeeze_challenge();
    msm.append_term(xi, s_poly_commitment);

    let z = transcript.squeeze_challenge();

    let mut rounds = Vec::with_capacity(k);
    for _ in 0..k {
        let l = transcript.read_point()?;
        let r = transcript.read_point()?;
        let u_j = transcript.squeeze_challenge();
        rounds.push((l, r, u_j));
    }
    let mut u_inv: Vec<Fp> = rounds.iter().map(|r| r.2).collect();
    let mut scratch = vec![Fp::ZERO; k];
    Fp::batch_invert(&mut u_inv, &mut scratch);

    // P' + sum([u_j^-1] L_j) + sum([u_j] R_j)
    let mut u = Vec::with_capacity(k);
    for ((l, r, u_j), u_j_inv) in rounds.into_iter().zip(u_inv) {
        msm.append_term(u_j_inv, l);
        msm.append_term(u_j, r);
        u.push(u_j);
    }

    // The final commitment is [c] G'_0 + [c * b_0 * z] U + [f] W, with G'_0
    // the folded generator and b_0 the folded evaluation vector.
    let c = transcript.read_scalar()?;
    let neg_c = -c;
    let f = transcript.read_scalar()?;
    let b = compute_b(x, &u);

    msm.add_to_u_scalar(neg_c * b * z);
    msm.add_to_w_scalar(-f);
    msm.add_to_g_scalars(&compute_s(&u, neg_c));
    Ok(msm)
}

/// `prod (1 + u_j x^(2^j))` over the challenges in reverse: the folded
/// evaluation vector.
fn compute_b(x: Fp, u: &[Fp]) -> Fp {
    let mut tmp = Fp::ONE;
    let mut cur = x;
    for u_j in u.iter().rev() {
        tmp *= Fp::ONE + *u_j * cur;
        cur *= cur;
    }
    tmp
}

/// The coefficients of `init * prod (1 + u_j X^(2^j))`: the scalars the
/// folded generator is made of.
fn compute_s(u: &[Fp], init: Fp) -> Vec<Fp> {
    assert!(!u.is_empty());
    let mut v = vec![Fp::ZERO; 1 << u.len()];
    v[0] = init;
    for (len, u_j) in u.iter().rev().enumerate().map(|(i, u_j)| (1 << i, u_j)) {
        let (left, right) = v.split_at_mut(len);
        let right = &mut right[0..len];
        right.copy_from_slice(left);
        for v in right {
            *v *= *u_j;
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchard::halo2::poly::EvaluationDomain;

    #[test]
    fn commitment_bases_agree_and_openings_verify() {
        const K: u32 = 4;
        let params = Params::new(K);
        let domain = EvaluationDomain::new(1 + 1, K);
        let values: Vec<Fp> = (0..16u64).map(|i| Fp::from_u64(i * i + 3)).collect();
        let coeffs = domain.lagrange_to_coeff(values.clone());
        let blind = Fp::from_u64(99);
        let c = params.commit(&coeffs, blind);
        assert_eq!(
            c.to_affine(),
            params.commit_lagrange(&values, blind).to_affine()
        );
        // the verifier-only parameters hold the same first generators
        let short = Params::for_verifier(K, 3);
        assert_eq!(short.g_lagrange[..], params.g_lagrange[..3]);

        let x = Fp::from_u64(0xdead_beef);
        let v = eval_polynomial(&coeffs, x);
        let mut rng = ProverRng::new(&[7u8; 64]);
        let mut t = TranscriptWrite::new();
        create_proof(&params, &mut rng, &mut t, &coeffs, blind, x).unwrap();
        let proof = t.finalize();

        let check = |proof: &[u8], v: Fp| {
            let mut msm = Msm::new();
            msm.append_term(Fp::ONE, c.to_affine());
            let mut t = TranscriptRead::new(proof);
            verify_proof(&params, msm, &mut t, x, v).map(|msm| msm.eval(&params))
        };
        assert_eq!(check(&proof, v), Ok(true));
        assert_eq!(check(&proof, v + Fp::ONE), Ok(false));
        assert!(check(&proof[..proof.len() - 1], v).is_err());
    }
}
