//! CLSAG: the ring signature of RingCT types 5 and 6 (Goodell, Noether and
//! RandomRun, "Concise Linkable Ring Signatures and Forgery Against
//! Adversarial Keys"), as in Monero's `rctSigs.cpp`.
//!
//! One signature proves, for one input, that the signer knows the secret key
//! of one of the ring's outputs and that this output's commitment hides the
//! same amount as the input's pseudo-output commitment — without saying which
//! output. The key image ties the signature to the output, so that it cannot
//! be spent twice.

use super::ringct::{Table, inv_eight, multiexp};
use super::{Error, random_scalar};
use crate::cryptonote::{
    EdwardsPoint, Hasher, Scalar, point_from_bytes, point_from_hash, scalar_from_bytes,
};

#[cfg(feature = "alloc")]
use crate::prelude::*;

/// An output in a ring: its one-time public key and the commitment to its
/// amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingMember {
    /// The one-time public key of the output.
    pub key: [u8; 32],
    /// The commitment to its amount (for a coinbase output, whose amount is
    /// in the clear, [`zero_commit`](super::zero_commit)).
    pub commitment: [u8; 32],
}

/// The fixed part of a CLSAG signature; the responses, one per ring member,
/// go in a slice next to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClsagParts {
    /// The first challenge.
    pub c1: [u8; 32],
    /// The commitment key image, divided by 8.
    pub d: [u8; 32],
}

/// A domain separator, padded with zeros to 32 bytes.
fn domain(name: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (o, b) in out.iter_mut().zip(name) {
        *o = *b;
    }
    out
}

/// The aggregation coefficients `mu_P` and `mu_C`, and the hasher of the
/// round challenges with everything but `L` and `R` absorbed.
fn prepare(
    message: &[u8; 32],
    ring: &[RingMember],
    key_image: &[u8; 32],
    d: &[u8; 32],
    pseudo_out: &[u8; 32],
) -> (Scalar, Scalar, Hasher) {
    let mut agg = Hasher::new();
    let mut round = Hasher::new();
    round.update(&domain(b"CLSAG_round"));
    let mut agg1 = Hasher::new();
    agg.update(&domain(b"CLSAG_agg_0"));
    agg1.update(&domain(b"CLSAG_agg_1"));
    for member in ring {
        agg.update(&member.key);
        agg1.update(&member.key);
        round.update(&member.key);
    }
    for member in ring {
        agg.update(&member.commitment);
        agg1.update(&member.commitment);
        round.update(&member.commitment);
    }
    for h in [&mut agg, &mut agg1] {
        h.update(key_image);
        h.update(d);
        h.update(pseudo_out);
    }
    round.update(pseudo_out);
    round.update(message);
    (agg.finalize_to_scalar(), agg1.finalize_to_scalar(), round)
}

/// The next challenge: the round hash over `L` and `R`.
fn challenge(round: &Hasher, l: &EdwardsPoint, r: &EdwardsPoint) -> Scalar {
    let mut h = round.clone();
    h.update(&l.compress());
    h.update(&r.compress());
    h.finalize_to_scalar()
}

/// The points of the ring step of member `member`: its key `P`, its
/// commitment less the pseudo-output `C`, and `Hp(P)`.
fn member_points(
    member: &RingMember,
    pseudo_out: &EdwardsPoint,
) -> Result<(EdwardsPoint, EdwardsPoint, EdwardsPoint), Error> {
    let key = point_from_bytes(&member.key)?;
    let commitment = point_from_bytes(&member.commitment)?.sub(pseudo_out);
    Ok((key, commitment, point_from_hash(&member.key)))
}

/// One step around the ring: from the challenge `c` and the response `s` of a
/// member to the next challenge. Variable-time, for public values.
#[allow(clippy::too_many_arguments)]
fn step(
    round: &Hasher,
    mu_p: &Scalar,
    mu_c: &Scalar,
    c: &Scalar,
    s: &Scalar,
    points: &(EdwardsPoint, EdwardsPoint, EdwardsPoint),
    key_image: &EdwardsPoint,
    d8: &EdwardsPoint,
    tables: &mut [Table; 3],
) -> Scalar {
    let (key, commitment, hashed) = points;
    let c_p = mu_p.mul(c);
    let c_c = mu_c.mul(c);
    let scalars = [s.clone(), c_p, c_c];
    // L = s * G + c_p * P + c_c * C
    let l = multiexp(
        &scalars,
        &[EdwardsPoint::generator(), *key, *commitment],
        tables,
        false,
    );
    // R = s * Hp(P) + c_p * I + c_c * D
    let r = multiexp(&scalars, &[*hashed, *key_image, *d8], tables, false);
    challenge(round, &l, &r)
}

fn new_tables() -> [Table; 3] {
    [Table::new(), Table::new(), Table::new()]
}

/// Verifies a CLSAG signature (`verRctCLSAGSimple`).
///
/// `message` is the transaction's
/// signature hash (`Transaction::signature_hash`), `ring` the outputs
/// the input refers to, `key_image` the input's key image, `pseudo_out` its
/// pseudo-output commitment; `responses` (one per ring member) and `parts`
/// are the signature.
///
/// The key image must be in the prime-order subgroup, as consensus requires
/// (a key image with a torsion component would allow spending an output more
/// than once). Variable-time: everything here is public.
pub fn clsag_verify(
    message: &[u8; 32],
    ring: &[RingMember],
    key_image: &[u8; 32],
    pseudo_out: &[u8; 32],
    responses: &[[u8; 32]],
    parts: &ClsagParts,
) -> bool {
    verify_inner(message, ring, key_image, pseudo_out, responses, parts).unwrap_or(false)
}

fn verify_inner(
    message: &[u8; 32],
    ring: &[RingMember],
    key_image: &[u8; 32],
    pseudo_out: &[u8; 32],
    responses: &[[u8; 32]],
    parts: &ClsagParts,
) -> Result<bool, Error> {
    if ring.is_empty() || ring.len() != responses.len() {
        return Ok(false);
    }
    let image = point_from_bytes(key_image)?;
    let d8 = point_from_bytes(&parts.d)?.mul_by_cofactor();
    let identity = EdwardsPoint::identity();
    if image == identity || d8 == identity || !bool::from(image.is_torsion_free()) {
        return Ok(false);
    }
    let offset = point_from_bytes(pseudo_out)?;
    let c1 = scalar_from_bytes(&parts.c1)?;

    let (mu_p, mu_c, round) = prepare(message, ring, key_image, &parts.d, pseudo_out);
    let mut tables = new_tables();
    let mut c = c1.clone();
    for (member, response) in ring.iter().zip(responses) {
        let s = scalar_from_bytes(response)?;
        let points = member_points(member, &offset)?;
        c = step(
            &round,
            &mu_p,
            &mu_c,
            &c,
            &s,
            &points,
            &image,
            &d8,
            &mut tables,
        );
    }
    Ok(c == c1)
}

/// Makes a CLSAG signature (`proveRctCLSAGSimple`), writing the responses to
/// `responses` and returning the rest of the signature and the key image.
///
/// - `message`: the transaction's
///   signature hash (`Transaction::signature_hash`).
/// - `ring`: the outputs of the ring, in the order of the input's key
///   offsets; `real_index` is the position of the output being spent.
/// - `secret_key`: the one-time secret key of that output
///   ([`AccountKeys::output_secret_key`](super::AccountKeys::output_secret_key)).
/// - `mask_difference`: the output's commitment mask less the mask of
///   `pseudo_out`, which must commit to the same amount.
/// - `rng`: fills its argument with cryptographically secure random bytes.
///   The nonce of the signature comes from it, so it must never repeat or be
///   predictable: that would reveal the secret key.
/// - `responses`: one slot per ring member.
///
/// Fails with [`Error::InvalidRing`] if the ring is empty, `real_index` is
/// outside it or `responses` has another length; [`Error::KeyMismatch`] if
/// `secret_key` or `mask_difference` do not open the ring member at
/// `real_index`; [`Error::CryptoNote`] if a key is not a curve point or a
/// secret not a reduced scalar; [`Error::BadRandomness`] if `rng` yields
/// only zeros.
///
/// The operations on the secrets are constant-time; the position of the
/// real output is not treated as secret from the local machine (the walk
/// around the ring starts there).
#[allow(clippy::too_many_arguments)]
pub fn clsag_sign(
    message: &[u8; 32],
    ring: &[RingMember],
    real_index: usize,
    secret_key: &[u8; 32],
    mask_difference: &[u8; 32],
    pseudo_out: &[u8; 32],
    rng: &mut dyn FnMut(&mut [u8]),
    responses: &mut [[u8; 32]],
) -> Result<(ClsagParts, [u8; 32]), Error> {
    let n = ring.len();
    let real = ring.get(real_index).ok_or(Error::InvalidRing)?;
    if responses.len() != n {
        return Err(Error::InvalidRing);
    }
    let p = scalar_from_bytes(secret_key)?;
    let z = scalar_from_bytes(mask_difference)?;
    let offset = point_from_bytes(pseudo_out)?;
    let (real_key, real_commitment, hashed) = member_points(real, &offset)?;
    if EdwardsPoint::mul_base(&p) != real_key || EdwardsPoint::mul_base(&z) != real_commitment {
        return Err(Error::KeyMismatch);
    }

    let image = hashed.mul(&p);
    let d_full = hashed.mul(&z);
    let key_image = image.compress();
    let d = d_full.mul(&inv_eight()).compress();
    // What the verifier will use: 8 * (D / 8).
    let d8 = d_full;

    let alpha = random_scalar(rng)?;
    let a_g = EdwardsPoint::mul_base(&alpha);
    let a_h = hashed.mul(&alpha);

    let (mu_p, mu_c, round) = prepare(message, ring, &key_image, &d, pseudo_out);
    let mut tables = new_tables();
    let mut c = challenge(&round, &a_g, &a_h);
    let mut c1 = None;
    let mut i = real_index;
    for _ in 1..n {
        i = if i + 1 >= n { 0 } else { i + 1 };
        if i == 0 {
            c1 = Some(c.clone());
        }
        let s = random_scalar(rng)?;
        let member = ring.get(i).ok_or(Error::InvalidRing)?;
        let points = member_points(member, &offset)?;
        c = step(
            &round,
            &mu_p,
            &mu_c,
            &c,
            &s,
            &points,
            &image,
            &d8,
            &mut tables,
        );
        *responses.get_mut(i).ok_or(Error::InvalidRing)? = s.to_bytes();
    }
    // The walk is back at the real output: `c` is its challenge.
    let c_real = c;
    // The walk passed index 0 unless it started there, in which case the
    // challenge of index 0 is the one it ends with.
    let c1 = c1.unwrap_or_else(|| c_real.clone());
    // s = alpha - c * (mu_P * p + mu_C * z)
    let s = alpha.sub(&c_real.mul(&mu_p.mul(&p).add(&mu_c.mul(&z))));
    *responses.get_mut(real_index).ok_or(Error::InvalidRing)? = s.to_bytes();
    Ok((
        ClsagParts {
            c1: c1.to_bytes(),
            d,
        },
        key_image,
    ))
}

/// A CLSAG signature, as a transaction carries it.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clsag {
    /// The responses, one per ring member.
    pub s: Vec<[u8; 32]>,
    /// The first challenge.
    pub c1: [u8; 32],
    /// The commitment key image, divided by 8.
    pub d: [u8; 32],
}

#[cfg(feature = "alloc")]
impl Clsag {
    /// Signs: [`clsag_sign`] with the responses in a `Vec`. Returns the
    /// signature and the key image.
    pub fn sign(
        message: &[u8; 32],
        ring: &[RingMember],
        real_index: usize,
        secret_key: &[u8; 32],
        mask_difference: &[u8; 32],
        pseudo_out: &[u8; 32],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(Clsag, [u8; 32]), Error> {
        let mut s = vec![[0u8; 32]; ring.len()];
        let (parts, key_image) = clsag_sign(
            message,
            ring,
            real_index,
            secret_key,
            mask_difference,
            pseudo_out,
            rng,
            &mut s,
        )?;
        Ok((
            Clsag {
                s,
                c1: parts.c1,
                d: parts.d,
            },
            key_image,
        ))
    }

    /// Verifies the signature: [`clsag_verify`].
    pub fn verify(
        &self,
        message: &[u8; 32],
        ring: &[RingMember],
        key_image: &[u8; 32],
        pseudo_out: &[u8; 32],
    ) -> bool {
        let parts = ClsagParts {
            c1: self.c1,
            d: self.d,
        };
        clsag_verify(message, ring, key_image, pseudo_out, &self.s, &parts)
    }
}

/// What the signers of a multisig CLSAG (`multisig::signing::CLSAG_context_t`)
/// derive from the public data of an input and the aggregate nonces.
#[cfg(feature = "alloc")]
pub(crate) struct MultisigChallenge {
    /// The factor that merges the nonce components: component `i` counts
    /// `b^i` times.
    pub(crate) b: Scalar,
    /// The challenge of the output being spent.
    pub(crate) c: Scalar,
    /// The first challenge, which the signature carries.
    pub(crate) c1: Scalar,
    /// The aggregation coefficient of the key.
    pub(crate) mu_p: Scalar,
    /// The aggregation coefficient of the commitment.
    pub(crate) mu_c: Scalar,
}

/// The challenges of a multisig CLSAG
/// (`CLSAG_context_t::combine_alpha_and_compute_challenge`): the signers'
/// aggregate nonces `alpha_g` (on `G`) and `alpha_h` (on `Hp(P)`), one per
/// component, are merged with a factor that binds everything the signature
/// is about, and the ring is walked from the output being spent.
///
/// `d` is the commitment key image as the signature carries it (divided by
/// 8), `responses` the responses of the signature, the one at `real_index`
/// being ignored. Variable-time: everything here is public.
#[cfg(feature = "alloc")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn multisig_challenge(
    message: &[u8; 32],
    ring: &[RingMember],
    real_index: usize,
    key_image: &[u8; 32],
    d: &[u8; 32],
    pseudo_out: &[u8; 32],
    responses: &[[u8; 32]],
    alpha_g: &[[u8; 32]],
    alpha_h: &[[u8; 32]],
) -> Result<MultisigChallenge, Error> {
    let n = ring.len();
    if real_index >= n
        || responses.len() != n
        || alpha_g.is_empty()
        || alpha_g.len() != alpha_h.len()
    {
        return Err(Error::InvalidRing);
    }
    let image = point_from_bytes(key_image)?;
    let d8 = point_from_bytes(d)?.mul_by_cofactor();
    let offset = point_from_bytes(pseudo_out)?;
    let (mu_p, mu_c, round) = prepare(message, ring, key_image, d, pseudo_out);

    let mut h = Hasher::new();
    h.update(&domain(b"CLSAG_round_ms_merge_factor"));
    for member in ring {
        h.update(&member.key);
    }
    for member in ring {
        h.update(&member.commitment);
    }
    h.update(pseudo_out);
    h.update(message);
    for nonce in alpha_g.iter().chain(alpha_h) {
        h.update(nonce);
    }
    h.update(key_image);
    h.update(&d8.compress());
    for (i, response) in responses.iter().enumerate() {
        if i != real_index {
            h.update(response);
        }
    }
    let number = |value: usize| {
        let mut key = [0u8; 32];
        for (o, b) in key.iter_mut().zip((value as u64).to_le_bytes()) {
            *o = b;
        }
        key
    };
    h.update(&number(real_index));
    h.update(&number(alpha_g.len()));
    h.update(&number(n));
    let b = h.finalize_to_scalar();

    let mut l = EdwardsPoint::identity();
    let mut r = EdwardsPoint::identity();
    let mut power = Scalar::ONE;
    for (g, h) in alpha_g.iter().zip(alpha_h) {
        l = l.add(&point_from_bytes(g)?.mul(&power));
        r = r.add(&point_from_bytes(h)?.mul(&power));
        power = power.mul(&b);
    }
    let mut tables = new_tables();
    let mut c = challenge(&round, &l, &r);
    let mut c1 = None;
    let mut i = real_index;
    for _ in 1..n {
        i = if i + 1 >= n { 0 } else { i + 1 };
        if i == 0 {
            c1 = Some(c.clone());
        }
        let s = scalar_from_bytes(responses.get(i).ok_or(Error::InvalidRing)?)?;
        let points = member_points(ring.get(i).ok_or(Error::InvalidRing)?, &offset)?;
        c = step(
            &round,
            &mu_p,
            &mu_c,
            &c,
            &s,
            &points,
            &image,
            &d8,
            &mut tables,
        );
    }
    let c1 = c1.unwrap_or_else(|| c.clone());
    Ok(MultisigChallenge {
        b,
        c,
        c1,
        mu_p,
        mu_c,
    })
}
