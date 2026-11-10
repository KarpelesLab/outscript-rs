//! CLSAG-GGX: the three-layer linkable ring signature of a confidential
//! input (`clsag.cpp`).
//!
//! The layers prove, for one hidden member of the ring, knowledge of the
//! output's secret key (over `G`, with the key image for linkability), of
//! the difference between the amount blinding masks of the output and of the
//! pseudo-output (over `G`), and of the difference between their asset
//! blinding masks (over `X`).

use crate::cryptonote::{EdwardsPoint, Scalar, point_from_hash, scalar_reduce};
use crate::prelude::*;

use super::Error;
use super::crypto::{
    self, Transcript, generator_x, msm_vartime, mul_vartime, random_scalar, scalar_1div8,
};
use super::tx::ClsagGgxSig;

const HDS_LAYER_0: &[u8; 32] = b"ZANO_HDS_CLSAG_GGX_LAYER_ZERO__\0";
const HDS_LAYER_1: &[u8; 32] = b"ZANO_HDS_CLSAG_GGX_LAYER_ONE___\0";
const HDS_LAYER_2: &[u8; 32] = b"ZANO_HDS_CLSAG_GGX_LAYER_TWO___\0";
const HDS_CHALLENGE: &[u8; 32] = b"ZANO_HDS_CLSAG_GGX_CHALLENGE___\0";

/// One member of the ring of a CLSAG-GGX signature: an output as it is on
/// chain (`CLSAG_GGX_input_ref_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClsagGgxInput {
    /// The one-time public key of the output.
    pub stealth_address: [u8; 32],
    /// Its amount commitment, times `1/8`.
    pub amount_commitment: [u8; 32],
    /// Its blinded asset id, times `1/8`.
    pub blinded_asset_id: [u8; 32],
}

/// The ring, decoded: stealth addresses as they are, commitments and asset
/// ids multiplied by 8.
struct Ring {
    stealth: Vec<EdwardsPoint>,
    amount: Vec<EdwardsPoint>,
    asset: Vec<EdwardsPoint>,
}

impl Ring {
    fn decode(ring: &[ClsagGgxInput]) -> Result<Self, Error> {
        let mut out = Ring {
            stealth: Vec::with_capacity(ring.len()),
            amount: Vec::with_capacity(ring.len()),
            asset: Vec::with_capacity(ring.len()),
        };
        for member in ring {
            out.stealth.push(crypto::point(&member.stealth_address)?);
            out.amount
                .push(crypto::point(&member.amount_commitment)?.mul_by_cofactor());
            out.asset
                .push(crypto::point(&member.blinded_asset_id)?.mul_by_cofactor());
        }
        Ok(out)
    }
}

/// What both signer and verifier derive from the public data.
struct Context {
    input_hash: [u8; 32],
    /// `agg_coeff_0 * P_i + agg_coeff_1 * (A_i - A^p)` for each member.
    w_pub_g: Vec<EdwardsPoint>,
    /// `agg_coeff_2 * (Q_i - T^p)` for each member.
    w_pub_x: Vec<EdwardsPoint>,
    w_key_image_g: EdwardsPoint,
    w_key_image_x: EdwardsPoint,
    coeffs: [Scalar; 3],
}

#[allow(clippy::too_many_arguments)]
fn context(
    m: &[u8; 32],
    raw_ring: &[ClsagGgxInput],
    ring: &Ring,
    pseudo_out_amount_commitment_1div8: &[u8; 32],
    pseudo_out_blinded_asset_id_1div8: &[u8; 32],
    pseudo_out_amount_commitment: &EdwardsPoint,
    pseudo_out_blinded_asset_id: &EdwardsPoint,
    key_image: &EdwardsPoint,
    k1_div8: &[u8; 32],
    k2_div8: &[u8; 32],
    k1: &EdwardsPoint,
    k2: &EdwardsPoint,
) -> Context {
    let mut hsc = Transcript::new();
    // The message goes in as a scalar: reduced modulo the group order.
    hsc.scalar(&scalar_reduce(m));
    for member in raw_ring {
        hsc.bytes(&member.stealth_address)
            .bytes(&member.amount_commitment)
            .bytes(&member.blinded_asset_id);
    }
    hsc.bytes(pseudo_out_amount_commitment_1div8)
        .bytes(pseudo_out_blinded_asset_id_1div8)
        .point(key_image)
        .bytes(k1_div8)
        .bytes(k2_div8);
    let input_hash = hsc.take_hash();

    let coeff = |domain: &[u8; 32]| {
        let mut hsc = Transcript::new();
        hsc.bytes(domain).bytes(&input_hash);
        hsc.take_scalar()
    };
    let coeffs = [coeff(HDS_LAYER_0), coeff(HDS_LAYER_1), coeff(HDS_LAYER_2)];

    let w_pub_g = ring
        .stealth
        .iter()
        .zip(&ring.amount)
        .map(|(stealth, amount)| {
            msm_vartime(&[
                (coeffs[0].clone(), *stealth),
                (coeffs[1].clone(), amount.sub(pseudo_out_amount_commitment)),
            ])
        })
        .collect();
    let w_pub_x = ring
        .asset
        .iter()
        .map(|asset| mul_vartime(&coeffs[2], &asset.sub(pseudo_out_blinded_asset_id)))
        .collect();
    Context {
        input_hash,
        w_pub_g,
        w_pub_x,
        w_key_image_g: msm_vartime(&[(coeffs[0].clone(), *key_image), (coeffs[1].clone(), *k1)]),
        w_key_image_x: mul_vartime(&coeffs[2], k2),
        coeffs,
    }
}

/// The next challenge of the ring, from the four commitments of a member.
fn challenge(input_hash: &[u8; 32], commitments: [EdwardsPoint; 4]) -> Scalar {
    let mut hsc = Transcript::new();
    hsc.bytes(HDS_CHALLENGE).bytes(input_hash);
    for point in &commitments {
        hsc.point(point);
    }
    hsc.take_scalar()
}

/// The challenge that follows member `i`, given the challenge `c` at `i` and
/// the member's responses. Variable-time: everything here is public.
fn next_challenge(
    ctx: &Context,
    stealth: &EdwardsPoint,
    i: usize,
    c: &Scalar,
    r_g: &Scalar,
    r_x: &Scalar,
) -> Option<Scalar> {
    let hp = point_from_hash(&stealth.compress());
    let x = generator_x();
    Some(challenge(
        &ctx.input_hash,
        [
            EdwardsPoint::double_scalar_mul_base_vartime(c, ctx.w_pub_g.get(i)?, r_g),
            msm_vartime(&[(r_g.clone(), hp), (c.clone(), ctx.w_key_image_g)]),
            msm_vartime(&[(r_x.clone(), x), (c.clone(), *ctx.w_pub_x.get(i)?)]),
            msm_vartime(&[(r_x.clone(), hp), (c.clone(), ctx.w_key_image_x)]),
        ],
    ))
}

/// Signs `m` with the ring member at `secret_index` (`generate_CLSAG_GGX`).
///
/// - `pseudo_out_amount_commitment` and `pseudo_out_blinded_asset_id` are the
///   pseudo-output's points, *not* multiplied by `1/8`;
/// - `key_image` is `secret_0_xp * Hp(stealth_address)`;
/// - `secret_0_xp` is the secret key of the real output's stealth address;
/// - `secret_1_f` is the output's amount blinding mask minus the
///   pseudo-output's;
/// - `secret_2_t` is the output's asset blinding mask minus the
///   pseudo-output's (so, minus the extra mask the pseudo-output adds).
///
/// `rng` supplies the nonces and the decoys' responses: it must fill its
/// buffer from a cryptographically secure source.
///
/// Fails with [`Error::InvalidRing`] for an empty ring or an index outside
/// it, [`Error::SecretMismatch`] when a secret does not match the ring member
/// (or the key image), and `InvalidPoint` if a ring member does not decode.
#[allow(clippy::too_many_arguments)]
pub fn generate_clsag_ggx(
    rng: &mut dyn FnMut(&mut [u8]),
    m: &[u8; 32],
    ring: &[ClsagGgxInput],
    key_image: &EdwardsPoint,
    pseudo_out_amount_commitment: &EdwardsPoint,
    pseudo_out_blinded_asset_id: &EdwardsPoint,
    secret_0_xp: &Scalar,
    secret_1_f: &Scalar,
    secret_2_t: &Scalar,
    secret_index: usize,
) -> Result<ClsagGgxSig, Error> {
    let points = Ring::decode(ring)?;
    let (Some(stealth), Some(amount), Some(asset)) = (
        points.stealth.get(secret_index),
        points.amount.get(secret_index),
        points.asset.get(secret_index),
    ) else {
        return Err(Error::InvalidRing);
    };
    let x = generator_x();
    let ki_base = point_from_hash(&stealth.compress());

    // The secrets must open the real member of the ring.
    if ki_base.mul(secret_0_xp) != *key_image
        || EdwardsPoint::mul_base(secret_0_xp) != *stealth
        || EdwardsPoint::mul_base(secret_1_f) != amount.sub(pseudo_out_amount_commitment)
        || x.mul(secret_2_t) != asset.sub(pseudo_out_blinded_asset_id)
    {
        return Err(Error::SecretMismatch);
    }

    let inv8 = scalar_1div8();
    let k1_div8 = ki_base.mul(&inv8.mul(secret_1_f));
    let k2_div8 = ki_base.mul(&inv8.mul(secret_2_t));
    let k1_bytes = k1_div8.compress();
    let k2_bytes = k2_div8.compress();

    let ctx = context(
        m,
        ring,
        &points,
        &mul_vartime(&inv8, pseudo_out_amount_commitment).compress(),
        &mul_vartime(&inv8, pseudo_out_blinded_asset_id).compress(),
        pseudo_out_amount_commitment,
        pseudo_out_blinded_asset_id,
        key_image,
        &k1_bytes,
        &k2_bytes,
        &k1_div8.mul_by_cofactor(),
        &k2_div8.mul_by_cofactor(),
    );

    // The aggregated secret keys.
    let w_sec_g = ctx.coeffs[0]
        .mul(secret_0_xp)
        .add(&ctx.coeffs[1].mul(secret_1_f));
    let w_sec_x = ctx.coeffs[2].mul(secret_2_t);

    let alpha_g = random_scalar(rng);
    let alpha_x = random_scalar(rng);
    let mut c = challenge(
        &ctx.input_hash,
        [
            EdwardsPoint::mul_base(&alpha_g),
            ki_base.mul(&alpha_g),
            x.mul(&alpha_x),
            ki_base.mul(&alpha_x),
        ],
    );

    let n = ring.len();
    let mut r_g = Vec::with_capacity(n);
    let mut r_x = Vec::with_capacity(n);
    for _ in 0..n {
        r_g.push(random_scalar(rng));
        r_x.push(random_scalar(rng));
    }

    let mut c0 = None;
    let mut i = (secret_index + 1) % n;
    while i != secret_index {
        if i == 0 {
            c0 = Some(c.clone());
        }
        let (Some(stealth), Some(rg), Some(rx)) = (points.stealth.get(i), r_g.get(i), r_x.get(i))
        else {
            return Err(Error::InvalidRing);
        };
        c = next_challenge(&ctx, stealth, i, &c, rg, rx).ok_or(Error::InvalidRing)?;
        i = (i + 1) % n;
    }
    if secret_index == 0 {
        c0 = Some(c.clone());
    }

    // Close the ring at the real member.
    if let (Some(rg), Some(rx)) = (r_g.get_mut(secret_index), r_x.get_mut(secret_index)) {
        *rg = alpha_g.sub(&c.mul(&w_sec_g));
        *rx = alpha_x.sub(&c.mul(&w_sec_x));
    }

    Ok(ClsagGgxSig {
        c: c0.ok_or(Error::InvalidRing)?.to_bytes(),
        r_g: r_g.iter().map(Scalar::to_bytes).collect(),
        r_x: r_x.iter().map(Scalar::to_bytes).collect(),
        k1: k1_bytes,
        k2: k2_bytes,
    })
}

/// Verifies a CLSAG-GGX signature of `m` over `ring` (`verify_CLSAG_GGX`).
///
/// Unlike for [`generate_clsag_ggx`], the pseudo-output's points are given
/// as they are in the transaction: multiplied by `1/8`.
///
/// As in the reference, the key image must lie in the prime-order subgroup,
/// the responses are taken modulo the group order, and the challenge must be
/// a reduced scalar. Variable-time.
pub fn verify_clsag_ggx(
    m: &[u8; 32],
    ring: &[ClsagGgxInput],
    pseudo_out_amount_commitment_1div8: &[u8; 32],
    pseudo_out_blinded_asset_id_1div8: &[u8; 32],
    key_image: &[u8; 32],
    sig: &ClsagGgxSig,
) -> bool {
    verify(
        m,
        ring,
        pseudo_out_amount_commitment_1div8,
        pseudo_out_blinded_asset_id_1div8,
        key_image,
        sig,
    )
    .unwrap_or(false)
}

fn verify(
    m: &[u8; 32],
    ring: &[ClsagGgxInput],
    pseudo_amount: &[u8; 32],
    pseudo_asset: &[u8; 32],
    key_image: &[u8; 32],
    sig: &ClsagGgxSig,
) -> Option<bool> {
    if ring.is_empty() || sig.r_g.len() != ring.len() || sig.r_x.len() != ring.len() {
        return None;
    }
    let points = Ring::decode(ring).ok()?;
    let ki = crypto::point(key_image).ok()?;
    if !bool::from(ki.is_torsion_free()) {
        return None;
    }
    let ctx = context(
        m,
        ring,
        &points,
        pseudo_amount,
        pseudo_asset,
        &crypto::point(pseudo_amount).ok()?.mul_by_cofactor(),
        &crypto::point(pseudo_asset).ok()?.mul_by_cofactor(),
        &ki,
        &sig.k1,
        &sig.k2,
        &crypto::point(&sig.k1).ok()?.mul_by_cofactor(),
        &crypto::point(&sig.k2).ok()?.mul_by_cofactor(),
    );

    let c0 = crypto::scalar(&sig.c).ok()?;
    let mut c = c0.clone();
    for (i, ((stealth, r_g), r_x)) in points
        .stealth
        .iter()
        .zip(&sig.r_g)
        .zip(&sig.r_x)
        .enumerate()
    {
        c = next_challenge(
            &ctx,
            stealth,
            i,
            &c,
            &scalar_reduce(r_g),
            &scalar_reduce(r_x),
        )?;
    }
    Some(c == c0)
}
