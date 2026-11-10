//! Verification of the Zarcanum proof-of-stake proof (`zarcanum.cpp`): the
//! signature of the stake input of a proof-of-stake block, which shows that
//! a hidden amount staked by a hidden output meets the difficulty. It is
//! made of three Schnorr-like proofs, a double-blinded range proof
//! (`bppe_verify` with the trait `bpp_crypto_trait_Zarcanum`) and a
//! five-layer ring signature (`verify_CLSAG_GGXXG`).

use crate::cryptonote::scalar_reduce;
use crate::cryptonote::{EdwardsPoint, Scalar, cn_fast_hash, point_from_hash, scalar_from_hash};
use crate::prelude::*;

use super::bpp::{RangeProof, verify_range};
use super::crypto::{
    self, Transcript, generator_h, generator_x, msm_vartime, mul_vartime, scalar_1div8,
};
use super::transfer::RingMember;
use super::tx_ext::{BppeSignature, ClsagGgxxgSig, ZarcanumSig};

const HDS_LAST_POW_HASH: &[u8; 32] = b"ZANO_HDS_ZARCANUM_LAST_POW_HASH\0";
const HDS_PROOF_HASH: &[u8; 32] = b"ZANO_HDS_ZARCANUM_PROOF_HASH___\0";
const HDS_GGXXG_LAYERS: [&[u8; 32]; 5] = [
    b"ZANO_HDS_CLSAG_GGXXG_LAYER_ZERO\0",
    b"ZANO_HDS_CLSAG_GGXXG_LAYER_ONE_\0",
    b"ZANO_HDS_CLSAG_GGXXG_LAYER_TWO_\0",
    b"ZANO_HDS_CLSAG_GGXXG_LAYER_3___\0",
    b"ZANO_HDS_CLSAG_GGXXG_LAYER_FOUR\0",
];
const HDS_GGXXG_CHALLENGE: &[u8; 32] = b"ZANO_HDS_CLSAG_GGXXG_CHALLENGE_\0";

/// The group order, as little-endian 64-bit limbs.
const ORDER: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
];

/// What the stake proof of a proof-of-stake block is about
/// (`validate_pos_block`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StakeContext {
    /// The id of the block: what the stake signs.
    pub block_id: [u8; 32],
    /// The timestamp of the block (its header's, not the one in the extra
    /// of its first transaction).
    pub timestamp: u64,
    /// The id of the last proof-of-work block before it (the first half of
    /// the stake modifier).
    pub last_pow_id: [u8; 32],
    /// The kernel hash of the last proof-of-stake block before it (the
    /// second half of the stake modifier).
    pub last_pos_kernel_id: [u8; 32],
    /// The proof-of-stake difficulty the block has to meet
    /// (`pos_basic_difficulty`).
    pub pos_difficulty: u128,
    /// The outputs the stake input refers to, in ring order. Their global
    /// indices are not used. Empty for a stake before hard fork 4, whose
    /// ring goes with the other inputs' (and whose kernel is not checked
    /// against the difficulty).
    pub ring: Vec<RingMember>,
}

impl StakeContext {
    /// The hash of the stake kernel — the stake modifier, the timestamp of
    /// the block and the key image of the stake (`stake_kernel`).
    pub fn kernel_hash(&self, key_image: &[u8; 32]) -> [u8; 32] {
        let mut kernel = [0u8; 104];
        kernel[..32].copy_from_slice(&self.last_pow_id);
        kernel[32..64].copy_from_slice(&self.last_pos_kernel_id);
        kernel[64..72].copy_from_slice(&self.timestamp.to_le_bytes());
        kernel[72..].copy_from_slice(key_image);
        cn_fast_hash(&kernel)
    }
}

/// `floor(l / (2^64 * difficulty))`, as little-endian limbs
/// (`zarcanum_precalculate_l_div_z_D`); `None` for a zero difficulty.
fn order_div_z_difficulty(difficulty: u128) -> Option<[u64; 4]> {
    if difficulty == 0 {
        return None;
    }
    // 2^64 * difficulty
    let divisor = [0u64, difficulty as u64, (difficulty >> 64) as u64, 0];
    let less = |a: &[u64; 4], b: &[u64; 4]| a.iter().rev().lt(b.iter().rev());
    let mut quotient = [0u64; 4];
    // The remainder stays below the divisor, which is below 2^192.
    let mut remainder = [0u64; 4];
    for bit in (0..256).rev() {
        let mut carry = (ORDER[bit / 64] >> (bit % 64)) & 1;
        for limb in remainder.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        if !less(&remainder, &divisor) {
            let mut borrow = false;
            for (limb, d) in remainder.iter_mut().zip(&divisor) {
                let (value, b1) = limb.overflowing_sub(*d);
                let (value, b2) = value.overflowing_sub(u64::from(borrow));
                *limb = value;
                borrow = b1 || b2;
            }
            quotient[bit / 64] |= 1 << (bit % 64);
        }
    }
    Some(quotient)
}

/// Verifies a double-blinded range proof of `commitments_1div8`, each
/// `value * H + mask_1 * G + mask_2 * X` with a value below `2^128`
/// (`bppe_verify`, with the trait `bpp_crypto_trait_Zarcanum`).
/// Variable-time.
pub fn verify_bppe(sig: &BppeSignature, commitments_1div8: &[[u8; 32]]) -> bool {
    let (Ok(delta_1), Ok(delta_2)) = (crypto::scalar(&sig.delta_1), crypto::scalar(&sig.delta_2))
    else {
        return false;
    };
    verify_range(
        &RangeProof {
            bits: 128,
            max_values: 16,
            lv: &sig.lv,
            rv: &sig.rv,
            a0: &sig.a0,
            a: &sig.a,
            b: &sig.b,
            r: &sig.r,
            s: &sig.s,
            value_generator: generator_h(),
            masks: &[
                (delta_1, EdwardsPoint::generator()),
                (delta_2, generator_x()),
            ],
        },
        commitments_1div8,
    )
    .unwrap_or(false)
}

/// Verifies a CLSAG-GGXXG signature of `m` over `ring`
/// (`verify_CLSAG_GGXXG`). The pseudo-output's points and the extended
/// amount commitment are given as they are on the wire: multiplied by
/// `1/8`. Variable-time.
pub fn verify_clsag_ggxxg(
    m: &[u8; 32],
    ring: &[RingMember],
    pseudo_out_amount_commitment_1div8: &[u8; 32],
    pseudo_out_blinded_asset_id_1div8: &[u8; 32],
    extended_amount_commitment_1div8: &[u8; 32],
    key_image: &[u8; 32],
    sig: &ClsagGgxxgSig,
) -> bool {
    ggxxg(
        m,
        ring,
        pseudo_out_amount_commitment_1div8,
        pseudo_out_blinded_asset_id_1div8,
        extended_amount_commitment_1div8,
        key_image,
        sig,
    )
    .unwrap_or(false)
}

fn ggxxg(
    m: &[u8; 32],
    ring: &[RingMember],
    pseudo_amount: &[u8; 32],
    pseudo_asset: &[u8; 32],
    extended: &[u8; 32],
    key_image: &[u8; 32],
    sig: &ClsagGgxxgSig,
) -> Option<bool> {
    if ring.is_empty() || sig.r_g.len() != ring.len() || sig.r_x.len() != ring.len() {
        return None;
    }
    let point8 = |bytes: &[u8; 32]| Some(crypto::point(bytes).ok()?.mul_by_cofactor());
    let ki = crypto::point(key_image).ok()?;
    if !bool::from(ki.is_torsion_free()) {
        return None;
    }
    let pseudo_amount_pt = point8(pseudo_amount)?;
    let pseudo_asset_pt = point8(pseudo_asset)?;
    let extended_pt = point8(extended)?;

    let mut hsc = Transcript::new();
    hsc.scalar(&scalar_reduce(m));
    for member in ring {
        hsc.bytes(&member.stealth_address)
            .bytes(&member.amount_commitment)
            .bytes(&member.blinded_asset_id)
            .bytes(&member.concealing_point);
    }
    hsc.bytes(pseudo_amount)
        .bytes(pseudo_asset)
        .bytes(extended)
        .bytes(key_image)
        .bytes(&sig.k1)
        .bytes(&sig.k2)
        .bytes(&sig.k3)
        .bytes(&sig.k4);
    let input_hash = hsc.take_hash();
    let coeffs = HDS_GGXXG_LAYERS.map(|domain| scalar_from_hash(&[domain, &input_hash]));
    let [c0, c1, c2, c3, c4] = &coeffs;

    let x = generator_x();
    let w_key_image_g = msm_vartime(&[
        (c0.clone(), ki),
        (c1.clone(), point8(&sig.k1)?),
        (c4.clone(), point8(&sig.k4)?),
    ]);
    let w_key_image_x = msm_vartime(&[
        (c2.clone(), point8(&sig.k2)?),
        (c3.clone(), point8(&sig.k3)?),
    ]);

    let c_first = crypto::scalar(&sig.c).ok()?;
    let mut c = c_first.clone();
    for ((member, r_g), r_x) in ring.iter().zip(&sig.r_g).zip(&sig.r_x) {
        let stealth = crypto::point(&member.stealth_address).ok()?;
        let amount = point8(&member.amount_commitment)?;
        let asset = point8(&member.blinded_asset_id)?;
        let concealing = point8(&member.concealing_point)?;
        let w_pub_g = msm_vartime(&[
            (c0.clone(), stealth),
            (c1.clone(), amount.sub(&pseudo_amount_pt)),
            (c4.clone(), concealing),
        ]);
        let w_pub_x = msm_vartime(&[
            (c2.clone(), asset.sub(&pseudo_asset_pt)),
            (c3.clone(), extended_pt.sub(&amount).sub(&concealing)),
        ]);
        let hp = point_from_hash(&member.stealth_address);
        let r_g = scalar_reduce(r_g);
        let r_x = scalar_reduce(r_x);
        let mut hsc = Transcript::new();
        hsc.bytes(HDS_GGXXG_CHALLENGE)
            .bytes(&input_hash)
            .point(&EdwardsPoint::double_scalar_mul_base_vartime(
                &c, &w_pub_g, &r_g,
            ))
            .point(&msm_vartime(&[(r_g, hp), (c.clone(), w_key_image_g)]))
            .point(&msm_vartime(&[(r_x.clone(), x), (c.clone(), w_pub_x)]))
            .point(&msm_vartime(&[(r_x, hp), (c.clone(), w_key_image_x)]));
        c = hsc.take_scalar();
    }
    Some(c == c_first)
}

/// Verifies the stake proof `sig` of the proof-of-stake block `stake`
/// describes, for the key image `key_image` of its stake input
/// (`zarcanum_verify_proof`). Variable-time.
pub fn verify_zarcanum_proof(
    stake: &StakeContext,
    key_image: &[u8; 32],
    sig: &ZarcanumSig,
) -> bool {
    zarcanum(stake, key_image, sig).unwrap_or(false)
}

fn zarcanum(stake: &StakeContext, key_image: &[u8; 32], sig: &ZarcanumSig) -> Option<bool> {
    // 0 < d < floor(l / (2^64 * D))
    let bound = order_div_z_difficulty(stake.pos_difficulty)?;
    let d_limbs: Vec<u64> = sig
        .d
        .as_chunks::<8>()
        .0
        .iter()
        .map(|limb| u64::from_le_bytes(*limb))
        .collect();
    if d_limbs.iter().all(|limb| *limb == 0) || !d_limbs.iter().rev().lt(bound.iter().rev()) {
        return Some(false);
    }
    let d = crypto::scalar(&sig.d).ok()?;
    // z = 2^64
    let mut z = [0u8; 32];
    z[8] = 1;
    let dz = d.mul(&Scalar::from_bytes_canonical(&z)?);

    let kernel_hash = stake.kernel_hash(key_image);
    let h = scalar_reduce(&kernel_hash);
    let last_pow = scalar_from_hash(&[HDS_LAST_POW_HASH, &stake.last_pow_id]);
    let point8 = |bytes: &[u8; 32]| Some(crypto::point(bytes).ok()?.mul_by_cofactor());
    let c_prime_pt = point8(&sig.c_prime)?;
    let c_pt = point8(&sig.c_point)?;
    let e_pt = point8(&sig.e)?;
    let g = EdwardsPoint::generator();
    let h_gen = generator_h();
    let x = generator_x();

    // F = h * C' - d * z * C + E + f' * h * H
    let f = msm_vartime(&[
        (h.clone(), c_prime_pt),
        (dz.negate(), c_pt),
        (Scalar::ONE, e_pt),
        (last_pow.mul(&h), h_gen),
    ]);
    let sum = c_pt.add(&c_prime_pt);
    let difference = c_pt.sub(&c_prime_pt);

    let c = crypto::scalar(&sig.c).ok()?;
    let minus_c = c.negate();
    let [y0, y1, y2, y3, y4] = [&sig.y0, &sig.y1, &sig.y2, &sig.y3, &sig.y4].map(scalar_reduce);
    let mut hsc = Transcript::new();
    hsc.bytes(HDS_PROOF_HASH)
        .point(&msm_vartime(&[
            (y0, x),
            (y1, h_gen.add(&g)),
            (minus_c.clone(), sum),
        ]))
        .point(&msm_vartime(&[
            (y2, x),
            (y3, h_gen.sub(&g)),
            (minus_c.clone(), difference),
        ]))
        .point(&msm_vartime(&[(y4, x), (minus_c, f)]))
        .point(&sum)
        .point(&difference)
        .point(&f);
    if hsc.take_scalar() != c {
        return Some(false);
    }

    if !verify_bppe(&sig.e_range_proof, &[sig.e]) {
        return Some(false);
    }
    let native_1div8 = mul_vartime(&scalar_1div8(), &h_gen).compress();
    Some(verify_clsag_ggxxg(
        &stake.block_id,
        &stake.ring,
        &sig.pseudo_out_amount_commitment,
        &native_1div8,
        &sig.c_point,
        key_image,
        &sig.clsag_ggxxg,
    ))
}
