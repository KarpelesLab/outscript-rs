//! The CryptoNote ring signature of a transparent (pre-Zarcanum) input
//! (`generate_ring_signature`, `check_ring_signature`), and the generic
//! Schnorr signature that proves the ownership of an asset
//! (`generate_schnorr_sig`, `verify_schnorr_sig`).

use crate::cryptonote::{EdwardsPoint, Hasher, Scalar, point_from_hash};
use crate::prelude::*;

use super::Error;
use super::crypto::{self, Transcript, msm_vartime, random_scalar};
use super::tx_ext::{NlsagSig, SchnorrSig};

/// Signs `prefix_hash` with the ring member at `secret_index`
/// (`generate_ring_signature`).
///
/// - `ring`: the one-time public keys of the outputs the input refers to,
///   in ring order;
/// - `key_image`: `secret * Hp(ring[secret_index])`;
/// - `secret`: the secret key of `ring[secret_index]`.
///
/// `rng` supplies the nonce and the decoys' challenges and responses: it
/// must fill its buffer from a cryptographically secure source.
///
/// Fails with [`Error::InvalidRing`] for an empty ring or an index outside
/// it, [`Error::SecretMismatch`] if `secret` is not the key of the member
/// or of the key image, and `InvalidPoint` if a member does not decode.
pub fn generate_ring_signature(
    rng: &mut dyn FnMut(&mut [u8]),
    prefix_hash: &[u8; 32],
    ring: &[[u8; 32]],
    key_image: &EdwardsPoint,
    secret: &Scalar,
    secret_index: usize,
) -> Result<NlsagSig, Error> {
    let real = ring.get(secret_index).ok_or(Error::InvalidRing)?;
    let real_point = crypto::point(real)?;
    let real_base = point_from_hash(real);
    if EdwardsPoint::mul_base(secret) != real_point || real_base.mul(secret) != *key_image {
        return Err(Error::SecretMismatch);
    }

    let mut hasher = Hasher::new();
    hasher.update(prefix_hash);
    let mut sum = Scalar::ZERO;
    let mut sig: Vec<(Scalar, Scalar)> = Vec::with_capacity(ring.len());
    let mut nonce = Scalar::ZERO;
    for (i, member) in ring.iter().enumerate() {
        if i == secret_index {
            nonce = random_scalar(rng);
            hasher.update(&EdwardsPoint::mul_base(&nonce).compress());
            hasher.update(&real_base.mul(&nonce).compress());
            sig.push((Scalar::ZERO, Scalar::ZERO));
            continue;
        }
        let c = random_scalar(rng);
        let r = random_scalar(rng);
        let point = crypto::point(member)?;
        // The decoys' side is public: variable time.
        hasher.update(&EdwardsPoint::double_scalar_mul_base_vartime(&c, &point, &r).compress());
        hasher.update(
            &msm_vartime(&[
                (r.clone(), point_from_hash(member)),
                (c.clone(), *key_image),
            ])
            .compress(),
        );
        sum = sum.add(&c);
        sig.push((c, r));
    }
    let c = hasher.finalize_to_scalar().sub(&sum);
    let r = nonce.sub(&c.mul(secret));
    if let Some(slot) = sig.get_mut(secret_index) {
        *slot = (c, r);
    }
    Ok(NlsagSig {
        s: sig
            .iter()
            .map(|(c, r)| {
                let mut out = [0u8; 64];
                out[..32].copy_from_slice(&c.to_bytes());
                out[32..].copy_from_slice(&r.to_bytes());
                out
            })
            .collect(),
    })
}

/// Verifies the ring signature of `prefix_hash` over `ring` for the key
/// image `key_image` (`check_ring_signature`). Variable-time.
///
/// As in the reference, the challenges and responses must be reduced
/// scalars. The key image is also required to lie in the prime-order
/// subgroup, which the reference checks when it validates the input.
pub fn verify_ring_signature(
    prefix_hash: &[u8; 32],
    ring: &[[u8; 32]],
    key_image: &[u8; 32],
    sig: &NlsagSig,
) -> bool {
    verify(prefix_hash, ring, key_image, sig).unwrap_or(false)
}

fn verify(
    prefix_hash: &[u8; 32],
    ring: &[[u8; 32]],
    key_image: &[u8; 32],
    sig: &NlsagSig,
) -> Option<bool> {
    if ring.is_empty() || sig.s.len() != ring.len() {
        return None;
    }
    let image = crypto::point(key_image).ok()?;
    if !bool::from(image.is_torsion_free()) {
        return None;
    }
    let mut hasher = Hasher::new();
    hasher.update(prefix_hash);
    let mut sum = Scalar::ZERO;
    for (member, s) in ring.iter().zip(&sig.s) {
        let (c, r) = s.split_first_chunk::<32>()?;
        let c = crypto::scalar(c).ok()?;
        let r = crypto::scalar(r.try_into().ok()?).ok()?;
        let point = crypto::point(member).ok()?;
        hasher.update(&EdwardsPoint::double_scalar_mul_base_vartime(&c, &point, &r).compress());
        hasher.update(&msm_vartime(&[(r, point_from_hash(member)), (c.clone(), image)]).compress());
        sum = sum.add(&c);
    }
    Some(hasher.finalize_to_scalar() == sum)
}

/// Signs `m` with `secret` (`generate_schnorr_sig`, over `G`): the proof
/// of ownership of an asset is this signature of the transaction id with
/// the owner's key.
///
/// `rng` must fill its buffer from a cryptographically secure source.
pub fn generate_schnorr_sig(
    rng: &mut dyn FnMut(&mut [u8]),
    m: &[u8; 32],
    secret: &Scalar,
) -> SchnorrSig {
    let public = EdwardsPoint::mul_base(secret);
    let r = random_scalar(rng);
    let mut hsc = Transcript::new();
    hsc.bytes(m)
        .point(&public)
        .point(&EdwardsPoint::mul_base(&r));
    let c = hsc.take_scalar();
    SchnorrSig {
        y: r.sub(&c.mul(secret)).to_bytes(),
        c: c.to_bytes(),
    }
}

/// Verifies a Schnorr signature of `m` by the key `public`
/// (`verify_schnorr_sig`, over `G`). Variable-time.
pub fn verify_schnorr_sig(m: &[u8; 32], public: &[u8; 32], sig: &SchnorrSig) -> bool {
    let (Ok(c), Ok(y), Ok(point)) = (
        crypto::scalar(&sig.c),
        crypto::scalar(&sig.y),
        crypto::point(public),
    ) else {
        return false;
    };
    let mut hsc = Transcript::new();
    hsc.bytes(m)
        .bytes(public)
        .point(&EdwardsPoint::double_scalar_mul_base_vartime(
            &c, &point, &y,
        ));
    hsc.take_scalar() == c
}
