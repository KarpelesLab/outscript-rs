//! The cases of the reference's functional tests for the proofs
//! (`tests/functional_tests/crypto_tests_one_out_of_many_proofs.h` and
//! `crypto_tests_range_proofs.h`): they generate proofs and check them, as
//! here, rather than hold vectors. The verifiers they are checked with are
//! themselves checked against proofs the reference made: those of the
//! main network's transactions (see `chain.rs`), which have rings of up to
//! ten members and up to eleven outputs.

use super::super::*;
use super::stream;
use crate::cryptonote::{EdwardsPoint, Scalar, point_from_hash, scalar_from_u64};
use crate::prelude::*;

fn div8(p: &EdwardsPoint) -> [u8; 32] {
    p.mul(&scalar_1div8()).compress()
}

/// A point of order two: adding it to a point of a proof must break it.
fn torsion() -> EdwardsPoint {
    let mut bytes = [0xff; 32];
    bytes[0] = 0xec;
    bytes[31] = 0x7f;
    EdwardsPoint::decompress(&bytes).unwrap()
}

fn add_torsion(bytes: &mut [u8; 32]) {
    *bytes = EdwardsPoint::decompress(bytes)
        .unwrap()
        .add(&torsion())
        .compress();
}

/// `BGE_proff_check_t::prepare_random_data`: a ring of `size` points with
/// the secret's at `index`.
fn bge_ring(size: usize, index: usize, secret: &Scalar) -> Vec<EdwardsPoint> {
    (0..size)
        .map(|i| {
            if i == index {
                generator_x().mul(secret)
            } else {
                point_from_hash(&(i as u64).to_le_bytes())
            }
        })
        .collect()
}

/// `TEST(BGE_proof, positive)`, for ring sizes on both sides of each power
/// of four (the reference goes through all of 1 to 256).
#[test]
fn bge_positive() {
    let context = [7u8; 32];
    for (n, size) in [1usize, 2, 4, 5, 13, 16, 17].into_iter().enumerate() {
        let secret = scalar_from_u64(1000 + size as u64);
        let index = (size * 7 + 3) % size;
        let ring = bge_ring(size, index, &secret);
        let proof =
            generate_bge_proof(&mut stream(n as u64 * 100), &context, &ring, &secret, index)
                .unwrap();
        // m = ceil(log4(size)), at least one.
        let m = match size {
            ..=4 => 1,
            5..=16 => 2,
            _ => 3,
        };
        assert_eq!((proof.pk.len(), proof.f.len()), (m, m * 3), "size {size}");
        let ring_1div8: Vec<[u8; 32]> = ring.iter().map(div8).collect();
        assert!(
            verify_bge_proof(&context, &ring_1div8, &proof),
            "size {size}"
        );
        // Not over another context, nor another ring.
        assert!(!verify_bge_proof(&[8u8; 32], &ring_1div8, &proof));
        if size > 1 {
            let mut other = ring_1div8.clone();
            other.swap(0, size - 1);
            assert!(!verify_bge_proof(&context, &other, &proof));
        }
    }
}

/// `TEST(BGE_proof, negative)`: every way `invalidate_BGE_proof` breaks a
/// proof over thirteen members.
#[test]
fn bge_negative() {
    let context = [9u8; 32];
    let secret = scalar_from_u64(424242);
    let ring = bge_ring(13, 6, &secret);
    let good = generate_bge_proof(&mut stream(0), &context, &ring, &secret, 6).unwrap();
    let ring_1div8: Vec<[u8; 32]> = ring.iter().map(div8).collect();
    assert!(verify_bge_proof(&context, &ring_1div8, &good));
    let max = [0xff; 32];
    for case in 0..12 {
        let mut bad = good.clone();
        let last_pk = bad.pk.len() - 1;
        let last_f = bad.f.len() - 1;
        match case {
            0 => add_torsion(&mut bad.a),
            1 => add_torsion(&mut bad.b),
            2 => add_torsion(&mut bad.pk[0]),
            3 => add_torsion(&mut bad.pk[last_pk]),
            4 => bad.f[0] = [0; 32],
            5 => bad.f[0] = max,
            6 => bad.f[last_f] = [0; 32],
            7 => bad.f[last_f] = max,
            8 => bad.y = [0; 32],
            9 => bad.y = max,
            10 => bad.z = [0; 32],
            _ => bad.z = max,
        }
        assert!(
            !verify_bge_proof(&context, &ring_1div8, &bad),
            "case {case}"
        );
    }
}

/// Commitments `value * U + mask * G` times `1/8`, and a proof of them.
fn bpp(values: &[u64], seed: u64) -> (BppSignature, Vec<[u8; 32]>) {
    let masks: Vec<Scalar> = (0..values.len())
        .map(|i| scalar_from_u64(77 + 256 * 77 + i as u64))
        .collect();
    let commitments: Vec<[u8; 32]> = values
        .iter()
        .zip(&masks)
        .map(|(value, mask)| {
            div8(
                &generator_u()
                    .mul(&scalar_from_u64(*value))
                    .add(&EdwardsPoint::mul_base(mask)),
            )
        })
        .collect();
    let sig = generate_bpp(&mut stream(seed), values, &masks, &commitments).unwrap();
    (sig, commitments)
}

/// `TEST(bpp, basics)`: one value at the edges of the range. (The values
/// the reference refuses there are above `2^64`, which a `u64` cannot
/// hold.)
#[test]
fn bpp_basics() {
    for (n, value) in [0u64, 1, 5, u64::MAX].into_iter().enumerate() {
        let (sig, commitments) = bpp(&[value], n as u64);
        assert_eq!(sig.lv.len(), 6);
        assert!(verify_bpp(&sig, &commitments), "value {value}");
        // A commitment to another value does not verify.
        let (_, other) = bpp(&[value ^ 1], n as u64);
        assert!(!verify_bpp(&sig, &other));
    }
}

/// `TEST(bpp, two)`, its proof of three values (`{5, 700, 8}`), and one of
/// four: the aggregated proofs that zanolib got wrong.
#[test]
fn bpp_three_and_four_values() {
    for values in [&[5u64, 700, 8][..], &[u64::MAX, 0, 1, 1 << 63][..]] {
        let (sig, commitments) = bpp(values, 3);
        // Padded to four values of 64 bits: eight rounds.
        assert_eq!((sig.lv.len(), sig.rv.len()), (8, 8));
        assert!(verify_bpp(&sig, &commitments));
        // Not for fewer commitments, nor in another order, nor once touched.
        assert!(!verify_bpp(&sig, &commitments[..2]));
        let mut other = commitments.clone();
        other.swap(0, 1);
        assert!(!verify_bpp(&sig, &other));
        let mut bad = sig.clone();
        bad.delta[0] ^= 1;
        assert!(!verify_bpp(&bad, &commitments));
        let mut bad = sig.clone();
        add_torsion(&mut bad.lv[7]);
        assert!(!verify_bpp(&bad, &commitments));
    }
}

/// The ring signature of transparent inputs and the Schnorr signature of
/// asset owners: what is signed verifies, and nothing else does.
#[test]
fn ring_and_schnorr_signatures() {
    let secrets: Vec<Scalar> = (0..5).map(|i| scalar_from_u64(500 + i)).collect();
    let ring: Vec<[u8; 32]> = secrets
        .iter()
        .map(|s| EdwardsPoint::mul_base(s).compress())
        .collect();
    let m = [3u8; 32];
    for index in [0usize, 2, 4] {
        let secret = &secrets[index];
        let image = key_image(secret, &EdwardsPoint::mul_base(secret));
        let sig =
            generate_ring_signature(&mut stream(index as u64), &m, &ring, &image, secret, index)
                .unwrap();
        assert_eq!(sig.s.len(), 5);
        assert!(verify_ring_signature(&m, &ring, &image.compress(), &sig));
        assert!(!verify_ring_signature(
            &[4u8; 32],
            &ring,
            &image.compress(),
            &sig
        ));
        assert!(!verify_ring_signature(
            &m,
            &ring[..4],
            &image.compress(),
            &sig
        ));
        let other = key_image(&secrets[1], &EdwardsPoint::mul_base(&secrets[3]));
        assert!(!verify_ring_signature(&m, &ring, &other.compress(), &sig));
        let mut bad = sig.clone();
        bad.s[3][40] ^= 1;
        assert!(!verify_ring_signature(&m, &ring, &image.compress(), &bad));
        // A secret that is not the member's is refused.
        assert_eq!(
            generate_ring_signature(&mut stream(0), &m, &ring, &image, secret, (index + 1) % 5)
                .unwrap_err(),
            Error::SecretMismatch
        );
    }
    assert_eq!(
        generate_ring_signature(
            &mut stream(0),
            &m,
            &ring,
            &EdwardsPoint::identity(),
            &secrets[0],
            5
        )
        .unwrap_err(),
        Error::InvalidRing
    );

    let secret = scalar_from_u64(99);
    let public = EdwardsPoint::mul_base(&secret).compress();
    let sig = generate_schnorr_sig(&mut stream(1), &m, &secret);
    assert!(verify_schnorr_sig(&m, &public, &sig));
    assert!(!verify_schnorr_sig(&[4u8; 32], &public, &sig));
    assert!(!verify_schnorr_sig(&m, &ring[0], &sig));
    let mut bad = sig;
    bad.y[0] ^= 1;
    assert!(!verify_schnorr_sig(&m, &public, &bad));
}
