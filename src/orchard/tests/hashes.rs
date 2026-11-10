use super::{arr, bytes, vectors};
use crate::orchard::pallas::Point;
use crate::orchard::sinsemilla::{self, CommitDomain, HashDomain};
use crate::orchard::{Fp, Fq, constants, poseidon};

#[test]
fn fixed_bases_match_vectors() {
    let tvs = vectors(include_str!("../testdata/orchard_generators.json"));
    assert_eq!(tvs.len(), 1);
    let tv = &tvs[0];
    // skb, nkb, vcvb, vcrb, cmb, cmq, ivkb, ivkq, mcq
    let ours = [
        constants::SPEND_AUTH_G,
        constants::NULLIFIER_K,
        constants::VALUE_COMMIT_V,
        constants::VALUE_COMMIT_R,
        constants::NOTE_COMMIT_R,
        constants::NOTE_COMMIT_Q,
        constants::COMMIT_IVK_R,
        constants::COMMIT_IVK_Q,
        constants::MERKLE_CRH_Q,
    ];
    for (p, expected) in ours.iter().zip(tv) {
        assert!(bool::from(p.is_on_curve()));
        assert_eq!(p.to_bytes(), arr::<32>(expected));
    }
}

#[test]
fn fixed_bases_match_their_derivation() {
    let gh = |d: &[u8], m: &[u8]| constants::group_hash(d, m).to_affine();
    assert_eq!(constants::SPEND_AUTH_G, gh(b"z.cash:Orchard", b"G"));
    assert_eq!(constants::NULLIFIER_K, gh(b"z.cash:Orchard", b"K"));
    assert_eq!(constants::VALUE_COMMIT_V, gh(b"z.cash:Orchard-cv", b"v"));
    assert_eq!(constants::VALUE_COMMIT_R, gh(b"z.cash:Orchard-cv", b"r"));
    let note = CommitDomain::new(b"z.cash:Orchard-NoteCommit");
    assert_eq!(note.r(), constants::NOTE_COMMIT_R);
    assert_eq!(note.hash_domain().q(), constants::NOTE_COMMIT_Q);
    assert_eq!(CommitDomain::NOTE_COMMIT.r(), note.r());
    let ivk = CommitDomain::new(b"z.cash:Orchard-CommitIvk");
    assert_eq!(ivk.r(), constants::COMMIT_IVK_R);
    assert_eq!(ivk.hash_domain().q(), constants::COMMIT_IVK_Q);
    assert_eq!(
        HashDomain::new(b"z.cash:Orchard-MerkleCRH").q(),
        HashDomain::MERKLE_CRH.q()
    );
}

#[test]
fn sinsemilla_s_table_matches_its_derivation() {
    for (j, s) in constants::SINSEMILLA_S.iter().enumerate() {
        let expected = Point::hash_to_curve(b"z.cash:SinsemillaS", &(j as u32).to_le_bytes());
        assert_eq!(s.to_point(), expected, "S({j})");
        assert_eq!(sinsemilla::generator_s(j), Some(*s));
    }
    assert!(sinsemilla::generator_s(1024).is_none());
}

#[test]
fn sinsemilla_vectors() {
    let tvs = vectors(include_str!("../testdata/orchard_sinsemilla.json"));
    assert!(tvs.len() > 5);
    for tv in tvs {
        let domain = HashDomain::new(&bytes(&tv[0]));
        // the message is a list of bits, either as numbers or as bytes
        let msg: Vec<bool> = match tv[1].as_array() {
            Some(bits) => bits.iter().map(|b| b.as_u64().unwrap() == 1).collect(),
            None => bytes(&tv[1]).iter().map(|b| *b == 1).collect(),
        };
        let point = domain.hash_to_point(msg.iter().copied()).unwrap();
        assert_eq!(point.to_bytes(), arr::<32>(&tv[2]));
        let hash = domain.hash(msg.iter().copied()).unwrap();
        assert_eq!(hash.to_bytes(), arr::<32>(&tv[3]));
    }
}

#[test]
fn sinsemilla_limits_and_commit() {
    let domain = HashDomain::new(b"z.cash:test-Sinsemilla");
    // the empty message hashes to Q
    assert_eq!(
        domain.hash_to_point(core::iter::empty()),
        Some(domain.q().to_point())
    );
    let max = sinsemilla::K * sinsemilla::C;
    assert!(domain.hash((0..max).map(|i| i % 3 == 0)).is_some());
    assert!(domain.hash((0..max + 1).map(|i| i % 3 == 0)).is_none());
    // padding: trailing zero bits of the last chunk do not matter
    assert_eq!(
        domain.hash([true, false, true]),
        domain.hash([true, false, true, false, false])
    );
    assert_ne!(domain.hash([true, false, true]), domain.hash([true, false]));
    let commit = CommitDomain::new(b"z.cash:test-Sinsemilla");
    let r = Fq::from_u64(0x1234_5678);
    let msg = [
        true, true, false, true, false, false, true, true, true, false, true,
    ];
    let c = commit.commit(msg, &r).unwrap();
    let expected = commit.hash_domain().hash_to_point(msg).unwrap() + commit.r() * r;
    assert_eq!(c, expected);
    assert_eq!(commit.short_commit(msg, &r), Some(c.to_affine().x()));
    assert_eq!(
        sinsemilla::le_bits(&[0b0000_0101, 0xff], 10).collect::<Vec<_>>(),
        [
            true, false, true, false, false, false, false, false, true, true
        ]
    );
}

#[test]
#[allow(clippy::needless_range_loop)]
fn poseidon_constants_are_the_grain_output() {
    let (round_constants, mds, mds_inv) = poseidon::generate_constants();
    assert_eq!(round_constants, poseidon::ROUND_CONSTANTS);
    assert_eq!(mds, poseidon::MDS);
    for (i, row) in mds.iter().enumerate() {
        for j in 0..3 {
            let sum = row[0] * mds_inv[0][j] + row[1] * mds_inv[1][j] + row[2] * mds_inv[2][j];
            assert_eq!(sum, if i == j { Fp::ONE } else { Fp::ZERO });
        }
    }
}

#[test]
fn poseidon_permutation_vectors() {
    let tvs = vectors(include_str!("../testdata/orchard_poseidon.json"));
    assert!(tvs.len() > 5);
    for tv in tvs {
        let field = |v: &serde_json::Value| Fp::from_bytes(&arr(v)).unwrap();
        let input = tv[0].as_array().unwrap();
        let output = tv[1].as_array().unwrap();
        let mut state = [field(&input[0]), field(&input[1]), field(&input[2])];
        poseidon::permute(&mut state);
        for (s, expected) in state.iter().zip(output) {
            assert_eq!(s.to_bytes(), arr::<32>(expected));
        }
    }
}

#[test]
fn poseidon_hash_vectors() {
    let tvs = vectors(include_str!("../testdata/orchard_poseidon_hash.json"));
    assert!(tvs.len() > 5);
    for tv in tvs {
        let input = tv[0].as_array().unwrap();
        let a = Fp::from_bytes(&arr(&input[0])).unwrap();
        let b = Fp::from_bytes(&arr(&input[1])).unwrap();
        assert_eq!(poseidon::hash(a, b).to_bytes(), arr::<32>(&tv[1]));
    }
}
