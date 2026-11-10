//! Tests of the wallet-side helpers: weights and fees, decoy selection.
//!
//! - `testdata/wallet2_fees.txt`: what the reference wallet's own functions
//!   give, compiled as they are.
//! - The statistics of the decoy picker are those of the reference wallet's
//!   `gamma_picker`, compiled as it is and run over the same distribution
//!   of outputs.

use std::vec::Vec;

use super::super::decoys as math;
use super::with_alloc::mainnet_txs;
use super::*;

/// The reference wallet's size, weight and fee estimates.
#[test]
fn wallet2_fee_estimates() {
    let (mut estimates, mut clawbacks) = (0, 0);
    for line in include_str!("../testdata/wallet2_fees.txt").lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let n = |i: usize| f[i].parse::<u64>().unwrap();
        match f[0] {
            "est" => {
                let (inputs, ring, outputs, extra) =
                    (n(1) as usize, n(2) as usize, n(3) as usize, n(4) as usize);
                assert_eq!(
                    estimate_tx_size(inputs, ring, outputs, extra),
                    n(5),
                    "{line}"
                );
                assert_eq!(
                    estimate_tx_weight(inputs, ring, outputs, extra),
                    n(6),
                    "{line}"
                );
                for (fee_per_byte, expected) in [20000u64, 7870, 80000, 123457].iter().zip(&f[7..])
                {
                    let expected: u64 = expected.parse().unwrap();
                    assert_eq!(
                        calculate_fee_from_weight(*fee_per_byte, n(6), FEE_QUANTIZATION_MASK),
                        Some(expected),
                        "{line}"
                    );
                    assert_eq!(
                        estimate_fee(*fee_per_byte, 10_000, inputs, ring, outputs, extra),
                        Some(expected),
                        "{line}"
                    );
                }
                estimates += 1;
            }
            "clawback" => {
                assert_eq!(
                    super::super::fee::weight_clawback(n(2), n(1) == 1),
                    n(3),
                    "{line}"
                );
                clawbacks += 1;
            }
            _ => assert!(line.starts_with('#'), "{line}"),
        }
    }
    assert_eq!((estimates, clawbacks), (180, 10));

    // The edges: no mask, and fees that do not fit.
    assert_eq!(calculate_fee_from_weight(20_000, 1_500, 0), None);
    assert_eq!(calculate_fee_from_weight(u64::MAX, 2, 1), None);
    assert_eq!(calculate_fee_from_weight(u64::MAX, 1, 10_000), None);
    assert_eq!(calculate_fee_from_weight(0, 1_500, 10_000), Some(0));
    assert_eq!(calculate_fee_from_weight(7, 3, 1), Some(21));
    assert_eq!(estimate_fee(1, 0, 1, 16, 2, 0), None);
    // Sizes that do not fit saturate instead of wrapping.
    assert_eq!(estimate_tx_size(usize::MAX, usize::MAX, 2, 0), u64::MAX);
    assert_eq!(estimate_tx_weight(1, 16, usize::MAX, usize::MAX), u64::MAX);
    assert_eq!(RING_SIZE, 16);
}

/// The weight of real transactions, and the fee they paid: what the
/// reference wallet's estimate gives at a round fee per byte.
#[test]
fn mainnet_weights_and_fees() {
    let txs = mainnet_txs();
    let mut plus = 0;
    for (name, real) in &txs {
        let tx = Transaction::parse(&real.bytes).unwrap();
        let size = real.bytes.len() as u64;
        let outputs = tx.prefix.outputs.len();
        let weight = tx.weight();
        // Only an aggregated proof over more than two outputs adds weight.
        if tx.rct.rct_type >= RCT_TYPE_BULLETPROOF && outputs > 2 {
            assert!(weight > size, "{name}");
        } else {
            assert_eq!(weight, size, "{name}");
        }
        if tx.rct.rct_type != RCT_TYPE_BULLETPROOF_PLUS {
            continue;
        }
        plus += 1;
        // The estimate is within a few bytes per input and output of the
        // real size and weight (it counts every key offset as two bytes
        // and every amount as six), and has the same clawback.
        let inputs = tx.prefix.inputs.len();
        let ring_size = tx.prefix.inputs[0].ring_size();
        assert_eq!(ring_size, RING_SIZE);
        let extra = tx.prefix.extra.len();
        let estimate = estimate_tx_weight(inputs, ring_size, outputs, extra);
        let slack = 20 + 20 * inputs as u64 + 5 * outputs as u64;
        assert!(estimate.abs_diff(weight) < slack, "{name}");
        assert_eq!(
            estimate - estimate_tx_size(inputs, ring_size, outputs, extra),
            weight - size,
            "{name}"
        );
        // The fee the transaction paid is the reference wallet's for its
        // weight — clawback included — at a round fee per byte.
        let fee = tx.rct.fee;
        let per_byte = fee / weight;
        assert_eq!(per_byte % 10_000, 0, "{name}: {fee} {weight}");
        assert_eq!(
            calculate_fee_from_weight(per_byte, weight, FEE_QUANTIZATION_MASK),
            Some(fee),
            "{name}"
        );
    }
    assert_eq!(plus, 5);

    // The original Bulletproofs have their own clawback. The transactions
    // of late 2018 in the fixtures, of 2 to 16 outputs and all within a
    // few hundred blocks, paid the same fee per unit of weight (it moved
    // with the block reward only), though from 24 to 48 thousand per byte.
    let rate = |name: &str| {
        let tx = Transaction::parse(&txs[name].bytes).unwrap();
        assert_eq!(tx.rct.rct_type, RCT_TYPE_BULLETPROOF);
        (
            tx.rct.fee as f64 / tx.weight() as f64,
            tx.prefix.outputs.len(),
        )
    };
    let (base, _) = rate("rct3");
    let mut sizes = Vec::new();
    for name in [
        "rct3_donation",
        "rct3_1in_3out",
        "rct3_1in_8out",
        "rct3_1in_16out",
    ] {
        let (per_weight, outputs) = rate(name);
        assert!(
            (per_weight / base - 1.0).abs() < 0.005,
            "{name}: {per_weight}"
        );
        sizes.push(outputs);
    }
    assert_eq!(sizes, [2, 3, 8, 16]);
}

/// The logarithm, exponential and square root in software against the
/// standard library's.
#[test]
fn soft_float_functions() {
    let close = |a: f64, b: f64| (a - b).abs() <= 4e-15 * b.abs().max(1e-300);
    let mut x = 1e-12f64;
    while x < 1e18 {
        assert!(
            (math::ln(x) - x.ln()).abs() < 1e-14 * x.ln().abs().max(1.0),
            "ln {x}"
        );
        assert!(close(math::sqrt(x), x.sqrt()), "sqrt {x}");
        x *= 1.0371;
    }
    let mut x = -60.0f64;
    while x < 60.0 {
        assert!(close(math::exp(x), x.exp()), "exp {x}");
        x += 0.0137;
    }
    for x in [
        1.0f64,
        2.0,
        0.5,
        4.0,
        core::f64::consts::E,
        1200.0,
        1e-300,
        1e300,
    ] {
        assert!(close(math::sqrt(x), x.sqrt()), "sqrt {x}");
        assert!((math::ln(x) - x.ln()).abs() < 1e-13, "ln {x}");
    }
    assert_eq!(math::ln(1.0), 0.0);
    assert_eq!(math::exp(0.0), 1.0);
    assert_eq!(math::sqrt(4.0), 2.0);
    // Outside their domains: no panic, no NaN from the square root.
    assert_eq!(math::sqrt(-1.0), 0.0);
    assert_eq!(math::sqrt(0.0), 0.0);
    assert_eq!(math::ln(0.0), f64::NEG_INFINITY);
    assert_eq!(math::ln(-1.0), f64::NEG_INFINITY);
    assert!(math::exp(1e9).is_finite() && math::exp(-1e9) >= 0.0);
    assert!(math::exp(f64::NAN).is_nan());
}

/// A fast random source for the statistics (splitmix64).
fn stat_rng(seed: u64) -> impl FnMut(&mut [u8]) {
    let mut state = seed;
    move |out: &mut [u8]| {
        for chunk in out.chunks_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
        }
    }
}

/// The normal and gamma variates have the moments of their distributions:
/// mean 0 and variance 1; mean `shape * scale` and variance
/// `shape * scale^2`.
#[test]
fn sampler_moments() {
    let mut rng = stat_rng(1);
    let n = 40_000usize;
    let moments = |values: &[f64]| {
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let variance =
            values.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / values.len() as f64;
        (mean, variance)
    };
    let normals: Vec<f64> = (0..n)
        .map(|_| math::random_normal(&mut rng).unwrap())
        .collect();
    let (mean, variance) = moments(&normals);
    assert!(mean.abs() < 0.03, "{mean}");
    assert!((variance - 1.0).abs() < 0.05, "{variance}");

    let (shape, scale) = (19.28, 1.0 / 1.61);
    let gammas: Vec<f64> = (0..n)
        .map(|_| math::random_gamma(&mut rng, shape, scale).unwrap())
        .collect();
    let (mean, variance) = moments(&gammas);
    assert!((mean - shape * scale).abs() < 0.07, "{mean}");
    assert!((variance - shape * scale * scale).abs() < 0.4, "{variance}");
    assert!(gammas.iter().all(|g| *g > 0.0));

    // A stuck source is noticed rather than looped on.
    for byte in [0u8, 0xff] {
        let mut stuck = |out: &mut [u8]| out.fill(byte);
        assert_eq!(math::random_normal(&mut stuck), Err(Error::BadRandomness));
        assert_eq!(
            math::random_gamma(&mut stuck, shape, scale),
            Err(Error::BadRandomness)
        );
    }
}

/// The picks over a chain of 300 000 blocks of 20 outputs each are
/// distributed as those of the reference wallet's `gamma_picker` over the
/// same chain (four million picks of it: the share of picks that fail, and
/// of picks younger than a number of outputs).
#[test]
fn decoy_picker_distribution() {
    let distribution: Vec<u64> = (1..=300_000u64).map(|block| block * 20).collect();
    let picker = DecoyPicker::new(&distribution).unwrap();
    let num_outputs = picker.num_outputs();
    assert_eq!(num_outputs, 20 * (300_000 - 9));

    let reference = [
        (100u64, 0.019571),
        (1_000, 0.120498),
        (10_000, 0.388470),
        (100_000, 0.707659),
        (1_000_000, 0.901528),
        (3_000_000, 0.947432),
    ];
    let reference_bad = 0.034261;

    let mut rng = stat_rng(2);
    let n = 30_000usize;
    let mut bad = 0usize;
    let mut younger = [0usize; 6];
    for _ in 0..n {
        match picker.pick(&mut rng).unwrap() {
            None => bad += 1,
            Some(index) => {
                assert!(index < num_outputs);
                let age = num_outputs - 1 - index;
                for (count, (limit, _)) in younger.iter_mut().zip(&reference) {
                    if age < *limit {
                        *count += 1;
                    }
                }
            }
        }
    }
    // Five standard deviations of a share of 30 000 picks is under 0.015.
    let share = |count: usize| count as f64 / n as f64;
    assert!((share(bad) - reference_bad).abs() < 0.015, "{bad}");
    for (count, (limit, expected)) in younger.iter().zip(&reference) {
        assert!((share(*count) - expected).abs() < 0.015, "{limit}: {count}");
    }
}

#[test]
fn decoy_picker_edges() {
    // Too short, not cumulative, or without spendable outputs.
    assert_eq!(DecoyPicker::new(&[]).unwrap_err(), Error::InvalidRing);
    assert_eq!(DecoyPicker::new(&[5; 10]).unwrap_err(), Error::InvalidRing);
    assert!(DecoyPicker::new(&[5; 11]).is_ok());
    let mut bad: Vec<u64> = (1..=20).collect();
    bad[7] = 3;
    assert_eq!(DecoyPicker::new(&bad).unwrap_err(), Error::InvalidRing);
    assert_eq!(DecoyPicker::new(&[0; 20]).unwrap_err(), Error::InvalidRing);
    // Outputs in the last nine blocks only: none can be spent.
    let mut young = std::vec![0u64; 20];
    young[19] = 7;
    assert_eq!(DecoyPicker::new(&young).unwrap_err(), Error::InvalidRing);

    // A chain with empty blocks: picks never land in them.
    let mut rng = stat_rng(3);
    let distribution: Vec<u64> = (0..2000u64).map(|block| (block / 4 + 1) * 8).collect();
    let picker = DecoyPicker::new(&distribution).unwrap();
    assert_eq!(picker.num_outputs(), distribution[2000 - 10]);
    for _ in 0..2000 {
        if let Some(index) = picker.pick(&mut rng).unwrap() {
            assert!(index < picker.num_outputs());
        }
    }

    // The number of candidates the reference wallet asks for.
    assert_eq!(DecoyPicker::candidate_count(16), 75);
    assert_eq!(DecoyPicker::candidate_count(11), 67);
    assert!(DecoyPicker::candidate_count(usize::MAX) > usize::MAX / 2);

    // Candidates: the real one first, all distinct, all spendable.
    let count = DecoyPicker::candidate_count(RING_SIZE);
    for real in [0u64, 2000, picker.num_outputs() - 1] {
        let candidates = picker.select_candidates(real, count, &mut rng).unwrap();
        assert_eq!(candidates.len(), count);
        assert_eq!(candidates[0], real);
        let mut sorted = candidates.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), count);
        assert!(sorted.iter().all(|index| *index < picker.num_outputs()));
    }
    assert_eq!(
        picker.select_candidates(picker.num_outputs(), count, &mut rng),
        Err(Error::InvalidRing)
    );
    // A chain with fewer outputs than asked for gives them all.
    let tiny: Vec<u64> = (1..=30u64).collect();
    let picker = DecoyPicker::new(&tiny).unwrap();
    assert_eq!(picker.num_outputs(), 21);
    let all = picker.select_candidates(5, 40, &mut rng).unwrap();
    assert_eq!(all.len(), 21);
    assert_eq!(all[0], 5);
    let mut sorted = all.clone();
    sorted.sort();
    assert_eq!(sorted, (0..21).collect::<Vec<u64>>());
    // And one with barely more is still gone through to the end.
    let some = picker.select_candidates(5, 12, &mut rng).unwrap();
    assert_eq!(some.len(), 12);

    // A stuck random source.
    let mut stuck = |out: &mut [u8]| out.fill(0);
    assert_eq!(picker.pick(&mut stuck), Err(Error::BadRandomness));
    assert_eq!(
        picker.select_candidates(5, 10, &mut stuck),
        Err(Error::BadRandomness)
    );
}

#[test]
fn ring_from_candidates() {
    let member = |index: u64| RingMember {
        key: crate::cryptonote::hash_to_ec(&index.to_le_bytes()),
        commitment: crate::cryptonote::hash_to_ec(&(!index).to_le_bytes()),
    };
    let candidate = |index: u64| DecoyCandidate {
        global_index: index,
        member: member(index),
        unlocked: true,
    };
    let real_index = 500u64;
    let real = member(real_index);
    // In picking order: the real one, then decoys.
    let order = [500u64, 900, 20, 700, 300, 100, 800];
    let candidates: Vec<DecoyCandidate> = order.iter().map(|index| candidate(*index)).collect();

    let (ring, indices, position) = build_ring(real_index, &real, &candidates, 4).unwrap();
    // The first three decoys picked, sorted with the real one.
    assert_eq!(indices, [20, 500, 700, 900]);
    assert_eq!(position, 1);
    assert_eq!(ring[position], real);
    for (index, entry) in indices.iter().zip(&ring) {
        assert_eq!(*entry, member(*index));
    }
    assert_eq!(relative_offsets(&indices).unwrap(), [20, 480, 200, 200]);

    // Locked, repeated and invalid candidates are passed over.
    let mut some = candidates.clone();
    some[1].unlocked = false;
    some[2] = some[3];
    // A point of order 8 as the key, a point with torsion as the commitment.
    let torsion = h32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");
    some[4].member.key = torsion;
    let mixed = EdwardsPoint::decompress(&some[5].member.commitment)
        .unwrap()
        .add(&EdwardsPoint::decompress(&torsion).unwrap());
    some[5].member.commitment = mixed.compress();
    let (_, indices, position) = build_ring(real_index, &real, &some, 3).unwrap();
    assert_eq!(indices, [500, 700, 800]);
    assert_eq!(position, 0);
    assert_eq!(
        build_ring(real_index, &real, &some, 4).unwrap_err(),
        Error::InvalidRing
    );
    some[6].member.key = [0xff; 32];
    assert_eq!(
        build_ring(real_index, &real, &some, 3).unwrap_err(),
        Error::InvalidRing
    );

    // A ring of one: the real output alone.
    let (ring, indices, position) = build_ring(real_index, &real, &candidates, 1).unwrap();
    assert_eq!(
        (ring.len(), indices.as_slice(), position),
        (1, &[500u64][..], 0)
    );
    // All of them.
    let (_, indices, position) = build_ring(real_index, &real, &candidates, 7).unwrap();
    assert_eq!(indices, [20, 100, 300, 500, 700, 800, 900]);
    assert_eq!(position, 3);
    assert_eq!(
        build_ring(real_index, &real, &candidates, 8).unwrap_err(),
        Error::InvalidRing
    );
    assert_eq!(
        build_ring(real_index, &real, &candidates, 0).unwrap_err(),
        Error::InvalidRing
    );

    // The daemon's entry for the real output must be there and be right.
    assert_eq!(
        build_ring(real_index, &real, &candidates[1..], 3).unwrap_err(),
        Error::KeyMismatch
    );
    let mut lying = candidates.clone();
    lying[0].member.commitment = lying[1].member.commitment;
    assert_eq!(
        build_ring(real_index, &real, &lying, 3).unwrap_err(),
        Error::KeyMismatch
    );
    let mut lying = candidates.clone();
    lying[0].unlocked = false;
    assert_eq!(
        build_ring(real_index, &real, &lying, 3).unwrap_err(),
        Error::KeyMismatch
    );
}
