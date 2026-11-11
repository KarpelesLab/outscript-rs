//! Tests for `cn_slow_hash` and the files of the reference wallet.
//!
//! - `testdata/monero_slow_hash.txt`: Monero's `tests/hash/tests-slow.txt`.
//! - `testdata/monero_extra_*.txt`: a selection of the lines of Monero's
//!   `tests/hash/tests-extra-*.txt` (every length up to 65 bytes, then some
//!   around the block sizes).

use super::super::slow_hash::{blake256, groestl256, jh256, skein512_256};
use super::super::*;

/// The lines of a vector file: the expected hash, then the input in hex
/// (`x` for none).
fn hash_vectors(text: &str) -> Vec<([u8; 32], Vec<u8>)> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut fields = line.split_whitespace();
            let expected = fields.next().unwrap();
            let input = fields.next().unwrap();
            let mut hash = [0u8; 32];
            hex::decode_to_slice(expected, &mut hash).unwrap();
            let input = if input == "x" {
                Vec::new()
            } else {
                hex::decode(input).unwrap()
            };
            (hash, input)
        })
        .collect()
}

#[test]
fn extra_hashes_match_monero_vectors() {
    type Hash = fn(&[u8]) -> [u8; 32];
    let sets: [(&str, Hash, &str); 4] = [
        (
            "blake",
            blake256,
            include_str!("../testdata/monero_extra_blake.txt"),
        ),
        (
            "groestl",
            groestl256,
            include_str!("../testdata/monero_extra_groestl.txt"),
        ),
        ("jh", jh256, include_str!("../testdata/monero_extra_jh.txt")),
        (
            "skein",
            skein512_256,
            include_str!("../testdata/monero_extra_skein.txt"),
        ),
    ];
    for (name, hash, text) in sets {
        let vectors = hash_vectors(text);
        assert_eq!(vectors.len(), 71);
        for (expected, input) in vectors {
            assert_eq!(hash(&input), expected, "{name} of {} bytes", input.len());
        }
    }
}

#[test]
fn slow_hash_matches_one_monero_vector() {
    let vectors = hash_vectors(include_str!("../testdata/monero_slow_hash.txt"));
    let (expected, input) = &vectors[0];
    assert_eq!(cn_slow_hash(input), *expected);
}

#[test]
#[ignore = "slow without optimizations"]
fn slow_hash_matches_monero_vectors() {
    let vectors = hash_vectors(include_str!("../testdata/monero_slow_hash.txt"));
    assert_eq!(vectors.len(), 4);
    for (expected, input) in vectors {
        assert_eq!(cn_slow_hash(&input), expected);
    }
}
