//! Tests for the CryptoNote primitives.
//!
//! The crypto vectors in `testdata/monero_crypto_tests.txt` are lines of
//! Monero's `tests/crypto/tests.txt` (the vectors the Go port
//! `KarpelesLab/zanolib` tests against too); the base58, address and varint
//! vectors are those of Monero's `tests/unit_tests/base58.cpp` and of
//! zanolib's `address_test.go`.

use super::*;

const VECTORS: &str = include_str!("testdata/monero_crypto_tests.txt");

fn h32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).unwrap_or_else(|e| panic!("bad hex {s:?}: {e}"));
    out
}

fn h64(s: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    hex::decode_to_slice(s, &mut out).unwrap_or_else(|e| panic!("bad hex {s:?}: {e}"));
    out
}

fn flag(s: &str) -> bool {
    match s {
        "true" => true,
        "false" => false,
        _ => panic!("bad bool {s:?}"),
    }
}

/// Runs every line of the vector file through the function it names.
#[test]
fn monero_crypto_vectors() {
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    for (n, line) in VECTORS.lines().enumerate() {
        let f: std::vec::Vec<&str> = line.split_whitespace().collect();
        let ctx = n + 1;
        *counts.entry(f[0]).or_default() += 1;
        match f[0] {
            "check_scalar" => {
                assert_eq!(sc_check(&h32(f[1])), flag(f[2]), "line {ctx}");
                assert_eq!(scalar_from_bytes(&h32(f[1])).is_ok(), flag(f[2]));
            }
            "hash_to_scalar" => {
                let data = if f[1] == "x" {
                    std::vec::Vec::new()
                } else {
                    hex::decode(f[1]).unwrap()
                };
                assert_eq!(hash_to_scalar(&data), h32(f[2]), "line {ctx}");
                // The same through the multi-part and streaming forms.
                let (a, b) = data.split_at(data.len() / 2);
                assert_eq!(hash_to_scalar_parts(&[a, b]), h32(f[2]), "line {ctx}");
                assert_eq!(scalar_from_hash(&[a, &[], b]).to_bytes(), h32(f[2]));
                let mut h = Hasher::new();
                for byte in &data {
                    h.update(&[*byte]);
                }
                assert_eq!(h.clone().finalize(), cn_fast_hash(&data), "line {ctx}");
                assert_eq!(h.finalize_scalar(), h32(f[2]), "line {ctx}");
            }
            "check_key" => {
                assert_eq!(check_key(&h32(f[1])), flag(f[2]), "line {ctx}");
            }
            "secret_key_to_public_key" => {
                let got = secret_key_to_public_key(&h32(f[1]));
                if flag(f[2]) {
                    assert_eq!(got, Ok(h32(f[3])), "line {ctx}");
                } else {
                    assert_eq!(got, Err(Error::InvalidScalar), "line {ctx}");
                }
            }
            "generate_key_derivation" => {
                let got = generate_key_derivation(&h32(f[1]), &h32(f[2]));
                if flag(f[3]) {
                    assert_eq!(got, Ok(h32(f[4])), "line {ctx}");
                } else {
                    assert_eq!(got, Err(Error::InvalidPoint), "line {ctx}");
                }
            }
            "derive_public_key" => {
                let index: u64 = f[2].parse().unwrap();
                let got = derive_public_key(&h32(f[1]), index, &h32(f[3]));
                if flag(f[4]) {
                    assert_eq!(got, Ok(h32(f[5])), "line {ctx}");
                } else {
                    assert_eq!(got, Err(Error::InvalidPoint), "line {ctx}");
                }
            }
            "derive_secret_key" => {
                let index: u64 = f[2].parse().unwrap();
                let got = derive_secret_key(&h32(f[1]), index, &h32(f[3])).unwrap();
                assert_eq!(*got, h32(f[4]), "line {ctx}");
                // It is the secret key of the derived public key.
                let base = secret_key_to_public_key(&h32(f[3])).unwrap();
                assert_eq!(
                    secret_key_to_public_key(&got),
                    derive_public_key(&h32(f[1]), index, &base),
                    "line {ctx}"
                );
            }
            "generate_signature" => {
                // prefix_hash, public, secret, signature. The reference drew
                // its nonce at random; recover it (k = r + c * secret) and
                // the signature must come out the same.
                let (hash, public, secret, sig) = (h32(f[1]), h32(f[2]), h32(f[3]), h64(f[4]));
                assert!(check_signature(&hash, &public, &sig), "line {ctx}");
                let c = scalar_from_bytes(&h32(&f[4][..64])).unwrap();
                let r = scalar_from_bytes(&h32(&f[4][64..])).unwrap();
                let k = r.add(&c.mul(&scalar_from_bytes(&secret).unwrap()));
                assert_eq!(
                    generate_signature(&hash, &public, &secret, &k.to_bytes()),
                    Ok(sig),
                    "line {ctx}"
                );
            }
            "check_signature" => {
                let got = check_signature(&h32(f[1]), &h32(f[2]), &h64(f[3]));
                assert_eq!(got, flag(f[4]), "line {ctx}");
            }
            "hash_to_point" => {
                assert_eq!(hash_to_point(&h32(f[1])), h32(f[2]), "line {ctx}");
            }
            // Named `hash_to_ec` before Monero grew an unbiased variant.
            "biased_hash_to_ec" => {
                assert_eq!(hash_to_ec(&h32(f[1])), h32(f[2]), "line {ctx}");
                let p = point_from_hash(&h32(f[1]));
                assert!(bool::from(p.is_torsion_free()), "line {ctx}");
            }
            "generate_key_image" => {
                let got = generate_key_image(&h32(f[1]), &h32(f[2]));
                assert_eq!(got, Ok(h32(f[3])), "line {ctx}");
            }
            other => panic!("line {ctx}: unknown vector {other:?}"),
        }
    }
    for name in [
        "check_scalar",
        "hash_to_scalar",
        "check_key",
        "secret_key_to_public_key",
        "generate_key_derivation",
        "derive_public_key",
        "derive_secret_key",
        "generate_signature",
        "check_signature",
        "hash_to_point",
        "biased_hash_to_ec",
        "generate_key_image",
    ] {
        assert!(counts.get(name).copied().unwrap_or(0) >= 16, "{name}");
    }
}

/// The map reads its input as a 256-bit integer, and always lands on the
/// curve.
#[test]
fn map_edge_cases() {
    for hash in [[0u8; 32], [1u8; 32], [0xffu8; 32], [0x80u8; 32]] {
        let p = map_to_point(&hash);
        assert_eq!(point_from_bytes(&p.compress()), Ok(p));
        assert_eq!(hash_to_point(&hash), p.compress());
    }
    let small = |n: u8| {
        let mut b = [0u8; 32];
        b[0] = n;
        b
    };
    // u = 0 gives the point of order two, (0, -1).
    let mut order_two = [0xffu8; 32];
    order_two[0] = 0xec;
    order_two[31] = 0x7f;
    assert_eq!(hash_to_point(&small(0)), order_two);
    assert_eq!(hash_to_ec(&[]).len(), 32);
    // p = 2^255 - 19 is 0.
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    assert_eq!(hash_to_point(&p), hash_to_point(&small(0)));
    // 2^255 is 19, and 2^256 - 1 is 37: the top bit counts.
    let mut top = [0u8; 32];
    top[31] = 0x80;
    assert_eq!(hash_to_point(&top), hash_to_point(&small(19)));
    assert_eq!(hash_to_point(&[0xff; 32]), hash_to_point(&small(37)));
    assert_ne!(hash_to_point(&top), hash_to_point(&small(0)));
}

#[test]
fn view_key_from_spend_key() {
    // spend secret, view secret, public spend key, public view key: computed
    // with zanolib's `LoadSpendSecret` (Go, filippo.io/edwards25519).
    let vectors = [
        (
            "0100000000000000000000000000000000000000000000000000000000000000",
            "06c0f15cce848179f575821411bac9878ec4f8e5bc173827ba75cb10a63a9605",
            "5866666666666666666666666666666666666666666666666666666666666666",
            "7db1402bcabb40ad2e2059b5671ad9503b2dcb52bb559e7f88c60889dde9037d",
        ),
        (
            "b2f420097cd63cdbdf834d090b1e604f08acf0af5a3827d0887863aaa4cc4406",
            "499132b37ecc51af6cd780a0ff5c4f7c0cebfd3877f6a1ff13482a5907b4a00b",
            "d764c19d6c14280315d81eb8f2fc777582941047918f52f8dcef8225e9c92c52",
            "8122b0910dbb19e09120fda0c73b092432cf565e570bec58d7ce12bef68cbe45",
        ),
        (
            "f264699c939208870fecebc013b773b793dd18ea39dbe1cb712a19a692fdb000",
            "411f14548bef6214634d83433d542443a051b9e1f63483123525b43ec2c85a04",
            "bcb483f075d37658b854d4b9968fafae976e5532ca99879479c85ef5da1deead",
            "0f7e1deb2d84262f9d6f7747fc40080c4ef55e8421b9cfdefa4715ba7b1b27bd",
        ),
    ];
    for (spend, view, spend_pub, view_pub) in vectors {
        let got = derive_view_secret_key(&h32(spend));
        assert_eq!(*got, h32(view));
        assert_eq!(secret_key_to_public_key(&h32(spend)), Ok(h32(spend_pub)));
        assert_eq!(secret_key_to_public_key(&got), Ok(h32(view_pub)));
    }
}

#[test]
fn signature_rejections() {
    let secret = h32("b2f420097cd63cdbdf834d090b1e604f08acf0af5a3827d0887863aaa4cc4406");
    let public = secret_key_to_public_key(&secret).unwrap();
    let hash = cn_fast_hash(b"message");
    let nonce = cn_fast_hash(b"nonce");
    let sig = generate_signature(&hash, &public, &secret, &nonce).unwrap();
    assert!(check_signature(&hash, &public, &sig));

    // Another message, another key, a flipped bit.
    assert!(!check_signature(&cn_fast_hash(b"other"), &public, &sig));
    let other = secret_key_to_public_key(&sc_reduce32(&nonce)).unwrap();
    assert!(!check_signature(&hash, &other, &sig));
    for i in [0, 31, 32, 63] {
        let mut bad = sig;
        bad[i] ^= 1;
        assert!(!check_signature(&hash, &public, &bad));
    }
    // Unreduced scalars, and c = 0.
    let mut bad = sig;
    bad[..32].copy_from_slice(&[0xff; 32]);
    assert!(!check_signature(&hash, &public, &bad));
    let mut bad = sig;
    bad[32..].copy_from_slice(&[0xff; 32]);
    assert!(!check_signature(&hash, &public, &bad));
    let mut bad = sig;
    bad[..32].copy_from_slice(&[0; 32]);
    assert!(!check_signature(&hash, &public, &bad));
    assert!(!check_signature(&hash, &[0xff; 32], &sig));

    // Signing refuses a wrong public key, an unreduced secret, a zero nonce.
    assert_eq!(
        generate_signature(&hash, &other, &secret, &nonce),
        Err(Error::KeyMismatch)
    );
    assert_eq!(
        generate_signature(&hash, &public, &[0xff; 32], &nonce),
        Err(Error::InvalidScalar)
    );
    assert_eq!(
        generate_signature(&hash, &public, &secret, &[0; 32]),
        Err(Error::InvalidNonce)
    );
    // An unreduced nonce is reduced.
    assert_eq!(
        generate_signature(&hash, &public, &secret, &sc_reduce32(&nonce)),
        Ok(sig)
    );
}

#[test]
fn scalar_helpers() {
    assert_eq!(scalar_from_u64(0), Scalar::ZERO);
    assert_eq!(scalar_from_u64(1), Scalar::ONE);
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(scalar_from_u64(u64::MAX).to_bytes(), b);
    // l itself reduces to zero, and is not a valid scalar.
    let l = h32("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    assert!(!sc_check(&l));
    assert_eq!(sc_reduce32(&l), [0u8; 32]);
    assert_eq!(scalar_from_bytes(&l), Err(Error::InvalidScalar));
    let mut l_minus_1 = l;
    l_minus_1[0] -= 1;
    assert!(sc_check(&l_minus_1));
    assert_eq!(sc_reduce32(&l_minus_1), l_minus_1);
    // derivation_to_scalar is Hs(derivation || varint(index)).
    let d = cn_fast_hash(b"derivation");
    let mut buf = d.to_vec();
    buf.extend_from_slice(&[0xac, 0x02]);
    assert_eq!(derivation_to_scalar(&d, 300), hash_to_scalar(&buf));
    assert_eq!(
        cn_fast_hash_parts(&[&d, &[0xac], &[0x02]]),
        cn_fast_hash(&buf)
    );
}

#[test]
fn varint_round_trip() {
    let cases: &[(u64, &[u8])] = &[
        (0, &[0x00]),
        (1, &[0x01]),
        (0x7f, &[0x7f]),
        (0x80, &[0x80, 0x01]),
        (0xff, &[0xff, 0x01]),
        (300, &[0xac, 0x02]),
        (0x3fff, &[0xff, 0x7f]),
        (0x4000, &[0x80, 0x80, 0x01]),
        (
            0x1122334455667788,
            &[0x88, 0xef, 0x99, 0xab, 0xc5, 0xe8, 0x8c, 0x91, 0x11],
        ),
        (
            u64::MAX,
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
        ),
    ];
    for &(value, bytes) in cases {
        let mut buf = [0u8; MAX_VARINT_LEN];
        let n = write_varint(value, &mut buf).unwrap();
        assert_eq!(&buf[..n], bytes, "{value}");
        assert_eq!(varint_len(value), bytes.len(), "{value}");
        assert_eq!(read_varint(bytes), Ok((value, bytes.len())), "{value}");
        // Trailing data is left alone, a short buffer is refused.
        let mut more = bytes.to_vec();
        more.push(0xff);
        assert_eq!(read_varint(&more), Ok((value, bytes.len())));
        assert_eq!(
            write_varint(value, &mut buf[..n - 1]),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(
            read_varint(&bytes[..bytes.len() - 1]),
            Err(Error::UnexpectedEof)
        );
        #[cfg(feature = "alloc")]
        {
            let mut v = std::vec![0xaa];
            push_varint(&mut v, value);
            assert_eq!(&v[1..], bytes);
        }
    }
    // Every power of two and its neighbours.
    for bit in 0..64 {
        for value in [(1u64 << bit) - 1, 1 << bit, (1 << bit) + 1] {
            let mut buf = [0u8; MAX_VARINT_LEN];
            let n = write_varint(value, &mut buf).unwrap();
            assert_eq!(n, varint_len(value));
            assert_eq!(read_varint(&buf[..n]), Ok((value, n)));
        }
    }
}

#[test]
fn varint_rejects_non_canonical() {
    assert_eq!(read_varint(&[]), Err(Error::UnexpectedEof));
    assert_eq!(read_varint(&[0x80]), Err(Error::UnexpectedEof));
    assert_eq!(read_varint(&[0xff; 9]), Err(Error::UnexpectedEof));
    // Padded encodings of 0, 1 and 0x80.
    assert_eq!(read_varint(&[0x80, 0x00]), Err(Error::NonCanonical));
    assert_eq!(read_varint(&[0x81, 0x00]), Err(Error::NonCanonical));
    assert_eq!(read_varint(&[0x80, 0x81, 0x00]), Err(Error::NonCanonical));
    assert_eq!(read_varint(&[0xff, 0x00, 0xff]), Err(Error::NonCanonical));
    // 2^64 and beyond.
    let mut over = [0xffu8; 10];
    over[9] = 0x02;
    assert_eq!(read_varint(&over), Err(Error::Overflow));
    over[9] = 0x7f;
    assert_eq!(read_varint(&over), Err(Error::Overflow));
    assert_eq!(read_varint(&[0xff; 10]), Err(Error::Overflow));
    assert_eq!(read_varint(&[0xff; 32]), Err(Error::Overflow));
    let mut zero_top = [0x80u8; 10];
    zero_top[9] = 0x00;
    assert_eq!(read_varint(&zero_top), Err(Error::NonCanonical));
}

/// The block vectors of Monero's `tests/unit_tests/base58.cpp`.
#[test]
fn base58_blocks() {
    let blocks: &[(&[u8], &str)] = &[
        (&[0x00], "11"),
        (&[0x39], "1z"),
        (&[0xff], "5Q"),
        (&[0x00, 0x00], "111"),
        (&[0x00, 0x39], "11z"),
        (&[0x01, 0x00], "15R"),
        (&[0xff, 0xff], "LUv"),
        (&[0x00, 0x00, 0x00], "11111"),
        (&[0x00, 0x00, 0x39], "1111z"),
        (&[0x01, 0x00, 0x00], "11LUw"),
        (&[0xff, 0xff, 0xff], "2UzHL"),
        (&[0x00, 0x00, 0x00, 0x39], "11111z"),
        (&[0xff, 0xff, 0xff, 0xff], "7YXq9G"),
        (&[0x00, 0x00, 0x00, 0x00, 0x39], "111111z"),
        (&[0xff, 0xff, 0xff, 0xff, 0xff], "VtB5VXc"),
        (&[0x00, 0x00, 0x00, 0x00, 0x00, 0x39], "11111111z"),
        (&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff], "3CUsUpv9t"),
        (&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x39], "111111111z"),
        (&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], "Ahg1opVcGW"),
        (
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x39],
            "1111111111z",
        ),
        (
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            "jpXCZedGfVQ",
        ),
        (
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "11111111111",
        ),
        (
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            "11111111112",
        ),
        (
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08],
            "11111111119",
        ),
        (
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09],
            "1111111111A",
        ),
        (
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a],
            "11111111121",
        ),
        (
            &[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            "1Ahg1opVcGW",
        ),
        (
            &[0x06, 0x15, 0x60, 0x13, 0x76, 0x28, 0x79, 0xf7],
            "22222222222",
        ),
        (
            &[0x05, 0xe0, 0x22, 0xba, 0x37, 0x4b, 0x2a, 0x00],
            "1z111111111",
        ),
        // Several blocks.
        (&[], ""),
        (&[0; 9], "1111111111111"),
        (&[0; 10], "11111111111111"),
        (&[0; 11], "1111111111111111"),
        (&[0; 12], "11111111111111111"),
        (&[0; 13], "111111111111111111"),
        (&[0; 14], "11111111111111111111"),
        (&[0; 15], "111111111111111111111"),
        (&[0; 16], "1111111111111111111111"),
        (
            &[
                0x06, 0x15, 0x60, 0x13, 0x76, 0x28, 0x79, 0xf7, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
            "22222222222VtB5VXc",
        ),
        (&[0xff; 9], "jpXCZedGfVQ5Q"),
        (&[0xff; 10], "jpXCZedGfVQLUv"),
        (&[0xff; 11], "jpXCZedGfVQ2UzHL"),
        (&[0xff; 12], "jpXCZedGfVQ7YXq9G"),
        (&[0xff; 13], "jpXCZedGfVQVtB5VXc"),
        (&[0xff; 14], "jpXCZedGfVQ3CUsUpv9t"),
        (&[0xff; 15], "jpXCZedGfVQAhg1opVcGW"),
        (&[0xff; 16], "jpXCZedGfVQjpXCZedGfVQ"),
    ];
    for &(data, text) in blocks {
        let mut enc = [0u8; 32];
        let n = base58::encode_to_slice(data, &mut enc).unwrap();
        assert_eq!(core::str::from_utf8(&enc[..n]), Ok(text));
        assert_eq!(base58::encoded_len(data.len()), text.len());
        assert_eq!(base58::decoded_len(text.len()), Some(data.len()));
        let mut dec = [0u8; 16];
        let n = base58::decode_to_slice(text, &mut dec).unwrap();
        assert_eq!(&dec[..n], data);
        // Exact buffers do, shorter ones do not.
        if !data.is_empty() {
            assert_eq!(
                base58::encode_to_slice(data, &mut enc[..text.len() - 1]),
                Err(Error::BufferTooSmall)
            );
            assert_eq!(
                base58::decode_to_slice(text, &mut dec[..data.len() - 1]),
                Err(Error::BufferTooSmall)
            );
        }
        #[cfg(feature = "alloc")]
        {
            assert_eq!(base58::encode(data), text);
            assert_eq!(base58::decode(text).as_deref(), Ok(data));
        }
    }
}

/// The negative vectors of Monero's `tests/unit_tests/base58.cpp`.
#[test]
fn base58_rejections() {
    let mut out = [0u8; 64];
    let invalid_length = [
        "1",
        "z",
        "1111",
        "zzzz",
        "11111111",
        "zzzzzzzz",
        "123456789AB1",
        "123456789ABz",
        "123456789AB1111",
        "123456789ABzzzz",
        "123456789AB11111111",
        "123456789ABzzzzzzzz",
    ];
    for text in invalid_length {
        assert_eq!(base58::decoded_len(text.len()), None, "{text}");
        assert_eq!(
            base58::decode_to_slice(text, &mut out),
            Err(Error::InvalidLength),
            "{text}"
        );
    }
    let overflow = [
        "5R",
        "zz",
        "LUw",
        "zzz",
        "2UzHM",
        "zzzzz",
        "7YXq9H",
        "zzzzzz",
        "VtB5VXd",
        "zzzzzzz",
        "3CUsUpv9u",
        "zzzzzzzzz",
        "Ahg1opVcGX",
        "zzzzzzzzzz",
        "jpXCZedGfVR",
        "zzzzzzzzzzz",
        "123456789AB5R",
        "123456789ABzz",
        "123456789ABLUw",
        "123456789ABzzz",
        "123456789AB2UzHM",
        "123456789ABzzzzz",
        "123456789AB7YXq9H",
        "123456789ABzzzzzz",
        "123456789ABVtB5VXd",
        "123456789ABzzzzzzz",
        "123456789AB3CUsUpv9u",
        "123456789ABzzzzzzzzz",
        "123456789ABAhg1opVcGX",
        "123456789ABzzzzzzzzzz",
        "123456789ABjpXCZedGfVR",
        "123456789ABzzzzzzzzzzz",
        "zzzzzzzzzzz11",
    ];
    for text in overflow {
        assert_eq!(
            base58::decode_to_slice(text, &mut out),
            Err(Error::Overflow),
            "{text}"
        );
    }
    let invalid_character = [
        "10",
        "11I",
        "11O11",
        "11l111",
        "11_11111111",
        "1101111111111",
        "11I11111111111111",
        "11O1111111111111111111",
        "1111111111110",
        "111111111111l1111",
        "111111111111_111111111",
        "01111111111",
        "11111111110",
        "11111011111",
        "I1111111111",
        "O1111111111",
        "l1111111111",
        "_1111111111",
        "1\u{e9}",
        "\u{20ac}",
    ];
    for text in invalid_character {
        assert_eq!(
            base58::decode_to_slice(text, &mut out),
            Err(Error::InvalidCharacter),
            "{text}"
        );
    }
    #[cfg(feature = "alloc")]
    {
        assert_eq!(base58::decode("1"), Err(Error::InvalidLength));
        assert_eq!(base58::decode("zz"), Err(Error::Overflow));
        assert_eq!(base58::decode("10"), Err(Error::InvalidCharacter));
    }
}

/// Every alphabet character decodes to its index, and nothing else decodes.
#[test]
fn base58_alphabet() {
    let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    assert_eq!(alphabet.len(), 58);
    let mut out = [0u8; 1];
    for c in 0u8..128 {
        let text = [b'1', c];
        let text = core::str::from_utf8(&text).unwrap();
        let got = base58::decode_to_slice(text, &mut out);
        match alphabet.bytes().position(|a| a == c) {
            Some(i) => assert_eq!((got, out[0]), (Ok(1), i as u8), "{c}"),
            None => assert_eq!(got, Err(Error::InvalidCharacter), "{c}"),
        }
    }
}

fn check_address(address: &str, prefix: u64, payload: &[u8]) {
    let mut enc = [0u8; 160];
    let n = encode_address_to_slice(prefix, payload, &mut enc).unwrap();
    assert_eq!(core::str::from_utf8(&enc[..n]), Ok(address));
    assert_eq!(address_encoded_len(prefix, payload.len()), address.len());
    assert_eq!(
        encode_address_to_slice(prefix, payload, &mut enc[..n - 1]),
        Err(Error::BufferTooSmall)
    );

    let need = address_decoded_len(address.len()).unwrap();
    let mut dec = [0u8; 128];
    let (got_prefix, len) = decode_address_to_slice(address, &mut dec[..need]).unwrap();
    assert_eq!((got_prefix, &dec[..len]), (prefix, payload), "{address}");
    assert_eq!(
        decode_address_to_slice(address, &mut dec[..need - 1]),
        Err(Error::BufferTooSmall)
    );

    #[cfg(feature = "alloc")]
    {
        assert_eq!(encode_address(prefix, payload), address);
        assert_eq!(decode_address(address), Ok((prefix, payload.to_vec())));
    }
}

/// The address vectors of Monero's `tests/unit_tests/base58.cpp`.
#[test]
fn monero_addresses() {
    let pattern: std::vec::Vec<u8> = (0..64u8).map(|i| (i % 16) * 0x11).collect();
    let big = 0x1122334455667788;
    let cases: &[(&str, u64, &[u8])] = &[
        (
            "21D35quxec71111111111111111111111111111111111111111111111111111111111111111111111111111116Q5tCH",
            6,
            &[0x00; 64],
        ),
        (
            "2Aui6ejTFscjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQVqegMoV",
            6,
            &[0xff; 64],
        ),
        (
            "1119XrkPuSmLzdHXgVgrZKjepg5hZAxffLzdHXgVgrZKjepg5hZAxffLzdHXgVgrZKjepg5hZAxffLzdHXgVgrZKVphZRvn",
            0,
            &pattern,
        ),
        (
            "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115TXfiA",
            0,
            &[0x00; 64],
        ),
        (
            "PuT7GAdgbA83qvSEivPLYo11111111111111111111111111111111111111111111111111111111111111111111111111111169tWrH",
            big,
            &[0x00; 64],
        ),
        (
            "PuT7GAdgbA841d7FXjswpJjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQVq4LL1v",
            big,
            &[0xff; 64],
        ),
        ("PuT7GAdgbA819VwdWVDP", big, &[0x11]),
        ("PuT7GAdgbA81efAfdCjPg", big, &[0x22; 2]),
        ("PuT7GAdgbA83sryEt3YC8Q", big, &[0x33; 3]),
        ("PuT7GAdgbA83tWUuc54PFP3b", big, &[0x44; 4]),
        ("PuT7GAdgbA83u9zaKrtRKZ1J6", big, &[0x55; 5]),
        ("PuT7GAdgbA83uoWF3eanGG1aRoG", big, &[0x66; 6]),
        ("PuT7GAdgbA83vT1umSHMYJ4oNVdu", big, &[0x77; 7]),
        ("PuT7GAdgbA83w6XaVDyvpoGQBEWbB", big, &[0x88; 8]),
        ("PuT7GAdgbA83wk3FD1gW7J2KVGofA1r", big, &[0x99; 9]),
        ("15p2yAV", 0, &[]),
        ("FNQ3D6A", 0x7f, &[]),
        ("26k9QWweu", 0x80, &[]),
        ("3BzAD7n3y", 0xff, &[]),
        (
            "11efCaY6UjG7JrxuB",
            0,
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
        ),
        (
            "21rhHRT48LN4PriP9",
            6,
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
        ),
    ];
    for &(address, prefix, payload) in cases {
        check_address(address, prefix, payload);
    }

    // A mainnet address (prefix 18) and the keys it holds.
    let keys = hex::decode(
        "f724bc5c6cfbb9d97602c300423a2f28641874513a035778a0c1778d833201e9\
         220939689edf1abd5bc1d031f73ecd6c993add66d6808870456afeb8e7eeb68d",
    )
    .unwrap();
    check_address(
        "4AzKEX4gXdJdNeM6dfiBFL7kqund3HYGvMBF3ttsNd9SfzgYB6L7ep1Yg1osYJzLdaKAYSLVh6e6jKnAuzj3bw1oGy9kXCb",
        18,
        &keys,
    );
}

/// The negative address vectors of Monero's `tests/unit_tests/base58.cpp`.
#[test]
fn address_rejections() {
    let mut out = [0u8; 64];
    let cases = [
        ("zuT7GAdgbA819VwdWVDP", Error::Overflow),
        ("0uT7GAdgbA819VwdWVDP", Error::InvalidCharacter),
        ("IuT7GAdgbA819VwdWVDP", Error::InvalidCharacter),
        ("OuT7GAdgbA819VwdWVDP", Error::InvalidCharacter),
        ("luT7GAdgbA819VwdWVDP", Error::InvalidCharacter),
        ("\0uT7GAdgbA819VwdWVDP", Error::InvalidCharacter),
        ("PuT7GAdgbA819VwdWVD", Error::InvalidLength),
        ("11efCaY6UjG7JrxuC", Error::BadChecksum),
        // ff 00 ff ff, with a valid checksum: a padded varint.
        ("jerj2e4mESo", Error::NonCanonical),
        ("1", Error::InvalidLength),
        ("1111", Error::InvalidLength),
        ("", Error::InvalidLength),
        ("11", Error::InvalidLength),
        ("111", Error::InvalidLength),
        ("11111", Error::InvalidLength),
        ("111111", Error::InvalidLength),
        ("999999", Error::Overflow),
        ("ZZZZZZ", Error::Overflow),
    ];
    for (address, error) in cases {
        assert_eq!(
            decode_address_to_slice(address, &mut out),
            Err(error),
            "{address:?}"
        );
        #[cfg(feature = "alloc")]
        assert_eq!(decode_address(address), Err(error), "{address:?}");
    }
    // A prefix that runs into the checksum: 80 80 80 80, checksummed.
    let body = [0x80u8; 4];
    let sum = cn_fast_hash(&body);
    let mut data = [0u8; 8];
    data[..4].copy_from_slice(&body);
    data[4..].copy_from_slice(&sum[..4]);
    let mut text = [0u8; 11];
    base58::encode_to_slice(&data, &mut text).unwrap();
    assert_eq!(
        decode_address_to_slice(core::str::from_utf8(&text).unwrap(), &mut out),
        Err(Error::UnexpectedEof)
    );
}

/// The address vectors of zanolib's `address_test.go`: the prefix is the
/// address type, the payload the two keys, then the flags and payment id of
/// the types that have them.
#[test]
fn zano_addresses() {
    let keys = "9f5e1fa93630d4b281b18bb67a3db79e9622fc703cc3ad4a453a82e0a36d51fa\
                a3f208c8f9ba49bab28eed62b35b0f6be0a297bcd85c2faa1eb1820527bcf7e3";
    let cases = [
        (
            "ZxD5aoLDPTdcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp338Se7AxeH",
            0xc5,
            "",
        ),
        (
            "iZ2Zi6RmTWwcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp3iTqEsjvJoco1aLSZXS6T",
            0x3678,
            "87440d0b9acc42f1",
        ),
        (
            "ZxD5aoLDPTdcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp3APrDvRoL5C",
            0xc5,
            "fe",
        ),
        (
            "iZ4mBxubNfqcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp3iTrG7nU5rRCWmcozLaMoY95sAbo6",
            0x36f8,
            "fe3ba0527bcfb1fa93630d28eed6",
        ),
        (
            "aZxb9Et6FhP9AinRwcPqSqBKjckre7PgoZjK3q5YG2fUKHYWFZMWjB6YAEAdw4yDDUGEQ7CGEgbqhGRKeadGV1jLYcEJMEmqQFn",
            0x98c8,
            "01",
        ),
        (
            "aiZXDondHWu9AinRwcPqSqBKjckre7PgoZjK3q5YG2fUKHYWFZMWjB6YAEAdw4yDDUGEQ7CGEgbqhGRKeadGV1jLYcEJM9xJH8EbjuRiMJgFmPRATsEV9",
            0x8a49,
            "013ba0527bcfb1fa93630d28eed6",
        ),
    ];
    for (address, prefix, tail) in cases {
        let mut payload = hex::decode(keys).unwrap();
        payload.extend(hex::decode(tail).unwrap());
        check_address(address, prefix, &payload);
    }
}

#[test]
fn error_conversion() {
    assert_eq!(
        crate::Error::from(Error::BufferTooSmall),
        crate::Error::BufferTooSmall
    );
    assert_eq!(
        crate::Error::from(Error::BadChecksum),
        crate::Error::CryptoNote(Error::BadChecksum)
    );
    assert_eq!(
        std::format!("{}", crate::Error::from(Error::InvalidPoint)),
        "invalid curve point"
    );
}
