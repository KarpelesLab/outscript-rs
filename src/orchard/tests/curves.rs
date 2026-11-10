use super::{arr, bytes, vectors};
use crate::orchard::{Fp, Fq, pallas, vesta};

#[test]
fn swu_constants() {
    // theta is sqrt(Z / ROOT_OF_UNITY), as map_to_curve_simple_swu assumes
    let theta = Fp::from_raw([
        0xca33_0bcc_09ac_318e,
        0x51f6_4fc4_dc88_8857,
        0x4647_aef7_82d5_cdc8,
        0x0f7b_db65_8141_79b4,
    ]);
    assert_eq!(theta.square() * Fp::ROOT_OF_UNITY, -Fp::from_u64(13));
    let theta = Fq::from_raw([
        0x632c_ae98_72df_1b5d,
        0x3857_8cca_df03_ac27,
        0x53c3_808d_9e2f_2357,
        0x2b34_83a1_ee9a_382f,
    ]);
    assert_eq!(theta.square() * Fq::ROOT_OF_UNITY, -Fq::from_u64(13));
}

macro_rules! curve_tests {
    ($name:ident, $m:ident) => {
        #[test]
        fn $name() {
            use $m::{Affine, Point, Scalar};
            let g = Point::GENERATOR;
            assert!(bool::from(Affine::GENERATOR.is_on_curve()));
            assert!(bool::from(Affine::IDENTITY.is_on_curve()));
            assert!(Affine::from_xy(Affine::GENERATOR.x(), Affine::GENERATOR.y()).is_some());
            assert!(Affine::from_xy(Affine::GENERATOR.x(), Affine::GENERATOR.x()).is_none());
            assert_eq!(g.double(), g + g);
            assert_eq!(g.double() + g, g + g + g);
            assert_eq!(g + Point::IDENTITY, g);
            assert_eq!(Point::IDENTITY + g, g);
            assert_eq!(g - g, Point::IDENTITY);
            assert_eq!(Point::IDENTITY.double(), Point::IDENTITY);
            assert_eq!(g.add_affine(&Affine::IDENTITY), g);
            assert_eq!(Point::IDENTITY.add_affine(&Affine::GENERATOR), g);
            assert_eq!(g.add_affine(&Affine::GENERATOR), g.double());
            assert_eq!(g.add_affine(&Affine::GENERATOR.neg()), Point::IDENTITY);
            assert_eq!(Point::IDENTITY.to_affine(), Affine::IDENTITY);
            assert_eq!(Affine::IDENTITY.to_point(), Point::IDENTITY);
            assert_eq!(Point::IDENTITY.to_bytes(), [0u8; 32]);
            assert_eq!(Point::from_bytes(&[0u8; 32]), Some(Point::IDENTITY));
            // the curve has prime order: (order - 1) * G = -G
            let minus_one = -Scalar::ONE;
            assert_eq!(g.mul(&minus_one), -g);
            assert_eq!(g.mul_vartime(&minus_one) + g, Point::IDENTITY);
            assert_eq!(g.mul(&Scalar::ZERO), Point::IDENTITY);
            // the endomorphism is multiplication by a cube root of unity
            let e = g.endo();
            assert!(bool::from(e.to_affine().is_on_curve()));
            assert!(e == g.mul(&Scalar::ZETA) || e == g.mul(&Scalar::ZETA.square()));
            assert_eq!(Affine::GENERATOR.endo().to_point(), e);

            let mut k = Scalar::from_u64(0x1234_5678_9abc_def1);
            let mut acc = Point::IDENTITY;
            let mut scalars = [Scalar::ZERO; 40];
            let mut points = [Point::IDENTITY; 40];
            for i in 0..40 {
                k = k.square() + Scalar::from_u64(i as u64 + 3);
                let p = g.mul(&k);
                assert_eq!(p, g.mul_vartime(&k));
                assert_eq!(p + g, g.mul(&(k + Scalar::ONE)));
                assert_eq!(p.double(), g.mul(&k.double()));
                assert_eq!(p + acc, acc + p);
                acc = acc + p;
                let a = p.to_affine();
                assert!(bool::from(a.is_on_curve()));
                assert_eq!(acc.add_affine(&a), acc + p);
                let bytes = p.to_bytes();
                assert_eq!(Affine::from_bytes(&bytes), Some(a));
                assert_eq!((-p).to_bytes()[..31], bytes[..31]);
                assert_eq!((-p).to_bytes()[31], bytes[31] ^ 0x80);
                scalars[i] = k + Scalar::from_u64(99);
                points[i] = if i % 7 == 3 { Point::IDENTITY } else { p };
            }
            let mut affine = [Affine::GENERATOR; 40];
            Point::batch_normalize(&points, &mut affine);
            let mut expected = Point::IDENTITY;
            for i in 0..40 {
                assert_eq!(affine[i], points[i].to_affine());
                expected = expected + points[i].mul(&scalars[i]);
            }
            assert_eq!(Point::msm_vartime(&scalars, &affine), expected);
            let small = Point::msm_vartime(&scalars[..5], &affine[..5]);
            let mut expected = Point::IDENTITY;
            for i in 0..5 {
                expected = expected + points[i].mul(&scalars[i]);
            }
            assert_eq!(small, expected);
            // a non-canonical x and an x not on the curve
            assert!(Affine::from_bytes(&[0xff; 32]).is_none());
            let mut zero_odd = [0u8; 32];
            zero_odd[31] = 0x80;
            assert!(Affine::from_bytes(&zero_odd).is_none());
            // hashing to the curve
            let h = Point::hash_to_curve(b"z.cash:test", b"");
            assert!(bool::from(h.to_affine().is_on_curve()));
            assert!(!bool::from(h.is_identity()));
            assert_ne!(h, Point::hash_to_curve(b"z.cash:test", b"x"));
        }
    };
}

curve_tests!(pallas_arithmetic, pallas);
curve_tests!(vesta_arithmetic, vesta);

#[test]
fn pallas_group_hash_vectors() {
    let tvs = vectors(include_str!("../testdata/orchard_group_hash.json"));
    assert!(tvs.len() > 5);
    for tv in tvs {
        let p = pallas::Point::hash_to_curve(&bytes(&tv[0]), &bytes(&tv[1]));
        assert_eq!(p.to_bytes(), arr::<32>(&tv[2]));
    }
}

#[test]
fn pallas_map_to_curve_vectors() {
    let tvs = vectors(include_str!("../testdata/orchard_map_to_curve.json"));
    assert!(tvs.len() > 5);
    for tv in tvs {
        let u = Fp::from_bytes(&arr(&tv[0])).unwrap();
        let (x, y) = pallas::Point::map_to_curve_simple_swu(&u);
        let mut encoded = x.to_bytes();
        encoded[31] |= y.is_odd().unwrap_u8() << 7;
        assert_eq!(encoded, arr::<32>(&tv[1]));
    }
}

/// The Vesta vector of `pasta_curves` (`src/vesta.rs`, `test_hash_to_curve`),
/// which gives the point in Jacobian coordinates.
#[test]
fn vesta_hash_to_curve_vector() {
    let fq = |s: &str| {
        let mut bytes: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
        bytes.reverse();
        Fq::from_bytes(&bytes).unwrap()
    };
    let x = fq("12763505036e0e1a6684b7a7d8d5afb7378cc2b191a95e34f44824a06fcbd08e");
    let y = fq("0256eafc0188b79bfa7c4b2b393893ddc298e90da500fa4a9aee17c2ea4240e6");
    let z = fq("1b58d4aa4d68c3f4d9916b77c79ff9911597a27f2ee46244e98eb9615172d2ad");
    let zinv = z.invert().unwrap();
    let expected = vesta::Affine::from_xy(x * zinv.square(), y * zinv.square() * zinv).unwrap();
    let p = vesta::Point::hash_to_curve(b"z.cash:test", b"hello");
    assert_eq!(p.to_affine(), expected);
}
