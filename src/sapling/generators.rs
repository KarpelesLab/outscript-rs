//! The fixed generators of Sapling (protocol specification §5.4.9.5,
//! §5.4.1.7, §5.4.8.2 and §5.4.8.3) and the window tables circuits use to
//! multiply by them.
//!
//! The generators are constants here; a test rederives each of them with
//! [`find_group_hash`] and checks them against the official test vectors.
//!
//! # For circuit synthesis
//!
//! A Groth16 circuit multiplies by a fixed generator with 3-bit windows
//! ([`fixed_base_windows`]) and evaluates a Pedersen hash segment with 2-bit
//! lookups, plus a sign bit, of Montgomery-form points
//! ([`pedersen_segment_windows`], [`to_montgomery`]).

use super::field::Fq;
use super::group_hash::find_group_hash;
use super::jubjub::{AffinePoint, D, Point};

/// The personalization of the Pedersen hash generators and of the note
/// commitment randomness base.
pub const PEDERSEN_HASH_PERSONALIZATION: &[u8; 8] = b"Zcash_PH";

/// The personalization of `DiversifyHash`.
pub const KEY_DIVERSIFICATION_PERSONALIZATION: &[u8; 8] = b"Zcash_gd";

/// The personalization of the value commitment generators.
pub const VALUE_COMMITMENT_PERSONALIZATION: &[u8; 8] = b"Zcash_cv";

/// `G = FindGroupHash("Zcash_G_", "")`: the base of spend authorization keys
/// (`ak = [ask] G`) and of the `SpendAuthSig` scheme.
pub const SPENDING_KEY_BASE: AffinePoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x47bf_4692_0a95_a753,
        0xd5b9_a7d3_ef8e_2827,
        0xd418_a7ff_2675_3b6a,
        0x0926_d4f3_2059_c712,
    ]),
    Fq::from_raw([
        0x3056_32ad_aaf2_b530,
        0x6d65_674d_cedb_ddbc,
        0x53bb_37d0_c21c_fd05,
        0x57a1_019e_6de9_b675,
    ]),
);

/// `H = FindGroupHash("Zcash_H_", "")`: the base of nullifier deriving keys
/// (`nk = [nsk] H`).
pub const PROOF_GENERATION_KEY_BASE: AffinePoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x3af2_dbef_b96e_2571,
        0xadf2_d038_f2fb_b820,
        0x7043_03f1_e890_6081,
        0x1457_a502_31cd_e2df,
    ]),
    Fq::from_raw([
        0x467a_f9f7_e05d_e8e7,
        0x50df_51ea_f5a1_49d2,
        0xdec9_0184_0f49_48cc,
        0x54b6_d107_18df_2a7a,
    ]),
);

/// `J = FindGroupHash("Zcash_J_", "")`: the base a note's position is mixed
/// into its commitment with, before the nullifier is derived.
pub const NULLIFIER_POSITION_BASE: AffinePoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x2ce3_3921_888d_30db,
        0xe81c_ee09_a561_229e,
        0xdb56_b6db_8d80_75ed,
        0x2400_c2e2_e336_2644,
    ]),
    Fq::from_raw([
        0xa3f7_fa36_c72b_0065,
        0xe155_b8e8_ffff_2e42,
        0xfc9e_8a15_a096_ba8f,
        0x6136_9d54_40bf_84a5,
    ]),
);

/// `FindGroupHash("Zcash_PH", "r")`: the randomness base of windowed Pedersen
/// commitments, hence of note commitments.
pub const NOTE_COMMITMENT_RANDOMNESS_BASE: AffinePoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0xa514_3b34_a8e3_6462,
        0xf091_9d06_ffb1_ecda,
        0xa140_9aa1_f33b_ec2c,
        0x26eb_9f8a_9ec7_2a8c,
    ]),
    Fq::from_raw([
        0xd4fc_6365_796c_77ac,
        0x96b7_8bea_fa9c_c44c,
        0x949d_7747_6e26_2c95,
        0x114b_7501_ad10_4c57,
    ]),
);

/// `V = FindGroupHash("Zcash_cv", "v")`: the value base of value commitments.
pub const VALUE_COMMITMENT_VALUE_BASE: AffinePoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x3618_3b2c_b4d7_ef51,
        0x9472_c89a_c043_042d,
        0xd861_8ed1_d15f_ef4e,
        0x273f_910d_9ecc_1615,
    ]),
    Fq::from_raw([
        0xa77a_81f5_0667_c8d7,
        0xbc33_32d0_fa1c_cd18,
        0xd322_94fd_8977_4ad6,
        0x466a_7e3a_82f6_7ab1,
    ]),
);

/// `R = FindGroupHash("Zcash_cv", "r")`: the randomness base of value
/// commitments, and the base of the `BindingSig` scheme.
pub const VALUE_COMMITMENT_RANDOMNESS_BASE: AffinePoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x3bce_3b77_9366_4337,
        0xd1d8_da41_af03_744e,
        0x7ff6_826a_d580_04b4,
        0x6800_f4fa_0f00_1cfc,
    ]),
    Fq::from_raw([
        0x3cae_fab9_380b_6a8b,
        0xad46_f1b0_473b_803b,
        0xe6fb_2a6e_1e22_ab50,
        0x6d81_d3a9_cb45_dedb,
    ]),
);

/// The first six Pedersen hash segment generators,
/// `FindGroupHash("Zcash_PH", I2LEOSP_32(i))` for `i` in `0..6`: enough for
/// every hash Sapling computes (a Merkle node takes three segments, a note
/// commitment four). See [`pedersen_hash_generator`].
pub const PEDERSEN_HASH_GENERATORS: [AffinePoint; 6] = [
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0x194e_4292_6f66_1b51,
            0x2f0c_718f_6f0f_badd,
            0xb5ea_25de_7ec0_e378,
            0x73c0_16a4_2ded_9578,
        ]),
        Fq::from_raw([
            0x77bf_abd4_3224_3cca,
            0xf947_2e8b_c04e_4632,
            0x79c9_166b_837e_dc5e,
            0x289e_87a2_d352_1b57,
        ]),
    ),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0xb981_9dc8_2d90_607e,
            0xa361_ee3f_d48f_df77,
            0x52a3_5a8c_1908_dd87,
            0x15a3_6d1f_0f39_0d88,
        ]),
        Fq::from_raw([
            0x7b0d_c53c_4ebf_1891,
            0x1f3a_beeb_98fa_d3e8,
            0xf789_1142_c001_d925,
            0x015d_8c7f_5b43_fe33,
        ]),
    ),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0x76d6_f7c2_b67f_c475,
            0xbae8_e5c4_6641_ae5c,
            0xeb69_ae39_f5c8_4210,
            0x6643_21a5_8246_e2f6,
        ]),
        Fq::from_raw([
            0x80ed_502c_9793_d457,
            0x8bb2_2a7f_1784_b498,
            0xe000_a46c_8e8c_e853,
            0x362e_1500_d24e_ee9e,
        ]),
    ),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0x4c76_7804_c1c4_a2cc,
            0x7d02_d50e_654b_87f2,
            0xedc5_f4a9_cff2_9fd5,
            0x323a_6548_ce9d_9876,
        ]),
        Fq::from_raw([
            0x8471_4bec_a335_70e9,
            0x5103_afa1_a11f_6a85,
            0x9107_0acb_d8d9_47b7,
            0x2f7e_e40c_4b56_cad8,
        ]),
    ),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0x4680_9430_657f_82d1,
            0xefd5_9313_05f2_f0bf,
            0x89b6_4b4e_0336_2796,
            0x3bd2_6660_00b5_4796,
        ]),
        Fq::from_raw([
            0x9996_8299_c365_8aef,
            0xb3b9_d809_5859_d14c,
            0x3978_3238_1406_c9e5,
            0x494b_c521_03ab_9d0a,
        ]),
    ),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0xcb3c_0232_58d3_2079,
            0x1d9e_5ca2_1135_ff6f,
            0xda04_9746_d76d_3ee5,
            0x6344_7b2b_a31b_b28a,
        ]),
        Fq::from_raw([
            0x4360_8211_9f8d_629a,
            0xa802_00d2_c66b_13a7,
            0x64cd_b107_0a13_6a28,
            0x64ec_4689_e8bf_b6e5,
        ]),
    ),
];

/// The number of 3-bit chunks (63) one Pedersen hash segment generator
/// absorbs.
pub const PEDERSEN_HASH_CHUNKS_PER_GENERATOR: usize = 63;

/// The number of 3-bit windows (84) a circuit splits a scalar into for a
/// fixed-base multiplication.
pub const FIXED_BASE_CHUNKS_PER_GENERATOR: usize = 84;

/// The Pedersen hash generator of segment `i` (counting from 0):
/// `FindGroupHash("Zcash_PH", I2LEOSP_32(i))`, from the table for the first
/// six and computed beyond.
pub fn pedersen_hash_generator(i: u32) -> Point {
    match PEDERSEN_HASH_GENERATORS.get(i as usize) {
        Some(g) => g.to_point(),
        // FindGroupHash fails with probability 2^-256
        None => find_group_hash(PEDERSEN_HASH_PERSONALIZATION, &i.to_le_bytes())
            .unwrap_or(Point::IDENTITY),
    }
}

/// The 3-bit window tables of a fixed generator, as a circuit's fixed-base
/// scalar multiplication consumes them: [`FIXED_BASE_CHUNKS_PER_GENERATOR`]
/// tables, the `w`-th holding `[j·8^w] base` for `j` in `0..8`.
pub fn fixed_base_windows(base: &AffinePoint) -> impl Iterator<Item = [AffinePoint; 8]> {
    let mut generator = base.to_point();
    (0..FIXED_BASE_CHUNKS_PER_GENERATOR).map(move |_| {
        let mut points = [Point::IDENTITY; 8];
        for j in 1..8 {
            points[j] = points[j - 1].add(&generator);
        }
        generator = points[7].add(&generator);
        let mut table = [AffinePoint::IDENTITY; 8];
        Point::batch_to_affine(&points, &mut table);
        table
    })
}

/// The lookup tables of Pedersen hash segment `segment`, as the circuit
/// consumes them: [`PEDERSEN_HASH_CHUNKS_PER_GENERATOR`] tables, the `w`-th
/// holding `[j·16^w] I_segment` for `j` in `1..=4`. The two low bits of a
/// chunk select an entry and the third negates it. The circuit works with
/// the Montgomery form of these points: see [`to_montgomery`].
pub fn pedersen_segment_windows(segment: u32) -> impl Iterator<Item = [AffinePoint; 4]> {
    let mut generator = pedersen_hash_generator(segment);
    (0..PEDERSEN_HASH_CHUNKS_PER_GENERATOR).map(move |_| {
        let mut points = [generator; 4];
        for j in 1..4 {
            points[j] = points[j - 1].add(&generator);
        }
        generator = generator.double().double().double().double();
        let mut table = [AffinePoint::IDENTITY; 4];
        Point::batch_to_affine(&points, &mut table);
        table
    })
}

/// The `A` coefficient (40962) of the Montgomery curve
/// `y² = x³ + A·x² + x` birationally equivalent to Jubjub.
pub const MONTGOMERY_A: Fq = Fq::from_u64(40962);

/// The scaling factor `sqrt(4 / (a - d))` of the map to Montgomery form.
pub const MONTGOMERY_SCALE: Fq = Fq::from_raw([
    0x8f45_35f7_cf82_b8d9,
    0xce40_6970_3da8_8abd,
    0x31de_341e_77d7_64e5,
    0x2762_de61_e862_645e,
]);

/// The Montgomery coordinates of a point: `x = (1 + v) / (1 - v)` and
/// `y = scale · x / u`. The point of order two maps to `(0, 0)`; the
/// identity is the point at infinity and gives `None`.
pub fn to_montgomery(p: &AffinePoint) -> Option<(Fq, Fq)> {
    let (u, v) = (p.u(), p.v());
    if v == Fq::ONE {
        return None;
    }
    if u.is_zero() {
        return Some((Fq::ZERO, Fq::ZERO));
    }
    let x = (Fq::ONE + v) * (Fq::ONE - v).invert()?;
    let y = x * u.invert()? * MONTGOMERY_SCALE;
    Some((x, y))
}

/// Whether `(x, y)` is on the Montgomery form of Jubjub,
/// `y² = x³ + A·x² + x`.
pub fn is_on_montgomery_curve(x: &Fq, y: &Fq) -> bool {
    y.square() == x.square() * *x + MONTGOMERY_A * x.square() + *x
}

const _: () = {
    // 4 / (a - d) with a = -1: the scale is its square root
    let a_minus_d = Fq::ONE.const_neg().const_sub(&D);
    let four = Fq::from_u64(4);
    let lhs = MONTGOMERY_SCALE.square().const_mul(&a_minus_d).to_raw();
    let rhs = four.to_raw();
    assert!(lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2] && lhs[3] == rhs[3]);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sapling::field::Fr;

    #[test]
    fn generators_are_the_group_hashes() {
        let cases: [(&AffinePoint, &[u8; 8], &[u8]); 6] = [
            (&SPENDING_KEY_BASE, b"Zcash_G_", b""),
            (&PROOF_GENERATION_KEY_BASE, b"Zcash_H_", b""),
            (&NULLIFIER_POSITION_BASE, b"Zcash_J_", b""),
            (&NOTE_COMMITMENT_RANDOMNESS_BASE, b"Zcash_PH", b"r"),
            (&VALUE_COMMITMENT_VALUE_BASE, b"Zcash_cv", b"v"),
            (&VALUE_COMMITMENT_RANDOMNESS_BASE, b"Zcash_cv", b"r"),
        ];
        for (constant, personalization, message) in cases {
            assert!(constant.is_on_curve());
            assert!(constant.to_point().is_prime_order());
            assert_eq!(
                find_group_hash(personalization, message),
                Some(constant.to_point())
            );
        }
        for (i, constant) in PEDERSEN_HASH_GENERATORS.iter().enumerate() {
            assert!(constant.is_on_curve());
            assert_eq!(
                find_group_hash(b"Zcash_PH", &(i as u32).to_le_bytes()),
                Some(constant.to_point())
            );
            assert_eq!(pedersen_hash_generator(i as u32), constant.to_point());
        }
        // beyond the table
        assert_eq!(
            Some(pedersen_hash_generator(6)),
            find_group_hash(b"Zcash_PH", &[6, 0, 0, 0])
        );
    }

    #[test]
    fn fixed_base_tables() {
        let base = SPENDING_KEY_BASE.to_point();
        let mut count = 0;
        let mut scale = Fr::ONE;
        for (w, table) in fixed_base_windows(&SPENDING_KEY_BASE).enumerate() {
            count += 1;
            assert_eq!(table[0], AffinePoint::IDENTITY);
            if w < 3 || w == 83 {
                for (j, entry) in table.iter().enumerate() {
                    assert!(entry.is_on_curve());
                    let expect = base.mul_vartime(&(scale * Fr::from_u64(j as u64)));
                    assert_eq!(entry.to_point(), expect);
                }
            }
            scale *= Fr::from_u64(8);
        }
        assert_eq!(count, FIXED_BASE_CHUNKS_PER_GENERATOR);
    }

    #[test]
    fn pedersen_tables() {
        let base = pedersen_hash_generator(2);
        let mut count = 0;
        let mut scale = Fr::ONE;
        for (w, table) in pedersen_segment_windows(2).enumerate() {
            count += 1;
            if w < 3 || w == 62 {
                for (j, entry) in table.iter().enumerate() {
                    let expect = base.mul_vartime(&(scale * Fr::from_u64(j as u64 + 1)));
                    assert_eq!(entry.to_point(), expect);
                    let (x, y) = to_montgomery(entry).unwrap();
                    assert!(is_on_montgomery_curve(&x, &y));
                }
            }
            scale *= Fr::from_u64(16);
        }
        assert_eq!(count, PEDERSEN_HASH_CHUNKS_PER_GENERATOR);
    }

    #[test]
    fn montgomery_map() {
        assert_eq!(to_montgomery(&AffinePoint::IDENTITY), None);
        let two = AffinePoint::new(Fq::ZERO, -Fq::ONE).unwrap();
        assert_eq!(to_montgomery(&two), Some((Fq::ZERO, Fq::ZERO)));
        // A = 2 (a + d) / (a - d)
        let a = -Fq::ONE;
        assert_eq!(
            MONTGOMERY_A * (a - D),
            (a + D).double()
        );
    }
}
