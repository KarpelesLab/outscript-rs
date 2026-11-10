//! The fixed bases of the Orchard circuit (port of
//! `orchard::constants::fixed_bases`): the generators, and for each of them
//! the per-window `z` values the fixed-base scalar multiplication gates use.
//!
//! The `Z` tables are those of the `orchard` 0.16 crate (they can be
//! reproduced with `find_zs_and_us` of `halo2_gadgets`). Its `U` tables are
//! not embedded: `u` is the square root of `y + z` that
//! [`Fp::sqrt`](crate::orchard::Fp::sqrt) returns, computed when a witness
//! needs it (see [`fixed_u`](super::constants::fixed_u)); a test checks that
//! this reproduces every table of the reference.

use super::constants::{NUM_WINDOWS, NUM_WINDOWS_SHORT};
use crate::orchard::constants::{
    COMMIT_IVK_R, NOTE_COMMIT_R, NULLIFIER_K, SPEND_AUTH_G, VALUE_COMMIT_R, VALUE_COMMIT_V,
};
use crate::orchard::pallas;

/// A fixed base of the circuit, with the constants its windows need.
pub(crate) trait FixedPoint: Copy + core::fmt::Debug + Eq {
    /// The generator.
    fn generator(&self) -> pallas::Affine;

    /// The `z` value of each window: `y + z` is a square and `-y + z` is not
    /// for the `y` coordinate of every point of the window. The number of
    /// windows is the length of this table.
    fn z(&self) -> &'static [u64];
}

/// The full-width fixed bases (multiplied by a full scalar).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum OrchardFixedBasesFull {
    /// The blinding base of `Commit^ivk`.
    CommitIvkR,
    /// The blinding base of `NoteCommit`.
    NoteCommitR,
    /// The blinding base of the value commitment.
    ValueCommitR,
    /// The base of the spend authorization key.
    SpendAuthG,
}

/// The fixed bases multiplied by a base field element.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum OrchardBaseFieldBases {
    /// The nullifier base.
    NullifierK,
    /// The spend authorization base (same generator and tables as
    /// [`OrchardFixedBasesFull::SpendAuthG`]): the Action circuit does not
    /// multiply it by a base field element; kept to test the gadget.
    #[cfg(test)]
    SpendAuthGBase,
}

/// The fixed bases multiplied by a signed short (64-bit) scalar.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum OrchardShortScalarBases {
    /// The value base of the value commitment.
    ValueCommitV,
    /// The spend authorization base, on 22 windows: the Action circuit
    /// does not multiply it by a short scalar; kept to test the gadget.
    #[cfg(test)]
    SpendAuthGShort,
}

/// The nullifier base (converts into [`OrchardBaseFieldBases`]).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct NullifierK;

/// The value base (converts into [`OrchardShortScalarBases`]).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValueCommitV;

impl From<NullifierK> for OrchardBaseFieldBases {
    fn from(_: NullifierK) -> Self {
        Self::NullifierK
    }
}

impl From<ValueCommitV> for OrchardShortScalarBases {
    fn from(_: ValueCommitV) -> Self {
        Self::ValueCommitV
    }
}

impl FixedPoint for OrchardFixedBasesFull {
    fn generator(&self) -> pallas::Affine {
        match self {
            Self::CommitIvkR => COMMIT_IVK_R,
            Self::NoteCommitR => NOTE_COMMIT_R,
            Self::ValueCommitR => VALUE_COMMIT_R,
            Self::SpendAuthG => SPEND_AUTH_G,
        }
    }

    fn z(&self) -> &'static [u64] {
        match self {
            Self::CommitIvkR => &COMMIT_IVK_R_Z,
            Self::NoteCommitR => &NOTE_COMMIT_R_Z,
            Self::ValueCommitR => &VALUE_COMMIT_R_Z,
            Self::SpendAuthG => &SPEND_AUTH_G_Z,
        }
    }
}

impl FixedPoint for OrchardBaseFieldBases {
    fn generator(&self) -> pallas::Affine {
        match self {
            Self::NullifierK => NULLIFIER_K,
            #[cfg(test)]
            Self::SpendAuthGBase => SPEND_AUTH_G,
        }
    }

    fn z(&self) -> &'static [u64] {
        match self {
            Self::NullifierK => &NULLIFIER_K_Z,
            #[cfg(test)]
            Self::SpendAuthGBase => &SPEND_AUTH_G_Z,
        }
    }
}

impl FixedPoint for OrchardShortScalarBases {
    fn generator(&self) -> pallas::Affine {
        match self {
            Self::ValueCommitV => VALUE_COMMIT_V,
            #[cfg(test)]
            Self::SpendAuthGShort => SPEND_AUTH_G,
        }
    }

    fn z(&self) -> &'static [u64] {
        match self {
            Self::ValueCommitV => &VALUE_COMMIT_V_Z_SHORT,
            #[cfg(test)]
            Self::SpendAuthGShort => &SPEND_AUTH_G_Z_SHORT,
        }
    }
}

/// Full-width z-values of `COMMIT_IVK_R`.
#[rustfmt::skip]
const COMMIT_IVK_R_Z: [u64; NUM_WINDOWS] = [
    18172, 17390, 61749, 65182, 33835, 155942, 26189, 52444, 40096, 139582, 99218, 20669, 291337,
    12465, 132211, 75527, 68003, 95835, 237325, 21348, 35494, 215451, 49456, 6332, 99036, 224845,
    25324, 23649, 83567, 20531, 9280, 72505, 136089, 21180, 132741, 32676, 18421, 107173, 45630,
    24851, 53914, 156083, 104170, 103364, 25728, 9482, 140699, 42185, 285585, 342, 78646, 326807,
    68908, 10376, 335378, 138003, 41031, 105432, 37682, 15886, 9325, 42470, 27439, 11884, 13979,
    214340, 53073, 76228, 67906, 44696, 178502, 130216, 4242, 142464, 211101, 13210, 66616, 103624,
    7870, 143575, 13058, 27070, 30734, 41157, 2955,
];

/// Full-width z-values of `NOTE_COMMIT_R`.
#[rustfmt::skip]
const NOTE_COMMIT_R_Z: [u64; NUM_WINDOWS] = [
    253356, 149209, 114903, 10575, 6973, 30969, 55415, 206450, 18453, 24528, 13099, 213949, 29959,
    49929, 80867, 17465, 43715, 80241, 55983, 132629, 66101, 24136, 31372, 107975, 161748, 24107,
    72184, 9338, 232543, 13519, 33536, 32530, 130885, 41578, 18166, 91947, 59796, 35560, 5631,
    158600, 24695, 42654, 138331, 11268, 54733, 92869, 33770, 169166, 94853, 7006, 117687, 8073,
    11865, 15349, 186445, 7696, 25167, 30146, 277659, 53921, 19594, 41306, 30172, 8124, 46133,
    38659, 61965, 92134, 43958, 86662, 2047, 3542, 20976, 7411, 53574, 38271, 48233, 65338, 30516,
    41201, 40964, 8563, 36035, 6334, 176,
];

/// Full-width z-values of `VALUE_COMMIT_R`.
#[rustfmt::skip]
const VALUE_COMMIT_R_Z: [u64; NUM_WINDOWS] = [
    181916, 22148, 340526, 80718, 104958, 86894, 43381, 1060, 82130, 4741, 55897, 4304, 114469,
    20503, 25001, 62408, 52978, 35893, 72071, 154369, 67304, 7299, 27960, 42929, 51869, 89967,
    62210, 59433, 47868, 32536, 105000, 1546, 2116, 18717, 50694, 22864, 254428, 54966, 108762,
    46706, 65730, 45555, 7376, 50051, 24773, 74636, 44806, 23223, 78561, 50668, 7380, 13697,
    171970, 269484, 25534, 5098, 79584, 6889, 21432, 73095, 36745, 37350, 6274, 5179, 50216, 12007,
    44029, 88199, 70401, 14120, 19017, 2423, 26494, 34954, 126293, 167379, 136922, 45619, 30331,
    22632, 163228, 12997, 4461, 32320, 13430,
];

/// Full-width z-values of `SPEND_AUTH_G`.
#[rustfmt::skip]
const SPEND_AUTH_G_Z: [u64; NUM_WINDOWS] = [
    49707, 15701, 45931, 163127, 41654, 212130, 34473, 25205, 4118, 10240, 12264, 22866, 203610,
    18808, 13851, 62448, 62380, 94497, 39496, 73216, 32037, 32774, 61690, 39173, 74580, 84678,
    23418, 103090, 34763, 19801, 54976, 196082, 131117, 20556, 58936, 139049, 49530, 488, 2129,
    44219, 64328, 38875, 58430, 34536, 84014, 15455, 38059, 15915, 26893, 100337, 120701, 98937,
    37075, 35293, 8351, 8361, 273432, 717, 3253, 40140, 28024, 95195, 41937, 200127, 95471, 103562,
    75737, 4182, 362357, 15219, 136680, 168274, 25085, 5925, 254392, 93041, 56204, 46757, 109788,
    100797, 80349, 87315, 77372, 96572, 18965,
];

/// Short signed z-values of `SPEND_AUTH_G`.
#[cfg(test)]
#[rustfmt::skip]
const SPEND_AUTH_G_Z_SHORT: [u64; NUM_WINDOWS_SHORT] = [
    49707, 15701, 45931, 163127, 41654, 212130, 34473, 25205, 4118, 10240, 12264, 22866, 203610,
    18808, 13851, 62448, 62380, 94497, 39496, 73216, 32037, 65411,
];

/// Full-width z-values of `NULLIFIER_K`.
#[rustfmt::skip]
const NULLIFIER_K_Z: [u64; NUM_WINDOWS] = [
    34374, 173069, 40776, 220066, 45494, 37762, 5245, 11979, 33386, 238556, 128731, 12128, 89982,
    85351, 9804, 12820, 80455, 100009, 24382, 17854, 26367, 7067, 102106, 64293, 114999, 172304,
    36687, 11287, 66386, 41470, 182654, 12214, 36528, 16257, 26179, 15660, 106189, 211703, 12936,
    2506, 149799, 82965, 117810, 98881, 296, 146201, 63200, 31766, 78221, 6587, 27974, 126041,
    19927, 79339, 210060, 127148, 10109, 19815, 107452, 10296, 642, 11828, 3985, 2984, 30806,
    12554, 1815, 19894, 16790, 33748, 12879, 1742, 30858, 118563, 26855, 75617, 10167, 17660,
    33638, 89236, 50234, 30489, 67488, 50229, 29277,
];

/// Short signed z-values of `VALUE_COMMIT_V`.
#[rustfmt::skip]
const VALUE_COMMIT_V_Z_SHORT: [u64; NUM_WINDOWS_SHORT] = [
    163547, 76040, 88852, 128479, 54088, 89871, 39598, 144309, 43471, 102492, 741, 55288, 33756,
    77312, 12095, 48253, 45718, 202901, 33132, 71081, 152108, 169712,
];

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::super::constants::{H, compute_window_table, fixed_u};
    use super::*;
    use crate::orchard::Fp;

    /// The SHA-256 hash of the `u` values computed for all the windows of a
    /// base (32 bytes each, window by window), and the `z` table checked on
    /// the way as `test_zs_and_us` of `halo2_gadgets` does.
    fn u_hash<F: FixedPoint>(base: F) -> alloc::string::String {
        let z = base.z();
        let table = compute_window_table(base.generator(), z.len());
        let mut bytes = Vec::with_capacity(z.len() * H * 32);
        for (window, z) in table.iter().zip(z) {
            for point in window {
                let u = fixed_u(point.y(), *z);
                assert_eq!(Fp::from_u64(*z) + point.y(), u.square());
                assert!((Fp::from_u64(*z) - point.y()).sqrt().is_none());
                bytes.extend_from_slice(&u.to_bytes());
            }
        }
        hex::encode(purecrypto::hash::sha256(&bytes))
    }

    /// The `u` values we compute are those of the `U` (`U_SHORT`) tables
    /// embedded in the `orchard` 0.16 crate, for every base.
    ///
    /// The expected hashes are the SHA-256 of these tables as returned by
    /// `FixedPoint::u()` of the reference (`sha256sum out/u_*.bin` after
    /// `cargo run --release` in the scratch project
    /// `/tmp/claude-1000/sp/ref-ecc/`).
    #[test]
    fn u_tables_match_reference() {
        assert_eq!(
            u_hash(OrchardFixedBasesFull::CommitIvkR),
            "773cf164445bf2a9ccf52d9feb3b361f553c516852ebcf047f98eef51490abbb"
        );
        assert_eq!(
            u_hash(OrchardFixedBasesFull::NoteCommitR),
            "e341f5e5d5242d1a105214bb3f8c0dfeade19a48fca0d6e45054cdf756630405"
        );
        assert_eq!(
            u_hash(OrchardFixedBasesFull::ValueCommitR),
            "521f111807bc64341bb4d02f5efd94191b59f2e9e4c56118b9a5289577a5b8c9"
        );
        assert_eq!(
            u_hash(OrchardFixedBasesFull::SpendAuthG),
            "082b0aac2a04649de623ccb60d8d64c05df7d9807f6e74b101eb08b501f4d22d"
        );
        assert_eq!(
            u_hash(OrchardBaseFieldBases::NullifierK),
            "b58d870fd57cae05a2dfc2659eec1bc8efddce6169e5e46f944af1a819f7cd7d"
        );
        assert_eq!(
            u_hash(OrchardBaseFieldBases::SpendAuthGBase),
            "082b0aac2a04649de623ccb60d8d64c05df7d9807f6e74b101eb08b501f4d22d"
        );
        assert_eq!(
            u_hash(OrchardShortScalarBases::ValueCommitV),
            "ebcdcfeb188c6c1972ebcafcf6b4e3d57c1707d71cb962185ae4a41e42086b84"
        );
        assert_eq!(
            u_hash(OrchardShortScalarBases::SpendAuthGShort),
            "7d961ccc5e73f16fbab63b9f47a12387dc722ba5cf427b7eb8276113f536b85b"
        );
    }
}
