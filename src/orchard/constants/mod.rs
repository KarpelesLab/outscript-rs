//! The fixed generators of the Orchard protocol.
//!
//! Each is the output of [`pallas::Point::hash_to_curve`] under the domain
//! and message given in its description, precomputed so that no hashing to
//! the curve happens at run time.

use super::fields::Fp;
use super::pallas::{self, Affine};

mod empty_roots;
mod fixed_bases;
mod sinsemilla_s;

const fn point(raw: &([u64; 4], [u64; 4])) -> Affine {
    Affine::from_xy_unchecked(
        Fp::from_montgomery_unchecked(raw.0),
        Fp::from_montgomery_unchecked(raw.1),
    )
}

/// `SpendAuthG`, the base of spend authorization keys and signatures:
/// `GroupHash("z.cash:Orchard", "G")`.
pub const SPEND_AUTH_G: Affine = point(&fixed_bases::SPEND_AUTH_G_RAW);
/// `K^Orchard`, the base of nullifier derivation:
/// `GroupHash("z.cash:Orchard", "K")`.
pub const NULLIFIER_K: Affine = point(&fixed_bases::NULLIFIER_K_RAW);
/// `V^Orchard`, the value base of value commitments:
/// `GroupHash("z.cash:Orchard-cv", "v")`.
pub const VALUE_COMMIT_V: Affine = point(&fixed_bases::VALUE_COMMIT_V_RAW);
/// `R^Orchard`, the randomness base of value commitments and the base of
/// binding signatures: `GroupHash("z.cash:Orchard-cv", "r")`.
pub const VALUE_COMMIT_R: Affine = point(&fixed_bases::VALUE_COMMIT_R_RAW);
/// The randomness base of note commitments:
/// `GroupHash("z.cash:Orchard-NoteCommit-r", "")`.
pub const NOTE_COMMIT_R: Affine = point(&fixed_bases::NOTE_COMMIT_R_RAW);
/// The Sinsemilla `Q` of note commitments:
/// `GroupHash("z.cash:SinsemillaQ", "z.cash:Orchard-NoteCommit-M")`.
pub const NOTE_COMMIT_Q: Affine = point(&fixed_bases::NOTE_COMMIT_Q_RAW);
/// The randomness base of `CommitIvk`:
/// `GroupHash("z.cash:Orchard-CommitIvk-r", "")`.
pub const COMMIT_IVK_R: Affine = point(&fixed_bases::COMMIT_IVK_R_RAW);
/// The Sinsemilla `Q` of `CommitIvk`:
/// `GroupHash("z.cash:SinsemillaQ", "z.cash:Orchard-CommitIvk-M")`.
pub const COMMIT_IVK_Q: Affine = point(&fixed_bases::COMMIT_IVK_Q_RAW);
/// The Sinsemilla `Q` of the note commitment tree hash:
/// `GroupHash("z.cash:SinsemillaQ", "z.cash:Orchard-MerkleCRH")`.
pub const MERKLE_CRH_Q: Affine = point(&fixed_bases::MERKLE_CRH_Q_RAW);

/// The Sinsemilla generators: entry `j` is
/// `GroupHash("z.cash:SinsemillaS", I2LEOSP_32(j))`.
pub static SINSEMILLA_S: [Affine; 1024] = {
    let mut out = [Affine::IDENTITY; 1024];
    let mut i = 0;
    while i < 1024 {
        out[i] = point(&sinsemilla_s::S_RAW[i]);
        i += 1;
    }
    out
};

/// `GroupHash^P(domain, msg)`: [`pallas::Point::hash_to_curve`], the way
/// every generator above is derived.
pub fn group_hash(domain: &[u8], msg: &[u8]) -> pallas::Point {
    pallas::Point::hash_to_curve(domain, msg)
}

/// The roots of the empty subtrees of the note commitment tree: entry `l`
/// is the root of an empty subtree of height `l`, entry 0 being the
/// uncommitted leaf and entry 32 the anchor of the empty tree.
pub const EMPTY_ROOTS: [Fp; 33] = {
    let mut out = [Fp::ZERO; 33];
    let mut i = 0;
    while i < 33 {
        out[i] = Fp::from_montgomery_unchecked(empty_roots::EMPTY_ROOTS_RAW[i]);
        i += 1;
    }
    out
};
