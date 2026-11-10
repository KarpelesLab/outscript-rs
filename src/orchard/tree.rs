//! The Orchard note commitment tree: a Merkle tree of depth 32 over
//! extracted note commitments, hashed with Sinsemilla.
//!
//! Levels are counted from the leaves: leaves are at level 0 and the root
//! (the *anchor* of a bundle) at level 32.

use super::Error;
use super::constants::EMPTY_ROOTS;
use super::fields::Fp;
use super::sinsemilla::{HashDomain, le_bits};

#[cfg(feature = "alloc")]
use crate::prelude::*;

/// The depth of the tree.
pub const DEPTH: usize = 32;

/// The value of a leaf no note commitment has been appended at (which is
/// not the x coordinate of any point of the curve).
pub const UNCOMMITTED: Fp = Fp::from_u64(2);

/// `MerkleCRH^Orchard`: the node at `level + 1` whose children at `level`
/// are `left` and `right` (so `level` is 0 when hashing two leaves, and at
/// most 31). When the underlying Sinsemilla hash is undefined the node is
/// zero, as the protocol specifies.
///
/// # Panics
/// Panics if `level` is 32 or more.
pub fn merkle_crh(level: usize, left: &Fp, right: &Fp) -> Fp {
    assert!(level < DEPTH, "level out of range");
    let l = (level as u16).to_le_bytes();
    let (left, right) = (left.to_bytes(), right.to_bytes());
    HashDomain::MERKLE_CRH
        .hash(
            le_bits(&l, 10)
                .chain(le_bits(&left, 255))
                .chain(le_bits(&right, 255)),
        )
        .unwrap_or(Fp::ZERO)
}

/// The root of an empty subtree of height `level` (0 to 32):
/// [`UNCOMMITTED`] at level 0, the anchor of the empty tree at level 32.
///
/// # Panics
/// Panics if `level` is above 32.
pub fn empty_root(level: usize) -> Fp {
    EMPTY_ROOTS[level]
}

/// The authentication path of a leaf: its position and its sibling at every
/// level, from the leaves up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerklePath {
    position: u32,
    auth_path: [Fp; DEPTH],
}

impl MerklePath {
    /// A path from its parts.
    pub fn from_parts(position: u32, auth_path: [Fp; DEPTH]) -> Self {
        MerklePath {
            position,
            auth_path,
        }
    }

    /// The position of the leaf.
    pub fn position(&self) -> u32 {
        self.position
    }

    /// The siblings, from the leaves up.
    pub fn auth_path(&self) -> &[Fp; DEPTH] {
        &self.auth_path
    }

    /// The root of the tree in which the leaf `cmx` is at this path.
    pub fn root(&self, cmx: Fp) -> Fp {
        let mut node = cmx;
        for (level, sibling) in self.auth_path.iter().enumerate() {
            node = if (self.position >> level) & 1 == 0 {
                merkle_crh(level, &node, sibling)
            } else {
                merkle_crh(level, sibling, &node)
            };
        }
        node
    }
}

/// The right edge of the note commitment tree: enough state to append
/// commitments and compute the root, in constant space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontier {
    size: u64,
    /// At each level, the left sibling waiting for its right one (only
    /// meaningful where the matching bit of `size` is set).
    /// The last entry is the root once the tree is full.
    ommers: [Fp; DEPTH + 1],
}

impl Default for Frontier {
    fn default() -> Self {
        Self::new()
    }
}

impl Frontier {
    /// The frontier of the empty tree.
    pub const fn new() -> Self {
        Frontier {
            size: 0,
            ommers: [Fp::ZERO; DEPTH + 1],
        }
    }

    /// The number of commitments appended so far.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Appends a commitment, returning its position.
    pub fn append(&mut self, cmx: Fp) -> Result<u32, Error> {
        if self.size >= 1 << DEPTH {
            return Err(Error::TreeFull);
        }
        let position = self.size;
        let mut node = cmx;
        for level in 0..=DEPTH {
            if level == DEPTH || (position >> level) & 1 == 0 {
                self.ommers[level] = node;
                break;
            }
            node = merkle_crh(level, &self.ommers[level], &node);
        }
        self.size += 1;
        Ok(position as u32)
    }

    /// The root of the tree.
    pub fn root(&self) -> Fp {
        // `node` is the root of the rightmost, partly filled subtree of
        // each level; while it is still empty no hashing is needed
        let mut node = None;
        for (level, empty) in EMPTY_ROOTS[..DEPTH].iter().enumerate() {
            node = if (self.size >> level) & 1 == 1 {
                let right = node.unwrap_or(*empty);
                Some(merkle_crh(level, &self.ommers[level], &right))
            } else {
                node.map(|n| merkle_crh(level, &n, empty))
            };
        }
        match node {
            Some(n) => n,
            // either empty or completely full
            None if self.size == 0 => EMPTY_ROOTS[DEPTH],
            None => self.ommers[DEPTH],
        }
    }
}

/// The nodes of every level above the given leaves, the missing ones being
/// empty: `levels[l]` holds the nodes of level `l` that have a leaf under
/// them.
#[cfg(feature = "alloc")]
fn levels(leaves: &[Fp]) -> Vec<Vec<Fp>> {
    let mut levels = Vec::with_capacity(DEPTH + 1);
    levels.push(leaves.to_vec());
    for level in 0..DEPTH {
        let cur = &levels[level];
        let next = cur
            .chunks(2)
            .map(|pair| {
                let right = pair.get(1).unwrap_or(&EMPTY_ROOTS[level]);
                merkle_crh(level, &pair[0], right)
            })
            .collect();
        levels.push(next);
    }
    levels
}

/// The root of the tree whose first leaves are `leaves`, the rest being
/// uncommitted. `None` if there are more than `2^32` leaves.
#[cfg(feature = "alloc")]
pub fn root(leaves: &[Fp]) -> Option<Fp> {
    if leaves.len() as u64 > 1 << DEPTH {
        return None;
    }
    let levels = levels(leaves);
    Some(levels[DEPTH].first().copied().unwrap_or(EMPTY_ROOTS[DEPTH]))
}

/// The authentication path of the leaf at `position` in the tree whose
/// first leaves are `leaves`, the rest being uncommitted. `None` if the
/// position is not one of `leaves`.
///
/// This hashes the whole tree; a wallet tracking many notes over a growing
/// tree wants an incremental structure instead.
#[cfg(feature = "alloc")]
pub fn witness(leaves: &[Fp], position: u32) -> Option<MerklePath> {
    if position as usize >= leaves.len() || leaves.len() as u64 > 1 << DEPTH {
        return None;
    }
    let levels = levels(leaves);
    let mut auth_path = [Fp::ZERO; DEPTH];
    for (level, sibling) in auth_path.iter_mut().enumerate() {
        let index = (position as usize >> level) ^ 1;
        *sibling = levels[level]
            .get(index)
            .copied()
            .unwrap_or(EMPTY_ROOTS[level]);
    }
    Some(MerklePath {
        position,
        auth_path,
    })
}
