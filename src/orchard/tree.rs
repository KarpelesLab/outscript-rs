//! The Orchard note commitment tree: a Merkle tree of depth 32 over
//! extracted note commitments, hashed with Sinsemilla.
//!
//! Levels are counted from the leaves: leaves are at level 0 and the root
//! (the *anchor* of a bundle) at level 32.
//!
//! A wallet following the chain keeps a [`Frontier`], to which it appends
//! the commitment of every action in order, and an [`IncrementalWitness`]
//! for each of its own notes ([`Frontier::append_witnessed`]), to which it
//! appends every commitment that follows: the witness then gives the
//! authentication path of the note ([`MerklePath`]) for the tree as it
//! stands, which is what spending the note takes. Both are of constant
//! size and need no allocator.

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

    /// Appends a commitment, returning a witness for it: its
    /// authentication path, to keep up to date by appending to the witness
    /// every commitment appended to the tree afterwards.
    pub fn append_witnessed(&mut self, cmx: Fp) -> Result<IncrementalWitness, Error> {
        if self.size >= 1 << DEPTH {
            return Err(Error::TreeFull);
        }
        let position = self.size as u32;
        // The siblings on the left are the nodes waiting for their right
        // one; those on the right are empty for now.
        let mut auth_path = EMPTY_ROOTS_BELOW;
        for (level, sibling) in auth_path.iter_mut().enumerate() {
            if (position >> level) & 1 == 1 {
                *sibling = self.ommers[level];
            }
        }
        let witness = IncrementalWitness {
            cmx,
            position,
            auth_path,
            size: self.size + 1,
            cursor_level: position.trailing_ones() as usize,
            cursor: Subtree::new(),
        };
        self.append(cmx)?;
        Ok(witness)
    }

    /// The root of the tree.
    pub fn root(&self) -> Fp {
        match partial_root(&self.ommers, self.size, DEPTH) {
            Some(n) => n,
            // either empty or completely full
            None if self.size == 0 => EMPTY_ROOTS[DEPTH],
            None => self.ommers[DEPTH],
        }
    }
}

/// The roots of the empty subtrees of the levels below the root.
const EMPTY_ROOTS_BELOW: [Fp; DEPTH] = {
    let mut roots = [Fp::ZERO; DEPTH];
    let mut level = 0;
    while level < DEPTH {
        roots[level] = EMPTY_ROOTS[level];
        level += 1;
    }
    roots
};

/// The root of a subtree of height `height` whose first `size` leaves are
/// committed (fewer than all of them), given the left siblings waiting at
/// each level; `None` if there is none.
fn partial_root(ommers: &[Fp], size: u64, height: usize) -> Option<Fp> {
    // `node` is the root of the rightmost, partly filled subtree of each
    // level; while it is still empty no hashing is needed
    let mut node = None;
    for (level, empty) in EMPTY_ROOTS[..height].iter().enumerate() {
        node = if (size >> level) & 1 == 1 {
            let right = node.unwrap_or(*empty);
            Some(merkle_crh(level, &ommers[level], &right))
        } else {
            node.map(|n| merkle_crh(level, &n, empty))
        };
    }
    node
}

/// The left edge of a subtree being filled: as a [`Frontier`], for the
/// subtree to the right of a witnessed leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Subtree {
    size: u64,
    ommers: [Fp; DEPTH],
}

impl Subtree {
    const fn new() -> Self {
        Subtree {
            size: 0,
            ommers: [Fp::ZERO; DEPTH],
        }
    }

    /// Appends a leaf to a subtree of height `height` (which must not be
    /// full); returns its root if that completes it.
    fn append(&mut self, cmx: Fp, height: usize) -> Option<Fp> {
        let mut node = cmx;
        for level in 0..height {
            if (self.size >> level) & 1 == 0 {
                self.ommers[level] = node;
                self.size += 1;
                return None;
            }
            node = merkle_crh(level, &self.ommers[level], &node);
        }
        Some(node)
    }
}

/// The authentication path of one leaf of the note commitment tree, kept
/// up to date as the tree grows: made by [`Frontier::append_witnessed`]
/// when the leaf is appended, and given every commitment appended to the
/// tree after it ([`IncrementalWitness::append`]), each of which costs one
/// hash on average. Of constant size.
///
/// The path and the root it leads to are those of the tree after the last
/// commitment given: [`IncrementalWitness::path`] is what `witness`
/// (with `alloc`) computes from all the leaves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncrementalWitness {
    cmx: Fp,
    position: u32,
    /// The siblings: those on the left, and the roots of the subtrees on
    /// the right that are complete; the others are empty.
    auth_path: [Fp; DEPTH],
    /// The number of leaves of the tree.
    size: u64,
    /// The level of the first sibling on the right that is not complete
    /// (32 if there is none): the subtrees on the right fill up in order
    /// of level.
    cursor_level: usize,
    /// The leaves of that subtree so far.
    cursor: Subtree,
}

impl IncrementalWitness {
    /// The position of the leaf.
    pub fn position(&self) -> u32 {
        self.position
    }

    /// The leaf: the commitment the witness is for.
    pub fn cmx(&self) -> Fp {
        self.cmx
    }

    /// The number of commitments of the tree the witness is up to date
    /// with: those before the leaf, the leaf, and those appended since.
    pub fn tree_size(&self) -> u64 {
        self.size
    }

    /// Takes the next commitment appended to the tree.
    pub fn append(&mut self, cmx: Fp) -> Result<(), Error> {
        if self.cursor_level >= DEPTH {
            // every sibling is complete: the leaf was the last but those
            return Err(Error::TreeFull);
        }
        if let Some(root) = self.cursor.append(cmx, self.cursor_level) {
            self.auth_path[self.cursor_level] = root;
            self.cursor = Subtree::new();
            // the next sibling on the right
            let above = self.position >> self.cursor_level >> 1;
            self.cursor_level += 1 + above.trailing_ones() as usize;
        }
        self.size += 1;
        Ok(())
    }

    /// The authentication path of the leaf in the tree as it stands.
    pub fn path(&self) -> MerklePath {
        let mut auth_path = self.auth_path;
        if self.cursor_level < DEPTH
            && let Some(root) =
                partial_root(&self.cursor.ommers, self.cursor.size, self.cursor_level)
        {
            auth_path[self.cursor_level] = root;
        }
        MerklePath {
            position: self.position,
            auth_path,
        }
    }

    /// The root of the tree as it stands (the anchor to spend the note
    /// with).
    pub fn root(&self) -> Fp {
        self.path().root(self.cmx)
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
/// This hashes the whole tree; a wallet tracking notes over a growing tree
/// keeps an [`IncrementalWitness`] for each instead.
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
