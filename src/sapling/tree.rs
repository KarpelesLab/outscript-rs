//! The Sapling note commitment tree (protocol specification §4.9 and
//! §5.4.1.3): an incremental Merkle tree of depth 32 whose leaves are note
//! commitments (`cmu`) and whose nodes are Pedersen hashes.
//!
//! Nothing here allocates. A [`Frontier`] is the right edge of the tree,
//! which is all that is needed to append leaves and compute roots (it is
//! what `zcashd` and `lightwalletd` exchange as a "commitment tree"). A
//! [`Witness`] follows the tree from the moment a note is appended and
//! yields the [`MerklePath`] of that note against any later root, which is
//! what a Spend proof takes.
//!
//! Levels count from the leaves: level 0 is the leaf level, and
//! [`merkle_crh`]`(0, ..)` hashes two leaves. The types take the depth as a
//! parameter, which defaults to the consensus depth [`DEPTH`]; smaller trees
//! are for tests.

use super::Error;
use super::pedersen::{bits_le, bits_le_u64, pedersen_hash_vartime};

/// The depth of the Sapling note commitment tree.
pub const DEPTH: usize = 32;

/// A node of the tree: the little-endian encoding of a field element (the
/// `u` coordinate of a Pedersen hash, or a note commitment `cmu`).
pub type Node = [u8; 32];

/// The value of a leaf that holds no note commitment: the field element 1.
pub const UNCOMMITTED: Node = {
    let mut node = [0u8; 32];
    node[0] = 1;
    node
};

/// `MerkleCRH^Sapling(layer, left, right)` for two nodes at `level` (0 for
/// leaves): the Pedersen hash of the level as six bits, then the low 255
/// bits of each child. In the specification's numbering, where the root is
/// layer 0, this is layer `31 - level`.
///
/// Tree nodes are public, so this is not constant time.
pub fn merkle_crh(level: usize, left: &Node, right: &Node) -> Node {
    debug_assert!(level < 63);
    pedersen_hash_vartime(
        bits_le_u64(level as u64, 6)
            .chain(bits_le(left).take(255))
            .chain(bits_le(right).take(255)),
    )
    .to_bytes()
}

/// The roots of the empty subtrees: `EMPTY_ROOTS[level]` is the root of a
/// subtree of height `level` without any note commitment, so
/// `EMPTY_ROOTS[0]` is [`UNCOMMITTED`] and `EMPTY_ROOTS[32]` is the root of
/// the empty Sapling tree.
pub const EMPTY_ROOTS: [Node; DEPTH + 1] = [
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    [
        0x81, 0x7d, 0xe3, 0x6a, 0xb2, 0xd5, 0x7f, 0xeb, 0x07, 0x76, 0x34, 0xbc, 0xa7, 0x78, 0x19,
        0xc8, 0xe0, 0xbd, 0x29, 0x8c, 0x04, 0xf6, 0xfe, 0xd0, 0xe6, 0xa8, 0x3c, 0xc1, 0x35, 0x6c,
        0xa1, 0x55,
    ],
    [
        0xff, 0xe9, 0xfc, 0x03, 0xf1, 0x8b, 0x17, 0x6c, 0x99, 0x88, 0x06, 0x43, 0x9f, 0xf0, 0xbb,
        0x8a, 0xd1, 0x93, 0xaf, 0xdb, 0x27, 0xb2, 0xcc, 0xbc, 0x88, 0x85, 0x69, 0x16, 0xdd, 0x80,
        0x4e, 0x34,
    ],
    [
        0xd8, 0x28, 0x33, 0x86, 0xef, 0x2e, 0xf0, 0x7e, 0xbd, 0xbb, 0x43, 0x83, 0xc1, 0x2a, 0x73,
        0x9a, 0x95, 0x3a, 0x4d, 0x6e, 0x0d, 0x6f, 0xb1, 0x13, 0x9a, 0x40, 0x36, 0xd6, 0x93, 0xbf,
        0xbb, 0x6c,
    ],
    [
        0xe1, 0x10, 0xde, 0x65, 0xc9, 0x07, 0xb9, 0xde, 0xa4, 0xae, 0x0b, 0xd8, 0x3a, 0x4b, 0x0a,
        0x51, 0xbe, 0xa1, 0x75, 0x64, 0x6a, 0x64, 0xc1, 0x2b, 0x4c, 0x9f, 0x93, 0x1b, 0x2c, 0xb3,
        0x1b, 0x49,
    ],
    [
        0x91, 0x2d, 0x82, 0xb2, 0xc2, 0xbc, 0xa2, 0x31, 0xf7, 0x1e, 0xfc, 0xf6, 0x17, 0x37, 0xfb,
        0xf0, 0xa0, 0x8b, 0xef, 0xa0, 0x41, 0x62, 0x15, 0xae, 0xef, 0x53, 0xe8, 0xbb, 0x6d, 0x23,
        0x39, 0x0a,
    ],
    [
        0x8a, 0xc9, 0xcf, 0x9c, 0x39, 0x1e, 0x3f, 0xd4, 0x28, 0x91, 0xd2, 0x72, 0x38, 0xa8, 0x1a,
        0x8a, 0x5c, 0x1d, 0x3a, 0x72, 0xb1, 0xbc, 0xbe, 0xa8, 0xcf, 0x44, 0xa5, 0x8c, 0xe7, 0x38,
        0x96, 0x13,
    ],
    [
        0xd6, 0xc6, 0x39, 0xac, 0x24, 0xb4, 0x6b, 0xd1, 0x93, 0x41, 0xc9, 0x1b, 0x13, 0xfd, 0xca,
        0xb3, 0x15, 0x81, 0xdd, 0xaf, 0x7f, 0x14, 0x11, 0x33, 0x6a, 0x27, 0x1f, 0x3d, 0x0a, 0xa5,
        0x28, 0x13,
    ],
    [
        0x7b, 0x99, 0xab, 0xdc, 0x37, 0x30, 0x99, 0x1c, 0xc9, 0x27, 0x47, 0x27, 0xd7, 0xd8, 0x2d,
        0x28, 0xcb, 0x79, 0x4e, 0xdb, 0xc7, 0x03, 0x4b, 0x4f, 0x00, 0x53, 0xff, 0x7c, 0x4b, 0x68,
        0x04, 0x44,
    ],
    [
        0x43, 0xff, 0x54, 0x57, 0xf1, 0x3b, 0x92, 0x6b, 0x61, 0xdf, 0x55, 0x2d, 0x4e, 0x40, 0x2e,
        0xe6, 0xdc, 0x14, 0x63, 0xf9, 0x9a, 0x53, 0x5f, 0x9a, 0x71, 0x34, 0x39, 0x26, 0x4d, 0x5b,
        0x61, 0x6b,
    ],
    [
        0xba, 0x49, 0xb6, 0x59, 0xfb, 0xd0, 0xb7, 0x33, 0x42, 0x11, 0xea, 0x6a, 0x9d, 0x9d, 0xf1,
        0x85, 0xc7, 0x57, 0xe7, 0x0a, 0xa8, 0x1d, 0xa5, 0x62, 0xfb, 0x91, 0x2b, 0x84, 0xf4, 0x9b,
        0xce, 0x72,
    ],
    [
        0x47, 0x77, 0xc8, 0x77, 0x6a, 0x3b, 0x1e, 0x69, 0xb7, 0x3a, 0x62, 0xfa, 0x70, 0x1f, 0xa4,
        0xf7, 0xa6, 0x28, 0x2d, 0x9a, 0xee, 0x2c, 0x7a, 0x6b, 0x82, 0xe7, 0x93, 0x7d, 0x70, 0x81,
        0xc2, 0x3c,
    ],
    [
        0xec, 0x67, 0x71, 0x14, 0xc2, 0x72, 0x06, 0xf5, 0xde, 0xbc, 0x1c, 0x1e, 0xd6, 0x6f, 0x95,
        0xe2, 0xb1, 0x88, 0x5d, 0xa5, 0xb7, 0xbe, 0x3d, 0x73, 0x6b, 0x1d, 0xe9, 0x85, 0x79, 0x47,
        0x30, 0x48,
    ],
    [
        0x1b, 0x77, 0xda, 0xc4, 0xd2, 0x4f, 0xb7, 0x25, 0x8c, 0x3c, 0x52, 0x87, 0x04, 0xc5, 0x94,
        0x30, 0xb6, 0x30, 0x71, 0x8b, 0xec, 0x48, 0x64, 0x21, 0x83, 0x70, 0x21, 0xcf, 0x75, 0xda,
        0xb6, 0x51,
    ],
    [
        0xbd, 0x74, 0xb2, 0x5a, 0xac, 0xb9, 0x23, 0x78, 0xa8, 0x71, 0xbf, 0x27, 0xd2, 0x25, 0xcf,
        0xc2, 0x6b, 0xac, 0xa3, 0x44, 0xa1, 0xea, 0x35, 0xfd, 0xd9, 0x45, 0x10, 0xf3, 0xd1, 0x57,
        0x08, 0x2c,
    ],
    [
        0xd6, 0xac, 0xde, 0xdf, 0x95, 0xf6, 0x08, 0xe0, 0x9f, 0xa5, 0x3f, 0xb4, 0x3d, 0xcd, 0x09,
        0x90, 0x47, 0x57, 0x26, 0xc5, 0x13, 0x12, 0x10, 0xc9, 0xe5, 0xca, 0xea, 0xb9, 0x7f, 0x0e,
        0x64, 0x2f,
    ],
    [
        0x1e, 0xa6, 0x67, 0x5f, 0x95, 0x51, 0xee, 0xb9, 0xdf, 0xaa, 0xa9, 0x24, 0x7b, 0xc9, 0x85,
        0x82, 0x70, 0xd3, 0xd3, 0xa4, 0xc5, 0xaf, 0xa7, 0x17, 0x7a, 0x98, 0x4d, 0x5e, 0xd1, 0xbe,
        0x24, 0x51,
    ],
    [
        0x6e, 0xdb, 0x16, 0xd0, 0x19, 0x07, 0xb7, 0x59, 0x97, 0x7d, 0x76, 0x50, 0xda, 0xd7, 0xe3,
        0xec, 0x04, 0x9a, 0xf1, 0xa3, 0xd8, 0x75, 0x38, 0x0b, 0x69, 0x7c, 0x86, 0x2c, 0x9e, 0xc5,
        0xd5, 0x1c,
    ],
    [
        0xcd, 0x1c, 0x8d, 0xbf, 0x6e, 0x3a, 0xcc, 0x7a, 0x80, 0x43, 0x9b, 0xc4, 0x96, 0x2c, 0xf2,
        0x5b, 0x9d, 0xce, 0x7c, 0x89, 0x6f, 0x3a, 0x5b, 0xd7, 0x08, 0x03, 0xfc, 0x5a, 0x0e, 0x33,
        0xcf, 0x00,
    ],
    [
        0x6a, 0xca, 0x84, 0x48, 0xd8, 0x26, 0x3e, 0x54, 0x7d, 0x5f, 0xf2, 0x95, 0x0e, 0x2e, 0xd3,
        0x83, 0x9e, 0x99, 0x8d, 0x31, 0xcb, 0xc6, 0xac, 0x9f, 0xd5, 0x7b, 0xc6, 0x00, 0x2b, 0x15,
        0x92, 0x16,
    ],
    [
        0x8d, 0x5f, 0xa4, 0x3e, 0x5a, 0x10, 0xd1, 0x16, 0x05, 0xac, 0x74, 0x30, 0xba, 0x1f, 0x5d,
        0x81, 0xfb, 0x1b, 0x68, 0xd2, 0x9a, 0x64, 0x04, 0x05, 0x76, 0x77, 0x49, 0xe8, 0x41, 0x52,
        0x76, 0x73,
    ],
    [
        0x08, 0xee, 0xab, 0x0c, 0x13, 0xab, 0xd6, 0x06, 0x9e, 0x63, 0x10, 0x19, 0x7b, 0xf8, 0x0f,
        0x9c, 0x1e, 0xa6, 0xde, 0x78, 0xfd, 0x19, 0xcb, 0xae, 0x24, 0xd4, 0xa5, 0x20, 0xe6, 0xcf,
        0x30, 0x23,
    ],
    [
        0x07, 0x69, 0x55, 0x7b, 0xc6, 0x82, 0xb1, 0xbf, 0x30, 0x86, 0x46, 0xfd, 0x0b, 0x22, 0xe6,
        0x48, 0xe8, 0xb9, 0xe9, 0x8f, 0x57, 0xe2, 0x9f, 0x5a, 0xf4, 0x0f, 0x6e, 0xdb, 0x83, 0x3e,
        0x2c, 0x49,
    ],
    [
        0x4c, 0x69, 0x37, 0xd7, 0x8f, 0x42, 0x68, 0x5f, 0x84, 0xb4, 0x3a, 0xd3, 0xb7, 0xb0, 0x0f,
        0x81, 0x28, 0x56, 0x62, 0xf8, 0x5c, 0x6a, 0x68, 0xef, 0x11, 0xd6, 0x2a, 0xd1, 0xa3, 0xee,
        0x08, 0x50,
    ],
    [
        0xfe, 0xe0, 0xe5, 0x28, 0x02, 0xcb, 0x0c, 0x46, 0xb1, 0xeb, 0x4d, 0x37, 0x6c, 0x62, 0x69,
        0x7f, 0x47, 0x59, 0xf6, 0xc8, 0x91, 0x7f, 0xa3, 0x52, 0x57, 0x12, 0x02, 0xfd, 0x77, 0x8f,
        0xd7, 0x12,
    ],
    [
        0x16, 0xd6, 0x25, 0x29, 0x68, 0x97, 0x1a, 0x83, 0xda, 0x85, 0x21, 0xd6, 0x53, 0x82, 0xe6,
        0x1f, 0x01, 0x76, 0x64, 0x6d, 0x77, 0x1c, 0x91, 0x52, 0x8e, 0x32, 0x76, 0xee, 0x45, 0x38,
        0x3e, 0x4a,
    ],
    [
        0xd2, 0xe1, 0x64, 0x2c, 0x9a, 0x46, 0x22, 0x29, 0x28, 0x9e, 0x5b, 0x0e, 0x3b, 0x7f, 0x90,
        0x08, 0xe0, 0x30, 0x1c, 0xbb, 0x93, 0x38, 0x5e, 0xe0, 0xe2, 0x1d, 0xa2, 0x54, 0x50, 0x73,
        0xcb, 0x58,
    ],
    [
        0xa5, 0x12, 0x2c, 0x08, 0xff, 0x9c, 0x16, 0x1d, 0x9c, 0xa6, 0xfc, 0x46, 0x20, 0x73, 0x39,
        0x6c, 0x7d, 0x7d, 0x38, 0xe8, 0xee, 0x48, 0xcd, 0xb3, 0xbe, 0xa7, 0xe2, 0x23, 0x01, 0x34,
        0xed, 0x6a,
    ],
    [
        0x28, 0xe7, 0xb8, 0x41, 0xdc, 0xbc, 0x47, 0xcc, 0xeb, 0x69, 0xd7, 0xcb, 0x8d, 0x94, 0x24,
        0x5f, 0xb7, 0xcb, 0x2b, 0xa3, 0xa7, 0xa6, 0xbc, 0x18, 0xf1, 0x3f, 0x94, 0x5f, 0x7d, 0xbd,
        0x6e, 0x2a,
    ],
    [
        0xe1, 0xf3, 0x4b, 0x03, 0x4d, 0x4a, 0x3c, 0xd2, 0x85, 0x57, 0xe2, 0x90, 0x7e, 0xbf, 0x99,
        0x0c, 0x91, 0x8f, 0x64, 0xec, 0xb5, 0x0a, 0x94, 0xf0, 0x1d, 0x6f, 0xda, 0x5c, 0xa5, 0xc7,
        0xef, 0x72,
    ],
    [
        0x12, 0x93, 0x5f, 0x14, 0xb6, 0x76, 0x50, 0x9b, 0x81, 0xeb, 0x49, 0xef, 0x25, 0xf3, 0x92,
        0x69, 0xed, 0x72, 0x30, 0x92, 0x38, 0xb4, 0xc1, 0x45, 0x80, 0x35, 0x44, 0xb6, 0x46, 0xdc,
        0xa6, 0x2d,
    ],
    [
        0xb2, 0xee, 0xd0, 0x31, 0xd4, 0xd6, 0xa4, 0xf0, 0x2a, 0x09, 0x7f, 0x80, 0xb5, 0x4c, 0xc1,
        0x54, 0x1d, 0x41, 0x63, 0xc6, 0xb6, 0xf5, 0x97, 0x1f, 0x88, 0xb6, 0xe4, 0x1d, 0x35, 0xc5,
        0x38, 0x14,
    ],
    [
        0xfb, 0xc2, 0xf4, 0x30, 0x0c, 0x01, 0xf0, 0xb7, 0x82, 0x0d, 0x00, 0xe3, 0x34, 0x7c, 0x8d,
        0xa4, 0xee, 0x61, 0x46, 0x74, 0x37, 0x6c, 0xbc, 0x45, 0x35, 0x9d, 0xaa, 0x54, 0xf9, 0xb5,
        0x49, 0x3e,
    ],
];

/// Computes [`EMPTY_ROOTS`] (32 hashes).
pub fn compute_empty_roots() -> [Node; DEPTH + 1] {
    let mut roots = [UNCOMMITTED; DEPTH + 1];
    for level in 0..DEPTH {
        roots[level + 1] = merkle_crh(level, &roots[level], &roots[level]);
    }
    roots
}

/// The right edge of a note commitment tree of depth `D`: the last leaf
/// appended and the roots of the complete subtrees to its left. This is
/// enough to append further leaves and to compute the root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frontier<const D: usize = DEPTH> {
    /// The number of leaves in the tree.
    size: u64,
    /// The last leaf, at position `size - 1`.
    leaf: Node,
    /// For each bit `l` set in the last leaf's position, the left sibling of
    /// its ancestor at level `l`. The other entries are unspecified.
    ommers: [Node; D],
}

impl<const D: usize> Default for Frontier<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const D: usize> Frontier<D> {
    const CAPACITY: u64 = {
        assert!(D >= 1 && D <= DEPTH, "tree depth must be between 1 and 32");
        1 << D
    };

    /// The frontier of the empty tree.
    pub const fn new() -> Self {
        // rejects unsupported depths at compile time
        let _ = Self::CAPACITY;
        Frontier {
            size: 0,
            leaf: UNCOMMITTED,
            ommers: [UNCOMMITTED; D],
        }
    }

    /// The number of leaves appended so far.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Whether no leaf has been appended.
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// The last leaf appended, with its position.
    pub fn last(&self) -> Option<(u64, &Node)> {
        (self.size > 0).then(|| (self.size - 1, &self.leaf))
    }

    /// Appends a leaf (a note commitment `cmu`), returning its position.
    pub fn append(&mut self, leaf: &Node) -> Result<u64, Error> {
        if self.size >= Self::CAPACITY {
            return Err(Error::TreeFull);
        }
        if self.size > 0 {
            // The last leaf closes the subtrees below the lowest clear bit of
            // its position: fold them into the ommer the new leaf will need.
            let position = self.size - 1;
            let closed = position.trailing_ones() as usize;
            let mut cur = self.leaf;
            for (level, ommer) in self.ommers[..closed].iter().enumerate() {
                cur = merkle_crh(level, ommer, &cur);
            }
            self.ommers[closed] = cur;
        }
        self.leaf = *leaf;
        self.size += 1;
        Ok(self.size - 1)
    }

    /// The root of the subtree of height `level` that contains the last
    /// leaf, its missing leaves being uncommitted. `None` for an empty tree
    /// or a level above the depth.
    pub fn subtree_root(&self, level: usize) -> Option<Node> {
        if self.size == 0 || level > D {
            return None;
        }
        let position = self.size - 1;
        let mut cur = self.leaf;
        for (l, ommer) in self.ommers[..level].iter().enumerate() {
            cur = if (position >> l) & 1 == 1 {
                merkle_crh(l, ommer, &cur)
            } else {
                merkle_crh(l, &cur, &EMPTY_ROOTS[l])
            };
        }
        Some(cur)
    }

    /// The root of the tree (the anchor a Spend refers to).
    pub fn root(&self) -> Node {
        self.subtree_root(D).unwrap_or(EMPTY_ROOTS[D])
    }

    /// Appends a leaf and starts a [`Witness`] for it.
    pub fn append_witnessed(&mut self, leaf: &Node) -> Result<Witness<D>, Error> {
        let position = self.append(leaf)?;
        Ok(Witness {
            position,
            leaf: *leaf,
            // the entries for the set bits of the position are the left
            // siblings; the others are filled in as the tree grows
            path: self.ommers,
            filled: position as u32,
            frontier: *self,
        })
    }

    /// The length of [`write`](Self::write)'s output.
    pub fn serialized_len(&self) -> usize {
        let mut buf = [0u8; 2 + 66 + DEPTH * 33];
        self.write(&mut buf).unwrap_or(0)
    }

    /// Serializes the frontier in the "commitment tree" format of `zcashd`
    /// (and of `lightwalletd`'s `TreeState`): the optional left and right
    /// leaves of the last pair, then the optional parents from the bottom
    /// up. Returns the number of bytes written (at most 1124).
    pub fn write(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = NodeWriter { out, pos: 0 };
        let Some(position) = self.size.checked_sub(1) else {
            w.optional(None)?;
            w.optional(None)?;
            w.byte(0)?;
            return Ok(w.pos);
        };
        if position & 1 == 1 {
            w.optional(Some(&self.ommers[0]))?;
            w.optional(Some(&self.leaf))?;
        } else {
            w.optional(Some(&self.leaf))?;
            w.optional(None)?;
        }
        // the parents stop at the highest set bit of the position; their
        // count is a compact size below 253, so a single byte
        let parents = (64 - (position >> 1).leading_zeros()) as usize;
        let ommers = self.ommers.get(1..=parents).ok_or(Error::TreeFull)?;
        w.byte(parents as u8)?;
        for (i, ommer) in ommers.iter().enumerate() {
            w.optional(((position >> (i + 1)) & 1 == 1).then_some(ommer))?;
        }
        Ok(w.pos)
    }

    /// Parses the "commitment tree" format (see [`write`](Self::write)),
    /// which must fill `data` exactly.
    pub fn read(data: &[u8]) -> Result<Self, Error> {
        let mut data = data;
        fn optional(data: &mut &[u8]) -> Result<Option<Node>, Error> {
            let (&flag, rest) = data.split_first().ok_or(Error::UnexpectedEof)?;
            *data = rest;
            match flag {
                0 => Ok(None),
                1 => {
                    let (node, rest) =
                        data.split_first_chunk::<32>().ok_or(Error::UnexpectedEof)?;
                    *data = rest;
                    Ok(Some(*node))
                }
                _ => Err(Error::InvalidLength),
            }
        }
        let left = optional(&mut data)?;
        let right = optional(&mut data)?;
        let (&parents, rest) = data.split_first().ok_or(Error::UnexpectedEof)?;
        data = rest;
        let parents = parents as usize;
        // a parent at index i is an ommer at level i + 1
        if parents >= D {
            return Err(Error::InvalidLength);
        }
        let mut frontier = Self::new();
        let mut position = 0u64;
        match (left, right) {
            (None, None) => {
                if parents != 0 || !data.is_empty() {
                    return Err(Error::InvalidLength);
                }
                return Ok(frontier);
            }
            (None, Some(_)) => return Err(Error::InvalidLength),
            (Some(left), None) => frontier.leaf = left,
            (Some(left), Some(right)) => {
                frontier.ommers[0] = left;
                frontier.leaf = right;
                position |= 1;
            }
        }
        for level in 1..=parents {
            if let Some(node) = optional(&mut data)? {
                frontier.ommers[level] = node;
                position |= 1 << level;
            }
        }
        if !data.is_empty() {
            return Err(Error::TrailingData);
        }
        frontier.size = position + 1;
        Ok(frontier)
    }
}

/// Writes optional nodes into a caller's buffer.
struct NodeWriter<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl NodeWriter<'_> {
    fn byte(&mut self, b: u8) -> Result<(), Error> {
        *self.out.get_mut(self.pos).ok_or(Error::BufferTooSmall)? = b;
        self.pos += 1;
        Ok(())
    }

    fn optional(&mut self, node: Option<&Node>) -> Result<(), Error> {
        self.byte(u8::from(node.is_some()))?;
        if let Some(node) = node {
            self.out
                .get_mut(self.pos..self.pos + 32)
                .ok_or(Error::BufferTooSmall)?
                .copy_from_slice(node);
            self.pos += 32;
        }
        Ok(())
    }
}

/// The authentication path of a leaf: its position and the sibling of each
/// of its ancestors, from the leaf level up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerklePath<const D: usize = DEPTH> {
    /// The position of the leaf (its index among the leaves).
    pub position: u64,
    /// `siblings[l]` is the sibling of the leaf's ancestor at level `l`.
    pub siblings: [Node; D],
}

impl<const D: usize> MerklePath<D> {
    /// The root this path leads to from `leaf`.
    pub fn root(&self, leaf: &Node) -> Node {
        let mut cur = *leaf;
        for (level, sibling) in self.siblings.iter().enumerate() {
            cur = if (self.position >> level) & 1 == 1 {
                merkle_crh(level, sibling, &cur)
            } else {
                merkle_crh(level, &cur, sibling)
            };
        }
        cur
    }

    /// Checks that `leaf` is in the tree with root `anchor` at this
    /// position.
    pub fn verify(&self, leaf: &Node, anchor: &Node) -> Result<(), Error> {
        if D < 64 && self.position >> D != 0 {
            return Err(Error::InvalidPath);
        }
        if self.root(leaf) == *anchor {
            Ok(())
        } else {
            Err(Error::InvalidPath)
        }
    }
}

/// An incremental witness: the authentication path of one leaf, kept up to
/// date as leaves are appended after it.
///
/// Obtained from [`Frontier::append_witnessed`]; every leaf appended to the
/// tree afterwards must be given to [`append`](Self::append) as well, in
/// order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Witness<const D: usize = DEPTH> {
    position: u64,
    leaf: Node,
    path: [Node; D],
    /// Bit `l` is set once `path[l]` is final.
    filled: u32,
    /// The frontier of the tree as of the last leaf seen.
    frontier: Frontier<D>,
}

impl<const D: usize> Witness<D> {
    /// The position of the witnessed leaf.
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// The witnessed leaf.
    pub const fn leaf(&self) -> &Node {
        &self.leaf
    }

    /// The number of leaves in the tree this witness is current for.
    pub const fn tree_size(&self) -> u64 {
        self.frontier.size
    }

    /// The first leaf position of the sibling subtree at `level`, for a
    /// level where the witnessed leaf is on the left.
    fn sibling_start(&self, level: usize) -> u64 {
        ((self.position >> level) + 1) << level
    }

    /// Records the next leaf appended to the tree.
    pub fn append(&mut self, leaf: &Node) -> Result<(), Error> {
        let tip = self.frontier.append(leaf)?;
        for level in 0..D {
            if (self.filled >> level) & 1 == 1 {
                continue;
            }
            // the sibling subtree is complete once its last leaf arrives
            if tip == self.sibling_start(level) + (1 << level) - 1 {
                if let Some(root) = self.frontier.subtree_root(level) {
                    self.path[level] = root;
                    self.filled |= 1 << level;
                }
                break;
            }
        }
        Ok(())
    }

    /// The root of the tree as of the last leaf seen.
    pub fn root(&self) -> Node {
        self.frontier.root()
    }

    /// The authentication path of the witnessed leaf in the tree as of the
    /// last leaf seen; its root is [`root`](Self::root).
    pub fn path(&self) -> MerklePath<D> {
        let tip = self.frontier.size - 1;
        let mut siblings = self.path;
        for (level, sibling) in siblings.iter_mut().enumerate() {
            if (self.filled >> level) & 1 == 1 {
                continue;
            }
            *sibling = if tip < self.sibling_start(level) {
                EMPTY_ROOTS[level]
            } else {
                // partially filled: the tip is inside it
                self.frontier
                    .subtree_root(level)
                    .unwrap_or(EMPTY_ROOTS[level])
            };
        }
        MerklePath {
            position: self.position,
            siblings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(hex_str: &str) -> Node {
        hex::decode(hex_str).unwrap().try_into().unwrap()
    }

    fn strings(json: &str) -> Vec<String> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn empty_roots() {
        assert_eq!(EMPTY_ROOTS, compute_empty_roots());
        assert_eq!(Frontier::<DEPTH>::new().root(), EMPTY_ROOTS[DEPTH]);
    }

    /// From zcash-test-vectors' `sapling/merkle_tree.py`.
    #[test]
    fn merkle_crh_vector() {
        let rev = |s: &str| {
            let mut n = node(s);
            n.reverse();
            n
        };
        let a = rev("87a086ae7d2252d58729b30263fb7b66308bf94ef59a76c9c86e7ea016536505");
        let b = rev("a75b84a125b2353da7e8d96ee2a15efe4de23df9601b9d9564ba59de57130406");
        let c = rev("5bf43b5736c19b714d1f462c9d22ba3492c36e3d9bbd7ca24d94b440550aa561");
        assert_eq!(merkle_crh(25, &a, &b), c);
        assert_ne!(merkle_crh(26, &a, &b), c);
    }

    /// The depth-4 test tree of `zcashd` (`src/test/data/merkle_*_sapling.json`,
    /// used by `test_merkletree.cpp`): the root and serialization after each
    /// of 16 appends, and the path of every earlier leaf at every step.
    #[test]
    fn zcashd_test_tree() {
        let commitments = strings(include_str!("testdata/merkle_commitments_sapling.json"));
        let roots = strings(include_str!("testdata/merkle_roots_sapling.json"));
        let serializations = strings(include_str!("testdata/merkle_serialization_sapling.json"));
        let paths = strings(include_str!("testdata/merkle_path_sapling.json"));
        assert_eq!(commitments.len(), 16);
        let mut next_path = paths.iter();

        let mut tree = Frontier::<4>::new();
        assert_eq!(tree.root(), EMPTY_ROOTS[4]);
        let mut witnesses: Vec<Witness<4>> = Vec::new();
        for (i, commitment) in commitments.iter().enumerate() {
            // zcashd reads the commitments as uint256 hex, so byte-reversed
            let mut cm = node(commitment);
            cm.reverse();
            for witness in witnesses.iter_mut() {
                witness.append(&cm).unwrap();
            }
            witnesses.push(tree.append_witnessed(&cm).unwrap());
            assert_eq!(tree.size(), i as u64 + 1);
            assert_eq!(hex::encode(tree.root()), roots[i], "root {i}");

            let mut buf = [0u8; 256];
            let n = tree.write(&mut buf).unwrap();
            assert_eq!(hex::encode(&buf[..n]), serializations[i], "tree {i}");
            assert_eq!(tree.serialized_len(), n);
            let parsed = Frontier::<4>::read(&buf[..n]).unwrap();
            assert_eq!(parsed.root(), tree.root());
            assert_eq!(parsed.size(), tree.size());
            assert!(Frontier::<4>::read(&buf[..n - 1]).is_err());
            assert!(Frontier::<4>::read(&buf[..n + 1]).is_err());

            // zcashd's witnesses[k] follows leaf k - 1; at this step it has
            // paths for the leaves before the one just appended
            for witness in &witnesses[..i] {
                let expect = hex::decode(next_path.next().unwrap()).unwrap();
                let path = witness.path();
                // depth, then (length, node) from the root down, then the
                // position as a little-endian u64
                assert_eq!(expect.len(), 1 + 4 * 33 + 8);
                assert_eq!(expect[0], 4);
                for level in 0..4 {
                    let entry = &expect[1 + (3 - level) * 33..][..33];
                    assert_eq!(entry[0], 32);
                    assert_eq!(&entry[1..], &path.siblings[level], "step {i} level {level}");
                }
                assert_eq!(
                    u64::from_le_bytes(expect[133..].try_into().unwrap()),
                    path.position
                );
            }
            // a few of the paths, checked against the root
            for witness in witnesses.iter().skip(i % 3).step_by(5) {
                assert_eq!(witness.root(), tree.root());
                let path = witness.path();
                path.verify(witness.leaf(), &tree.root()).unwrap();
            }
        }
        assert!(next_path.next().is_none());
        let path = witnesses[3].path();
        assert_eq!(
            path.verify(&UNCOMMITTED, &tree.root()),
            Err(Error::InvalidPath)
        );
        let moved = MerklePath {
            position: path.position + 16,
            ..path
        };
        assert_eq!(
            moved.verify(witnesses[3].leaf(), &tree.root()),
            Err(Error::InvalidPath)
        );
        assert_eq!(tree.append(&UNCOMMITTED), Err(Error::TreeFull));
        assert_eq!(witnesses[0].append(&UNCOMMITTED), Err(Error::TreeFull));
    }

    #[test]
    fn full_depth_tree() {
        let mut tree = Frontier::<DEPTH>::new();
        let mut buf = [0u8; 1200];
        assert_eq!(tree.write(&mut buf), Ok(3));
        assert_eq!(Frontier::<DEPTH>::read(&buf[..3]), Ok(tree));
        let leaves: Vec<Node> = (1u8..=5)
            .map(|i| {
                let mut n = [0u8; 32];
                n[0] = i;
                n[5] = i;
                n
            })
            .collect();
        let mut witnesses = Vec::new();
        for leaf in &leaves {
            for w in witnesses.iter_mut() {
                Witness::append(w, leaf).unwrap();
            }
            witnesses.push(tree.append_witnessed(leaf).unwrap());
        }
        // the same root, built by hand: ((l0 l1) (l2 l3)) ((l4 ·) ·) ...
        let h01 = merkle_crh(0, &leaves[0], &leaves[1]);
        let h23 = merkle_crh(0, &leaves[2], &leaves[3]);
        let h4 = merkle_crh(0, &leaves[4], &EMPTY_ROOTS[0]);
        let left = merkle_crh(1, &h01, &h23);
        let right = merkle_crh(1, &h4, &EMPTY_ROOTS[1]);
        let mut root = merkle_crh(2, &left, &right);
        for (level, empty) in EMPTY_ROOTS.iter().enumerate().take(DEPTH).skip(3) {
            root = merkle_crh(level, &root, empty);
        }
        assert_eq!(tree.root(), root);
        for (i, w) in witnesses.iter().enumerate() {
            assert_eq!(w.position(), i as u64);
            assert_eq!(w.tree_size(), 5);
            w.path().verify(&leaves[i], &root).unwrap();
        }
        let n = tree.write(&mut buf).unwrap();
        let parsed = Frontier::<DEPTH>::read(&buf[..n]).unwrap();
        assert_eq!(parsed.root(), root);
        assert_eq!(tree.write(&mut buf[..n - 1]), Err(Error::BufferTooSmall));
        // malformed encodings are rejected without panicking
        for len in 0..n {
            assert!(Frontier::<DEPTH>::read(&buf[..len]).is_err());
        }
        assert!(Frontier::<DEPTH>::read(&[0, 1]).is_err());
        assert!(Frontier::<DEPTH>::read(&[2]).is_err());
        assert!(Frontier::<DEPTH>::read(&[0, 0, 1, 0]).is_err());
        assert!(Frontier::<4>::read(&[0, 0, 200]).is_err());
    }
}
