//! BIP-341 taproot script trees, heap-free: leaf and branch hashes, merkle
//! roots and paths, output keys and control blocks.
//!
//! A script tree is a slice of [`TapLeaf`] in depth-first order, each with its
//! depth — the same shape as the BIP-371 `PSBT_OUT_TAP_TREE` field. A single
//! script is one leaf at depth 0; two scripts are two leaves at depth 1; and
//! so on:
//!
//! ```text
//!        root            leaves = [ (1, A), (2, B), (2, C) ]
//!       /    \
//!      A      *
//!            / \
//!           B   C
//! ```
//!
//! To pay to a tree, commit its [`tap_tree_root`] into the output key with
//! [`p2tr_script_pubkey`]. To spend through a leaf, the witness ends with the
//! leaf script and its [`control_block_to_slice`]; sign with the script-path
//! sighash ([`TaprootMidstate`](crate::btcraw::TaprootMidstate)) and the
//! untweaked key
//! ([`SecpPrivateKey::sign_schnorr`](crate::crypto::secp256k1::SecpPrivateKey::sign_schnorr)).
//! The key path stays available through
//! [`SecpPrivateKey::sign_taproot_with_root`](crate::crypto::secp256k1::SecpPrivateKey::sign_taproot_with_root).

pub use crate::Error;

use crate::btcvarint::BtcVarInt;
use crate::crypto::secp256k1::tagged_hash;
pub use crate::crypto::secp256k1::taproot_tweak_with_root;

/// The BIP-342 tapscript leaf version.
pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;
/// The deepest a leaf may sit in a script tree.
pub const MAX_TAPROOT_DEPTH: usize = 128;
/// The largest control block: a header byte, the internal key, and one node
/// per level of a maximally deep tree.
pub const MAX_CONTROL_BLOCK_LEN: usize = 33 + 32 * MAX_TAPROOT_DEPTH;

/// A script-tree leaf, positioned by its depth in a depth-first listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TapLeaf<'a> {
    /// Depth of the leaf: 0 for a lone script, at most [`MAX_TAPROOT_DEPTH`].
    pub depth: u8,
    /// Leaf version (even, and not 0x50): [`TAPSCRIPT_LEAF_VERSION`] for
    /// tapscript.
    pub leaf_version: u8,
    /// The leaf script.
    pub script: &'a [u8],
}

impl<'a> TapLeaf<'a> {
    /// A tapscript leaf at `depth`.
    pub const fn new(depth: u8, script: &'a [u8]) -> Self {
        TapLeaf {
            depth,
            leaf_version: TAPSCRIPT_LEAF_VERSION,
            script,
        }
    }

    /// The leaf's `TapLeaf` hash.
    pub fn hash(&self) -> [u8; 32] {
        tapleaf_hash(self.leaf_version, self.script)
    }
}

/// A leaf version is the control block's first byte with its parity bit
/// cleared, and must not collide with the annex tag.
fn check_leaf_version(v: u8) -> Result<(), Error> {
    if v & 1 != 0 || v == 0x50 {
        return Err(Error::InvalidData);
    }
    Ok(())
}

/// `tagged_hash("TapLeaf", leaf_version || compact_size(script) || script)`.
pub fn tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let (len_buf, len_len) = BtcVarInt(script.len() as u64).to_array();
    tagged_hash("TapLeaf", &[&[leaf_version], &len_buf[..len_len], script])
}

/// `tagged_hash("TapBranch", min(a, b) || max(a, b))`: branches hash their
/// children in lexicographic order, so a merkle path needs no left/right bits.
pub fn tapbranch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    if a <= b {
        tagged_hash("TapBranch", &[a, b])
    } else {
        tagged_hash("TapBranch", &[b, a])
    }
}

/// Splits a merkle path into its 32-byte nodes.
fn path_nodes(path: &[u8]) -> Result<impl Iterator<Item = &[u8; 32]>, Error> {
    let (nodes, rest) = path.as_chunks::<32>();
    if !rest.is_empty() {
        return Err(Error::InvalidLength);
    }
    if nodes.len() > MAX_TAPROOT_DEPTH {
        return Err(Error::TooLarge);
    }
    Ok(nodes.iter())
}

/// The merkle root reached from `leaf_hash` by combining it with each 32-byte
/// node of `path` (leaf to root, as stored in a control block).
pub fn merkle_root_from_path(leaf_hash: &[u8; 32], path: &[u8]) -> Result<[u8; 32], Error> {
    let mut node = *leaf_hash;
    for sibling in path_nodes(path)? {
        node = tapbranch_hash(&node, sibling);
    }
    Ok(node)
}

/// Folds a depth-first leaf listing into its root. When `target` names a
/// leaf, the siblings met on the way up from it are written to `path_out`
/// (leaf to root). Returns the root and the path length in bytes.
fn walk(
    leaves: &[TapLeaf<'_>],
    target: Option<usize>,
    path_out: &mut [u8],
) -> Result<([u8; 32], usize), Error> {
    #[derive(Clone, Copy)]
    struct Node {
        hash: [u8; 32],
        depth: u8,
        holds_target: bool,
    }
    // depths strictly increase up the stack, so it never outgrows the deepest
    // allowed leaf
    let mut stack = [Node {
        hash: [0u8; 32],
        depth: 0,
        holds_target: false,
    }; MAX_TAPROOT_DEPTH + 1];
    let mut len = 0usize;
    let mut path_len = 0usize;

    if target.is_some_and(|t| t >= leaves.len()) {
        return Err(Error::IndexOutOfRange);
    }
    for (i, leaf) in leaves.iter().enumerate() {
        check_leaf_version(leaf.leaf_version)?;
        if leaf.depth as usize > MAX_TAPROOT_DEPTH {
            return Err(Error::TooLarge);
        }
        // a depth-first listing never steps back above an unfinished subtree
        if len > 0 && leaf.depth < stack[len - 1].depth {
            return Err(Error::InvalidData);
        }
        stack[len] = Node {
            hash: leaf.hash(),
            depth: leaf.depth,
            holds_target: target == Some(i),
        };
        len += 1;
        // two finished subtrees at the same depth become their parent
        while len >= 2 && stack[len - 1].depth == stack[len - 2].depth {
            let (a, b) = (stack[len - 2], stack[len - 1]);
            if a.depth == 0 {
                return Err(Error::InvalidData);
            }
            if a.holds_target || b.holds_target {
                let sibling = if a.holds_target { b.hash } else { a.hash };
                path_out
                    .get_mut(path_len..path_len + 32)
                    .ok_or(Error::BufferTooSmall)?
                    .copy_from_slice(&sibling);
                path_len += 32;
            }
            stack[len - 2] = Node {
                hash: tapbranch_hash(&a.hash, &b.hash),
                depth: a.depth - 1,
                holds_target: a.holds_target || b.holds_target,
            };
            len -= 1;
        }
    }
    // a complete tree folds to a single node at depth 0
    if len != 1 || stack[0].depth != 0 {
        return Err(Error::InvalidData);
    }
    Ok((stack[0].hash, path_len))
}

/// The merkle root of a script tree given as a depth-first leaf listing.
/// Fails with [`Error::InvalidData`] if the depths do not describe a complete
/// binary tree.
pub fn tap_tree_root(leaves: &[TapLeaf<'_>]) -> Result<[u8; 32], Error> {
    walk(leaves, None, &mut []).map(|(root, _)| root)
}

/// Writes the merkle path of leaf `index` (its sibling hashes, leaf to root)
/// into `out`, returning its length: `32 * depth` bytes.
pub fn tap_tree_path(leaves: &[TapLeaf<'_>], index: usize, out: &mut [u8]) -> Result<usize, Error> {
    walk(leaves, Some(index), out).map(|(_, n)| n)
}

/// The scriptPubKey (`OP_1 <32-byte output key>`) of the taproot output with
/// the given x-only internal key, committing to `merkle_root` (`None` for a
/// key-path-only output).
pub fn p2tr_script_pubkey(
    internal_key: &[u8; 32],
    merkle_root: Option<&[u8; 32]>,
) -> Result<[u8; 34], Error> {
    let (output_key, _) = taproot_tweak_with_root(internal_key, merkle_root)?;
    let mut spk = [0u8; 34];
    spk[..2].copy_from_slice(&[0x51, 0x20]);
    spk[2..].copy_from_slice(&output_key);
    Ok(spk)
}

/// Writes the control block for spending leaf `index` of the tree `leaves`
/// under `internal_key` into `out`, returning its length
/// (`33 + 32 * depth`; [`MAX_CONTROL_BLOCK_LEN`] always suffices).
pub fn control_block_to_slice(
    internal_key: &[u8; 32],
    leaves: &[TapLeaf<'_>],
    index: usize,
    out: &mut [u8],
) -> Result<usize, Error> {
    let leaf = leaves.get(index).ok_or(Error::IndexOutOfRange)?;
    if out.len() < 33 {
        return Err(Error::BufferTooSmall);
    }
    let (root, path_len) = walk(leaves, Some(index), &mut out[33..])?;
    let (_, parity) = taproot_tweak_with_root(internal_key, Some(&root))?;
    out[0] = leaf.leaf_version | parity;
    out[1..33].copy_from_slice(internal_key);
    Ok(33 + path_len)
}

/// A parsed script-path control block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlBlock<'a> {
    /// The leaf version (the first byte without its parity bit).
    pub leaf_version: u8,
    /// Parity of the output key's Y coordinate (0 even, 1 odd).
    pub output_key_parity: u8,
    /// The x-only internal key.
    pub internal_key: [u8; 32],
    /// The merkle path: 32-byte sibling hashes, leaf to root.
    pub path: &'a [u8],
}

impl<'a> ControlBlock<'a> {
    /// Parses a control block: `33 + 32m` bytes with `m <= 128`.
    pub fn parse(data: &'a [u8]) -> Result<ControlBlock<'a>, Error> {
        let (head, path) = data.split_at_checked(33).ok_or(Error::InvalidLength)?;
        let _ = path_nodes(path)?; // length checks only
        let leaf_version = head[0] & 0xfe;
        check_leaf_version(leaf_version)?;
        Ok(ControlBlock {
            leaf_version,
            output_key_parity: head[0] & 1,
            internal_key: head[1..].try_into().expect("32 bytes"),
            path,
        })
    }

    /// The `TapLeaf` hash of `script` under this block's leaf version.
    pub fn leaf_hash(&self, script: &[u8]) -> [u8; 32] {
        tapleaf_hash(self.leaf_version, script)
    }

    /// The merkle root this block commits `script` to.
    pub fn merkle_root(&self, script: &[u8]) -> Result<[u8; 32], Error> {
        merkle_root_from_path(&self.leaf_hash(script), self.path)
    }

    /// Reports whether spending `script` with this block is valid for the
    /// output with x-only key `output_key` (the BIP-341 script-path check).
    pub fn verify(&self, script: &[u8], output_key: &[u8; 32]) -> bool {
        let Ok(root) = self.merkle_root(script) else {
            return false;
        };
        taproot_tweak_with_root(&self.internal_key, Some(&root))
            .is_ok_and(|(key, parity)| key == *output_key && parity == self.output_key_parity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{MAX_ADDRESS_LEN, encode_address_to_slice};

    const VECTORS: &str = include_str!("../testdata/bip341_wallet_vectors.json");

    fn arr32(v: &serde_json::Value) -> [u8; 32] {
        let mut a = [0u8; 32];
        hex::decode_to_slice(v.as_str().unwrap(), &mut a).unwrap();
        a
    }

    /// Flattens the vectors' nested script tree into (depth, version, script).
    fn flatten(tree: &serde_json::Value, depth: u8, out: &mut Vec<(u8, u8, Vec<u8>)>) {
        match tree {
            serde_json::Value::Array(children) => {
                for c in children {
                    flatten(c, depth + 1, out);
                }
            }
            leaf => out.push((
                depth,
                leaf["leafVersion"].as_u64().unwrap() as u8,
                hex::decode(leaf["script"].as_str().unwrap()).unwrap(),
            )),
        }
    }

    /// The BIP-341 wallet test vectors: leaf hashes, merkle roots, tweaked
    /// keys, scriptPubKeys, addresses and control blocks.
    #[test]
    fn bip341_script_pubkey_vectors() {
        let json: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let vectors = json["scriptPubKey"].as_array().unwrap();
        assert_eq!(vectors.len(), 7);
        for v in vectors {
            let internal = arr32(&v["given"]["internalPubkey"]);
            let mut owned = Vec::new();
            if !v["given"]["scriptTree"].is_null() {
                flatten(&v["given"]["scriptTree"], 0, &mut owned);
            }
            let leaves: Vec<TapLeaf<'_>> = owned
                .iter()
                .map(|(depth, leaf_version, script)| TapLeaf {
                    depth: *depth,
                    leaf_version: *leaf_version,
                    script,
                })
                .collect();

            let root = if leaves.is_empty() {
                assert!(v["intermediary"]["merkleRoot"].is_null());
                None
            } else {
                for (leaf, want) in leaves
                    .iter()
                    .zip(v["intermediary"]["leafHashes"].as_array().unwrap())
                {
                    assert_eq!(leaf.hash(), arr32(want));
                }
                let root = tap_tree_root(&leaves).unwrap();
                assert_eq!(root, arr32(&v["intermediary"]["merkleRoot"]));
                Some(root)
            };

            let (output_key, _) = taproot_tweak_with_root(&internal, root.as_ref()).unwrap();
            assert_eq!(output_key, arr32(&v["intermediary"]["tweakedPubkey"]));
            let spk = p2tr_script_pubkey(&internal, root.as_ref()).unwrap();
            assert_eq!(
                hex::encode(spk),
                v["expected"]["scriptPubKey"].as_str().unwrap()
            );
            let mut addr = [0u8; MAX_ADDRESS_LEN];
            let n = encode_address_to_slice("p2tr", &spk, "bitcoin", &mut addr).unwrap();
            assert_eq!(
                core::str::from_utf8(&addr[..n]).unwrap(),
                v["expected"]["bip350Address"].as_str().unwrap()
            );

            for (i, want) in v["expected"]["scriptPathControlBlocks"]
                .as_array()
                .into_iter()
                .flatten()
                .enumerate()
            {
                let mut cb = [0u8; MAX_CONTROL_BLOCK_LEN];
                let n = control_block_to_slice(&internal, &leaves, i, &mut cb).unwrap();
                assert_eq!(hex::encode(&cb[..n]), want.as_str().unwrap());
                assert_eq!(n, 33 + 32 * leaves[i].depth as usize);

                // and the block proves the leaf against the output key
                let parsed = ControlBlock::parse(&cb[..n]).unwrap();
                assert_eq!(parsed.leaf_version, leaves[i].leaf_version);
                assert_eq!(parsed.internal_key, internal);
                assert_eq!(parsed.merkle_root(leaves[i].script).unwrap(), root.unwrap());
                assert!(parsed.verify(leaves[i].script, &output_key));
                assert!(!parsed.verify(b"other script", &output_key));
                let mut path = [0u8; 32 * MAX_TAPROOT_DEPTH];
                let pn = tap_tree_path(&leaves, i, &mut path).unwrap();
                assert_eq!(&path[..pn], parsed.path);
            }
        }
    }

    #[test]
    fn rejects_malformed_trees() {
        let s: &[u8] = &[0x51];
        let leaf = |depth| TapLeaf::new(depth, s);
        assert_eq!(tap_tree_root(&[]), Err(Error::InvalidData));
        // incomplete: a lone leaf below the root, or a missing sibling
        assert_eq!(tap_tree_root(&[leaf(1)]), Err(Error::InvalidData));
        assert_eq!(tap_tree_root(&[leaf(1), leaf(2)]), Err(Error::InvalidData));
        // not depth-first / overfull
        assert_eq!(
            tap_tree_root(&[leaf(2), leaf(1), leaf(2)]),
            Err(Error::InvalidData)
        );
        assert_eq!(tap_tree_root(&[leaf(0), leaf(0)]), Err(Error::InvalidData));
        assert_eq!(
            tap_tree_root(&[leaf(1), leaf(1), leaf(1)]),
            Err(Error::InvalidData)
        );
        assert_eq!(tap_tree_root(&[leaf(129)]), Err(Error::TooLarge));
        // leaf versions: odd, and the annex tag
        for bad in [0xc1, 0x50] {
            let l = TapLeaf {
                depth: 0,
                leaf_version: bad,
                script: s,
            };
            assert_eq!(tap_tree_root(&[l]), Err(Error::InvalidData));
        }
        // well formed
        tap_tree_root(&[leaf(0)]).unwrap();
        tap_tree_root(&[leaf(1), leaf(2), leaf(2)]).unwrap();
        tap_tree_root(&[leaf(2), leaf(2), leaf(1)]).unwrap();

        let leaves = [leaf(1), leaf(1)];
        let key = [0x11u8; 32];
        let mut cb = [0u8; 65];
        assert_eq!(
            control_block_to_slice(&key, &leaves, 2, &mut cb),
            Err(Error::IndexOutOfRange)
        );
        assert_eq!(
            control_block_to_slice(&key, &leaves, 0, &mut cb[..64]),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(
            control_block_to_slice(&key, &leaves, 0, &mut cb[..32]),
            Err(Error::BufferTooSmall)
        );

        assert_eq!(ControlBlock::parse(&[0u8; 32]), Err(Error::InvalidLength));
        assert_eq!(ControlBlock::parse(&[0xc0; 34]), Err(Error::InvalidLength));
        assert_eq!(
            ControlBlock::parse(&[0xc0; 33 + 32 * 129]),
            Err(Error::TooLarge)
        );
        assert_eq!(ControlBlock::parse(&[0x50; 33]), Err(Error::InvalidData));
        assert_eq!(
            merkle_root_from_path(&key, &[0u8; 31]),
            Err(Error::InvalidLength)
        );
    }

    /// A deep, maximally unbalanced tree exercises the whole node stack.
    #[test]
    fn maximum_depth_tree() {
        let s: &[u8] = &[0x51];
        let mut leaves = [TapLeaf::new(0, s); MAX_TAPROOT_DEPTH + 1];
        for (i, l) in leaves.iter_mut().enumerate() {
            l.depth = (i + 1).min(MAX_TAPROOT_DEPTH) as u8;
        }
        let root = tap_tree_root(&leaves).unwrap();
        let key = [0x22u8; 32];
        // x = 0x22.. may not be on the curve; pick a real key instead
        let key = crate::crypto::secp256k1::SecpPrivateKey::from_bytes(&key)
            .unwrap()
            .xonly_public_key();
        let (output_key, _) = taproot_tweak_with_root(&key, Some(&root)).unwrap();
        let mut cb = [0u8; MAX_CONTROL_BLOCK_LEN];
        let last = leaves.len() - 1;
        let n = control_block_to_slice(&key, &leaves, last, &mut cb).unwrap();
        assert_eq!(n, MAX_CONTROL_BLOCK_LEN);
        assert!(
            ControlBlock::parse(&cb[..n])
                .unwrap()
                .verify(s, &output_key)
        );
        let n = control_block_to_slice(&key, &leaves, 0, &mut cb).unwrap();
        assert_eq!(n, 33 + 32);
        assert!(
            ControlBlock::parse(&cb[..n])
                .unwrap()
                .verify(s, &output_key)
        );
    }
}
