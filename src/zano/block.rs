//! Blocks: the header, the block as it is serialized, its id, the tree hash
//! of its transactions and the reward it may create
//! (`currency_basic.h`, `currency_format_utils_blocks.cpp`,
//! `get_block_reward`).

use crate::cryptonote::{cn_fast_hash_parts, push_varint};
use crate::prelude::*;

use super::Error;
use super::ser::{self, Reader, Wire, write_vec};
use super::tx::{Transaction, Variant};

/// `CURRENCY_BLOCK_FLAG_POS_BLOCK`: the block is a proof-of-stake one.
pub const BLOCK_FLAG_POS: u8 = 1;
/// `CURRENT_BLOCK_MAJOR_VERSION`: the highest major version a block may
/// have.
pub const BLOCK_MAJOR_VERSION_MAX: u8 = 3;
/// `CURRENCY_BLOCK_REWARD`: what a block creates, in atomic units — one
/// coin, whatever its height (but the first: [`PREMINE_AMOUNT`]).
pub const BLOCK_REWARD: u64 = 1_000_000_000_000;
/// `PREMINE_AMOUNT`: what the first block of the main network created.
pub const PREMINE_AMOUNT: u64 = 17_517_203_000_000_000_000;
/// `CURRENCY_BLOCK_GRANTED_FULL_REWARD_ZONE`: the size, in bytes, up to
/// which a block gets the whole reward whatever the sizes of the blocks
/// before it.
pub const BLOCK_GRANTED_FULL_REWARD_ZONE: u64 = 125_000;
/// `CURRENCY_REWARD_BLOCKS_WINDOW`: how many blocks before a block the
/// median size its reward depends on is taken over.
pub const REWARD_BLOCKS_WINDOW: usize = 400;

/// The header of a block (`block_header`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockHeader {
    /// The major version: 0 or 1 at first, 2 from hard fork 3 on, 3 from
    /// hard fork 4 on.
    pub major_version: u8,
    /// The nonce of the proof of work (zero in a proof-of-stake block).
    pub nonce: u64,
    /// The id of the block before.
    pub prev_id: [u8; 32],
    /// The minor version.
    pub minor_version: u8,
    /// The timestamp. For a proof-of-stake block it is the one of the stake
    /// kernel, a multiple of 15 seconds; the time the block was made at is
    /// in the extra of its first transaction.
    pub timestamp: u64,
    /// The flags ([`BLOCK_FLAG_POS`]).
    pub flags: u8,
}

impl Wire for BlockHeader {
    const MIN_SIZE: usize = 44;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let major_version = r.u8()?;
        if major_version > BLOCK_MAJOR_VERSION_MAX {
            return Err(Error::UnsupportedVersion);
        }
        Ok(BlockHeader {
            major_version,
            nonce: r.u64()?,
            prev_id: r.key()?,
            minor_version: u8::try_from(r.varint()?).map_err(|_| Error::InvalidEncoding)?,
            timestamp: r.varint()?,
            flags: r.u8()?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.major_version);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.prev_id);
        push_varint(out, u64::from(self.minor_version));
        push_varint(out, self.timestamp);
        out.push(self.flags);
    }
}

impl BlockHeader {
    /// Parses a header, which must take the whole of `data`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        ser::from_bytes(data)
    }

    /// Serializes the header.
    pub fn to_bytes(&self) -> Vec<u8> {
        ser::to_bytes(self)
    }
}

/// A block (`block`): its header, its first transaction — which creates the
/// reward and, in a proof-of-stake block, spends the stake — and the ids of
/// the other transactions.
///
/// ```
/// use outscript::zano::{Block, BlockHeader, Transaction, Variant};
///
/// let block = Block {
///     header: BlockHeader { major_version: 3, timestamp: 1_700_000_000, ..Default::default() },
///     miner_tx: Transaction {
///         version: 2,
///         vin: vec![Variant::Gen { height: 7 }],
///         ..Default::default()
///     },
///     tx_hashes: vec![[1; 32]],
/// };
/// let bytes = block.to_bytes();
/// assert_eq!(Block::from_bytes(&bytes)?, block);
/// assert_eq!(block.height(), Some(7));
/// assert!(!block.is_pos());
/// // The id covers the header, the transactions and their count.
/// let mut other = block.clone();
/// other.tx_hashes[0][0] ^= 1;
/// assert_ne!(other.id(), block.id());
/// # Ok::<(), outscript::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Block {
    /// The header.
    pub header: BlockHeader,
    /// The first transaction of the block.
    pub miner_tx: Transaction,
    /// The ids of the other transactions, in block order.
    pub tx_hashes: Vec<[u8; 32]>,
}

impl Wire for Block {
    const MIN_SIZE: usize = BlockHeader::MIN_SIZE + Transaction::MIN_SIZE + 1;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Block {
            header: Wire::read(r)?,
            miner_tx: Wire::read(r)?,
            tx_hashes: r.vec()?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.header.write(out);
        self.miner_tx.write(out);
        write_vec(out, &self.tx_hashes);
    }
}

impl Block {
    /// Parses a block, which must take the whole of `data`.
    ///
    /// Fails with [`Error::UnsupportedVersion`] for a major version above
    /// [`BLOCK_MAJOR_VERSION_MAX`] or a first transaction of a version this
    /// module does not know.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        ser::from_bytes(data)
    }

    /// Serializes the block.
    pub fn to_bytes(&self) -> Vec<u8> {
        ser::to_bytes(self)
    }

    /// The root of the tree hash of the transactions of the block, the
    /// first one included (`get_tx_tree_hash`).
    pub fn tx_tree_hash(&self) -> [u8; 32] {
        let mut ids = Vec::with_capacity(self.tx_hashes.len() + 1);
        ids.push(self.miner_tx.prefix_hash());
        ids.extend_from_slice(&self.tx_hashes);
        tree_hash(&ids)
    }

    /// What the id of the block hashes (`get_block_hashing_blob`): the
    /// header, the tree hash of the transactions and their count.
    pub fn hashing_blob(&self) -> Vec<u8> {
        let mut blob = self.header.to_bytes();
        blob.extend_from_slice(&self.tx_tree_hash());
        push_varint(&mut blob, self.tx_hashes.len() as u64 + 1);
        blob
    }

    /// The id of the block (`get_block_hash`): the Keccak-256 hash of the
    /// [hashing blob](Self::hashing_blob) with its length in front.
    ///
    /// (The proof of work — ProgPoWZ over the hash of that blob with a zero
    /// nonce — is not computed by this module.)
    pub fn id(&self) -> [u8; 32] {
        let blob = self.hashing_blob();
        let mut length = Vec::with_capacity(2);
        push_varint(&mut length, blob.len() as u64);
        cn_fast_hash_parts(&[&length, &blob])
    }

    /// Whether this is a proof-of-stake block (`is_pos_block`): its flag
    /// says so and its first transaction spends a stake.
    pub fn is_pos(&self) -> bool {
        self.header.flags & BLOCK_FLAG_POS != 0 && self.miner_tx.is_pos_coinbase()
    }

    /// The height of the block, which its first transaction states
    /// (`get_block_height`); `None` if that is not a coinbase transaction.
    pub fn height(&self) -> Option<u64> {
        match self.miner_tx.vin.first() {
            Some(Variant::Gen { height }) => Some(*height),
            _ => None,
        }
    }

    /// The key image of the stake of a proof-of-stake block.
    pub fn stake_key_image(&self) -> Option<&[u8; 32]> {
        if !self.is_pos() {
            return None;
        }
        self.miner_tx.vin.get(1)?.key_image()
    }
}

/// The root of CryptoNote's tree hash of `hashes` (`tree_hash`): the one
/// hash, the hash of the two, or the root of the binary tree whose first
/// level pairs the last hashes so that a power of two is left. All zeros
/// for no hash at all.
pub fn tree_hash(hashes: &[[u8; 32]]) -> [u8; 32] {
    let pair = |a: &[u8; 32], b: &[u8; 32]| cn_fast_hash_parts(&[a, b]);
    match hashes {
        [] => [0; 32],
        [one] => *one,
        [a, b] => pair(a, b),
        _ => {
            // The largest power of two below the count.
            let mut width = 1usize;
            while width * 2 < hashes.len() {
                width *= 2;
            }
            let kept = 2 * width - hashes.len();
            let mut level: Vec<[u8; 32]> = Vec::with_capacity(width);
            level.extend_from_slice(&hashes[..kept]);
            level.extend(
                hashes[kept..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|[a, b]| pair(a, b)),
            );
            while level.len() > 1 {
                level = level
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|[a, b]| pair(a, b))
                    .collect();
            }
            level[0]
        }
    }
}

/// The median of the sizes of the blocks before a block, as the reward
/// takes it (`misc_utils::median`): the middle one, or the mean of the two
/// middle ones rounded down; zero for none. `sizes` is sorted in place.
pub fn median_block_size(sizes: &mut [u64]) -> u64 {
    sizes.sort_unstable();
    let half = sizes.len() / 2;
    match sizes.len() {
        0 => 0,
        n if n % 2 == 1 => sizes[half],
        // Their sum, which a 64-bit daemon wraps, cannot overflow for real
        // sizes.
        _ => (sizes[half - 1].wrapping_add(sizes[half])) / 2,
    }
}

/// What a block at `height` may create, fees aside (`get_block_reward`):
/// [`BLOCK_REWARD`] if its size is not above the median — taken as at least
/// [`BLOCK_GRANTED_FULL_REWARD_ZONE`] — and less beyond, down to nothing
/// at twice the median:
/// `reward * (2 * median - size) * size / median^2`, rounded down. `None`
/// for a block of twice the median or more, which the chain does not
/// accept.
///
/// `median_size` is the [median](median_block_size) of the sizes of the
/// [`REWARD_BLOCKS_WINDOW`] blocks before; `block_size` the cumulative size
/// of the block: the sizes of its transactions, with that of the first
/// one if it is over 1100 bytes (before hard fork 6), or what the first
/// transaction states in its
/// [`CoinbaseBlockCumulativeSize`](Variant::CoinbaseBlockCumulativeSize)
/// entry (from hard fork 6 on).
///
/// Before hard fork 4 the first transaction also collects the fees of the
/// block; since then they are burnt.
///
/// ```
/// use outscript::zano::{BLOCK_REWARD, block_reward};
///
/// assert_eq!(block_reward(3_000_000, 0, 90_000), Some(BLOCK_REWARD));
/// assert_eq!(block_reward(3_000_000, 0, 187_500), Some(BLOCK_REWARD / 4 * 3));
/// assert_eq!(block_reward(3_000_000, 0, 250_000), None);
/// ```
pub fn block_reward(height: u64, median_size: u64, block_size: u64) -> Option<u64> {
    if height == 0 {
        return Some(PREMINE_AMOUNT);
    }
    let median = median_size.max(BLOCK_GRANTED_FULL_REWARD_ZONE);
    if block_size <= median {
        return Some(BLOCK_REWARD);
    }
    let twice = median.checked_mul(2)?;
    if block_size > twice {
        return None;
    }
    // The reference divides by the median as a 32-bit number.
    let divisor = u128::from(u32::try_from(median).ok()?);
    let multiplicand = u128::from((twice - block_size).checked_mul(block_size)?);
    let reward = u128::from(BLOCK_REWARD) * multiplicand / divisor / divisor;
    // A block that would create nothing is refused as well.
    u64::try_from(reward).ok().filter(|reward| *reward != 0)
}

/// Whether `hash` meets `difficulty` (`check_hash`): read as a big-endian
/// number, its product with the difficulty stays below `2^256`. It is what
/// the kernel hash of a stake had to meet before hard fork 4
/// ([`StakeContext::check_bare_kernel`](super::StakeContext::check_bare_kernel)),
/// and what the ProgPoWZ hash of a proof-of-work block has to (that hash is
/// not computed by this module).
pub fn check_hash(hash: &[u8; 32], difficulty: u128) -> bool {
    // The limbs of the hash, least significant first.
    let mut limbs = [0u64; 4];
    for (limb, bytes) in limbs.iter_mut().rev().zip(hash.as_chunks::<8>().0) {
        *limb = u64::from_be_bytes(*bytes);
    }
    let low = difficulty as u64;
    let high = (difficulty >> 64) as u64;
    // Schoolbook product of four limbs by two: six limbs, of which the two
    // highest must be zero.
    let mut product = [0u64; 6];
    for (i, limb) in limbs.iter().enumerate() {
        let mut carry = 0u128;
        for (j, factor) in [low, high].into_iter().enumerate() {
            let value = u128::from(*limb) * u128::from(factor) + u128::from(product[i + j]) + carry;
            product[i + j] = value as u64;
            carry = value >> 64;
        }
        product[i + 2] = carry as u64;
    }
    product[4] == 0 && product[5] == 0
}
