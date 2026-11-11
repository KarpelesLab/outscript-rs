//! Coinbase transactions: the input that spends nothing.
//!
//! A coinbase transaction is the first of a block and has one transparent
//! input, whose outpoint is null (an all-zero transaction id and the index
//! `0xffffffff`) and whose script is not run: it must start with the
//! height of the block, and the rest is the miner's. Its outputs create
//! the block subsidy and collect the fees of the block; what they must be
//! (funding streams, the lockbox) are rules about the block, for which see
//! [`subsidy`](super::subsidy).
//!
//! From NU5 the `nExpiryHeight` of a coinbase transaction must be the
//! height of its block (protocol specification, section 7.1.2), which makes
//! the ids of coinbase transactions distinct.

use super::{ZcashTx, ZcashTxIn};
use crate::Error;

/// The shortest script a coinbase input can have, in bytes.
pub const MIN_COINBASE_SCRIPT_LEN: usize = 2;

/// The longest script a coinbase input can have, in bytes.
pub const MAX_COINBASE_SCRIPT_LEN: usize = 100;

/// The index of the null outpoint a coinbase input spends.
pub const COINBASE_VOUT: u32 = u32::MAX;

/// The encoding of `height` that starts a coinbase script, and its length
/// (protocol specification, section 7.1.2, which matches BIP 34): for a
/// height from 1 to 16 the one byte `0x50 + height` (`OP_1` to `OP_16`);
/// otherwise the push of the height as a little-endian signed number of the
/// fewest bytes. `None` for height 0: the genesis block has no such script.
pub const fn coinbase_height_prefix(height: u32) -> Option<([u8; 6], usize)> {
    let mut out = [0u8; 6];
    if height == 0 {
        return None;
    }
    if height <= 16 {
        out[0] = 0x50 + height as u8;
        return Some((out, 1));
    }
    let bytes = height.to_le_bytes();
    let mut n = 4;
    while n > 1 && bytes[n - 1] == 0 {
        n -= 1;
    }
    let mut i = 0;
    while i < n {
        out[1 + i] = bytes[i];
        i += 1;
    }
    // a set high bit would make the number negative: one more zero byte
    if bytes[n - 1] & 0x80 != 0 {
        n += 1;
    }
    out[0] = n as u8;
    Some((out, 1 + n))
}

/// Writes the script of the coinbase input of the block at `height` into
/// `out` (at most [`MAX_COINBASE_SCRIPT_LEN`] bytes), and returns its
/// length: the encoding of the height ([`coinbase_height_prefix`])
/// followed by `extra`, the miner's own bytes (an extra nonce, a tag;
/// consensus does not interpret them, though miners make them pushes).
///
/// A script that would be a single byte (a height up to 16 and nothing
/// else) is completed with `OP_0`, as the reference does, since consensus
/// requires two bytes at least. [`Error::InvalidData`] for height 0,
/// [`Error::TooLarge`] for a script over the limit.
pub fn coinbase_script_sig_to_slice(
    height: u32,
    extra: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let (prefix, n) = coinbase_height_prefix(height).ok_or(Error::InvalidData)?;
    let pad = n + extra.len() < MIN_COINBASE_SCRIPT_LEN;
    let len = n + extra.len() + pad as usize;
    if len > MAX_COINBASE_SCRIPT_LEN {
        return Err(Error::TooLarge);
    }
    let out = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;
    out[..n].copy_from_slice(&prefix[..n]);
    out[n..n + extra.len()].copy_from_slice(extra);
    if pad {
        out[n] = 0;
    }
    Ok(len)
}

/// The height a coinbase script starts with, and the bytes that follow
/// it; `None` if the script does not start with the encoding
/// [`coinbase_height_prefix`] gives of a height (which consensus requires)
/// or has not a length consensus allows.
pub fn coinbase_script_height(script_sig: &[u8]) -> Option<(u32, &[u8])> {
    if !(MIN_COINBASE_SCRIPT_LEN..=MAX_COINBASE_SCRIPT_LEN).contains(&script_sig.len()) {
        return None;
    }
    let (&first, rest) = script_sig.split_first()?;
    let height = match first {
        0x51..=0x60 => (first - 0x50) as u32,
        1..=5 => {
            let bytes = rest.get(..first as usize)?;
            let mut value = 0u64;
            for (i, byte) in bytes.iter().enumerate() {
                value |= (*byte as u64) << (8 * i);
            }
            u32::try_from(value).ok()?
        }
        _ => return None,
    };
    // only the one encoding of each height is valid
    let (prefix, n) = coinbase_height_prefix(height)?;
    if script_sig.get(..n)? != &prefix[..n] {
        return None;
    }
    Some((height, &script_sig[n..]))
}

impl<'a> ZcashTxIn<'a> {
    /// The input of a coinbase transaction, with the given script
    /// ([`coinbase_script_sig_to_slice`]): the null outpoint, and the
    /// final sequence number.
    pub const fn coinbase(script_sig: &'a [u8]) -> Self {
        ZcashTxIn {
            txid: [0; 32],
            vout: COINBASE_VOUT,
            script_sig,
            sequence: u32::MAX,
        }
    }

    /// Whether this is the input of a coinbase transaction: its outpoint
    /// is null.
    pub fn is_coinbase(&self) -> bool {
        self.txid == [0; 32] && self.vout == COINBASE_VOUT
    }
}

impl ZcashTx<'_> {
    /// The height of the block a coinbase transaction is for, as its input
    /// states; `None` for a transaction that is not a coinbase one (one
    /// input, with a null outpoint) or whose script does not start with a
    /// height.
    pub fn coinbase_height(&self) -> Option<u32> {
        match self.inputs {
            [input] if input.is_coinbase() => {
                coinbase_script_height(input.script_sig).map(|(height, _)| height)
            }
            _ => None,
        }
    }
}
