//! Decoy selection: choosing the other outputs of a ring the way the
//! reference wallet does (`gamma_picker` and `get_outs` of `wallet2.cpp`),
//! so that the transactions made with this crate do not stand out.
//!
//! The real output of a ring tends to be recent: the age at which outputs
//! are spent was measured (Möser et al., "An Empirical Analysis of
//! Traceability in the Monero Blockchain") and fits a gamma distribution of
//! the logarithm of the age in seconds, with shape 19.28 and rate 1.61. The
//! decoys are drawn from the same distribution, so that the real output is
//! not the odd one out.
//!
//! Everything here is computation on data the caller fetches: the
//! distribution of outputs over the blocks (the daemon's
//! `get_output_distribution`), then the keys of the candidates picked
//! (`get_outs`). The floating-point arithmetic is done with the basic
//! operations only, so it runs without `std`.

use super::Error;
use super::clsag::RingMember;
use crate::cryptonote::point_from_bytes;
use crate::prelude::*;

/// The shape of the gamma distribution of the logarithm of an output's age
/// when spent, in seconds.
const GAMMA_SHAPE: f64 = 19.28;
/// Its scale: one over the rate 1.61.
const GAMMA_SCALE: f64 = 1.0 / 1.61;
/// The seconds between blocks.
const BLOCK_TIME: u64 = 120;
/// The blocks an output must wait before it can be spent.
const SPENDABLE_AGE: usize = 10;
/// The blocks a coinbase output must wait.
const COINBASE_UNLOCK_WINDOW: usize = 60;
/// The age of the youngest output that can be spent, in seconds.
const UNLOCK_TIME: f64 = (SPENDABLE_AGE as u64 * BLOCK_TIME) as f64;
/// The seconds after unlocking in which an output picked younger than
/// spendable is placed.
const RECENT_SPEND_WINDOW: u64 = 15 * BLOCK_TIME;
/// The blocks of a year: the span over which the rate of new outputs is
/// averaged.
const BLOCKS_IN_A_YEAR: usize = (86400 * 365 / BLOCK_TIME) as usize;

// --- floating point without `std` ---
//
// `core` has the arithmetic of `f64` but not its functions. These are
// accurate to a few units in the last place over the ranges used here,
// which is far finer than the sampling they serve.

/// The high bits of ln(2), with trailing zeros so that its small multiples
/// are exact (6.93147180369123816490e-01).
const LN_2_HI: f64 = f64::from_bits(0x3fe6_2e42_fee0_0000);
/// The rest of ln(2) (1.90821492927058770002e-10).
const LN_2_LO: f64 = f64::from_bits(0x3dea_39ef_3579_3c76);
const LN_2: f64 = core::f64::consts::LN_2;

/// The square root of a positive, finite, normal number (zero otherwise):
/// Newton's iteration from an estimate with half the exponent.
pub(super) fn sqrt(x: f64) -> f64 {
    if !(x > 0.0 && x.is_finite()) {
        return 0.0;
    }
    let mut y = f64::from_bits((x.to_bits() >> 1) + (0x3ff0_0000_0000_0000u64 >> 1));
    for _ in 0..6 {
        y = 0.5 * (y + x / y);
    }
    y
}

/// The natural logarithm of a positive, finite, normal number.
pub(super) fn ln(x: f64) -> f64 {
    if !(x > 0.0 && x.is_finite()) {
        return f64::NEG_INFINITY;
    }
    let bits = x.to_bits();
    // The exponent field is 11 bits: it fits in an i64.
    let mut exponent = ((bits >> 52) & 0x7ff) as i64 - 1023;
    let mut mantissa = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000);
    if mantissa > core::f64::consts::SQRT_2 {
        mantissa *= 0.5;
        exponent += 1;
    }
    // ln(m) = 2 * atanh(s), s = (m - 1) / (m + 1), |s| < 0.172.
    let s = (mantissa - 1.0) / (mantissa + 1.0);
    let s2 = s * s;
    let mut sum = 0.0;
    let mut k = 25u32;
    while k >= 1 {
        sum = sum * s2 + 1.0 / f64::from(k);
        if k == 1 {
            break;
        }
        k -= 2;
    }
    let exponent = exponent as f64;
    2.0 * s * sum + exponent * LN_2_LO + exponent * LN_2_HI
}

/// The exponential, for arguments within ±700.
pub(super) fn exp(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    let x = x.clamp(-700.0, 700.0);
    // x = k * ln(2) + r, |r| <= ln(2) / 2.
    let scaled = x / LN_2;
    let k = (if scaled < 0.0 {
        scaled - 0.5
    } else {
        scaled + 0.5
    }) as i64;
    let r = (x - (k as f64) * LN_2_HI) - (k as f64) * LN_2_LO;
    let mut sum = 1.0;
    let mut n = 14u32;
    while n >= 1 {
        sum = 1.0 + sum * r / f64::from(n);
        n -= 1;
    }
    // |k| <= 1010: 2^k is a normal number.
    sum * f64::from_bits(((k + 1023) as u64) << 52)
}

// --- sampling ---

/// How many times a sampler tries again before deciding that the random
/// source is broken. Each try succeeds with a probability well over a half.
const MAX_TRIES: usize = 256;

fn random_u64(rng: &mut dyn FnMut(&mut [u8])) -> u64 {
    let mut bytes = [0u8; 8];
    rng(&mut bytes);
    u64::from_le_bytes(bytes)
}

/// A uniform number strictly between 0 and 1.
fn random_unit(rng: &mut dyn FnMut(&mut [u8])) -> f64 {
    const SCALE: f64 = 1.0 / (1u64 << 53) as f64;
    ((random_u64(rng) >> 11) as f64 + 0.5) * SCALE
}

/// A uniform integer below `bound`, without bias (`crypto::rand_idx`).
fn random_below(rng: &mut dyn FnMut(&mut [u8]), bound: u64) -> Result<u64, Error> {
    if bound <= 1 {
        return Ok(0);
    }
    let mask = u64::MAX >> (bound - 1).leading_zeros();
    for _ in 0..MAX_TRIES {
        let value = random_u64(rng) & mask;
        if value < bound {
            return Ok(value);
        }
    }
    Err(Error::BadRandomness)
}

/// A standard normal variate (Marsaglia's polar method).
pub(super) fn random_normal(rng: &mut dyn FnMut(&mut [u8])) -> Result<f64, Error> {
    for _ in 0..MAX_TRIES {
        let u = 2.0 * random_unit(rng) - 1.0;
        let v = 2.0 * random_unit(rng) - 1.0;
        let s = u * u + v * v;
        if s > 0.0 && s < 1.0 {
            return Ok(u * sqrt(-2.0 * ln(s) / s));
        }
    }
    Err(Error::BadRandomness)
}

/// A gamma variate of the given shape (at least 1) and scale (Marsaglia and
/// Tsang's method).
pub(super) fn random_gamma(
    rng: &mut dyn FnMut(&mut [u8]),
    shape: f64,
    scale: f64,
) -> Result<f64, Error> {
    let d = shape - 1.0 / 3.0;
    let c = 1.0 / sqrt(9.0 * d);
    for _ in 0..MAX_TRIES {
        let z = random_normal(rng)?;
        let v = 1.0 + c * z;
        if v <= 0.0 {
            continue;
        }
        let v = v * v * v;
        let u = random_unit(rng);
        if ln(u) < 0.5 * z * z + d - d * v + d * ln(v) {
            return Ok(d * v * scale);
        }
    }
    Err(Error::BadRandomness)
}

/// Picks decoys among the RingCT outputs of the chain (`gamma_picker`).
///
/// It is made from the cumulative distribution of RingCT outputs over the
/// blocks — entry `i` is the number of RingCT outputs in the chain up to and
/// including block `i` of the range — as the daemon's
/// `get_output_distribution` returns it for the amount 0 with
/// `cumulative` set, up to the top of the chain. The range should cover at
/// least the last year; the reference wallet asks for all of it.
///
/// The global indices handed out are positions in that count, so the
/// entries must count from the first RingCT output of the chain, as the
/// daemon's cumulative ones do whatever the height the range starts at.
/// (Without `cumulative`, the daemon gives the outputs of each block and,
/// apart, the `base` count before the range: sum them up from there.)
///
/// # Randomness
///
/// `rng` fills its argument with random bytes. They decide which outputs
/// hide the real one: a source an observer can predict or reproduce tells
/// them the decoys, and so the output being spent. A source that keeps
/// giving the same bytes is detected ([`Error::BadRandomness`]).
///
/// # Differences from the reference wallet
///
/// The picks have the distribution of the reference wallet's but not its
/// values for a given random stream: it draws its gamma variates with the
/// C++ standard library, whose algorithm and random engine are its own.
/// Here they come from Marsaglia and Tsang's method over normal variates
/// from the polar method, and the logarithm, exponential and square root
/// are computed in software, accurate to a few units in the last place.
///
/// ```
/// use outscript::monero::{DecoyCandidate, DecoyPicker, RING_SIZE, RingMember, build_ring};
/// # use outscript::cryptonote::{cn_fast_hash, hash_to_ec};
/// // A stand-in for a random source. Use a cryptographically secure one.
/// let mut state = [7u8; 32];
/// let mut rng = |out: &mut [u8]| {
///     for chunk in out.chunks_mut(32) {
///         state = cn_fast_hash(&state);
///         chunk.copy_from_slice(&state[..chunk.len()]);
///     }
/// };
/// // `get_output_distribution`: here, 1000 blocks of 20 outputs each.
/// let distribution: Vec<u64> = (1..=1000u64).map(|block| block * 20).collect();
/// let picker = DecoyPicker::new(&distribution)?;
/// assert_eq!(picker.num_outputs(), 991 * 20);
///
/// // The output being spent, and candidates to hide it among.
/// let real_index = 12_345;
/// let count = DecoyPicker::candidate_count(RING_SIZE);
/// let candidates = picker.select_candidates(real_index, count, &mut rng)?;
/// assert_eq!(candidates[0], real_index);
///
/// // `get_outs` for the candidates (asked for in increasing order, so that
/// // the daemon cannot tell the real one), here made up.
/// # let fetch = |index: u64| RingMember {
/// #     key: hash_to_ec(&index.to_le_bytes()),
/// #     commitment: hash_to_ec(&(!index).to_le_bytes()),
/// # };
/// let real = fetch(real_index);
/// let fetched: Vec<DecoyCandidate> = candidates
///     .iter()
///     .map(|index| DecoyCandidate { global_index: *index, member: fetch(*index), unlocked: true })
///     .collect();
/// let (ring, global_indices, real_position) = build_ring(real_index, &real, &fetched, RING_SIZE)?;
/// assert_eq!(ring.len(), RING_SIZE);
/// assert!(global_indices.is_sorted());
/// assert_eq!(global_indices[real_position], real_index);
/// assert_eq!(ring[real_position], real);
/// # Ok::<(), outscript::monero::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct DecoyPicker<'a> {
    /// The cumulative counts up to the last block whose outputs can be
    /// spent.
    offsets: &'a [u64],
    /// The number of outputs that can be spent.
    num_outputs: u64,
    /// The average time between two outputs over the last year, in seconds.
    average_output_time: f64,
}

impl<'a> DecoyPicker<'a> {
    /// A picker over the cumulative `distribution` of RingCT outputs, whose
    /// last entry is for the block at the top of the chain.
    ///
    /// Fails with [`Error::InvalidRing`] if the distribution covers ten
    /// blocks or fewer, is not cumulative (an entry below the one before),
    /// or has no output old enough to be spent.
    pub fn new(distribution: &'a [u64]) -> Result<Self, Error> {
        let blocks = distribution.len();
        let last = distribution.last().copied().unwrap_or(0);
        if blocks <= SPENDABLE_AGE || !distribution.is_sorted() {
            return Err(Error::InvalidRing);
        }
        let considered = blocks.min(BLOCKS_IN_A_YEAR);
        let before = match blocks.checked_sub(considered + 1) {
            Some(index) => distribution.get(index).copied().unwrap_or(0),
            None => 0,
        };
        let outputs_considered = last.saturating_sub(before);
        // The outputs of the last nine blocks are too young to be spent in
        // the next one.
        let offsets = distribution
            .get(..blocks - (SPENDABLE_AGE - 1))
            .ok_or(Error::InvalidRing)?;
        let num_outputs = offsets.last().copied().unwrap_or(0);
        if num_outputs == 0 || outputs_considered == 0 {
            return Err(Error::InvalidRing);
        }
        let average_output_time =
            (BLOCK_TIME * considered as u64) as f64 / outputs_considered as f64;
        Ok(DecoyPicker {
            offsets,
            num_outputs,
            average_output_time,
        })
    }

    /// The number of RingCT outputs that can be spent: a pick is below it.
    pub fn num_outputs(&self) -> u64 {
        self.num_outputs
    }

    /// Picks an output (`gamma_picker::pick`): its global index among the
    /// RingCT outputs, or `None` when the age drawn is beyond the start of
    /// the chain or falls on a block without outputs — pick again.
    ///
    /// An age is drawn from the gamma distribution; one below the ten
    /// blocks an output has to wait is replaced by a uniform one in the
    /// thirty minutes after them, since that is when such an output would
    /// have been spent. The age is turned into a number of outputs back
    /// from the youngest spendable one by the average rate of new outputs,
    /// and the pick is uniform among the outputs of the block that one is
    /// in.
    ///
    /// Fails with [`Error::BadRandomness`] if `rng` is stuck.
    pub fn pick(&self, rng: &mut dyn FnMut(&mut [u8])) -> Result<Option<u64>, Error> {
        let mut age = exp(random_gamma(rng, GAMMA_SHAPE, GAMMA_SCALE)?);
        if age > UNLOCK_TIME {
            age -= UNLOCK_TIME;
        } else {
            age = random_below(rng, RECENT_SPEND_WINDOW)? as f64;
        }
        // Saturates for an age beyond what a u64 holds.
        let back = (age / self.average_output_time) as u64;
        if back >= self.num_outputs {
            return Ok(None);
        }
        let output = self.num_outputs - 1 - back;
        // The first block whose count reaches the output.
        let block = self.offsets.partition_point(|count| *count < output);
        let Some(count) = self.offsets.get(block).copied() else {
            return Ok(None);
        };
        let first = match block.checked_sub(1) {
            Some(previous) => self.offsets.get(previous).copied().unwrap_or(0),
            None => 0,
        };
        let in_block = count.saturating_sub(first);
        if in_block == 0 {
            return Ok(None);
        }
        Ok(Some(first + random_below(rng, in_block)?))
    }

    /// The number of candidates the reference wallet asks the daemon about
    /// for a ring of `ring_size`: half as many again, plus one, since some
    /// may turn out not to be spendable yet, and fifty more for the blocks
    /// a coinbase output stays locked beyond the usual ten.
    pub fn candidate_count(ring_size: usize) -> usize {
        (ring_size.saturating_mul(3) / 2).saturating_add(1 + COINBASE_UNLOCK_WINDOW - SPENDABLE_AGE)
    }

    /// Chooses `count` distinct outputs to ask the daemon about for the ring
    /// of the output with the global index `real_index`: that one first,
    /// then decoys in the order they were picked, which
    /// [`build_ring`] wants kept.
    ///
    /// The order is a secret between the wallet and itself. Ask the daemon
    /// for the outputs in increasing order of index (as the reference
    /// wallet does), not in this one, which starts with the real output.
    ///
    /// When the chain has no more than `count` spendable outputs, all of
    /// them are returned.
    ///
    /// Fails with [`Error::InvalidRing`] if `real_index` is not a spendable
    /// output of the distribution, and [`Error::BadRandomness`] if `rng` is
    /// stuck.
    pub fn select_candidates(
        &self,
        real_index: u64,
        count: usize,
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Vec<u64>, Error> {
        if real_index >= self.num_outputs {
            return Err(Error::InvalidRing);
        }
        if self.num_outputs <= count as u64 {
            let others = (0..self.num_outputs).filter(|index| *index != real_index);
            return Ok(core::iter::once(real_index).chain(others).collect());
        }
        let mut picked = Vec::with_capacity(count);
        picked.push(real_index);
        // Sorted copies of the picks, to tell duplicates.
        let mut seen = Vec::with_capacity(count);
        seen.push(real_index);
        // A pick is new with a probability that only gets low when the
        // chain has few outputs: far more tries than that takes.
        let mut tries = count.saturating_mul(4 * MAX_TRIES);
        while picked.len() < count {
            tries = tries.checked_sub(1).ok_or(Error::BadRandomness)?;
            let Some(index) = self.pick(rng)? else {
                continue;
            };
            if let Err(position) = seen.binary_search(&index) {
                seen.insert(position, index);
                picked.push(index);
            }
        }
        Ok(picked)
    }
}

/// An output the daemon was asked about as a possible ring member
/// (`get_outs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoyCandidate {
    /// Its global index among the RingCT outputs.
    pub global_index: u64,
    /// Its public key and commitment (`key` and `mask`).
    pub member: RingMember,
    /// Whether it can be spent yet (`unlocked`).
    pub unlocked: bool,
}

/// Whether a key or commitment is a point of the prime-order subgroup.
fn in_main_subgroup(bytes: &[u8; 32]) -> bool {
    point_from_bytes(bytes).is_ok_and(|point| bool::from(point.is_torsion_free()))
}

/// Makes the ring of an input from the daemon's answer about the
/// candidates of [`DecoyPicker::select_candidates`], as the reference
/// wallet does: the real output, then the candidates in the order they
/// were picked, leaving out those that are locked, repeated, or whose key
/// or commitment is not in the prime-order subgroup, until the ring has
/// `ring_size` members; then sorted by global index.
///
/// `candidates` must be in picking order, and include the daemon's entry
/// for the real output itself (as the list of
/// [`DecoyPicker::select_candidates`] does), which is checked against
/// `real`.
///
/// Returns the ring, the global indices of its members and the position
/// of the real output: the `ring`, `global_indices` and `real_index` of a
/// `TransactionInput`.
///
/// Fails with [`Error::InvalidRing`] if there are not enough usable
/// candidates, and [`Error::KeyMismatch`] if the daemon's entry for the
/// real output is missing, is not the output the wallet knows, or says that
/// it is locked: a daemon that answers with made-up outputs could
/// otherwise tell the real one, the only one the wallet would not take
/// from its answer.
pub fn build_ring(
    real_index: u64,
    real: &RingMember,
    candidates: &[DecoyCandidate],
    ring_size: usize,
) -> Result<(Vec<RingMember>, Vec<u64>, usize), Error> {
    if ring_size == 0 {
        return Err(Error::InvalidRing);
    }
    let mut members: Vec<(u64, RingMember)> = Vec::with_capacity(ring_size);
    members.push((real_index, *real));
    let mut real_found = false;
    for candidate in candidates {
        if candidate.global_index == real_index {
            if candidate.member != *real || !candidate.unlocked {
                return Err(Error::KeyMismatch);
            }
            real_found = true;
            continue;
        }
        if members.len() >= ring_size {
            continue;
        }
        if !candidate.unlocked
            || members
                .iter()
                .any(|(index, _)| *index == candidate.global_index)
            || !in_main_subgroup(&candidate.member.key)
            || !in_main_subgroup(&candidate.member.commitment)
        {
            continue;
        }
        members.push((candidate.global_index, candidate.member));
    }
    if !real_found {
        return Err(Error::KeyMismatch);
    }
    if members.len() < ring_size {
        return Err(Error::InvalidRing);
    }
    members.sort_by_key(|(index, _)| *index);
    let real_position = members
        .iter()
        .position(|(index, _)| *index == real_index)
        .ok_or(Error::InvalidRing)?;
    let (indices, ring) = members.into_iter().unzip();
    Ok((ring, indices, real_position))
}
