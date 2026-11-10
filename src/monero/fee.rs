//! Transaction weights and fees, as the reference wallet computes them
//! (`estimate_tx_weight` and `calculate_fee_from_weight` of `wallet2.cpp`,
//! `get_transaction_weight` of `cryptonote_format_utils.cpp`).
//!
//! The fee of a transaction is its weight times the fee per byte the daemon
//! asks for (`get_fee_estimate`), rounded up to a multiple of the
//! quantization mask the daemon gives with it. The weight is the size in
//! bytes, plus a "clawback" for transactions with more than two outputs: an
//! aggregated range proof grows with the logarithm of the number of outputs
//! but costs a verifier time in proportion to it, so most of what the
//! aggregation saves in bytes is added back.

/// The ring size consensus requires since the 2022 network upgrade: the
/// output being spent and fifteen decoys.
pub const RING_SIZE: usize = 16;

/// The fee quantization mask daemons give (`quantization_mask` of
/// `get_fee_estimate`): fees are multiples of it. Prefer the daemon's value.
pub const FEE_QUANTIZATION_MASK: u64 = 10_000;

/// The number of scalars and points of a range proof besides its `L` and
/// `R`: 6 for Bulletproofs+, 9 for the original Bulletproofs.
const fn proof_fields(plus: bool) -> u64 {
    if plus { 6 } else { 9 }
}

/// `get_transaction_weight_clawback`: what the weight of a transaction with
/// a range proof padded to `padded_outputs` outputs (a power of two) adds
/// to its size; zero up to two outputs. `plus` tells Bulletproofs+ from
/// the original Bulletproofs.
pub(crate) fn weight_clawback(padded_outputs: u64, plus: bool) -> u64 {
    if padded_outputs <= 2 {
        return 0;
    }
    // The notional size of a proof for two outputs, per output.
    let base = 32 * (proof_fields(plus) + 7 * 2) / 2;
    let mut rounds = 6u64;
    let mut covered = 1u64;
    while covered < padded_outputs && rounds < 64 {
        covered = covered.saturating_mul(2);
        rounds += 1;
    }
    let size = 32 * (proof_fields(plus) + 2 * rounds);
    // Four fifths of what the aggregation saved.
    let saved = base.saturating_mul(padded_outputs).saturating_sub(size);
    saved.saturating_mul(4) / 5
}

/// `log2` of the smallest power of two that is at least `outputs`.
fn log_padded(outputs: u64) -> u64 {
    let mut log = 0u64;
    while log < 63 && (1u64 << log) < outputs {
        log += 1;
    }
    log
}

/// The reference wallet's estimate of the size in bytes of a transaction of
/// the current format (RingCT type 6: CLSAG, Bulletproofs+, view tags) with
/// `inputs` inputs of `ring_size` members each, `outputs` outputs and an
/// extra field of `extra_len` bytes (`estimate_tx_size`).
///
/// It is an estimate: what a varint takes depends on its value, and each
/// key offset of a ring, for one, is counted as two bytes. The transaction
/// built comes out within a few bytes per input and output of it.
pub fn estimate_tx_size(inputs: usize, ring_size: usize, outputs: usize, extra_len: usize) -> u64 {
    let (inputs, ring_size) = (inputs as u64, ring_size as u64);
    let (outputs, extra_len) = (outputs as u64, extra_len as u64);
    let mut size = 0u64;
    let mut add = |count: u64, each: u64| size = size.saturating_add(count.saturating_mul(each));
    // The prefix: version and unlock time, inputs, outputs, extra.
    add(1, 1 + 6);
    add(
        inputs,
        (1 + 6 + 32u64).saturating_add(ring_size.saturating_mul(2)),
    );
    add(outputs, 6 + 32);
    add(1, extra_len);
    // The RingCT type.
    add(1, 1);
    // The range proof.
    add(1, (2 * (6 + log_padded(outputs)) + 6) * 32 + 3);
    // The CLSAGs.
    add(inputs, ring_size.saturating_mul(32).saturating_add(64));
    // The view tags.
    add(outputs, 1);
    // The pseudo-outputs, the encrypted amounts, the commitments, the fee.
    add(inputs, 32);
    add(outputs, 8 + 32);
    add(1, 4);
    size
}

/// The reference wallet's estimate of the weight of a transaction of the
/// current format (`estimate_tx_weight`): [`estimate_tx_size`] plus the
/// clawback of a range proof over more than two outputs.
///
/// ```
/// use outscript::monero::{RING_SIZE, estimate_tx_size, estimate_tx_weight};
///
/// // Up to two outputs, the weight is the size.
/// assert_eq!(estimate_tx_weight(1, RING_SIZE, 2, 44), estimate_tx_size(1, RING_SIZE, 2, 44));
/// // More outputs weigh more than their bytes.
/// assert!(estimate_tx_weight(1, RING_SIZE, 16, 44) > estimate_tx_size(1, RING_SIZE, 16, 44));
/// ```
pub fn estimate_tx_weight(
    inputs: usize,
    ring_size: usize,
    outputs: usize,
    extra_len: usize,
) -> u64 {
    let size = estimate_tx_size(inputs, ring_size, outputs, extra_len);
    let outputs = outputs as u64;
    if outputs <= 2 {
        return size;
    }
    size.saturating_add(weight_clawback(1u64 << log_padded(outputs).max(2), true))
}

/// The fee of a transaction of `weight` at `fee_per_byte`, rounded up to a
/// multiple of `quantization_mask` (`calculate_fee_from_weight`). Both
/// come from the daemon's `get_fee_estimate`.
///
/// Returns `None` if the mask is zero or the fee does not fit in 64 bits.
///
/// ```
/// use outscript::monero::{FEE_QUANTIZATION_MASK, calculate_fee_from_weight};
///
/// let fee = calculate_fee_from_weight(20_000, 2_229, FEE_QUANTIZATION_MASK);
/// assert_eq!(fee, Some(44_580_000));
/// assert_eq!(calculate_fee_from_weight(20_001, 2_229, 10_000), Some(44_590_000));
/// ```
pub fn calculate_fee_from_weight(
    fee_per_byte: u64,
    weight: u64,
    quantization_mask: u64,
) -> Option<u64> {
    let fee = weight.checked_mul(fee_per_byte)?;
    fee.checked_add(quantization_mask.checked_sub(1)?)?
        .checked_div(quantization_mask)?
        .checked_mul(quantization_mask)
}

/// The fee the reference wallet would pay for a transaction of the current
/// format: [`calculate_fee_from_weight`] of [`estimate_tx_weight`].
///
/// The reference wallet uses this to choose the inputs, builds the
/// transaction with it, and then pays for what the transaction really
/// weighs: it builds it again with
/// [`calculate_fee_from_weight`] of its `Transaction::weight`, until the
/// fee covers the weight. Paying exactly what it pays is part of not
/// standing out, so do the same.
///
/// Returns `None` if the mask is zero or the fee does not fit in 64 bits.
///
/// ```
/// use outscript::monero::{FEE_QUANTIZATION_MASK, RING_SIZE, estimate_fee};
///
/// // Two inputs, two outputs, the usual extra field (a public key and an
/// // encrypted payment id), at 20000 piconero per byte.
/// let fee = estimate_fee(20_000, FEE_QUANTIZATION_MASK, 2, RING_SIZE, 2, 44);
/// assert_eq!(fee, Some(44_300_000));
/// ```
pub fn estimate_fee(
    fee_per_byte: u64,
    quantization_mask: u64,
    inputs: usize,
    ring_size: usize,
    outputs: usize,
    extra_len: usize,
) -> Option<u64> {
    let weight = estimate_tx_weight(inputs, ring_size, outputs, extra_len);
    calculate_fee_from_weight(fee_per_byte, weight, quantization_mask)
}
