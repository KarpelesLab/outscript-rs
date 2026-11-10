//! The order `halo2_proofs`' `V1` floor planner sorts regions in.

use alloc::vec::Vec;

/// The indices of `keys` in the order the reference sorts them (ascending,
/// with its particular order among equal keys).
pub(crate) fn sorted_order(keys: &[usize]) -> Vec<usize> {
    // PLACEHOLDER: a stable sort, to be replaced by the exact port.
    let mut order: Vec<usize> = (0..keys.len()).collect();
    order.sort_by_key(|i| keys[*i]);
    order
}
