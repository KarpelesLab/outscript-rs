//! The order `halo2_proofs`' `V1` floor planner sorts regions in.
//!
//! The reference sorts its regions with `halo2_legacy_pdqsort::sort::quicksort`,
//! a frozen copy of the pattern-defeating quicksort that was
//! `core::slice::sort::quicksort` in Rust 1.56 to 1.80. That sort is unstable
//! but deterministic, and the order it leaves equal keys in decides where
//! regions land, so it is ported here move for move: every comparison is made
//! in the same situation and every element ends up where the original puts it.
//!
//! The elements are `(key, original index)` pairs, which are `Copy`; the
//! holes and raw pointer moves of the original become plain assignments.
//! Nothing here depends on the width of `usize`: the generator of
//! [`break_patterns`] and the limit of [`quicksort`] use 64-bit arithmetic on
//! every target, which is what the reference computes on the 64-bit machines
//! it is run on.

use alloc::vec::Vec;

/// A sorted element: its key and its index in the input.
type Elem = (usize, usize);

/// The indices of `keys` in the order the reference sorts them (ascending,
/// with its particular order among equal keys).
pub(crate) fn sorted_order(keys: &[usize]) -> Vec<usize> {
    let mut v: Vec<Elem> = keys.iter().copied().zip(0..).collect();
    quicksort(&mut v);
    v.into_iter().map(|e| e.1).collect()
}

/// The comparison of the sort: keys only, strictly less.
fn is_less(a: &Elem, b: &Elem) -> bool {
    a.0 < b.0
}

/// Shifts the first element to the right until it meets a greater or equal
/// one.
fn shift_head(v: &mut [Elem]) {
    let len = v.len();
    if len >= 2 && is_less(&v[1], &v[0]) {
        let tmp = v[0];
        let mut hole = 1;
        v[0] = v[1];
        for i in 2..len {
            if !is_less(&v[i], &tmp) {
                break;
            }
            v[i - 1] = v[i];
            hole = i;
        }
        v[hole] = tmp;
    }
}

/// Shifts the last element to the left until it meets a smaller or equal
/// one.
fn shift_tail(v: &mut [Elem]) {
    let len = v.len();
    if len >= 2 && is_less(&v[len - 1], &v[len - 2]) {
        let tmp = v[len - 1];
        let mut hole = len - 2;
        v[len - 1] = v[len - 2];
        for i in (0..len - 2).rev() {
            if !is_less(&tmp, &v[i]) {
                break;
            }
            v[i + 1] = v[i];
            hole = i;
        }
        v[hole] = tmp;
    }
}

/// Partially sorts a slice by shifting a few out-of-order elements around;
/// `true` when the slice ends up sorted.
fn partial_insertion_sort(v: &mut [Elem]) -> bool {
    // Maximum number of adjacent out-of-order pairs that get shifted.
    const MAX_STEPS: usize = 5;
    // Shorter slices are left alone.
    const SHORTEST_SHIFTING: usize = 50;

    let len = v.len();
    let mut i = 1;

    for _ in 0..MAX_STEPS {
        while i < len && !is_less(&v[i], &v[i - 1]) {
            i += 1;
        }
        if i == len {
            return true;
        }
        if len < SHORTEST_SHIFTING {
            return false;
        }
        v.swap(i - 1, i);
        shift_tail(&mut v[..i]);
        shift_head(&mut v[i..]);
    }

    false
}

/// Sorts a slice by insertion.
fn insertion_sort(v: &mut [Elem]) {
    for i in 1..v.len() {
        shift_tail(&mut v[..i + 1]);
    }
}

/// Restores the heap invariant `parent >= child` below `node`.
fn sift_down(v: &mut [Elem], mut node: usize) {
    loop {
        let left = 2 * node + 1;
        let right = 2 * node + 2;

        let greater = if right < v.len() && is_less(&v[left], &v[right]) {
            right
        } else {
            left
        };

        if greater >= v.len() || !is_less(&v[node], &v[greater]) {
            break;
        }

        v.swap(node, greater);
        node = greater;
    }
}

/// Sorts a slice with heapsort, the fallback after too many bad pivots.
fn heapsort(v: &mut [Elem]) {
    for i in (0..v.len() / 2).rev() {
        sift_down(v, i);
    }
    for i in (1..v.len()).rev() {
        v.swap(0, i);
        sift_down(&mut v[..i], 0);
    }
}

/// Partitions `v` into the elements smaller than `pivot` followed by the
/// others, block by block, and returns the number of smaller ones.
fn partition_in_blocks(v: &mut [Elem], pivot: &Elem) -> usize {
    // Number of elements in a typical block.
    const BLOCK: usize = 128;

    // The block on the left side, `v[l..l + block_l]`, and the offsets in it
    // of the elements that belong on the right, `offsets_l[start_l..end_l]`.
    let mut l = 0;
    let mut block_l = BLOCK;
    let mut start_l = 0;
    let mut end_l = 0;
    let mut offsets_l = [0u8; BLOCK];

    // The block on the right side, `v[r - block_r..r]`, and the offsets from
    // its end of the elements that belong on the left.
    let mut r = v.len();
    let mut block_r = BLOCK;
    let mut start_r = 0;
    let mut end_r = 0;
    let mut offsets_r = [0u8; BLOCK];

    loop {
        // The blocks are about to meet: size them to cover the gap exactly.
        let is_done = r - l <= 2 * BLOCK;

        if is_done {
            let mut rem = r - l;
            if start_l < end_l || start_r < end_r {
                rem -= BLOCK;
            }

            if start_l < end_l {
                block_r = rem;
            } else if start_r < end_r {
                block_l = rem;
            } else {
                block_l = rem / 2;
                block_r = rem - block_l;
            }
        }

        if start_l == end_l {
            // Trace `block_l` elements from the left side.
            start_l = 0;
            end_l = 0;
            for i in 0..block_l {
                offsets_l[end_l] = i as u8;
                if !is_less(&v[l + i], pivot) {
                    end_l += 1;
                }
            }
        }

        if start_r == end_r {
            // Trace `block_r` elements from the right side.
            start_r = 0;
            end_r = 0;
            for i in 0..block_r {
                offsets_r[end_r] = i as u8;
                if is_less(&v[r - 1 - i], pivot) {
                    end_r += 1;
                }
            }
        }

        // Number of out-of-order elements to exchange between the sides.
        let count = (end_l - start_l).min(end_r - start_r);

        if count > 0 {
            // A cyclic permutation rather than pairwise swaps: the result is
            // not the same, so it is reproduced as is.
            let mut left = l + offsets_l[start_l] as usize;
            let mut right = r - offsets_r[start_r] as usize - 1;
            let tmp = v[left];
            v[left] = v[right];

            for _ in 1..count {
                start_l += 1;
                left = l + offsets_l[start_l] as usize;
                v[right] = v[left];
                start_r += 1;
                right = r - offsets_r[start_r] as usize - 1;
                v[left] = v[right];
            }

            v[right] = tmp;
            start_l += 1;
            start_r += 1;
        }

        if start_l == end_l {
            // The left block is exhausted: move to the next one.
            l += block_l;
        }

        if start_r == end_r {
            // The right block is exhausted: move to the previous one.
            r -= block_r;
        }

        if is_done {
            break;
        }
    }

    // At most one block still holds out-of-order elements: shift them to
    // its far end.
    if start_l < end_l {
        while start_l < end_l {
            end_l -= 1;
            v.swap(l + offsets_l[end_l] as usize, r - 1);
            r -= 1;
        }
        r
    } else if start_r < end_r {
        while start_r < end_r {
            end_r -= 1;
            v.swap(l, r - offsets_r[end_r] as usize - 1);
            l += 1;
        }
        l
    } else {
        l
    }
}

/// Partitions `v` into the elements smaller than `v[pivot]` followed by the
/// others; returns the number of smaller ones and whether `v` was already
/// partitioned.
fn partition(v: &mut [Elem], pivot: usize) -> (usize, bool) {
    // The pivot waits at the beginning of the slice.
    v.swap(0, pivot);
    let pivot = v[0];
    let rest = &mut v[1..];

    // Find the first pair of out-of-order elements.
    let mut l = 0;
    let mut r = rest.len();
    while l < r && is_less(&rest[l], &pivot) {
        l += 1;
    }
    while l < r && !is_less(&rest[r - 1], &pivot) {
        r -= 1;
    }

    let mid = l + partition_in_blocks(&mut rest[l..r], &pivot);
    let was_partitioned = l >= r;

    // Place the pivot between the two partitions.
    v.swap(0, mid);

    (mid, was_partitioned)
}

/// Partitions `v`, which holds nothing smaller than `v[pivot]`, into the
/// elements equal to it followed by the greater ones; returns the number of
/// equal ones.
fn partition_equal(v: &mut [Elem], pivot: usize) -> usize {
    v.swap(0, pivot);
    let pivot = v[0];
    let rest = &mut v[1..];

    let mut l = 0;
    let mut r = rest.len();
    loop {
        while l < r && !is_less(&pivot, &rest[l]) {
            l += 1;
        }
        while l < r && is_less(&pivot, &rest[r - 1]) {
            r -= 1;
        }
        if l >= r {
            break;
        }
        r -= 1;
        rest.swap(l, r);
        l += 1;
    }

    // The `l` elements found, and the pivot itself.
    l + 1
}

/// Scatters a few elements around to break the patterns that unbalance the
/// partitions.
fn break_patterns(v: &mut [Elem]) {
    let len = v.len();
    if len >= 8 {
        // Marsaglia's xorshift, seeded with the length. The reference joins
        // two 32-bit outputs into a `usize`; this is the value it gets on a
        // 64-bit target, computed as a `u64` so that the order is the same
        // on every platform.
        let mut random = len as u32;
        let mut gen_u32 = || {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            random
        };
        let mut gen_u64 = || {
            let high = gen_u32() as u64;
            let low = gen_u32() as u64;
            (high << 32) | low
        };

        // Random numbers are taken modulo this power of two.
        let modulus = (len as u64).next_power_of_two();

        // Some pivot candidates are around this index.
        let pos = len / 4 * 2;

        for i in 0..3 {
            // Below `2 * len`, so one subtraction brings it under `len`.
            let mut other = (gen_u64() & (modulus - 1)) as usize;
            if other >= len {
                other -= len;
            }

            v.swap(pos - 1 + i, other);
        }
    }
}

/// Orders the indices `a` and `b` so that `v[a] <= v[b]`, counting the swap.
fn sort2(v: &[Elem], a: &mut usize, b: &mut usize, swaps: &mut usize) {
    if is_less(&v[*b], &v[*a]) {
        core::mem::swap(a, b);
        *swaps += 1;
    }
}

/// Orders the indices `a`, `b` and `c` so that `v[a] <= v[b] <= v[c]`.
fn sort3(v: &[Elem], a: &mut usize, b: &mut usize, c: &mut usize, swaps: &mut usize) {
    sort2(v, a, b, swaps);
    sort2(v, b, c, swaps);
    sort2(v, a, b, swaps);
}

/// Replaces `a` by the index of the median of `v[a - 1]`, `v[a]` and
/// `v[a + 1]`.
fn sort_adjacent(v: &[Elem], a: &mut usize, swaps: &mut usize) {
    let tmp = *a;
    sort3(v, &mut (tmp - 1), a, &mut (tmp + 1), swaps);
}

/// Chooses a pivot in `v`; returns its index and whether the slice is likely
/// sorted already. A slice that looks descending is reversed.
fn choose_pivot(v: &mut [Elem]) -> (usize, bool) {
    // Shorter slices use the median of three rather than of medians.
    const SHORTEST_MEDIAN_OF_MEDIANS: usize = 50;
    // Maximum number of swaps that can be performed in this function.
    const MAX_SWAPS: usize = 4 * 3;

    let len = v.len();

    // Three indices near which the pivot is chosen.
    let mut a = len / 4;
    let mut b = len / 4 * 2;
    let mut c = len / 4 * 3;

    let mut swaps = 0;

    if len >= 8 {
        if len >= SHORTEST_MEDIAN_OF_MEDIANS {
            sort_adjacent(v, &mut a, &mut swaps);
            sort_adjacent(v, &mut b, &mut swaps);
            sort_adjacent(v, &mut c, &mut swaps);
        }
        sort3(v, &mut a, &mut b, &mut c, &mut swaps);
    }

    if swaps < MAX_SWAPS {
        (b, swaps == 0)
    } else {
        // Every swap was needed: the slice is probably descending.
        v.reverse();
        (len - 1 - b, true)
    }
}

/// Sorts `v`, whose predecessor in the whole slice has key `pred` (if it has
/// one), switching to heapsort once `limit` unbalanced partitions were made.
fn recurse(mut v: &mut [Elem], mut pred: Option<Elem>, mut limit: u32) {
    // Slices of up to this length are sorted by insertion.
    const MAX_INSERTION: usize = 20;

    // Whether the last partitioning was reasonably balanced.
    let mut was_balanced = true;
    // Whether the last partitioning did not move anything.
    let mut was_partitioned = true;

    loop {
        let len = v.len();

        if len <= MAX_INSERTION {
            insertion_sort(v);
            return;
        }

        if limit == 0 {
            heapsort(v);
            return;
        }

        if !was_balanced {
            break_patterns(v);
            limit -= 1;
        }

        let (pivot, likely_sorted) = choose_pivot(v);

        if was_balanced && was_partitioned && likely_sorted && partial_insertion_sort(v) {
            return;
        }

        // A pivot equal to the predecessor is the smallest element of the
        // slice: split off everything equal to it.
        if let Some(p) = pred
            && !is_less(&p, &v[pivot])
        {
            let mid = partition_equal(v, pivot);
            v = &mut core::mem::take(&mut v)[mid..];
            continue;
        }

        let (mid, was_p) = partition(v, pivot);
        was_balanced = mid.min(len - mid) >= len / 8;
        was_partitioned = was_p;

        let (left, right) = core::mem::take(&mut v).split_at_mut(mid);
        let (pivot, right) = right.split_at_mut(1);
        let pivot = pivot[0];

        // Recurse into the shorter side, continue with the longer one.
        if left.len() < right.len() {
            recurse(left, pred, limit);
            v = right;
            pred = Some(pivot);
        } else {
            recurse(right, Some(pivot), limit);
            v = left;
        }
    }
}

/// Sorts `v` with the pattern-defeating quicksort of the reference.
fn quicksort(v: &mut [Elem]) {
    // `floor(log2(len)) + 1` unbalanced partitions are allowed: the bit
    // length of `len`, whatever the width of `usize`.
    let len = v.len() as u64;
    let limit = u64::BITS - len.leading_zeros();

    recurse(v, None, limit);
}

#[cfg(test)]
mod tests {
    //! Every expected value below was printed by a run of the reference,
    //! `halo2_legacy_pdqsort::sort::quicksort` 0.1.0, on `(key, index)`
    //! pairs compared by key (on a 64-bit target).

    use super::*;
    use alloc::vec;

    /// The larger lengths of the generated cases, after `0..=60`.
    const LENS_BIG: [usize; 6] = [100, 257, 500, 777, 1000, 2000];
    /// The number of key distributions.
    const KINDS: usize = 16;

    /// A linear congruential generator, the same as in the reference run.
    fn lcg(state: &mut u64) -> usize {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (*state >> 33) as usize
    }

    /// The keys of one generated case: `len` keys of distribution `kind`.
    fn gen_keys(len: usize, kind: usize) -> Vec<usize> {
        let mut s = (len as u64) * 1000 + kind as u64;
        let mut k: Vec<usize> = (0..len)
            .map(|i| match kind {
                // all equal
                0 => 7,
                // few distinct values
                1..=5 => lcg(&mut s) % [2, 3, 5, 10, 50][kind - 1],
                // ascending, descending, ascending with ties, organ pipe
                6 => i,
                7 => len - i,
                8 => i / 3,
                9 => i.min(len - 1 - i),
                // random with few ties
                10 => lcg(&mut s) % (4 * len + 1),
                // descending with ties
                11 => (len - i) / 4,
                // nearly sorted (two misplaced elements, set below)
                12 => i / 2,
                // sawtooth
                13 => i % 7,
                // ascending with a random tail
                14 => {
                    if i < len - len / 10 {
                        i
                    } else {
                        lcg(&mut s) % len
                    }
                }
                // random with moderate ties
                _ => lcg(&mut s) % (len / 4 + 1),
            })
            .collect();
        if kind == 12 && len >= 8 {
            k[len / 7] = len;
            k[len - 2] = 0;
        }
        k
    }

    /// One step of a word-wise FNV-1a.
    fn fnv(h: &mut u64, x: u64) {
        *h = (*h ^ x).wrapping_mul(0x0000_0100_0000_01b3);
    }

    /// Per length (`0..=60`, then `LENS_BIG`), the digest of the orders of
    /// its `KINDS` cases, as printed by the reference.
    #[rustfmt::skip]
    const DIGESTS: [u64; 67] = [
        0x88201fb960ff6465,
        0x62f69d9a386fc465,
        0xf317b8227803a8a7,
        0xb515791a941c5437,
        0x333a2df629469007,
        0xa4fe8aa441711173,
        0x99bd19bff9011507,
        0xb74568d675c8ce07,
        0xee7ed7cd42bd5cc7,
        0x091d06432b8a9acf,
        0x492095a6d06b288d,
        0xe940d6ec6c9653d1,
        0x9cdadb57bf5c1d6d,
        0x97d5772304ca4701,
        0x163f3de7389e5379,
        0xd8a8f60317d743f5,
        0x286a4e7cd829cb19,
        0xa23d75a196ba1ab9,
        0xe8155faecdd7d611,
        0x2f9902065814be65,
        0x5d19e9e80f778b77,
        0xebe9933087d52501,
        0x0cf188a8104f6ddb,
        0x11035514cec0a0d3,
        0xe5aafa286f86a6c7,
        0xe49d1e4bd6edd5cb,
        0xff879b4a16a2c307,
        0xb96e1cb572519ca5,
        0xb6517b8b35359b9d,
        0x0a979e129ac89c63,
        0xd653a140e538f339,
        0xaff8a57040020d99,
        0x7fe8d19042af4bdf,
        0x449e3819dadb76a7,
        0xa2f1471330d04ac3,
        0x98f9180ab6856b9f,
        0x1ef78c189e069221,
        0x3d1b87d653e771eb,
        0xa2ffc29e4a6960f5,
        0xf6b263d039f55819,
        0x68c3bf46fc995383,
        0x908402fce9866565,
        0xfff65397f3d355a7,
        0xcbec7568f53242f7,
        0x82a9139aa399c28f,
        0xe595fd46e1f0ac0d,
        0xd62271e69a917763,
        0xbb68e2050056a151,
        0xeb6e1d7de73c4e97,
        0x1601a010b8a69675,
        0x54107a7364dd89f9,
        0xdeefa0c8ed130e51,
        0x75726c3d34b3ea6d,
        0x18c5e57b4c826793,
        0x521e87a608c8b927,
        0x5120a786090f1503,
        0x1da55459ed48127f,
        0x3f78ff62eddfde9b,
        0x7e7eabfdeb5a92a3,
        0x8e11d8763233ffcf,
        0xd2ff350c8b80dd8b,
        0x3ecbdd9210bbf383,
        0xa6f86fc2ebbe98ed,
        0xce51d05cbbd846b3,
        0xc43b4d98cbea9633,
        0x16b13a9d2e830dbf,
        0x449ceb52ae4d1d61,
];

    #[test]
    fn generated_cases_match_the_reference() {
        let lens = (0..=60).chain(LENS_BIG);
        for (len, expected) in lens.zip(DIGESTS) {
            let mut h = 0xcbf2_9ce4_8422_2325u64;
            for kind in 0..KINDS {
                let keys = gen_keys(len, kind);
                let order = sorted_order(&keys);
                // a permutation that sorts the keys
                let mut seen = vec![false; len];
                for i in &order {
                    assert!(!core::mem::replace(&mut seen[*i], true));
                }
                assert!(order.windows(2).all(|w| keys[w[0]] <= keys[w[1]]));
                fnv(&mut h, len as u64);
                for i in order {
                    fnv(&mut h, i as u64);
                }
            }
            assert_eq!(h, expected, "length {len}");
        }
    }

    #[test]
    #[rustfmt::skip]
    fn small_cases_match_the_reference() {
        assert_eq!(sorted_order(&[]), vec![0usize; 0]);
        assert_eq!(sorted_order(&[3]), [0]);
        // insertion sort (stable), then quicksort proper
        assert_eq!(
            sorted_order(&gen_keys(12, 1)),
            [1, 3, 4, 5, 8, 9, 10, 0, 2, 6, 7, 11]
        );
        assert_eq!(
            sorted_order(&gen_keys(20, 2)),
            [2, 3, 4, 7, 8, 10, 12, 18, 0, 6, 13, 17, 1, 5, 9, 11, 14, 15, 16, 19]
        );
        assert_eq!(
            sorted_order(&gen_keys(24, 3)),
            [3, 4, 6, 9, 14, 1, 5, 7, 15, 16, 21, 2, 10, 8, 11, 23, 13, 22, 20, 12, 18, 19, 0, 17]
        );
        assert_eq!(
            sorted_order(&gen_keys(30, 9)),
            [0, 29, 1, 28, 2, 27, 3, 26, 4, 25, 5, 24, 6, 23, 7, 22, 21, 8, 20, 9, 19, 10, 18, 11, 17, 12, 16, 13, 15, 14]
        );
        assert_eq!(
            sorted_order(&gen_keys(64, 2)),
            [29, 1, 2, 3, 58, 57, 56, 54, 52, 46, 10, 44, 12, 13, 40, 38, 16, 17, 18, 19, 36, 32, 21, 63, 62, 60, 25, 59, 5, 8, 30, 31, 51, 50, 49, 48, 4, 37, 47, 39, 15, 43, 42, 53, 14, 45, 11, 41, 20, 35, 34, 33, 9, 22, 0, 55, 7, 6, 28, 27, 26, 61, 24, 23]
        );
    }

    /// Inputs on which the reference exhausts its limit of unbalanced
    /// partitions and falls back to heapsort, with tied keys (found with
    /// McIlroy's adversary against the reference; checked there to reach
    /// `heapsort`).
    #[test]
    #[rustfmt::skip]
    fn heapsort_fallback_matches_the_reference() {
        assert_eq!(
            sorted_order(&[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 17, 0, 27, 12, 27, 22, 22, 20, 27, 21, 25, 13, 1, 23, 22, 26, 19, 18, 27, 14, 26, 23, 24, 25, 26, 25, 28, 25, 24, 24, 22, 24, 23, 16, 23, 15, 26]),
            [11, 22, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 21, 29, 45, 43, 10, 27, 26, 17, 19, 15, 16, 24, 40, 42, 23, 44, 31, 39, 32, 41, 38, 37, 33, 20, 35, 34, 25, 46, 30, 28, 18, 12, 14, 36]
        );
        assert_eq!(
            sorted_order(&[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 18, 0, 13, 12, 21, 23, 19, 25, 20, 29, 26, 26, 1, 29, 26, 14, 17, 24, 24, 25, 15, 22, 26, 25, 28, 25, 27, 27, 27, 27, 24, 28, 28, 28, 16, 24]),
            [11, 22, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 12, 25, 30, 44, 26, 10, 16, 18, 14, 31, 15, 40, 27, 45, 28, 35, 29, 33, 17, 32, 21, 24, 20, 38, 37, 39, 36, 43, 42, 41, 34, 19, 23]
        );
        assert_eq!(
            sorted_order(&[2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 9, 0, 23, 7, 23, 12, 13, 11, 22, 11, 19, 7, 1, 14, 13, 21, 10, 10, 22, 8, 20, 15, 16, 18, 20, 19, 24, 18, 17, 17, 12, 16, 15, 9, 14, 8, 21]),
            [11, 22, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 21, 29, 45, 43, 10, 27, 26, 17, 19, 15, 40, 16, 24, 23, 44, 42, 31, 41, 32, 38, 39, 37, 33, 35, 20, 30, 34, 25, 46, 18, 28, 12, 14, 36]
        );
    }
}
