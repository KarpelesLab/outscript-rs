//! Running independent pieces of work on several threads.
//!
//! With the `std` feature the helpers here split their work over scoped
//! threads ([`std::thread::scope`]); without it they run it in order on the
//! calling thread. Either way the result is the same, bit for bit: only
//! pure computations are split, each piece is given its position, and the
//! results are put back in order. Everything that depends on an order (the
//! transcript, the stream of blinding factors) stays on the calling thread.

use alloc::vec::Vec;

use crate::orchard::{Fp, vesta};

#[cfg(feature = "std")]
static MAX_THREADS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Limits the number of threads key generation, proving and verification
/// use, for the whole process: `1` keeps everything on the calling thread,
/// `0` (the default) uses as many threads as the machine has cores.
///
/// The number of threads never changes a result: keys and proofs are
/// identical, for the same inputs, whatever it is.
#[cfg(feature = "std")]
pub fn set_max_threads(threads: usize) {
    MAX_THREADS.store(threads, core::sync::atomic::Ordering::Relaxed);
}

/// The number of threads work is split over (see [`set_max_threads`]).
#[cfg(feature = "std")]
pub fn max_threads() -> usize {
    match MAX_THREADS.load(core::sync::atomic::Ordering::Relaxed) {
        0 => std::thread::available_parallelism().map_or(1, |n| n.get()),
        n => n,
    }
}

/// The number of threads work is split over: one, without `std`.
#[cfg(not(feature = "std"))]
pub(crate) fn max_threads() -> usize {
    1
}

/// `f(i, &items[i])` for every item, in order.
pub(crate) fn map<T, R, F>(items: &[T], f: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(usize, &T) -> R + Sync,
{
    #[cfg(feature = "std")]
    {
        let threads = max_threads().min(items.len());
        if threads > 1 {
            let per_thread = items.len().div_ceil(threads);
            let f = &f;
            return std::thread::scope(|scope| {
                let handles: Vec<_> = items
                    .chunks(per_thread)
                    .enumerate()
                    .map(|(chunk, part)| {
                        scope.spawn(move || {
                            part.iter()
                                .enumerate()
                                .map(|(i, item)| f(chunk * per_thread + i, item))
                                .collect::<Vec<R>>()
                        })
                    })
                    .collect();
                let mut out = Vec::with_capacity(items.len());
                for handle in handles {
                    match handle.join() {
                        Ok(part) => out.extend(part),
                        Err(panic) => std::panic::resume_unwind(panic),
                    }
                }
                out
            });
        }
    }
    items
        .iter()
        .enumerate()
        .map(|(i, item)| f(i, item))
        .collect()
}

/// `f(i)` for every `i` below `count`, in order.
pub(crate) fn map_range<R, F>(count: usize, f: F) -> Vec<R>
where
    R: Send,
    F: Fn(usize) -> R + Sync,
{
    #[cfg(feature = "std")]
    {
        let threads = max_threads().min(count);
        if threads > 1 {
            let per_thread = count.div_ceil(threads);
            let f = &f;
            return std::thread::scope(|scope| {
                let handles: Vec<_> = (0..count)
                    .step_by(per_thread)
                    .map(|start| {
                        scope.spawn(move || {
                            (start..(start + per_thread).min(count))
                                .map(f)
                                .collect::<Vec<R>>()
                        })
                    })
                    .collect();
                let mut out = Vec::with_capacity(count);
                for handle in handles {
                    match handle.join() {
                        Ok(part) => out.extend(part),
                        Err(panic) => std::panic::resume_unwind(panic),
                    }
                }
                out
            });
        }
    }
    (0..count).map(f).collect()
}

/// Splits `data` into consecutive pieces of at least `min_len` elements (a
/// multiple of `align`, but for the last) and runs `f(start, piece)` on
/// each, where `start` is the index of the piece's first element.
pub(crate) fn chunks_mut<T, F>(data: &mut [T], min_len: usize, align: usize, f: F)
where
    T: Send,
    F: Fn(usize, &mut [T]) + Sync,
{
    #[cfg(feature = "std")]
    {
        let threads = max_threads().min(data.len() / min_len.max(1));
        if threads > 1 {
            let per_thread = data.len().div_ceil(threads).next_multiple_of(align.max(1));
            let f = &f;
            std::thread::scope(|scope| {
                let handles: Vec<_> = data
                    .chunks_mut(per_thread)
                    .enumerate()
                    .map(|(chunk, part)| scope.spawn(move || f(chunk * per_thread, part)))
                    .collect();
                for handle in handles {
                    if let Err(panic) = handle.join() {
                        std::panic::resume_unwind(panic);
                    }
                }
            });
            return;
        }
    }
    let _ = (min_len, align);
    f(0, data);
}

/// The smallest multi-scalar multiplication worth a thread of its own.
const MSM_MIN_LEN: usize = 256;

/// [`vesta::Point::msm_vartime`], split over the threads. (The pieces add
/// up to the same point; only its projective coordinates, which nothing
/// depends on, may differ.)
pub(crate) fn msm(scalars: &[Fp], bases: &[vesta::Affine]) -> vesta::Point {
    let n = scalars.len().min(bases.len());
    let threads = max_threads().min(n / MSM_MIN_LEN);
    if threads <= 1 {
        return vesta::Point::msm_vartime(scalars, bases);
    }
    let per_thread = n.div_ceil(threads);
    let pieces = map_range(threads, |i| {
        let range = i * per_thread..((i + 1) * per_thread).min(n);
        vesta::Point::msm_vartime(&scalars[range.clone()], &bases[range])
    });
    pieces
        .iter()
        .fold(vesta::Point::IDENTITY, |acc, piece| acc.add(piece))
}
