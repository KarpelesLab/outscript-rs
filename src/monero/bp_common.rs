//! What the two range proofs (the original Bulletproofs and Bulletproofs+)
//! share: their generators and the accumulator of a batched verification.

use super::ringct::{h_point, multiexp_vartime};
use crate::cryptonote::{EdwardsPoint, Scalar, cn_fast_hash, point_from_hash, push_varint};
use crate::prelude::*;

/// Bits of an amount.
pub(crate) const N: usize = 64;
/// `log2(N)`.
pub(crate) const LOG_N: usize = 6;
/// The most commitments one proof can cover.
pub(crate) const MAX_OUTPUTS: usize = 16;

/// Which proof system a set of generators is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// The original Bulletproofs.
    Original,
    /// Bulletproofs+.
    Plus,
}

impl Kind {
    fn domain(self) -> &'static [u8] {
        match self {
            Kind::Original => b"bulletproof",
            Kind::Plus => b"bulletproof_plus",
        }
    }
}

/// The generators `Gi` and `Hi`: 64 of each per commitment.
#[derive(Debug, Clone)]
pub(crate) struct Generators {
    pub(crate) gi: Vec<EdwardsPoint>,
    pub(crate) hi: Vec<EdwardsPoint>,
}

/// `get_exponent`: the generator number `index`,
/// `Hp(cn_fast_hash(H || domain || varint(index)))`.
fn generator(kind: Kind, index: u64) -> EdwardsPoint {
    let mut data = Vec::with_capacity(32 + 16 + 10);
    data.extend_from_slice(&super::H);
    data.extend_from_slice(kind.domain());
    push_varint(&mut data, index);
    point_from_hash(&cn_fast_hash(&data))
}

/// The number of generator pairs for proofs over up to `outputs`
/// commitments.
fn pairs_for(outputs: usize) -> usize {
    outputs.clamp(1, MAX_OUTPUTS).next_power_of_two() * N
}

impl Generators {
    /// The generators for proofs over up to `outputs` commitments (at most
    /// [`MAX_OUTPUTS`]; more is treated as that).
    pub(crate) fn new(kind: Kind, outputs: usize) -> Self {
        let mut generators = Generators {
            gi: Vec::new(),
            hi: Vec::new(),
        };
        generators.extend(kind, pairs_for(outputs));
        generators
    }

    /// Makes the generators up to `count` pairs.
    fn extend(&mut self, kind: Kind, count: usize) {
        self.gi.reserve(count.saturating_sub(self.gi.len()));
        self.hi.reserve(count.saturating_sub(self.hi.len()));
        for i in self.gi.len()..count {
            let i = i as u64;
            self.hi.push(generator(kind, 2 * i));
            self.gi.push(generator(kind, 2 * i + 1));
        }
    }

    /// The number of commitments these generators can serve.
    pub(crate) fn max_outputs(&self) -> usize {
        self.gi.len() / N
    }
}

/// The generators of `kind` for `outputs` commitments, made once and kept
/// for the life of the process.
#[cfg(any(feature = "std", test))]
pub(crate) fn cached(kind: Kind, outputs: usize) -> std::sync::Arc<Generators> {
    use std::sync::{Arc, Mutex};
    static ORIGINAL: Mutex<Option<Arc<Generators>>> = Mutex::new(None);
    static PLUS: Mutex<Option<Arc<Generators>>> = Mutex::new(None);
    let cell = match kind {
        Kind::Original => &ORIGINAL,
        Kind::Plus => &PLUS,
    };
    let count = pairs_for(outputs);
    // The cache holds public constants: a panic elsewhere cannot have left
    // it in a bad state.
    let mut guard = cell.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(generators) = guard.as_ref()
        && generators.gi.len() >= count
    {
        return generators.clone();
    }
    let mut generators = match guard.as_ref() {
        Some(existing) => Generators::clone(existing),
        None => Generators {
            gi: Vec::new(),
            hi: Vec::new(),
        },
    };
    generators.extend(kind, count);
    let generators = Arc::new(generators);
    *guard = Some(generators.clone());
    generators
}

/// Runs `f` with the generators of `kind` for `outputs` commitments: the
/// process-wide ones with `std`, fresh ones otherwise.
pub(crate) fn with_generators<T>(
    kind: Kind,
    outputs: usize,
    f: impl FnOnce(&Generators) -> T,
) -> T {
    #[cfg(any(feature = "std", test))]
    {
        f(&cached(kind, outputs))
    }
    #[cfg(not(any(feature = "std", test)))]
    {
        f(&Generators::new(kind, outputs))
    }
}

/// The smallest power of two that is at least `outputs`, and its logarithm.
pub(crate) fn padded(outputs: usize) -> Option<(usize, usize)> {
    if outputs == 0 || outputs > MAX_OUTPUTS {
        return None;
    }
    let m = outputs.next_power_of_two();
    Some((m, m.trailing_zeros() as usize))
}

/// The terms of the equations of one or several proofs, each scaled by a
/// weight, to be checked in one multi-scalar multiplication: the sum must be
/// the identity.
pub(crate) struct Accumulator {
    /// The coefficient of `G`.
    pub(crate) g: Scalar,
    /// The coefficient of `H`.
    pub(crate) h: Scalar,
    /// The coefficients of the `Gi`.
    pub(crate) gi: Vec<Scalar>,
    /// The coefficients of the `Hi`.
    pub(crate) hi: Vec<Scalar>,
    /// The other terms: the points of the proofs and the commitments.
    pub(crate) others: Vec<(Scalar, EdwardsPoint)>,
}

impl Accumulator {
    pub(crate) fn new() -> Self {
        Accumulator {
            g: Scalar::ZERO,
            h: Scalar::ZERO,
            gi: Vec::new(),
            hi: Vec::new(),
            others: Vec::new(),
        }
    }

    /// Makes room for the coefficients of `count` generator pairs.
    pub(crate) fn grow(&mut self, count: usize) {
        if self.gi.len() < count {
            self.gi.resize(count, Scalar::ZERO);
            self.hi.resize(count, Scalar::ZERO);
        }
    }

    /// Adds `scalar * point`.
    pub(crate) fn push(&mut self, scalar: Scalar, point: EdwardsPoint) {
        self.others.push((scalar, point));
    }

    /// Whether the terms sum to the identity. Variable-time.
    pub(crate) fn is_identity(&self, generators: &Generators) -> bool {
        let count = self.gi.len();
        let (Some(gi), Some(hi)) = (generators.gi.get(..count), generators.hi.get(..count)) else {
            return false;
        };
        let total = 2 + 2 * count + self.others.len();
        let mut scalars: Vec<Scalar> = Vec::with_capacity(total);
        let mut points: Vec<EdwardsPoint> = Vec::with_capacity(total);
        scalars.push(self.g.clone());
        points.push(EdwardsPoint::generator());
        scalars.push(self.h.clone());
        points.push(h_point());
        scalars.extend(self.gi.iter().cloned());
        points.extend_from_slice(gi);
        scalars.extend(self.hi.iter().cloned());
        points.extend_from_slice(hi);
        for (scalar, point) in &self.others {
            scalars.push(scalar.clone());
            points.push(*point);
        }
        multiexp_vartime(&scalars, &points) == EdwardsPoint::identity()
    }
}

/// The products of the round challenges and their inverses, one per
/// generator: entry `i` multiplies, for each round `j`, the challenge if bit
/// `rounds - 1 - j` of `i` is set and its inverse otherwise. `None` unless
/// there are as many inverses as challenges, at least one.
pub(crate) fn challenge_products(
    challenges: &[Scalar],
    inverses: &[Scalar],
) -> Option<Vec<Scalar>> {
    let rounds = challenges.len();
    if rounds == 0 || rounds != inverses.len() || rounds > 16 {
        return None;
    }
    let mut cache: Vec<Scalar> = vec![Scalar::ZERO; 1 << rounds];
    *cache.get_mut(0)? = inverses.first()?.clone();
    *cache.get_mut(1)? = challenges.first()?.clone();
    for (j, (challenge, inverse)) in challenges.iter().zip(inverses).enumerate().skip(1) {
        let mut s = 1usize << (j + 1);
        while s >= 2 {
            // s is even: the slots s - 1 and s - 2 both descend from slot
            // (s - 1) / 2, which is overwritten only after them.
            let base = cache.get((s - 1) / 2)?.clone();
            *cache.get_mut(s - 1)? = base.mul(challenge);
            *cache.get_mut(s - 2)? = base.mul(inverse);
            s -= 2;
        }
    }
    Some(cache)
}

/// `x^0, x^1, ..., x^(n - 1)`.
pub(crate) fn powers(x: &Scalar, n: usize) -> Vec<Scalar> {
    let mut out = Vec::with_capacity(n);
    let mut value = Scalar::ONE;
    for _ in 0..n {
        let next = value.mul(x);
        out.push(value);
        value = next;
    }
    out
}

/// The inverses of `values`, none of which may be zero, with one inversion
/// (Montgomery's trick).
pub(crate) fn batch_invert(values: &[Scalar]) -> Vec<Scalar> {
    let mut prefix = Vec::with_capacity(values.len());
    let mut product = Scalar::ONE;
    for value in values {
        prefix.push(product.clone());
        product = product.mul(value);
    }
    let mut inverse = product.invert();
    let mut out = vec![Scalar::ZERO; values.len()];
    for ((slot, value), prefix) in out.iter_mut().zip(values).zip(&prefix).rev() {
        *slot = inverse.mul(prefix);
        inverse = inverse.mul(value);
    }
    out
}
