//! A witness value that may not be known (it is not during key generation).

use alloc::vec::Vec;
use core::ops::{Add, Mul, Neg, Sub};

use super::Error;
use crate::orchard::Fp;

/// A value that might exist: known when a proof is being created, unknown
/// when only the shape of the circuit matters (key generation).
#[derive(Clone, Copy, Debug)]
pub struct Value<V>(Option<V>);

impl<V> Default for Value<V> {
    fn default() -> Self {
        Self::unknown()
    }
}

impl<V> Value<V> {
    /// An unknown value.
    pub const fn unknown() -> Self {
        Self(None)
    }

    /// A known value.
    pub const fn known(value: V) -> Self {
        Self(Some(value))
    }

    /// The value, if known.
    pub fn into_option(self) -> Option<V> {
        self.0
    }

    /// Borrows the value.
    pub fn as_ref(&self) -> Value<&V> {
        Value(self.0.as_ref())
    }

    /// Panics if the value is known and `f` is false for it.
    pub fn assert_if_known<F: FnOnce(&V) -> bool>(&self, f: F) {
        if let Some(v) = self.0.as_ref() {
            assert!(f(v));
        }
    }

    /// [`Error::Synthesis`] if the value is known and `f` is true for it.
    pub fn error_if_known_and<F: FnOnce(&V) -> bool>(&self, f: F) -> Result<(), Error> {
        match self.0.as_ref().map(f) {
            Some(true) => Err(Error::Synthesis),
            _ => Ok(()),
        }
    }

    /// Maps the value, if known.
    pub fn map<W, F: FnOnce(V) -> W>(self, f: F) -> Value<W> {
        Value(self.0.map(f))
    }

    /// Chains a computation that may itself be unknown.
    pub fn and_then<W, F: FnOnce(V) -> Value<W>>(self, f: F) -> Value<W> {
        match self.0 {
            Some(v) => f(v),
            None => Value(None),
        }
    }

    /// Pairs two values; unknown if either is.
    pub fn zip<W>(self, other: Value<W>) -> Value<(V, W)> {
        Value(self.0.zip(other.0))
    }
}

impl<V, W> Value<(V, W)> {
    /// Splits a pair.
    pub fn unzip(self) -> (Value<V>, Value<W>) {
        match self.0 {
            Some((a, b)) => (Value(Some(a)), Value(Some(b))),
            None => (Value(None), Value(None)),
        }
    }
}

impl<V> Value<&V> {
    /// Copies the borrowed value.
    pub fn copied(self) -> Value<V>
    where
        V: Copy,
    {
        Value(self.0.copied())
    }

    /// Clones the borrowed value.
    pub fn cloned(self) -> Value<V>
    where
        V: Clone,
    {
        Value(self.0.cloned())
    }
}

impl<V: Copy, const LEN: usize> Value<[V; LEN]> {
    /// An array of values out of a value of an array.
    pub fn transpose_array(self) -> [Value<V>; LEN] {
        let mut ret = [Value::unknown(); LEN];
        if let Some(arr) = self.0 {
            for (r, a) in ret.iter_mut().zip(arr) {
                *r = Value::known(a);
            }
        }
        ret
    }
}

impl<V, I> Value<I>
where
    I: IntoIterator<Item = V>,
    I::IntoIter: ExactSizeIterator,
{
    /// A vector of `length` values out of a value of a collection.
    ///
    /// # Panics
    /// Panics if the collection is known and not `length` long.
    pub fn transpose_vec(self, length: usize) -> Vec<Value<V>> {
        match self.0 {
            Some(values) => {
                let values = values.into_iter();
                assert_eq!(values.len(), length);
                values.map(Value::known).collect()
            }
            None => (0..length).map(|_| Value::unknown()).collect(),
        }
    }
}

impl<A, V: FromIterator<A>> FromIterator<Value<A>> for Value<V> {
    fn from_iter<I: IntoIterator<Item = Value<A>>>(iter: I) -> Self {
        Value(iter.into_iter().map(|v| v.0).collect())
    }
}

impl<V: Neg> Neg for Value<V> {
    type Output = Value<V::Output>;
    fn neg(self) -> Self::Output {
        Value(self.0.map(|v| -v))
    }
}

macro_rules! value_op {
    ($tr:ident, $f:ident) => {
        impl<V: $tr<W>, W> $tr<Value<W>> for Value<V> {
            type Output = Value<V::Output>;
            fn $f(self, rhs: Value<W>) -> Self::Output {
                Value(self.0.zip(rhs.0).map(|(a, b)| a.$f(b)))
            }
        }
        impl $tr<Fp> for Value<Fp> {
            type Output = Value<Fp>;
            fn $f(self, rhs: Fp) -> Self::Output {
                Value(self.0.map(|a| a.$f(rhs)))
            }
        }
    };
}
value_op!(Add, add);
value_op!(Sub, sub);
value_op!(Mul, mul);

impl Value<Fp> {
    /// Twice the value.
    pub fn double(&self) -> Value<Fp> {
        self.map(|v| v.double())
    }

    /// The square of the value.
    pub fn square(&self) -> Value<Fp> {
        self.map(|v| v.square())
    }

    /// The cube of the value.
    pub fn cube(&self) -> Value<Fp> {
        self.map(|v| v.square() * v)
    }

    /// The inverse of the value, zero for zero.
    pub fn invert(&self) -> Value<Fp> {
        self.map(|v| v.invert_or_zero())
    }
}
