//! Zano's binary serialization (`binary_archive`): fixed-width little-endian
//! integers, CryptoNote varints for counts and marked fields, and one tag
//! byte in front of each variant.
//!
//! Reading never panics and never allocates more than the input justifies:
//! an element count is checked against the bytes that are left before
//! anything is reserved, and the nesting of variants is bounded.

use crate::cryptonote::{push_varint, read_varint};
use crate::prelude::*;

use super::Error;

/// How deep variants may nest: a transaction needs three levels (an input,
/// its ring, a reference), the wallet blobs a few more.
const MAX_DEPTH: u8 = 12;

/// A cursor over serialized data.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    /// How many variants are open around the cursor.
    depth: u8,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Reader { data, depth: 0 }
    }

    /// Fails with [`Error::TrailingData`] unless everything was read.
    pub(crate) fn finish(&self) -> Result<(), Error> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingData)
        }
    }

    /// Enters a nested variant; [`Error::TooDeep`] past the limit, so that
    /// crafted input cannot exhaust the stack.
    pub(crate) fn enter(&mut self) -> Result<(), Error> {
        if self.depth >= MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        self.depth += 1;
        Ok(())
    }

    /// Leaves a nested variant.
    pub(crate) fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (head, tail) = self.data.split_at_checked(n).ok_or(Error::UnexpectedEof)?;
        self.data = tail;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub(crate) fn bool(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidEncoding),
        }
    }

    pub(crate) fn key(&mut self) -> Result<[u8; 32], Error> {
        self.array()
    }

    pub(crate) fn varint(&mut self) -> Result<u64, Error> {
        let (value, n) = read_varint(self.data).map_err(|e| match e {
            crate::cryptonote::Error::UnexpectedEof => Error::UnexpectedEof,
            e => Error::CryptoNote(e),
        })?;
        self.take(n)?;
        Ok(value)
    }

    /// The version a versioned structure starts with, which must not exceed
    /// `last` ([`Error::UnsupportedVersion`]).
    pub(crate) fn version(&mut self, last: u8) -> Result<u8, Error> {
        match u8::try_from(self.varint()?) {
            Ok(version) if version <= last => Ok(version),
            _ => Err(Error::UnsupportedVersion),
        }
    }

    /// A count of elements that take at least `min_size` bytes each: it
    /// cannot exceed what the remaining input can hold.
    pub(crate) fn count(&mut self, min_size: usize) -> Result<usize, Error> {
        let count = usize::try_from(self.varint()?).map_err(|_| Error::UnexpectedEof)?;
        let needed = count.checked_mul(min_size).ok_or(Error::UnexpectedEof)?;
        if needed > self.data.len() {
            return Err(Error::UnexpectedEof);
        }
        Ok(count)
    }

    /// A length-prefixed byte string.
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>, Error> {
        let n = self.count(1)?;
        Ok(self.take(n)?.to_vec())
    }

    /// A length-prefixed sequence.
    pub(crate) fn vec<T: Wire>(&mut self) -> Result<Vec<T>, Error> {
        let n = self.count(T::MIN_SIZE)?;
        // Reserve modestly: the in-memory size of an element can be much
        // larger than its encoding.
        let mut out = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            out.push(T::read(self)?);
        }
        Ok(out)
    }

    /// A length-prefixed sequence of varints.
    pub(crate) fn varints(&mut self) -> Result<Vec<u64>, Error> {
        let n = self.count(1)?;
        let mut out = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            out.push(self.varint()?);
        }
        Ok(out)
    }

    /// An optional value: a byte telling whether it is absent, then the
    /// value.
    pub(crate) fn opt<T: Wire>(&mut self) -> Result<Option<T>, Error> {
        if self.bool()? {
            Ok(None)
        } else {
            Ok(Some(T::read(self)?))
        }
    }
}

/// A value with a binary serialization.
pub(crate) trait Wire: Sized {
    /// The fewest bytes a value takes, which bounds how many a sequence can
    /// hold.
    const MIN_SIZE: usize;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error>;
    fn write(&self, out: &mut Vec<u8>);
}

impl<const N: usize> Wire for [u8; N] {
    const MIN_SIZE: usize = N;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        r.array()
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl Wire for u64 {
    const MIN_SIZE: usize = 8;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        r.u64()
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }
}

impl Wire for u32 {
    const MIN_SIZE: usize = 4;

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        r.u32()
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }
}

pub(crate) fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

pub(crate) fn write_vec<T: Wire>(out: &mut Vec<u8>, items: &[T]) {
    push_varint(out, items.len() as u64);
    for item in items {
        item.write(out);
    }
}

/// Writes a sequence of varints.
pub(crate) fn write_varints(out: &mut Vec<u8>, items: &[u64]) {
    push_varint(out, items.len() as u64);
    for item in items {
        push_varint(out, *item);
    }
}

/// Writes an optional value.
pub(crate) fn write_opt<T: Wire>(out: &mut Vec<u8>, value: &Option<T>) {
    match value {
        None => out.push(1),
        Some(value) => {
            out.push(0);
            value.write(out);
        }
    }
}

/// Decodes a whole buffer as one value.
pub(crate) fn from_bytes<T: Wire>(data: &[u8]) -> Result<T, Error> {
    let mut r = Reader::new(data);
    let value = T::read(&mut r)?;
    r.finish()?;
    Ok(value)
}

/// Encodes one value.
pub(crate) fn to_bytes<T: Wire>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    value.write(&mut out);
    out
}
