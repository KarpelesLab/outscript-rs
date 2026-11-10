//! epee "portable storage": the binary key/value format of the Zano
//! daemon's `.bin` RPC endpoints.
//!
//! Only what those endpoints need is here: sections (objects) that keep
//! their entries in order, unsigned integers, booleans, byte strings, nested
//! sections, and arrays of those. Integers of every width decode to `u64`
//! (a `double` to its raw bits) and encode as `uint64`.

use crate::prelude::*;

use super::Error;

const SIGNATURE_A: u32 = 0x0101_1101;
const SIGNATURE_B: u32 = 0x0102_0101;
const FORMAT_VERSION: u8 = 1;

const TYPE_INT64: u8 = 1;
const TYPE_INT32: u8 = 2;
const TYPE_INT16: u8 = 3;
const TYPE_INT8: u8 = 4;
const TYPE_UINT64: u8 = 5;
const TYPE_UINT32: u8 = 6;
const TYPE_UINT16: u8 = 7;
const TYPE_UINT8: u8 = 8;
const TYPE_DOUBLE: u8 = 9;
const TYPE_STRING: u8 = 10;
const TYPE_BOOL: u8 = 11;
const TYPE_OBJECT: u8 = 12;
const FLAG_ARRAY: u8 = 0x80;

/// How deep sections may nest when decoding.
const MAX_DEPTH: usize = 32;

/// A value of a portable storage entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpeeValue {
    /// An integer (of any width or signedness on the wire).
    Uint(u64),
    /// A boolean.
    Bool(bool),
    /// A string or blob.
    Bytes(Vec<u8>),
    /// A nested section.
    Section(EpeeSection),
    /// An array of integers.
    UintArray(Vec<u64>),
    /// An array of booleans.
    BoolArray(Vec<bool>),
    /// An array of strings or blobs.
    BytesArray(Vec<Vec<u8>>),
    /// An array of sections.
    SectionArray(Vec<EpeeSection>),
}

/// A section: named entries, in order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EpeeSection {
    entries: Vec<(String, EpeeValue)>,
}

impl EpeeSection {
    /// An empty section.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an entry, or replaces the one with this name (keeping its
    /// place).
    pub fn set(&mut self, name: &str, value: EpeeValue) -> &mut Self {
        match self.entries.iter_mut().find(|(n, _)| n == name) {
            Some((_, slot)) => *slot = value,
            None => self.entries.push((name.to_string(), value)),
        }
        self
    }

    /// The entry with this name.
    pub fn get(&self, name: &str) -> Option<&EpeeValue> {
        self.entries
            .iter()
            .find_map(|(n, v)| (n == name).then_some(v))
    }

    /// The entries, in order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &EpeeValue)> {
        self.entries.iter().map(|(n, v)| (n.as_str(), v))
    }

    /// The integer entry with this name.
    pub fn uint(&self, name: &str) -> Option<u64> {
        match self.get(name)? {
            EpeeValue::Uint(v) => Some(*v),
            _ => None,
        }
    }

    /// The boolean entry with this name.
    pub fn bool(&self, name: &str) -> Option<bool> {
        match self.get(name)? {
            EpeeValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// The string or blob entry with this name.
    pub fn bytes(&self, name: &str) -> Option<&[u8]> {
        match self.get(name)? {
            EpeeValue::Bytes(v) => Some(v),
            _ => None,
        }
    }

    /// The nested section with this name.
    pub fn section(&self, name: &str) -> Option<&EpeeSection> {
        match self.get(name)? {
            EpeeValue::Section(v) => Some(v),
            _ => None,
        }
    }

    /// The array of sections with this name.
    pub fn sections(&self, name: &str) -> Option<&[EpeeSection]> {
        match self.get(name)? {
            EpeeValue::SectionArray(v) => Some(v),
            _ => None,
        }
    }

    /// The array of integers with this name.
    pub fn uints(&self, name: &str) -> Option<&[u64]> {
        match self.get(name)? {
            EpeeValue::UintArray(v) => Some(v),
            _ => None,
        }
    }

    /// Encodes the section as a portable storage document.
    ///
    /// Fails with [`Error::TooLarge`] if a name is longer than 255 bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        out.extend_from_slice(&SIGNATURE_A.to_le_bytes());
        out.extend_from_slice(&SIGNATURE_B.to_le_bytes());
        out.push(FORMAT_VERSION);
        self.write(&mut out)?;
        Ok(out)
    }

    /// Decodes a portable storage document.
    ///
    /// Fails with [`Error::InvalidEncoding`] (a bad header, a type this
    /// module does not handle, a name that is not UTF-8),
    /// [`Error::UnexpectedEof`], [`Error::TooDeep`] and
    /// [`Error::TrailingData`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        let mut r = Reader { data };
        if r.u32()? != SIGNATURE_A || r.u32()? != SIGNATURE_B || r.u8()? != FORMAT_VERSION {
            return Err(Error::InvalidEncoding);
        }
        let section = r.section(0)?;
        if !r.data.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(section)
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        write_varint(out, self.entries.len());
        for (name, value) in &self.entries {
            out.push(u8::try_from(name.len()).map_err(|_| Error::TooLarge)?);
            out.extend_from_slice(name.as_bytes());
            value.write(out)?;
        }
        Ok(())
    }
}

/// The portable storage varint: the size class in the two low bits.
fn write_varint(out: &mut Vec<u8>, value: usize) {
    let v = value as u64;
    if v <= 63 {
        out.push((v << 2) as u8);
    } else if v <= 16383 {
        out.extend_from_slice(&(((v << 2) | 1) as u16).to_le_bytes());
    } else if v <= 0x3fff_ffff {
        out.extend_from_slice(&(((v << 2) | 2) as u32).to_le_bytes());
    } else {
        out.extend_from_slice(&((v << 2) | 3).to_le_bytes());
    }
}

fn write_string(out: &mut Vec<u8>, bytes: &[u8]) {
    write_varint(out, bytes.len());
    out.extend_from_slice(bytes);
}

impl EpeeValue {
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            EpeeValue::Uint(v) => {
                out.push(TYPE_UINT64);
                out.extend_from_slice(&v.to_le_bytes());
            }
            EpeeValue::Bool(v) => {
                out.push(TYPE_BOOL);
                out.push(u8::from(*v));
            }
            EpeeValue::Bytes(v) => {
                out.push(TYPE_STRING);
                write_string(out, v);
            }
            EpeeValue::Section(v) => {
                out.push(TYPE_OBJECT);
                v.write(out)?;
            }
            EpeeValue::UintArray(items) => {
                out.push(TYPE_UINT64 | FLAG_ARRAY);
                write_varint(out, items.len());
                for v in items {
                    out.extend_from_slice(&v.to_le_bytes());
                }
            }
            EpeeValue::BoolArray(items) => {
                out.push(TYPE_BOOL | FLAG_ARRAY);
                write_varint(out, items.len());
                out.extend(items.iter().map(|v| u8::from(*v)));
            }
            EpeeValue::BytesArray(items) => {
                out.push(TYPE_STRING | FLAG_ARRAY);
                write_varint(out, items.len());
                for v in items {
                    write_string(out, v);
                }
            }
            EpeeValue::SectionArray(items) => {
                out.push(TYPE_OBJECT | FLAG_ARRAY);
                write_varint(out, items.len());
                for v in items {
                    v.write(out)?;
                }
            }
        }
        Ok(())
    }
}

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (head, tail) = self.data.split_at_checked(n).ok_or(Error::UnexpectedEof)?;
        self.data = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn varint(&mut self) -> Result<u64, Error> {
        let first = *self.data.first().ok_or(Error::UnexpectedEof)?;
        let value = match first & 3 {
            0 => u64::from(self.u8()?),
            1 => u64::from(u16::from_le_bytes(self.array()?)),
            2 => u64::from(self.u32()?),
            _ => u64::from_le_bytes(self.array()?),
        };
        Ok(value >> 2)
    }

    /// A count of items of at least `min_size` bytes each, checked against
    /// what is left.
    fn count(&mut self, min_size: usize) -> Result<usize, Error> {
        let count = usize::try_from(self.varint()?).map_err(|_| Error::UnexpectedEof)?;
        match count.checked_mul(min_size) {
            Some(needed) if needed <= self.data.len() => Ok(count),
            _ => Err(Error::UnexpectedEof),
        }
    }

    fn string(&mut self) -> Result<Vec<u8>, Error> {
        let n = self.count(1)?;
        Ok(self.take(n)?.to_vec())
    }

    /// An integer of the width `kind` says, if `kind` is an integer type.
    fn uint(&mut self, kind: u8) -> Result<Option<u64>, Error> {
        Ok(Some(match kind {
            TYPE_INT64 | TYPE_UINT64 | TYPE_DOUBLE => u64::from_le_bytes(self.array()?),
            TYPE_INT32 | TYPE_UINT32 => u64::from(self.u32()?),
            TYPE_INT16 | TYPE_UINT16 => u64::from(u16::from_le_bytes(self.array()?)),
            TYPE_INT8 | TYPE_UINT8 => u64::from(self.u8()?),
            _ => return Ok(None),
        }))
    }

    fn section(&mut self, depth: usize) -> Result<EpeeSection, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        // An entry is at least a name length, a type and a byte of value.
        let count = self.count(3)?;
        let mut section = EpeeSection::new();
        for _ in 0..count {
            let name_len = usize::from(self.u8()?);
            let name =
                core::str::from_utf8(self.take(name_len)?).map_err(|_| Error::InvalidEncoding)?;
            let value = self.entry(depth)?;
            section.set(name, value);
        }
        Ok(section)
    }

    fn entry(&mut self, depth: usize) -> Result<EpeeValue, Error> {
        let kind = self.u8()?;
        if kind & FLAG_ARRAY != 0 {
            return self.array_entry(kind & !FLAG_ARRAY, depth);
        }
        if let Some(v) = self.uint(kind)? {
            return Ok(EpeeValue::Uint(v));
        }
        Ok(match kind {
            TYPE_BOOL => EpeeValue::Bool(self.u8()? != 0),
            TYPE_STRING => EpeeValue::Bytes(self.string()?),
            TYPE_OBJECT => EpeeValue::Section(self.section(depth + 1)?),
            _ => return Err(Error::InvalidEncoding),
        })
    }

    fn array_entry(&mut self, kind: u8, depth: usize) -> Result<EpeeValue, Error> {
        let min_size = match kind {
            TYPE_INT64 | TYPE_UINT64 | TYPE_DOUBLE => 8,
            TYPE_INT32 | TYPE_UINT32 => 4,
            TYPE_INT16 | TYPE_UINT16 => 2,
            TYPE_INT8 | TYPE_UINT8 | TYPE_BOOL | TYPE_STRING | TYPE_OBJECT => 1,
            _ => return Err(Error::InvalidEncoding),
        };
        let count = self.count(min_size)?;
        // Reserve modestly: a section is larger in memory than on the wire.
        let cap = count.min(64);
        Ok(match kind {
            TYPE_BOOL => {
                let mut items = Vec::with_capacity(cap);
                for _ in 0..count {
                    items.push(self.u8()? != 0);
                }
                EpeeValue::BoolArray(items)
            }
            TYPE_STRING => {
                let mut items = Vec::with_capacity(cap);
                for _ in 0..count {
                    items.push(self.string()?);
                }
                EpeeValue::BytesArray(items)
            }
            TYPE_OBJECT => {
                let mut items = Vec::with_capacity(cap);
                for _ in 0..count {
                    items.push(self.section(depth + 1)?);
                }
                EpeeValue::SectionArray(items)
            }
            _ => {
                let mut items = Vec::with_capacity(cap);
                for _ in 0..count {
                    items.push(self.uint(kind)?.ok_or(Error::InvalidEncoding)?);
                }
                EpeeValue::UintArray(items)
            }
        })
    }
}
