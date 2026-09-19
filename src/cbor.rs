//! A minimal, self-contained CBOR codec sufficient for Cardano transaction
//! serialization.
//!
//! Encoding follows the canonical rules required by the Cardano ledger
//! (RFC 7049 canonical form): definite-length items, shortest-form integers,
//! and map keys sorted length-first then lexicographically by their encoded
//! bytes.
//!
//! The decoder parses the subset produced by [`Cbor::encode`] into [`Cbor`]
//! values, and additionally provides [`scan_item`], which measures one complete
//! data item — including indefinite-length strings/arrays/maps and tags — so
//! real on-chain transactions can be split into their raw top-level elements.

use crate::prelude::*;

/// A CBOR data item, limited to the variants outscript needs to build and parse
/// Cardano transactions.
///
/// Non-exhaustive: this is a deliberate, growing subset of the CBOR model (tags,
/// text strings, negative integers and floats may be added).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Cbor {
    /// Unsigned integer (major type 0).
    Uint(u64),
    /// Byte string (major type 2).
    Bytes(Vec<u8>),
    /// Definite-length array (major type 4).
    Array(Vec<Cbor>),
    /// Definite-length map (major type 5). Entries are sorted canonically at
    /// encode time, so insertion order does not affect the output.
    Map(Vec<(Cbor, Cbor)>),
    /// Boolean (major type 7, simple values 20/21).
    Bool(bool),
    /// Null (major type 7, simple value 22).
    Null,
    /// Pre-encoded CBOR bytes inserted verbatim. Used to embed the exact
    /// transaction-body bytes that were hashed for signing.
    Raw(Vec<u8>),
}

/// Errors from CBOR decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The data ended in the middle of an item.
    UnexpectedEof,
    /// A head used a reserved additional-information value (28-30).
    ReservedAdditionalInfo(u8),
    /// An indefinite-length item where only definite lengths are supported.
    UnsupportedIndefiniteLength,
    /// A simple value or float outside the supported subset.
    UnsupportedSimpleValue(u64),
    /// A major type outside the supported subset.
    UnsupportedMajorType(u8),
    /// A break code outside an indefinite-length container.
    UnexpectedBreak,
    /// A chunk of an indefinite-length string has the wrong type.
    InvalidChunk,
    /// The data is not a definite-length array.
    ExpectedArray,
    /// Arrays and maps are nested deeper than [`MAX_DEPTH`].
    NestingTooDeep,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::UnexpectedEof => f.write_str("unexpected end of CBOR data"),
            Error::ReservedAdditionalInfo(v) => write!(f, "reserved CBOR additional info {v}"),
            Error::UnsupportedIndefiniteLength => {
                f.write_str("unsupported indefinite-length CBOR item")
            }
            Error::UnsupportedSimpleValue(v) => write!(f, "unsupported CBOR simple value {v}"),
            Error::UnsupportedMajorType(m) => write!(f, "unsupported CBOR major type {m}"),
            Error::UnexpectedBreak => f.write_str("unexpected CBOR break"),
            Error::InvalidChunk => f.write_str("invalid chunk in indefinite-length CBOR string"),
            Error::ExpectedArray => f.write_str("expected a definite-length CBOR array"),
            Error::NestingTooDeep => f.write_str("CBOR items nested too deep"),
        }
    }
}

impl core::error::Error for Error {}

/// Writes the head of an item: its major type and argument, in shortest form.
pub(crate) fn write_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let mt = major << 5;
    if value < 24 {
        out.push(mt | value as u8);
    } else if value <= u8::MAX as u64 {
        out.push(mt | 24);
        out.push(value as u8);
    } else if value <= u16::MAX as u64 {
        out.push(mt | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        out.push(mt | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

impl Cbor {
    /// Encodes this value as canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Cbor::Uint(v) => write_head(out, 0, *v),
            Cbor::Bytes(b) => {
                write_head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Cbor::Array(items) => {
                write_head(out, 4, items.len() as u64);
                for item in items {
                    item.encode_into(out);
                }
            }
            Cbor::Map(entries) => {
                // Canonical (RFC 7049) ordering: sort by the encoded key,
                // shorter encodings first, ties broken lexicographically.
                let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|(k, v)| (k.encode(), v.encode()))
                    .collect();
                encoded.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
                write_head(out, 5, encoded.len() as u64);
                for (k, v) in encoded {
                    out.extend_from_slice(&k);
                    out.extend_from_slice(&v);
                }
            }
            Cbor::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
            Cbor::Null => out.push(0xf6),
            Cbor::Raw(bytes) => out.extend_from_slice(bytes),
        }
    }

    /// Decodes a single CBOR value from `data`, returning it and the number of
    /// bytes consumed. Only the subset emitted by [`Cbor::encode`] is supported
    /// (unsigned ints, byte strings, arrays, maps, bool and null); other types
    /// produce an error, and so do arrays and maps nested deeper than
    /// [`MAX_DEPTH`].
    pub fn decode(data: &[u8]) -> Result<(Cbor, usize), Error> {
        let mut pos = 0;
        let v = decode_value(data, &mut pos, 0)?;
        Ok((v, pos))
    }

    /// Returns the inner bytes if this is a [`Cbor::Bytes`].
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Returns the value if this is a [`Cbor::Uint`].
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Cbor::Uint(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the elements if this is a [`Cbor::Array`].
    pub fn as_array(&self) -> Option<&[Cbor]> {
        match self {
            Cbor::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Returns the entries if this is a [`Cbor::Map`].
    pub fn as_map(&self) -> Option<&[(Cbor, Cbor)]> {
        match self {
            Cbor::Map(entries) => Some(entries),
            _ => None,
        }
    }
}

/// Reads the major type and argument of a CBOR head, advancing `pos`. The
/// flag tells an indefinite length.
pub(crate) fn read_head(data: &[u8], pos: &mut usize) -> Result<(u8, u64, bool), Error> {
    if *pos >= data.len() {
        return Err(Error::UnexpectedEof);
    }
    let ib = data[*pos];
    *pos += 1;
    let major = ib >> 5;
    let info = ib & 0x1f;
    let (arg, indefinite) = match info {
        0..=23 => (info as u64, false),
        24 => (read_uint(data, pos, 1)?, false),
        25 => (read_uint(data, pos, 2)?, false),
        26 => (read_uint(data, pos, 4)?, false),
        27 => (read_uint(data, pos, 8)?, false),
        31 => (0, true),
        _ => return Err(Error::ReservedAdditionalInfo(info)),
    };
    Ok((major, arg, indefinite))
}

fn read_uint(data: &[u8], pos: &mut usize, n: usize) -> Result<u64, Error> {
    let bytes = take(data, pos, n as u64)?;
    Ok(bytes.iter().fold(0, |v, &b| (v << 8) | b as u64))
}

/// The `len` bytes at `pos`, which is advanced past them. `len` is whatever
/// the data claims: it may be past the end of the data, or of `usize`.
fn take<'a>(data: &'a [u8], pos: &mut usize, len: u64) -> Result<&'a [u8], Error> {
    let end = usize::try_from(len)
        .ok()
        .and_then(|len| pos.checked_add(len))
        .ok_or(Error::UnexpectedEof)?;
    let bytes = data.get(*pos..end).ok_or(Error::UnexpectedEof)?;
    *pos = end;
    Ok(bytes)
}

/// Checks the number of items a container claims against what is left of the
/// data, as each takes a byte at least, so that a few bytes cannot ask for
/// memory or time beyond their own length. Returns the count.
fn check_count(data: &[u8], pos: usize, count: u64) -> Result<usize, Error> {
    match usize::try_from(count) {
        Ok(count) if count <= data.len().saturating_sub(pos) => Ok(count),
        _ => Err(Error::UnexpectedEof),
    }
}

/// How deep [`Cbor::decode`] follows arrays and maps into one another: well
/// past what transactions need, and short of what the stack can take, as
/// values are decoded, encoded and dropped recursively.
pub const MAX_DEPTH: usize = 64;

fn decode_value(data: &[u8], pos: &mut usize, depth: usize) -> Result<Cbor, Error> {
    let (major, arg, indefinite) = read_head(data, pos)?;
    if indefinite && matches!(major, 0 | 2 | 4 | 5) {
        return Err(Error::UnsupportedIndefiniteLength);
    }
    if matches!(major, 4 | 5) && depth >= MAX_DEPTH {
        return Err(Error::NestingTooDeep);
    }
    match major {
        0 => Ok(Cbor::Uint(arg)),
        2 => Ok(Cbor::Bytes(take(data, pos, arg)?.to_vec())),
        4 => {
            let count = check_count(data, *pos, arg)?;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(decode_value(data, pos, depth + 1)?);
            }
            Ok(Cbor::Array(items))
        }
        5 => {
            // two items an entry
            let items = arg.checked_mul(2).ok_or(Error::UnexpectedEof)?;
            let count = check_count(data, *pos, items)? / 2;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let k = decode_value(data, pos, depth + 1)?;
                let v = decode_value(data, pos, depth + 1)?;
                entries.push((k, v));
            }
            Ok(Cbor::Map(entries))
        }
        7 => match arg {
            20 => Ok(Cbor::Bool(false)),
            21 => Ok(Cbor::Bool(true)),
            22 | 23 => Ok(Cbor::Null),
            _ => Err(Error::UnsupportedSimpleValue(arg)),
        },
        _ => Err(Error::UnsupportedMajorType(major)),
    }
}

/// A container being scanned, by what it still expects.
enum Open {
    /// This many more items: those of an array, the keys and values of a map,
    /// or the one item of a tag.
    Items(u64),
    /// Items until a break code. In a map (`pairs`), the break cannot come
    /// between a key and its value (`mid_pair`).
    UntilBreak { pairs: bool, mid_pair: bool },
}

/// Advances `pos` past one complete CBOR data item, supporting every major type
/// including tags and indefinite-length strings, arrays and maps. Used to carve
/// real transactions into their raw top-level elements without fully decoding
/// the (Plutus-laden) contents.
///
/// Items may be nested to any depth: the containers being scanned are kept on
/// the heap, not on the stack. On error, `pos` is left as it was.
pub fn scan_item(data: &[u8], pos: &mut usize) -> Result<(), Error> {
    let mut at = *pos;
    // The containers the current item is in, the innermost last.
    let mut open: Vec<Open> = Vec::new();
    loop {
        let closes = matches!(
            open.last(),
            Some(Open::UntilBreak {
                mid_pair: false,
                ..
            })
        ) && data.get(at) == Some(&0xff);
        if closes {
            // the break code completes the innermost container
            at += 1;
            open.pop();
        } else {
            let (major, arg, indefinite) = read_head(data, &mut at)?;
            let container = match major {
                0 | 1 => None, // integers: all in the head
                2 | 3 if indefinite => {
                    scan_indefinite_chunks(data, &mut at, major)?;
                    None
                }
                2 | 3 => {
                    take(data, &mut at, arg)?;
                    None
                }
                4 | 5 if indefinite => Some(Open::UntilBreak {
                    pairs: major == 5,
                    mid_pair: false,
                }),
                4 | 5 => {
                    // a map has two items an entry
                    let items = arg.checked_mul(major as u64 - 3);
                    let items = items.ok_or(Error::UnexpectedEof)?;
                    check_count(data, at, items)?;
                    (items > 0).then_some(Open::Items(items))
                }
                6 => Some(Open::Items(1)), // tag: one tagged item follows
                // simple values and floats are all in the head, which leaves
                // the break code, here where none is expected
                7 if indefinite => return Err(Error::UnexpectedBreak),
                7 => None,
                _ => return Err(Error::UnsupportedMajorType(major)),
            };
            if let Some(container) = container {
                // its items come next
                open.push(container);
                continue;
            }
        }

        // An item is complete, and with it every container it was the last of.
        loop {
            match open.last_mut() {
                None => {
                    *pos = at;
                    return Ok(());
                }
                Some(Open::UntilBreak { pairs, mid_pair }) => {
                    *mid_pair = *pairs && !*mid_pair;
                    break;
                }
                Some(Open::Items(left)) => {
                    *left -= 1;
                    if *left > 0 {
                        break;
                    }
                    open.pop();
                }
            }
        }
    }
}

/// Scans the definite-length chunks of an indefinite-length string until the
/// break code (0xff). `major` is the expected chunk major type (2 or 3).
fn scan_indefinite_chunks(data: &[u8], pos: &mut usize, major: u8) -> Result<(), Error> {
    loop {
        if data.get(*pos) == Some(&0xff) {
            *pos += 1;
            return Ok(());
        }
        let (m, arg, indef) = read_head(data, pos)?;
        if m != major || indef {
            return Err(Error::InvalidChunk);
        }
        take(data, pos, arg)?;
    }
}

/// Splits a top-level CBOR array into the raw byte slices of its elements.
/// Errors if `data` is not a definite-length array.
pub fn split_array_items(data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut pos = 0;
    let (major, arg, indefinite) = read_head(data, &mut pos)?;
    if major != 4 || indefinite {
        return Err(Error::ExpectedArray);
    }
    let count = check_count(data, pos, arg)?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let start = pos;
        scan_item(data, &mut pos)?;
        items.push(data[start..pos].to_vec());
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A head for `major` claiming 2^64-1 of whatever it counts.
    fn huge(major: u8) -> [u8; 9] {
        let mut head = [0xff; 9];
        head[0] = major << 5 | 27;
        head
    }

    /// Lengths and counts are claims: nothing is allocated, skipped or looped
    /// over on their word alone.
    #[test]
    fn hostile_lengths_are_errors() {
        for major in [2, 4, 5] {
            assert_eq!(Cbor::decode(&huge(major)), Err(Error::UnexpectedEof));
            // and just past the end
            assert_eq!(
                Cbor::decode(&[major << 5 | 2, 0x00]),
                Err(Error::UnexpectedEof)
            );
        }
        for count in [1u64 << 60, 1 << 40, 1 << 31, 9] {
            let mut data = vec![0x9b];
            data.extend_from_slice(&count.to_be_bytes());
            data.extend_from_slice(&[0; 8]);
            assert_eq!(Cbor::decode(&data), Err(Error::UnexpectedEof));
            assert_eq!(split_array_items(&data), Err(Error::UnexpectedEof));
            assert_eq!(scan_item(&data, &mut 0), Err(Error::UnexpectedEof));
            data[0] = 0xbb; // a map, of twice as many items
            assert_eq!(Cbor::decode(&data), Err(Error::UnexpectedEof));
            assert_eq!(scan_item(&data, &mut 0), Err(Error::UnexpectedEof));
        }

        for major in [2, 3, 4, 5] {
            let mut pos = 0;
            assert_eq!(scan_item(&huge(major), &mut pos), Err(Error::UnexpectedEof));
            assert_eq!(pos, 0);

            let mut in_array = vec![0x81];
            in_array.extend_from_slice(&huge(major));
            assert_eq!(split_array_items(&in_array), Err(Error::UnexpectedEof));
        }
        for major in [2, 3] {
            // a chunk of an indefinite-length string
            let mut data = vec![major << 5 | 31];
            data.extend_from_slice(&huge(major));
            data.push(0xff);
            assert_eq!(scan_item(&data, &mut 0), Err(Error::UnexpectedEof));
        }
        // a length that wraps `pos` around to within the data
        let mut data = vec![0x00];
        data.extend_from_slice(&huge(2));
        let mut pos = 1;
        assert_eq!(scan_item(&data, &mut pos), Err(Error::UnexpectedEof));
        assert_eq!(pos, 1);
        assert_eq!(read_uint(&[1, 2], &mut 1, 8), Err(Error::UnexpectedEof));

        // counts that are true are fine, however many
        let mut data = vec![0x99, 0x27, 0x10]; // 10000
        data.resize(10003, 0x00);
        assert_eq!(Cbor::decode(&data).unwrap().1, 10003);
        assert_eq!(split_array_items(&data).unwrap().len(), 10000);
        let mut data = vec![0xb9, 0x13, 0x88]; // 5000 entries
        data.resize(10003, 0x00);
        assert_eq!(Cbor::decode(&data).unwrap().0.as_map().unwrap().len(), 5000);
    }

    /// `depth` arrays in one another, around a 0.
    fn nested(opening: &[u8], depth: usize, closing: &[u8]) -> Vec<u8> {
        let mut data = opening.repeat(depth);
        data.push(0x00);
        data.extend(closing.repeat(depth));
        data
    }

    #[test]
    fn nesting_is_bounded_or_free() {
        // decoding stops at MAX_DEPTH
        let (value, len) = Cbor::decode(&nested(&[0x81], MAX_DEPTH, &[])).unwrap();
        assert_eq!(len, MAX_DEPTH + 1);
        let mut depth = 0;
        let mut inner = &value;
        while let Some([item]) = inner.as_array() {
            inner = item;
            depth += 1;
        }
        assert_eq!((depth, inner), (MAX_DEPTH, &Cbor::Uint(0)));
        assert_eq!(value.encode(), nested(&[0x81], MAX_DEPTH, &[]));
        for opening in [&[0x81][..], &[0xa1, 0x00], &[0xa1, 0x00, 0x81]] {
            assert_eq!(
                Cbor::decode(&nested(opening, MAX_DEPTH + 1, &[])),
                Err(Error::NestingTooDeep)
            );
            assert_eq!(
                Cbor::decode(&nested(opening, 1_000_000, &[])),
                Err(Error::NestingTooDeep)
            );
        }

        // scanning goes as deep as the data does, without a stack to overflow
        for (opening, closing) in [
            (&[0x81][..], &[][..]),         // arrays
            (&[0xa1, 0x00], &[]),           // maps, as values
            (&[0xa1, 0x81], &[0x00]),       // maps, as keys
            (&[0xc0], &[]),                 // tags
            (&[0xd8, 0x79, 0x9f], &[0xff]), // Plutus constructors
            (&[0x9f], &[0xff]),             // indefinite-length arrays
            (&[0xbf, 0x00], &[0xff]),       // and maps
        ] {
            let data = nested(opening, 1_000_000, closing);
            let mut pos = 0;
            assert_eq!(scan_item(&data, &mut pos), Ok(()));
            assert_eq!(pos, data.len());
            // and notices what is missing at the bottom of it
            let mut pos = 0;
            let cut = &data[..opening.len() * 1_000_000];
            assert_eq!(scan_item(cut, &mut pos), Err(Error::UnexpectedEof));
            assert_eq!(pos, 0);
        }
    }

    #[test]
    fn scan_tracks_containers() {
        for (data, expected) in [
            (&[0x80][..], Ok(1)),                           // []
            (&[0xa0], Ok(1)),                               // {}
            (&[0x9f, 0xff], Ok(2)),                         // [_ ]
            (&[0xbf, 0xff], Ok(2)),                         // {_ }
            (&[0x82, 0x80, 0xa0], Ok(3)),                   // [[], {}]
            (&[0x82, 0x01, 0x02, 0x03], Ok(3)),             // stops after the item
            (&[0xa1, 0x01, 0x82, 0x02, 0x03], Ok(5)),       // {1: [2, 3]}
            (&[0xbf, 0x01, 0x9f, 0x02, 0xff, 0xff], Ok(6)), // {_ 1: [_ 2]}
            (&[0xc2, 0x42, 0x01, 0x00], Ok(4)),             // 2(h'0100')
            (&[0x5f, 0x41, 0x01, 0x40, 0xff], Ok(5)),       // (_ h'01', h'')
            (&[0xf9, 0x3e, 0x00], Ok(3)),                   // 1.5
            (&[0x82, 0x01], Err(Error::UnexpectedEof)),
            (&[0xa1, 0x01], Err(Error::UnexpectedEof)),
            (&[0x9f, 0x01], Err(Error::UnexpectedEof)),
            (&[0xc2], Err(Error::UnexpectedEof)),
            (&[0xff], Err(Error::UnexpectedBreak)),
            (&[0x82, 0x01, 0xff], Err(Error::UnexpectedBreak)),
            (&[0xc2, 0xff], Err(Error::UnexpectedBreak)),
            // a break between a key and its value
            (&[0xbf, 0x01, 0xff], Err(Error::UnexpectedBreak)),
            (&[0xbf, 0x01, 0x02, 0x03, 0xff], Err(Error::UnexpectedBreak)),
            (&[0x5f, 0x61, 0x61, 0xff], Err(Error::InvalidChunk)),
            (&[0x5f, 0x5f, 0xff, 0xff], Err(Error::InvalidChunk)),
            (&[0x1c], Err(Error::ReservedAdditionalInfo(28))),
        ] {
            let mut pos = 0;
            let result = scan_item(data, &mut pos).map(|()| pos);
            assert_eq!(result, expected, "{data:x?}");
            if expected.is_err() {
                assert_eq!(pos, 0, "{data:x?}");
            }
        }
    }

    #[test]
    fn encodes_shortest_uint() {
        assert_eq!(Cbor::Uint(0).encode(), vec![0x00]);
        assert_eq!(Cbor::Uint(23).encode(), vec![0x17]);
        assert_eq!(Cbor::Uint(24).encode(), vec![0x18, 0x18]);
        assert_eq!(Cbor::Uint(255).encode(), vec![0x18, 0xff]);
        assert_eq!(Cbor::Uint(256).encode(), vec![0x19, 0x01, 0x00]);
        assert_eq!(
            Cbor::Uint(1_000_000).encode(),
            vec![0x1a, 0x00, 0x0f, 0x42, 0x40]
        );
    }

    #[test]
    fn map_is_canonically_sorted() {
        // length-first: 1-byte key before 2-byte key regardless of insertion order
        let m = Cbor::Map(vec![
            (Cbor::Bytes(vec![0, 0]), Cbor::Uint(2)),
            (Cbor::Bytes(vec![9]), Cbor::Uint(1)),
        ]);
        let enc = m.encode();
        // a2 (map of 2) 41 09 01 (1-byte key first) 42 00 00 02
        assert_eq!(enc, vec![0xa2, 0x41, 0x09, 0x01, 0x42, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn roundtrip_decode() {
        let v = Cbor::Array(vec![
            Cbor::Bytes(vec![1, 2, 3]),
            Cbor::Uint(42),
            Cbor::Bool(true),
            Cbor::Null,
        ]);
        let enc = v.encode();
        let (dec, n) = Cbor::decode(&enc).unwrap();
        assert_eq!(n, enc.len());
        assert_eq!(dec, v);
    }

    #[test]
    fn scan_handles_indefinite_and_tags() {
        // [_ 1, 2] indefinite array inside a definite array: [ 9f 01 02 ff ]
        let data = vec![0x81, 0x9f, 0x01, 0x02, 0xff];
        let items = split_array_items(&data).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], vec![0x9f, 0x01, 0x02, 0xff]);

        // tagged item d8 18 43 010203 (tag 24 wrapping a 3-byte string)
        let tagged = vec![0x81, 0xd8, 0x18, 0x43, 0x01, 0x02, 0x03];
        let items = split_array_items(&tagged).unwrap();
        assert_eq!(items[0], vec![0xd8, 0x18, 0x43, 0x01, 0x02, 0x03]);
    }
}
