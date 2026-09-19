//! BBQr, Coinkite's protocol for moving a file through a series of QR codes.
//! Only the strings are handled here; rendering or scanning QR codes is left
//! to the caller.
//!
//! A file is cut into up to 1295 parts that each start with an 8-character
//! header, and stick to the alphanumeric character set of QR codes:
//!
//! ```text
//! B$ Z P 05 00 ...
//! |  | | |  |  the data of this part, in hex or base32
//! |  | | |  this part, from 00, in base 36
//! |  | | the number of parts, in base 36
//! |  | the file type: P for a PSBT, T for a transaction...
//! |  the encoding: H for hex, 2 for base32, Z for deflate then base32
//! the protocol
//! ```
//!
//! Parts can be received in any order, but none can be missed. Without
//! `alloc`, [`Header::parse`], [`decode_part_to_slice`] and
//! [`encode_part_to_slice`] handle one part at a time, and
//! [`inflate_to_slice`] and [`deflate_to_slice`] the compression. With
//! `alloc`, `split` cuts a file into parts and a `Joiner`, or `join`, puts
//! them back together.
//!
//! Parts are produced in uppercase, as they have to be, and parsed whatever
//! their case.
//!
//! ```
//! # #[cfg(feature = "alloc")] {
//! use outscript::bbqr::{self, FileType};
//!
//! let psbt = [0x70, 0x73, 0x62, 0x74, 0xff, 0x01, 0x00, 0x75, 0x02, 0x00];
//! // parts of at most 16 characters, to force several
//! let parts = bbqr::split(&psbt, FileType::PSBT, 16).unwrap();
//! assert_eq!(parts, ["B$2P0200OBZWE5H7", "B$2P0201AEAHKAQA"]);
//!
//! let (file_type, data) = bbqr::join(&parts).unwrap();
//! assert_eq!((file_type, &data[..]), (FileType::PSBT, &psbt[..]));
//! # }
//! ```

#[cfg(feature = "alloc")]
use crate::prelude::*;

use minizlib::{Buffer, Compressor, Raw};

/// The length of the header each part starts with.
pub const HEADER_LEN: usize = 8;
/// The most parts a file can be cut into: `ZZ` in base 36.
pub const MAX_PARTS: usize = 36 * 36 - 1;

/// The back-references of the compressed data must stay within this distance
/// (`wbits=10`), which is what receivers set aside to decompress it.
const WINDOW: usize = 1024;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Errors from BBQr operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The part does not start with a well-formed `B$` header.
    InvalidHeader,
    /// The encoding is none of `H`, `2` and `Z`.
    UnsupportedEncoding(char),
    /// The part number is not below the number of parts, or the number of
    /// parts is not in 1..=1295.
    InvalidIndex,
    /// The data of the part is not valid hex or base32.
    InvalidEncoding,
    /// The output buffer is too small.
    BufferTooSmall,
    /// The compressed data is malformed.
    InvalidCompression,
    /// The part has another encoding, file type or number of parts than the
    /// previous ones, or other data than when it was last received.
    InconsistentPart,
    /// Some parts have not been received yet.
    Incomplete,
    /// The file exceeds the allowed maximum.
    TooLarge,
    /// The file does not fit in 1295 parts of the requested length.
    TooManyParts,
    /// The requested part length has no room for data after the header.
    PartTooSmall,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::InvalidHeader => "invalid BBQr header",
            Error::UnsupportedEncoding(c) => return write!(f, "unsupported BBQr encoding {c:?}"),
            Error::InvalidIndex => "invalid BBQr part number",
            Error::InvalidEncoding => "invalid BBQr part data",
            Error::BufferTooSmall => "BBQr output buffer too small",
            Error::InvalidCompression => "invalid BBQr compressed data",
            Error::InconsistentPart => "BBQr part is inconsistent with previous ones",
            Error::Incomplete => "BBQr parts are missing",
            Error::TooLarge => "BBQr file too large",
            Error::TooManyParts => "too many BBQr parts",
            Error::PartTooSmall => "BBQr part length too small",
        })
    }
}

impl core::error::Error for Error {}

/// How the data of each part is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// `H`: hexadecimal. Two characters a byte.
    Hex,
    /// `2`: base32 (RFC 4648) without padding. Eight characters for five
    /// bytes.
    Base32,
    /// `Z`: the file is compressed as a whole (raw deflate, within a window of
    /// 1 KiB), then cut and encoded as base32.
    Zlib,
}

impl Encoding {
    /// The character standing for this encoding in a header.
    pub const fn as_char(self) -> char {
        match self {
            Encoding::Hex => 'H',
            Encoding::Base32 => '2',
            Encoding::Zlib => 'Z',
        }
    }

    /// The encoding a header character stands for, in either case.
    pub const fn from_char(c: char) -> Option<Self> {
        match c {
            'H' | 'h' => Some(Encoding::Hex),
            '2' => Some(Encoding::Base32),
            'Z' | 'z' => Some(Encoding::Zlib),
            _ => None,
        }
    }

    /// The smallest numbers of bytes and characters that stand for each
    /// other: parts are cut between such groups.
    #[cfg(feature = "alloc")]
    const fn group(self) -> (usize, usize) {
        match self {
            Encoding::Hex => (1, 2),
            Encoding::Base32 | Encoding::Zlib => (5, 8),
        }
    }
}

/// What a file is, as one character: an uppercase letter or a digit.
///
/// The known types are the associated constants. Others are reserved, but are
/// parsed and produced all the same: a few are in use already, and more may
/// come.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileType(u8);

impl FileType {
    /// `P`: a PSBT, in binary.
    pub const PSBT: FileType = FileType(b'P');
    /// `T`: a Bitcoin transaction, as on the wire.
    pub const TRANSACTION: FileType = FileType(b'T');
    /// `J`: JSON.
    pub const JSON: FileType = FileType(b'J');
    /// `C`: CBOR.
    pub const CBOR: FileType = FileType(b'C');
    /// `U`: UTF-8 text.
    pub const UNICODE: FileType = FileType(b'U');
    /// `B`: binary data of no particular type.
    pub const BINARY: FileType = FileType(b'B');
    /// `X`: executable data.
    pub const EXECUTABLE: FileType = FileType(b'X');

    /// The file type a character stands for: a letter, in either case, or a
    /// digit.
    pub const fn from_char(c: char) -> Option<Self> {
        if c.is_ascii_alphanumeric() {
            Some(FileType((c as u8).to_ascii_uppercase()))
        } else {
            None
        }
    }

    /// The character standing for this file type in a header.
    pub const fn as_char(self) -> char {
        self.0 as char
    }
}

fn base36_digit(c: u8) -> Option<u16> {
    (c as char).to_digit(36).map(|digit| digit as u16)
}

/// The header of a part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// How the data that follows is encoded.
    pub encoding: Encoding,
    /// What the file is.
    pub file_type: FileType,
    /// The number of parts the file is cut into, 1 to 1295.
    pub num_parts: u16,
    /// Which part this is, from 0.
    pub index: u16,
}

impl Header {
    /// Splits a part into its header and the encoded data that follows.
    pub fn parse(part: &str) -> Result<(Header, &str), Error> {
        let (header, body) = part
            .split_at_checked(HEADER_LEN)
            .ok_or(Error::InvalidHeader)?;
        let &[b'B' | b'b', b'$', encoding, file_type, n1, n0, i1, i0] = header.as_bytes() else {
            return Err(Error::InvalidHeader);
        };
        let file_type = FileType::from_char(file_type as char).ok_or(Error::InvalidHeader)?;
        let number = |high, low| Some(base36_digit(high)? * 36 + base36_digit(low)?);
        let num_parts = number(n1, n0).ok_or(Error::InvalidHeader)?;
        let index = number(i1, i0).ok_or(Error::InvalidHeader)?;
        if !encoding.is_ascii_alphanumeric() {
            return Err(Error::InvalidHeader);
        }
        let encoding = Encoding::from_char(encoding as char)
            .ok_or(Error::UnsupportedEncoding(encoding as char))?;
        if num_parts == 0 || index >= num_parts {
            return Err(Error::InvalidIndex);
        }
        Ok((
            Header {
                encoding,
                file_type,
                num_parts,
                index,
            },
            body,
        ))
    }

    /// The eight (ASCII) characters of this header.
    pub fn to_bytes(&self) -> Result<[u8; HEADER_LEN], Error> {
        if self.num_parts == 0
            || self.num_parts as usize > MAX_PARTS
            || self.index >= self.num_parts
        {
            return Err(Error::InvalidIndex);
        }
        let digit = |value: u16| b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[value as usize % 36];
        Ok([
            b'B',
            b'$',
            self.encoding.as_char() as u8,
            self.file_type.0,
            digit(self.num_parts / 36),
            digit(self.num_parts),
            digit(self.index / 36),
            digit(self.index),
        ])
    }
}

/// The number of characters `n` bytes are encoded as, header not included.
pub const fn encoded_len(encoding: Encoding, n: usize) -> usize {
    match encoding {
        Encoding::Hex => n * 2,
        Encoding::Base32 | Encoding::Zlib => (n * 8).div_ceil(5),
    }
}

/// An upper bound on the number of bytes `n` characters are decoded to.
pub const fn decoded_len_bound(encoding: Encoding, n: usize) -> usize {
    match encoding {
        Encoding::Hex => n / 2,
        Encoding::Base32 | Encoding::Zlib => n * 5 / 8,
    }
}

/// Writes a part into `out`: `header`, then `data` in the header's encoding.
/// Returns the number of (ASCII) bytes written.
///
/// For [`Encoding::Zlib`], `data` is a piece of the file as already
/// compressed, by [`deflate_to_slice`]. To be decodable on their own, all
/// parts but the last must hold a multiple of five bytes in base32.
pub fn encode_part_to_slice(header: &Header, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let len = HEADER_LEN + encoded_len(header.encoding, data.len());
    let out = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;
    let (head, body) = out.split_at_mut(HEADER_LEN);
    head.copy_from_slice(&header.to_bytes()?);
    match header.encoding {
        Encoding::Hex => {
            for (pair, &byte) in body.as_chunks_mut::<2>().0.iter_mut().zip(data) {
                pair[0] = HEX[(byte >> 4) as usize];
                pair[1] = HEX[(byte & 15) as usize];
            }
        }
        Encoding::Base32 | Encoding::Zlib => {
            for (chars, bytes) in body.chunks_mut(8).zip(data.chunks(5)) {
                let mut group = [0u8; 8];
                group[3..3 + bytes.len()].copy_from_slice(bytes);
                let bits = u64::from_be_bytes(group);
                for (i, c) in chars.iter_mut().enumerate() {
                    *c = BASE32[(bits >> (35 - 5 * i)) as usize & 31];
                }
            }
        }
    }
    Ok(len)
}

/// Decodes a part into `out`. Returns its header and the number of bytes
/// written, which are still compressed for [`Encoding::Zlib`]: once all the
/// parts are together, they go through [`inflate_to_slice`].
pub fn decode_part_to_slice(part: &str, out: &mut [u8]) -> Result<(Header, usize), Error> {
    let (header, body) = Header::parse(part)?;
    let body = body.as_bytes();
    let len = match header.encoding {
        Encoding::Hex => {
            if !body.len().is_multiple_of(2) {
                return Err(Error::InvalidEncoding);
            }
            let out = out.get_mut(..body.len() / 2).ok_or(Error::BufferTooSmall)?;
            for (byte, pair) in out.iter_mut().zip(body.as_chunks::<2>().0) {
                let digit = |c: u8| (c as char).to_digit(16).ok_or(Error::InvalidEncoding);
                *byte = (digit(pair[0])? << 4 | digit(pair[1])?) as u8;
            }
            out.len()
        }
        Encoding::Base32 | Encoding::Zlib => {
            // No padding: 2, 4, 5 and 7 characters stand for 1 to 4 bytes,
            // and 1, 3 or 6 for nothing.
            if matches!(body.len() % 8, 1 | 3 | 6) {
                return Err(Error::InvalidEncoding);
            }
            let len = body.len() * 5 / 8;
            let out = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;
            for (chars, bytes) in body.chunks(8).zip(out.chunks_mut(5)) {
                let mut bits = 0u64;
                for &c in chars {
                    let value = match c.to_ascii_uppercase() {
                        c @ b'A'..=b'Z' => c - b'A',
                        c @ b'2'..=b'7' => c - b'2' + 26,
                        _ => return Err(Error::InvalidEncoding),
                    };
                    bits = bits << 5 | value as u64;
                }
                bits <<= 5 * (8 - chars.len());
                let group = &bits.to_be_bytes()[3..];
                // The bits that do not make a byte must be zeros.
                if group[bytes.len()..].iter().any(|&b| b != 0) {
                    return Err(Error::InvalidEncoding);
                }
                bytes.copy_from_slice(&group[..bytes.len()]);
            }
            len
        }
    };
    Ok((header, len))
}

/// An upper bound on the length [`deflate_to_slice`] produces for `n` bytes.
pub const fn deflate_len_bound(n: usize) -> usize {
    // At most nine bits a byte, ten a block, and ten to end the stream.
    n + n.div_ceil(8) + n.div_ceil(WINDOW) * 2 + 4
}

/// Compresses a file for [`Encoding::Zlib`] into `out`: a raw deflate stream
/// whose back-references stay within 1 KiB. Returns the number of bytes
/// written.
///
/// The compressor is a small and simple one: it makes up for the 5 bits per
/// byte that base32 loses on files with some redundancy, such as PSBTs with
/// several inputs or outputs of a kind, and may well make others longer. Use
/// the result when it is the shorter of the two, as `split` does.
pub fn deflate_to_slice(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let full = |_| Error::BufferTooSmall;
    let mut table = [0u16; WINDOW];
    let mut compressor = Compressor::<_, Raw>::new(Buffer::new(out), &mut table);
    // Matches are only looked for within what is written at once.
    for block in data.chunks(WINDOW) {
        compressor.write(block).map_err(full)?;
    }
    compressor.finish().map(|len| len as usize).map_err(full)
}

/// Decompresses a file received as [`Encoding::Zlib`], all parts together,
/// into `out`. Returns the number of bytes written.
pub fn inflate_to_slice(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    match minizlib::inflate(data, Buffer::new(out)) {
        Ok(len) => Ok(len as usize),
        Err(minizlib::Error::OutputFull) => Err(Error::BufferTooSmall),
        Err(_) => Err(Error::InvalidCompression),
    }
}

/// Compresses a file for [`Encoding::Zlib`]: see [`deflate_to_slice`].
#[cfg(feature = "alloc")]
pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; deflate_len_bound(data.len())];
    let len = deflate_to_slice(data, &mut out).expect("buffer sized by deflate_len_bound");
    out.truncate(len);
    out
}

/// Decompresses a file received as [`Encoding::Zlib`], all parts together,
/// unless it is longer than `max_len`.
#[cfg(feature = "alloc")]
pub fn inflate(data: &[u8], max_len: usize) -> Result<Vec<u8>, Error> {
    // A first pass for the length: it is nowhere to be found.
    let len = match minizlib::inflate_len(data, max_len as u64) {
        Ok(len) => len as usize,
        Err(minizlib::Error::OutputFull) => return Err(Error::TooLarge),
        Err(_) => return Err(Error::InvalidCompression),
    };
    let mut out = vec![0u8; len];
    inflate_to_slice(data, &mut out)?;
    Ok(out)
}

/// Cuts a file into parts of at most `max_part_len` characters, header
/// included: what the QR codes to be shown can hold in alphanumeric mode, such
/// as 2132 for version 27 or 4296 for version 40 (with low error correction).
///
/// The file is sent compressed ([`Encoding::Zlib`]) when that makes it
/// shorter, and as base32 otherwise. The parts are as few as `max_part_len`
/// allows, and then as short: all of the same length, but the last one which
/// may be shorter.
#[cfg(feature = "alloc")]
pub fn split(data: &[u8], file_type: FileType, max_part_len: usize) -> Result<Vec<String>, Error> {
    let compressed = deflate(data);
    if compressed.len() < data.len() {
        split_raw(&compressed, file_type, Encoding::Zlib, max_part_len)
    } else {
        split_raw(data, file_type, Encoding::Base32, max_part_len)
    }
}

/// Cuts a file into parts as [`split`] does, in the given encoding:
/// [`Encoding::Zlib`] compresses the file even if that makes it longer.
#[cfg(feature = "alloc")]
pub fn split_with(
    data: &[u8],
    file_type: FileType,
    encoding: Encoding,
    max_part_len: usize,
) -> Result<Vec<String>, Error> {
    match encoding {
        Encoding::Zlib => split_raw(&deflate(data), file_type, encoding, max_part_len),
        _ => split_raw(data, file_type, encoding, max_part_len),
    }
}

/// Cuts `data`, compressed already if it has to be.
#[cfg(feature = "alloc")]
fn split_raw(
    data: &[u8],
    file_type: FileType,
    encoding: Encoding,
    max_part_len: usize,
) -> Result<Vec<String>, Error> {
    let capacity = max_part_len
        .checked_sub(HEADER_LEN)
        .ok_or(Error::PartTooSmall)?;
    let part_len = if encoded_len(encoding, data.len()) <= capacity {
        data.len()
    } else {
        // Parts are cut between groups, so that each can be decoded on its
        // own: as few parts as fit, then as few groups in each as it takes.
        let (group_bytes, group_chars) = encoding.group();
        let max_groups = capacity / group_chars;
        if max_groups == 0 {
            return Err(Error::PartTooSmall);
        }
        let groups = data.len().div_ceil(group_bytes);
        let num_parts = groups.div_ceil(max_groups);
        groups.div_ceil(num_parts) * group_bytes
    };

    let num_parts = data.len().div_ceil(part_len.max(1)).max(1);
    if num_parts > MAX_PARTS {
        return Err(Error::TooManyParts);
    }
    // An empty file still makes a part.
    let chunks = data
        .chunks(part_len.max(1))
        .chain([&[][..]])
        .take(num_parts);
    chunks
        .enumerate()
        .map(|(index, chunk)| {
            let header = Header {
                encoding,
                file_type,
                num_parts: num_parts as u16,
                index: index as u16,
            };
            let mut part = vec![0u8; HEADER_LEN + encoded_len(encoding, chunk.len())];
            encode_part_to_slice(&header, chunk, &mut part)?;
            Ok(String::from_utf8(part).expect("BBQr parts are ASCII"))
        })
        .collect()
}

/// Puts the parts of a file back together, in whatever order they come and
/// however many times.
///
/// Feed it each scanned string with [`receive`](Self::receive) until it is
/// complete, then [`finish`](Self::finish). A joiner handles one file: once
/// it has seen a part, parts of another file are an error, and
/// [`reset`](Self::reset) starts over.
///
/// A file cannot be longer than
/// [`DEFAULT_MAX_LEN`](Self::DEFAULT_MAX_LEN), compressed or not, unless
/// [`with_max_len`](Self::with_max_len) says otherwise: a few kilobytes of
/// compressed data can stand for gigabytes.
#[cfg(feature = "alloc")]
pub struct Joiner {
    max_len: usize,
    /// What every part agrees on: their index is set to 0.
    header: Option<Header>,
    parts: Vec<Option<Vec<u8>>>,
    received: usize,
    len: usize,
}

#[cfg(feature = "alloc")]
impl Default for Joiner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl Joiner {
    /// The longest file accepted by default: 8 MiB.
    pub const DEFAULT_MAX_LEN: usize = 8 << 20;

    /// Creates a joiner with the default limit.
    pub fn new() -> Self {
        Self::with_max_len(Self::DEFAULT_MAX_LEN)
    }

    /// Creates a joiner that refuses, with [`Error::TooLarge`], files of more
    /// than `max_len` bytes, be it as received or once decompressed.
    pub fn with_max_len(max_len: usize) -> Self {
        Joiner {
            max_len,
            header: None,
            parts: Vec::new(),
            received: 0,
            len: 0,
        }
    }

    /// Forgets everything received, keeping the limit.
    pub fn reset(&mut self) {
        *self = Self::with_max_len(self.max_len);
    }

    /// The file type, once a part has been received.
    pub fn file_type(&self) -> Option<FileType> {
        self.header.map(|header| header.file_type)
    }

    /// The encoding, once a part has been received.
    pub fn encoding(&self) -> Option<Encoding> {
        self.header.map(|header| header.encoding)
    }

    /// The number of parts of the file, 0 until a part has been received.
    pub fn part_count(&self) -> usize {
        self.parts.len()
    }

    /// The number of parts received so far.
    pub fn received_part_count(&self) -> usize {
        self.received
    }

    /// Whether the part of this index, from 0, has been received.
    pub fn has_part(&self, index: usize) -> bool {
        matches!(self.parts.get(index), Some(Some(_)))
    }

    /// Whether every part has been received.
    pub fn is_complete(&self) -> bool {
        self.header.is_some() && self.received == self.parts.len()
    }

    /// Takes in a part. Returns whether every part has now been received.
    ///
    /// Parts already seen are ignored. An error leaves the joiner as it was.
    pub fn receive(&mut self, part: &str) -> Result<bool, Error> {
        let body_len = part.len().saturating_sub(HEADER_LEN);
        let mut data = vec![0u8; decoded_len_bound(Encoding::Base32, body_len)];
        let (header, len) = decode_part_to_slice(part, &mut data)?;
        data.truncate(len);

        let index = header.index as usize;
        let common = Header { index: 0, ..header };
        match self.header {
            Some(expected) if expected != common => return Err(Error::InconsistentPart),
            _ => {}
        }
        match self.parts.get(index) {
            Some(Some(known)) if *known != data => return Err(Error::InconsistentPart),
            Some(Some(_)) => return Ok(self.is_complete()),
            _ => {}
        }
        if data.len() > self.max_len - self.len {
            return Err(Error::TooLarge);
        }

        if self.header.is_none() {
            self.header = Some(common);
            self.parts.resize(header.num_parts as usize, None);
        }
        self.len += data.len();
        self.received += 1;
        self.parts[index] = Some(data);
        Ok(self.is_complete())
    }

    /// Puts the file together, and decompresses it if it has to be. Returns
    /// its type and contents.
    pub fn finish(&self) -> Result<(FileType, Vec<u8>), Error> {
        let header = match self.header {
            Some(header) if self.is_complete() => header,
            _ => return Err(Error::Incomplete),
        };
        let mut data = Vec::with_capacity(self.len);
        for part in self.parts.iter().flatten() {
            data.extend_from_slice(part);
        }
        if header.encoding == Encoding::Zlib {
            data = inflate(&data, self.max_len)?;
        }
        Ok((header.file_type, data))
    }
}

/// Puts a file back together from all its parts, in any order. Returns its
/// type and contents, which cannot be longer than
/// [`Joiner::DEFAULT_MAX_LEN`]: use a [`Joiner`] to choose.
#[cfg(feature = "alloc")]
pub fn join<S: AsRef<str>>(parts: &[S]) -> Result<(FileType, Vec<u8>), Error> {
    let mut joiner = Joiner::new();
    for part in parts {
        joiner.receive(part.as_ref())?;
    }
    joiner.finish()
}

#[cfg(test)]
mod tests;
