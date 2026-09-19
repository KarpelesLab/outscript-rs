//! Uniform Resources (BCR-2020-005), the `ur:` strings hardware wallets
//! exchange as QR codes. Only the strings are handled here; rendering or
//! scanning QR codes is left to the caller.
//!
//! A UR carries a CBOR payload, encoded with minimal [`bytewords`], under a
//! type such as `crypto-psbt`:
//!
//! - single-part: `ur:<type>/<bytewords>`
//! - multi-part: `ur:<type>/<seq>-<count>/<bytewords>`, where each part is a
//!   fountain-coded fragment of the payload. The first `count` parts are the
//!   payload's fragments in order, and those after them are XORs of several
//!   fragments, so a receiver that missed some parts can carry on with
//!   whichever come next.
//!
//! Without `alloc`, [`Ur::parse`] splits a string without copying,
//! [`Ur::decode_to_slice`] decodes its body, and [`encode_to_slice`] writes a
//! single-part UR. With `alloc`, an `Encoder` produces the parts of a payload
//! of any length and a `Decoder` puts them back together.
//!
//! Strings are produced in lowercase and parsed whatever their case: they are
//! usually uppercased (`str::to_ascii_uppercase`) before going into a QR code,
//! whose alphanumeric mode has no lowercase.
//!
//! Most payloads are a single CBOR byte string: see `bytes_to_cbor` and
//! `cbor_to_bytes`.
//!
//! ```
//! # #[cfg(feature = "alloc")] {
//! use outscript::bcur::{self, Decoder, Encoder};
//!
//! let psbt = [0x70, 0x73, 0x62, 0x74, 0xff, 0x01, 0x00];
//! let cbor = bcur::bytes_to_cbor(&psbt);
//!
//! // fragments of at most 4 bytes, to force several parts
//! let mut encoder = Encoder::new(bcur::TYPE_CRYPTO_PSBT, &cbor, 4).unwrap();
//! let mut decoder = Decoder::new();
//! while !decoder.receive(&encoder.next_part()).unwrap() {}
//!
//! assert_eq!(decoder.ur_type(), Some("crypto-psbt"));
//! assert_eq!(bcur::cbor_to_bytes(decoder.message().unwrap()).unwrap(), psbt);
//! # }
//! ```

pub mod bytewords;
#[cfg(feature = "alloc")]
mod fountain;

#[cfg(feature = "alloc")]
pub use fountain::{Decoder, Encoder};

#[cfg(feature = "alloc")]
use crate::prelude::*;

use bytewords::Style;

/// The UR type of an arbitrary byte string.
pub const TYPE_BYTES: &str = "bytes";
/// The UR type of a PSBT (BCR-2020-006), as most wallets produce and expect.
pub const TYPE_CRYPTO_PSBT: &str = "crypto-psbt";
/// The UR type of a PSBT in the second generation of the registry, which
/// dropped the `crypto-` prefixes.
pub const TYPE_PSBT: &str = "psbt";

/// Errors from UR and bytewords operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The string does not start with `ur:`.
    InvalidScheme,
    /// The UR type is missing, or has characters other than letters, digits
    /// and hyphens.
    InvalidType,
    /// The `<seq>-<count>` component is malformed, or disagrees with the part
    /// it comes with.
    InvalidSequence,
    /// A word is not one of the bytewords.
    InvalidWord,
    /// The bytewords are too short to hold a checksum, or are cut mid-word.
    InvalidLength,
    /// The checksum of the bytewords, or of the reassembled message, does not
    /// verify.
    BadChecksum,
    /// The output buffer is too small.
    BufferTooSmall,
    /// The body of a multi-part UR is not a well-formed fountain part.
    InvalidPart,
    /// A multi-part UR where a single-part one is required.
    MultiPart,
    /// The message to encode is empty.
    EmptyMessage,
    /// The maximum fragment length is zero.
    InvalidFragmentLen,
    /// The message, or its number of fragments, exceeds the allowed maximum.
    TooLarge,
    /// The part belongs to a different message than the previous ones.
    InconsistentPart,
    /// The part has a different UR type than the previous ones.
    TypeMismatch,
    /// The CBOR is not a single definite-length byte string.
    InvalidCbor,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::InvalidScheme => "not a UR (missing ur: scheme)",
            Error::InvalidType => "invalid UR type",
            Error::InvalidSequence => "invalid UR sequence",
            Error::InvalidWord => "invalid byteword",
            Error::InvalidLength => "invalid bytewords length",
            Error::BadChecksum => "bad UR checksum",
            Error::BufferTooSmall => "UR output buffer too small",
            Error::InvalidPart => "invalid UR fountain part",
            Error::MultiPart => "unexpected multi-part UR",
            Error::EmptyMessage => "empty UR message",
            Error::InvalidFragmentLen => "invalid UR fragment length",
            Error::TooLarge => "UR message too large",
            Error::InconsistentPart => "UR part is inconsistent with previous ones",
            Error::TypeMismatch => "UR part has a different type than previous ones",
            Error::InvalidCbor => "UR payload is not a CBOR byte string",
        })
    }
}

impl core::error::Error for Error {}

/// CRC-32 (IEEE 802.3, as in zlib and PNG), by nibbles: a 16-entry table
/// keeps the footprint small on embedded targets.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Crc32(u32);

const CRC_TABLE: [u32; 16] = {
    let mut table = [0u32; 16];
    let mut i = 0;
    while i < 16 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 4 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

impl Crc32 {
    pub(crate) fn new() -> Self {
        Crc32(!0)
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.0 ^= byte as u32;
            self.0 = CRC_TABLE[(self.0 & 15) as usize] ^ (self.0 >> 4);
            self.0 = CRC_TABLE[(self.0 & 15) as usize] ^ (self.0 >> 4);
        }
    }

    pub(crate) fn finish(self) -> u32 {
        !self.0
    }
}

/// The CRC-32 (IEEE 802.3) of `data`: the checksum bytewords append, and the
/// one multi-part URs identify their message with.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(data);
    crc.finish()
}

/// Checks a UR type: letters, digits and hyphens, in lowercase unless
/// `any_case`.
fn validate_type(ur_type: &str, any_case: bool) -> Result<(), Error> {
    let valid = |c: u8| {
        c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == b'-'
            || any_case && c.is_ascii_uppercase()
    };
    if ur_type.is_empty() || !ur_type.bytes().all(valid) {
        return Err(Error::InvalidType);
    }
    Ok(())
}

/// Parses a positive decimal number: digits only, no sign.
fn parse_index(text: &str) -> Option<u32> {
    if text.is_empty() {
        return None;
    }
    let mut value = 0u32;
    for c in text.bytes() {
        let digit = (c as char).to_digit(10)?;
        value = value.checked_mul(10)?.checked_add(digit)?;
    }
    (value > 0).then_some(value)
}

/// The components of a UR string, borrowed from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ur<'a> {
    /// The UR type, such as `crypto-psbt`, in the case it came in: compare it
    /// with `eq_ignore_ascii_case`.
    pub ur_type: &'a str,
    /// For a multi-part UR, the sequence number of this part (from 1) and the
    /// number of fragments the message was cut into. The sequence number
    /// exceeds the count for the fountain-coded parts.
    pub sequence: Option<(u32, u32)>,
    /// The minimal bytewords: of the CBOR payload for a single-part UR, of a
    /// fountain part for a multi-part one.
    pub body: &'a str,
}

impl<'a> Ur<'a> {
    /// Splits a UR string into its components, of any ASCII case. The body is
    /// not decoded, see [`Ur::decode_to_slice`].
    pub fn parse(text: &'a str) -> Result<Self, Error> {
        let rest = match text.split_at_checked(3) {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("ur:") => rest,
            _ => return Err(Error::InvalidScheme),
        };
        let (ur_type, rest) = rest.split_once('/').ok_or(Error::InvalidType)?;
        validate_type(ur_type, true)?;
        let (sequence, body) = match rest.rsplit_once('/') {
            None => (None, rest),
            Some((sequence, body)) => {
                let (seq_num, seq_len) = sequence.split_once('-').ok_or(Error::InvalidSequence)?;
                let seq_num = parse_index(seq_num).ok_or(Error::InvalidSequence)?;
                let seq_len = parse_index(seq_len).ok_or(Error::InvalidSequence)?;
                (Some((seq_num, seq_len)), body)
            }
        };
        Ok(Ur {
            ur_type,
            sequence,
            body,
        })
    }

    /// Whether this is one part of a multi-part UR.
    pub fn is_multi_part(&self) -> bool {
        self.sequence.is_some()
    }

    /// An upper bound on the length [`Ur::decode_to_slice`] writes.
    pub fn decoded_len_bound(&self) -> usize {
        bytewords::decoded_len_bound(self.body.len(), Style::Minimal)
    }

    /// Decodes the body into `out`, verifying its checksum. Returns the number
    /// of bytes written: the CBOR payload of a single-part UR, or one
    /// CBOR-encoded fountain part of a multi-part one.
    pub fn decode_to_slice(&self, out: &mut [u8]) -> Result<usize, Error> {
        bytewords::decode_to_slice(self.body, Style::Minimal, out)
    }

    /// Decodes the body, verifying its checksum: the CBOR payload of a
    /// single-part UR, or one CBOR-encoded fountain part of a multi-part one.
    #[cfg(feature = "alloc")]
    pub fn decode(&self) -> Result<Vec<u8>, Error> {
        bytewords::decode(self.body, Style::Minimal)
    }
}

/// The length of a single-part UR for a type of `type_len` characters and
/// `cbor_len` bytes of CBOR.
pub const fn encoded_len(type_len: usize, cbor_len: usize) -> usize {
    3 + type_len + 1 + bytewords::encoded_len(cbor_len, Style::Minimal)
}

/// Writes the single-part UR of a CBOR payload into `out`, returning the
/// number of (ASCII) bytes written.
pub fn encode_to_slice(ur_type: &str, cbor: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    validate_type(ur_type, false)?;
    let len = encoded_len(ur_type.len(), cbor.len());
    let out = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;
    let (head, body) = out.split_at_mut(3 + ur_type.len() + 1);
    head[..3].copy_from_slice(b"ur:");
    head[3..3 + ur_type.len()].copy_from_slice(ur_type.as_bytes());
    head[3 + ur_type.len()] = b'/';
    bytewords::encode_to_slice(cbor, Style::Minimal, body)?;
    Ok(len)
}

/// Encodes a CBOR payload as a single-part UR, whatever its length. Use an
/// [`Encoder`] to cut long payloads into parts.
#[cfg(feature = "alloc")]
pub fn encode(ur_type: &str, cbor: &[u8]) -> Result<String, Error> {
    let mut buf = vec![0u8; encoded_len(ur_type.len(), cbor.len())];
    encode_to_slice(ur_type, cbor, &mut buf)?;
    Ok(String::from_utf8(buf).expect("URs are ASCII"))
}

/// Decodes a single-part UR into its type, in lowercase, and CBOR payload.
/// Multi-part URs go through a [`Decoder`].
#[cfg(feature = "alloc")]
pub fn decode(text: &str) -> Result<(String, Vec<u8>), Error> {
    let ur = Ur::parse(text)?;
    if ur.is_multi_part() {
        return Err(Error::MultiPart);
    }
    Ok((ur.ur_type.to_ascii_lowercase(), ur.decode()?))
}

/// Wraps `data` as a CBOR byte string, the payload of `bytes`, `crypto-psbt`
/// and `psbt` URs.
#[cfg(feature = "alloc")]
pub fn bytes_to_cbor(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 9);
    crate::cbor::write_head(&mut out, 2, data.len() as u64);
    out.extend_from_slice(data);
    out
}

/// Unwraps a CBOR byte string, the payload of `bytes`, `crypto-psbt` and
/// `psbt` URs.
#[cfg(feature = "alloc")]
pub fn cbor_to_bytes(cbor: &[u8]) -> Result<&[u8], Error> {
    let mut pos = 0;
    match crate::cbor::read_head(cbor, &mut pos) {
        Ok((2, len, false)) => match cbor.get(pos..) {
            Some(data) if data.len() as u64 == len => Ok(data),
            _ => Err(Error::InvalidCbor),
        },
        _ => Err(Error::InvalidCbor),
    }
}

#[cfg(test)]
mod tests;
