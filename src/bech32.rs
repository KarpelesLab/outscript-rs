//! Bech32 / Bech32m segwit addresses (BIP-173 / BIP-350) and Bitcoin Cash
//! CashAddr encoding.
//!
//! Port of the parts of `github.com/KarpelesLab/bech32m` used by outscript:
//! `SegwitAddrEncode`/`SegwitAddrDecode` and `CashAddrEncode`/`CashAddrDecode`.
//!
//! The `*_to_slice` functions work on caller-provided buffers and never
//! allocate; the `String`/`Vec` variants are `alloc` conveniences over them.
//! No 90-character limit is enforced, so the generic codec also serves Cardano
//! addresses (CIP-19), which routinely exceed it.

#[cfg(feature = "alloc")]
use crate::prelude::*;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The checksum variant of a bech32 string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// BIP-173 bech32 (segwit v0, Cardano).
    Bech32,
    /// BIP-350 bech32m (segwit v1+).
    Bech32m,
}

impl Variant {
    fn constant(self) -> u32 {
        match self {
            Variant::Bech32 => 1,
            Variant::Bech32m => 0x2bc8_30a3,
        }
    }
}

/// Error type for bech32/cashaddr operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The string mixes upper- and lower-case characters.
    MixedCase,
    /// The separator is missing or leaves no room for the checksum.
    InvalidSeparator,
    /// A character is outside the bech32 alphabet.
    InvalidChar,
    /// The checksum does not verify.
    InvalidChecksum,
    /// The data part has non-zero or excess padding bits.
    InvalidPadding,
    /// The human-readable part (or CashAddr prefix) is not the expected one.
    PrefixMismatch,
    /// The segwit witness version is above 16.
    InvalidWitnessVersion,
    /// The witness program length is invalid for its version.
    InvalidProgramLength,
    /// The segwit address uses the wrong checksum variant for its version.
    WrongVariant,
    /// The CashAddr hash length is not one of the defined sizes, or does not
    /// match the version byte.
    InvalidHashLength,
    /// The CashAddr version byte is invalid.
    InvalidVersionByte,
    /// The decoded payload is empty.
    EmptyPayload,
    /// The output buffer is too small for the result.
    BufferTooSmall,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::MixedCase => "mixed case bech32 string",
            Error::InvalidSeparator => "invalid bech32 separator position",
            Error::InvalidChar => "invalid bech32 data character",
            Error::InvalidChecksum => "invalid bech32 checksum",
            Error::InvalidPadding => "invalid bech32 padding",
            Error::PrefixMismatch => "unexpected bech32 human-readable part",
            Error::InvalidWitnessVersion => "invalid witness version",
            Error::InvalidProgramLength => "invalid witness program length",
            Error::WrongVariant => "wrong bech32 variant for witness version",
            Error::InvalidHashLength => "invalid cashaddr hash length",
            Error::InvalidVersionByte => "invalid cashaddr version byte",
            Error::EmptyPayload => "empty bech32 payload",
            Error::BufferTooSmall => "bech32 output buffer too small",
        })
    }
}
impl core::error::Error for Error {}

fn charset_rev(c: u8) -> Option<u8> {
    CHARSET
        .iter()
        .position(|&x| x == c.to_ascii_lowercase())
        .map(|p| p as u8)
}

/// Appends bytes to a caller buffer, tracking the write position.
struct SliceWriter<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl SliceWriter<'_> {
    fn push(&mut self, b: u8) -> Result<(), Error> {
        *self.out.get_mut(self.pos).ok_or(Error::BufferTooSmall)? = b;
        self.pos += 1;
        Ok(())
    }
    fn push_slice(&mut self, s: &[u8]) -> Result<(), Error> {
        let end = self.pos + s.len();
        self.out
            .get_mut(self.pos..end)
            .ok_or(Error::BufferTooSmall)?
            .copy_from_slice(s);
        self.pos = end;
        Ok(())
    }
}

/// Regroups `data` between bit widths, feeding each output group to `emit`.
/// `pad` controls whether trailing bits are padded; without it, leftover bits
/// must be zero and fewer than `from`.
fn convert_bits<I, F>(data: I, from: u32, to: u32, pad: bool, mut emit: F) -> Result<(), Error>
where
    I: IntoIterator<Item = u8>,
    F: FnMut(u8) -> Result<(), Error>,
{
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << to) - 1;
    let max_acc: u32 = (1 << (from + to - 1)) - 1;
    for value in data {
        let v = value as u32;
        if (v >> from) != 0 {
            return Err(Error::InvalidPadding);
        }
        acc = ((acc << from) | v) & max_acc;
        bits += from;
        while bits >= to {
            bits -= to;
            emit(((acc >> bits) & maxv) as u8)?;
        }
    }
    if pad {
        if bits > 0 {
            emit(((acc << (to - bits)) & maxv) as u8)?;
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(Error::InvalidPadding);
    }
    Ok(())
}

// ----- bech32 core -----

fn bech32_polymod_step(chk: u32, v: u8) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let b = chk >> 25;
    let mut chk = ((chk & 0x1ff_ffff) << 5) ^ (v as u32);
    for (i, g) in GEN.iter().enumerate() {
        if (b >> i) & 1 == 1 {
            chk ^= g;
        }
    }
    chk
}

/// The polymod state after the expanded (lower-cased) human-readable part.
fn bech32_hrp_polymod(hrp: &[u8]) -> u32 {
    let mut chk = 1;
    for &c in hrp {
        chk = bech32_polymod_step(chk, c.to_ascii_lowercase() >> 5);
    }
    chk = bech32_polymod_step(chk, 0);
    for &c in hrp {
        chk = bech32_polymod_step(chk, c.to_ascii_lowercase() & 31);
    }
    chk
}

/// Writes `hrp`, the separator, an optional 5-bit prefix value, the 8→5 bit
/// conversion of `payload`, and the checksum.
fn bech32_encode_raw(
    hrp: &str,
    prefix5: Option<u8>,
    payload: &[u8],
    variant: Variant,
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut w = SliceWriter { out, pos: 0 };
    w.push_slice(hrp.as_bytes())?;
    w.push(b'1')?;
    let mut chk = bech32_hrp_polymod(hrp.as_bytes());
    let mut emit = |v: u8| {
        chk = bech32_polymod_step(chk, v);
        w.push(CHARSET[v as usize])
    };
    if let Some(v) = prefix5 {
        emit(v)?;
    }
    convert_bits(payload.iter().copied(), 8, 5, true, &mut emit)?;
    for _ in 0..6 {
        chk = bech32_polymod_step(chk, 0);
    }
    chk ^= variant.constant();
    for i in 0..6 {
        w.push(CHARSET[((chk >> (5 * (5 - i))) & 31) as usize])?;
    }
    Ok(w.pos)
}

/// Splits and verifies a bech32/bech32m string, returning the human-readable
/// part (as written), the data characters without the checksum, and the
/// checksum variant.
fn bech32_parse(s: &str) -> Result<(&str, &[u8], Variant), Error> {
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Error::MixedCase);
    }
    let pos = s.rfind('1').ok_or(Error::InvalidSeparator)?;
    if pos == 0 || pos + 7 > s.len() {
        return Err(Error::InvalidSeparator);
    }
    let (hrp, rest) = (&s[..pos], &s.as_bytes()[pos + 1..]);
    let mut chk = bech32_hrp_polymod(hrp.as_bytes());
    for &c in rest {
        chk = bech32_polymod_step(chk, charset_rev(c).ok_or(Error::InvalidChar)?);
    }
    let variant = if chk == Variant::Bech32.constant() {
        Variant::Bech32
    } else if chk == Variant::Bech32m.constant() {
        Variant::Bech32m
    } else {
        return Err(Error::InvalidChecksum);
    };
    Ok((hrp, &rest[..rest.len() - 6], variant))
}

/// Maps already-validated data characters to their 5-bit values.
fn values(chars: &[u8]) -> impl Iterator<Item = u8> + '_ {
    chars.iter().map(|&c| charset_rev(c).unwrap_or(0))
}

/// Case-insensitively compares a parsed prefix with the expected (lower-case)
/// one.
fn prefix_matches(got: &str, want: &str) -> bool {
    got.len() == want.len()
        && got
            .bytes()
            .zip(want.bytes())
            .all(|(a, b)| a.to_ascii_lowercase() == b)
}

/// Encodes 8-bit `data` as a bech32 string of the given variant into `out`,
/// returning the number of (ASCII) bytes written. `hrp` must be lower-case.
pub fn encode_to_slice(
    hrp: &str,
    data: &[u8],
    variant: Variant,
    out: &mut [u8],
) -> Result<usize, Error> {
    bech32_encode_raw(hrp, None, data, variant, out)
}

/// Decodes a bech32/bech32m string, writing its 8-bit payload into `out`.
/// Returns the human-readable part (as written in `s`), the payload length and
/// the checksum variant.
pub fn decode_to_slice<'s>(s: &'s str, out: &mut [u8]) -> Result<(&'s str, usize, Variant), Error> {
    let (hrp, chars, variant) = bech32_parse(s)?;
    let mut w = SliceWriter { out, pos: 0 };
    convert_bits(values(chars), 5, 8, false, |b| w.push(b))?;
    Ok((hrp, w.pos, variant))
}

// ----- segwit -----

fn check_program(version: u8, len: usize) -> Result<(), Error> {
    if version > 16 {
        return Err(Error::InvalidWitnessVersion);
    }
    if !(2..=40).contains(&len) || (version == 0 && len != 20 && len != 32) {
        return Err(Error::InvalidProgramLength);
    }
    Ok(())
}

/// Encodes a segwit address for the given human-readable part, witness version
/// (0..=16) and witness program into `out`, returning the number of (ASCII)
/// bytes written. 90 bytes always suffice for a standard hrp.
pub fn segwit_addr_encode_to_slice(
    hrp: &str,
    version: u8,
    program: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    check_program(version, program.len())?;
    let variant = if version == 0 {
        Variant::Bech32
    } else {
        Variant::Bech32m
    };
    bech32_encode_raw(hrp, Some(version), program, variant, out)
}

/// Decodes a segwit address, verifying it uses the expected human-readable
/// part, and writes the witness program into `out` (40 bytes always suffice).
/// Returns the witness version and program length.
pub fn segwit_addr_decode_to_slice(
    hrp: &str,
    addr: &str,
    out: &mut [u8],
) -> Result<(u8, usize), Error> {
    let (got_hrp, chars, variant) = bech32_parse(addr)?;
    if !prefix_matches(got_hrp, hrp) {
        return Err(Error::PrefixMismatch);
    }
    let (&first, rest) = chars.split_first().ok_or(Error::EmptyPayload)?;
    let version = charset_rev(first).unwrap_or(0);
    if version > 16 {
        return Err(Error::InvalidWitnessVersion);
    }
    let mut w = SliceWriter { out, pos: 0 };
    convert_bits(values(rest), 5, 8, false, |b| {
        // Stop at the maximum program length instead of overrunning `out`.
        if w.pos == 40 {
            return Err(Error::InvalidProgramLength);
        }
        w.push(b)
    })?;
    check_program(version, w.pos)?;
    let expected = if version == 0 {
        Variant::Bech32
    } else {
        Variant::Bech32m
    };
    if variant != expected {
        return Err(Error::WrongVariant);
    }
    Ok((version, w.pos))
}

/// Encodes a segwit address for the given human-readable part, witness version
/// (0..=16) and witness program.
#[cfg(feature = "alloc")]
pub fn segwit_addr_encode(hrp: &str, version: u8, program: &[u8]) -> Result<String, Error> {
    let mut buf = vec![0u8; hrp.len() + 1 + 1 + (program.len() * 8).div_ceil(5) + 6];
    let n = segwit_addr_encode_to_slice(hrp, version, program, &mut buf)?;
    buf.truncate(n);
    Ok(String::from_utf8(buf).expect("bech32 output is ASCII"))
}

/// Decodes a segwit address, verifying it uses the expected human-readable part.
/// Returns the witness version and program.
#[cfg(feature = "alloc")]
pub fn segwit_addr_decode(hrp: &str, addr: &str) -> Result<(u8, Vec<u8>), Error> {
    let mut buf = [0u8; 40];
    let (version, n) = segwit_addr_decode_to_slice(hrp, addr, &mut buf)?;
    Ok((version, buf[..n].to_vec()))
}

// ----- CashAddr (Bitcoin Cash) -----

// The CashAddr polymod generator constants are 40-bit values defined by the
// Bitcoin Cash spec; their natural grouping is not byte-aligned.
#[allow(clippy::unusual_byte_groupings)]
fn cashaddr_polymod_step(c: u64, d: u8) -> u64 {
    let c0 = (c >> 35) as u8;
    let mut c = ((c & 0x07_ffff_ffff) << 5) ^ (d as u64);
    if c0 & 0x01 != 0 {
        c ^= 0x98f2_bc8e_61;
    }
    if c0 & 0x02 != 0 {
        c ^= 0x79b7_6d99_e2;
    }
    if c0 & 0x04 != 0 {
        c ^= 0xf33e_5fb3_c4;
    }
    if c0 & 0x08 != 0 {
        c ^= 0xae2e_abe2_a8;
    }
    if c0 & 0x10 != 0 {
        c ^= 0x1e4f_43e4_70;
    }
    c
}

fn cashaddr_prefix(prefix: &str) -> &str {
    prefix.strip_suffix(':').unwrap_or(prefix)
}

/// The polymod state after the expanded prefix.
fn cashaddr_prefix_polymod(prefix: &str) -> u64 {
    let mut c = 1;
    for b in prefix.bytes() {
        c = cashaddr_polymod_step(c, b & 0x1f);
    }
    cashaddr_polymod_step(c, 0)
}

fn size_bits(len: usize) -> Option<u8> {
    match len {
        20 => Some(0),
        24 => Some(1),
        28 => Some(2),
        32 => Some(3),
        40 => Some(4),
        48 => Some(5),
        56 => Some(6),
        64 => Some(7),
        _ => None,
    }
}

fn size_from_bits(bits: u8) -> usize {
    match bits {
        0 => 20,
        1 => 24,
        2 => 28,
        3 => 32,
        4 => 40,
        5 => 48,
        6 => 56,
        _ => 64,
    }
}

/// Encodes a Bitcoin Cash CashAddr into `out`, returning the number of (ASCII)
/// bytes written. `prefix` may include a trailing colon (e.g.
/// "bitcoincash:"); the output is `prefix:payload`.
pub fn cashaddr_encode_to_slice(
    prefix: &str,
    version_type: u8,
    hash: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let p = cashaddr_prefix(prefix);
    let size = size_bits(hash.len()).ok_or(Error::InvalidHashLength)?;
    let version_byte = (version_type << 3) | size;

    let mut w = SliceWriter { out, pos: 0 };
    w.push_slice(p.as_bytes())?;
    w.push(b':')?;
    let mut chk = cashaddr_prefix_polymod(p);
    convert_bits(
        core::iter::once(version_byte).chain(hash.iter().copied()),
        8,
        5,
        true,
        |v| {
            chk = cashaddr_polymod_step(chk, v);
            w.push(CHARSET[v as usize])
        },
    )?;
    for _ in 0..8 {
        chk = cashaddr_polymod_step(chk, 0);
    }
    chk ^= 1;
    for i in 0..8 {
        w.push(CHARSET[((chk >> (5 * (7 - i))) & 0x1f) as usize])?;
    }
    Ok(w.pos)
}

/// Decodes a Bitcoin Cash CashAddr, verifying the expected prefix, and writes
/// the hash into `out` (64 bytes always suffice). Returns the type (0 is P2PKH,
/// 1 is P2SH) and the hash length.
pub fn cashaddr_decode_to_slice(
    prefix: &str,
    addr: &str,
    out: &mut [u8],
) -> Result<(u8, usize), Error> {
    let p = cashaddr_prefix(prefix);
    let body = match addr.split_once(':') {
        Some((pre, rest)) => {
            if !prefix_matches(pre, p) {
                return Err(Error::PrefixMismatch);
            }
            rest
        }
        None => addr,
    };

    let mut chk = cashaddr_prefix_polymod(p);
    for c in body.bytes() {
        chk = cashaddr_polymod_step(chk, charset_rev(c).ok_or(Error::InvalidChar)?);
    }
    if chk ^ 1 != 0 {
        return Err(Error::InvalidChecksum);
    }
    let payload5 = body
        .as_bytes()
        .get(..body.len().saturating_sub(8))
        .filter(|p| !p.is_empty())
        .ok_or(Error::EmptyPayload)?;

    let mut version_byte = None;
    let mut w = SliceWriter { out, pos: 0 };
    convert_bits(values(payload5), 5, 8, false, |b| {
        if version_byte.is_none() {
            version_byte = Some(b);
            Ok(())
        } else if w.pos == 64 {
            Err(Error::InvalidHashLength)
        } else {
            w.push(b)
        }
    })?;
    let version_byte = version_byte.ok_or(Error::EmptyPayload)?;
    if version_byte & 0x80 != 0 {
        return Err(Error::InvalidVersionByte);
    }
    if w.pos != size_from_bits(version_byte & 0x07) {
        return Err(Error::InvalidHashLength);
    }
    Ok(((version_byte >> 3) & 0x0f, w.pos))
}

/// Encodes a Bitcoin Cash CashAddr. `prefix` may include a trailing colon
/// (e.g. "bitcoincash:"); the returned string is `prefix:payload`.
#[cfg(feature = "alloc")]
pub fn cashaddr_encode(prefix: &str, version_type: u8, hash: &[u8]) -> Result<String, Error> {
    let mut buf = vec![0u8; prefix.len() + 1 + ((hash.len() + 1) * 8).div_ceil(5) + 8];
    let n = cashaddr_encode_to_slice(prefix, version_type, hash, &mut buf)?;
    buf.truncate(n);
    Ok(String::from_utf8(buf).expect("cashaddr output is ASCII"))
}

/// Decodes a Bitcoin Cash CashAddr, verifying the expected prefix. Returns the
/// (type, hash) pair where type 0 is P2PKH and type 1 is P2SH.
#[cfg(feature = "alloc")]
pub fn cashaddr_decode(prefix: &str, addr: &str) -> Result<(u8, Vec<u8>), Error> {
    let mut buf = [0u8; 64];
    let (typ, n) = cashaddr_decode_to_slice(prefix, addr, &mut buf)?;
    Ok((typ, buf[..n].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIP173_PROG: &str = "751e76e8199196d454941c45d1b3a323f1433bd6";
    const BIP173_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const CASHADDR: &str = "bitcoincash:qpusjxtjrpkyf843mmfzk78yp5qfhhcq3yv38ma5lm";

    #[test]
    fn segwit_v0_slice_roundtrip() {
        let prog = hex::decode(BIP173_PROG).unwrap();
        let mut out = [0u8; 90];
        let n = segwit_addr_encode_to_slice("bc", 0, &prog, &mut out).unwrap();
        assert_eq!(&out[..n], BIP173_ADDR.as_bytes());
        let mut p = [0u8; 40];
        assert_eq!(
            segwit_addr_decode_to_slice("bc", BIP173_ADDR, &mut p),
            Ok((0, 20))
        );
        assert_eq!(&p[..20], &prog[..]);
        // upper-case addresses are valid too
        let upper = BIP173_ADDR.to_ascii_uppercase();
        assert_eq!(
            segwit_addr_decode_to_slice("bc", &upper, &mut p),
            Ok((0, 20))
        );
        assert_eq!(
            segwit_addr_decode_to_slice("tb", BIP173_ADDR, &mut p),
            Err(Error::PrefixMismatch)
        );
        assert_eq!(
            segwit_addr_encode_to_slice("bc", 0, &prog, &mut out[..41]),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn cashaddr_slice_roundtrip() {
        let mut hash = [0u8; 64];
        let (typ, n) = cashaddr_decode_to_slice("bitcoincash:", CASHADDR, &mut hash).unwrap();
        assert_eq!((typ, n), (0, 20));
        let mut out = [0u8; 64];
        let m = cashaddr_encode_to_slice("bitcoincash:", 0, &hash[..n], &mut out).unwrap();
        assert_eq!(&out[..m], CASHADDR.as_bytes());
        // prefix-less form
        let bare = CASHADDR.strip_prefix("bitcoincash:").unwrap();
        assert_eq!(
            cashaddr_decode_to_slice("bitcoincash:", bare, &mut hash),
            Ok((0, 20))
        );
    }

    #[test]
    fn cashaddr_short_body_is_an_error() {
        let mut hash = [0u8; 64];
        assert!(cashaddr_decode_to_slice("bitcoincash:", "bitcoincash:qp", &mut hash).is_err());
        assert!(cashaddr_decode_to_slice("bitcoincash:", "", &mut hash).is_err());
    }

    #[test]
    fn generic_bech32_roundtrip() {
        let data = [0xabu8; 57];
        let mut out = [0u8; 128];
        let n = encode_to_slice("addr", &data, Variant::Bech32, &mut out).unwrap();
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.len() > 90);
        let mut dec = [0u8; 64];
        let (hrp, len, variant) = decode_to_slice(s, &mut dec).unwrap();
        assert_eq!((hrp, variant), ("addr", Variant::Bech32));
        assert_eq!(&dec[..len], &data[..]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn segwit_v0_roundtrip() {
        // BIP-173 test vector.
        let prog = hex::decode(BIP173_PROG).unwrap();
        let addr = segwit_addr_encode("bc", 0, &prog).unwrap();
        assert_eq!(addr, BIP173_ADDR);
        let (v, p) = segwit_addr_decode("bc", &addr).unwrap();
        assert_eq!(v, 0);
        assert_eq!(p, prog);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn segwit_v1_taproot_roundtrip() {
        let prog = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
        let addr = segwit_addr_encode("bc", 1, &prog).unwrap();
        let (v, p) = segwit_addr_decode("bc", &addr).unwrap();
        assert_eq!(v, 1);
        assert_eq!(p, prog);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn cashaddr_roundtrip() {
        // From the outscript address test vector:
        // p2pkh bitcoincash:qpusjxtjrpkyf843mmfzk78yp5qfhhcq3yv38ma5lm
        let (typ, hash) = cashaddr_decode("bitcoincash:", CASHADDR).unwrap();
        assert_eq!(typ, 0);
        let re = cashaddr_encode("bitcoincash:", 0, &hash).unwrap();
        assert_eq!(re, CASHADDR);
    }
}
