//! Address parsing and encoding across Bitcoin-family, EVM, Massa and Solana
//! networks (port of `address.go`, `eip55.go`).

use purecrypto::hash::{Digest, Sha256};

use crate::base58;
use crate::bech32;
use crate::hash::{dsha256, keccak256_once, sha256_once};
use crate::pushbytes::parse_push_bytes;
use crate::script::ScriptBytes;

#[cfg(feature = "alloc")]
use crate::out::Out;
#[cfg(feature = "alloc")]
use crate::prelude::*;

/// Errors from heap-free address encoding and decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The script format has no address form.
    UnsupportedFormat,
    /// The network is not supported for this format.
    UnsupportedNetwork,
    /// The script bytes do not match their format.
    InvalidScript,
    /// A key hash or payload has the wrong length.
    InvalidLength,
    /// The output buffer is too small.
    BufferTooSmall,
    /// A bech32/CashAddr encoding error.
    Bech32(bech32::Error),
    /// The string is not a recognized address encoding.
    InvalidAddress,
    /// The address checksum does not verify.
    BadChecksum,
    /// The address belongs to a different network than the one requested.
    NetworkMismatch,
    /// The base58 version byte, witness version or address type is not
    /// supported.
    UnsupportedVersion(u8),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::UnsupportedFormat => f.write_str("format has no address form"),
            Error::UnsupportedNetwork => f.write_str("unsupported network for this address"),
            Error::InvalidScript => f.write_str("invalid script for address type"),
            Error::InvalidLength => f.write_str("invalid address payload length"),
            Error::BufferTooSmall => f.write_str("address output buffer too small"),
            Error::Bech32(e) => e.fmt(f),
            Error::InvalidAddress => f.write_str("unsupported or malformed address"),
            Error::BadChecksum => f.write_str("bad address checksum"),
            Error::NetworkMismatch => f.write_str("address is for a different network"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported address version {v:#x}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Self {
        match e {
            bech32::Error::BufferTooSmall => Error::BufferTooSmall,
            e => Error::Bech32(e),
        }
    }
}

impl From<base58::Error> for Error {
    fn from(_: base58::Error) -> Self {
        // encoding only fails for lack of space
        Error::BufferTooSmall
    }
}

/// An upper bound on the length of any address [`encode_address_to_slice`]
/// produces for a built-in format.
pub const MAX_ADDRESS_LEN: usize = crate::cardano::MAX_CARDANO_ADDRESS_LEN;

/// base58check versions of P2PKH and P2SH addresses for a network.
fn base58_versions(network: &str) -> Option<(u8, u8)> {
    Some(match network {
        "litecoin" => (0x30, 0x32),
        "namecoin" => (0x34, 0x0d),
        "dogecoin" => (0x1e, 0x16),
        "monacoin" => (0x32, 0x37),
        "electraproto" => (0x37, 0x89),
        "dash" => (0x4c, 0x10),
        "bitcoin-testnet" => (0x6f, 0xc4),
        "bitcoin" => (0x00, 0x05),
        _ => return None,
    })
}

/// The segwit human-readable part for a network.
fn segwit_hrp(network: &str) -> Option<&'static str> {
    Some(match network {
        "litecoin" => "ltc",
        "namecoin" => "nc",
        "bitcoin" => "bc",
        "bitcoin-testnet" => "tb",
        "monacoin" => "mona",
        "electraproto" => "ep",
        _ => return None,
    })
}

/// Writes `prefix` followed by the base58 of `data || dsha256(data)[..4]`.
fn prefixed_base58check(prefix: &[u8], data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let chk = dsha256(data);
    let body = out.get_mut(prefix.len()..).ok_or(Error::BufferTooSmall)?;
    let n =
        base58::encode_iter_to_slice(data.iter().copied().chain(chk[..4].iter().copied()), body)?;
    out[..prefix.len()].copy_from_slice(prefix);
    Ok(prefix.len() + n)
}

/// Renders the human-readable address of an output script into `out`,
/// returning the number of (ASCII) bytes written.
///
/// `format` is the script's format name (as produced by
/// [`generate_script`](crate::script::generate_script); anything after a `:`
/// is ignored, so `p2sh:p2wpkh` renders as `p2sh`), `script` its bytes, and
/// `network` selects the encoding where a format is shared between chains
/// (e.g. `bitcoin`, `litecoin`, `bitcoin-cash`, `cardano-testnet`).
/// [`MAX_ADDRESS_LEN`] bytes always suffice for built-in formats.
pub fn encode_address_to_slice(
    format: &str,
    script: &[u8],
    network: &str,
    out: &mut [u8],
) -> Result<usize, Error> {
    let base = format.split_once(':').map_or(format, |(b, _)| b);
    match base {
        "solana" => Ok(base58::encode_to_slice(script, out)?),
        "cardano" => crate::cardano::cardano_address_from_raw_to_slice(script, network, out),
        "eth" | "evm" => eip55_to_slice(script, out).ok_or(Error::BufferTooSmall),
        "massa_pubkey" => prefixed_base58check(b"P", script, out),
        "massa" => match script.split_first() {
            Some((0, rest)) => prefixed_base58check(b"AU", rest, out),
            Some((1, rest)) => prefixed_base58check(b"AS", rest, out),
            _ => Err(Error::InvalidScript),
        },
        "p2pkh" | "p2pukh" | "p2sh" => {
            let (p2sh, inner) = if base == "p2sh" {
                (true, script.get(1..script.len().saturating_sub(1)))
            } else {
                (false, script.get(2..script.len().saturating_sub(2)))
            };
            let (hash, _) = inner
                .and_then(parse_push_bytes)
                .filter(|(hash, _)| hash.len() == 20)
                .ok_or(Error::InvalidScript)?;
            if matches!(network, "bitcoin-cash" | "bitcoincash") {
                return Ok(bech32::cashaddr_encode_to_slice(
                    "bitcoincash:",
                    p2sh as u8,
                    hash,
                    out,
                )?);
            }
            let (pkh, sh) = base58_versions(network).ok_or(Error::UnsupportedNetwork)?;
            Ok(encode_base58_addr_to_slice(
                if p2sh { sh } else { pkh },
                hash,
                out,
            )?)
        }
        "p2wpkh" | "p2wsh" | "p2tr" => {
            let (hash, _) = script
                .get(1..)
                .and_then(parse_push_bytes)
                .ok_or(Error::InvalidScript)?;
            let (version, hrp) = if base == "p2tr" {
                let hrp = match network {
                    "bitcoin" => "bc",
                    "bitcoin-testnet" => "tb",
                    _ => return Err(Error::UnsupportedNetwork),
                };
                (1, hrp)
            } else {
                (0, segwit_hrp(network).ok_or(Error::UnsupportedNetwork)?)
            };
            Ok(bech32::segwit_addr_encode_to_slice(
                hrp, version, hash, out,
            )?)
        }
        _ => Err(Error::UnsupportedFormat),
    }
}

/// Writes the EIP-55 checksummed hex address (`0x...`) for `addr` (normally 20
/// bytes) into `out`, returning the number of (ASCII) bytes written —
/// `2 + 2 * addr.len()` — or `None` if `out` is too small.
pub fn eip55_to_slice(addr: &[u8], out: &mut [u8]) -> Option<usize> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let len = 2 + addr.len() * 2;
    let out = out.get_mut(..len)?;
    out[0] = b'0';
    out[1] = b'x';
    for (i, &b) in addr.iter().enumerate() {
        out[2 + 2 * i] = HEX[(b >> 4) as usize];
        out[3 + 2 * i] = HEX[(b & 0xf) as usize];
    }
    // The checksum hashes the lower-case hex digits.
    let hash = keccak256_once(&out[2..]);
    for (i, c) in out[2..].iter_mut().enumerate() {
        let hash_byte = hash[i / 2];
        let nibble = if i % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0xf
        };
        if *c > b'9' && nibble > 7 {
            *c -= 32;
        }
    }
    Some(len)
}

/// Computes the EIP-55 checksummed hex address (`0x...`) for a 20-byte address.
#[cfg(feature = "alloc")]
pub fn eip55(addr: &[u8]) -> String {
    let mut buf = vec![0u8; 2 + addr.len() * 2];
    eip55_to_slice(addr, &mut buf).expect("buffer sized for the address");
    String::from_utf8(buf).expect("hex output is ASCII")
}

/// Writes a base58check address built from a version byte and payload into
/// `out`, returning the number of (ASCII) bytes written.
/// [`base58::encoded_len_bound`]`(payload.len() + 5)` bytes always suffice
/// (35 for a standard 20-byte hash).
pub fn encode_base58_addr_to_slice(
    version: u8,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, base58::Error> {
    let mut h = Sha256::new();
    h.update(&[version]);
    h.update(payload);
    let chk = sha256_once(&h.finalize());
    let data = core::iter::once(version)
        .chain(payload.iter().copied())
        .chain(chk[..4].iter().copied());
    base58::encode_iter_to_slice(data, out)
}

/// Builds a base58check address from a version byte and payload.
#[cfg(feature = "alloc")]
pub fn encode_base58_addr(version: u8, buf: &[u8]) -> String {
    let mut out = vec![0u8; base58::encoded_len_bound(buf.len() + 5)];
    let n = encode_base58_addr_to_slice(version, buf, &mut out).expect("buffer sized by bound");
    out.truncate(n);
    String::from_utf8(out).expect("base58 output is ASCII")
}

/// An address decoded without allocating: the output script it pays to, its
/// format name and the networks it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedAddress {
    /// Format name, e.g. "p2pkh", "p2wsh", "eth", "cardano".
    pub format: &'static str,
    /// The output script (for EVM, Massa, Solana and Cardano: the raw address
    /// payload, as produced by [`generate_script`](crate::script::generate_script)).
    pub script: ScriptBytes,
    /// The networks the address is valid on.
    pub networks: &'static [&'static str],
}

impl DecodedAddress {
    pub(crate) fn new(
        format: &'static str,
        parts: &[&[u8]],
        networks: &'static [&'static str],
    ) -> Self {
        let mut script = ScriptBytes::new();
        for p in parts {
            script
                .extend_from_slice(p)
                .expect("decoded payload fits a script buffer");
        }
        DecodedAddress {
            format,
            script,
            networks,
        }
    }
}

#[cfg(feature = "alloc")]
impl From<DecodedAddress> for Out {
    fn from(a: DecodedAddress) -> Out {
        Out::make(a.format, a.script.to_vec(), a.networks)
    }
}

/// The single-network flag list for a known network name.
fn network_flags(net: &str) -> &'static [&'static str] {
    match net {
        "bitcoin" => &["bitcoin"],
        "bitcoin-cash" => &["bitcoin-cash"],
        "bitcoin-testnet" => &["bitcoin-testnet"],
        "litecoin" => &["litecoin"],
        "namecoin" => &["namecoin"],
        "dogecoin" => &["dogecoin"],
        "monacoin" => &["monacoin"],
        "electraproto" => &["electraproto"],
        "dash" => &["dash"],
        _ => &[],
    }
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodes an EVM (`0x...`) address. Mixed-case addresses must carry a valid
/// EIP-55 checksum.
pub fn decode_evm_address(address: &str) -> Result<DecodedAddress, Error> {
    let digits = address
        .strip_prefix("0x")
        .filter(|d| d.len() == 40)
        .ok_or(Error::InvalidAddress)?
        .as_bytes();
    let mut addr = [0u8; 20];
    for (i, pair) in digits.as_chunks::<2>().0.iter().enumerate() {
        let (hi, lo) = hex_nibble(pair[0])
            .zip(hex_nibble(pair[1]))
            .ok_or(Error::InvalidAddress)?;
        addr[i] = (hi << 4) | lo;
    }
    if address.bytes().any(|b| b.is_ascii_uppercase()) {
        let mut checksummed = [0u8; 42];
        eip55_to_slice(&addr, &mut checksummed);
        if checksummed != address.as_bytes() {
            return Err(Error::BadChecksum);
        }
    }
    Ok(DecodedAddress::new("eth", &[&addr], &["evm"]))
}

fn p2pkh(hash: &[u8], networks: &'static [&'static str]) -> DecodedAddress {
    DecodedAddress::new(
        "p2pkh",
        &[&[0x76, 0xa9, 0x14], hash, &[0x88, 0xac]],
        networks,
    )
}

fn p2sh(hash: &[u8], networks: &'static [&'static str]) -> DecodedAddress {
    DecodedAddress::new("p2sh", &[&[0xa9, 0x14], hash, &[0x87]], networks)
}

/// Decodes a Bitcoin-family address for `network`, without allocating. The
/// special network `"auto"` detects the network from the address.
pub fn decode_bitcoin_based_address(network: &str, address: &str) -> Result<DecodedAddress, Error> {
    // case 1: explicit bitcoincash: prefix
    if address.starts_with("bitcoincash:") {
        if network != "bitcoin-cash" && network != "auto" {
            return Err(Error::NetworkMismatch);
        }
        return decode_cashaddr(address);
    }

    // attempt segwit bech32 decode
    if let Some(pos) = address.rfind('1')
        && pos > 0
    {
        let hrp = &address[..pos];
        let mut program = [0u8; 40];
        if let Ok((version, len)) = bech32::segwit_addr_decode_to_slice(hrp, address, &mut program)
        {
            let program = &program[..len];
            let net = match hrp {
                "ltc" => "litecoin",
                "nc" => "namecoin",
                "bc" => "bitcoin",
                "tb" => "bitcoin-testnet",
                "mona" => "monacoin",
                "ep" => "electraproto",
                _ => return Err(Error::UnsupportedNetwork),
            };
            if net != network && network != "auto" {
                return Err(Error::NetworkMismatch);
            }
            let flags = network_flags(net);
            if version == 1 && (net == "bitcoin" || net == "bitcoin-testnet") && len == 32 {
                return Ok(DecodedAddress::new(
                    "p2tr",
                    &[&[0x51, 0x20], program],
                    flags,
                ));
            }
            return match (version, len) {
                (0, 20) => Ok(DecodedAddress::new(
                    "p2wpkh",
                    &[&[0x00, 0x14], program],
                    flags,
                )),
                (0, 32) => Ok(DecodedAddress::new(
                    "p2wsh",
                    &[&[0x00, 0x20], program],
                    flags,
                )),
                (0, _) => Err(Error::InvalidLength),
                (v, _) => Err(Error::UnsupportedVersion(v)),
            };
        }
    }

    // base58check
    let mut buf = [0u8; 64];
    if let Ok(n) = base58::decode_to_slice(address, &mut buf)
        && n >= 5
    {
        let (payload, chk) = buf[..n].split_at(n - 4);
        if dsha256(payload)[..4] == *chk {
            // a standard P2PKH/P2SH payload is exactly 1 version byte + a 20-byte
            // hash; reject anything else rather than emit a non-standard script.
            if payload.len() != 21 {
                return Err(Error::InvalidLength);
            }
            return decode_base58_versioned(network, payload[0], &payload[1..]);
        }
    }

    // bitcoincash: addr missing its prefix
    if (network == "auto" || network == "bitcoin-cash")
        && let Ok(a) = decode_cashaddr(address)
    {
        return Ok(a);
    }

    Err(Error::InvalidAddress)
}

fn decode_cashaddr(address: &str) -> Result<DecodedAddress, Error> {
    let mut hash = [0u8; 64];
    let (typ, len) = bech32::cashaddr_decode_to_slice("bitcoincash:", address, &mut hash)?;
    // only the 20-byte P2PKH/P2SH forms have an output script here
    if len != 20 {
        return Err(Error::InvalidLength);
    }
    match typ {
        0 => Ok(p2pkh(&hash[..20], &["bitcoin-cash"])),
        1 => Ok(p2sh(&hash[..20], &["bitcoin-cash"])),
        n => Err(Error::UnsupportedVersion(n)),
    }
}

fn decode_base58_versioned(
    network: &str,
    version: u8,
    hash: &[u8],
) -> Result<DecodedAddress, Error> {
    if network == "auto" {
        return match version {
            0x00 => Ok(p2pkh(hash, &["bitcoin", "bitcoin-cash"])),
            0x05 => Ok(p2sh(hash, &["bitcoin", "bitcoin-cash"])),
            0x0d => Ok(p2sh(hash, &["namecoin"])),
            0x10 => Ok(p2sh(hash, &["dash"])),
            0x16 => Ok(p2sh(hash, &["dogecoin"])),
            0x1e => Ok(p2pkh(hash, &["dogecoin"])),
            0x30 => Ok(p2pkh(hash, &["litecoin"])),
            0x32 => Ok(p2sh(hash, &["litecoin"])),
            0x34 => Ok(p2pkh(hash, &["namecoin"])),
            0x37 => Ok(p2sh(hash, &["monacoin"])),
            0x4c => Ok(p2pkh(hash, &["dash"])),
            0x6f => Ok(p2pkh(hash, &["bitcoin-testnet"])),
            0x89 => Ok(p2sh(hash, &["electraproto"])),
            0xc4 => Ok(p2sh(hash, &["bitcoin-testnet"])),
            v => Err(Error::UnsupportedVersion(v)),
        };
    }
    // bitcoin-cash legacy addresses share bitcoin's versions
    let lookup = if network == "bitcoin-cash" {
        "bitcoin"
    } else {
        network
    };
    let (pkh, sh) = base58_versions(lookup).ok_or(Error::UnsupportedNetwork)?;
    let flags = network_flags(network);
    match version {
        v if v == pkh => Ok(p2pkh(hash, flags)),
        v if v == sh => Ok(p2sh(hash, flags)),
        v => Err(Error::UnsupportedVersion(v)),
    }
}

/// Parses an EVM (`0x...`) address.
#[cfg(feature = "alloc")]
pub fn parse_evm_address(address: &str) -> Result<Out, String> {
    decode_evm_address(address)
        .map(Out::from)
        .map_err(|e| format!("failed to parse ethereum address: {e}"))
}

/// Parses a Bitcoin-family address for the given network. The special network
/// `"auto"` attempts to detect the network from the address.
#[cfg(feature = "alloc")]
pub fn parse_bitcoin_based_address(network: &str, address: &str) -> Result<Out, String> {
    decode_bitcoin_based_address(network, address)
        .map(Out::from)
        .map_err(|e| match e {
            Error::NetworkMismatch => {
                format!("{address} is not a {network} address")
            }
            Error::UnsupportedNetwork => {
                format!("unsupported network {network:?} for address {address}")
            }
            e => format!("failed to parse address {address}: {e}"),
        })
}

#[cfg(feature = "alloc")]
impl Out {
    /// Returns the human-readable address for this output. Flags provide network
    /// hints when multiple addresses are possible.
    pub fn address(&self, flags: &[&str]) -> Result<String, String> {
        // the first of the provided flags, then of the output's own flags
        let net = flags
            .first()
            .copied()
            .or_else(|| self.flags.first().map(String::as_str))
            .unwrap_or("");
        let mut buf = vec![0u8; MAX_ADDRESS_LEN.max(16 + 2 * self.raw.len())];
        match encode_address_to_slice(&self.name, &self.raw, net, &mut buf) {
            Ok(n) => {
                buf.truncate(n);
                Ok(String::from_utf8(buf).expect("addresses are ASCII"))
            }
            Err(Error::UnsupportedFormat) => Err(format!(
                "could not transform outscript of format {}",
                self.name
            )),
            Err(Error::UnsupportedNetwork) => Err(format!(
                "unsupported network {net:?} for {} address",
                self.name
            )),
            Err(e) => Err(format!("{} address: {e}", self.name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip55_slice() {
        let addr = [
            0x5a, 0xae, 0xb6, 0x05, 0x3f, 0x3e, 0x94, 0xc9, 0xb9, 0xa0, 0x9f, 0x33, 0x66, 0x94,
            0x35, 0xe7, 0xef, 0x1b, 0xea, 0xed,
        ];
        let mut out = [0u8; 42];
        assert_eq!(eip55_to_slice(&addr, &mut out), Some(42));
        assert_eq!(&out, b"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        assert_eq!(eip55_to_slice(&addr, &mut out[..41]), None);
    }

    #[test]
    fn render_rejects_short_scripts() {
        let mut out = [0u8; MAX_ADDRESS_LEN];
        for fmt in ["p2pkh", "p2sh", "p2wpkh", "p2tr", "massa"] {
            assert_eq!(
                encode_address_to_slice(fmt, &[], "bitcoin", &mut out),
                Err(Error::InvalidScript),
                "{fmt}"
            );
            if fmt == "massa" {
                continue; // any non-empty payload is renderable
            }
            for len in 1..4 {
                let r = encode_address_to_slice(fmt, &[0u8; 3][..len], "bitcoin", &mut out);
                assert!(r.is_err(), "{fmt} {len}");
            }
        }
        assert_eq!(
            encode_address_to_slice("p2pk", &[0u8; 35], "bitcoin", &mut out),
            Err(Error::UnsupportedFormat)
        );
    }

    #[test]
    fn base58_addr_slice() {
        // decoding must give back version + hash + dsha256 checksum
        let hash = [
            0xb5, 0xbd, 0x07, 0x9c, 0x4d, 0x57, 0xcc, 0x7f, 0xc2, 0x8e, 0xcf, 0x8a, 0x6e, 0xba,
            0xf9, 0x65, 0x6e, 0x6b, 0x4c, 0x5c,
        ];
        let mut out = [0u8; 35];
        let n = encode_base58_addr_to_slice(0x00, &hash, &mut out).unwrap();
        let mut dec = [0u8; 25];
        assert_eq!(
            base58::decode_to_slice(core::str::from_utf8(&out[..n]).unwrap(), &mut dec),
            Ok(25)
        );
        assert_eq!(dec[0], 0x00);
        assert_eq!(&dec[1..21], &hash);
        assert_eq!(&dec[21..], &crate::hash::dsha256(&dec[..21])[..4]);
    }
}
