//! Address parsing and encoding across Bitcoin-family, EVM, Massa and Solana
//! networks (port of `address.go`, `eip55.go`).

use purecrypto::hash::{Digest, Sha256};

use crate::base58;
use crate::bech32;
use crate::hash::{dsha256, keccak256_once, sha256_once};
use crate::pushbytes::parse_push_bytes;

#[cfg(feature = "alloc")]
use crate::out::Out;
#[cfg(feature = "alloc")]
use crate::prelude::*;
#[cfg(feature = "alloc")]
use crate::pushbytes::push_bytes;

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

#[cfg(feature = "alloc")]
/// Parses an EVM (`0x...`) address.
pub fn parse_evm_address(address: &str) -> Result<Out, String> {
    if address.len() != 42 || !address.starts_with("0x") {
        return Err("EVM addresses must be 42 characters long and start with 0x".into());
    }
    let data =
        hex::decode(&address[2..]).map_err(|e| format!("failed to parse ethereum address: {e}"))?;
    if address.bytes().any(|b| b.is_ascii_uppercase()) && address != eip55(&data) {
        return Err("bad checksum on ethereum address".into());
    }
    Ok(Out::make("eth", data, &["evm"]))
}

#[cfg(feature = "alloc")]
fn p2pkh_script(hash: &[u8]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9];
    s.extend_from_slice(&push_bytes(hash));
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

#[cfg(feature = "alloc")]
fn p2sh_script(hash: &[u8]) -> Vec<u8> {
    let mut s = vec![0xa9];
    s.extend_from_slice(&push_bytes(hash));
    s.push(0x87);
    s
}

#[cfg(feature = "alloc")]
/// Parses a Bitcoin-family address for the given network. The special network
/// `"auto"` attempts to detect the network from the address.
pub fn parse_bitcoin_based_address(network: &str, address: &str) -> Result<Out, String> {
    // case 1: explicit bitcoincash: prefix
    if address.starts_with("bitcoincash:") {
        if network != "bitcoin-cash" && network != "auto" {
            return Err(format!(
                "bitcoincash address provided while expecting a {network} address"
            ));
        }
        let (typ, buf) = bech32::cashaddr_decode("bitcoincash:", address)
            .map_err(|e| format!("failed to parse bitcoin cash address: {e}"))?;
        return cashaddr_out(typ, &buf);
    }

    // attempt segwit bech32 decode
    if let Some(pos) = address.rfind('1')
        && pos > 0
    {
        let hrp = &address[..pos];
        if let Ok((typ, buf)) = bech32::segwit_addr_decode(hrp, address) {
            let net = match hrp {
                "ltc" => "litecoin",
                "nc" => "namecoin",
                "bc" => "bitcoin",
                "tb" => "bitcoin-testnet",
                "mona" => "monacoin",
                "ep" => "electraproto",
                _ => return Err(format!("unsupported hrp value {hrp}")),
            };
            if net != network && network != "auto" {
                return Err(format!(
                    "got a {net} address where we expected a {network} address"
                ));
            }
            if typ == 1 && (net == "bitcoin" || net == "bitcoin-testnet") && buf.len() == 32 {
                let mut script = vec![0x51];
                script.extend_from_slice(&push_bytes(&buf));
                return Ok(Out::make("p2tr", script, &[net]));
            }
            if typ != 0 {
                return Err(format!("unsupported segwit type {typ}"));
            }
            let mut script = vec![0x00];
            script.extend_from_slice(&push_bytes(&buf));
            return match buf.len() {
                20 => Ok(Out::make("p2wpkh", script, &[net])),
                32 => Ok(Out::make("p2wsh", script, &[net])),
                n => Err(format!("invalid segwit address length {n}")),
            };
        }
    }

    // base58check
    if let Ok(mut buf) = base58::decode(address)
        && buf.len() >= 5
    {
        let chk_start = buf.len() - 4;
        let chk = buf[chk_start..].to_vec();
        buf.truncate(chk_start);
        let h = dsha256(&buf);
        if h[..4] == chk[..] {
            // a standard P2PKH/P2SH payload is exactly 1 version byte + a 20-byte
            // hash; reject anything else rather than emit a non-standard script.
            if buf.len() != 21 {
                return Err(format!(
                    "invalid base58 address payload length {}",
                    buf.len()
                ));
            }
            return parse_base58_versioned(network, &buf);
        }
    }

    // bitcoincash: addr missing its prefix
    if (network == "auto" || network == "bitcoin-cash")
        && let Ok((typ, buf)) =
            bech32::cashaddr_decode("bitcoincash:", &format!("bitcoincash:{address}"))
    {
        return cashaddr_out(typ, &buf);
    }

    Err(format!("unsupported address {address}"))
}

#[cfg(feature = "alloc")]
fn cashaddr_out(typ: u8, buf: &[u8]) -> Result<Out, String> {
    match typ {
        0 => Ok(Out::make("p2pkh", p2pkh_script(buf), &["bitcoin-cash"])),
        1 => Ok(Out::make("p2sh", p2sh_script(buf), &["bitcoin-cash"])),
        n => Err(format!("unsupported bitcoincash address type {n}")),
    }
}

#[cfg(feature = "alloc")]
fn parse_base58_versioned(network: &str, buf: &[u8]) -> Result<Out, String> {
    let version = buf[0];
    let payload = &buf[1..];
    let pkh = |net: &str| Out::make("p2pkh", p2pkh_script(payload), &[net]);
    let psh = |net: &str| Out::make("p2sh", p2sh_script(payload), &[net]);
    // For auto, also attach multiple flags.
    let pkh_multi = |nets: &[&str]| Out::make("p2pkh", p2pkh_script(payload), nets);
    let psh_multi = |nets: &[&str]| Out::make("p2sh", p2sh_script(payload), nets);

    match network {
        "auto" => match version {
            0x00 => Ok(pkh_multi(&["bitcoin", "bitcoin-cash"])),
            0x05 => Ok(psh_multi(&["bitcoin", "bitcoin-cash"])),
            0x0d => Ok(psh("namecoin")),
            0x10 => Ok(psh("dash")),
            0x16 => Ok(psh("dogecoin")),
            0x1e => Ok(pkh("dogecoin")),
            0x30 => Ok(pkh("litecoin")),
            0x32 => Ok(psh("litecoin")),
            0x34 => Ok(pkh("namecoin")),
            0x37 => Ok(psh("monacoin")),
            0x4c => Ok(pkh("dash")),
            0x6f => Ok(pkh("bitcoin-testnet")),
            0x89 => Ok(psh("electraproto")),
            0xc4 => Ok(psh("bitcoin-testnet")),
            v => Err(format!("unsupported base58 address version={v:x}")),
        },
        "bitcoin" | "bitcoin-cash" => match version {
            0x00 => Ok(pkh(network)),
            0x05 => Ok(psh(network)),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        "bitcoin-testnet" => match version {
            0x6f => Ok(pkh(network)),
            0xc4 => Ok(psh(network)),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        "litecoin" => match version {
            0x30 => Ok(pkh("litecoin")),
            0x32 => Ok(psh("litecoin")),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        "namecoin" => match version {
            0x34 => Ok(pkh("namecoin")),
            0x0d => Ok(psh("namecoin")),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        "dogecoin" => match version {
            0x16 => Ok(psh("dogecoin")),
            0x1e => Ok(pkh("dogecoin")),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        "monacoin" => match version {
            0x32 => Ok(pkh("monacoin")),
            0x37 => Ok(psh("monacoin")),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        "electraproto" => match version {
            0x37 => Ok(pkh("electraproto")),
            0x89 => Ok(psh("electraproto")),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        "dash" => match version {
            0x4c => Ok(pkh("dash")),
            0x10 => Ok(psh("dash")),
            v => Err(format!(
                "unsupported {network} base58 address version={v:x}"
            )),
        },
        _ => Err(format!("unsupported {network} network for address parsing")),
    }
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
