//! Cardano (Shelley-era) addresses: enterprise, base and reward addresses for
//! mainnet and testnet, plus the blake2b-224 key credentials they encode.
//!
//! A Shelley address is a 1-byte header followed by one or two 28-byte
//! credentials. The header's high 4 bits select the address type and its low 4
//! bits carry the network id (0 = testnet, 1 = mainnet). Key credentials are the
//! blake2b-224 hash of the raw 32-byte Ed25519 public key. The whole payload is
//! Bech32-encoded (BIP-173, not Bech32m).
//!
//! See CIP-19 (<https://cips.cardano.org/cip/CIP-19>) for the binary format.
//!
//! Port of `cardano.go`.

#[cfg(feature = "alloc")]
use crate::prelude::*;

use crate::address::{DecodedAddress, Error};
use crate::bech32::{self, Variant};
use crate::hash::blake2b224;
#[cfg(feature = "alloc")]
use crate::out::Out;

// Address type nibbles (high 4 bits of the header byte).
const TYPE_BASE: u8 = 0x0; // payment key hash + stake key hash
const TYPE_ENTERPRISE: u8 = 0x6; // payment key hash only
const TYPE_REWARD: u8 = 0xe; // stake key hash only (reward/account address)

// Network ids (low 4 bits of the header byte).
const NET_TESTNET: u8 = 0x0;
const NET_MAINNET: u8 = 0x1;

/// The longest Cardano address this module produces (a testnet base address).
pub const MAX_CARDANO_ADDRESS_LEN: usize = 108;

/// Returns the 28-byte blake2b-224 credential for an Ed25519 public key, as used
/// in Cardano payment and stake credentials.
pub fn cardano_key_hash(pubkey: &[u8]) -> [u8; 28] {
    blake2b224(pubkey)
}

/// Maps a network flag to its network id nibble.
fn cardano_network(network: &str) -> Result<u8, Error> {
    match network {
        "" | "cardano" | "cardano-mainnet" | "mainnet" => Ok(NET_MAINNET),
        "cardano-testnet" | "testnet" => Ok(NET_TESTNET),
        _ => Err(Error::UnsupportedNetwork),
    }
}

/// Returns the Bech32 human-readable prefix for an address type nibble and
/// network id.
fn cardano_hrp(typ: u8, net: u8) -> &'static str {
    match (typ == TYPE_REWARD, net == NET_TESTNET) {
        (true, true) => "stake_test",
        (true, false) => "stake",
        (false, true) => "addr_test",
        (false, false) => "addr",
    }
}

/// Bech32-encodes a full address payload (header byte followed by credentials)
/// into `out`. The header byte determines the human-readable prefix.
fn cardano_encode_payload(payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let header = *payload.first().ok_or(Error::InvalidScript)?;
    let hrp = cardano_hrp(header >> 4, header & 0x0f);
    Ok(bech32::encode_to_slice(hrp, payload, Variant::Bech32, out)?)
}

/// Builds a payload from a header and credentials, then encodes it.
fn cardano_encode_parts(
    typ: u8,
    network: &str,
    credentials: &[&[u8]],
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut payload = [0u8; 57];
    payload[0] = (typ << 4) | cardano_network(network)?;
    let mut len = 1;
    for c in credentials {
        if c.len() != 28 {
            return Err(Error::InvalidLength);
        }
        payload[len..len + 28].copy_from_slice(c);
        len += 28;
    }
    cardano_encode_payload(&payload[..len], out)
}

/// Writes a type-6 enterprise address (payment credential only) for a 28-byte
/// payment key hash into `out`, returning the number of (ASCII) bytes written.
pub fn cardano_enterprise_address_to_slice(
    payment_key_hash: &[u8],
    network: &str,
    out: &mut [u8],
) -> Result<usize, Error> {
    cardano_encode_parts(TYPE_ENTERPRISE, network, &[payment_key_hash], out)
}

/// Writes a type-0 base address (payment credential + stake credential) for
/// two 28-byte key hashes into `out`, returning the number of (ASCII) bytes
/// written.
pub fn cardano_base_address_to_slice(
    payment_key_hash: &[u8],
    stake_key_hash: &[u8],
    network: &str,
    out: &mut [u8],
) -> Result<usize, Error> {
    cardano_encode_parts(TYPE_BASE, network, &[payment_key_hash, stake_key_hash], out)
}

/// Writes a type-14 reward (stake/account) address for a 28-byte stake key hash
/// into `out`, returning the number of (ASCII) bytes written.
pub fn cardano_reward_address_to_slice(
    stake_key_hash: &[u8],
    network: &str,
    out: &mut [u8],
) -> Result<usize, Error> {
    cardano_encode_parts(TYPE_REWARD, network, &[stake_key_hash], out)
}

/// Renders a Cardano address for a raw payload ("header byte + credentials",
/// at most 57 bytes) into `out`. The network flag overrides the header's
/// network nibble so the same payload can produce mainnet or testnet forms.
pub fn cardano_address_from_raw_to_slice(
    raw: &[u8],
    network: &str,
    out: &mut [u8],
) -> Result<usize, Error> {
    if raw.is_empty() || raw.len() > 57 {
        return Err(Error::InvalidScript);
    }
    let mut payload = [0u8; 57];
    payload[..raw.len()].copy_from_slice(raw);
    payload[0] = (payload[0] & 0xf0) | cardano_network(network)?;
    cardano_encode_payload(&payload[..raw.len()], out)
}

#[cfg(feature = "alloc")]
fn to_string_with(f: impl FnOnce(&mut [u8]) -> Result<usize, Error>) -> Result<String, String> {
    let mut buf = [0u8; MAX_CARDANO_ADDRESS_LEN];
    let n = f(&mut buf).map_err(|e| format!("cardano: {e}"))?;
    Ok(String::from_utf8(buf[..n].to_vec()).expect("bech32 output is ASCII"))
}

/// Builds a type-6 enterprise address (payment credential only) from a 28-byte
/// payment key hash.
#[cfg(feature = "alloc")]
pub fn cardano_enterprise_address(
    payment_key_hash: &[u8],
    network: &str,
) -> Result<String, String> {
    to_string_with(|out| cardano_enterprise_address_to_slice(payment_key_hash, network, out))
}

/// Builds a type-0 base address (payment credential + stake credential) from two
/// 28-byte key hashes.
#[cfg(feature = "alloc")]
pub fn cardano_base_address(
    payment_key_hash: &[u8],
    stake_key_hash: &[u8],
    network: &str,
) -> Result<String, String> {
    to_string_with(|out| {
        cardano_base_address_to_slice(payment_key_hash, stake_key_hash, network, out)
    })
}

/// Builds a type-14 reward (stake/account) address from a 28-byte stake key
/// hash.
#[cfg(feature = "alloc")]
pub fn cardano_reward_address(stake_key_hash: &[u8], network: &str) -> Result<String, String> {
    to_string_with(|out| cardano_reward_address_to_slice(stake_key_hash, network, out))
}

/// Decodes a Bech32-encoded Cardano Shelley address (`addr…`, `addr_test…`,
/// `stake…`, `stake_test…`) without allocating. The script is the raw payload
/// (header byte followed by credentials), so it can be re-encoded with
/// [`cardano_address_from_raw_to_slice`].
pub fn decode_cardano_address(address: &str) -> Result<DecodedAddress, Error> {
    let mut buf = [0u8; 57];
    let (hrp, n, variant) = bech32::decode_to_slice(address, &mut buf).map_err(|e| match e {
        bech32::Error::BufferTooSmall => Error::InvalidLength,
        e => Error::Bech32(e),
    })?;
    if variant != Variant::Bech32 {
        return Err(Error::Bech32(bech32::Error::InvalidChecksum));
    }
    let hrp_is = |want: &str| hrp.eq_ignore_ascii_case(want);
    if !(hrp_is("addr") || hrp_is("addr_test") || hrp_is("stake") || hrp_is("stake_test")) {
        return Err(Error::UnsupportedNetwork);
    }
    let payload = &buf[..n];
    let header = *payload.first().ok_or(Error::InvalidLength)?;
    let typ = header >> 4;
    let net = header & 0x0f;
    if net != NET_MAINNET && net != NET_TESTNET {
        return Err(Error::UnsupportedNetwork);
    }

    let want_len = match typ {
        TYPE_BASE => 1 + 28 + 28,
        TYPE_ENTERPRISE | TYPE_REWARD => 1 + 28,
        _ => return Err(Error::UnsupportedVersion(typ)),
    };
    if payload.len() != want_len {
        return Err(Error::InvalidLength);
    }

    // Cross-check that the human-readable prefix agrees with the header byte, so a
    // checksum-valid address can't claim a different network/kind than its HRP.
    // "stake"/"stake_test" must wrap a reward address; "addr"/"addr_test" must
    // wrap a payment (base/enterprise) address. The "_test" suffix must match the
    // testnet network id and its absence the mainnet id.
    let hrp_is_stake = hrp_is("stake") || hrp_is("stake_test");
    if hrp_is_stake != (typ == TYPE_REWARD) {
        return Err(Error::NetworkMismatch);
    }
    let hrp_is_test = hrp_is("addr_test") || hrp_is("stake_test");
    if (net == NET_TESTNET) != hrp_is_test {
        return Err(Error::NetworkMismatch);
    }

    let flags: &'static [&'static str] = if net == NET_TESTNET {
        &["cardano-testnet"]
    } else {
        &["cardano"]
    };
    Ok(DecodedAddress::new("cardano", &[payload], flags))
}

/// Parses a Bech32-encoded Cardano Shelley address (`addr…`, `addr_test…`,
/// `stake…`, `stake_test…`) and returns the corresponding [`Out`]. The raw
/// payload (header byte followed by credentials) is preserved so the address can
/// be re-encoded via [`Out::address`].
#[cfg(feature = "alloc")]
pub fn parse_cardano_address(address: &str) -> Result<Out, String> {
    decode_cardano_address(address)
        .map(Out::from)
        .map_err(|e| format!("failed to parse cardano address: {e}"))
}

#[cfg(feature = "alloc")]
/// Renders a Cardano address for a parsed or generated [`Out`] whose raw payload
/// is "header byte + credentials". The network flag overrides the header's
/// network nibble so the same `Out` can produce mainnet or testnet forms.
pub fn cardano_address_from_out(raw: &[u8], network: &str) -> Result<String, String> {
    to_string_with(|out| cardano_address_from_raw_to_slice(raw, network, out))
}
