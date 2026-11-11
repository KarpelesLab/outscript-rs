//! Zcash transparent addresses (`t1…`/`t3…` on mainnet, `tm…`/`t2…` on
//! testnet): base58check with a two-byte version. Shielded addresses have no
//! output script and are not handled here (see the `sapling` and `orchard`
//! modules). TEX addresses (ZIP 320, `tex1…`), which are P2PKH addresses
//! that must be paid from transparent funds only, have their own functions:
//! [`encode_tex_address_to_slice`] and [`decode_tex_address`].
//!
//! Transactions are built and signed in [`zcashtx`](crate::zcashtx).

use crate::address::{DecodedAddress, Error};
use crate::base58;
use crate::bech32;
use crate::hash::dsha256;
#[cfg(feature = "alloc")]
use crate::out::Out;

/// The two-byte base58check versions of P2PKH and P2SH addresses.
fn versions(network: &str) -> Option<([u8; 2], [u8; 2])> {
    Some(match network {
        "zcash" => ([0x1c, 0xb8], [0x1c, 0xbd]),
        "zcash-testnet" => ([0x1d, 0x25], [0x1c, 0xba]),
        _ => return None,
    })
}

/// Writes the address of a P2PKH (`t1`) or P2SH (`t3`) hash into `out`,
/// returning the number of (ASCII) bytes written.
pub(crate) fn encode_to_slice(
    p2sh: bool,
    hash: &[u8],
    network: &str,
    out: &mut [u8],
) -> Result<usize, Error> {
    let (pkh, sh) = versions(network).ok_or(Error::UnsupportedNetwork)?;
    let version = if p2sh { sh } else { pkh };
    let mut payload = [0u8; 22];
    payload[..2].copy_from_slice(&version);
    payload[2..].copy_from_slice(hash);
    let checksum = dsha256(&payload);
    let bytes = payload.iter().chain(&checksum[..4]).copied();
    Ok(base58::encode_iter_to_slice(bytes, out)?)
}

/// Decodes a Zcash transparent address for `network` (`zcash` or
/// `zcash-testnet`; `auto` tells them apart), without allocating.
pub fn decode_zcash_address(network: &str, address: &str) -> Result<DecodedAddress, Error> {
    let mut buf = [0u8; 32];
    let n = base58::decode_to_slice(address, &mut buf).map_err(|e| match e {
        base58::Error::BufferTooSmall => Error::InvalidLength,
        _ => Error::InvalidAddress,
    })?;
    if n < 4 {
        return Err(Error::InvalidLength);
    }
    let (payload, checksum) = buf[..n].split_at(n - 4);
    if dsha256(payload)[..4] != *checksum {
        return Err(Error::BadChecksum);
    }
    // two version bytes and a 20-byte hash: anything else has no script
    let (version, hash) = match payload {
        [v0, v1, hash @ ..] if hash.len() == 20 => ([*v0, *v1], hash),
        _ => return Err(Error::InvalidLength),
    };
    let networks: &[&str] = if network == "auto" {
        &["zcash", "zcash-testnet"]
    } else {
        core::slice::from_ref(match network {
            "zcash" => &"zcash",
            "zcash-testnet" => &"zcash-testnet",
            _ => return Err(Error::UnsupportedNetwork),
        })
    };
    for &net in networks {
        let (pkh, sh) = versions(net).expect("known network");
        let flags: &'static [&'static str] = match net {
            "zcash" => &["zcash"],
            _ => &["zcash-testnet"],
        };
        if version == pkh {
            return Ok(DecodedAddress::new(
                "p2pkh",
                &[&[0x76, 0xa9, 0x14], hash, &[0x88, 0xac]],
                flags,
            ));
        }
        if version == sh {
            return Ok(DecodedAddress::new(
                "p2sh",
                &[&[0xa9, 0x14], hash, &[0x87]],
                flags,
            ));
        }
    }
    Err(Error::UnsupportedAddressVersion(version[1]))
}

/// The human-readable part of the TEX addresses of `network`.
fn tex_hrp(network: &str) -> Option<&'static str> {
    Some(match network {
        "zcash" => "tex",
        "zcash-testnet" => "textest",
        _ => return None,
    })
}

/// The length of the longest TEX address (a testnet one).
pub const TEX_ADDRESS_MAX_LEN: usize = 7 + 1 + 32 + 6;

/// Writes the TEX address (ZIP 320, `tex1…` on mainnet, `textest1…` on
/// testnet) of the public key hash `hash` into `out`
/// ([`TEX_ADDRESS_MAX_LEN`] bytes always suffice), returning the number of
/// (ASCII) bytes written.
///
/// A TEX address, or *transparent-source-only* address, is the Bech32m
/// encoding of the hash of a P2PKH address: the same output script, with
/// the request that the transaction paying it spend only transparent
/// outputs (so that the recipient can send the funds back to where they
/// came from). There is no TEX form of a P2SH address.
pub fn encode_tex_address_to_slice(
    hash: &[u8; 20],
    network: &str,
    out: &mut [u8],
) -> Result<usize, Error> {
    let hrp = tex_hrp(network).ok_or(Error::UnsupportedNetwork)?;
    Ok(bech32::encode_to_slice(
        hrp,
        hash,
        bech32::Variant::Bech32m,
        out,
    )?)
}

/// Decodes a TEX address (ZIP 320) of `network` (`zcash` or
/// `zcash-testnet`; `auto` tells them apart), returning the hash of the
/// public key it pays to (the output script is the P2PKH script of that
/// hash, `zcashtx::p2pkh_script`) and its network.
///
/// A transaction with an output to a TEX address must spend only
/// transparent outputs, and should have only transparent outputs: that is
/// what distinguishes the address from the P2PKH address of the same key,
/// and why [`decode_zcash_address`] does not accept it. The transaction
/// builder (`zcash_builder`) enforces the rule for the outputs added as
/// TEX ones.
pub fn decode_tex_address(network: &str, address: &str) -> Result<([u8; 20], &'static str), Error> {
    // twenty bytes are 32 characters: longer payloads are refused before
    // they are decoded
    let mut hash = [0u8; 20];
    let (hrp, len, variant) = bech32::decode_to_slice(address, &mut hash).map_err(|e| match e {
        bech32::Error::BufferTooSmall => Error::InvalidLength,
        bech32::Error::InvalidChecksum => Error::BadChecksum,
        _ => Error::InvalidAddress,
    })?;
    let found = ["zcash", "zcash-testnet"]
        .into_iter()
        .find(|net| tex_hrp(net).is_some_and(|want| hrp.eq_ignore_ascii_case(want)))
        .ok_or(Error::InvalidAddress)?;
    match network {
        "auto" => {}
        "zcash" | "zcash-testnet" => {
            if network != found {
                return Err(Error::NetworkMismatch);
            }
        }
        _ => return Err(Error::UnsupportedNetwork),
    }
    if variant != bech32::Variant::Bech32m {
        return Err(Error::BadChecksum);
    }
    if len != 20 {
        return Err(Error::InvalidLength);
    }
    Ok((hash, found))
}

/// Parses a Zcash transparent address: see [`decode_zcash_address`].
#[cfg(feature = "alloc")]
pub fn parse_zcash_address(network: &str, address: &str) -> Result<Out, Error> {
    decode_zcash_address(network, address).map(Out::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::encode_address_to_slice;

    /// Addresses of the all-zero and all-ones hashes, computed independently
    /// (`base58check(version || hash)` in Python).
    #[test]
    fn known_addresses() {
        let cases: [(&str, bool, [u8; 20], &str); 5] = [
            (
                "zcash",
                false,
                [0; 20],
                "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs",
            ),
            (
                "zcash",
                true,
                [0; 20],
                "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ",
            ),
            (
                "zcash",
                false,
                [0xff; 20],
                "t1hDCzSiRgWFUR5Byxr9ScwNhtAT2UTqDNs",
            ),
            (
                "zcash-testnet",
                false,
                [0; 20],
                "tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma",
            ),
            (
                "zcash-testnet",
                true,
                [0; 20],
                "t26YoyZ1iPgiMEWL4zGUm74eVWfhyDMXzY2",
            ),
        ];
        for (network, p2sh, hash, want) in cases {
            let mut out = [0u8; 40];
            let n = encode_to_slice(p2sh, &hash, network, &mut out).unwrap();
            assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), want);

            let decoded = decode_zcash_address(network, want).unwrap();
            assert_eq!(decoded.format, if p2sh { "p2sh" } else { "p2pkh" });
            assert_eq!(decoded.networks, &[network]);
            let script = &decoded.script[..];
            assert_eq!(&script[if p2sh { 2 } else { 3 }..][..20], &hash);
            // and back through the generic renderer
            let n = encode_address_to_slice(decoded.format, script, network, &mut out).unwrap();
            assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), want);

            let auto = decode_zcash_address("auto", want).unwrap();
            assert_eq!(auto.networks, &[network]);
            let other = if network == "zcash" {
                "zcash-testnet"
            } else {
                "zcash"
            };
            assert!(matches!(
                decode_zcash_address(other, want),
                Err(Error::UnsupportedAddressVersion(_))
            ));
        }
    }

    /// The address pair of ZIP 320 (its reference implementation's
    /// example), and encodings of the same hash by an independent Bech32m
    /// implementation that reproduces that pair.
    #[test]
    fn tex_addresses() {
        let t1 = "t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC";
        let tex = "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte";
        let textest = "textest1s2rt77ggv6q989lr49rkgzmh5slsksa90ej7wz";
        let decoded = decode_zcash_address("zcash", t1).unwrap();
        let hash: [u8; 20] = decoded.script[3..23].try_into().unwrap();
        let mut out = [0u8; TEX_ADDRESS_MAX_LEN];
        let n = encode_tex_address_to_slice(&hash, "zcash", &mut out).unwrap();
        assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), tex);
        let n = encode_tex_address_to_slice(&hash, "zcash-testnet", &mut out).unwrap();
        assert_eq!(n, TEX_ADDRESS_MAX_LEN);
        assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), textest);
        for network in ["zcash", "auto"] {
            assert_eq!(decode_tex_address(network, tex), Ok((hash, "zcash")));
        }
        for network in ["zcash-testnet", "auto"] {
            assert_eq!(
                decode_tex_address(network, textest),
                Ok((hash, "zcash-testnet"))
            );
        }
        assert_eq!(
            decode_tex_address("zcash", textest),
            Err(Error::NetworkMismatch)
        );
        assert_eq!(
            decode_tex_address("bitcoin", tex),
            Err(Error::UnsupportedNetwork)
        );
        assert_eq!(
            encode_tex_address_to_slice(&hash, "bitcoin", &mut out),
            Err(Error::UnsupportedNetwork)
        );
        assert!(encode_tex_address_to_slice(&hash, "zcash", &mut out[..10]).is_err());
        // upper case is the same address; a transparent address is not one
        let mut upper = [0u8; 42];
        upper.copy_from_slice(tex.as_bytes());
        upper.make_ascii_uppercase();
        assert_eq!(
            decode_tex_address("zcash", core::str::from_utf8(&upper).unwrap()),
            Ok((hash, "zcash"))
        );
        assert!(decode_tex_address("zcash", t1).is_err());
        assert!(decode_zcash_address("zcash", tex).is_err());
        // every single-character change is refused
        let mut damaged = [0u8; 42];
        for i in 0..tex.len() {
            damaged.copy_from_slice(tex.as_bytes());
            damaged[i] = if damaged[i] == b'q' { b'p' } else { b'q' };
            let s = core::str::from_utf8(&damaged).unwrap();
            assert!(decode_tex_address("auto", s).is_err(), "{s}");
        }
        // a segwit address (another prefix), a Bech32 checksum under the
        // right prefix, and hashes of other lengths
        assert_eq!(
            decode_tex_address("auto", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            Err(Error::InvalidAddress)
        );
        assert_eq!(
            decode_tex_address("auto", "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9rtaywm"),
            Err(Error::BadChecksum)
        );
        assert_eq!(
            decode_tex_address("auto", "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9qqf37tgt"),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            decode_tex_address("auto", "tex1s2rt77ggv6q989lr49rkgzmh5slskscxv8q42"),
            Err(Error::InvalidLength)
        );
    }

    #[test]
    fn rejects_malformed() {
        let t1 = "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs";
        assert_eq!(decode_zcash_address("zcash", ""), Err(Error::InvalidLength));
        assert_eq!(
            decode_zcash_address("zcash", "t1Hs"),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            decode_zcash_address("zcash", "0OIl"),
            Err(Error::InvalidAddress)
        );
        let mut damaged = [0u8; 35];
        damaged.copy_from_slice(t1.as_bytes());
        damaged[34] = b't';
        assert_eq!(
            decode_zcash_address("zcash", core::str::from_utf8(&damaged).unwrap()),
            Err(Error::BadChecksum)
        );
        // a bitcoin address: right shape, wrong version
        assert_eq!(
            decode_zcash_address("zcash", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            decode_zcash_address("bitcoin", t1),
            Err(Error::UnsupportedNetwork)
        );
        assert_eq!(
            encode_to_slice(false, &[0; 20], "bitcoin", &mut [0u8; 40]),
            Err(Error::UnsupportedNetwork)
        );
        assert_eq!(
            encode_to_slice(false, &[0; 20], "zcash", &mut [0u8; 10]),
            Err(Error::BufferTooSmall)
        );
    }
}
