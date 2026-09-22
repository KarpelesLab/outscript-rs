//! Zcash transparent addresses (`t1…`/`t3…` on mainnet, `tm…`/`t2…` on
//! testnet): base58check with a two-byte version. Shielded addresses have no
//! output script and are not handled.
//!
//! Transactions are built and signed in [`zcashtx`](crate::zcashtx).

use crate::address::{DecodedAddress, Error};
use crate::base58;
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
