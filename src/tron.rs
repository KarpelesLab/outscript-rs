//! Tron addresses: the Ethereum account hash (the last 20 bytes of the
//! keccak-256 of the uncompressed public key) behind a `0x41` prefix byte,
//! base58check encoded, so every address is 34 characters starting with `T`.
//!
//! Transactions are built and signed in [`trontx`](crate::trontx).

use crate::address::{DecodedAddress, Error, encode_base58_addr_to_slice};
use crate::base58;
use crate::crypto::secp256k1::SecpPublicKey;
use crate::hash::{dsha256, ether_hash};
#[cfg(feature = "alloc")]
use crate::out::Out;
#[cfg(feature = "alloc")]
use crate::prelude::*;

/// The byte every raw Tron address starts with.
pub const ADDRESS_PREFIX: u8 = 0x41;
/// The length of an encoded (`T...`) Tron address.
pub const ADDRESS_LEN: usize = 34;

/// A raw Tron address: [`ADDRESS_PREFIX`] followed by the 20-byte account
/// hash. This is the form transactions carry; `T...` strings are
/// [`address_to_slice`] / [`address_from_str`] away. The `tron` output script
/// of [`generate_script`](crate::generate_script) has these very bytes.
pub type TronAddress = [u8; 21];

/// The address of a public key.
pub fn address_from_pubkey(pubkey: &SecpPublicKey) -> TronAddress {
    let mut raw = [ADDRESS_PREFIX; 21];
    raw[1..].copy_from_slice(&ether_hash(&pubkey.serialize_uncompressed()));
    raw
}

/// Writes the `T...` form of a raw address into `out` ([`ADDRESS_LEN`] bytes
/// suffice), returning the number of (ASCII) bytes written. The address must
/// start with [`ADDRESS_PREFIX`] ([`Error::InvalidAddress`] otherwise).
pub fn address_to_slice(raw: &TronAddress, out: &mut [u8]) -> Result<usize, Error> {
    if raw[0] != ADDRESS_PREFIX {
        return Err(Error::InvalidAddress);
    }
    Ok(encode_base58_addr_to_slice(raw[0], &raw[1..], out)?)
}

/// The `T...` form of a raw address: see [`address_to_slice`].
#[cfg(feature = "alloc")]
pub fn address_to_string(raw: &TronAddress) -> Result<String, Error> {
    let mut out = [0u8; ADDRESS_LEN];
    let n = address_to_slice(raw, &mut out)?;
    Ok(String::from_utf8(out[..n].to_vec()).expect("base58 is ASCII"))
}

/// Decodes a `T...` address into its raw form, checking the length, the
/// checksum and the prefix.
pub fn address_from_str(address: &str) -> Result<TronAddress, Error> {
    // 21-byte payload and 4-byte checksum; anything longer is not an address
    let mut buf = [0u8; 25];
    let n = base58::decode_to_slice(address, &mut buf).map_err(|e| match e {
        base58::Error::BufferTooSmall => Error::InvalidLength,
        _ => Error::InvalidAddress,
    })?;
    if n != 25 {
        return Err(Error::InvalidLength);
    }
    let (payload, checksum) = buf.split_at(21);
    if dsha256(payload)[..4] != *checksum {
        return Err(Error::BadChecksum);
    }
    if payload[0] != ADDRESS_PREFIX {
        return Err(Error::UnsupportedAddressVersion(payload[0]));
    }
    Ok(payload.try_into().expect("21 bytes"))
}

/// Decodes a `T...` address without allocating. The script is the raw
/// address ([`TronAddress`]).
pub fn decode_tron_address(address: &str) -> Result<DecodedAddress, Error> {
    let raw = address_from_str(address)?;
    Ok(DecodedAddress::new("tron", &[&raw], &["tron"]))
}

/// Parses a `T...` address.
#[cfg(feature = "alloc")]
pub fn parse_tron_address(address: &str) -> Result<Out, Error> {
    decode_tron_address(address).map(Out::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::encode_address_to_slice;
    use crate::crypto::secp256k1::SecpPrivateKey;
    use crate::{PubKey, generate_script};

    fn raw(hex: &str) -> TronAddress {
        let mut a = [0u8; 21];
        hex::decode_to_slice(hex, &mut a).unwrap();
        a
    }

    /// Addresses computed independently (base58check in Python), including
    /// the USDT contract and the all-zero and all-ones hashes.
    #[test]
    fn known_addresses() {
        for (hex, want) in [
            (
                "41a614f803b6fd780986a42c78ec9c7f77e6ded13c",
                "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
            ),
            (
                "412aeb8add8337360e088b7d9ce4e857b9be60f3a7",
                "TDt9YtfuttvxD2Jv8F8v4JEDbnBBb1jVNt",
            ),
            (
                "410000000000000000000000000000000000000000",
                "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
            ),
            (
                "41ffffffffffffffffffffffffffffffffffffffff",
                "TZJozAg1ruapycCicgz31GxvYJ1FraLjZa",
            ),
        ] {
            let raw = raw(hex);
            let mut out = [0u8; ADDRESS_LEN];
            let n = address_to_slice(&raw, &mut out).unwrap();
            assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), want);
            assert_eq!(address_from_str(want), Ok(raw));

            let decoded = decode_tron_address(want).unwrap();
            assert_eq!((decoded.format, decoded.networks), ("tron", &["tron"][..]));
            assert_eq!(&decoded.script[..], &raw);
            let n = encode_address_to_slice("tron", &decoded.script, "tron", &mut out).unwrap();
            assert_eq!(&out[..n], want.as_bytes());
        }
    }

    /// The key whose Ethereum address is 0x2AeB8ADD... has the Tron address
    /// of `0x41 || that hash`.
    #[test]
    fn address_of_key() {
        let key = SecpPrivateKey::from_bytes(&{
            let mut s = [0u8; 32];
            hex::decode_to_slice(
                "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf",
                &mut s,
            )
            .unwrap();
            s
        })
        .unwrap();
        let want = raw("412aeb8add8337360e088b7d9ce4e857b9be60f3a7");
        assert_eq!(address_from_pubkey(&key.public_key()), want);
        let script = generate_script(&PubKey::Secp256k1(key.public_key()), "tron").unwrap();
        assert_eq!(&script[..], &want);
    }

    #[test]
    fn rejects_malformed() {
        let usdt = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
        assert_eq!(address_from_str(""), Err(Error::InvalidLength));
        assert_eq!(address_from_str("TR7N"), Err(Error::InvalidLength));
        assert_eq!(address_from_str("0OIl"), Err(Error::InvalidAddress));
        // too long to be an address
        assert_eq!(
            address_from_str("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t1"),
            Err(Error::InvalidLength)
        );
        // the last character changed
        assert_eq!(
            address_from_str("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6a"),
            Err(Error::BadChecksum)
        );
        // a Bitcoin address: right shape, wrong prefix
        assert_eq!(
            address_from_str("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
            Err(Error::UnsupportedAddressVersion(0))
        );
        assert!(address_from_str(usdt).is_ok());

        let mut out = [0u8; ADDRESS_LEN];
        assert_eq!(
            address_to_slice(&[0u8; 21], &mut out),
            Err(Error::InvalidAddress)
        );
        assert_eq!(
            address_to_slice(
                &raw("41a614f803b6fd780986a42c78ec9c7f77e6ded13c"),
                &mut out[..33]
            ),
            Err(Error::BufferTooSmall)
        );
        // the generic renderer wants exactly a raw address
        for bad in [
            &[][..],
            &[0x41u8; 20][..],
            &[0x00u8; 21][..],
            &[0x41u8; 22][..],
        ] {
            assert_eq!(
                encode_address_to_slice("tron", bad, "tron", &mut out),
                Err(Error::InvalidScript)
            );
        }
    }
}
