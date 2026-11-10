//! Massa address parsing (port of `massa.go`).

use crate::address::{DecodedAddress, Error};
use crate::base58;
use crate::hash::dsha256;
#[cfg(feature = "alloc")]
use crate::out::Out;

/// Length of the hash in a Massa address.
const MASSA_HASH_LEN: usize = 32;

/// Decodes a Massa address ("AU" for user accounts, "AS" for smart contracts)
/// without allocating. The script is the address type byte followed by the
/// decoded payload: a version byte, which must be 0, and a 32-byte hash. Any
/// other payload is rejected, even with a valid checksum.
pub fn decode_massa_address(address: &str) -> Result<DecodedAddress, Error> {
    let typ: u8 = match address.get(..2) {
        Some("AU") => 0,
        Some("AS") => 1,
        _ => return Err(Error::InvalidAddress),
    };

    // type byte + payload must fit a script buffer
    let mut buf = [0u8; crate::script::MAX_SCRIPT_LEN - 1 + 4];
    let n = base58::decode_to_slice(&address[2..], &mut buf).map_err(|e| match e {
        base58::Error::BufferTooSmall => Error::InvalidLength,
        _ => Error::InvalidAddress,
    })?;
    if n < 4 {
        return Err(Error::InvalidLength);
    }
    let (payload, chk) = buf[..n].split_at(n - 4);
    if dsha256(payload)[..4] != *chk {
        return Err(Error::BadChecksum);
    }
    // The payload is a version byte (0, the only version there is) and the
    // 32-byte hash of the public key or of the contract: what
    // `generate_script` and the address encoder produce.
    let [version, hash @ ..] = payload else {
        return Err(Error::InvalidLength);
    };
    if hash.len() != MASSA_HASH_LEN {
        return Err(Error::InvalidLength);
    }
    if *version != 0 {
        return Err(Error::UnsupportedAddressVersion(*version));
    }
    Ok(DecodedAddress::new("massa", &[&[typ], payload], &["massa"]))
}

/// Parses a Massa address ("AU" for user accounts, "AS" for smart contracts).
#[cfg(feature = "alloc")]
pub fn parse_massa_address(address: &str) -> Result<Out, Error> {
    decode_massa_address(address).map(Out::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed() {
        assert_eq!(
            decode_massa_address("not-a-massa-address"),
            Err(Error::InvalidAddress)
        );
        assert_eq!(decode_massa_address("AU"), Err(Error::InvalidLength));
        assert_eq!(decode_massa_address("AU11111"), Err(Error::BadChecksum));
    }

    /// An address for `payload`, with a valid checksum.
    fn encode(prefix: &str, payload: &[u8]) -> ([u8; 96], usize) {
        let mut raw = [0u8; 64];
        raw[..payload.len()].copy_from_slice(payload);
        raw[payload.len()..payload.len() + 4].copy_from_slice(&dsha256(payload)[..4]);
        let mut out = [0u8; 96];
        out[..2].copy_from_slice(prefix.as_bytes());
        let n = base58::encode_to_slice(&raw[..payload.len() + 4], &mut out[2..]).unwrap();
        (out, n + 2)
    }

    /// A valid checksum is not enough: the payload must be a version 0 byte
    /// and a 32-byte hash.
    #[test]
    fn requires_version_and_hash_length() {
        let decode = |prefix: &str, payload: &[u8]| {
            let (buf, n) = encode(prefix, payload);
            decode_massa_address(core::str::from_utf8(&buf[..n]).unwrap())
        };
        let mut good = [0x5au8; 33];
        good[0] = 0;
        for (prefix, typ) in [("AU", 0u8), ("AS", 1)] {
            let decoded = decode(prefix, &good).unwrap();
            let mut script = [0x5au8; 34];
            script[0] = typ;
            script[1] = 0;
            assert_eq!(&decoded.script[..], &script[..]);

            let mut long = [0x5au8; 40];
            long[0] = 0;
            for len in [0, 1, 21, 32, 34, 40] {
                assert_eq!(
                    decode(prefix, &long[..len]),
                    Err(Error::InvalidLength),
                    "{len}-byte payload"
                );
            }
            let mut versioned = good;
            versioned[0] = 1;
            assert_eq!(
                decode(prefix, &versioned),
                Err(Error::UnsupportedAddressVersion(1))
            );
        }
    }
}
