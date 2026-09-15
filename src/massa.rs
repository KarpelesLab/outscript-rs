//! Massa address parsing (port of `massa.go`).

#[cfg(feature = "alloc")]
use crate::prelude::*;

use crate::address::{DecodedAddress, Error};
use crate::base58;
use crate::hash::dsha256;
#[cfg(feature = "alloc")]
use crate::out::Out;

/// Decodes a Massa address ("AU" for user accounts, "AS" for smart contracts)
/// without allocating. The script is the address type byte followed by the
/// decoded payload.
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
    Ok(DecodedAddress::new("massa", &[&[typ], payload], &["massa"]))
}

/// Parses a Massa address ("AU" for user accounts, "AS" for smart contracts).
#[cfg(feature = "alloc")]
pub fn parse_massa_address(address: &str) -> Result<Out, String> {
    decode_massa_address(address)
        .map(Out::from)
        .map_err(|e| format!("failed to parse massa address: {e}"))
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
}
