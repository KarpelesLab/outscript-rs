//! Solana address parsing (port of `solana.go`).

use crate::address::{DecodedAddress, Error};
use crate::base58;
#[cfg(feature = "alloc")]
use crate::out::Out;

/// Decodes a Solana base58 address (32 bytes when decoded) into its raw key.
pub fn decode_solana_key(address: &str) -> Result<[u8; 32], Error> {
    let mut key = [0u8; 32];
    match base58::decode_to_slice(address, &mut key) {
        Ok(32) => Ok(key),
        Ok(_) | Err(base58::Error::BufferTooSmall) => Err(Error::InvalidLength),
        Err(_) => Err(Error::InvalidAddress),
    }
}

/// Decodes a Solana base58 address without allocating.
pub fn decode_solana_address(address: &str) -> Result<DecodedAddress, Error> {
    let key = decode_solana_key(address)?;
    Ok(DecodedAddress::new("solana", &[&key], &["solana"]))
}

/// Parses a Solana base58-encoded address (32 bytes when decoded).
#[cfg(feature = "alloc")]
pub fn parse_solana_address(address: &str) -> Result<Out, Error> {
    decode_solana_address(address).map(Out::from)
}
