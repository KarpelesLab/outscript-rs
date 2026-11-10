//! Zano: addresses, keys and transactions, built on the primitives the
//! CryptoNote family shares ([`cryptonote`](crate::cryptonote)).

/// Errors specific to Zano.
///
/// It converts into the crate's [`Error`](crate::Error) (as
/// [`Error::Zano`](crate::Error::Zano)), so `?` composes; so does the shared
/// [`cryptonote::Error`](crate::cryptonote::Error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {}
    }
}

impl core::error::Error for Error {}
