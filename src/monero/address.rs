//! Monero addresses: standard, integrated and subaddress, on the three
//! networks.

use core::fmt;
use core::str::FromStr;

use super::Error;
use crate::cryptonote::{
    address_decoded_len, check_key, decode_address_to_slice, encode_address_to_slice,
};

/// The length of a payment id carried by an integrated address.
pub const PAYMENT_ID_LEN: usize = 8;

/// The longest address, in characters (an integrated address; a standard
/// address or a subaddress has [`STANDARD_ADDRESS_LEN`]).
pub const MAX_ADDRESS_LEN: usize = 106;

/// The length of a standard address or a subaddress, in characters.
pub const STANDARD_ADDRESS_LEN: usize = 95;

/// A Monero network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// The main network.
    Mainnet,
    /// The test network.
    Testnet,
    /// The staging network.
    Stagenet,
}

/// The kind of an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressKind {
    /// The main address of an account.
    Standard,
    /// A standard address with an 8-byte payment id folded in.
    Integrated([u8; PAYMENT_ID_LEN]),
    /// A subaddress. Paying it takes a transaction public key made from its
    /// spend key (`TransactionBuilder` does it).
    Subaddress,
}

impl Network {
    /// The address prefixes of this network: standard, integrated,
    /// subaddress.
    const fn prefixes(self) -> [u64; 3] {
        match self {
            Network::Mainnet => [18, 19, 42],
            Network::Testnet => [53, 54, 63],
            Network::Stagenet => [24, 25, 36],
        }
    }
}

/// A decoded Monero address: the network, the kind, and the public spend and
/// view keys.
///
/// It prints ([`Display`](fmt::Display)) and parses ([`FromStr`]) as the
/// base58 text, without a heap.
///
/// ```
/// use outscript::monero::{Address, AddressKind, Network};
///
/// let text = "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge";
/// let address: Address = text.parse().unwrap();
/// assert_eq!(address.network, Network::Mainnet);
/// assert_eq!(address.kind, AddressKind::Standard);
/// assert_eq!(address.to_string(), text);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address {
    /// The network the address belongs to.
    pub network: Network,
    /// Standard, integrated (with its payment id) or subaddress.
    pub kind: AddressKind,
    /// The public spend key.
    pub spend_public: [u8; 32],
    /// The public view key.
    pub view_public: [u8; 32],
}

impl Address {
    /// The standard address of the keys.
    pub const fn standard(network: Network, spend_public: [u8; 32], view_public: [u8; 32]) -> Self {
        Address {
            network,
            kind: AddressKind::Standard,
            spend_public,
            view_public,
        }
    }

    /// The subaddress with these keys (the subaddress's own keys, as given by
    /// [`ViewKeys::subaddress_keys`](super::ViewKeys::subaddress_keys)).
    pub const fn subaddress(
        network: Network,
        spend_public: [u8; 32],
        view_public: [u8; 32],
    ) -> Self {
        Address {
            network,
            kind: AddressKind::Subaddress,
            spend_public,
            view_public,
        }
    }

    /// The integrated address of the keys and `payment_id`.
    pub const fn integrated(
        network: Network,
        spend_public: [u8; 32],
        view_public: [u8; 32],
        payment_id: [u8; PAYMENT_ID_LEN],
    ) -> Self {
        Address {
            network,
            kind: AddressKind::Integrated(payment_id),
            spend_public,
            view_public,
        }
    }

    /// The same keys as an integrated address carrying `payment_id`.
    ///
    /// Fails with [`Error::InvalidAddress`] for a subaddress, which cannot
    /// carry a payment id.
    pub fn with_payment_id(&self, payment_id: [u8; PAYMENT_ID_LEN]) -> Result<Self, Error> {
        if self.is_subaddress() {
            return Err(Error::InvalidAddress);
        }
        Ok(Address {
            kind: AddressKind::Integrated(payment_id),
            ..*self
        })
    }

    /// The payment id of an integrated address.
    pub const fn payment_id(&self) -> Option<[u8; PAYMENT_ID_LEN]> {
        match self.kind {
            AddressKind::Integrated(id) => Some(id),
            _ => None,
        }
    }

    /// Whether this is a subaddress.
    pub const fn is_subaddress(&self) -> bool {
        matches!(self.kind, AddressKind::Subaddress)
    }

    /// The base58 prefix (tag) of the address.
    pub const fn prefix(&self) -> u64 {
        let [standard, integrated, subaddress] = self.network.prefixes();
        match self.kind {
            AddressKind::Standard => standard,
            AddressKind::Integrated(_) => integrated,
            AddressKind::Subaddress => subaddress,
        }
    }

    /// The number of characters of the text form.
    pub const fn encoded_len(&self) -> usize {
        match self.kind {
            AddressKind::Integrated(_) => MAX_ADDRESS_LEN,
            _ => STANDARD_ADDRESS_LEN,
        }
    }

    /// Writes the text form at the start of `out`, returning its length
    /// ([`encoded_len`](Self::encoded_len), at most [`MAX_ADDRESS_LEN`]).
    ///
    /// Fails with [`Error::CryptoNote`] ([`BufferTooSmall`]) if `out` is too
    /// short.
    ///
    /// [`BufferTooSmall`]: crate::cryptonote::Error::BufferTooSmall
    pub fn encode_to_slice(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut payload = [0u8; 72];
        let (keys, id) = payload.split_at_mut(64);
        let (spend, view) = keys.split_at_mut(32);
        spend.copy_from_slice(&self.spend_public);
        view.copy_from_slice(&self.view_public);
        let len = match self.kind {
            AddressKind::Integrated(payment_id) => {
                id.copy_from_slice(&payment_id);
                72
            }
            _ => 64,
        };
        let payload = payload.get(..len).unwrap_or(&[]);
        Ok(encode_address_to_slice(self.prefix(), payload, out)?)
    }

    /// Decodes the text form of an address of any network and kind.
    ///
    /// Fails with the errors of
    /// [`decode_address_to_slice`] (as [`Error::CryptoNote`]) for a
    /// malformed text or a bad checksum, and with [`Error::InvalidAddress`]
    /// for an unknown prefix, a payload of the wrong length, or keys that are
    /// not curve points.
    pub fn decode(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_ADDRESS_LEN {
            return Err(Error::InvalidAddress);
        }
        let mut buf = [0u8; 88];
        let need = address_decoded_len(text.len()).ok_or(Error::InvalidAddress)?;
        let scratch = buf.get_mut(..need).ok_or(Error::InvalidAddress)?;
        let (prefix, len) = decode_address_to_slice(text, scratch)?;
        let payload = scratch.get(..len).ok_or(Error::InvalidAddress)?;

        let (network, kind) = [Network::Mainnet, Network::Testnet, Network::Stagenet]
            .into_iter()
            .find_map(|network| {
                let position = network.prefixes().iter().position(|p| *p == prefix)?;
                Some((network, position))
            })
            .ok_or(Error::InvalidAddress)?;

        let expected = if kind == 1 { 72 } else { 64 };
        if payload.len() != expected {
            return Err(Error::InvalidAddress);
        }
        let mut spend_public = [0u8; 32];
        let mut view_public = [0u8; 32];
        let mut payment_id = [0u8; PAYMENT_ID_LEN];
        for (d, s) in spend_public.iter_mut().zip(payload) {
            *d = *s;
        }
        for (d, s) in view_public.iter_mut().zip(payload.iter().skip(32)) {
            *d = *s;
        }
        for (d, s) in payment_id.iter_mut().zip(payload.iter().skip(64)) {
            *d = *s;
        }
        if !check_key(&spend_public) || !check_key(&view_public) {
            return Err(Error::InvalidAddress);
        }
        let kind = match kind {
            0 => AddressKind::Standard,
            1 => AddressKind::Integrated(payment_id),
            _ => AddressKind::Subaddress,
        };
        Ok(Address {
            network,
            kind,
            spend_public,
            view_public,
        })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; MAX_ADDRESS_LEN];
        let n = self.encode_to_slice(&mut buf).map_err(|_| fmt::Error)?;
        let text = buf.get(..n).ok_or(fmt::Error)?;
        f.write_str(core::str::from_utf8(text).map_err(|_| fmt::Error)?)
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Address::decode(s)
    }
}
