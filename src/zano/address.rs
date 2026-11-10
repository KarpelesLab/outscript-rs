//! Zano addresses: the CryptoNote framing
//! ([`cryptonote`](crate::cryptonote)) around the public spend and view keys,
//! an optional flags byte and an optional payment id.

use core::fmt;
use core::str::FromStr;

use crate::cryptonote::{address_decoded_len, decode_address_to_slice, encode_address_to_slice};

use super::Error;

/// The longest payment id an integrated address carries.
pub const MAX_PAYMENT_ID_LEN: usize = 128;

/// The longest address text: a three-byte prefix, both keys, the flags, a
/// full payment id and the checksum, in base58.
pub const MAX_ADDRESS_LEN: usize = 275;

/// The flag bit that marks an account as auditable.
pub const ADDRESS_FLAG_AUDITABLE: u8 = 1;

/// The longest payload: keys, flags and payment id.
const MAX_PAYLOAD_LEN: usize = 64 + 1 + MAX_PAYMENT_ID_LEN;
/// Room to decode the longest address (prefix and checksum included).
const DECODE_BUF_LEN: usize = 200;

/// The kind of a Zano address, which is its base58 prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    /// A standard address (`Zx...`, prefix `0xc5`). It carries a flags byte
    /// only when the flags are not zero.
    Standard,
    /// An integrated address: a standard address with a payment id (`iZ...`,
    /// prefix `0x3678`), without flags.
    Integrated,
    /// An integrated address with a flags byte (`iZ...`, prefix `0x36f8`).
    IntegratedV2,
    /// An auditable address (`aZx...`, prefix `0x98c8`).
    Auditable,
    /// An auditable integrated address (`aiZX...`, prefix `0x8a49`).
    AuditableIntegrated,
}

impl AddressType {
    /// The base58 prefix (tag) of this kind.
    pub const fn prefix(self) -> u64 {
        match self {
            AddressType::Standard => 0xc5,
            AddressType::Integrated => 0x3678,
            AddressType::IntegratedV2 => 0x36f8,
            AddressType::Auditable => 0x98c8,
            AddressType::AuditableIntegrated => 0x8a49,
        }
    }

    /// The kind with this base58 prefix.
    pub const fn from_prefix(prefix: u64) -> Option<Self> {
        Some(match prefix {
            0xc5 => AddressType::Standard,
            0x3678 => AddressType::Integrated,
            0x36f8 => AddressType::IntegratedV2,
            0x98c8 => AddressType::Auditable,
            0x8a49 => AddressType::AuditableIntegrated,
            _ => return None,
        })
    }

    /// Whether this is an auditable kind.
    pub const fn is_auditable(self) -> bool {
        matches!(
            self,
            AddressType::Auditable | AddressType::AuditableIntegrated
        )
    }

    /// Whether this kind carries a payment id.
    pub const fn is_integrated(self) -> bool {
        matches!(
            self,
            AddressType::Integrated | AddressType::IntegratedV2 | AddressType::AuditableIntegrated
        )
    }

    /// Whether the encoding of this kind always has a flags byte.
    pub const fn has_flags(self) -> bool {
        matches!(
            self,
            AddressType::IntegratedV2 | AddressType::Auditable | AddressType::AuditableIntegrated
        )
    }
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AddressType::Standard => "Public Address (Zx)",
            AddressType::Integrated => "Integrated Address (iZ)",
            AddressType::IntegratedV2 => "Integrated Address V2 (iZ)",
            AddressType::Auditable => "Audit Address (aZx)",
            AddressType::AuditableIntegrated => "Audit Integrated Address (aiZX)",
        })
    }
}

/// A payment id: up to [`MAX_PAYMENT_ID_LEN`] bytes an integrated address
/// asks the sender to attach to the transaction.
#[derive(Clone, Copy)]
pub struct PaymentId {
    len: u8,
    bytes: [u8; MAX_PAYMENT_ID_LEN],
}

impl PaymentId {
    /// No payment id.
    pub const EMPTY: PaymentId = PaymentId {
        len: 0,
        bytes: [0; MAX_PAYMENT_ID_LEN],
    };

    /// A payment id; fails with [`Error::PaymentIdTooLong`] past
    /// [`MAX_PAYMENT_ID_LEN`] bytes.
    pub fn new(id: &[u8]) -> Result<Self, Error> {
        let len = u8::try_from(id.len()).map_err(|_| Error::PaymentIdTooLong)?;
        let mut bytes = [0u8; MAX_PAYMENT_ID_LEN];
        bytes
            .get_mut(..id.len())
            .ok_or(Error::PaymentIdTooLong)?
            .copy_from_slice(id);
        Ok(PaymentId { len, bytes })
    }

    /// The bytes of the payment id.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// Whether there is no payment id.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for PaymentId {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl PartialEq for PaymentId {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for PaymentId {}

impl fmt::Debug for PaymentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PaymentId(")?;
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

impl AsRef<[u8]> for PaymentId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A Zano address.
///
/// ```
/// use outscript::zano::{Address, AddressType};
///
/// let text = "ZxD5aoLDPTdcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp338Se7AxeH";
/// let mut address: Address = text.parse()?;
/// assert_eq!(address.address_type(), AddressType::Standard);
/// assert_eq!(address.spend_key()[..4], [0x9f, 0x5e, 0x1f, 0xa9]);
///
/// // Asking for a payment id makes it an integrated address.
/// address.set_payment_id(&[0x87, 0x44, 0x0d, 0x0b, 0x9a, 0xcc, 0x42, 0xf1])?;
/// assert_eq!(address.address_type(), AddressType::Integrated);
/// let mut buf = [0u8; outscript::zano::MAX_ADDRESS_LEN];
/// let n = address.encode_to_slice(&mut buf)?;
/// assert!(buf[..n].starts_with(b"iZ"));
/// # Ok::<(), outscript::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address {
    kind: AddressType,
    flags: u8,
    spend_key: [u8; 32],
    view_key: [u8; 32],
    payment_id: PaymentId,
}

impl Address {
    /// The address of an account: [`AddressType::Auditable`] when `flags` has
    /// [`ADDRESS_FLAG_AUDITABLE`], [`AddressType::Standard`] otherwise.
    ///
    /// The keys are not checked to be curve points.
    pub fn new(spend_key: [u8; 32], view_key: [u8; 32], flags: u8) -> Self {
        let kind = if flags & ADDRESS_FLAG_AUDITABLE != 0 {
            AddressType::Auditable
        } else {
            AddressType::Standard
        };
        Address {
            kind,
            flags,
            spend_key,
            view_key,
            payment_id: PaymentId::EMPTY,
        }
    }

    /// Parses an address.
    ///
    /// Fails with the errors of
    /// [`decode_address_to_slice`](crate::cryptonote::decode_address_to_slice)
    /// (wrapped in [`Error::CryptoNote`]), [`Error::UnknownAddressType`] for a
    /// prefix that is not Zano's, [`Error::InvalidAddressLength`] when the
    /// payload does not fit the kind, and [`Error::PaymentIdTooLong`].
    pub fn parse(address: &str) -> Result<Self, Error> {
        let mut buf = [0u8; DECODE_BUF_LEN];
        match address_decoded_len(address.len()) {
            Some(n) if n <= buf.len() => {}
            _ => return Err(Error::InvalidAddressLength),
        }
        let (prefix, len) = decode_address_to_slice(address, &mut buf)?;
        let kind = AddressType::from_prefix(prefix).ok_or(Error::UnknownAddressType)?;
        let payload = buf.get(..len).ok_or(Error::InvalidAddressLength)?;
        let (keys, rest) = payload
            .split_at_checked(64)
            .ok_or(Error::InvalidAddressLength)?;
        let mut spend_key = [0u8; 32];
        let mut view_key = [0u8; 32];
        spend_key.copy_from_slice(&keys[..32]);
        view_key.copy_from_slice(&keys[32..]);

        let (flags, payment_id) = match kind {
            // The flags byte of a standard address is only there when not zero.
            AddressType::Standard => match rest {
                [] => (0, rest),
                [flags] => (*flags, &rest[1..]),
                _ => return Err(Error::InvalidAddressLength),
            },
            AddressType::Integrated => (0, rest),
            AddressType::IntegratedV2
            | AddressType::Auditable
            | AddressType::AuditableIntegrated => {
                let (flags, id) = rest.split_first().ok_or(Error::InvalidAddressLength)?;
                (*flags, id)
            }
        };
        if !kind.is_integrated() && !payment_id.is_empty() {
            return Err(Error::InvalidAddressLength);
        }
        Ok(Address {
            kind,
            flags,
            spend_key,
            view_key,
            payment_id: PaymentId::new(payment_id)?,
        })
    }

    /// The kind of the address.
    pub fn address_type(&self) -> AddressType {
        self.kind
    }

    /// The flags of the account ([`ADDRESS_FLAG_AUDITABLE`]).
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Whether the account is auditable.
    pub fn is_auditable(&self) -> bool {
        self.flags & ADDRESS_FLAG_AUDITABLE != 0
    }

    /// The public spend key.
    pub fn spend_key(&self) -> &[u8; 32] {
        &self.spend_key
    }

    /// The public view key.
    pub fn view_key(&self) -> &[u8; 32] {
        &self.view_key
    }

    /// The payment id (empty unless the address is integrated).
    pub fn payment_id(&self) -> &[u8] {
        self.payment_id.as_bytes()
    }

    /// Sets the payment id, turning the address into the matching integrated
    /// kind; an empty id removes it and gives back the plain kind.
    ///
    /// Fails with [`Error::PaymentIdTooLong`] past [`MAX_PAYMENT_ID_LEN`]
    /// bytes.
    pub fn set_payment_id(&mut self, payment_id: &[u8]) -> Result<(), Error> {
        self.payment_id = PaymentId::new(payment_id)?;
        self.kind = match (self.kind, payment_id.is_empty()) {
            (AddressType::Integrated | AddressType::IntegratedV2, true) => AddressType::Standard,
            (AddressType::AuditableIntegrated, true) => AddressType::Auditable,
            (AddressType::Standard, false) if self.flags != 0 => AddressType::IntegratedV2,
            (AddressType::Standard, false) => AddressType::Integrated,
            (AddressType::Auditable, false) => AddressType::AuditableIntegrated,
            (kind, _) => kind,
        };
        Ok(())
    }

    /// The payload the address frames: keys, flags and payment id.
    fn payload(&self) -> ([u8; MAX_PAYLOAD_LEN], usize) {
        let mut buf = [0u8; MAX_PAYLOAD_LEN];
        buf[..32].copy_from_slice(&self.spend_key);
        buf[32..64].copy_from_slice(&self.view_key);
        let mut n = 64;
        let flags = match self.kind {
            AddressType::Standard => self.flags != 0,
            kind => kind.has_flags(),
        };
        if flags {
            buf[n] = self.flags;
            n += 1;
        }
        if self.kind.is_integrated() {
            let id = self.payment_id.as_bytes();
            // A payment id is at most `MAX_PAYMENT_ID_LEN` bytes, so it fits.
            if let Some(dst) = buf.get_mut(n..n + id.len()) {
                dst.copy_from_slice(id);
                n += id.len();
            }
        }
        (buf, n)
    }

    /// Writes the address text at the start of `out`, returning its length
    /// (at most [`MAX_ADDRESS_LEN`]). The text is ASCII.
    ///
    /// Fails with [`Error::CryptoNote`] (`BufferTooSmall`) if `out` is too
    /// short.
    pub fn encode_to_slice(&self, out: &mut [u8]) -> Result<usize, Error> {
        let (payload, n) = self.payload();
        Ok(encode_address_to_slice(
            self.kind.prefix(),
            &payload[..n],
            out,
        )?)
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
        Address::parse(s)
    }
}
