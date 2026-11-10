//! Revision 2 of ZIP-316 (a draft at the time of writing): unified
//! addresses and viewing keys with metadata.
//!
//! Revision 2 adds *Metadata Items* to the receivers and keys of a unified
//! encoding: an expiry height and an expiry time, after which an address
//! must not be paid to any more, and for viewing keys a birthday height,
//! from which the chain is worth scanning. Metadata typecodes from `0xE0`
//! are *MUST-understand*: a consumer that does not know one must not use
//! the encoding at all. Since older consumers would skip them, encodings
//! of Revision 2 have human-readable parts of their own:
//!
//! |                                     | main  | test      |
//! |-------------------------------------|-------|-----------|
//! | address without transparent receiver | `zu`  | `zutest`  |
//! | address that may have one            | `tu`  | `tutest`  |
//! | full viewing key                     | `uvf` | `uvftest` |
//! | incoming viewing key                 | `uvi` | `uvitest` |
//!
//! ZIP-316 defines none for regression test networks, and neither does
//! this module: encoding for [`Network::Regtest`] fails.
//!
//! (Revision 1 of the ZIP, which had other human-readable parts, was
//! withdrawn, and is not implemented.)
//!
//! Revision 2 also drops the requirement that a viewing key have a
//! shielded item, and lets viewing keys carry a *P2SH viewing key*
//! ([`P2shViewingKey`]): a BIP 388 wallet policy.
//!
//! The containers here mirror those of Revision 0
//! ([`super::UnifiedAddress`] and the others), hold their items as
//! fixed-size arrays and never allocate. Nothing is derived: making the
//! incoming viewing key of a full viewing key, or an address of a viewing
//! key, is done item by item with the key types of each pool, carrying the
//! metadata over as the ZIP requires (the expiry of what is derived must
//! not be later than that of the key; the birthday height stays out of
//! addresses).

use purecrypto::zeroize::Zeroize;

use super::{
    Error, Item, Items, Network, PADDING_LEN, TYPECODE_BIRTHDAY_HEIGHT, TYPECODE_EXPIRY_HEIGHT,
    TYPECODE_EXPIRY_TIME, TYPECODE_ORCHARD, TYPECODE_P2PKH, TYPECODE_P2SH, TYPECODE_SAPLING,
    decode_to_slice, encode_to_slice, fixed, is_metadata, is_must_understand,
};
use crate::orchard::keys::{Address, FullViewingKey, IncomingViewingKey};
use crate::orchard::spec::{compact_size, read_compact_size, take};

#[cfg(feature = "alloc")]
use crate::prelude::*;

const SHIELDED_ADDRESS_HRPS: [&str; 2] = ["zu", "zutest"];
const TRANSPARENT_ADDRESS_HRPS: [&str; 2] = ["tu", "tutest"];
const UFVK_HRPS: [&str; 2] = ["uvf", "uvftest"];
const UIVK_HRPS: [&str; 2] = ["uvi", "uvitest"];

/// The longest P2SH viewing key item held: enough for the policy of a
/// multisignature of fifteen keys, the most a P2SH script has room for.
pub const P2SH_VIEWING_KEY_MAX_LEN: usize = 1152;

/// The size of the buffer the decoders use without `alloc`: the longest
/// encoding the containers here produce fits.
const STACK_BUF: usize = 2560;

fn hrp_for<'a>(hrps: &[&'a str; 2], network: Network) -> Result<&'a str, Error> {
    match network {
        Network::Main => Ok(hrps[0]),
        Network::Test => Ok(hrps[1]),
        Network::Regtest => Err(Error::InvalidPrefix),
    }
}

fn network_of(hrps: &[&str; 2], hrp: &str) -> Option<Network> {
    if hrp.eq_ignore_ascii_case(hrps[0]) {
        Some(Network::Main)
    } else if hrp.eq_ignore_ascii_case(hrps[1]) {
        Some(Network::Test)
    } else {
        None
    }
}

/// Decodes `s` and hands its human-readable part and items to `f`.
fn decode_with<R>(
    s: &str,
    f: impl FnOnce(&str, Items<'_>) -> Result<R, Error>,
) -> Result<R, Error> {
    let mut stack = [0u8; STACK_BUF];
    #[cfg(feature = "alloc")]
    let mut heap = Vec::new();
    #[cfg(feature = "alloc")]
    let buf: &mut [u8] = if s.len() > STACK_BUF {
        heap.resize(s.len(), 0);
        &mut heap
    } else {
        &mut stack
    };
    #[cfg(not(feature = "alloc"))]
    let buf: &mut [u8] = &mut stack;
    let result = match decode_to_slice(s, buf) {
        Ok((hrp, items)) => f(hrp, items),
        Err(Error::BufferTooSmall) => Err(Error::TooLarge),
        Err(e) => Err(e),
    };
    // viewing keys pass through the buffer
    buf.zeroize();
    result
}

/// Encodes the items that are present, already in typecode order.
fn encode_some<'o, const N: usize>(
    hrp: &str,
    items: [Option<Item<'_>>; N],
    out: &'o mut [u8],
) -> Result<&'o str, Error> {
    let mut list = [Item {
        typecode: 0,
        data: &[],
    }; N];
    let mut n = 0;
    for item in items.into_iter().flatten() {
        list[n] = item;
        n += 1;
    }
    if !list[..n].iter().any(|item| !is_metadata(item.typecode)) {
        return Err(Error::OnlyMetadata);
    }
    let mut scratch = [0u8; STACK_BUF];
    let result = encode_to_slice(hrp, &list[..n], &mut scratch, out);
    scratch.zeroize();
    result
}

fn item<'a>(typecode: u32, data: &'a Option<impl AsRef<[u8]>>) -> Option<Item<'a>> {
    data.as_ref().map(|d| Item {
        typecode,
        data: d.as_ref(),
    })
}

/// When an address stops being valid, or a viewing key stops giving valid
/// addresses: the metadata items `0xE0` and `0xE1`. Without either, never.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Expiry {
    /// The Address Expiry Height: the address is expired once the chain is
    /// higher than this.
    pub height: Option<u32>,
    /// The Address Expiry Time, in seconds since the Unix epoch: the
    /// address is expired after it.
    pub time: Option<u64>,
}

impl Expiry {
    /// No expiry.
    pub const NONE: Expiry = Expiry {
        height: None,
        time: None,
    };

    /// Whether the address is expired when the chain is at `chain_height`
    /// and the time is `unix_time` (seconds since the Unix epoch): a wallet
    /// must not pay to it then.
    pub fn is_expired(&self, chain_height: u32, unix_time: u64) -> bool {
        self.height.is_some_and(|height| chain_height > height)
            || self.time.is_some_and(|time| unix_time > time)
    }

    /// Whether a transaction paying the address may have the expiry height
    /// `tx_expiry_height` (its `nExpiryHeight`): it must have one (not 0)
    /// when the address has an expiry height, and not above it. (The
    /// transaction is not to be given the expiry height of the address
    /// itself, which would tell which address it pays.)
    pub fn allows_tx_expiry_height(&self, tx_expiry_height: u32) -> bool {
        match self.height {
            Some(height) => tx_expiry_height != 0 && tx_expiry_height <= height,
            None => true,
        }
    }

    /// Whether this expiry is no later than `other`, in height and in
    /// time: what the expiry of an address must be with respect to the
    /// viewing key it is derived from.
    pub fn is_within(&self, other: &Expiry) -> bool {
        let within = |own: Option<u64>, limit: Option<u64>| match (own, limit) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(own), Some(limit)) => own <= limit,
        };
        within(self.height.map(u64::from), other.height.map(u64::from))
            && within(self.time, other.time)
    }

    fn height_bytes(&self) -> Option<[u8; 4]> {
        self.height.map(u32::to_le_bytes)
    }

    fn time_bytes(&self) -> Option<[u8; 8]> {
        self.time.map(u64::to_le_bytes)
    }
}

/// What the decoders collect from the metadata items of an encoding.
#[derive(Default)]
struct Metadata {
    birthday_height: Option<u32>,
    expiry: Expiry,
    /// An item that is not metadata was skipped for its unknown typecode.
    unknown: bool,
}

impl Metadata {
    /// Takes an item none of the known receivers or keys: metadata, or of
    /// an unknown typecode.
    fn take(&mut self, item: &Item<'_>) -> Result<(), Error> {
        match item.typecode {
            TYPECODE_BIRTHDAY_HEIGHT => {
                self.birthday_height = fixed(item.data)?.map(u32::from_le_bytes);
            }
            TYPECODE_EXPIRY_HEIGHT => {
                self.expiry.height = fixed(item.data)?.map(u32::from_le_bytes);
            }
            TYPECODE_EXPIRY_TIME => {
                self.expiry.time = fixed(item.data)?.map(u64::from_le_bytes);
            }
            typecode if is_must_understand(typecode) => return Err(Error::MustUnderstand),
            typecode if is_metadata(typecode) => {}
            _ => self.unknown = true,
        }
        Ok(())
    }

    /// The rule for viewing keys: the birthday is not after the expiry.
    fn check_birthday(&self) -> Result<(), Error> {
        match (self.birthday_height, self.expiry.height) {
            (Some(birthday), Some(expiry)) if birthday > expiry => Err(Error::InvalidItem),
            _ => Ok(()),
        }
    }
}

/// A unified address of Revision 2: at most one receiver per pool, and
/// when it stops being valid.
///
/// There are two kinds, told apart by their human-readable part: those
/// that cannot have a transparent receiver (`zu`), and those that can
/// (`tu`), which give up some privacy and say so.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnifiedAddress {
    /// Whether the address is of the kind that may have a transparent
    /// receiver (`tu`). An address of the other kind (`zu`) with one does
    /// not encode.
    pub transparent_enabled: bool,
    /// The transparent P2PKH receiver: the hash of a public key.
    pub p2pkh: Option<[u8; 20]>,
    /// The transparent P2SH receiver: the hash of a script. An address
    /// cannot have both transparent receivers.
    pub p2sh: Option<[u8; 20]>,
    /// The Sapling receiver: a raw Sapling address (not interpreted here).
    pub sapling: Option<[u8; 43]>,
    /// The Orchard receiver: a raw Orchard address, see
    /// [`orchard_address`](Self::orchard_address).
    pub orchard: Option<[u8; 43]>,
    /// When the address expires.
    pub expiry: Expiry,
}

impl UnifiedAddress {
    /// The longest string an address made of these items encodes to.
    pub const MAX_ENCODED_LEN: usize = 6 + 1 + (Self::MAX_RAW_LEN * 8).div_ceil(5) + 6;
    const MAX_RAW_LEN: usize = 22 + 45 + 45 + 6 + 10 + PADDING_LEN;

    /// The address with only an Orchard receiver, without expiry.
    pub fn from_orchard(address: &Address) -> Self {
        UnifiedAddress {
            orchard: Some(address.to_raw_address_bytes()),
            ..Default::default()
        }
    }

    /// The Orchard receiver as an address, if there is one and it is valid.
    pub fn orchard_address(&self) -> Result<Option<Address>, Error> {
        self.orchard
            .as_ref()
            .map(Address::from_raw_address_bytes)
            .transpose()
    }

    fn check(&self) -> Result<(), Error> {
        if self.p2pkh.is_some() && self.p2sh.is_some() {
            return Err(Error::BothP2pkhAndP2sh);
        }
        if !self.transparent_enabled && (self.p2pkh.is_some() || self.p2sh.is_some()) {
            return Err(Error::InvalidItem);
        }
        Ok(())
    }

    /// Encodes the address into `out` ([`MAX_ENCODED_LEN`](Self::MAX_ENCODED_LEN)
    /// bytes always suffice), returning the string.
    pub fn encode_to_slice<'o>(
        &self,
        network: Network,
        out: &'o mut [u8],
    ) -> Result<&'o str, Error> {
        self.check()?;
        let hrps = if self.transparent_enabled {
            &TRANSPARENT_ADDRESS_HRPS
        } else {
            &SHIELDED_ADDRESS_HRPS
        };
        encode_some(
            hrp_for(hrps, network)?,
            [
                item(TYPECODE_P2PKH, &self.p2pkh),
                item(TYPECODE_P2SH, &self.p2sh),
                item(TYPECODE_SAPLING, &self.sapling),
                item(TYPECODE_ORCHARD, &self.orchard),
                item(TYPECODE_EXPIRY_HEIGHT, &self.expiry.height_bytes()),
                item(TYPECODE_EXPIRY_TIME, &self.expiry.time_bytes()),
            ],
            out,
        )
    }

    /// Encodes the address as a `String`.
    #[cfg(feature = "alloc")]
    pub fn encode(&self, network: Network) -> Result<String, Error> {
        let mut out = [0u8; Self::MAX_ENCODED_LEN];
        self.encode_to_slice(network, &mut out).map(String::from)
    }

    /// Decodes a unified address of Revision 2 (`zu...` or `tu...`),
    /// returning its network too.
    ///
    /// Items of unknown typecode are skipped, except metadata that must be
    /// understood ([`Error::MustUnderstand`]). A birthday height, which
    /// has no place in an address, is ignored as the ZIP requires.
    pub fn decode(s: &str) -> Result<(Network, Self), Error> {
        decode_with(s, |hrp, items| {
            let (network, transparent_enabled) = match (
                network_of(&SHIELDED_ADDRESS_HRPS, hrp),
                network_of(&TRANSPARENT_ADDRESS_HRPS, hrp),
            ) {
                (Some(network), _) => (network, false),
                (_, Some(network)) => (network, true),
                _ => return Err(Error::InvalidPrefix),
            };
            let mut ua = UnifiedAddress {
                transparent_enabled,
                ..Default::default()
            };
            let mut metadata = Metadata::default();
            for item in items {
                match item.typecode {
                    TYPECODE_P2PKH => ua.p2pkh = fixed(item.data)?,
                    TYPECODE_P2SH => ua.p2sh = fixed(item.data)?,
                    TYPECODE_SAPLING => ua.sapling = fixed(item.data)?,
                    TYPECODE_ORCHARD => ua.orchard = fixed(item.data)?,
                    _ => metadata.take(&item)?,
                }
            }
            ua.expiry = metadata.expiry;
            ua.check()?;
            let known = ua.p2pkh.is_some()
                || ua.p2sh.is_some()
                || ua.sapling.is_some()
                || ua.orchard.is_some();
            if !known && !metadata.unknown {
                return Err(Error::OnlyMetadata);
            }
            Ok((network, ua))
        })
    }
}

/// A P2SH viewing key item of a unified viewing key of Revision 2: a
/// BIP 388 wallet policy, that is a descriptor template (as
/// `sh(sortedmulti(2,@0/**,@1/**,@2/**))`) and the chain code and public
/// key of each key the template refers to as `@N`.
///
/// In a full viewing key every key of the template is followed by `/**`
/// (both the external and the internal chain); in an incoming viewing key
/// by `/*` (the keys being those of the external chain).
///
/// What is checked is the shape of the item: its lengths, that the
/// template is ASCII and refers to exactly the keys given, each in the
/// notation its kind of viewing key requires, and that the public keys
/// look compressed. Whether the template is a valid descriptor is for a
/// descriptor parser to tell.
#[derive(Clone, Copy)]
pub struct P2shViewingKey {
    len: usize,
    template_start: usize,
    template_len: usize,
    keys_start: usize,
    keys: usize,
    data: [u8; P2SH_VIEWING_KEY_MAX_LEN],
}

impl PartialEq for P2shViewingKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for P2shViewingKey {}

impl core::fmt::Debug for P2shViewingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("P2shViewingKey")
            .field("template", &self.template())
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

impl AsRef<[u8]> for P2shViewingKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl P2shViewingKey {
    /// Parses the item of a full viewing key (`full`) or of an incoming
    /// viewing key.
    pub fn from_bytes(item: &[u8], full: bool) -> Result<Self, Error> {
        if item.len() > P2SH_VIEWING_KEY_MAX_LEN {
            return Err(Error::TooLarge);
        }
        let mut rest = item;
        let template_len =
            usize::try_from(read_compact_size(&mut rest)?).map_err(|_| Error::TooLarge)?;
        let template_start = item.len() - rest.len();
        let template = take(&mut rest, template_len)?;
        let keys = usize::try_from(read_compact_size(&mut rest)?).map_err(|_| Error::TooLarge)?;
        let keys_start = item.len() - rest.len();
        if keys.checked_mul(65) != Some(rest.len()) {
            return Err(Error::InvalidItem);
        }
        if !rest
            .as_chunks::<65>()
            .0
            .iter()
            .all(|key| matches!(key[32], 0x02 | 0x03))
        {
            return Err(Error::InvalidItem);
        }
        check_template(template, keys, full)?;
        let mut data = [0u8; P2SH_VIEWING_KEY_MAX_LEN];
        data[..item.len()].copy_from_slice(item);
        Ok(P2shViewingKey {
            len: item.len(),
            template_start,
            template_len,
            keys_start,
            keys,
            data,
        })
    }

    /// The item for a descriptor template and the keys it refers to (each
    /// a chain code followed by a compressed public key), in the order the
    /// policy defines (for the keys of ZIP 48, sorted as byte strings).
    pub fn new(template: &str, keys: &[[u8; 65]], full: bool) -> Result<Self, Error> {
        let (template_len, t) = compact_size(template.len() as u64);
        let (key_count, k) = compact_size(keys.len() as u64);
        let len = t + template.len() + k + 65 * keys.len();
        let mut data = [0u8; P2SH_VIEWING_KEY_MAX_LEN];
        let out = data.get_mut(..len).ok_or(Error::TooLarge)?;
        let (head, rest) = out.split_at_mut(t);
        head.copy_from_slice(&template_len[..t]);
        let (head, rest) = rest.split_at_mut(template.len());
        head.copy_from_slice(template.as_bytes());
        let (head, rest) = rest.split_at_mut(k);
        head.copy_from_slice(&key_count[..k]);
        for (slot, key) in rest.as_chunks_mut::<65>().0.iter_mut().zip(keys) {
            slot.copy_from_slice(key);
        }
        Self::from_bytes(&data[..len], full)
    }

    /// The encoding of the item.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// The descriptor template.
    pub fn template(&self) -> &str {
        let bytes = &self.data[self.template_start..self.template_start + self.template_len];
        // checked to be ASCII when the item was made
        core::str::from_utf8(bytes).unwrap_or_default()
    }

    /// The keys: for each, its chain code and its compressed public key.
    pub fn keys(&self) -> impl ExactSizeIterator<Item = (&[u8; 32], &[u8; 33])> {
        self.data[self.keys_start..self.keys_start + 65 * self.keys]
            .as_chunks::<65>()
            .0
            .iter()
            .map(|key| {
                let (chain_code, public_key) = key.split_at(32);
                (
                    chain_code.try_into().expect("32 bytes"),
                    public_key.try_into().expect("33 bytes"),
                )
            })
    }
}

/// Checks that a descriptor template is printable ASCII and refers to
/// exactly the keys `@0` to `@(keys - 1)`, each time followed by `/**`
/// (`full`) or by `/*` alone.
fn check_template(template: &[u8], keys: usize, full: bool) -> Result<(), Error> {
    if template.is_empty() || !template.iter().all(|b| (0x20..0x7f).contains(b)) {
        return Err(Error::InvalidItem);
    }
    // (a P2SH script has room for fifteen keys; the item for 64)
    let mut seen = 0u64;
    let mut rest = template;
    while let Some(at) = rest.iter().position(|b| *b == b'@') {
        rest = &rest[at + 1..];
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        // no leading zero, as BIP 388 writes indices
        if digits == 0 || digits > 2 || (digits > 1 && rest[0] == b'0') {
            return Err(Error::InvalidItem);
        }
        let index = rest[..digits]
            .iter()
            .fold(0usize, |acc, d| acc * 10 + (d - b'0') as usize);
        if index >= keys || index >= 64 {
            return Err(Error::InvalidItem);
        }
        seen |= 1 << index;
        rest = &rest[digits..];
        let multipath = rest.starts_with(b"/**");
        let single = rest.starts_with(b"/*") && !multipath;
        if (full && !multipath) || (!full && !single) {
            return Err(Error::InvalidItem);
        }
    }
    if keys > 64 || seen.count_ones() as usize != keys {
        return Err(Error::InvalidItem);
    }
    Ok(())
}

/// A unified full viewing key of Revision 2: at most one full viewing key
/// per pool (none of which need be shielded), and metadata.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnifiedFullViewingKey {
    /// The transparent P2PKH item: the chain code and compressed public
    /// key of the account's BIP-44 node (`m / 44' / coin_type' / account'`).
    pub transparent: Option<[u8; 65]>,
    /// The P2SH item: a wallet policy. A key cannot have both transparent
    /// items.
    pub p2sh: Option<P2shViewingKey>,
    /// The Sapling item: `ak || nk || ovk || dk` (not interpreted here).
    pub sapling: Option<[u8; 128]>,
    /// The Orchard item: `ak || nk || rivk`, see
    /// [`orchard_fvk`](Self::orchard_fvk).
    pub orchard: Option<[u8; 96]>,
    /// The height of the first block worth scanning for the funds of the
    /// key (not above its expiry height, if it has one).
    pub birthday_height: Option<u32>,
    /// When the addresses of the key expire, at the latest.
    pub expiry: Expiry,
}

/// The longest raw encoding of the metadata of a viewing key.
const METADATA_RAW_LEN: usize = 7 + 6 + 10;

impl UnifiedFullViewingKey {
    /// The longest string a key made of these items encodes to.
    pub const MAX_ENCODED_LEN: usize = 7 + 1 + (Self::MAX_RAW_LEN * 8).div_ceil(5) + 6;
    const MAX_RAW_LEN: usize =
        67 + (4 + P2SH_VIEWING_KEY_MAX_LEN) + 130 + 98 + METADATA_RAW_LEN + PADDING_LEN;

    /// The key with only an Orchard item, without metadata.
    pub fn from_orchard(fvk: &FullViewingKey) -> Self {
        UnifiedFullViewingKey {
            orchard: Some(fvk.to_bytes()),
            ..Default::default()
        }
    }

    /// The Orchard item as a full viewing key, if there is one and it is
    /// valid.
    pub fn orchard_fvk(&self) -> Result<Option<FullViewingKey>, Error> {
        self.orchard
            .as_ref()
            .map(FullViewingKey::from_bytes)
            .transpose()
    }

    fn check(&self) -> Result<(), Error> {
        if self.transparent.is_some() && self.p2sh.is_some() {
            return Err(Error::BothP2pkhAndP2sh);
        }
        match (self.birthday_height, self.expiry.height) {
            (Some(birthday), Some(expiry)) if birthday > expiry => Err(Error::InvalidItem),
            _ => Ok(()),
        }
    }

    /// Encodes the key into `out` ([`MAX_ENCODED_LEN`](Self::MAX_ENCODED_LEN)
    /// bytes always suffice), returning the string.
    pub fn encode_to_slice<'o>(
        &self,
        network: Network,
        out: &'o mut [u8],
    ) -> Result<&'o str, Error> {
        self.check()?;
        encode_some(
            hrp_for(&UFVK_HRPS, network)?,
            [
                item(TYPECODE_P2PKH, &self.transparent),
                item(TYPECODE_P2SH, &self.p2sh),
                item(TYPECODE_SAPLING, &self.sapling),
                item(TYPECODE_ORCHARD, &self.orchard),
                item(
                    TYPECODE_BIRTHDAY_HEIGHT,
                    &self.birthday_height.map(u32::to_le_bytes),
                ),
                item(TYPECODE_EXPIRY_HEIGHT, &self.expiry.height_bytes()),
                item(TYPECODE_EXPIRY_TIME, &self.expiry.time_bytes()),
            ],
            out,
        )
    }

    /// Encodes the key as a `String`.
    #[cfg(feature = "alloc")]
    pub fn encode(&self, network: Network) -> Result<String, Error> {
        let mut out = vec![0u8; Self::MAX_ENCODED_LEN];
        let result = self.encode_to_slice(network, &mut out).map(String::from);
        out.zeroize();
        result
    }

    /// Decodes a unified full viewing key of Revision 2 (`uvf...`),
    /// returning its network too. Items of unknown typecode are skipped,
    /// except metadata that must be understood
    /// ([`Error::MustUnderstand`]).
    pub fn decode(s: &str) -> Result<(Network, Self), Error> {
        decode_with(s, |hrp, items| {
            let network = network_of(&UFVK_HRPS, hrp).ok_or(Error::InvalidPrefix)?;
            let mut key = UnifiedFullViewingKey::default();
            let mut metadata = Metadata::default();
            for item in items {
                match item.typecode {
                    TYPECODE_P2PKH => key.transparent = fixed(item.data)?,
                    TYPECODE_P2SH => key.p2sh = Some(P2shViewingKey::from_bytes(item.data, true)?),
                    TYPECODE_SAPLING => key.sapling = fixed(item.data)?,
                    TYPECODE_ORCHARD => key.orchard = fixed(item.data)?,
                    _ => metadata.take(&item)?,
                }
            }
            metadata.check_birthday()?;
            key.birthday_height = metadata.birthday_height;
            key.expiry = metadata.expiry;
            key.check()?;
            let known = key.transparent.is_some()
                || key.p2sh.is_some()
                || key.sapling.is_some()
                || key.orchard.is_some();
            if !known && !metadata.unknown {
                return Err(Error::OnlyMetadata);
            }
            Ok((network, key))
        })
    }
}

/// A unified incoming viewing key of Revision 2: at most one incoming
/// viewing key per pool (none of which need be shielded), and metadata.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnifiedIncomingViewingKey {
    /// The transparent P2PKH item: the chain code and compressed public
    /// key of the account's external chain
    /// (`m / 44' / coin_type' / account' / 0`).
    pub transparent: Option<[u8; 65]>,
    /// The P2SH item: a wallet policy over the keys of the external chain.
    /// A key cannot have both transparent items.
    pub p2sh: Option<P2shViewingKey>,
    /// The Sapling item: `dk || ivk` (not interpreted here).
    pub sapling: Option<[u8; 64]>,
    /// The Orchard item: `dk || ivk`, see
    /// [`orchard_ivk`](Self::orchard_ivk).
    pub orchard: Option<[u8; 64]>,
    /// The height of the first block worth scanning for the funds of the
    /// key (not above its expiry height, if it has one).
    pub birthday_height: Option<u32>,
    /// When the addresses of the key expire, at the latest.
    pub expiry: Expiry,
}

impl UnifiedIncomingViewingKey {
    /// The longest string a key made of these items encodes to.
    pub const MAX_ENCODED_LEN: usize = 7 + 1 + (Self::MAX_RAW_LEN * 8).div_ceil(5) + 6;
    const MAX_RAW_LEN: usize =
        67 + (4 + P2SH_VIEWING_KEY_MAX_LEN) + 66 + 66 + METADATA_RAW_LEN + PADDING_LEN;

    /// The key with only an Orchard item, without metadata.
    pub fn from_orchard(ivk: &IncomingViewingKey) -> Self {
        UnifiedIncomingViewingKey {
            orchard: Some(ivk.to_bytes()),
            ..Default::default()
        }
    }

    /// The Orchard item as an incoming viewing key, if there is one and it
    /// is valid.
    pub fn orchard_ivk(&self) -> Result<Option<IncomingViewingKey>, Error> {
        self.orchard
            .as_ref()
            .map(IncomingViewingKey::from_bytes)
            .transpose()
    }

    fn check(&self) -> Result<(), Error> {
        if self.transparent.is_some() && self.p2sh.is_some() {
            return Err(Error::BothP2pkhAndP2sh);
        }
        match (self.birthday_height, self.expiry.height) {
            (Some(birthday), Some(expiry)) if birthday > expiry => Err(Error::InvalidItem),
            _ => Ok(()),
        }
    }

    /// Encodes the key into `out` ([`MAX_ENCODED_LEN`](Self::MAX_ENCODED_LEN)
    /// bytes always suffice), returning the string.
    pub fn encode_to_slice<'o>(
        &self,
        network: Network,
        out: &'o mut [u8],
    ) -> Result<&'o str, Error> {
        self.check()?;
        encode_some(
            hrp_for(&UIVK_HRPS, network)?,
            [
                item(TYPECODE_P2PKH, &self.transparent),
                item(TYPECODE_P2SH, &self.p2sh),
                item(TYPECODE_SAPLING, &self.sapling),
                item(TYPECODE_ORCHARD, &self.orchard),
                item(
                    TYPECODE_BIRTHDAY_HEIGHT,
                    &self.birthday_height.map(u32::to_le_bytes),
                ),
                item(TYPECODE_EXPIRY_HEIGHT, &self.expiry.height_bytes()),
                item(TYPECODE_EXPIRY_TIME, &self.expiry.time_bytes()),
            ],
            out,
        )
    }

    /// Encodes the key as a `String`.
    #[cfg(feature = "alloc")]
    pub fn encode(&self, network: Network) -> Result<String, Error> {
        let mut out = vec![0u8; Self::MAX_ENCODED_LEN];
        let result = self.encode_to_slice(network, &mut out).map(String::from);
        out.zeroize();
        result
    }

    /// Decodes a unified incoming viewing key of Revision 2 (`uvi...`),
    /// returning its network too. Items of unknown typecode are skipped,
    /// except metadata that must be understood
    /// ([`Error::MustUnderstand`]).
    pub fn decode(s: &str) -> Result<(Network, Self), Error> {
        decode_with(s, |hrp, items| {
            let network = network_of(&UIVK_HRPS, hrp).ok_or(Error::InvalidPrefix)?;
            let mut key = UnifiedIncomingViewingKey::default();
            let mut metadata = Metadata::default();
            for item in items {
                match item.typecode {
                    TYPECODE_P2PKH => key.transparent = fixed(item.data)?,
                    TYPECODE_P2SH => key.p2sh = Some(P2shViewingKey::from_bytes(item.data, false)?),
                    TYPECODE_SAPLING => key.sapling = fixed(item.data)?,
                    TYPECODE_ORCHARD => key.orchard = fixed(item.data)?,
                    _ => metadata.take(&item)?,
                }
            }
            metadata.check_birthday()?;
            key.birthday_height = metadata.birthday_height;
            key.expiry = metadata.expiry;
            key.check()?;
            let known = key.transparent.is_some()
                || key.p2sh.is_some()
                || key.sapling.is_some()
                || key.orchard.is_some();
            if !known && !metadata.unknown {
                return Err(Error::OnlyMetadata);
            }
            Ok((network, key))
        })
    }
}
