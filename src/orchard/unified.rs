//! ZIP-316 unified addresses and unified viewing keys (Revision 0).
//!
//! A unified encoding is a list of typed items (receivers of an address, or
//! viewing keys of an account, one per pool), followed by 16 bytes of
//! padding derived from the human-readable part, scrambled with
//! [F4Jumble](f4jumble) and encoded as bech32m without a length limit.
//!
//! Two layers are provided, neither of which allocates:
//!
//! - [`encode_to_slice`] and [`decode_to_slice`] handle any list of
//!   [`Item`]s, unknown typecodes included, and enforce the rules common to
//!   every unified encoding (padding, ascending typecodes, no duplicates).
//! - [`UnifiedAddress`], [`UnifiedFullViewingKey`] and
//!   [`UnifiedIncomingViewingKey`] hold the items this crate understands as
//!   fixed-size arrays and enforce the rules of their kind (item lengths,
//!   at least one shielded item, not both P2PKH and P2SH). Items of unknown
//!   typecode are skipped when decoding, as ZIP-316 asks of consumers.

use purecrypto::hash::Blake2bMac;
use purecrypto::zeroize::Zeroize;

use super::Error;
use super::keys::{Address, FullViewingKey, IncomingViewingKey};
use super::spec::{compact_size, read_compact_size, take};
use crate::bech32::{self, Variant};

#[cfg(feature = "alloc")]
use crate::prelude::*;

/// The shortest message F4Jumble takes.
pub const F4JUMBLE_MIN_LEN: usize = 48;
/// The longest message F4Jumble takes.
pub const F4JUMBLE_MAX_LEN: usize = 4_194_368;

/// The typecode of a transparent P2PKH receiver (or, in a viewing key, of a
/// transparent account key).
pub const TYPECODE_P2PKH: u32 = 0x00;
/// The typecode of a transparent P2SH receiver.
pub const TYPECODE_P2SH: u32 = 0x01;
/// The typecode of a Sapling item.
pub const TYPECODE_SAPLING: u32 = 0x02;
/// The typecode of an Orchard item.
pub const TYPECODE_ORCHARD: u32 = 0x03;
/// The largest typecode.
pub const TYPECODE_MAX: u32 = 0x0200_0000;

const PADDING_LEN: usize = 16;

/// One BLAKE2b call of F4Jumble's `G` or `H`, XORed into `out` (at most 64
/// bytes).
fn xor_hash(tag: &[u8; 13], i: u8, j: u16, input: &[u8], hash_len: usize, out: &mut [u8]) {
    let mut personal = [0u8; 16];
    personal[..13].copy_from_slice(tag);
    personal[13] = i;
    personal[14..].copy_from_slice(&j.to_le_bytes());
    let mut h = Blake2bMac::try_new_with_salt_personal(&[], hash_len, &[], &personal)
        .expect("valid BLAKE2b parameters");
    h.update(input);
    let mut digest = [0u8; 64];
    h.finalize_into(&mut digest[..hash_len]);
    for (o, d) in out.iter_mut().zip(&digest) {
        *o ^= d;
    }
    digest.zeroize();
}

/// `right ^= G_i(left)`.
fn xor_g(i: u8, left: &[u8], right: &mut [u8]) {
    for (j, chunk) in right.chunks_mut(64).enumerate() {
        xor_hash(b"UA_F4Jumble_G", i, j as u16, left, 64, chunk);
    }
}

/// `left ^= H_i(right)`.
fn xor_h(i: u8, right: &[u8], left: &mut [u8]) {
    xor_hash(b"UA_F4Jumble_H", i, 0, right, left.len(), left);
}

fn f4jumble_split(msg: &mut [u8]) -> Result<(&mut [u8], &mut [u8]), Error> {
    if !(F4JUMBLE_MIN_LEN..=F4JUMBLE_MAX_LEN).contains(&msg.len()) {
        return Err(Error::InvalidLength);
    }
    let left_len = (msg.len() / 2).min(64);
    Ok(msg.split_at_mut(left_len))
}

/// Applies F4Jumble to `msg` in place: an unkeyed 4-round Feistel
/// permutation that makes every bit of the output depend on every bit of
/// the input, so that a truncated or partly matching address looks nothing
/// like the original. The message must be 48 to 4194368 bytes long.
pub fn f4jumble(msg: &mut [u8]) -> Result<(), Error> {
    let (a, b) = f4jumble_split(msg)?;
    xor_g(0, a, b);
    xor_h(0, b, a);
    xor_g(1, a, b);
    xor_h(1, b, a);
    Ok(())
}

/// Applies the inverse of [`f4jumble`] to `msg` in place.
pub fn f4jumble_inv(msg: &mut [u8]) -> Result<(), Error> {
    let (a, b) = f4jumble_split(msg)?;
    xor_h(1, b, a);
    xor_g(1, a, b);
    xor_h(0, b, a);
    xor_g(0, a, b);
    Ok(())
}

/// An item of a unified encoding: a typecode and its raw data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item<'a> {
    /// The typecode.
    pub typecode: u32,
    /// The raw encoding of the receiver or key.
    pub data: &'a [u8],
}

/// The items of a decoded unified encoding, in ascending typecode order.
#[derive(Clone, Debug)]
pub struct Items<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for Items<'a> {
    type Item = Item<'a>;

    fn next(&mut self) -> Option<Item<'a>> {
        if self.data.is_empty() {
            return None;
        }
        // the data was validated when it was decoded
        let item = read_item(&mut self.data).ok();
        if item.is_none() {
            self.data = &[];
        }
        item
    }
}

fn read_item<'a>(data: &mut &'a [u8]) -> Result<Item<'a>, Error> {
    let typecode = read_compact_size(data)?;
    if typecode > TYPECODE_MAX as u64 {
        return Err(Error::InvalidTypecode);
    }
    let len = usize::try_from(read_compact_size(data)?).map_err(|_| Error::TooLarge)?;
    Ok(Item {
        typecode: typecode as u32,
        data: take(data, len)?,
    })
}

/// Checks the rules common to all unified encodings.
fn check_order(items: impl Iterator<Item = u32>) -> Result<(), Error> {
    let mut prev: Option<u32> = None;
    for typecode in items {
        if typecode > TYPECODE_MAX {
            return Err(Error::InvalidTypecode);
        }
        match prev {
            Some(p) if typecode == p => return Err(Error::DuplicateTypecode),
            Some(p) if typecode < p => return Err(Error::InvalidTypecodeOrder),
            _ => {}
        }
        prev = Some(typecode);
    }
    Ok(())
}

fn padding(hrp: &str) -> Result<[u8; PADDING_LEN], Error> {
    let mut padding = [0u8; PADDING_LEN];
    let dst = padding.get_mut(..hrp.len()).ok_or(Error::InvalidPrefix)?;
    dst.copy_from_slice(hrp.as_bytes());
    dst.make_ascii_lowercase();
    Ok(padding)
}

/// The length of the raw (unjumbled) encoding of `items`, padding included.
pub fn raw_len(items: &[Item<'_>]) -> usize {
    items
        .iter()
        .map(|item| {
            compact_size(item.typecode as u64).1
                + compact_size(item.data.len() as u64).1
                + item.data.len()
        })
        .sum::<usize>()
        + PADDING_LEN
}

/// The length of the string [`encode_to_slice`] produces for a raw encoding
/// of `raw_len` bytes under the human-readable part `hrp`.
pub fn encoded_len(hrp: &str, raw_len: usize) -> usize {
    hrp.len() + 1 + (raw_len * 8).div_ceil(5) + 6
}

/// Encodes `items` under the human-readable part `hrp` (lower case, at most
/// 16 bytes) into `out`, returning the string. `scratch` must hold
/// [`raw_len`] bytes and `out` [`encoded_len`].
///
/// The items must be in ascending typecode order without duplicates, as
/// every unified encoding requires; rules specific to addresses or viewing
/// keys are the caller's (see the typed containers).
pub fn encode_to_slice<'o>(
    hrp: &str,
    items: &[Item<'_>],
    scratch: &mut [u8],
    out: &'o mut [u8],
) -> Result<&'o str, Error> {
    check_order(items.iter().map(|item| item.typecode))?;
    if hrp.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(Error::InvalidPrefix);
    }
    let padding = padding(hrp)?;
    let len = raw_len(items);
    let raw = scratch.get_mut(..len).ok_or(Error::BufferTooSmall)?;
    let mut pos = 0;
    let mut put = |bytes: &[u8]| {
        raw[pos..pos + bytes.len()].copy_from_slice(bytes);
        pos += bytes.len();
    };
    for item in items {
        let (typecode, n) = compact_size(item.typecode as u64);
        put(&typecode[..n]);
        let (data_len, n) = compact_size(item.data.len() as u64);
        put(&data_len[..n]);
        put(item.data);
    }
    put(&padding);
    f4jumble(raw)?;
    let written =
        bech32::encode_to_slice(hrp, raw, Variant::Bech32m, out).map_err(|e| match e {
            bech32::Error::BufferTooSmall => Error::BufferTooSmall,
            e => Error::Bech32(e),
        })?;
    Ok(core::str::from_utf8(&out[..written]).expect("bech32 is ASCII"))
}

/// Decodes a unified encoding, using `buf` for its raw form (which is at
/// most five eighths of the length of the string). Returns the
/// human-readable part as written and the items.
///
/// This checks what every unified encoding must satisfy: bech32m, the
/// F4Jumble length range, the padding, well-formed items in ascending
/// typecode order without duplicates. It does not know which
/// human-readable parts or item lengths are meaningful.
pub fn decode_to_slice<'s, 'b>(
    s: &'s str,
    buf: &'b mut [u8],
) -> Result<(&'s str, Items<'b>), Error> {
    let (hrp, len, variant) = bech32::decode_to_slice(s, buf).map_err(|e| match e {
        bech32::Error::BufferTooSmall => Error::BufferTooSmall,
        e => Error::Bech32(e),
    })?;
    if variant != Variant::Bech32m {
        return Err(Error::Bech32(bech32::Error::WrongVariant));
    }
    let raw = &mut buf[..len];
    f4jumble_inv(raw)?;
    let (data, tail) = raw.split_at(len - PADDING_LEN);
    if tail != padding(hrp)? {
        return Err(Error::InvalidPadding);
    }
    let mut rest = data;
    let mut prev: Option<u32> = None;
    while !rest.is_empty() {
        let item = read_item(&mut rest)?;
        check_order(prev.into_iter().chain([item.typecode]))?;
        prev = Some(item.typecode);
    }
    Ok((hrp, Items { data }))
}

/// Encodes `items` under `hrp` as a `String`, see [`encode_to_slice`].
#[cfg(feature = "alloc")]
pub fn encode(hrp: &str, items: &[Item<'_>]) -> Result<String, Error> {
    let len = raw_len(items);
    let mut scratch = vec![0u8; len];
    let mut out = vec![0u8; encoded_len(hrp, len)];
    let written = encode_to_slice(hrp, items, &mut scratch, &mut out)?.len();
    out.truncate(written);
    Ok(String::from_utf8(out).expect("bech32 is ASCII"))
}

/// Decodes a unified encoding into its human-readable part and owned
/// `(typecode, data)` items, see [`decode_to_slice`].
#[cfg(feature = "alloc")]
#[allow(clippy::type_complexity)]
pub fn decode(s: &str) -> Result<(&str, Vec<(u32, Vec<u8>)>), Error> {
    let mut buf = vec![0u8; s.len()];
    let (hrp, items) = decode_to_slice(s, &mut buf)?;
    Ok((
        hrp,
        items
            .map(|item| (item.typecode, item.data.to_vec()))
            .collect(),
    ))
}

/// The Zcash network a unified encoding is for, which its human-readable
/// part tells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// The main network.
    Main,
    /// The test network.
    Test,
    /// A regression test network.
    Regtest,
}

/// The size of the stack buffer the typed decoders use without `alloc`.
const STACK_BUF: usize = 512;

/// Decodes `s`, expecting one of the three human-readable parts (main,
/// test, regtest), and hands the items to `f`.
fn decode_with<R>(
    s: &str,
    hrps: &[&str; 3],
    f: impl FnOnce(Network, Items<'_>) -> Result<R, Error>,
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
        Ok((hrp, items)) => {
            let network = if hrp.eq_ignore_ascii_case(hrps[0]) {
                Ok(Network::Main)
            } else if hrp.eq_ignore_ascii_case(hrps[1]) {
                Ok(Network::Test)
            } else if hrp.eq_ignore_ascii_case(hrps[2]) {
                Ok(Network::Regtest)
            } else {
                Err(Error::InvalidPrefix)
            };
            network.and_then(|network| f(network, items))
        }
        Err(Error::BufferTooSmall) => Err(Error::TooLarge),
        Err(e) => Err(e),
    };
    // viewing keys pass through the buffer
    buf.zeroize();
    result
}

fn hrp_for<'a>(hrps: &[&'a str; 3], network: Network) -> &'a str {
    match network {
        Network::Main => hrps[0],
        Network::Test => hrps[1],
        Network::Regtest => hrps[2],
    }
}

fn fixed<const N: usize>(data: &[u8]) -> Result<Option<[u8; N]>, Error> {
    data.try_into().map(Some).map_err(|_| Error::InvalidItem)
}

/// Encodes up to four optional items, already in typecode order.
fn encode_some<'o, const SCRATCH: usize>(
    hrp: &str,
    items: [Option<Item<'_>>; 4],
    out: &'o mut [u8],
) -> Result<&'o str, Error> {
    let mut list = [Item {
        typecode: 0,
        data: &[],
    }; 4];
    let mut n = 0;
    for item in items.into_iter().flatten() {
        list[n] = item;
        n += 1;
    }
    let mut scratch = [0u8; SCRATCH];
    let result = encode_to_slice(hrp, &list[..n], &mut scratch, out);
    scratch.zeroize();
    result
}

fn item(typecode: u32, data: &Option<impl AsRef<[u8]>>) -> Option<Item<'_>> {
    data.as_ref().map(|d| Item {
        typecode,
        data: d.as_ref(),
    })
}

const ADDRESS_HRPS: [&str; 3] = ["u", "utest", "uregtest"];
const UFVK_HRPS: [&str; 3] = ["uview", "uviewtest", "uviewregtest"];
const UIVK_HRPS: [&str; 3] = ["uivk", "uivktest", "uivkregtest"];

/// A unified address: at most one receiver per pool, at least one of them
/// shielded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnifiedAddress {
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
}

impl UnifiedAddress {
    /// The longest string an address made of these receivers encodes to.
    pub const MAX_ENCODED_LEN: usize = 8 + 1 + (Self::MAX_RAW_LEN * 8).div_ceil(5) + 6;
    const MAX_RAW_LEN: usize = 22 + 45 + 45 + PADDING_LEN;

    /// The address with only an Orchard receiver.
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
        if self.sapling.is_none() && self.orchard.is_none() {
            return Err(Error::OnlyTransparent);
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
        encode_some::<{ Self::MAX_RAW_LEN }>(
            hrp_for(&ADDRESS_HRPS, network),
            [
                item(TYPECODE_P2PKH, &self.p2pkh),
                item(TYPECODE_P2SH, &self.p2sh),
                item(TYPECODE_SAPLING, &self.sapling),
                item(TYPECODE_ORCHARD, &self.orchard),
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

    /// Decodes a unified address, returning its network too. Receivers of
    /// unknown typecode are skipped (they still make the address valid when
    /// its only known receivers are transparent, as nothing says they are
    /// not shielded).
    ///
    /// Without `alloc`, strings longer than 512 characters are rejected
    /// with [`Error::TooLarge`].
    pub fn decode(s: &str) -> Result<(Network, Self), Error> {
        decode_with(s, &ADDRESS_HRPS, |network, items| {
            let mut ua = UnifiedAddress::default();
            let mut unknown = false;
            for item in items {
                match item.typecode {
                    TYPECODE_P2PKH => ua.p2pkh = fixed(item.data)?,
                    TYPECODE_P2SH => ua.p2sh = fixed(item.data)?,
                    TYPECODE_SAPLING => ua.sapling = fixed(item.data)?,
                    TYPECODE_ORCHARD => ua.orchard = fixed(item.data)?,
                    _ => unknown = true,
                }
            }
            if ua.p2pkh.is_some() && ua.p2sh.is_some() {
                return Err(Error::BothP2pkhAndP2sh);
            }
            if ua.sapling.is_none() && ua.orchard.is_none() && !unknown {
                return Err(Error::OnlyTransparent);
            }
            Ok((network, ua))
        })
    }
}

/// A unified full viewing key: at most one full viewing key per pool, at
/// least one of them shielded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnifiedFullViewingKey {
    /// The transparent item: the chain code and compressed public key of
    /// the account's BIP-44 node (`m / 44' / coin_type' / account'`).
    pub transparent: Option<[u8; 65]>,
    /// The Sapling item: `ak || nk || ovk || dk` (not interpreted here).
    pub sapling: Option<[u8; 128]>,
    /// The Orchard item: `ak || nk || rivk`, see
    /// [`orchard_fvk`](Self::orchard_fvk).
    pub orchard: Option<[u8; 96]>,
}

impl UnifiedFullViewingKey {
    /// The longest string a key made of these items encodes to.
    pub const MAX_ENCODED_LEN: usize = 12 + 1 + (Self::MAX_RAW_LEN * 8).div_ceil(5) + 6;
    const MAX_RAW_LEN: usize = 67 + 130 + 98 + PADDING_LEN;

    /// The key with only an Orchard item.
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

    /// Encodes the key into `out` ([`MAX_ENCODED_LEN`](Self::MAX_ENCODED_LEN)
    /// bytes always suffice), returning the string.
    pub fn encode_to_slice<'o>(
        &self,
        network: Network,
        out: &'o mut [u8],
    ) -> Result<&'o str, Error> {
        if self.sapling.is_none() && self.orchard.is_none() {
            return Err(Error::OnlyTransparent);
        }
        encode_some::<{ Self::MAX_RAW_LEN }>(
            hrp_for(&UFVK_HRPS, network),
            [
                item(TYPECODE_P2PKH, &self.transparent),
                item(TYPECODE_SAPLING, &self.sapling),
                item(TYPECODE_ORCHARD, &self.orchard),
                None,
            ],
            out,
        )
    }

    /// Encodes the key as a `String`.
    #[cfg(feature = "alloc")]
    pub fn encode(&self, network: Network) -> Result<String, Error> {
        let mut out = [0u8; Self::MAX_ENCODED_LEN];
        self.encode_to_slice(network, &mut out).map(String::from)
    }

    /// Decodes a unified full viewing key, returning its network too. Items
    /// of unknown typecode (which includes `0x01`, meaningless in a viewing
    /// key) are skipped.
    ///
    /// Without `alloc`, strings longer than 512 characters are rejected
    /// with [`Error::TooLarge`].
    pub fn decode(s: &str) -> Result<(Network, Self), Error> {
        decode_with(s, &UFVK_HRPS, |network, items| {
            let mut key = UnifiedFullViewingKey::default();
            let mut unknown = false;
            for item in items {
                match item.typecode {
                    TYPECODE_P2PKH => key.transparent = fixed(item.data)?,
                    TYPECODE_SAPLING => key.sapling = fixed(item.data)?,
                    TYPECODE_ORCHARD => key.orchard = fixed(item.data)?,
                    _ => unknown = true,
                }
            }
            if key.sapling.is_none() && key.orchard.is_none() && !unknown {
                return Err(Error::OnlyTransparent);
            }
            Ok((network, key))
        })
    }
}

/// A unified incoming viewing key: at most one incoming viewing key per
/// pool, at least one of them shielded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnifiedIncomingViewingKey {
    /// The transparent item: the chain code and compressed public key of
    /// the account's external chain (`m / 44' / coin_type' / account' / 0`).
    pub transparent: Option<[u8; 65]>,
    /// The Sapling item: `dk || ivk` (not interpreted here).
    pub sapling: Option<[u8; 64]>,
    /// The Orchard item: `dk || ivk`, see
    /// [`orchard_ivk`](Self::orchard_ivk).
    pub orchard: Option<[u8; 64]>,
}

impl UnifiedIncomingViewingKey {
    /// The longest string a key made of these items encodes to.
    pub const MAX_ENCODED_LEN: usize = 11 + 1 + (Self::MAX_RAW_LEN * 8).div_ceil(5) + 6;
    const MAX_RAW_LEN: usize = 67 + 66 + 66 + PADDING_LEN;

    /// The key with only an Orchard item.
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

    /// Encodes the key into `out` ([`MAX_ENCODED_LEN`](Self::MAX_ENCODED_LEN)
    /// bytes always suffice), returning the string.
    pub fn encode_to_slice<'o>(
        &self,
        network: Network,
        out: &'o mut [u8],
    ) -> Result<&'o str, Error> {
        if self.sapling.is_none() && self.orchard.is_none() {
            return Err(Error::OnlyTransparent);
        }
        encode_some::<{ Self::MAX_RAW_LEN }>(
            hrp_for(&UIVK_HRPS, network),
            [
                item(TYPECODE_P2PKH, &self.transparent),
                item(TYPECODE_SAPLING, &self.sapling),
                item(TYPECODE_ORCHARD, &self.orchard),
                None,
            ],
            out,
        )
    }

    /// Encodes the key as a `String`.
    #[cfg(feature = "alloc")]
    pub fn encode(&self, network: Network) -> Result<String, Error> {
        let mut out = [0u8; Self::MAX_ENCODED_LEN];
        self.encode_to_slice(network, &mut out).map(String::from)
    }

    /// Decodes a unified incoming viewing key, returning its network too.
    /// Items of unknown typecode (which includes `0x01`, meaningless in a
    /// viewing key) are skipped.
    ///
    /// Without `alloc`, strings longer than 512 characters are rejected
    /// with [`Error::TooLarge`].
    pub fn decode(s: &str) -> Result<(Network, Self), Error> {
        decode_with(s, &UIVK_HRPS, |network, items| {
            let mut key = UnifiedIncomingViewingKey::default();
            let mut unknown = false;
            for item in items {
                match item.typecode {
                    TYPECODE_P2PKH => key.transparent = fixed(item.data)?,
                    TYPECODE_SAPLING => key.sapling = fixed(item.data)?,
                    TYPECODE_ORCHARD => key.orchard = fixed(item.data)?,
                    _ => unknown = true,
                }
            }
            if key.sapling.is_none() && key.orchard.is_none() && !unknown {
                return Err(Error::OnlyTransparent);
            }
            Ok((network, key))
        })
    }
}
