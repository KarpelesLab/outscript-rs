//! ZIP-32 hierarchical deterministic Sapling keys: extended spending and
//! full viewing keys, child derivation, diversifier keys and internal
//! (change) keys.
//!
//! The usual account key is `m / 32' / coin_type' / account'`
//! ([`ExtendedSpendingKey::derive_path`] with [`harden`]ed indices; the coin
//! type is 133 on the main network and 1 on the others). Wallets derive
//! hardened children only; non-hardened derivation, which also works from an
//! extended full viewing key, is kept for compatibility with older keys.

use super::Error;
use super::field::Fr;
use super::generators::{PROOF_GENERATION_KEY_BASE, SPENDING_KEY_BASE};
use super::keys::{
    Diversifier, ExpandedSpendingKey, FullViewingKey, IncomingViewingKey, Network,
    OutgoingViewingKey, PaymentAddress, bech32_decode, bech32_encode, expand_to_32,
    expand_to_scalar,
};
use super::prf::{blake2b, prf_expand};
use purecrypto::cipher::{Aes256, BlockCipher};
use purecrypto::ct::ConstantTimeEq;
use purecrypto::zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The offset that marks a derivation index as hardened.
pub const HARDENED: u32 = 1 << 31;

/// The ZIP-32 purpose of Sapling keys (`32'`, to be [`harden`]ed).
pub const PURPOSE: u32 = 32;

/// The SLIP-44 coin type of Zcash's main network.
pub const COIN_TYPE_MAIN: u32 = 133;

/// The coin type of the test networks.
pub const COIN_TYPE_TEST: u32 = 1;

/// The hardened form of a derivation index (`index | 2^31`).
pub const fn harden(index: u32) -> u32 {
    index | HARDENED
}

/// The length of an encoded extended key.
pub const EXTENDED_KEY_LEN: usize = 169;

/// The longest Bech32 encoding of an extended key (a regtest spending key).
pub const EXTENDED_KEY_MAX_ENCODED_LEN: usize = 305;

/// An 88-bit diversifier index `j`, in little-endian order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct DiversifierIndex(pub [u8; 11]);

impl DiversifierIndex {
    /// The index zero.
    pub const ZERO: DiversifierIndex = DiversifierIndex([0; 11]);

    /// The largest index, `2^88 - 1`.
    pub const MAX: DiversifierIndex = DiversifierIndex([0xff; 11]);

    /// The index as an integer.
    pub fn to_u128(&self) -> u128 {
        let mut bytes = [0u8; 16];
        bytes[..11].copy_from_slice(&self.0);
        u128::from_le_bytes(bytes)
    }

    /// The index for an integer below `2^88`.
    pub fn from_u128(j: u128) -> Option<Self> {
        let bytes = j.to_le_bytes();
        let (index, rest) = bytes.split_at(11);
        if rest.iter().any(|b| *b != 0) {
            return None;
        }
        let mut out = [0u8; 11];
        out.copy_from_slice(index);
        Some(DiversifierIndex(out))
    }

    /// The next index, or `None` after the last.
    pub fn next(&self) -> Option<Self> {
        Self::from_u128(self.to_u128() + 1)
    }
}

impl From<u64> for DiversifierIndex {
    fn from(j: u64) -> Self {
        let mut out = [0u8; 11];
        out[..8].copy_from_slice(&j.to_le_bytes());
        DiversifierIndex(out)
    }
}

/// A diversifier key `dk`: it maps diversifier indices to diversifiers with
/// FF1-AES-256, so that the addresses of a key are unlinkable without it.
#[derive(Clone, PartialEq, Eq)]
pub struct DiversifierKey([u8; 32]);

impl Zeroize for DiversifierKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for DiversifierKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DiversifierKey {}

impl core::fmt::Debug for DiversifierKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DiversifierKey(..)")
    }
}

/// The 44-bit halves of an FF1 input, each as a big-endian numeral.
fn ff1_split(bytes: &[u8; 11]) -> (u64, u64) {
    // bit k of the input string is bit k of the little-endian integer, and
    // the first bit of a half is its most significant numeral
    let bit = |k: usize| u64::from((bytes[k / 8] >> (k % 8)) & 1);
    let half = |start: usize| (start..start + 44).fold(0u64, |acc, k| acc << 1 | bit(k));
    (half(0), half(44))
}

fn ff1_join(a: u64, b: u64) -> [u8; 11] {
    let mut out = [0u8; 11];
    for k in 0..88 {
        let (half, i) = if k < 44 { (a, k) } else { (b, k - 44) };
        out[k / 8] |= (((half >> (43 - i)) & 1) as u8) << (k % 8);
    }
    out
}

const FF1_MASK: u64 = (1 << 44) - 1;

/// The FF1 round function for radix 2, 88-bit inputs and an empty tweak:
/// the low 44 bits of `PRF(P ‖ Q)`, a two-block AES-CBC-MAC.
fn ff1_round(cipher: &Aes256, round: u8, half: u64) -> u64 {
    // P = [1, 2, 1] ‖ radix ‖ 10 ‖ u mod 256 ‖ n ‖ t
    let mut block = [1, 2, 1, 0, 0, 2, 10, 44, 0, 0, 0, 88, 0, 0, 0, 0];
    cipher.encrypt_block(&mut block);
    // Q = 0^9 ‖ round ‖ NUM(half) as 6 bytes
    block[9] ^= round;
    for (dst, src) in block[10..].iter_mut().zip(&half.to_be_bytes()[2..]) {
        *dst ^= src;
    }
    cipher.encrypt_block(&mut block);
    // y is the first 12 bytes as a big-endian integer; only its low 44 bits
    // survive the reduction modulo 2^44
    let mut y = [0u8; 8];
    y[2..].copy_from_slice(&block[6..12]);
    block.zeroize();
    u64::from_be_bytes(y) & FF1_MASK
}

fn ff1_encrypt(key: &[u8; 32], input: &[u8; 11]) -> [u8; 11] {
    let cipher = Aes256::new(key);
    let (mut a, mut b) = ff1_split(input);
    for round in 0..10 {
        let c = a.wrapping_add(ff1_round(&cipher, round, b)) & FF1_MASK;
        a = b;
        b = c;
    }
    ff1_join(a, b)
}

fn ff1_decrypt(key: &[u8; 32], input: &[u8; 11]) -> [u8; 11] {
    let cipher = Aes256::new(key);
    let (mut a, mut b) = ff1_split(input);
    for round in (0..10).rev() {
        let c = b.wrapping_sub(ff1_round(&cipher, round, a)) & FF1_MASK;
        b = a;
        a = c;
    }
    ff1_join(a, b)
}

impl DiversifierKey {
    /// The diversifier key of a master key: the first half of
    /// `PRF^expand(sk_m, [0x10])`.
    pub fn master(sk_m: &[u8]) -> Self {
        DiversifierKey(expand_to_32(sk_m, &[&[0x10]]))
    }

    /// Wraps the 32 key bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        DiversifierKey(bytes)
    }

    /// The key bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn derive_child(&self, i_l: &[u8]) -> Self {
        DiversifierKey(expand_to_32(i_l, &[&[0x16], &self.0]))
    }

    /// The diversifier at index `j`, `FF1-AES256.Encrypt(dk, "", j)`, or
    /// `None` if it is not a valid diversifier (about half are not).
    pub fn diversifier(&self, j: DiversifierIndex) -> Option<Diversifier> {
        let d = Diversifier(ff1_encrypt(&self.0, &j.0));
        d.g_d().map(|_| d)
    }

    /// The index a diversifier was derived from.
    pub fn diversifier_index(&self, d: &Diversifier) -> DiversifierIndex {
        DiversifierIndex(ff1_decrypt(&self.0, &d.0))
    }

    /// The first valid diversifier at index `j` or above, with its index.
    /// `None` only if the index space is exhausted.
    pub fn find_diversifier(
        &self,
        mut j: DiversifierIndex,
    ) -> Option<(DiversifierIndex, Diversifier)> {
        loop {
            if let Some(d) = self.diversifier(j) {
                return Some((j, d));
            }
            j = j.next()?;
        }
    }
}

/// The position of an extended key in its tree, and its chain code.
#[derive(Clone, PartialEq, Eq)]
struct KeyMeta {
    depth: u8,
    parent_fvk_tag: [u8; 4],
    child_index: u32,
    chain_code: [u8; 32],
}

impl KeyMeta {
    fn write(&self, out: &mut [u8]) {
        out[0] = self.depth;
        out[1..5].copy_from_slice(&self.parent_fvk_tag);
        out[5..9].copy_from_slice(&self.child_index.to_le_bytes());
        out[9..41].copy_from_slice(&self.chain_code);
    }

    fn read(bytes: &[u8; EXTENDED_KEY_LEN]) -> (Self, &[u8; 96], &[u8; 32]) {
        let (head, rest) = bytes.split_at(41);
        let mut parent_fvk_tag = [0u8; 4];
        parent_fvk_tag.copy_from_slice(&head[1..5]);
        let mut index = [0u8; 4];
        index.copy_from_slice(&head[5..9]);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&head[9..]);
        let (key, dk) = rest.split_at(96);
        (
            KeyMeta {
                depth: head[0],
                parent_fvk_tag,
                child_index: u32::from_le_bytes(index),
                chain_code,
            },
            key.try_into().expect("96 bytes"),
            dk.try_into().expect("32 bytes"),
        )
    }

    fn child(&self, parent_tag: [u8; 4], index: u32, chain_code: &[u8]) -> Result<Self, Error> {
        let mut c = [0u8; 32];
        c.copy_from_slice(chain_code);
        Ok(KeyMeta {
            depth: self.depth.checked_add(1).ok_or(Error::MaxDepthExceeded)?,
            parent_fvk_tag: parent_tag,
            child_index: index,
            chain_code: c,
        })
    }
}

/// The fingerprint of a full viewing key: BLAKE2b-256 personalized
/// `ZcashSaplingFVFP` of its encoding. Its first four bytes tag the children
/// of the key.
pub fn fvk_fingerprint(fvk: &FullViewingKey) -> [u8; 32] {
    blake2b(b"ZcashSaplingFVFP", &[&fvk.to_bytes()])
}

fn fvk_tag(fvk: &FullViewingKey) -> [u8; 4] {
    let fp = fvk_fingerprint(fvk);
    [fp[0], fp[1], fp[2], fp[3]]
}

/// The pieces of the internal key derivation shared by spending and viewing
/// keys: `I_nsk`, and the internal `dk` and `ovk`.
fn internal_parts(
    fvk: &FullViewingKey,
    dk: &DiversifierKey,
) -> (Fr, DiversifierKey, OutgoingViewingKey) {
    let i = Zeroizing::new(blake2b::<32>(
        b"Zcash_SaplingInt",
        &[&fvk.to_bytes(), &dk.0],
    ));
    let i_nsk = expand_to_scalar(&i[..], &[&[0x17]]);
    let r = Zeroizing::new(prf_expand(&i[..], &[&[0x18]]));
    let mut dk_internal = [0u8; 32];
    dk_internal.copy_from_slice(&r[..32]);
    let mut ovk_internal = [0u8; 32];
    ovk_internal.copy_from_slice(&r[32..]);
    (
        i_nsk,
        DiversifierKey(dk_internal),
        OutgoingViewingKey(ovk_internal),
    )
}

/// A ZIP-32 extended spending key.
#[derive(Clone)]
pub struct ExtendedSpendingKey {
    meta: KeyMeta,
    expsk: ExpandedSpendingKey,
    dk: DiversifierKey,
}

impl Zeroize for ExtendedSpendingKey {
    fn zeroize(&mut self) {
        self.meta.chain_code.zeroize();
        self.expsk.zeroize();
        self.dk.zeroize();
    }
}

impl Drop for ExtendedSpendingKey {
    fn drop(&mut self) {
        self.meta.chain_code.zeroize();
    }
}

impl ZeroizeOnDrop for ExtendedSpendingKey {}

impl PartialEq for ExtendedSpendingKey {
    /// Compares the secret parts in constant time.
    fn eq(&self, other: &Self) -> bool {
        let secret = self.expsk == other.expsk
            && bool::from(
                self.dk.0.ct_eq(&other.dk.0) & self.meta.chain_code.ct_eq(&other.meta.chain_code),
            );
        secret && self.meta == other.meta
    }
}

impl Eq for ExtendedSpendingKey {}

impl core::fmt::Debug for ExtendedSpendingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ExtendedSpendingKey(depth {}, index {}, ..)",
            self.meta.depth, self.meta.child_index
        )
    }
}

impl ExtendedSpendingKey {
    /// The master key of a seed (at least 32 bytes of entropy; ZIP-32 allows
    /// up to 252).
    pub fn master(seed: &[u8]) -> Result<Self, Error> {
        if !(32..=252).contains(&seed.len()) {
            return Err(Error::InvalidKey);
        }
        let i = Zeroizing::new(blake2b::<64>(b"ZcashIP32Sapling", &[seed]));
        let (sk_m, c_m) = i.split_at(32);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(c_m);
        Ok(ExtendedSpendingKey {
            meta: KeyMeta {
                depth: 0,
                parent_fvk_tag: [0; 4],
                child_index: 0,
                chain_code,
            },
            expsk: ExpandedSpendingKey::from_spending_key(sk_m)?,
            dk: DiversifierKey::master(sk_m),
        })
    }

    /// The child key at `index`, hardened if [`HARDENED`] is set.
    pub fn derive_child(&self, index: u32) -> Result<Self, Error> {
        let fvk = self.expsk.full_viewing_key();
        let i = if index >= HARDENED {
            let expsk = self.expsk.to_bytes();
            Zeroizing::new(prf_expand(
                &self.meta.chain_code,
                &[&[0x11], &expsk[..], &self.dk.0, &index.to_le_bytes()],
            ))
        } else {
            Zeroizing::new(prf_expand(
                &self.meta.chain_code,
                &[&[0x12], &fvk.to_bytes(), &self.dk.0, &index.to_le_bytes()],
            ))
        };
        let (i_l, i_r) = i.split_at(32);
        let ask = expand_to_scalar(i_l, &[&[0x13]]) + *self.expsk.ask();
        let nsk = expand_to_scalar(i_l, &[&[0x14]]) + *self.expsk.nsk();
        let ovk = OutgoingViewingKey(expand_to_32(i_l, &[&[0x15], &self.expsk.ovk().0]));
        Ok(ExtendedSpendingKey {
            meta: self.meta.child(fvk_tag(&fvk), index, i_r)?,
            expsk: ExpandedSpendingKey::from_parts(ask, nsk, ovk)?,
            dk: self.dk.derive_child(i_l),
        })
    }

    /// The descendant at `path`, one [`derive_child`](Self::derive_child)
    /// per index.
    pub fn derive_path(&self, path: &[u32]) -> Result<Self, Error> {
        let mut key = self.clone();
        for &index in path {
            key = key.derive_child(index)?;
        }
        Ok(key)
    }

    /// The account key `m / 32' / coin_type' / account'` of a seed.
    pub fn from_seed_account(seed: &[u8], coin_type: u32, account: u32) -> Result<Self, Error> {
        if coin_type >= HARDENED || account >= HARDENED {
            return Err(Error::InvalidChildIndex);
        }
        Self::master(seed)?.derive_path(&[harden(PURPOSE), harden(coin_type), harden(account)])
    }

    /// The internal key of this key, whose addresses receive change and
    /// other wallet-internal transfers (ZIP-32 "Sapling internal key
    /// derivation").
    pub fn internal(&self) -> Result<Self, Error> {
        let fvk = self.expsk.full_viewing_key();
        let (i_nsk, dk, ovk) = internal_parts(&fvk, &self.dk);
        Ok(ExtendedSpendingKey {
            meta: self.meta.clone(),
            expsk: ExpandedSpendingKey::from_parts(
                *self.expsk.ask(),
                i_nsk + *self.expsk.nsk(),
                ovk,
            )?,
            dk,
        })
    }

    /// Decodes the 169-byte encoding
    /// `depth ‖ parent tag ‖ index ‖ chain code ‖ ask ‖ nsk ‖ ovk ‖ dk`.
    pub fn from_bytes(bytes: &[u8; EXTENDED_KEY_LEN]) -> Result<Self, Error> {
        let (meta, key, dk) = KeyMeta::read(bytes);
        Ok(ExtendedSpendingKey {
            meta,
            expsk: ExpandedSpendingKey::from_bytes(key)?,
            dk: DiversifierKey(*dk),
        })
    }

    /// The 169-byte encoding, wiped when dropped.
    pub fn to_bytes(&self) -> Zeroizing<[u8; EXTENDED_KEY_LEN]> {
        let mut out = Zeroizing::new([0u8; EXTENDED_KEY_LEN]);
        self.meta.write(&mut out[..41]);
        out[41..137].copy_from_slice(&self.expsk.to_bytes()[..]);
        out[137..].copy_from_slice(&self.dk.0);
        out
    }

    /// Writes the Bech32 encoding (`secret-extended-key-main1...`) into
    /// `out` ([`EXTENDED_KEY_MAX_ENCODED_LEN`] bytes always suffice). The
    /// string is secret key material.
    pub fn encode<'a>(&self, network: Network, out: &'a mut [u8]) -> Result<&'a str, Error> {
        bech32_encode(
            network.hrp_extended_spending_key(),
            &self.to_bytes()[..],
            out,
        )
    }

    /// Decodes a Bech32 extended spending key of any network.
    pub fn decode(s: &str) -> Result<(Network, Self), Error> {
        let mut bytes = Zeroizing::new([0u8; EXTENDED_KEY_LEN]);
        let network = bech32_decode(s, Network::hrp_extended_spending_key, &mut *bytes)?;
        Ok((network, Self::from_bytes(&bytes)?))
    }

    /// The depth of this key (0 for a master key).
    pub const fn depth(&self) -> u8 {
        self.meta.depth
    }

    /// The first four bytes of the parent's full viewing key fingerprint.
    pub const fn parent_fvk_tag(&self) -> [u8; 4] {
        self.meta.parent_fvk_tag
    }

    /// The index of this key under its parent.
    pub const fn child_index(&self) -> u32 {
        self.meta.child_index
    }

    /// The chain code.
    pub const fn chain_code(&self) -> &[u8; 32] {
        &self.meta.chain_code
    }

    /// The expanded spending key.
    pub const fn expanded_spending_key(&self) -> &ExpandedSpendingKey {
        &self.expsk
    }

    /// The diversifier key.
    pub const fn diversifier_key(&self) -> &DiversifierKey {
        &self.dk
    }

    /// The matching extended full viewing key.
    pub fn to_extended_full_viewing_key(&self) -> ExtendedFullViewingKey {
        ExtendedFullViewingKey {
            meta: self.meta.clone(),
            fvk: self.expsk.full_viewing_key(),
            dk: self.dk.clone(),
        }
    }

    /// The default address: the one at the first valid diversifier index.
    pub fn default_address(&self) -> Option<(DiversifierIndex, PaymentAddress)> {
        self.to_extended_full_viewing_key().default_address()
    }
}

/// A ZIP-32 extended full viewing key.
#[derive(Clone, PartialEq, Eq)]
pub struct ExtendedFullViewingKey {
    meta: KeyMeta,
    fvk: FullViewingKey,
    dk: DiversifierKey,
}

impl Zeroize for ExtendedFullViewingKey {
    fn zeroize(&mut self) {
        self.meta.chain_code.zeroize();
        self.fvk.zeroize();
        self.dk.zeroize();
    }
}

impl Drop for ExtendedFullViewingKey {
    fn drop(&mut self) {
        self.meta.chain_code.zeroize();
        self.fvk.zeroize();
    }
}

impl ZeroizeOnDrop for ExtendedFullViewingKey {}

impl core::fmt::Debug for ExtendedFullViewingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ExtendedFullViewingKey(depth {}, index {}, ..)",
            self.meta.depth, self.meta.child_index
        )
    }
}

impl ExtendedFullViewingKey {
    /// The non-hardened child key at `index`. Hardened children need the
    /// spending key ([`Error::InvalidChildIndex`]).
    pub fn derive_child(&self, index: u32) -> Result<Self, Error> {
        if index >= HARDENED {
            return Err(Error::InvalidChildIndex);
        }
        let i = Zeroizing::new(prf_expand(
            &self.meta.chain_code,
            &[
                &[0x12],
                &self.fvk.to_bytes(),
                &self.dk.0,
                &index.to_le_bytes(),
            ],
        ));
        let (i_l, i_r) = i.split_at(32);
        let i_ask = expand_to_scalar(i_l, &[&[0x13]]);
        let i_nsk = expand_to_scalar(i_l, &[&[0x14]]);
        let ak = SPENDING_KEY_BASE.to_point().mul(&i_ask) + *self.fvk.ak();
        let nk = PROOF_GENERATION_KEY_BASE.to_point().mul(&i_nsk) + *self.fvk.nk();
        let ovk = OutgoingViewingKey(expand_to_32(i_l, &[&[0x15], &self.fvk.ovk().0]));
        Ok(ExtendedFullViewingKey {
            meta: self.meta.child(fvk_tag(&self.fvk), index, i_r)?,
            fvk: FullViewingKey::from_parts(ak, nk, ovk)?,
            dk: self.dk.derive_child(i_l),
        })
    }

    /// The internal (change) key of this key: see
    /// [`ExtendedSpendingKey::internal`].
    pub fn internal(&self) -> Result<Self, Error> {
        let (i_nsk, dk, ovk) = internal_parts(&self.fvk, &self.dk);
        let nk = PROOF_GENERATION_KEY_BASE.to_point().mul(&i_nsk) + *self.fvk.nk();
        Ok(ExtendedFullViewingKey {
            meta: self.meta.clone(),
            fvk: FullViewingKey::from_parts(*self.fvk.ak(), nk, ovk)?,
            dk,
        })
    }

    /// Decodes the 169-byte encoding
    /// `depth ‖ parent tag ‖ index ‖ chain code ‖ ak ‖ nk ‖ ovk ‖ dk`.
    pub fn from_bytes(bytes: &[u8; EXTENDED_KEY_LEN]) -> Result<Self, Error> {
        let (meta, key, dk) = KeyMeta::read(bytes);
        Ok(ExtendedFullViewingKey {
            meta,
            fvk: FullViewingKey::from_bytes(key)?,
            dk: DiversifierKey(*dk),
        })
    }

    /// The 169-byte encoding.
    pub fn to_bytes(&self) -> [u8; EXTENDED_KEY_LEN] {
        let mut out = [0u8; EXTENDED_KEY_LEN];
        self.meta.write(&mut out[..41]);
        out[41..137].copy_from_slice(&self.fvk.to_bytes());
        out[137..].copy_from_slice(&self.dk.0);
        out
    }

    /// Writes the Bech32 encoding (`zxviews1...`) into `out`
    /// ([`EXTENDED_KEY_MAX_ENCODED_LEN`] bytes always suffice).
    pub fn encode<'a>(&self, network: Network, out: &'a mut [u8]) -> Result<&'a str, Error> {
        bech32_encode(
            network.hrp_extended_full_viewing_key(),
            &self.to_bytes(),
            out,
        )
    }

    /// Decodes a Bech32 extended full viewing key of any network.
    pub fn decode(s: &str) -> Result<(Network, Self), Error> {
        let mut bytes = Zeroizing::new([0u8; EXTENDED_KEY_LEN]);
        let network = bech32_decode(s, Network::hrp_extended_full_viewing_key, &mut *bytes)?;
        Ok((network, Self::from_bytes(&bytes)?))
    }

    /// The depth of this key (0 for a master key).
    pub const fn depth(&self) -> u8 {
        self.meta.depth
    }

    /// The first four bytes of the parent's full viewing key fingerprint.
    pub const fn parent_fvk_tag(&self) -> [u8; 4] {
        self.meta.parent_fvk_tag
    }

    /// The index of this key under its parent.
    pub const fn child_index(&self) -> u32 {
        self.meta.child_index
    }

    /// The chain code.
    pub const fn chain_code(&self) -> &[u8; 32] {
        &self.meta.chain_code
    }

    /// The full viewing key.
    pub const fn full_viewing_key(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// The diversifier key.
    pub const fn diversifier_key(&self) -> &DiversifierKey {
        &self.dk
    }

    /// The fingerprint of the full viewing key: see [`fvk_fingerprint`].
    pub fn fingerprint(&self) -> [u8; 32] {
        fvk_fingerprint(&self.fvk)
    }

    /// The incoming viewing key.
    pub fn ivk(&self) -> IncomingViewingKey {
        self.fvk.ivk()
    }

    /// The address at diversifier index `j`, or `None` if that index gives
    /// no valid diversifier.
    pub fn address(&self, j: DiversifierIndex) -> Option<PaymentAddress> {
        self.fvk.to_payment_address(self.dk.diversifier(j)?)
    }

    /// The address at the first valid diversifier index at or after `j`.
    pub fn find_address(&self, j: DiversifierIndex) -> Option<(DiversifierIndex, PaymentAddress)> {
        let (j, d) = self.dk.find_diversifier(j)?;
        Some((j, self.fvk.to_payment_address(d)?))
    }

    /// The default address: the one at the first valid diversifier index.
    pub fn default_address(&self) -> Option<(DiversifierIndex, PaymentAddress)> {
        self.find_address(DiversifierIndex::ZERO)
    }

    /// The diversifier index of one of this key's addresses, or `None` if
    /// the address does not belong to the key.
    pub fn address_index(&self, address: &PaymentAddress) -> Option<DiversifierIndex> {
        let j = self.dk.diversifier_index(address.diversifier());
        (self.address(j).as_ref() == Some(address)).then_some(j)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sapling::test_vectors::{Row, for_each_row};

    /// The FF1-AES-256 vectors of zcash-test-vectors' `ff1.py` (empty
    /// tweak), as bit strings.
    #[test]
    fn ff1_vectors() {
        let key: [u8; 32] =
            hex::decode("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94")
                .unwrap()
                .try_into()
                .unwrap();
        let from_bits = |s: &str| {
            let mut out = [0u8; 11];
            for (k, c) in s.bytes().enumerate() {
                out[k / 8] |= (c - b'0') << (k % 8);
            }
            out
        };
        let zero = "0".repeat(88);
        let first = "0000100100110101011101111111110011000001101100111110011101110101011010100100010011001111";
        let second = "1101101011010001100011110000010011001111110110011101010110100001111001000101011111011000";
        let alternating = "01".repeat(44);
        let third = "0000111101000001111011010111011111110001100101000000001101101110100010010111001100100110";
        for (pt, ct) in [
            (zero.as_str(), first),
            (first, second),
            (alternating.as_str(), third),
        ] {
            assert_eq!(ff1_encrypt(&key, &from_bits(pt)), from_bits(ct));
            assert_eq!(ff1_decrypt(&key, &from_bits(ct)), from_bits(pt));
        }
    }

    #[test]
    fn diversifier_indices() {
        assert_eq!(DiversifierIndex::from(5u64).to_u128(), 5);
        assert_eq!(DiversifierIndex::MAX.to_u128(), (1 << 88) - 1);
        assert_eq!(DiversifierIndex::MAX.next(), None);
        assert_eq!(DiversifierIndex::from_u128(1 << 88), None);
        assert_eq!(
            DiversifierIndex::from(0xffu64).next(),
            Some(DiversifierIndex::from(0x100u64))
        );
    }

    /// Checks a key against a row of `sapling_zip32.json`.
    fn check(row: &Row<'_>, xsk: Option<&ExtendedSpendingKey>, xfvk: &ExtendedFullViewingKey) {
        if let Some(xsk) = xsk {
            let expsk = xsk.expanded_spending_key();
            assert_eq!(Some(expsk.ask().to_bytes()), row.opt_array("ask"));
            assert_eq!(Some(expsk.nsk().to_bytes()), row.opt_array("nsk"));
            assert_eq!(Some(*xsk.to_bytes()), row.opt_array("xsk"));
            assert_eq!(&xsk.to_extended_full_viewing_key(), xfvk);
            let again = ExtendedSpendingKey::from_bytes(&xsk.to_bytes()).unwrap();
            assert_eq!(&again, xsk);
            let internal = xsk.internal().unwrap();
            assert_eq!(
                Some(internal.expanded_spending_key().nsk().to_bytes()),
                row.opt_array("internal_nsk")
            );
            assert_eq!(Some(*internal.to_bytes()), row.opt_array("internal_xsk"));
            // the diagram commutes
            assert_eq!(
                internal.to_extended_full_viewing_key(),
                xfvk.internal().unwrap()
            );
        } else {
            for column in ["ask", "nsk", "xsk", "internal_nsk", "internal_xsk"] {
                assert_eq!(row.opt_array::<1>(column), None);
            }
        }
        let fvk = xfvk.full_viewing_key();
        assert_eq!(fvk.ovk().0, row.array::<32>("ovk"));
        assert_eq!(*xfvk.diversifier_key().as_bytes(), row.array::<32>("dk"));
        assert_eq!(*xfvk.chain_code(), row.array::<32>("c"));
        assert_eq!(fvk.ak().to_bytes(), row.array::<32>("ak"));
        assert_eq!(fvk.nk().to_bytes(), row.array::<32>("nk"));
        assert_eq!(xfvk.ivk().to_bytes(), row.array::<32>("ivk"));
        assert_eq!(xfvk.to_bytes(), row.array::<169>("xfvk"));
        assert_eq!(xfvk.fingerprint(), row.array::<32>("fp"));
        assert_eq!(
            ExtendedFullViewingKey::from_bytes(&xfvk.to_bytes()).as_ref(),
            Ok(xfvk)
        );
        let dk = xfvk.diversifier_key();
        for (column, j) in [
            ("d0", DiversifierIndex::from(0u64)),
            ("d1", DiversifierIndex::from(1u64)),
            ("d2", DiversifierIndex::from(2u64)),
            ("dmax", DiversifierIndex::MAX),
        ] {
            let d = dk.diversifier(j);
            assert_eq!(d.map(|d| d.0), row.opt_array(column), "{column}");
            if let Some(d) = d {
                assert_eq!(dk.diversifier_index(&d), j);
                let address = xfvk.address(j).unwrap();
                assert_eq!(xfvk.address_index(&address), Some(j));
            } else {
                assert_eq!(xfvk.address(j), None);
            }
        }
        let internal = xfvk.internal().unwrap();
        let ifvk = internal.full_viewing_key();
        assert_eq!(ifvk.ovk().0, row.array::<32>("internal_ovk"));
        assert_eq!(
            *internal.diversifier_key().as_bytes(),
            row.array::<32>("internal_dk")
        );
        assert_eq!(ifvk.nk().to_bytes(), row.array::<32>("internal_nk"));
        assert_eq!(internal.ivk().to_bytes(), row.array::<32>("internal_ivk"));
        assert_eq!(internal.to_bytes(), row.array::<169>("internal_xfvk"));
        assert_eq!(internal.fingerprint(), row.array::<32>("internal_fp"));
    }

    fn seed() -> [u8; 32] {
        core::array::from_fn(|i| i as u8)
    }

    /// `m`, `m/1`, `m/1/2'`, then the viewing keys of `m/1/2'` and
    /// `m/1/2'/3`.
    #[test]
    fn sapling_zip32() {
        let m = ExtendedSpendingKey::master(&seed()).unwrap();
        let m_1 = m.derive_child(1).unwrap();
        let m_1_2h = m_1.derive_child(harden(2)).unwrap();
        let m_1_2hv = m_1_2h.to_extended_full_viewing_key();
        let m_1_2hv_3 = m_1_2hv.derive_child(3).unwrap();
        // the same key, from the spending side
        assert_eq!(
            m_1_2h
                .derive_child(3)
                .unwrap()
                .to_extended_full_viewing_key(),
            m_1_2hv_3
        );
        assert_eq!(m.derive_path(&[1, harden(2)]).unwrap(), m_1_2h);
        let keys = [
            (Some(&m), m.to_extended_full_viewing_key()),
            (Some(&m_1), m_1.to_extended_full_viewing_key()),
            (Some(&m_1_2h), m_1_2hv.clone()),
            (None, m_1_2hv.clone()),
            (None, m_1_2hv_3.clone()),
        ];
        let mut seen = 0;
        for_each_row(include_str!("testdata/sapling_zip32.json"), |i, row| {
            seen += 1;
            check(&row, keys[i].0, &keys[i].1);
        });
        assert_eq!(seen, 5);
        assert_eq!(m.depth(), 0);
        assert_eq!(m_1_2hv_3.depth(), 3);
        assert_eq!(m_1_2hv_3.child_index(), 3);
        assert_eq!(m_1_2hv_3.parent_fvk_tag(), m_1_2hv.fingerprint()[..4]);
        assert_eq!(
            m_1_2hv.derive_child(harden(3)).err(),
            Some(Error::InvalidChildIndex)
        );
    }

    /// `m`, `m/1'`, `m/1'/2'`, `m/1'/2'/3'`.
    #[test]
    fn sapling_zip32_hard() {
        let m = ExtendedSpendingKey::master(&seed()).unwrap();
        let path = [harden(1), harden(2), harden(3)];
        let mut seen = 0;
        for_each_row(
            include_str!("testdata/sapling_zip32_hard.json"),
            |i, row| {
                seen += 1;
                let key = m.derive_path(&path[..i]).unwrap();
                assert_eq!(key.depth() as usize, i);
                check(&row, Some(&key), &key.to_extended_full_viewing_key());
            },
        );
        assert_eq!(seen, 4);
    }

    #[test]
    fn accounts_and_addresses() {
        let seed = seed();
        let account = ExtendedSpendingKey::from_seed_account(&seed, COIN_TYPE_MAIN, 0).unwrap();
        assert_eq!(account.depth(), 3);
        assert_eq!(account.child_index(), harden(0));
        assert_eq!(
            account,
            ExtendedSpendingKey::master(&seed)
                .unwrap()
                .derive_path(&[harden(32), harden(133), harden(0)])
                .unwrap()
        );
        assert_eq!(
            ExtendedSpendingKey::from_seed_account(&seed, harden(1), 0).err(),
            Some(Error::InvalidChildIndex)
        );
        let xfvk = account.to_extended_full_viewing_key();
        let (j, address) = account.default_address().unwrap();
        assert_eq!(xfvk.default_address(), Some((j, address)));
        assert_eq!(xfvk.address_index(&address), Some(j));
        let (j2, second) = xfvk.find_address(j.next().unwrap()).unwrap();
        assert!(j2 > j);
        assert_ne!(second, address);
        // the internal key has other addresses
        let internal = xfvk.internal().unwrap();
        let (_, change) = internal.default_address().unwrap();
        assert_ne!(change, address);
        assert_eq!(xfvk.address_index(&change), None);
        assert!(internal.address_index(&change).is_some());

        assert_eq!(
            ExtendedSpendingKey::master(&seed[..31]).err(),
            Some(Error::InvalidKey)
        );
        assert_eq!(
            ExtendedSpendingKey::master(&[0; 253]).err(),
            Some(Error::InvalidKey)
        );
        // the depth is bounded
        let mut bytes = account.to_bytes();
        bytes[0] = 255;
        let deepest = ExtendedSpendingKey::from_bytes(&bytes).unwrap();
        assert_eq!(
            deepest.derive_child(harden(0)).err(),
            Some(Error::MaxDepthExceeded)
        );
        assert_eq!(
            deepest.to_extended_full_viewing_key().derive_child(0).err(),
            Some(Error::MaxDepthExceeded)
        );
    }

    #[test]
    fn bech32_encodings() {
        let account = ExtendedSpendingKey::from_seed_account(&seed(), COIN_TYPE_TEST, 7).unwrap();
        let xfvk = account.to_extended_full_viewing_key();
        let mut buf = [0u8; EXTENDED_KEY_MAX_ENCODED_LEN];
        for network in Network::ALL {
            let s = account.encode(network, &mut buf).unwrap().to_owned();
            assert!(s.starts_with(network.hrp_extended_spending_key()));
            let (n, key) = ExtendedSpendingKey::decode(&s).unwrap();
            assert_eq!(n, network);
            assert_eq!(key, account);
            // not a viewing key
            assert_eq!(
                ExtendedFullViewingKey::decode(&s).err(),
                Some(Error::InvalidEncoding)
            );
            let s = xfvk.encode(network, &mut buf).unwrap().to_owned();
            assert!(s.starts_with(network.hrp_extended_full_viewing_key()));
            assert_eq!(
                ExtendedFullViewingKey::decode(&s),
                Ok((network, xfvk.clone()))
            );
        }
        let s = account.encode(Network::Regtest, &mut buf).unwrap();
        assert_eq!(s.len(), EXTENDED_KEY_MAX_ENCODED_LEN);
        assert!(account.encode(Network::Main, &mut buf[..100]).is_err());
        assert_eq!(
            format!("{account:?}"),
            "ExtendedSpendingKey(depth 3, index 2147483655, ..)"
        );
    }
}
