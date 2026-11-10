//! Orchard key components (protocol specification section 4.2.3) and their
//! ZIP-32 hierarchical derivation.
//!
//! ```text
//! SpendingKey ─┬─> SpendAuthorizingKey (ask) ──> SpendValidatingKey (ak) ─┐
//!              ├─> nk ───────────────────────────────────────────────────┼─> FullViewingKey
//!              └─> rivk ─────────────────────────────────────────────────┘
//! FullViewingKey ──(scope)──> IncomingViewingKey (dk, ivk) ──> Address (d, pk_d)
//!                └──(scope)──> OutgoingViewingKey
//! ```
//!
//! Nothing here allocates. Spending material is wiped when dropped.

use purecrypto::cipher::{Aes256, BlockCipher};
use purecrypto::ct::{ConditionallySelectable, ConstantTimeEq};
use purecrypto::zeroize::{Zeroize, ZeroizeOnDrop};

use super::Error;
use super::constants::SPEND_AUTH_G;
use super::fields::{Fp, Fq};
use super::pallas::{Affine, Point};
use super::sinsemilla::{CommitDomain, le_bits};
use super::spec::{blake2b, prf_expand, prf_expand_base, prf_expand_scalar};

/// The ZIP-32 purpose of shielded key derivation (`m / 32' / ...`).
pub const ZIP32_PURPOSE: u32 = 32;

/// Which of the two address families of an account a key belongs to
/// (ZIP-32): addresses given out to receive payments, or addresses internal
/// to the wallet (change and auto-shielding), which a holder of the external
/// incoming viewing key cannot link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Addresses given to senders.
    External,
    /// Addresses for the wallet's own change.
    Internal,
}

/// An Orchard spending key: 32 bytes every other key derives from.
#[derive(Clone)]
pub struct SpendingKey([u8; 32]);

impl Zeroize for SpendingKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SpendingKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SpendingKey {}

impl SpendingKey {
    /// Wraps spending key bytes, rejecting the (negligibly rare) ones the
    /// protocol does not allow: those whose `ask` is zero or whose incoming
    /// viewing key, in either scope, is zero or undefined.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        let sk = SpendingKey(bytes);
        let mut ask = prf_expand_scalar(&sk.0, &[&[0x06]]);
        let ask_is_zero = bool::from(ask.is_zero());
        let fvk = FullViewingKey::derive(&sk, &ask);
        ask.zeroize();
        if ask_is_zero
            || fvk.ivk_value(Scope::External).is_none()
            || fvk.ivk_value(Scope::Internal).is_none()
        {
            return Err(Error::InvalidSpendingKey);
        }
        Ok(sk)
    }

    /// The raw key bytes.
    pub fn to_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The spending key of an account, derived from a wallet seed along the
    /// ZIP-32 path `m / 32' / coin_type' / account'`.
    pub fn from_zip32_seed(seed: &[u8], coin_type: u32, account: u32) -> Result<Self, Error> {
        let xsk = ExtendedSpendingKey::from_path(seed, &[ZIP32_PURPOSE, coin_type, account])?;
        Ok(xsk.spending_key().clone())
    }

    /// The spend authorizing key `ask`.
    pub fn to_ask(&self) -> SpendAuthorizingKey {
        SpendAuthorizingKey::from(self)
    }

    /// The full viewing key.
    pub fn to_fvk(&self) -> FullViewingKey {
        FullViewingKey::from(self)
    }
}

impl core::fmt::Debug for SpendingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SpendingKey(..)")
    }
}

/// The spend authorizing key `ask`: the RedPallas private key that signs for
/// the notes of a spending key. Normalized so that the encoding of its
/// public key `ak` has a zero top bit.
pub struct SpendAuthorizingKey(Fq);

impl Zeroize for SpendAuthorizingKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SpendAuthorizingKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SpendAuthorizingKey {}

impl SpendAuthorizingKey {
    /// The key as a scalar.
    pub fn to_scalar(&self) -> Fq {
        self.0
    }

    /// The spend validating key `ak = [ask] SpendAuthG`.
    pub fn to_ak(&self) -> SpendValidatingKey {
        SpendValidatingKey(SPEND_AUTH_G.to_point().mul(&self.0).to_affine())
    }

    /// The key randomized by `alpha` (`rsk = ask + alpha`), which signs for
    /// the randomized validating key `rk` of one action.
    pub fn randomize(
        &self,
        alpha: &Fq,
    ) -> super::redpallas::SigningKey<super::redpallas::SpendAuth> {
        super::redpallas::SigningKey::from_scalar(self.0 + *alpha)
    }
}

impl From<&SpendingKey> for SpendAuthorizingKey {
    fn from(sk: &SpendingKey) -> Self {
        let mut ask = prf_expand_scalar(&sk.0, &[&[0x06]]);
        // negate when the y coordinate of ak is odd
        let ak = SPEND_AUTH_G.to_point().mul(&ask).to_affine();
        ask = Fq::conditional_select(&ask.neg(), &ask, ak.y().is_odd());
        SpendAuthorizingKey(ask)
    }
}

impl core::fmt::Debug for SpendAuthorizingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SpendAuthorizingKey(..)")
    }
}

/// The spend validating key `ak`: the RedPallas public key of `ask`, a
/// non-identity point whose y coordinate is even.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendValidatingKey(Affine);

impl SpendValidatingKey {
    /// The key as a point.
    pub fn to_point(&self) -> Affine {
        self.0
    }

    /// The 32-byte encoding (the x coordinate).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Decodes [`to_bytes`](Self::to_bytes): a canonical non-identity point
    /// with a zero top bit.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        if bytes[31] & 0x80 != 0 {
            return None;
        }
        let p = Affine::from_bytes(bytes)?;
        if bool::from(p.is_identity()) {
            return None;
        }
        Some(SpendValidatingKey(p))
    }

    /// The validating key randomized by `alpha`: `rk = ak + [alpha]
    /// SpendAuthG`, as published in an action.
    pub fn randomize(
        &self,
        alpha: &Fq,
    ) -> super::redpallas::VerificationKey<super::redpallas::SpendAuth> {
        let rk = SPEND_AUTH_G.to_point().mul(alpha).add_affine(&self.0);
        super::redpallas::VerificationKey::from_point(rk.to_affine())
    }
}

/// A full viewing key: everything needed to detect and decrypt the notes of
/// a spending key, received or sent, and to tell when they are spent, but
/// not to spend them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullViewingKey {
    ak: SpendValidatingKey,
    nk: Fp,
    rivk: Fq,
}

impl From<&SpendingKey> for FullViewingKey {
    fn from(sk: &SpendingKey) -> Self {
        let mut ask = prf_expand_scalar(&sk.0, &[&[0x06]]);
        let fvk = FullViewingKey::derive(sk, &ask);
        ask.zeroize();
        fvk
    }
}

impl FullViewingKey {
    fn derive(sk: &SpendingKey, ask: &Fq) -> Self {
        // the sign of ask does not change the x coordinate of ak; the
        // normalized ak is the one of even y
        let ak = SPEND_AUTH_G.to_point().mul(ask).to_affine();
        let ak = Affine::conditional_select(&ak.neg(), &ak, ak.y().is_odd());
        FullViewingKey {
            ak: SpendValidatingKey(ak),
            nk: prf_expand_base(&sk.0, &[&[0x07]]),
            rivk: prf_expand_scalar(&sk.0, &[&[0x08]]),
        }
    }

    /// The spend validating key `ak`.
    pub fn ak(&self) -> &SpendValidatingKey {
        &self.ak
    }

    /// The nullifier deriving key `nk`.
    pub fn nk(&self) -> Fp {
        self.nk
    }

    /// The randomness `rivk` of the incoming viewing key commitment, for the
    /// given scope.
    pub fn rivk(&self, scope: Scope) -> Fq {
        match scope {
            Scope::External => self.rivk,
            Scope::Internal => prf_expand_scalar(
                &self.rivk.to_bytes(),
                &[&[0x83], &self.ak.to_bytes(), &self.nk.to_bytes()],
            ),
        }
    }

    /// `ivk = Commit^ivk_rivk(ak, nk)`, or `None` if it is undefined or zero.
    fn ivk_value(&self, scope: Scope) -> Option<Fp> {
        let (ak, nk) = (self.ak.to_bytes(), self.nk.to_bytes());
        let ivk = CommitDomain::COMMIT_IVK.short_commit(
            le_bits(&ak, 255).chain(le_bits(&nk, 255)),
            &self.rivk(scope),
        )?;
        if bool::from(ivk.is_zero()) {
            None
        } else {
            Some(ivk)
        }
    }

    /// `(dk, ovk)` of a scope.
    fn dk_ovk(&self, scope: Scope) -> ([u8; 32], [u8; 32]) {
        let r = prf_expand(
            &self.rivk(scope).to_bytes(),
            &[&[0x82], &self.ak.to_bytes(), &self.nk.to_bytes()],
        );
        (
            r[..32].try_into().expect("32 bytes"),
            r[32..].try_into().expect("32 bytes"),
        )
    }

    /// The incoming viewing key of a scope.
    pub fn to_ivk(&self, scope: Scope) -> IncomingViewingKey {
        IncomingViewingKey {
            dk: DiversifierKey(self.dk_ovk(scope).0),
            // a full viewing key is only ever built with defined ivks
            ivk: self.ivk_value(scope).unwrap_or(Fp::ONE),
        }
    }

    /// The outgoing viewing key of a scope.
    pub fn to_ovk(&self, scope: Scope) -> OutgoingViewingKey {
        OutgoingViewingKey(self.dk_ovk(scope).1)
    }

    /// The address at a diversifier index of a scope.
    pub fn address_at(&self, index: impl Into<DiversifierIndex>, scope: Scope) -> Address {
        self.to_ivk(scope).address_at(index)
    }

    /// The scope under which `address` belongs to this key, if it does.
    pub fn scope_for_address(&self, address: &Address) -> Option<Scope> {
        [Scope::External, Scope::Internal]
            .into_iter()
            .find(|scope| self.to_ivk(*scope).diversifier_index(address).is_some())
    }

    /// The 96-byte encoding `ak || nk || rivk` (the raw encoding of ZIP-316).
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        out[..32].copy_from_slice(&self.ak.to_bytes());
        out[32..64].copy_from_slice(&self.nk.to_bytes());
        out[64..].copy_from_slice(&self.rivk.to_bytes());
        out
    }

    /// Decodes [`to_bytes`](Self::to_bytes), checking every component and
    /// that the incoming viewing keys of both scopes are defined.
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, Error> {
        let part = |i: usize| -> &[u8; 32] { bytes[32 * i..32 * i + 32].try_into().expect("32") };
        let fvk = FullViewingKey {
            ak: SpendValidatingKey::from_bytes(part(0)).ok_or(Error::InvalidFullViewingKey)?,
            nk: Fp::from_bytes(part(1)).ok_or(Error::InvalidFullViewingKey)?,
            rivk: Fq::from_bytes(part(2)).ok_or(Error::InvalidFullViewingKey)?,
        };
        if fvk.ivk_value(Scope::External).is_none() || fvk.ivk_value(Scope::Internal).is_none() {
            return Err(Error::InvalidFullViewingKey);
        }
        Ok(fvk)
    }

    /// The ZIP-32 fingerprint of this key: BLAKE2b-256 personalized with
    /// `ZcashOrchardFVFP` over its encoding.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        blake2b(b"ZcashOrchardFVFP", &[&self.to_bytes()], &mut out);
        out
    }
}

/// A diversifier key `dk`, which maps diversifier indices to diversifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiversifierKey([u8; 32]);

impl DiversifierKey {
    /// Wraps the key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        DiversifierKey(bytes)
    }

    /// The key bytes.
    pub fn to_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The diversifier at `index`: `FF1-AES256.Encrypt(dk, "", index)`.
    pub fn get(&self, index: impl Into<DiversifierIndex>) -> Diversifier {
        Diversifier(ff1_aes256(&self.0, &index.into().0, true))
    }

    /// The index `diversifier` is at.
    pub fn diversifier_index(&self, diversifier: &Diversifier) -> DiversifierIndex {
        DiversifierIndex(ff1_aes256(&self.0, &diversifier.0, false))
    }
}

/// An 88-bit diversifier index, little-endian.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiversifierIndex([u8; 11]);

impl DiversifierIndex {
    /// Wraps the 11 little-endian bytes of an index.
    pub fn from_bytes(bytes: [u8; 11]) -> Self {
        DiversifierIndex(bytes)
    }

    /// The 11 little-endian bytes of the index.
    pub fn to_bytes(&self) -> &[u8; 11] {
        &self.0
    }

    /// The index as an integer.
    pub fn to_u128(&self) -> u128 {
        let mut le = [0u8; 16];
        le[..11].copy_from_slice(&self.0);
        u128::from_le_bytes(le)
    }

    /// The index for an integer, or `None` if it needs more than 88 bits.
    pub fn from_u128(v: u128) -> Option<Self> {
        let le = v.to_le_bytes();
        if le[11..] != [0; 5] {
            return None;
        }
        Some(DiversifierIndex(le[..11].try_into().expect("11 bytes")))
    }
}

impl From<u32> for DiversifierIndex {
    fn from(v: u32) -> Self {
        Self::from(v as u64)
    }
}

impl From<u64> for DiversifierIndex {
    fn from(v: u64) -> Self {
        let mut out = [0u8; 11];
        out[..8].copy_from_slice(&v.to_le_bytes());
        DiversifierIndex(out)
    }
}

/// FF1-AES256 (NIST SP 800-38G) over 88-bit binary strings with an empty
/// tweak, as ZIP-32 uses it. The string is the bytes in order, each least
/// significant bit first.
fn ff1_aes256(key: &[u8; 32], input: &[u8; 11], encrypt: bool) -> [u8; 11] {
    const HALF: u32 = 44;
    const MASK: u64 = (1 << HALF) - 1;
    let aes = Aes256::new(key);
    // NUM_2 of each half: the first bit of the string is the most
    // significant
    let bit = |k: u32| ((input[(k / 8) as usize] >> (k % 8)) & 1) as u64;
    let (mut a, mut b) = (0u64, 0u64);
    for k in 0..HALF {
        a |= bit(k) << (HALF - 1 - k);
        b |= bit(HALF + k) << (HALF - 1 - k);
    }
    // P = [1, 2, 1] || radix (3 bytes) || 10 || u mod 256 || n (4 bytes) ||
    // t (4 bytes), whose encryption starts the CBC-MAC of every round
    let mut p = [1u8, 2, 1, 0, 0, 2, 10, HALF as u8, 0, 0, 0, 88, 0, 0, 0, 0];
    aes.encrypt_block(&mut p);
    let round = |i: u8, half: u64| -> u64 {
        // Q = 9 zero bytes || i || the half as 6 big-endian bytes
        let mut block = p;
        block[9] ^= i;
        for (dst, src) in block[10..].iter_mut().zip(&half.to_be_bytes()[2..]) {
            *dst ^= *src;
        }
        aes.encrypt_block(&mut block);
        // y is the first 12 bytes as a big-endian integer, used modulo 2^44
        let mut low = [0u8; 8];
        low.copy_from_slice(&block[4..12]);
        block.zeroize();
        u64::from_be_bytes(low) & MASK
    };
    if encrypt {
        for i in 0..10 {
            let c = (a + round(i, b)) & MASK;
            a = b;
            b = c;
        }
    } else {
        for i in (0..10).rev() {
            let c = b.wrapping_sub(round(i, a)) & MASK;
            b = a;
            a = c;
        }
    }
    p.zeroize();
    let mut out = [0u8; 11];
    for k in 0..HALF {
        out[(k / 8) as usize] |= (((a >> (HALF - 1 - k)) & 1) as u8) << (k % 8);
        let kb = HALF + k;
        out[(kb / 8) as usize] |= (((b >> (HALF - 1 - k)) & 1) as u8) << (kb % 8);
    }
    out
}

/// An 11-byte address diversifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Diversifier([u8; 11]);

impl Diversifier {
    /// Wraps diversifier bytes (every value is valid).
    pub fn from_bytes(bytes: [u8; 11]) -> Self {
        Diversifier(bytes)
    }

    /// The diversifier bytes.
    pub fn to_bytes(&self) -> &[u8; 11] {
        &self.0
    }

    /// The diversified base `g_d = DiversifyHash(d)`.
    pub fn g_d(&self) -> Point {
        let p = Point::hash_to_curve(b"z.cash:Orchard-gd", &self.0);
        if bool::from(p.is_identity()) {
            Point::hash_to_curve(b"z.cash:Orchard-gd", b"")
        } else {
            p
        }
    }
}

/// An incoming viewing key: detects and decrypts the notes sent to the
/// addresses of one scope of a full viewing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncomingViewingKey {
    dk: DiversifierKey,
    ivk: Fp,
}

impl IncomingViewingKey {
    /// The diversifier key.
    pub fn dk(&self) -> &DiversifierKey {
        &self.dk
    }

    /// The key agreement private key `ivk` (never zero).
    pub fn ivk(&self) -> Fp {
        self.ivk
    }

    /// `ivk` as a scalar.
    pub(crate) fn ivk_scalar(&self) -> Fq {
        Fq::from_fp(&self.ivk)
    }

    /// The 64-byte encoding `dk || ivk` (the raw encoding of ZIP-316).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.dk.0);
        out[32..].copy_from_slice(&self.ivk.to_bytes());
        out
    }

    /// Decodes [`to_bytes`](Self::to_bytes): `ivk` must be a canonical
    /// non-zero field element.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, Error> {
        let ivk = Fp::from_bytes(bytes[32..].try_into().expect("32 bytes"))
            .ok_or(Error::InvalidIncomingViewingKey)?;
        if bool::from(ivk.is_zero()) {
            return Err(Error::InvalidIncomingViewingKey);
        }
        Ok(IncomingViewingKey {
            dk: DiversifierKey(bytes[..32].try_into().expect("32 bytes")),
            ivk,
        })
    }

    /// The address with the given diversifier.
    pub fn address(&self, d: Diversifier) -> Address {
        let pk_d = d.g_d().mul(&self.ivk_scalar()).to_affine();
        Address { d, pk_d }
    }

    /// The address at a diversifier index.
    pub fn address_at(&self, index: impl Into<DiversifierIndex>) -> Address {
        self.address(self.dk.get(index))
    }

    /// The diversifier index of `address`, or `None` if it is not an address
    /// of this key.
    pub fn diversifier_index(&self, address: &Address) -> Option<DiversifierIndex> {
        if self.address(address.d) == *address {
            Some(self.dk.diversifier_index(&address.d))
        } else {
            None
        }
    }
}

/// An outgoing viewing key: recovers the notes a wallet has sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutgoingViewingKey([u8; 32]);

impl OutgoingViewingKey {
    /// Wraps the key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        OutgoingViewingKey(bytes)
    }

    /// The key bytes.
    pub fn to_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An Orchard shielded payment address: a diversifier and the transmission
/// key `pk_d = [ivk] g_d`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    d: Diversifier,
    pk_d: Affine,
}

impl Address {
    /// The diversifier.
    pub fn diversifier(&self) -> Diversifier {
        self.d
    }

    /// The diversified base `g_d`.
    pub fn g_d(&self) -> Point {
        self.d.g_d()
    }

    /// The diversified transmission key `pk_d` (never the identity).
    pub fn pk_d(&self) -> Affine {
        self.pk_d
    }

    /// The raw 43-byte encoding `d || pk_d`: the Orchard receiver of a
    /// unified address.
    pub fn to_raw_address_bytes(&self) -> [u8; 43] {
        let mut out = [0u8; 43];
        out[..11].copy_from_slice(&self.d.0);
        out[11..].copy_from_slice(&self.pk_d.to_bytes());
        out
    }

    /// Decodes [`to_raw_address_bytes`](Self::to_raw_address_bytes): `pk_d`
    /// must be the canonical encoding of a non-identity point.
    pub fn from_raw_address_bytes(bytes: &[u8; 43]) -> Result<Self, Error> {
        let pk_d = Affine::from_bytes(bytes[11..].try_into().expect("32 bytes"))
            .ok_or(Error::InvalidAddress)?;
        if bool::from(pk_d.is_identity()) {
            return Err(Error::InvalidAddress);
        }
        Ok(Address {
            d: Diversifier(bytes[..11].try_into().expect("11 bytes")),
            pk_d,
        })
    }

    pub(crate) fn from_parts(d: Diversifier, pk_d: Affine) -> Self {
        Address { d, pk_d }
    }
}

/// An Orchard extended spending key (ZIP-32): a spending key with the chain
/// code and position that let it derive children. Orchard only has hardened
/// derivation, so there is no extended viewing key.
#[derive(Clone)]
pub struct ExtendedSpendingKey {
    depth: u8,
    parent_fvk_tag: [u8; 4],
    child_index: u32,
    chain_code: [u8; 32],
    sk: SpendingKey,
}

impl Zeroize for ExtendedSpendingKey {
    fn zeroize(&mut self) {
        self.depth = 0;
        self.parent_fvk_tag.zeroize();
        self.child_index = 0;
        self.chain_code.zeroize();
        self.sk.zeroize();
    }
}

impl Drop for ExtendedSpendingKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ExtendedSpendingKey {}

impl core::fmt::Debug for ExtendedSpendingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtendedSpendingKey")
            .field("depth", &self.depth)
            .field("child_index", &self.child_index)
            .finish_non_exhaustive()
    }
}

impl ExtendedSpendingKey {
    /// The master key of a seed, which must be 32 to 252 bytes long.
    pub fn master(seed: &[u8]) -> Result<Self, Error> {
        if !(32..=252).contains(&seed.len()) {
            return Err(Error::InvalidSeedLength);
        }
        let mut i = [0u8; 64];
        blake2b(b"ZcashIP32Orchard", &[seed], &mut i);
        let sk = SpendingKey::from_bytes(i[..32].try_into().expect("32 bytes"));
        let chain_code = i[32..].try_into().expect("32 bytes");
        i.zeroize();
        Ok(ExtendedSpendingKey {
            depth: 0,
            parent_fvk_tag: [0; 4],
            child_index: 0,
            chain_code,
            sk: sk?,
        })
    }

    /// The hardened child at `index` (the index itself, below `2^31`; the
    /// hardening bit is added here).
    pub fn derive_child(&self, index: u32) -> Result<Self, Error> {
        if index >= 1 << 31 {
            return Err(Error::InvalidChildIndex);
        }
        let hardened = index | 1 << 31;
        let depth = self.depth.checked_add(1).ok_or(Error::InvalidChildIndex)?;
        let i = prf_expand(
            &self.chain_code,
            &[&[0x81], &self.sk.0, &hardened.to_le_bytes()],
        );
        let sk = SpendingKey::from_bytes(i[..32].try_into().expect("32 bytes"))?;
        let fp = self.sk.to_fvk().fingerprint();
        Ok(ExtendedSpendingKey {
            depth,
            parent_fvk_tag: fp[..4].try_into().expect("4 bytes"),
            child_index: hardened,
            chain_code: i[32..].try_into().expect("32 bytes"),
            sk,
        })
    }

    /// The key at a path of hardened indices (each below `2^31`) from the
    /// master key of `seed`.
    pub fn from_path(seed: &[u8], path: &[u32]) -> Result<Self, Error> {
        let mut key = Self::master(seed)?;
        for index in path {
            key = key.derive_child(*index)?;
        }
        Ok(key)
    }

    /// The spending key.
    pub fn spending_key(&self) -> &SpendingKey {
        &self.sk
    }

    /// The chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// The number of derivation steps from the master key.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// The index of this key under its parent, with the hardening bit (0
    /// for the master key).
    pub fn child_index(&self) -> u32 {
        self.child_index
    }

    /// The first four bytes of the fingerprint of the parent's full viewing
    /// key (zeros for the master key).
    pub fn parent_fvk_tag(&self) -> [u8; 4] {
        self.parent_fvk_tag
    }

    /// The 73-byte ZIP-32 encoding: depth, parent tag, child index, chain
    /// code, spending key. The caller is responsible for wiping it.
    pub fn to_bytes(&self) -> [u8; 73] {
        let mut out = [0u8; 73];
        out[0] = self.depth;
        out[1..5].copy_from_slice(&self.parent_fvk_tag);
        out[5..9].copy_from_slice(&self.child_index.to_le_bytes());
        out[9..41].copy_from_slice(&self.chain_code);
        out[41..].copy_from_slice(&self.sk.0);
        out
    }

    /// Decodes [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8; 73]) -> Result<Self, Error> {
        let depth = bytes[0];
        let child_index = u32::from_le_bytes(bytes[5..9].try_into().expect("4 bytes"));
        let parent_fvk_tag: [u8; 4] = bytes[1..5].try_into().expect("4 bytes");
        let valid = if depth == 0 {
            child_index == 0 && parent_fvk_tag == [0; 4]
        } else {
            child_index >= 1 << 31
        };
        if !valid {
            return Err(Error::InvalidSpendingKey);
        }
        Ok(ExtendedSpendingKey {
            depth,
            parent_fvk_tag,
            child_index,
            chain_code: bytes[9..41].try_into().expect("32 bytes"),
            sk: SpendingKey::from_bytes(bytes[41..].try_into().expect("32 bytes"))?,
        })
    }
}

impl PartialEq for ExtendedSpendingKey {
    fn eq(&self, other: &Self) -> bool {
        let same_position = self.depth == other.depth
            && self.parent_fvk_tag == other.parent_fvk_tag
            && self.child_index == other.child_index;
        let same_secret = self.chain_code.ct_eq(&other.chain_code) & self.sk.0.ct_eq(&other.sk.0);
        same_position & bool::from(same_secret)
    }
}

impl Eq for ExtendedSpendingKey {}
