//! Sapling keys and payment addresses (protocol specification §4.2.2 and
//! §5.6.3).
//!
//! ```text
//! sk ─► ask ─► ak ─┐
//!    ─► nsk ─► nk ─┼─► ivk ─► pk_d = [ivk] DiversifyHash(d)
//!    ─► ovk        │
//! ```
//!
//! An [`ExpandedSpendingKey`] (`ask`, `nsk`, `ovk`) spends; a
//! [`FullViewingKey`] (`ak`, `nk`, `ovk`) sees everything and derives
//! nullifiers; an [`IncomingViewingKey`] (`ivk`) detects and decrypts
//! incoming notes; a [`PaymentAddress`] (`d`, `pk_d`) receives. Hierarchical
//! derivation of these keys is in [`zip32`](super::zip32).
//!
//! Types holding secrets wipe themselves when dropped and print nothing of
//! their content through `Debug`.

use super::Error;
use super::field::Fr;
use super::generators::{
    KEY_DIVERSIFICATION_PERSONALIZATION, PROOF_GENERATION_KEY_BASE, SPENDING_KEY_BASE,
};
use super::group_hash::group_hash;
use super::jubjub::Point;
use super::prf::{crh_ivk, prf_expand};
use crate::bech32;
use purecrypto::ct::ConstantTimeEq;
use purecrypto::zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A Zcash network, which selects the human-readable parts of the Bech32
/// encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// The main network.
    Main,
    /// The test network.
    Test,
    /// A regression test network.
    Regtest,
}

impl Network {
    /// Every network, in the order prefixes are tried when decoding.
    pub const ALL: [Network; 3] = [Network::Main, Network::Test, Network::Regtest];

    /// The human-readable part of payment addresses (`zs` on the main
    /// network).
    pub const fn hrp_payment_address(self) -> &'static str {
        match self {
            Network::Main => "zs",
            Network::Test => "ztestsapling",
            Network::Regtest => "zregtestsapling",
        }
    }

    /// The human-readable part of extended spending keys
    /// (`secret-extended-key-main` on the main network).
    pub const fn hrp_extended_spending_key(self) -> &'static str {
        match self {
            Network::Main => "secret-extended-key-main",
            Network::Test => "secret-extended-key-test",
            Network::Regtest => "secret-extended-key-regtest",
        }
    }

    /// The human-readable part of extended full viewing keys (`zxviews` on
    /// the main network).
    pub const fn hrp_extended_full_viewing_key(self) -> &'static str {
        match self {
            Network::Main => "zxviews",
            Network::Test => "zxviewtestsapling",
            Network::Regtest => "zxviewregtestsapling",
        }
    }

    /// The human-readable part of incoming viewing keys (`zivks` on the main
    /// network).
    pub const fn hrp_incoming_viewing_key(self) -> &'static str {
        match self {
            Network::Main => "zivks",
            Network::Test => "zivktestsapling",
            Network::Regtest => "zivkregtestsapling",
        }
    }
}

/// Encodes `data` as Bech32 with the given human-readable part into `out`,
/// returning the string.
pub(crate) fn bech32_encode<'a>(
    hrp: &str,
    data: &[u8],
    out: &'a mut [u8],
) -> Result<&'a str, Error> {
    let n =
        bech32::encode_to_slice(hrp, data, bech32::Variant::Bech32, out).map_err(|e| match e {
            bech32::Error::BufferTooSmall => Error::BufferTooSmall,
            e => Error::Bech32(e),
        })?;
    // the bech32 alphabet and the prefixes are ASCII
    core::str::from_utf8(&out[..n]).map_err(|_| Error::InvalidEncoding)
}

/// Decodes a Bech32 string whose payload must be exactly `N` bytes and whose
/// human-readable part must be `hrp(network)` for one of the networks;
/// returns that network. The payload buffer is wiped on failure.
pub(crate) fn bech32_decode<const N: usize>(
    s: &str,
    hrp: fn(Network) -> &'static str,
    out: &mut [u8; N],
) -> Result<Network, Error> {
    let result = (|| {
        let (got, len, variant) = bech32::decode_to_slice(s, out).map_err(|e| match e {
            bech32::Error::BufferTooSmall => Error::InvalidEncoding,
            e => Error::Bech32(e),
        })?;
        if len != N || variant != bech32::Variant::Bech32 {
            return Err(Error::InvalidEncoding);
        }
        Network::ALL
            .into_iter()
            .find(|n| got.eq_ignore_ascii_case(hrp(*n)))
            .ok_or(Error::InvalidEncoding)
    })();
    if result.is_err() {
        out.zeroize();
    }
    result
}

/// An outgoing viewing key `ovk`: it decrypts the outgoing ciphertexts of
/// the outputs created with it.
#[derive(Clone, PartialEq, Eq)]
pub struct OutgoingViewingKey(pub [u8; 32]);

impl core::fmt::Debug for OutgoingViewingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OutgoingViewingKey(..)")
    }
}

impl Zeroize for OutgoingViewingKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// A diversifier `d`: 11 bytes that select one of the payment addresses of
/// an incoming viewing key. About half of all values are valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Diversifier(pub [u8; 11]);

impl Diversifier {
    /// `DiversifyHash(d)`: the base point `g_d` of the address, or `None`
    /// for an invalid diversifier.
    pub fn g_d(&self) -> Option<Point> {
        group_hash(KEY_DIVERSIFICATION_PERSONALIZATION, &self.0)
    }
}

/// The first valid diversifier of a (non-hierarchical) spending key `sk`:
/// the first `PRF^expand(sk, [3, i])[..11]` with a valid `DiversifyHash`
/// (protocol specification §4.2.2). Keys derived through ZIP-32 use their
/// diversifier key instead.
pub fn default_diversifier(sk: &[u8]) -> Option<Diversifier> {
    (0..=255u8).find_map(|i| {
        let mut expanded = Zeroizing::new(prf_expand(sk, &[&[3, i]]));
        let mut d = [0u8; 11];
        d.copy_from_slice(&expanded[..11]);
        expanded.zeroize();
        let d = Diversifier(d);
        d.g_d().map(|_| d)
    })
}

/// A Sapling shielded payment address: a diversifier and the diversified
/// transmission key `pk_d = [ivk] g_d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentAddress {
    diversifier: Diversifier,
    g_d: Point,
    pk_d: Point,
}

impl PaymentAddress {
    /// The longest Bech32 encoding of an address (a regtest one); 78 bytes
    /// on the main network.
    pub const MAX_ENCODED_LEN: usize = 91;

    /// Builds an address from its parts: the diversifier must be valid and
    /// `pk_d` a point of the prime-order subgroup other than the identity.
    pub fn from_parts(diversifier: Diversifier, pk_d: Point) -> Result<Self, Error> {
        let g_d = diversifier.g_d().ok_or(Error::InvalidDiversifier)?;
        if !pk_d.is_prime_order() {
            return Err(Error::InvalidAddress);
        }
        Ok(PaymentAddress {
            diversifier,
            g_d,
            pk_d,
        })
    }

    /// For a `pk_d` already known to be `[ivk] g_d`.
    pub(crate) fn from_derived(diversifier: Diversifier, g_d: Point, pk_d: Point) -> Option<Self> {
        (!pk_d.is_identity()).then_some(PaymentAddress {
            diversifier,
            g_d,
            pk_d,
        })
    }

    /// Decodes the raw 43-byte encoding `d ‖ repr(pk_d)`.
    pub fn from_bytes(bytes: &[u8; 43]) -> Result<Self, Error> {
        let (d, pk_d) = bytes.split_at(11);
        let mut diversifier = [0u8; 11];
        diversifier.copy_from_slice(d);
        let mut repr = [0u8; 32];
        repr.copy_from_slice(pk_d);
        let pk_d = Point::from_bytes(&repr).ok_or(Error::InvalidAddress)?;
        Self::from_parts(Diversifier(diversifier), pk_d)
    }

    /// The raw 43-byte encoding `d ‖ repr(pk_d)`.
    pub fn to_bytes(&self) -> [u8; 43] {
        let mut bytes = [0u8; 43];
        bytes[..11].copy_from_slice(&self.diversifier.0);
        bytes[11..].copy_from_slice(&self.pk_d.to_bytes());
        bytes
    }

    /// The diversifier `d`.
    pub const fn diversifier(&self) -> &Diversifier {
        &self.diversifier
    }

    /// The diversified base `g_d = DiversifyHash(d)`.
    pub const fn g_d(&self) -> &Point {
        &self.g_d
    }

    /// The diversified transmission key `pk_d`.
    pub const fn pk_d(&self) -> &Point {
        &self.pk_d
    }

    /// Writes the Bech32 encoding (`zs1...`) into `out`
    /// ([`MAX_ENCODED_LEN`](Self::MAX_ENCODED_LEN) bytes always suffice).
    pub fn encode<'a>(&self, network: Network, out: &'a mut [u8]) -> Result<&'a str, Error> {
        bech32_encode(network.hrp_payment_address(), &self.to_bytes(), out)
    }

    /// Decodes a Bech32 address of any network, returning the network too.
    pub fn decode(s: &str) -> Result<(Network, Self), Error> {
        let mut bytes = [0u8; 43];
        let network = bech32_decode(s, Network::hrp_payment_address, &mut bytes)?;
        Ok((network, Self::from_bytes(&bytes)?))
    }

    /// The Bech32 encoding as a `String`.
    #[cfg(feature = "alloc")]
    pub fn encode_string(&self, network: Network) -> crate::prelude::String {
        let mut buf = [0u8; Self::MAX_ENCODED_LEN];
        self.encode(network, &mut buf)
            .map(crate::prelude::String::from)
            .unwrap_or_default()
    }
}

/// An expanded spending key: the spend authorizing key `ask`, the proof
/// authorizing key `nsk` and the outgoing viewing key `ovk`.
#[derive(Clone)]
pub struct ExpandedSpendingKey {
    ask: Fr,
    nsk: Fr,
    ovk: OutgoingViewingKey,
}

impl Zeroize for ExpandedSpendingKey {
    fn zeroize(&mut self) {
        self.ask.zeroize();
        self.nsk.zeroize();
        self.ovk.zeroize();
    }
}

impl Drop for ExpandedSpendingKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ExpandedSpendingKey {}

impl PartialEq for ExpandedSpendingKey {
    /// Compares in constant time.
    fn eq(&self, other: &Self) -> bool {
        bool::from(
            self.ask.ct_eq(&other.ask)
                & self.nsk.ct_eq(&other.nsk)
                & self.ovk.0.ct_eq(&other.ovk.0),
        )
    }
}

impl Eq for ExpandedSpendingKey {}

impl core::fmt::Debug for ExpandedSpendingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ExpandedSpendingKey(..)")
    }
}

/// `ToScalar(PRF^expand(sk, t))`.
pub(crate) fn expand_to_scalar(sk: &[u8], t: &[&[u8]]) -> Fr {
    let expanded = Zeroizing::new(prf_expand(sk, t));
    Fr::from_bytes_wide(&expanded)
}

/// The first 32 bytes of `PRF^expand(sk, t)`.
pub(crate) fn expand_to_32(sk: &[u8], t: &[&[u8]]) -> [u8; 32] {
    let expanded = Zeroizing::new(prf_expand(sk, t));
    let mut out = [0u8; 32];
    out.copy_from_slice(&expanded[..32]);
    out
}

impl ExpandedSpendingKey {
    /// Expands a spending key `sk`: `ask = ToScalar(PRF^expand(sk, [0]))`,
    /// `nsk = ToScalar(PRF^expand(sk, [1]))` and `ovk` the first half of
    /// `PRF^expand(sk, [2])`. Fails for the (unreachable in practice) keys
    /// whose `ask` is zero.
    pub fn from_spending_key(sk: &[u8]) -> Result<Self, Error> {
        Self::from_parts(
            expand_to_scalar(sk, &[&[0]]),
            expand_to_scalar(sk, &[&[1]]),
            OutgoingViewingKey(expand_to_32(sk, &[&[2]])),
        )
    }

    /// Builds the key from its components; `ask` must not be zero.
    pub fn from_parts(ask: Fr, nsk: Fr, ovk: OutgoingViewingKey) -> Result<Self, Error> {
        let key = ExpandedSpendingKey { ask, nsk, ovk };
        if key.ask.is_zero() {
            return Err(Error::InvalidKey);
        }
        Ok(key)
    }

    /// Decodes `ask ‖ nsk ‖ ovk` (96 bytes), requiring canonical scalars and
    /// a non-zero `ask`.
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, Error> {
        let (ask, rest) = bytes.split_first_chunk::<32>().ok_or(Error::InvalidKey)?;
        let (nsk, ovk) = rest.split_first_chunk::<32>().ok_or(Error::InvalidKey)?;
        let mut ovk_bytes = [0u8; 32];
        ovk_bytes.copy_from_slice(ovk);
        Self::from_parts(
            Fr::from_bytes(ask).ok_or(Error::InvalidKey)?,
            Fr::from_bytes(nsk).ok_or(Error::InvalidKey)?,
            OutgoingViewingKey(ovk_bytes),
        )
    }

    /// Encodes `ask ‖ nsk ‖ ovk`. The result is wiped when dropped.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 96]> {
        let mut bytes = Zeroizing::new([0u8; 96]);
        bytes[..32].copy_from_slice(&self.ask.to_bytes());
        bytes[32..64].copy_from_slice(&self.nsk.to_bytes());
        bytes[64..].copy_from_slice(&self.ovk.0);
        bytes
    }

    /// The spend authorizing key `ask`.
    pub const fn ask(&self) -> &Fr {
        &self.ask
    }

    /// The proof authorizing key `nsk`.
    pub const fn nsk(&self) -> &Fr {
        &self.nsk
    }

    /// The outgoing viewing key `ovk`.
    pub const fn ovk(&self) -> &OutgoingViewingKey {
        &self.ovk
    }

    /// The spend validating key `ak = [ask] G`.
    pub fn ak(&self) -> Point {
        SPENDING_KEY_BASE.to_point().mul(&self.ask)
    }

    /// The nullifier deriving key `nk = [nsk] H`.
    pub fn nk(&self) -> Point {
        PROOF_GENERATION_KEY_BASE.to_point().mul(&self.nsk)
    }

    /// The proof generation key `(ak, nsk)`, which a prover needs.
    pub fn proof_generation_key(&self) -> ProofGenerationKey {
        ProofGenerationKey {
            ak: self.ak(),
            nsk: self.nsk,
        }
    }

    /// The full viewing key `(ak, nk, ovk)`.
    pub fn full_viewing_key(&self) -> FullViewingKey {
        FullViewingKey {
            ak: self.ak(),
            nk: self.nk(),
            ovk: self.ovk.clone(),
        }
    }
}

/// The proof generation key `(ak, nsk)`: what the creator of a Spend proof
/// needs to know. It cannot authorize spends.
#[derive(Clone)]
pub struct ProofGenerationKey {
    /// The spend validating key `ak`.
    pub ak: Point,
    /// The proof authorizing key `nsk`.
    pub nsk: Fr,
}

impl Zeroize for ProofGenerationKey {
    fn zeroize(&mut self) {
        self.nsk.zeroize();
    }
}

impl Drop for ProofGenerationKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ProofGenerationKey {}

impl core::fmt::Debug for ProofGenerationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProofGenerationKey(..)")
    }
}

impl ProofGenerationKey {
    /// The nullifier deriving key `nk = [nsk] H`.
    pub fn nk(&self) -> Point {
        PROOF_GENERATION_KEY_BASE.to_point().mul(&self.nsk)
    }

    /// The incoming viewing key of this key.
    pub fn ivk(&self) -> IncomingViewingKey {
        IncomingViewingKey::derive(&self.ak, &self.nk())
    }
}

/// A full viewing key `(ak, nk, ovk)`: it detects and decrypts incoming and
/// outgoing notes and computes their nullifiers, but cannot spend.
#[derive(Clone, PartialEq, Eq)]
pub struct FullViewingKey {
    ak: Point,
    nk: Point,
    ovk: OutgoingViewingKey,
}

impl core::fmt::Debug for FullViewingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FullViewingKey(..)")
    }
}

impl Zeroize for FullViewingKey {
    fn zeroize(&mut self) {
        self.ak = Point::IDENTITY;
        self.nk = Point::IDENTITY;
        self.ovk.zeroize();
    }
}

impl FullViewingKey {
    /// Builds the key from its components: `ak` must be a point of the
    /// prime-order subgroup other than the identity, `nk` a point of the
    /// prime-order subgroup.
    pub fn from_parts(ak: Point, nk: Point, ovk: OutgoingViewingKey) -> Result<Self, Error> {
        if !ak.is_prime_order() || !nk.is_torsion_free() {
            return Err(Error::InvalidKey);
        }
        Ok(FullViewingKey { ak, nk, ovk })
    }

    /// Decodes `repr(ak) ‖ repr(nk) ‖ ovk` (96 bytes).
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, Error> {
        let (ak, rest) = bytes.split_first_chunk::<32>().ok_or(Error::InvalidKey)?;
        let (nk, ovk) = rest.split_first_chunk::<32>().ok_or(Error::InvalidKey)?;
        let mut ovk_bytes = [0u8; 32];
        ovk_bytes.copy_from_slice(ovk);
        Self::from_parts(
            Point::from_bytes(ak).ok_or(Error::InvalidKey)?,
            Point::from_bytes(nk).ok_or(Error::InvalidKey)?,
            OutgoingViewingKey(ovk_bytes),
        )
    }

    /// Encodes `repr(ak) ‖ repr(nk) ‖ ovk`.
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut bytes = [0u8; 96];
        bytes[..32].copy_from_slice(&self.ak.to_bytes());
        bytes[32..64].copy_from_slice(&self.nk.to_bytes());
        bytes[64..].copy_from_slice(&self.ovk.0);
        bytes
    }

    /// The spend validating key `ak`.
    pub const fn ak(&self) -> &Point {
        &self.ak
    }

    /// The nullifier deriving key `nk`.
    pub const fn nk(&self) -> &Point {
        &self.nk
    }

    /// The outgoing viewing key `ovk`.
    pub const fn ovk(&self) -> &OutgoingViewingKey {
        &self.ovk
    }

    /// The incoming viewing key `ivk = CRH^ivk(ak, nk)`.
    pub fn ivk(&self) -> IncomingViewingKey {
        IncomingViewingKey::derive(&self.ak, &self.nk)
    }

    /// The payment address for a diversifier, or `None` if the diversifier
    /// is invalid.
    pub fn to_payment_address(&self, diversifier: Diversifier) -> Option<PaymentAddress> {
        self.ivk().to_payment_address(diversifier)
    }
}

/// An incoming viewing key `ivk`: it detects and decrypts the notes sent to
/// any of its payment addresses.
#[derive(Clone, PartialEq, Eq)]
pub struct IncomingViewingKey(Fr);

impl core::fmt::Debug for IncomingViewingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IncomingViewingKey(..)")
    }
}

impl Zeroize for IncomingViewingKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for IncomingViewingKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for IncomingViewingKey {}

impl IncomingViewingKey {
    /// The longest Bech32 encoding of an incoming viewing key.
    pub const MAX_ENCODED_LEN: usize = 77;

    /// `CRH^ivk(repr(ak), repr(nk))`.
    pub fn derive(ak: &Point, nk: &Point) -> Self {
        let mut bytes = crh_ivk(&ak.to_bytes(), &nk.to_bytes());
        // 251 bits: always below the group order
        let ivk = Fr::from_bytes_reduced(&bytes);
        bytes.zeroize();
        IncomingViewingKey(ivk)
    }

    /// The key as a scalar.
    pub const fn to_scalar(&self) -> &Fr {
        &self.0
    }

    /// Decodes the canonical little-endian encoding of `ivk`.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        Fr::from_bytes(bytes)
            .map(IncomingViewingKey)
            .ok_or(Error::InvalidKey)
    }

    /// The little-endian encoding of `ivk`.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The payment address for a diversifier: `pk_d = [ivk] g_d`. `None` if
    /// the diversifier is invalid (or `ivk` is zero, which makes the key
    /// unusable).
    pub fn to_payment_address(&self, diversifier: Diversifier) -> Option<PaymentAddress> {
        let g_d = diversifier.g_d()?;
        PaymentAddress::from_derived(diversifier, g_d, g_d.mul(&self.0))
    }

    /// Writes the Bech32 encoding (`zivks1...`) into `out`.
    pub fn encode<'a>(&self, network: Network, out: &'a mut [u8]) -> Result<&'a str, Error> {
        let bytes = Zeroizing::new(self.to_bytes());
        bech32_encode(network.hrp_incoming_viewing_key(), &bytes[..], out)
    }

    /// Decodes a Bech32 incoming viewing key of any network.
    pub fn decode(s: &str) -> Result<(Network, Self), Error> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        let network = bech32_decode(s, Network::hrp_incoming_viewing_key, &mut bytes)?;
        Ok((network, Self::from_bytes(&bytes)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sapling::test_vectors::for_each_row;

    #[test]
    fn sapling_key_components() {
        let json = include_str!("testdata/sapling_key_components.json");
        let mut seen = 0;
        for_each_row(json, |_, row| {
            seen += 1;
            let sk = row.array::<32>("sk");
            let expsk = ExpandedSpendingKey::from_spending_key(&sk).unwrap();
            assert_eq!(expsk.ask().to_bytes(), row.array::<32>("ask"));
            assert_eq!(expsk.nsk().to_bytes(), row.array::<32>("nsk"));
            assert_eq!(expsk.ovk().0, row.array::<32>("ovk"));
            assert_eq!(expsk.ak().to_bytes(), row.array::<32>("ak"));
            assert_eq!(expsk.nk().to_bytes(), row.array::<32>("nk"));
            let fvk = expsk.full_viewing_key();
            let ivk = fvk.ivk();
            assert_eq!(ivk.to_bytes(), row.array::<32>("ivk"));
            assert_eq!(expsk.proof_generation_key().ivk(), ivk);
            let d = default_diversifier(&sk).unwrap();
            assert_eq!(d.0, row.array::<11>("default_d"));
            let address = ivk.to_payment_address(d).unwrap();
            assert_eq!(address.pk_d().to_bytes(), row.array::<32>("default_pk_d"));
            assert_eq!(fvk.to_payment_address(d), Some(address));

            // encodings round-trip
            let bytes = expsk.to_bytes();
            let again = ExpandedSpendingKey::from_bytes(&bytes).unwrap();
            assert_eq!(again, expsk);
            assert_eq!(FullViewingKey::from_bytes(&fvk.to_bytes()), Ok(fvk));
            assert_eq!(PaymentAddress::from_bytes(&address.to_bytes()), Ok(address));
            assert_eq!(IncomingViewingKey::from_bytes(&ivk.to_bytes()), Ok(ivk));
        });
        assert_eq!(seen, 10);
    }

    fn sample_address() -> PaymentAddress {
        let sk = [7u8; 32];
        let fvk = ExpandedSpendingKey::from_spending_key(&sk)
            .unwrap()
            .full_viewing_key();
        fvk.to_payment_address(default_diversifier(&sk).unwrap())
            .unwrap()
    }

    #[test]
    fn address_encoding() {
        let address = sample_address();
        let mut buf = [0u8; PaymentAddress::MAX_ENCODED_LEN];
        for network in Network::ALL {
            let s = address.encode(network, &mut buf).unwrap();
            assert!(s.starts_with(network.hrp_payment_address()));
            assert_eq!(PaymentAddress::decode(s), Ok((network, address)));
            let upper = s.to_ascii_uppercase();
            assert_eq!(PaymentAddress::decode(&upper), Ok((network, address)));
            #[cfg(feature = "alloc")]
            assert_eq!(address.encode_string(network), s);
        }
        let s = address.encode(Network::Main, &mut buf).unwrap();
        assert_eq!(s.len(), 78);
        assert!(s.starts_with("zs1"));
        let s = s.to_owned();
        assert_eq!(
            address.encode(Network::Main, &mut buf[..77]),
            Err(Error::BufferTooSmall)
        );
        // a flipped character breaks the checksum
        let mut bad = s.clone().into_bytes();
        bad[10] = if bad[10] == b'q' { b'p' } else { b'q' };
        assert!(matches!(
            PaymentAddress::decode(core::str::from_utf8(&bad).unwrap()),
            Err(Error::Bech32(_))
        ));
        // other prefixes, lengths and variants
        let mut out = [0u8; 128];
        let other = bech32_encode("zt", &address.to_bytes(), &mut out).unwrap();
        assert_eq!(PaymentAddress::decode(other), Err(Error::InvalidEncoding));
        let short = bech32_encode("zs", &address.to_bytes()[..42], &mut out).unwrap();
        assert_eq!(PaymentAddress::decode(short), Err(Error::InvalidEncoding));
        let mut long = [0u8; 44];
        long[..43].copy_from_slice(&address.to_bytes());
        let long = bech32_encode("zs", &long, &mut out).unwrap();
        assert_eq!(PaymentAddress::decode(long), Err(Error::InvalidEncoding));
        let n = bech32::encode_to_slice(
            "zs",
            &address.to_bytes(),
            bech32::Variant::Bech32m,
            &mut out,
        )
        .unwrap();
        assert_eq!(
            PaymentAddress::decode(core::str::from_utf8(&out[..n]).unwrap()),
            Err(Error::InvalidEncoding)
        );
        assert!(PaymentAddress::decode("").is_err());
        assert!(PaymentAddress::decode("zs1").is_err());
    }

    #[test]
    fn invalid_addresses() {
        let address = sample_address();
        let mut bytes = address.to_bytes();
        // an invalid diversifier
        let bad_d = (0..=255u8)
            .map(|i| Diversifier([i; 11]))
            .find(|d| d.g_d().is_none())
            .unwrap();
        bytes[..11].copy_from_slice(&bad_d.0);
        assert_eq!(
            PaymentAddress::from_bytes(&bytes),
            Err(Error::InvalidDiversifier)
        );
        assert!(address.pk_d().is_prime_order());
        // pk_d: the identity, a small-order point, a point with torsion
        let mut bytes = address.to_bytes();
        bytes[11..].copy_from_slice(&Point::IDENTITY.to_bytes());
        assert_eq!(
            PaymentAddress::from_bytes(&bytes),
            Err(Error::InvalidAddress)
        );
        let two = Point::from_bytes(&(-crate::sapling::Fq::ONE).to_bytes()).unwrap();
        bytes[11..].copy_from_slice(&(*address.pk_d() + two).to_bytes());
        assert_eq!(
            PaymentAddress::from_bytes(&bytes),
            Err(Error::InvalidAddress)
        );
        bytes[11..].copy_from_slice(&[0xff; 32]);
        assert_eq!(
            PaymentAddress::from_bytes(&bytes),
            Err(Error::InvalidAddress)
        );
    }

    #[test]
    fn invalid_keys() {
        let mut bytes = [0u8; 96];
        // ask = 0
        assert_eq!(
            ExpandedSpendingKey::from_bytes(&bytes).err(),
            Some(Error::InvalidKey)
        );
        bytes[0] = 1;
        assert!(ExpandedSpendingKey::from_bytes(&bytes).is_ok());
        // a non-canonical nsk
        bytes[32..64].fill(0xff);
        assert_eq!(
            ExpandedSpendingKey::from_bytes(&bytes).err(),
            Some(Error::InvalidKey)
        );
        // ak = identity
        let mut fvk = [0u8; 96];
        fvk[0] = 1;
        fvk[32] = 1;
        assert_eq!(FullViewingKey::from_bytes(&fvk), Err(Error::InvalidKey));
        assert_eq!(
            IncomingViewingKey::from_bytes(&[0xff; 32]),
            Err(Error::InvalidKey)
        );
        // a zero ivk has no addresses
        let zero = IncomingViewingKey::from_bytes(&[0; 32]).unwrap();
        assert_eq!(
            zero.to_payment_address(*sample_address().diversifier()),
            None
        );
    }

    #[test]
    fn ivk_encoding() {
        let ivk = ExpandedSpendingKey::from_spending_key(&[9u8; 32])
            .unwrap()
            .full_viewing_key()
            .ivk();
        let mut buf = [0u8; IncomingViewingKey::MAX_ENCODED_LEN];
        for network in Network::ALL {
            let s = ivk.encode(network, &mut buf).unwrap();
            assert!(s.starts_with(network.hrp_incoming_viewing_key()));
            assert_eq!(IncomingViewingKey::decode(s), Ok((network, ivk.clone())));
        }
        let s = ivk.encode(Network::Regtest, &mut buf).unwrap();
        assert_eq!(s.len(), IncomingViewingKey::MAX_ENCODED_LEN);
        assert_eq!(format!("{ivk:?}"), "IncomingViewingKey(..)");

        // The first `ivk` of `sapling_key_components.json`, encoded with the
        // `bech32` crate (0.11) under the prefixes of zcashd's
        // `chainparams.cpp` (`bech32HRPs[SAPLING_INCOMING_VIEWING_KEY]`).
        // zcashd defines the prefixes but has no encoder of its own for
        // this key type; the layout is that of its other Sapling keys.
        let ivk = IncomingViewingKey::from_bytes(
            &hex::decode("b70b7cd0ed03cbdfd7ada9502ee245b13e569d54a5719d2daa0f5f1451479204")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let expected = [
            "zivks1ku9he58dq09al4ad49gzacj9kyl9d82554ce6td2pa03g528jgzqhh38dg",
            "zivktestsapling1ku9he58dq09al4ad49gzacj9kyl9d82554ce6td2pa03g528jgzqyq6d78",
            "zivkregtestsapling1ku9he58dq09al4ad49gzacj9kyl9d82554ce6td2pa03g528jgzqsnuqkh",
        ];
        for (network, expected) in Network::ALL.into_iter().zip(expected) {
            assert_eq!(ivk.encode(network, &mut buf), Ok(expected));
            assert_eq!(
                IncomingViewingKey::decode(expected),
                Ok((network, ivk.clone()))
            );
        }
    }
}
