//! Account keys, view-only key sets and subaddresses.

use purecrypto::zeroize::Zeroizing;

use super::Error;
use super::address::{Address, Network};
use crate::cryptonote::{
    EdwardsPoint, Hasher, derive_view_secret_key, point_from_bytes, sc_reduce32, scalar_from_bytes,
};

/// The index of a subaddress: the account (`major`) and the address within
/// it (`minor`). `(0, 0)` is the main address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct SubaddressIndex {
    /// The account.
    pub major: u32,
    /// The address within the account.
    pub minor: u32,
}

impl SubaddressIndex {
    /// The main address, `(0, 0)`.
    pub const MAIN: SubaddressIndex = SubaddressIndex { major: 0, minor: 0 };

    /// The subaddress `(major, minor)`.
    pub const fn new(major: u32, minor: u32) -> Self {
        SubaddressIndex { major, minor }
    }

    /// Whether this is the main address.
    pub const fn is_main(&self) -> bool {
        self.major == 0 && self.minor == 0
    }
}

/// `get_subaddress_secret_key`: the scalar
/// `m = Hs("SubAddr\0" || view_secret || major || minor)` that offsets the
/// spend key for the subaddress `index` (both indices as 4 little-endian
/// bytes).
///
/// The subaddress's public spend key is `D = B + m * G` and its secret spend
/// key `b + m`. The value is as secret as the view key. For `(0, 0)` the
/// scalar is still the hash, but Monero never uses it: the main address has
/// no offset.
pub fn subaddress_secret_key(
    view_secret: &[u8; 32],
    index: SubaddressIndex,
) -> Zeroizing<[u8; 32]> {
    let mut h = Hasher::new();
    h.update(b"SubAddr\0");
    h.update(view_secret);
    h.update(&index.major.to_le_bytes());
    h.update(&index.minor.to_le_bytes());
    Zeroizing::new(h.finalize_scalar())
}

/// The keys that watch an account without being able to spend from it: the
/// secret view key and the public spend key.
///
/// The view key is wiped when the value is dropped.
#[derive(Clone)]
pub struct ViewKeys {
    view_secret: Zeroizing<[u8; 32]>,
    spend_public: [u8; 32],
}

impl core::fmt::Debug for ViewKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ViewKeys")
            .field("spend_public", &self.spend_public)
            .finish_non_exhaustive()
    }
}

impl ViewKeys {
    /// A view-only key set.
    ///
    /// Fails with [`Error::CryptoNote`] if `view_secret` is not a reduced
    /// scalar or `spend_public` is not a curve point.
    pub fn new(view_secret: &[u8; 32], spend_public: &[u8; 32]) -> Result<Self, Error> {
        scalar_from_bytes(view_secret)?;
        point_from_bytes(spend_public)?;
        Ok(ViewKeys {
            view_secret: Zeroizing::new(*view_secret),
            spend_public: *spend_public,
        })
    }

    /// The secret view key.
    pub fn view_secret(&self) -> &[u8; 32] {
        &self.view_secret
    }

    /// The public spend key of the main address.
    pub fn spend_public(&self) -> &[u8; 32] {
        &self.spend_public
    }

    /// The public view key of the main address.
    pub fn view_public(&self) -> [u8; 32] {
        // The scalar was checked at construction.
        scalar_from_bytes(&self.view_secret)
            .map(|a| EdwardsPoint::mul_base(&a).compress())
            .unwrap_or([0u8; 32])
    }

    /// The main address of the account.
    pub fn address(&self, network: Network) -> Address {
        Address::standard(network, self.spend_public, self.view_public())
    }

    /// The public spend key `D = B + m * G` of the subaddress `index` (the
    /// account's own spend key for `(0, 0)`): the key a wallet looks up to
    /// recognise its outputs.
    pub fn subaddress_spend_public(&self, index: SubaddressIndex) -> [u8; 32] {
        self.subaddress_keys(index).0
    }

    /// The public keys `(spend, view)` of the subaddress `index`:
    /// `D = B + m * G` and `C = a * D`. For `(0, 0)` they are the keys of the
    /// main address.
    pub fn subaddress_keys(&self, index: SubaddressIndex) -> ([u8; 32], [u8; 32]) {
        if index.is_main() {
            return (self.spend_public, self.view_public());
        }
        let m = subaddress_secret_key(&self.view_secret, index);
        // All three were checked at construction or are reduced hashes.
        let (Ok(m), Ok(a), Ok(b)) = (
            scalar_from_bytes(&m),
            scalar_from_bytes(&self.view_secret),
            point_from_bytes(&self.spend_public),
        ) else {
            return ([0u8; 32], [0u8; 32]);
        };
        let d = EdwardsPoint::mul_base(&m).add(&b);
        (d.compress(), d.mul(&a).compress())
    }

    /// The address of the subaddress `index`: a
    /// [`Subaddress`](super::AddressKind::Subaddress), or the standard
    /// address for `(0, 0)`.
    pub fn subaddress(&self, network: Network, index: SubaddressIndex) -> Address {
        let (spend, view) = self.subaddress_keys(index);
        if index.is_main() {
            Address::standard(network, spend, view)
        } else {
            Address::subaddress(network, spend, view)
        }
    }
}

/// The full keys of an account: the secret spend and view keys.
///
/// Both are wiped when the value is dropped.
#[derive(Clone)]
pub struct AccountKeys {
    spend_secret: Zeroizing<[u8; 32]>,
    view: ViewKeys,
}

impl core::fmt::Debug for AccountKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AccountKeys")
            .field("spend_public", &self.view.spend_public)
            .finish_non_exhaustive()
    }
}

impl AccountKeys {
    /// The keys of the deterministic wallet with this secret spend key: the
    /// view key is `Hs(spend_secret)`.
    ///
    /// Fails with [`Error::CryptoNote`] if `spend_secret` is not a reduced
    /// scalar; use [`from_seed`](Self::from_seed) for arbitrary bytes.
    pub fn from_spend_secret(spend_secret: &[u8; 32]) -> Result<Self, Error> {
        let view_secret = derive_view_secret_key(spend_secret);
        Self::from_secret_keys(spend_secret, &view_secret)
    }

    /// The keys of the deterministic wallet with this 32-byte seed (what a
    /// 25-word mnemonic encodes): the spend key is the seed reduced modulo
    /// the group order, the view key `Hs(spend_secret)`.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, Error> {
        let spend_secret = Zeroizing::new(sc_reduce32(seed));
        Self::from_spend_secret(&spend_secret)
    }

    /// The keys of a wallet whose view key is not derived from its spend key.
    ///
    /// Fails with [`Error::CryptoNote`] if either is not a reduced scalar.
    pub fn from_secret_keys(
        spend_secret: &[u8; 32],
        view_secret: &[u8; 32],
    ) -> Result<Self, Error> {
        let spend = scalar_from_bytes(spend_secret)?;
        let spend_public = EdwardsPoint::mul_base(&spend).compress();
        Ok(AccountKeys {
            spend_secret: Zeroizing::new(*spend_secret),
            view: ViewKeys::new(view_secret, &spend_public)?,
        })
    }

    /// The secret spend key.
    pub fn spend_secret(&self) -> &[u8; 32] {
        &self.spend_secret
    }

    /// The secret view key.
    pub fn view_secret(&self) -> &[u8; 32] {
        self.view.view_secret()
    }

    /// The public spend key.
    pub fn spend_public(&self) -> &[u8; 32] {
        self.view.spend_public()
    }

    /// The public view key.
    pub fn view_public(&self) -> [u8; 32] {
        self.view.view_public()
    }

    /// The view-only key set of the account.
    pub fn view_keys(&self) -> &ViewKeys {
        &self.view
    }

    /// The main address of the account.
    pub fn address(&self, network: Network) -> Address {
        self.view.address(network)
    }

    /// The address of the subaddress `index` (see [`ViewKeys::subaddress`]).
    pub fn subaddress(&self, network: Network, index: SubaddressIndex) -> Address {
        self.view.subaddress(network, index)
    }

    /// The secret spend key of the subaddress `index`: `b + m`, or `b`
    /// itself for `(0, 0)`.
    pub fn subaddress_spend_secret(&self, index: SubaddressIndex) -> Zeroizing<[u8; 32]> {
        if index.is_main() {
            return self.spend_secret.clone();
        }
        let m = subaddress_secret_key(self.view.view_secret(), index);
        match (scalar_from_bytes(&m), scalar_from_bytes(&self.spend_secret)) {
            (Ok(m), Ok(b)) => Zeroizing::new(b.add(&m).to_bytes()),
            // Both are reduced by construction.
            _ => Zeroizing::new([0u8; 32]),
        }
    }
}
