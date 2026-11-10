//! Wallet keys: the spend and view key pairs of a Zano account.

use core::fmt;

use purecrypto::zeroize::Zeroizing;

use crate::cryptonote::{
    EdwardsPoint, Scalar, derive_view_secret_key, point_from_bytes, scalar_from_bytes,
};

use super::address::{ADDRESS_FLAG_AUDITABLE, Address};
use super::{Error, crypto};

/// The keys of a Zano account.
///
/// A full wallet holds the secret spend key, from which Zano derives the
/// secret view key (`Hs(spend_secret)`, without clamping). A view-only wallet
/// holds the secret view key and the public spend key: it can find and decode
/// incoming outputs, but cannot sign.
///
/// The secret keys are wiped when the wallet is dropped.
///
/// ```
/// use outscript::zano::Wallet;
///
/// let mut secret = [0u8; 32];
/// secret[0] = 1;
/// let wallet = Wallet::from_spend_secret(&secret, 0)?;
/// assert!(!wallet.is_view_only());
///
/// // The watch-only half: the secret view key and the public spend key.
/// let watch = Wallet::view_only(wallet.view_secret_key(), wallet.spend_public_key(), 0)?;
/// assert!(watch.is_view_only());
/// assert_eq!(watch.address(), wallet.address());
/// # Ok::<(), outscript::Error>(())
/// ```
#[derive(Clone)]
pub struct Wallet {
    spend_secret: Option<Zeroizing<[u8; 32]>>,
    view_secret: Zeroizing<[u8; 32]>,
    spend_public: [u8; 32],
    view_public: [u8; 32],
    flags: u8,
}

impl Wallet {
    /// A full wallet from its secret spend key (what Zano's `spendkey`
    /// command shows), deriving the view key the way Zano does.
    ///
    /// `flags` is `0` for a normal account and
    /// [`ADDRESS_FLAG_AUDITABLE`] for an auditable one.
    ///
    /// Fails with [`Error::CryptoNote`] (`InvalidScalar`) if `spend_secret`
    /// is not a reduced scalar.
    pub fn from_spend_secret(spend_secret: &[u8; 32], flags: u8) -> Result<Self, Error> {
        let spend = scalar_from_bytes(spend_secret)?;
        let view_secret = derive_view_secret_key(spend_secret);
        let view = scalar_from_bytes(&view_secret)?;
        Ok(Wallet {
            spend_secret: Some(Zeroizing::new(*spend_secret)),
            spend_public: EdwardsPoint::mul_base(&spend).compress(),
            view_public: EdwardsPoint::mul_base(&view).compress(),
            view_secret,
            flags,
        })
    }

    /// A new wallet, with a spend key drawn from `rng`: 64 bytes, reduced
    /// modulo the group order.
    ///
    /// This crate has no random number generator: `rng` must fill the buffer
    /// it is given from a cryptographically secure source.
    pub fn generate(rng: &mut dyn FnMut(&mut [u8]), flags: u8) -> Result<Self, Error> {
        let secret = Zeroizing::new(crypto::random_scalar(rng).to_bytes());
        Self::from_spend_secret(&secret, flags)
    }

    /// A view-only wallet, from the secret view key and the public spend key
    /// (what a Zano watch-only wallet exports).
    ///
    /// Fails with [`Error::CryptoNote`] if `view_secret` is not a reduced
    /// scalar (`InvalidScalar`) or `spend_public` is not a point
    /// (`InvalidPoint`).
    pub fn view_only(
        view_secret: &[u8; 32],
        spend_public: &[u8; 32],
        flags: u8,
    ) -> Result<Self, Error> {
        let view = scalar_from_bytes(view_secret)?;
        point_from_bytes(spend_public)?;
        Ok(Wallet {
            spend_secret: None,
            view_secret: Zeroizing::new(*view_secret),
            spend_public: *spend_public,
            view_public: EdwardsPoint::mul_base(&view).compress(),
            flags,
        })
    }

    /// Whether the wallet has no secret spend key (it can scan, not sign).
    pub fn is_view_only(&self) -> bool {
        self.spend_secret.is_none()
    }

    /// The flags of the account.
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Whether the account is auditable.
    pub fn is_auditable(&self) -> bool {
        self.flags & ADDRESS_FLAG_AUDITABLE != 0
    }

    /// The secret spend key, unless the wallet is view-only.
    pub fn spend_secret_key(&self) -> Option<&[u8; 32]> {
        self.spend_secret.as_deref()
    }

    /// The secret view key.
    pub fn view_secret_key(&self) -> &[u8; 32] {
        &self.view_secret
    }

    /// The public spend key.
    pub fn spend_public_key(&self) -> &[u8; 32] {
        &self.spend_public
    }

    /// The public view key.
    pub fn view_public_key(&self) -> &[u8; 32] {
        &self.view_public
    }

    /// The address of the account.
    pub fn address(&self) -> Address {
        Address::new(self.spend_public, self.view_public, self.flags)
    }

    /// The secret view key as a scalar.
    pub(crate) fn view_scalar(&self) -> Result<Scalar, Error> {
        crypto::scalar(&self.view_secret)
    }

    /// The secret spend key as a scalar; [`Error::ViewOnly`] without one.
    #[cfg(feature = "alloc")]
    pub(crate) fn spend_scalar(&self) -> Result<Scalar, Error> {
        crypto::scalar(self.spend_secret.as_deref().ok_or(Error::ViewOnly)?)
    }
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("spend_public", &self.spend_public)
            .field("view_public", &self.view_public)
            .field("flags", &self.flags)
            .field("view_only", &self.is_view_only())
            .finish_non_exhaustive()
    }
}
