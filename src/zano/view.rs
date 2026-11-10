//! A JSON description of a view-only wallet, for handing to a scanner.

use purecrypto::zeroize::{Zeroize, Zeroizing};
use serde::{Deserialize, Serialize};

use crate::prelude::*;

use super::{Address, Error, Wallet};

fn is_zero(flags: &u8) -> bool {
    *flags == 0
}

/// What a scanner needs to watch a wallet: the secret view key, the public
/// spend key (given directly or through the address) and the block height
/// to resume from. Keys are lowercase hex.
///
/// The secret view key is wiped when the value is dropped.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ViewWalletData {
    /// The address of the wallet; an alternative to `spend_public_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The public spend key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend_public_key: Option<String>,
    /// The public view key: optional, and checked against the secret one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_public_key: Option<String>,
    /// The secret view key.
    pub view_secret_key: String,
    /// The account flags
    /// ([`ADDRESS_FLAG_AUDITABLE`](super::ADDRESS_FLAG_AUDITABLE)); with an
    /// address and no `spend_public_key`, the flags of the address are used.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub flags: u8,
    /// The block height to scan from.
    #[serde(default)]
    pub start_height: u64,
}

impl Drop for ViewWalletData {
    fn drop(&mut self) {
        self.view_secret_key.zeroize();
    }
}

fn key_from_hex(text: &str) -> Result<[u8; 32], Error> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(text, &mut key).map_err(|_| Error::InvalidHex)?;
    Ok(key)
}

impl ViewWalletData {
    /// The view-only wallet this describes.
    ///
    /// Fails with [`Error::InvalidHex`], [`Error::KeyMismatch`] when there is
    /// neither an address nor a spend key or when `view_public_key` is not
    /// the secret key's, [`Error::AddressMismatch`] when the address is not
    /// the keys', and the errors of [`Address::parse`] and
    /// [`Wallet::view_only`].
    pub fn load(&self) -> Result<Wallet, Error> {
        let view_secret = Zeroizing::new(key_from_hex(&self.view_secret_key)?);
        let address = self.address.as_deref().map(Address::parse).transpose()?;
        let (spend_public, flags) = match (&self.spend_public_key, &address) {
            (Some(key), _) => (key_from_hex(key)?, self.flags),
            (None, Some(address)) => (*address.spend_key(), address.flags()),
            (None, None) => return Err(Error::KeyMismatch),
        };
        let wallet = Wallet::view_only(&view_secret, &spend_public, flags)?;
        if let Some(view_public) = &self.view_public_key
            && key_from_hex(view_public)? != *wallet.view_public_key()
        {
            return Err(Error::KeyMismatch);
        }
        if address.is_some_and(|address| address != wallet.address()) {
            return Err(Error::AddressMismatch);
        }
        Ok(wallet)
    }
}

impl Wallet {
    /// The view-only description of this wallet, for a scanner that starts
    /// at `start_height`. It holds the secret view key.
    pub fn export_view(&self, start_height: u64) -> ViewWalletData {
        ViewWalletData {
            address: Some(self.address().to_string()),
            spend_public_key: Some(hex::encode(self.spend_public_key())),
            view_public_key: Some(hex::encode(self.view_public_key())),
            view_secret_key: hex::encode(self.view_secret_key()),
            flags: self.flags(),
            start_height,
        }
    }
}
