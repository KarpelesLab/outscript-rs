//! Zano: addresses, keys and transactions, built on the primitives the
//! CryptoNote family shares ([`cryptonote`](crate::cryptonote)).

mod address;
#[cfg(feature = "alloc")]
mod bge;
#[cfg(feature = "alloc")]
mod bpp;
mod chacha8;
#[cfg(feature = "alloc")]
mod clsag;
mod crypto;
#[cfg(feature = "alloc")]
pub mod epee;
#[cfg(feature = "alloc")]
mod ftp;
mod scan;
#[cfg(feature = "alloc")]
mod schnorr;
#[cfg(feature = "alloc")]
mod ser;
#[cfg(feature = "alloc")]
mod sign;
#[cfg(feature = "alloc")]
mod transfer;
#[cfg(feature = "alloc")]
mod tx;
#[cfg(feature = "alloc")]
mod view;
mod wallet;

#[cfg(test)]
mod tests;

pub use address::{
    ADDRESS_FLAG_AUDITABLE, Address, AddressType, MAX_ADDRESS_LEN, MAX_PAYMENT_ID_LEN, PaymentId,
};
pub use chacha8::{chacha8, chacha8_crypt, chacha8_generate_key};
pub use crypto::{
    NATIVE_COIN_ASSET_ID, POINT_G, POINT_H, POINT_H2, POINT_U, POINT_X, derivation_hint,
    generator_h, generator_h2, generator_u, generator_x, key_image, scalar_1div8,
};
pub use scan::{
    PAYMENT_ID_SERVICE_ID, ReceivedOutput, TX_SERVICE_ATTACHMENT_DEFLATE_BODY,
    TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF, TX_SERVICE_ATTACHMENT_ENCRYPT_BODY,
    TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE, TxOutZarcanum, crypt_payment_id,
};
pub use wallet::Wallet;

#[cfg(feature = "alloc")]
pub use bge::{BGE_MAX_RING_SIZE, generate_bge_proof, verify_bge_proof};
#[cfg(feature = "alloc")]
pub use bpp::{BPP_MAX_VALUES, generate_bpp, verify_bpp};
#[cfg(feature = "alloc")]
pub use clsag::{ClsagGgxInput, generate_clsag_ggx, verify_clsag_ggx};
#[cfg(feature = "alloc")]
pub use ftp::{
    FinalizeTxParam, FinalizedTx, KeyImageIndex, TxDest, TxDestHtlcOut, TxSource,
    TxSourceOutputEntry,
};
#[cfg(feature = "alloc")]
pub use scan::ScanResult;
#[cfg(feature = "alloc")]
pub use schnorr::{
    SchnorrGenerator, generate_double_schnorr_sig, generate_vector_ug_aggregation_proof,
    verify_double_schnorr_sig, verify_vector_ug_aggregation_proof,
};
#[cfg(feature = "alloc")]
pub use sign::{InputSigner, LocalInputSigner};
#[cfg(feature = "alloc")]
pub use transfer::{RingMember, TransferDest, TransferInput};
#[cfg(feature = "alloc")]
pub use tx::{
    AccountPublicAddr, BgeProof, BppSignature, ClsagGgxSig, DoubleSchnorrSig, ExtraAttachmentInfo,
    RefById, SignedParts, TRANSACTION_VERSION_INITIAL, TRANSACTION_VERSION_POST_HF4,
    TRANSACTION_VERSION_POST_HF5, TRANSACTION_VERSION_PRE_HF4, Transaction, TxCryptoChecksum,
    TxInToKey, TxInZcInput, TxServiceAttachment, UgAggProof, Variant, ZcAssetSurjectionProof,
    ZcBalanceProof, ZcOutsRangeProof, ZcSig,
};
#[cfg(feature = "alloc")]
pub use view::ViewWalletData;

/// Errors specific to Zano.
///
/// It converts into the crate's [`Error`](crate::Error) (as
/// [`Error::Zano`](crate::Error::Zano)), so `?` composes; so does the shared
/// [`cryptonote::Error`](crate::cryptonote::Error), which this module wraps
/// as [`Error::CryptoNote`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A CryptoNote primitive failed (base58, checksum, varint, an invalid
    /// point or scalar, a buffer too small).
    CryptoNote(crate::cryptonote::Error),
    /// The address prefix is not one of Zano's.
    UnknownAddressType,
    /// The address is too long, or its payload does not fit its kind.
    InvalidAddressLength,
    /// A payment id is longer than
    /// [`MAX_PAYMENT_ID_LEN`] bytes.
    PaymentIdTooLong,
    /// The wallet is view-only: the operation needs the secret spend key.
    ViewOnly,
    /// A key does not match the one it should (the spend key of the unsigned
    /// transaction, the view key of an export, the key of the output being
    /// spent), or is missing.
    KeyMismatch,
    /// An address is not the one of the keys it comes with.
    AddressMismatch,
    /// The serialized data ended early.
    UnexpectedEof,
    /// The serialized data has bytes left after the value.
    TrailingData,
    /// The serialized data holds a variant this module does not know (the
    /// binary format cannot skip it).
    UnsupportedVariant(u8),
    /// The serialized data is malformed (a bad header, a boolean that is
    /// neither 0 nor 1, a type the format does not allow there, ...).
    InvalidEncoding,
    /// The data nests deeper than this module accepts.
    TooDeep,
    /// A count or an index is larger than the operation supports.
    TooLarge,
    /// The transaction version is not one this module can build.
    UnsupportedVersion,
    /// The transaction needs something this module cannot build (an input
    /// that is not a confidential one, an output with several addresses,
    /// ...).
    Unsupported,
    /// A ring is empty, does not hold the real output, or is not usable.
    InvalidRing,
    /// A secret does not open the commitment or key it should.
    SecretMismatch,
    /// The inputs and outputs of a non-native asset do not balance.
    Unbalanced,
    /// The native outputs exceed the native inputs.
    InsufficientFunds,
    /// The transaction has no fee field.
    MissingFee,
    /// An output with the wallet's stealth address is not what the sender
    /// should have built.
    MalformedOutput,
    /// Text that should be hex is not, or has the wrong length.
    InvalidHex,
}

impl From<crate::cryptonote::Error> for Error {
    fn from(e: crate::cryptonote::Error) -> Self {
        Error::CryptoNote(e)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::CryptoNote(e) => return e.fmt(f),
            Error::UnknownAddressType => "unknown Zano address type",
            Error::InvalidAddressLength => "invalid Zano address length",
            Error::PaymentIdTooLong => "payment id too long",
            Error::ViewOnly => "view-only wallet (no secret spend key)",
            Error::KeyMismatch => "key mismatch",
            Error::AddressMismatch => "address does not match the keys",
            Error::UnexpectedEof => "unexpected end of data",
            Error::TrailingData => "trailing data",
            Error::UnsupportedVariant(tag) => {
                return write!(f, "unsupported variant tag {tag}");
            }
            Error::InvalidEncoding => "invalid encoding",
            Error::TooDeep => "data nested too deep",
            Error::TooLarge => "value too large",
            Error::UnsupportedVersion => "unsupported transaction version",
            Error::Unsupported => "unsupported transaction feature",
            Error::InvalidRing => "invalid ring",
            Error::SecretMismatch => "secret does not match its public value",
            Error::Unbalanced => "asset inputs and outputs do not balance",
            Error::InsufficientFunds => "insufficient native funds",
            Error::MissingFee => "transaction has no fee",
            Error::MalformedOutput => "malformed output",
            Error::InvalidHex => "invalid hex",
        })
    }
}

impl core::error::Error for Error {}
