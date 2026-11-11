//! Zano: addresses, keys and transactions, built on the primitives the
//! CryptoNote family shares ([`cryptonote`](crate::cryptonote)).
//!
//! It started as a port of the Go library `KarpelesLab/zanolib` and now
//! follows Zano's C++ sources, checked against the main network's
//! transactions of every era and against the C++ itself: what it signs,
//! Zano's verifiers accept, and what Zano's `construct_tx` signs it
//! verifies and scans (see [Compatibility](#compatibility)). It covers
//! what an offline signer, a deposit scanner and a verifier need:
//!
//! - **Addresses** ([`Address`], [`AddressType`]): standard, integrated,
//!   auditable and auditable integrated, with flags and payment ids.
//! - **Keys** ([`Wallet`]): the secret spend key and the view key derived
//!   from it, view-only wallets, auditable accounts.
//! - **Scanning**: [`Wallet::key_derivation`] and [`Wallet::scan_output`]
//!   tell whether an output belongs to the wallet and decode its amount and
//!   asset — the native coin or any other — with the view key only and
//!   without a heap; `Wallet::scan_tx` does a whole `Transaction`, and
//!   recovers the payment id of the transaction and of each output, and
//!   its comments; `Wallet::decrypt_payload_items` decrypts everything a
//!   transaction encrypts for its recipient, or for its sender.
//! - **Signing**: `Wallet::parse_ftp` reads the unsigned transaction a
//!   view-only `simplewallet` prepares (`FinalizeTxParam`),
//!   `Wallet::sign` builds and signs it as `construct_tx` does, and
//!   `FinalizedTx::encrypt` gives the blob that wallet broadcasts.
//!   `Wallet::build_transfer` does without the wallet, from scanned outputs
//!   and rings of decoys; `Wallet::build_transfer_at_height` picks the
//!   transaction version of the height.
//! - **Verification**: `Transaction::verify` checks a whole transaction of
//!   any version given the outputs its rings refer to — the signatures of
//!   its inputs, the asset surjection, range and balance proofs, the
//!   proofs of an asset operation, and the stake proof of a
//!   proof-of-stake block (`StakeContext`).
//! - **Proofs**, each with its verifier: the CLSAG-GGX ring signature
//!   (`generate_clsag_ggx`), the CryptoNote ring signature of transparent
//!   inputs (`generate_ring_signature`), Bulletproofs+ range proofs
//!   (`generate_bpp`), the BGE one-out-of-many proof of asset surjection
//!   (`generate_bge_proof`), the vector UG aggregation proof and the
//!   double Schnorr proof of the balance
//!   (`generate_vector_ug_aggregation_proof`,
//!   `generate_double_schnorr_sig`), the Schnorr signature of asset owners
//!   (`generate_schnorr_sig`); and, to verify only, the Zarcanum
//!   proof-of-stake proof with its range proof and ring signature
//!   (`verify_zarcanum_proof`, `verify_bppe`, `verify_clsag_ggxxg`).
//! - **Assets**: asset operations (`AssetDescriptorOperation`), the
//!   derivation of an asset id (`AssetDescriptorBase::asset_id`), and
//!   `Transaction::verify_asset_operation`.
//! - **Wire formats**: `Transaction` and its `Variant`s for versions 0 to
//!   4, the wallet blobs, ChaCha8 and ChaCha20 ([`chacha8`], [`chacha20`])
//!   and epee portable storage (`epee`).
//!
//! The network client (`zanorpc`) and threshold signing (`zanompc`) of
//! zanolib are not ported; `InputSigner` is the seam the latter plugs
//! into.
//!
//! ```
//! use outscript::zano::{Address, AddressType, Wallet};
//!
//! let secret: [u8; 32] = core::array::from_fn(|i| if i == 0 { 1 } else { 0 });
//! let wallet = Wallet::from_spend_secret(&secret, 0)?;
//! let address = wallet.address();
//! assert_eq!(address.address_type(), AddressType::Standard);
//!
//! // The text form needs no heap: it goes into a caller buffer, or through
//! // `Display`.
//! let mut buf = [0u8; outscript::zano::MAX_ADDRESS_LEN];
//! let n = address.encode_to_slice(&mut buf)?;
//! let text = core::str::from_utf8(&buf[..n]).unwrap();
//! assert!(text.starts_with("Zx"));
//! assert_eq!(text.parse::<Address>()?, address);
//! # Ok::<(), outscript::Error>(())
//! ```
//!
//! # Features
//!
//! Addresses, keys, ChaCha8 and single-output scanning work without a heap.
//! Everything else — serialization, proofs, signing, whole-transaction
//! scanning, epee, the JSON view-wallet description — needs `alloc`.
//!
//! # Randomness
//!
//! The crate has no random number generator. Whatever draws random values
//! takes an `rng: &mut dyn FnMut(&mut [u8])`, which must fill the buffer it
//! is given from a cryptographically secure source (and never repeat its
//! output: the nonces of the signatures come from it). Random scalars are 64
//! bytes reduced modulo the group order, as in zanolib; given the same bytes
//! in the same order, signing produces the same transaction as zanolib does.
//!
//! # Secrets
//!
//! Secret keys are reduced scalars, and are wiped when the values that hold
//! them are dropped ([`Wallet`], `TxSource`, `FinalizedTx`,
//! `TransferInput`, ...). Scalar arithmetic and every multiplication by a
//! secret scalar are `purecrypto`'s constant-time ones; in the range proof
//! the bits of the amounts select points without branching. Verification,
//! and the operations on public values during signing (challenges, the
//! decoys' side of a ring, hashing to points), are variable-time.
//!
//! # Untrusted input
//!
//! Parsing — addresses, transactions, wallet blobs, portable storage —
//! never panics, and never reserves more memory than the input justifies: a
//! count is checked against the bytes left before anything is allocated,
//! and nesting is bounded. Points and scalars of a transaction are kept as
//! the bytes on the wire and checked where they are used; verification
//! returns `false` for anything malformed.
//!
//! # Compatibility
//!
//! The transaction formats are those of Zano's main network up to hard
//! fork 7: transaction versions 0 and 1 (transparent, before hard fork 4 at
//! block 2 555 000), 2 (Zarcanum), 3 (hard fork 5, block 3 076 400) and 4
//! (hard forks 6 and 7, block 3 833 000), which `mainnet_tx_version` tells
//! from a height. The gateway types of hard fork 6, which the main network
//! never accepted, are parsed and nothing more.
//!
//! The wallet blobs are not versioned and follow the wallet's C++
//! structures, in three layouts (`FtpFormat`): that of Zano 2.0 and
//! 2.1.0.382 to 2.1.7.424, that of 2.1.8.428 to 2.1.19.477, and that of
//! Zano 2.2. Parsing tells them apart.
//!
//! What a transaction encrypts for its recipient (comments, flagged
//! service attachments, payer and receiver) is encrypted with ChaCha8 in
//! versions 2 and 3 and, from hard fork 6 on (version 4), with ChaCha20
//! under a key from a Keccak sponge; both are built and read.
//!
//! Beside the fixtures of zanolib and of the main network, the tests hold
//! this module to Zano's C++ (2.2.3.608), through a harness linked with
//! its libraries (`testdata/zano_harness.cpp`):
//!
//! - the payload encryption of both eras gives the bytes
//!   `encrypt_payload_items` gives, and reads back what
//!   `decrypt_payload_items` reads;
//! - the wallet blobs of the three layouts, serialized by the C++ from the
//!   structures of the releases that had them, parse to the same field
//!   values and serialize back to the same bytes;
//! - transactions of version 2, 3 and 4 signed here — confidential and
//!   transparent inputs, the native coin and another asset, payment ids,
//!   encrypted entries — pass `validate_tx_semantic`, the verification of
//!   each input's signature and of the range, balance and asset surjection
//!   proofs, and are scanned by `lookup_acc_outs` as they are here;
//! - the same unsigned transactions signed by `construct_tx` verify and
//!   scan here.
//!
//! No transaction signed here has been sent to the network, and the chain
//! rules beyond those checks (unlock times, mixin counts, fees, sizes)
//! are left to the caller.
//!
//! Where zanolib and Zano disagree, this module follows Zano:
//!
//! - varints are the standard ones (zanolib writes 128 as the single byte
//!   `0x80`), and the output index of a `ref_by_id` is one;
//! - the range proof is right for three and more outputs, and the
//!   surjection proof for more than four inputs (zanolib's are not);
//! - an output's mixing attribute comes from the unsigned transaction;
//! - the concealing point of a scanned output is compared after the
//!   multiplication by 8;
//! - signing sorts the rings, shuffles the outputs when asked, copies and
//!   encrypts the extra entries and attachments, and shows the bare native
//!   asset id where `construct_tx` does;
//! - a payment id attachment encrypted for someone else is not reported,
//!   and an output's encrypted payment id of zero means none.
//!
//! What signing does not build is listed with `Wallet::sign`, what
//! verification leaves to the chain with `Transaction::verify`.

mod address;
#[cfg(feature = "alloc")]
mod asset;
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
mod keccak;
#[cfg(feature = "alloc")]
mod nlsag;
#[cfg(feature = "alloc")]
mod payload;
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
mod tx_ext;
#[cfg(feature = "alloc")]
mod verify;
#[cfg(feature = "alloc")]
mod view;
mod wallet;
#[cfg(feature = "alloc")]
mod zarcanum;

#[cfg(test)]
mod tests;

pub use address::{
    ADDRESS_FLAG_AUDITABLE, Address, AddressType, MAX_ADDRESS_LEN, MAX_PAYMENT_ID_LEN, PaymentId,
};
pub use chacha8::{
    chacha8, chacha8_crypt, chacha8_generate_key, chacha20, chacha20_generate_key_and_iv,
};
pub use crypto::{
    NATIVE_COIN_ASSET_ID, POINT_G, POINT_H, POINT_H2, POINT_U, POINT_X, derivation_hint,
    generator_h, generator_h2, generator_u, generator_x, key_image, scalar_1div8,
};
pub use scan::{
    PAYMENT_ID_SERVICE_ID, ReceivedOutput, TX_SERVICE_ATTACHMENT_DEFLATE_BODY,
    TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF, TX_SERVICE_ATTACHMENT_ENCRYPT_BODY,
    TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE, TxOutZarcanum, crypt_output_payment_id,
    crypt_payment_id,
};
pub use wallet::Wallet;

#[cfg(all(feature = "alloc", feature = "secp256k1"))]
pub use asset::verify_eth_signature;
#[cfg(feature = "alloc")]
pub use bge::{BGE_MAX_RING_SIZE, generate_bge_proof, verify_bge_proof};
#[cfg(feature = "alloc")]
pub use bpp::{BPP_MAX_VALUES, generate_bpp, verify_bpp};
#[cfg(feature = "alloc")]
pub use clsag::{ClsagGgxInput, generate_clsag_ggx, verify_clsag_ggx};
#[cfg(feature = "alloc")]
pub use ftp::{
    FinalizeTxParam, FinalizedTx, FtpFormat, KeyImageIndex,
    TX_DEST_FLAG_EXPLICIT_AMOUNT_TO_PROVIDE, TX_DEST_FLAG_EXPLICIT_NATIVE_ASSET_ID,
    TX_DEST_FLAG_ZERO_AMOUNT_BLINDING_MASK, TxDest, TxDestHtlcOut, TxSource, TxSourceOutputEntry,
};
#[cfg(feature = "alloc")]
pub use nlsag::{
    generate_ring_signature, generate_schnorr_sig, verify_ring_signature, verify_schnorr_sig,
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
    HARDFORK_04_ZARCANUM, HARDFORK_05, HARDFORK_06, HARDFORK_07, MAINNET_HARDFORK_HEIGHTS, RefById,
    SignedParts, TRANSACTION_VERSION_INITIAL, TRANSACTION_VERSION_POST_HF4,
    TRANSACTION_VERSION_POST_HF5, TRANSACTION_VERSION_POST_HF6, TRANSACTION_VERSION_PRE_HF4,
    TX_FLAG_SIGNATURE_MODE_SEPARATE, Transaction, TxCryptoChecksum, TxInToKey, TxInZcInput,
    TxServiceAttachment, UgAggProof, Variant, ZcAssetSurjectionProof, ZcBalanceProof,
    ZcOutsRangeProof, ZcSig, mainnet_hardfork_id, mainnet_tx_version, tx_version_for_hardfork,
};
#[cfg(feature = "alloc")]
pub use tx_ext::{
    ASSET_DESCRIPTOR_BASE_HF4_VER, ASSET_DESCRIPTOR_BASE_HF5_VER, ASSET_DESCRIPTOR_OPERATION_EMIT,
    ASSET_DESCRIPTOR_OPERATION_HF4_VER, ASSET_DESCRIPTOR_OPERATION_HF5_VER,
    ASSET_DESCRIPTOR_OPERATION_PUBLIC_BURN, ASSET_DESCRIPTOR_OPERATION_REGISTER,
    ASSET_DESCRIPTOR_OPERATION_UPDATE, AccountPublicAddrOld, AssetDescriptorBase,
    AssetDescriptorOperation, AssetOperationProof, AssetOwnershipProof, AssetOwnershipProofEth,
    BppeSignature, ClsagGgxxgSig, ExtraAliasEntry, ExtraAliasEntryOld, GatewayAddressDescriptor,
    GatewayAddressOperation, GatewayOwnerKey, GatewaySignature, LinearCompositionProof, NlsagSig,
    SchnorrSig, TxInGateway, TxInMultisig, TxOutBare, TxOutGateway, TxOutMultisig, TxOutToKey,
    TxOutZarcanumHf6, ZarcanumSig, ZcGwBalanceProof,
};
#[cfg(feature = "alloc")]
pub use verify::{VerifyContext, VerifyError};
#[cfg(feature = "alloc")]
pub use view::ViewWalletData;
#[cfg(feature = "alloc")]
pub use zarcanum::{StakeContext, verify_bppe, verify_clsag_ggxxg, verify_zarcanum_proof};

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
