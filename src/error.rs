//! The crate's error type.

/// Everything that can go wrong in outscript.
///
/// One type covers the interrelated parts of the crate (keys and scripts,
/// addresses, transactions, PSBTs), so `?` composes across them without
/// wrapping. The self-contained codecs keep their own small error types
/// ([`base58`](crate::base58), [`base64`](crate::base64),
/// [`bech32`](crate::bech32), `cbor`, `rlp`, `crypto::secp256k1` and
/// Solana's compact-u16), which convert into this one.
///
/// Each module re-exports this type, so `psbt::Error`, `btctx::Error` and
/// `outscript::Error` all name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    // --- malformed data ---
    /// The data ended in the middle of a value.
    UnexpectedEof,
    /// Bytes remain after the last complete value.
    TrailingData,
    /// The data does not have the expected structure.
    InvalidData,
    /// A value has the wrong length.
    InvalidLength,
    /// An integer is not minimally encoded.
    NonCanonical,
    /// A count or buffer exceeds the allowed maximum.
    TooLarge,
    /// A computation overflowed its integer type.
    Overflow,
    /// The output buffer is too small for the result.
    BufferTooSmall,

    // --- keys and signing ---
    /// The key type is not supported by this format.
    UnsupportedKeyType,
    /// The key is malformed or unusable for this operation.
    InvalidKey,
    /// A signature is malformed.
    InvalidSignature,
    /// The signature at this index does not verify.
    SignatureVerification(usize),
    /// Fewer signatures than required signers.
    MissingSignatures,
    /// The transaction carries no signature.
    NoSignature,
    /// The signer failed (see [`SignerError`](crate::crypto::SignerError)).
    Signer,
    /// A signing entry has no key.
    MissingKey,
    /// The signer does not expose an ECDSA public key.
    NoPublicKey,
    /// The signer's key is not involved in this input.
    KeyNotInvolved,
    /// The key is not one of the transaction's required signers.
    NotRequiredSigner,
    /// Public-key recovery failed.
    Recovery,

    // --- Cardano keys ---
    /// Derivation needs a chain code the key does not carry.
    NoChainCode,
    /// A hardened child cannot be derived from a public key.
    HardenedFromPublic,
    /// The public key is not a valid curve point.
    InvalidPoint,
    /// The master-key entropy was empty.
    EmptyEntropy,

    // --- scripts and addresses ---
    /// The format name is not a built-in output-script format.
    UnknownFormat,
    /// The format has no address form.
    UnsupportedFormat,
    /// The network is not supported for this operation.
    UnsupportedNetwork,
    /// The address belongs to a different network than the one requested.
    NetworkMismatch,
    /// The string is not a recognized address.
    InvalidAddress,
    /// The address checksum does not verify.
    BadChecksum,
    /// The base58 version byte, witness version or address type is not
    /// supported.
    UnsupportedAddressVersion(u8),
    /// The script bytes do not match their format.
    InvalidScript,
    /// The script type is not supported for this operation.
    UnsupportedScript,
    /// A spend needs a redeem or leaf script that was not provided.
    MissingScript,
    /// A P2SH input has no redeem script.
    MissingRedeemScript,
    /// The redeem script does not hash to the P2SH scriptPubKey.
    RedeemScriptMismatch,
    /// A P2WSH input has no witness script.
    MissingWitnessScript,
    /// The witness script does not hash to the P2WSH program.
    WitnessScriptMismatch,
    /// No standard witness script matches the key and the scriptPubKey.
    NoMatchingWitnessScript,

    // --- transactions ---
    /// The input index is out of range.
    InputIndex,
    /// The output index is out of range.
    OutputIndex,
    /// An index does not reference an addressable account.
    IndexOutOfRange,
    /// The number of signing entries does not match the number of inputs.
    KeyCount,
    /// The previous outputs do not match the inputs one to one.
    PrevOutCount,
    /// A taproot sighash needs the previous scriptPubKey of this input.
    MissingPrevScript(usize),
    /// The input has no UTXO information.
    MissingUtxo,
    /// The non-witness UTXO's txid does not match the spent outpoint.
    UtxoTxidMismatch,
    /// Only a witness UTXO is provided for a non-witness spend.
    WitnessUtxoForNonWitness,
    /// The sighash type is not supported.
    UnsupportedSighash,
    /// The spend scheme is not supported.
    UnsupportedScheme,
    /// The transaction type is not supported.
    UnsupportedTxType,
    /// The transaction is not signed.
    NotSigned,
    /// The signature's `v` value is invalid.
    InvalidV,
    /// The RLP list has the wrong number of fields for its type.
    InvalidFieldCount,
    /// The transaction has no inputs.
    NoInputs,
    /// The transaction has no outputs.
    NoOutputs,
    /// An output has an empty address.
    EmptyAddress,
    /// The message header counts are inconsistent with the account keys.
    InvalidHeader,
    /// The message is not a versioned message.
    NotVersioned,
    /// The message or transaction version is not supported.
    UnsupportedVersion(u8),

    // --- PSBT ---
    /// The data does not start with the PSBT magic.
    InvalidMagic,
    /// A map contains the same key twice.
    DuplicateKey,
    /// A record key has the wrong key data for its type.
    InvalidRecordKey,
    /// A record value is malformed for its key type.
    InvalidRecordValue,
    /// The global map has no unsigned transaction.
    MissingUnsignedTx,
    /// The unsigned transaction is malformed or already has signatures.
    InvalidUnsignedTx,
    /// The PSBT version is not 0.
    UnsupportedPsbtVersion,
    /// Not every input is finalized.
    NotFinalized,
    /// The PSBTs being combined are for different transactions.
    TxMismatch,

    // --- EVM ABI ---
    /// The ABI signature is not of the form `name(type,...)`.
    InvalidAbiSignature,
    /// The number of values does not match the number of ABI types.
    AbiArgumentCount,
    /// An ABI type is not supported.
    UnsupportedAbiType,
    /// A value's kind does not fit its ABI type.
    AbiValueMismatch,

    // --- Solana program-derived addresses ---
    /// More than 16 seeds were given.
    TooManySeeds,
    /// A seed is longer than 32 bytes.
    SeedTooLong,
    /// The derived address lies on the Ed25519 curve.
    AddressOnCurve,
    /// No bump seed produced a valid program address.
    PdaNotFound,

    // --- amounts ---
    /// The text is not a valid amount.
    InvalidAmount,
    /// The decimal amount has more than 8 fractional digits.
    TooManyDecimals,

    // --- codecs ---
    /// A base58 error.
    Base58(crate::base58::Error),
    /// A base64 error.
    Base64(crate::base64::Error),
    /// A bech32 or CashAddr error.
    Bech32(crate::bech32::Error),
    /// A secp256k1 error.
    #[cfg(feature = "secp256k1")]
    Secp256k1(crate::crypto::secp256k1::Error),
    /// A Solana compact-u16 error.
    #[cfg(feature = "solana")]
    CompactU16(crate::solana::CompactU16Error),
    /// A CBOR error.
    #[cfg(feature = "alloc")]
    Cbor(crate::cbor::Error),
    /// An RLP error.
    #[cfg(feature = "alloc")]
    Rlp(crate::rlp::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::UnexpectedEof => f.write_str("unexpected end of data"),
            Error::TrailingData => f.write_str("trailing data"),
            Error::InvalidData => f.write_str("malformed data"),
            Error::InvalidLength => f.write_str("invalid length"),
            Error::NonCanonical => f.write_str("non-canonical encoding"),
            Error::TooLarge => f.write_str("value exceeds the allowed maximum"),
            Error::Overflow => f.write_str("integer overflow"),
            Error::BufferTooSmall => f.write_str("output buffer too small"),
            Error::UnsupportedKeyType => f.write_str("key type not supported by this format"),
            Error::InvalidKey => f.write_str("invalid key"),
            Error::InvalidSignature => f.write_str("invalid signature"),
            Error::SignatureVerification(i) => write!(f, "signature {i} does not verify"),
            Error::MissingSignatures => f.write_str("missing signatures"),
            Error::NoSignature => f.write_str("transaction has no signature"),
            Error::Signer => f.write_str("signer failed"),
            Error::MissingKey => f.write_str("signing requires a key"),
            Error::NoPublicKey => f.write_str("signer does not expose an ECDSA public key"),
            Error::KeyNotInvolved => f.write_str("signer key is not involved in this input"),
            Error::NotRequiredSigner => f.write_str("key is not a required signer"),
            Error::Recovery => f.write_str("public-key recovery failed"),
            Error::NoChainCode => f.write_str("extended key has no chain code"),
            Error::HardenedFromPublic => {
                f.write_str("cannot derive a hardened child from a public key")
            }
            Error::InvalidPoint => f.write_str("invalid curve point"),
            Error::EmptyEntropy => f.write_str("empty entropy"),
            Error::UnknownFormat => f.write_str("unknown output-script format"),
            Error::UnsupportedFormat => f.write_str("format has no address form"),
            Error::UnsupportedNetwork => f.write_str("unsupported network"),
            Error::NetworkMismatch => f.write_str("address is for a different network"),
            Error::InvalidAddress => f.write_str("unsupported or malformed address"),
            Error::BadChecksum => f.write_str("bad checksum"),
            Error::UnsupportedAddressVersion(v) => {
                write!(f, "unsupported address version {v:#x}")
            }
            Error::InvalidScript => f.write_str("invalid script for this format"),
            Error::UnsupportedScript => f.write_str("unsupported script type"),
            Error::MissingScript => f.write_str("missing redeem or leaf script"),
            Error::MissingRedeemScript => f.write_str("P2SH input has no redeem script"),
            Error::RedeemScriptMismatch => {
                f.write_str("redeem script does not match the scriptPubKey")
            }
            Error::MissingWitnessScript => f.write_str("P2WSH input has no witness script"),
            Error::WitnessScriptMismatch => {
                f.write_str("witness script does not match the witness program")
            }
            Error::NoMatchingWitnessScript => {
                f.write_str("no standard witness script matches the input")
            }
            Error::InputIndex => f.write_str("input index out of range"),
            Error::OutputIndex => f.write_str("output index out of range"),
            Error::IndexOutOfRange => f.write_str("account index out of range"),
            Error::KeyCount => f.write_str("signing needs one entry per input"),
            Error::PrevOutCount => f.write_str("previous outputs must match the inputs"),
            Error::MissingPrevScript(i) => write!(f, "input {i} is missing its previous script"),
            Error::MissingUtxo => f.write_str("input has no UTXO information"),
            Error::UtxoTxidMismatch => {
                f.write_str("non-witness UTXO does not match the input txid")
            }
            Error::WitnessUtxoForNonWitness => {
                f.write_str("witness UTXO provided for a non-witness input")
            }
            Error::UnsupportedSighash => f.write_str("unsupported sighash type"),
            Error::UnsupportedScheme => f.write_str("unsupported spend scheme"),
            Error::UnsupportedTxType => f.write_str("unsupported transaction type"),
            Error::NotSigned => f.write_str("transaction is not signed"),
            Error::InvalidV => f.write_str("invalid signature v value"),
            Error::InvalidFieldCount => f.write_str("wrong number of transaction fields"),
            Error::NoInputs => f.write_str("transaction has no inputs"),
            Error::NoOutputs => f.write_str("transaction has no outputs"),
            Error::EmptyAddress => f.write_str("output has an empty address"),
            Error::InvalidHeader => f.write_str("invalid message header"),
            Error::NotVersioned => f.write_str("not a versioned message"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported version {v}"),
            Error::InvalidMagic => f.write_str("not a PSBT (bad magic)"),
            Error::DuplicateKey => f.write_str("duplicate key in PSBT map"),
            Error::InvalidRecordKey => f.write_str("invalid PSBT key"),
            Error::InvalidRecordValue => f.write_str("invalid PSBT value"),
            Error::MissingUnsignedTx => f.write_str("PSBT has no unsigned transaction"),
            Error::InvalidUnsignedTx => f.write_str("invalid PSBT unsigned transaction"),
            Error::UnsupportedPsbtVersion => f.write_str("unsupported PSBT version"),
            Error::NotFinalized => f.write_str("PSBT is not fully finalized"),
            Error::TxMismatch => f.write_str("PSBTs are for different transactions"),
            Error::InvalidAbiSignature => f.write_str("invalid ABI signature"),
            Error::AbiArgumentCount => f.write_str("wrong number of ABI arguments"),
            Error::UnsupportedAbiType => f.write_str("unsupported ABI type"),
            Error::AbiValueMismatch => f.write_str("value does not fit its ABI type"),
            Error::TooManySeeds => f.write_str("too many seeds: maximum 16"),
            Error::SeedTooLong => f.write_str("seed too long: maximum 32 bytes"),
            Error::AddressOnCurve => f.write_str("derived address is on the Ed25519 curve"),
            Error::PdaNotFound => f.write_str("could not find valid program address"),
            Error::InvalidAmount => f.write_str("invalid amount"),
            Error::TooManyDecimals => f.write_str("amount has more than 8 decimals"),
            Error::Base58(e) => e.fmt(f),
            Error::Base64(e) => e.fmt(f),
            Error::Bech32(e) => e.fmt(f),
            #[cfg(feature = "secp256k1")]
            Error::Secp256k1(e) => e.fmt(f),
            #[cfg(feature = "solana")]
            Error::CompactU16(e) => e.fmt(f),
            #[cfg(feature = "alloc")]
            Error::Cbor(e) => e.fmt(f),
            #[cfg(feature = "alloc")]
            Error::Rlp(e) => e.fmt(f),
        }
    }
}

impl core::error::Error for Error {}

impl From<crate::base58::Error> for Error {
    fn from(e: crate::base58::Error) -> Self {
        match e {
            crate::base58::Error::BufferTooSmall => Error::BufferTooSmall,
            e => Error::Base58(e),
        }
    }
}

impl From<crate::base64::Error> for Error {
    fn from(e: crate::base64::Error) -> Self {
        match e {
            crate::base64::Error::BufferTooSmall => Error::BufferTooSmall,
            e => Error::Base64(e),
        }
    }
}

impl From<crate::bech32::Error> for Error {
    fn from(e: crate::bech32::Error) -> Self {
        match e {
            crate::bech32::Error::BufferTooSmall => Error::BufferTooSmall,
            e => Error::Bech32(e),
        }
    }
}

#[cfg(feature = "secp256k1")]
impl From<crate::crypto::secp256k1::Error> for Error {
    fn from(e: crate::crypto::secp256k1::Error) -> Self {
        Error::Secp256k1(e)
    }
}

#[cfg(feature = "solana")]
impl From<crate::solana::CompactU16Error> for Error {
    fn from(e: crate::solana::CompactU16Error) -> Self {
        Error::CompactU16(e)
    }
}

#[cfg(feature = "alloc")]
impl From<crate::cbor::Error> for Error {
    fn from(e: crate::cbor::Error) -> Self {
        Error::Cbor(e)
    }
}

#[cfg(feature = "alloc")]
impl From<crate::rlp::Error> for Error {
    fn from(e: crate::rlp::Error) -> Self {
        Error::Rlp(e)
    }
}

impl From<crate::crypto::SignerError> for Error {
    fn from(_: crate::crypto::SignerError) -> Self {
        Error::Signer
    }
}
