//! outscript generates potential output scripts for a given public key.
//!
//! It supports Bitcoin and Bitcoin-like cryptocurrency output script formats
//! (P2PKH, P2SH, P2WPKH, P2WSH, P2PK, P2TR, etc.), EVM-based networks (Ethereum
//! and compatible chains), and other blockchains such as Litecoin, Dogecoin,
//! Namecoin, Monacoin, Electraproto, Dash, Bitcoin Cash, Massa, Solana and
//! Cardano.
//!
//! This is a Rust port of the Go library `github.com/KarpelesLab/outscript`. All
//! cryptography is provided by the `purecrypto` crate.
//!
//! # Errors
//!
//! Everything in the crate reports failures as [`Error`], which each module
//! re-exports (`psbt::Error`, `btctx::Error` and `outscript::Error` are the
//! same type), so `?` composes across modules. The self-contained codecs
//! ([`base58`], [`base64`], [`bech32`], `bcur`, `bbqr`, `cbor`, `rlp`,
//! `crypto::secp256k1` and Solana's compact-u16) keep their own
//! small error types, which convert into [`Error`].
//!
//! # Secrets
//!
//! `SecpPrivateKey` and `CardanoExtendedKey` wipe their
//! key material when dropped, and implement [`crypto::Zeroize`] to scrub it
//! earlier. Signing and derivation wipe the secret-derived buffers they create
//! (nonces, HMAC state, PBKDF2 output), and `CardanoExtendedKey::bytes` returns
//! a [`crypto::Zeroizing`] buffer. Seeds and key bytes you pass in by reference
//! remain yours to wipe: wrap them in [`crypto::Zeroizing`].
//!
//! # Features
//!
//! Chains are opt-in. Each chain feature enables its modules, output-script
//! formats and address codecs, and pulls in only the curve arithmetic it
//! needs from `purecrypto`; all of them are on by default.
//!
//! - `bitcoin`: Bitcoin and Bitcoin-like networks (Litecoin, Dogecoin,
//!   Namecoin, Monacoin, Dash, Bitcoin Cash, Electraproto) — scripts,
//!   addresses, `btcraw`, `psbt`, `taproot` (script trees and control
//!   blocks), `btcguess`, `BtcAmount` and (with `alloc`) `BtcTx` and block
//!   rewards. Implies `secp256k1`.
//! - `evm`: EIP-55 addresses, `evmraw`, `evmabi` and (with `alloc`)
//!   `EvmTx`. Implies `secp256k1`.
//! - `solana`: addresses, program-derived addresses and (with `alloc`)
//!   `SolanaTx`. Implies `ed25519`.
//! - `cardano`: Shelley addresses, BIP32-Ed25519 derivation and (with
//!   `alloc`) `CardanoTx`. Implies `ed25519`.
//! - `massa`: addresses. Implies `ed25519`.
//! - `secp256k1` / `ed25519`: the raw [`crypto`] helpers and the matching
//!   [`PubKey`] variant, without any chain.
//!
//! So are the transports, which move PSBTs and other payloads between devices
//! as text, usually shown as QR codes (rendering and scanning those is not
//! this crate's business). They need no chain, and are on by default:
//!
//! - `bcur`: Uniform Resources (`ur:crypto-psbt/...`) — bytewords and
//!   single-part URs, and (with `alloc`) multi-part fountain encoding and
//!   decoding.
//! - `bbqr`: BBQr (`B$ZP0500...`) — headers, hex/base32 parts and compression,
//!   and (with `alloc`) splitting and joining.
//!
//! The runtime environment is selected separately:
//!
//! - `std` (default): implies `alloc`, and adds `std::io` adapters
//!   (`BtcVarInt::read_from`/`write_to`, `BtcTx::read_from`).
//! - `alloc`: the full API on `no_std` targets with a global allocator —
//!   `Out`/`Script`, the `BtcTx`/`EvmTx`/`SolanaTx`/`CardanoTx` builders and
//!   parsers, RLP/CBOR and serde JSON.
//!
//! With neither feature the crate is `no_std` and never allocates. That core
//! offers (for the enabled chains):
//!
//! - [`hash`], [`crypto`] (secp256k1 ECDSA/Schnorr/taproot, Ed25519) and
//!   `cardano_derive` (BIP32-Ed25519 keys);
//! - output-script generation for every built-in format
//!   ([`generate_script`]), address rendering
//!   ([`encode_address_to_slice`], plus the `cardano` address builders) and
//!   address decoding (`decode_bitcoin_based_address` and friends);
//! - transaction signing: `btcraw` (legacy, BIP-143 and every BIP-341 taproot
//!   sighash, serialization, txid), `taproot` (script trees, merkle roots and
//!   control blocks), `psbt` (BIP-174 creator, updater, signer, combiner,
//!   finalizer and extractor, including taproot script paths) and `evmraw`
//!   (legacy/EIP-2930/EIP-1559 signing, encoding, hashing and sender
//!   recovery);
//! - `solana` keys, program-derived addresses and compact-u16; `evmabi`
//!   selectors, words and ERC-20 calldata; `BtcAmount` parsing/formatting;
//!   `btcguess` script heuristics;
//! - caller-buffer codecs: [`base58`], [`base64`], [`bech32`] (segwit, CashAddr and generic
//!   bech32), `eip55_to_slice`, [`encode_base58_addr_to_slice`],
//!   [`pushbytes`] and [`BtcVarInt`];
//! - transports, a part at a time: `bcur` bytewords, UR parsing and
//!   single-part URs; `bbqr` headers, parts and compression.

#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// The `alloc` items used across the crate, imported by each module that needs
/// them (a `no_std` crate has no implicit `Vec`/`String` prelude).
#[cfg(feature = "alloc")]
mod prelude {
    pub(crate) use alloc::boxed::Box;
    pub(crate) use alloc::string::{String, ToString};
    pub(crate) use alloc::vec::Vec;
    pub(crate) use alloc::{format, vec};
}

pub mod address;
pub mod base58;
pub mod base64;
#[cfg(feature = "bbqr")]
pub mod bbqr;
#[cfg(feature = "bcur")]
pub mod bcur;
pub mod bech32;
#[cfg(feature = "bitcoin")]
pub mod btcguess;
#[cfg(feature = "bitcoin")]
pub mod btcraw;
#[cfg(feature = "cardano")]
pub mod cardano;
#[cfg(feature = "cardano")]
pub mod cardano_derive;
pub mod crypto;
#[cfg(feature = "evm")]
pub mod evmabi;
#[cfg(feature = "evm")]
pub mod evmraw;
pub mod hash;
pub mod inline;
#[cfg(feature = "massa")]
pub mod massa;
#[cfg(feature = "bitcoin")]
pub mod psbt;
pub mod pubkey;
pub mod pushbytes;
pub mod script;
#[cfg(feature = "solana")]
pub mod solana;
#[cfg(feature = "solana")]
pub mod solana_addr;
#[cfg(feature = "bitcoin")]
pub mod taproot;

#[cfg(all(feature = "alloc", feature = "bitcoin"))]
pub mod btctx;
#[cfg(all(feature = "alloc", feature = "bitcoin"))]
pub mod btctxparse;
#[cfg(all(feature = "alloc", feature = "cardano"))]
pub mod cardanotx;
#[cfg(feature = "alloc")]
pub mod cbor;
#[cfg(all(feature = "alloc", feature = "evm"))]
pub mod evmtx;
#[cfg(feature = "alloc")]
pub mod insertable;
#[cfg(feature = "alloc")]
pub mod out;
#[cfg(all(feature = "alloc", feature = "bitcoin"))]
pub mod reward;
#[cfg(feature = "alloc")]
pub mod rlp;

#[cfg(feature = "bitcoin")]
mod btcamount;
mod btcvarint;
mod error;
#[cfg(any(feature = "bitcoin", feature = "evm"))]
mod sink;

#[cfg(feature = "bitcoin")]
pub use address::decode_bitcoin_based_address;
pub use address::{DecodedAddress, encode_address_to_slice, encode_base58_addr_to_slice};
#[cfg(feature = "evm")]
pub use address::{decode_evm_address, eip55_to_slice};
#[cfg(feature = "bitcoin")]
pub use btcamount::BtcAmount;
pub use crypto::SignerError;
pub use error::Error;

/// A [`Result`](core::result::Result) with this crate's [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
#[cfg(feature = "bitcoin")]
pub use btcguess::{ScriptGuess, guess_in_script, guess_out_script};
pub use btcvarint::BtcVarInt;
#[cfg(feature = "cardano")]
pub use cardano::decode_cardano_address;
#[cfg(feature = "cardano")]
pub use cardano_derive::{
    CARDANO_HARDENED, CardanoExtendedKey, CardanoExtendedPubKey, cardano_harden,
    cardano_icarus_master_key,
};
pub use inline::InlineBytes;
#[cfg(feature = "massa")]
pub use massa::decode_massa_address;
pub use pubkey::PubKey;
pub use pushbytes::{parse_push_bytes, push_bytes_to_slice};
pub use script::{ALL_FORMATS, ScriptBytes, formats_per_network, generate_script};
#[cfg(feature = "solana")]
pub use solana_addr::decode_solana_address;

#[cfg(feature = "alloc")]
pub use address::encode_base58_addr;
#[cfg(all(feature = "alloc", feature = "bitcoin"))]
pub use address::parse_bitcoin_based_address;
#[cfg(all(feature = "alloc", feature = "evm"))]
pub use address::{eip55, parse_evm_address};
#[cfg(all(feature = "alloc", feature = "bitcoin"))]
pub use btcguess::{GuessResult, guess_by_in_script, guess_by_out_script};
#[cfg(all(feature = "alloc", feature = "bitcoin"))]
pub use btctx::{BtcTx, BtcTxInput, BtcTxOutput, BtcTxSign, Signer};
#[cfg(all(feature = "alloc", feature = "bitcoin"))]
pub use btctxparse::{BtcInputSig, extract_btc_input_sig};
#[cfg(all(feature = "alloc", feature = "cardano"))]
pub use cardano::{
    cardano_base_address, cardano_enterprise_address, cardano_key_hash, cardano_reward_address,
    parse_cardano_address,
};
#[cfg(all(feature = "alloc", feature = "cardano"))]
pub use cardanotx::{
    CardanoAsset, CardanoInput, CardanoOutput, CardanoSigner, CardanoTx, CardanoVkeyWitness,
};
#[cfg(all(feature = "alloc", feature = "evm"))]
pub use evmabi::{AbiBuffer, AbiValue, evm_call};
#[cfg(all(feature = "alloc", feature = "evm"))]
pub use evmtx::{EvmTx, EvmTxType};
#[cfg(feature = "alloc")]
pub use insertable::{Format, Insertable};
#[cfg(all(feature = "alloc", feature = "massa"))]
pub use massa::parse_massa_address;
#[cfg(all(feature = "alloc", feature = "bitcoin"))]
pub use out::guess_out;
#[cfg(feature = "alloc")]
pub use out::{Out, get_outs};
#[cfg(feature = "alloc")]
pub use pushbytes::push_bytes;
#[cfg(all(feature = "alloc", feature = "bitcoin"))]
pub use reward::{block_reward, cumulative_reward};
#[cfg(feature = "alloc")]
pub use script::{Script, format_def};
#[cfg(all(feature = "alloc", feature = "solana"))]
pub use solana_addr::parse_solana_address;

#[cfg(all(
    test,
    feature = "bitcoin",
    feature = "evm",
    feature = "solana",
    feature = "cardano",
    feature = "massa"
))]
mod nostd_tests;

#[cfg(all(
    test,
    feature = "alloc",
    feature = "bitcoin",
    feature = "evm",
    feature = "massa"
))]
mod address_tests;
#[cfg(all(test, feature = "alloc", feature = "bitcoin"))]
mod btctx_tests;
#[cfg(all(test, feature = "alloc", feature = "cardano"))]
mod cardano_tests;
#[cfg(all(test, feature = "alloc", feature = "solana"))]
mod solana_tests;
