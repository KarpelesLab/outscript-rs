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
//! # Features
//!
//! - `std` (default): implies `alloc`, and adds `std::io` adapters
//!   (`BtcVarInt::read_from`/`write_to`, `BtcTx::read_from`).
//! - `alloc`: the full API on `no_std` targets with a global allocator —
//!   `Out`/`Script`, the `BtcTx`/`EvmTx`/`SolanaTx`/`CardanoTx` builders and
//!   parsers, RLP/CBOR and serde JSON.
//!
//! With neither feature the crate is `no_std` and never allocates. That core
//! offers:
//!
//! - [`hash`], [`crypto`] (secp256k1 ECDSA/Schnorr/taproot, Ed25519) and
//!   [`cardano_derive`] (BIP32-Ed25519 keys);
//! - output-script generation for every built-in format
//!   ([`generate_script`]), address rendering
//!   ([`encode_address_to_slice`], plus the [`cardano`] address builders) and
//!   address decoding ([`decode_bitcoin_based_address`] and friends);
//! - transaction signing: [`btcraw`] (legacy, BIP-143 and taproot sighashes,
//!   serialization, txid) and [`evmraw`] (legacy/EIP-2930/EIP-1559 signing,
//!   encoding, hashing and sender recovery);
//! - [`solana`] keys, program-derived addresses and compact-u16; [`evmabi`]
//!   selectors, words and ERC-20 calldata; [`BtcAmount`] parsing/formatting;
//!   [`btcguess`] script heuristics;
//! - caller-buffer codecs: [`base58`], [`bech32`] (segwit, CashAddr and generic
//!   bech32), [`eip55_to_slice`], [`encode_base58_addr_to_slice`],
//!   [`pushbytes`] and [`BtcVarInt`].

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
pub mod bech32;
pub mod btcguess;
pub mod btcraw;
pub mod cardano;
pub mod cardano_derive;
pub mod crypto;
pub mod evmabi;
pub mod evmraw;
pub mod hash;
pub mod inline;
pub mod massa;
pub mod psbt;
pub mod pubkey;
pub mod pushbytes;
pub mod script;
pub mod solana;
pub mod solana_addr;

#[cfg(feature = "alloc")]
pub mod btctx;
#[cfg(feature = "alloc")]
pub mod btctxparse;
#[cfg(feature = "alloc")]
pub mod cardanotx;
#[cfg(feature = "alloc")]
pub mod cbor;
#[cfg(feature = "alloc")]
pub mod evmtx;
#[cfg(feature = "alloc")]
pub mod insertable;
#[cfg(feature = "alloc")]
pub mod out;
#[cfg(feature = "alloc")]
pub mod reward;
#[cfg(feature = "alloc")]
pub mod rlp;

mod btcamount;
mod btcvarint;
mod sink;

pub use address::{
    DecodedAddress, decode_bitcoin_based_address, decode_evm_address, eip55_to_slice,
    encode_address_to_slice, encode_base58_addr_to_slice,
};
pub use btcamount::{AmountError, BtcAmount};
pub use btcguess::{ScriptGuess, guess_in_script, guess_out_script};
pub use btcvarint::BtcVarInt;
pub use cardano::decode_cardano_address;
pub use cardano_derive::{
    CARDANO_HARDENED, CardanoExtendedKey, CardanoExtendedPubKey, cardano_harden,
    cardano_icarus_master_key,
};
pub use inline::InlineBytes;
pub use massa::decode_massa_address;
pub use pubkey::PubKey;
pub use pushbytes::{parse_push_bytes, push_bytes_to_slice};
pub use script::{ALL_FORMATS, ScriptBytes, formats_per_network, generate_script};
pub use solana_addr::decode_solana_address;

#[cfg(feature = "alloc")]
pub use address::{eip55, encode_base58_addr, parse_bitcoin_based_address, parse_evm_address};
#[cfg(feature = "alloc")]
pub use btcguess::{GuessResult, guess_by_in_script, guess_by_out_script};
#[cfg(feature = "alloc")]
pub use btctx::{BtcTx, BtcTxInput, BtcTxOutput, BtcTxSign, Signer};
#[cfg(feature = "alloc")]
pub use btctxparse::{BtcInputSig, extract_btc_input_sig};
#[cfg(feature = "alloc")]
pub use cardano::{
    cardano_base_address, cardano_enterprise_address, cardano_key_hash, cardano_reward_address,
    parse_cardano_address,
};
#[cfg(feature = "alloc")]
pub use cardanotx::{
    CardanoAsset, CardanoInput, CardanoOutput, CardanoSigner, CardanoTx, CardanoVkeyWitness,
};
#[cfg(feature = "alloc")]
pub use evmabi::{AbiBuffer, AbiValue, evm_call};
#[cfg(feature = "alloc")]
pub use evmtx::{EvmTx, EvmTxType};
#[cfg(feature = "alloc")]
pub use insertable::{Format, Insertable};
#[cfg(feature = "alloc")]
pub use massa::parse_massa_address;
#[cfg(feature = "alloc")]
pub use out::{Out, get_outs, guess_out};
#[cfg(feature = "alloc")]
pub use pushbytes::push_bytes;
#[cfg(feature = "alloc")]
pub use reward::{block_reward, cumulative_reward};
#[cfg(feature = "alloc")]
pub use script::{Script, format_def};
#[cfg(feature = "alloc")]
pub use solana_addr::parse_solana_address;

#[cfg(test)]
mod nostd_tests;

#[cfg(all(test, feature = "alloc"))]
mod address_tests;
#[cfg(all(test, feature = "alloc"))]
mod btctx_tests;
#[cfg(all(test, feature = "alloc"))]
mod cardano_tests;
#[cfg(all(test, feature = "alloc"))]
mod solana_tests;
