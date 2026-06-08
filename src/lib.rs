//! outscript generates potential output scripts for a given public key.
//!
//! It supports Bitcoin and Bitcoin-like cryptocurrency output script formats
//! (P2PKH, P2SH, P2WPKH, P2WSH, P2PK, P2TR, etc.), EVM-based networks (Ethereum
//! and compatible chains), and other blockchains such as Litecoin, Dogecoin,
//! Namecoin, Monacoin, Electraproto, Dash, Bitcoin Cash, Massa and Solana.
//!
//! This is a Rust port of the Go library `github.com/KarpelesLab/outscript`. All
//! cryptography is provided by the `purecrypto` crate.

pub mod base58;
pub mod bech32;
pub mod crypto;
pub mod hash;
pub mod pushbytes;
pub mod rlp;

pub mod address;
pub mod btcguess;
pub mod btctx;
pub mod btctxparse;
pub mod evmabi;
pub mod evmtx;
pub mod insertable;
pub mod massa;
pub mod out;
pub mod pubkey;
pub mod script;
pub mod solana;
pub mod solana_addr;

mod btcamount;
mod btcvarint;

pub use address::{eip55, encode_base58_addr, parse_bitcoin_based_address, parse_evm_address};
pub use btcamount::BtcAmount;
pub use btctx::{BtcTx, BtcTxInput, BtcTxOutput, BtcTxSign, Signer};
pub use btctxparse::{BtcInputSig, extract_btc_input_sig};
pub use evmabi::{AbiBuffer, AbiValue, evm_call};
pub use evmtx::{EvmTx, EvmTxType};
pub use btcguess::{GuessResult, guess_by_in_script, guess_by_out_script};
pub use btcvarint::BtcVarInt;
pub use insertable::{Format, Insertable};
pub use massa::parse_massa_address;
pub use out::{Out, get_outs, guess_out};
pub use pubkey::PubKey;
pub use pushbytes::{parse_push_bytes, push_bytes};
pub use script::{Script, format_def, formats_per_network};
pub use solana_addr::parse_solana_address;

#[cfg(test)]
mod address_tests;
#[cfg(test)]
mod btctx_tests;
#[cfg(test)]
mod solana_tests;
