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
pub mod hash;
pub mod pushbytes;
pub mod rlp;

mod btcamount;
mod btcvarint;

pub use btcamount::BtcAmount;
pub use btcvarint::BtcVarInt;
pub use pushbytes::{parse_push_bytes, push_bytes};
