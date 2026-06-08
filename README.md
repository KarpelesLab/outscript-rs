# outscript

[![crates.io](https://img.shields.io/crates/v/outscript.svg)](https://crates.io/crates/outscript)
[![docs.rs](https://img.shields.io/docsrs/outscript)](https://docs.rs/outscript)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Rust crate for generating output scripts, parsing/encoding addresses, and
building/signing transactions across multiple cryptocurrency networks.

This is a Rust port of the Go library
[`github.com/KarpelesLab/outscript`](https://github.com/KarpelesLab/outscript).
All cryptography is provided by the pure-Rust
[`purecrypto`](https://crates.io/crates/purecrypto) crate.

## Supported Networks

| Network | Address Formats | Transactions |
|---------|----------------|--------------|
| Bitcoin | p2pkh, p2pk, p2wpkh, p2sh:p2wpkh, p2wsh, p2tr | `BtcTx` |
| Bitcoin Cash | p2pkh, p2pk (CashAddr) | `BtcTx` |
| Litecoin | p2pkh, p2pk, p2wpkh, p2sh:p2wpkh | `BtcTx` |
| Dogecoin | p2pkh, p2pk | `BtcTx` |
| Namecoin | p2pkh, p2sh | `BtcTx` |
| Monacoin | p2pkh, p2sh, p2wpkh | `BtcTx` |
| Dash | p2pkh, p2sh | `BtcTx` |
| Electraproto | p2pkh, p2sh, p2wpkh | `BtcTx` |
| EVM (Ethereum, etc.) | EIP-55 checksummed | `EvmTx` |
| Massa | AU (user) / AS (smart contract) | - |
| Solana | Base58 (32 bytes) | `SolanaTx` |

## Usage

### Address generation

```rust
use outscript::Script;
use outscript::crypto::secp256k1::SecpPrivateKey;
use outscript::crypto::ed25519;
use outscript::PubKey;

// Bitcoin / EVM (secp256k1)
let key = SecpPrivateKey::from_bytes(&seed).unwrap();
let s = Script::new(key.public_key());
let addr = s.address("p2wpkh", &["bitcoin"]).unwrap(); // bc1q...
let eth  = s.address("eth", &[]).unwrap();              // 0x...

// Solana / Massa (ed25519)
let pk = ed25519::public_from_seed(&seed);
let s = Script::new(PubKey::Ed25519(pk));
let sol = s.address("solana", &["solana"]).unwrap();    // base58
```

### Address parsing

```rust
use outscript::{parse_bitcoin_based_address, parse_evm_address, parse_solana_address, parse_massa_address};

let out = parse_bitcoin_based_address("auto", "1A1zP1...").unwrap(); // auto-detect
let out = parse_evm_address("0x2AeB8ADD...").unwrap();
let out = parse_solana_address("83astBRgu...").unwrap();
let out = parse_massa_address("AU16f3K8u...").unwrap();
```

### Bitcoin transactions

```rust
use outscript::{BtcTx, BtcTxSign};

let mut tx = BtcTx::unmarshal_binary(&raw).unwrap();
tx.sign(&[
    BtcTxSign::new(&key0, "p2pk"),
    BtcTxSign::new(&key1, "p2wpkh").amount(600_000_000),
]).unwrap();
let bytes = tx.bytes();

// P2TR (BIP-341 key-path, SIGHASH_DEFAULT) — PrevScript is required.
tx.sign(&[BtcTxSign::new(&key, "p2tr").amount(100_000).prev_script(prev_spk)]).unwrap();
```

Taproot supports both raw `SecpPrivateKey` signing (the library applies the
BIP-341 tweak) and external signers implementing the [`Signer::sign_taproot`]
method (TSS / MuSig2 / FROST / HSM). Use [`crypto::secp256k1::taproot_tweak`]
and [`BtcTx::taproot_sighash`] to compute the tweaked key and sighash offline.

### EVM transactions

```rust
use outscript::{EvmTx, EvmTxType, AbiValue};
use num_bigint::BigInt;

let mut tx = EvmTx {
    tx_type: EvmTxType::Eip1559,
    chain_id: 1,
    nonce: 0,
    gas_tip_cap: BigInt::from(1_000_000_000u64),
    gas_fee_cap: BigInt::from(20_000_000_000u64),
    gas: 21000,
    to: "0x...".into(),
    value: BigInt::from(10u64).pow(18),
    ..Default::default()
};
tx.call("transfer(address,uint256)", &[/* AbiValue... */]).unwrap();
tx.sign(&key).unwrap();
let data = tx.marshal_binary().unwrap();
let sender = tx.sender_address().unwrap();
```

### Solana transactions

```rust
use outscript::solana::{new_solana_tx, transfer_instruction, SolanaKey};

let ix = transfer_instruction(from, to, 1_000_000); // lamports
let mut tx = new_solana_tx(from, blockhash, &[ix]).unwrap();
tx.sign(&[seed]).unwrap();
let data = tx.marshal_binary().unwrap();
let txid = tx.hash().unwrap(); // first signature
```

### Block rewards

```rust
let reward = outscript::block_reward("bitcoin", 840_000).unwrap();      // 3.125 BTC in sats
let total  = outscript::cumulative_reward("bitcoin", 840_000).unwrap(); // total minted
```

## Architecture

- **Format / Insertable** — a sequence of operations (literal bytes, lookups,
  hashes, push-data, taproot tweak) that derive an output script from a key.
- **Script** — holds a [`PubKey`] and evaluates named formats, caching results.
- **Out** — a generated output script with its format name, hex and network
  flags; converts to/from human-readable addresses.
- **Transactions** — `BtcTx`, `EvmTx`, `SolanaTx` with binary
  serialization, signing and hashing.

## License

See [LICENSE](LICENSE).
