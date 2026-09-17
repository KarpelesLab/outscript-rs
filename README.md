# outscript

[![CI](https://github.com/KarpelesLab/outscript-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/outscript-rs/actions/workflows/ci.yml)
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
| Cardano | Shelley bech32 (addr / addr_test / stake) | `CardanoTx` |

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

// Cardano (ed25519). "cardano" yields a Shelley enterprise address (payment
// credential only); pass "cardano-testnet" for the testnet form.
let addr = s.address("cardano", &[]).unwrap();                  // addr1...
let test = s.address("cardano", &["cardano-testnet"]).unwrap(); // addr_test1...

// Base (payment+stake) and reward addresses need two key hashes:
use outscript::{cardano_base_address, cardano_reward_address, cardano_key_hash};
let ph = cardano_key_hash(&payment_pub);
let sh = cardano_key_hash(&stake_pub);
let base   = cardano_base_address(&ph, &sh, "cardano").unwrap();  // addr1...
let reward = cardano_reward_address(&sh, "cardano").unwrap();     // stake1...
```

### Address parsing

```rust
use outscript::{parse_bitcoin_based_address, parse_evm_address, parse_solana_address, parse_massa_address};

let out = parse_bitcoin_based_address("auto", "1A1zP1...").unwrap(); // auto-detect
let out = parse_evm_address("0x2AeB8ADD...").unwrap();
let out = parse_solana_address("83astBRgu...").unwrap();
let out = parse_massa_address("AU16f3K8u...").unwrap();

// Cardano (addr / addr_test / stake / stake_test)
use outscript::parse_cardano_address;
let out = parse_cardano_address("addr1vx2fxv2umyhttkxyxp8...").unwrap();
let raw = out.bytes(); // raw address bytes (header + credentials), for a tx output
```

### Bitcoin transactions

```rust
use outscript::{BtcTx, BtcTxSign};

let mut tx = BtcTx::from_bytes(&raw).unwrap();
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

### PSBT (BIP-174)

Parse, update, sign (fully or partially), combine, finalize and extract
Partially Signed Bitcoin Transactions. Every operation works on borrowed bytes
and writes into a caller buffer, so it also runs without `alloc`; the
`*_to_vec` variants below need `alloc`.

```rust
use outscript::psbt::Psbt;

// creator: from an unsigned BtcTx (or a btcraw::RawTx with create_to_slice)
let psbt = tx.to_psbt().unwrap();

// updater: attach what signers need
let psbt = Psbt::parse(&psbt)?.set_witness_utxo_to_vec(0, 100_000, &prev_spk)?;

// signer: signs every input the key is involved in
let (psbt, signed) = Psbt::parse(&psbt)?.sign_to_vec(&key)?;

// combiner / finalizer / extractor
let psbt = Psbt::parse(&psbt)?.combine_to_vec(&Psbt::parse(&other_signers_psbt)?)?;
let (psbt, finalized) = Psbt::parse(&psbt)?.finalize_to_vec()?;
let raw_tx = Psbt::parse(&psbt)?.extract_tx_to_vec()?;

// base64
let text = Psbt::parse(&psbt)?.to_base64();
let bytes = Psbt::decode_base64(&text)?;
```

Signing covers P2PKH, P2PK, multisig, P2WPKH, P2WSH, their P2SH-nested forms
and P2TR key path (`SIGHASH_ALL`, and `SIGHASH_DEFAULT` for taproot), through
the `PsbtSigner` trait for external signers. The implementation reproduces
the BIP-174 test vectors byte for byte.

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
let data = tx.to_bytes().unwrap();
let sender = tx.sender_address().unwrap();
```

### Solana transactions

```rust
use outscript::solana::{new_solana_tx, transfer_instruction, SolanaKey};

let ix = transfer_instruction(from, to, 1_000_000); // lamports
let mut tx = new_solana_tx(from, blockhash, &[ix]).unwrap();
tx.sign(&[seed]).unwrap();
let data = tx.to_bytes().unwrap();
let txid = tx.hash().unwrap(); // first signature
```

`new_solana_tx_v0` builds a v0 transaction with address lookup tables, and
`new_solana_tx_v1` a v1 transaction (SIMD-0385, up to 4096 bytes): fee and
resource requests move from ComputeBudget instructions into a
`SolanaTxConfig`, and the signatures trail the message.

```rust
use outscript::solana::{new_solana_tx_v1, SolanaTxConfig};

let config = SolanaTxConfig::new()      // unset = minimum (0 CU, 32 KiB heap, ...)
    .with_priority_fee(5_000)           // total lamports, not per compute unit
    .with_compute_unit_limit(200_000);
let mut tx = new_solana_tx_v1(from, blockhash, config, &[ix]).unwrap();
tx.sign(&[seed]).unwrap();
let data = tx.to_bytes().unwrap();      // starts with 0x81
```

`SolanaTx::from_bytes` recognizes all three formats.

### Cardano transactions

Builds Shelley/Conway-era transactions: a CBOR-encoded body (inputs, outputs,
fee, optional TTL), ADA and native-asset outputs, and Ed25519 vkey witnesses.
The transaction id and signing digest are `blake2b-256` of the transaction body.

```rust
use outscript::{CardanoTx, CardanoInput, CardanoOutput, parse_cardano_address};

let to = parse_cardano_address("addr1vx2fxv2umyhttkxyxp8...").unwrap();

let mut tx = CardanoTx {
    inputs: vec![CardanoInput { txid: prev_txid /* 32 bytes */, index: 0 }],
    outputs: vec![CardanoOutput {
        address: to.bytes().to_vec(),
        amount: 1_000_000, // lovelace
        assets: vec![],
    }],
    fee: 170_000,
    ttl: 41_000_000, // optional (slot); 0 omits it
    witnesses: vec![],
};

// Sign with one or more 32-byte standard Ed25519 seeds (a vkey witness per seed)
tx.sign(&[seed]).unwrap();

let data = tx.to_bytes().unwrap(); // CBOR transaction
let txid = tx.hash().unwrap();           // blake2b-256 of the body
```

Cardano HD wallets (CIP-1852) use BIP32-Ed25519 *extended* keys, which store an
already-expanded 64-byte secret and cannot be used as a standard Ed25519 seed.
Sign with those (or any external/HSM signer) through the `CardanoSigner` trait:

```rust
use outscript::CardanoExtendedKey;

// secret is the 64-byte extended secret (e.g. the first 64 bytes of an xprv)
let ext = CardanoExtendedKey::new(&secret).unwrap();
tx.sign_with(&[&ext]).unwrap(); // standard Ed25519 signature, verifiable as usual
```

#### HD key derivation (CIP-1852 / BIP32-Ed25519)

Derive keys from BIP-39 entropy using the Icarus master-key scheme and the
CIP-1852 path `m/1852'/1815'/account'/role/index`:

```rust
use outscript::{cardano_icarus_master_key, cardano_harden as h, cardano_key_hash,
    cardano_base_address};

let master = cardano_icarus_master_key(&entropy, &[]).unwrap(); // &[] = no passphrase

// payment key m/1852'/1815'/0'/0/0 and stake key m/1852'/1815'/0'/2/0
let spend = master.derive_path(&[h(1852), h(1815), h(0), 0, 0]).unwrap();
let stake = master.derive_path(&[h(1852), h(1815), h(0), 2, 0]).unwrap();

let ph = cardano_key_hash(&spend.public_key());
let sh = cardano_key_hash(&stake.public_key());
let addr = cardano_base_address(&ph, &sh, "cardano").unwrap(); // addr1...

// `spend` signs transactions directly via sign_with.
// Watch-only soft derivation (no private key) is available from an xpub:
let xpub = master.derive_path(&[h(1852), h(1815), h(0), 0]).unwrap()
    .extended_public_key().unwrap();
let child = xpub.derive_child(0).unwrap();
```

Native tokens are added via `CardanoOutput.assets` (`CardanoAsset { policy_id,
asset_name, amount }`). Plutus scripts, certificates, staking actions and
metadata are out of scope.

### Block rewards

```rust
let reward = outscript::block_reward("bitcoin", 840_000).unwrap();      // 3.125 BTC in sats
let total  = outscript::cumulative_reward("bitcoin", 840_000).unwrap(); // total minted
```

## Cargo features

Chains are opt-in. Each chain feature enables its modules, output-script
formats and address codecs, and pulls in only the curve arithmetic it needs
from `purecrypto`. All chains are enabled by default.

| Feature | Enables | Curve |
|---------|---------|-------|
| `bitcoin` | Bitcoin-family scripts and addresses, `btcraw`, `BtcTx`, PSBT, script guessing, `BtcAmount`, block rewards | `secp256k1` |
| `evm` | EIP-55 addresses, `evmraw`, `EvmTx`, ABI helpers | `secp256k1` |
| `solana` | addresses, program-derived addresses, `SolanaTx` | `ed25519` |
| `cardano` | Shelley addresses, BIP32-Ed25519 derivation, `CardanoTx` | `ed25519` |
| `massa` | addresses | `ed25519` |

The `secp256k1` and `ed25519` features can also be enabled on their own for
the raw `crypto` helpers and the matching `PubKey` variant. Formats and
networks of chains that are not enabled are simply unknown to
`generate_script`, `formats_per_network` and `encode_address_to_slice`.

```toml
# Solana only: no secp256k1 code is compiled in
outscript = { version = "0.1", default-features = false, features = ["std", "solana"] }
```

## Key hygiene

`SecpPrivateKey` and `CardanoExtendedKey` wipe their key material when dropped
and implement `Zeroize` to scrub it on demand. Signing and key derivation wipe
the secret-derived buffers they create, and `CardanoExtendedKey::bytes` returns
a self-wiping buffer. The wiping API is re-exported from `purecrypto`, so no
extra dependency is needed:

```rust
use outscript::crypto::{Zeroize, Zeroizing, secp256k1::SecpPrivateKey};

let secret = Zeroizing::new(load_secret());   // your copy: wiped on drop
let mut key = SecpPrivateKey::from_bytes(&secret).unwrap();
let sig = key.sign_der(&digest);
key.zeroize();                                // or just let it drop
```

Seeds passed by reference (Solana and Cardano `sign(&[seed])`) stay yours to
wipe. Wiping is hygiene: it cannot reach copies the compiler left in registers
or on the stack.

## `no_std` and no-alloc

The crate is `#![no_std]`. Independently of the chain features, the runtime
tiers are:

| Features | Available |
|----------|-----------|
| `std` (default) | everything, plus `std::io` adapters (`BtcTx::read_from`, `BtcVarInt::read_from`/`write_to`) |
| `alloc` | everything else: `Out`/`Script`, address parsing, all transaction types, RLP/CBOR, JSON |
| none | a heap-free core (below) |

Disabling the default features also disables every chain, so name the ones
you need:

```toml
# heap-free core only
outscript = { version = "0.1", default-features = false, features = ["bitcoin", "evm"] }
# full API on no_std targets with an allocator
outscript = { version = "0.1", default-features = false, features = ["alloc", "bitcoin", "evm", "solana", "cardano", "massa"] }
```

Without `alloc` you still get:

- **Keys and signing** — secp256k1 ECDSA/Schnorr/taproot, Ed25519, Cardano
  BIP32-Ed25519 derivation.
- **Scripts and addresses** — `generate_script` for every built-in format,
  `encode_address_to_slice` to render them, and `decode_*_address` to parse
  Bitcoin-family, EVM, Massa, Solana and Cardano addresses.
- **Transaction signing** — `psbt::Psbt` (the full BIP-174 workflow),
  `btcraw::RawTx` (legacy, BIP-143 and taproot sighashes, serialization,
  txid) and `evmraw::RawEvmTx` (legacy/EIP-2930/
  EIP-1559 signing, encoding, hash, sender recovery).
- **Utilities** — Solana keys/PDAs/compact-u16, EVM ABI selectors and ERC-20
  calldata, `BtcAmount` parsing/formatting, script guessing, and base58,
  bech32/CashAddr, EIP-55, pushdata and varint codecs.

Results come back in caller buffers or small inline values:

```rust
use outscript::{PubKey, address, generate_script, crypto::secp256k1::SecpPrivateKey};
use outscript::evmraw::{EvmTxType, RawEvmTx};

let key = SecpPrivateKey::from_bytes(&secret).unwrap();
let pubkey = PubKey::Secp256k1(key.public_key());

// bc1q... for the key's P2WPKH script
let script = generate_script(&pubkey, "p2wpkh").unwrap();
let mut buf = [0u8; address::MAX_ADDRESS_LEN];
let n = address::encode_address_to_slice("p2wpkh", &script, "bitcoin", &mut buf).unwrap();

// sign an EIP-1559 transfer and encode it for broadcast
let tx = RawEvmTx {
    tx_type: EvmTxType::Eip1559,
    chain_id: 1,
    nonce: 0,
    max_priority_fee_per_gas: 1_000_000_000,
    max_fee_per_gas: 30_000_000_000,
    gas: 21_000,
    to: Some(recipient),
    value: amount_be,
    data: &[],
};
let sig = tx.sign(&key).unwrap();
let mut raw = [0u8; 128];
let len = tx.encode_signed_to_slice(&sig, &mut raw).unwrap();
```

## Architecture

- **Format / Insertable** — a sequence of operations (literal bytes, lookups,
  hashes, push-data, taproot tweak) that derive an output script from a key.
- **Script** — holds a [`PubKey`] and evaluates named formats, caching results.
- **Out** — a generated output script with its format name, hex and network
  flags; converts to/from human-readable addresses.
- **Transactions** — `BtcTx`, `EvmTx`, `SolanaTx`, `CardanoTx` with binary
  serialization, signing and hashing.

## License

See [LICENSE](LICENSE).
