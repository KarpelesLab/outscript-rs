# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.4](https://github.com/KarpelesLab/outscript-rs/compare/v0.2.3...v0.2.4) - 2026-09-19

### Other

- errors, not panics, on hostile lengths, counts and nesting
- Uniform Resources (bcur) and BBQr strings

## [0.2.3](https://github.com/KarpelesLab/outscript-rs/compare/v0.2.2...v0.2.3) - 2026-09-18

### Other

- Sign with the unified sighash in BtcTx and PSBT
- Unified opt-in sighash (hash type bit 0x20)

## [0.2.2](https://github.com/KarpelesLab/outscript-rs/compare/v0.2.1...v0.2.2) - 2026-09-17

### Other

- [**breaking**] taproot script trees, script-path spends, all sighash types
- taproot script trees, script-path signing and finalization
- Taproot sighash: all hash types, annex and script path
- Taproot script trees: leaf/branch hashes, merkle roots, control blocks

## [0.2.1](https://github.com/KarpelesLab/outscript-rs/compare/v0.2.0...v0.2.1) - 2026-09-17

### Other

- Zeroize key material on drop and wipe secret temporaries (breaking)

## [0.2.0](https://github.com/KarpelesLab/outscript-rs/compare/v0.1.3...v0.2.0) - 2026-09-17

### Other

- make SolanaTx and SolanaTxConfig non_exhaustive
- support v1 transactions (SIMD-0385)
- Feature-gate chains so each pulls in only its curve (breaking)
- Bump purecrypto to 0.9
- Unify the domain error types into one outscript::Error
- Replace String errors with typed errors (Cardano, Solana)
- Replace String errors with typed errors (addresses, scripts, EVM, Bitcoin)
- cross-check against BtcTx signing, add BtcTx::to_psbt, docs
- PSBT (BIP-174) support without alloc

## [0.1.3](https://github.com/KarpelesLab/outscript-rs/compare/v0.1.2...v0.1.3) - 2026-09-15

### Other

- Heap-free EVM transaction signing (evmraw)
- Heap-free Bitcoin transaction signing (btcraw)
- Heap-free Solana keys/PDA, amounts, script guessing and ABI helpers
- Heap-free address decoding
- Heap-free script generation and address rendering
- Support no_std and no-alloc builds (breaking)
- Raise MSRV to 1.89 (required by purecrypto 0.8.6)
- Bump purecrypto to 0.8.6

## [0.1.2](https://github.com/KarpelesLab/outscript-rs/compare/v0.1.1...v0.1.2) - 2026-06-27

### Other

- Guard Out::hash() against short raw scripts
- Rename APIs to idiomatic Rust conventions (breaking)
- Clean up Go-isms, tighten idiomatic Rust, mark growth enums non_exhaustive

## [0.1.1](https://github.com/KarpelesLab/outscript-rs/compare/v0.1.0...v0.1.1) - 2026-06-27

### Other

- Replace HashFn enum with a function-pointer alias
- Port security hardening from upstream outscript audit
- Add Cardano support: addresses, transactions, and BIP32-Ed25519 HD keys
- Bump purecrypto to 0.6.14 (MSRV 1.88)
- add MSRV (1.88) build check; lower rust-version to 1.88
- Add CI workflow + badge
- Add crates.io, docs.rs and license badges to README
