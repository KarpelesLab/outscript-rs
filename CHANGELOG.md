# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
