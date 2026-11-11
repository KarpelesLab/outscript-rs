# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/KarpelesLab/outscript-rs/compare/v0.2.8...v0.3.0) - 2026-11-11

### Other

- compcol's embed::flate in place of minizlib, which only re-exports it
- a late transaction of version 1, the fetch script reads keys not to be mixed
- transactions of the chain of hard fork 6 without 7, and what a daemon confirms
- verify separately signed transactions
- the reward of an oversized block, on block 3 832 995
- blocks of the main network and the stakes of its first blocks
- blocks, block reward, stake kernel, getrandom_outs3 replies, daemon tools
- multisig as in the reference wallet (experimental)
- the files of the reference wallet's cold signing
- cn_slow_hash (CryptoNight v0), the key derivation of the reference wallet
- the circuit build test signs both actions of a restricted bundle
- any transparent input, external signing, change, coinbase
- coinbase inputs, block subsidy and funding streams of mainnet
- bundles without cross-address transfers as ZIP 326 has them
- TEX addresses (ZIP 320)
- P2SH and bare multisig, P2PK and custom scriptSigs, external signatures
- tests against the compiled C++ (payload encryption, wallet blobs, signing both ways)
- payload encryption of hard fork 6, decryption of both eras, the 2.1.8 wallet blob layout
- no id, signature or encoding for a transaction out of range
- sign refuses a transaction without a chain id
- Document version 6 transactions, the unified builder and the wider Monero and Zano coverage
- version 6 transactions (ZIP 229), parsed, digested and built
- the Ironwood pool (notes of ZIP 2005, flags, bundles, builder)
- Fix the Monero word lists on Windows checkouts
- mainnet fixtures of every era, ported proof tests, multi-asset transfers
- current-chain formats, full transaction verification, construct_tx alignment
- weights, fees and decoy selection as the reference wallet
- scan the whole chain history, more real-chain fixtures
- mnemonics in the eleven other languages of the reference wallet
- verify every historical signature and proof type, batch range proofs
- documentation of threads, test lock, batch count
- no blanket dead_code allowance in the circuit
- ZIP-316 Revision 2 unified encodings
- incremental witnesses, batched trial decryption
- batch validation of bundles, mainnet fixtures after NU6.2
- circuit version of a consensus branch or height
- spend authorization signatures made elsewhere
- multithreaded key generation and proving, shared subexpressions
- the Sapling fields of v4 transactions, module docs
- reference checks of depth-32 witnesses and of zivks encodings
- builder change, dummies, padding, shuffle and external signing
- batched verification of signatures and proofs, verify_bundle
- witnesses in zcashd's IncrementalWitness format
- batched trial decryption, wipe key agreement secrets
- cite the reference's bundle versions, fix doc links
- one builder for transparent, Sapling and Orchard parts
- strict compact sizes, typed bundle views, ZIP-317 fee
- run the slow tests in release, with the Sapling parameters

## [0.2.8](https://github.com/KarpelesLab/outscript-rs/compare/v0.2.7...v0.2.8) - 2026-11-10

### Other

- Mark EvmTx and CardanoTx as non_exhaustive
- cancel superseded runs on the same ref
- describe the Sapling prover feature
- document the prover modules, fix alloc-only test imports
- shielded bundle builder (spends, outputs, proofs, signatures)
- Spend and Output circuits, parameter loading, embedded verifying keys
- Groth16 over BLS12-381 (R1CS, QAP, MSM, prover, verifier, bellman parameter format)
- Wire the shielded pools into the crate error, document the new chains
- scanning vectors from real transactions, documented proof fields
- mnemonic seeds, pruned transactions, module documentation
- addresses, keys, transactions, scanning, CLSAG, Bulletproofs+ and transaction construction
- module overview, zanolib's crypto vector tables, faster verification
- addresses, wallet keys, proofs, serialization, offline signing and scanning
- build the prover features on alloc, so the bare-metal step applies
- Scaffold the Zcash prover features
- verify a mainnet transaction's signatures, Vesta hash-to-curve vector
- keys, notes, note encryption, RedPallas, bundles, unified encodings
- Sinsemilla, Poseidon and the fixed generators
- Pasta fields and the Pallas/Vesta curves
- cross-check against the reference implementation, scanning helpers
- fix lints and documentation links
- typed v5 Sapling bundle
- notes, note encryption and RedJubjub
- keys, payment addresses and ZIP-32 derivation
- note commitment tree (MerkleCRH, empty roots, frontier, witnesses)
- Jubjub fields and curve, group hash, generators, Pedersen hashes
- shared CryptoNote primitives, and the monero/zano feature scaffolding
- Sort the new module declarations (rustfmt)
- Scaffold the zcash-sapling and zcash-orchard features
- bound the fountain decoder's parts on hold by memory, require canonical fragment length
- Follow up the PSBT sighash policy and Cardano parsed-body changes
- harden signer, finalizer and parser against untrusted input
- hash, sign and serialize the original body of a parsed tx (audit findings 1, 6)
- no panics on short signature lists or oversize lengths; reject trailing bytes (audit findings 2, 5, 6)
- decode false/true/null by exact initial byte (audit finding 7)
- require a version-0, 33-byte address payload (audit finding 4)
- checked compact-size arithmetic in take_items (audit finding 3)
- strict contract type/URL pairing, address prefix and int64 bounds (audit findings 10, 11)
- range-check integers, left-align bytesN, fix seeded offsets and alias selectors (audit findings 5, 6)
- strict parsing, access lists, address and v checks (audit findings 2-4, 7-9)
- limit list nesting depth when decoding (audit finding 1)
- strict, consensus-bounded transaction parsing (audit finding 4)
- btctx, btcraw: refuse ECDSA sighash types that are not implemented (audit finding 2)
- accept a sign only as the first byte (audit finding 6)
- guess_out requires exact witness program templates (audit finding 5)
- no overflow or unbounded work at extreme heights (audit finding 3)
- drop the unspendable p2wsh:p2wpkh format (audit finding 1)
- Document ether_hash input contract and cofactored Ed25519 verify
- strict BIP-66 DER parsing and r/s range checks
- Harden address rendering and bech32/CashAddr case handling

## [0.2.7](https://github.com/KarpelesLab/outscript-rs/compare/v0.2.6...v0.2.7) - 2026-10-18

### Other

- Update purecrypto to 0.10 and bump MSRV to 1.95

## [0.2.6](https://github.com/KarpelesLab/outscript-rs/compare/v0.2.5...v0.2.6) - 2026-10-03

### Other

- addresses and protobuf transaction signing
- transparent addresses and v5 transaction signing (ZIP-244)

## [0.2.5](https://github.com/KarpelesLab/outscript-rs/compare/v0.2.4...v0.2.5) - 2026-09-20

### Other

- Add public constructors for DerSignature

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
