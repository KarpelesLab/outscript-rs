//! Solana instructions, messages and transactions (legacy, v0 and v1). Port of
//! `solanatx.go` and `solana_instructions.go`, plus the SIMD-0385 v1 format.

use alloc::collections::BTreeMap;

use super::*;

/// Decodes a compact-u16 length, advancing `pos`.
fn read_len(data: &[u8], pos: &mut usize) -> Result<usize, Error> {
    decode_compact_u16(data, pos).map_err(Error::from)
}

/// Encodes a value in Solana compact-u16 format.
///
/// # Panics
/// Panics if `v` exceeds `0xffff`.
pub fn encode_compact_u16(v: usize) -> Vec<u8> {
    let v = u16::try_from(v).expect("compact-u16 value out of range");
    let (buf, len) = encode_compact_u16_to_array(v);
    buf[..len].to_vec()
}

#[derive(Debug, Clone)]
pub struct SolanaAccountMeta {
    /// The account public key.
    pub pubkey: SolanaKey,
    /// Whether the account must sign.
    pub is_signer: bool,
    /// Whether the account is writable.
    pub is_writable: bool,
}

/// A high-level instruction (before account compilation).
#[derive(Debug, Clone)]
pub struct SolanaInstruction {
    /// The program that processes the instruction.
    pub program_id: SolanaKey,
    /// Accounts referenced.
    pub accounts: Vec<SolanaAccountMeta>,
    /// Instruction data.
    pub data: Vec<u8>,
}

/// Builds a System Program transfer instruction.
pub fn transfer_instruction(from: SolanaKey, to: SolanaKey, lamports: u64) -> SolanaInstruction {
    let mut data = vec![0u8; 12];
    data[0..4].copy_from_slice(&2u32.to_le_bytes());
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    SolanaInstruction {
        program_id: system_program(),
        accounts: vec![
            SolanaAccountMeta {
                pubkey: from,
                is_signer: true,
                is_writable: true,
            },
            SolanaAccountMeta {
                pubkey: to,
                is_signer: false,
                is_writable: true,
            },
        ],
        data,
    }
}

/// Builds a Compute Budget SetComputeUnitLimit instruction.
pub fn set_compute_unit_limit(units: u32) -> SolanaInstruction {
    let mut data = vec![0u8; 5];
    data[0] = 2;
    data[1..5].copy_from_slice(&units.to_le_bytes());
    SolanaInstruction {
        program_id: compute_budget_program(),
        accounts: vec![],
        data,
    }
}

/// Builds a Compute Budget SetComputeUnitPrice instruction.
pub fn set_compute_unit_price(micro_lamports: u64) -> SolanaInstruction {
    let mut data = vec![0u8; 9];
    data[0] = 3;
    data[1..9].copy_from_slice(&micro_lamports.to_le_bytes());
    SolanaInstruction {
        program_id: compute_budget_program(),
        accounts: vec![],
        data,
    }
}

/// Builds an SPL Token transfer instruction.
pub fn spl_transfer_instruction(
    source: SolanaKey,
    destination: SolanaKey,
    owner: SolanaKey,
    amount: u64,
) -> SolanaInstruction {
    let mut data = vec![0u8; 9];
    data[0] = 3;
    data[1..9].copy_from_slice(&amount.to_le_bytes());
    SolanaInstruction {
        program_id: token_program(),
        accounts: vec![
            SolanaAccountMeta {
                pubkey: source,
                is_signer: false,
                is_writable: true,
            },
            SolanaAccountMeta {
                pubkey: destination,
                is_signer: false,
                is_writable: true,
            },
            SolanaAccountMeta {
                pubkey: owner,
                is_signer: true,
                is_writable: false,
            },
        ],
        data,
    }
}

/// Builds an instruction to create an Associated Token Account.
pub fn create_ata_instruction(
    payer: SolanaKey,
    wallet: SolanaKey,
    mint: SolanaKey,
) -> Result<SolanaInstruction, Error> {
    let ata = associated_token_address(wallet, mint)?;
    Ok(SolanaInstruction {
        program_id: ata_program(),
        accounts: vec![
            SolanaAccountMeta {
                pubkey: payer,
                is_signer: true,
                is_writable: true,
            },
            SolanaAccountMeta {
                pubkey: ata,
                is_signer: false,
                is_writable: true,
            },
            SolanaAccountMeta {
                pubkey: wallet,
                is_signer: false,
                is_writable: false,
            },
            SolanaAccountMeta {
                pubkey: mint,
                is_signer: false,
                is_writable: false,
            },
            SolanaAccountMeta {
                pubkey: system_program(),
                is_signer: false,
                is_writable: false,
            },
            SolanaAccountMeta {
                pubkey: token_program(),
                is_signer: false,
                is_writable: false,
            },
        ],
        data: vec![],
    })
}

/// Builds a System Program AdvanceNonceAccount instruction (must be first).
pub fn advance_nonce_instruction(
    nonce_account: SolanaKey,
    nonce_authority: SolanaKey,
) -> SolanaInstruction {
    let mut data = vec![0u8; 4];
    data[0..4].copy_from_slice(&4u32.to_le_bytes());
    SolanaInstruction {
        program_id: system_program(),
        accounts: vec![
            SolanaAccountMeta {
                pubkey: nonce_account,
                is_signer: false,
                is_writable: true,
            },
            SolanaAccountMeta {
                pubkey: recent_blockhashes_sysvar(),
                is_signer: false,
                is_writable: false,
            },
            SolanaAccountMeta {
                pubkey: nonce_authority,
                is_signer: true,
                is_writable: false,
            },
        ],
        data,
    }
}

/// Message header counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SolanaMessageHeader {
    /// Number of required signatures.
    pub num_required_signatures: u8,
    /// Number of read-only signed accounts.
    pub num_readonly_signed: u8,
    /// Number of read-only unsigned accounts.
    pub num_readonly_unsigned: u8,
}

/// An instruction with account references replaced by indices.
#[derive(Debug, Clone, Default)]
pub struct SolanaCompiledInstruction {
    /// Index of the program id in the account key array.
    pub program_id_index: u8,
    /// Indices of the referenced accounts.
    pub account_indices: Vec<u8>,
    /// Instruction data.
    pub data: Vec<u8>,
}

/// A legacy message.
#[derive(Debug, Clone, Default)]
pub struct SolanaMessage {
    /// Header.
    pub header: SolanaMessageHeader,
    /// Static account keys.
    pub account_keys: Vec<SolanaKey>,
    /// Recent blockhash.
    pub recent_blockhash: SolanaKey,
    /// Compiled instructions.
    pub instructions: Vec<SolanaCompiledInstruction>,
}

/// An address lookup table reference (v0).
#[derive(Debug, Clone, Default)]
pub struct SolanaAddressTableLookup {
    /// The lookup table account.
    pub account_key: SolanaKey,
    /// Writable index positions.
    pub writable_indexes: Vec<u8>,
    /// Read-only index positions.
    pub readonly_indexes: Vec<u8>,
}

/// A versioned (v0) message.
#[derive(Debug, Clone, Default)]
pub struct SolanaMessageV0 {
    /// Header.
    pub header: SolanaMessageHeader,
    /// Static account keys.
    pub account_keys: Vec<SolanaKey>,
    /// Recent blockhash.
    pub recent_blockhash: SolanaKey,
    /// Compiled instructions.
    pub instructions: Vec<SolanaCompiledInstruction>,
    /// Address table lookups.
    pub address_table_lookups: Vec<SolanaAddressTableLookup>,
}

/// Version byte that opens a v1 message and transaction (SIMD-0385).
pub const SOLANA_V1_PREFIX: u8 = 0x81;
/// The largest serialized v1 transaction the network accepts.
pub const SOLANA_V1_MAX_TX_SIZE: usize = 4096;
const V1_MAX_SIGNATURES: usize = 12;
const V1_MAX_ADDRESSES: usize = 64;
const V1_MAX_INSTRUCTIONS: usize = 64;
const V1_MIN_HEAP_SIZE: u32 = 32 * 1024;
const V1_MAX_HEAP_SIZE: u32 = 256 * 1024;
/// Config-mask bits this crate understands; any other bit is rejected.
const V1_KNOWN_CONFIG_BITS: u32 = 0b1_1111;
const V1_FIXED_HEADER_LEN: usize = 1 + 3 + 4 + 32 + 1 + 1;

/// Fee and resource requests carried in a v1 message (SIMD-0385). They replace
/// the ComputeBudget instructions of legacy/v0 transactions, which a v1
/// transaction ignores.
///
/// An unset field requests the minimum: no priority fee, a compute-unit limit
/// of 0, a loaded-accounts data size limit of 0 and a 32 KiB heap.
///
/// Non-exhaustive: the mask reserves bits for future requests, so build it
/// from [`SolanaTxConfig::default`] and the `with_*` setters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct SolanaTxConfig {
    /// Total priority fee for the transaction, in lamports (not per compute
    /// unit).
    pub priority_fee: Option<u64>,
    /// Compute-unit limit.
    pub compute_unit_limit: Option<u32>,
    /// Loaded-accounts data size limit, in bytes.
    pub loaded_accounts_data_size_limit: Option<u32>,
    /// Heap size in bytes: a multiple of 1024 between 32 KiB and 256 KiB.
    pub heap_size: Option<u32>,
}

impl SolanaTxConfig {
    /// A config with nothing requested (every field unset).
    pub const fn new() -> Self {
        SolanaTxConfig {
            priority_fee: None,
            compute_unit_limit: None,
            loaded_accounts_data_size_limit: None,
            heap_size: None,
        }
    }

    /// Sets the total priority fee, in lamports.
    #[must_use]
    pub const fn with_priority_fee(mut self, lamports: u64) -> Self {
        self.priority_fee = Some(lamports);
        self
    }

    /// Sets the compute-unit limit.
    #[must_use]
    pub const fn with_compute_unit_limit(mut self, units: u32) -> Self {
        self.compute_unit_limit = Some(units);
        self
    }

    /// Sets the loaded-accounts data size limit, in bytes.
    #[must_use]
    pub const fn with_loaded_accounts_data_size_limit(mut self, bytes: u32) -> Self {
        self.loaded_accounts_data_size_limit = Some(bytes);
        self
    }

    /// Sets the heap size in bytes (a multiple of 1024 between 32 KiB and
    /// 256 KiB; checked when the message is built or serialized).
    #[must_use]
    pub const fn with_heap_size(mut self, bytes: u32) -> Self {
        self.heap_size = Some(bytes);
        self
    }

    /// The `TransactionConfigMask` for the fields that are set.
    pub fn mask(&self) -> u32 {
        let mut mask = 0;
        if self.priority_fee.is_some() {
            mask |= 0b11;
        }
        if self.compute_unit_limit.is_some() {
            mask |= 1 << 2;
        }
        if self.loaded_accounts_data_size_limit.is_some() {
            mask |= 1 << 3;
        }
        if self.heap_size.is_some() {
            mask |= 1 << 4;
        }
        mask
    }

    fn validate(&self) -> Result<(), Error> {
        if let Some(heap) = self.heap_size
            && (!heap.is_multiple_of(1024)
                || !(V1_MIN_HEAP_SIZE..=V1_MAX_HEAP_SIZE).contains(&heap))
        {
            return Err(Error::InvalidTxConfig);
        }
        Ok(())
    }

    /// Appends the `ConfigValues` (in mask-bit order, little-endian).
    fn write_values(&self, buf: &mut Vec<u8>) {
        if let Some(v) = self.priority_fee {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        if let Some(v) = self.compute_unit_limit {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        if let Some(v) = self.loaded_accounts_data_size_limit {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        if let Some(v) = self.heap_size {
            buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    /// Reads the `ConfigValues` selected by `mask`, advancing `pos`.
    fn read_values(mask: u32, data: &[u8], pos: &mut usize) -> Result<SolanaTxConfig, Error> {
        if mask & !V1_KNOWN_CONFIG_BITS != 0 {
            return Err(Error::InvalidTxConfig);
        }
        // the priority fee spans two bits: both or neither
        if matches!(mask & 0b11, 0b01 | 0b10) {
            return Err(Error::InvalidTxConfig);
        }
        let mut cfg = SolanaTxConfig::default();
        if mask & 0b11 != 0 {
            cfg.priority_fee = Some(u64::from_le_bytes(take_array(data, pos)?));
        }
        if mask & (1 << 2) != 0 {
            cfg.compute_unit_limit = Some(u32::from_le_bytes(take_array(data, pos)?));
        }
        if mask & (1 << 3) != 0 {
            cfg.loaded_accounts_data_size_limit = Some(u32::from_le_bytes(take_array(data, pos)?));
        }
        if mask & (1 << 4) != 0 {
            cfg.heap_size = Some(u32::from_le_bytes(take_array(data, pos)?));
        }
        Ok(cfg)
    }
}

/// Copies the next `N` bytes out of `data`, advancing `pos`.
fn take_array<const N: usize>(data: &[u8], pos: &mut usize) -> Result<[u8; N], Error> {
    let bytes = data.get(*pos..*pos + N).ok_or(Error::UnexpectedEof)?;
    *pos += N;
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// A v1 message (SIMD-0385): fixed-width counts, fee and resource requests in
/// the header, no address lookup tables, and signatures *after* the message
/// in the serialized transaction.
#[derive(Debug, Clone, Default)]
pub struct SolanaMessageV1 {
    /// Header.
    pub header: SolanaMessageHeader,
    /// Fee and resource requests.
    pub config: SolanaTxConfig,
    /// Recent blockhash (the "lifetime specifier").
    pub recent_blockhash: SolanaKey,
    /// Account keys (at most 64, no duplicates, fee payer first).
    pub account_keys: Vec<SolanaKey>,
    /// Compiled instructions (at most 64).
    pub instructions: Vec<SolanaCompiledInstruction>,
}

/// A Solana transaction: legacy, v0 or v1. `message_v1` takes precedence over
/// `message_v0`, which takes precedence over the legacy `message`.
///
/// Non-exhaustive: construct one with [`new_solana_tx`], [`new_solana_tx_v0`],
/// [`new_solana_tx_v1`] or [`SolanaTx::from_bytes`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SolanaTx {
    /// Signatures (64 bytes each; empty = unsigned slot).
    pub signatures: Vec<Vec<u8>>,
    /// Legacy message.
    pub message: SolanaMessage,
    /// v0 message (when present, the transaction is versioned).
    pub message_v0: Option<SolanaMessageV0>,
    /// v1 message (when present, the transaction uses the SIMD-0385 format).
    pub message_v1: Option<SolanaMessageV1>,
}

struct AccountInfo {
    key: SolanaKey,
    is_signer: bool,
    is_writable: bool,
}

/// Result of account compilation: ordered keys, key->index map, message header.
type CompiledAccounts = (Vec<SolanaKey>, BTreeMap<SolanaKey, u8>, SolanaMessageHeader);

fn compile_accounts(
    fee_payer: SolanaKey,
    instructions: &[SolanaInstruction],
) -> Result<CompiledAccounts, Error> {
    let mut seen: BTreeMap<SolanaKey, AccountInfo> = BTreeMap::new();
    seen.insert(
        fee_payer,
        AccountInfo {
            key: fee_payer,
            is_signer: true,
            is_writable: true,
        },
    );
    for ix in instructions {
        for acc in &ix.accounts {
            if let Some(info) = seen.get_mut(&acc.pubkey) {
                info.is_signer |= acc.is_signer;
                info.is_writable |= acc.is_writable;
            } else {
                seen.insert(
                    acc.pubkey,
                    AccountInfo {
                        key: acc.pubkey,
                        is_signer: acc.is_signer,
                        is_writable: acc.is_writable,
                    },
                );
            }
        }
        seen.entry(ix.program_id).or_insert(AccountInfo {
            key: ix.program_id,
            is_signer: false,
            is_writable: false,
        });
    }

    let (mut sw, mut sr, mut nw, mut nr) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for info in seen.values() {
        if info.key == fee_payer {
            continue;
        }
        match (info.is_signer, info.is_writable) {
            (true, true) => sw.push(info.key),
            (true, false) => sr.push(info.key),
            (false, true) => nw.push(info.key),
            (false, false) => nr.push(info.key),
        }
    }
    let by_key = |v: &mut Vec<SolanaKey>| v.sort_by_key(|a| a.0);
    by_key(&mut sw);
    by_key(&mut sr);
    by_key(&mut nw);
    by_key(&mut nr);

    let mut all = Vec::with_capacity(seen.len());
    all.push(fee_payer);
    all.extend_from_slice(&sw);
    all.extend_from_slice(&sr);
    all.extend_from_slice(&nw);
    all.extend_from_slice(&nr);
    if all.len() > 256 {
        return Err(Error::TooLarge);
    }

    let mut index = BTreeMap::new();
    for (i, k) in all.iter().enumerate() {
        index.insert(*k, i as u8);
    }
    let header = SolanaMessageHeader {
        num_required_signatures: (1 + sw.len() + sr.len()) as u8,
        num_readonly_signed: sr.len() as u8,
        num_readonly_unsigned: nr.len() as u8,
    };
    Ok((all, index, header))
}

fn compile_instructions(
    instructions: &[SolanaInstruction],
    index: &BTreeMap<SolanaKey, u8>,
) -> Vec<SolanaCompiledInstruction> {
    instructions
        .iter()
        .map(|ix| SolanaCompiledInstruction {
            program_id_index: index[&ix.program_id],
            account_indices: ix.accounts.iter().map(|a| index[&a.pubkey]).collect(),
            data: ix.data.clone(),
        })
        .collect()
}

/// Compiles instructions into a legacy transaction (fee payer first).
pub fn new_solana_tx(
    fee_payer: SolanaKey,
    recent_blockhash: SolanaKey,
    instructions: &[SolanaInstruction],
) -> Result<SolanaTx, Error> {
    let (account_keys, index, header) = compile_accounts(fee_payer, instructions)?;
    let compiled = compile_instructions(instructions, &index);
    let num_signers = header.num_required_signatures as usize;
    Ok(SolanaTx {
        signatures: vec![Vec::new(); num_signers],
        message: SolanaMessage {
            header,
            account_keys,
            recent_blockhash,
            instructions: compiled,
        },
        message_v0: None,
        message_v1: None,
    })
}

/// Compiles instructions into a v0 versioned transaction.
pub fn new_solana_tx_v0(
    fee_payer: SolanaKey,
    recent_blockhash: SolanaKey,
    lookups: Vec<SolanaAddressTableLookup>,
    instructions: &[SolanaInstruction],
) -> Result<SolanaTx, Error> {
    let (account_keys, index, header) = compile_accounts(fee_payer, instructions)?;
    let compiled = compile_instructions(instructions, &index);
    let num_signers = header.num_required_signatures as usize;
    Ok(SolanaTx {
        signatures: vec![Vec::new(); num_signers],
        message: SolanaMessage::default(),
        message_v0: Some(SolanaMessageV0 {
            header,
            account_keys,
            recent_blockhash,
            instructions: compiled,
            address_table_lookups: lookups,
        }),
        message_v1: None,
    })
}

/// Compiles instructions into a v1 transaction (SIMD-0385) with the given fee
/// and resource requests. ComputeBudget instructions are unnecessary (and
/// ignored by the network) in this format; use `config` instead.
pub fn new_solana_tx_v1(
    fee_payer: SolanaKey,
    recent_blockhash: SolanaKey,
    config: SolanaTxConfig,
    instructions: &[SolanaInstruction],
) -> Result<SolanaTx, Error> {
    let (account_keys, index, header) = compile_accounts(fee_payer, instructions)?;
    let compiled = compile_instructions(instructions, &index);
    let message = SolanaMessageV1 {
        header,
        config,
        recent_blockhash,
        account_keys,
        instructions: compiled,
    };
    message.validate()?;
    let num_signers = header.num_required_signatures as usize;
    Ok(SolanaTx {
        signatures: vec![Vec::new(); num_signers],
        message: SolanaMessage::default(),
        message_v0: None,
        message_v1: Some(message),
    })
}

impl SolanaTx {
    /// The bytes that are signed: the message, or for v1 everything before the
    /// signatures.
    fn message_bytes(&self) -> Result<Vec<u8>, Error> {
        if let Some(m) = &self.message_v1 {
            return m.to_bytes();
        }
        Ok(match &self.message_v0 {
            Some(m) => m.to_bytes(),
            None => self.message.to_bytes(),
        })
    }
    fn header(&self) -> SolanaMessageHeader {
        if let Some(m) = &self.message_v1 {
            return m.header;
        }
        match &self.message_v0 {
            Some(m) => m.header,
            None => self.message.header,
        }
    }
    fn account_keys(&self) -> &[SolanaKey] {
        if let Some(m) = &self.message_v1 {
            return &m.account_keys;
        }
        match &self.message_v0 {
            Some(m) => &m.account_keys,
            None => &self.message.account_keys,
        }
    }

    /// Signs the transaction message with the given Ed25519 seeds, matching each
    /// to its signature slot by public key.
    pub fn sign(&mut self, seeds: &[[u8; 32]]) -> Result<(), Error> {
        let msg = self.message_bytes()?;
        let num_signers = self.header().num_required_signatures as usize;
        let account_keys: Vec<SolanaKey> = self.account_keys().to_vec();
        if num_signers > account_keys.len() {
            return Err(Error::InvalidHeader);
        }
        for seed in seeds {
            let pubkey = SolanaKey(ed25519::public_from_seed(seed));
            let idx = account_keys[..num_signers]
                .iter()
                .position(|k| *k == pubkey);
            let idx = idx.ok_or(Error::NotRequiredSigner)?;
            self.signatures[idx] = ed25519::sign(seed, &msg).to_vec();
        }
        Ok(())
    }

    /// Verifies all required signatures.
    pub fn verify(&self) -> Result<(), Error> {
        let msg = self.message_bytes()?;
        let num_signers = self.header().num_required_signatures as usize;
        if num_signers > self.account_keys().len() {
            return Err(Error::InvalidHeader);
        }
        if self.signatures.len() < num_signers {
            return Err(Error::MissingSignatures);
        }
        for i in 0..num_signers {
            let sig = &self.signatures[i];
            if sig.len() != 64 {
                return Err(Error::InvalidSignature);
            }
            let pubkey = self.account_keys()[i];
            let mut s = [0u8; 64];
            s.copy_from_slice(sig);
            if !ed25519::verify(&pubkey.0, &msg, &s) {
                return Err(Error::SignatureVerification(i));
            }
        }
        Ok(())
    }

    /// Returns the transaction id (the first signature).
    pub fn hash(&self) -> Result<Vec<u8>, Error> {
        if self.signatures.is_empty() || self.signatures[0].is_empty() {
            return Err(Error::NoSignature);
        }
        Ok(self.signatures[0].clone())
    }

    /// Serializes the transaction. A v1 transaction carries exactly
    /// `num_required_signatures` signatures after the message and must fit in
    /// [`SOLANA_V1_MAX_TX_SIZE`] bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let msg = self.message_bytes()?;
        if let Some(m) = &self.message_v1 {
            let required = m.header.num_required_signatures as usize;
            if self.signatures.len() < required {
                return Err(Error::MissingSignatures);
            }
            if self.signatures.len() > required {
                return Err(Error::InvalidData);
            }
            let mut buf = msg;
            write_signatures(&mut buf, &self.signatures)?;
            if buf.len() > SOLANA_V1_MAX_TX_SIZE {
                return Err(Error::TooLarge);
            }
            return Ok(buf);
        }
        let mut buf = encode_compact_u16(self.signatures.len());
        write_signatures(&mut buf, &self.signatures)?;
        buf.extend_from_slice(&msg);
        Ok(buf)
    }

    /// Parses a transaction from bytes (legacy, v0 or v1; a v1 transaction is
    /// recognized by its leading [`SOLANA_V1_PREFIX`] byte).
    pub fn from_bytes(data: &[u8]) -> Result<SolanaTx, Error> {
        if data.first() == Some(&SOLANA_V1_PREFIX) {
            return Self::from_bytes_v1(data);
        }
        let mut pos = 0;
        let sig_count = read_len(data, &mut pos)?;
        if sig_count > 256 {
            return Err(Error::TooLarge);
        }
        let mut signatures = Vec::with_capacity(sig_count);
        for _ in 0..sig_count {
            if data.len() < pos + 64 {
                return Err(Error::UnexpectedEof);
            }
            signatures.push(data[pos..pos + 64].to_vec());
            pos += 64;
        }
        let rest = &data[pos..];
        let mut tx = SolanaTx {
            signatures,
            ..Default::default()
        };
        if !rest.is_empty() && rest[0] & 0x80 != 0 {
            let version = rest[0] & 0x7f;
            if version != 0 {
                return Err(Error::UnsupportedVersion(version));
            }
            tx.message_v0 = Some(SolanaMessageV0::from_bytes(rest)?);
        } else {
            tx.message = SolanaMessage::from_bytes(rest)?;
        }
        Ok(tx)
    }

    fn from_bytes_v1(data: &[u8]) -> Result<SolanaTx, Error> {
        if data.len() > SOLANA_V1_MAX_TX_SIZE {
            return Err(Error::TooLarge);
        }
        let mut pos = 0;
        let message = SolanaMessageV1::read(data, &mut pos)?;
        let required = message.header.num_required_signatures as usize;
        let mut signatures = Vec::with_capacity(required);
        for _ in 0..required {
            signatures.push(take_array::<64>(data, &mut pos)?.to_vec());
        }
        if pos != data.len() {
            return Err(Error::TrailingData);
        }
        Ok(SolanaTx {
            signatures,
            message: SolanaMessage::default(),
            message_v0: None,
            message_v1: Some(message),
        })
    }
}

/// Appends signatures, writing an all-zero signature for each empty slot.
fn write_signatures(buf: &mut Vec<u8>, signatures: &[Vec<u8>]) -> Result<(), Error> {
    for sig in signatures {
        if sig.is_empty() {
            buf.extend(core::iter::repeat_n(0u8, 64));
        } else if sig.len() != 64 {
            return Err(Error::InvalidSignature);
        } else {
            buf.extend_from_slice(sig);
        }
    }
    Ok(())
}

fn write_message_common(
    buf: &mut Vec<u8>,
    header: &SolanaMessageHeader,
    account_keys: &[SolanaKey],
    recent_blockhash: &SolanaKey,
    instructions: &[SolanaCompiledInstruction],
) {
    buf.push(header.num_required_signatures);
    buf.push(header.num_readonly_signed);
    buf.push(header.num_readonly_unsigned);
    buf.extend_from_slice(&encode_compact_u16(account_keys.len()));
    for k in account_keys {
        buf.extend_from_slice(&k.0);
    }
    buf.extend_from_slice(&recent_blockhash.0);
    buf.extend_from_slice(&encode_compact_u16(instructions.len()));
    for ix in instructions {
        buf.push(ix.program_id_index);
        buf.extend_from_slice(&encode_compact_u16(ix.account_indices.len()));
        buf.extend_from_slice(&ix.account_indices);
        buf.extend_from_slice(&encode_compact_u16(ix.data.len()));
        buf.extend_from_slice(&ix.data);
    }
}

/// Checks that the message header account counts are internally consistent with
/// the number of account keys. Prevents out-of-bounds indexing in sign/verify
/// when handling a crafted message.
fn validate_solana_header(h: &SolanaMessageHeader, num_keys: usize) -> Result<(), Error> {
    if h.num_required_signatures as usize > num_keys {
        return Err(Error::InvalidHeader);
    }
    if h.num_readonly_signed > h.num_required_signatures {
        return Err(Error::InvalidHeader);
    }
    if h.num_required_signatures as usize + h.num_readonly_unsigned as usize > num_keys {
        return Err(Error::InvalidHeader);
    }
    Ok(())
}

/// Validates that every instruction's program id index and account indices
/// reference an addressable account (`< addressable`).
fn validate_instruction_indexes(
    instructions: &[SolanaCompiledInstruction],
    addressable: usize,
) -> Result<(), Error> {
    for ix in instructions {
        if ix.program_id_index as usize >= addressable {
            return Err(Error::IndexOutOfRange);
        }
        for &ai in &ix.account_indices {
            if ai as usize >= addressable {
                return Err(Error::IndexOutOfRange);
            }
        }
    }
    Ok(())
}

fn read_message_common(
    data: &[u8],
    pos: &mut usize,
) -> Result<
    (
        SolanaMessageHeader,
        Vec<SolanaKey>,
        SolanaKey,
        Vec<SolanaCompiledInstruction>,
    ),
    Error,
> {
    if data.len() < *pos + 3 {
        return Err(Error::UnexpectedEof);
    }
    let header = SolanaMessageHeader {
        num_required_signatures: data[*pos],
        num_readonly_signed: data[*pos + 1],
        num_readonly_unsigned: data[*pos + 2],
    };
    *pos += 3;
    let key_count = read_len(data, pos)?;
    if key_count > 256 {
        return Err(Error::TooLarge);
    }
    let mut account_keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        if data.len() < *pos + 32 {
            return Err(Error::UnexpectedEof);
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&data[*pos..*pos + 32]);
        account_keys.push(SolanaKey(k));
        *pos += 32;
    }
    validate_solana_header(&header, account_keys.len())?;
    if data.len() < *pos + 32 {
        return Err(Error::UnexpectedEof);
    }
    let mut bh = [0u8; 32];
    bh.copy_from_slice(&data[*pos..*pos + 32]);
    *pos += 32;
    let ix_count = read_len(data, pos)?;
    // Sanity cap: every instruction needs at least one byte (the program id
    // index), so the count cannot exceed the remaining bytes.
    if ix_count > data.len() - *pos {
        return Err(Error::TooLarge);
    }
    let mut instructions = Vec::with_capacity(ix_count);
    for _ in 0..ix_count {
        if data.len() < *pos + 1 {
            return Err(Error::UnexpectedEof);
        }
        let program_id_index = data[*pos];
        *pos += 1;
        let acc_count = read_len(data, pos)?;
        if data.len() < *pos + acc_count {
            return Err(Error::UnexpectedEof);
        }
        let account_indices = data[*pos..*pos + acc_count].to_vec();
        *pos += acc_count;
        let data_len = read_len(data, pos)?;
        if data.len() < *pos + data_len {
            return Err(Error::UnexpectedEof);
        }
        let ix_data = data[*pos..*pos + data_len].to_vec();
        *pos += data_len;
        instructions.push(SolanaCompiledInstruction {
            program_id_index,
            account_indices,
            data: ix_data,
        });
    }
    Ok((header, account_keys, SolanaKey(bh), instructions))
}

impl SolanaMessage {
    /// Serializes the legacy message.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_message_common(
            &mut buf,
            &self.header,
            &self.account_keys,
            &self.recent_blockhash,
            &self.instructions,
        );
        buf
    }
    /// Parses a legacy message.
    pub fn from_bytes(data: &[u8]) -> Result<SolanaMessage, Error> {
        let mut pos = 0;
        let (header, account_keys, recent_blockhash, instructions) =
            read_message_common(data, &mut pos)?;
        // For the legacy format the addressable set is exactly the static
        // account key list.
        validate_instruction_indexes(&instructions, account_keys.len())?;
        Ok(SolanaMessage {
            header,
            account_keys,
            recent_blockhash,
            instructions,
        })
    }
}

impl SolanaMessageV0 {
    /// Serializes the v0 message (with version prefix 0x80).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0x80];
        write_message_common(
            &mut buf,
            &self.header,
            &self.account_keys,
            &self.recent_blockhash,
            &self.instructions,
        );
        buf.extend_from_slice(&encode_compact_u16(self.address_table_lookups.len()));
        for lookup in &self.address_table_lookups {
            buf.extend_from_slice(&lookup.account_key.0);
            buf.extend_from_slice(&encode_compact_u16(lookup.writable_indexes.len()));
            buf.extend_from_slice(&lookup.writable_indexes);
            buf.extend_from_slice(&encode_compact_u16(lookup.readonly_indexes.len()));
            buf.extend_from_slice(&lookup.readonly_indexes);
        }
        buf
    }
    /// Parses a v0 message.
    pub fn from_bytes(data: &[u8]) -> Result<SolanaMessageV0, Error> {
        if data.is_empty() {
            return Err(Error::UnexpectedEof);
        }
        if data[0] & 0x80 == 0 {
            return Err(Error::NotVersioned);
        }
        let version = data[0] & 0x7f;
        if version != 0 {
            return Err(Error::UnsupportedVersion(version));
        }
        let mut pos = 1;
        let (header, account_keys, recent_blockhash, instructions) =
            read_message_common(data, &mut pos)?;
        let lookup_count = read_len(data, &mut pos)?;
        // Sanity cap: every lookup needs at least one byte, so the count cannot
        // exceed the remaining bytes.
        if lookup_count > data.len() - pos {
            return Err(Error::TooLarge);
        }
        let mut lookups = Vec::with_capacity(lookup_count);
        for _ in 0..lookup_count {
            if data.len() < pos + 32 {
                return Err(Error::UnexpectedEof);
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;
            let w_count = read_len(data, &mut pos)?;
            if data.len() < pos + w_count {
                return Err(Error::UnexpectedEof);
            }
            let writable_indexes = data[pos..pos + w_count].to_vec();
            pos += w_count;
            let r_count = read_len(data, &mut pos)?;
            if data.len() < pos + r_count {
                return Err(Error::UnexpectedEof);
            }
            let readonly_indexes = data[pos..pos + r_count].to_vec();
            pos += r_count;
            lookups.push(SolanaAddressTableLookup {
                account_key: SolanaKey(k),
                writable_indexes,
                readonly_indexes,
            });
        }
        // For v0 the addressable account set is the static account keys followed
        // by accounts loaded from address lookup tables (all writable indexes,
        // then all readonly indexes). The lookup counts are only known after the
        // lookups are parsed, which is why this validation happens here.
        let addressable = account_keys.len()
            + lookups
                .iter()
                .map(|l| l.writable_indexes.len() + l.readonly_indexes.len())
                .sum::<usize>();
        validate_instruction_indexes(&instructions, addressable)?;
        Ok(SolanaMessageV0 {
            header,
            account_keys,
            recent_blockhash,
            instructions,
            address_table_lookups: lookups,
        })
    }
}

impl SolanaMessageV1 {
    /// Checks the SIMD-0385 sanitization rules: at most 12 signatures, 64
    /// addresses and 64 instructions; a writable fee payer; enough addresses
    /// for the header; no duplicate addresses; a valid heap size; and every
    /// instruction referencing a non-fee-payer program and in-range accounts.
    pub fn validate(&self) -> Result<(), Error> {
        let h = &self.header;
        let num_keys = self.account_keys.len();
        if h.num_required_signatures as usize > V1_MAX_SIGNATURES
            || self.instructions.len() > V1_MAX_INSTRUCTIONS
            || num_keys > V1_MAX_ADDRESSES
        {
            return Err(Error::TooLarge);
        }
        if num_keys < h.num_required_signatures as usize + h.num_readonly_unsigned as usize
            || h.num_readonly_signed >= h.num_required_signatures
        {
            return Err(Error::InvalidHeader);
        }
        for (i, k) in self.account_keys.iter().enumerate() {
            if self.account_keys[..i].contains(k) {
                return Err(Error::DuplicateKey);
            }
        }
        self.config.validate()?;
        for ix in &self.instructions {
            // the fee payer (index 0) can never be the program
            if ix.program_id_index == 0 {
                return Err(Error::IndexOutOfRange);
            }
            if ix.account_indices.len() > u8::MAX as usize || ix.data.len() > u16::MAX as usize {
                return Err(Error::TooLarge);
            }
        }
        validate_instruction_indexes(&self.instructions, num_keys)
    }

    /// Serializes the message (with version prefix 0x81), after [`validate`](Self::validate).
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut buf = vec![SOLANA_V1_PREFIX];
        buf.push(self.header.num_required_signatures);
        buf.push(self.header.num_readonly_signed);
        buf.push(self.header.num_readonly_unsigned);
        buf.extend_from_slice(&self.config.mask().to_le_bytes());
        buf.extend_from_slice(&self.recent_blockhash.0);
        buf.push(self.instructions.len() as u8);
        buf.push(self.account_keys.len() as u8);
        for k in &self.account_keys {
            buf.extend_from_slice(&k.0);
        }
        self.config.write_values(&mut buf);
        for ix in &self.instructions {
            buf.push(ix.program_id_index);
            buf.push(ix.account_indices.len() as u8);
            buf.extend_from_slice(&(ix.data.len() as u16).to_le_bytes());
        }
        for ix in &self.instructions {
            buf.extend_from_slice(&ix.account_indices);
            buf.extend_from_slice(&ix.data);
        }
        Ok(buf)
    }

    /// Parses a v1 message from the start of `data` (trailing bytes, such as
    /// a transaction's signatures, are ignored).
    pub fn from_bytes(data: &[u8]) -> Result<SolanaMessageV1, Error> {
        Self::read(data, &mut 0)
    }

    /// Parses a v1 message at `pos`, leaving `pos` just after it.
    fn read(data: &[u8], pos: &mut usize) -> Result<SolanaMessageV1, Error> {
        let start = *pos;
        if data.len() < start + V1_FIXED_HEADER_LEN {
            return Err(Error::UnexpectedEof);
        }
        match data[start] {
            SOLANA_V1_PREFIX => {}
            v if v & 0x80 == 0 => return Err(Error::NotVersioned),
            v => return Err(Error::UnsupportedVersion(v & 0x7f)),
        }
        let header = SolanaMessageHeader {
            num_required_signatures: data[start + 1],
            num_readonly_signed: data[start + 2],
            num_readonly_unsigned: data[start + 3],
        };
        *pos = start + 4;
        let mask = u32::from_le_bytes(take_array(data, pos)?);
        let recent_blockhash = SolanaKey(take_array(data, pos)?);
        let ix_count = data[*pos] as usize;
        let key_count = data[*pos + 1] as usize;
        *pos += 2;
        if ix_count > V1_MAX_INSTRUCTIONS || key_count > V1_MAX_ADDRESSES {
            return Err(Error::TooLarge);
        }
        let mut account_keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            account_keys.push(SolanaKey(take_array(data, pos)?));
        }
        let config = SolanaTxConfig::read_values(mask, data, pos)?;
        let mut headers = Vec::with_capacity(ix_count);
        for _ in 0..ix_count {
            let h: [u8; 4] = take_array(data, pos)?;
            headers.push((
                h[0],
                h[1] as usize,
                u16::from_le_bytes([h[2], h[3]]) as usize,
            ));
        }
        let mut instructions = Vec::with_capacity(ix_count);
        for (program_id_index, acc_count, data_len) in headers {
            let account_indices = data
                .get(*pos..*pos + acc_count)
                .ok_or(Error::UnexpectedEof)?
                .to_vec();
            *pos += acc_count;
            let ix_data = data
                .get(*pos..*pos + data_len)
                .ok_or(Error::UnexpectedEof)?
                .to_vec();
            *pos += data_len;
            instructions.push(SolanaCompiledInstruction {
                program_id_index,
                account_indices,
                data: ix_data,
            });
        }
        let message = SolanaMessageV1 {
            header,
            config,
            recent_blockhash,
            account_keys,
            instructions,
        };
        message.validate()?;
        Ok(message)
    }
}
