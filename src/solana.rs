//! Solana keys, program-derived addresses and compact-u16 encoding, plus (with
//! `alloc`) instructions and transactions (legacy + v0). Port of
//! `solanatx.go`, `solana_instructions.go`, `solana_pda.go`.

pub use crate::Error;

use purecrypto::hash::{Digest, Sha256};

use crate::base58;
use crate::crypto::ed25519;
#[cfg(feature = "alloc")]
use crate::prelude::*;

#[cfg(feature = "alloc")]
mod tx;
#[cfg(feature = "alloc")]
pub use tx::*;

/// A 32-byte Solana public key / account address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SolanaKey(pub [u8; 32]);

impl SolanaKey {
    /// Parses a base58-encoded key (must decode to 32 bytes).
    pub fn parse(s: &str) -> Result<SolanaKey, Error> {
        crate::solana_addr::decode_solana_key(s).map(SolanaKey)
    }
    /// Writes the base58 encoding into `out` (44 bytes always suffice),
    /// returning the number of (ASCII) bytes written.
    pub fn to_base58_slice(&self, out: &mut [u8]) -> Result<usize, base58::Error> {
        base58::encode_to_slice(&self.0, out)
    }
    /// Base58 string encoding.
    #[cfg(feature = "alloc")]
    pub fn to_base58(&self) -> String {
        base58::encode(&self.0)
    }
    /// Whether the key is all zeros.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl core::fmt::Display for SolanaKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; 44];
        let n = self
            .to_base58_slice(&mut buf)
            .expect("44 bytes fit any 32-byte key");
        f.write_str(core::str::from_utf8(&buf[..n]).expect("base58 is ASCII"))
    }
}

/// Defines a well-known program/sysvar address, decoded at compile time.
macro_rules! well_known_key {
    ($func:ident, $addr:literal, $doc:literal) => {
        #[doc = $doc]
        pub fn $func() -> SolanaKey {
            const KEY: SolanaKey = SolanaKey(base58::decode_32_const($addr));
            KEY
        }
    };
}

well_known_key!(
    system_program,
    "11111111111111111111111111111111",
    "The Solana System Program address."
);
well_known_key!(
    compute_budget_program,
    "ComputeBudget111111111111111111111111111111",
    "The Compute Budget Program address."
);
well_known_key!(
    token_program,
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "The SPL Token Program address."
);
well_known_key!(
    ata_program,
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
    "The Associated Token Account Program address."
);
well_known_key!(
    recent_blockhashes_sysvar,
    "SysvarRecentB1ockHashes11111111111111111111",
    "The Recent Blockhashes Sysvar address."
);

// --- compact-u16 ---

/// Errors from [`decode_compact_u16`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompactU16Error {
    /// The input ended mid-value.
    UnexpectedEof,
    /// The value used a longer encoding than necessary.
    NonCanonical,
    /// The value exceeds `0xffff`.
    Overflow,
}

impl core::fmt::Display for CompactU16Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            CompactU16Error::UnexpectedEof => "unexpected EOF",
            CompactU16Error::NonCanonical => "non-canonical compact-u16",
            CompactU16Error::Overflow => "compact-u16 overflow",
        })
    }
}

impl core::error::Error for CompactU16Error {}

/// Encodes a value in Solana compact-u16 format, returning a buffer and its
/// used length (1 to 3 bytes).
pub fn encode_compact_u16_to_array(v: u16) -> ([u8; 3], usize) {
    let v = v as usize;
    if v < 0x80 {
        ([v as u8, 0, 0], 1)
    } else if v < 0x4000 {
        ([(v & 0x7f) as u8 | 0x80, (v >> 7) as u8, 0], 2)
    } else {
        (
            [
                (v & 0x7f) as u8 | 0x80,
                ((v >> 7) & 0x7f) as u8 | 0x80,
                (v >> 14) as u8,
            ],
            3,
        )
    }
}

/// Decodes a compact-u16, advancing `pos`.
pub fn decode_compact_u16(data: &[u8], pos: &mut usize) -> Result<usize, CompactU16Error> {
    let byte = |i: usize| {
        data.get(*pos + i)
            .copied()
            .ok_or(CompactU16Error::UnexpectedEof)
    };
    let b0 = byte(0)?;
    if b0 < 0x80 {
        *pos += 1;
        return Ok(b0 as usize);
    }
    let b1 = byte(1)?;
    if b1 < 0x80 {
        // Reject non-canonical encodings: a 2-byte form whose high group is zero
        // should have been encoded in a single byte.
        if b1 == 0 {
            return Err(CompactU16Error::NonCanonical);
        }
        *pos += 2;
        return Ok((b0 & 0x7f) as usize | (b1 as usize) << 7);
    }
    let b2 = byte(2)?;
    if b2 > 3 {
        return Err(CompactU16Error::Overflow);
    }
    // Reject non-canonical encodings: a 3-byte form whose high group is zero
    // should have been encoded in two bytes.
    if b2 == 0 {
        return Err(CompactU16Error::NonCanonical);
    }
    *pos += 3;
    Ok((b0 & 0x7f) as usize | ((b1 & 0x7f) as usize) << 7 | (b2 as usize) << 14)
}

// --- PDA ---

/// Derives a program address from seeds and a program id; errors if the result
/// lies on the Ed25519 curve.
pub fn create_program_address(seeds: &[&[u8]], program_id: SolanaKey) -> Result<SolanaKey, Error> {
    if seeds.len() > 16 {
        return Err(Error::TooManySeeds);
    }
    let mut h = Sha256::new();
    for &seed in seeds {
        if seed.len() > 32 {
            return Err(Error::SeedTooLong);
        }
        h.update(seed);
    }
    h.update(&program_id.0);
    h.update(b"ProgramDerivedAddress");
    let hash = h.finalize();

    if ed25519::is_on_curve(&hash) {
        return Err(Error::AddressOnCurve);
    }
    Ok(SolanaKey(hash))
}

/// Finds a valid program address by iterating bump seeds from 255 down to 0.
pub fn find_program_address(
    seeds: &[&[u8]],
    program_id: SolanaKey,
) -> Result<(SolanaKey, u8), Error> {
    if seeds.len() > 15 {
        // the bump seed takes the 16th slot
        return Err(Error::TooManySeeds);
    }
    for bump in (0..=255u8).rev() {
        // Append the trailing bump byte to the caller's seeds for this attempt.
        let bump_seed = [bump];
        let mut all: [&[u8]; 16] = [&[]; 16];
        all[..seeds.len()].copy_from_slice(seeds);
        all[seeds.len()] = &bump_seed;
        match create_program_address(&all[..=seeds.len()], program_id) {
            Ok(addr) => return Ok((addr, bump)),
            Err(Error::AddressOnCurve) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(Error::PdaNotFound)
}

/// Derives the Associated Token Account address for a wallet and mint.
pub fn associated_token_address(wallet: SolanaKey, mint: SolanaKey) -> Result<SolanaKey, Error> {
    let (addr, _) = find_program_address(
        &[&wallet.0[..], &token_program().0[..], &mint.0[..]],
        ata_program(),
    )?;
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_u16_roundtrip() {
        for v in [0u16, 0x7f, 0x80, 0x3fff, 0x4000, 0xffff] {
            let (buf, len) = encode_compact_u16_to_array(v);
            let mut pos = 0;
            assert_eq!(decode_compact_u16(&buf[..len], &mut pos), Ok(v as usize));
            assert_eq!(pos, len);
            let mut pos = 0;
            if len > 1 {
                assert_eq!(
                    decode_compact_u16(&buf[..len - 1], &mut pos),
                    Err(CompactU16Error::UnexpectedEof)
                );
            }
        }
    }

    #[test]
    fn well_known_and_display() {
        let mut buf = [0u8; 44];
        let n = token_program().to_base58_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        assert_eq!(
            SolanaKey::parse("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            Ok(token_program())
        );
    }

    #[test]
    fn pda_seed_limits() {
        let seeds: [&[u8]; 16] = [b"x"; 16];
        assert_eq!(
            find_program_address(&seeds, system_program()),
            Err(Error::TooManySeeds)
        );
        assert_eq!(
            find_program_address(&[&[0u8; 33]], system_program()),
            Err(Error::SeedTooLong)
        );
        let (addr, bump) = find_program_address(&seeds[..15], system_program()).unwrap();
        let mut with_bump: [&[u8]; 16] = seeds;
        let b = [bump];
        with_bump[15] = &b;
        assert_eq!(
            create_program_address(&with_bump, system_program()),
            Ok(addr)
        );
    }
}
