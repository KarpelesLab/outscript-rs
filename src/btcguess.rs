//! Heuristics to recover a public-key hash (and possibly the pubkey) from a
//! Bitcoin output or input script (port of `btcguess.go`).

#[cfg(feature = "alloc")]
use crate::prelude::*;

use crate::hash::hash160;
use crate::inline::InlineBytes;
use crate::pushbytes::parse_push_bytes;

/// A heap-free guess: the public key borrowed from the script, and the
/// public-key (or script) hash, which is either copied from the script or
/// computed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScriptGuess<'a> {
    /// The full public key, if it appears directly in the script.
    pub pubkey: Option<&'a [u8]>,
    /// The public-key (or script) hash: 20 bytes, or 32 for P2WSH/P2TR.
    pub pubkey_hash: Option<InlineBytes<32>>,
}

impl<'a> ScriptGuess<'a> {
    fn hash(h: &[u8]) -> Self {
        ScriptGuess {
            pubkey: None,
            pubkey_hash: InlineBytes::from_slice(h),
        }
    }
    fn pubkey(pk: &'a [u8]) -> Self {
        ScriptGuess {
            pubkey: Some(pk),
            pubkey_hash: InlineBytes::from_slice(&hash160(pk)),
        }
    }
}

/// Attempts to guess the pubkey hash (and possibly the pubkey) from an output
/// script, without allocating.
pub fn guess_out_script(script: &[u8]) -> ScriptGuess<'_> {
    match script {
        // P2PKH: 76 a9 14 <20> 88 ac
        [0x76, 0xa9, 0x14, h @ .., 0x88, 0xac] if h.len() == 20 => ScriptGuess::hash(h),
        // P2SH: a9 14 <20> 87
        [0xa9, 0x14, h @ .., 0x87] if h.len() == 20 => ScriptGuess::hash(h),
        // P2PK: 21 <33> ac  OR  41 <65> ac
        [0x21, pk @ .., 0xac] if pk.len() == 33 => ScriptGuess::pubkey(pk),
        [0x41, pk @ .., 0xac] if pk.len() == 65 => ScriptGuess::pubkey(pk),
        // SegWit P2WPKH (22) / P2WSH (34), P2TR: 51 20 <32>
        [0x00, 0x14, h @ ..] if h.len() == 20 => ScriptGuess::hash(h),
        [0x00, 0x20, h @ ..] | [0x51, 0x20, h @ ..] if h.len() == 32 => ScriptGuess::hash(h),
        _ => ScriptGuess::default(),
    }
}

/// Attempts to guess the pubkey hash (and pubkey) from an input script,
/// without allocating.
pub fn guess_in_script(script: &[u8]) -> ScriptGuess<'_> {
    if let Some((_, pos1)) = parse_push_bytes(script)
        && let Some((pubkey, _)) = parse_push_bytes(&script[pos1..])
    {
        return ScriptGuess::pubkey(pubkey);
    }
    ScriptGuess::default()
}

/// Result of a guess: an optional full public key and an optional pubkey hash.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuessResult {
    /// The full public key, if it could be recovered directly from the script.
    pub pubkey: Option<Vec<u8>>,
    /// The public-key (or script) hash, if recognized.
    pub pubkey_hash: Option<Vec<u8>>,
}

#[cfg(feature = "alloc")]
impl From<ScriptGuess<'_>> for GuessResult {
    fn from(g: ScriptGuess<'_>) -> Self {
        GuessResult {
            pubkey: g.pubkey.map(<[u8]>::to_vec),
            pubkey_hash: g.pubkey_hash.map(Vec::from),
        }
    }
}

/// Attempts to guess the pubkey hash (and possibly the pubkey) from an output
/// script.
#[cfg(feature = "alloc")]
pub fn guess_by_out_script(script: &[u8]) -> GuessResult {
    guess_out_script(script).into()
}

/// Attempts to guess the pubkey hash (and pubkey) from an input script.
#[cfg(feature = "alloc")]
pub fn guess_by_in_script(script: &[u8]) -> GuessResult {
    guess_in_script(script).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_standard_scripts() {
        let h20 = [7u8; 20];
        let h32 = [9u8; 32];
        let mut p2pkh = [0u8; 25];
        p2pkh[..3].copy_from_slice(&[0x76, 0xa9, 0x14]);
        p2pkh[3..23].copy_from_slice(&h20);
        p2pkh[23..].copy_from_slice(&[0x88, 0xac]);
        assert_eq!(&*guess_out_script(&p2pkh).pubkey_hash.unwrap(), &h20);

        let mut p2tr = [0u8; 34];
        p2tr[..2].copy_from_slice(&[0x51, 0x20]);
        p2tr[2..].copy_from_slice(&h32);
        assert_eq!(&*guess_out_script(&p2tr).pubkey_hash.unwrap(), &h32);

        let mut p2pk = [0u8; 35];
        p2pk[0] = 0x21;
        p2pk[1] = 0x02;
        p2pk[34] = 0xac;
        let g = guess_out_script(&p2pk);
        assert_eq!(g.pubkey, Some(&p2pk[1..34]));
        assert_eq!(&*g.pubkey_hash.unwrap(), &hash160(&p2pk[1..34]));

        // wrong lengths are not recognized
        assert_eq!(guess_out_script(&p2pkh[..24]), ScriptGuess::default());
        assert_eq!(guess_out_script(&[]), ScriptGuess::default());

        // scriptSig: <sig> <pubkey>
        let script_sig = [0x02, 0xaa, 0xbb, 0x03, 0x01, 0x02, 0x03];
        let g = guess_in_script(&script_sig);
        assert_eq!(g.pubkey, Some(&[1u8, 2, 3][..]));
    }
}
