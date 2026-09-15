//! Output-script generation for a public key.
//!
//! [`generate_script`] derives any built-in format into an inline buffer
//! without allocating. With `alloc`, the `Script` engine wraps it with a
//! cache and `Out` conversion, and `format_def` describes each format as
//! composable `Insertable` steps.

#[cfg(feature = "alloc")]
use crate::prelude::*;
#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;
#[cfg(feature = "alloc")]
use core::cell::RefCell;

use crate::crypto::secp256k1::taproot_tweak;
use crate::hash::{blake2b224, blake3_256, ether_hash, hash160, sha256_once};
#[cfg(feature = "alloc")]
use crate::hash::{blake2b224_vec, blake3_vec, ether_hash_vec, sha256_vec};
use crate::inline::InlineBytes;
#[cfg(feature = "alloc")]
use crate::insertable::{Format, b, ihash, ihash160, lookup, push, ttweak};
#[cfg(feature = "alloc")]
use crate::out::Out;
use crate::pubkey::PubKey;

/// The longest script any built-in format produces (`p2puk`: a 65-byte push
/// plus `OP_CHECKSIG`).
pub const MAX_SCRIPT_LEN: usize = 67;

/// A generated output script (or public-key encoding), stored inline.
pub type ScriptBytes = InlineBytes<MAX_SCRIPT_LEN>;

/// Errors from [`generate_script`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The format name is not a built-in format.
    UnknownFormat,
    /// The format needs a different key type (e.g. `p2pkh` from an Ed25519
    /// key).
    UnsupportedKey,
    /// The key could not be used for the format (e.g. a failed taproot tweak).
    InvalidKey,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::UnknownFormat => "unsupported format",
            Error::UnsupportedKey => "public key type not supported by this format",
            Error::InvalidKey => "invalid public key for this format",
        })
    }
}

impl core::error::Error for Error {}

fn script_of(parts: &[&[u8]]) -> ScriptBytes {
    let mut out = ScriptBytes::new();
    for p in parts {
        out.extend_from_slice(p)
            .expect("built-in formats fit MAX_SCRIPT_LEN");
    }
    out
}

/// Generates the bytes of a built-in format (any name in [`ALL_FORMATS`], or
/// `pubkey:comp` / `pubkey:uncomp` / `pubkey:ed25519`) for `pubkey`, without
/// allocating.
pub fn generate_script(pubkey: &PubKey, name: &str) -> Result<ScriptBytes, Error> {
    let comp = || match pubkey {
        PubKey::Secp256k1(k) => Ok(k.serialize_compressed()),
        _ => Err(Error::UnsupportedKey),
    };
    let uncomp = || match pubkey {
        PubKey::Secp256k1(k) => Ok(k.serialize_uncompressed()),
        _ => Err(Error::UnsupportedKey),
    };
    let ed = || match pubkey {
        PubKey::Ed25519(k) => Ok(*k),
        _ => Err(Error::UnsupportedKey),
    };

    if let Some(inner) = name.strip_prefix("p2sh:") {
        if !matches!(inner, "p2pkh" | "p2pukh" | "p2pk" | "p2puk" | "p2wpkh") {
            return Err(Error::UnknownFormat);
        }
        let redeem = generate_script(pubkey, inner)?;
        return Ok(script_of(&[&[0xa9, 0x14], &hash160(&redeem), &[0x87]]));
    }
    if let Some(inner) = name.strip_prefix("p2wsh:") {
        if !matches!(inner, "p2pkh" | "p2pukh" | "p2pk" | "p2puk" | "p2wpkh") {
            return Err(Error::UnknownFormat);
        }
        let witness_script = generate_script(pubkey, inner)?;
        return Ok(script_of(&[&[0x00, 0x20], &sha256_once(&witness_script)]));
    }

    Ok(match name {
        "pubkey:comp" => script_of(&[&comp()?]),
        "pubkey:uncomp" => script_of(&[&uncomp()?]),
        "pubkey:ed25519" => script_of(&[&ed()?]),
        "p2pkh" => script_of(&[&[0x76, 0xa9, 0x14], &hash160(&comp()?), &[0x88, 0xac]]),
        "p2pukh" => script_of(&[&[0x76, 0xa9, 0x14], &hash160(&uncomp()?), &[0x88, 0xac]]),
        "p2pk" => script_of(&[&[0x21], &comp()?, &[0xac]]),
        "p2puk" => script_of(&[&[0x41], &uncomp()?, &[0xac]]),
        "p2wpkh" => script_of(&[&[0x00, 0x14], &hash160(&comp()?)]),
        "p2tr" => {
            let c = comp()?;
            let mut x_only = [0u8; 32];
            x_only.copy_from_slice(&c[1..]);
            let (tweaked, _) = taproot_tweak(&x_only).map_err(|_| Error::InvalidKey)?;
            script_of(&[&[0x51, 0x20], &tweaked])
        }
        "eth" => script_of(&[&ether_hash(&uncomp()?)]),
        "massa_pubkey" => script_of(&[&[0x00], &ed()?]),
        "massa" => {
            let mut massa_pubkey = [0u8; 33];
            massa_pubkey[1..].copy_from_slice(&ed()?);
            script_of(&[&[0x00, 0x00], &blake3_256(&massa_pubkey)])
        }
        "solana" => script_of(&[&ed()?]),
        // type-6 enterprise address payload (mainnet header 0x61) followed by
        // the blake2b-224 payment key hash; the address encoder adjusts the
        // network nibble.
        "cardano" => script_of(&[&[0x61], &blake2b224(&ed()?)]),
        _ => return Err(Error::UnknownFormat),
    })
}

/// Returns the format definition for a name.
#[cfg(feature = "alloc")]
pub fn format_def(name: &str) -> Option<Format> {
    let f = match name {
        "p2pkh" => vec![
            b(&[0x76, 0xa9]),
            push(ihash160(lookup("pubkey:comp"))),
            b(&[0x88, 0xac]),
        ],
        "p2pukh" => vec![
            b(&[0x76, 0xa9]),
            push(ihash160(lookup("pubkey:uncomp"))),
            b(&[0x88, 0xac]),
        ],
        "p2pk" => vec![push(lookup("pubkey:comp")), b(&[0xac])],
        "p2puk" => vec![push(lookup("pubkey:uncomp")), b(&[0xac])],
        "p2wpkh" => vec![b(&[0x00]), push(ihash160(lookup("pubkey:comp")))],
        "p2tr" => vec![b(&[0x51]), push(ttweak(lookup("pubkey:comp")))],
        "p2sh:p2pkh" => vec![b(&[0xa9]), push(ihash160(lookup("p2pkh"))), b(&[0x87])],
        "p2sh:p2pukh" => vec![b(&[0xa9]), push(ihash160(lookup("p2pukh"))), b(&[0x87])],
        "p2sh:p2pk" => vec![b(&[0xa9]), push(ihash160(lookup("p2pk"))), b(&[0x87])],
        "p2sh:p2puk" => vec![b(&[0xa9]), push(ihash160(lookup("p2puk"))), b(&[0x87])],
        "p2sh:p2wpkh" => vec![b(&[0xa9]), push(ihash160(lookup("p2wpkh"))), b(&[0x87])],
        "p2wsh:p2pkh" => vec![b(&[0x00]), push(ihash(lookup("p2pkh"), &[sha256_vec]))],
        "p2wsh:p2pukh" => vec![b(&[0x00]), push(ihash(lookup("p2pukh"), &[sha256_vec]))],
        "p2wsh:p2pk" => vec![b(&[0x00]), push(ihash(lookup("p2pk"), &[sha256_vec]))],
        "p2wsh:p2puk" => vec![b(&[0x00]), push(ihash(lookup("p2puk"), &[sha256_vec]))],
        "p2wsh:p2wpkh" => vec![b(&[0x00]), push(ihash(lookup("p2wpkh"), &[sha256_vec]))],
        "eth" => vec![ihash(lookup("pubkey:uncomp"), &[ether_hash_vec])],
        "massa_pubkey" => vec![b(&[0x00]), lookup("pubkey:ed25519")],
        "massa" => vec![
            b(&[0x00, 0x00]),
            ihash(lookup("massa_pubkey"), &[blake3_vec]),
        ],
        "solana" => vec![lookup("pubkey:ed25519")],
        // cardano: type-6 enterprise address payload (mainnet header 0x61) followed
        // by the blake2b-224 payment key hash. Out::address adjusts the network nibble.
        "cardano" => vec![
            b(&[0x61]),
            ihash(lookup("pubkey:ed25519"), &[blake2b224_vec]),
        ],
        _ => return None,
    };
    Some(f)
}

/// All built-in format names (enumerated by `get_outs`).
pub const ALL_FORMATS: &[&str] = &[
    "p2pkh",
    "p2pukh",
    "p2pk",
    "p2puk",
    "p2wpkh",
    "p2tr",
    "p2sh:p2pkh",
    "p2sh:p2pukh",
    "p2sh:p2pk",
    "p2sh:p2puk",
    "p2sh:p2wpkh",
    "p2wsh:p2pkh",
    "p2wsh:p2pukh",
    "p2wsh:p2pk",
    "p2wsh:p2puk",
    "p2wsh:p2wpkh",
    "eth",
    "massa_pubkey",
    "massa",
    "solana",
    "cardano",
];

/// Typical formats available for each network (port of `FormatsPerNetwork`).
pub fn formats_per_network(network: &str) -> Option<&'static [&'static str]> {
    Some(match network {
        "bitcoin" => &[
            "p2tr",
            "p2wpkh",
            "p2sh:p2wpkh",
            "p2puk",
            "p2pk",
            "p2pukh",
            "p2pkh",
        ],
        "bitcoin-cash" => &["p2puk", "p2pk", "p2pukh", "p2pkh"],
        "litecoin" => &["p2wpkh", "p2sh:p2wpkh", "p2puk", "p2pk", "p2pukh", "p2pkh"],
        "dogecoin" => &["p2puk", "p2pk", "p2pukh", "p2pkh"],
        "evm" => &["eth"],
        "massa" => &["massa"],
        "solana" => &["solana"],
        "cardano" => &["cardano"],
        _ => return None,
    })
}

/// Holds a public key and caches generated output scripts for various formats.
#[cfg(feature = "alloc")]
pub struct Script {
    pubkey: PubKey,
    cache: RefCell<BTreeMap<String, Vec<u8>>>,
}

#[cfg(feature = "alloc")]
impl Script {
    /// Creates a new [`Script`] for the given public key.
    pub fn new(pubkey: impl Into<PubKey>) -> Script {
        Script {
            pubkey: pubkey.into(),
            cache: RefCell::new(BTreeMap::new()),
        }
    }

    /// The underlying public key.
    pub fn pubkey(&self) -> &PubKey {
        &self.pubkey
    }

    /// Returns the byte value for the specified format name, generating and
    /// caching it as needed.
    pub fn generate(&self, name: &str) -> Result<Vec<u8>, String> {
        if let Some(v) = self.cache.borrow().get(name) {
            return Ok(v.clone());
        }

        let out: Vec<u8> = generate_script(&self.pubkey, name)
            .map_err(|e| match e {
                Error::UnknownFormat => format!("unsupported format {name}"),
                Error::UnsupportedKey => format!("public key does not support {name}"),
                e => format!("{name}: {e}"),
            })?
            .into();
        self.cache
            .borrow_mut()
            .insert(name.to_string(), out.clone());
        Ok(out)
    }

    /// Returns an [`Out`] for the requested format.
    pub fn out(&self, name: &str) -> Result<Out, String> {
        let buf = self.generate(name)?;
        Ok(Out::make(name, buf, &[]))
    }

    /// Formats the key as an address using the given format and optional network
    /// hints.
    pub fn address(&self, script: &str, flags: &[&str]) -> Result<String, String> {
        let out = self.out(script)?;
        out.address(flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secp256k1::SecpPrivateKey;

    #[test]
    fn generate_script_checks_names_and_key_types() {
        let secp = PubKey::Secp256k1(key().public_key());
        let ed = PubKey::Ed25519([9u8; 32]);
        assert_eq!(
            generate_script(&secp, "p2puk").unwrap().len(),
            MAX_SCRIPT_LEN
        );
        assert_eq!(generate_script(&secp, "solana"), Err(Error::UnsupportedKey));
        assert_eq!(
            generate_script(&ed, "p2sh:p2pkh"),
            Err(Error::UnsupportedKey)
        );
        assert_eq!(
            generate_script(&secp, "p2sh:eth"),
            Err(Error::UnknownFormat)
        );
        assert_eq!(generate_script(&secp, "nope"), Err(Error::UnknownFormat));
    }

    /// The heap-free generator must agree with the `Insertable` format
    /// definitions for every built-in format and both key types.
    #[cfg(feature = "alloc")]
    #[test]
    fn generate_script_matches_format_defs() {
        for pk in [
            PubKey::Secp256k1(key().public_key()),
            PubKey::Ed25519(crate::crypto::ed25519::public_from_seed(&[7u8; 32])),
        ] {
            let s = Script::new(pk.clone());
            for name in ALL_FORMATS {
                let via_defs: Result<Vec<u8>, String> = format_def(name)
                    .unwrap()
                    .iter()
                    .map(|piece| piece.bytes(&s))
                    .collect::<Result<Vec<_>, _>>()
                    .map(|parts| parts.concat());
                match generate_script(&pk, name) {
                    Ok(got) => assert_eq!(Ok(got.to_vec()), via_defs, "{name}"),
                    Err(_) => assert!(via_defs.is_err(), "{name}"),
                }
            }
        }
    }

    fn key() -> SecpPrivateKey {
        let mut s = [0u8; 32];
        s.copy_from_slice(
            &hex::decode("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")
                .unwrap(),
        );
        SecpPrivateKey::from_bytes(&s).unwrap()
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn generates_p2pkh_script() {
        let s = Script::new(key().public_key());
        let script = s.generate("p2pkh").unwrap();
        // OP_DUP OP_HASH160 <20> ... OP_EQUALVERIFY OP_CHECKSIG
        assert_eq!(script.len(), 25);
        assert_eq!(&script[..3], &[0x76, 0xa9, 0x14]);
        assert_eq!(&script[23..], &[0x88, 0xac]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn generates_p2wpkh_and_p2tr() {
        let s = Script::new(key().public_key());
        let wpkh = s.generate("p2wpkh").unwrap();
        assert_eq!(wpkh.len(), 22);
        assert_eq!(&wpkh[..2], &[0x00, 0x14]);
        let tr = s.generate("p2tr").unwrap();
        assert_eq!(tr.len(), 34);
        assert_eq!(&tr[..2], &[0x51, 0x20]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn caching_is_consistent() {
        let s = Script::new(key().public_key());
        assert_eq!(
            s.generate("p2sh:p2wpkh").unwrap(),
            s.generate("p2sh:p2wpkh").unwrap()
        );
    }
}
