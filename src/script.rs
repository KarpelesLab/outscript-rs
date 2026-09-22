//! Output-script generation for a public key.
//!
//! [`generate_script`] derives any built-in format into an inline buffer
//! without allocating. With `alloc`, the `Script` engine wraps it with a
//! cache and `Out` conversion, and `format_def` describes each format as
//! composable `Insertable` steps.

pub use crate::Error;

#[cfg(feature = "alloc")]
use crate::prelude::*;
#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;
#[cfg(feature = "alloc")]
use core::cell::RefCell;

#[cfg(feature = "bitcoin")]
use crate::crypto::secp256k1::taproot_tweak;
#[cfg(feature = "cardano")]
use crate::hash::blake2b224;
#[cfg(all(feature = "alloc", feature = "cardano"))]
use crate::hash::blake2b224_vec;
#[cfg(feature = "massa")]
use crate::hash::blake3_256;
#[cfg(all(feature = "alloc", feature = "massa"))]
use crate::hash::blake3_vec;
#[cfg(feature = "evm")]
use crate::hash::ether_hash;
#[cfg(all(feature = "alloc", feature = "evm"))]
use crate::hash::ether_hash_vec;
#[cfg(any(feature = "bitcoin", feature = "zcash"))]
use crate::hash::hash160;
#[cfg(feature = "bitcoin")]
use crate::hash::sha256_once;
#[cfg(all(feature = "alloc", feature = "bitcoin"))]
use crate::hash::sha256_vec;
use crate::inline::InlineBytes;
// `Format` plus the constructors `format_def` uses for the enabled chains.
#[cfg(feature = "alloc")]
use crate::insertable::*;
#[cfg(feature = "alloc")]
use crate::out::Out;
use crate::pubkey::PubKey;

/// The longest script any built-in format produces (`p2puk`: a 65-byte push
/// plus `OP_CHECKSIG`).
pub const MAX_SCRIPT_LEN: usize = 67;

/// A generated output script (or public-key encoding), stored inline.
pub type ScriptBytes = InlineBytes<MAX_SCRIPT_LEN>;

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
///
/// Formats of chains that are not enabled are unknown
/// ([`Error::UnknownFormat`]); the key-encoding formats always exist but fail
/// with [`Error::UnsupportedKeyType`] for a key of another curve.
pub fn generate_script(pubkey: &PubKey, name: &str) -> Result<ScriptBytes, Error> {
    let comp = || -> Result<[u8; 33], Error> {
        match pubkey {
            #[cfg(feature = "secp256k1")]
            PubKey::Secp256k1(k) => Ok(k.serialize_compressed()),
            #[allow(unreachable_patterns)]
            _ => Err(Error::UnsupportedKeyType),
        }
    };
    let uncomp = || -> Result<[u8; 65], Error> {
        match pubkey {
            #[cfg(feature = "secp256k1")]
            PubKey::Secp256k1(k) => Ok(k.serialize_uncompressed()),
            #[allow(unreachable_patterns)]
            _ => Err(Error::UnsupportedKeyType),
        }
    };
    let ed = || -> Result<[u8; 32], Error> {
        match pubkey {
            #[cfg(feature = "ed25519")]
            PubKey::Ed25519(k) => Ok(*k),
            #[allow(unreachable_patterns)]
            _ => Err(Error::UnsupportedKeyType),
        }
    };

    #[cfg(feature = "bitcoin")]
    if let Some(inner) = name.strip_prefix("p2sh:") {
        if !matches!(inner, "p2pkh" | "p2pukh" | "p2pk" | "p2puk" | "p2wpkh") {
            return Err(Error::UnknownFormat);
        }
        let redeem = generate_script(pubkey, inner)?;
        return Ok(script_of(&[&[0xa9, 0x14], &hash160(&redeem), &[0x87]]));
    }
    #[cfg(feature = "bitcoin")]
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
        #[cfg(any(feature = "bitcoin", feature = "zcash"))]
        "p2pkh" => script_of(&[&[0x76, 0xa9, 0x14], &hash160(&comp()?), &[0x88, 0xac]]),
        #[cfg(feature = "bitcoin")]
        "p2pukh" => script_of(&[&[0x76, 0xa9, 0x14], &hash160(&uncomp()?), &[0x88, 0xac]]),
        #[cfg(feature = "bitcoin")]
        "p2pk" => script_of(&[&[0x21], &comp()?, &[0xac]]),
        #[cfg(feature = "bitcoin")]
        "p2puk" => script_of(&[&[0x41], &uncomp()?, &[0xac]]),
        #[cfg(feature = "bitcoin")]
        "p2wpkh" => script_of(&[&[0x00, 0x14], &hash160(&comp()?)]),
        #[cfg(feature = "bitcoin")]
        "p2tr" => {
            let c = comp()?;
            let mut x_only = [0u8; 32];
            x_only.copy_from_slice(&c[1..]);
            let (tweaked, _) = taproot_tweak(&x_only).map_err(|_| Error::InvalidKey)?;
            script_of(&[&[0x51, 0x20], &tweaked])
        }
        #[cfg(feature = "evm")]
        "eth" => script_of(&[&ether_hash(&uncomp()?)]),
        #[cfg(feature = "massa")]
        "massa_pubkey" => script_of(&[&[0x00], &ed()?]),
        #[cfg(feature = "massa")]
        "massa" => {
            let mut massa_pubkey = [0u8; 33];
            massa_pubkey[1..].copy_from_slice(&ed()?);
            script_of(&[&[0x00, 0x00], &blake3_256(&massa_pubkey)])
        }
        #[cfg(feature = "solana")]
        "solana" => script_of(&[&ed()?]),
        // type-6 enterprise address payload (mainnet header 0x61) followed by
        // the blake2b-224 payment key hash; the address encoder adjusts the
        // network nibble.
        #[cfg(feature = "cardano")]
        "cardano" => script_of(&[&[0x61], &blake2b224(&ed()?)]),
        _ => return Err(Error::UnknownFormat),
    })
}

/// Returns the format definition for a name (`None` for unknown names and for
/// the formats of chains that are not enabled).
#[cfg(feature = "alloc")]
pub fn format_def(name: &str) -> Option<Format> {
    match name {
        #[cfg(any(feature = "bitcoin", feature = "zcash"))]
        "p2pkh" => Some(vec![
            b(&[0x76, 0xa9]),
            push(ihash160(lookup("pubkey:comp"))),
            b(&[0x88, 0xac]),
        ]),
        #[cfg(feature = "bitcoin")]
        "p2pukh" => Some(vec![
            b(&[0x76, 0xa9]),
            push(ihash160(lookup("pubkey:uncomp"))),
            b(&[0x88, 0xac]),
        ]),
        #[cfg(feature = "bitcoin")]
        "p2pk" => Some(vec![push(lookup("pubkey:comp")), b(&[0xac])]),
        #[cfg(feature = "bitcoin")]
        "p2puk" => Some(vec![push(lookup("pubkey:uncomp")), b(&[0xac])]),
        #[cfg(feature = "bitcoin")]
        "p2wpkh" => Some(vec![b(&[0x00]), push(ihash160(lookup("pubkey:comp")))]),
        #[cfg(feature = "bitcoin")]
        "p2tr" => Some(vec![b(&[0x51]), push(ttweak(lookup("pubkey:comp")))]),
        #[cfg(feature = "bitcoin")]
        "p2sh:p2pkh" => Some(vec![
            b(&[0xa9]),
            push(ihash160(lookup("p2pkh"))),
            b(&[0x87]),
        ]),
        #[cfg(feature = "bitcoin")]
        "p2sh:p2pukh" => Some(vec![
            b(&[0xa9]),
            push(ihash160(lookup("p2pukh"))),
            b(&[0x87]),
        ]),
        #[cfg(feature = "bitcoin")]
        "p2sh:p2pk" => Some(vec![b(&[0xa9]), push(ihash160(lookup("p2pk"))), b(&[0x87])]),
        #[cfg(feature = "bitcoin")]
        "p2sh:p2puk" => Some(vec![
            b(&[0xa9]),
            push(ihash160(lookup("p2puk"))),
            b(&[0x87]),
        ]),
        #[cfg(feature = "bitcoin")]
        "p2sh:p2wpkh" => Some(vec![
            b(&[0xa9]),
            push(ihash160(lookup("p2wpkh"))),
            b(&[0x87]),
        ]),
        #[cfg(feature = "bitcoin")]
        "p2wsh:p2pkh" => Some(vec![
            b(&[0x00]),
            push(ihash(lookup("p2pkh"), &[sha256_vec])),
        ]),
        #[cfg(feature = "bitcoin")]
        "p2wsh:p2pukh" => Some(vec![
            b(&[0x00]),
            push(ihash(lookup("p2pukh"), &[sha256_vec])),
        ]),
        #[cfg(feature = "bitcoin")]
        "p2wsh:p2pk" => Some(vec![b(&[0x00]), push(ihash(lookup("p2pk"), &[sha256_vec]))]),
        #[cfg(feature = "bitcoin")]
        "p2wsh:p2puk" => Some(vec![
            b(&[0x00]),
            push(ihash(lookup("p2puk"), &[sha256_vec])),
        ]),
        #[cfg(feature = "bitcoin")]
        "p2wsh:p2wpkh" => Some(vec![
            b(&[0x00]),
            push(ihash(lookup("p2wpkh"), &[sha256_vec])),
        ]),
        #[cfg(feature = "evm")]
        "eth" => Some(vec![ihash(lookup("pubkey:uncomp"), &[ether_hash_vec])]),
        #[cfg(feature = "massa")]
        "massa_pubkey" => Some(vec![b(&[0x00]), lookup("pubkey:ed25519")]),
        #[cfg(feature = "massa")]
        "massa" => Some(vec![
            b(&[0x00, 0x00]),
            ihash(lookup("massa_pubkey"), &[blake3_vec]),
        ]),
        #[cfg(feature = "solana")]
        "solana" => Some(vec![lookup("pubkey:ed25519")]),
        // cardano: type-6 enterprise address payload (mainnet header 0x61) followed
        // by the blake2b-224 payment key hash. Out::address adjusts the network nibble.
        #[cfg(feature = "cardano")]
        "cardano" => Some(vec![
            b(&[0x61]),
            ihash(lookup("pubkey:ed25519"), &[blake2b224_vec]),
        ]),
        _ => None,
    }
}

/// All built-in format names of the enabled chains (enumerated by `get_outs`).
pub const ALL_FORMATS: &[&str] = &[
    #[cfg(any(feature = "bitcoin", feature = "zcash"))]
    "p2pkh",
    #[cfg(feature = "bitcoin")]
    "p2pukh",
    #[cfg(feature = "bitcoin")]
    "p2pk",
    #[cfg(feature = "bitcoin")]
    "p2puk",
    #[cfg(feature = "bitcoin")]
    "p2wpkh",
    #[cfg(feature = "bitcoin")]
    "p2tr",
    #[cfg(feature = "bitcoin")]
    "p2sh:p2pkh",
    #[cfg(feature = "bitcoin")]
    "p2sh:p2pukh",
    #[cfg(feature = "bitcoin")]
    "p2sh:p2pk",
    #[cfg(feature = "bitcoin")]
    "p2sh:p2puk",
    #[cfg(feature = "bitcoin")]
    "p2sh:p2wpkh",
    #[cfg(feature = "bitcoin")]
    "p2wsh:p2pkh",
    #[cfg(feature = "bitcoin")]
    "p2wsh:p2pukh",
    #[cfg(feature = "bitcoin")]
    "p2wsh:p2pk",
    #[cfg(feature = "bitcoin")]
    "p2wsh:p2puk",
    #[cfg(feature = "bitcoin")]
    "p2wsh:p2wpkh",
    #[cfg(feature = "evm")]
    "eth",
    #[cfg(feature = "massa")]
    "massa_pubkey",
    #[cfg(feature = "massa")]
    "massa",
    #[cfg(feature = "solana")]
    "solana",
    #[cfg(feature = "cardano")]
    "cardano",
];

/// Typical formats available for each network (port of `FormatsPerNetwork`).
/// Networks of chains that are not enabled are unknown (`None`).
pub fn formats_per_network(network: &str) -> Option<&'static [&'static str]> {
    match network {
        #[cfg(feature = "bitcoin")]
        "bitcoin" => Some(&[
            "p2tr",
            "p2wpkh",
            "p2sh:p2wpkh",
            "p2puk",
            "p2pk",
            "p2pukh",
            "p2pkh",
        ]),
        #[cfg(feature = "bitcoin")]
        "bitcoin-cash" => Some(&["p2puk", "p2pk", "p2pukh", "p2pkh"]),
        #[cfg(feature = "bitcoin")]
        "litecoin" => Some(&["p2wpkh", "p2sh:p2wpkh", "p2puk", "p2pk", "p2pukh", "p2pkh"]),
        #[cfg(feature = "bitcoin")]
        "dogecoin" => Some(&["p2puk", "p2pk", "p2pukh", "p2pkh"]),
        #[cfg(feature = "zcash")]
        "zcash" | "zcash-testnet" => Some(&["p2pkh"]),
        #[cfg(feature = "evm")]
        "evm" => Some(&["eth"]),
        #[cfg(feature = "massa")]
        "massa" => Some(&["massa"]),
        #[cfg(feature = "solana")]
        "solana" => Some(&["solana"]),
        #[cfg(feature = "cardano")]
        "cardano" => Some(&["cardano"]),
        _ => None,
    }
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
    pub fn generate(&self, name: &str) -> Result<Vec<u8>, Error> {
        if let Some(v) = self.cache.borrow().get(name) {
            return Ok(v.clone());
        }

        let out: Vec<u8> = generate_script(&self.pubkey, name)?.into();
        self.cache
            .borrow_mut()
            .insert(name.to_string(), out.clone());
        Ok(out)
    }

    /// Returns an [`Out`] for the requested format.
    pub fn out(&self, name: &str) -> Result<Out, Error> {
        let buf = self.generate(name)?;
        Ok(Out::make(name, buf, &[]))
    }

    /// Formats the key as an address using the given format and optional network
    /// hints.
    pub fn address(&self, script: &str, flags: &[&str]) -> Result<String, crate::address::Error> {
        let out = self.out(script)?;
        out.address(flags)
    }
}

#[cfg(all(test, feature = "bitcoin"))]
mod tests {
    use super::*;
    use crate::crypto::secp256k1::SecpPrivateKey;

    #[test]
    fn generate_script_checks_names_and_key_types() {
        let secp = PubKey::Secp256k1(key().public_key());
        assert_eq!(
            generate_script(&secp, "p2puk").unwrap().len(),
            MAX_SCRIPT_LEN
        );
        assert_eq!(
            generate_script(&secp, "pubkey:ed25519"),
            Err(Error::UnsupportedKeyType)
        );
        #[cfg(feature = "solana")]
        assert_eq!(
            generate_script(&secp, "solana"),
            Err(Error::UnsupportedKeyType)
        );
        #[cfg(feature = "ed25519")]
        assert_eq!(
            generate_script(&PubKey::Ed25519([9u8; 32]), "p2sh:p2pkh"),
            Err(Error::UnsupportedKeyType)
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
            #[cfg(feature = "ed25519")]
            PubKey::Ed25519(crate::crypto::ed25519::public_from_seed(&[7u8; 32])),
        ] {
            let s = Script::new(pk.clone());
            for name in ALL_FORMATS {
                let via_defs: Result<Vec<u8>, Error> = format_def(name)
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
