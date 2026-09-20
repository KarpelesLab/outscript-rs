//! The PSBT signer role, and the input-script resolution shared with the
//! finalizer.

use super::{Error, MapEdit, MapLoc, NewRecord, Psbt, input, write_map};
use crate::btcraw::{
    self, RawTxIn, RawTxOut, SIGHASH_UNIFIED, SegwitV0Midstate, TapScriptPath, TapSighash,
    TaprootMidstate, UnifiedSpend, legacy_sighash_of, segwit_v0_midstate_of, taproot_midstate_of,
    taproot_sighash_of, unified_sighash_of,
};
use crate::crypto::secp256k1::{
    DerSignature, SecpPrivateKey, SecpPublicKey, taproot_tweak_with_root,
};
use crate::hash::{hash160, sha256_once};
use crate::inline::InlineBytes;
use crate::pushbytes::parse_push_bytes;
use crate::taproot::{ControlBlock, TAPSCRIPT_LEAF_VERSION};

#[cfg(feature = "alloc")]
use crate::prelude::*;

pub use crate::crypto::SignerError;

/// A key that can sign PSBT inputs: a [`SecpPrivateKey`], or an external
/// signer (hardware wallet, HSM, remote service).
pub trait PsbtSigner {
    /// The public key. For taproot, the internal (untweaked) key.
    fn public_key(&self) -> SecpPublicKey;
    /// A DER-encoded low-S ECDSA signature over `digest` (without the sighash
    /// byte). External signers can build the return value with
    /// [`DerSignature::from_rs_low_s`] or [`DerSignature::from_der`].
    fn sign_ecdsa(&self, digest: &[u8; 32]) -> Result<DerSignature, SignerError>;
    /// A BIP-340 signature over a taproot key-path `sighash` with the key
    /// tweaked for an empty script tree (BIP-86). Unsupported by default.
    fn sign_taproot(&self, _sighash: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        Err(SignerError)
    }
    /// A BIP-340 key-path signature with the key tweaked for the script tree
    /// with `merkle_root` (`None` for an empty tree, as
    /// [`sign_taproot`](Self::sign_taproot)). By default only the empty tree
    /// is supported, through `sign_taproot`.
    fn sign_taproot_with_root(
        &self,
        sighash: &[u8; 32],
        merkle_root: Option<&[u8; 32]>,
    ) -> Result<[u8; 64], SignerError> {
        match merkle_root {
            None => self.sign_taproot(sighash),
            Some(_) => Err(SignerError),
        }
    }
    /// A BIP-340 signature over a taproot script-path `sighash` with the key
    /// as is (no tweak), for a tapscript `OP_CHECKSIG` against the x-only
    /// [`public_key`](Self::public_key). Unsupported by default.
    fn sign_schnorr(&self, _sighash: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        Err(SignerError)
    }
}

impl PsbtSigner for SecpPrivateKey {
    fn public_key(&self) -> SecpPublicKey {
        SecpPrivateKey::public_key(self)
    }
    fn sign_ecdsa(&self, digest: &[u8; 32]) -> Result<DerSignature, SignerError> {
        Ok(self.sign_der(digest))
    }
    fn sign_taproot(&self, sighash: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        SecpPrivateKey::sign_taproot(self, sighash).map_err(|_| SignerError)
    }
    fn sign_taproot_with_root(
        &self,
        sighash: &[u8; 32],
        merkle_root: Option<&[u8; 32]>,
    ) -> Result<[u8; 64], SignerError> {
        SecpPrivateKey::sign_taproot_with_root(self, sighash, merkle_root).map_err(|_| SignerError)
    }
    fn sign_schnorr(&self, sighash: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        SecpPrivateKey::sign_schnorr(self, sighash).map_err(|_| SignerError)
    }
}

// --- script resolution ---

/// What an input spends, once P2SH and P2WSH wrappers are opened.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Kind<'a> {
    /// A non-witness script (bare, or the P2SH redeem script).
    Legacy(&'a [u8]),
    /// P2WPKH (native or P2SH-nested) with this key hash.
    P2wpkh([u8; 20]),
    /// P2WSH (native or P2SH-nested) with this witness script.
    P2wsh(&'a [u8]),
    /// P2TR with this output key.
    P2tr([u8; 32]),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Resolved<'a> {
    pub(crate) utxo: RawTxOut<'a>,
    pub(crate) outpoint: RawTxIn<'a>,
    /// The P2SH redeem script, when the output is P2SH.
    pub(crate) redeem: Option<&'a [u8]>,
    pub(crate) kind: Kind<'a>,
}

fn program<const N: usize>(script: &[u8], version_op: u8) -> Option<[u8; N]> {
    match script {
        [op, len, rest @ ..] if *op == version_op && *len as usize == N && rest.len() == N => {
            rest.try_into().ok()
        }
        _ => None,
    }
}

fn is_witness_program(script: &[u8]) -> bool {
    matches!(script, [op, len, rest @ ..]
        if (*op == 0 || (0x51..=0x60).contains(op))
            && (2..=40).contains(len)
            && rest.len() == *len as usize)
}

/// Resolves what input `index` spends, applying the BIP-174 signer checks.
pub(crate) fn resolve<'a>(psbt: &Psbt<'a>, index: usize) -> Result<Resolved<'a>, Error> {
    let inp = psbt.input(index).ok_or(Error::InputIndex)?;
    let outpoint = psbt
        .unsigned_tx()
        .inputs()
        .nth(index)
        .ok_or(Error::InputIndex)?;
    let utxo = psbt.utxo(index)?;
    let (script, redeem) = match utxo.script {
        [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => {
            let rs = inp.redeem_script().ok_or(Error::MissingRedeemScript)?;
            if hash160(rs) != hash {
                return Err(Error::RedeemScriptMismatch);
            }
            (rs, Some(rs))
        }
        spk => (spk, None),
    };
    let kind = if let Some(hash) = program::<20>(script, 0x00) {
        Kind::P2wpkh(hash)
    } else if let Some(hash) = program::<32>(script, 0x00) {
        let ws = inp.witness_script().ok_or(Error::MissingWitnessScript)?;
        if sha256_once(ws) != hash {
            return Err(Error::WitnessScriptMismatch);
        }
        Kind::P2wsh(ws)
    } else if let (Some(key), None) = (program::<32>(script, 0x51), redeem) {
        Kind::P2tr(key)
    } else if is_witness_program(script) {
        return Err(Error::UnsupportedScript);
    } else {
        if inp.non_witness_utxo().is_none() {
            return Err(Error::WitnessUtxoForNonWitness);
        }
        Kind::Legacy(script)
    };
    Ok(Resolved {
        utxo,
        outpoint,
        redeem,
        kind,
    })
}

/// Calls `f` with each push in `script`, stopping at malformed data.
pub(crate) fn for_each_push<'a>(script: &'a [u8], mut f: impl FnMut(&'a [u8])) {
    let mut pos = 0;
    while let Some(&op) = script.get(pos) {
        if (0x01..=0x4e).contains(&op) {
            match parse_push_bytes(&script[pos..]) {
                Some((data, used)) => {
                    f(data);
                    pos += used;
                }
                None => return,
            }
        } else {
            pos += 1;
        }
    }
}

/// The form of `pubkey` (compressed or uncompressed) that `script` pushes
/// directly or by HASH160, if any.
fn key_in_script<'k>(script: &[u8], comp: &'k [u8; 33], uncomp: &'k [u8; 65]) -> Option<&'k [u8]> {
    let (hc, hu) = (hash160(comp), hash160(uncomp));
    let mut found: Option<&'k [u8]> = None;
    for_each_push(script, |data| {
        if found.is_none() {
            if data == comp || data == hc {
                found = Some(comp);
            } else if data == &uncomp[..] || data == hu {
                found = Some(uncomp);
            }
        }
    });
    found
}

// --- signing ---

/// A signature record to add to an input map.
#[derive(Clone, Copy, Default)]
pub(crate) struct Signed {
    key: InlineBytes<66>,
    value: InlineBytes<73>,
}

/// The most taproot leaves one signing call signs per input. Leaves that
/// already carry this key's signature are skipped, so signing again covers
/// the rest.
pub(crate) const MAX_LEAF_SIGS: usize = 8;

/// The signature records one signer adds to one input: an ECDSA partial
/// signature, or a taproot key-path signature and/or script-path signatures.
#[derive(Clone, Copy, Default)]
pub(crate) struct SignedSet {
    items: [Signed; 1 + MAX_LEAF_SIGS],
    len: usize,
}

impl SignedSet {
    fn push(&mut self, signed: Signed) {
        self.items[self.len] = signed;
        self.len += 1;
    }
    fn is_full(&self) -> bool {
        self.len == self.items.len()
    }
    /// A taproot signature record: the 64-byte signature, followed by the
    /// sighash type unless it is `SIGHASH_DEFAULT`.
    fn push_schnorr(&mut self, key: &[&[u8]], sig: &[u8; 64], hash_type: u8) {
        let mut signed = Signed::default();
        for part in key {
            signed
                .key
                .extend_from_slice(part)
                .expect("fits a 65-byte key");
        }
        signed.value.extend_from_slice(sig).expect("fits");
        if hash_type != 0 {
            signed.value.push(hash_type).expect("fits");
        }
        self.push(signed);
    }
    fn records(&self) -> [NewRecord<'_>; 1 + MAX_LEAF_SIGS] {
        core::array::from_fn(|i| NewRecord {
            key: &self.items[i].key,
            key_tail: &[],
            value: &self.items[i].value,
        })
    }
}

struct SignCtx<'p, 'a> {
    psbt: &'p Psbt<'a>,
    segwit: Option<SegwitV0Midstate>,
    taproot: Option<Result<TaprootMidstate, Error>>,
}

impl<'a> SignCtx<'_, 'a> {
    fn taproot(&mut self) -> Result<TaprootMidstate, Error> {
        let psbt = self.psbt;
        *self.taproot.get_or_insert_with(|| {
            let tx = psbt.unsigned_tx();
            let mut missing = false;
            let prevouts = (0..tx.input_count()).map_while(|i| match psbt.utxo(i) {
                Ok(u) => Some(u),
                Err(_) => {
                    missing = true;
                    None
                }
            });
            let mid = taproot_midstate_of(&tx, prevouts);
            if missing {
                Err(Error::MissingUtxo)
            } else {
                mid.map_err(|_| Error::MissingUtxo)
            }
        })
    }

    /// The digest a taproot signature on input `index` commits to: the unified
    /// sighash if `hash_type` opts in, BIP-341 otherwise.
    fn taproot_digest(
        &mut self,
        index: usize,
        res: &Resolved<'_>,
        hash_type: u8,
        script_path: Option<TapScriptPath>,
    ) -> Result<[u8; 32], Error> {
        let mid = self.taproot()?;
        let tx = self.psbt.unsigned_tx();
        if hash_type & SIGHASH_UNIFIED != 0 {
            let spend = UnifiedSpend::Taproot {
                annex: None,
                script_path,
            };
            return unified_sighash_of(&tx, &mid, index, res.utxo, hash_type, &spend);
        }
        let mut opts = TapSighash::new(hash_type);
        if let Some(leaf) = script_path {
            opts = opts.with_script_path(leaf);
        }
        taproot_sighash_of(&tx, &mid, index, res.utxo, &opts)
    }

    /// Signs input `index` wherever the signer's key is involved (an empty
    /// set if it is not).
    fn sign_input(&mut self, index: usize, signer: &dyn PsbtSigner) -> Result<SignedSet, Error> {
        let mut set = SignedSet::default();
        if let Some(signed) = self.sign_input_ecdsa_or_taproot(index, signer, &mut set)? {
            set.push(signed);
        }
        Ok(set)
    }

    /// Taproot signatures go into `set`; an ECDSA signature is returned.
    fn sign_input_ecdsa_or_taproot(
        &mut self,
        index: usize,
        signer: &dyn PsbtSigner,
        set: &mut SignedSet,
    ) -> Result<Option<Signed>, Error> {
        let psbt = self.psbt;
        let inp = psbt.input(index).ok_or(Error::InputIndex)?;
        if inp.is_finalized() {
            return Ok(None);
        }
        let res = resolve(psbt, index)?;
        let pubkey = signer.public_key();
        let comp = pubkey.serialize_compressed();
        let uncomp = pubkey.serialize_uncompressed();

        if let Kind::P2tr(output_key) = res.kind {
            let x_only: [u8; 32] = comp[1..].try_into().unwrap();
            let hash_type = match inp.sighash_type() {
                None => 0,
                Some(t @ (0x00..=0x03 | 0x81..=0x83 | 0x21..=0x23 | 0xa1..=0xa3)) => t as u8,
                Some(_) => return Err(Error::UnsupportedSighash),
            };
            let mut signer_failed = false;

            // key path: the signer holds the internal key, and tweaking it with
            // the input's merkle root (if any) gives the output key
            let root = inp.tap_merkle_root();
            if inp.tap_internal_key().is_none_or(|k| k == x_only)
                && taproot_tweak_with_root(&x_only, root.as_ref())
                    .map(|(k, _)| k)
                    .ok()
                    == Some(output_key)
            {
                let sighash = self.taproot_digest(index, &res, hash_type, None)?;
                match signer.sign_taproot_with_root(&sighash, root.as_ref()) {
                    Ok(sig) => set.push_schnorr(&[&[input::TAP_KEY_SIG as u8]], &sig, hash_type),
                    Err(_) => signer_failed = true,
                }
            }

            // script path: every proven tapscript leaf that pushes the key and
            // is not signed by it yet
            for leaf in inp.tap_leaf_scripts() {
                if set.is_full() {
                    break;
                }
                if leaf.leaf_version != TAPSCRIPT_LEAF_VERSION {
                    continue;
                }
                let mut involved = false;
                for_each_push(leaf.script, |data| involved |= data == x_only);
                if !involved {
                    continue;
                }
                let Ok(cb) = ControlBlock::parse(leaf.control_block) else {
                    continue;
                };
                if cb.leaf_version != leaf.leaf_version || !cb.verify(leaf.script, &output_key) {
                    continue;
                }
                let leaf_hash = cb.leaf_hash(leaf.script);
                if inp.tap_script_sig(&x_only, &leaf_hash).is_some() {
                    continue;
                }
                let path = TapScriptPath::new(leaf_hash);
                let sighash = self.taproot_digest(index, &res, hash_type, Some(path))?;
                match signer.sign_schnorr(&sighash) {
                    Ok(sig) => set.push_schnorr(
                        &[&[input::TAP_SCRIPT_SIG as u8], &x_only, &leaf_hash],
                        &sig,
                        hash_type,
                    ),
                    Err(_) => signer_failed = true,
                }
            }
            // a signer that cannot do one of the two still signs what it can
            if set.len == 0 && signer_failed {
                return Err(Error::Signer);
            }
            return Ok(None);
        }

        let p2wpkh_code;
        let (script_code, segwit, key): (&[u8], bool, &[u8]) = match res.kind {
            Kind::P2wpkh(hash) => {
                if hash160(&comp) != hash {
                    return Ok(None);
                }
                p2wpkh_code = btcraw::p2pkh_script_code(&hash);
                (&p2wpkh_code, true, &comp)
            }
            Kind::P2wsh(ws) => match key_in_script(ws, &comp, &uncomp) {
                Some(k) => (ws, true, k),
                None => return Ok(None),
            },
            Kind::Legacy(script) => match key_in_script(script, &comp, &uncomp) {
                Some(k) => (script, false, k),
                None => return Ok(None),
            },
            Kind::P2tr(_) => unreachable!("handled above"),
        };
        let hash_type = match inp.sighash_type().unwrap_or(1) {
            1 => 1,
            t @ 0..=0xff if t & u32::from(SIGHASH_UNIFIED) != 0 => t as u8,
            _ => return Err(Error::UnsupportedSighash),
        };
        let digest = if hash_type & SIGHASH_UNIFIED != 0 {
            let spend = if segwit {
                UnifiedSpend::SegwitV0(script_code)
            } else {
                UnifiedSpend::Legacy(script_code)
            };
            let mid = self.taproot()?;
            unified_sighash_of(
                &psbt.unsigned_tx(),
                &mid,
                index,
                res.utxo,
                hash_type,
                &spend,
            )?
        } else if segwit {
            let tx = psbt.unsigned_tx();
            self.segwit
                .get_or_insert_with(|| segwit_v0_midstate_of(&tx))
                .sighash(&res.outpoint, script_code, res.utxo.amount, 1)
        } else {
            legacy_sighash_of(&psbt.unsigned_tx(), index, script_code, 1)
                .map_err(|_: btcraw::Error| Error::InputIndex)?
        };
        let der = signer.sign_ecdsa(&digest).map_err(|_| Error::Signer)?;
        let mut value = InlineBytes::from_slice(&der).ok_or(Error::Signer)?;
        value.push(hash_type).unwrap();
        let mut k = InlineBytes::from_slice(&[input::PARTIAL_SIG as u8]).unwrap();
        k.extend_from_slice(key).unwrap();
        Ok(Some(Signed { key: k, value }))
    }
}

/// Errors that make an input unsignable without failing the whole operation.
fn skippable(e: Error) -> bool {
    matches!(
        e,
        Error::MissingUtxo
            | Error::UnsupportedScript
            | Error::MissingRedeemScript
            | Error::MissingWitnessScript
    )
}

impl<'a> Psbt<'a> {
    /// An upper bound on the size of a PSBT produced by signing this one.
    pub fn sign_len_bound(&self) -> usize {
        // per input: key length + 66-byte key + value length + 73-byte value,
        // plus a 65-byte key and 65-byte signature per taproot leaf signed
        let leaf_sigs: usize = self
            .inputs()
            .map(|i| i.tap_leaf_scripts().count().min(MAX_LEAF_SIGS))
            .sum();
        self.len() + self.unsigned_tx().input_count() * 141 + leaf_sigs * 132
    }

    /// Signs every input `signer`'s key is involved in, writing the updated
    /// PSBT into `out` ([`Psbt::sign_len_bound`] bytes suffice). Returns the
    /// length written and the number of inputs signed.
    ///
    /// Taproot inputs are signed on the key path when `signer` holds the
    /// internal key (tweaked with the input's merkle root, if any), and on the
    /// script path for each tapscript leaf that pushes its x-only key and has a
    /// valid control block, up to 8 leaves per input and call; leaves the key
    /// already signed are skipped. The input's sighash type is honoured (any
    /// BIP-341 type for taproot, `SIGHASH_ALL` otherwise), and a type setting
    /// [`SIGHASH_UNIFIED`] signs under the unified opt-in sighash, which needs
    /// the UTXO of every input.
    ///
    /// Inputs that are already finalized, lack the UTXO/script data to sign,
    /// or do not involve the key are left unchanged. An input whose data fails
    /// the BIP-174 signer checks (mismatched txid, redeem or witness script, a
    /// witness UTXO for a non-witness spend) makes the whole operation fail.
    pub fn sign_to_slice(
        &self,
        signer: &dyn PsbtSigner,
        out: &mut [u8],
    ) -> Result<(usize, usize), Error> {
        let mut ctx = SignCtx {
            psbt: self,
            segwit: None,
            taproot: None,
        };
        let mut signed_count = 0;
        let n = self.emit(out, &mut |loc, map, s| {
            if let MapLoc::Input(i) = loc {
                match ctx.sign_input(i, signer) {
                    Ok(set) if set.len > 0 => {
                        signed_count += 1;
                        let add = set.records();
                        write_map(s, map, &MapEdit::add(&add[..set.len]));
                        return Ok(());
                    }
                    Ok(_) => {}
                    Err(e) if skippable(e) => {}
                    Err(e) => return Err(e),
                }
            }
            write_map(s, map, &MapEdit::none());
            Ok(())
        })?;
        Ok((n, signed_count))
    }

    /// Signs input `index` with `signer`, writing the updated PSBT into `out`.
    /// Fails with [`Error::KeyNotInvolved`] if the key does not appear in the
    /// input, or with the reason the input cannot be signed.
    pub fn sign_input_to_slice(
        &self,
        index: usize,
        signer: &dyn PsbtSigner,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut ctx = SignCtx {
            psbt: self,
            segwit: None,
            taproot: None,
        };
        let set = ctx.sign_input(index, signer)?;
        if set.len == 0 {
            return Err(Error::KeyNotInvolved);
        }
        let add = set.records();
        self.edit_map(out, MapLoc::Input(index), MapEdit::add(&add[..set.len]))
    }

    /// [`Psbt::sign_to_slice`] into a new vector.
    #[cfg(feature = "alloc")]
    pub fn sign_to_vec(&self, signer: &dyn PsbtSigner) -> Result<(Vec<u8>, usize), Error> {
        let mut buf = vec![0u8; self.sign_len_bound()];
        let (n, count) = self.sign_to_slice(signer, &mut buf)?;
        buf.truncate(n);
        Ok((buf, count))
    }

    /// [`Psbt::sign_input_to_slice`] into a new vector.
    #[cfg(feature = "alloc")]
    pub fn sign_input_to_vec(
        &self,
        index: usize,
        signer: &dyn PsbtSigner,
    ) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; self.sign_len_bound()];
        let n = self.sign_input_to_slice(index, signer, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}
