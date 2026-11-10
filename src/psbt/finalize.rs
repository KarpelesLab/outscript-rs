//! The PSBT finalizer role.

use super::sign::{Kind, Resolved, SignCtx, for_each_push, resolve};
use super::{
    Error, MapEdit, MapLoc, NewRecord, Psbt, PsbtInput, WriteValue, input, put_varint, write_map,
};
use crate::btcraw::{self, SIGHASH_UNIFIED, TapScriptPath};
use crate::crypto::secp256k1::{SecpPublicKey, bip340_verify, parse_der_signature};
use crate::hash::hash160;
use crate::pushbytes::push_bytes_len;
use crate::sink::{Counter, Sink, SliceSink};
use crate::taproot::{ControlBlock, TAPSCRIPT_LEAF_VERSION};

#[cfg(feature = "alloc")]
use crate::prelude::*;

/// Up to 20 stack items (enough for a 16-of-16 multisig with its dummy and
/// script).
#[derive(Clone, Copy)]
struct Stack<'a> {
    items: [&'a [u8]; 20],
    len: usize,
}

impl<'a> Stack<'a> {
    const EMPTY: Stack<'static> = Stack {
        items: [&[]; 20],
        len: 0,
    };
    fn push(&mut self, item: &'a [u8]) {
        self.items[self.len] = item;
        self.len += 1;
    }
    fn items(&self) -> &[&'a [u8]] {
        &self.items[..self.len]
    }
}

/// A final scriptSig: pushes of `items`, then of `redeem`.
struct ScriptSigValue<'a> {
    items: Stack<'a>,
    redeem: Option<&'a [u8]>,
}

impl ScriptSigValue<'_> {
    fn is_empty(&self) -> bool {
        self.items.len == 0 && self.redeem.is_none()
    }
}

impl WriteValue for ScriptSigValue<'_> {
    fn write_value(&self, s: &mut dyn Sink) {
        for item in self.items.items().iter().chain(self.redeem.as_ref()) {
            let mut header = [0u8; 5];
            let hl = push_bytes_len(item.len()) - item.len();
            write_push_header(s, item.len(), &mut header[..hl]);
            s.put(item);
        }
    }
}

fn write_push_header(s: &mut dyn Sink, len: usize, header: &mut [u8]) {
    match header.len() {
        1 => header[0] = len as u8,
        2 => header.copy_from_slice(&[0x4c, len as u8]),
        3 => {
            header[0] = 0x4d;
            header[1..].copy_from_slice(&(len as u16).to_le_bytes());
        }
        _ => {
            header[0] = 0x4e;
            header[1..].copy_from_slice(&(len as u32).to_le_bytes());
        }
    }
    s.put(header);
}

/// A final witness: item count, then length-prefixed items.
struct WitnessValue<'a>(Stack<'a>);

impl WriteValue for WitnessValue<'_> {
    fn write_value(&self, s: &mut dyn Sink) {
        put_varint(s, self.0.len);
        for item in self.0.items() {
            put_varint(s, item.len());
            s.put(item);
        }
    }
}

/// The standard single-key and multisig script templates.
#[allow(clippy::large_enum_variant)] // short-lived, stack-only
enum Template<'a> {
    Pkh([u8; 20]),
    Pk(&'a [u8]),
    Multi { m: usize, keys: Stack<'a> },
}

fn template(script: &[u8]) -> Option<Template<'_>> {
    match script {
        [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => {
            return Some(Template::Pkh(hash.try_into().ok()?));
        }
        [0x21, key @ .., 0xac] if key.len() == 33 => return Some(Template::Pk(key)),
        [0x41, key @ .., 0xac] if key.len() == 65 => return Some(Template::Pk(key)),
        [m @ 0x51..=0x60, body @ .., n @ 0x51..=0x60, 0xae] => {
            let (m, n) = ((m - 0x50) as usize, (n - 0x50) as usize);
            let mut keys = Stack::EMPTY;
            let mut used = 0;
            let mut ok = true;
            for_each_push(body, |k| {
                if matches!(k.len(), 33 | 65) && keys.len < 16 {
                    keys.push(k);
                    used += 1 + k.len();
                } else {
                    ok = false;
                }
            });
            if ok && used == body.len() && keys.len == n && m <= n {
                return Some(Template::Multi { m, keys });
            }
        }
        _ => {}
    }
    None
}

/// Checks the signatures of one input before the finalizer uses them: a
/// signature whose sighash type disagrees with the input's declared
/// `PSBT_IN_SIGHASH_TYPE`, or that does not verify, is treated as absent.
struct Checker<'c, 'p, 'a> {
    ctx: &'c mut SignCtx<'p, 'a>,
    index: usize,
    res: Resolved<'a>,
    /// The input's `PSBT_IN_SIGHASH_TYPE`, if declared.
    declared: Option<u32>,
}

impl Checker<'_, '_, '_> {
    fn type_ok(&self, hash_type: u8) -> bool {
        self.declared.is_none_or(|d| d == u32::from(hash_type))
    }

    /// Reports whether `sig` (DER, then the sighash byte) is a usable ECDSA
    /// signature of `pubkey` over this input with `script_code`. A hash type
    /// this crate computes no digest for (anything but `SIGHASH_ALL` and the
    /// unified types) cannot be verified and is accepted as is.
    fn ecdsa(&mut self, script_code: &[u8], segwit: bool, pubkey: &[u8], sig: &[u8]) -> bool {
        let Some((&hash_type, der)) = sig.split_last() else {
            return false;
        };
        if !self.type_ok(hash_type) {
            return false;
        }
        if hash_type != 1 && hash_type & SIGHASH_UNIFIED == 0 {
            return true;
        }
        let Ok(digest) =
            self.ctx
                .ecdsa_digest(self.index, &self.res, script_code, segwit, hash_type)
        else {
            return false;
        };
        let (Ok(pk), Ok((r, s))) = (SecpPublicKey::from_sec1(pubkey), parse_der_signature(der))
        else {
            return false;
        };
        pk.verify(&digest, &r, &s)
    }

    /// Reports whether `sig` (64 bytes, or 65 with a non-default sighash
    /// byte) is a valid BIP-340 signature of the x-only `key` over this input,
    /// on the key path or for the leaf `path`.
    fn schnorr(&mut self, key: &[u8], sig: &[u8], path: Option<TapScriptPath>) -> bool {
        let (sig, hash_type) = match sig {
            [sig @ .., hash_type] if sig.len() == 64 && *hash_type != 0 => (sig, *hash_type),
            sig if sig.len() == 64 => (sig, 0),
            _ => return false,
        };
        if !self.type_ok(hash_type) {
            return false;
        }
        let (Ok(key), Ok(sig)) = (<&[u8; 32]>::try_from(key), <&[u8; 64]>::try_from(sig)) else {
            return false;
        };
        match self
            .ctx
            .taproot_digest(self.index, &self.res, hash_type, path)
        {
            Ok(digest) => bip340_verify(key, &digest, sig),
            Err(_) => false,
        }
    }
}

/// The signature stack satisfying `template`, if enough signatures pass `ok`
/// (called with a public key and its signature).
fn satisfy<'a>(
    inp: &PsbtInput<'a>,
    t: &Template<'a>,
    ok: &mut dyn FnMut(&[u8], &[u8]) -> bool,
) -> Option<Stack<'a>> {
    let mut st = Stack::EMPTY;
    match t {
        Template::Pkh(hash) => {
            let (pk, sig) = inp
                .partial_sigs()
                .find(|(pk, sig)| hash160(pk) == *hash && ok(pk, sig))?;
            st.push(sig);
            st.push(pk);
        }
        Template::Pk(key) => st.push(inp.partial_sig(key).filter(|sig| ok(key, sig))?),
        Template::Multi { m, keys } => {
            st.push(&[]); // CHECKMULTISIG dummy
            for key in keys.items() {
                if st.len - 1 == *m {
                    break;
                }
                if let Some(sig) = inp.partial_sig(key).filter(|sig| ok(key, sig)) {
                    st.push(sig);
                }
            }
            if st.len - 1 < *m {
                return None;
            }
        }
    }
    Some(st)
}

/// The tapscript key templates: `<key> OP_CHECKSIG`, and the BIP-342
/// `multi_a` form `<k1> OP_CHECKSIG <k2> OP_CHECKSIGADD ... <m> OP_NUMEQUAL`.
/// Returns the threshold and the 32-byte keys in script order.
fn tap_template(script: &[u8]) -> Option<(usize, Stack<'_>)> {
    let mut keys = Stack::EMPTY;
    let mut rest = script;
    loop {
        // a 32-byte push, then CHECKSIG for the first key and CHECKSIGADD after
        let (key, tail) = match rest {
            [0x20, tail @ ..] => tail.split_at_checked(32)?,
            _ => return None,
        };
        let (&op, tail) = tail.split_first()?;
        if op != if keys.len == 0 { 0xac } else { 0xba } {
            return None;
        }
        // the witness also holds the script and the control block
        if keys.len == 18 {
            return None;
        }
        keys.push(key);
        rest = tail;
        let m = match rest {
            [] if keys.len == 1 => 1,
            [m @ 0x51..=0x60, 0x9c] => (m - 0x50) as usize,
            [0x01, m @ 17..=0x7f, 0x9c] => *m as usize,
            _ => continue,
        };
        return (1..=keys.len).contains(&m).then_some((m, keys));
    }
}

/// The witness spending a taproot input through the script path: the first
/// provable tapscript leaf (preferring the shortest control block) whose
/// template has enough valid signatures.
fn tap_script_witness<'a>(
    inp: &PsbtInput<'a>,
    output_key: &[u8; 32],
    chk: &mut Checker<'_, '_, '_>,
) -> Option<Stack<'a>> {
    let mut best: Option<(usize, Stack<'a>)> = None;
    for leaf in inp.tap_leaf_scripts() {
        if leaf.leaf_version != TAPSCRIPT_LEAF_VERSION
            || best
                .as_ref()
                .is_some_and(|(len, _)| *len <= leaf.control_block.len())
        {
            continue;
        }
        let Some((m, keys)) = tap_template(leaf.script) else {
            continue;
        };
        let Ok(cb) = ControlBlock::parse(leaf.control_block) else {
            continue;
        };
        if cb.leaf_version != leaf.leaf_version || !cb.verify(leaf.script, output_key) {
            continue;
        }
        let leaf_hash = cb.leaf_hash(leaf.script);
        let path = TapScriptPath::new(leaf_hash);
        // exactly `m` signatures, from the first keys that have a valid one;
        // the other keys get an empty vector
        let mut sigs: [&'a [u8]; 18] = [&[]; 18];
        let mut count = 0;
        for (i, key) in keys.items().iter().enumerate() {
            if count == m {
                break;
            }
            let sig = inp
                .tap_script_sigs()
                .find(|(k, l, _)| k == key && *l == leaf_hash)
                .map(|(_, _, sig)| sig);
            if let Some(sig) = sig.filter(|sig| chk.schnorr(key, sig, Some(path))) {
                sigs[i] = sig;
                count += 1;
            }
        }
        if count < m {
            continue;
        }
        // the first key's signature is consumed first, so it sits on top
        let mut st = Stack::EMPTY;
        for sig in sigs[..keys.len].iter().rev() {
            st.push(sig);
        }
        st.push(leaf.script);
        st.push(leaf.control_block);
        best = Some((leaf.control_block.len(), st));
    }
    best.map(|(_, st)| st)
}

struct Final<'a> {
    script_sig: ScriptSigValue<'a>,
    witness: Stack<'a>,
}

fn build_final<'a>(
    ctx: &mut SignCtx<'_, 'a>,
    psbt: &Psbt<'a>,
    index: usize,
    inp: PsbtInput<'a>,
) -> Result<Option<Final<'a>>, Error> {
    let res = resolve(psbt, index, &inp)?;
    let mut chk = Checker {
        ctx,
        index,
        res,
        declared: inp.sighash_type(),
    };
    let mut script_sig = ScriptSigValue {
        items: Stack::EMPTY,
        redeem: res.redeem,
    };
    let mut witness = Stack::EMPTY;
    match res.kind {
        Kind::Legacy(script) => {
            let mut ok = |pk: &[u8], sig: &[u8]| chk.ecdsa(script, false, pk, sig);
            let Some(st) = template(script).and_then(|t| satisfy(&inp, &t, &mut ok)) else {
                return Ok(None);
            };
            script_sig.items = st;
        }
        Kind::P2wpkh(hash) => {
            let code = btcraw::p2pkh_script_code(&hash);
            let mut ok = |pk: &[u8], sig: &[u8]| chk.ecdsa(&code, true, pk, sig);
            let Some(st) = satisfy(&inp, &Template::Pkh(hash), &mut ok) else {
                return Ok(None);
            };
            witness = st;
        }
        Kind::P2wsh(ws) => {
            let mut ok = |pk: &[u8], sig: &[u8]| chk.ecdsa(ws, true, pk, sig);
            let Some(mut st) = template(ws).and_then(|t| satisfy(&inp, &t, &mut ok)) else {
                return Ok(None);
            };
            st.push(ws);
            witness = st;
        }
        // the key path is the cheapest spend; otherwise a signed leaf
        Kind::P2tr(output_key) => {
            let key_sig = inp
                .tap_key_sig()
                .filter(|sig| chk.schnorr(&output_key, sig, None));
            match key_sig {
                Some(sig) => witness.push(sig),
                None => match tap_script_witness(&inp, &output_key, &mut chk) {
                    Some(st) => witness = st,
                    None => return Ok(None),
                },
            }
        }
    }
    Ok(Some(Final {
        script_sig,
        witness,
    }))
}

impl<'a> Psbt<'a> {
    fn write_finalized(&self, s: &mut dyn Sink, finalized: &mut usize) -> Result<(), Error> {
        let mut ctx = SignCtx::new(self, &[]);
        self.write(s, &mut |loc, map, s| {
            if let MapLoc::Input(i) = loc
                && !PsbtInput(map).is_finalized()
            {
                match build_final(&mut ctx, self, i, PsbtInput(map)) {
                    Ok(Some(fin)) => {
                        *finalized += 1;
                        let witness = WitnessValue(fin.witness);
                        let sig_rec = NewRecord {
                            key_tail: &[],
                            key: &[input::FINAL_SCRIPTSIG as u8],
                            value: &fin.script_sig,
                        };
                        let wit_rec = NewRecord {
                            key_tail: &[],
                            key: &[input::FINAL_SCRIPTWITNESS as u8],
                            value: &witness,
                        };
                        let both = [sig_rec, wit_rec];
                        let added: &[NewRecord<'_>] =
                            match (fin.script_sig.is_empty(), fin.witness.len == 0) {
                                (false, false) => &both,
                                (false, true) => &both[..1],
                                (true, false) => &both[1..],
                                (true, true) => &[],
                            };
                        // keep only the UTXOs and unknown/proprietary data
                        let keep = |r: &super::Record<'_>| !(0x02..=0x18).contains(&r.key_type());
                        write_map(
                            s,
                            map,
                            &MapEdit {
                                keep: Some(&keep),
                                added,
                                ..MapEdit::none()
                            },
                        );
                        return Ok(());
                    }
                    Ok(None) => {}
                    Err(Error::MissingUtxo | Error::UnsupportedScript) => {}
                    Err(Error::MissingRedeemScript | Error::MissingWitnessScript) => {}
                    Err(e) => return Err(e),
                }
            }
            write_map(s, map, &MapEdit::none());
            Ok(())
        })
    }

    /// Finalizes every input that has enough signatures, writing the updated
    /// PSBT into `out` ([`Psbt::finalized_len`] gives the exact size). Returns
    /// the length written and the number of inputs finalized by this call.
    ///
    /// Supports P2PKH, P2PK and `m`-of-`n` multisig scripts (bare, P2SH,
    /// P2WSH and P2SH-P2WSH), P2WPKH (native and P2SH-nested), and taproot:
    /// the key path when its signature is present, else the script path
    /// through a `<key> OP_CHECKSIG` or `multi_a` leaf (up to 18 keys) with
    /// enough signatures. Finalized inputs keep only their UTXO and unknown
    /// fields.
    ///
    /// Signatures are not taken on trust: one whose sighash type differs from
    /// the input's `PSBT_IN_SIGHASH_TYPE` (when declared), or that does not
    /// verify against its key and the transaction, is ignored, so an input
    /// left without enough valid signatures stays unfinalized instead of
    /// yielding an invalid transaction. Verifying a taproot or unified-sighash
    /// signature needs the UTXO of every input. The one exception is an ECDSA
    /// signature with a non-unified hash type other than `SIGHASH_ALL`
    /// (`NONE`, `SINGLE`, `ANYONECANPAY`), which this crate computes no digest
    /// for: it is used unverified.
    pub fn finalize_to_slice(&self, out: &mut [u8]) -> Result<(usize, usize), Error> {
        let mut sink = SliceSink::new(out);
        let mut count = 0;
        self.write_finalized(&mut sink, &mut count)?;
        let n = sink.finish().ok_or(Error::BufferTooSmall)?;
        Psbt::parse(&out[..n])?;
        Ok((n, count))
    }

    /// The size of the PSBT [`Psbt::finalize_to_slice`] writes.
    pub fn finalized_len(&self) -> Result<usize, Error> {
        let mut c = Counter::default();
        self.write_finalized(&mut c, &mut 0)?;
        Ok(c.0)
    }

    /// [`Psbt::finalize_to_slice`] into a new vector.
    #[cfg(feature = "alloc")]
    pub fn finalize_to_vec(&self) -> Result<(Vec<u8>, usize), Error> {
        let mut buf = vec![0u8; self.finalized_len()?];
        let (n, count) = self.finalize_to_slice(&mut buf)?;
        buf.truncate(n);
        Ok((buf, count))
    }
}
