//! The PSBT finalizer role.

use super::sign::{Kind, for_each_push, resolve};
use super::{
    Error, MapEdit, MapLoc, NewRecord, Psbt, PsbtInput, WriteValue, input, put_varint, write_map,
};
use crate::hash::hash160;
use crate::pushbytes::push_bytes_len;
use crate::sink::{Counter, Sink, SliceSink};

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

/// The signature stack satisfying `template`, if enough signatures exist.
fn satisfy<'a>(inp: &PsbtInput<'a>, t: &Template<'a>) -> Option<Stack<'a>> {
    let mut st = Stack::EMPTY;
    match t {
        Template::Pkh(hash) => {
            let (pk, sig) = inp.partial_sigs().find(|(pk, _)| hash160(pk) == *hash)?;
            st.push(sig);
            st.push(pk);
        }
        Template::Pk(key) => st.push(inp.partial_sig(key)?),
        Template::Multi { m, keys } => {
            st.push(&[]); // CHECKMULTISIG dummy
            for key in keys.items() {
                if st.len - 1 == *m {
                    break;
                }
                if let Some(sig) = inp.partial_sig(key) {
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

struct Final<'a> {
    script_sig: ScriptSigValue<'a>,
    witness: Stack<'a>,
}

fn build_final<'a>(psbt: &Psbt<'a>, index: usize) -> Result<Option<Final<'a>>, Error> {
    let inp = psbt.input(index).ok_or(Error::InputIndex)?;
    let res = resolve(psbt, index)?;
    let mut script_sig = ScriptSigValue {
        items: Stack::EMPTY,
        redeem: res.redeem,
    };
    let mut witness = Stack::EMPTY;
    match res.kind {
        Kind::Legacy(script) => {
            let Some(st) = template(script).and_then(|t| satisfy(&inp, &t)) else {
                return Ok(None);
            };
            script_sig.items = st;
        }
        Kind::P2wpkh(hash) => {
            let Some(st) = satisfy(&inp, &Template::Pkh(hash)) else {
                return Ok(None);
            };
            witness = st;
        }
        Kind::P2wsh(ws) => {
            let Some(mut st) = template(ws).and_then(|t| satisfy(&inp, &t)) else {
                return Ok(None);
            };
            st.push(ws);
            witness = st;
        }
        Kind::P2tr(_) => match inp.tap_key_sig() {
            Some(sig) => witness.push(sig),
            None => return Ok(None),
        },
    }
    Ok(Some(Final {
        script_sig,
        witness,
    }))
}

impl<'a> Psbt<'a> {
    fn write_finalized(&self, s: &mut dyn Sink, finalized: &mut usize) -> Result<(), Error> {
        self.write(s, &mut |loc, map, s| {
            if let MapLoc::Input(i) = loc
                && !PsbtInput(map).is_finalized()
            {
                match build_final(self, i) {
                    Ok(Some(fin)) => {
                        *finalized += 1;
                        let witness = WitnessValue(fin.witness);
                        let sig_rec = NewRecord {
                            key: &[input::FINAL_SCRIPTSIG as u8],
                            value: &fin.script_sig,
                        };
                        let wit_rec = NewRecord {
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
    /// P2WSH and P2SH-P2WSH), P2WPKH (native and P2SH-nested) and taproot key
    /// path. Finalized inputs keep only their UTXO and unknown fields.
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
