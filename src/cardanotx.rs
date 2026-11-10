//! Cardano (Shelley/Conway-era) transactions: build, sign and (de)serialize the
//! CBOR wire format expected by the Cardano ledger.
//!
//! ```text
//! transaction = [transaction_body, transaction_witness_set, bool, auxiliary_data/nil]
//! ```
//!
//! Only Ed25519 vkey witnesses and ADA/native-asset outputs are supported;
//! Plutus scripts, certificates, metadata and staking actions are out of scope.
//! Inputs are encoded as a plain array (the CDDL `set` form without the optional
//! #6.258 tag).
//!
//! The transaction is signed by hashing the CBOR-encoded transaction body with
//! blake2b-256 and producing Ed25519 signatures over that 32-byte hash.
//! [`CardanoTx::sign`] takes standard 32-byte Ed25519 seeds; [`CardanoTx::sign_with`]
//! accepts any [`CardanoSigner`], including the BIP32-Ed25519 extended keys used
//! by Cardano HD wallets (see [`crate::cardano_derive`]) and external/HSM signers.
//!
//! # Parsed transactions
//!
//! A transaction id is the hash of the body's exact bytes, and those of a
//! transaction made elsewhere need not be the ones this crate would write:
//! integers may not be in shortest form, the map may be ordered differently,
//! and the body may carry fields this crate does not model (certificates,
//! withdrawals, mint, ...). So [`CardanoTx::from_bytes`] keeps the original
//! bytes, in [`CardanoTx::parsed`], and [`CardanoTx::hash`],
//! [`CardanoTx::sign`], [`CardanoTx::verify`] and [`CardanoTx::to_bytes`] use
//! them as they are: what is signed is the transaction that was given, and
//! nothing of it is dropped when it is serialized again. See
//! [`CardanoParsed`].
//!
//! Port of `cardanotx.go`.

pub use crate::Error;

use crate::prelude::*;

use alloc::collections::BTreeSet;

use crate::cbor::{Cbor, read_head, scan_item, split_array_items, write_head};
use crate::crypto::SignerError;
use crate::crypto::ed25519;
use crate::hash::blake2b_256;

/// References an unspent transaction output being spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardanoInput {
    /// 32-byte id of the transaction that produced the output.
    pub txid: Vec<u8>,
    /// Index of the output within that transaction.
    pub index: u64,
}

/// A native-token amount within an output (multiasset value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardanoAsset {
    /// 28-byte minting policy id (script hash).
    pub policy_id: Vec<u8>,
    /// 0..32 byte asset name.
    pub asset_name: Vec<u8>,
    /// Token amount.
    pub amount: u64,
}

/// A transaction output: a destination address, an ADA amount in lovelace, and
/// optional native tokens. `address` holds the raw address bytes (header byte
/// followed by credentials), as produced by [`crate::out::Out::bytes`] for a
/// parsed Cardano address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardanoOutput {
    /// Raw address bytes (header + credentials).
    pub address: Vec<u8>,
    /// Amount in lovelace.
    pub amount: u64,
    /// Optional native tokens.
    pub assets: Vec<CardanoAsset>,
}

/// Produces an Ed25519 signature over a 32-byte message (the transaction body
/// hash) and exposes the public key it signs with. This lets a [`CardanoTx`] be
/// signed by standard Ed25519 keys, BIP32-Ed25519 extended keys (see
/// [`crate::cardano_derive::CardanoExtendedKey`]), or external signers such as
/// HSMs.
pub trait CardanoSigner {
    /// Returns the 32-byte Ed25519 public key.
    fn cardano_public_key(&self) -> [u8; 32];
    /// Returns a 64-byte Ed25519 signature over `message`.
    fn sign_cardano(&self, message: &[u8]) -> Result<[u8; 64], SignerError>;
}

/// Adapts a standard 32-byte Ed25519 seed to [`CardanoSigner`]. The copied
/// seed is wiped when the adapter is dropped.
struct StdEd25519Signer {
    seed: [u8; 32],
}

impl Drop for StdEd25519Signer {
    fn drop(&mut self) {
        crate::crypto::Zeroize::zeroize(&mut self.seed);
    }
}

impl CardanoSigner for StdEd25519Signer {
    fn cardano_public_key(&self) -> [u8; 32] {
        ed25519::public_from_seed(&self.seed)
    }
    fn sign_cardano(&self, message: &[u8]) -> Result<[u8; 64], SignerError> {
        Ok(ed25519::sign(&self.seed, message))
    }
}

/// An Ed25519 verification-key witness: the 32-byte public key and its 64-byte
/// signature over the transaction body hash.
#[derive(Debug, Clone)]
pub struct CardanoVkeyWitness {
    /// 32-byte Ed25519 public key.
    pub vkey: Vec<u8>,
    /// 64-byte signature over the body hash.
    pub signature: Vec<u8>,
}

/// What a transaction parsed by [`CardanoTx::from_bytes`] keeps of its
/// original bytes: the exact transaction body, and everything else this crate
/// does not model (the other entries of the witness set, the validity flag
/// and the auxiliary data).
///
/// While a [`CardanoTx`] has one, its body *is* these bytes: they are what is
/// hashed, signed, verified and serialized, not a re-encoding of `inputs`,
/// `outputs`, `fee` and `ttl`. Those fields are then a view of the body, and
/// a partial one:
///
/// - [`extra_body_keys`](Self::extra_body_keys) lists the body fields that
///   have no counterpart in [`CardanoTx`] (certificates, withdrawals, mint,
///   ...). A wallet showing a transaction for approval must not present
///   `inputs`/`outputs`/`fee` as the whole of it when this is not empty.
/// - an output's datum hash (the third field of the legacy output form) is
///   kept in the body but not shown in [`CardanoOutput`].
///
/// Changing `inputs`, `outputs`, `fee` or `ttl` of a parsed transaction does
/// not change its body: the methods that need the body then fail with
/// [`Error::UnsupportedField`] rather than sign or serialize something other
/// than what the fields say. To edit a parsed transaction, set
/// [`CardanoTx::parsed`] to `None` first: the body is then encoded from the
/// fields alone, which drops everything listed above (and the witnesses, made
/// for another body, no longer verify).
///
/// `witnesses` may be changed freely: they are written in place of the vkey
/// witnesses that were parsed, next to the preserved rest of the witness set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardanoParsed {
    /// The transaction body, as it was.
    body: Vec<u8>,
    /// Body map keys other than 0..=3, in body order.
    extra_body_keys: Vec<u64>,
    /// Whether the vkey witnesses were wrapped in the set tag (#6.258).
    vkeys_tagged: bool,
    /// The witness-set entries other than the vkey witnesses (key 0): their
    /// count, and their keys and values as they were.
    extra_witness_count: u64,
    extra_witnesses: Vec<u8>,
    /// The items after the witness set (validity flag, auxiliary data): their
    /// count, and their bytes as they were.
    trailer_count: u64,
    trailer: Vec<u8>,
}

impl CardanoParsed {
    /// The exact bytes of the transaction body: what is hashed for the
    /// transaction id and signed.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The keys of the body fields that [`CardanoTx`] does not model, in body
    /// order: anything but inputs (0), outputs (1), fee (2) and ttl (3). For
    /// instance 4 is certificates, 5 withdrawals, 7 the auxiliary data hash,
    /// 8 the validity start and 9 mint.
    pub fn extra_body_keys(&self) -> &[u64] {
        &self.extra_body_keys
    }

    /// Whether the witness set has entries other than vkey witnesses (native
    /// or Plutus scripts, datums, redeemers, bootstrap witnesses). They are
    /// preserved on serialization.
    pub fn has_extra_witnesses(&self) -> bool {
        self.extra_witness_count != 0
    }
}

/// A Cardano transaction.
///
/// Build one from its fields with `parsed: None` (or
/// `..Default::default()`), or parse one with [`CardanoTx::from_bytes`].
#[derive(Debug, Clone, Default)]
pub struct CardanoTx {
    /// Inputs being spent.
    pub inputs: Vec<CardanoInput>,
    /// Outputs being created.
    pub outputs: Vec<CardanoOutput>,
    /// Fee in lovelace.
    pub fee: u64,
    /// Optional time-to-live (slot); 0 means omit.
    pub ttl: u64,
    /// Ed25519 vkey witnesses.
    pub witnesses: Vec<CardanoVkeyWitness>,
    /// The original bytes of a transaction that was parsed, `None` for one
    /// built from its fields. When set, the body is these bytes and not an
    /// encoding of the fields above: see [`CardanoParsed`].
    pub parsed: Option<CardanoParsed>,
}

/// Groups assets by policy id then asset name, summing amounts of duplicates,
/// and builds the CBOR multiasset map `{policy_id => {asset_name => amount}}`.
/// Returns an error if aggregating duplicate `(policy, asset name)` entries
/// overflows `u64`, rather than silently wrapping.
fn multiasset_map(assets: &[CardanoAsset]) -> Result<Cbor, Error> {
    // (policy_id, [(asset_name, amount)]) grouping, built in insertion order;
    // the CBOR encoder applies the canonical key ordering at encode time.
    type Policy = (Vec<u8>, Vec<(Vec<u8>, u64)>);
    let mut policies: Vec<Policy> = Vec::new();
    for a in assets {
        let policy = policies.iter_mut().find(|(p, _)| *p == a.policy_id);
        let names = match policy {
            Some((_, names)) => names,
            None => {
                policies.push((a.policy_id.clone(), Vec::new()));
                &mut policies.last_mut().unwrap().1
            }
        };
        match names.iter_mut().find(|(n, _)| *n == a.asset_name) {
            Some((_, amount)) => {
                *amount = amount.checked_add(a.amount).ok_or(Error::Overflow)?;
            }
            None => names.push((a.asset_name.clone(), a.amount)),
        }
    }
    let entries = policies
        .into_iter()
        .map(|(policy, names)| {
            let inner = names
                .into_iter()
                .map(|(name, amount)| (Cbor::Bytes(name), Cbor::Uint(amount)))
                .collect();
            (Cbor::Bytes(policy), Cbor::Map(inner))
        })
        .collect();
    Ok(Cbor::Map(entries))
}

/// Returns the CBOR value for an output's amount: a bare coin for ADA-only
/// outputs, or `[coin, multiasset]` when native tokens are present.
fn output_value(out: &CardanoOutput) -> Result<Cbor, Error> {
    if out.assets.is_empty() {
        Ok(Cbor::Uint(out.amount))
    } else {
        Ok(Cbor::Array(vec![
            Cbor::Uint(out.amount),
            multiasset_map(&out.assets)?,
        ]))
    }
}

impl CardanoTx {
    /// Builds the transaction_body as an integer-keyed CBOR map.
    fn body_map(&self) -> Result<Cbor, Error> {
        if self.inputs.is_empty() {
            return Err(Error::NoInputs);
        }
        if self.outputs.is_empty() {
            return Err(Error::NoOutputs);
        }

        let mut inputs = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            if input.txid.len() != 32 {
                return Err(Error::InvalidLength);
            }
            inputs.push(Cbor::Array(vec![
                Cbor::Bytes(input.txid.clone()),
                Cbor::Uint(input.index),
            ]));
        }

        let mut outputs = Vec::with_capacity(self.outputs.len());
        for out in &self.outputs {
            if out.address.is_empty() {
                return Err(Error::EmptyAddress);
            }
            outputs.push(Cbor::Array(vec![
                Cbor::Bytes(out.address.clone()),
                output_value(out)?,
            ]));
        }

        let mut entries = vec![
            (Cbor::Uint(0), Cbor::Array(inputs)),
            (Cbor::Uint(1), Cbor::Array(outputs)),
            (Cbor::Uint(2), Cbor::Uint(self.fee)),
        ];
        if self.ttl != 0 {
            entries.push((Cbor::Uint(3), Cbor::Uint(self.ttl)));
        }
        Ok(Cbor::Map(entries))
    }

    /// Returns the CBOR encoding of the transaction body: the canonical
    /// encoding of the fields for a transaction that was built, the original
    /// bytes for one that was parsed (see [`CardanoParsed`]).
    ///
    /// Fails with [`Error::UnsupportedField`] if `inputs`, `outputs`, `fee`
    /// or `ttl` of a parsed transaction were changed, as the original body no
    /// longer says what they do.
    pub fn body_bytes(&self) -> Result<Vec<u8>, Error> {
        let Some(parsed) = &self.parsed else {
            return Ok(self.body_map()?.encode());
        };
        let body = parse_body(&parsed.body)?;
        if body.inputs != self.inputs
            || body.outputs != self.outputs
            || body.fee != self.fee
            || body.ttl != self.ttl
        {
            return Err(Error::UnsupportedField);
        }
        Ok(parsed.body.clone())
    }

    /// Returns the 32-byte blake2b-256 hash of the transaction body, which is
    /// the digest Ed25519 witnesses sign and also the transaction id.
    pub fn sign_bytes(&self) -> Result<[u8; 32], Error> {
        Ok(blake2b_256(&self.body_bytes()?))
    }

    /// Returns the transaction id: the blake2b-256 hash of the transaction body.
    pub fn hash(&self) -> Result<[u8; 32], Error> {
        self.sign_bytes()
    }

    /// Signs the transaction body with each provided 32-byte standard Ed25519
    /// seed, appending a vkey witness for each. Existing witnesses are preserved.
    /// For BIP32-Ed25519 extended keys or external signers, use
    /// [`CardanoTx::sign_with`].
    pub fn sign(&mut self, seeds: &[[u8; 32]]) -> Result<(), Error> {
        let signers: Vec<StdEd25519Signer> = seeds
            .iter()
            .map(|&seed| StdEd25519Signer { seed })
            .collect();
        let refs: Vec<&dyn CardanoSigner> =
            signers.iter().map(|s| s as &dyn CardanoSigner).collect();
        self.sign_with(&refs)
    }

    /// Signs the transaction body with each provided [`CardanoSigner`], appending
    /// a vkey witness for each. Existing witnesses are preserved.
    pub fn sign_with(&mut self, signers: &[&dyn CardanoSigner]) -> Result<(), Error> {
        let digest = self.sign_bytes()?;
        for signer in signers {
            let pub_key = signer.cardano_public_key();
            let sig = signer.sign_cardano(&digest).map_err(|_| Error::Signer)?;
            self.witnesses.push(CardanoVkeyWitness {
                vkey: pub_key.to_vec(),
                signature: sig.to_vec(),
            });
        }
        Ok(())
    }

    /// Appends a pre-computed vkey witness (32-byte public key, 64-byte
    /// signature over [`CardanoTx::sign_bytes`]). For external/hardware signers.
    pub fn add_witness(&mut self, vkey: &[u8], signature: &[u8]) -> Result<(), Error> {
        if vkey.len() != 32 {
            return Err(Error::InvalidLength);
        }
        if signature.len() != 64 {
            return Err(Error::InvalidLength);
        }
        self.witnesses.push(CardanoVkeyWitness {
            vkey: vkey.to_vec(),
            signature: signature.to_vec(),
        });
        Ok(())
    }

    /// Verifies every vkey witness signature against the transaction body
    /// digest.
    pub fn verify(&self) -> Result<(), Error> {
        let digest = self.sign_bytes()?;
        for (i, w) in self.witnesses.iter().enumerate() {
            if w.vkey.len() != 32 {
                return Err(Error::InvalidLength);
            }
            if w.signature.len() != 64 {
                return Err(Error::InvalidLength);
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&w.vkey);
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&w.signature);
            if !ed25519::verify(&pk, &digest, &sig) {
                return Err(Error::SignatureVerification(i));
            }
        }
        Ok(())
    }

    /// Appends the transaction_witness_set CBOR map: the vkey witnesses under
    /// key 0, when there are any, then the entries of `parsed` that are not
    /// vkey witnesses, as they were.
    fn write_witness_set(&self, out: &mut Vec<u8>, parsed: Option<&CardanoParsed>) {
        let has_vkeys = !self.witnesses.is_empty();
        let extra = parsed.map_or(0, |p| p.extra_witness_count);
        write_head(out, 5, extra + has_vkeys as u64);
        if has_vkeys {
            write_head(out, 0, 0);
            if parsed.is_some_and(|p| p.vkeys_tagged) {
                write_head(out, 6, SET_TAG);
            }
            write_head(out, 4, self.witnesses.len() as u64);
            for w in &self.witnesses {
                write_head(out, 4, 2);
                write_head(out, 2, w.vkey.len() as u64);
                out.extend_from_slice(&w.vkey);
                write_head(out, 2, w.signature.len() as u64);
                out.extend_from_slice(&w.signature);
            }
        }
        if let Some(parsed) = parsed {
            out.extend_from_slice(&parsed.extra_witnesses);
        }
    }

    /// Encodes the full transaction as CBOR. The embedded body bytes are
    /// byte-identical to those hashed for signing.
    ///
    /// A transaction that was built is written in canonical form, with a true
    /// validity flag and null auxiliary data. One that was parsed keeps its
    /// original body, validity flag, auxiliary data and witness-set entries
    /// other than vkey witnesses, byte for byte; only the vkey witnesses are
    /// written from [`CardanoTx::witnesses`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let body_bytes = self.body_bytes()?;
        let parsed = self.parsed.as_ref();
        let mut out = Vec::with_capacity(body_bytes.len() + 16);
        write_head(&mut out, 4, 2 + parsed.map_or(2, |p| p.trailer_count));
        out.extend_from_slice(&body_bytes);
        self.write_witness_set(&mut out, parsed);
        match parsed {
            Some(parsed) => out.extend_from_slice(&parsed.trailer),
            None => {
                // script validity flag: always true (no Plutus phase-2 support)
                out.push(0xf5);
                // auxiliary data: null
                out.push(0xf6);
            }
        }
        Ok(out)
    }

    /// Decodes a CBOR-encoded Cardano transaction: `[body, witness_set]`
    /// followed by up to two more items (the validity flag and the auxiliary
    /// data). The whole input must be the transaction: trailing bytes are an
    /// error.
    ///
    /// The original bytes are kept in [`CardanoTx::parsed`] and are what
    /// [`hash`](Self::hash), [`sign`](Self::sign), [`verify`](Self::verify)
    /// and [`to_bytes`](Self::to_bytes) work on, so the transaction id and
    /// the signed digest are those of the transaction that was given,
    /// whatever its encoding and whatever fields it has. See
    /// [`CardanoParsed`] for what the fields of the result do not show.
    ///
    /// Decoded into fields are the inputs, the ADA/native-asset outputs in
    /// the legacy (alonzo) array form, the fee, the ttl and the Ed25519 vkey
    /// witnesses. Other body fields and witness-set entries are preserved
    /// without being decoded. A body or witness set with a duplicate key is
    /// rejected with [`Error::DuplicateKey`].
    pub fn from_bytes(data: &[u8]) -> Result<CardanoTx, Error> {
        let items = split_array_items(data).map_err(Error::from)?;
        // the array is the whole of the data
        let mut consumed = 0;
        read_head(data, &mut consumed).map_err(Error::from)?;
        consumed += items.iter().map(Vec::len).sum::<usize>();
        if consumed != data.len() {
            return Err(Error::TrailingData);
        }
        if !(2..=4).contains(&items.len()) {
            return Err(Error::InvalidData);
        }

        let body = parse_body(&items[0])?;

        let mut witnesses = Vec::new();
        let mut vkeys_tagged = false;
        let mut extra_witness_count = 0;
        let mut extra_witnesses = Vec::new();
        for (key, key_and_value, value) in split_uint_map(&items[1])? {
            if key != 0 {
                extra_witness_count += 1;
                extra_witnesses.extend_from_slice(key_and_value);
                continue;
            }
            let (tagged, vkeys) = strip_set_tag(value);
            vkeys_tagged = tagged;
            let vkeys = decode_whole(vkeys)?;
            for vk in vkeys.as_array().ok_or(Error::InvalidData)? {
                let fields = vk.as_array().ok_or(Error::InvalidData)?;
                if fields.len() != 2 {
                    return Err(Error::InvalidData);
                }
                let vkey = fields[0].as_bytes().ok_or(Error::InvalidData)?.to_vec();
                let signature = fields[1].as_bytes().ok_or(Error::InvalidData)?.to_vec();
                witnesses.push(CardanoVkeyWitness { vkey, signature });
            }
        }

        let mut items = items.into_iter();
        let raw_body = items.next().ok_or(Error::InvalidData)?;
        let _witness_set = items.next();
        let trailer_count = items.len() as u64;
        let trailer = items.flatten().collect();

        Ok(CardanoTx {
            inputs: body.inputs,
            outputs: body.outputs,
            fee: body.fee,
            ttl: body.ttl,
            witnesses,
            parsed: Some(CardanoParsed {
                body: raw_body,
                extra_body_keys: body.extra_keys,
                vkeys_tagged,
                extra_witness_count,
                extra_witnesses,
                trailer_count,
                trailer,
            }),
        })
    }
}

/// The CBOR tag marking a set (#6.258), optional around the inputs and the
/// vkey witnesses since Conway.
const SET_TAG: u64 = 258;

/// Removes the set tag (#6.258) from the front of an item, telling whether it
/// was there.
fn strip_set_tag(item: &[u8]) -> (bool, &[u8]) {
    let mut pos = 0;
    match read_head(item, &mut pos) {
        Ok((6, SET_TAG, false)) => (true, &item[pos..]),
        _ => (false, item),
    }
}

/// Decodes `item`, which must be one CBOR value and nothing more.
fn decode_whole(item: &[u8]) -> Result<Cbor, Error> {
    let (value, len) = Cbor::decode(item).map_err(Error::from)?;
    if len != item.len() {
        return Err(Error::TrailingData);
    }
    Ok(value)
}

/// An entry of a map with unsigned-integer keys: the key, the bytes of the
/// key and its value together, and those of the value alone.
type UintMapEntry<'a> = (u64, &'a [u8], &'a [u8]);

/// Splits a definite-length CBOR map with unsigned-integer keys (a
/// transaction body or a witness set) into its entries, in the order they
/// come, without decoding the values. The map must be the whole of `data`,
/// and no key may come twice ([`Error::DuplicateKey`]): which of the two
/// values a ledger or another parser would take is not something to guess.
fn split_uint_map(data: &[u8]) -> Result<Vec<UintMapEntry<'_>>, Error> {
    let mut pos = 0;
    let (major, count, indefinite) = read_head(data, &mut pos).map_err(Error::from)?;
    if major != 5 {
        return Err(Error::InvalidData);
    }
    if indefinite {
        return Err(crate::cbor::Error::UnsupportedIndefiniteLength.into());
    }
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    // `count` is a claim: every entry takes bytes, and running out of them
    // ends the loop
    for _ in 0..count {
        let start = pos;
        let (major, key, indefinite) = read_head(data, &mut pos).map_err(Error::from)?;
        if major != 0 || indefinite {
            return Err(Error::InvalidData);
        }
        if !seen.insert(key) {
            return Err(Error::DuplicateKey);
        }
        let value = pos;
        scan_item(data, &mut pos).map_err(Error::from)?;
        entries.push((key, &data[start..pos], &data[value..pos]));
    }
    if pos != data.len() {
        return Err(Error::TrailingData);
    }
    Ok(entries)
}

/// The fields of a transaction body that [`CardanoTx`] models, and the keys
/// of those it does not.
struct Body {
    inputs: Vec<CardanoInput>,
    outputs: Vec<CardanoOutput>,
    fee: u64,
    ttl: u64,
    extra_keys: Vec<u64>,
}

/// Decodes the modelled fields of a transaction body (inputs, outputs, fee,
/// ttl), noting the keys of the others without decoding their values.
fn parse_body(raw: &[u8]) -> Result<Body, Error> {
    let mut body = Body {
        inputs: Vec::new(),
        outputs: Vec::new(),
        fee: 0,
        ttl: 0,
        extra_keys: Vec::new(),
    };
    for (key, _, value) in split_uint_map(raw)? {
        match key {
            0 => {
                let inputs = decode_whole(strip_set_tag(value).1)?;
                for input in inputs.as_array().ok_or(Error::InvalidData)? {
                    let fields = input.as_array().ok_or(Error::InvalidData)?;
                    if fields.len() != 2 {
                        return Err(Error::InvalidData);
                    }
                    let txid = fields[0].as_bytes().ok_or(Error::InvalidData)?.to_vec();
                    let index = fields[1].as_uint().ok_or(Error::InvalidData)?;
                    body.inputs.push(CardanoInput { txid, index });
                }
            }
            1 => {
                let outputs = decode_whole(value)?;
                for raw_out in outputs.as_array().ok_or(Error::InvalidData)? {
                    body.outputs.push(decode_output(raw_out)?);
                }
            }
            2 => body.fee = decode_whole(value)?.as_uint().ok_or(Error::InvalidData)?,
            3 => body.ttl = decode_whole(value)?.as_uint().ok_or(Error::InvalidData)?,
            _ => body.extra_keys.push(key),
        }
    }
    Ok(body)
}

/// Decodes a single transaction output in the legacy (alonzo) array form
/// `[address, value, ? datum_hash]`.
fn decode_output(raw: &Cbor) -> Result<CardanoOutput, Error> {
    let fields = raw.as_array().ok_or(Error::InvalidData)?;
    if fields.len() < 2 {
        return Err(Error::InvalidData);
    }
    let address = fields[0].as_bytes().ok_or(Error::InvalidData)?.to_vec();

    // value is either a bare coin (uint) or [coin, multiasset]
    if let Some(amount) = fields[1].as_uint() {
        return Ok(CardanoOutput {
            address,
            amount,
            assets: Vec::new(),
        });
    }
    let value = fields[1].as_array().ok_or(Error::InvalidData)?;
    if value.len() != 2 {
        return Err(Error::InvalidData);
    }
    let amount = value[0].as_uint().ok_or(Error::InvalidData)?;
    let multiasset = value[1].as_map().ok_or(Error::InvalidData)?;
    let assets = flatten_assets(multiasset)?;
    Ok(CardanoOutput {
        address,
        amount,
        assets,
    })
}

/// Converts a decoded `{policy => {name => amount}}` map into a deterministically
/// ordered slice of [`CardanoAsset`].
fn flatten_assets(multiasset: &[(Cbor, Cbor)]) -> Result<Vec<CardanoAsset>, Error> {
    let mut assets = Vec::new();
    for (policy, names) in multiasset {
        let policy_id = policy.as_bytes().ok_or(Error::InvalidData)?.to_vec();
        let names = names.as_map().ok_or(Error::InvalidData)?;
        for (name, amount) in names {
            assets.push(CardanoAsset {
                policy_id: policy_id.clone(),
                asset_name: name.as_bytes().ok_or(Error::InvalidData)?.to_vec(),
                amount: amount.as_uint().ok_or(Error::InvalidData)?,
            });
        }
    }
    assets.sort_by(|a, b| {
        a.policy_id
            .cmp(&b.policy_id)
            .then_with(|| a.asset_name.cmp(&b.asset_name))
    });
    Ok(assets)
}
