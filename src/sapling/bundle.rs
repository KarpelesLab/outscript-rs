//! The Sapling bundle of a v5 transaction (ZIP-225): spend and output
//! descriptions, the value balance, the anchor, the proofs and the
//! signatures.
//!
//! The serialized layout is the one
//! [`ZcashTx::sapling`](crate::zcashtx::ZcashTx#structfield.sapling) carries and whose
//! ZIP-244 digest [`zcashtx`](crate::zcashtx) computes:
//!
//! ```text
//! nSpendsSapling        compactSize
//! vSpendsSapling        nSpends × (cv ‖ nullifier ‖ rk)                96 bytes each
//! nOutputsSapling       compactSize
//! vOutputsSapling       nOutputs × (cv ‖ cmu ‖ ephemeralKey ‖
//!                                   encCiphertext ‖ outCiphertext)     756 bytes each
//! valueBalanceSapling   int64            if nSpends + nOutputs > 0
//! anchorSapling         32 bytes         if nSpends > 0
//! vSpendProofsSapling   nSpends × 192 bytes
//! vSpendAuthSigsSapling nSpends × 64 bytes
//! vOutputProofsSapling  nOutputs × 192 bytes
//! bindingSigSapling     64 bytes         if nSpends + nOutputs > 0
//! ```
//!
//! [`BundleRef`] is a zero-copy view of a serialized bundle and
//! [`write_bundle`] serializes one from its parts, both without allocating;
//! `Bundle` (with `alloc`) owns its descriptions.
//!
//! The Groth16 proofs are carried, not checked: [`BundleRef::verify`] checks
//! everything else a validator does that does not need the chain state.

use super::Error;
use super::jubjub::Point;
use super::keys::{IncomingViewingKey, OutgoingViewingKey};
use super::note::MAX_MONEY;
use super::note::Note;
use super::note_encryption::{
    ENC_CIPHERTEXT_SIZE, MEMO_SIZE, OUT_CIPHERTEXT_SIZE, Zip212Enforcement, try_note_decryption,
    try_output_recovery_with_ovk,
};
use super::redjubjub::{self, BatchVerifier, SigType, Signature};
use crate::btcvarint::BtcVarInt;
#[cfg(feature = "alloc")]
use crate::prelude::*;

/// The size of a Groth16 proof.
pub const GROTH_PROOF_SIZE: usize = 192;
/// The size of the part of a spend description serialized first: `cv`,
/// nullifier and `rk`.
pub const SPEND_SIZE: usize = 96;
/// The size of an output description without its proof.
pub const OUTPUT_SIZE: usize = 32 * 3 + ENC_CIPHERTEXT_SIZE + OUT_CIPHERTEXT_SIZE;
/// The serialization of a bundle without spends or outputs.
pub const EMPTY_BUNDLE: [u8; 2] = [0, 0];

/// A spend description: the public part of the spend of a note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendDescription {
    /// The value commitment to the spent note's value.
    pub cv: [u8; 32],
    /// The nullifier of the spent note.
    pub nullifier: [u8; 32],
    /// The randomized spend validating key `rk`.
    pub rk: [u8; 32],
    /// The Spend proof.
    pub zkproof: [u8; GROTH_PROOF_SIZE],
    /// The spend authorization signature, by `rk` over the signature hash.
    pub spend_auth_sig: Signature,
}

/// An output description: the public part of the creation of a note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputDescription {
    /// The value commitment to the new note's value.
    pub cv: [u8; 32],
    /// The note commitment `cmu`.
    pub cmu: [u8; 32],
    /// The ephemeral key `epk` of the note encryption.
    pub ephemeral_key: [u8; 32],
    /// The note ciphertext.
    pub enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    /// The outgoing ciphertext.
    pub out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
    /// The Output proof.
    pub zkproof: [u8; GROTH_PROOF_SIZE],
}

/// A spend description borrowed from a serialized bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendRef<'a> {
    /// The value commitment to the spent note's value.
    pub cv: &'a [u8; 32],
    /// The nullifier of the spent note.
    pub nullifier: &'a [u8; 32],
    /// The randomized spend validating key `rk`.
    pub rk: &'a [u8; 32],
    /// The Spend proof.
    pub zkproof: &'a [u8; GROTH_PROOF_SIZE],
    /// The spend authorization signature.
    pub spend_auth_sig: &'a [u8; 64],
}

impl SpendRef<'_> {
    /// An owned copy.
    pub fn to_owned(&self) -> SpendDescription {
        SpendDescription {
            cv: *self.cv,
            nullifier: *self.nullifier,
            rk: *self.rk,
            zkproof: *self.zkproof,
            spend_auth_sig: Signature(*self.spend_auth_sig),
        }
    }
}

/// An output description borrowed from a serialized bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputRef<'a> {
    /// The value commitment to the new note's value.
    pub cv: &'a [u8; 32],
    /// The note commitment `cmu`.
    pub cmu: &'a [u8; 32],
    /// The ephemeral key `epk` of the note encryption.
    pub ephemeral_key: &'a [u8; 32],
    /// The note ciphertext.
    pub enc_ciphertext: &'a [u8; ENC_CIPHERTEXT_SIZE],
    /// The outgoing ciphertext.
    pub out_ciphertext: &'a [u8; OUT_CIPHERTEXT_SIZE],
    /// The Output proof.
    pub zkproof: &'a [u8; GROTH_PROOF_SIZE],
}

impl OutputRef<'_> {
    /// Trial-decrypts the output with an incoming viewing key: see
    /// [`try_note_decryption`].
    pub fn try_note_decryption(
        &self,
        ivk: &IncomingViewingKey,
        zip212: Zip212Enforcement,
    ) -> Option<(Note, [u8; MEMO_SIZE])> {
        try_note_decryption(
            ivk,
            self.ephemeral_key,
            self.cmu,
            self.enc_ciphertext,
            zip212,
        )
    }

    /// Recovers the note of an output created with the outgoing viewing key
    /// `ovk`: see [`try_output_recovery_with_ovk`].
    pub fn try_output_recovery(
        &self,
        ovk: &OutgoingViewingKey,
        zip212: Zip212Enforcement,
    ) -> Option<(Note, [u8; MEMO_SIZE])> {
        try_output_recovery_with_ovk(
            ovk,
            self.cv,
            self.cmu,
            self.ephemeral_key,
            self.enc_ciphertext,
            self.out_ciphertext,
            zip212,
        )
    }

    /// An owned copy.
    pub fn to_owned(&self) -> OutputDescription {
        OutputDescription {
            cv: *self.cv,
            cmu: *self.cmu,
            ephemeral_key: *self.ephemeral_key,
            enc_ciphertext: *self.enc_ciphertext,
            out_ciphertext: *self.out_ciphertext,
            zkproof: *self.zkproof,
        }
    }
}

/// Reads a canonical compact size.
fn take_count(data: &mut &[u8]) -> Result<usize, Error> {
    let (count, n) = BtcVarInt::decode(data).ok_or(Error::UnexpectedEof)?;
    // consensus requires the shortest encoding
    if BtcVarInt(count.0).len() != n {
        return Err(Error::InvalidLength);
    }
    *data = &data[n..];
    usize::try_from(count.0).map_err(|_| Error::InvalidLength)
}

fn take<'a>(data: &mut &'a [u8], len: usize) -> Result<&'a [u8], Error> {
    let (bytes, rest) = data.split_at_checked(len).ok_or(Error::UnexpectedEof)?;
    *data = rest;
    Ok(bytes)
}

/// Takes `count` items of `N` bytes; the count is whatever the data claims,
/// so the multiplication is checked.
fn take_items<'a, const N: usize>(
    data: &mut &'a [u8],
    count: usize,
) -> Result<&'a [[u8; N]], Error> {
    let bytes = take(data, count.checked_mul(N).ok_or(Error::InvalidLength)?)?;
    Ok(bytes.as_chunks::<N>().0)
}

/// The `M` bytes at `offset` of an item, for constant offsets within it.
fn sub<const N: usize, const M: usize>(item: &[u8; N], offset: usize) -> &[u8; M] {
    item[offset..offset + M]
        .try_into()
        .expect("a constant range within the item")
}

fn spend_ref<'a>(
    item: &'a [u8; SPEND_SIZE],
    zkproof: &'a [u8; GROTH_PROOF_SIZE],
    spend_auth_sig: &'a [u8; 64],
) -> SpendRef<'a> {
    SpendRef {
        cv: sub(item, 0),
        nullifier: sub(item, 32),
        rk: sub(item, 64),
        zkproof,
        spend_auth_sig,
    }
}

fn output_ref<'a>(
    item: &'a [u8; OUTPUT_SIZE],
    zkproof: &'a [u8; GROTH_PROOF_SIZE],
) -> OutputRef<'a> {
    OutputRef {
        cv: sub(item, 0),
        cmu: sub(item, 32),
        ephemeral_key: sub(item, 64),
        enc_ciphertext: sub(item, 96),
        out_ciphertext: sub(item, 96 + ENC_CIPHERTEXT_SIZE),
        zkproof,
    }
}

/// A parsed view of a serialized Sapling bundle, borrowing its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleRef<'a> {
    spends: &'a [[u8; SPEND_SIZE]],
    outputs: &'a [[u8; OUTPUT_SIZE]],
    value_balance: i64,
    anchor: Option<&'a [u8; 32]>,
    // as many as there are spends, or outputs
    spend_proofs: &'a [[u8; GROTH_PROOF_SIZE]],
    spend_auth_sigs: &'a [[u8; 64]],
    output_proofs: &'a [[u8; GROTH_PROOF_SIZE]],
    binding_sig: Option<&'a [u8; 64]>,
}

impl<'a> BundleRef<'a> {
    /// Parses a serialized bundle, which must fill `data` exactly. An empty
    /// slice is the empty bundle, as in
    /// [`ZcashTx::sapling`](crate::zcashtx::ZcashTx#structfield.sapling).
    ///
    /// Only the structure is checked, and that the value balance is within
    /// ±[`MAX_MONEY`]; see [`verify`](Self::verify) for the rest.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let mut data = if data.is_empty() {
            &EMPTY_BUNDLE[..]
        } else {
            data
        };
        let n_spends = take_count(&mut data)?;
        let spends = take_items(&mut data, n_spends)?;
        let n_outputs = take_count(&mut data)?;
        let outputs = take_items(&mut data, n_outputs)?;
        let mut bundle = BundleRef {
            spends,
            outputs,
            value_balance: 0,
            anchor: None,
            spend_proofs: &[],
            spend_auth_sigs: &[],
            output_proofs: &[],
            binding_sig: None,
        };
        if n_spends > 0 || n_outputs > 0 {
            let balance = take(&mut data, 8)?;
            bundle.value_balance =
                i64::from_le_bytes(balance.try_into().map_err(|_| Error::UnexpectedEof)?);
            if !(-MAX_MONEY..=MAX_MONEY).contains(&bundle.value_balance) {
                return Err(Error::ValueOutOfRange);
            }
            if n_spends > 0 {
                bundle.anchor = take(&mut data, 32)?.first_chunk();
            }
            bundle.spend_proofs = take_items(&mut data, n_spends)?;
            bundle.spend_auth_sigs = take_items(&mut data, n_spends)?;
            bundle.output_proofs = take_items(&mut data, n_outputs)?;
            bundle.binding_sig = take(&mut data, 64)?.first_chunk();
        }
        if !data.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(bundle)
    }

    /// Whether the bundle has neither spends nor outputs.
    pub const fn is_empty(&self) -> bool {
        self.spends.is_empty() && self.outputs.is_empty()
    }

    /// The number of spend descriptions.
    pub const fn n_spends(&self) -> usize {
        self.spends.len()
    }

    /// The number of output descriptions.
    pub const fn n_outputs(&self) -> usize {
        self.outputs.len()
    }

    /// The net value leaving the Sapling pool, in zatoshis: positive when
    /// the bundle pays the transparent pool, Orchard or the fee.
    pub const fn value_balance(&self) -> i64 {
        self.value_balance
    }

    /// The root of the note commitment tree the spends refer to; `None`
    /// without spends.
    pub const fn anchor(&self) -> Option<&'a [u8; 32]> {
        self.anchor
    }

    /// The binding signature; `None` for an empty bundle.
    pub fn binding_sig(&self) -> Option<Signature> {
        self.binding_sig.map(|sig| Signature(*sig))
    }

    /// Spend description `i`.
    pub fn spend(&self, i: usize) -> Option<SpendRef<'a>> {
        Some(spend_ref(
            self.spends.get(i)?,
            self.spend_proofs.get(i)?,
            self.spend_auth_sigs.get(i)?,
        ))
    }

    /// Output description `i`.
    pub fn output(&self, i: usize) -> Option<OutputRef<'a>> {
        Some(output_ref(self.outputs.get(i)?, self.output_proofs.get(i)?))
    }

    /// The spend descriptions, in order.
    pub fn spends(&self) -> impl ExactSizeIterator<Item = SpendRef<'a>> + Clone + use<'a> {
        self.spends
            .iter()
            .zip(self.spend_proofs)
            .zip(self.spend_auth_sigs)
            .map(|((item, proof), sig)| spend_ref(item, proof, sig))
    }

    /// The output descriptions, in order.
    pub fn outputs(&self) -> impl ExactSizeIterator<Item = OutputRef<'a>> + Clone + use<'a> {
        self.outputs
            .iter()
            .zip(self.output_proofs)
            .map(|(item, proof)| output_ref(item, proof))
    }

    /// The binding validating key: the sum of the spends' value commitments
    /// minus the outputs', minus the commitment to the value balance. Fails
    /// if a value commitment is not a canonical point.
    pub fn binding_validating_key(&self) -> Result<Point, Error> {
        let mut sum = Point::IDENTITY;
        for spend in self.spends() {
            sum += Point::from_bytes(spend.cv).ok_or(Error::InvalidPoint)?;
        }
        for output in self.outputs() {
            sum += Point::from_bytes(output.cv)
                .ok_or(Error::InvalidPoint)?
                .negate();
        }
        Ok(redjubjub::binding_validating_key(
            [&sum],
            [],
            self.value_balance,
        ))
    }

    /// The encoding rules of the consensus: every `cv`, `rk` and ephemeral
    /// key is a canonical point and not of small order, and every `cmu` and
    /// the anchor are canonical field elements.
    fn check_encodings(&self) -> Result<(), Error> {
        let not_small_order = |bytes: &[u8; 32]| -> Result<(), Error> {
            let p = Point::from_bytes(bytes).ok_or(Error::InvalidPoint)?;
            if p.is_small_order() {
                return Err(Error::InvalidPoint);
            }
            Ok(())
        };
        let field_element = |bytes: &[u8; 32]| -> Result<(), Error> {
            super::field::Fq::from_bytes(bytes)
                .map(|_| ())
                .ok_or(Error::InvalidScalar)
        };
        if let Some(anchor) = self.anchor {
            field_element(anchor)?;
        }
        for spend in self.spends() {
            not_small_order(spend.cv)?;
            not_small_order(spend.rk)?;
        }
        for output in self.outputs() {
            not_small_order(output.cv)?;
            not_small_order(output.ephemeral_key)?;
            field_element(output.cmu)?;
        }
        Ok(())
    }

    /// Checks what a validator checks of a bundle without the chain state
    /// and without verifying proofs, given the transaction's signature hash
    /// (see [`ZcashTx::sighash`](crate::zcashtx::ZcashTx::sighash) with no
    /// input index):
    ///
    /// - every `cv`, `rk` and ephemeral key is a canonical point and not of
    ///   small order, and every `cmu` and the anchor are canonical field
    ///   elements;
    /// - every spend authorization signature verifies under its `rk`;
    /// - the binding signature verifies, so the values balance.
    ///
    /// **The Spend and Output proofs are not verified**, and neither are the
    /// anchor or the nullifiers against the chain. With the feature
    /// `zcash-sapling-prover`, `prover::verify_bundle` checks the proofs as
    /// well.
    pub fn verify(&self, sighash: &[u8; 32]) -> Result<(), Error> {
        self.check_encodings()?;
        for spend in self.spends() {
            redjubjub::verify_spend(spend.rk, sighash, &Signature(*spend.spend_auth_sig))?;
        }
        if let Some(sig) = self.binding_sig {
            let bvk = self.binding_validating_key()?;
            redjubjub::verify_binding(&bvk, sighash, &Signature(*sig))?;
        }
        Ok(())
    }

    /// The number of signatures of the bundle: one per spend and the
    /// binding signature, none for an empty bundle.
    pub const fn n_signatures(&self) -> usize {
        if self.is_empty() {
            0
        } else {
            self.spends.len() + 1
        }
    }

    /// Checks the encodings as [`verify`](Self::verify) does, and adds the
    /// signatures of the bundle to a batch instead of verifying them: for
    /// verifying the signatures of many bundles (each with its own
    /// signature hash) together.
    ///
    /// `random` must hold [`BATCH_RANDOM_SIZE`](redjubjub::BATCH_RANDOM_SIZE)
    /// fresh random bytes per signature ([`n_signatures`](Self::n_signatures)
    /// of them): see [`BatchVerifier`]. On error the batch may hold part of
    /// the bundle's signatures and must be discarded.
    pub fn queue_signatures(
        &self,
        sighash: &[u8; 32],
        batch: &mut BatchVerifier,
        random: &[u8],
    ) -> Result<(), Error> {
        let (random, rest) = random.as_chunks::<{ redjubjub::BATCH_RANDOM_SIZE }>();
        if !rest.is_empty() || random.len() != self.n_signatures() {
            return Err(Error::RandomLength);
        }
        self.check_encodings()?;
        let mut random = random.iter();
        for (spend, z) in self.spends().zip(&mut random) {
            let signature = Signature(*spend.spend_auth_sig);
            batch.queue(SigType::SpendAuth, spend.rk, sighash, &signature, z)?;
        }
        if let (Some(sig), Some(z)) = (self.binding_sig, random.next()) {
            let bvk = self.binding_validating_key()?.to_bytes();
            batch.queue(SigType::Binding, &bvk, sighash, &Signature(*sig), z)?;
        }
        Ok(())
    }

    /// [`verify`](Self::verify) with the signatures verified as a batch,
    /// which is faster as soon as there is a spend. `random` is as for
    /// [`queue_signatures`](Self::queue_signatures).
    pub fn verify_batched(&self, sighash: &[u8; 32], random: &[u8]) -> Result<(), Error> {
        let mut batch = BatchVerifier::new();
        self.queue_signatures(sighash, &mut batch, random)?;
        batch.verify()
    }

    /// Trial-decrypts every output with every incoming viewing key, in
    /// one batch: see
    /// [`try_note_decryption_batch`](super::note_encryption::try_note_decryption_batch).
    /// `found` gets the index of the output, the index of the key, the
    /// note and its memo.
    pub fn try_note_decryption_batch(
        &self,
        ivks: &[IncomingViewingKey],
        zip212: Zip212Enforcement,
        found: impl FnMut(usize, usize, Note, &[u8; MEMO_SIZE]),
    ) {
        super::note_encryption::try_note_decryption_batch(
            ivks,
            self.outputs()
                .map(|o| (o.ephemeral_key, o.cmu, o.enc_ciphertext)),
            zip212,
            found,
        );
    }

    /// An owned copy of the bundle.
    #[cfg(feature = "alloc")]
    pub fn to_bundle(&self) -> Bundle {
        Bundle {
            spends: self.spends().map(|s| s.to_owned()).collect(),
            outputs: self.outputs().map(|o| o.to_owned()).collect(),
            value_balance: self.value_balance,
            anchor: self.anchor.copied().unwrap_or([0; 32]),
            binding_sig: self.binding_sig().unwrap_or(Signature([0; 64])),
        }
    }
}

/// The serialized length of a bundle with these numbers of spends and
/// outputs.
pub const fn bundle_len(n_spends: usize, n_outputs: usize) -> usize {
    const fn compact_size_len(n: usize) -> usize {
        match n as u64 {
            0..0xfd => 1,
            0xfd..=0xffff => 3,
            0x1_0000..=0xffff_ffff => 5,
            _ => 9,
        }
    }
    let counts = compact_size_len(n_spends) + compact_size_len(n_outputs);
    if n_spends == 0 && n_outputs == 0 {
        return counts;
    }
    counts
        + n_spends * (SPEND_SIZE + GROTH_PROOF_SIZE + 64)
        + n_outputs * (OUTPUT_SIZE + GROTH_PROOF_SIZE)
        + 8
        + if n_spends > 0 { 32 } else { 0 }
        + 64
}

/// Appends to a caller's buffer.
struct Writer<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .pos
            .checked_add(bytes.len())
            .ok_or(Error::BufferTooSmall)?;
        self.out
            .get_mut(self.pos..end)
            .ok_or(Error::BufferTooSmall)?
            .copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    fn put_count(&mut self, count: usize) -> Result<(), Error> {
        let (buf, len) = BtcVarInt(count as u64).to_array();
        self.put(&buf[..len])
    }
}

/// Serializes a Sapling bundle into `out`, returning the number of bytes
/// written ([`bundle_len`]). The anchor and the binding signature are only
/// written when the layout has them; without spends and outputs the result
/// is [`EMPTY_BUNDLE`].
pub fn write_bundle(
    spends: &[SpendDescription],
    outputs: &[OutputDescription],
    value_balance: i64,
    anchor: &[u8; 32],
    binding_sig: &Signature,
    out: &mut [u8],
) -> Result<usize, Error> {
    if !(-MAX_MONEY..=MAX_MONEY).contains(&value_balance) {
        return Err(Error::ValueOutOfRange);
    }
    let mut w = Writer { out, pos: 0 };
    w.put_count(spends.len())?;
    for spend in spends {
        w.put(&spend.cv)?;
        w.put(&spend.nullifier)?;
        w.put(&spend.rk)?;
    }
    w.put_count(outputs.len())?;
    for output in outputs {
        w.put(&output.cv)?;
        w.put(&output.cmu)?;
        w.put(&output.ephemeral_key)?;
        w.put(&output.enc_ciphertext)?;
        w.put(&output.out_ciphertext)?;
    }
    if spends.is_empty() && outputs.is_empty() {
        return Ok(w.pos);
    }
    w.put(&value_balance.to_le_bytes())?;
    if !spends.is_empty() {
        w.put(anchor)?;
    }
    for spend in spends {
        w.put(&spend.zkproof)?;
    }
    for spend in spends {
        w.put(&spend.spend_auth_sig.0)?;
    }
    for output in outputs {
        w.put(&output.zkproof)?;
    }
    w.put(&binding_sig.0)?;
    Ok(w.pos)
}

/// An owned Sapling bundle.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// The spend descriptions.
    pub spends: Vec<SpendDescription>,
    /// The output descriptions.
    pub outputs: Vec<OutputDescription>,
    /// The net value leaving the Sapling pool, in zatoshis.
    pub value_balance: i64,
    /// The root of the note commitment tree the spends refer to (unused,
    /// and not serialized, without spends).
    pub anchor: [u8; 32],
    /// The binding signature (unused, and not serialized, for an empty
    /// bundle).
    pub binding_sig: Signature,
}

#[cfg(feature = "alloc")]
impl Bundle {
    /// Parses a serialized bundle: see [`BundleRef::parse`].
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        BundleRef::parse(data).map(|b| b.to_bundle())
    }

    /// The serialized length.
    pub fn serialized_len(&self) -> usize {
        bundle_len(self.spends.len(), self.outputs.len())
    }

    /// Serializes the bundle into `out`: see [`write_bundle`].
    pub fn write(&self, out: &mut [u8]) -> Result<usize, Error> {
        write_bundle(
            &self.spends,
            &self.outputs,
            self.value_balance,
            &self.anchor,
            &self.binding_sig,
            out,
        )
    }

    /// The serialized bundle, as
    /// [`ZcashTx::sapling`](crate::zcashtx::ZcashTx#structfield.sapling) takes it.
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; self.serialized_len()];
        let n = self.write(&mut out)?;
        out.truncate(n);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sapling::field::Fr;
    use crate::sapling::note::value_commitment;
    use crate::sapling::redjubjub::{
        SigType, binding_signing_key, randomized_spend_key, sign_binding, sign_spend,
        verification_key,
    };
    use crate::zcashtx::{ZcashTx, ZcashTxIn, ZcashTxOut};

    /// The Sapling bundles of the official ZIP-244 transactions parse, give
    /// back their fields and serialize to the same bytes.
    #[test]
    fn zip244_bundles_round_trip() {
        let rows: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../../testdata/zip_0244.json")).unwrap();
        let (mut spends_seen, mut outputs_seen) = (0, 0);
        for row in &rows[2..] {
            let tx = hex::decode(row[0].as_str().unwrap()).unwrap();
            let mut inputs = [ZcashTxIn::default(); 8];
            let mut outputs = [ZcashTxOut::default(); 8];
            let tx = ZcashTx::parse_into(&tx, &mut inputs, &mut outputs).unwrap();
            let bundle = BundleRef::parse(tx.sapling).unwrap();
            assert_eq!(bundle.is_empty(), tx.sapling.is_empty());
            spends_seen += bundle.n_spends();
            outputs_seen += bundle.n_outputs();
            assert_eq!(bundle.spends().len(), bundle.n_spends());
            assert_eq!(bundle.anchor().is_some(), bundle.n_spends() > 0);
            assert_eq!(bundle.binding_sig().is_some(), !bundle.is_empty());
            assert_eq!(bundle.spend(bundle.n_spends()), None);
            assert_eq!(bundle.output(bundle.n_outputs()), None);

            // the vectors' points are valid ones
            for (i, spend) in bundle.spends().enumerate() {
                assert_eq!(bundle.spend(i), Some(spend));
                assert!(Point::from_bytes(spend.cv).is_some());
                assert!(Point::from_bytes(spend.rk).is_some());
            }
            for (i, output) in bundle.outputs().enumerate() {
                assert_eq!(bundle.output(i), Some(output));
                assert!(Point::from_bytes(output.cv).is_some());
                assert!(Point::from_bytes(output.ephemeral_key).is_some());
            }
            if !bundle.is_empty() {
                assert!(bundle.binding_validating_key().is_ok());
                // their signatures are random bytes
                let sighash: [u8; 32] = hex::decode(row[6].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                assert!(bundle.verify(&sighash).is_err());
            }

            let spends: Vec<SpendDescription> = bundle.spends().map(|s| s.to_owned()).collect();
            let outs: Vec<OutputDescription> = bundle.outputs().map(|o| o.to_owned()).collect();
            let mut buf = vec![0u8; bundle_len(spends.len(), outs.len())];
            let n = write_bundle(
                &spends,
                &outs,
                bundle.value_balance(),
                bundle.anchor().unwrap_or(&[0; 32]),
                &bundle.binding_sig().unwrap_or(Signature([0; 64])),
                &mut buf,
            )
            .unwrap();
            assert_eq!(n, buf.len());
            let expect: &[u8] = if tx.sapling.is_empty() {
                &EMPTY_BUNDLE
            } else {
                tx.sapling
            };
            assert_eq!(buf, expect);
            #[cfg(feature = "alloc")]
            {
                let owned = Bundle::parse(tx.sapling).unwrap();
                assert_eq!(owned.serialize().unwrap(), expect);
                assert_eq!(owned, bundle.to_bundle());
            }
            // no prefix of a bundle is a bundle
            for len in (1..expect.len()).step_by(97) {
                assert!(BundleRef::parse(&expect[..len]).is_err());
            }
            let mut longer = expect.to_vec();
            longer.push(0);
            assert_eq!(BundleRef::parse(&longer), Err(Error::TrailingData));
        }
        assert!(spends_seen > 0 && outputs_seen > 0);
    }

    /// A bundle with real signatures (and no proofs), as a builder makes it.
    fn signed_bundle(
        sighash: &[u8; 32],
    ) -> (
        Vec<SpendDescription>,
        Vec<OutputDescription>,
        i64,
        Signature,
    ) {
        let ask = Fr::from_u64(0x1234_5678);
        let ak = verification_key(SigType::SpendAuth, &ask);
        let alpha = Fr::from_u64(777);
        let rcv = [Fr::from_u64(5), Fr::from_u64(6), Fr::from_u64(7)];
        let spends = vec![SpendDescription {
            cv: value_commitment(1_000, &rcv[0]).to_bytes(),
            nullifier: [0x11; 32],
            rk: randomized_spend_key(&ak, &alpha).to_bytes(),
            zkproof: [0; GROTH_PROOF_SIZE],
            spend_auth_sig: sign_spend(&ask, &alpha, sighash, &[1; 80]),
        }];
        let output = |value: u64, rcv: &Fr, tag: u8| OutputDescription {
            cv: value_commitment(value, rcv).to_bytes(),
            cmu: [tag; 32],
            ephemeral_key: value_commitment(1, rcv).to_bytes(),
            enc_ciphertext: [tag; ENC_CIPHERTEXT_SIZE],
            out_ciphertext: [tag; OUT_CIPHERTEXT_SIZE],
            zkproof: [0; GROTH_PROOF_SIZE],
        };
        let outputs = vec![output(600, &rcv[1], 1), output(300, &rcv[2], 2)];
        let bsk = binding_signing_key(&rcv[..1], &rcv[1..]);
        (spends, outputs, 100, sign_binding(&bsk, sighash, &[2; 80]))
    }

    /// An output built as a sender does is found by its recipient and
    /// recovered by its sender, through the serialized bundle.
    #[test]
    fn scanning() {
        use crate::sapling::keys::{ExpandedSpendingKey, default_diversifier};
        use crate::sapling::note::Rseed;
        use crate::sapling::note_encryption::{
            EMPTY_MEMO, encrypt_note, encrypt_outgoing, outgoing_cipher_key,
        };
        let sk = [0x33u8; 32];
        let fvk = ExpandedSpendingKey::from_spending_key(&sk)
            .unwrap()
            .full_viewing_key();
        let address = fvk
            .to_payment_address(default_diversifier(&sk).unwrap())
            .unwrap();
        let note = Note::new(address, 5_000, Rseed::AfterZip212([0x44; 32]));
        let rcv = Fr::from_u64(31337);
        let cv = value_commitment(note.value(), &rcv).to_bytes();
        let cmu = note.cmu();
        let (ephemeral_key, enc_ciphertext) = encrypt_note(&note, &EMPTY_MEMO).unwrap();
        let ock = outgoing_cipher_key(fvk.ovk(), &cv, &cmu, &ephemeral_key);
        let esk = note.rseed().esk().unwrap();
        let output = OutputDescription {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext: encrypt_outgoing(&ock, address.pk_d(), &esk),
            zkproof: [0; GROTH_PROOF_SIZE],
        };
        let sighash = [0x21; 32];
        let binding_sig = sign_binding(&binding_signing_key([], [&rcv]), &sighash, &[3; 80]);
        let mut bytes = vec![0u8; bundle_len(0, 1)];
        write_bundle(&[], &[output], -5_000, &[0; 32], &binding_sig, &mut bytes).unwrap();

        let bundle = BundleRef::parse(&bytes).unwrap();
        assert_eq!(bundle.anchor(), None);
        assert_eq!(bundle.verify(&sighash), Ok(()));
        let found = bundle.output(0).unwrap();
        let on = Zip212Enforcement::On;
        assert_eq!(
            found.try_note_decryption(&fvk.ivk(), on),
            Some((note, EMPTY_MEMO))
        );
        assert_eq!(
            found.try_output_recovery(fvk.ovk(), on),
            Some((note, EMPTY_MEMO))
        );
        let other = ExpandedSpendingKey::from_spending_key(&[0x34; 32])
            .unwrap()
            .full_viewing_key();
        assert_eq!(found.try_note_decryption(&other.ivk(), on), None);
        assert_eq!(found.try_output_recovery(other.ovk(), on), None);
    }

    #[test]
    fn verification() {
        let sighash = [0x77; 32];
        let (spends, outputs, balance, binding_sig) = signed_bundle(&sighash);
        let mut anchor = [0u8; 32];
        anchor[0] = 9;
        let serialize = |spends: &[SpendDescription],
                         outputs: &[OutputDescription],
                         balance: i64,
                         anchor: &[u8; 32]| {
            let mut buf = vec![0u8; bundle_len(spends.len(), outputs.len())];
            write_bundle(spends, outputs, balance, anchor, &binding_sig, &mut buf).unwrap();
            buf
        };
        let bytes = serialize(&spends, &outputs, balance, &anchor);
        let bundle = BundleRef::parse(&bytes).unwrap();
        assert_eq!(bundle.value_balance(), 100);
        assert_eq!(bundle.anchor(), Some(&anchor));
        assert_eq!(bundle.verify(&sighash), Ok(()));
        // another signature hash, another balance
        assert_eq!(bundle.verify(&[0x78; 32]), Err(Error::InvalidSignature));
        let bytes = serialize(&spends, &outputs, balance + 1, &anchor);
        assert_eq!(
            BundleRef::parse(&bytes).unwrap().verify(&sighash),
            Err(Error::InvalidSignature)
        );
        // a spend signature by another key
        let mut bad = spends.clone();
        bad[0].spend_auth_sig = sign_spend(&Fr::from_u64(1), &Fr::ZERO, &sighash, &[1; 80]);
        let bytes = serialize(&bad, &outputs, balance, &anchor);
        assert_eq!(
            BundleRef::parse(&bytes).unwrap().verify(&sighash),
            Err(Error::InvalidSignature)
        );
        // small-order and non-canonical encodings
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut bad = spends.clone();
        bad[0].rk = identity;
        let bytes = serialize(&bad, &outputs, balance, &anchor);
        assert_eq!(
            BundleRef::parse(&bytes).unwrap().verify(&sighash),
            Err(Error::InvalidPoint)
        );
        let mut bad = outputs.clone();
        bad[1].ephemeral_key = [0xff; 32];
        let bytes = serialize(&spends, &bad, balance, &anchor);
        assert_eq!(
            BundleRef::parse(&bytes).unwrap().verify(&sighash),
            Err(Error::InvalidPoint)
        );
        let mut bad = outputs.clone();
        bad[0].cmu = [0xff; 32];
        let bytes = serialize(&spends, &bad, balance, &anchor);
        assert_eq!(
            BundleRef::parse(&bytes).unwrap().verify(&sighash),
            Err(Error::InvalidScalar)
        );
        let bytes = serialize(&spends, &outputs, balance, &[0xff; 32]);
        assert_eq!(
            BundleRef::parse(&bytes).unwrap().verify(&sighash),
            Err(Error::InvalidScalar)
        );
    }

    #[test]
    fn structure() {
        let empty = BundleRef::parse(&[]).unwrap();
        assert!(empty.is_empty());
        assert_eq!(BundleRef::parse(&EMPTY_BUNDLE), Ok(empty));
        assert_eq!(empty.verify(&[0; 32]), Ok(()));
        assert_eq!(bundle_len(0, 0), 2);
        assert_eq!(bundle_len(1, 0), 2 + 96 + 8 + 32 + 192 + 64 + 64);
        assert_eq!(bundle_len(0, 1), 2 + 756 + 8 + 192 + 64);
        assert_eq!(bundle_len(253, 0) - bundle_len(252, 0), 352 + 2);
        let mut buf = [0u8; 8];
        assert_eq!(
            write_bundle(&[], &[], 0, &[0; 32], &Signature([0; 64]), &mut buf),
            Ok(2)
        );
        assert_eq!(
            write_bundle(&[], &[], 0, &[0; 32], &Signature([0; 64]), &mut buf[..1]),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(
            write_bundle(
                &[],
                &[],
                MAX_MONEY + 1,
                &[0; 32],
                &Signature([0; 64]),
                &mut buf
            ),
            Err(Error::ValueOutOfRange)
        );

        // malformed inputs: no panics, and the right errors
        assert_eq!(BundleRef::parse(&[0]), Err(Error::UnexpectedEof));
        assert_eq!(BundleRef::parse(&[1, 0]), Err(Error::UnexpectedEof));
        assert_eq!(BundleRef::parse(&[0, 0, 0]), Err(Error::TrailingData));
        // counts that are not minimally encoded, or absurd
        assert_eq!(
            BundleRef::parse(&[0xfd, 0, 0, 0]),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            BundleRef::parse(&[0xfe, 1, 0, 0, 0, 0]),
            Err(Error::InvalidLength)
        );
        let mut huge = vec![0xff];
        huge.extend_from_slice(&u64::MAX.to_le_bytes());
        huge.push(0);
        assert!(matches!(
            BundleRef::parse(&huge),
            Err(Error::InvalidLength | Error::UnexpectedEof)
        ));
        // a value balance out of range
        let sighash = [0; 32];
        let (spends, outputs, _, sig) = signed_bundle(&sighash);
        let mut bytes = vec![0u8; bundle_len(1, 2)];
        write_bundle(&spends, &outputs, 5, &[0; 32], &sig, &mut bytes).unwrap();
        let at = 1 + 96 + 1 + 2 * 756;
        assert_eq!(bytes[at], 5);
        bytes[at..at + 8].copy_from_slice(&(MAX_MONEY + 1).to_le_bytes());
        assert_eq!(BundleRef::parse(&bytes), Err(Error::ValueOutOfRange));
        bytes[at..at + 8].copy_from_slice(&(-MAX_MONEY).to_le_bytes());
        assert!(BundleRef::parse(&bytes).is_ok());
        for len in 0..bytes.len() {
            if len != 0 {
                assert!(BundleRef::parse(&bytes[..len]).is_err(), "{len}");
            }
        }
    }
}
