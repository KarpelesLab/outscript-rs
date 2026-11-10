//! Building the Sapling part of a transaction (feature
//! `zcash-sapling-prover`): spends and outputs with their proofs, then the
//! signatures.
//!
//! A [`Builder`] collects the notes to spend and the outputs to create.
//! [`Builder::build`] creates the proofs and gives an
//! [`UnauthorizedBundle`]: the complete bundle but for its signatures.
//! Its serialization, with the signatures zeroed, is what the transaction
//! digests are computed over (signatures are not part of the ZIP-244
//! transaction id or signature hash), so the caller places it in the
//! transaction, computes the signature hash, and passes it to
//! [`UnauthorizedBundle::sign`] for the final [`Bundle`]:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use outscript::sapling::builder::{Builder, OUTPUT_RANDOM_SIZE, SPEND_RANDOM_SIZE};
//! use outscript::sapling::prover::{OutputParameters, SpendParameters};
//! use outscript::zcashtx::{SIGHASH_ALL, ZcashTx};
//! # let expsk: outscript::sapling::keys::ExpandedSpendingKey = todo!();
//! # let note: outscript::sapling::note::Note = todo!();
//! # let path: outscript::sapling::tree::MerklePath = todo!();
//! # let anchor: [u8; 32] = todo!();
//! # let recipient: outscript::sapling::keys::PaymentAddress = todo!();
//! # let (spend_file, output_file): (Vec<u8>, Vec<u8>) = todo!();
//! # let spend_random: [u8; SPEND_RANDOM_SIZE] = todo!();
//! # let output_random: [u8; OUTPUT_RANDOM_SIZE] = todo!();
//! # let sig_random: Vec<u8> = todo!();
//!
//! // the contents of sapling-spend.params and sapling-output.params
//! let spend_params = SpendParameters::read(&spend_file)?;
//! let output_params = OutputParameters::read(&output_file)?;
//!
//! // every piece of randomness comes from the caller's generator
//! let mut builder = Builder::new(anchor);
//! builder.add_spend(&expsk, &note, &path, &spend_random)?;
//! builder.add_output(Some(expsk.ovk()), &recipient, 60_000, None, &output_random)?;
//! let unauthorized = builder.build(Some(&spend_params), Some(&output_params))?;
//!
//! // the digests do not cover the signatures
//! let sapling = unauthorized.to_bytes()?;
//! let tx = ZcashTx { sapling: &sapling, ..ZcashTx::default() };
//! let sighash = tx.sighash(None, SIGHASH_ALL, &[])?;
//!
//! // sig_random: unauthorized.signature_random_len() random bytes
//! let sapling = unauthorized.sign(&sighash, &sig_random)?.serialize()?;
//! let raw = ZcashTx { sapling: &sapling, ..tx }.serialize();
//! # Ok(()) }
//! ```
//!
//! The value balance of the bundle (spends minus outputs) is whatever the
//! caller's spends and outputs make it: it pays the fee and feeds the
//! transparent outputs and the other pools. The builder adds no change
//! output and no dummies, and keeps the order in which spends and outputs
//! were added; a wallet that wants to hide that order shuffles first.
//!
//! # Randomness
//!
//! The crate has no random number generator. Each spend takes
//! [`SPEND_RANDOM_SIZE`] random bytes, each output [`OUTPUT_RANDOM_SIZE`],
//! and signing [`UnauthorizedBundle::signature_random_len`]; all must come
//! fresh from a cryptographically secure generator. Reusing or predicting
//! them reveals values, links spends, or leaks the spend authorizing key.

use crate::prelude::*;
use crate::sapling::Error as SaplingError;
use crate::sapling::bundle::{Bundle, OutputDescription, SpendDescription};
use crate::sapling::circuit::{Output, Spend};
use crate::sapling::field::{Fq, Fr};
use crate::sapling::groth16::{self, SynthesisError};
use crate::sapling::keys::{ExpandedSpendingKey, OutgoingViewingKey, PaymentAddress};
use crate::sapling::note::{MAX_MONEY, Note, Rseed, value_commitment};
use crate::sapling::note_encryption::{
    EMPTY_MEMO, MEMO_SIZE, encrypt_note_with_esk, encrypt_outgoing, outgoing_cipher_key,
};
use crate::sapling::prover::{OutputParameters, PROOF_RANDOM_SIZE, SpendParameters};
use crate::sapling::redjubjub::{
    Signature, binding_signing_key, randomized_spend_key, sign_binding, sign_spend,
};
use crate::sapling::tree::MerklePath;
use purecrypto::zeroize::Zeroize;

/// The random bytes a spend consumes: 64 for the value commitment
/// randomness `rcv`, 64 for the spend authorization randomizer `α`, and
/// 128 for the proof.
pub const SPEND_RANDOM_SIZE: usize = 64 + 64 + PROOF_RANDOM_SIZE;

/// The random bytes an output consumes: 64 for the value commitment
/// randomness `rcv`, 32 for the note's `rseed`, 128 for the proof, and 32
/// for the outgoing cipher key of an output created without an outgoing
/// viewing key.
pub const OUTPUT_RANDOM_SIZE: usize = 64 + 32 + PROOF_RANDOM_SIZE + 32;

/// The random bytes one signature consumes.
pub const SIGNATURE_RANDOM_SIZE: usize = 80;

/// Why a bundle could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A key, note, path or value is invalid: see the inner error.
    Sapling(SaplingError),
    /// The spending key does not own the note.
    WrongKey,
    /// The note's position is already being spent in this bundle.
    DuplicateSpend,
    /// The bundle needs proving parameters that were not supplied.
    MissingParameters,
    /// A proof could not be created.
    Proof(SynthesisError),
    /// A proof that was created does not verify: the parameters are not
    /// the ones for this circuit.
    InvalidProof(groth16::Error),
    /// The randomness for the signatures has the wrong length.
    RandomLength,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Sapling(e) => write!(f, "{e}"),
            Error::WrongKey => f.write_str("the spending key does not own the note"),
            Error::DuplicateSpend => f.write_str("note spent twice"),
            Error::MissingParameters => f.write_str("missing proving parameters"),
            Error::Proof(e) => write!(f, "proof creation failed: {e}"),
            Error::InvalidProof(e) => write!(f, "created proof is invalid: {e}"),
            Error::RandomLength => f.write_str("wrong amount of signature randomness"),
        }
    }
}

impl core::error::Error for Error {}

impl From<SaplingError> for Error {
    fn from(e: SaplingError) -> Self {
        Error::Sapling(e)
    }
}

impl From<SynthesisError> for Error {
    fn from(e: SynthesisError) -> Self {
        Error::Proof(e)
    }
}

/// Splits fixed-size pieces off a random buffer.
struct Random<'a>(&'a [u8]);

impl Random<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        // the callers' buffers are sized for what is taken
        if let Some((head, tail)) = self.0.split_at_checked(N) {
            out.copy_from_slice(head);
            self.0 = tail;
        }
        out
    }

    fn scalar(&mut self) -> Fr {
        let mut wide = self.take::<64>();
        let s = Fr::from_bytes_wide(&wide);
        wide.zeroize();
        s
    }
}

/// A spend waiting for its proof.
struct SpendInfo {
    circuit: Spend,
    ask: Fr,
    cv: [u8; 32],
    nullifier: [u8; 32],
    rk: [u8; 32],
    position: u64,
    proof_random: [u8; PROOF_RANDOM_SIZE],
}

impl Drop for SpendInfo {
    fn drop(&mut self) {
        self.ask.zeroize();
        self.proof_random.zeroize();
    }
}

/// An output waiting for its proof.
struct OutputInfo {
    circuit: Output,
    description: OutputDescription,
    proof_random: [u8; PROOF_RANDOM_SIZE],
}

impl Drop for OutputInfo {
    fn drop(&mut self) {
        self.proof_random.zeroize();
    }
}

/// Collects the spends and outputs of a Sapling bundle: see the
/// [module documentation](self).
pub struct Builder {
    anchor: [u8; 32],
    spends: Vec<SpendInfo>,
    outputs: Vec<OutputInfo>,
}

impl core::fmt::Debug for Builder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Builder")
            .field("spends", &self.spends.len())
            .field("outputs", &self.outputs.len())
            .finish_non_exhaustive()
    }
}

impl Builder {
    /// A builder whose spends are all of notes in the commitment tree with
    /// root `anchor`. The anchor is not used by a bundle without spends.
    pub fn new(anchor: [u8; 32]) -> Self {
        Builder {
            anchor,
            spends: Vec::new(),
            outputs: Vec::new(),
        }
    }

    /// The number of spends added.
    pub fn n_spends(&self) -> usize {
        self.spends.len()
    }

    /// The number of outputs added.
    pub fn n_outputs(&self) -> usize {
        self.outputs.len()
    }

    /// The value balance of the bundle so far: the spent value minus the
    /// created value.
    pub fn value_balance(&self) -> i64 {
        // each value is at most MAX_MONEY, far from overflowing an i128
        let spent: i128 = self.spends.iter().map(|s| s.circuit.value as i128).sum();
        let created: i128 = self.outputs.iter().map(|o| o.circuit.value as i128).sum();
        (spent - created).clamp(i64::MIN as i128, i64::MAX as i128) as i64
    }

    /// Adds the spend of `note`, owned by the key `expsk` and located in
    /// the tree by `path`, which must lead to the builder's anchor. The
    /// key is kept (and wiped with the builder) for the spend
    /// authorization signature.
    ///
    /// Fails if the note's value is out of range, the key does not own the
    /// note ([`Error::WrongKey`]), the path does not lead from the note to
    /// the anchor ([`SaplingError::InvalidPath`]) or the same position is
    /// already spent.
    pub fn add_spend(
        &mut self,
        expsk: &ExpandedSpendingKey,
        note: &Note,
        path: &MerklePath,
        random: &[u8; SPEND_RANDOM_SIZE],
    ) -> Result<(), Error> {
        if note.value() > MAX_MONEY as u64 {
            return Err(SaplingError::ValueOutOfRange.into());
        }
        let pgk = expsk.proof_generation_key();
        let recipient = note.recipient();
        if recipient.g_d().mul(pgk.ivk().to_scalar()) != *recipient.pk_d() {
            return Err(Error::WrongKey);
        }
        path.verify(&note.cmu(), &self.anchor)?;
        if self.spends.iter().any(|s| s.position == path.position) {
            return Err(Error::DuplicateSpend);
        }
        let mut auth_path = Vec::with_capacity(path.siblings.len());
        for (level, sibling) in path.siblings.iter().enumerate() {
            let sibling = Fq::from_bytes(sibling).ok_or(SaplingError::InvalidPath)?;
            auth_path.push((sibling, (path.position >> level) & 1 == 1));
        }
        let anchor = Fq::from_bytes(&self.anchor).ok_or(SaplingError::InvalidPath)?;

        let mut random = Random(random);
        let rcv = random.scalar();
        let alpha = random.scalar();
        let proof_random = random.take();

        let cv = value_commitment(note.value(), &rcv).to_bytes();
        let nullifier = note.nullifier(&pgk.nk(), path.position);
        let rk = randomized_spend_key(&pgk.ak, &alpha).to_bytes();
        self.spends.push(SpendInfo {
            circuit: Spend {
                value: note.value(),
                rcv,
                g_d: *recipient.g_d(),
                rcm: note.rcm(),
                alpha,
                auth_path,
                anchor,
                proof_generation_key: pgk,
            },
            ask: *expsk.ask(),
            cv,
            nullifier,
            rk,
            position: path.position,
            proof_random,
        });
        Ok(())
    }

    /// Adds an output of `value` to the address `to`, with a memo
    /// ([`EMPTY_MEMO`] when `None`), and returns the note it creates.
    ///
    /// With an outgoing viewing key the sender (or anyone holding that
    /// key) can later decrypt the output; without, the outgoing ciphertext
    /// is encrypted under a random key that is thrown away.
    pub fn add_output(
        &mut self,
        ovk: Option<&OutgoingViewingKey>,
        to: &PaymentAddress,
        value: u64,
        memo: Option<&[u8; MEMO_SIZE]>,
        random: &[u8; OUTPUT_RANDOM_SIZE],
    ) -> Result<Note, Error> {
        if value > MAX_MONEY as u64 {
            return Err(SaplingError::ValueOutOfRange.into());
        }
        let mut random = Random(random);
        let rcv = random.scalar();
        let rseed = Rseed::AfterZip212(random.take());
        let proof_random = random.take();
        let mut random_ock: [u8; 32] = random.take();

        let note = Note::new(*to, value, rseed);
        // a ZIP-212 seed always has an esk
        let esk = rseed.esk().unwrap_or(Fr::ZERO);
        let cv = value_commitment(value, &rcv).to_bytes();
        let cmu = note.cmu();
        let (ephemeral_key, enc_ciphertext) =
            encrypt_note_with_esk(&note, memo.unwrap_or(&EMPTY_MEMO), &esk);
        let out_ciphertext = match ovk {
            Some(ovk) => {
                let ock = outgoing_cipher_key(ovk, &cv, &cmu, &ephemeral_key);
                encrypt_outgoing(&ock, to.pk_d(), &esk)
            }
            None => encrypt_outgoing(&random_ock, to.pk_d(), &esk),
        };
        random_ock.zeroize();

        self.outputs.push(OutputInfo {
            circuit: Output {
                value,
                rcv,
                g_d: *to.g_d(),
                pk_d: *to.pk_d(),
                rcm: note.rcm(),
                esk,
            },
            description: OutputDescription {
                cv,
                cmu,
                ephemeral_key,
                enc_ciphertext,
                out_ciphertext,
                zkproof: [0; 192],
            },
            proof_random,
        });
        Ok(note)
    }

    /// Creates the proofs and assembles the bundle, ready to be signed.
    ///
    /// The Spend parameters are only needed when there are spends and the
    /// Output parameters when there are outputs
    /// ([`Error::MissingParameters`] otherwise). Each proof is verified
    /// before it is returned. A Spend proof takes on the order of a second
    /// on one core, an Output proof a tenth of that; with `std` the work
    /// is spread over the available cores.
    pub fn build(
        self,
        spend_params: Option<&SpendParameters>,
        output_params: Option<&OutputParameters>,
    ) -> Result<UnauthorizedBundle, Error> {
        let value_balance = self.value_balance();
        if !(-MAX_MONEY..=MAX_MONEY).contains(&value_balance) {
            return Err(SaplingError::ValueOutOfRange.into());
        }

        let mut spends = Vec::with_capacity(self.spends.len());
        let mut signing_keys = Vec::with_capacity(self.spends.len());
        if !self.spends.is_empty() {
            let params = spend_params.ok_or(Error::MissingParameters)?;
            let vk = params.verifying_key();
            for spend in &self.spends {
                let zkproof = params.prove(&spend.circuit, &spend.proof_random)?;
                vk.verify(
                    &spend.cv,
                    &self.anchor,
                    &spend.nullifier,
                    &spend.rk,
                    &zkproof,
                )
                .map_err(Error::InvalidProof)?;
                spends.push(SpendDescription {
                    cv: spend.cv,
                    nullifier: spend.nullifier,
                    rk: spend.rk,
                    zkproof,
                    spend_auth_sig: Signature([0; 64]),
                });
                signing_keys.push(SigningKey {
                    ask: spend.ask,
                    alpha: spend.circuit.alpha,
                });
            }
        }

        let mut outputs = Vec::with_capacity(self.outputs.len());
        if !self.outputs.is_empty() {
            let params = output_params.ok_or(Error::MissingParameters)?;
            let vk = params.verifying_key();
            for output in &self.outputs {
                let mut description = output.description;
                description.zkproof = params.prove(&output.circuit, &output.proof_random)?;
                vk.verify(
                    &description.cv,
                    &description.cmu,
                    &description.ephemeral_key,
                    &description.zkproof,
                )
                .map_err(Error::InvalidProof)?;
                outputs.push(description);
            }
        }

        let bsk = binding_signing_key(
            self.spends.iter().map(|s| &s.circuit.rcv),
            self.outputs.iter().map(|o| &o.circuit.rcv),
        );
        Ok(UnauthorizedBundle {
            bundle: Bundle {
                spends,
                outputs,
                value_balance,
                anchor: self.anchor,
                binding_sig: Signature([0; 64]),
            },
            signing_keys,
            bsk,
        })
    }
}

/// What signs one spend.
struct SigningKey {
    ask: Fr,
    alpha: Fr,
}

/// A Sapling bundle with its proofs but without its signatures, and the
/// keys to sign it. The keys are wiped when the value is dropped.
pub struct UnauthorizedBundle {
    bundle: Bundle,
    signing_keys: Vec<SigningKey>,
    bsk: Fr,
}

impl core::fmt::Debug for UnauthorizedBundle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnauthorizedBundle")
            .field("bundle", &self.bundle)
            .finish_non_exhaustive()
    }
}

impl Drop for UnauthorizedBundle {
    fn drop(&mut self) {
        for key in &mut self.signing_keys {
            key.ask.zeroize();
            key.alpha.zeroize();
        }
        self.bsk.zeroize();
    }
}

impl UnauthorizedBundle {
    /// The bundle, with every signature zeroed.
    pub fn bundle(&self) -> &Bundle {
        &self.bundle
    }

    /// The serialized bundle with every signature zeroed: what to place in
    /// the transaction to compute its ZIP-244 digests, which do not cover
    /// the signatures.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.bundle.serialize()?)
    }

    /// The number of random bytes [`sign`](Self::sign) needs:
    /// [`SIGNATURE_RANDOM_SIZE`] per spend and for the binding signature,
    /// or none for an empty bundle.
    pub fn signature_random_len(&self) -> usize {
        if self.bundle.spends.is_empty() && self.bundle.outputs.is_empty() {
            0
        } else {
            SIGNATURE_RANDOM_SIZE * (self.bundle.spends.len() + 1)
        }
    }

    /// Signs the bundle for the transaction's signature hash (the ZIP-244
    /// digest for shielded signatures:
    /// [`ZcashTx::sighash`](crate::zcashtx::ZcashTx::sighash) with no input
    /// index): one spend authorization signature per spend, then the
    /// binding signature. `random` must hold exactly
    /// [`signature_random_len`](Self::signature_random_len) fresh random
    /// bytes.
    pub fn sign(mut self, sighash: &[u8; 32], random: &[u8]) -> Result<Bundle, Error> {
        if random.len() != self.signature_random_len() {
            return Err(Error::RandomLength);
        }
        let mut bundle = core::mem::replace(
            &mut self.bundle,
            Bundle {
                spends: Vec::new(),
                outputs: Vec::new(),
                value_balance: 0,
                anchor: [0; 32],
                binding_sig: Signature([0; 64]),
            },
        );
        let (chunks, _) = random.as_chunks::<SIGNATURE_RANDOM_SIZE>();
        let mut chunks = chunks.iter();
        for (spend, key) in bundle.spends.iter_mut().zip(&self.signing_keys) {
            let random = chunks.next().ok_or(Error::RandomLength)?;
            spend.spend_auth_sig = sign_spend(&key.ask, &key.alpha, sighash, random);
        }
        if let Some(random) = chunks.next() {
            bundle.binding_sig = sign_binding(&self.bsk, sighash, random);
        }
        Ok(bundle)
    }
}

#[cfg(test)]
mod tests;
