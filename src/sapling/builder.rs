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
//! transparent outputs and the other pools. By default the builder adds
//! nothing and keeps the order in which spends and outputs were added.
//! What `sapling-crypto`'s builder does on its own is done on request,
//! before [`Builder::build`]:
//!
//! - [`Builder::add_change`] adds the output that brings the value balance
//!   down to what must leave the pool;
//! - [`Builder::pad`] adds the dummy spends and outputs a [`BundleType`]
//!   asks for (at least two outputs for an ordinary bundle), and
//!   [`Builder::add_dummy_spend`] and [`Builder::add_dummy_output`] add
//!   them one by one;
//! - [`Builder::shuffle`] puts the spends and the outputs in a random
//!   order and tells where each one went.
//!
//! # Signing elsewhere
//!
//! The spend authorizing key `ask` need not be in the memory of the
//! machine that builds the transaction. [`Builder::add_spend_with_proof_key`]
//! takes the proof generation key `(ak, nsk)` instead, which is enough to
//! prove but cannot authorize a spend. After [`Builder::build`],
//! [`UnauthorizedBundle::prepare`] fixes the signature hash and signs what
//! the builder can sign (the binding signature, and the spends it has a key
//! for, dummies included); the holder of `ask` then signs the signature
//! hash for each remaining spend with `rsk = ask + α`
//! ([`redjubjub::sign_spend`](sign_spend)), `α` and `rk`
//! being given by [`PartiallyAuthorized::signing_parts`]; the signatures
//! come back through [`PartiallyAuthorized::append_signature`], which
//! verifies them:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use outscript::sapling::builder::{Builder, SPEND_RANDOM_SIZE};
//! use outscript::sapling::prover::SpendParameters;
//! use outscript::sapling::redjubjub::Signature;
//! # let proof_key: outscript::sapling::keys::ProofGenerationKey = todo!();
//! # let note: outscript::sapling::note::Note = todo!();
//! # let path: outscript::sapling::tree::MerklePath = todo!();
//! # let anchor: [u8; 32] = todo!();
//! # let spend_params: SpendParameters = todo!();
//! # let spend_random: [u8; SPEND_RANDOM_SIZE] = todo!();
//! # let sig_random: Vec<u8> = todo!();
//! # let sighash: [u8; 32] = todo!();
//! # fn device_sign(alpha: &outscript::sapling::Fr, sighash: &[u8; 32]) -> Signature { todo!() }
//!
//! let mut builder = Builder::new(anchor);
//! builder.add_spend_with_proof_key(&proof_key, &note, &path, &spend_random)?;
//! let unauthorized = builder.build(Some(&spend_params), None)?;
//! // ... place unauthorized.to_bytes() in the transaction, compute sighash
//!
//! let mut partial = unauthorized.prepare(&sighash, &sig_random)?;
//! for index in partial.missing().collect::<Vec<_>>() {
//!     let parts = partial.signing_parts(index).expect("a missing signature");
//!     // on the device: sign_spend(&ask, &parts.alpha, &sighash, &random)
//!     let signature = device_sign(&parts.alpha, partial.sighash());
//!     partial.append_signature(index, &signature)?;
//! }
//! let bundle = partial.finalize()?;
//! # Ok(()) }
//! ```
//!
//! # Randomness
//!
//! The crate has no random number generator. Each spend takes
//! [`SPEND_RANDOM_SIZE`] random bytes, each output [`OUTPUT_RANDOM_SIZE`],
//! and signing [`UnauthorizedBundle::signature_random_len`] (dummies,
//! padding and shuffling have their own sizes); all must come fresh from a
//! cryptographically secure generator. Reusing or predicting them reveals
//! values, links spends, or leaks the spend authorizing key.

use crate::prelude::*;
use crate::sapling::Error as SaplingError;
use crate::sapling::bundle::{Bundle, OutputDescription, SpendDescription};
use crate::sapling::circuit::{Output, Spend};
use crate::sapling::field::{Fq, Fr};
use crate::sapling::groth16::{self, SynthesisError};
use crate::sapling::jubjub::Point;
use crate::sapling::keys::{
    Diversifier, ExpandedSpendingKey, OutgoingViewingKey, PaymentAddress, ProofGenerationKey,
    default_diversifier,
};
use crate::sapling::note::{MAX_MONEY, Note, Rseed, value_commitment};
use crate::sapling::note_encryption::{
    EMPTY_MEMO, MEMO_SIZE, encrypt_note_with_esk, encrypt_outgoing, outgoing_cipher_key,
};
use crate::sapling::prf::blake2b;
use crate::sapling::prover::{OutputParameters, PROOF_RANDOM_SIZE, SpendParameters};
use crate::sapling::redjubjub::{
    SigType, Signature, binding_signing_key, randomized_spend_key, sign_binding, sign_spend,
    verification_key, verify_spend,
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

/// The random bytes a dummy spend consumes: 32 for the spending key of the
/// dummy note, 32 for its `rseed`, 32 for its authentication path, and
/// those of a spend.
pub const DUMMY_SPEND_RANDOM_SIZE: usize = 96 + SPEND_RANDOM_SIZE;

/// The random bytes a dummy output consumes: 64 for the incoming viewing
/// key of its recipient, 32 for the diversifier, and those of an output.
pub const DUMMY_OUTPUT_RANDOM_SIZE: usize = 96 + OUTPUT_RANDOM_SIZE;

/// The random bytes [`Builder::shuffle`] consumes per spend and per output.
pub const SHUFFLE_RANDOM_SIZE: usize = 8;

/// The least number of outputs of an ordinary bundle that has any spend or
/// output: with fewer, dummies are added, so that a bundle does not tell
/// whether it has change (as `sapling-crypto` and `zcashd` do).
pub const MIN_SHIELDED_OUTPUTS: usize = 2;

/// The rules a bundle is padded to: those of `sapling-crypto`'s
/// `BundleType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleType {
    /// An ordinary bundle: padded to at least [`MIN_SHIELDED_OUTPUTS`]
    /// outputs as soon as it has a spend or an output.
    Transactional {
        /// Whether a bundle is wanted even when nothing was added: it then
        /// gets one dummy spend and two dummy outputs, to make a
        /// transaction look like one that uses the Sapling pool.
        bundle_required: bool,
    },
    /// The bundle of a coinbase transaction: no spends are allowed, and
    /// nothing is padded.
    Coinbase,
}

impl BundleType {
    /// The usual rules: pad the outputs, and build nothing when there is
    /// nothing to build.
    pub const DEFAULT: BundleType = BundleType::Transactional {
        bundle_required: false,
    };

    /// The number of spends of a bundle of this type for which
    /// `requested_spends` were added.
    /// [`Error::BundleTypeNotSatisfiable`] for a coinbase bundle with
    /// spends.
    pub const fn num_spends(&self, requested_spends: usize) -> Result<usize, Error> {
        match self {
            BundleType::Transactional { bundle_required } => {
                if *bundle_required && requested_spends == 0 {
                    Ok(1)
                } else {
                    Ok(requested_spends)
                }
            }
            BundleType::Coinbase if requested_spends == 0 => Ok(0),
            BundleType::Coinbase => Err(Error::BundleTypeNotSatisfiable),
        }
    }

    /// The number of outputs of a bundle of this type for which
    /// `requested_spends` and `requested_outputs` were added.
    pub const fn num_outputs(
        &self,
        requested_spends: usize,
        requested_outputs: usize,
    ) -> Result<usize, Error> {
        match self {
            BundleType::Transactional { bundle_required } => {
                if (*bundle_required || requested_spends > 0 || requested_outputs > 0)
                    && requested_outputs < MIN_SHIELDED_OUTPUTS
                {
                    Ok(MIN_SHIELDED_OUTPUTS)
                } else {
                    Ok(requested_outputs)
                }
            }
            BundleType::Coinbase if requested_spends == 0 => Ok(requested_outputs),
            BundleType::Coinbase => Err(Error::BundleTypeNotSatisfiable),
        }
    }
}

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
    /// The randomness supplied has the wrong length.
    RandomLength,
    /// The spends do not cover the outputs and the value that must leave
    /// the pool: there is nothing left for a change output.
    InsufficientFunds,
    /// The spends and outputs do not fit the [`BundleType`] (a coinbase
    /// bundle with spends).
    BundleTypeNotSatisfiable,
    /// A spend has no signature: its key is held elsewhere (see
    /// [`UnauthorizedBundle::prepare`]).
    MissingSignatures,
    /// A signature made elsewhere does not verify for the spend it was
    /// given for, or for any spend still to be signed.
    InvalidExternalSignature,
    /// A signature made elsewhere is for a spend that is already signed,
    /// or fits more than one spend.
    DuplicateSignature,
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
            Error::RandomLength => f.write_str("wrong amount of randomness"),
            Error::InsufficientFunds => f.write_str("insufficient funds"),
            Error::BundleTypeNotSatisfiable => {
                f.write_str("the spends and outputs do not fit the bundle type")
            }
            Error::MissingSignatures => f.write_str("a spend is not signed"),
            Error::InvalidExternalSignature => f.write_str("invalid external signature"),
            Error::DuplicateSignature => f.write_str("duplicate signature"),
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
    /// `None` when the spend is authorized elsewhere.
    ask: Option<Fr>,
    cv: [u8; 32],
    nullifier: [u8; 32],
    rk: [u8; 32],
    /// `None` for a dummy.
    position: Option<u64>,
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

/// Where the spends and outputs of a builder went when they were shuffled:
/// the result of [`Builder::shuffle`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metadata {
    spend_indices: Vec<usize>,
    output_indices: Vec<usize>,
}

impl Metadata {
    /// The index in the bundle of the spend that was number `n` before the
    /// shuffle (the `n`-th added, when nothing was shuffled before).
    pub fn spend_index(&self, n: usize) -> Option<usize> {
        self.spend_indices.get(n).copied()
    }

    /// The index in the bundle of the output that was number `n` before
    /// the shuffle.
    pub fn output_index(&self, n: usize) -> Option<usize> {
        self.output_indices.get(n).copied()
    }
}

/// Shuffles `items` (Fisher–Yates) with 8 random bytes per item, and
/// returns where each one went.
fn shuffle_items<T>(items: &mut [T], random: &[[u8; SHUFFLE_RANDOM_SIZE]]) -> Vec<usize> {
    // origin[i]: the original index of the item now at i
    let mut origin: Vec<usize> = (0..items.len()).collect();
    for (i, bytes) in (1..items.len()).rev().zip(random) {
        // uniform in 0..=i, with a bias below 2⁻⁶⁴·(i + 1)
        let j = ((u64::from_le_bytes(*bytes) as u128 * (i as u128 + 1)) >> 64) as usize;
        items.swap(i, j);
        origin.swap(i, j);
    }
    let mut indices = vec![0; items.len()];
    for (now, was) in origin.into_iter().enumerate() {
        if let Some(index) = indices.get_mut(was) {
            *index = now;
        }
    }
    indices
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
        let pgk = expsk.proof_generation_key();
        self.push_spend(pgk, Some(*expsk.ask()), note, path, random)
    }

    /// Adds the spend of `note` as [`add_spend`](Self::add_spend) does, but
    /// with the proof generation key `(ak, nsk)` of its owner instead of
    /// the spending key: the spend authorizing key `ask` stays wherever it
    /// is kept (a hardware wallet, another machine), and the spend is
    /// signed there. The proof generation key is the full viewing key with
    /// `nsk` in place of `nk`: it sees what the owner sees and lets a
    /// prover make the Spend proof, but cannot authorize a spend.
    ///
    /// The bundle is then signed in two steps: see
    /// [`UnauthorizedBundle::prepare`].
    pub fn add_spend_with_proof_key(
        &mut self,
        proof_generation_key: &ProofGenerationKey,
        note: &Note,
        path: &MerklePath,
        random: &[u8; SPEND_RANDOM_SIZE],
    ) -> Result<(), Error> {
        self.push_spend(proof_generation_key.clone(), None, note, path, random)
    }

    fn push_spend(
        &mut self,
        pgk: ProofGenerationKey,
        ask: Option<Fr>,
        note: &Note,
        path: &MerklePath,
        random: &[u8; SPEND_RANDOM_SIZE],
    ) -> Result<(), Error> {
        if note.value() > MAX_MONEY as u64 {
            return Err(SaplingError::ValueOutOfRange.into());
        }
        let recipient = note.recipient();
        if recipient.g_d().mul(pgk.ivk().to_scalar()) != *recipient.pk_d() {
            return Err(Error::WrongKey);
        }
        path.verify(&note.cmu(), &self.anchor)?;
        if self
            .spends
            .iter()
            .any(|s| s.position == Some(path.position))
        {
            return Err(Error::DuplicateSpend);
        }
        self.push_spend_unchecked(pgk, ask, note, path, Some(path.position), random)
    }

    /// Adds a spend whose note, key and path are consistent (or whose
    /// value is zero, when the path is not checked by the circuit).
    fn push_spend_unchecked(
        &mut self,
        pgk: ProofGenerationKey,
        ask: Option<Fr>,
        note: &Note,
        path: &MerklePath,
        position: Option<u64>,
        random: &[u8; SPEND_RANDOM_SIZE],
    ) -> Result<(), Error> {
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
                g_d: *note.recipient().g_d(),
                rcm: note.rcm(),
                alpha,
                auth_path,
                anchor,
                proof_generation_key: pgk,
            },
            ask,
            cv,
            nullifier,
            rk,
            position,
            proof_random,
        });
        Ok(())
    }

    /// Adds a dummy spend (protocol specification §4.8.2): the spend of a
    /// note of value zero that was never created, under a key made up for
    /// it, which is indistinguishable from a real spend. Its nullifier is
    /// random and its authentication path arbitrary, which the Spend
    /// circuit allows for a zero value; its anchor is the builder's, which
    /// must therefore be a root of the note commitment tree even when the
    /// bundle has no real spend.
    ///
    /// The builder holds the dummy's key and signs for it.
    pub fn add_dummy_spend(&mut self, random: &[u8; DUMMY_SPEND_RANDOM_SIZE]) -> Result<(), Error> {
        let mut random = Random(random);
        let mut sk: [u8; 32] = random.take();
        let rseed: [u8; 32] = random.take();
        let mut path_seed: [u8; 32] = random.take();
        let spend_random = random.take();

        // an invalid key or diversifier has a negligible probability
        let made = ExpandedSpendingKey::from_spending_key(&sk).and_then(|expsk| {
            let diversifier = default_diversifier(&sk).ok_or(SaplingError::InvalidDiversifier)?;
            let address = expsk
                .full_viewing_key()
                .to_payment_address(diversifier)
                .ok_or(SaplingError::InvalidAddress)?;
            Ok((expsk, address))
        });
        sk.zeroize();
        let (expsk, address) = made?;
        let note = Note::new(address, 0, Rseed::AfterZip212(rseed));
        let mut path = MerklePath {
            position: 0,
            siblings: [[0; 32]; crate::sapling::tree::DEPTH],
        };
        for (level, sibling) in path.siblings.iter_mut().enumerate() {
            let mut wide: [u8; 64] = blake2b(b"outscript_dummy_", &[&path_seed, &[level as u8]]);
            *sibling = Fq::from_bytes_wide(&wide).to_bytes();
            wide.zeroize();
        }
        path_seed.zeroize();
        let result = self.push_spend_unchecked(
            expsk.proof_generation_key(),
            Some(*expsk.ask()),
            &note,
            &path,
            None,
            &spend_random,
        );
        let mut spend_random = spend_random;
        spend_random.zeroize();
        result
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

    /// Adds the change output: an output to `to` (an address of the
    /// sender) of whatever the spends leave once the outputs added so far
    /// and `value_balance` are paid, `value_balance` being the value that
    /// must leave the Sapling pool (the fee, plus what goes to transparent
    /// outputs and other pools, minus what comes from them). Afterwards
    /// [`value_balance`](Self::value_balance) is that value.
    ///
    /// Returns the change note, or `None` (adding nothing) when nothing is
    /// left. Fails with [`Error::InsufficientFunds`] when the spends do not
    /// cover the outputs and `value_balance`. The parameters are those of
    /// [`add_output`](Self::add_output).
    pub fn add_change(
        &mut self,
        ovk: Option<&OutgoingViewingKey>,
        to: &PaymentAddress,
        value_balance: i64,
        memo: Option<&[u8; MEMO_SIZE]>,
        random: &[u8; OUTPUT_RANDOM_SIZE],
    ) -> Result<Option<Note>, Error> {
        let change = self.value_balance() as i128 - value_balance as i128;
        if change < 0 {
            return Err(Error::InsufficientFunds);
        }
        if change == 0 {
            return Ok(None);
        }
        let change = u64::try_from(change).map_err(|_| SaplingError::ValueOutOfRange)?;
        self.add_output(ovk, to, change, memo, random).map(Some)
    }

    /// Adds a dummy output: an output of value zero to an address made up
    /// for it, with an all-zero memo, which nobody can decrypt and which is
    /// indistinguishable from a real output.
    pub fn add_dummy_output(
        &mut self,
        random: &[u8; DUMMY_OUTPUT_RANDOM_SIZE],
    ) -> Result<(), Error> {
        let mut random = Random(random);
        let mut ivk = random.scalar();
        let mut seed: [u8; 32] = random.take();
        let mut output_random = random.take();
        // the first candidate that is a valid diversifier: about one in two
        let made = (0..=255u8)
            .find_map(|i| {
                let d = Diversifier(blake2b(b"outscript_dummy_", &[&seed, &[0xff, i]]));
                d.g_d().map(|g_d| (d, g_d))
            })
            .ok_or(SaplingError::InvalidDiversifier)
            .and_then(|(d, g_d)| PaymentAddress::from_parts(d, g_d.mul(&ivk)));
        ivk.zeroize();
        seed.zeroize();
        let result = made
            .map_err(Error::from)
            .and_then(|to| self.add_output(None, &to, 0, Some(&[0; MEMO_SIZE]), &output_random));
        output_random.zeroize();
        result.map(|_| ())
    }

    /// The numbers of dummy spends and dummy outputs [`pad`](Self::pad)
    /// adds for a bundle type.
    pub fn padding(&self, bundle_type: BundleType) -> Result<(usize, usize), Error> {
        let (spends, outputs) = (self.spends.len(), self.outputs.len());
        Ok((
            bundle_type.num_spends(spends)? - spends,
            bundle_type.num_outputs(spends, outputs)? - outputs,
        ))
    }

    /// The number of random bytes [`pad`](Self::pad) needs for a bundle
    /// type: [`DUMMY_SPEND_RANDOM_SIZE`] and [`DUMMY_OUTPUT_RANDOM_SIZE`]
    /// for each dummy of [`padding`](Self::padding).
    pub fn padding_random_len(&self, bundle_type: BundleType) -> Result<usize, Error> {
        let (spends, outputs) = self.padding(bundle_type)?;
        Ok(spends * DUMMY_SPEND_RANDOM_SIZE + outputs * DUMMY_OUTPUT_RANDOM_SIZE)
    }

    /// Adds the dummy spends and outputs the bundle type asks for, as
    /// `sapling-crypto`'s builder does: for [`BundleType::DEFAULT`], dummy
    /// outputs up to [`MIN_SHIELDED_OUTPUTS`] when there is any spend or
    /// output. Call it once everything else is added, and before
    /// [`shuffle`](Self::shuffle).
    ///
    /// `random` must hold exactly
    /// [`padding_random_len`](Self::padding_random_len) fresh random bytes
    /// ([`Error::RandomLength`] otherwise). Fails with
    /// [`Error::BundleTypeNotSatisfiable`] for a coinbase bundle with
    /// spends.
    pub fn pad(&mut self, bundle_type: BundleType, random: &[u8]) -> Result<(), Error> {
        let (spends, outputs) = self.padding(bundle_type)?;
        let (for_spends, for_outputs) = random
            .split_at_checked(spends * DUMMY_SPEND_RANDOM_SIZE)
            .ok_or(Error::RandomLength)?;
        if for_outputs.len() != outputs * DUMMY_OUTPUT_RANDOM_SIZE {
            return Err(Error::RandomLength);
        }
        for random in for_spends.as_chunks::<DUMMY_SPEND_RANDOM_SIZE>().0 {
            self.add_dummy_spend(random)?;
        }
        for random in for_outputs.as_chunks::<DUMMY_OUTPUT_RANDOM_SIZE>().0 {
            self.add_dummy_output(random)?;
        }
        Ok(())
    }

    /// The number of random bytes [`shuffle`](Self::shuffle) needs:
    /// [`SHUFFLE_RANDOM_SIZE`] per spend and per output.
    pub fn shuffle_random_len(&self) -> usize {
        SHUFFLE_RANDOM_SIZE * (self.spends.len() + self.outputs.len())
    }

    /// Puts the spends in a random order, and the outputs in another, so
    /// that their order in the transaction says nothing of the order they
    /// were added in (which output is the change, which spends are
    /// dummies). Returns where each one went.
    ///
    /// `random` must hold exactly
    /// [`shuffle_random_len`](Self::shuffle_random_len) fresh random bytes
    /// ([`Error::RandomLength`] otherwise): the permutation is as
    /// unpredictable as they are.
    pub fn shuffle(&mut self, random: &[u8]) -> Result<Metadata, Error> {
        let (random, rest) = random.as_chunks::<SHUFFLE_RANDOM_SIZE>();
        if !rest.is_empty() || random.len() != self.spends.len() + self.outputs.len() {
            return Err(Error::RandomLength);
        }
        let (for_spends, for_outputs) = random
            .split_at_checked(self.spends.len())
            .ok_or(Error::RandomLength)?;
        Ok(Metadata {
            spend_indices: shuffle_items(&mut self.spends, for_spends),
            output_indices: shuffle_items(&mut self.outputs, for_outputs),
        })
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
                    ak: spend.circuit.proof_generation_key.ak,
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
    /// `None` when the spend is authorized elsewhere.
    ask: Option<Fr>,
    alpha: Fr,
    ak: Point,
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.ask.zeroize();
        self.alpha.zeroize();
    }
}

/// What the holder of a spend authorizing key needs to sign a spend, and
/// what tells which key that is.
///
/// `alpha` is not a key, but it links the spend to its owner's `ak`: it is
/// for the signer only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendSigningParts {
    /// The spend validating key `ak` of the note's owner: the signer holds
    /// the `ask` with `ak = [ask] G`.
    pub ak: Point,
    /// The spend authorization randomizer `α`: the signature is made with
    /// `rsk = ask + α`.
    pub alpha: Fr,
    /// The randomized key `rk = ak + [α] G` of the spend description, under
    /// which the signature must verify.
    pub rk: [u8; 32],
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
        self.bsk.zeroize();
    }
}

/// A bundle without spends, outputs or signatures.
fn empty_bundle() -> Bundle {
    Bundle {
        spends: Vec::new(),
        outputs: Vec::new(),
        value_balance: 0,
        anchor: [0; 32],
        binding_sig: Signature([0; 64]),
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

    /// The number of random bytes [`sign`](Self::sign) and
    /// [`prepare`](Self::prepare) need: [`SIGNATURE_RANDOM_SIZE`] per spend
    /// and for the binding signature, or none for an empty bundle.
    pub fn signature_random_len(&self) -> usize {
        if self.bundle.spends.is_empty() && self.bundle.outputs.is_empty() {
            0
        } else {
            SIGNATURE_RANDOM_SIZE * (self.bundle.spends.len() + 1)
        }
    }

    /// What the signer of spend `index` needs; `None` past the last
    /// spend. See [`SpendSigningParts`].
    pub fn signing_parts(&self, index: usize) -> Option<SpendSigningParts> {
        let key = self.signing_keys.get(index)?;
        Some(SpendSigningParts {
            ak: key.ak,
            alpha: key.alpha,
            rk: self.bundle.spends.get(index)?.rk,
        })
    }

    /// The indices of the spends the builder has no key for (those added
    /// with [`Builder::add_spend_with_proof_key`]): they are signed
    /// elsewhere, through [`prepare`](Self::prepare).
    pub fn external_spends(&self) -> impl Iterator<Item = usize> + '_ {
        self.signing_keys
            .iter()
            .enumerate()
            .filter(|(_, key)| key.ask.is_none())
            .map(|(index, _)| index)
    }

    /// Signs the bundle for the transaction's signature hash (the ZIP-244
    /// digest for shielded signatures:
    /// [`ZcashTx::sighash`](crate::zcashtx::ZcashTx::sighash) with no input
    /// index): one spend authorization signature per spend, then the
    /// binding signature. `random` must hold exactly
    /// [`signature_random_len`](Self::signature_random_len) fresh random
    /// bytes.
    ///
    /// Fails with [`Error::MissingSignatures`] when a spend is to be
    /// signed elsewhere: use [`prepare`](Self::prepare) then.
    pub fn sign(self, sighash: &[u8; 32], random: &[u8]) -> Result<Bundle, Error> {
        if self.signing_keys.iter().any(|key| key.ask.is_none()) {
            return Err(Error::MissingSignatures);
        }
        self.prepare(sighash, random)?.finalize()
    }

    /// Fixes the signature hash and makes every signature the builder can
    /// make: the binding signature, and the spend authorization signature
    /// of each spend it has the key of (dummy spends among them). What is
    /// left are the spends whose key is held elsewhere: see
    /// [`PartiallyAuthorized`].
    ///
    /// `random` must hold exactly
    /// [`signature_random_len`](Self::signature_random_len) fresh random
    /// bytes (the part for the spends signed elsewhere is not used).
    pub fn prepare(
        mut self,
        sighash: &[u8; 32],
        random: &[u8],
    ) -> Result<PartiallyAuthorized, Error> {
        if random.len() != self.signature_random_len() {
            return Err(Error::RandomLength);
        }
        let mut bundle = core::mem::replace(&mut self.bundle, empty_bundle());
        let (chunks, _) = random.as_chunks::<SIGNATURE_RANDOM_SIZE>();
        let mut chunks = chunks.iter();
        let mut pending = Vec::with_capacity(bundle.spends.len());
        for (spend, key) in bundle.spends.iter_mut().zip(&self.signing_keys) {
            let random = chunks.next().ok_or(Error::RandomLength)?;
            match &key.ask {
                Some(ask) => {
                    spend.spend_auth_sig = sign_spend(ask, &key.alpha, sighash, random);
                    pending.push(None);
                }
                None => pending.push(Some(Pending {
                    ak: key.ak,
                    alpha: key.alpha,
                })),
            }
        }
        if let Some(random) = chunks.next() {
            bundle.binding_sig = sign_binding(&self.bsk, sighash, random);
        }
        Ok(PartiallyAuthorized {
            bundle,
            sighash: *sighash,
            pending,
        })
    }
}

/// A spend waiting for a signature made elsewhere.
#[derive(Clone)]
struct Pending {
    ak: Point,
    alpha: Fr,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.alpha.zeroize();
    }
}

/// A Sapling bundle being signed: the signature hash is fixed, the binding
/// signature and the signatures the builder could make are in place, and
/// the others are added as their signers return them. Obtained from
/// [`UnauthorizedBundle::prepare`].
///
/// It holds no key. For each spend of [`missing`](Self::missing), the
/// holder of its spend authorizing key signs [`sighash`](Self::sighash)
/// with the randomizer of [`signing_parts`](Self::signing_parts), as
/// [`redjubjub::sign_spend`](sign_spend) does, and the
/// signature is given to [`append_signature`](Self::append_signature);
/// [`finalize`](Self::finalize) then gives the bundle.
#[derive(Clone)]
pub struct PartiallyAuthorized {
    bundle: Bundle,
    sighash: [u8; 32],
    /// For each spend, what its signer needs, until it is signed.
    pending: Vec<Option<Pending>>,
}

impl core::fmt::Debug for PartiallyAuthorized {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PartiallyAuthorized")
            .field("bundle", &self.bundle)
            .field("missing", &self.missing().count())
            .finish_non_exhaustive()
    }
}

impl PartiallyAuthorized {
    /// The signature hash every signature of the bundle is over.
    pub fn sighash(&self) -> &[u8; 32] {
        &self.sighash
    }

    /// The bundle as it stands: the signatures still missing are zeroed.
    pub fn bundle(&self) -> &Bundle {
        &self.bundle
    }

    /// The indices of the spends that are not signed yet.
    pub fn missing(&self) -> impl Iterator<Item = usize> + '_ {
        self.pending
            .iter()
            .enumerate()
            .filter(|(_, pending)| pending.is_some())
            .map(|(index, _)| index)
    }

    /// Whether every spend is signed.
    pub fn is_complete(&self) -> bool {
        self.pending.iter().all(Option::is_none)
    }

    /// What the signer of spend `index` needs; `None` when the spend is
    /// signed already, or past the last spend.
    pub fn signing_parts(&self, index: usize) -> Option<SpendSigningParts> {
        let pending = self.pending.get(index)?.as_ref()?;
        Some(SpendSigningParts {
            ak: pending.ak,
            alpha: pending.alpha,
            rk: self.bundle.spends.get(index)?.rk,
        })
    }

    /// Signs spend `index` with the spend authorizing key `ask` of its
    /// note's owner and [`SIGNATURE_RANDOM_SIZE`] fresh random bytes: for
    /// a key that is at hand after all. Fails with [`Error::WrongKey`]
    /// when the key is not the spend's, and with
    /// [`Error::DuplicateSignature`] when the spend is signed already (or
    /// there is no such spend).
    pub fn sign_spend(
        &mut self,
        index: usize,
        ask: &Fr,
        random: &[u8; SIGNATURE_RANDOM_SIZE],
    ) -> Result<(), Error> {
        let sighash = self.sighash;
        let (slot, spend) = self.slot(index)?;
        let pending = slot.as_ref().ok_or(Error::DuplicateSignature)?;
        if verification_key(SigType::SpendAuth, ask) != pending.ak {
            return Err(Error::WrongKey);
        }
        spend.spend_auth_sig = sign_spend(ask, &pending.alpha, &sighash, random);
        *slot = None;
        Ok(())
    }

    fn slot(
        &mut self,
        index: usize,
    ) -> Result<(&mut Option<Pending>, &mut SpendDescription), Error> {
        match (
            self.pending.get_mut(index),
            self.bundle.spends.get_mut(index),
        ) {
            (Some(slot), Some(spend)) => Ok((slot, spend)),
            _ => Err(Error::DuplicateSignature),
        }
    }

    /// Adds the spend authorization signature of spend `index`, made by
    /// the holder of its key. The signature is verified under the spend's
    /// `rk` for the signature hash: [`Error::InvalidExternalSignature`]
    /// when it does not verify, leaving the bundle as it was;
    /// [`Error::DuplicateSignature`] when the spend is signed already (or
    /// there is no such spend).
    pub fn append_signature(&mut self, index: usize, signature: &Signature) -> Result<(), Error> {
        let sighash = self.sighash;
        let (slot, spend) = self.slot(index)?;
        if slot.is_none() {
            return Err(Error::DuplicateSignature);
        }
        verify_spend(&spend.rk, &sighash, signature)
            .map_err(|_| Error::InvalidExternalSignature)?;
        spend.spend_auth_sig = *signature;
        *slot = None;
        Ok(())
    }

    /// Adds signatures made elsewhere without saying which spend each is
    /// for, as `sapling-crypto`'s `append_signatures` does: each signature
    /// goes to the one unsigned spend it verifies for. Fails, leaving the
    /// bundle as it was, with [`Error::InvalidExternalSignature`] when a
    /// signature verifies for none, and with [`Error::DuplicateSignature`]
    /// when it verifies for several or two signatures are for the same
    /// spend.
    pub fn append_signatures(&mut self, signatures: &[Signature]) -> Result<(), Error> {
        let mut placed: Vec<(usize, Signature)> = Vec::with_capacity(signatures.len());
        for signature in signatures {
            let mut fits = self.missing().filter(|&index| {
                self.bundle
                    .spends
                    .get(index)
                    .is_some_and(|spend| verify_spend(&spend.rk, &self.sighash, signature).is_ok())
            });
            let index = fits.next().ok_or(Error::InvalidExternalSignature)?;
            if fits.next().is_some() || placed.iter().any(|(i, _)| *i == index) {
                return Err(Error::DuplicateSignature);
            }
            placed.push((index, *signature));
        }
        for (index, signature) in placed {
            if let Ok((slot, spend)) = self.slot(index) {
                spend.spend_auth_sig = signature;
                *slot = None;
            }
        }
        Ok(())
    }

    /// The signed bundle. Fails with [`Error::MissingSignatures`] while a
    /// spend is not signed.
    pub fn finalize(self) -> Result<Bundle, Error> {
        if !self.is_complete() {
            return Err(Error::MissingSignatures);
        }
        Ok(self.bundle)
    }
}

#[cfg(test)]
mod tests;
