//! Sapling Spend and Output proofs: the proving parameters, the embedded
//! verifying keys, and typed proving and verification (feature
//! `zcash-sapling-prover`).
//!
//! # Parameters
//!
//! Creating proofs needs the Sapling proving parameters, the output of the
//! Sapling MPC: `sapling-spend.params` (about 48 MB) and
//! `sapling-output.params` (about 3.5 MB), as published at
//! `https://download.z.cash/downloads/` and installed by `zcashd`'s
//! `fetch-params` in `~/.zcash-params`. They are not part of this crate:
//! the caller supplies their bytes to [`SpendParameters::read`] and
//! [`OutputParameters::read`], which check them against their well-known
//! BLAKE2b-512 hashes ([`SPEND_PARAMS_HASH`], [`OUTPUT_PARAMS_HASH`])
//! before use.
//!
//! Verifying needs no file: the two verifying keys are embedded
//! ([`SpendVerifyingKey::mainnet`], [`OutputVerifyingKey::mainnet`]). They
//! are the same on every Zcash network.
//!
//! [`verify_bundle`] checks a whole bundle: encodings, signatures and
//! proofs, the last two in batches. [`SpendVerifyingKey::queue`],
//! [`OutputVerifyingKey::queue`] and [`queue_bundle_proofs`] put proofs of
//! any number of transactions in one [`BatchVerifier`].
//!
//! # Randomness
//!
//! A proof takes 128 bytes of randomness from the caller, which blind it:
//! they must come from a cryptographically secure generator and never be
//! reused for another proof. Batched verification takes 16 random bytes
//! per proof or signature, which must be unpredictable to whoever made
//! them.

#[cfg(feature = "std")]
use crate::prelude::*;
use crate::sapling::Error as SaplingError;
use crate::sapling::bundle::BundleRef;
use crate::sapling::circuit::{Output, Spend, multipack};
use crate::sapling::field::Fq;
use crate::sapling::groth16::{
    BATCH_RANDOM_SIZE, BatchVerifier, Error, PROOF_SIZE, Parameters, PreparedVerifyingKey, Proof,
    SynthesisError, VerifyingKey, create_proof, verify_proof,
};
use crate::sapling::jubjub::AffinePoint;
use purecrypto::hash::Blake2bMac;

/// The BLAKE2b-512 hash of `sapling-spend.params`.
pub const SPEND_PARAMS_HASH: [u8; 64] = hex64(
    b"8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63\
      991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c",
);

/// The BLAKE2b-512 hash of `sapling-output.params`.
pub const OUTPUT_PARAMS_HASH: [u8; 64] = hex64(
    b"657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60b\
      f593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028",
);

/// The size of `sapling-spend.params`, in bytes.
pub const SPEND_PARAMS_LEN: usize = 47_958_396;
/// The size of `sapling-output.params`, in bytes.
pub const OUTPUT_PARAMS_LEN: usize = 3_592_860;

/// The file name of the Spend parameters.
pub const SPEND_PARAMS_NAME: &str = "sapling-spend.params";
/// The file name of the Output parameters.
pub const OUTPUT_PARAMS_NAME: &str = "sapling-output.params";

/// The number of random bytes a proof consumes.
pub const PROOF_RANDOM_SIZE: usize = 128;

/// The verifying key of the Spend circuit, in `bellman`'s encoding: the
/// first bytes of `sapling-spend.params`.
const SPEND_VK: &[u8] = include_bytes!("vk/sapling-spend.vk");
/// The verifying key of the Output circuit: the first bytes of
/// `sapling-output.params`.
const OUTPUT_VK: &[u8] = include_bytes!("vk/sapling-output.vk");

/// Decodes 128 hexadecimal digits, skipping spaces.
const fn hex64(s: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut n = 0;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        i += 1;
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b' ' => continue,
            _ => panic!("invalid hex digit"),
        };
        if n % 2 == 0 {
            out[n / 2] = digit << 4;
        } else {
            out[n / 2] |= digit;
        }
        n += 1;
    }
    assert!(n == 128);
    out
}

/// BLAKE2b-512 of `data`.
fn blake2b_512(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    // the parameters are always valid
    if let Ok(mut h) = Blake2bMac::try_new_with_salt_personal(&[], 64, &[], &[]) {
        h.update(data);
        h.finalize_into(&mut out);
    }
    out
}

/// Parses parameters after checking their length and hash.
fn read_hashed(data: &[u8], len: usize, hash: &[u8; 64]) -> Result<Parameters, Error> {
    if data.len() != len || blake2b_512(data) != *hash {
        return Err(Error::HashMismatch);
    }
    // the hash vouches for the points being in their groups
    Parameters::read(data, false)
}

#[cfg(feature = "std")]
fn read_file(path: &std::path::Path) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|_| Error::Io)
}

/// The two random scalars of a proof.
fn blinding(random: &[u8; PROOF_RANDOM_SIZE]) -> (Fq, Fq) {
    let mut r = [0u8; 64];
    let mut s = [0u8; 64];
    r.copy_from_slice(&random[..64]);
    s.copy_from_slice(&random[64..]);
    let scalars = (Fq::from_bytes_wide(&r), Fq::from_bytes_wide(&s));
    purecrypto::zeroize::Zeroize::zeroize(&mut r);
    purecrypto::zeroize::Zeroize::zeroize(&mut s);
    scalars
}

/// A point that must be on the curve and not of small order.
fn point_input(bytes: &[u8; 32]) -> Result<AffinePoint, Error> {
    let p = AffinePoint::from_bytes(bytes).ok_or(Error::InvalidPublicInput)?;
    if p.to_point().is_small_order() {
        return Err(Error::InvalidPublicInput);
    }
    Ok(p)
}

/// A canonically encoded field element.
fn field_input(bytes: &[u8; 32]) -> Result<Fq, Error> {
    Fq::from_bytes(bytes).ok_or(Error::InvalidPublicInput)
}

/// The public inputs of a Spend statement, in the circuit's order: `rk`,
/// `cv`, the anchor, and the nullifier packed into two field elements.
///
/// Fails with [`Error::InvalidPublicInput`] unless `rk` and `cv` are
/// canonical encodings of points that are not of small order, and the
/// anchor a canonical field element, as consensus requires.
pub fn spend_public_inputs(
    cv: &[u8; 32],
    anchor: &[u8; 32],
    nullifier: &[u8; 32],
    rk: &[u8; 32],
) -> Result<[Fq; 7], Error> {
    let rk = point_input(rk)?;
    let cv = point_input(cv)?;
    let anchor = field_input(anchor)?;
    let mut nf = multipack(nullifier);
    Ok([
        rk.u(),
        rk.v(),
        cv.u(),
        cv.v(),
        anchor,
        nf.next().unwrap_or(Fq::ZERO),
        nf.next().unwrap_or(Fq::ZERO),
    ])
}

/// The public inputs of an Output statement, in the circuit's order: `cv`,
/// `epk` and the note commitment.
///
/// Fails with [`Error::InvalidPublicInput`] unless `cv` and the ephemeral
/// key are canonical encodings of points that are not of small order, and
/// `cmu` a canonical field element, as consensus requires.
pub fn output_public_inputs(
    cv: &[u8; 32],
    cmu: &[u8; 32],
    ephemeral_key: &[u8; 32],
) -> Result<[Fq; 5], Error> {
    let cv = point_input(cv)?;
    let epk = point_input(ephemeral_key)?;
    let cmu = field_input(cmu)?;
    Ok([cv.u(), cv.v(), epk.u(), epk.v(), cmu])
}

/// The proving parameters of the Spend circuit.
#[derive(Debug)]
pub struct SpendParameters(Parameters);

impl SpendParameters {
    /// Parses the contents of `sapling-spend.params`, after checking that
    /// their BLAKE2b-512 hash is [`SPEND_PARAMS_HASH`].
    ///
    /// Hashing and decoding take a few hundred milliseconds; the result
    /// occupies about as much memory as the file.
    pub fn read(data: &[u8]) -> Result<Self, Error> {
        read_hashed(data, SPEND_PARAMS_LEN, &SPEND_PARAMS_HASH).map(Self)
    }

    /// Parses Spend parameters in `bellman`'s format without checking any
    /// hash: for parameters other than Zcash's, such as ones generated for
    /// tests. With `checked`, every point is verified to be in its group
    /// (slow); without, the parameters must be trusted. See
    /// [`Parameters::read`].
    pub fn read_unverified(data: &[u8], checked: bool) -> Result<Self, Error> {
        Parameters::read(data, checked).map(Self)
    }

    /// Reads and parses `sapling-spend.params` from the directory `dir`,
    /// checking its hash.
    #[cfg(feature = "std")]
    pub fn load(dir: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        Self::read(&read_file(&dir.as_ref().join(SPEND_PARAMS_NAME))?)
    }

    /// The Groth16 parameters.
    pub fn parameters(&self) -> &Parameters {
        &self.0
    }

    /// The verifying key these parameters contain.
    pub fn verifying_key(&self) -> SpendVerifyingKey {
        SpendVerifyingKey(self.0.vk.prepare())
    }

    /// Creates a Spend proof for the witness `circuit`, blinded with
    /// `random`, which must be fresh output of a cryptographically secure
    /// generator.
    ///
    /// The proof is not verified: a witness that is not consistent with
    /// the public inputs gives a proof that is not valid.
    pub fn prove(
        &self,
        circuit: &Spend,
        random: &[u8; PROOF_RANDOM_SIZE],
    ) -> Result<[u8; PROOF_SIZE], SynthesisError> {
        let (r, s) = blinding(random);
        Ok(create_proof(circuit, &self.0, &r, &s)?.to_bytes())
    }
}

/// The proving parameters of the Output circuit.
#[derive(Debug)]
pub struct OutputParameters(Parameters);

impl OutputParameters {
    /// Parses the contents of `sapling-output.params`, after checking that
    /// their BLAKE2b-512 hash is [`OUTPUT_PARAMS_HASH`].
    pub fn read(data: &[u8]) -> Result<Self, Error> {
        read_hashed(data, OUTPUT_PARAMS_LEN, &OUTPUT_PARAMS_HASH).map(Self)
    }

    /// Parses Output parameters in `bellman`'s format without checking any
    /// hash: see [`SpendParameters::read_unverified`].
    pub fn read_unverified(data: &[u8], checked: bool) -> Result<Self, Error> {
        Parameters::read(data, checked).map(Self)
    }

    /// Reads and parses `sapling-output.params` from the directory `dir`,
    /// checking its hash.
    #[cfg(feature = "std")]
    pub fn load(dir: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        Self::read(&read_file(&dir.as_ref().join(OUTPUT_PARAMS_NAME))?)
    }

    /// The Groth16 parameters.
    pub fn parameters(&self) -> &Parameters {
        &self.0
    }

    /// The verifying key these parameters contain.
    pub fn verifying_key(&self) -> OutputVerifyingKey {
        OutputVerifyingKey(self.0.vk.prepare())
    }

    /// Creates an Output proof for the witness `circuit`, blinded with
    /// `random`, which must be fresh output of a cryptographically secure
    /// generator.
    pub fn prove(
        &self,
        circuit: &Output,
        random: &[u8; PROOF_RANDOM_SIZE],
    ) -> Result<[u8; PROOF_SIZE], SynthesisError> {
        let (r, s) = blinding(random);
        Ok(create_proof(circuit, &self.0, &r, &s)?.to_bytes())
    }
}

/// The verifying key of the Spend circuit, prepared for verification.
#[derive(Clone, Debug)]
pub struct SpendVerifyingKey(PreparedVerifyingKey);

impl SpendVerifyingKey {
    /// The key of the Zcash networks, embedded in the crate. Preparing it
    /// costs one pairing: keep the result around when verifying many
    /// proofs.
    pub fn mainnet() -> Self {
        Self::from_verifying_key(&embedded(SPEND_VK))
    }

    /// Wraps a Groth16 verifying key for a Spend circuit.
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        SpendVerifyingKey(vk.prepare())
    }

    /// Verifies the proof of a Spend description. Also fails unless `cv`
    /// and `rk` are points that are not of small order and the anchor a
    /// canonical field element.
    pub fn verify(
        &self,
        cv: &[u8; 32],
        anchor: &[u8; 32],
        nullifier: &[u8; 32],
        rk: &[u8; 32],
        zkproof: &[u8; PROOF_SIZE],
    ) -> Result<(), Error> {
        let inputs = spend_public_inputs(cv, anchor, nullifier, rk)?;
        verify_proof(&self.0, &Proof::from_bytes(zkproof)?, &inputs)
    }
}

/// The verifying key of the Output circuit, prepared for verification.
#[derive(Clone, Debug)]
pub struct OutputVerifyingKey(PreparedVerifyingKey);

impl OutputVerifyingKey {
    /// The key of the Zcash networks, embedded in the crate. Preparing it
    /// costs one pairing: keep the result around when verifying many
    /// proofs.
    pub fn mainnet() -> Self {
        Self::from_verifying_key(&embedded(OUTPUT_VK))
    }

    /// Wraps a Groth16 verifying key for an Output circuit.
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        OutputVerifyingKey(vk.prepare())
    }

    /// Verifies the proof of an Output description. Also fails unless
    /// `cv` and the ephemeral key are points that are not of small order
    /// and `cmu` a canonical field element.
    pub fn verify(
        &self,
        cv: &[u8; 32],
        cmu: &[u8; 32],
        ephemeral_key: &[u8; 32],
        zkproof: &[u8; PROOF_SIZE],
    ) -> Result<(), Error> {
        let inputs = output_public_inputs(cv, cmu, ephemeral_key)?;
        verify_proof(&self.0, &Proof::from_bytes(zkproof)?, &inputs)
    }
}

impl SpendVerifyingKey {
    /// Adds the proof of a Spend description to a batch instead of
    /// verifying it: see [`BatchVerifier`]. Fails right away, as
    /// [`verify`](Self::verify) does, on public inputs consensus forbids
    /// and on a proof that does not decode.
    #[allow(clippy::too_many_arguments)]
    pub fn queue<'a>(
        &'a self,
        batch: &mut BatchVerifier<'a>,
        cv: &[u8; 32],
        anchor: &[u8; 32],
        nullifier: &[u8; 32],
        rk: &[u8; 32],
        zkproof: &[u8; PROOF_SIZE],
        random: &[u8; BATCH_RANDOM_SIZE],
    ) -> Result<(), Error> {
        let inputs = spend_public_inputs(cv, anchor, nullifier, rk)?;
        batch.queue(&self.0, &Proof::from_bytes(zkproof)?, &inputs, random)
    }
}

impl OutputVerifyingKey {
    /// Adds the proof of an Output description to a batch instead of
    /// verifying it: see [`BatchVerifier`]. Fails right away, as
    /// [`verify`](Self::verify) does, on public inputs consensus forbids
    /// and on a proof that does not decode.
    pub fn queue<'a>(
        &'a self,
        batch: &mut BatchVerifier<'a>,
        cv: &[u8; 32],
        cmu: &[u8; 32],
        ephemeral_key: &[u8; 32],
        zkproof: &[u8; PROOF_SIZE],
        random: &[u8; BATCH_RANDOM_SIZE],
    ) -> Result<(), Error> {
        let inputs = output_public_inputs(cv, cmu, ephemeral_key)?;
        batch.queue(&self.0, &Proof::from_bytes(zkproof)?, &inputs, random)
    }
}

/// Decodes an embedded verifying key, which is known to be valid.
fn embedded(bytes: &[u8]) -> VerifyingKey {
    match VerifyingKey::read(bytes) {
        Ok(vk) => vk,
        // unreachable: the embedded keys are checked by the tests
        Err(_) => unreachable!("embedded verifying key is valid"),
    }
}

/// Verifies every Spend and Output proof of a Sapling bundle. The
/// signatures are checked by
/// [`BundleRef::verify`](crate::sapling::bundle::BundleRef::verify).
pub fn verify_bundle_proofs(
    bundle: &BundleRef<'_>,
    spend_vk: &SpendVerifyingKey,
    output_vk: &OutputVerifyingKey,
) -> Result<(), Error> {
    if let Some(anchor) = bundle.anchor() {
        for spend in bundle.spends() {
            spend_vk.verify(spend.cv, anchor, spend.nullifier, spend.rk, spend.zkproof)?;
        }
    }
    for output in bundle.outputs() {
        output_vk.verify(output.cv, output.cmu, output.ephemeral_key, output.zkproof)?;
    }
    Ok(())
}

/// Adds every Spend and Output proof of a Sapling bundle to a batch, to
/// verify the proofs of many bundles together. `random` must hold
/// [`BATCH_RANDOM_SIZE`] fresh random bytes per proof
/// ([`Error::RandomLength`] otherwise): see [`BatchVerifier`]. On error the
/// batch may hold part of the bundle's proofs and must be discarded.
pub fn queue_bundle_proofs<'a>(
    bundle: &BundleRef<'_>,
    spend_vk: &'a SpendVerifyingKey,
    output_vk: &'a OutputVerifyingKey,
    batch: &mut BatchVerifier<'a>,
    random: &[u8],
) -> Result<(), Error> {
    let (random, rest) = random.as_chunks::<BATCH_RANDOM_SIZE>();
    if !rest.is_empty() || random.len() != bundle.n_spends() + bundle.n_outputs() {
        return Err(Error::RandomLength);
    }
    let mut random = random.iter();
    if let Some(anchor) = bundle.anchor() {
        for (spend, r) in bundle.spends().zip(&mut random) {
            let (cv, nf, rk) = (spend.cv, spend.nullifier, spend.rk);
            spend_vk.queue(batch, cv, anchor, nf, rk, spend.zkproof, r)?;
        }
    }
    for (output, r) in bundle.outputs().zip(&mut random) {
        let (cv, cmu, epk) = (output.cv, output.cmu, output.ephemeral_key);
        output_vk.queue(batch, cv, cmu, epk, output.zkproof, r)?;
    }
    Ok(())
}

/// [`verify_bundle_proofs`] with the proofs verified as one batch, which is
/// faster as soon as there are two. `random` is as for
/// [`queue_bundle_proofs`].
pub fn verify_bundle_proofs_batch(
    bundle: &BundleRef<'_>,
    spend_vk: &SpendVerifyingKey,
    output_vk: &OutputVerifyingKey,
    random: &[u8],
) -> Result<(), Error> {
    let mut batch = BatchVerifier::new();
    queue_bundle_proofs(bundle, spend_vk, output_vk, &mut batch, random)?;
    batch.verify()
}

/// Why a bundle is not valid: see [`verify_bundle`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BundleError {
    /// An encoding or a signature is invalid: see the inner error.
    Sapling(SaplingError),
    /// A proof is invalid: see the inner error.
    Proof(Error),
    /// The random bytes supplied have the wrong length.
    RandomLength,
}

impl core::fmt::Display for BundleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BundleError::Sapling(e) => write!(f, "{e}"),
            BundleError::Proof(e) => write!(f, "{e}"),
            BundleError::RandomLength => f.write_str("wrong amount of randomness"),
        }
    }
}

impl core::error::Error for BundleError {}

/// The number of random bytes [`verify_bundle`] needs for a bundle:
/// [`BATCH_RANDOM_SIZE`] for each signature and each proof.
pub fn verify_bundle_random_len(bundle: &BundleRef<'_>) -> usize {
    BATCH_RANDOM_SIZE * (bundle.n_signatures() + bundle.n_spends() + bundle.n_outputs())
}

/// Checks everything a validator checks of a parsed Sapling bundle without
/// the chain state, given the transaction's signature hash (see
/// [`ZcashTx::sighash`](crate::zcashtx::ZcashTx::sighash) with no input
/// index): the encodings, the spend authorization signatures, the binding
/// signature (so the values balance), and the Spend and Output proofs.
/// What is left to the caller is the chain: the anchor must be a root of
/// the note commitment tree, and the nullifiers unspent.
///
/// The signatures are verified as one batch and the proofs as another,
/// with [`verify_bundle_random_len`] random bytes from the caller, which
/// must be fresh output of a cryptographically secure generator: see
/// [`BatchVerifier`]. An invalid bundle is accepted with probability 2⁻¹²⁸
/// at most; an error does not say which signature or proof is at fault
/// ([`BundleRef::verify`] and [`verify_bundle_proofs`] do).
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use outscript::sapling::bundle::BundleRef;
/// use outscript::sapling::prover::{
///     OutputVerifyingKey, SpendVerifyingKey, verify_bundle, verify_bundle_random_len,
/// };
/// use outscript::zcashtx::{SIGHASH_ALL, ZcashTx};
/// # let raw: Vec<u8> = todo!();
/// # let random: Vec<u8> = todo!();
///
/// let tx = ZcashTx::parse_into(&raw, &mut [], &mut [])?;
/// let sighash = tx.sighash(None, SIGHASH_ALL, &[])?;
/// let bundle = BundleRef::parse(tx.sapling)?;
/// // random: verify_bundle_random_len(&bundle) fresh random bytes
/// assert_eq!(random.len(), verify_bundle_random_len(&bundle));
/// let (spend_vk, output_vk) = (SpendVerifyingKey::mainnet(), OutputVerifyingKey::mainnet());
/// verify_bundle(&bundle, &sighash, &spend_vk, &output_vk, &random)?;
/// # Ok(()) }
/// ```
pub fn verify_bundle(
    bundle: &BundleRef<'_>,
    sighash: &[u8; 32],
    spend_vk: &SpendVerifyingKey,
    output_vk: &OutputVerifyingKey,
    random: &[u8],
) -> Result<(), BundleError> {
    let (for_signatures, for_proofs) = random
        .split_at_checked(BATCH_RANDOM_SIZE * bundle.n_signatures())
        .ok_or(BundleError::RandomLength)?;
    if for_proofs.len() != BATCH_RANDOM_SIZE * (bundle.n_spends() + bundle.n_outputs()) {
        return Err(BundleError::RandomLength);
    }
    bundle
        .verify_batched(sighash, for_signatures)
        .map_err(BundleError::Sapling)?;
    verify_bundle_proofs_batch(bundle, spend_vk, output_vk, for_proofs).map_err(BundleError::Proof)
}

#[cfg(test)]
pub(crate) mod tests;
