//! Verifying many bundles together.

use alloc::vec::Vec;

use purecrypto::zeroize::Zeroize;

use super::{VerifyingKey, halo2, halo2_instances};
use crate::orchard::Fp;
use crate::orchard::bundle::BundleRef;
use crate::orchard::redpallas;

/// Verifies the proofs and the signatures of many bundles of one circuit
/// version together (the Orchard bundles of the transactions of a block,
/// say): the proofs share one final multi-scalar multiplication and the
/// signatures another, which is several times faster than verifying the
/// bundles one by one.
///
/// A batch accepts exactly when each of its bundles would be accepted by
/// [`BundleRef::verify_proof`] and [`BundleRef::verify_signatures`] (but
/// for a negligible chance over the randomness given to
/// [`BatchValidator::new`]). When it rejects, it does not tell which bundle
/// is at fault: verify them singly, or in smaller batches, to find out.
pub struct BatchValidator<'a> {
    vk: &'a VerifyingKey,
    proofs: halo2::BatchVerifier,
    signatures: redpallas::BatchVerifier,
    random: [u8; 64],
    bundles: usize,
    failed: bool,
}

impl core::fmt::Debug for BatchValidator<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BatchValidator")
            .field("version", &self.vk.version)
            .field("bundles", &self.bundles)
            .finish_non_exhaustive()
    }
}

impl Drop for BatchValidator<'_> {
    fn drop(&mut self) {
        self.random.zeroize();
    }
}

impl<'a> BatchValidator<'a> {
    /// An empty batch of bundles for the circuit version of `vk`. `random`
    /// must be 64 uniformly random bytes that whoever made the bundles
    /// could not predict: the bundles are combined with coefficients
    /// derived from them.
    pub fn new(vk: &'a VerifyingKey, random: &[u8; 64]) -> Self {
        BatchValidator {
            vk,
            proofs: halo2::BatchVerifier::new(random),
            signatures: redpallas::BatchVerifier::new(),
            random: *random,
            bundles: 0,
            failed: false,
        }
    }

    /// The number of bundles added.
    pub fn len(&self) -> usize {
        self.bundles
    }

    /// Whether no bundle was added.
    pub fn is_empty(&self) -> bool {
        self.bundles == 0
    }

    /// Adds a bundle, whose signatures are over `sighash` (the ZIP-244
    /// signature hash of its transaction for shielded inputs).
    pub fn add_bundle(&mut self, bundle: &BundleRef<'_>, sighash: &[u8; 32]) {
        self.bundles += 1;
        let version = self.vk.version;
        let instances = match bundle.instances(version) {
            Ok(instances) if bundle.proof_length_is_valid(version) => instances,
            _ => {
                self.failed = true;
                return;
            }
        };
        if bundle
            .queue_signatures(sighash, &mut self.signatures)
            .is_err()
        {
            self.failed = true;
            return;
        }
        let columns = halo2_instances(&instances);
        let columns: Vec<[&[Fp]; 1]> = columns.iter().map(|c| [&c[..]]).collect();
        let columns: Vec<&[&[Fp]]> = columns.iter().map(|c| &c[..]).collect();
        self.proofs
            .add_proof(&self.vk.params, &self.vk.vk, &columns, bundle.proof());
    }

    /// Whether every bundle added is valid: its proof for the circuit
    /// version of the key, its binding signature and its spend
    /// authorization signatures. An empty batch is valid.
    pub fn validate(mut self) -> bool {
        if self.failed {
            return false;
        }
        if self.bundles == 0 {
            return true;
        }
        let signatures = core::mem::take(&mut self.signatures);
        let proofs = core::mem::replace(&mut self.proofs, halo2::BatchVerifier::new(&[0; 64]));
        // The signatures first: they are much the cheaper to check.
        signatures.verify(&self.random).is_ok() && proofs.finalize(&self.vk.params)
    }
}

/// Verifies the proofs and the signatures of several bundles of the
/// circuit version of `vk` together, each given with the ZIP-244 signature
/// hash of its transaction: see [`BatchValidator`]. `random` must be 64
/// uniformly random bytes that whoever made the bundles could not predict.
pub fn verify_bundles(
    vk: &VerifyingKey,
    bundles: &[(BundleRef<'_>, [u8; 32])],
    random: &[u8; 64],
) -> bool {
    let mut batch = BatchValidator::new(vk, random);
    for (bundle, sighash) in bundles {
        batch.add_bundle(bundle, sighash);
    }
    batch.validate()
}
