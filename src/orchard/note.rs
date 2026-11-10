//! Orchard notes, their commitments and their nullifiers.

use purecrypto::zeroize::Zeroize;

use super::Error;
use super::constants::NULLIFIER_K;
use super::fields::{Fp, Fq};
use super::keys::{Address, FullViewingKey};
use super::pallas::Affine;
use super::poseidon;
use super::sinsemilla::{CommitDomain, le_bits};
use super::spec::{prf_expand_base, prf_expand_scalar};

/// A nullifier: the value a note reveals when spent, and the `rho` of the
/// note the same action creates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nullifier(Fp);

impl Nullifier {
    /// The nullifier for a field element.
    pub fn from_fp(v: Fp) -> Self {
        Nullifier(v)
    }

    /// The nullifier as a field element.
    pub fn to_fp(&self) -> Fp {
        self.0
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Decodes the canonical 32-byte encoding of a field element.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Fp::from_bytes(bytes).map(Nullifier)
    }
}

/// An extracted note commitment `cmx`: the x coordinate of a note
/// commitment, which is what an action publishes and what the note
/// commitment tree holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtractedNoteCommitment(Fp);

impl ExtractedNoteCommitment {
    /// The commitment for a field element.
    pub fn from_fp(v: Fp) -> Self {
        ExtractedNoteCommitment(v)
    }

    /// The commitment as a field element.
    pub fn to_fp(&self) -> Fp {
        self.0
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Decodes the canonical 32-byte encoding of a field element.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Fp::from_bytes(bytes).map(ExtractedNoteCommitment)
    }
}

/// An Orchard note: a value held by an address, made unique by `rho` (the
/// nullifier of the note spent in the action that created this one) and by
/// the random seed `rseed`, from which `psi`, `rcm` and the ephemeral key
/// `esk` are derived (ZIP-212).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    recipient: Address,
    value: u64,
    rho: Nullifier,
    rseed: [u8; 32],
    /// The note commitment, computed once.
    cm: Affine,
}

impl Note {
    /// Builds a note, or fails for the (negligibly rare) `rseed` the
    /// protocol does not allow with this `rho`: one whose `esk` is zero or
    /// whose note commitment is undefined.
    pub fn from_parts(
        recipient: Address,
        value: u64,
        rho: Nullifier,
        rseed: [u8; 32],
    ) -> Result<Self, Error> {
        let rho_bytes = rho.to_bytes();
        let mut esk = prf_expand_scalar(&rseed, &[&[0x04], &rho_bytes]);
        let esk_is_zero = bool::from(esk.is_zero());
        esk.zeroize();
        if esk_is_zero {
            return Err(Error::InvalidNote);
        }
        let psi = prf_expand_base(&rseed, &[&[0x09], &rho_bytes]);
        let mut rcm = prf_expand_scalar(&rseed, &[&[0x05], &rho_bytes]);
        let g_d = recipient.g_d().to_bytes();
        let pk_d = recipient.pk_d().to_bytes();
        let psi_bytes = psi.to_bytes();
        let cm = CommitDomain::NOTE_COMMIT.commit(
            le_bits(&g_d, 256)
                .chain(le_bits(&pk_d, 256))
                .chain(le_bits(&value.to_le_bytes(), 64))
                .chain(le_bits(&rho_bytes, 255))
                .chain(le_bits(&psi_bytes, 255)),
            &rcm,
        );
        rcm.zeroize();
        Ok(Note {
            recipient,
            value,
            rho,
            rseed,
            cm: cm.ok_or(Error::InvalidNote)?.to_affine(),
        })
    }

    /// The address holding the note.
    pub fn recipient(&self) -> Address {
        self.recipient
    }

    /// The value, in zatoshi.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// `rho`.
    pub fn rho(&self) -> Nullifier {
        self.rho
    }

    /// The random seed.
    pub fn rseed(&self) -> &[u8; 32] {
        &self.rseed
    }

    /// The ephemeral secret key
    /// `esk = ToScalar(PRF^expand(rseed, [4] || rho))` (never zero).
    pub fn esk(&self) -> Fq {
        prf_expand_scalar(&self.rseed, &[&[0x04], &self.rho.to_bytes()])
    }

    /// The note commitment randomness
    /// `rcm = ToScalar(PRF^expand(rseed, [5] || rho))`.
    pub fn rcm(&self) -> Fq {
        prf_expand_scalar(&self.rseed, &[&[0x05], &self.rho.to_bytes()])
    }

    /// `psi = ToBase(PRF^expand(rseed, [9] || rho))`.
    pub fn psi(&self) -> Fp {
        prf_expand_base(&self.rseed, &[&[0x09], &self.rho.to_bytes()])
    }

    /// The note commitment `cm`, a point.
    pub fn commitment(&self) -> Affine {
        self.cm
    }

    /// The extracted note commitment `cmx`.
    pub fn cmx(&self) -> ExtractedNoteCommitment {
        ExtractedNoteCommitment(self.cm.x())
    }

    /// The nullifier of the note:
    /// `Extract([(Poseidon(nk, rho) + psi) mod p] K + cm)`.
    pub fn nullifier(&self, fvk: &FullViewingKey) -> Nullifier {
        let scalar = poseidon::hash(fvk.nk(), self.rho.0) + self.psi();
        let point = NULLIFIER_K
            .to_point()
            .mul(&Fq::from_fp(&scalar))
            .add_affine(&self.cm);
        Nullifier(point.to_affine().x())
    }
}
