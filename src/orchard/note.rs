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

/// The version of a note plaintext, which its lead byte states and which
/// decides how the note commitment randomness `rcm` derives from `rseed`.
///
/// The version goes with the value pool (ZIP 2005, protocol specification
/// section 3.2.1): every note of the Orchard pool is a [`V2`](Self::V2)
/// note, every note of the Ironwood pool (from NU6.3, in version 6
/// transactions) a [`V3`](Self::V3) note.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NoteVersion {
    /// The ZIP 212 format, lead byte `0x02`: the notes of the Orchard pool.
    /// `rcm = ToScalar(PRF^expand(rseed, [5] || rho))`.
    #[default]
    V2,
    /// The quantum-recoverable format of ZIP 2005, lead byte `0x03`: the
    /// notes of the Ironwood pool. `rcm` commits to every field of the
    /// note: `ToScalar(PRF^expand(rseed, [0x0B] || g_d || pk_d || v || rho
    /// || psi))`.
    V3,
}

impl NoteVersion {
    /// The lead byte of the note plaintexts of this version.
    pub const fn lead_byte(self) -> u8 {
        match self {
            NoteVersion::V2 => 0x02,
            NoteVersion::V3 => 0x03,
        }
    }

    /// The version a lead byte states, or `None` for an unknown one.
    pub const fn from_lead_byte(byte: u8) -> Option<Self> {
        match byte {
            0x02 => Some(NoteVersion::V2),
            0x03 => Some(NoteVersion::V3),
            _ => None,
        }
    }
}

/// `rcm` of a note, by version (`Derive_rcm^Orchard` of ZIP 2005).
fn derive_rcm(
    version: NoteVersion,
    rseed: &[u8; 32],
    recipient: &Address,
    value: u64,
    rho: &[u8; 32],
    psi: &Fp,
) -> Fq {
    match version {
        NoteVersion::V2 => prf_expand_scalar(rseed, &[&[0x05], rho]),
        NoteVersion::V3 => prf_expand_scalar(
            rseed,
            &[
                &[0x0b],
                &recipient.g_d().to_bytes(),
                &recipient.pk_d().to_bytes(),
                &value.to_le_bytes(),
                rho,
                &psi.to_bytes(),
            ],
        ),
    }
}

/// An Orchard note: a value held by an address, made unique by `rho` (the
/// nullifier of the note spent in the action that created this one) and by
/// the random seed `rseed`, from which `psi`, `rcm` and the ephemeral key
/// `esk` are derived (ZIP-212; ZIP 2005 for the notes of the Ironwood
/// pool, see [`NoteVersion`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    recipient: Address,
    value: u64,
    rho: Nullifier,
    rseed: [u8; 32],
    version: NoteVersion,
    /// The note commitment, computed once.
    cm: Affine,
}

impl Note {
    /// Builds a note of the Orchard pool ([`NoteVersion::V2`]), or fails
    /// for the (negligibly rare) `rseed` the protocol does not allow with
    /// this `rho`: one whose `esk` is zero or whose note commitment is
    /// undefined.
    pub fn from_parts(
        recipient: Address,
        value: u64,
        rho: Nullifier,
        rseed: [u8; 32],
    ) -> Result<Self, Error> {
        Self::from_parts_versioned(recipient, value, rho, rseed, NoteVersion::V2)
    }

    /// Builds a note of the given version ([`NoteVersion::V3`] for the
    /// Ironwood pool), as [`from_parts`](Self::from_parts).
    pub fn from_parts_versioned(
        recipient: Address,
        value: u64,
        rho: Nullifier,
        rseed: [u8; 32],
        version: NoteVersion,
    ) -> Result<Self, Error> {
        let rho_bytes = rho.to_bytes();
        let mut esk = prf_expand_scalar(&rseed, &[&[0x04], &rho_bytes]);
        let esk_is_zero = bool::from(esk.is_zero());
        esk.zeroize();
        if esk_is_zero {
            return Err(Error::InvalidNote);
        }
        let psi = prf_expand_base(&rseed, &[&[0x09], &rho_bytes]);
        let mut rcm = derive_rcm(version, &rseed, &recipient, value, &rho_bytes, &psi);
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
            version,
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

    /// The version of the note plaintext: [`NoteVersion::V2`] for a note
    /// of the Orchard pool, [`NoteVersion::V3`] for one of the Ironwood
    /// pool.
    pub fn version(&self) -> NoteVersion {
        self.version
    }

    /// The note commitment randomness: for a note of the Orchard pool,
    /// `rcm = ToScalar(PRF^expand(rseed, [5] || rho))`; for one of the
    /// Ironwood pool, see [`NoteVersion::V3`].
    pub fn rcm(&self) -> Fq {
        derive_rcm(
            self.version,
            &self.rseed,
            &self.recipient,
            self.value,
            &self.rho.to_bytes(),
            &self.psi(),
        )
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
