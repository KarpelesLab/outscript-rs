//! Sapling notes: note commitments, nullifiers and value commitments
//! (protocol specification §3.2, §4.1.2, §5.4.8.2 and §5.4.8.3; ZIP-212).

use super::field::Fr;
use super::jubjub::Point;
use super::keys::{PaymentAddress, expand_to_scalar};
use super::pedersen::{
    bits_le, bits_le_u64, homomorphic_pedersen_commit, mixing_pedersen_hash,
    windowed_pedersen_commit,
};
use super::prf::prf_nf;

/// The largest amount of zatoshis that can exist: 21 million ZEC.
pub const MAX_MONEY: i64 = 21_000_000 * 100_000_000;

/// The randomness of a note.
///
/// Since Canopy (ZIP-212) a note carries a 32-byte seed from which both its
/// commitment randomness `rcm` and the ephemeral key `esk` of its ciphertext
/// derive; before, it carried `rcm` itself.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Rseed {
    /// The commitment randomness `rcm`, of a note created before Canopy.
    BeforeZip212(Fr),
    /// The seed `rseed`.
    AfterZip212([u8; 32]),
}

impl core::fmt::Debug for Rseed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Rseed::BeforeZip212(_) => "Rseed::BeforeZip212(..)",
            Rseed::AfterZip212(_) => "Rseed::AfterZip212(..)",
        })
    }
}

impl Rseed {
    /// The commitment randomness: `rcm` itself, or
    /// `ToScalar(PRF^expand(rseed, [4]))`.
    pub fn rcm(&self) -> Fr {
        match self {
            Rseed::BeforeZip212(rcm) => *rcm,
            Rseed::AfterZip212(rseed) => expand_to_scalar(rseed, &[&[4]]),
        }
    }

    /// The ephemeral secret key `esk = ToScalar(PRF^expand(rseed, [5]))` the
    /// note must be encrypted with, or `None` for a note from before
    /// ZIP-212, whose `esk` was chosen at random.
    pub fn esk(&self) -> Option<Fr> {
        match self {
            Rseed::BeforeZip212(_) => None,
            Rseed::AfterZip212(rseed) => Some(expand_to_scalar(rseed, &[&[5]])),
        }
    }

    /// The lead byte of the note plaintext: 1 before ZIP-212, 2 after.
    pub const fn lead_byte(&self) -> u8 {
        match self {
            Rseed::BeforeZip212(_) => 0x01,
            Rseed::AfterZip212(_) => 0x02,
        }
    }
}

/// A Sapling note: a value sent to a payment address, with the randomness
/// that hides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Note {
    recipient: PaymentAddress,
    value: u64,
    rseed: Rseed,
}

impl Note {
    /// A note of `value` zatoshis for `recipient`.
    pub const fn new(recipient: PaymentAddress, value: u64, rseed: Rseed) -> Self {
        Note {
            recipient,
            value,
            rseed,
        }
    }

    /// The address the note is for.
    pub const fn recipient(&self) -> &PaymentAddress {
        &self.recipient
    }

    /// The value, in zatoshis.
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// The randomness.
    pub const fn rseed(&self) -> &Rseed {
        &self.rseed
    }

    /// The commitment randomness `rcm`.
    pub fn rcm(&self) -> Fr {
        self.rseed.rcm()
    }

    /// The note commitment `cm`, as a point.
    pub fn commitment(&self) -> Point {
        note_commitment(
            &self.recipient.g_d().to_bytes(),
            &self.recipient.pk_d().to_bytes(),
            self.value,
            &self.rcm(),
        )
    }

    /// The note commitment as it appears in an output and in the commitment
    /// tree: `cmu`, the `u` coordinate of `cm`.
    pub fn cmu(&self) -> [u8; 32] {
        extract_u(&self.commitment())
    }

    /// The nullifier of the note at `position` in the commitment tree, for
    /// the nullifier deriving key `nk` of its owner.
    pub fn nullifier(&self, nk: &Point, position: u64) -> [u8; 32] {
        nullifier(nk, &self.commitment(), position)
    }
}

/// `Extract_J(P)`: the `u` coordinate of a point, little-endian. Injective
/// on the prime-order subgroup.
pub fn extract_u(p: &Point) -> [u8; 32] {
    p.to_affine().u().to_bytes()
}

/// The bit sequence a note commitment hashes, after the six personalization
/// bits: the value as 64 bits, then the encodings of `g_d` and `pk_d`
/// (582 bits in total with the personalization). A Spend or Output circuit
/// consumes the same sequence.
pub fn note_commitment_bits<'a>(
    g_d: &'a [u8; 32],
    pk_d: &'a [u8; 32],
    value: u64,
) -> impl Iterator<Item = bool> + Clone + 'a {
    core::iter::repeat_n(true, 6)
        .chain(bits_le_u64(value, 64))
        .chain(bits_le(g_d))
        .chain(bits_le(pk_d))
}

/// `NoteCommit^Sapling_rcm(repr(g_d), repr(pk_d), v)`: a windowed Pedersen
/// commitment to [`note_commitment_bits`].
pub fn note_commitment(g_d: &[u8; 32], pk_d: &[u8; 32], value: u64, rcm: &Fr) -> Point {
    windowed_pedersen_commit(note_commitment_bits(g_d, pk_d, value), rcm)
}

/// The nullifier of the note with commitment `cm` at `position`:
/// `PRF^nfSapling(nk, MixingPedersenHash(cm, position))`.
pub fn nullifier(nk: &Point, cm: &Point, position: u64) -> [u8; 32] {
    let rho = mixing_pedersen_hash(cm, &Fr::from_u64(position));
    prf_nf(&nk.to_bytes(), &rho.to_bytes())
}

/// `ValueCommit_rcv(v) = [v] V + [rcv] R`: the commitment `cv` to the value
/// of a spent or created note.
pub fn value_commitment(value: u64, rcv: &Fr) -> Point {
    homomorphic_pedersen_commit(&Fr::from_u64(value), rcv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sapling::keys::{Diversifier, ExpandedSpendingKey};
    use crate::sapling::test_vectors::for_each_row;

    /// The note columns of `sapling_key_components.json`.
    #[test]
    fn note_commitments_and_nullifiers() {
        let json = include_str!("testdata/sapling_key_components.json");
        for_each_row(json, |_, row| {
            let fvk = ExpandedSpendingKey::from_spending_key(&row.array::<32>("sk"))
                .unwrap()
                .full_viewing_key();
            let address = fvk
                .to_payment_address(Diversifier(row.array("default_d")))
                .unwrap();
            let rcm = Fr::from_bytes(&row.array("note_r")).unwrap();
            let note = Note::new(address, row.u64("note_v"), Rseed::BeforeZip212(rcm));
            assert_eq!(note.rcm(), rcm);
            assert_eq!(note.cmu(), row.array::<32>("note_cmu"));
            assert_eq!(
                note.nullifier(fvk.nk(), row.u64("note_pos")),
                row.array::<32>("note_nf")
            );
            assert!(note.commitment().is_torsion_free());
        });
    }

    #[test]
    fn rseed_derivations() {
        let before = Rseed::BeforeZip212(Fr::from_u64(5));
        assert_eq!(before.esk(), None);
        assert_eq!(before.lead_byte(), 1);
        let after = Rseed::AfterZip212([7; 32]);
        assert_eq!(after.lead_byte(), 2);
        let esk = after.esk().unwrap();
        assert_ne!(esk, after.rcm());
        assert_ne!(after.rcm(), Rseed::AfterZip212([8; 32]).rcm());
        assert_eq!(format!("{after:?}"), "Rseed::AfterZip212(..)");
    }

    #[test]
    fn value_commitments_are_homomorphic() {
        let (r1, r2) = (Fr::from_u64(1234), Fr::from_u64(98765));
        assert_eq!(
            value_commitment(5, &r1) + value_commitment(7, &r2),
            value_commitment(12, &(r1 + r2))
        );
        assert_eq!(note_commitment_bits(&[0; 32], &[0; 32], 0).count(), 582);
    }
}
