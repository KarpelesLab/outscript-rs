//! In-band secret distribution: the encryption of notes to their recipient
//! and to the sender's outgoing viewing key (protocol specification §4.19
//! and §5.4.3–§5.4.5, ZIP-212, ZIP-307 for compact outputs).
//!
//! An output carries an ephemeral key `epk = [esk] g_d`, the note ciphertext
//! (580 bytes: the 564-byte note plaintext and a tag, under a key agreed
//! between `esk` and `pk_d`) and the outgoing ciphertext (80 bytes: `pk_d`
//! and `esk` and a tag, under a key derived from `ovk`).
//!
//! Nothing here allocates: scanning a block is a loop of
//! [`try_compact_note_decryption`] over its outputs.

use super::field::Fr;
use super::jubjub::Point;
use super::keys::{Diversifier, IncomingViewingKey, OutgoingViewingKey, PaymentAddress};
use super::note::{Note, Rseed};
use super::prf::{kdf_sapling, prf_ock};
use purecrypto::cipher::{ChaCha20, ChaCha20Poly1305};
use purecrypto::ct::ConstantTimeEq;
use purecrypto::zeroize::{Zeroize, Zeroizing};

/// The size of a memo.
pub const MEMO_SIZE: usize = 512;
/// The size of a note plaintext: lead byte, diversifier, value, `rseed` and
/// memo.
pub const NOTE_PLAINTEXT_SIZE: usize = 1 + 11 + 8 + 32 + MEMO_SIZE;
/// The size of the part of a note plaintext, or ciphertext, before the
/// memo: what a compact output carries.
pub const COMPACT_NOTE_SIZE: usize = 1 + 11 + 8 + 32;
/// The size of a note ciphertext `C^enc`.
pub const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + 16;
/// The size of an outgoing plaintext: `pk_d` and `esk`.
pub const OUT_PLAINTEXT_SIZE: usize = 64;
/// The size of an outgoing ciphertext `C^out`.
pub const OUT_CIPHERTEXT_SIZE: usize = OUT_PLAINTEXT_SIZE + 16;

/// The memo that says "no memo": `0xf6` followed by zeros (ZIP-302).
pub const EMPTY_MEMO: [u8; MEMO_SIZE] = {
    let mut memo = [0u8; MEMO_SIZE];
    memo[0] = 0xf6;
    memo
};

/// Which note plaintext lead bytes are acceptable, depending on the height
/// of the transaction relative to the Canopy activation (ZIP-212).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zip212Enforcement {
    /// Before Canopy: only the original format (lead byte 1).
    Off,
    /// The 32256 blocks after the Canopy activation: both formats.
    GracePeriod,
    /// Since then: only the ZIP-212 format (lead byte 2).
    On,
}

impl Zip212Enforcement {
    /// Whether a plaintext with this lead byte is acceptable.
    pub const fn accepts(self, lead_byte: u8) -> bool {
        match self {
            Zip212Enforcement::Off => lead_byte == 0x01,
            Zip212Enforcement::GracePeriod => lead_byte == 0x01 || lead_byte == 0x02,
            Zip212Enforcement::On => lead_byte == 0x02,
        }
    }
}

const NONCE: [u8; 12] = [0; 12];

/// `KA.DerivePublic(esk, g_d) = [esk] g_d`: the ephemeral public key of an
/// output for a recipient with diversified base `g_d`.
pub fn ka_derive_public(esk: &Fr, g_d: &Point) -> Point {
    g_d.mul(esk)
}

/// `KA.Agree(sk, P) = [8·sk] P`: the shared secret, from either side
/// (`esk` and `pk_d`, or `ivk` and `epk`).
pub fn ka_agree(sk: &Fr, p: &Point) -> Point {
    p.mul(sk).mul_by_cofactor()
}

/// The symmetric key of the note ciphertext for a shared secret.
fn note_key(shared_secret: &Point, ephemeral_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut secret = shared_secret.to_bytes();
    let key = Zeroizing::new(kdf_sapling(&secret, ephemeral_key));
    secret.zeroize();
    key
}

/// The note plaintext: lead byte, diversifier, value, `rseed` (or `rcm`)
/// and memo.
pub fn note_plaintext(note: &Note, memo: &[u8; MEMO_SIZE]) -> [u8; NOTE_PLAINTEXT_SIZE] {
    let mut pt = [0u8; NOTE_PLAINTEXT_SIZE];
    pt[0] = note.rseed().lead_byte();
    pt[1..12].copy_from_slice(&note.recipient().diversifier().0);
    pt[12..20].copy_from_slice(&note.value().to_le_bytes());
    match note.rseed() {
        Rseed::BeforeZip212(rcm) => pt[20..52].copy_from_slice(&rcm.to_bytes()),
        Rseed::AfterZip212(rseed) => pt[20..52].copy_from_slice(rseed),
    }
    pt[52..].copy_from_slice(memo);
    pt
}

/// Encrypts a note and its memo to its recipient with the ephemeral secret
/// key `esk`, returning the ephemeral key `epk` and the note ciphertext.
///
/// `esk` must be [`Rseed::esk`] for a ZIP-212 note (see
/// [`encrypt_note`]); recipients reject anything else.
pub fn encrypt_note_with_esk(
    note: &Note,
    memo: &[u8; MEMO_SIZE],
    esk: &Fr,
) -> ([u8; 32], [u8; ENC_CIPHERTEXT_SIZE]) {
    let recipient = note.recipient();
    let ephemeral_key = ka_derive_public(esk, recipient.g_d()).to_bytes();
    let key = note_key(&ka_agree(esk, recipient.pk_d()), &ephemeral_key);
    let mut out = [0u8; ENC_CIPHERTEXT_SIZE];
    let mut pt = note_plaintext(note, memo);
    let (body, tag) = out.split_at_mut(NOTE_PLAINTEXT_SIZE);
    body.copy_from_slice(&pt);
    pt.zeroize();
    tag.copy_from_slice(&ChaCha20Poly1305::new(&key).encrypt(&NONCE, &[], body));
    (ephemeral_key, out)
}

/// Encrypts a ZIP-212 note and its memo to its recipient, returning the
/// ephemeral key `epk` and the note ciphertext. `None` for a note from
/// before ZIP-212, which has no derived `esk`: see
/// [`encrypt_note_with_esk`].
pub fn encrypt_note(
    note: &Note,
    memo: &[u8; MEMO_SIZE],
) -> Option<([u8; 32], [u8; ENC_CIPHERTEXT_SIZE])> {
    let mut esk = note.rseed().esk()?;
    let out = encrypt_note_with_esk(note, memo, &esk);
    esk.zeroize();
    Some(out)
}

/// The outgoing cipher key of an output, `PRF^ock(ovk, cv, cmu, epk)`.
pub fn outgoing_cipher_key(
    ovk: &OutgoingViewingKey,
    cv: &[u8; 32],
    cmu: &[u8; 32],
    ephemeral_key: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(prf_ock(&ovk.0, cv, cmu, ephemeral_key))
}

/// Encrypts the outgoing plaintext `repr(pk_d) ‖ esk` under an outgoing
/// cipher key, giving the outgoing ciphertext `C^out` of an output.
///
/// A sender who does not want the output to be recoverable encrypts with a
/// random key instead (or fills `C^out` with random bytes).
pub fn encrypt_outgoing(ock: &[u8; 32], pk_d: &Point, esk: &Fr) -> [u8; OUT_CIPHERTEXT_SIZE] {
    let mut out = [0u8; OUT_CIPHERTEXT_SIZE];
    let (body, tag) = out.split_at_mut(OUT_PLAINTEXT_SIZE);
    body[..32].copy_from_slice(&pk_d.to_bytes());
    body[32..].copy_from_slice(&esk.to_bytes());
    tag.copy_from_slice(&ChaCha20Poly1305::new(ock).encrypt(&NONCE, &[], body));
    out
}

/// How the `pk_d` of a decrypted note is established.
enum Recipient<'a> {
    /// Derived from the incoming viewing key.
    Ivk(&'a IncomingViewingKey),
    /// Taken from the outgoing plaintext.
    PkD(Point),
}

/// Parses the compact part of a note plaintext and checks the note against
/// the output it came with: its commitment must be `cmu` and, for a ZIP-212
/// note, its derived `esk` must give back the ephemeral key (and equal
/// `known_esk` when the sender is recovering the note).
fn parse_and_check(
    plaintext: &[u8; COMPACT_NOTE_SIZE],
    recipient: Recipient<'_>,
    ephemeral_key: &[u8; 32],
    cmu: &[u8; 32],
    known_esk: Option<&Fr>,
    zip212: Zip212Enforcement,
) -> Option<Note> {
    let lead_byte = plaintext[0];
    if !zip212.accepts(lead_byte) {
        return None;
    }
    let (d, rest) = plaintext[1..].split_first_chunk::<11>()?;
    let (value, rest) = rest.split_first_chunk::<8>()?;
    let r: &[u8; 32] = rest.try_into().ok()?;
    let rseed = if lead_byte == 0x01 {
        Rseed::BeforeZip212(Fr::from_bytes(r)?)
    } else {
        Rseed::AfterZip212(*r)
    };
    let diversifier = Diversifier(*d);
    let g_d = diversifier.g_d()?;
    let pk_d = match recipient {
        Recipient::Ivk(ivk) => g_d.mul(ivk.to_scalar()),
        Recipient::PkD(pk_d) => pk_d,
    };
    let address = PaymentAddress::from_derived(diversifier, g_d, pk_d)?;
    let note = Note::new(address, u64::from_le_bytes(*value), rseed);
    if !bool::from(note.cmu().ct_eq(cmu)) {
        return None;
    }
    if let Some(mut esk) = rseed.esk() {
        let matches_known = known_esk.is_none_or(|known| bool::from(esk.ct_eq(known)));
        let matches_epk = ka_derive_public(&esk, &g_d).to_bytes() == *ephemeral_key;
        esk.zeroize();
        if !matches_known || !matches_epk {
            return None;
        }
    }
    Some(note)
}

/// The key of an output's note ciphertext, for the holder of `ivk`.
fn ivk_note_key(ivk: &IncomingViewingKey, ephemeral_key: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
    // ZIP-216: only canonical encodings are points
    let epk = Point::from_bytes(ephemeral_key)?;
    Some(note_key(&ka_agree(ivk.to_scalar(), &epk), ephemeral_key))
}

/// Decrypts and authenticates a note ciphertext, returning the plaintext.
fn open_note(
    key: &[u8; 32],
    enc_ciphertext: &[u8; ENC_CIPHERTEXT_SIZE],
) -> Option<Zeroizing<[u8; NOTE_PLAINTEXT_SIZE]>> {
    let (body, tag) = enc_ciphertext.split_first_chunk::<NOTE_PLAINTEXT_SIZE>()?;
    let tag: &[u8; 16] = tag.try_into().ok()?;
    let mut pt = Zeroizing::new(*body);
    ChaCha20Poly1305::new(key)
        .decrypt(&NONCE, &[], &mut pt[..], tag)
        .ok()?;
    Some(pt)
}

fn split_plaintext(
    pt: &[u8; NOTE_PLAINTEXT_SIZE],
) -> Option<(&[u8; COMPACT_NOTE_SIZE], [u8; MEMO_SIZE])> {
    let (compact, memo) = pt.split_first_chunk::<COMPACT_NOTE_SIZE>()?;
    Some((compact, memo.try_into().ok()?))
}

/// Trial-decrypts an output with an incoming viewing key.
///
/// Returns the note and its memo if the output is addressed to one of the
/// key's payment addresses and passes every check of the specification:
/// the ciphertext authenticates, the plaintext is well-formed for the given
/// [`Zip212Enforcement`], the note's commitment is `cmu`, and (ZIP-212) the
/// ephemeral key is the one derived from the note.
pub fn try_note_decryption(
    ivk: &IncomingViewingKey,
    ephemeral_key: &[u8; 32],
    cmu: &[u8; 32],
    enc_ciphertext: &[u8; ENC_CIPHERTEXT_SIZE],
    zip212: Zip212Enforcement,
) -> Option<(Note, [u8; MEMO_SIZE])> {
    let key = ivk_note_key(ivk, ephemeral_key)?;
    let pt = open_note(&key, enc_ciphertext)?;
    let (compact, memo) = split_plaintext(&pt)?;
    let note = parse_and_check(
        compact,
        Recipient::Ivk(ivk),
        ephemeral_key,
        cmu,
        None,
        zip212,
    )?;
    Some((note, memo))
}

/// Trial-decrypts a compact output (ZIP-307): the first 52 bytes of the note
/// ciphertext, which hold everything but the memo.
///
/// There is no authentication tag to check here; the note is accepted
/// because its commitment is `cmu` (and its `esk` gives the ephemeral key),
/// which only the right key achieves.
pub fn try_compact_note_decryption(
    ivk: &IncomingViewingKey,
    ephemeral_key: &[u8; 32],
    cmu: &[u8; 32],
    compact_ciphertext: &[u8; COMPACT_NOTE_SIZE],
    zip212: Zip212Enforcement,
) -> Option<Note> {
    let key = ivk_note_key(ivk, ephemeral_key)?;
    let mut pt = Zeroizing::new(*compact_ciphertext);
    // the AEAD's keystream for the message starts at block 1
    ChaCha20::new(&key).apply_keystream(&NONCE, 1, &mut pt[..]);
    parse_and_check(&pt, Recipient::Ivk(ivk), ephemeral_key, cmu, None, zip212)
}

/// Recovers a sent note from an output with its outgoing cipher key (see
/// [`outgoing_cipher_key`]): decrypts the outgoing ciphertext to `pk_d` and
/// `esk`, then the note ciphertext with them, with the same checks as
/// [`try_note_decryption`].
pub fn try_output_recovery_with_ock(
    ock: &[u8; 32],
    cmu: &[u8; 32],
    ephemeral_key: &[u8; 32],
    enc_ciphertext: &[u8; ENC_CIPHERTEXT_SIZE],
    out_ciphertext: &[u8; OUT_CIPHERTEXT_SIZE],
    zip212: Zip212Enforcement,
) -> Option<(Note, [u8; MEMO_SIZE])> {
    let (body, tag) = out_ciphertext.split_first_chunk::<OUT_PLAINTEXT_SIZE>()?;
    let tag: &[u8; 16] = tag.try_into().ok()?;
    let mut op = Zeroizing::new(*body);
    ChaCha20Poly1305::new(ock)
        .decrypt(&NONCE, &[], &mut op[..], tag)
        .ok()?;
    let (pk_d, esk) = op.split_first_chunk::<32>()?;
    let pk_d = Point::from_bytes_prime_order(pk_d)?;
    let mut esk = Fr::from_bytes(esk.try_into().ok()?)?;

    let key = note_key(&ka_agree(&esk, &pk_d), ephemeral_key);
    let result = (|| {
        let pt = open_note(&key, enc_ciphertext)?;
        let (compact, memo) = split_plaintext(&pt)?;
        let note = parse_and_check(
            compact,
            Recipient::PkD(pk_d),
            ephemeral_key,
            cmu,
            Some(&esk),
            zip212,
        )?;
        // a note from before ZIP-212 does not commit to its esk: check it
        if note.rseed().esk().is_none()
            && ka_derive_public(&esk, note.recipient().g_d()).to_bytes() != *ephemeral_key
        {
            return None;
        }
        Some((note, memo))
    })();
    esk.zeroize();
    result
}

/// Recovers a sent note from an output with the outgoing viewing key it was
/// created with: see [`try_output_recovery_with_ock`].
pub fn try_output_recovery_with_ovk(
    ovk: &OutgoingViewingKey,
    cv: &[u8; 32],
    cmu: &[u8; 32],
    ephemeral_key: &[u8; 32],
    enc_ciphertext: &[u8; ENC_CIPHERTEXT_SIZE],
    out_ciphertext: &[u8; OUT_CIPHERTEXT_SIZE],
    zip212: Zip212Enforcement,
) -> Option<(Note, [u8; MEMO_SIZE])> {
    let ock = outgoing_cipher_key(ovk, cv, cmu, ephemeral_key);
    try_output_recovery_with_ock(
        &ock,
        cmu,
        ephemeral_key,
        enc_ciphertext,
        out_ciphertext,
        zip212,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sapling::keys::{ExpandedSpendingKey, default_diversifier};
    use crate::sapling::note::value_commitment;
    use crate::sapling::test_vectors::for_each_row;
    use Zip212Enforcement::{GracePeriod, Off, On};

    /// `sapling_note_encryption.json`: every intermediate value of the
    /// encryption of ten notes (in the original, pre-ZIP-212 format), and
    /// their decryption.
    #[test]
    fn sapling_note_encryption() {
        let mut seen = 0;
        let json = include_str!("testdata/sapling_note_encryption.json");
        for_each_row(json, |_, row| {
            seen += 1;
            let ovk = OutgoingViewingKey(row.array("ovk"));
            let ivk = IncomingViewingKey::from_bytes(&row.array("ivk")).unwrap();
            let address = ivk
                .to_payment_address(Diversifier(row.array("default_d")))
                .unwrap();
            assert_eq!(address.pk_d().to_bytes(), row.array::<32>("default_pk_d"));
            let rcm = Fr::from_bytes(&row.array("rcm")).unwrap();
            let value = row.u64("v");
            let note = Note::new(address, value, Rseed::BeforeZip212(rcm));
            let memo: [u8; MEMO_SIZE] = row.array("memo");
            let cv: [u8; 32] = row.array("cv");
            let cmu: [u8; 32] = row.array("cmu");
            let esk = Fr::from_bytes(&row.array("esk")).unwrap();
            let epk: [u8; 32] = row.array("epk");
            let c_enc: [u8; ENC_CIPHERTEXT_SIZE] = row.array("c_enc");
            let c_out: [u8; OUT_CIPHERTEXT_SIZE] = row.array("c_out");

            // the building blocks
            assert_eq!(value_commitment(value, &rcm).to_bytes(), cv);
            assert_eq!(note.cmu(), cmu);
            assert_eq!(ka_derive_public(&esk, address.g_d()).to_bytes(), epk);
            let shared = ka_agree(&esk, address.pk_d());
            assert_eq!(shared.to_bytes(), row.array::<32>("shared_secret"));
            let epk_point = Point::from_bytes(&epk).unwrap();
            assert_eq!(ka_agree(ivk.to_scalar(), &epk_point), shared);
            assert_eq!(*note_key(&shared, &epk), row.array::<32>("k_enc"));
            assert_eq!(note_plaintext(&note, &memo), row.array::<564>("p_enc"));
            let ock = outgoing_cipher_key(&ovk, &cv, &cmu, &epk);
            assert_eq!(*ock, row.array::<32>("ock"));
            let mut op = [0u8; 64];
            op[..32].copy_from_slice(&address.pk_d().to_bytes());
            op[32..].copy_from_slice(&esk.to_bytes());
            assert_eq!(op, row.array::<64>("op"));

            // encryption
            assert_eq!(encrypt_note_with_esk(&note, &memo, &esk), (epk, c_enc));
            assert_eq!(encrypt_outgoing(&ock, address.pk_d(), &esk), c_out);
            assert_eq!(encrypt_note(&note, &memo), None);

            // decryption, each way
            for zip212 in [Off, GracePeriod] {
                assert_eq!(
                    try_note_decryption(&ivk, &epk, &cmu, &c_enc, zip212),
                    Some((note, memo))
                );
                let compact: [u8; COMPACT_NOTE_SIZE] = c_enc[..52].try_into().unwrap();
                assert_eq!(
                    try_compact_note_decryption(&ivk, &epk, &cmu, &compact, zip212),
                    Some(note)
                );
                assert_eq!(
                    try_output_recovery_with_ovk(&ovk, &cv, &cmu, &epk, &c_enc, &c_out, zip212),
                    Some((note, memo))
                );
                assert_eq!(
                    try_output_recovery_with_ock(&ock, &cmu, &epk, &c_enc, &c_out, zip212),
                    Some((note, memo))
                );
            }
            // the original format is no longer valid
            assert_eq!(try_note_decryption(&ivk, &epk, &cmu, &c_enc, On), None);
            assert_eq!(
                try_output_recovery_with_ovk(&ovk, &cv, &cmu, &epk, &c_enc, &c_out, On),
                None
            );
        });
        assert_eq!(seen, 10);
    }

    struct Sent {
        ivk: IncomingViewingKey,
        ovk: OutgoingViewingKey,
        note: Note,
        memo: [u8; MEMO_SIZE],
        cv: [u8; 32],
        cmu: [u8; 32],
        epk: [u8; 32],
        enc: [u8; ENC_CIPHERTEXT_SIZE],
        out: [u8; OUT_CIPHERTEXT_SIZE],
    }

    /// A ZIP-212 output, as a sender builds it.
    fn zip212_output() -> Sent {
        let sk = [0x42u8; 32];
        let fvk = ExpandedSpendingKey::from_spending_key(&sk)
            .unwrap()
            .full_viewing_key();
        let ivk = fvk.ivk();
        let address = ivk
            .to_payment_address(default_diversifier(&sk).unwrap())
            .unwrap();
        let note = Note::new(address, 123_456_789, Rseed::AfterZip212([0x17; 32]));
        let mut memo = [0u8; MEMO_SIZE];
        memo[..5].copy_from_slice(b"hello");
        let cv = value_commitment(note.value(), &Fr::from_u64(999)).to_bytes();
        let cmu = note.cmu();
        let (epk, enc) = encrypt_note(&note, &memo).unwrap();
        let esk = note.rseed().esk().unwrap();
        let ock = outgoing_cipher_key(fvk.ovk(), &cv, &cmu, &epk);
        let out = encrypt_outgoing(&ock, address.pk_d(), &esk);
        Sent {
            ivk,
            ovk: fvk.ovk().clone(),
            note,
            memo,
            cv,
            cmu,
            epk,
            enc,
            out,
        }
    }

    fn compact(enc: &[u8; ENC_CIPHERTEXT_SIZE]) -> [u8; COMPACT_NOTE_SIZE] {
        enc[..COMPACT_NOTE_SIZE].try_into().unwrap()
    }

    #[test]
    fn zip212_round_trip() {
        let s = zip212_output();
        assert_eq!(note_plaintext(&s.note, &s.memo)[0], 2);
        for zip212 in [GracePeriod, On] {
            assert_eq!(
                try_note_decryption(&s.ivk, &s.epk, &s.cmu, &s.enc, zip212),
                Some((s.note, s.memo))
            );
            assert_eq!(
                try_compact_note_decryption(&s.ivk, &s.epk, &s.cmu, &compact(&s.enc), zip212),
                Some(s.note)
            );
            assert_eq!(
                try_output_recovery_with_ovk(
                    &s.ovk, &s.cv, &s.cmu, &s.epk, &s.enc, &s.out, zip212
                ),
                Some((s.note, s.memo))
            );
        }
        // before Canopy the new format is not valid
        assert_eq!(
            try_note_decryption(&s.ivk, &s.epk, &s.cmu, &s.enc, Off),
            None
        );
        assert_eq!(
            try_compact_note_decryption(&s.ivk, &s.epk, &s.cmu, &compact(&s.enc), Off),
            None
        );
    }

    #[test]
    fn decryption_failures() {
        let s = zip212_output();
        let other_ivk = ExpandedSpendingKey::from_spending_key(&[1; 32])
            .unwrap()
            .full_viewing_key()
            .ivk();
        // another key
        assert_eq!(
            try_note_decryption(&other_ivk, &s.epk, &s.cmu, &s.enc, On),
            None
        );
        assert_eq!(
            try_compact_note_decryption(&other_ivk, &s.epk, &s.cmu, &compact(&s.enc), On),
            None
        );
        // another commitment
        let mut cmu = s.cmu;
        cmu[0] ^= 1;
        assert_eq!(try_note_decryption(&s.ivk, &s.epk, &cmu, &s.enc, On), None);
        assert_eq!(
            try_compact_note_decryption(&s.ivk, &s.epk, &cmu, &compact(&s.enc), On),
            None
        );
        assert_eq!(
            try_output_recovery_with_ovk(&s.ovk, &s.cv, &cmu, &s.epk, &s.enc, &s.out, On),
            None
        );
        // an ephemeral key that is not a point, or not a canonical one
        assert_eq!(
            try_note_decryption(&s.ivk, &[0xff; 32], &s.cmu, &s.enc, On),
            None
        );
        let mut identity_with_sign = [0u8; 32];
        identity_with_sign[0] = 1;
        identity_with_sign[31] = 0x80;
        assert_eq!(
            try_compact_note_decryption(
                &s.ivk,
                &identity_with_sign,
                &s.cmu,
                &compact(&s.enc),
                On
            ),
            None
        );
        // tampered ciphertexts
        for i in [0, 51, 52, 563, 564, 579] {
            let mut enc = s.enc;
            enc[i] ^= 1;
            assert_eq!(try_note_decryption(&s.ivk, &s.epk, &s.cmu, &enc, On), None);
            assert_eq!(
                try_output_recovery_with_ovk(&s.ovk, &s.cv, &s.cmu, &s.epk, &enc, &s.out, On),
                None
            );
        }
        for i in [0, 32, 79] {
            let mut out = s.out;
            out[i] ^= 1;
            assert_eq!(
                try_output_recovery_with_ovk(&s.ovk, &s.cv, &s.cmu, &s.epk, &s.enc, &out, On),
                None
            );
        }
        // another ovk, or another cv (which the outgoing key commits to)
        let other_ovk = OutgoingViewingKey([3; 32]);
        assert_eq!(
            try_output_recovery_with_ovk(&other_ovk, &s.cv, &s.cmu, &s.epk, &s.enc, &s.out, On),
            None
        );
        let mut cv = s.cv;
        cv[5] ^= 1;
        assert_eq!(
            try_output_recovery_with_ovk(&s.ovk, &cv, &s.cmu, &s.epk, &s.enc, &s.out, On),
            None
        );
    }

    /// ZIP-212: a note encrypted with another `esk` than the one its seed
    /// derives is rejected, although it decrypts and its commitment matches.
    #[test]
    fn zip212_esk_must_be_derived() {
        let s = zip212_output();
        let esk = Fr::from_u64(0xdead_beef);
        let (epk, enc) = encrypt_note_with_esk(&s.note, &s.memo, &esk);
        assert_ne!(epk, s.epk);
        assert_eq!(try_note_decryption(&s.ivk, &epk, &s.cmu, &enc, On), None);
        assert_eq!(
            try_compact_note_decryption(&s.ivk, &epk, &s.cmu, &compact(&enc), On),
            None
        );
        let ock = outgoing_cipher_key(&s.ovk, &s.cv, &s.cmu, &epk);
        let out = encrypt_outgoing(&ock, s.note.recipient().pk_d(), &esk);
        assert_eq!(
            try_output_recovery_with_ock(&ock, &s.cmu, &epk, &enc, &out, On),
            None
        );
        // an outgoing plaintext that lies about esk
        let ock = outgoing_cipher_key(&s.ovk, &s.cv, &s.cmu, &s.epk);
        let out = encrypt_outgoing(&ock, s.note.recipient().pk_d(), &esk);
        assert_eq!(
            try_output_recovery_with_ock(&ock, &s.cmu, &s.epk, &s.enc, &out, On),
            None
        );
        // or about pk_d: not a point of the prime-order subgroup
        let two = Point::from_bytes(&(-crate::sapling::Fq::ONE).to_bytes()).unwrap();
        let esk = s.note.rseed().esk().unwrap();
        for pk_d in [Point::IDENTITY, *s.note.recipient().pk_d() + two] {
            let out = encrypt_outgoing(&ock, &pk_d, &esk);
            assert_eq!(
                try_output_recovery_with_ock(&ock, &s.cmu, &s.epk, &s.enc, &out, On),
                None
            );
        }
    }

    #[test]
    fn malformed_plaintexts() {
        let s = zip212_output();
        let esk = s.note.rseed().esk().unwrap();
        let recipient = s.note.recipient();
        let key = note_key(&ka_agree(&esk, recipient.pk_d()), &s.epk);
        let seal = |pt: &[u8; NOTE_PLAINTEXT_SIZE]| {
            let mut enc = [0u8; ENC_CIPHERTEXT_SIZE];
            enc[..NOTE_PLAINTEXT_SIZE].copy_from_slice(pt);
            let tag = ChaCha20Poly1305::new(&key).encrypt(
                &NONCE,
                &[],
                &mut enc[..NOTE_PLAINTEXT_SIZE],
            );
            enc[NOTE_PLAINTEXT_SIZE..].copy_from_slice(&tag);
            enc
        };
        let pt = note_plaintext(&s.note, &s.memo);
        assert_eq!(seal(&pt), s.enc);
        // an unknown lead byte
        for lead in [0u8, 3, 0xff] {
            let mut bad = pt;
            bad[0] = lead;
            let enc = seal(&bad);
            for zip212 in [Off, GracePeriod, On] {
                assert_eq!(
                    try_note_decryption(&s.ivk, &s.epk, &s.cmu, &enc, zip212),
                    None
                );
            }
        }
        // another diversifier of the same key, a wrong value: the commitment
        // no longer matches
        let mut bad = pt;
        bad[12] ^= 1;
        assert_eq!(
            try_note_decryption(&s.ivk, &s.epk, &s.cmu, &seal(&bad), On),
            None
        );
        let invalid_d = (0..=255u8)
            .map(|i| Diversifier([i; 11]))
            .find(|d| d.g_d().is_none())
            .unwrap();
        let mut bad = pt;
        bad[1..12].copy_from_slice(&invalid_d.0);
        assert_eq!(
            try_note_decryption(&s.ivk, &s.epk, &s.cmu, &seal(&bad), On),
            None
        );
        // the original format with an rcm that is not a canonical scalar
        let mut bad = pt;
        bad[0] = 1;
        bad[20..52].fill(0xff);
        assert_eq!(
            try_note_decryption(&s.ivk, &s.epk, &s.cmu, &seal(&bad), GracePeriod),
            None
        );
    }
}
