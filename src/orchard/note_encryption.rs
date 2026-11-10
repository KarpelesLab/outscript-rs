//! In-band secret distribution for Orchard notes (protocol specification
//! section 4.20, ZIP-212): encryption of a note to its recipient, trial
//! decryption with an incoming viewing key, and recovery of sent notes with
//! an outgoing viewing key.
//!
//! Everything works on fixed-size arrays and nothing allocates, so a device
//! without a heap can scan for its notes. [`try_compact_note_decryption`]
//! only needs the first 52 bytes of a ciphertext, as light clients receive
//! them.

use purecrypto::cipher::{ChaCha20, ChaCha20Poly1305};
use purecrypto::ct::ConstantTimeEq;
use purecrypto::zeroize::Zeroize;

use super::fields::Fq;
use super::keys::{Address, Diversifier, IncomingViewingKey, OutgoingViewingKey};
use super::note::{Note, Nullifier};
use super::pallas::{Affine, Point};
use super::spec::blake2b;
use super::value::ValueCommitment;

/// The size of a memo.
pub const MEMO_SIZE: usize = 512;
/// The size of a note plaintext: lead byte, diversifier, value, `rseed`,
/// memo.
pub const NOTE_PLAINTEXT_SIZE: usize = 1 + 11 + 8 + 32 + MEMO_SIZE;
/// The size of the part of a note plaintext before the memo, which is all a
/// light client is given the ciphertext of.
pub const COMPACT_NOTE_SIZE: usize = 1 + 11 + 8 + 32;
/// The size of an encrypted note (`encCiphertext`).
pub const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + 16;
/// The size of an encrypted outgoing plaintext (`outCiphertext`).
pub const OUT_CIPHERTEXT_SIZE: usize = 32 + 32 + 16;

/// The lead byte of an Orchard note plaintext.
const LEAD_BYTE: u8 = 0x02;

/// The public fields of an action that the decryption of its note needs.
#[derive(Clone, Copy, Debug)]
pub struct ActionOutput<'a> {
    /// The nullifier the action reveals, which is the `rho` of its note.
    pub nullifier: &'a [u8; 32],
    /// The extracted commitment `cmx` of the note.
    pub cmx: &'a [u8; 32],
    /// The ephemeral public key.
    pub ephemeral_key: &'a [u8; 32],
}

/// `KDF^Orchard`: the symmetric key for a shared secret.
fn kdf(mut shared_secret: Point, ephemeral_key: &[u8; 32]) -> [u8; 32] {
    let mut secret = shared_secret.to_bytes();
    shared_secret.zeroize();
    let mut key = [0u8; 32];
    blake2b(b"Zcash_OrchardKDF", &[&secret, ephemeral_key], &mut key);
    secret.zeroize();
    key
}

/// `PRF^ock`: the key of the outgoing ciphertext.
fn prf_ock(
    ovk: &OutgoingViewingKey,
    cv: &[u8; 32],
    cmx: &[u8; 32],
    ephemeral_key: &[u8; 32],
) -> [u8; 32] {
    let mut key = [0u8; 32];
    blake2b(
        b"Zcash_Orchardock",
        &[ovk.to_bytes(), cv, cmx, ephemeral_key],
        &mut key,
    );
    key
}

fn split_tag<const N: usize, const M: usize>(ciphertext: &[u8; N]) -> ([u8; M], [u8; 16]) {
    debug_assert_eq!(M + 16, N);
    let body = ciphertext[..M].try_into().expect("M bytes");
    let tag = ciphertext[M..].try_into().expect("16 bytes");
    (body, tag)
}

/// The encryption of a note under its own ephemeral key.
#[derive(Clone, Copy, Debug)]
pub struct EncryptedNote {
    /// The ephemeral public key `epk = [esk] g_d`.
    pub ephemeral_key: [u8; 32],
    /// The note and memo, encrypted to the recipient.
    pub enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
}

/// Encrypts `note` and `memo` to the recipient of the note.
pub fn encrypt_note(note: &Note, memo: &[u8; MEMO_SIZE]) -> EncryptedNote {
    let recipient = note.recipient();
    let mut esk = note.esk();
    let ephemeral_key = recipient.g_d().mul(&esk).to_bytes();
    let shared = recipient.pk_d().to_point().mul(&esk);
    esk.zeroize();
    let mut key = kdf(shared, &ephemeral_key);

    let mut enc_ciphertext = [0u8; ENC_CIPHERTEXT_SIZE];
    let (plaintext, tag) = enc_ciphertext.split_at_mut(NOTE_PLAINTEXT_SIZE);
    plaintext[0] = LEAD_BYTE;
    plaintext[1..12].copy_from_slice(recipient.diversifier().to_bytes());
    plaintext[12..20].copy_from_slice(&note.value().to_le_bytes());
    plaintext[20..52].copy_from_slice(note.rseed());
    plaintext[52..].copy_from_slice(memo);
    tag.copy_from_slice(&ChaCha20Poly1305::new(&key).encrypt(&[0; 12], &[], plaintext));
    key.zeroize();
    EncryptedNote {
        ephemeral_key,
        enc_ciphertext,
    }
}

/// Encrypts the outgoing plaintext of `note` (`pk_d` and `esk`) so that the
/// holder of `ovk` can recover the note from the action it is in, whose
/// value commitment is `cv` and whose ephemeral key is `ephemeral_key` (as
/// [`encrypt_note`] returned it).
pub fn encrypt_outgoing(
    note: &Note,
    ovk: &OutgoingViewingKey,
    cv: &ValueCommitment,
    ephemeral_key: &[u8; 32],
) -> [u8; OUT_CIPHERTEXT_SIZE] {
    let mut ock = prf_ock(ovk, &cv.to_bytes(), &note.cmx().to_bytes(), ephemeral_key);
    let mut op = [0u8; 64];
    op[..32].copy_from_slice(&note.recipient().pk_d().to_bytes());
    op[32..].copy_from_slice(&note.esk().to_bytes());
    let out = encrypt_outgoing_with_key(&ock, &op);
    ock.zeroize();
    op.zeroize();
    out
}

/// The outgoing ciphertext of an action nobody is meant to recover: the
/// encryption of 64 random bytes under a random key. `random` must be 96
/// fresh uniformly random bytes.
pub fn encrypt_outgoing_unrecoverable(random: &[u8; 96]) -> [u8; OUT_CIPHERTEXT_SIZE] {
    let ock = random[..32].try_into().expect("32 bytes");
    let op = random[32..].try_into().expect("64 bytes");
    encrypt_outgoing_with_key(&ock, &op)
}

fn encrypt_outgoing_with_key(ock: &[u8; 32], op: &[u8; 64]) -> [u8; OUT_CIPHERTEXT_SIZE] {
    let mut out = [0u8; OUT_CIPHERTEXT_SIZE];
    let (body, tag) = out.split_at_mut(64);
    body.copy_from_slice(op);
    tag.copy_from_slice(&ChaCha20Poly1305::new(ock).encrypt(&[0; 12], &[], body));
    out
}

/// Rebuilds the note a (decrypted) compact plaintext describes and checks
/// it against the action, per ZIP-212: the lead byte, that `esk` derived
/// from `rseed` gives the action's ephemeral key, and that the note
/// commitment is the action's. `pk_d` computes the transmission key from
/// the diversified base.
fn check_note(
    plaintext: &[u8; COMPACT_NOTE_SIZE],
    output: &ActionOutput<'_>,
    pk_d: impl FnOnce(&Point) -> Affine,
    expected_esk: Option<&Fq>,
) -> Option<Note> {
    if plaintext[0] != LEAD_BYTE {
        return None;
    }
    let d = Diversifier::from_bytes(plaintext[1..12].try_into().expect("11 bytes"));
    let value = u64::from_le_bytes(plaintext[12..20].try_into().expect("8 bytes"));
    let rseed: [u8; 32] = plaintext[20..52].try_into().expect("32 bytes");
    let rho = Nullifier::from_bytes(output.nullifier)?;
    let g_d = d.g_d();
    let pk_d = pk_d(&g_d);
    if bool::from(pk_d.is_identity()) {
        return None;
    }
    let note = Note::from_parts(Address::from_parts(d, pk_d), value, rho, rseed).ok()?;
    let mut esk = note.esk();
    let esk_ok = match expected_esk {
        Some(expected) => esk.ct_eq(expected),
        None => 1u8.ct_eq(&1),
    };
    let epk = g_d.mul(&esk).to_bytes();
    esk.zeroize();
    let ok = esk_ok & epk.ct_eq(output.ephemeral_key) & note.cmx().to_bytes().ct_eq(output.cmx);
    if bool::from(ok) { Some(note) } else { None }
}

/// The symmetric key a recipient derives for an action, or `None` if the
/// ephemeral key is not a valid non-identity point.
fn recipient_key(ivk: &IncomingViewingKey, ephemeral_key: &[u8; 32]) -> Option<[u8; 32]> {
    let epk = Affine::from_bytes(ephemeral_key)?;
    if bool::from(epk.is_identity()) {
        return None;
    }
    let shared = epk.to_point().mul(&ivk.ivk_scalar());
    Some(kdf(shared, ephemeral_key))
}

/// Tries to decrypt the note of an action with an incoming viewing key,
/// returning the note and its memo when the action pays an address of that
/// key. The note returned has passed every check of the protocol: it is
/// the one the action commits to.
pub fn try_note_decryption(
    ivk: &IncomingViewingKey,
    output: &ActionOutput<'_>,
    enc_ciphertext: &[u8; ENC_CIPHERTEXT_SIZE],
) -> Option<(Note, [u8; MEMO_SIZE])> {
    let mut key = recipient_key(ivk, output.ephemeral_key)?;
    let result = decrypt_and_check(&key, output, enc_ciphertext, None, |g_d| {
        g_d.mul(&ivk.ivk_scalar()).to_affine()
    });
    key.zeroize();
    result
}

fn decrypt_and_check(
    key: &[u8; 32],
    output: &ActionOutput<'_>,
    enc_ciphertext: &[u8; ENC_CIPHERTEXT_SIZE],
    expected_esk: Option<&Fq>,
    pk_d: impl FnOnce(&Point) -> Affine,
) -> Option<(Note, [u8; MEMO_SIZE])> {
    let (mut plaintext, tag) =
        split_tag::<ENC_CIPHERTEXT_SIZE, NOTE_PLAINTEXT_SIZE>(enc_ciphertext);
    ChaCha20Poly1305::new(key)
        .decrypt(&[0; 12], &[], &mut plaintext, &tag)
        .ok()?;
    let compact = plaintext[..COMPACT_NOTE_SIZE].try_into().expect("52 bytes");
    let note = check_note(&compact, output, pk_d, expected_esk);
    let memo = plaintext[COMPACT_NOTE_SIZE..]
        .try_into()
        .expect("512 bytes");
    plaintext.zeroize();
    note.map(|note| (note, memo))
}

/// Tries to decrypt the compact form of an action's note (the first
/// [`COMPACT_NOTE_SIZE`] bytes of its ciphertext, without the memo or the
/// authentication tag) with an incoming viewing key.
///
/// There is no tag to check, so detection relies on the ZIP-212 checks
/// alone, which only the right key passes.
pub fn try_compact_note_decryption(
    ivk: &IncomingViewingKey,
    output: &ActionOutput<'_>,
    compact_ciphertext: &[u8; COMPACT_NOTE_SIZE],
) -> Option<Note> {
    let mut key = recipient_key(ivk, output.ephemeral_key)?;
    let mut plaintext = *compact_ciphertext;
    // the ciphertext is ChaCha20 from block 1 (block 0 keys the tag)
    ChaCha20::new(&key).apply_keystream(&[0; 12], 1, &mut plaintext);
    key.zeroize();
    let note = check_note(
        &plaintext,
        output,
        |g_d| g_d.mul(&ivk.ivk_scalar()).to_affine(),
        None,
    );
    plaintext.zeroize();
    note
}

/// Tries to recover the note of an action with an outgoing viewing key,
/// returning the note and its memo when the action was built with that key.
/// `cv` is the value commitment of the action.
pub fn try_output_recovery_with_ovk(
    ovk: &OutgoingViewingKey,
    cv: &[u8; 32],
    output: &ActionOutput<'_>,
    enc_ciphertext: &[u8; ENC_CIPHERTEXT_SIZE],
    out_ciphertext: &[u8; OUT_CIPHERTEXT_SIZE],
) -> Option<(Note, [u8; MEMO_SIZE])> {
    let mut ock = prf_ock(ovk, cv, output.cmx, output.ephemeral_key);
    let (mut op, tag) = split_tag::<OUT_CIPHERTEXT_SIZE, 64>(out_ciphertext);
    let opened = ChaCha20Poly1305::new(&ock).decrypt(&[0; 12], &[], &mut op, &tag);
    ock.zeroize();
    opened.ok()?;
    let pk_d = Affine::from_bytes(op[..32].try_into().expect("32 bytes"));
    let esk = Fq::from_bytes(op[32..].try_into().expect("32 bytes"));
    op.zeroize();
    let (pk_d, mut esk) = (pk_d?, esk?);
    if bool::from(pk_d.is_identity() | esk.is_zero()) {
        return None;
    }
    let shared = pk_d.to_point().mul(&esk);
    let mut key = kdf(shared, output.ephemeral_key);
    let result = decrypt_and_check(&key, output, enc_ciphertext, Some(&esk), |_| pk_d);
    key.zeroize();
    esk.zeroize();
    result
}
