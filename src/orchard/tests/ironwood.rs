//! Notes of the Ironwood pool (ZIP 2005, note plaintext version 3) against
//! the `orchard` crate (0.16.0).
//!
//! `testdata/ironwood_notes.json` was made with that crate by a program
//! outside this repository: for fixed spending keys, addresses (external
//! and internal), values, `rho` and `rseed`, the extracted commitment of
//! the version 3 note (`Note::from_parts` with `NoteVersion::V3`) and of
//! the version 2 note of the same fields, the nullifier of the former, and
//! its encryption (`IronwoodNoteEncryption`: the ephemeral key and the
//! ciphertext, which are deterministic).

use super::arr;
use crate::orchard::bundle::Flags;
use crate::orchard::keys::*;
use crate::orchard::note::NoteVersion;
use crate::orchard::note_encryption::*;
use crate::orchard::{Note, Nullifier};

#[test]
fn ironwood_note_vectors() {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../testdata/ironwood_notes.json")).unwrap();
    assert_eq!(rows.len(), 4);
    for row in rows {
        let sk = SpendingKey::from_bytes(arr(&row["sk"])).unwrap();
        let fvk = sk.to_fvk();
        let scope = match row["scope"].as_str().unwrap() {
            "external" => Scope::External,
            "internal" => Scope::Internal,
            other => panic!("{other}"),
        };
        let index = row["index"].as_u64().unwrap() as u32;
        let recipient = fvk.address_at(index, scope);
        assert_eq!(recipient.to_raw_address_bytes(), arr(&row["address"]));
        let value = row["value"].as_u64().unwrap();
        let rho = Nullifier::from_bytes(&arr(&row["rho"])).unwrap();
        let rseed: [u8; 32] = arr(&row["rseed"]);
        let mut memo = [0u8; MEMO_SIZE];
        memo[..4].copy_from_slice(&arr::<4>(&row["memo"]));

        let v3 = Note::from_parts_versioned(recipient, value, rho, rseed, NoteVersion::V3).unwrap();
        let v2 = Note::from_parts_versioned(recipient, value, rho, rseed, NoteVersion::V2).unwrap();
        assert_eq!(v3.version(), NoteVersion::V3);
        assert_eq!(v2, Note::from_parts(recipient, value, rho, rseed).unwrap());
        assert_eq!(v2.version(), NoteVersion::V2);
        let cmx: [u8; 32] = arr(&row["cmx_v3"]);
        assert_eq!(v3.cmx().to_bytes(), cmx);
        assert_eq!(v2.cmx().to_bytes(), arr::<32>(&row["cmx_v2"]));
        assert_ne!(v3.cmx(), v2.cmx());
        // only the commitment randomness differs
        assert_eq!(v3.psi(), v2.psi());
        assert_eq!(v3.esk(), v2.esk());
        assert_ne!(v3.rcm(), v2.rcm());
        assert_eq!(v3.nullifier(&fvk).to_bytes(), arr::<32>(&row["nf_v3"]));

        // the encryption states the version in its lead byte
        let encrypted = encrypt_note(&v3, &memo);
        let epk: [u8; 32] = arr(&row["epk"]);
        let ciphertext: [u8; ENC_CIPHERTEXT_SIZE] = arr(&row["enc_ciphertext"]);
        assert_eq!(encrypted.ephemeral_key, epk);
        assert_eq!(encrypted.enc_ciphertext, ciphertext);
        assert_ne!(encrypt_note(&v2, &memo).enc_ciphertext, ciphertext);

        // and each pool only reads the notes of its version
        let rho_bytes = rho.to_bytes();
        let output = ActionOutput {
            nullifier: &rho_bytes,
            cmx: &cmx,
            ephemeral_key: &epk,
        };
        let ivk = fvk.to_ivk(scope);
        let found = try_note_decryption_versioned(NoteVersion::V3, &ivk, &output, &ciphertext);
        assert_eq!(found, Some((v3, memo)));
        assert_eq!(try_note_decryption(&ivk, &output, &ciphertext), None);
        assert_eq!(
            try_note_decryption_versioned(NoteVersion::V2, &ivk, &output, &ciphertext),
            None
        );
        let compact = ciphertext[..COMPACT_NOTE_SIZE].try_into().unwrap();
        assert_eq!(
            try_compact_note_decryption_versioned(NoteVersion::V3, &ivk, &output, &compact),
            Some(v3)
        );
        assert_eq!(try_compact_note_decryption(&ivk, &output, &compact), None);
        #[cfg(feature = "alloc")]
        {
            let batch = [(output, &ciphertext)];
            let ivks = [fvk.to_ivk(Scope::External), fvk.to_ivk(Scope::Internal)];
            let which = (scope == Scope::Internal) as usize;
            assert_eq!(
                batch_note_decryption_versioned(NoteVersion::V3, &ivks, &batch),
                [Some((which, v3, memo))]
            );
            assert_eq!(batch_note_decryption(&ivks, &batch), [None]);
            let compact_batch = [(output, &compact)];
            assert_eq!(
                batch_compact_note_decryption_versioned(NoteVersion::V3, &ivks, &compact_batch),
                [Some((which, v3))]
            );
            assert_eq!(batch_compact_note_decryption(&ivks, &compact_batch), [None]);
        }
        // a version 2 note of the same fields, encrypted, is not at that
        // commitment either way
        let other = encrypt_note(&v2, &memo);
        for version in [NoteVersion::V2, NoteVersion::V3] {
            assert_eq!(
                try_note_decryption_versioned(version, &ivk, &output, &other.enc_ciphertext),
                None
            );
        }

        // the sender's copy
        let ovk = fvk.to_ovk(scope);
        let cv = crate::orchard::ValueCommitment::derive(value as i128, &crate::orchard::Fq::ONE);
        let out = encrypt_outgoing(&v3, &ovk, &cv, &epk);
        let cv = cv.to_bytes();
        assert_eq!(
            try_output_recovery_with_ovk_versioned(
                NoteVersion::V3,
                &ovk,
                &cv,
                &output,
                &ciphertext,
                &out
            ),
            Some((v3, memo))
        );
        assert_eq!(
            try_output_recovery_with_ovk(&ovk, &cv, &output, &ciphertext, &out),
            None
        );
    }
}

#[test]
fn note_versions_and_flags() {
    assert_eq!(NoteVersion::default(), NoteVersion::V2);
    assert_eq!(NoteVersion::V2.lead_byte(), 2);
    assert_eq!(NoteVersion::V3.lead_byte(), 3);
    assert_eq!(NoteVersion::from_lead_byte(2), Some(NoteVersion::V2));
    assert_eq!(NoteVersion::from_lead_byte(3), Some(NoteVersion::V3));
    for byte in [0, 1, 4, 0xff] {
        assert_eq!(NoteVersion::from_lead_byte(byte), None);
    }

    // two flags in the Orchard pool, three in the Ironwood pool
    assert_eq!(Flags::ENABLED.to_byte(), 0b011);
    assert_eq!(Flags::IRONWOOD_ENABLED.to_byte(), 0b111);
    assert!(!Flags::ENABLED.cross_address_enabled());
    assert!(Flags::IRONWOOD_ENABLED.cross_address_enabled());
    for byte in 0..=u8::MAX {
        assert_eq!(Flags::from_byte(byte).is_some(), byte < 4);
        assert_eq!(Flags::from_byte_ironwood(byte).is_some(), byte < 8);
    }
    assert_eq!(
        Flags::ENABLED.with_cross_address(true),
        Flags::IRONWOOD_ENABLED
    );
    assert_eq!(
        Flags::IRONWOOD_ENABLED.with_cross_address(false),
        Flags::ENABLED
    );
    let restricted = Flags::from_byte_ironwood(0b011).unwrap();
    assert!(restricted.spends_enabled() && restricted.outputs_enabled());
    assert!(!restricted.cross_address_enabled());
}
