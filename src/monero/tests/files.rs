//! Tests for `cn_slow_hash` and the files of the reference wallet.
//!
//! - `testdata/monero_slow_hash.txt`: Monero's `tests/hash/tests-slow.txt`.
//! - `testdata/monero_extra_*.txt`: a selection of the lines of Monero's
//!   `tests/hash/tests-extra-*.txt` (every length up to 65 bytes, then some
//!   around the block sizes).
//! - `testdata/wallet2_*`: files made by `monero-wallet-rpc` and
//!   `monero-wallet-cli` 0.18.5.4 on a regtest chain, for the account of the
//!   mnemonic below: a view-only wallet's output exports and unsigned
//!   transaction sets, and the offline wallet's key images and signed
//!   transaction set. The signed sets this crate made from the same
//!   unsigned sets were submitted by the view-only wallet and mined.

use super::super::slow_hash::{blake256, groestl256, jh256, skein512_256};
use super::super::*;
use super::test_rng;

const MNEMONIC: &str = "washing thirsty occur lectures tuesday fainted toxic adapt \
     abnormal memoir nylon mostly building shrugged online ember northern \
     ruby woes dauntless boil family illness inroads northern";

fn fixture(text: &str) -> Vec<u8> {
    hex::decode(text.trim()).unwrap()
}

/// The payload of a file, decrypted.
fn payload(cipher: &WalletCipher, magic: &[u8], file: &[u8]) -> Vec<u8> {
    cipher
        .decrypt(file.strip_prefix(magic).unwrap())
        .unwrap()
        .to_vec()
}

/// The rings of a signed transaction, from what it was built from.
fn rings(tx: &PendingTx) -> Vec<Vec<RingMember>> {
    tx.construction_data
        .sources
        .iter()
        .map(|source| source.outputs.iter().map(|(_, member)| *member).collect())
        .collect()
}

#[test]
fn reference_wallet_files() {
    let account = AccountKeys::from_seed(&seed_from_mnemonic(MNEMONIC).unwrap()).unwrap();
    let cipher = WalletCipher::new(account.view_secret()).unwrap();
    let mut rng = test_rng(21);

    // --- the output export of the view-only wallet ---
    let outputs_file = fixture(include_str!("../testdata/wallet2_outputs.hex"));
    let outputs = OutputExport::from_file(&cipher, &outputs_file).unwrap();
    assert_eq!(outputs.spend_public, *account.spend_public());
    assert_eq!(outputs.view_public, account.view_public());
    assert_eq!((outputs.offset, outputs.total), (0, 20));
    assert_eq!(outputs.outputs.len(), 20);
    let again = outputs.to_file(&cipher, &mut rng).unwrap();
    assert_eq!(
        payload(&cipher, OUTPUT_EXPORT_MAGIC, &again),
        payload(&cipher, OUTPUT_EXPORT_MAGIC, &outputs_file)
    );
    assert_eq!(OutputExport::from_file(&cipher, &again).unwrap(), outputs);

    // --- the key images of the offline wallet ---
    let key_images_file = include_bytes!("../testdata/wallet2_key_images.bin");
    let key_images = KeyImageExport::from_file(&cipher, key_images_file).unwrap();
    assert_eq!(key_images.offset, 0);
    assert_eq!(key_images.spend_public, *account.spend_public());
    assert_eq!(key_images.key_images.len(), 20);
    for (signed, output) in key_images.key_images.iter().zip(&outputs.outputs) {
        assert!(signed.verify(&output.public_key));
        assert_eq!(output.key_image(&account).unwrap().1, signed.key_image);
        let mut other = *signed;
        other.signature[40] ^= 1;
        assert!(!other.verify(&output.public_key));
    }
    // Ours: the same key images, with signatures that verify.
    let ours = outputs.key_images(&account, &mut rng).unwrap();
    assert_eq!(ours.offset, 0);
    for ((ours, theirs), output) in ours
        .key_images
        .iter()
        .zip(&key_images.key_images)
        .zip(&outputs.outputs)
    {
        assert_eq!(ours.key_image, theirs.key_image);
        assert!(ours.verify(&output.public_key));
    }
    let again = ours.to_file(&cipher, &mut rng).unwrap();
    assert_eq!(KeyImageExport::from_file(&cipher, &again).unwrap(), ours);
    let again = key_images.to_file(&cipher, &mut rng).unwrap();
    assert_eq!(
        payload(&cipher, KEY_IMAGE_EXPORT_MAGIC, &again),
        payload(&cipher, KEY_IMAGE_EXPORT_MAGIC, key_images_file)
    );

    // --- the unsigned transaction set ---
    let unsigned_file = fixture(include_str!("../testdata/wallet2_unsigned_tx.hex"));
    let unsigned = UnsignedTxSet::from_file(&cipher, &unsigned_file).unwrap();
    assert_eq!(unsigned.transactions.len(), 1);
    // The view-only wallet had every key image: it describes no output.
    assert_eq!((unsigned.offset, unsigned.total), (20, 20));
    assert!(unsigned.outputs.is_empty());
    let data = &unsigned.transactions[0];
    assert_eq!(data.sources.len(), 2);
    assert_eq!(data.destinations.len(), 1);
    assert_eq!(data.destinations[0].amount, 1_000_000_000_000);
    assert_eq!(data.fee(), Some(2_599_200_000));
    assert_eq!(
        data.change.address(Network::Mainnet),
        account.address(Network::Mainnet)
    );
    let again = unsigned.to_file(&cipher, &mut rng).unwrap();
    assert_eq!(
        payload(&cipher, UNSIGNED_TX_SET_MAGIC, &again),
        payload(&cipher, UNSIGNED_TX_SET_MAGIC, &unsigned_file)
    );

    // --- signing it ---
    let signed = unsigned.sign(&account, &outputs.outputs, &mut rng).unwrap();
    assert_eq!(signed.transactions.len(), 1);
    let pending = &signed.transactions[0];
    assert_eq!(pending.fee, 2_599_200_000);
    assert_eq!(pending.transaction.fee(), Some(2_599_200_000));
    assert_eq!(pending.transaction.verify(&rings(pending)), Ok(true));
    // The key image of every output of the wallet.
    let expected: Vec<[u8; 32]> = key_images
        .key_images
        .iter()
        .map(|signed| signed.key_image)
        .collect();
    assert_eq!(signed.key_images, expected);
    // The inputs spend the outputs selected.
    for index in &data.selected_transfers {
        let key_image = expected[*index as usize];
        assert!(
            pending
                .transaction
                .prefix
                .inputs
                .iter()
                .any(|input| input.key_image() == Some(&key_image))
        );
        assert!(pending.key_images.contains(&hex::encode(key_image)));
    }
    // The change comes back, with its key image.
    let found = account
        .view_keys()
        .scan_transaction(&pending.transaction, &mut |_| None)
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].amount, data.change.amount);
    assert_eq!(signed.tx_key_images.len(), 1);
    assert_eq!(signed.tx_key_images[0].0, found[0].key);
    // The destinations follow the outputs.
    for (output, destination) in pending
        .transaction
        .prefix
        .outputs
        .iter()
        .zip(&pending.construction_data.splitted_destinations)
    {
        assert_eq!(
            output.key == found[0].key,
            destination.spend_public == *account.spend_public()
        );
    }
    // The file does not carry the transaction secret key.
    let file = signed.to_file(&cipher, &mut rng).unwrap();
    let read = SignedTxSet::from_file(&cipher, &file).unwrap();
    assert_eq!(read.transactions[0].transaction, pending.transaction);
    assert_ne!(*read.transactions[0].tx_secret_key, *pending.tx_secret_key);
    assert_eq!(read.key_images, signed.key_images);
    assert_eq!(read.tx_key_images, signed.tx_key_images);

    // Without the outputs before the set's own, nothing can be signed.
    assert_eq!(
        unsigned.sign(&account, &[], &mut rng).unwrap_err(),
        Error::MissingOutputs
    );
    // Another account cannot sign.
    let other = AccountKeys::from_seed(&[9u8; 32]).unwrap();
    assert!(unsigned.sign(&other, &outputs.outputs, &mut rng).is_err());
    // A change that goes elsewhere is refused.
    let mut diverted = unsigned.clone();
    let thief = other.address(Network::Mainnet);
    let tx = &mut diverted.transactions[0];
    for destination in core::iter::once(&mut tx.change)
        .chain(tx.splitted_destinations.iter_mut())
        .filter(|destination| destination.spend_public == *account.spend_public())
    {
        destination.spend_public = thief.spend_public;
        destination.view_public = thief.view_public;
    }
    assert_eq!(
        diverted
            .sign(&account, &outputs.outputs, &mut rng)
            .unwrap_err(),
        Error::InvalidAddress
    );

    // --- the signed set of the reference wallet ---
    let signed_file = fixture(include_str!("../testdata/wallet2_signed_tx.hex"));
    let theirs = SignedTxSet::from_file(&cipher, &signed_file).unwrap();
    assert_eq!(theirs.transactions.len(), 1);
    let pending = &theirs.transactions[0];
    assert_eq!(pending.transaction.verify(&rings(pending)), Ok(true));
    assert_eq!(pending.fee, 2_599_200_000);
    assert_eq!(theirs.key_images, expected);
    assert_eq!(theirs.tx_key_images.len(), 1);
    let again = theirs.to_file(&cipher, &mut rng).unwrap();
    assert_eq!(
        payload(&cipher, SIGNED_TX_SET_MAGIC, &again),
        payload(&cipher, SIGNED_TX_SET_MAGIC, &signed_file)
    );

    // --- outputs on subaddresses, with additional transaction keys ---
    let outputs = OutputExport::from_file(
        &cipher,
        &fixture(include_str!("../testdata/wallet2_outputs_subaddresses.hex")),
    )
    .unwrap();
    assert!(
        outputs
            .outputs
            .iter()
            .any(|output| output.subaddress == SubaddressIndex::new(0, 1)
                && !output.additional_tx_keys.is_empty())
    );
    assert!(
        outputs
            .outputs
            .iter()
            .any(|output| output.subaddress == SubaddressIndex::new(1, 0))
    );
    for output in &outputs.outputs {
        output.key_image(&account).unwrap();
    }
    // Spending from the subaddress (0, 1), to a subaddress and a standard
    // address: the transaction has additional keys.
    let unsigned = UnsignedTxSet::from_file(
        &cipher,
        &fixture(include_str!(
            "../testdata/wallet2_unsigned_tx_subaddresses.hex"
        )),
    )
    .unwrap();
    let signed = unsigned.sign(&account, &outputs.outputs, &mut rng).unwrap();
    let pending = &signed.transactions[0];
    assert_eq!(pending.transaction.verify(&rings(pending)), Ok(true));
    assert_eq!(pending.additional_tx_secret_keys.len(), 3);
    assert_eq!(signed.key_images.len(), outputs.outputs.len());
    assert_eq!(signed.tx_key_images.len(), 1);

    // To an integrated address: the payment id is encrypted for it.
    let unsigned = UnsignedTxSet::from_file(
        &cipher,
        &fixture(include_str!(
            "../testdata/wallet2_unsigned_tx_integrated.hex"
        )),
    )
    .unwrap();
    let data = &unsigned.transactions[0];
    assert!(data.destinations[0].is_integrated);
    let signed = unsigned.sign(&account, &outputs.outputs, &mut rng).unwrap();
    let pending = &signed.transactions[0];
    assert_eq!(pending.transaction.verify(&rings(pending)), Ok(true));
    let Some(PaymentId::Encrypted(encrypted)) = payment_id(&pending.transaction.prefix.extra)
    else {
        panic!("no payment id");
    };
    let derivation = crate::cryptonote::generate_key_derivation(
        &data.destinations[0].view_public,
        &pending.tx_secret_key,
    )
    .unwrap();
    assert_eq!(
        encrypt_payment_id(&derivation, &encrypted),
        [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
    );

    // --- what is not a file ---
    assert_eq!(
        OutputExport::from_file(&cipher, &unsigned_file).unwrap_err(),
        Error::InvalidFile
    );
    assert_eq!(
        UnsignedTxSet::from_file(&cipher, b"Monero unsigned tx set\x05short").unwrap_err(),
        Error::InvalidFile
    );
    let mut damaged = unsigned_file.clone();
    damaged[100] ^= 1;
    assert_eq!(
        UnsignedTxSet::from_file(&cipher, &damaged).unwrap_err(),
        Error::AuthenticationFailed
    );
    // A truncated payload, signed again: every prefix fails cleanly.
    let plain = payload(&cipher, UNSIGNED_TX_SET_MAGIC, &unsigned_file);
    for len in (0..plain.len()).step_by(37) {
        let mut file = UNSIGNED_TX_SET_MAGIC.to_vec();
        file.extend_from_slice(&cipher.encrypt(&plain[..len], &mut rng).unwrap());
        assert_eq!(
            UnsignedTxSet::from_file(&cipher, &file).unwrap_err(),
            Error::InvalidFile
        );
    }
}

#[test]
fn key_image_signature() {
    let mut rng = test_rng(22);
    let secret = crate::cryptonote::sc_reduce32(&[1u8; 32]);
    let key = crate::cryptonote::secret_key_to_public_key(&secret).unwrap();
    let signed = SignedKeyImage::sign(&key, &secret, &mut rng).unwrap();
    assert_eq!(
        signed.key_image,
        crate::cryptonote::generate_key_image(&key, &secret).unwrap()
    );
    assert!(signed.verify(&key));
    let other =
        crate::cryptonote::secret_key_to_public_key(&crate::cryptonote::sc_reduce32(&[2u8; 32]))
            .unwrap();
    assert!(!signed.verify(&other));
    assert_eq!(
        SignedKeyImage::sign(&other, &secret, &mut rng).unwrap_err(),
        Error::KeyMismatch
    );
    let mut bad = signed;
    bad.key_image = other;
    assert!(!bad.verify(&key));
    // A source that writes nothing is refused.
    assert_eq!(
        SignedKeyImage::sign(&key, &secret, &mut |_| {}).unwrap_err(),
        Error::BadRandomness
    );
}

/// The lines of a vector file: the expected hash, then the input in hex
/// (`x` for none).
fn hash_vectors(text: &str) -> Vec<([u8; 32], Vec<u8>)> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut fields = line.split_whitespace();
            let expected = fields.next().unwrap();
            let input = fields.next().unwrap();
            let mut hash = [0u8; 32];
            hex::decode_to_slice(expected, &mut hash).unwrap();
            let input = if input == "x" {
                Vec::new()
            } else {
                hex::decode(input).unwrap()
            };
            (hash, input)
        })
        .collect()
}

#[test]
fn extra_hashes_match_monero_vectors() {
    type Hash = fn(&[u8]) -> [u8; 32];
    let sets: [(&str, Hash, &str); 4] = [
        (
            "blake",
            blake256,
            include_str!("../testdata/monero_extra_blake.txt"),
        ),
        (
            "groestl",
            groestl256,
            include_str!("../testdata/monero_extra_groestl.txt"),
        ),
        ("jh", jh256, include_str!("../testdata/monero_extra_jh.txt")),
        (
            "skein",
            skein512_256,
            include_str!("../testdata/monero_extra_skein.txt"),
        ),
    ];
    for (name, hash, text) in sets {
        let vectors = hash_vectors(text);
        assert_eq!(vectors.len(), 71);
        for (expected, input) in vectors {
            assert_eq!(hash(&input), expected, "{name} of {} bytes", input.len());
        }
    }
}

#[test]
fn slow_hash_matches_one_monero_vector() {
    let vectors = hash_vectors(include_str!("../testdata/monero_slow_hash.txt"));
    let (expected, input) = &vectors[0];
    assert_eq!(cn_slow_hash(input), *expected);
}

#[test]
#[ignore = "slow without optimizations"]
fn slow_hash_matches_monero_vectors() {
    let vectors = hash_vectors(include_str!("../testdata/monero_slow_hash.txt"));
    assert_eq!(vectors.len(), 4);
    for (expected, input) in vectors {
        assert_eq!(cn_slow_hash(&input), expected);
    }
}
