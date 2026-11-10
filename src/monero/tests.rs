//! Tests for the Monero module.
//!
//! - `testdata/monero_view_tags.txt`: the `derive_view_tag` lines of Monero's
//!   `tests/crypto/tests.txt`.
//! - `testdata/mainnet_txs.txt`: real mainnet transactions of every format,
//!   fetched from a public daemon, with the ring members of some.
//! - The address and subaddress vectors are those of the test suites of
//!   `monero-oxide` (`monero-address`) and `monero-rs`.

use super::*;
use crate::cryptonote::{
    EdwardsPoint, Scalar, cn_fast_hash, derivation_to_scalar, derive_public_key,
    generate_key_derivation, secret_key_to_public_key,
};

fn h32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).unwrap_or_else(|e| panic!("bad hex {s:?}: {e}"));
    out
}

/// A deterministic stand-in for a random source: a hash chain.
pub(super) fn test_rng(seed: u8) -> impl FnMut(&mut [u8]) {
    let mut state = [seed; 32];
    move |out: &mut [u8]| {
        for chunk in out.chunks_mut(32) {
            state = cn_fast_hash(&state);
            chunk.copy_from_slice(&state[..chunk.len()]);
        }
    }
}

// --- addresses ---

const SPEND: &str = "f8631661f6ab4e6fda310c797330d86e23a682f20d5bc8cc27b18051191f16d7";
const VIEW: &str = "4a1535063ad1fee2dabbf909d4fd9a873e29541b401f0944754e17c9a41820ce";
const STANDARD: &str = "4B33mFPMq6mKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KQH4pNey";
const PAYMENT_ID: [u8; 8] = [0xb8, 0x96, 0x3a, 0x57, 0x85, 0x5c, 0xf7, 0x3f];
const INTEGRATED: &str = "4Ljin4CrSNHKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KbaTH6MnpXSn88oBX35";
const SUB_SPEND: &str = "fe358188b528335ad1cfdc24a22a23988d742c882b6f19a602892eaab3c1b62b";
const SUB_VIEW: &str = "9bc2b464de90d058468522098d5610c5019c45fd1711a9517db1eea7794f5470";
const SUBADDRESS: &str = "8C5zHM5ud8nGC4hC2ULiBLSWx9infi8JUUmWEat4fcTf8J4H38iWYVdFmPCA9UmfLTZxD43RsyKnGEdZkoGij6csDeUnbEB";

fn encode(address: &Address) -> std::string::String {
    let mut buf = [0u8; MAX_ADDRESS_LEN];
    let n = address.encode_to_slice(&mut buf).unwrap();
    assert_eq!(n, address.encoded_len());
    std::str::from_utf8(&buf[..n]).unwrap().into()
}

/// The vectors of `monero-address`.
#[test]
fn address_vectors() {
    let standard = Address::decode(STANDARD).unwrap();
    assert_eq!(
        standard,
        Address::standard(Network::Mainnet, h32(SPEND), h32(VIEW))
    );
    assert_eq!(encode(&standard), STANDARD);
    assert_eq!(standard.payment_id(), None);
    assert!(!standard.is_subaddress());

    let integrated = Address::decode(INTEGRATED).unwrap();
    assert_eq!(
        integrated,
        Address::integrated(Network::Mainnet, h32(SPEND), h32(VIEW), PAYMENT_ID)
    );
    assert_eq!(encode(&integrated), INTEGRATED);
    assert_eq!(integrated.payment_id(), Some(PAYMENT_ID));
    assert_eq!(standard.with_payment_id(PAYMENT_ID).unwrap(), integrated);

    let sub = Address::decode(SUBADDRESS).unwrap();
    assert_eq!(
        sub,
        Address::subaddress(Network::Mainnet, h32(SUB_SPEND), h32(SUB_VIEW))
    );
    assert_eq!(encode(&sub), SUBADDRESS);
    assert!(sub.is_subaddress());
    assert_eq!(sub.with_payment_id(PAYMENT_ID), Err(Error::InvalidAddress));

    // Display and FromStr.
    use std::string::ToString;
    for text in [STANDARD, INTEGRATED, SUBADDRESS] {
        let address: Address = text.parse().unwrap();
        assert_eq!(address.to_string(), text);
    }
}

/// Every network and kind has its own prefix, and decoding finds them back.
#[test]
fn address_networks() {
    let (spend, view) = (h32(SPEND), h32(VIEW));
    let cases = [
        (Network::Mainnet, [18u64, 19, 42]),
        (Network::Testnet, [53, 54, 63]),
        (Network::Stagenet, [24, 25, 36]),
    ];
    for (network, prefixes) in cases {
        let addresses = [
            Address::standard(network, spend, view),
            Address::integrated(network, spend, view, PAYMENT_ID),
            Address::subaddress(network, spend, view),
        ];
        for (address, prefix) in addresses.iter().zip(prefixes) {
            assert_eq!(address.prefix(), prefix);
            let text = encode(address);
            assert_eq!(Address::decode(&text).unwrap(), *address);
            // The same through the shared framing.
            let mut raw = [0u8; 80];
            let (p, n) = crate::cryptonote::decode_address_to_slice(&text, &mut raw).unwrap();
            assert_eq!(
                (p, n),
                (prefix, if prefix == prefixes[1] { 72 } else { 64 })
            );
        }
    }
    // Mainnet addresses start with 4 or, for subaddresses, 8.
    assert!(STANDARD.starts_with('4') && INTEGRATED.starts_with('4'));
    assert!(SUBADDRESS.starts_with('8'));
}

#[test]
fn address_rejections() {
    // A buffer too small.
    let standard = Address::decode(STANDARD).unwrap();
    assert_eq!(
        standard.encode_to_slice(&mut [0u8; 94]),
        Err(Error::CryptoNote(crate::cryptonote::Error::BufferTooSmall))
    );
    // A changed character breaks the checksum.
    let mut bad = std::string::String::from(STANDARD);
    bad.replace_range(10..11, "A");
    assert_eq!(
        Address::decode(&bad),
        Err(Error::CryptoNote(crate::cryptonote::Error::BadChecksum))
    );
    // Too long, empty, not base58.
    let long = "4".repeat(MAX_ADDRESS_LEN + 1);
    assert_eq!(Address::decode(&long), Err(Error::InvalidAddress));
    assert!(Address::decode("").is_err());
    assert!(Address::decode("0OIl").is_err());

    // A valid frame with an unknown prefix, a wrong payload length, or keys
    // that are not points.
    let frame = |prefix: u64, payload: &[u8]| {
        let mut buf = [0u8; 120];
        let n = crate::cryptonote::encode_address_to_slice(prefix, payload, &mut buf).unwrap();
        std::string::String::from_utf8(buf[..n].to_vec()).unwrap()
    };
    let mut keys = [0u8; 72];
    keys[..32].copy_from_slice(&h32(SPEND));
    keys[32..64].copy_from_slice(&h32(VIEW));
    assert!(Address::decode(&frame(18, &keys[..64])).is_ok());
    assert!(Address::decode(&frame(19, &keys)).is_ok());
    assert_eq!(
        Address::decode(&frame(17, &keys[..64])),
        Err(Error::InvalidAddress)
    );
    assert_eq!(
        Address::decode(&frame(18, &keys)),
        Err(Error::InvalidAddress)
    );
    assert_eq!(
        Address::decode(&frame(19, &keys[..64])),
        Err(Error::InvalidAddress)
    );
    assert_eq!(
        Address::decode(&frame(42, &keys[..63])),
        Err(Error::InvalidAddress)
    );
    // y = 2 is not on the curve.
    let mut not_a_point = keys;
    not_a_point[..32].copy_from_slice(&{
        let mut k = [0u8; 32];
        k[0] = 2;
        k
    });
    assert!(!crate::cryptonote::check_key(
        &not_a_point[..32].try_into().unwrap()
    ));
    assert_eq!(
        Address::decode(&frame(18, &not_a_point[..64])),
        Err(Error::InvalidAddress)
    );
}

// --- keys ---

/// The subaddress vectors of `monero-rs`.
#[test]
fn subaddress_vectors() {
    let view = h32("77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404");
    let spend = h32("8163466f1883598e6dd14027b8da727057165da91485834314f5500a65846f09");
    let account = AccountKeys::from_secret_keys(&spend, &view).unwrap();
    let index = SubaddressIndex::new(2, 18);
    let (sub_spend, sub_view) = account.view_keys().subaddress_keys(index);
    assert_eq!(
        sub_view,
        h32("601782bdde614e9ba664048a27b7407df4b76ae2e50a85fcc168a4c1766b3edf")
    );
    assert_eq!(
        sub_spend,
        h32("c25179ddef2ca4728fb691dd71561dc9f2e7e6b2a14284a4fe5441d7757aea02")
    );
    assert_eq!(
        account.view_keys().subaddress_spend_public(index),
        sub_spend
    );
    assert_eq!(
        encode(&account.subaddress(Network::Mainnet, index)),
        "89pMNxzcCo5LAPZDX4qaTeanA6ZiS3VRdUbeKHzbDZkD1Q3YsDDfmXbT2zyjLeHWuuN4vxKne8kNpjH3cMk7nmhwSALCxsd"
    );

    // The secret spend key of the subaddress is the secret of its public key.
    let sub_secret = account.subaddress_spend_secret(index);
    assert_eq!(secret_key_to_public_key(&sub_secret).unwrap(), sub_spend);

    // (0, 0) is the main address.
    let main = account.subaddress(Network::Mainnet, SubaddressIndex::MAIN);
    assert_eq!(main, account.address(Network::Mainnet));
    assert_eq!(main.kind, AddressKind::Standard);
    assert_eq!(
        *account.subaddress_spend_secret(SubaddressIndex::MAIN),
        spend
    );
}

#[test]
fn account_keys() {
    // The deterministic wallet of the cryptonote tests' vector.
    let spend = h32("77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404");
    let account = AccountKeys::from_spend_secret(&spend).unwrap();
    assert_eq!(
        *account.view_secret(),
        *crate::cryptonote::derive_view_secret_key(&spend)
    );
    assert_eq!(
        *account.spend_public(),
        secret_key_to_public_key(&spend).unwrap()
    );
    assert_eq!(
        account.view_public(),
        secret_key_to_public_key(account.view_secret()).unwrap()
    );
    let address = account.address(Network::Stagenet);
    assert_eq!(address.spend_public, *account.spend_public());
    assert_eq!(address.view_public, account.view_public());

    // A seed is reduced first.
    let seed = [0xffu8; 32];
    assert!(AccountKeys::from_spend_secret(&seed).is_err());
    let from_seed = AccountKeys::from_seed(&seed).unwrap();
    assert_eq!(
        *from_seed.spend_secret(),
        crate::cryptonote::sc_reduce32(&seed)
    );

    // View-only.
    let view_only = ViewKeys::new(account.view_secret(), account.spend_public()).unwrap();
    assert_eq!(view_only.address(Network::Stagenet), address);
    assert!(ViewKeys::new(&seed, account.spend_public()).is_err());
    let mut bad_point = [0u8; 32];
    bad_point[0] = 2;
    assert!(ViewKeys::new(account.view_secret(), &bad_point).is_err());

    // The donation address of the Monero project and its published secret
    // view key.
    let donation: Address = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
        .parse()
        .unwrap();
    let donation_view = h32("f359631075708155cc3d92a32b75a7d02a5dcf27756707b47a2b31b21c389501");
    let watch = ViewKeys::new(&donation_view, &donation.spend_public).unwrap();
    assert_eq!(watch.address(Network::Mainnet), donation);

    // Secrets stay out of Debug output.
    let debug = std::format!("{account:?} {view_only:?}");
    assert!(!debug.contains("view_secret") && !debug.contains("spend_secret"));
}

// --- the mnemonic ---

/// The English vectors of `monero-wallet-util`'s seed tests.
#[test]
fn mnemonic_vectors() {
    let vectors = [
        (
            "washing thirsty occur lectures tuesday fainted toxic adapt \
             abnormal memoir nylon mostly building shrugged online ember northern \
             ruby woes dauntless boil family illness inroads northern",
            "c0af65c0dd837e666b9d0dfed62745f4df35aed7ea619b2798a709f0fe545403",
            "513ba91c538a5a9069e0094de90e927c0cd147fa10428ce3ac1afd49f63e3b01",
        ),
        (
            "plus plus plus plus plus plus plus plus \
             plus plus plus plus plus plus plus plus \
             plus plus plus plus plus plus plus plus plus",
            "3b0400003b0400003b0400003b0400003b0400003b0400003b0400003b040000",
            "43a8a7715eed11eff145a2024ddcc39740255156da7bbd736ee66a0838053a02",
        ),
        (
            "audio audio audio audio audio audio audio audio \
             audio audio audio audio audio audio audio audio \
             audio audio audio audio audio audio audio audio audio",
            "7900000079000000790000007900000079000000790000007900000079000000",
            "20bec797ab96780ae6a045dd816676ca7ed1d7c6773f7022d03ad234b581d600",
        ),
    ];
    for (mnemonic, spend, view) in vectors {
        let seed = seed_from_mnemonic(mnemonic).unwrap();
        let account = AccountKeys::from_seed(&seed).unwrap();
        assert_eq!(*account.spend_secret(), h32(spend));
        assert_eq!(*account.view_secret(), h32(view));

        let words = seed_to_mnemonic_words(&seed);
        let want: std::vec::Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.as_slice(), want.as_slice());
        #[cfg(feature = "alloc")]
        assert_eq!(*seed_to_mnemonic(&seed), want.join(" "));

        // Three letters identify a word; case does not matter.
        let short: std::vec::Vec<std::string::String> = want
            .iter()
            .map(|word| word[..3].to_ascii_uppercase())
            .collect();
        assert_eq!(*seed_from_mnemonic(&short.join("\t")).unwrap(), *seed);
    }

    // Every seed comes back.
    let mut rng = test_rng(5);
    for _ in 0..20 {
        let mut seed = [0u8; 32];
        rng(&mut seed);
        let words = seed_to_mnemonic_words(&seed);
        assert_eq!(*seed_from_mnemonic(&words.join(" ")).unwrap(), seed);
    }
    for seed in [[0u8; 32], [0xff; 32]] {
        let words = seed_to_mnemonic_words(&seed);
        assert_eq!(*seed_from_mnemonic(&words.join(" ")).unwrap(), seed);
    }

    // Rejections: the count, an unknown word, the checksum.
    let good: std::vec::Vec<&str> = vectors[0].0.split_whitespace().collect();
    let bad = |words: &[&str]| {
        assert_eq!(
            seed_from_mnemonic(&words.join(" ")).unwrap_err(),
            Error::InvalidMnemonic,
            "{words:?}"
        );
    };
    bad(&good[..24]);
    bad(&[&good[..], &["northern"]].concat());
    bad(&[]);
    let mut words = good.clone();
    words[3] = "xyzzy";
    bad(&words);
    words[3] = "ab";
    bad(&words);
    let mut words = good.clone();
    words[24] = "washing";
    bad(&words);
    let mut words = good.clone();
    words.swap(0, 1);
    bad(&words);
    // Three words hold a little more than 32 bits: the first word, then the
    // last, then the one before it, stand for
    // 0 + 1625 * 1626 + 1625 * 1626^2, which does not fit. The value check
    // must fail whatever the checksum word is.
    let overflow = ["abbey", "zoom", "zones"];
    let mut words: std::vec::Vec<&str> = overflow.iter().cycle().take(24).copied().collect();
    for candidate in overflow {
        words.truncate(24);
        words.push(candidate);
        bad(&words);
    }
}

// --- scanning primitives ---

/// The `derive_view_tag` vectors of Monero's `tests/crypto/tests.txt`.
#[test]
fn view_tag_vectors() {
    let mut count = 0;
    for line in include_str!("testdata/monero_view_tags.txt").lines() {
        let f: std::vec::Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f[0], "derive_view_tag");
        let index: u64 = f[2].parse().unwrap();
        let tag = u8::from_str_radix(f[3], 16).unwrap();
        assert_eq!(derive_view_tag(&h32(f[1]), index), tag, "{line}");
        count += 1;
    }
    assert_eq!(count, 70);
}

/// The constants are what Monero derives them from.
#[test]
fn generator_h() {
    let g = EdwardsPoint::generator().compress();
    let h = EdwardsPoint::decompress(&cn_fast_hash(&g))
        .unwrap()
        .mul_by_cofactor();
    assert_eq!(h.compress(), H);
    assert_eq!(ringct::h_point(), h);
    let eight = crate::cryptonote::scalar_from_u64(8);
    assert_eq!(ringct::inv_eight().mul(&eight), Scalar::ONE);

    // commit and zero_commit.
    let mut one = [0u8; 32];
    one[0] = 1;
    assert_eq!(commit(0, &one).unwrap(), g);
    assert_eq!(commit(1, &[0u8; 32]).unwrap(), H);
    assert_eq!(commit(12345, &one).unwrap(), zero_commit(12345));
    assert!(commit(1, &[0xff; 32]).is_err());
}

/// The multi-scalar multiplication against plain scalar multiplications, in
/// both modes and across group boundaries.
#[test]
fn multiexp_matches_naive() {
    let mut rng = test_rng(7);
    for count in [0usize, 1, 2, 3, 5] {
        let mut scalars = std::vec::Vec::new();
        let mut points = std::vec::Vec::new();
        let mut want = EdwardsPoint::identity();
        for i in 0..count {
            let s = if i == 1 {
                Scalar::ZERO
            } else {
                random_scalar(&mut rng).unwrap()
            };
            let p = EdwardsPoint::mul_base(&random_scalar(&mut rng).unwrap());
            want = want.add(&p.mul(&s));
            scalars.push(s);
            points.push(p);
        }
        for constant_time in [false, true] {
            let mut tables = [ringct::Table::new(), ringct::Table::new()];
            let got = ringct::multiexp(&scalars, &points, &mut tables, constant_time);
            assert_eq!(got, want, "{count} {constant_time}");
        }
    }
    // Small and extreme scalars.
    let p = EdwardsPoint::generator();
    let minus_one = Scalar::ZERO.sub(&Scalar::ONE);
    let mut tables = [ringct::Table::new()];
    for constant_time in [false, true] {
        let got = ringct::multiexp(
            &[minus_one.clone(), Scalar::ONE],
            &[p, p],
            &mut tables,
            constant_time,
        );
        assert_eq!(got, EdwardsPoint::identity());
    }
}

/// The sender's and the recipient's sides of an output agree, for the main
/// address and for a subaddress.
#[test]
fn output_round_trip() {
    let mut rng = test_rng(1);
    let account = AccountKeys::from_seed(&[0x42; 32]).unwrap();
    let view = account.view_keys();
    let index = SubaddressIndex::new(1, 7);
    let sub_spend = view.subaddress_spend_public(index);
    let mut lookup = |key: &[u8; 32]| (*key == sub_spend).then_some(index);

    let tx_secret = random_secret(&mut rng).unwrap();
    for (subaddress, output_index) in [(SubaddressIndex::MAIN, 0u64), (index, 3)] {
        let (spend_public, view_public) = view.subaddress_keys(subaddress);
        // R = r * G for a standard address, r * D for a subaddress.
        let tx_public = if subaddress.is_main() {
            secret_key_to_public_key(&tx_secret).unwrap()
        } else {
            let r = crate::cryptonote::scalar_from_bytes(&tx_secret).unwrap();
            EdwardsPoint::decompress(&spend_public)
                .unwrap()
                .mul(&r)
                .compress()
        };
        let sender_derivation = generate_key_derivation(&view_public, &tx_secret).unwrap();
        let output_key =
            derive_public_key(&sender_derivation, output_index, &spend_public).unwrap();
        let tag = derive_view_tag(&sender_derivation, output_index);
        let shared = derivation_to_scalar(&sender_derivation, output_index);
        let amount = 123_456_789_000u64;
        let encrypted = encrypt_amount(&shared, amount);
        let mask = commitment_mask(&shared);
        let commitment = commit(amount, &mask).unwrap();

        // The recipient.
        let derivation = view.key_derivation(&tx_public).unwrap();
        assert_eq!(*derivation, sender_derivation);
        assert_eq!(
            derive_subaddress_public_key(&output_key, &derivation, output_index).unwrap(),
            spend_public
        );
        for view_tag in [None, Some(tag)] {
            let found = view
                .check_output(
                    &derivation,
                    output_index,
                    &output_key,
                    view_tag,
                    &mut lookup,
                )
                .unwrap();
            assert_eq!(found, Some(subaddress));
        }
        // A wrong view tag, a wrong index.
        assert_eq!(
            view.check_output(
                &derivation,
                output_index,
                &output_key,
                Some(tag ^ 1),
                &mut lookup
            )
            .unwrap(),
            None
        );
        assert_eq!(
            view.check_output(
                &derivation,
                output_index + 1,
                &output_key,
                None,
                &mut lookup
            )
            .unwrap(),
            None
        );

        let opened = decode_amount(&derivation, output_index, &encrypted, &commitment).unwrap();
        assert_eq!(opened.amount, amount);
        assert_eq!(*opened.mask, *mask);
        assert_eq!(decrypt_amount(&shared, &encrypted), amount);
        let mut wrong = commitment;
        wrong[0] ^= 1;
        assert!(decode_amount(&derivation, output_index, &encrypted, &wrong).is_err());

        // The spend side.
        let (secret, image) = account
            .output_key_image(&derivation, output_index, subaddress, &output_key)
            .unwrap();
        assert_eq!(secret_key_to_public_key(&secret).unwrap(), output_key);
        assert_eq!(
            image,
            crate::cryptonote::generate_key_image(&output_key, &secret).unwrap()
        );
        let other = SubaddressIndex::new(9, 9);
        assert_eq!(
            account
                .output_key_image(&derivation, output_index, other, &output_key)
                .unwrap_err(),
            Error::KeyMismatch
        );

        // The payment id.
        let id = [1, 2, 3, 4, 5, 6, 7, 8];
        let encrypted_id = encrypt_payment_id(&sender_derivation, &id);
        assert_ne!(encrypted_id, id);
        assert_eq!(
            view.decrypt_payment_id(&tx_public, &encrypted_id).unwrap(),
            id
        );
    }
}

// --- the extra field ---

#[test]
fn extra_fields() {
    let key = h32(SPEND);
    let mut extra = std::vec::Vec::new();
    extra.push(TX_EXTRA_TAG_PUBKEY);
    extra.extend_from_slice(&key);
    extra.extend_from_slice(&[TX_EXTRA_TAG_NONCE, 9, 1, 1, 2, 3, 4, 5, 6, 7, 8]);
    extra.extend_from_slice(&[TX_EXTRA_TAG_ADDITIONAL_PUBKEYS, 2]);
    extra.extend_from_slice(&h32(VIEW));
    extra.extend_from_slice(&h32(SUB_SPEND));
    extra.extend_from_slice(&[TX_EXTRA_TAG_MERGE_MINING, 33, 5]);
    extra.extend_from_slice(&h32(SUB_VIEW));
    extra.extend_from_slice(&[TX_EXTRA_TAG_MYSTERIOUS_MINERGATE, 2, 0xaa, 0xbb]);
    extra.extend_from_slice(&[TX_EXTRA_TAG_PADDING, 0, 0]);

    let fields: std::vec::Vec<_> = parse_extra(&extra).collect::<Result<_, _>>().unwrap();
    assert_eq!(fields.len(), 6);
    assert_eq!(fields[0], ExtraField::PublicKey(key));
    assert_eq!(fields[1], ExtraField::Nonce(&[1, 1, 2, 3, 4, 5, 6, 7, 8]));
    let additional: std::vec::Vec<_> = fields[2].additional_keys().collect();
    assert_eq!(additional, [h32(VIEW), h32(SUB_SPEND)]);
    assert_eq!(fields[0].additional_keys().len(), 0);
    assert_eq!(
        fields[3],
        ExtraField::MergeMining {
            depth: 5,
            merkle_root: h32(SUB_VIEW)
        }
    );
    assert_eq!(fields[4], ExtraField::MysteriousMinergate(&[0xaa, 0xbb]));
    assert_eq!(fields[5], ExtraField::Padding(2));

    assert_eq!(tx_public_key(&extra), Some(key));
    assert_eq!(tx_public_keys(&extra).count(), 1);
    assert_eq!(additional_public_keys(&extra).len(), 64);
    assert_eq!(additional_public_key(&extra, 2, 1), Some(h32(SUB_SPEND)));
    assert_eq!(additional_public_key(&extra, 2, 2), None);
    // Ignored unless there is one per output.
    assert_eq!(additional_public_key(&extra, 3, 1), None);
    assert_eq!(
        payment_id(&extra),
        Some(PaymentId::Encrypted([1, 2, 3, 4, 5, 6, 7, 8]))
    );

    let mut long_id = std::vec![TX_EXTRA_TAG_NONCE, 33, 0];
    long_id.extend_from_slice(&key);
    assert_eq!(payment_id(&long_id), Some(PaymentId::Unencrypted(key)));
    assert_eq!(PaymentId::from_nonce(&[1, 2, 3]), None);
    assert_eq!(PaymentId::from_nonce(&[7; 9]), None);
    assert_eq!(PaymentId::from_nonce(&[]), None);

    // Malformed entries end the iteration with an error, and the helpers
    // keep what came before.
    let cases: [(&[u8], Error); 8] = [
        (&[TX_EXTRA_TAG_PUBKEY, 1, 2], Error::UnexpectedEof),
        (&[TX_EXTRA_TAG_NONCE, 5, 1], Error::UnexpectedEof),
        (
            &[TX_EXTRA_TAG_NONCE],
            Error::CryptoNote(crate::cryptonote::Error::UnexpectedEof),
        ),
        (&[TX_EXTRA_TAG_PADDING, 0, 1], Error::InvalidExtra),
        (&[0x05, 0], Error::InvalidExtra),
        (
            &[TX_EXTRA_TAG_ADDITIONAL_PUBKEYS, 1, 0],
            Error::UnexpectedEof,
        ),
        (
            &[
                TX_EXTRA_TAG_ADDITIONAL_PUBKEYS,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0x01,
            ],
            Error::UnexpectedEof,
        ),
        (&[TX_EXTRA_TAG_MERGE_MINING, 2, 5, 0], Error::UnexpectedEof),
    ];
    for (bytes, error) in cases {
        let mut data = extra.clone();
        // Drop the padding, which would swallow what follows.
        data.truncate(data.len() - 3);
        data.extend_from_slice(bytes);
        let mut iter = parse_extra(&data);
        let last = iter.by_ref().last().unwrap();
        assert_eq!(last, Err(error), "{bytes:02x?}");
        assert_eq!(iter.next(), None);
        assert_eq!(tx_public_key(&data), Some(key));
    }
    // Padding longer than 255 bytes.
    let mut padded = std::vec![TX_EXTRA_TAG_PADDING];
    padded.extend_from_slice(&[0u8; 256]);
    assert_eq!(parse_extra(&padded).next(), Some(Err(Error::InvalidExtra)));
    assert_eq!(parse_extra(&[]).next(), None);
}

// --- CLSAG ---

/// A ring of `n` outputs with the real one at `real`, its secret key and
/// mask, and a pseudo-output commitment to the same amount.
fn make_ring(
    rng: &mut dyn FnMut(&mut [u8]),
    n: usize,
    real: usize,
) -> (std::vec::Vec<RingMember>, [u8; 32], [u8; 32], [u8; 32]) {
    let amount = 5_000_000u64;
    let secret = random_scalar(rng).unwrap();
    let mask = random_scalar(rng).unwrap();
    let pseudo_mask = random_scalar(rng).unwrap();
    let mut ring = std::vec::Vec::new();
    for i in 0..n {
        if i == real {
            ring.push(RingMember {
                key: EdwardsPoint::mul_base(&secret).compress(),
                commitment: commit(amount, &mask.to_bytes()).unwrap(),
            });
        } else {
            ring.push(RingMember {
                key: EdwardsPoint::mul_base(&random_scalar(rng).unwrap()).compress(),
                commitment: EdwardsPoint::mul_base(&random_scalar(rng).unwrap()).compress(),
            });
        }
    }
    let pseudo_out = commit(amount, &pseudo_mask.to_bytes()).unwrap();
    (
        ring,
        secret.to_bytes(),
        mask.sub(&pseudo_mask).to_bytes(),
        pseudo_out,
    )
}

#[test]
fn clsag_sign_and_verify() {
    let mut rng = test_rng(3);
    let message = cn_fast_hash(b"message");
    for (n, real) in [(1usize, 0usize), (2, 0), (2, 1), (4, 2), (16, 15), (16, 0)] {
        let (ring, secret, z, pseudo_out) = make_ring(&mut rng, n, real);
        let mut responses = std::vec![[0u8; 32]; n];
        let (parts, key_image) = clsag_sign(
            &message,
            &ring,
            real,
            &secret,
            &z,
            &pseudo_out,
            &mut rng,
            &mut responses,
        )
        .unwrap();
        assert_eq!(
            key_image,
            crate::cryptonote::generate_key_image(&ring[real].key, &secret).unwrap()
        );
        assert!(
            clsag_verify(&message, &ring, &key_image, &pseudo_out, &responses, &parts),
            "{n} {real}"
        );

        // Anything changed breaks it.
        let other = cn_fast_hash(b"other");
        assert!(!clsag_verify(
            &other,
            &ring,
            &key_image,
            &pseudo_out,
            &responses,
            &parts
        ));
        let mut bad = responses.clone();
        bad[n - 1][0] ^= 1;
        assert!(!clsag_verify(
            &message,
            &ring,
            &key_image,
            &pseudo_out,
            &bad,
            &parts
        ));
        let mut bad = parts;
        bad.c1[0] ^= 1;
        assert!(!clsag_verify(
            &message,
            &ring,
            &key_image,
            &pseudo_out,
            &responses,
            &bad
        ));
        let mut bad = ring.clone();
        bad[0].commitment = bad[0].key;
        assert!(!clsag_verify(
            &message,
            &bad,
            &key_image,
            &pseudo_out,
            &responses,
            &parts
        ));
        let other_image = EdwardsPoint::generator().compress();
        assert!(!clsag_verify(
            &message,
            &ring,
            &other_image,
            &pseudo_out,
            &responses,
            &parts
        ));
        let other_out = H;
        assert!(!clsag_verify(
            &message, &ring, &key_image, &other_out, &responses, &parts
        ));
        assert!(!clsag_verify(
            &message,
            &ring,
            &key_image,
            &pseudo_out,
            &responses[1..],
            &parts
        ));
        assert!(!clsag_verify(
            &message,
            &[],
            &key_image,
            &pseudo_out,
            &[],
            &parts
        ));

        // Signing with the wrong secrets or shape.
        let sign = |real: usize, secret: &[u8; 32], z: &[u8; 32], len: usize| {
            let mut responses = std::vec![[0u8; 32]; len];
            clsag_sign(
                &message,
                &ring,
                real,
                secret,
                z,
                &pseudo_out,
                &mut test_rng(9),
                &mut responses,
            )
            .map(|_| ())
        };
        assert_eq!(sign(real, &z, &z, n), Err(Error::KeyMismatch));
        assert_eq!(sign(real, &secret, &secret, n), Err(Error::KeyMismatch));
        assert_eq!(sign(n, &secret, &z, n), Err(Error::InvalidRing));
        assert_eq!(sign(real, &secret, &z, n + 1), Err(Error::InvalidRing));
        if n > 1 {
            let wrong = if real == 0 { 1 } else { 0 };
            assert_eq!(sign(wrong, &secret, &z, n), Err(Error::KeyMismatch));
        }
    }
}

#[test]
fn bad_randomness_is_detected() {
    let (ring, secret, z, pseudo_out) = make_ring(&mut test_rng(4), 2, 0);
    let mut responses = [[0u8; 32]; 2];
    let result = clsag_sign(
        &[0u8; 32],
        &ring,
        0,
        &secret,
        &z,
        &pseudo_out,
        &mut |_out: &mut [u8]| {},
        &mut responses,
    );
    assert_eq!(result.unwrap_err(), Error::BadRandomness);
}

#[test]
fn error_conversion() {
    let e: crate::Error = Error::InvalidAddress.into();
    assert_eq!(e, crate::Error::Monero(Error::InvalidAddress));
    let e: Error = crate::cryptonote::Error::InvalidPoint.into();
    assert_eq!(e, Error::CryptoNote(crate::cryptonote::Error::InvalidPoint));
    use std::string::ToString;
    assert_eq!(e.to_string(), "invalid curve point");
    assert_eq!(Error::TrailingData.to_string(), "trailing data");
}

#[cfg(feature = "alloc")]
mod build;
#[cfg(feature = "alloc")]
mod with_alloc;
