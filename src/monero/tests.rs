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

/// The vectors of `monero-wallet-util`'s seed tests ("test against
/// Monero"): a mnemonic in each language with the keys the reference wallet
/// derives from it.
#[test]
fn mnemonic_language_vectors() {
    use MnemonicLanguage::*;
    let vectors = [
        (
            ChineseSimplified,
            "摇 曲 艺 武 滴 然 效 似 赏 式 祥 歌 买 疑 小 碧 堆 博 键 房 鲜 悲 付 喷 武",
            "a5e4fff1706ef9212993a69f246f5c95ad6d84371692d63e9bb0ea112a58340d",
            "1176c43ce541477ea2f3ef0b49b25112b084e26b8a843e1304ac4677b74cdf02",
        ),
        (
            English,
            "washing thirsty occur lectures tuesday fainted toxic adapt \
             abnormal memoir nylon mostly building shrugged online ember northern \
             ruby woes dauntless boil family illness inroads northern",
            "c0af65c0dd837e666b9d0dfed62745f4df35aed7ea619b2798a709f0fe545403",
            "513ba91c538a5a9069e0094de90e927c0cd147fa10428ce3ac1afd49f63e3b01",
        ),
        (
            Dutch,
            "setwinst riphagen vimmetje extase blief tuitelig fuiven meifeest \
             ponywagen zesmaal ripdeal matverf codetaal leut ivoor rotten \
             wisgerhof winzucht typograaf atrium rein zilt traktaat verzaagd setwinst",
            "e2d2873085c447c2bc7664222ac8f7d240df3aeac137f5ff2022eaa629e5b10a",
            "eac30b69477e3f68093d131c7fd961564458401b07f8c87ff8f6030c1a0c7301",
        ),
        (
            French,
            "poids vaseux tarte bazar poivre effet entier nuance \
             sensuel ennui pacte osselet poudre battre alibi mouton \
             stade paquet pliage gibier type question position projet pliage",
            "2dd39ff1a4628a94b5c2ec3e42fb3dfe15c2b2f010154dc3b3de6791e805b904",
            "6725b32230400a1032f31d622b44c3a227f88258939b14a7c72e00939e7bdf0e",
        ),
        (
            Spanish,
            "minero ocupar mirar evadir octubre cal logro miope \
             opaco disco ancla litio clase cuello nasal clase \
             fiar avance deseo mente grumo negro cordón croqueta clase",
            "ae2c9bebdddac067d73ec0180147fc92bdf9ac7337f1bcafbbe57dd13558eb02",
            "18deafb34d55b7a43cae2c1c1c206a3c80c12cc9d1f84640b484b95b7fec3e05",
        ),
        (
            German,
            "Kaliber Gabelung Tapir Liveband Favorit Specht Enklave Nabel \
             Jupiter Foliant Chronik nisten löten Vase Aussage Rekord \
             Yeti Gesetz Eleganz Alraune Künstler Almweide Jahr Kastanie Almweide",
            "79801b7a1b9796856e2397d862a113862e1fdc289a205e79d8d70995b276db06",
            "99f0ec556643bd9c038a4ed86edcb9c6c16032c4622ed2e000299d527a792701",
        ),
        (
            Italian,
            "cavo pancetta auto fulmine alleanza filmato diavolo prato \
             forzare meritare litigare lezione segreto evasione votare buio \
             licenza cliente dorso natale crescere vento tutelare vetta evasione",
            "5e7fd774eb00fa5877e2a8b4dc9c7ffe111008a3891220b56a6e49ac816d650a",
            "698a1dce6018aef5516e82ca0cb3e3ec7778d17dfb41a137567bfa2e55e63a03",
        ),
        (
            Portuguese,
            "agito eventualidade onus itrio holograma sodomizar objetos dobro \
             iugoslavo bcrepuscular odalisca abjeto iuane darwinista eczema acetona \
             cibernetico hoquei gleba driver buffer azoto megera nogueira agito",
            "13b3115f37e35c6aa1db97428b897e584698670c1b27854568d678e729200c0f",
            "ad1b4fd35270f5f36c4da7166672b347e75c3f4d41346ec2a06d1d0193632801",
        ),
        (
            Japanese,
            "ぜんぶ どうぐ おたがい せんきょ おうじ そんちょう じゅしん いろえんぴつ \
             かほう つかれる えらぶ にちじょう くのう にちようび ぬまえび さんきゃく \
             おおや ちぬき うすめる いがく せつでん さうな すいえい せつだん おおや",
            "c56e895cdb13007eda8399222974cdbab493640663804b93cbef3d8c3df80b0b",
            "6c3634a313ec2ee979d565c33888fd7c3502d696ce0134a8bc1a2698c7f2c508",
        ),
        (
            Russian,
            "шатер икра нация ехать получать инерция доза реальный \
             рыжий таможня лопата душа веселый клетка атлас лекция \
             обгонять паек наивный лыжный дурак стать ежик задача паек",
            "7cb5492df5eb2db4c84af20766391cd3e3662ab1a241c70fc881f3d02c381f05",
            "fcd53e41ec0df995ab43927f7c44bc3359c93523d5009fb3f5ba87431d545a03",
        ),
        (
            Esperanto,
            "ukazo klini peco etikedo fabriko imitado onklino urino \
             pudro incidento kumuluso ikono smirgi hirundo uretro krii \
             sparkado super speciala pupo alpinisto cvana vokegi zombio fabriko",
            "82ebf0336d3b152701964ed41df6b6e9a035e57fc98b84039ed0bd4611c58904",
            "cd4d120e1ea34360af528f6a3e6156063312d9cefc9aa6b5218d366c0ed6a201",
        ),
        (
            Lojban,
            "jetnu vensa julne xrotu xamsi julne cutci dakli \
             mlatu xedja muvgau palpi xindo sfubu ciste cinri \
             blabi darno dembi janli blabi fenki bukpu burcu blabi",
            "e4f8c6819ab6cf792cebb858caabac9307fd646901d72123e0367ebc0a79c200",
            "c806ce62bafaa7b2d597f1a1e2dbe4a2f96bfd804bf6f8420fc7f4a6bd700c00",
        ),
        // Mnemonics that are valid in two languages, for different seeds.
        (
            Spanish,
            "pluma laico atraer pintor peor cerca balde buscar \
             lancha batir nulo reloj resto gemelo nevera poder columna gol \
             oveja latir amplio bolero feliz fuerza nevera",
            "30303983fc8d215dd020cc6b8223793318d55c466a86e4390954f373fdc7200a",
            "97c649143f3c147ba59aa5506cc09c7992c5c219bb26964442142bf97980800e",
        ),
        (
            Spanish,
            "pluma pluma pluma pluma pluma pluma pluma pluma \
             pluma pluma pluma pluma pluma pluma pluma pluma \
             pluma pluma pluma pluma pluma pluma pluma pluma pluma",
            "b4050000b4050000b4050000b4050000b4050000b4050000b4050000b4050000",
            "d73534f7912b395eb70ef911791a2814eb6df7ce56528eaaa83ff2b72d9f5e0f",
        ),
        (
            Spanish,
            "audio audio audio audio audio audio audio audio \
             audio audio audio audio audio audio audio audio \
             audio audio audio audio audio audio audio audio audio",
            "ba000000ba000000ba000000ba000000ba000000ba000000ba000000ba000000",
            "1437256da2c85d029b293d8c6b1d625d9374969301869b12f37186e3f906c708",
        ),
        (
            English,
            "audio audio audio audio audio audio audio audio \
             audio audio audio audio audio audio audio audio \
             audio audio audio audio audio audio audio audio audio",
            "7900000079000000790000007900000079000000790000007900000079000000",
            "20bec797ab96780ae6a045dd816676ca7ed1d7c6773f7022d03ad234b581d600",
        ),
    ];
    let mut languages = std::vec::Vec::new();
    for (language, mnemonic, spend, view) in vectors {
        let name = language.english_name();
        let seed =
            seed_from_mnemonic_in(language, mnemonic).unwrap_or_else(|e| panic!("{name}: {e}"));
        let account = AccountKeys::from_seed(&seed).unwrap();
        assert_eq!(*account.spend_secret(), h32(spend), "{name}");
        assert_eq!(*account.view_secret(), h32(view), "{name}");

        // Back to the same words.
        let want: std::vec::Vec<&str> = mnemonic.split_whitespace().collect();
        let words = seed_to_mnemonic_words_in(language, &seed);
        assert_eq!(words.as_slice(), want.as_slice(), "{name}");
        #[cfg(feature = "alloc")]
        assert_eq!(*seed_to_mnemonic_in(language, &seed), want.join(" "));

        // The prefixes are enough, and case does not matter.
        let short: std::vec::Vec<std::string::String> = want
            .iter()
            .map(|word| word.chars().take(language.prefix_len()).collect())
            .collect();
        assert_eq!(
            *seed_from_mnemonic_in(language, &short.join(" ")).unwrap(),
            *seed,
            "{name}"
        );
        for text in [mnemonic.to_uppercase(), mnemonic.to_lowercase()] {
            assert_eq!(
                *seed_from_mnemonic_in(language, &text).unwrap(),
                *seed,
                "{name}"
            );
        }

        // Guessing the language finds it, or an earlier one in which the
        // same words are valid too.
        let (guessed_seed, guessed) = seed_from_mnemonic_any(mnemonic).unwrap();
        if guessed == language {
            assert_eq!(*guessed_seed, *seed);
        } else {
            assert_eq!((guessed, language), (English, Spanish), "{mnemonic}");
            assert_ne!(*guessed_seed, *seed);
        }
        languages.push(language);
    }
    for language in MnemonicLanguage::ALL {
        assert!(languages.contains(&language), "{language:?}");
    }
}

/// The word lists: their size, the uniqueness of the prefixes that identify
/// the words, and what Monero's unit tests (`mnemonics.cpp`) check.
#[test]
fn mnemonic_word_lists() {
    use MnemonicLanguage::*;
    assert_eq!(MnemonicLanguage::ALL.len(), 12);
    let mut rng = test_rng(6);
    for language in MnemonicLanguage::ALL {
        let name = language.english_name();
        assert_eq!(language.words().count(), 1626, "{name}");
        assert!(language.word(1625).is_some() && language.word(1626).is_none());
        let mut prefixes: std::vec::Vec<std::string::String> = language
            .words()
            .map(|word| {
                assert!(!word.is_empty() && !word.contains(char::is_whitespace));
                word.chars()
                    .take(language.prefix_len())
                    .flat_map(char::to_lowercase)
                    .collect()
            })
            .collect();
        prefixes.sort();
        prefixes.dedup();
        assert_eq!(prefixes.len(), 1626, "{name}");
        for (index, word) in language.words().enumerate().step_by(271) {
            assert_eq!(language.word_index(word), Some(index as u16), "{name}");
        }
        assert_eq!(language.word_index(""), None);
        assert_eq!(language.word_index("\u{10ffff}"), None);

        // Every seed comes back, in every language.
        for _ in 0..2 {
            let mut seed = [0u8; 32];
            rng(&mut seed);
            let words = seed_to_mnemonic_words_in(language, &seed);
            let text = words.join(" ");
            assert_eq!(
                *seed_from_mnemonic_in(language, &text).unwrap(),
                seed,
                "{name}"
            );
            // The checksum word is one of the others.
            assert!(words[..24].contains(&words[24]));
            // A wrong checksum word.
            let other = language.word(usize::from(seed[0])).unwrap();
            if !same_word(language, other, words[24]) {
                let bad = [&words[..24], &[other]].concat().join(" ");
                assert_eq!(
                    seed_from_mnemonic_in(language, &bad).unwrap_err(),
                    Error::InvalidMnemonic
                );
            }
        }
        for seed in [[0u8; 32], [0xff; 32]] {
            let text = seed_to_mnemonic_words_in(language, &seed).join(" ");
            assert_eq!(*seed_from_mnemonic_in(language, &text).unwrap(), seed);
        }
    }
    assert_eq!(English.name(), "English");
    assert_eq!(Japanese.name(), "日本語");
    assert_eq!(German.english_name(), "German");
    assert_eq!(ChineseSimplified.prefix_len(), 1);
    assert_eq!((English.prefix_len(), Japanese.prefix_len()), (3, 3));
    assert_eq!((Spanish.prefix_len(), Lojban.prefix_len()), (4, 4));
    // Spanish has words shorter than its prefix: only the whole word
    // matches them.
    assert_eq!(
        Spanish.word_index("cal"),
        Spanish.words().position(|w| w == "cal").map(|i| i as u16)
    );
    assert!(Spanish.word_index("cal").is_some());
    assert_ne!(Spanish.word_index("cala"), Spanish.word_index("cal"));

    // `language_detection_with_bad_checksum`: these words are Portuguese
    // with the right checksum word, and nothing with another.
    let base = "cinzento luxuriante leonardo gnostico digressao cupula fifa broxar iniquo louvor \
                ovario dorsal ideologo besuntar decurso rosto susto lemure unheiro pagodeiro \
                nitroglicerina eclusa mazurca bigorna";
    let good = std::format!("{base} gnostico");
    let (_, language) = seed_from_mnemonic_any(&good).unwrap();
    assert_eq!(language, Portuguese);
    let bad = std::format!("{base} luxuriante");
    assert_eq!(
        seed_from_mnemonic_any(&bad).unwrap_err(),
        Error::InvalidMnemonic
    );
    assert_eq!(
        seed_from_mnemonic_in(Portuguese, &bad).unwrap_err(),
        Error::InvalidMnemonic
    );

    // `case_tolerance`: German, as written and in lower case.
    let german = "Neubau umarmen Abart umarmen Turban feilen Brett Bargeld Episode Milchkuh \
                  Substanz Jahr Armband Maibaum Tand Grünalge Tabak erziehen Federboa Lobrede \
                  Tenor Leuchter Curry Diskurs Tenor";
    let (seed, language) = seed_from_mnemonic_any(german).unwrap();
    assert_eq!(language, German);
    let (lower, language) = seed_from_mnemonic_any(&german.to_lowercase()).unwrap();
    assert_eq!((language, *lower), (German, *seed));

    // `partial_word_tolerance`: English words cut short.
    let partial = "crim bam scamp gna limi woma wron tuit birth mundane donuts square cohesive \
                   dolphin titans narrate fue saved wrap aloof magic mirr toget upda wra";
    let (seed, language) = seed_from_mnemonic_any(partial).unwrap();
    assert_eq!(language, English);
    assert_eq!(*seed_from_mnemonic(partial).unwrap(), *seed);
    // The full words start with what was typed.
    for (word, typed) in seed_to_mnemonic_words(&seed)
        .iter()
        .zip(partial.split_whitespace())
    {
        assert!(word.starts_with(typed), "{word} {typed}");
    }
}

/// Whether two words of a list are the same word.
fn same_word(language: MnemonicLanguage, a: &str, b: &str) -> bool {
    language.word_index(a) == language.word_index(b)
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

// --- the signatures of the old formats ---

/// Runs the `check_ring_signature` lines of `vectors` and returns how many
/// there were, valid and invalid.
fn run_ring_signature_vectors(vectors: &str) -> (usize, usize) {
    let (mut valid, mut invalid) = (0, 0);
    for line in vectors.lines() {
        let f: std::vec::Vec<&str> = line.split_whitespace().collect();
        if f.first() != Some(&"check_ring_signature") {
            continue;
        }
        let count: usize = f[3].parse().unwrap();
        assert_eq!(f.len(), 6 + count, "{line}");
        let ring: std::vec::Vec<[u8; 32]> = f[4..4 + count].iter().map(|key| h32(key)).collect();
        let signatures: std::vec::Vec<[u8; 64]> = hex::decode(f[4 + count])
            .unwrap()
            .as_chunks::<64>()
            .0
            .to_vec();
        assert_eq!(signatures.len(), count);
        let expected = match f[5 + count] {
            "true" => true,
            "false" => false,
            other => panic!("{other}"),
        };
        assert_eq!(
            check_ring_signature(&h32(f[1]), &h32(f[2]), &ring, &signatures),
            expected,
            "{line}"
        );
        if expected {
            valid += 1;
        } else {
            invalid += 1;
        }
    }
    (valid, invalid)
}

/// `check_ring_signature` vectors of Monero's `tests/crypto/tests.txt`: a
/// selection with rings of 1 to 16 keys, valid and not.
#[test]
fn ring_signature_vectors() {
    let counts = run_ring_signature_vectors(include_str!("testdata/monero_ring_signatures.txt"));
    assert_eq!(counts, (51, 51));
    assert!(!check_ring_signature(&[0; 32], &H, &[], &[]));
}

/// All the `check_ring_signature` vectors of Monero's
/// `tests/crypto/tests.txt`, given its path in `MONERO_CRYPTO_TESTS`.
#[test]
#[ignore]
fn ring_signature_vectors_all() {
    let Ok(path) = std::env::var("MONERO_CRYPTO_TESTS") else {
        return;
    };
    let (valid, invalid) = run_ring_signature_vectors(&std::fs::read_to_string(path).unwrap());
    assert_eq!(valid + invalid, 1024);
    assert!(valid > 200 && invalid > 200);
}

/// Scalars of 2^255 and more, as some Borromean proofs of the chain have
/// them, and what Monero's `slide` makes of them: the vectors of
/// `monero-oxide` (`monero-ed25519`), taken from the chain.
#[test]
fn slide_scalar_vectors() {
    use legacy_sig::slide_scalar;
    let vectors = [
        (
            "cb2be144948166d0a9edb831ea586da0c376efa217871505ad77f6ff80f203f8",
            "b8ffd6a1aee47828808ab0d4c8524cb5c376efa217871505ad77f6ff80f20308",
        ),
        (
            "343d3df8a1051c15a400649c423dc4ed58bef49c50caef6ca4a618b80dee22f4",
            "21113355bc682e6d7a9d5b3f2137a30259bef49c50caef6ca4a618b80dee2204",
        ),
        (
            "c14f75d612800ca2c1dcfa387a42c9cc086c005bc94b18d204dd61342418eba7",
            "4f473804b1d27ab2c789c80ab21d034a096c005bc94b18d204dd61342418eb07",
        ),
        (
            "000102030405060708090a0b0c0d0e0f826c4f6e2329a31bc5bc320af0b2bcbb",
            "a124cfd387f461bf3719e03965ee6877826c4f6e2329a31bc5bc320af0b2bc0b",
        ),
    ];
    for (stored, recovered) in vectors {
        assert_eq!(slide_scalar(&h32(stored)).to_bytes(), h32(recovered));
    }
    // Below 2^255, the value itself, reduced.
    let mut rng = test_rng(8);
    for _ in 0..20 {
        let mut bytes = [0u8; 32];
        rng(&mut bytes);
        bytes[31] &= 0x7f;
        assert_eq!(
            slide_scalar(&bytes),
            crate::cryptonote::scalar_reduce(&bytes)
        );
    }
    assert_eq!(slide_scalar(&[0; 32]), Scalar::ZERO);
}

#[cfg(feature = "alloc")]
mod build;
#[cfg(feature = "alloc")]
mod files;
#[cfg(feature = "alloc")]
mod legacy;
#[cfg(feature = "alloc")]
mod wallet;
#[cfg(feature = "alloc")]
mod with_alloc;
