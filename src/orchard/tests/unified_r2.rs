//! ZIP-316 Revision 2, against the vectors of `zcash-test-vectors`
//! (`unified_address_r2.json` and `unified_viewing_keys_r2.json`).

use super::unified::{encode_items, jumble_and_encode};
use super::{arr, bytes, vectors};
use crate::orchard::Error;
use crate::orchard::keys::*;
use crate::orchard::unified::revision2::*;
use crate::orchard::unified::{
    self, Item, Network, TYPECODE_BIRTHDAY_HEIGHT, TYPECODE_EXPIRY_HEIGHT, TYPECODE_EXPIRY_TIME,
    TYPECODE_ORCHARD, TYPECODE_P2PKH, TYPECODE_P2SH, TYPECODE_SAPLING,
};
use serde_json::Value;

fn opt<const N: usize>(v: &Value) -> Option<[u8; N]> {
    if v.is_null() { None } else { Some(arr(v)) }
}

fn expiry(height: &Value, time: &Value) -> Expiry {
    Expiry {
        height: height.as_u64().map(|h| h as u32),
        time: time.as_u64(),
    }
}

#[test]
fn unified_address_r2_vectors() {
    let tvs = vectors(include_str!("../testdata/unified_address_r2.json"));
    assert_eq!(tvs.len(), 60);
    let (mut shielded, mut transparent, mut expiring) = (0, 0, 0);
    for tv in tvs {
        // p2pkh_bytes, p2sh_bytes, sapling_raw_addr, orchard_raw_addr,
        // expiry_height, expiry_time, unified_addr, root_seed, account,
        // diversifier_index
        let encoded = tv[6].as_str().unwrap();
        let expected = UnifiedAddress {
            transparent_enabled: encoded.starts_with("tu"),
            p2pkh: opt(&tv[0]),
            p2sh: opt(&tv[1]),
            sapling: opt(&tv[2]),
            orchard: opt(&tv[3]),
            expiry: expiry(&tv[4], &tv[5]),
        };
        assert!(expected.transparent_enabled || encoded.starts_with("zu"));
        assert_eq!(
            UnifiedAddress::decode(encoded),
            Ok((Network::Main, expected))
        );
        let mut out = [0u8; UnifiedAddress::MAX_ENCODED_LEN];
        assert_eq!(
            expected.encode_to_slice(Network::Main, &mut out),
            Ok(encoded)
        );
        #[cfg(feature = "alloc")]
        assert_eq!(expected.encode(Network::Main).as_deref(), Ok(encoded));
        assert!(encoded.len() <= UnifiedAddress::MAX_ENCODED_LEN);
        // an encoding of Revision 2 is not one of Revision 0
        assert_eq!(
            unified::UnifiedAddress::decode(encoded),
            Err(Error::InvalidPrefix)
        );
        // the Orchard receiver is the address of the account
        if let Some(address) = expected.orchard_address().unwrap() {
            let seed = bytes(&tv[7]);
            let account = tv[8].as_u64().unwrap() as u32;
            let index = tv[9].as_u64().unwrap();
            let fvk = SpendingKey::from_zip32_seed(&seed, 133, account)
                .unwrap()
                .to_fvk();
            assert_eq!(fvk.address_at(index, Scope::External), address);
        }
        // the test network
        let test = expected.encode_to_slice(Network::Test, &mut out).unwrap();
        assert!(test.starts_with(if expected.transparent_enabled {
            "tutest1"
        } else {
            "zutest1"
        }));
        assert_eq!(UnifiedAddress::decode(test), Ok((Network::Test, expected)));

        shielded += !expected.transparent_enabled as usize;
        transparent += (expected.p2pkh.is_some() || expected.p2sh.is_some()) as usize;
        expiring += (expected.expiry != Expiry::NONE) as usize;
    }
    assert!(shielded > 10 && transparent > 10 && expiring > 20);
}

#[test]
fn unified_viewing_key_r2_vectors() {
    let tvs = vectors(include_str!("../testdata/unified_viewing_keys_r2.json"));
    assert_eq!(tvs.len(), 20);
    let mut with_p2sh = 0;
    for tv in tvs {
        // t_p2pkh_fvk_bytes, p2sh_fvk_bytes, sapling_fvk_bytes,
        // orchard_fvk_bytes, expiry_height, expiry_time, unified_fvk,
        // t_p2pkh_ivk_bytes, p2sh_ivk_bytes, sapling_ivk_bytes,
        // orchard_ivk_bytes, unified_ivk, p2pkh_addr, p2sh_addr,
        // sapling_raw_addr, orchard_raw_addr, derived_ua, root_seed,
        // cosigner_seed_1, cosigner_seed_2, account, diversifier_index
        let p2sh = |v: &Value, full: bool| {
            (!v.is_null()).then(|| P2shViewingKey::from_bytes(&bytes(v), full).unwrap())
        };
        let expiry = expiry(&tv[4], &tv[5]);
        let ufvk = UnifiedFullViewingKey {
            transparent: opt(&tv[0]),
            p2sh: p2sh(&tv[1], true),
            sapling: opt(&tv[2]),
            orchard: opt(&tv[3]),
            birthday_height: None,
            expiry,
        };
        let encoded = tv[6].as_str().unwrap();
        assert!(encoded.starts_with("uvf1"));
        assert_eq!(
            UnifiedFullViewingKey::decode(encoded),
            Ok((Network::Main, ufvk))
        );
        let mut out = vec![0u8; UnifiedFullViewingKey::MAX_ENCODED_LEN];
        assert_eq!(ufvk.encode_to_slice(Network::Main, &mut out), Ok(encoded));
        #[cfg(feature = "alloc")]
        assert_eq!(ufvk.encode(Network::Main).as_deref(), Ok(encoded));
        assert_eq!(
            unified::UnifiedFullViewingKey::decode(encoded),
            Err(Error::InvalidPrefix)
        );
        assert_eq!(
            UnifiedIncomingViewingKey::decode(encoded),
            Err(Error::InvalidPrefix)
        );

        let uivk = UnifiedIncomingViewingKey {
            transparent: opt(&tv[7]),
            p2sh: p2sh(&tv[8], false),
            sapling: opt(&tv[9]),
            orchard: opt(&tv[10]),
            birthday_height: None,
            expiry,
        };
        let encoded = tv[11].as_str().unwrap();
        assert!(encoded.starts_with("uvi1"));
        assert_eq!(
            UnifiedIncomingViewingKey::decode(encoded),
            Ok((Network::Main, uivk))
        );
        assert_eq!(uivk.encode_to_slice(Network::Main, &mut out), Ok(encoded));
        let test = uivk.encode_to_slice(Network::Test, &mut out).unwrap();
        assert!(test.starts_with("uvitest1"));
        assert_eq!(
            UnifiedIncomingViewingKey::decode(test),
            Ok((Network::Test, uivk))
        );

        // the P2SH items: a policy of three keys, of both chains in the
        // full viewing key and of the external one in the incoming one
        if let (Some(full), Some(incoming)) = (&ufvk.p2sh, &uivk.p2sh) {
            with_p2sh += 1;
            assert_eq!(full.template(), "sh(sortedmulti(2,@0/**,@1/**,@2/**))");
            assert_eq!(incoming.template(), "sh(sortedmulti(2,@0/*,@1/*,@2/*))");
            assert_eq!(full.keys().len(), 3);
            assert_eq!(incoming.keys().len(), 3);
            assert_eq!(full.as_bytes(), &bytes(&tv[1])[..]);
            // an item of one kind is not one of the other
            assert_eq!(
                P2shViewingKey::from_bytes(full.as_bytes(), false),
                Err(Error::InvalidItem)
            );
            assert_eq!(
                P2shViewingKey::from_bytes(incoming.as_bytes(), true),
                Err(Error::InvalidItem)
            );
            // rebuilt from its parts
            let keys: Vec<[u8; 65]> = full
                .keys()
                .map(|(chain_code, public_key)| {
                    let mut key = [0u8; 65];
                    key[..32].copy_from_slice(chain_code);
                    key[32..].copy_from_slice(public_key);
                    key
                })
                .collect();
            assert_eq!(
                P2shViewingKey::new(full.template(), &keys, true).as_ref(),
                Ok(full)
            );
            assert!(format!("{full:?}").contains("sortedmulti"));
        }

        // the Orchard items are those of the account, the incoming key
        // that of the full one, and the address that of the incoming key
        if let Some(fvk) = ufvk.orchard_fvk().unwrap() {
            let seed = bytes(&tv[17]);
            let account = tv[20].as_u64().unwrap() as u32;
            let sk = SpendingKey::from_zip32_seed(&seed, 133, account).unwrap();
            assert_eq!(sk.to_fvk(), fvk);
            let ivk = uivk.orchard_ivk().unwrap().unwrap();
            assert_eq!(fvk.to_ivk(Scope::External), ivk);
            let index = tv[21].as_u64().unwrap();
            assert_eq!(
                ivk.address_at(index).to_raw_address_bytes(),
                arr::<43>(&tv[15])
            );
        }

        // the address derived: shielded unless the key has a transparent
        // item, and expiring when the key does
        let derived = UnifiedAddress {
            transparent_enabled: ufvk.transparent.is_some() || ufvk.p2sh.is_some(),
            p2pkh: opt(&tv[12]),
            p2sh: opt(&tv[13]),
            sapling: opt(&tv[14]),
            orchard: opt(&tv[15]),
            expiry,
        };
        let encoded = tv[16].as_str().unwrap();
        assert_eq!(
            UnifiedAddress::decode(encoded),
            Ok((Network::Main, derived))
        );
        let mut out = [0u8; UnifiedAddress::MAX_ENCODED_LEN];
        assert_eq!(
            derived.encode_to_slice(Network::Main, &mut out),
            Ok(encoded)
        );
        assert!(derived.expiry.is_within(&ufvk.expiry));
    }
    assert_eq!(with_p2sh, 7);
}

/// The rules of Revision 2 that the vectors do not exercise.
#[test]
fn unified_r2_rules() {
    let sk = SpendingKey::from_bytes([7; 32]).unwrap();
    let fvk = sk.to_fvk();
    let address = fvk.address_at(0u32, Scope::External);
    let raw = address.to_raw_address_bytes();
    let mut out = [0u8; 4096];

    // an address: shielded by default, round trip, the Orchard receiver
    let ua = UnifiedAddress::from_orchard(&address);
    assert!(!ua.transparent_enabled);
    let s = ua
        .encode_to_slice(Network::Main, &mut out)
        .unwrap()
        .to_string();
    assert!(s.starts_with("zu1"));
    assert_eq!(UnifiedAddress::decode(&s), Ok((Network::Main, ua)));
    assert_eq!(ua.orchard_address(), Ok(Some(address)));
    // no human-readable part is defined for regression test networks
    assert_eq!(
        ua.encode_to_slice(Network::Regtest, &mut out),
        Err(Error::InvalidPrefix)
    );
    // a transparent receiver needs the other kind of address
    let with_t = UnifiedAddress {
        p2pkh: Some([1; 20]),
        ..ua
    };
    assert_eq!(
        with_t.encode_to_slice(Network::Main, &mut out),
        Err(Error::InvalidItem)
    );
    let with_t = UnifiedAddress {
        transparent_enabled: true,
        ..with_t
    };
    let t = with_t
        .encode_to_slice(Network::Main, &mut out)
        .unwrap()
        .to_string();
    assert!(t.starts_with("tu1"));
    assert_eq!(UnifiedAddress::decode(&t), Ok((Network::Main, with_t)));
    // which may even have nothing shielded
    let only_t = UnifiedAddress {
        transparent_enabled: true,
        p2sh: Some([2; 20]),
        ..Default::default()
    };
    let t = only_t
        .encode_to_slice(Network::Test, &mut out)
        .unwrap()
        .to_string();
    assert_eq!(UnifiedAddress::decode(&t), Ok((Network::Test, only_t)));
    assert_eq!(
        UnifiedAddress {
            p2pkh: Some([1; 20]),
            ..only_t
        }
        .encode_to_slice(Network::Main, &mut out),
        Err(Error::BothP2pkhAndP2sh)
    );
    // but not nothing at all, or metadata alone
    assert_eq!(
        UnifiedAddress::default().encode_to_slice(Network::Main, &mut out),
        Err(Error::OnlyMetadata)
    );
    let only_metadata = UnifiedAddress {
        expiry: Expiry {
            height: Some(5),
            time: None,
        },
        ..Default::default()
    };
    assert_eq!(
        only_metadata.encode_to_slice(Network::Main, &mut out),
        Err(Error::OnlyMetadata)
    );

    // hand-made encodings
    let height = 3_000_000u32.to_le_bytes();
    let time = 1_900_000_000u64.to_le_bytes();
    let orchard = Item {
        typecode: TYPECODE_ORCHARD,
        data: &raw,
    };
    let item = |typecode: u32, data: &'static [u8]| Item { typecode, data };
    let decode = |hrp: &str, items: &[Item<'_>]| UnifiedAddress::decode(&encode_items(hrp, items));
    // a transparent receiver in a shielded address
    assert_eq!(
        decode("zu", &[item(TYPECODE_P2PKH, &[1; 20]), orchard]),
        Err(Error::InvalidItem)
    );
    assert_eq!(
        decode("zu", &[item(TYPECODE_P2SH, &[1; 20]), orchard]),
        Err(Error::InvalidItem)
    );
    assert!(decode("tu", &[item(TYPECODE_P2SH, &[1; 20]), orchard]).is_ok());
    assert_eq!(
        decode(
            "tu",
            &[
                item(TYPECODE_P2PKH, &[1; 20]),
                item(TYPECODE_P2SH, &[1; 20]),
                orchard
            ]
        ),
        Err(Error::BothP2pkhAndP2sh)
    );
    // metadata: expiry, of the right lengths
    let expiring = decode(
        "zu",
        &[
            orchard,
            Item {
                typecode: TYPECODE_EXPIRY_HEIGHT,
                data: &height,
            },
            Item {
                typecode: TYPECODE_EXPIRY_TIME,
                data: &time,
            },
        ],
    )
    .unwrap()
    .1;
    assert_eq!(
        expiring.expiry,
        Expiry {
            height: Some(3_000_000),
            time: Some(1_900_000_000)
        }
    );
    assert_eq!(
        decode("zu", &[orchard, item(TYPECODE_EXPIRY_HEIGHT, &[0; 8])]),
        Err(Error::InvalidItem)
    );
    assert_eq!(
        decode("zu", &[orchard, item(TYPECODE_EXPIRY_TIME, &[0; 4])]),
        Err(Error::InvalidItem)
    );
    // metadata that must be understood, and is not
    for typecode in [0xe2, 0xf0, 0xfc] {
        assert_eq!(
            decode("zu", &[orchard, item(typecode, &[0; 4])]),
            Err(Error::MustUnderstand)
        );
    }
    // other metadata and other items are skipped; the birthday height of
    // a viewing key is ignored in an address
    for typecode in [
        0x04,
        0xbf,
        TYPECODE_BIRTHDAY_HEIGHT,
        0xc1,
        0xdf,
        0xfd,
        0xffff,
    ] {
        assert_eq!(
            decode("zu", &[orchard, item(typecode, &[9; 4])]),
            Ok((Network::Main, ua)),
            "{typecode:#x}"
        );
    }
    // metadata alone is not an address; an unknown receiver may be one
    assert_eq!(
        decode(
            "zu",
            &[
                item(0xc1, &[0; 40]),
                Item {
                    typecode: TYPECODE_EXPIRY_HEIGHT,
                    data: &height,
                }
            ]
        ),
        Err(Error::OnlyMetadata)
    );
    assert!(decode("zu", &[item(0x04, &[0; 40])]).is_ok());
    // other human-readable parts
    for hrp in ["u", "ur", "zuregtest", "uvf", "tutest2"] {
        assert_eq!(
            UnifiedAddress::decode(&encode_items(hrp, &[orchard])),
            Err(Error::InvalidPrefix),
            "{hrp}"
        );
    }
    // the padding is that of the human-readable part
    let mut raw_encoding = vec![TYPECODE_ORCHARD as u8, 43];
    raw_encoding.extend_from_slice(&raw);
    raw_encoding.extend_from_slice(b"tu\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    assert_eq!(
        UnifiedAddress::decode(&jumble_and_encode("zu", &raw_encoding)),
        Err(Error::InvalidPadding)
    );
    assert!(UnifiedAddress::decode(&jumble_and_encode("tu", &raw_encoding)).is_ok());

    // Revision 0 cannot have metadata that must be understood, and does
    // not count other metadata as a shielded item
    let r0 = |items: &[Item<'_>]| unified::UnifiedAddress::decode(&encode_items("u", items));
    assert_eq!(
        r0(&[
            orchard,
            Item {
                typecode: TYPECODE_EXPIRY_HEIGHT,
                data: &height,
            }
        ]),
        Err(Error::MustUnderstand)
    );
    assert!(r0(&[orchard, item(0xc1, &[0; 4])]).is_ok());
    assert_eq!(
        r0(&[item(TYPECODE_P2PKH, &[1; 20]), item(0xc1, &[0; 40])]),
        Err(Error::OnlyTransparent)
    );
    assert!(r0(&[item(TYPECODE_P2PKH, &[1; 20]), item(0x04, &[0; 40])]).is_ok());
    let fvk_bytes = fvk.to_bytes();
    let orchard_fvk = Item {
        typecode: TYPECODE_ORCHARD,
        data: &fvk_bytes,
    };
    for hrp in ["uview", "uivk"] {
        let ivk_bytes = fvk.to_ivk(Scope::External).to_bytes();
        let key = if hrp == "uview" {
            orchard_fvk
        } else {
            Item {
                typecode: TYPECODE_ORCHARD,
                data: &ivk_bytes,
            }
        };
        let s = encode_items(hrp, &[key, item(0xe5, &[0; 4])]);
        if hrp == "uview" {
            assert_eq!(
                unified::UnifiedFullViewingKey::decode(&s),
                Err(Error::MustUnderstand)
            );
        } else {
            assert_eq!(
                unified::UnifiedIncomingViewingKey::decode(&s),
                Err(Error::MustUnderstand)
            );
        }
    }

    // viewing keys: metadata, and the birthday no later than the expiry
    let ufvk = UnifiedFullViewingKey {
        birthday_height: Some(2_000_000),
        expiry: Expiry {
            height: Some(2_500_000),
            time: Some(1_800_000_000),
        },
        ..UnifiedFullViewingKey::from_orchard(&fvk)
    };
    let s = ufvk
        .encode_to_slice(Network::Main, &mut out)
        .unwrap()
        .to_string();
    assert!(s.starts_with("uvf1"));
    assert_eq!(UnifiedFullViewingKey::decode(&s), Ok((Network::Main, ufvk)));
    assert_eq!(ufvk.orchard_fvk(), Ok(Some(fvk)));
    let late = UnifiedFullViewingKey {
        birthday_height: Some(2_500_001),
        ..ufvk
    };
    assert_eq!(
        late.encode_to_slice(Network::Main, &mut out),
        Err(Error::InvalidItem)
    );
    let birthday = 2_500_001u32.to_le_bytes();
    let expiry_height = 2_500_000u32.to_le_bytes();
    let late = encode_items(
        "uvf",
        &[
            orchard_fvk,
            Item {
                typecode: TYPECODE_BIRTHDAY_HEIGHT,
                data: &birthday,
            },
            Item {
                typecode: TYPECODE_EXPIRY_HEIGHT,
                data: &expiry_height,
            },
        ],
    );
    assert_eq!(
        UnifiedFullViewingKey::decode(&late),
        Err(Error::InvalidItem)
    );
    // a key of transparent items only
    let transparent = UnifiedFullViewingKey {
        transparent: Some([3; 65]),
        ..Default::default()
    };
    let s = transparent
        .encode_to_slice(Network::Test, &mut out)
        .unwrap()
        .to_string();
    assert!(s.starts_with("uvftest1"));
    assert_eq!(
        UnifiedFullViewingKey::decode(&s),
        Ok((Network::Test, transparent))
    );
    assert_eq!(
        UnifiedFullViewingKey::default().encode_to_slice(Network::Main, &mut out),
        Err(Error::OnlyMetadata)
    );
    let uivk = UnifiedIncomingViewingKey {
        birthday_height: Some(7),
        ..UnifiedIncomingViewingKey::from_orchard(&fvk.to_ivk(Scope::External))
    };
    let s = uivk
        .encode_to_slice(Network::Main, &mut out)
        .unwrap()
        .to_string();
    assert_eq!(
        UnifiedIncomingViewingKey::decode(&s),
        Ok((Network::Main, uivk))
    );
    assert_eq!(UnifiedFullViewingKey::decode(&s), Err(Error::InvalidPrefix));
    assert_eq!(
        uivk.encode_to_slice(Network::Regtest, &mut out),
        Err(Error::InvalidPrefix)
    );
    assert_eq!(
        UnifiedIncomingViewingKey::decode(&encode_items(
            "uvi",
            &[item(TYPECODE_SAPLING, &[1; 64]), item(0xe9, &[])]
        )),
        Err(Error::MustUnderstand)
    );

    // expiry
    let e = Expiry {
        height: Some(100),
        time: Some(5000),
    };
    assert!(!e.is_expired(100, 5000));
    assert!(e.is_expired(101, 5000));
    assert!(e.is_expired(100, 5001));
    assert!(!Expiry::NONE.is_expired(u32::MAX, u64::MAX));
    assert!(e.allows_tx_expiry_height(100));
    assert!(e.allows_tx_expiry_height(1));
    assert!(!e.allows_tx_expiry_height(101));
    assert!(!e.allows_tx_expiry_height(0));
    assert!(Expiry::NONE.allows_tx_expiry_height(0));
    assert!(e.is_within(&Expiry::NONE));
    assert!(e.is_within(&e));
    assert!(!Expiry::NONE.is_within(&e));
    let earlier = Expiry {
        height: Some(99),
        time: Some(5000),
    };
    assert!(earlier.is_within(&e));
    assert!(!e.is_within(&earlier));
    let no_time = Expiry {
        height: Some(99),
        time: None,
    };
    assert!(!no_time.is_within(&e));
    assert!(e.is_within(&no_time) == (e.height <= no_time.height));
}

/// The shape of P2SH viewing key items.
#[test]
fn p2sh_viewing_key_items() {
    let key = |tag: u8| {
        let mut key = [tag; 65];
        key[32] = 0x02 + (tag & 1);
        key
    };
    let keys = [key(1), key(2), key(3)];
    let full = "sh(sortedmulti(2,@0/**,@1/**,@2/**))";
    let item = P2shViewingKey::new(full, &keys, true).unwrap();
    assert_eq!(item.template(), full);
    assert_eq!(item.as_bytes().len(), 1 + full.len() + 1 + 3 * 65);
    let listed: Vec<_> = item.keys().collect();
    assert_eq!(listed.len(), 3);
    assert_eq!(listed[1].0, &[2u8; 32]);
    assert_eq!(listed[1].1[0], 0x02);
    assert_eq!(P2shViewingKey::from_bytes(item.as_bytes(), true), Ok(item));
    let new = |template: &str, keys: &[[u8; 65]], full: bool| {
        P2shViewingKey::new(template, keys, full).map(|_| ())
    };
    // the notation of the other kind of key, or none
    assert_eq!(new(full, &keys, false), Err(Error::InvalidItem));
    let incoming = "sh(sortedmulti(2,@0/*,@1/*,@2/*))";
    assert_eq!(new(incoming, &keys, false), Ok(()));
    assert_eq!(new(incoming, &keys, true), Err(Error::InvalidItem));
    assert_eq!(
        new("sh(sortedmulti(2,@0,@1/**,@2/**))", &keys, true),
        Err(Error::InvalidItem)
    );
    assert_eq!(
        new("sh(sortedmulti(2,@0/<0;1>/*,@1/**,@2/**))", &keys, true),
        Err(Error::InvalidItem)
    );
    // as many keys as the template refers to, all of them referred to
    assert_eq!(new(full, &keys[..2], true), Err(Error::InvalidItem));
    assert_eq!(
        new("sh(sortedmulti(2,@0/**,@1/**))", &keys, true),
        Err(Error::InvalidItem)
    );
    assert_eq!(
        new("sh(sortedmulti(2,@0/**,@1/**,@3/**))", &keys, true),
        Err(Error::InvalidItem)
    );
    assert_eq!(
        new("sh(sortedmulti(2,@0/**,@01/**,@2/**))", &keys, true),
        Err(Error::InvalidItem)
    );
    assert_eq!(
        new("sh(sortedmulti(2,@/**))", &keys[..1], true),
        Err(Error::InvalidItem)
    );
    // a key used twice is one key
    assert_eq!(
        new(
            "sh(or(pk(@0/**),and(pk(@1/**),pk(@0/**))))",
            &keys[..2],
            true
        ),
        Ok(())
    );
    assert_eq!(new("", &[], true), Err(Error::InvalidItem));
    assert_eq!(
        new("sh(pk(@0/**))\n", &keys[..1], true),
        Err(Error::InvalidItem)
    );
    // public keys that are not compressed
    let mut bad = keys;
    bad[2][32] = 0x04;
    assert_eq!(new(full, &bad, true), Err(Error::InvalidItem));
    // truncated, extended, too long
    let bytes = item.as_bytes();
    for len in [0, 1, 10, bytes.len() - 1] {
        assert!(P2shViewingKey::from_bytes(&bytes[..len], true).is_err());
    }
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert_eq!(
        P2shViewingKey::from_bytes(&longer, true),
        Err(Error::InvalidItem)
    );
    assert_eq!(
        P2shViewingKey::from_bytes(&[0u8; P2SH_VIEWING_KEY_MAX_LEN + 1], true),
        Err(Error::TooLarge)
    );
    // fifteen keys fit
    let many: Vec<[u8; 65]> = (0..15).map(key).collect();
    let mut template = String::from("sh(sortedmulti(15");
    for i in 0..15 {
        template.push_str(&format!(",@{i}/**"));
    }
    template.push_str("))");
    let item = P2shViewingKey::new(&template, &many, true).unwrap();
    assert_eq!(item.keys().len(), 15);
    let ufvk = UnifiedFullViewingKey {
        p2sh: Some(item),
        sapling: Some([5; 128]),
        orchard: Some([6; 96]),
        birthday_height: Some(1),
        expiry: Expiry {
            height: Some(2),
            time: Some(3),
        },
        ..Default::default()
    };
    let mut out = vec![0u8; UnifiedFullViewingKey::MAX_ENCODED_LEN];
    let s = ufvk
        .encode_to_slice(Network::Main, &mut out)
        .unwrap()
        .to_string();
    assert_eq!(UnifiedFullViewingKey::decode(&s), Ok((Network::Main, ufvk)));
    // a key cannot have both transparent items
    let both = UnifiedFullViewingKey {
        transparent: Some([4; 65]),
        ..ufvk
    };
    assert_eq!(
        both.encode_to_slice(Network::Main, &mut out),
        Err(Error::BothP2pkhAndP2sh)
    );
}
