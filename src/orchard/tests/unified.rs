use super::{arr, bytes, vectors};
use crate::orchard::keys::*;
use crate::orchard::unified::*;
use crate::orchard::{Error, spec};
use serde_json::Value;

fn opt<const N: usize>(v: &Value) -> Option<[u8; N]> {
    if v.is_null() { None } else { Some(arr(v)) }
}

#[test]
fn f4jumble_vectors() {
    let tvs = vectors(include_str!("../testdata/f4jumble.json"));
    assert_eq!(tvs.len(), 8);
    for tv in tvs {
        let normal = bytes(&tv[0]);
        let jumbled = bytes(&tv[1]);
        let mut buf = normal.clone();
        f4jumble(&mut buf).unwrap();
        assert_eq!(buf, jumbled);
        f4jumble_inv(&mut buf).unwrap();
        assert_eq!(buf, normal);
    }
    assert_eq!(f4jumble(&mut [0u8; 37]), Err(Error::InvalidLength));
    assert_eq!(f4jumble_inv(&mut [0u8; 37]), Err(Error::InvalidLength));
    assert!(f4jumble(&mut [0u8; 38]).is_ok());
    let mut short: [u8; 38] = core::array::from_fn(|i| i as u8);
    f4jumble(&mut short).unwrap();
    f4jumble_inv(&mut short).unwrap();
    assert!(short.iter().enumerate().all(|(i, b)| *b == i as u8));
}

/// The long vectors (3 MB and the 4 MB maximum) take a second or so
/// unoptimized: `cargo test -- --ignored f4jumble_long`.
#[test]
#[ignore = "slow in debug builds"]
fn f4jumble_long_vectors() {
    let tvs = vectors(include_str!("../testdata/f4jumble_long.json"));
    assert_eq!(tvs.len(), 2);
    for tv in tvs {
        let len = tv[0].as_u64().unwrap() as usize;
        let mut msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
        f4jumble(&mut msg).unwrap();
        let mut hash = [0u8; 64];
        spec::blake2b(&[], &[&msg], &mut hash);
        assert_eq!(hash, arr::<64>(&tv[1]));
        f4jumble_inv(&mut msg).unwrap();
        assert!(msg.iter().enumerate().all(|(i, b)| *b == i as u8));
    }
    let mut too_long = vec![0u8; F4JUMBLE_MAX_LEN + 1];
    assert_eq!(f4jumble(&mut too_long), Err(Error::InvalidLength));
}

/// The items of a vector, in encoding order.
fn items<'a>(
    known: [(u32, Option<&'a [u8]>); 4],
    unknown: Option<(u32, &'a [u8])>,
) -> Vec<Item<'a>> {
    let mut items: Vec<Item<'a>> = known
        .into_iter()
        .filter_map(|(typecode, data)| data.map(|data| Item { typecode, data }))
        .chain(unknown.map(|(typecode, data)| Item { typecode, data }))
        .collect();
    items.sort_by_key(|item| item.typecode);
    items
}

pub(super) fn encode_items(hrp: &str, items: &[Item<'_>]) -> String {
    let mut scratch = vec![0u8; raw_len(items)];
    let expected_len = encoded_len(hrp, scratch.len());
    let mut out = vec![0u8; expected_len];
    let s = encode_to_slice(hrp, items, &mut scratch, &mut out).unwrap();
    assert_eq!(s.len(), expected_len);
    s.to_string()
}

fn decode_items(s: &str) -> (String, Vec<(u32, Vec<u8>)>) {
    let mut buf = vec![0u8; s.len()];
    let (hrp, items) = decode_to_slice(s, &mut buf).unwrap();
    (
        hrp.to_string(),
        items.map(|i| (i.typecode, i.data.to_vec())).collect(),
    )
}

#[test]
fn unified_address_vectors() {
    let tvs = vectors(include_str!("../testdata/unified_address.json"));
    assert!(tvs.len() >= 20);
    for tv in tvs {
        // p2pkh_bytes, p2sh_bytes, sapling_raw_addr, orchard_raw_addr,
        // unknown_typecode, unknown_bytes, unified_addr, root_seed, account,
        // diversifier_index
        let expected = UnifiedAddress {
            p2pkh: opt(&tv[0]),
            p2sh: opt(&tv[1]),
            sapling: opt(&tv[2]),
            orchard: opt(&tv[3]),
        };
        let unknown_bytes = if tv[5].is_null() {
            None
        } else {
            Some(bytes(&tv[5]))
        };
        let unknown = unknown_bytes
            .as_deref()
            .map(|data| (tv[4].as_u64().unwrap() as u32, data));
        let string = tv[6].as_str().unwrap();

        // the typed decoder finds the known receivers
        let (network, ua) = UnifiedAddress::decode(string).unwrap();
        assert_eq!(network, Network::Main);
        assert_eq!(ua, expected);

        // the generic layer round-trips everything, unknown items included
        let all = items(
            [
                (TYPECODE_P2PKH, expected.p2pkh.as_ref().map(|d| &d[..])),
                (TYPECODE_P2SH, expected.p2sh.as_ref().map(|d| &d[..])),
                (TYPECODE_SAPLING, expected.sapling.as_ref().map(|d| &d[..])),
                (TYPECODE_ORCHARD, expected.orchard.as_ref().map(|d| &d[..])),
            ],
            unknown,
        );
        assert_eq!(encode_items("u", &all), string);
        let (hrp, decoded) = decode_items(string);
        assert_eq!(hrp, "u");
        assert_eq!(decoded.len(), all.len());
        for (got, want) in decoded.iter().zip(&all) {
            assert_eq!((got.0, &got.1[..]), (want.typecode, want.data));
        }
        #[cfg(feature = "alloc")]
        {
            assert_eq!(encode("u", &all).as_deref(), Ok(string));
            assert_eq!(decode(string), Ok(("u", decoded.clone())));
        }

        // and the typed encoder reproduces the string when it knows it all
        if unknown.is_none() {
            let mut out = [0u8; UnifiedAddress::MAX_ENCODED_LEN];
            assert_eq!(ua.encode_to_slice(Network::Main, &mut out), Ok(string));
            #[cfg(feature = "alloc")]
            assert_eq!(ua.encode(Network::Main).as_deref(), Ok(string));
        }

        // the Orchard receiver is the account's address at that index
        if let Some(raw) = expected.orchard {
            let seed = bytes(&tv[7]);
            let account = tv[8].as_u64().unwrap() as u32;
            let index = tv[9].as_u64().unwrap();
            let sk = SpendingKey::from_zip32_seed(&seed, 133, account).unwrap();
            let address = sk.to_fvk().address_at(index, Scope::External);
            assert_eq!(address.to_raw_address_bytes(), raw);
            assert_eq!(ua.orchard_address(), Ok(Some(address)));
        }
    }
}

#[test]
fn unified_full_viewing_key_vectors() {
    let tvs = vectors(include_str!("../testdata/unified_full_viewing_keys.json"));
    assert!(tvs.len() >= 10);
    for tv in tvs {
        // t_key_bytes, sapling_fvk_bytes, orchard_fvk_bytes,
        // unknown_fvk_typecode, unknown_fvk_bytes, unified_fvk, root_seed,
        // account
        let expected = UnifiedFullViewingKey {
            transparent: opt(&tv[0]),
            sapling: opt(&tv[1]),
            orchard: opt(&tv[2]),
        };
        let unknown_bytes = if tv[4].is_null() {
            None
        } else {
            Some(bytes(&tv[4]))
        };
        let unknown = unknown_bytes
            .as_deref()
            .map(|data| (tv[3].as_u64().unwrap() as u32, data));
        let string = tv[5].as_str().unwrap();
        let (network, key) = UnifiedFullViewingKey::decode(string).unwrap();
        assert_eq!(network, Network::Main);
        assert_eq!(key, expected);
        let all = items(
            [
                (
                    TYPECODE_P2PKH,
                    expected.transparent.as_ref().map(|d| &d[..]),
                ),
                (TYPECODE_SAPLING, expected.sapling.as_ref().map(|d| &d[..])),
                (TYPECODE_ORCHARD, expected.orchard.as_ref().map(|d| &d[..])),
                (0, None),
            ],
            unknown,
        );
        assert_eq!(encode_items("uview", &all), string);
        if unknown.is_none() {
            let mut out = [0u8; UnifiedFullViewingKey::MAX_ENCODED_LEN];
            assert_eq!(key.encode_to_slice(Network::Main, &mut out), Ok(string));
        }
        if let Some(raw) = expected.orchard {
            let seed = bytes(&tv[6]);
            let account = tv[7].as_u64().unwrap() as u32;
            let sk = SpendingKey::from_zip32_seed(&seed, 133, account).unwrap();
            assert_eq!(sk.to_fvk().to_bytes(), raw);
            assert_eq!(key.orchard_fvk(), Ok(Some(sk.to_fvk())));
            assert_eq!(
                UnifiedFullViewingKey::from_orchard(&sk.to_fvk()).orchard,
                Some(raw)
            );
        }
    }
}

#[test]
fn unified_incoming_viewing_key_vectors() {
    let tvs = vectors(include_str!(
        "../testdata/unified_incoming_viewing_keys.json"
    ));
    assert!(tvs.len() >= 10);
    for tv in tvs {
        let expected = UnifiedIncomingViewingKey {
            transparent: opt(&tv[0]),
            sapling: opt(&tv[1]),
            orchard: opt(&tv[2]),
        };
        let unknown_bytes = if tv[4].is_null() {
            None
        } else {
            Some(bytes(&tv[4]))
        };
        let unknown = unknown_bytes
            .as_deref()
            .map(|data| (tv[3].as_u64().unwrap() as u32, data));
        let string = tv[5].as_str().unwrap();
        let (network, key) = UnifiedIncomingViewingKey::decode(string).unwrap();
        assert_eq!(network, Network::Main);
        assert_eq!(key, expected);
        let all = items(
            [
                (
                    TYPECODE_P2PKH,
                    expected.transparent.as_ref().map(|d| &d[..]),
                ),
                (TYPECODE_SAPLING, expected.sapling.as_ref().map(|d| &d[..])),
                (TYPECODE_ORCHARD, expected.orchard.as_ref().map(|d| &d[..])),
                (0, None),
            ],
            unknown,
        );
        assert_eq!(encode_items("uivk", &all), string);
        if unknown.is_none() {
            let mut out = [0u8; UnifiedIncomingViewingKey::MAX_ENCODED_LEN];
            assert_eq!(key.encode_to_slice(Network::Main, &mut out), Ok(string));
        }
        if let Some(raw) = expected.orchard {
            let seed = bytes(&tv[6]);
            let account = tv[7].as_u64().unwrap() as u32;
            let sk = SpendingKey::from_zip32_seed(&seed, 133, account).unwrap();
            let ivk = sk.to_fvk().to_ivk(Scope::External);
            assert_eq!(ivk.to_bytes(), raw);
            assert_eq!(key.orchard_ivk(), Ok(Some(ivk)));
            assert_eq!(
                UnifiedIncomingViewingKey::from_orchard(&ivk).orchard,
                Some(raw)
            );
        }
    }
}

#[test]
fn unified_rules() {
    let sk = SpendingKey::from_bytes([3; 32]).unwrap();
    let address = sk.to_fvk().address_at(0u32, Scope::External);
    let orchard = address.to_raw_address_bytes();
    let ua = UnifiedAddress::from_orchard(&address);
    let mut out = [0u8; UnifiedAddress::MAX_ENCODED_LEN];

    // networks
    for (network, prefix) in [
        (Network::Main, "u1"),
        (Network::Test, "utest1"),
        (Network::Regtest, "uregtest1"),
    ] {
        let s = ua.encode_to_slice(network, &mut out).unwrap().to_string();
        assert!(s.starts_with(prefix));
        assert_eq!(UnifiedAddress::decode(&s), Ok((network, ua)));
        assert_eq!(UnifiedAddress::decode(&s.to_uppercase()), Ok((network, ua)));
        // an address is not a viewing key
        assert_eq!(UnifiedFullViewingKey::decode(&s), Err(Error::InvalidPrefix));
        // any single character change is caught
        let mut bad = s.clone().into_bytes();
        let last = bad.len() - 1;
        bad[last] = if bad[last] == b'q' { b'p' } else { b'q' };
        assert!(UnifiedAddress::decode(core::str::from_utf8(&bad).unwrap()).is_err());
    }

    // the largest address fits the advertised bound
    let full = UnifiedAddress {
        p2pkh: Some([1; 20]),
        p2sh: None,
        sapling: Some([2; 43]),
        orchard: Some(orchard),
    };
    let s = full.encode_to_slice(Network::Regtest, &mut out).unwrap();
    assert_eq!(s.len(), UnifiedAddress::MAX_ENCODED_LEN);
    assert_eq!(UnifiedAddress::decode(s), Ok((Network::Regtest, full)));

    // rules of an address
    let both = UnifiedAddress {
        p2pkh: Some([1; 20]),
        p2sh: Some([2; 20]),
        ..ua
    };
    assert_eq!(
        both.encode_to_slice(Network::Main, &mut out),
        Err(Error::BothP2pkhAndP2sh)
    );
    let transparent = UnifiedAddress {
        p2pkh: Some([1; 20]),
        ..Default::default()
    };
    assert_eq!(
        transparent.encode_to_slice(Network::Main, &mut out),
        Err(Error::OnlyTransparent)
    );
    assert_eq!(
        UnifiedAddress::default().encode_to_slice(Network::Main, &mut out),
        Err(Error::OnlyTransparent)
    );
    assert_eq!(
        ua.encode_to_slice(Network::Main, &mut out[..50]),
        Err(Error::BufferTooSmall)
    );

    // the same rules when decoding what another encoder produced
    let raw = |hrp: &str, list: &[(u32, &[u8])]| {
        let list: Vec<Item<'_>> = list
            .iter()
            .map(|(typecode, data)| Item {
                typecode: *typecode,
                data,
            })
            .collect();
        encode_items(hrp, &list)
    };
    let pad = [0u8; 20];
    assert_eq!(
        UnifiedAddress::decode(&raw("u", &[(0, &pad), (1, &pad), (3, &orchard)])),
        Err(Error::BothP2pkhAndP2sh)
    );
    assert_eq!(
        UnifiedAddress::decode(&raw("u", &[(0, &pad), (1, &[0; 40])])),
        Err(Error::InvalidItem)
    );
    assert_eq!(
        UnifiedAddress::decode(&raw("u", &[(0, &[0; 60])])),
        Err(Error::InvalidItem)
    );
    assert_eq!(
        UnifiedAddress::decode(&raw("u", &[(0, &pad), (2, &[0; 40])])),
        Err(Error::InvalidItem)
    );
    assert_eq!(
        UnifiedAddress::decode(&raw("u", &[(0, &pad), (0xfffa, &[0; 12])])).map(|r| r.1),
        Ok(UnifiedAddress {
            p2pkh: Some(pad),
            ..Default::default()
        })
    );
    assert_eq!(
        UnifiedAddress::decode(&raw("u", &[(1, &[0; 20]), (0xfffa, &[0; 12])])).map(|r| r.1.p2sh),
        Ok(Some(pad))
    );
    // an unknown human-readable part
    assert_eq!(
        UnifiedAddress::decode(&raw("x", &[(3, &orchard), (9, &[0; 12])])),
        Err(Error::InvalidPrefix)
    );
    // a receiver that is not a point is only caught when it is interpreted
    let (_, weird) = UnifiedAddress::decode(&raw("u", &[(3, &[0xff; 43])])).unwrap();
    assert_eq!(weird.orchard_address(), Err(Error::InvalidAddress));

    // rules of every unified encoding, on the encoder side
    let mut scratch = [0u8; 256];
    let mut out = [0u8; 512];
    let item = |typecode: u32, data: &'static [u8]| Item { typecode, data };
    let d43: &'static [u8] = &[7; 43];
    for (list, error) in [
        (
            vec![item(3, d43), item(2, d43)],
            Error::InvalidTypecodeOrder,
        ),
        (vec![item(2, d43), item(2, d43)], Error::DuplicateTypecode),
        (vec![item(TYPECODE_MAX + 1, d43)], Error::InvalidTypecode),
        // too short for F4Jumble
        (vec![item(3, &[1; 19])], Error::InvalidLength),
    ] {
        assert_eq!(
            encode_to_slice("u", &list, &mut scratch, &mut out),
            Err(error)
        );
    }
    let list = [item(3, d43)];
    assert_eq!(
        encode_to_slice("U", &list, &mut scratch, &mut out),
        Err(Error::InvalidPrefix)
    );
    assert_eq!(
        encode_to_slice("abcdefghijklmnopq", &list, &mut scratch, &mut out),
        Err(Error::InvalidPrefix)
    );
    assert_eq!(
        encode_to_slice("u", &list, &mut scratch[..10], &mut out),
        Err(Error::BufferTooSmall)
    );
    assert!(encode_to_slice("u", &[item(TYPECODE_MAX, d43)], &mut scratch, &mut out).is_ok());
}

/// Builds a unified string from a hand-made raw encoding, to check what
/// the decoder rejects.
pub(super) fn jumble_and_encode(hrp: &str, raw: &[u8]) -> String {
    let mut raw = raw.to_vec();
    f4jumble(&mut raw).unwrap();
    let mut out = vec![0u8; encoded_len(hrp, raw.len())];
    let n = crate::bech32::encode_to_slice(hrp, &raw, crate::bech32::Variant::Bech32m, &mut out)
        .unwrap();
    String::from_utf8(out[..n].to_vec()).unwrap()
}

#[test]
fn unified_decoder_rejects_malformed_encodings() {
    let mut padding = [0u8; 16];
    padding[0] = b'u';
    let with_padding = |items: &[u8], padding: &[u8; 16]| [items, &padding[..]].concat();
    let mut orchard = vec![3, 43];
    orchard.extend_from_slice(&[9; 43]);
    let mut sapling = vec![2, 43];
    sapling.extend_from_slice(&[8; 43]);
    let mut buf = [0u8; 512];
    let mut check = |raw: &[u8], expected: Result<usize, Error>| {
        let s = jumble_and_encode("u", raw);
        let got = decode_to_slice(&s, &mut buf).map(|(_, items)| items.count());
        assert_eq!(got, expected);
        s
    };
    check(&with_padding(&orchard, &padding), Ok(1));
    check(
        &with_padding(&[&sapling[..], &orchard[..]].concat(), &padding),
        Ok(2),
    );
    check(
        &with_padding(&[&orchard[..], &sapling[..]].concat(), &padding),
        Err(Error::InvalidTypecodeOrder),
    );
    check(
        &with_padding(&[&orchard[..], &orchard[..]].concat(), &padding),
        Err(Error::DuplicateTypecode),
    );
    // wrong padding: another prefix, or a stray byte
    let mut bad_padding = padding;
    bad_padding[15] = 1;
    check(
        &with_padding(&orchard, &bad_padding),
        Err(Error::InvalidPadding),
    );
    let mut bad_padding = [0u8; 16];
    bad_padding[..5].copy_from_slice(b"utest");
    check(
        &with_padding(&orchard, &bad_padding),
        Err(Error::InvalidPadding),
    );
    // an item running past the end, a truncated header, a huge length
    let mut truncated = vec![3, 60];
    truncated.extend_from_slice(&[9; 43]);
    check(
        &with_padding(&truncated, &padding),
        Err(Error::UnexpectedEof),
    );
    let mut dangling = orchard.clone();
    dangling.push(4);
    check(
        &with_padding(&dangling, &padding),
        Err(Error::UnexpectedEof),
    );
    let mut huge = vec![3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    huge.extend_from_slice(&[9; 43]);
    let expected = if usize::BITS < 64 {
        Error::TooLarge
    } else {
        Error::UnexpectedEof
    };
    check(&with_padding(&huge, &padding), Err(expected));
    // non-canonical compact sizes, a typecode out of range
    let mut noncanonical = vec![0xfd, 3, 0, 43];
    noncanonical.extend_from_slice(&[9; 43]);
    check(
        &with_padding(&noncanonical, &padding),
        Err(Error::NonCanonical),
    );
    let mut out_of_range = vec![0xfe, 0x01, 0x00, 0x00, 0x02, 43];
    out_of_range.extend_from_slice(&[9; 43]);
    check(
        &with_padding(&out_of_range, &padding),
        Err(Error::InvalidTypecode),
    );
    // too short for F4Jumble, bech32 (not bech32m), a small buffer
    let short = [5u8; 37];
    let mut out = [0u8; 128];
    let n = crate::bech32::encode_to_slice("u", &short, crate::bech32::Variant::Bech32m, &mut out)
        .unwrap();
    let s = core::str::from_utf8(&out[..n]).unwrap();
    assert_eq!(
        decode_to_slice(s, &mut buf).err(),
        Some(Error::InvalidLength)
    );
    let mut raw = with_padding(&orchard, &padding);
    f4jumble(&mut raw).unwrap();
    let n = crate::bech32::encode_to_slice("u", &raw, crate::bech32::Variant::Bech32, &mut out)
        .unwrap();
    let s = core::str::from_utf8(&out[..n]).unwrap();
    assert_eq!(
        decode_to_slice(s, &mut buf).err(),
        Some(Error::Bech32(crate::bech32::Error::WrongVariant))
    );
    let good = jumble_and_encode("u", &with_padding(&orchard, &padding));
    assert_eq!(
        decode_to_slice(&good, &mut buf[..20]).err(),
        Some(Error::BufferTooSmall)
    );
    assert!(matches!(
        decode_to_slice("u1qqqqqqqq", &mut buf),
        Err(Error::Bech32(_))
    ));
    assert!(decode_to_slice("", &mut buf).is_err());
    // an empty list of items is a valid container, but no address
    let empty = jumble_and_encode("u", &with_padding(&[0; 40], &padding));
    assert!(UnifiedAddress::decode(&empty).is_err());
    // an encoding too long for the stack buffer needs alloc
    let mut big = vec![0xfd, 0xfa, 0xff, 0xfd, 0x58, 0x02];
    big.extend_from_slice(&[1; 600]);
    let s = jumble_and_encode("u", &with_padding(&big, &padding));
    assert!(s.len() > 512);
    let decoded = UnifiedAddress::decode(&s);
    if cfg!(feature = "alloc") {
        assert_eq!(decoded, Ok((Network::Main, UnifiedAddress::default())));
    } else {
        assert_eq!(decoded, Err(Error::TooLarge));
    }
}
