//! Known answers from the reference implementations (BlockchainCommons bc-ur,
//! and its Rust port ur-rs). Everything but the last tests runs without
//! `alloc`.

use super::bytewords::{self, Style};
use super::*;

#[test]
fn crc32_vectors() {
    assert_eq!(crc32(b""), 0);
    assert_eq!(crc32(b"Hello, world!"), 0xebe6_c6e6);
    assert_eq!(crc32(b"Wolf"), 0x598c_84dc);
    assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
}

fn encoded<'a>(data: &[u8], style: Style, buf: &'a mut [u8]) -> &'a str {
    let n = bytewords::encode_to_slice(data, style, buf).unwrap();
    assert_eq!(n, bytewords::encoded_len(data.len(), style));
    core::str::from_utf8(&buf[..n]).unwrap()
}

#[test]
fn bytewords_styles() {
    let input = [0, 1, 2, 128, 255];
    let mut buf = [0u8; 64];
    for (style, text) in [
        (
            Style::Standard,
            "able acid also lava zoom jade need echo taxi",
        ),
        (Style::Uri, "able-acid-also-lava-zoom-jade-need-echo-taxi"),
        (Style::Minimal, "aeadaolazmjendeoti"),
    ] {
        assert_eq!(encoded(&input, style, &mut buf), text);
        let mut out = [0u8; 5];
        assert_eq!(bytewords::decode_to_slice(text, style, &mut out), Ok(5));
        assert_eq!(out, input);
        assert!(bytewords::decoded_len_bound(text.len(), style) >= 5);

        // any case
        let mut upper = [0u8; 64];
        let upper = &mut upper[..text.len()];
        upper.copy_from_slice(text.as_bytes());
        upper.make_ascii_uppercase();
        let upper = core::str::from_utf8(upper).unwrap();
        assert_eq!(bytewords::decode_to_slice(upper, style, &mut out), Ok(5));
        assert_eq!(out, input);

        // exact buffers
        assert_eq!(
            bytewords::decode_to_slice(text, style, &mut [0u8; 4]),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(
            bytewords::encode_to_slice(&input, style, &mut [0u8; 17]),
            Err(Error::BufferTooSmall)
        );
    }

    // nothing but a checksum
    assert_eq!(encoded(&[], Style::Minimal, &mut buf), "aeaeaeae");
    assert_eq!(
        bytewords::decode_to_slice("aeaeaeae", Style::Minimal, &mut []),
        Ok(0)
    );
}

#[test]
fn bytewords_errors() {
    let mut out = [0u8; 16];
    let mut decode = |text, style| bytewords::decode_to_slice(text, style, &mut out);
    for (text, style, error) in [
        (
            "able acid also lava zero jade need echo wolf",
            Style::Standard,
            Error::BadChecksum,
        ),
        (
            "able-acid-also-lava-zero-jade-need-echo-wolf",
            Style::Uri,
            Error::BadChecksum,
        ),
        ("aeadaolazojendeowf", Style::Minimal, Error::BadChecksum),
        (
            "axxe tied also webs lung",
            Style::Standard,
            Error::InvalidWord,
        ),
        ("axxe-tied-also-webs-lung", Style::Uri, Error::InvalidWord),
        ("abmuammdwe", Style::Minimal, Error::InvalidWord),
        // the right first and last letters do not make a word
        (
            "abbe acid also lava zoom jade need echo taxi",
            Style::Standard,
            Error::InvalidWord,
        ),
        // the wrong separator, or too many of them
        (
            "able-acid-also-lava-zoom-jade-need-echo-taxi",
            Style::Standard,
            Error::InvalidWord,
        ),
        (
            "able  acid also lava zoom jade need echo taxi",
            Style::Standard,
            Error::InvalidWord,
        ),
        (
            "able acid also lava zoom jade need echo taxi ",
            Style::Standard,
            Error::InvalidWord,
        ),
        ("", Style::Standard, Error::InvalidWord),
        ("wolf", Style::Standard, Error::InvalidLength),
        ("", Style::Minimal, Error::InvalidLength),
        ("aeaeae", Style::Minimal, Error::InvalidLength),
        ("aea", Style::Minimal, Error::InvalidLength),
        ("₿", Style::Standard, Error::InvalidWord),
        ("₿", Style::Uri, Error::InvalidWord),
        ("₿₿", Style::Minimal, Error::InvalidWord),
        ("a₿", Style::Minimal, Error::InvalidWord),
        ("a₿a", Style::Minimal, Error::InvalidLength),
    ] {
        assert_eq!(decode(text, style), Err(error), "{text:?}");
    }
}

#[test]
fn bytewords_long_vector() {
    let input: [u8; 100] = [
        245, 215, 20, 198, 241, 235, 69, 59, 209, 205, 165, 18, 150, 158, 116, 135, 229, 212, 19,
        159, 17, 37, 239, 240, 253, 11, 109, 191, 37, 242, 38, 120, 223, 41, 156, 189, 242, 254,
        147, 204, 66, 163, 216, 175, 191, 72, 169, 54, 32, 60, 144, 230, 210, 137, 184, 197, 33,
        113, 88, 14, 157, 31, 177, 46, 1, 115, 205, 69, 225, 150, 65, 235, 58, 144, 65, 240, 133,
        69, 113, 247, 63, 53, 242, 165, 160, 144, 26, 13, 79, 237, 133, 71, 82, 69, 254, 165, 138,
        41, 85, 24,
    ];
    let standard = "yank toys bulb skew when warm free fair tent swan \
                    open brag mint noon jury list view tiny brew note \
                    body data webs what zinc bald join runs data whiz \
                    days keys user diet news ruby whiz zone menu surf \
                    flew omit trip pose runs fund part even crux fern \
                    math visa tied loud redo silk curl jugs hard beta \
                    next cost puma drum acid junk swan free very mint \
                    flap warm fact math flap what limp free jugs yell \
                    fish epic whiz open numb math city belt glow wave \
                    limp fuel grim free zone open love diet gyro cats \
                    fizz holy city puff";
    let minimal = "yktsbbswwnwmfefrttsnonbgmtnnjyltvwtybwne\
                   bydawswtzcbdjnrsdawzdsksurdtnsrywzzemusf\
                   fwottppersfdptencxfnmhvatdldroskcljshdba\
                   ntctpadmadjksnfevymtfpwmftmhfpwtlpfejsyl\
                   fhecwzonnbmhcybtgwwelpflgmfezeonledtgocs\
                   fzhycypf";
    let mut buf = [0u8; 600];
    assert_eq!(encoded(&input, Style::Standard, &mut buf), standard);
    assert_eq!(encoded(&input, Style::Minimal, &mut buf), minimal);
    for (text, style) in [(standard, Style::Standard), (minimal, Style::Minimal)] {
        let mut out = [0u8; 100];
        assert_eq!(bytewords::decode_to_slice(text, style, &mut out), Ok(100));
        assert_eq!(out, input);
    }
}

/// A `crypto-request` from the reference tests: tags, maps, and a hyphen.
const REQUEST_CBOR: &str = "a201d82550020c223a86f7464693fc650ef3cac04702d901f4a101d902585820\
                            e824467caffeaf3bbc3e0ca095e660a9bad80ddb6a919433a37161908b9a3986";
const REQUEST_UR: &str = "ur:crypto-request/oeadtpdagdaobncpftlnylfgfgmuztihbawfsgrtflaotaadwkoyadtaaohdhdcxvsdkfgkepezepefrrffmbnnbmdvahnptrdtpbtuyimmemweootjshsmhlunyeslnameyhsdi";

fn request_cbor() -> [u8; 64] {
    let mut cbor = [0u8; 64];
    hex::decode_to_slice(REQUEST_CBOR, &mut cbor).unwrap();
    cbor
}

#[test]
fn single_part_to_slice() {
    let cbor = request_cbor();
    let mut buf = [0u8; 200];
    let n = encode_to_slice("crypto-request", &cbor, &mut buf).unwrap();
    assert_eq!(n, encoded_len("crypto-request".len(), cbor.len()));
    assert_eq!(core::str::from_utf8(&buf[..n]).unwrap(), REQUEST_UR);
    assert_eq!(
        encode_to_slice("crypto-request", &cbor, &mut buf[..n - 1]),
        Err(Error::BufferTooSmall)
    );
    for bad in ["", "Bytes", "crypto_psbt", "a/b", "psbt "] {
        assert_eq!(
            encode_to_slice(bad, &cbor, &mut buf),
            Err(Error::InvalidType),
            "{bad:?}"
        );
    }

    let ur = Ur::parse(REQUEST_UR).unwrap();
    assert_eq!(ur.ur_type, "crypto-request");
    assert_eq!(ur.sequence, None);
    assert!(!ur.is_multi_part());
    assert!(ur.decoded_len_bound() >= cbor.len());
    let mut out = [0u8; 64];
    assert_eq!(ur.decode_to_slice(&mut out), Ok(64));
    assert_eq!(out, cbor);
}

#[test]
fn parses_components() {
    let ur = Ur::parse("UR:BYTES/12-9/LPBNAS").unwrap();
    assert_eq!(
        ur,
        Ur {
            ur_type: "BYTES",
            sequence: Some((12, 9)),
            body: "LPBNAS"
        }
    );
    assert!(ur.is_multi_part());
    assert_eq!(
        Ur::parse("ur:psbt/4294967295-1/ae").unwrap().sequence,
        Some((u32::MAX, 1))
    );

    for (text, error) in [
        ("", Error::InvalidScheme),
        ("ur", Error::InvalidScheme),
        ("uri:bytes/aeaeaeae", Error::InvalidScheme),
        ("bytes/aeaeaeae", Error::InvalidScheme),
        ("₿r:bytes/aeaeaeae", Error::InvalidScheme),
        ("ur:", Error::InvalidType),
        ("ur:bytes", Error::InvalidType),
        ("ur:/aeaeaeae", Error::InvalidType),
        ("ur:by_tes/aeaeaeae", Error::InvalidType),
        ("ur:byt₿s/aeaeaeae", Error::InvalidType),
        ("ur:bytes/1of9/ae", Error::InvalidSequence),
        ("ur:bytes/0-9/ae", Error::InvalidSequence),
        ("ur:bytes/1-0/ae", Error::InvalidSequence),
        ("ur:bytes/+1-9/ae", Error::InvalidSequence),
        ("ur:bytes/-9/ae", Error::InvalidSequence),
        ("ur:bytes/1-/ae", Error::InvalidSequence),
        ("ur:bytes/1-9-9/ae", Error::InvalidSequence),
        ("ur:bytes/4294967296-9/ae", Error::InvalidSequence),
        ("ur:bytes/x/1-9/ae", Error::InvalidSequence),
    ] {
        assert_eq!(Ur::parse(text), Err(error), "{text:?}");
    }
}

#[cfg(feature = "alloc")]
#[test]
fn strings_and_byte_strings() {
    let cbor = request_cbor();
    assert_eq!(encode("crypto-request", &cbor).unwrap(), REQUEST_UR);
    assert_eq!(
        decode(&REQUEST_UR.to_ascii_uppercase()).unwrap(),
        ("crypto-request".to_string(), cbor.to_vec())
    );
    assert_eq!(decode("ur:bytes/1-9/lpbnas"), Err(Error::MultiPart));
    assert_eq!(
        bytewords::decode(&bytewords::encode(&cbor, Style::Uri), Style::Uri).unwrap(),
        cbor
    );

    for len in [0usize, 1, 23, 24, 255, 256, 70000] {
        let data = vec![0x5a; len];
        let wrapped = bytes_to_cbor(&data);
        assert_eq!(wrapped, crate::cbor::Cbor::Bytes(data.clone()).encode());
        assert_eq!(cbor_to_bytes(&wrapped), Ok(&data[..]));
    }
    for bad in [
        &[][..],
        &[0x01],                // an integer
        &[0x63, 1, 2, 3],       // a text string
        &[0x42, 1],             // cut short
        &[0x42, 1, 2, 3],       // trailing data
        &[0x5f, 0x41, 1, 0xff], // indefinite length
        &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ] {
        assert_eq!(cbor_to_bytes(bad), Err(Error::InvalidCbor), "{bad:x?}");
    }

    // the single-part UR of the reference tests: 50 bytes as a byte string
    let ur = "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch";
    let (ur_type, cbor) = decode(ur).unwrap();
    assert_eq!(ur_type, "bytes");
    let data = cbor_to_bytes(&cbor).unwrap();
    assert_eq!(data.len(), 50);
    assert_eq!(hex::encode(&data[..10]), "916ec65cf77cadf55cd7");
    assert_eq!(encode("bytes", &bytes_to_cbor(data)).unwrap(), ur);
}
