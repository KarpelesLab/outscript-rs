//! Everything but the tests of the last module runs without `alloc`.

use super::*;

fn header(encoding: Encoding, file_type: FileType, num_parts: u16, index: u16) -> Header {
    Header {
        encoding,
        file_type,
        num_parts,
        index,
    }
}

#[test]
fn headers() {
    for (text, expected) in [
        ("B$HP0300", header(Encoding::Hex, FileType::PSBT, 3, 0)),
        ("B$HP0302", header(Encoding::Hex, FileType::PSBT, 3, 2)),
        (
            "B$2T0100",
            header(Encoding::Base32, FileType::TRANSACTION, 1, 0),
        ),
        (
            "B$ZJZZZY",
            header(Encoding::Zlib, FileType::JSON, 1295, 1294),
        ),
        ("B$ZC1001", header(Encoding::Zlib, FileType::CBOR, 36, 1)),
        (
            "B$2U0A09",
            header(Encoding::Base32, FileType::UNICODE, 10, 9),
        ),
        ("B$HB0201", header(Encoding::Hex, FileType::BINARY, 2, 1)),
        (
            "B$HX0201",
            header(Encoding::Hex, FileType::EXECUTABLE, 2, 1),
        ),
        // a type in use that the specification does not list
        (
            "B$2R0201",
            header(Encoding::Base32, FileType::from_char('R').unwrap(), 2, 1),
        ),
    ] {
        assert_eq!(Header::parse(text), Ok((expected, "")), "{text}");
        assert_eq!(&expected.to_bytes().unwrap(), text.as_bytes());
        // whatever the case
        let mut lower = [0u8; 8];
        lower.copy_from_slice(text.as_bytes());
        lower.make_ascii_lowercase();
        let lower = core::str::from_utf8(&lower).unwrap();
        assert_eq!(Header::parse(lower), Ok((expected, "")), "{lower}");
    }
    assert_eq!(
        Header::parse("B$HP0300CAFE"),
        Ok((header(Encoding::Hex, FileType::PSBT, 3, 0), "CAFE"))
    );
    assert_eq!(FileType::PSBT.as_char(), 'P');
    assert_eq!(FileType::from_char('p'), Some(FileType::PSBT));
    assert_eq!(FileType::from_char('$'), None);
    assert_eq!(
        Encoding::from_char(Encoding::Zlib.as_char()),
        Some(Encoding::Zlib)
    );

    for (text, error) in [
        ("", Error::InvalidHeader),
        ("B$HP030", Error::InvalidHeader),
        ("A$HP0300", Error::InvalidHeader),
        ("BBHP0300", Error::InvalidHeader),
        ("B$H$0300", Error::InvalidHeader),
        ("B$$P0300", Error::InvalidHeader),
        ("B$HP-300", Error::InvalidHeader),
        ("B$HP03+0", Error::InvalidHeader),
        ("B$HP₿00", Error::InvalidHeader),
        ("B$HP030₿", Error::InvalidHeader),
        ("B$XP0300", Error::UnsupportedEncoding('X')),
        ("B$3P0300", Error::UnsupportedEncoding('3')),
        ("B$HP0000", Error::InvalidIndex),
        ("B$HP0303", Error::InvalidIndex),
        ("B$HP0110", Error::InvalidIndex),
    ] {
        assert_eq!(Header::parse(text), Err(error), "{text:?}");
    }
    for (num_parts, index) in [(0, 0), (1, 1), (1296, 0), (3, 7)] {
        let header = header(Encoding::Hex, FileType::PSBT, num_parts, index);
        assert_eq!(header.to_bytes(), Err(Error::InvalidIndex));
        assert_eq!(
            encode_part_to_slice(&header, &[], &mut [0u8; 8]),
            Err(Error::InvalidIndex)
        );
    }
}

/// RFC 4648 test vectors, without their padding.
const BASE32_VECTORS: [(&str, &str); 7] = [
    ("", ""),
    ("f", "MY"),
    ("fo", "MZXQ"),
    ("foo", "MZXW6"),
    ("foob", "MZXW6YQ"),
    ("fooba", "MZXW6YTB"),
    ("foobar", "MZXW6YTBOI"),
];

#[test]
fn parts_to_slice() {
    let mut buf = [0u8; 64];
    let mut out = [0u8; 16];
    for (raw, text) in BASE32_VECTORS {
        for encoding in [Encoding::Base32, Encoding::Zlib] {
            let header = header(encoding, FileType::UNICODE, 2, 1);
            let n = encode_part_to_slice(&header, raw.as_bytes(), &mut buf).unwrap();
            assert_eq!(n, HEADER_LEN + encoded_len(encoding, raw.len()));
            let part = core::str::from_utf8(&buf[..n]).unwrap();
            assert_eq!(part.split_at(HEADER_LEN), (&part[..HEADER_LEN], text));
            assert!(decoded_len_bound(encoding, text.len()) >= raw.len());

            assert_eq!(
                decode_part_to_slice(part, &mut out),
                Ok((header, raw.len()))
            );
            assert_eq!(&out[..raw.len()], raw.as_bytes());
            // exact buffers
            assert_eq!(
                decode_part_to_slice(part, &mut out[..raw.len()]),
                Ok((header, raw.len()))
            );
            if !raw.is_empty() {
                assert_eq!(
                    decode_part_to_slice(part, &mut out[..raw.len() - 1]),
                    Err(Error::BufferTooSmall)
                );
            }
            assert_eq!(
                encode_part_to_slice(&header, raw.as_bytes(), &mut buf[..n - 1]),
                Err(Error::BufferTooSmall)
            );
        }
    }

    let hex_header = header(Encoding::Hex, FileType::TRANSACTION, 1, 0);
    let n = encode_part_to_slice(&hex_header, &[0x00, 0x9f, 0xca, 0xfe], &mut buf).unwrap();
    assert_eq!(&buf[..n], b"B$HT0100009FCAFE");
    assert_eq!(
        decode_part_to_slice("B$HT0100009fCaFe", &mut out),
        Ok((hex_header, 4))
    );
    assert_eq!(out[..4], [0x00, 0x9f, 0xca, 0xfe]);
    assert_eq!(encoded_len(Encoding::Hex, 4), 8);
    assert_eq!(decoded_len_bound(Encoding::Hex, 8), 4);

    for bad in [
        "B$HT01000",    // half a byte
        "B$HT010000G0", // not hex
        "B$HT0100+1",   // nor is a sign
        "B$HT0100₿0",
        "B$2T0100M", // 1, 3 and 6 characters make no whole byte
        "B$2T0100MZX",
        "B$2T0100MZXW6Y",
        "B$2T0100MZXW6YTBO",
        "B$2T0100MZXW6YTBMZX",
        "B$2T0100MZ======", // no padding
        "B$2T0100M1",       // not base32: 0, 1, 8 and 9
        "B$2T0100M8",
        "B$2T0100MZ₿",
        "B$2T0100MZ ",
        "B$2T0100MZ\n",
        "B$2T0100MZXW7", // stray bits: canonical encodings only
        "B$2T0100MR",
    ] {
        assert_eq!(
            decode_part_to_slice(bad, &mut out),
            Err(Error::InvalidEncoding),
            "{bad:?}"
        );
    }
}

/// Some text with repetitions nearby and far away.
fn sample(len: usize, out: &mut [u8]) -> &[u8] {
    let line = b"output 0000 pays to bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\n";
    for (i, byte) in out[..len].iter_mut().enumerate() {
        let (row, column) = (i / line.len(), i % line.len());
        *byte = match column {
            // the row number, and then some that barely compresses
            7..=10 => b'0' + (row / 10usize.pow(10 - column as u32) % 10) as u8,
            20..=27 => ((row * 2_654_435_761) >> ((column - 20) * 4)) as u8,
            _ => line[column],
        };
    }
    &out[..len]
}

#[test]
fn compression_to_slice() {
    let mut data = [0u8; 5000];
    let mut compressed = [0u8; deflate_len_bound(5000)];
    let mut inflated = [0u8; 5000];
    for len in [0, 1, 100, 1023, 1024, 1025, 5000] {
        let data = sample(len, &mut data);
        let n = deflate_to_slice(data, &mut compressed).unwrap();
        assert!(n <= deflate_len_bound(len));
        if len >= 1000 {
            assert!(n < len * 2 / 3, "{len} bytes to {n}");
        }
        assert_eq!(inflate_to_slice(&compressed[..n], &mut inflated), Ok(len));
        assert_eq!(&inflated[..len], data);
        assert_eq!(
            deflate_to_slice(data, &mut compressed[..n - 1]),
            Err(Error::BufferTooSmall)
        );
        if len > 0 {
            assert_eq!(
                inflate_to_slice(&compressed[..n], &mut inflated[..len - 1]),
                Err(Error::BufferTooSmall)
            );
        }

        // The point of it all: what receivers set aside is enough. Inflating
        // through a window fails on any reference that reaches past it.
        let mut window = [0u8; 1024];
        let mut total = 0;
        let output = minizlib::Stream::new(&mut window, 5000, |piece| {
            assert_eq!(piece, &data[total..total + piece.len()]);
            total += piece.len();
            Ok(())
        });
        assert_eq!(minizlib::inflate(&compressed[..n], output), Ok(len as u64));
        assert_eq!(total, len);
    }

    // data that does not compress stays within the bound
    let mut noise = [0u8; 3000];
    let mut state = 1u32;
    for byte in &mut noise {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *byte = (state >> 24) as u8 | 0x90;
    }
    let n = deflate_to_slice(&noise, &mut compressed).unwrap();
    assert!(n > noise.len() && n <= deflate_len_bound(noise.len()));
    assert_eq!(inflate_to_slice(&compressed[..n], &mut inflated), Ok(3000));

    for bad in [&[][..], &[0x07], &[0x01, 0x05, 0x00], &compressed[..n / 2]] {
        assert_eq!(
            inflate_to_slice(bad, &mut inflated),
            Err(Error::InvalidCompression),
            "{bad:x?}"
        );
    }
}

#[cfg(feature = "alloc")]
mod with_alloc {
    use super::*;

    /// What zlib makes (`wbits=-10`, level 9, dynamic Huffman codes) of the
    /// 2870 bytes of [`zlib_text`], cut every 200 characters.
    const ZLIB_PARTS: [&str; 3] = [
        "B$ZU0300UXJMSTOEIAKELUJ5KE4AEVD7VJQQWKMQQDUQMJCYXDN3QBYTHVEER5PW6VXAA53VS3FXNOTMKONE5476HWS4P5GX6T2PEPDNZP2HVEHTFVJD3ZXT3PTX2O367APKX7OM5N2V553URD5227C55O5W37VQ7RXQIGZL4MN4LJXY7DDPURSEYY3Y5DOX6FGWAU3DPSJ7WRSV",
        "B$ZU0301Y43QLG3I4ONYUTOL4ON5MN3GI3YAGYZLBRRTR5SEHALEA5RHEAFSI6ZFEQFSRBYQSQCZMIYIZMBMZUIIZQBM2WIJZUBM4OITTQCZ4SZCHQVTYFZHHQVTZF2CPBLHRLSCPBLHRLSBPBLHRLUV6CWPBXEU6CWPBXBS4FM6DOJVYKZXNT4SRTYKYDM7IJ4LN3SZIQEM6JXY",
        "B$ZU0302HDQ5SFE7JJ4LN3SZKQE47ZXYATQ5SAU7IZ4LN3SZZQEM6VXQZGCGPA3HJ6CGPA3H64I47PY",
    ];

    fn zlib_text() -> String {
        (0..40)
            .map(|i| {
                format!(
                    "output {i} pays 0.{:04} BTC to bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\n",
                    i * 37 % 10000
                )
            })
            .collect()
    }

    #[test]
    fn joins_what_zlib_made() {
        let text = zlib_text();
        assert_eq!(text.len(), 2870);
        let (file_type, data) = join(&ZLIB_PARTS).unwrap();
        assert_eq!(file_type, FileType::UNICODE);
        assert_eq!(data, text.as_bytes());

        // in any order, however many times, in any case
        let mut joiner = Joiner::new();
        assert_eq!(joiner.finish(), Err(Error::Incomplete));
        assert_eq!((joiner.part_count(), joiner.file_type()), (0, None));
        assert_eq!(joiner.receive(ZLIB_PARTS[2]), Ok(false));
        assert_eq!(joiner.receive(ZLIB_PARTS[2]), Ok(false));
        assert_eq!(
            joiner.receive(&ZLIB_PARTS[0].to_ascii_lowercase()),
            Ok(false)
        );
        assert_eq!(joiner.receive(ZLIB_PARTS[0]), Ok(false));
        assert_eq!(joiner.finish(), Err(Error::Incomplete));
        assert_eq!((joiner.part_count(), joiner.received_part_count()), (3, 2));
        assert_eq!(
            [
                joiner.has_part(0),
                joiner.has_part(1),
                joiner.has_part(2),
                joiner.has_part(3)
            ],
            [true, false, true, false]
        );
        assert_eq!(joiner.file_type(), Some(FileType::UNICODE));
        assert_eq!(joiner.encoding(), Some(Encoding::Zlib));
        assert!(!joiner.is_complete());
        assert_eq!(joiner.receive(ZLIB_PARTS[1]), Ok(true));
        assert_eq!(joiner.receive(ZLIB_PARTS[1]), Ok(true));
        assert!(joiner.is_complete());
        assert_eq!(joiner.finish().unwrap().1, text.as_bytes());

        // not more than allowed, as received or once decompressed
        let mut joiner = Joiner::with_max_len(2869);
        for part in ZLIB_PARTS {
            joiner.receive(part).unwrap();
        }
        assert_eq!(joiner.finish(), Err(Error::TooLarge));
        let mut joiner = Joiner::with_max_len(200);
        assert_eq!(joiner.receive(ZLIB_PARTS[0]), Ok(false));
        assert_eq!(joiner.receive(ZLIB_PARTS[1]), Err(Error::TooLarge));
        assert_eq!(joiner.received_part_count(), 1);

        // parts in the wrong order do not make a file
        let swapped = [
            ZLIB_PARTS[0].to_string(),
            ZLIB_PARTS[1].replace("B$ZU0301", "B$ZU0302"),
            ZLIB_PARTS[2].replace("B$ZU0302", "B$ZU0301"),
        ];
        assert_eq!(join(&swapped), Err(Error::InvalidCompression));
        assert_eq!(join(&ZLIB_PARTS[..2]), Err(Error::Incomplete));
        assert_eq!(join::<&str>(&[]), Err(Error::Incomplete));
    }

    #[test]
    fn rejects_inconsistent_parts() {
        let mut joiner = Joiner::new();
        assert_eq!(joiner.receive("B$HP0300CAFE"), Ok(false));
        for other in [
            "B$2P0301MZXW6YTB", // another encoding
            "B$HT0301CAFE",     // another type
            "B$HP0401CAFE",     // another number of parts
            "B$HP0300CAFF",     // other data for a part already received
            "B$HP0300CAFE00",
        ] {
            assert_eq!(
                joiner.receive(other),
                Err(Error::InconsistentPart),
                "{other}"
            );
        }
        assert_eq!(joiner.receive("B$HP0301"), Ok(false));
        assert_eq!(joiner.receive("bad"), Err(Error::InvalidHeader));
        assert_eq!(joiner.receive("B$HP0302F"), Err(Error::InvalidEncoding));
        assert_eq!(joiner.received_part_count(), 2);
        // parts need not be of the same length to be put together
        assert_eq!(joiner.receive("B$HP0302BABE00"), Ok(true));
        assert_eq!(
            joiner.finish(),
            Ok((FileType::PSBT, vec![0xca, 0xfe, 0xba, 0xbe, 0x00]))
        );

        joiner.reset();
        assert_eq!(joiner.part_count(), 0);
        assert_eq!(joiner.receive("B$2T0100MZXW6"), Ok(true));
        assert_eq!(
            joiner.finish(),
            Ok((FileType::TRANSACTION, b"foo".to_vec()))
        );
    }

    /// What the specification asks of a series of parts.
    fn check_parts(parts: &[String], encoding: Encoding, max_part_len: usize) {
        let (last, others) = parts.split_last().unwrap();
        let (_, group_chars) = encoding.group();
        for (index, part) in parts.iter().enumerate() {
            let (header, _) = Header::parse(part).unwrap();
            let expected = Header {
                encoding,
                file_type: FileType::BINARY,
                num_parts: parts.len() as u16,
                index: index as u16,
            };
            assert_eq!(header, expected);
            assert!(part.len() <= max_part_len);
            let alphanumeric = |c: u8| c.is_ascii_digit() || c.is_ascii_uppercase() || c == b'$';
            assert!(part.bytes().all(alphanumeric), "{part}");
        }
        // equal lengths, of whole bytes, and a last part that is no longer
        for part in others {
            assert_eq!(part.len(), parts[0].len());
            assert_eq!((part.len() - HEADER_LEN) % group_chars, 0);
            assert!(last.len() <= part.len());
        }
        // no fewer parts would do, and they are no longer than it takes
        let chars: usize = parts.iter().map(|part| part.len() - HEADER_LEN).sum();
        let max_body = (max_part_len - HEADER_LEN) / group_chars * group_chars;
        if parts.len() > 1 {
            assert!(chars > (parts.len() - 1) * max_body);
            let shorter = parts[0].len() - HEADER_LEN - group_chars;
            assert!(chars > parts.len() * shorter);
        }
    }

    #[test]
    fn splits_and_joins() {
        let mut buf = [0u8; 5000];
        for len in [0, 1, 4, 5, 6, 99, 100, 101, 1000, 5000] {
            let data = sample(len, &mut buf);
            for max_part_len in [16, 17, 25, 100, 468, 2132, 4296, 100_000] {
                for encoding in [Encoding::Hex, Encoding::Base32, Encoding::Zlib] {
                    let parts = split_with(data, FileType::BINARY, encoding, max_part_len).unwrap();
                    check_parts(&parts, encoding, max_part_len);
                    let mut reversed: Vec<&str> = parts.iter().map(|part| &part[..]).collect();
                    reversed.reverse();
                    let (file_type, joined) = join(&reversed).unwrap();
                    assert_eq!(file_type, FileType::BINARY);
                    assert_eq!(joined, data, "{len} bytes in parts of {max_part_len}");
                }

                // whichever is the shorter of the two
                let parts = split(data, FileType::BINARY, max_part_len).unwrap();
                let encoding = Header::parse(&parts[0]).unwrap().0.encoding;
                let compresses = deflate(data).len() < data.len();
                assert_eq!(encoding == Encoding::Zlib, compresses);
                assert_ne!(encoding, Encoding::Hex);
                assert_eq!(compresses, len >= 99);
                check_parts(&parts, encoding, max_part_len);
                assert_eq!(join(&parts).unwrap().1, data);
            }
        }
    }

    #[test]
    fn split_limits() {
        // the examples of the specification: 2150 bytes as three parts of
        // hex, which here are of the same length
        let data = vec![0xa5; 2150];
        let parts = split_with(&data, FileType::PSBT, Encoding::Hex, 2008).unwrap();
        let lens: Vec<usize> = parts.iter().map(String::len).collect();
        assert_eq!(lens, [1442, 1442, 1440]);
        assert!(parts[2].starts_with("B$HP0302A5A5"));
        // and what fits in a single part stays in one
        let parts = split_with(&data[..1000], FileType::PSBT, Encoding::Hex, 2008).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].len(), 2008);

        // no room for data
        for max_part_len in [0, 7, 8, 9] {
            assert_eq!(
                split_with(&data, FileType::PSBT, Encoding::Hex, max_part_len),
                Err(Error::PartTooSmall)
            );
        }
        assert_eq!(
            split_with(&data, FileType::PSBT, Encoding::Base32, 15),
            Err(Error::PartTooSmall)
        );
        // but for no data
        assert_eq!(
            split_with(&[], FileType::PSBT, Encoding::Base32, 8),
            Ok(vec!["B$2P0100".to_string()])
        );
        assert_eq!(join(&["B$2P0100"]), Ok((FileType::PSBT, vec![])));
        // a single part may end on any number of bytes
        assert_eq!(
            split_with(b"fo", FileType::PSBT, Encoding::Base32, 12),
            Ok(vec!["B$2P0100MZXQ".to_string()])
        );

        // 1295 parts and no more
        let parts = split_with(&data[..1295], FileType::PSBT, Encoding::Hex, 10).unwrap();
        assert_eq!(parts.len(), 1295);
        assert_eq!(parts[1294], "B$HPZZZYA5");
        assert_eq!(join(&parts).unwrap().1, &data[..1295]);
        assert_eq!(
            split_with(&data[..1296], FileType::PSBT, Encoding::Hex, 10),
            Err(Error::TooManyParts)
        );
    }
}
