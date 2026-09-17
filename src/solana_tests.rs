//! Ported tests from `solana_test.go` and `solana_pda_test.go`.

use crate::crypto::ed25519::public_from_seed;
use crate::parse_solana_address;
use crate::pubkey::PubKey;
use crate::script::Script;
use crate::solana::*;

fn seed() -> [u8; 32] {
    let v =
        hex::decode("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88").unwrap();
    let mut s = [0u8; 32];
    s.copy_from_slice(&v);
    s
}

#[test]
fn solana_address_roundtrip() {
    let pk = public_from_seed(&seed());
    let s = Script::new(PubKey::Ed25519(pk));
    let sout = s.out("solana").unwrap();
    let addr = sout.address(&["solana"]).unwrap();
    let parsed = parse_solana_address(&addr).unwrap();
    assert_eq!(parsed.script, sout.script);
    assert_eq!(sout.hash().unwrap().len(), 32);
}

#[test]
fn solana_address_parse_system_program() {
    let addr = "11111111111111111111111111111111";
    let out = parse_solana_address(addr).unwrap();
    assert_eq!(out.address(&["solana"]).unwrap(), addr);
    assert!(parse_solana_address("abc").is_err());
    assert!(parse_solana_address("0000000000000000000000000000000O").is_err());
}

#[test]
fn compact_u16_via_tx_roundtrip() {
    let fee_payer = SolanaKey::parse("11111111111111111111111111111111").unwrap();
    let blockhash = SolanaKey::parse("11111111111111111111111111111111").unwrap();
    let tx = new_solana_tx(fee_payer, blockhash, &[]).unwrap();
    let data = tx.to_bytes().unwrap();
    let tx2 = SolanaTx::from_bytes(&data).unwrap();
    assert_eq!(
        tx2.message.account_keys.len(),
        tx.message.account_keys.len()
    );
}

#[test]
fn solana_transfer_sign() {
    let s = seed();
    let from = SolanaKey(public_from_seed(&s));
    let to = SolanaKey::parse("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri").unwrap();
    let blockhash = SolanaKey::parse("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC").unwrap();

    let ix = transfer_instruction(from, to, 1_000_000);
    let mut tx = new_solana_tx(from, blockhash, &[ix]).unwrap();

    assert_eq!(tx.message.header.num_required_signatures, 1);
    assert_eq!(tx.message.account_keys.len(), 3);
    assert_eq!(tx.message.account_keys[0], from);

    tx.sign(&[s]).unwrap();
    let h = tx.hash().unwrap();
    assert_eq!(h.len(), 64);
    assert_eq!(h, tx.signatures[0]);
    tx.verify().unwrap();

    let data = tx.to_bytes().unwrap();
    assert!(data.len() >= 100);
}

#[test]
fn solana_tx_roundtrip() {
    let s = seed();
    let from = SolanaKey(public_from_seed(&s));
    let to = SolanaKey::parse("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri").unwrap();
    let blockhash = SolanaKey::parse("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC").unwrap();
    let ix = transfer_instruction(from, to, 500_000);
    let mut tx = new_solana_tx(from, blockhash, &[ix]).unwrap();
    tx.sign(&[s]).unwrap();
    let data = tx.to_bytes().unwrap();

    let tx2 = SolanaTx::from_bytes(&data).unwrap();
    assert_eq!(tx2.signatures, tx.signatures);
    assert_eq!(tx2.message.header, tx.message.header);
    assert_eq!(tx2.message.account_keys, tx.message.account_keys);
    assert_eq!(tx2.message.recent_blockhash, tx.message.recent_blockhash);
    let data2 = tx2.to_bytes().unwrap();
    assert_eq!(data, data2);
}

#[test]
fn pda_create_and_find() {
    let program_id = SolanaKey::parse("11111111111111111111111111111111").unwrap();
    let (addr, bump) = find_program_address(&[&b"test"[..]], program_id).unwrap();
    let addr2 = create_program_address(&[&b"test"[..], &[bump]], program_id).unwrap();
    assert_eq!(addr, addr2);
}

#[test]
fn pda_find_deterministic() {
    let program_id = SolanaKey::parse("BPFLoaderUpgradeab1e11111111111111111111111").unwrap();
    let (addr, bump) = find_program_address(&[&b"hello"[..]], program_id).unwrap();
    assert!(!addr.is_zero());
    let (addr2, bump2) = find_program_address(&[&b"hello"[..]], program_id).unwrap();
    assert_eq!(addr, addr2);
    assert_eq!(bump, bump2);
}

#[test]
fn pda_validation() {
    let program_id = SolanaKey::parse("11111111111111111111111111111111").unwrap();
    let seeds: Vec<Vec<u8>> = (0..17).map(|i| vec![i as u8]).collect();
    let seed_refs: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
    assert!(create_program_address(&seed_refs, program_id).is_err());
    assert!(create_program_address(&[[0u8; 33].as_slice()], program_id).is_err());
}

#[test]
fn pda_multiple_seeds() {
    let program_id = SolanaKey::parse("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let wallet = SolanaKey::parse("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri").unwrap();
    let (addr, bump) = find_program_address(&[&wallet.0[..], &b"seed2"[..]], program_id).unwrap();
    let addr2 =
        create_program_address(&[&wallet.0[..], &b"seed2"[..], &[bump]], program_id).unwrap();
    assert_eq!(addr, addr2);
}

// --- Security regression tests (port of solanatx_extra_test.go) ---

/// Assembles a legacy SolanaMessage wire-format body for tests.
fn build_legacy_message(header: &[u8], key_count: &[u8], num_keys: usize, ix: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(header);
    buf.extend_from_slice(key_count);
    buf.extend(std::iter::repeat_n(0u8, num_keys * 32)); // account keys
    buf.extend(std::iter::repeat_n(0u8, 32)); // recent blockhash
    buf.extend_from_slice(ix);
    buf
}

#[test]
fn message_header_count_too_large() {
    // header: num_required_signatures=2, others=0; key_count=1
    let data = build_legacy_message(&[0x02, 0x00, 0x00], &[0x01], 1, &[0x00]);
    assert!(SolanaMessage::from_bytes(&data).is_err());
}

#[test]
fn verify_sign_no_panic_on_bad_header() {
    // header references more signers than keys; must error, not panic.
    let mut tx = SolanaTx {
        signatures: vec![Vec::new(); 3],
        message: SolanaMessage {
            header: SolanaMessageHeader {
                num_required_signatures: 3,
                ..Default::default()
            },
            account_keys: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(tx.verify().is_err());
    assert!(tx.sign(&[seed()]).is_err());
}

#[test]
fn non_canonical_compact_u16_rejected() {
    // header valid, then non-canonical compact-u16 ([0x80,0x00]) for key count.
    let data = vec![0x01, 0x00, 0x00, 0x80, 0x00];
    assert!(SolanaMessage::from_bytes(&data).is_err());
}

#[test]
fn instruction_index_out_of_range() {
    // one instruction with program_id_index=5 but only 1 account key
    let ix = [0x01, 0x05, 0x00, 0x00];
    let data = build_legacy_message(&[0x01, 0x00, 0x00], &[0x01], 1, &ix);
    assert!(SolanaMessage::from_bytes(&data).is_err());

    // out-of-range account index
    let ix2 = [0x01, 0x00, 0x01, 0x09, 0x00];
    let data2 = build_legacy_message(&[0x01, 0x00, 0x00], &[0x01], 1, &ix2);
    assert!(SolanaMessage::from_bytes(&data2).is_err());
}

// --- v1 transactions (SIMD-0385) ---

fn key(b: u8) -> SolanaKey {
    SolanaKey([b; 32])
}

/// Byte layouts ported from the reference `solana-message` crate tests
/// (`byte_layout_minimal` / `byte_layout_with_config`), prefixed with the v1
/// version byte.
#[test]
fn v1_byte_layout_matches_reference() {
    let minimal = SolanaMessageV1 {
        header: SolanaMessageHeader {
            num_required_signatures: 1,
            ..Default::default()
        },
        config: SolanaTxConfig::default(),
        recent_blockhash: key(0xAB),
        account_keys: vec![key(1), key(2)],
        instructions: vec![SolanaCompiledInstruction {
            program_id_index: 1,
            account_indices: vec![0],
            data: vec![0xDE, 0xAD],
        }],
    };
    let mut expected = vec![0x81, 1, 0, 0];
    expected.extend_from_slice(&0u32.to_le_bytes()); // config mask
    expected.extend_from_slice(&[0xAB; 32]); // lifetime specifier
    expected.push(1); // num instructions
    expected.push(2); // num addresses
    expected.extend_from_slice(&[1u8; 32]);
    expected.extend_from_slice(&[2u8; 32]);
    expected.extend_from_slice(&[1, 1]); // program index, num accounts
    expected.extend_from_slice(&2u16.to_le_bytes()); // data len
    expected.push(0); // account index
    expected.extend_from_slice(&[0xDE, 0xAD]);
    assert_eq!(minimal.to_bytes().unwrap(), expected);

    let with_config = SolanaMessageV1 {
        config: SolanaTxConfig::new()
            .with_priority_fee(0x0102030405060708)
            .with_compute_unit_limit(0x11223344),
        recent_blockhash: key(0xBB),
        instructions: vec![SolanaCompiledInstruction {
            program_id_index: 1,
            account_indices: vec![],
            data: vec![],
        }],
        ..minimal.clone()
    };
    let mut expected = vec![0x81, 1, 0, 0];
    expected.extend_from_slice(&7u32.to_le_bytes()); // priority fee (2 bits) + CU limit
    expected.extend_from_slice(&[0xBB; 32]);
    expected.push(1);
    expected.push(2);
    expected.extend_from_slice(&[1u8; 32]);
    expected.extend_from_slice(&[2u8; 32]);
    expected.extend_from_slice(&0x0102030405060708u64.to_le_bytes());
    expected.extend_from_slice(&0x11223344u32.to_le_bytes());
    expected.extend_from_slice(&[1, 0, 0, 0]); // program index, 0 accounts, data len 0
    let bytes = with_config.to_bytes().unwrap();
    assert_eq!(bytes, expected);

    // the parser reads the same layout back
    let parsed = SolanaMessageV1::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.config, with_config.config);
    assert_eq!(parsed.account_keys, with_config.account_keys);
    assert_eq!(parsed.to_bytes().unwrap(), bytes);
}

#[test]
fn v1_transfer_sign_verify_roundtrip() {
    let s = seed();
    let from = SolanaKey(public_from_seed(&s));
    let to = SolanaKey::parse("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri").unwrap();
    let blockhash = SolanaKey::parse("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC").unwrap();
    let config = SolanaTxConfig::new()
        .with_priority_fee(5_000)
        .with_compute_unit_limit(20_000)
        .with_loaded_accounts_data_size_limit(65_536)
        .with_heap_size(65_536);
    let ix = transfer_instruction(from, to, 1_000_000);
    let mut tx = new_solana_tx_v1(from, blockhash, config, &[ix]).unwrap();
    let msg = tx.message_v1.clone().unwrap();
    assert_eq!(msg.header.num_required_signatures, 1);
    assert_eq!(msg.account_keys[0], from);
    assert_eq!(msg.config.mask(), 0b1_1111);

    // unsigned: the signature slot serializes as zeros
    let unsigned = tx.to_bytes().unwrap();
    assert_eq!(unsigned[0], SOLANA_V1_PREFIX);
    assert!(unsigned[unsigned.len() - 64..].iter().all(|&b| b == 0));
    assert!(tx.verify().is_err());

    tx.sign(&[s]).unwrap();
    tx.verify().unwrap();
    assert_eq!(tx.hash().unwrap(), tx.signatures[0]);
    let data = tx.to_bytes().unwrap();
    // signatures trail the message, and the message is what was signed
    assert_eq!(&data[data.len() - 64..], &tx.signatures[0][..]);
    assert_eq!(&data[..data.len() - 64], &msg.to_bytes().unwrap()[..]);
    assert_eq!(data.len(), unsigned.len());

    let tx2 = SolanaTx::from_bytes(&data).unwrap();
    let msg2 = tx2.message_v1.as_ref().unwrap();
    assert_eq!(tx2.signatures, tx.signatures);
    assert_eq!(msg2.config, config);
    assert_eq!(msg2.header, msg.header);
    assert_eq!(msg2.account_keys, msg.account_keys);
    assert_eq!(msg2.recent_blockhash, blockhash);
    assert_eq!(msg2.instructions.len(), 1);
    assert_eq!(msg2.instructions[0].data, msg.instructions[0].data);
    tx2.verify().unwrap();
    assert_eq!(tx2.to_bytes().unwrap(), data);

    // a v1 wire image is not a v0 message
    assert_eq!(
        SolanaMessageV0::from_bytes(&data).err(),
        Some(Error::UnsupportedVersion(1))
    );
}

#[test]
fn v1_rejects_malformed_transactions() {
    let s = seed();
    let from = SolanaKey(public_from_seed(&s));
    let to = SolanaKey::parse("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri").unwrap();
    let blockhash = key(9);
    let ix = transfer_instruction(from, to, 1);
    let mut tx = new_solana_tx_v1(from, blockhash, SolanaTxConfig::default(), &[ix]).unwrap();
    tx.sign(&[s]).unwrap();
    let good = tx.to_bytes().unwrap();
    SolanaTx::from_bytes(&good).unwrap();

    // trailing / missing signature bytes
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        SolanaTx::from_bytes(&trailing).err(),
        Some(Error::TrailingData)
    );
    assert_eq!(
        SolanaTx::from_bytes(&good[..good.len() - 1]).err(),
        Some(Error::UnexpectedEof)
    );
    assert_eq!(
        SolanaTx::from_bytes(&good[..8]).err(),
        Some(Error::UnexpectedEof)
    );

    // config mask: unknown bit, half-set priority fee
    let mut unknown = good.clone();
    unknown[4] |= 1 << 5;
    assert_eq!(
        SolanaTx::from_bytes(&unknown).err(),
        Some(Error::InvalidTxConfig)
    );
    let mut half = good.clone();
    half[4] |= 0b01;
    assert_eq!(
        SolanaTx::from_bytes(&half).err(),
        Some(Error::InvalidTxConfig)
    );

    // signature count mismatch on encode
    let mut extra = tx.clone();
    extra.signatures.push(vec![0; 64]);
    assert_eq!(extra.to_bytes().err(), Some(Error::InvalidData));
    let mut missing = tx.clone();
    missing.signatures.clear();
    assert_eq!(missing.to_bytes().err(), Some(Error::MissingSignatures));

    // oversize
    assert_eq!(
        SolanaTx::from_bytes(&vec![SOLANA_V1_PREFIX; SOLANA_V1_MAX_TX_SIZE + 1]).err(),
        Some(Error::TooLarge)
    );
    let mut big = tx.clone();
    big.message_v1.as_mut().unwrap().instructions[0].data = vec![0; SOLANA_V1_MAX_TX_SIZE];
    assert_eq!(big.to_bytes().err(), Some(Error::TooLarge));
}

#[test]
fn v1_message_sanitization() {
    let base = SolanaMessageV1 {
        header: SolanaMessageHeader {
            num_required_signatures: 1,
            ..Default::default()
        },
        recent_blockhash: key(7),
        account_keys: vec![key(1), key(2)],
        instructions: vec![SolanaCompiledInstruction {
            program_id_index: 1,
            account_indices: vec![0],
            data: vec![],
        }],
        ..Default::default()
    };
    base.validate().unwrap();

    let check = |f: &dyn Fn(&mut SolanaMessageV1), want: Error| {
        let mut m = base.clone();
        f(&mut m);
        assert_eq!(m.validate().err(), Some(want));
        assert_eq!(m.to_bytes().err(), Some(want));
    };
    check(&|m| m.account_keys[1] = key(1), Error::DuplicateKey);
    check(
        &|m| m.instructions[0].program_id_index = 0,
        Error::IndexOutOfRange,
    );
    check(
        &|m| m.instructions[0].program_id_index = 2,
        Error::IndexOutOfRange,
    );
    check(
        &|m| m.instructions[0].account_indices = vec![2],
        Error::IndexOutOfRange,
    );
    check(&|m| m.header.num_readonly_signed = 1, Error::InvalidHeader);
    check(
        &|m| m.header.num_required_signatures = 0,
        Error::InvalidHeader,
    );
    check(
        &|m| m.header.num_readonly_unsigned = 2,
        Error::InvalidHeader,
    );
    check(&|m| m.header.num_required_signatures = 13, Error::TooLarge);
    check(
        &|m| m.account_keys = (0..65).map(key).collect(),
        Error::TooLarge,
    );
    check(
        &|m| m.instructions = vec![m.instructions[0].clone(); 65],
        Error::TooLarge,
    );
    check(
        &|m| m.instructions[0].data = vec![0; 65_536],
        Error::TooLarge,
    );
    check(
        &|m| m.config.heap_size = Some(32 * 1024 + 1),
        Error::InvalidTxConfig,
    );
    check(
        &|m| m.config.heap_size = Some(31 * 1024),
        Error::InvalidTxConfig,
    );
    check(
        &|m| m.config.heap_size = Some(257 * 1024),
        Error::InvalidTxConfig,
    );
    for ok in [32 * 1024, 100 * 1024, 256 * 1024] {
        let mut m = base.clone();
        m.config.heap_size = Some(ok);
        m.validate().unwrap();
    }

    // limits are inclusive: 64 addresses and 64 instructions are fine
    let mut m = base.clone();
    m.account_keys = (0..64).map(key).collect();
    m.instructions = vec![m.instructions[0].clone(); 64];
    m.validate().unwrap();
    let bytes = m.to_bytes().unwrap();
    assert_eq!(
        SolanaMessageV1::from_bytes(&bytes)
            .unwrap()
            .account_keys
            .len(),
        64
    );
}
