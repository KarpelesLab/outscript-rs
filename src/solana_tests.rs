//! Ported tests from `solana_test.go` and `solana_pda_test.go`.

use crate::crypto::ed25519::public_from_seed;
use crate::pubkey::PubKey;
use crate::script::Script;
use crate::solana::*;
use crate::{parse_solana_address};

fn seed() -> [u8; 32] {
    let v = hex::decode("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88").unwrap();
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
    let data = tx.marshal_binary().unwrap();
    let tx2 = SolanaTx::unmarshal_binary(&data).unwrap();
    assert_eq!(tx2.message.account_keys.len(), tx.message.account_keys.len());
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

    let data = tx.marshal_binary().unwrap();
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
    let data = tx.marshal_binary().unwrap();

    let tx2 = SolanaTx::unmarshal_binary(&data).unwrap();
    assert_eq!(tx2.signatures, tx.signatures);
    assert_eq!(tx2.message.header, tx.message.header);
    assert_eq!(tx2.message.account_keys, tx.message.account_keys);
    assert_eq!(tx2.message.recent_blockhash, tx.message.recent_blockhash);
    let data2 = tx2.marshal_binary().unwrap();
    assert_eq!(data, data2);
}

#[test]
fn pda_create_and_find() {
    let program_id = SolanaKey::parse("11111111111111111111111111111111").unwrap();
    let (addr, bump) = find_program_address(&[b"test".to_vec()], program_id).unwrap();
    let addr2 = create_program_address(&[b"test".to_vec(), vec![bump]], program_id).unwrap();
    assert_eq!(addr, addr2);
}

#[test]
fn pda_find_deterministic() {
    let program_id = SolanaKey::parse("BPFLoaderUpgradeab1e11111111111111111111111").unwrap();
    let (addr, bump) = find_program_address(&[b"hello".to_vec()], program_id).unwrap();
    assert!(!addr.is_zero());
    let (addr2, bump2) = find_program_address(&[b"hello".to_vec()], program_id).unwrap();
    assert_eq!(addr, addr2);
    assert_eq!(bump, bump2);
}

#[test]
fn pda_validation() {
    let program_id = SolanaKey::parse("11111111111111111111111111111111").unwrap();
    let seeds: Vec<Vec<u8>> = (0..17).map(|i| vec![i as u8]).collect();
    assert!(create_program_address(&seeds, program_id).is_err());
    assert!(create_program_address(&[vec![0u8; 33]], program_id).is_err());
}

#[test]
fn pda_multiple_seeds() {
    let program_id = SolanaKey::parse("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let wallet = SolanaKey::parse("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri").unwrap();
    let (addr, bump) =
        find_program_address(&[wallet.0.to_vec(), b"seed2".to_vec()], program_id).unwrap();
    let addr2 =
        create_program_address(&[wallet.0.to_vec(), b"seed2".to_vec(), vec![bump]], program_id)
            .unwrap();
    assert_eq!(addr, addr2);
}
