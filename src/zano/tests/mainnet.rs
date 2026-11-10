//! Transactions of Zano's main network, from before and after each hard
//! fork that changed the formats: they parse, serialize back to the same
//! bytes, hash to their ids, and verify — signatures, proofs and all.
//!
//! The transactions are in `testdata/mainnet/<name>.bin` as the daemon
//! serves them (`/gettransactions`), and the outputs their rings refer to
//! in `<name>.rings` (129 bytes per member: the index of the input, then
//! the stealth address, concealing point, amount commitment and blinded
//! asset id of the output, read from the transactions `get_out_info` names).
//! The tools that made them are the ignored tests of `chain.rs`.

use super::super::*;
use super::chain::{ggx_ring, rings_from_binary};
use super::h32;
use crate::prelude::*;

/// One coin: the reward of a block since hard fork 4.
const COIN: u64 = 1_000_000_000_000;

struct Fixture {
    name: &'static str,
    id: &'static str,
    /// The height of its block, when it matters.
    height: u64,
    tx: &'static [u8],
    rings: &'static [u8],
}

macro_rules! fixture {
    ($name:literal, $id:literal, $height:literal) => {
        Fixture {
            name: $name,
            id: $id,
            height: $height,
            tx: include_bytes!(concat!("../testdata/mainnet/", $name, ".bin")),
            rings: &[],
        }
    };
    ($name:literal, $id:literal, $height:literal, rings) => {
        Fixture {
            name: $name,
            id: $id,
            height: $height,
            tx: include_bytes!(concat!("../testdata/mainnet/", $name, ".bin")),
            rings: include_bytes!(concat!("../testdata/mainnet/", $name, ".rings")),
        }
    };
}

const FIXTURES: &[Fixture] = &[
    fixture!(
        "v1_transfer",
        "11aab71b744cfc58f1d90ce065e4fe27e41e62ebdc6ecc86ce5abddae47d28a5",
        2000004,
        rings
    ),
    fixture!(
        "v1_pos",
        "0bd9a4b3089edf1ef603e2e6854936d00934f9df6b1e90ba0d40a7ee821bbeb6",
        104,
        rings
    ),
    fixture!(
        "v1_pow",
        "17d10f45eaddc4bbd2d4fc24886ebd75a320f2a18eddc50330749245e5b5b040",
        2000001
    ),
    fixture!(
        "v2_pow",
        "12333b1cc53af19c4495dcd85a1fddcadfeb5107e820699b632e6d57b09ae219",
        2555003
    ),
    fixture!(
        "v2_pos",
        "04d8af74120430bdf69b2f40f343a7f8b9d473da62dc0fc96d00f123c0035501",
        2555017
    ),
    fixture!(
        "v2_bare",
        "53d9fd77757cca7dd53da845079f398944b1e76ae8544333052be1e7901534e5",
        2555008,
        rings
    ),
    fixture!(
        "v2_zc",
        "007d24bed210717220f83514150296306ed82e168aae181ff93fb512bbbb1772",
        3076390,
        rings
    ),
    fixture!(
        "v3_three_outs",
        "50664b3df2dac0f80d6276b4cb79c556dbc6309df12f24679702744c9abf48f1",
        0
    ),
    fixture!(
        "v4_transfer",
        "0098169b271c88d6f3d751ecf1494982d9fa9c708700e9420fd2e952affcb933",
        3850185,
        rings
    ),
    fixture!(
        "v4_three_outs",
        "14d808ff724d8b18835f7470ed4c3e5ff99a836a0c252c5e41b811ab27bf8f8c",
        3850029,
        rings
    ),
    fixture!(
        "v4_alias",
        "06c1465ed625eb3182403e73c33fb1b82ef2620ab9f80351d5326573af5a9f4b",
        3850238
    ),
    fixture!(
        "v4_pow",
        "013b6740748092f2ecf92c045c1da18204d7859f8cecdef88f818ba1917cdcc4",
        3850016
    ),
    fixture!(
        "v4_pos_a",
        "9aef58e5976cf852cc6e92bf06b3bebdcdfb08ae0d5b082f881b348b4e90695d",
        3898013,
        rings
    ),
    fixture!(
        "v4_pos_b",
        "50208f0d6737881599ceb06ecf2a41c3dbb4e460cc0bcc2c256f3c8346649d39",
        3898018,
        rings
    ),
    fixture!(
        "v2_mixed",
        "a47ea552f42297151e7df1be5ce7888d836753edd87d00a4a13d3c743e7f652b",
        2555021,
        rings
    ),
    fixture!(
        "v2_asset_register",
        "73971a83217dd71ad00179956ff72fb6fa519e460cd2913c93ac7972297a1812",
        0,
        rings
    ),
    fixture!(
        "v3_asset_register",
        "637b14d3b970df43eed6a4acb709fd56594a63be8af73a56f455cc5bdae3d835",
        3100171,
        rings
    ),
    fixture!(
        "v3_asset_emit",
        "6aca46dbdc2fc25ea3423bac2d967636aa4b4441c5c0365b636ee994e33a7df9",
        0,
        rings
    ),
    fixture!(
        "v3_asset_emit_eth",
        "c3c440faf9564e71d9974c225f10a61260a05d6bb6de67d5001e9224dbdc0743",
        3400126
    ),
    fixture!(
        "v3_asset_burn",
        "792ad22d194eb4781c3edbd787ad419afb75e18964a171f36f1984157ee36d3b",
        3400150
    ),
    fixture!(
        "v4_five_inputs",
        "43b5a6175c2c54e245c4d9fe55b2243829f0e286c1fedc36e09b92db2c96bedd",
        3850354,
        rings
    ),
];

fn load(name: &str) -> (&'static Fixture, Transaction) {
    let fixture = FIXTURES
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no fixture {name}"));
    (fixture, Transaction::from_bytes(fixture.tx).unwrap())
}

/// Verifies a fixture with its rings, as the first transaction of a block
/// that creates `block_reward` if that is not zero.
fn verify(name: &str, block_reward: u64, stake: Option<&StakeContext>) -> Result<(), VerifyError> {
    let (fixture, tx) = load(name);
    let rings: Vec<Vec<ClsagGgxInput>> = rings_from_binary(fixture.rings)
        .iter()
        .map(|ring| ggx_ring(ring))
        .collect();
    let refs: Vec<&[ClsagGgxInput]> = rings.iter().map(Vec::as_slice).collect();
    let mut context = VerifyContext::new(&refs).block_reward(block_reward);
    if let Some(stake) = stake {
        context = context.stake(stake);
    }
    tx.verify(&context)
}

fn names(items: &[Variant]) -> Vec<&'static str> {
    items.iter().map(Variant::name).collect()
}

/// Byte-exact round trip and transaction id of every fixture, and the
/// version the height calls for.
#[test]
fn round_trip_and_ids() {
    for fixture in FIXTURES {
        let tx = Transaction::from_bytes(fixture.tx).unwrap();
        assert_eq!(tx.to_bytes(), fixture.tx, "{}", fixture.name);
        assert_eq!(
            hex::encode(tx.prefix_hash()),
            fixture.id,
            "{}",
            fixture.name
        );
        // The scanning parser reads the same prefix and attachments.
        let scanned = Transaction::from_bytes_for_scan(fixture.tx).unwrap();
        assert_eq!(scanned.prefix_bytes(), tx.prefix_bytes());
        assert_eq!(scanned.attachment, tx.attachment);
        if fixture.height != 0 {
            let (version, hardfork_id) = mainnet_tx_version(fixture.height);
            assert_eq!(tx.version, version, "{}", fixture.name);
            if version >= TRANSACTION_VERSION_POST_HF5 {
                assert_eq!(tx.hardfork_id, hardfork_id, "{}", fixture.name);
            }
        }
        // Truncated anywhere, it is an error and not a panic.
        for cut in (0..fixture.tx.len()).step_by(37) {
            assert!(Transaction::from_bytes(&fixture.tx[..cut]).is_err());
        }
    }
}

/// The heights the main network changed transaction version at, as the
/// first transactions of its blocks show: version 2 from 2 555 001 to
/// 3 076 400, 3 up to 3 833 000, 4 above.
#[test]
fn hard_fork_heights() {
    assert_eq!(mainnet_tx_version(0), (1, 0));
    assert_eq!(mainnet_tx_version(194_625), (1, 1));
    assert_eq!(mainnet_tx_version(2_555_000), (1, 3));
    assert_eq!(mainnet_tx_version(2_555_001), (2, 4));
    assert_eq!(mainnet_tx_version(3_076_400), (2, 4));
    assert_eq!(mainnet_tx_version(3_076_401), (3, 5));
    assert_eq!(mainnet_tx_version(3_833_000), (3, 5));
    assert_eq!(mainnet_tx_version(3_833_001), (4, 7));
    assert_eq!(mainnet_hardfork_id(u64::MAX), HARDFORK_07);
    assert_eq!(tx_version_for_hardfork(HARDFORK_04_ZARCANUM), 2);
    assert_eq!(tx_version_for_hardfork(HARDFORK_05), 3);
    assert_eq!(tx_version_for_hardfork(HARDFORK_06), 4);
    assert_eq!(MAINNET_HARDFORK_HEIGHTS[4], 2_555_000);
}

/// Before hard fork 4: transparent outputs, ring signatures, and a layout
/// of its own.
#[test]
fn pre_zarcanum() {
    let (_, tx) = load("v1_transfer");
    assert_eq!(tx.version, TRANSACTION_VERSION_PRE_HF4);
    assert_eq!(names(&tx.vin), ["key"]);
    assert_eq!(names(&tx.vout), ["tx_out_bare"; 3]);
    assert_eq!(names(&tx.signatures), ["NLSAG_sig"]);
    assert!(tx.proofs.is_empty());
    assert_eq!(tx.fee(), None);
    assert_eq!(tx.bare_fee(), Some(10_000_000_000));
    let Variant::Nlsag(sig) = &tx.signatures[0] else {
        panic!()
    };
    assert_eq!(sig.s.len(), 11);
    let Variant::ToKey(input) = &tx.vin[0] else {
        panic!()
    };
    assert_eq!(
        (input.amount, input.key_offsets.len()),
        (400_000_000_000, 11)
    );
    assert_eq!(verify("v1_transfer", 0, None), Ok(()));
    // Not without its ring, with a shorter one, or once touched.
    assert_eq!(
        tx.verify(&VerifyContext::new(&[])),
        Err(VerifyError::MissingRing(0))
    );
    let (fixture, _) = load("v1_transfer");
    let ring = ggx_ring(&rings_from_binary(fixture.rings)[0]);
    assert!(tx.verify_input(0, &ring));
    assert!(!tx.verify_input(0, &ring[..3]));
    let mut swapped = ring.clone();
    swapped.swap(0, 1);
    assert_eq!(
        tx.verify(&VerifyContext::new(&[&swapped])),
        Err(VerifyError::InputSignature(0))
    );
    let mut bad = tx.clone();
    let Variant::OutBare(out) = &mut bad.vout[0] else {
        panic!()
    };
    out.amount += 1;
    assert!(!bad.verify_input(0, &ring));

    // The first transaction of a proof-of-work block creates the reward.
    let (_, tx) = load("v1_pow");
    assert!(tx.is_coinbase() && !tx.is_pos_coinbase());
    assert_eq!(verify("v1_pow", COIN, None), Ok(()));
    assert_eq!(verify("v1_pow", COIN + 1, None), Err(VerifyError::Balance));

    // That of a proof-of-stake block spends the stake, which signs the id
    // of the block.
    let (_, tx) = load("v1_pos");
    assert!(tx.is_pos_coinbase());
    assert_eq!(names(&tx.vin), ["gen", "key"]);
    let stake = StakeContext {
        block_id: h32("f67ed55382b1047b77a02df03d8a3066b46088211d0263667f5f12b935c29d4e"),
        ..Default::default()
    };
    assert_eq!(verify("v1_pos", COIN, Some(&stake)), Ok(()));
    assert_eq!(
        verify("v1_pos", COIN, None),
        Err(VerifyError::MissingStakeContext)
    );
    let other = StakeContext::default();
    assert_eq!(
        verify("v1_pos", COIN, Some(&other)),
        Err(VerifyError::InputSignature(1))
    );
}

/// Hard fork 4 (version 2): confidential outputs, spent from transparent
/// and confidential inputs.
#[test]
fn zarcanum_v2() {
    // Transparent inputs only: every output shows the native asset id, the
    // surjection proof is empty and the balance is over G.
    let (_, tx) = load("v2_bare");
    assert_eq!(tx.version, TRANSACTION_VERSION_POST_HF4);
    assert_eq!(names(&tx.vin), ["key"]);
    assert_eq!(names(&tx.signatures), ["NLSAG_sig"]);
    assert_eq!(
        names(&tx.vout),
        ["tx_out_zarcanum_v1", "tx_out_zarcanum_v1"]
    );
    assert_eq!(verify("v2_bare", 0, None), Ok(()));
    assert!(tx.verify_proofs());
    let mut bad = tx.clone();
    let Variant::ToKey(input) = &mut bad.vin[0] else {
        panic!()
    };
    input.amount += 1;
    // (The proofs are bound to the id, which the amount is part of.)
    assert_eq!(bad.try_verify_proofs(0), Err(VerifyError::RangeProof));

    // Confidential inputs.
    let (_, tx) = load("v2_zc");
    assert_eq!(names(&tx.signatures), ["ZC_sig"]);
    assert_eq!(verify("v2_zc", 0, None), Ok(()));
    let mut bad = tx.clone();
    let Variant::ZcSig(sig) = &mut bad.signatures[0] else {
        panic!()
    };
    sig.clsag_ggx.r_g[3][0] ^= 1;
    assert!(bad.verify_proofs());
    let (fixture, _) = load("v2_zc");
    let ring = ggx_ring(&rings_from_binary(fixture.rings)[0]);
    assert_eq!(
        bad.verify(&VerifyContext::new(&[&ring])),
        Err(VerifyError::InputSignature(0))
    );

    // The first transactions of blocks: the reward is one coin, fees are
    // burnt.
    assert_eq!(verify("v2_pow", COIN, None), Ok(()));
    assert_eq!(verify("v2_pow", COIN - 1, None), Err(VerifyError::Balance));
    assert_eq!(verify("v2_pow", 0, None), Err(VerifyError::Balance));
    // A proof-of-stake one, without the stake modifier of its time: its
    // proofs alone.
    let (_, tx) = load("v2_pos");
    assert_eq!(names(&tx.signatures), ["zarcanum_sig"]);
    assert!(tx.verify_coinbase_proofs(COIN));
    assert!(!tx.verify_coinbase_proofs(2 * COIN));
    assert!(!tx.verify_proofs());
}

/// Three outputs (the range proof is padded to four values): versions 3
/// and 4.
#[test]
fn three_outputs() {
    let (_, tx) = load("v3_three_outs");
    assert_eq!((tx.version, tx.vout.len()), (3, 3));
    assert!(tx.verify_proofs());
    let Some(Variant::OutsRangeProof(range)) = tx
        .proofs
        .iter()
        .find(|p| matches!(p, Variant::OutsRangeProof(_)))
    else {
        panic!()
    };
    assert_eq!(range.bpp.lv.len(), 8);
    let mut bad = tx.clone();
    let Variant::OutZarcanum(out) = &mut bad.vout[2] else {
        panic!()
    };
    out.encrypted_amount ^= 1;
    // The amount is not part of what the proofs cover but of the id.
    assert!(!bad.verify_proofs());

    let (_, tx) = load("v4_three_outs");
    assert_eq!((tx.version, tx.vin.len(), tx.vout.len()), (4, 2, 3));
    assert_eq!(verify("v4_three_outs", 0, None), Ok(()));
    // The inputs are sorted by key image.
    let mut bad = tx.clone();
    bad.vin.swap(0, 1);
    assert_eq!(
        bad.verify(&VerifyContext::new(&[&[], &[]])),
        Err(VerifyError::InputsNotSorted)
    );
}

/// Hard forks 6 and 7 (version 4): outputs with a payment id.
#[test]
fn hard_fork_7() {
    let (_, tx) = load("v4_transfer");
    assert_eq!((tx.version, tx.hardfork_id), (4, HARDFORK_07));
    assert_eq!(names(&tx.vout), ["tx_out_zarcanum", "tx_out_zarcanum"]);
    assert_eq!(verify("v4_transfer", 0, None), Ok(()));
    let mut bad = tx.clone();
    let Variant::OutZarcanumHf6(out) = &mut bad.vout[0] else {
        panic!()
    };
    out.encrypted_payment_id ^= 1;
    assert!(!bad.verify_proofs());
    assert_ne!(bad.prefix_hash(), tx.prefix_hash());

    // An alias registration.
    let (_, tx) = load("v4_alias");
    assert!(tx.verify_proofs());
    let Some(Variant::AliasEntry(alias)) = tx.extra.first() else {
        panic!()
    };
    assert!(!alias.alias.is_empty());

    // The first transaction of a proof-of-work block has no surjection
    // proof any more.
    let (_, tx) = load("v4_pow");
    assert_eq!(
        names(&tx.proofs),
        ["zc_outs_range_proof", "zc_balance_proof"]
    );
    assert_eq!(names(&tx.extra)[0], "etc_coinbase_block_cumulative_size");
    assert_eq!(verify("v4_pow", COIN, None), Ok(()));
    assert_eq!(verify("v4_pow", COIN + 1, None), Err(VerifyError::Balance));
}

/// The stake contexts of the two proof-of-stake blocks: the stake modifier
/// and the difficulty are what the daemon's `get_pos_details` gave while
/// the block before was the last one.
fn stake_context(name: &str) -> StakeContext {
    let (block_id, timestamp, modifier, difficulty) = match name {
        "v4_pos_a" => (
            "8e3053ce1171bbfeb152af0d9add3c6f8e01dcdf9c1024b980fc22c138eae708",
            1_794_349_440,
            "37c3d4ed85e4c5b914b93d78a281433b9d78b671f577e2613b0ebd1b8b9676b3\
             9c0f6705f9a6d16b434b94534802af10cf2e3d31e3806153b4990f466dcf4293",
            3_624_489_936_728_536_232_512u128,
        ),
        _ => (
            "634275e35d7f6d42ed2817761c7ca9a89325c490175ca9abd04764aee329bdcf",
            1_794_349_185,
            "236c1cc321d35a45bec668a0d390bd63fffb37738c4386cb4b3b52826bf2ff1a\
             5395155c49ed5d4aa733431b81a1fa1f37f96855cdcd73a7dc6016ca519078f0",
            3_576_358_761_138_523_368_232u128,
        ),
    };
    let (fixture, _) = load(name);
    StakeContext {
        block_id: h32(block_id),
        timestamp,
        last_pow_id: h32(&modifier[..64]),
        last_pos_kernel_id: h32(&modifier[64..]),
        pos_difficulty: difficulty,
        ring: rings_from_binary(fixture.rings).remove(0),
    }
}

/// The Zarcanum proof of stake of two blocks of the main network.
#[test]
fn proof_of_stake() {
    for name in ["v4_pos_a", "v4_pos_b"] {
        let (_, tx) = load(name);
        assert!(tx.is_pos_coinbase());
        assert_eq!(names(&tx.signatures), ["zarcanum_sig"]);
        let stake = stake_context(name);
        let context = VerifyContext::new(&[]).block_reward(COIN);
        assert_eq!(tx.verify(&context.stake(&stake)), Ok(()), "{name}");
        assert_eq!(tx.verify(&context), Err(VerifyError::MissingStakeContext));
    }

    // Everything the proof is about is bound to it.
    let (_, tx) = load("v4_pos_a");
    let good = stake_context("v4_pos_a");
    let Variant::ZcInput(input) = &tx.vin[1] else {
        panic!()
    };
    let Variant::ZarcanumSig(sig) = &tx.signatures[0] else {
        panic!()
    };
    assert!(verify_zarcanum_proof(&good, &input.key_image, sig));
    let broken = |change: &dyn Fn(&mut StakeContext)| {
        let mut stake = good.clone();
        change(&mut stake);
        !verify_zarcanum_proof(&stake, &input.key_image, sig)
    };
    assert!(broken(&|s| s.block_id[0] ^= 1));
    assert!(broken(&|s| s.timestamp += 15));
    assert!(broken(&|s| s.last_pow_id[0] ^= 1));
    assert!(broken(&|s| s.last_pos_kernel_id[0] ^= 1));
    assert!(broken(&|s| s.ring.swap(0, 1)));
    assert!(broken(&|s| s.ring.truncate(15)));
    // A difficulty the stake does not meet, and none at all.
    assert!(broken(&|s| s.pos_difficulty <<= 24));
    assert!(broken(&|s| s.pos_difficulty = 0));
    // The parts of the proof on their own.
    assert!(verify_bppe(&sig.e_range_proof, &[sig.e]));
    assert!(!verify_bppe(&sig.e_range_proof, &[sig.c_point]));
    let mut bad = (**sig).clone();
    bad.y4[0] ^= 1;
    assert!(!verify_zarcanum_proof(&good, &input.key_image, &bad));
    let mut bad = (**sig).clone();
    bad.clsag_ggxxg.r_x[5][0] ^= 1;
    assert!(!verify_zarcanum_proof(&good, &input.key_image, &bad));
    let mut bad = (**sig).clone();
    bad.e_range_proof.delta_2[0] ^= 1;
    assert!(!verify_zarcanum_proof(&good, &input.key_image, &bad));
    // And the reward.
    let context = VerifyContext::new(&[]).stake(&good);
    assert_eq!(
        tx.verify(&context.block_reward(COIN + 1)),
        Err(VerifyError::Balance)
    );
}

/// A transparent and two confidential inputs in one transaction: the
/// native coin of the former is a member of the surjection rings.
#[test]
fn mixed_inputs() {
    let (_, tx) = load("v2_mixed");
    assert_eq!(names(&tx.vin), ["key", "txin_zc_input", "txin_zc_input"]);
    assert_eq!(names(&tx.signatures), ["NLSAG_sig", "ZC_sig", "ZC_sig"]);
    assert_eq!(verify("v2_mixed", 0, None), Ok(()));
    // Each signature is of its own input.
    let mut bad = tx.clone();
    bad.signatures.swap(1, 2);
    let (fixture, _) = load("v2_mixed");
    let rings: Vec<Vec<ClsagGgxInput>> = rings_from_binary(fixture.rings)
        .iter()
        .map(|ring| ggx_ring(ring))
        .collect();
    let refs: Vec<&[ClsagGgxInput]> = rings.iter().map(Vec::as_slice).collect();
    assert_eq!(
        bad.verify(&VerifyContext::new(&refs)),
        Err(VerifyError::InputSignature(1))
    );
    assert_eq!(
        tx.verify(&VerifyContext::new(&refs[..2])),
        Err(VerifyError::MissingRing(2))
    );
}

/// Five inputs: the surjection proofs are over rings of five, the first
/// size the one-out-of-many proof needs two digits for (and zanolib got
/// wrong).
#[test]
fn five_inputs() {
    let (_, tx) = load("v4_five_inputs");
    assert_eq!((tx.vin.len(), tx.vout.len()), (5, 2));
    let Some(Variant::AssetSurjectionProof(surjection)) = tx.proofs.first() else {
        panic!()
    };
    assert_eq!(surjection.bge_proofs.len(), 2);
    assert_eq!(surjection.bge_proofs[0].pk.len(), 2);
    assert_eq!(surjection.bge_proofs[0].f.len(), 6);
    assert_eq!(verify("v4_five_inputs", 0, None), Ok(()));
    let mut bad = tx.clone();
    let Some(Variant::AssetSurjectionProof(surjection)) = bad.proofs.first_mut() else {
        panic!()
    };
    surjection.bge_proofs[1].f[5][0] ^= 1;
    assert_eq!(bad.try_verify_proofs(0), Err(VerifyError::AssetSurjection));
}

/// Asset operations: registration (in the forms of hard forks 4 and 5),
/// emission signed by a Zano key and by an Ethereum key, and public burn.
/// The asset ids the registrations derive are the ids the daemon lists
/// these assets under (`get_asset_info`).
#[test]
fn asset_operations() {
    // A registration of hard fork 4: version 1, the descriptor tells the
    // supply.
    let (_, tx) = load("v2_asset_register");
    let ado = tx.asset_operation().unwrap();
    assert_eq!(
        (ado.operation_type, ado.version),
        (ASSET_DESCRIPTOR_OPERATION_REGISTER, 1)
    );
    let descriptor = ado.descriptor.as_ref().unwrap();
    assert_eq!(
        (&descriptor.ticker[..], descriptor.current_supply),
        (&b"OBSC"[..], 1)
    );
    assert_eq!(
        ado.target_asset_id(),
        Some(h32(
            "97607ec5fb61d5a4b6435165378ae5be45acdeacbbf657a6fe0018c9c1dbda77"
        ))
    );
    assert!(ado.is_emitting());
    assert_eq!(tx.vout.len(), 11);
    assert_eq!(verify("v2_asset_register", 0, None), Ok(()));
    // Another supply, another asset: neither the surjection of the new
    // coins nor the amount commitment holds.
    let mut bad = tx.clone();
    let Variant::AssetOperation(ado) = &mut bad.extra[0] else {
        panic!()
    };
    ado.descriptor.as_mut().unwrap().current_supply = 2;
    assert!(bad.verify_asset_operation(None).is_err());
    assert!(!bad.verify_proofs());

    // A registration of hard fork 5: version 2, with an amount and a salt
    // that goes into the id.
    let (_, tx) = load("v3_asset_register");
    let ado = tx.asset_operation().unwrap();
    assert_eq!((ado.version, ado.amount), (2, Some(1)));
    assert_eq!(ado.asset_id_salt, Some(3_990_860_236));
    let id = h32("17c3094e9f8aa08bd11c880fa9612d2eb36d6f647cae3713e3099aa94c83966b");
    assert_eq!(ado.target_asset_id(), Some(id));
    let descriptor = ado.descriptor.as_ref().unwrap();
    assert_eq!(descriptor.asset_id(ado.asset_id_salt), id);
    assert_ne!(descriptor.asset_id(None), id);
    assert_eq!(verify("v3_asset_register", 0, None), Ok(()));
    assert_eq!(tx.verify_asset_operation(None), Ok(()));

    // An emission of fUSD: the owner of the asset signs.
    let (fixture, tx) = load("v3_asset_emit");
    let ado = tx.asset_operation().unwrap();
    assert_eq!(
        (ado.operation_type, ado.amount),
        (ASSET_DESCRIPTOR_OPERATION_EMIT, Some(1_000_000_000))
    );
    assert_eq!(
        ado.asset_id,
        Some(h32(
            "86143388bd056a8f0bab669f78f14873fac8e2dd8d57898cdb725a2d5e2e4f8f"
        ))
    );
    let owner = AssetDescriptorBase {
        owner: h32("497d6b7acd06401c59b2d52a3967968e8ca507a25f80e44d2bb4b5f8a348c7c1"),
        ..Default::default()
    };
    let rings: Vec<Vec<ClsagGgxInput>> = rings_from_binary(fixture.rings)
        .iter()
        .map(|ring| ggx_ring(ring))
        .collect();
    let refs: Vec<&[ClsagGgxInput]> = rings.iter().map(Vec::as_slice).collect();
    let context = VerifyContext::new(&refs);
    assert_eq!(tx.verify(&context.asset_descriptor(&owner)), Ok(()));
    assert_eq!(
        tx.verify(&context),
        Err(VerifyError::MissingAssetDescriptor)
    );
    let other = AssetDescriptorBase {
        owner: POINT_U,
        ..Default::default()
    };
    assert_eq!(
        tx.verify(&context.asset_descriptor(&other)),
        Err(VerifyError::AssetOwnership)
    );

    // An emission of ETHX, an asset owned by a secp256k1 key.
    let (_, tx) = load("v3_asset_emit_eth");
    assert_eq!(names(&tx.proofs)[4], "asset_operation_ownership_proof_eth");
    assert!(tx.verify_proofs());
    let mut key = [0u8; 33];
    hex::decode_to_slice(
        "03f3e70f95b08f6238acca21dab908a46cab1e4ce8a0761a2d11353218c9952702",
        &mut key,
    )
    .unwrap();
    let owner = AssetDescriptorBase {
        owner_eth_pub_key: Some(key),
        ..Default::default()
    };
    #[cfg(feature = "secp256k1")]
    {
        assert_eq!(tx.verify_asset_operation(Some(&owner)), Ok(()));
        let mut other = owner.clone();
        other.owner_eth_pub_key.as_mut().unwrap()[0] = 2;
        assert_eq!(
            tx.verify_asset_operation(Some(&other)),
            Err(VerifyError::AssetOwnership)
        );
        let Some(Variant::AssetOwnershipProofEth(proof)) = tx.proofs.last() else {
            panic!()
        };
        assert!(verify_eth_signature(
            &tx.prefix_hash(),
            &key,
            &proof.eth_sig
        ));
        assert!(!verify_eth_signature(&[1u8; 32], &key, &proof.eth_sig));
    }
    #[cfg(not(feature = "secp256k1"))]
    assert_eq!(
        tx.verify_asset_operation(Some(&owner)),
        Err(VerifyError::Unsupported)
    );

    // A public burn: no owner needed, the amount is proven.
    let (_, tx) = load("v3_asset_burn");
    let ado = tx.asset_operation().unwrap();
    assert_eq!(
        (ado.operation_type, ado.amount),
        (ASSET_DESCRIPTOR_OPERATION_PUBLIC_BURN, Some(5000))
    );
    assert!(!ado.is_emitting());
    assert!(tx.verify_proofs());
    assert_eq!(tx.verify_asset_operation(None), Ok(()));
    let mut bad = tx.clone();
    let Some(Variant::AssetOperationProof(proof)) = bad
        .proofs
        .iter_mut()
        .find(|p| matches!(p, Variant::AssetOperationProof(_)))
    else {
        panic!()
    };
    proof.amount_commitment_g_proof.as_mut().unwrap()[0] ^= 1;
    assert_eq!(
        bad.verify_asset_operation(None),
        Err(VerifyError::AssetOperation)
    );
}

/// Parsing is total: any change to a transaction gives a transaction or an
/// error, variants cannot nest deep enough to exhaust the stack, and a
/// count cannot make the parser allocate what the input does not hold.
#[test]
fn parsing_bounds() {
    for name in ["v1_transfer", "v4_pow", "v3_asset_emit_eth"] {
        let (fixture, _) = load(name);
        let mut bytes = fixture.tx.to_vec();
        for i in (0..bytes.len()).step_by(3) {
            for flip in [0x01, 0x80, 0xff] {
                bytes[i] ^= flip;
                if let Ok(tx) = Transaction::from_bytes(&bytes) {
                    // What parses serializes, and parses back the same.
                    assert_eq!(Transaction::from_bytes(&tx.to_bytes()), Ok(tx));
                }
                bytes[i] ^= flip;
            }
        }
    }

    // A transparent input whose ring is a transparent input whose ring...
    let mut nested = vec![2u8, 1];
    for _ in 0..100_000 {
        nested.extend_from_slice(&[1, 0, 1]);
    }
    assert_eq!(Transaction::from_bytes(&nested), Err(Error::TooDeep));
    // A bare output whose target is not a target is still bounded.
    let mut nested = vec![2u8, 0, 0, 1];
    for _ in 0..100_000 {
        nested.extend_from_slice(&[36, 0]);
    }
    assert_eq!(Transaction::from_bytes(&nested), Err(Error::TooDeep));

    // A count far beyond the input.
    for count in [&[0xff, 0xff, 0xff, 0xff, 0x0f][..], &[0xff; 9][..]] {
        let mut bytes = vec![2u8];
        bytes.extend_from_slice(count);
        assert!(Transaction::from_bytes(&bytes).is_err());
    }
    // A version this module does not know.
    assert_eq!(
        Transaction::from_bytes(&[5, 0, 0, 0, 0, 0, 0, 0]),
        Err(Error::UnsupportedVersion)
    );
    // Versions of structures above the ones known.
    let (fixture, tx) = load("v4_pow");
    let position = fixture
        .tx
        .windows(2)
        .position(|w| w == [63, 0])
        .expect("an output");
    let mut bytes = fixture.tx.to_vec();
    bytes[position + 1] = 1;
    assert_eq!(
        Transaction::from_bytes(&bytes),
        Err(Error::UnsupportedVersion)
    );
    assert!(tx.vout.iter().all(|out| out.zarcanum_out().is_some()));
}
