//! Tests of the Action circuit against the `orchard` crate (0.16.0) and
//! against the chain.
//!
//! The reference data comes from the `orchard` crate itself: the files
//! `src/circuit_data/circuit_description_*` (the pretty-printed pinned
//! verifying key of each circuit version, which that crate's own tests
//! compare its keys with; too large to copy here, so their BLAKE2b-256
//! hashes are embedded: `b2sum -l 256`) and
//! `src/circuit_data/circuit_proof_test_case_*.bin` (an instance and a
//! proof for each version, copied to `testdata/`).
//!
//! The chain data is five transactions of the main network
//! (`testdata/mainnet_tx_*.hex`, named after their ids), one or two for
//! each circuit version:
//!
//! | id (start) | height    | upgrade | format | circuit            |
//! |------------|-----------|---------|--------|--------------------|
//! | `db84ddff` |           | NU5     | v5     | `InsecurePreNu6_2` |
//! | `3ecd7b89` | 3 400 076 | NU6.2   | v5     | `FixedPostNu6_2`   |
//! | `b0fd5d92` | 3 428 142 | NU6.2   | v5     | `FixedPostNu6_2`   |
//! | `e39eab2b` | 3 428 147 | NU6.3   | v6     | `PostNu6_3`        |
//! | `2be7cf25` | 3 550 069 | NU7     | v6     | `PostNu6_3`        |
//!
//! From NU6.3 wallets use version 6 transactions: the tests below locate
//! the Orchard bundle (which has the layout it has in version 5) in them
//! by hand, and the Ironwood bundle that follows it (the tests of
//! `zcashtx` parse these same transactions whole, and others). None of
//! these transactions has transparent inputs, so their
//! signature hash for shielded inputs is their id (ZIP 244). The reference
//! (`zcash_primitives` 0.31.0 and `orchard` 0.16.0: the scratch program
//! `checktx`) computes the same ids from these files and accepts the
//! proofs and signatures of all their bundles.

use alloc::format;
use alloc::vec::Vec;

use purecrypto::hash::Blake2bMac;

use super::*;
use crate::orchard::bundle::BundleRef;
use crate::orchard::halo2::Error as Halo2Error;

/// BLAKE2b-256 of `circuit_description_{insecure,fixed,post_nu6_3}`.
const DESCRIPTION_HASHES: [(CircuitVersion, &str); 3] = [
    (
        CircuitVersion::InsecurePreNu6_2,
        "6993a245ea4279226115b1a527f0467c4ba3c28f177e22a64e21c2cf42d79d03",
    ),
    (
        CircuitVersion::FixedPostNu6_2,
        "304042ff591546182a2a73155cb4cebc60dc7ab4b812038be7743f1fe6297061",
    ),
    (
        CircuitVersion::PostNu6_3,
        "78e4047256ca39cdab3ea0cd1785ce253e4c2bb155818fc6fc4ba67bcb62fdae",
    ),
];

fn blake2b_256(data: &[u8]) -> alloc::string::String {
    let mut h = Blake2bMac::new_unkeyed(32);
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_into(&mut out);
    hex::encode(out)
}

/// The embedded keys, built once for all the tests.
pub(crate) fn keys() -> &'static [VerifyingKey; 3] {
    static KEYS: std::sync::OnceLock<[VerifyingKey; 3]> = std::sync::OnceLock::new();
    KEYS.get_or_init(VerifyingKey::embedded_all)
}

/// The embedded key of a version.
pub(crate) fn key(version: CircuitVersion) -> &'static VerifyingKey {
    keys().iter().find(|vk| vk.version() == version).unwrap()
}

/// The description of a key as the `orchard` crate's tests print it.
fn description(vk: &VerifyingKey) -> alloc::string::String {
    format!("{:#?}\n", vk.halo2().pinned())
}

/// The embedded keys rebuild into exactly the reference keys.
#[test]
fn embedded_verifying_keys_match_the_reference() {
    for (version, hash) in DESCRIPTION_HASHES {
        let vk = key(version);
        assert_eq!(blake2b_256(description(vk).as_bytes()), hash, "{version:?}");
    }
}

/// Key generation from scratch gives the reference keys, and the embedded
/// data is what it produces. With `OUTSCRIPT_DUMP_DIR` set, writes the
/// descriptions (to diff with the reference files) and the `vk_*.bin`
/// and `g_lagrange.bin` files to embed.
#[test]
#[ignore = "slow in the test profile"]
fn generated_verifying_keys_match_the_reference() {
    let params = Params::new(K);
    let g_lagrange: Vec<u8> = params.g_lagrange[..INSTANCE_ROWS]
        .iter()
        .flat_map(|p| p.to_bytes())
        .collect();
    #[cfg(feature = "std")]
    if let Ok(dir) = std::env::var("OUTSCRIPT_DUMP_DIR") {
        std::fs::write(format!("{dir}/g_lagrange.bin"), &g_lagrange).unwrap();
    }
    let mut stale = g_lagrange != G_LAGRANGE[..];
    for (version, hash) in DESCRIPTION_HASHES {
        let t = std::time::Instant::now();
        let (vk, plan) =
            halo2::keygen_vk_with_plan(&params, &ActionCircuit::empty(version)).unwrap();
        std::eprintln!("{version:?}: verifying key generated in {:?}", t.elapsed());
        let embedded = EmbeddedKey::from_vk(&vk, &plan).to_bytes();
        let vk = VerifyingKey {
            params: params.clone(),
            vk,
            version,
        };
        #[cfg(feature = "std")]
        if let Ok(dir) = std::env::var("OUTSCRIPT_DUMP_DIR") {
            let name = match version {
                CircuitVersion::InsecurePreNu6_2 => "insecure_pre_nu6_2",
                CircuitVersion::FixedPostNu6_2 => "fixed_post_nu6_2",
                CircuitVersion::PostNu6_3 => "post_nu6_3",
            };
            std::fs::write(format!("{dir}/description_{name}"), description(&vk)).unwrap();
            std::fs::write(format!("{dir}/vk_{name}.bin"), &embedded).unwrap();
        }
        assert_eq!(
            blake2b_256(description(&vk).as_bytes()),
            hash,
            "{version:?}"
        );
        stale |= embedded != version.embedded();
    }
    assert!(!stale, "the embedded verifying keys are out of date");
}

/// A test case of the `orchard` crate: the public inputs of one action
/// (anchor, cv, nf, rk, cmx, the flags) and its proof.
pub(crate) fn read_test_case(data: &[u8], three_flags: bool) -> (Instance, &[u8]) {
    let field = |i: usize| -> [u8; 32] { data[32 * i..32 * i + 32].try_into().unwrap() };
    let flags = if three_flags { 3 } else { 2 };
    let instance = Instance {
        anchor: Fp::from_bytes(&field(0)).unwrap(),
        cv_net: pallas::Affine::from_bytes(&field(1)).unwrap(),
        nf_old: Fp::from_bytes(&field(2)).unwrap(),
        rk: pallas::Affine::from_bytes(&field(3)).unwrap(),
        cmx: Fp::from_bytes(&field(4)).unwrap(),
        enable_spend: data[160] == 1,
        enable_output: data[161] == 1,
        disable_cross_address: three_flags && data[162] == 1,
    };
    (instance, &data[160 + flags..])
}

const TEST_CASES: [(CircuitVersion, &[u8], bool); 4] = [
    (
        CircuitVersion::InsecurePreNu6_2,
        include_bytes!("../testdata/circuit_proof_test_case_insecure.bin"),
        false,
    ),
    (
        CircuitVersion::FixedPostNu6_2,
        include_bytes!("../testdata/circuit_proof_test_case_fixed.bin"),
        false,
    ),
    (
        CircuitVersion::PostNu6_3,
        include_bytes!("../testdata/circuit_proof_test_case_post_nu6_3.bin"),
        true,
    ),
    (
        CircuitVersion::PostNu6_3,
        include_bytes!("../testdata/circuit_proof_test_case_post_nu6_3_restricted.bin"),
        true,
    ),
];

/// The proofs of the `orchard` crate's test cases verify, each with the key
/// of its circuit version only.
#[test]
fn reference_proofs_verify() {
    let keys = keys();
    let mut restricted = 0;
    for (version, data, three_flags) in TEST_CASES {
        let (instance, proof) = read_test_case(data, three_flags);
        assert_eq!(proof.len(), proof_size(1));
        restricted += instance.disable_cross_address as usize;
        for vk in keys.iter() {
            let result = verify_proof(vk, &[instance], proof);
            if vk.version() == version {
                assert_eq!(result, Ok(()), "{version:?}");
            } else {
                assert!(result.is_err(), "{version:?} with {:?}", vk.version());
            }
        }
        // other public inputs do not verify
        let vk = keys.iter().find(|vk| vk.version() == version).unwrap();
        let mut wrong = instance;
        wrong.cmx += Fp::ONE;
        assert_eq!(
            verify_proof(vk, &[wrong], proof),
            Err(Halo2Error::InvalidProof)
        );
        let mut wrong = instance;
        wrong.enable_spend = !wrong.enable_spend;
        assert!(verify_proof(vk, &[wrong], proof).is_err());
        if version.supports_cross_address_restriction() {
            let mut wrong = instance;
            wrong.disable_cross_address = !wrong.disable_cross_address;
            assert!(verify_proof(vk, &[wrong], proof).is_err());
        }
    }
    // one of the cases has the cross-address restriction on
    assert_eq!(restricted, 1);
}

/// The proof of a mainnet transaction (two actions, mined before NU6.2)
/// verifies with the key of its time, and with no other.
#[test]
fn mainnet_proof_verifies() {
    use crate::zcashtx::ZcashTx;
    let raw = hex::decode(include_str!("../testdata/mainnet_tx_db84ddff.hex").trim()).unwrap();
    let tx = ZcashTx::parse_into(&raw, &mut [], &mut []).unwrap();
    let bundle = BundleRef::parse(tx.orchard).unwrap().unwrap();
    assert_eq!(bundle.proof().len(), proof_size(2));
    // for the reference check (`checkbundle insecure <sighash> @mainnet_bundle.hex`)
    #[cfg(feature = "std")]
    if let Ok(dir) = std::env::var("OUTSCRIPT_DUMP_DIR") {
        let sighash = tx.sighash(None, crate::zcashtx::SIGHASH_ALL, &[]).unwrap();
        std::fs::write(format!("{dir}/mainnet_bundle.hex"), hex::encode(tx.orchard)).unwrap();
        std::fs::write(format!("{dir}/mainnet_sighash.hex"), hex::encode(sighash)).unwrap();
    }

    let vk = key(CircuitVersion::InsecurePreNu6_2);
    assert_eq!(bundle.verify_proof(vk), Ok(()));
    let fixed = key(CircuitVersion::FixedPostNu6_2);
    assert_eq!(
        bundle.verify_proof(fixed),
        Err(crate::orchard::Error::InvalidProof)
    );

    // a modified bundle does not verify
    let mut owned = bundle.to_owned();
    owned.value_balance += 1;
    let bytes = owned.to_bytes();
    // (the value balance is not a public input of the proof)
    assert_eq!(
        BundleRef::parse(&bytes).unwrap().unwrap().verify_proof(vk),
        Ok(())
    );
    owned.actions[1].cmx[0] ^= 1;
    let bytes = owned.to_bytes();
    assert_eq!(
        BundleRef::parse(&bytes).unwrap().unwrap().verify_proof(vk),
        Err(crate::orchard::Error::InvalidProof)
    );
    // before NU6.2 the length of the proof was not a consensus rule: what
    // follows the proof proper is ignored, a shorter one cannot verify
    let mut owned = bundle.to_owned();
    owned.proof.push(0);
    let bytes = owned.to_bytes();
    assert_eq!(
        BundleRef::parse(&bytes).unwrap().unwrap().verify_proof(vk),
        Ok(())
    );
    owned.proof.truncate(proof_size(2) - 1);
    let bytes = owned.to_bytes();
    assert_eq!(
        BundleRef::parse(&bytes).unwrap().unwrap().verify_proof(vk),
        Err(crate::orchard::Error::InvalidProof)
    );
    for i in [0, 100, 2000, 7000] {
        let mut owned = bundle.to_owned();
        owned.proof[i] ^= 0x10;
        let bytes = owned.to_bytes();
        assert!(
            BundleRef::parse(&bytes)
                .unwrap()
                .unwrap()
                .verify_proof(vk)
                .is_err()
        );
    }
}

/// The circuit version of each consensus branch and height, as
/// `zcash_protocol` 0.11.0 and `orchard` 0.16.0 give them.
#[test]
fn circuit_version_selection() {
    use crate::orchard::unified::Network;
    use CircuitVersion::*;
    for (branch, expected) in [
        (0u32, None),
        (0x5ba8_1b19, None),
        (0x76b8_09bb, None),
        (0x2bb4_0e60, None),
        (0xf5b9_230b, None),
        (0xe9ff_75a6, None),
        (0xc2d6_d0b4, Some(InsecurePreNu6_2)),
        (0xc8e7_1055, Some(InsecurePreNu6_2)),
        (0x4dec_4df0, Some(InsecurePreNu6_2)),
        (0x5437_f330, Some(FixedPostNu6_2)),
        (0x37a5_165b, Some(PostNu6_3)),
        (0x7719_0ad9, Some(PostNu6_3)),
        (0xffff_ffff, None),
    ] {
        assert_eq!(CircuitVersion::for_branch_id(branch), expected);
    }
    for (network, height, expected) in [
        (Network::Main, 0, None),
        (Network::Main, 1_687_103, None),
        (Network::Main, 1_687_104, Some(InsecurePreNu6_2)),
        (Network::Main, 3_364_599, Some(InsecurePreNu6_2)),
        (Network::Main, 3_364_600, Some(FixedPostNu6_2)),
        (Network::Main, 3_428_142, Some(FixedPostNu6_2)),
        (Network::Main, 3_428_143, Some(PostNu6_3)),
        (Network::Main, 3_543_405, Some(PostNu6_3)),
        (Network::Main, u32::MAX, Some(PostNu6_3)),
        (Network::Test, 1_842_419, None),
        (Network::Test, 1_842_420, Some(InsecurePreNu6_2)),
        (Network::Test, 4_051_999, Some(InsecurePreNu6_2)),
        (Network::Test, 4_052_000, Some(FixedPostNu6_2)),
        (Network::Test, 4_133_999, Some(FixedPostNu6_2)),
        (Network::Test, 4_134_000, Some(PostNu6_3)),
        (Network::Regtest, 4_134_000, None),
    ] {
        assert_eq!(CircuitVersion::for_height(network, height), expected);
    }
}

/// The transactions of the main network made after NU6.2, with their ids.
const TX_3ECD7B89: (&str, &str) = (
    include_str!("../testdata/mainnet_tx_3ecd7b89.hex"),
    "3ecd7b89d8fa204562d42bb72bb68c9cc09f45542a7659c9d0f87e3dbb92331e",
);
const TX_B0FD5D92: (&str, &str) = (
    include_str!("../testdata/mainnet_tx_b0fd5d92.hex"),
    "b0fd5d921bb44779124e2ba10128b5bfc8ea6c8e044e7802717cb43b7b671450",
);
const TX_E39EAB2B: (&str, &str) = (
    include_str!("../testdata/mainnet_tx_e39eab2b.hex"),
    "e39eab2bad5e0d210d4a5894e5b69254d5ecd888c8edcc46e0bd49936f1ea64a",
);
const TX_2BE7CF25: (&str, &str) = (
    include_str!("../testdata/mainnet_tx_2be7cf25.hex"),
    "2be7cf251872c4b20ce779efa0cf021c0a1eee42010dccc38db70973b4b8d439",
);

/// The signature hash for shielded inputs of a transaction without
/// transparent inputs: its id, in the byte order of the digest.
fn sighash_of_txid(txid: &str) -> [u8; 32] {
    let mut id: [u8; 32] = hex::decode(txid).unwrap().try_into().unwrap();
    id.reverse();
    id
}

/// The serialized Orchard bundle of a version 5 transaction (checked to
/// have the id given, and no transparent input), and its signature hash.
fn v5_orchard((raw, txid): (&str, &str), branch: u32) -> (Vec<u8>, [u8; 32]) {
    use crate::zcashtx::{SIGHASH_ALL, ZcashTx};
    let raw = hex::decode(raw.trim()).unwrap();
    let tx = ZcashTx::parse_into(&raw, &mut [], &mut []).unwrap();
    assert_eq!(tx.consensus_branch_id, branch);
    assert_eq!(hex::encode(tx.txid().unwrap()), txid);
    let sighash = tx.sighash(None, SIGHASH_ALL, &[]).unwrap();
    assert_eq!(sighash, sighash_of_txid(txid));
    (tx.orchard.to_vec(), sighash)
}

/// The serialized Orchard and Ironwood bundles of a version 6 transaction
/// without transparent inputs or Sapling parts, and its signature hash.
/// The header and the transparent and Sapling parts are laid out as in
/// version 5, the two bundles follow, each as the Orchard bundle of
/// version 5 (`Transaction::read_v6` of `zcash_primitives` 0.31.0).
fn v6_bundles((raw, txid): (&str, &str), branch: u32) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let raw = hex::decode(raw.trim()).unwrap();
    // version 6 with the overwintered bit, its version group id
    assert_eq!(raw[..4], 0x8000_0006u32.to_le_bytes());
    assert_eq!(raw[4..8], 0xd884_b698u32.to_le_bytes());
    assert_eq!(raw[8..12], branch.to_le_bytes());
    // lock time, expiry height; no transparent input
    let mut rest = &raw[20..];
    assert_eq!(rest[0], 0);
    let outputs = rest[1] as usize;
    assert!(outputs < 0xfd);
    rest = &rest[2..];
    for _ in 0..outputs {
        let script = rest[8] as usize;
        assert!(script < 0xfd);
        rest = &rest[9 + script..];
    }
    // no Sapling spend or output
    assert_eq!(rest[..2], [0, 0]);
    rest = &rest[2..];
    let both = rest;
    BundleRef::read(&mut rest).unwrap().unwrap();
    let orchard = &both[..both.len() - rest.len()];
    (orchard.to_vec(), rest.to_vec(), sighash_of_txid(txid))
}

/// Checks a bundle of the chain: its proof with the key of `version` and
/// with no other, and its signatures.
fn check_chain_bundle(bytes: &[u8], sighash: &[u8; 32], version: CircuitVersion) {
    let bundle = BundleRef::parse(bytes).unwrap().unwrap();
    assert_eq!(bundle.action_count(), 2);
    assert_eq!(bundle.proof().len(), proof_size(2));
    assert_eq!(bundle.verify_signatures(sighash), Ok(()));
    assert!(bundle.verify_signatures(&[0u8; 32]).is_err());
    for vk in keys() {
        let result = bundle.verify_proof(vk);
        if vk.version() == version {
            assert_eq!(result, Ok(()), "{version:?}");
        } else {
            assert_eq!(
                result,
                Err(crate::orchard::Error::InvalidProof),
                "{version:?} with {:?}",
                vk.version()
            );
        }
    }
}

/// Two transactions mined under NU6.2 (the second in its last block):
/// their proofs are for the corrected circuit.
#[test]
fn mainnet_nu6_2_bundles_verify() {
    for tx in [TX_3ECD7B89, TX_B0FD5D92] {
        let (bytes, sighash) = v5_orchard(tx, 0x5437_f330);
        assert_eq!(
            CircuitVersion::for_branch_id(0x5437_f330),
            Some(CircuitVersion::FixedPostNu6_2)
        );
        check_chain_bundle(&bytes, &sighash, CircuitVersion::FixedPostNu6_2);
        // from NU6.2 the proof must have its exact length
        let mut owned = BundleRef::parse(&bytes).unwrap().unwrap().to_owned();
        owned.proof.push(0);
        let longer = owned.to_bytes();
        assert_eq!(
            BundleRef::parse(&longer)
                .unwrap()
                .unwrap()
                .verify_proof(key(CircuitVersion::FixedPostNu6_2)),
            Err(crate::orchard::Error::InvalidProof)
        );
    }
}

/// The Orchard bundles of two version 6 transactions, mined under NU6.3
/// and under NU7: their proofs are for the NU6.3 circuit, with the
/// cross-address restriction on.
#[test]
fn mainnet_nu6_3_and_nu7_orchard_bundles_verify() {
    for (tx, branch) in [(TX_E39EAB2B, 0x37a5_165b), (TX_2BE7CF25, 0x7719_0ad9)] {
        let (orchard, _, sighash) = v6_bundles(tx, branch);
        assert_eq!(
            CircuitVersion::for_branch_id(branch),
            Some(CircuitVersion::PostNu6_3)
        );
        check_chain_bundle(&orchard, &sighash, CircuitVersion::PostNu6_3);
        // the restriction is a public input of these proofs
        let bundle = BundleRef::parse(&orchard).unwrap().unwrap();
        let vk = key(CircuitVersion::PostNu6_3);
        let mut instances = bundle.instances(vk.version()).unwrap();
        assert!(instances.iter().all(|i| i.disable_cross_address));
        assert_eq!(verify_proof(vk, &instances, bundle.proof()), Ok(()));
        instances[1].disable_cross_address = false;
        assert!(verify_proof(vk, &instances, bundle.proof()).is_err());
    }
}

/// The Ironwood bundle of a transaction mined under NU7 (one action): the
/// same circuit, without the cross-address restriction. Read as an
/// Orchard bundle, which it is but for the `enableCrossAddress` bit of its
/// flags, it is restricted, and its proof is not valid.
#[test]
fn mainnet_ironwood_proof_verifies() {
    let (_, mut ironwood, sighash) = v6_bundles(TX_2BE7CF25, 0x7719_0ad9);
    // one action; spends, outputs and cross-address transfers enabled
    assert_eq!(ironwood[0], 1);
    let flags = 1 + crate::orchard::bundle::ACTION_SIZE;
    assert_eq!(ironwood[flags], 0b111);
    assert_eq!(
        BundleRef::parse(&ironwood).err(),
        Some(crate::orchard::Error::InvalidFlags)
    );
    ironwood[flags] = 0b011;
    let bundle = BundleRef::parse(&ironwood).unwrap().unwrap();
    assert_eq!(bundle.proof().len(), proof_size(1));
    // (the signatures do not cover the flags directly: the hash does)
    assert_eq!(bundle.verify_signatures(&sighash), Ok(()));

    let vk = key(CircuitVersion::PostNu6_3);
    let mut instances = bundle.instances(vk.version()).unwrap();
    // read as an Orchard bundle of NU6.3, it would be restricted
    assert!(verify_proof(vk, &instances, bundle.proof()).is_err());
    instances[0].disable_cross_address = false;
    assert_eq!(verify_proof(vk, &instances, bundle.proof()), Ok(()));
    let fixed = key(CircuitVersion::FixedPostNu6_2);
    assert!(verify_proof(fixed, &instances, bundle.proof()).is_err());
}

/// Bundles of the chain verified together: proofs and signatures.
#[test]
fn batch_validation_of_mainnet_bundles() {
    let random = [0x3c; 64];
    let (a, a_sighash) = v5_orchard(TX_3ECD7B89, 0x5437_f330);
    let (b, b_sighash) = v5_orchard(TX_B0FD5D92, 0x5437_f330);
    let (c, _, c_sighash) = v6_bundles(TX_E39EAB2B, 0x37a5_165b);
    let (d, _, d_sighash) = v6_bundles(TX_2BE7CF25, 0x7719_0ad9);
    let parse = |bytes: &[u8]| BundleRef::parse(bytes).unwrap().unwrap().to_owned();
    let fixed = key(CircuitVersion::FixedPostNu6_2);
    let post = key(CircuitVersion::PostNu6_3);

    let valid = |vk: &VerifyingKey, bundles: &[(&crate::orchard::bundle::Bundle, [u8; 32])]| {
        let bytes: Vec<Vec<u8>> = bundles.iter().map(|(b, _)| b.to_bytes()).collect();
        let refs: Vec<(BundleRef<'_>, [u8; 32])> = bytes
            .iter()
            .zip(bundles.iter())
            .map(|(bytes, (_, sighash))| (BundleRef::parse(bytes).unwrap().unwrap(), *sighash))
            .collect();
        verify_bundles(vk, &refs, &random)
    };
    let (a, b, c, d) = (parse(&a), parse(&b), parse(&c), parse(&d));

    // an empty batch, one bundle, several
    assert!(valid(fixed, &[]));
    assert!(valid(fixed, &[(&a, a_sighash)]));
    assert!(valid(fixed, &[(&a, a_sighash), (&b, b_sighash)]));
    assert!(valid(post, &[(&c, c_sighash), (&d, d_sighash)]));
    // the batch type, used directly
    let bytes = [a.to_bytes(), b.to_bytes()];
    let mut batch = BatchValidator::new(fixed, &random);
    assert!(batch.is_empty());
    batch.add_bundle(&BundleRef::parse(&bytes[0]).unwrap().unwrap(), &a_sighash);
    batch.add_bundle(&BundleRef::parse(&bytes[1]).unwrap().unwrap(), &b_sighash);
    assert_eq!(batch.len(), 2);
    assert!(batch.validate());

    // a bundle of another circuit version
    assert!(!valid(fixed, &[(&a, a_sighash), (&c, c_sighash)]));
    assert!(!valid(post, &[(&c, c_sighash), (&a, a_sighash)]));
    // a wrong signature hash
    assert!(!valid(fixed, &[(&a, a_sighash), (&b, a_sighash)]));
    // a wrong spend authorization signature, a wrong binding signature
    let mut bad = b.clone();
    bad.actions[1].spend_auth_sig[5] ^= 1;
    assert!(!valid(fixed, &[(&a, a_sighash), (&bad, b_sighash)]));
    let mut bad = b.clone();
    bad.binding_sig[40] ^= 1;
    assert!(!valid(fixed, &[(&bad, b_sighash), (&a, a_sighash)]));
    // a wrong proof, a wrong public input, a proof too long
    let mut bad = b.clone();
    bad.proof[1000] ^= 1;
    assert!(!valid(fixed, &[(&a, a_sighash), (&bad, b_sighash)]));
    let mut bad = a.clone();
    bad.anchor[0] ^= 1;
    assert!(!valid(fixed, &[(&bad, a_sighash), (&b, b_sighash)]));
    let mut bad = a.clone();
    bad.proof.push(0);
    assert!(!valid(fixed, &[(&bad, a_sighash)]));
    // keys that are not points
    let mut bad = a.clone();
    bad.actions[0].rk = [0xff; 32];
    assert!(!valid(fixed, &[(&bad, a_sighash)]));
}
