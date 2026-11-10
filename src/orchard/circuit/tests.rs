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
    let mut owned = bundle.to_owned();
    owned.proof.push(0);
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
