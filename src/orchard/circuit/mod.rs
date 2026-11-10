//! The Orchard Action circuit (feature `zcash-orchard-prover`): verifying
//! and creating the zero-knowledge proofs of Orchard bundles.
//!
//! An Orchard bundle carries one proof for all its actions. For each action
//! it shows, without revealing them, that there are a note being spent
//! (present in the note commitment tree unless its value is zero, owned by
//! the key the action's `rk` is a randomization of, and with the action's
//! nullifier) and a note being created (with the action's commitment
//! `cmx`), whose values differ by what the action's value commitment
//! commits to.
//!
//! The circuit and the gadgets it is built from are ports of the `orchard`
//! (0.16) and `halo2_gadgets` (0.6) crates onto [`halo2`],
//! laid out exactly as the reference: the verifying keys are identical (see
//! [`VerifyingKey::build`]) and proofs are interchangeable.
//!
//! Three versions of the circuit exist ([`CircuitVersion`]); a proof made
//! for one does not verify with another.
//!
//! # Verifying
//!
//! [`VerifyingKey::embedded`] gives the verifying key of a circuit version
//! without generating it; `BundleRef::verify_proof`
//! checks the proof of a parsed bundle, and [`verify_proof`] a proof for
//! explicit public inputs ([`Instance`]). Many bundles (the transactions
//! of a block) are verified faster together: [`BatchValidator`] and
//! [`verify_bundles`] check their proofs and signatures at once.
//! [`CircuitVersion::for_branch_id`] and [`CircuitVersion::for_height`]
//! tell which version of the circuit a transaction is for.
//!
//! # Proving
//!
//! [`ProvingKey::build`] generates the proving key (once: it takes about
//! a second of computation), [`ActionCircuit`] holds the witness of one
//! action and [`create_proof`] proves a set of actions. The
//! builder does all of it for a whole bundle.
//!
//! With the `std` feature, key generation, proving and verification use
//! the threads of the machine (`orchard::set_max_threads` limits them);
//! keys and proofs are the same, byte for byte, whatever their number.

use alloc::vec::Vec;

use purecrypto::zeroize::Zeroize;

use super::halo2::{self, Params, Value};
use super::keys::{FullViewingKey, Scope};
use super::note::Note;
use super::tree::MerklePath;
use super::{Fp, Fq, pallas};

mod action;
pub(crate) mod add_chip;
mod batch;
pub(crate) mod commit_ivk;
pub(crate) mod ecc;
pub(crate) mod gadget;
pub(crate) mod note_commit;
pub(crate) mod poseidon;
pub(crate) mod sinsemilla;
pub(crate) mod utilities;

#[cfg(test)]
mod tests;
#[cfg(all(test, feature = "std"))]
mod tests_build;

pub use batch::{BatchValidator, verify_bundles};

/// The size of the circuit: `2^11` rows.
pub const K: u32 = 11;

/// The number of public inputs of an action.
const INSTANCE_ROWS: usize = 10;

// The rows of the public inputs.
const ANCHOR: usize = 0;
const CV_NET_X: usize = 1;
const CV_NET_Y: usize = 2;
const NF_OLD: usize = 3;
const RK_X: usize = 4;
const RK_Y: usize = 5;
const CMX: usize = 6;
const ENABLE_SPEND: usize = 7;
const ENABLE_OUTPUT: usize = 8;
const DISABLE_CROSS_ADDRESS: usize = 9;

/// The size in bytes of the proof of a bundle of `actions` actions.
pub const fn proof_size(actions: usize) -> usize {
    2720 + 2272 * actions
}

/// The versions of the Orchard Action circuit. They differ in their
/// verifying keys: which one applies to a transaction depends on the
/// network upgrade in force at its height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitVersion {
    /// The original circuit, from NU5 until NU6.2. Its variable-base scalar
    /// multiplication does not bind the base it multiplies, which makes it
    /// unsound: only use it to verify the historical chain.
    InsecurePreNu6_2,
    /// The corrected circuit, from NU6.2 on.
    FixedPostNu6_2,
    /// The circuit from NU6.3 on: the corrected circuit, which also checks
    /// that the note created goes to the address of the note spent when the
    /// `disableCrossAddress` public input is set, as it is for every action
    /// of the Orchard pool from NU6.3.
    PostNu6_3,
}

impl CircuitVersion {
    /// All versions.
    pub const ALL: [CircuitVersion; 3] = [
        CircuitVersion::InsecurePreNu6_2,
        CircuitVersion::FixedPostNu6_2,
        CircuitVersion::PostNu6_3,
    ];

    /// The circuit version of the Orchard pool under a consensus branch
    /// (the `nConsensusBranchId` of a transaction), or `None` for a branch
    /// without Orchard (before NU5) or not known here.
    ///
    /// The mapping is that of the reference implementation:
    /// `BranchId::orchard_protocol_revision` of `zcash_protocol` 0.11.0
    /// (NU5, NU6 and NU6.1 give `InsecureV1`, NU6.2 `V2`, NU6.3 and NU7
    /// `V3`), which `BundleVersion::circuit_version` of `orchard` 0.16.0
    /// maps to the circuit versions in this order. The branch ids are those
    /// of `zcash_protocol` and of ZIPs 252 (NU5), 253 (NU6), 255 (NU6.1),
    /// 257 (NU6.2: "This changes the Orchard verifying key"), 258 (NU6.3)
    /// and 259 (NU7).
    ///
    /// This is the version for the Orchard pool. The Ironwood pool NU6.3
    /// introduces has no earlier circuit: its bundles are always proven
    /// for [`CircuitVersion::PostNu6_3`], with the cross-address
    /// restriction off unless their flags ask for it.
    pub const fn for_branch_id(consensus_branch_id: u32) -> Option<Self> {
        match consensus_branch_id {
            // NU5, NU6, NU6.1
            0xc2d6_d0b4 | 0xc8e7_1055 | 0x4dec_4df0 => Some(CircuitVersion::InsecurePreNu6_2),
            // NU6.2
            0x5437_f330 => Some(CircuitVersion::FixedPostNu6_2),
            // NU6.3, NU7
            0x37a5_165b | 0x7719_0ad9 => Some(CircuitVersion::PostNu6_3),
            _ => None,
        }
    }

    /// The circuit version of the Orchard pool for a transaction mined at
    /// `height` on `network`, or `None` before NU5 and on a regression test
    /// network (whose activation heights are a matter of configuration).
    ///
    /// The activation heights are those of `zcash_protocol` 0.11.0
    /// (`MainNetwork` and `TestNetwork`) and of ZIPs 252, 257 and 258: NU5
    /// at 1 687 104 on the main network and 1 842 420 on the test network,
    /// NU6.2 at 3 364 600 and 4 052 000, NU6.3 at 3 428 143 and 4 134 000.
    /// No later upgrade known here (NU7, at 3 543 405 and 4 465 026)
    /// changes the circuit.
    ///
    /// (Shortly before NU6.2, from heights 3 363 426 and 4 048 500, the
    /// networks accepted no Orchard action at all, see ZIP 257; this
    /// function does not tell.)
    pub const fn for_height(network: super::unified::Network, height: u32) -> Option<Self> {
        let (nu5, nu6_2, nu6_3) = match network {
            super::unified::Network::Main => (1_687_104, 3_364_600, 3_428_143),
            super::unified::Network::Test => (1_842_420, 4_052_000, 4_134_000),
            super::unified::Network::Regtest => return None,
        };
        if height < nu5 {
            None
        } else if height < nu6_2 {
            Some(CircuitVersion::InsecurePreNu6_2)
        } else if height < nu6_3 {
            Some(CircuitVersion::FixedPostNu6_2)
        } else {
            Some(CircuitVersion::PostNu6_3)
        }
    }

    /// Whether the circuit enforces the `disableCrossAddress` public input
    /// (which must be zero for the versions that do not).
    pub const fn supports_cross_address_restriction(self) -> bool {
        matches!(self, CircuitVersion::PostNu6_3)
    }

    /// Whether the variable-base scalar multiplication binds its base.
    pub(crate) const fn anchored_base(self) -> bool {
        !matches!(self, CircuitVersion::InsecurePreNu6_2)
    }

    /// The embedded verifying key data of this version.
    fn embedded(self) -> &'static [u8] {
        match self {
            CircuitVersion::InsecurePreNu6_2 => include_bytes!("vk_insecure_pre_nu6_2.bin"),
            CircuitVersion::FixedPostNu6_2 => include_bytes!("vk_fixed_post_nu6_2.bin"),
            CircuitVersion::PostNu6_3 => include_bytes!("vk_post_nu6_3.bin"),
        }
    }
}

/// The public inputs of one action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instance {
    /// The root of the note commitment tree the spent note is in.
    pub anchor: Fp,
    /// The value commitment `cv` of the action.
    pub cv_net: pallas::Affine,
    /// The nullifier of the note spent.
    pub nf_old: Fp,
    /// The randomized spend validating key `rk` (not the identity).
    pub rk: pallas::Affine,
    /// The extracted commitment of the note created.
    pub cmx: Fp,
    /// Whether the bundle may spend notes of non-zero value.
    pub enable_spend: bool,
    /// Whether the bundle may create notes of non-zero value.
    pub enable_output: bool,
    /// Whether the note created must go to the address of the note spent
    /// (only circuits from NU6.3 enforce it; always set for the Orchard
    /// pool from NU6.3, never before; for the Ironwood pool, set when the
    /// flags of the bundle lack `enableCrossAddress`).
    pub disable_cross_address: bool,
}

impl Instance {
    /// The public inputs as the column of the circuit.
    fn to_halo2_instance(self) -> [Fp; INSTANCE_ROWS] {
        let bit = |b: bool| if b { Fp::ONE } else { Fp::ZERO };
        let mut instance = [Fp::ZERO; INSTANCE_ROWS];
        instance[ANCHOR] = self.anchor;
        instance[CV_NET_X] = self.cv_net.x();
        instance[CV_NET_Y] = self.cv_net.y();
        instance[NF_OLD] = self.nf_old;
        instance[RK_X] = self.rk.x();
        instance[RK_Y] = self.rk.y();
        instance[CMX] = self.cmx;
        instance[ENABLE_SPEND] = bit(self.enable_spend);
        instance[ENABLE_OUTPUT] = bit(self.enable_output);
        instance[DISABLE_CROSS_ADDRESS] = bit(self.disable_cross_address);
        instance
    }
}

/// The private inputs of one action.
#[derive(Clone)]
struct Witness {
    path: [Fp; 32],
    pos: u32,
    g_d_old: pallas::Affine,
    pk_d_old: pallas::Affine,
    v_old: u64,
    rho_old: Fp,
    psi_old: Fp,
    rcm_old: Fq,
    cm_old: pallas::Affine,
    alpha: Fq,
    ak: pallas::Affine,
    nk: Fp,
    rivk: Fq,
    g_d_new: pallas::Affine,
    pk_d_new: pallas::Affine,
    v_new: u64,
    psi_new: Fp,
    rcm_new: Fq,
    rcv: Fq,
}

impl Drop for Witness {
    fn drop(&mut self) {
        self.path.zeroize();
        self.pos.zeroize();
        self.g_d_old.zeroize();
        self.pk_d_old.zeroize();
        self.v_old.zeroize();
        self.rho_old.zeroize();
        self.psi_old.zeroize();
        self.rcm_old.zeroize();
        self.cm_old.zeroize();
        self.alpha.zeroize();
        self.ak.zeroize();
        self.nk.zeroize();
        self.rivk.zeroize();
        self.g_d_new.zeroize();
        self.pk_d_new.zeroize();
        self.v_new.zeroize();
        self.psi_new.zeroize();
        self.rcm_new.zeroize();
        self.rcv.zeroize();
    }
}

/// The Orchard Action circuit, with the witness of one action (or without
/// any, to generate keys). The witness is wiped when the circuit is
/// dropped.
#[derive(Clone)]
pub struct ActionCircuit {
    witness: Option<Witness>,
    version: CircuitVersion,
}

impl core::fmt::Debug for ActionCircuit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ActionCircuit")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl ActionCircuit {
    /// The circuit without a witness.
    pub fn empty(version: CircuitVersion) -> Self {
        ActionCircuit {
            witness: None,
            version,
        }
    }

    /// The circuit of an action spending `spend_note` (owned by `fvk`, at
    /// an address of the given `scope`, with the Merkle path `merkle_path`
    /// to the anchor) and creating `output_note`, where `alpha` randomizes
    /// the spend validating key (`rk = ak + [alpha] G`) and `rcv` is the
    /// randomness of the value commitment.
    ///
    /// `None` if `rho` of the output note is not the nullifier of the spent
    /// note, as the protocol requires.
    #[allow(clippy::too_many_arguments)]
    pub fn from_action_context(
        fvk: &FullViewingKey,
        scope: Scope,
        spend_note: &Note,
        merkle_path: &MerklePath,
        output_note: &Note,
        alpha: &Fq,
        rcv: &Fq,
        version: CircuitVersion,
    ) -> Option<Self> {
        if spend_note.nullifier(fvk) != output_note.rho() {
            return None;
        }
        let sender = spend_note.recipient();
        let recipient = output_note.recipient();
        Some(ActionCircuit {
            witness: Some(Witness {
                path: *merkle_path.auth_path(),
                pos: merkle_path.position(),
                g_d_old: sender.g_d().to_affine(),
                pk_d_old: sender.pk_d(),
                v_old: spend_note.value(),
                rho_old: spend_note.rho().to_fp(),
                psi_old: spend_note.psi(),
                rcm_old: spend_note.rcm(),
                cm_old: spend_note.commitment(),
                alpha: *alpha,
                ak: fvk.ak().to_point(),
                nk: fvk.nk(),
                rivk: fvk.rivk(scope),
                g_d_new: recipient.g_d().to_affine(),
                pk_d_new: recipient.pk_d(),
                v_new: output_note.value(),
                psi_new: output_note.psi(),
                rcm_new: output_note.rcm(),
                rcv: *rcv,
            }),
            version,
        })
    }

    /// The version of the circuit.
    pub fn version(&self) -> CircuitVersion {
        self.version
    }

    /// A field of the witness, if there is one.
    fn witness<T>(&self, f: impl FnOnce(&Witness) -> T) -> Value<T> {
        match &self.witness {
            Some(w) => Value::known(f(w)),
            None => Value::unknown(),
        }
    }
}

/// The verifying key of a version of the Action circuit, with the
/// parameters of the proving system.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    params: Params,
    vk: halo2::VerifyingKey,
    version: CircuitVersion,
}

/// A verifying key as embedded in the crate: how key generation merged the
/// selectors, and the commitments to the fixed columns and to the
/// permutation.
struct EmbeddedKey {
    plan: Vec<halo2::plonk::SelectorPlan>,
    fixed_commitments: Vec<super::vesta::Affine>,
    permutation_commitments: Vec<super::vesta::Affine>,
}

impl EmbeddedKey {
    #[cfg(test)]
    fn from_vk(vk: &halo2::VerifyingKey, plan: &[halo2::plonk::SelectorPlan]) -> Self {
        let mut plan = plan.to_vec();
        plan.sort_by_key(|p| p.selector);
        EmbeddedKey {
            plan,
            fixed_commitments: vk.fixed_commitments().to_vec(),
            permutation_commitments: vk.permutation_commitments().to_vec(),
        }
    }

    /// One byte for each count; three bytes per selector; 32 per point.
    #[cfg(test)]
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.plan.len() as u8);
        for (i, p) in self.plan.iter().enumerate() {
            assert_eq!(p.selector, i);
            out.extend_from_slice(&[
                p.combination_index as u8,
                p.assigned_root as u8,
                p.combination_len as u8,
            ]);
        }
        for points in [&self.fixed_commitments, &self.permutation_commitments] {
            out.push(points.len() as u8);
            for p in points.iter() {
                out.extend_from_slice(&p.to_bytes());
            }
        }
        out
    }

    fn from_bytes(mut data: &[u8]) -> Option<Self> {
        fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
            let (head, rest) = data.split_at_checked(n)?;
            *data = rest;
            Some(head)
        }
        let selectors = take(&mut data, 1)?[0] as usize;
        let mut plan = Vec::with_capacity(selectors);
        for selector in 0..selectors {
            let p = take(&mut data, 3)?;
            plan.push(halo2::plonk::SelectorPlan {
                selector,
                combination_index: p[0] as usize,
                assigned_root: p[1] as usize,
                combination_len: p[2] as usize,
            });
        }
        let mut points = || -> Option<Vec<super::vesta::Affine>> {
            let n = take(&mut data, 1)?[0] as usize;
            (0..n)
                .map(|_| {
                    let bytes: &[u8; 32] = take(&mut data, 32)?.try_into().ok()?;
                    super::vesta::Affine::from_bytes(bytes)
                })
                .collect()
        };
        let fixed_commitments = points()?;
        let permutation_commitments = points()?;
        data.is_empty().then_some(EmbeddedKey {
            plan,
            fixed_commitments,
            permutation_commitments,
        })
    }
}

/// The Lagrange basis generators of the rows of the public inputs, which
/// are costly to derive (a test regenerates them).
const G_LAGRANGE: &[u8; 32 * INSTANCE_ROWS] = include_bytes!("g_lagrange.bin");

/// The parameters for verifying, from the embedded generators.
fn verifier_params() -> Params {
    let g_lagrange = G_LAGRANGE
        .as_chunks::<32>()
        .0
        .iter()
        .map(|bytes| {
            super::vesta::Affine::from_bytes(bytes).expect("the embedded generators are valid")
        })
        .collect();
    Params::with_lagrange(K, g_lagrange)
}

impl VerifyingKey {
    /// Generates the verifying key of a circuit version from scratch, by
    /// synthesizing the circuit and committing to its fixed columns: slow
    /// (seconds). The result equals the key of the `orchard` crate, and
    /// [`VerifyingKey::embedded`].
    pub fn build(version: CircuitVersion) -> Self {
        let params = Params::new(K);
        let vk = halo2::keygen_vk(&params, &ActionCircuit::empty(version))
            .expect("the Action circuit is well-formed");
        VerifyingKey {
            params,
            vk,
            version,
        }
    }

    /// The verifying key of a circuit version, from the commitments
    /// embedded in the crate (which a test regenerates with
    /// [`VerifyingKey::build`]), and parameters sufficient for verifying:
    /// takes a fraction of a second.
    pub fn embedded(version: CircuitVersion) -> Self {
        Self::embedded_with(version, verifier_params())
    }

    /// [`VerifyingKey::embedded`] with parameters already at hand.
    fn embedded_with(version: CircuitVersion, params: Params) -> Self {
        let key =
            EmbeddedKey::from_bytes(version.embedded()).expect("the embedded key is well-formed");
        let vk = halo2::vk_from_parts(
            K,
            &ActionCircuit::empty(version),
            &key.plan,
            key.fixed_commitments,
            key.permutation_commitments,
        )
        .expect("the embedded key fits the circuit");
        VerifyingKey {
            params,
            vk,
            version,
        }
    }

    /// The embedded verifying keys of all the circuit versions (in the
    /// order of [`CircuitVersion::ALL`]), sharing the work they have in
    /// common.
    pub fn embedded_all() -> [Self; 3] {
        let params = verifier_params();
        CircuitVersion::ALL.map(|version| Self::embedded_with(version, params.clone()))
    }

    /// The version of the circuit.
    pub fn version(&self) -> CircuitVersion {
        self.version
    }

    /// The underlying Halo 2 verifying key.
    pub fn halo2(&self) -> &halo2::VerifyingKey {
        &self.vk
    }
}

/// The proving key of a version of the Action circuit, with the parameters
/// of the proving system.
#[derive(Clone, Debug)]
pub struct ProvingKey {
    params: Params,
    pk: halo2::ProvingKey,
    version: CircuitVersion,
}

impl ProvingKey {
    /// Generates the proving key of a circuit version: slow (about a
    /// second of computation, spread over the threads there are), and
    /// large (tens of megabytes); build it once and keep it.
    pub fn build(version: CircuitVersion) -> Self {
        let params = Params::new(K);
        let pk = halo2::keygen_pk(&params, &ActionCircuit::empty(version))
            .expect("the Action circuit is well-formed");
        ProvingKey {
            params,
            pk,
            version,
        }
    }

    /// The version of the circuit.
    pub fn version(&self) -> CircuitVersion {
        self.version
    }

    /// The verifying key for the proofs this key creates.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            params: self.params.clone(),
            vk: self.pk.vk().clone(),
            version: self.version,
        }
    }
}

/// The public inputs in the shape the proving system takes.
fn halo2_instances(instances: &[Instance]) -> Vec<[Fp; INSTANCE_ROWS]> {
    instances.iter().map(|i| i.to_halo2_instance()).collect()
}

/// Verifies the proof of the actions with the given public inputs (one
/// proof covers all the actions of a bundle).
///
/// The length of the proof is not checked here; consensus requires it to
/// be [`proof_size`] of the number of actions.
pub fn verify_proof(
    vk: &VerifyingKey,
    instances: &[Instance],
    proof: &[u8],
) -> Result<(), halo2::Error> {
    if instances.iter().any(|i| i.disable_cross_address)
        && !vk.version.supports_cross_address_restriction()
    {
        return Err(halo2::Error::InvalidInstances);
    }
    let columns = halo2_instances(instances);
    let columns: Vec<[&[Fp]; 1]> = columns.iter().map(|c| [&c[..]]).collect();
    let columns: Vec<&[&[Fp]]> = columns.iter().map(|c| &c[..]).collect();
    halo2::verify_proof(&vk.params, &vk.vk, &columns, proof)
}

/// Creates the proof of a set of actions: `circuits` hold their witnesses
/// and `instances` their public inputs, in the same order. `random` must be
/// 64 fresh uniformly random bytes, never used for another proof.
///
/// The result is not checked: a witness that does not match the public
/// inputs gives an error or a proof that does not verify.
pub fn create_proof(
    pk: &ProvingKey,
    circuits: &[ActionCircuit],
    instances: &[Instance],
    random: &[u8; 64],
) -> Result<Vec<u8>, halo2::Error> {
    if circuits.iter().any(|c| c.version != pk.version) {
        return Err(halo2::Error::Synthesis);
    }
    if instances.iter().any(|i| i.disable_cross_address)
        && !pk.version.supports_cross_address_restriction()
    {
        return Err(halo2::Error::InvalidInstances);
    }
    let columns = halo2_instances(instances);
    let columns: Vec<[&[Fp]; 1]> = columns.iter().map(|c| [&c[..]]).collect();
    let columns: Vec<&[&[Fp]]> = columns.iter().map(|c| &c[..]).collect();
    halo2::create_proof_sync(&pk.params, &pk.pk, circuits, &columns, random)
}
