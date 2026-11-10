//! Building Orchard bundles (feature `zcash-orchard-prover`): from the
//! notes to spend and the outputs to create to the actions, the proof and
//! the signatures.
//!
//! A [`Builder`] collects spends and outputs. [`Builder::build`] pairs
//! them into actions (padding with dummy spends and outputs of value zero,
//! to at least two actions, as the reference wallet does), encrypts the
//! new notes, and proves the bundle. The result, an
//! [`UnauthorizedBundle`], serializes with zeroed signatures into the
//! `orchard` field of a [`ZcashTx`](crate::zcashtx::ZcashTx), which gives
//! the ZIP-244 signature hash; [`UnauthorizedBundle::apply_signatures`]
//! then signs every action and the bundle.
//!
//! The crate has no random number generator: each step takes fresh
//! uniformly random bytes from the caller. They must never be reused, as
//! they seed the note randomness, the key randomizers, the blinding of the
//! proof and the signature nonces.

use alloc::vec::Vec;

use purecrypto::hash::Blake2bMac;
use purecrypto::zeroize::Zeroize;

use super::bundle::{Action, Bundle, Flags};
use super::circuit::{self, ActionCircuit, CircuitVersion, Instance, ProvingKey};
use super::keys::{
    Address, FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendingKey,
};
use super::note::{Note, Nullifier};
use super::note_encryption::{
    MEMO_SIZE, encrypt_note, encrypt_outgoing, encrypt_outgoing_unrecoverable,
};
use super::tree::MerklePath;
use super::value::{ValueCommitment, binding_signing_key};
use super::{Fp, Fq, halo2};

/// The minimum number of actions of a bundle the builder makes.
const MIN_ACTIONS: usize = 2;

/// Errors of the bundle builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildError {
    /// The flags of the bundle do not allow spends.
    SpendsDisabled,
    /// The flags of the bundle do not allow outputs.
    OutputsDisabled,
    /// The full viewing key does not own the note to spend.
    WrongKey,
    /// The Merkle path of a note does not lead to the anchor.
    AnchorMismatch,
    /// From NU6.3 a note of the Orchard pool can only be created at the
    /// address of the note spent by the same action: an output has no spend
    /// to be paired with.
    CrossAddressDisabled,
    /// The value balance does not fit in 63 bits.
    ValueOverflow,
    /// The proving key is for another circuit version than the builder.
    WrongProvingKey,
    /// No spend authorizing key was given for one of the notes spent.
    MissingSigningKey,
    /// The proof could not be created.
    Proof(halo2::Error),
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            BuildError::SpendsDisabled => "spends are disabled",
            BuildError::OutputsDisabled => "outputs are disabled",
            BuildError::WrongKey => "the key does not own the note",
            BuildError::AnchorMismatch => "the Merkle path does not lead to the anchor",
            BuildError::CrossAddressDisabled => "an output needs a spend from the same address",
            BuildError::ValueOverflow => "value balance overflow",
            BuildError::WrongProvingKey => "proving key of another circuit version",
            BuildError::MissingSigningKey => "missing spend authorizing key",
            BuildError::Proof(e) => return write!(f, "proof creation failed: {e}"),
        })
    }
}

impl core::error::Error for BuildError {}

/// A stream of random bytes expanded from a seed: BLAKE2b in counter mode.
struct Random {
    seed: [u8; 64],
    counter: u64,
}

impl Random {
    fn new(seed: &[u8; 64]) -> Self {
        Random {
            seed: *seed,
            counter: 0,
        }
    }

    fn block(&mut self) -> [u8; 64] {
        let mut h = Blake2bMac::try_new_with_salt_personal(&[], 64, &[], b"outscript_orchbd")
            .expect("valid BLAKE2b parameters");
        h.update(&self.seed);
        h.update(&self.counter.to_le_bytes());
        self.counter += 1;
        let mut out = [0u8; 64];
        h.finalize_into(&mut out);
        out
    }

    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for chunk in out.chunks_mut(64) {
            let mut block = self.block();
            chunk.copy_from_slice(&block[..chunk.len()]);
            block.zeroize();
        }
        out
    }

    fn scalar(&mut self) -> Fq {
        let mut block = self.block();
        let s = Fq::from_uniform_bytes(&block);
        block.zeroize();
        s
    }

    fn base(&mut self) -> Fp {
        let mut block = self.block();
        let s = Fp::from_uniform_bytes(&block);
        block.zeroize();
        s
    }

    /// A uniformly random index below `n` (which is small).
    fn below(&mut self, n: usize) -> usize {
        let wide = u128::from_le_bytes(self.bytes::<16>());
        (wide % n as u128) as usize
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.below(i + 1));
        }
    }

    /// A spending key (retrying the negligibly rare invalid ones).
    fn spending_key(&mut self) -> SpendingKey {
        loop {
            if let Ok(sk) = SpendingKey::from_bytes(self.bytes()) {
                return sk;
            }
        }
    }

    /// A note with fresh randomness (retrying the negligibly rare seeds
    /// the protocol does not allow).
    fn note(&mut self, recipient: Address, value: u64, rho: Nullifier) -> Note {
        loop {
            if let Ok(note) = Note::from_parts(recipient, value, rho, self.bytes()) {
                return note;
            }
        }
    }
}

impl Drop for Random {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// A note to spend.
#[derive(Clone)]
struct SpendInfo {
    /// The key of a dummy note, which the builder signs with itself.
    dummy_sk: Option<SpendingKey>,
    fvk: FullViewingKey,
    scope: Scope,
    note: Note,
    merkle_path: MerklePath,
}

impl SpendInfo {
    /// A note of value zero owned by a random key, at a random position.
    fn dummy(rng: &mut Random) -> Self {
        let sk = rng.spending_key();
        let fvk = sk.to_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Nullifier::from_fp(rng.base());
        let note = rng.note(recipient, 0, rho);
        let position = u32::from_le_bytes(rng.bytes());
        let mut auth_path = [Fp::ZERO; 32];
        for node in auth_path.iter_mut() {
            *node = rng.base();
        }
        SpendInfo {
            dummy_sk: Some(sk),
            fvk,
            scope: Scope::External,
            note,
            merkle_path: MerklePath::from_parts(position, auth_path),
        }
    }
}

/// A note to create.
#[derive(Clone)]
struct OutputInfo {
    ovk: Option<OutgoingViewingKey>,
    recipient: Address,
    value: u64,
    memo: [u8; MEMO_SIZE],
}

impl OutputInfo {
    /// An output of value zero to `recipient`, that nobody is meant to
    /// read.
    fn zero(recipient: Address) -> Self {
        OutputInfo {
            ovk: None,
            recipient,
            value: 0,
            memo: [0u8; MEMO_SIZE],
        }
    }

    /// An output of value zero to a random address.
    fn dummy(rng: &mut Random) -> Self {
        let fvk = rng.spending_key().to_fvk();
        Self::zero(fvk.address_at(0u32, Scope::External))
    }
}

/// The memo of an output without one: the "no memo" marker `0xF6` followed
/// by zeros (ZIP-302).
pub const NO_MEMO: [u8; MEMO_SIZE] = {
    let mut memo = [0u8; MEMO_SIZE];
    memo[0] = 0xf6;
    memo
};

/// Collects the spends and outputs of an Orchard bundle.
#[derive(Clone)]
pub struct Builder {
    version: CircuitVersion,
    flags: Flags,
    anchor: Fp,
    spends: Vec<SpendInfo>,
    outputs: Vec<OutputInfo>,
}

impl Builder {
    /// A builder of bundles for the circuit `version` in force at the
    /// height the transaction is for, with the given `flags`, spending
    /// notes of the note commitment tree of root `anchor`.
    pub fn new(version: CircuitVersion, flags: Flags, anchor: Fp) -> Self {
        Builder {
            version,
            flags,
            anchor,
            spends: Vec::new(),
            outputs: Vec::new(),
        }
    }

    /// Adds a note to spend: `note`, owned by `fvk`, at `merkle_path` in
    /// the note commitment tree.
    pub fn add_spend(
        &mut self,
        fvk: &FullViewingKey,
        note: Note,
        merkle_path: MerklePath,
    ) -> Result<(), BuildError> {
        if !self.flags.spends_enabled() {
            return Err(BuildError::SpendsDisabled);
        }
        // Consistency check: all anchors must be equal.
        if note.value() != 0 && merkle_path.root(note.cmx().to_fp()) != self.anchor {
            return Err(BuildError::AnchorMismatch);
        }
        let scope = fvk
            .scope_for_address(&note.recipient())
            .ok_or(BuildError::WrongKey)?;
        self.spends.push(SpendInfo {
            dummy_sk: None,
            fvk: *fvk,
            scope,
            note,
            merkle_path,
        });
        Ok(())
    }

    /// Adds a note to create: `value` zatoshi to `recipient`, with a memo
    /// ([`NO_MEMO`] for none). With `ovk`, its holder can later recover the
    /// note from the chain; without, only the recipient can read it.
    pub fn add_output(
        &mut self,
        ovk: Option<OutgoingViewingKey>,
        recipient: Address,
        value: u64,
        memo: [u8; MEMO_SIZE],
    ) -> Result<(), BuildError> {
        if !self.flags.outputs_enabled() {
            return Err(BuildError::OutputsDisabled);
        }
        self.outputs.push(OutputInfo {
            ovk,
            recipient,
            value,
            memo,
        });
        Ok(())
    }

    /// The value balance of the bundle: what it spends minus what it
    /// outputs, in zatoshi (positive when value leaves the Orchard pool).
    pub fn value_balance(&self) -> Result<i64, BuildError> {
        let spent: i128 = self.spends.iter().map(|s| s.note.value() as i128).sum();
        let output: i128 = self.outputs.iter().map(|o| o.value as i128).sum();
        i64::try_from(spent - output).map_err(|_| BuildError::ValueOverflow)
    }

    /// Pairs the spends and outputs into actions, padding with dummies.
    fn pair(self, rng: &mut Random) -> Result<Vec<(SpendInfo, OutputInfo)>, BuildError> {
        let Builder {
            version,
            mut spends,
            mut outputs,
            ..
        } = self;
        if version.supports_cross_address_restriction() {
            // Each output goes with a spend from its address; a spend
            // without one gets an output of value zero to its own address.
            let mut actions = Vec::with_capacity(spends.len().max(MIN_ACTIONS));
            for spend in spends {
                let recipient = spend.note.recipient();
                let output = match outputs.iter().position(|o| o.recipient == recipient) {
                    Some(i) => outputs.swap_remove(i),
                    None => OutputInfo::zero(recipient),
                };
                actions.push((spend, output));
            }
            if !outputs.is_empty() {
                return Err(BuildError::CrossAddressDisabled);
            }
            while actions.len() < MIN_ACTIONS {
                let spend = SpendInfo::dummy(rng);
                let output = OutputInfo::zero(spend.note.recipient());
                actions.push((spend, output));
            }
            rng.shuffle(&mut actions);
            Ok(actions)
        } else {
            let num_actions = spends.len().max(outputs.len()).max(MIN_ACTIONS);
            // Pair up the spends and outputs, extending with dummy values
            // as necessary, in an order that reveals nothing.
            while spends.len() < num_actions {
                spends.push(SpendInfo::dummy(rng));
            }
            while outputs.len() < num_actions {
                outputs.push(OutputInfo::dummy(rng));
            }
            rng.shuffle(&mut spends);
            rng.shuffle(&mut outputs);
            Ok(spends.into_iter().zip(outputs).collect())
        }
    }

    /// Builds and proves the bundle. `pk` must be the proving key of the
    /// circuit version the builder was made for; `random` must be 64 fresh
    /// uniformly random bytes.
    ///
    /// Proving takes seconds per action.
    pub fn build(
        self,
        pk: &ProvingKey,
        random: &[u8; 64],
    ) -> Result<UnauthorizedBundle, BuildError> {
        if pk.version() != self.version {
            return Err(BuildError::WrongProvingKey);
        }
        let value_balance = self.value_balance()?;
        let (version, flags, anchor) = (self.version, self.flags, self.anchor);
        let mut rng = Random::new(random);

        let pairs = self.pair(&mut rng)?;
        let mut actions = Vec::with_capacity(pairs.len());
        let mut circuits = Vec::with_capacity(pairs.len());
        let mut instances = Vec::with_capacity(pairs.len());
        let mut signing = Vec::with_capacity(pairs.len());
        let mut rcvs = Vec::with_capacity(pairs.len());
        for (spend, output) in pairs {
            let rcv = rng.scalar();
            let alpha = rng.scalar();
            let v_net = spend.note.value() as i128 - output.value as i128;
            let cv_net = ValueCommitment::derive(v_net, &rcv);
            let nf_old = spend.note.nullifier(&spend.fvk);
            let rk = spend.fvk.ak().randomize(&alpha);

            let note = rng.note(output.recipient, output.value, nf_old);
            let cmx = note.cmx();
            let encrypted = encrypt_note(&note, &output.memo);
            let out_ciphertext = match &output.ovk {
                Some(ovk) => encrypt_outgoing(&note, ovk, &cv_net, &encrypted.ephemeral_key),
                None => encrypt_outgoing_unrecoverable(&rng.bytes()),
            };

            let circuit = ActionCircuit::from_action_context(
                &spend.fvk,
                spend.scope,
                &spend.note,
                &spend.merkle_path,
                &note,
                &alpha,
                &rcv,
                version,
            )
            .expect("rho of the new note is the nullifier of the spent one");
            instances.push(Instance {
                anchor,
                cv_net: cv_net.to_point(),
                nf_old: nf_old.to_fp(),
                rk: rk.to_point(),
                cmx: cmx.to_fp(),
                enable_spend: flags.spends_enabled(),
                enable_output: flags.outputs_enabled(),
                disable_cross_address: version.supports_cross_address_restriction(),
            });
            circuits.push(circuit);
            actions.push(Action {
                cv: cv_net.to_bytes(),
                nullifier: nf_old.to_bytes(),
                rk: rk.to_bytes(),
                cmx: cmx.to_bytes(),
                ephemeral_key: encrypted.ephemeral_key,
                enc_ciphertext: encrypted.enc_ciphertext,
                out_ciphertext,
                spend_auth_sig: [0u8; 64],
            });
            signing.push(SigningParts {
                ak: spend.fvk.ak().to_bytes(),
                alpha,
                dummy_ask: spend.dummy_sk.as_ref().map(|sk| sk.to_ask()),
            });
            rcvs.push(rcv);
        }

        let proof = circuit::create_proof(pk, &circuits, &instances, &rng.bytes())
            .map_err(BuildError::Proof)?;
        Ok(UnauthorizedBundle {
            bundle: Bundle {
                actions,
                flags,
                value_balance,
                anchor: anchor.to_bytes(),
                proof,
                binding_sig: [0u8; 64],
            },
            signing,
            rcvs,
        })
    }
}

/// What signing an action takes.
struct SigningParts {
    /// The spend validating key of the note spent.
    ak: [u8; 32],
    /// The randomizer of the action.
    alpha: Fq,
    /// The spend authorizing key of a dummy note.
    dummy_ask: Option<SpendAuthorizingKey>,
}

impl Drop for SigningParts {
    fn drop(&mut self) {
        self.alpha.zeroize();
    }
}

/// A proven bundle that is not signed yet.
pub struct UnauthorizedBundle {
    bundle: Bundle,
    signing: Vec<SigningParts>,
    rcvs: Vec<Fq>,
}

impl Drop for UnauthorizedBundle {
    fn drop(&mut self) {
        self.rcvs.zeroize();
    }
}

impl UnauthorizedBundle {
    /// The bundle with all its signatures zeroed: its serialization
    /// ([`Bundle::to_bytes`]) in the `orchard` field of a
    /// [`ZcashTx`](crate::zcashtx::ZcashTx) gives the signature hash, which
    /// does not cover the signatures.
    pub fn bundle(&self) -> &Bundle {
        &self.bundle
    }

    /// Signs the bundle over `sighash`, the ZIP-244 signature hash of the
    /// transaction for shielded inputs: every action with the spend
    /// authorizing key of the note it spends (looked up in `asks`; dummy
    /// spends are signed with their own keys), and the bundle with its
    /// binding key. `random` must be 64 fresh uniformly random bytes.
    pub fn apply_signatures(
        mut self,
        sighash: &[u8; 32],
        asks: &[SpendAuthorizingKey],
        random: &[u8; 64],
    ) -> Result<Bundle, BuildError> {
        let mut rng = Random::new(random);
        let keys: Vec<[u8; 32]> = asks.iter().map(|ask| ask.to_ak().to_bytes()).collect();
        for (action, parts) in self.bundle.actions.iter_mut().zip(self.signing.iter()) {
            let ask = match &parts.dummy_ask {
                Some(ask) => ask,
                None => {
                    let i = keys
                        .iter()
                        .position(|ak| ak == &parts.ak)
                        .ok_or(BuildError::MissingSigningKey)?;
                    &asks[i]
                }
            };
            let rsk = ask.randomize(&parts.alpha);
            action.spend_auth_sig = rsk.sign(&rng.bytes(), sighash).to_bytes();
        }
        let bsk = binding_signing_key(self.rcvs.iter());
        self.bundle.binding_sig = bsk.sign(&rng.bytes(), sighash).to_bytes();
        Ok(self.bundle.clone())
    }
}
