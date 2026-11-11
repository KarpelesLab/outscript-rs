//! Building Orchard bundles (feature `zcash-orchard-prover`): from the
//! notes to spend and the outputs to create to the actions, the proof and
//! the signatures.
//!
//! A [`Builder`] collects spends and outputs. [`Builder::build`] pairs
//! them into actions (padding with dummy spends and outputs of value zero,
//! to at least two actions unless the [`BundleType`] says otherwise, as
//! the reference wallet does), encrypts the new notes, and proves the
//! bundle. The result, an [`UnauthorizedBundle`], serializes with zeroed
//! signatures into the `orchard` field of a
//! [`ZcashTx`](crate::zcashtx::ZcashTx), which gives the ZIP-244 signature
//! hash; [`UnauthorizedBundle::apply_signatures`] then signs every action
//! and the bundle.
//!
//! # Bundles without cross-address transfers
//!
//! From NU6.3 every action of the Orchard pool, and every action of an
//! Ironwood bundle whose flags clear `enableCrossAddress`, must create its
//! note at the address of the note it spends (ZIP 2006). Such a bundle is
//! built as ZIP 326 specifies and as the reference builder (`orchard`
//! 0.16.0) does, with actions of two kinds that never mix:
//!
//! - a *spend action* spends a real note and creates a note of value zero
//!   at the address of the note spent, whose ciphertext is random bytes
//!   and not an encryption (which whoever holds the incoming viewing key
//!   of that address could decrypt, in the very action that carries the
//!   nullifier of the spend: the spend would be linked to the address);
//! - an *output action* creates a note that carries value at an address of
//!   the wallet ([`Builder::add_change_output`]: change, ordinarily at an
//!   internal address), and spends a note of value zero made up at that
//!   address under the wallet's own full viewing key. That spend is
//!   authorized like a real one, with the spend authorizing key of the
//!   wallet (it is listed by
//!   [`UnauthorizedBundle::spend_auth_requests`]).
//!
//! The value that leaves such a bundle does so through its value balance.
//! A bundle has therefore as many actions as it has spends *plus* outputs,
//! not the larger of the two: [`Builder::num_actions`] tells, for the fee.
//! [`Builder::add_output`] to an address of a key that spends in the same
//! bundle is taken as a change output; to any other address it cannot be
//! built ([`BuildError::CrossAddressDisabled`]). The one difference with
//! the reference is that it randomizes the ciphertext of the note of value
//! zero of a spend action only when the note spent is at an external
//! address, where ZIP 326 says it must be random: here it always is.
//!
//! In a bundle with cross-address transfers (the Orchard pool before
//! NU6.3, the Ironwood pool ordinarily) spends and outputs share actions,
//! shuffled independently, and a change output is an output like another.
//!
//! # Signing elsewhere
//!
//! Building and proving take the full viewing key of the notes spent, not
//! their spending key: a watch-only wallet can do both. The spend
//! authorizing key is only needed for the signatures, which a hardware
//! wallet (or any other signer) can make:
//! [`UnauthorizedBundle::spend_auth_requests`] lists, for each action
//! spending a real note, the randomizer `alpha` and the randomized key
//! `rk` to sign for (the signer checks `rk = ak + [alpha] G` against its
//! own key, and signs the signature hash with `ask + alpha`), and
//! [`UnauthorizedBundle::authorize`] takes the signatures made, checks
//! them, and adds what the builder signs itself (the dummy spends and the
//! binding signature).
//!
//! The crate has no random number generator: each step takes fresh
//! uniformly random bytes from the caller. They must never be reused, as
//! they seed the note randomness, the key randomizers, the blinding of the
//! proof and the signature nonces.

use alloc::vec;
use alloc::vec::Vec;

use purecrypto::hash::Blake2bMac;
use purecrypto::zeroize::Zeroize;

use super::bundle::{Action, Bundle, Flags};
use super::circuit::{self, ActionCircuit, CircuitVersion, Instance, ProvingKey};
use super::keys::{
    Address, FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendingKey,
};
use super::note::{Note, NoteVersion, Nullifier};
use super::note_encryption::{
    MEMO_SIZE, encrypt_note, encrypt_outgoing, encrypt_outgoing_unrecoverable,
};
use super::redpallas::{Signature, SpendAuth, VerificationKey};
use super::tree::MerklePath;
use super::value::{ValueCommitment, binding_signing_key};
use super::{Fp, Fq, halo2};

/// The number of actions a bundle is padded to unless its [`BundleType`]
/// says otherwise.
pub const DEFAULT_MIN_ACTIONS: u8 = 2;

/// How a bundle is completed with dummy actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleType {
    /// The bundle of an ordinary transaction, padded to at least
    /// `pad_to_minimum` actions when it has any (and to one, the least a
    /// bundle can have, for a minimum of zero).
    Transactional {
        /// The least number of actions: [`DEFAULT_MIN_ACTIONS`]
        /// ordinarily, so that the number of actions does not tell a
        /// payment from a transfer. With 1 the bundle has exactly the
        /// actions asked for, and their number reveals the shape of the
        /// transaction: for transactions whose shape is public anyway,
        /// such as the migration of a pool, whose value balances show the
        /// transfer.
        pad_to_minimum: u8,
    },
    /// The bundle of a coinbase transaction: its flags must disable
    /// spends, it has one action per output, each spending a dummy note,
    /// and no padding.
    Coinbase,
}

impl BundleType {
    /// Padded to [`DEFAULT_MIN_ACTIONS`] actions.
    pub const DEFAULT: BundleType = BundleType::Transactional {
        pad_to_minimum: DEFAULT_MIN_ACTIONS,
    };
    /// Not padded: exactly the actions asked for.
    pub const UNPADDED: BundleType = BundleType::Transactional { pad_to_minimum: 1 };

    /// The number of actions of a bundle of this type with the given
    /// flags and numbers of spends and of outputs (change included), under
    /// a circuit that has the cross-address restriction or not; 0 for no
    /// bundle at all.
    pub fn num_actions(
        &self,
        restricted: bool,
        flags: Flags,
        spends: usize,
        outputs: usize,
    ) -> Result<usize, BuildError> {
        if !flags.spends_enabled() && spends > 0 {
            return Err(BuildError::SpendsDisabled);
        }
        if !flags.outputs_enabled() && outputs > 0 {
            return Err(BuildError::OutputsDisabled);
        }
        if restricted && !flags.spends_enabled() && outputs > 0 {
            return Err(BuildError::BundleTypeNotSatisfiable);
        }
        match self {
            BundleType::Transactional { pad_to_minimum } => {
                let requested = if restricted {
                    spends
                        .checked_add(outputs)
                        .ok_or(BuildError::ValueOverflow)?
                } else {
                    spends.max(outputs)
                };
                Ok(if requested == 0 {
                    0
                } else {
                    requested.max(*pad_to_minimum as usize)
                })
            }
            BundleType::Coinbase => {
                if flags.spends_enabled() || spends > 0 {
                    return Err(BuildError::BundleTypeNotSatisfiable);
                }
                Ok(outputs)
            }
        }
    }
}

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
    /// From NU6.3 a note of the Orchard pool (or of an Ironwood bundle
    /// without the `enableCrossAddress` flag) can only be created at the
    /// address of the note spent by the same action: an output has no spend
    /// to be paired with.
    CrossAddressDisabled,
    /// The value balance does not fit in 63 bits.
    ValueOverflow,
    /// The proving key is for another circuit version than the builder.
    WrongProvingKey,
    /// The note to spend is not one of the pool of the bundle: a note of
    /// the Ironwood pool in an Orchard bundle, or the reverse.
    WrongNoteVersion,
    /// No spend authorizing key was given for one of the notes spent.
    MissingSigningKey,
    /// The proof could not be created.
    Proof(halo2::Error),
    /// A spend authorization signature made elsewhere does not verify for
    /// the randomized key of its action and the signature hash.
    InvalidSignature,
    /// A spend authorization signature was given for an action that does
    /// not exist, that the builder signs itself (a dummy spend), or that
    /// has another signature already.
    UnexpectedSignature,
    /// The bundle cannot be built as its [`BundleType`] and flags say: a
    /// coinbase bundle whose flags enable spends or that has spends, or
    /// outputs in a bundle with neither spends nor cross-address
    /// transfers (the Orchard pool in a coinbase transaction from NU6.3).
    BundleTypeNotSatisfiable,
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
            BuildError::WrongNoteVersion => "the note is of the other pool",
            BuildError::MissingSigningKey => "missing spend authorizing key",
            BuildError::Proof(e) => return write!(f, "proof creation failed: {e}"),
            BuildError::InvalidSignature => "invalid spend authorization signature",
            BuildError::UnexpectedSignature => "signature for an action that takes none",
            BuildError::BundleTypeNotSatisfiable => "bundle type not satisfiable",
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
    fn note(
        &mut self,
        recipient: Address,
        value: u64,
        rho: Nullifier,
        version: NoteVersion,
    ) -> Note {
        loop {
            if let Ok(note) =
                Note::from_parts_versioned(recipient, value, rho, self.bytes(), version)
            {
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
    fn dummy(rng: &mut Random, note_version: NoteVersion) -> Self {
        let sk = rng.spending_key();
        let fvk = sk.to_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Nullifier::from_fp(rng.base());
        let note = rng.note(recipient, 0, rho, note_version);
        SpendInfo {
            dummy_sk: Some(sk),
            fvk,
            scope: Scope::External,
            note,
            merkle_path: Self::dummy_path(rng),
        }
    }

    /// A random Merkle path, for a note of value zero, whose path is not
    /// checked.
    fn dummy_path(rng: &mut Random) -> MerklePath {
        let position = u32::from_le_bytes(rng.bytes());
        let mut auth_path = [Fp::ZERO; 32];
        for node in auth_path.iter_mut() {
            *node = rng.base();
        }
        MerklePath::from_parts(position, auth_path)
    }
}

/// A note to create.
#[derive(Clone)]
struct OutputInfo {
    ovk: Option<OutgoingViewingKey>,
    recipient: Address,
    value: u64,
    memo: [u8; MEMO_SIZE],
    /// The ciphertext of the note is random bytes: for the note of value
    /// zero of a spend action, that nobody must be able to read.
    randomized: bool,
}

/// An output of the wallet itself, and the key that owns its address.
#[derive(Clone)]
struct ChangeInfo {
    output: OutputInfo,
    fvk: FullViewingKey,
    scope: Scope,
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
            randomized: false,
        }
    }

    /// The output of value zero of a spend action, at the address of the
    /// note spent, with a random ciphertext.
    fn fabricated_for_spend(recipient: Address) -> Self {
        OutputInfo {
            randomized: true,
            ..Self::zero(recipient)
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

/// Collects the spends and outputs of a bundle of the Orchard pool
/// ([`Builder::new`]) or of the Ironwood pool ([`Builder::new_ironwood`]).
#[derive(Clone)]
pub struct Builder {
    version: CircuitVersion,
    flags: Flags,
    anchor: Fp,
    /// The version of the notes of the pool.
    note_version: NoteVersion,
    spends: Vec<SpendInfo>,
    outputs: Vec<OutputInfo>,
    changes: Vec<ChangeInfo>,
    bundle_type: BundleType,
}

impl Builder {
    /// A builder of bundles of the Orchard pool for the circuit `version`
    /// in force at the height the transaction is for, with the given
    /// `flags`, spending notes of the Orchard note commitment tree of root
    /// `anchor`.
    ///
    /// The `enableCrossAddress` flag does not exist in the Orchard pool
    /// and is dropped from `flags`: from NU6.3 every output of the pool
    /// must go to the address of a note spent by the bundle
    /// ([`BuildError::CrossAddressDisabled`]).
    pub fn new(version: CircuitVersion, flags: Flags, anchor: Fp) -> Self {
        Builder {
            version,
            flags: flags.with_cross_address(false),
            anchor,
            note_version: NoteVersion::V2,
            spends: Vec::new(),
            outputs: Vec::new(),
            changes: Vec::new(),
            bundle_type: BundleType::DEFAULT,
        }
    }

    /// A builder of bundles of the Ironwood pool (NU6.3 and later, in
    /// version 6 transactions), with the given `flags`
    /// ([`Flags::IRONWOOD_ENABLED`] ordinarily), spending notes of the
    /// Ironwood note commitment tree of root `anchor`.
    ///
    /// The circuit is that of NU6.3
    /// ([`CircuitVersion::PostNu6_3`]), shared with the Orchard pool; the
    /// notes created are quantum-recoverable ones
    /// ([`NoteVersion::V3`]), and the notes spent must be notes of the
    /// Ironwood pool ([`BuildError::WrongNoteVersion`]). Without the
    /// `enableCrossAddress` flag the bundle is restricted as one of the
    /// Orchard pool is.
    pub fn new_ironwood(flags: Flags, anchor: Fp) -> Self {
        Builder {
            version: CircuitVersion::PostNu6_3,
            flags,
            anchor,
            note_version: NoteVersion::V3,
            spends: Vec::new(),
            outputs: Vec::new(),
            changes: Vec::new(),
            bundle_type: BundleType::DEFAULT,
        }
    }

    /// Whether every action must create its note at the address of the
    /// note it spends (see the [module documentation](self)): under the
    /// circuit of NU6.3, unless the flags enable cross-address transfers,
    /// which only those of an Ironwood bundle can.
    pub fn restricted(&self) -> bool {
        self.version.supports_cross_address_restriction() && !self.flags.cross_address_enabled()
    }

    /// How the bundle is padded: [`BundleType::DEFAULT`] unless set.
    pub fn bundle_type(&self) -> BundleType {
        self.bundle_type
    }

    /// Chooses how the bundle is padded: [`BundleType::UNPADDED`] for a
    /// bundle of exactly the actions asked for, [`BundleType::Coinbase`]
    /// for the bundle of a coinbase transaction (whose flags must disable
    /// spends: [`BuildError::BundleTypeNotSatisfiable`] when building
    /// otherwise).
    pub fn set_bundle_type(&mut self, bundle_type: BundleType) {
        self.bundle_type = bundle_type;
    }

    /// The outputs that [`build`](Self::build) will treat as plain ones
    /// and as change: in a restricted bundle, an output added with
    /// [`add_output`](Self::add_output) to an address of a key that spends
    /// here is change.
    fn split_outputs(&self) -> (usize, usize) {
        if !self.restricted() {
            return (self.outputs.len() + self.changes.len(), 0);
        }
        let own = self
            .outputs
            .iter()
            .filter(|output| self.owner_of(&output.recipient).is_some())
            .count();
        (self.outputs.len() - own, self.changes.len() + own)
    }

    /// The key spending in this bundle that owns `address`.
    fn owner_of(&self, address: &Address) -> Option<(FullViewingKey, Scope)> {
        self.spends.iter().find_map(|spend| {
            spend
                .fvk
                .scope_for_address(address)
                .map(|scope| (spend.fvk, scope))
        })
    }

    /// The number of actions the bundle will have as it stands: what the
    /// ZIP-317 fee counts. In a bundle with cross-address transfers, the
    /// larger of the numbers of spends and of outputs; in one without,
    /// their sum; padded as the [`BundleType`] says. An error if the
    /// bundle cannot be built ([`BuildError::CrossAddressDisabled`] for an
    /// output that would need a cross-address transfer).
    pub fn num_actions(&self) -> Result<usize, BuildError> {
        self.num_actions_with(0)
    }

    /// The number of actions the bundle would have with `extra` more
    /// outputs of the wallet itself ([`add_change_output`](Self::add_change_output)):
    /// see [`num_actions`](Self::num_actions).
    pub fn num_actions_with(&self, extra: usize) -> Result<usize, BuildError> {
        let (plain, changes) = self.split_outputs();
        let changes = changes + extra;
        if self.restricted() && plain > 0 {
            return Err(if self.flags.spends_enabled() {
                BuildError::CrossAddressDisabled
            } else {
                BuildError::BundleTypeNotSatisfiable
            });
        }
        self.bundle_type.num_actions(
            self.restricted(),
            self.flags,
            self.spends.len(),
            plain + changes,
        )
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
        if note.version() != self.note_version {
            return Err(BuildError::WrongNoteVersion);
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
            randomized: false,
        });
        Ok(())
    }

    /// Adds a note the wallet creates for itself, change ordinarily:
    /// `value` zatoshi to `recipient`, an address of `fvk`
    /// ([`BuildError::WrongKey`] otherwise; for change, the internal
    /// address `fvk.address_at(0, Scope::Internal)`, which is never
    /// published, with the internal outgoing viewing key or none).
    ///
    /// This is the only way to keep value in a bundle without
    /// cross-address transfers (the Orchard pool from NU6.3): the note is
    /// created by an action that spends a note of value zero made up at
    /// the same address, which the wallet authorizes with the spend
    /// authorizing key of `fvk` as it does its real spends (see the
    /// [module documentation](self)). It needs spends to be enabled
    /// ([`BuildError::SpendsDisabled`]). In a bundle with cross-address
    /// transfers this is [`add_output`](Self::add_output), with the check
    /// that the wallet owns the address.
    pub fn add_change_output(
        &mut self,
        fvk: &FullViewingKey,
        ovk: Option<OutgoingViewingKey>,
        recipient: Address,
        value: u64,
        memo: [u8; MEMO_SIZE],
    ) -> Result<(), BuildError> {
        if !self.flags.outputs_enabled() {
            return Err(BuildError::OutputsDisabled);
        }
        if self.restricted() && !self.flags.spends_enabled() {
            return Err(BuildError::SpendsDisabled);
        }
        let scope = fvk
            .scope_for_address(&recipient)
            .ok_or(BuildError::WrongKey)?;
        self.changes.push(ChangeInfo {
            output: OutputInfo {
                ovk,
                recipient,
                value,
                memo,
                randomized: false,
            },
            fvk: *fvk,
            scope,
        });
        Ok(())
    }

    /// The value balance of the bundle: what it spends minus what it
    /// outputs, in zatoshi (positive when value leaves the pool).
    pub fn value_balance(&self) -> Result<i64, BuildError> {
        let spent: i128 = self.spends.iter().map(|s| s.note.value() as i128).sum();
        let output: i128 = self
            .outputs
            .iter()
            .chain(self.changes.iter().map(|change| &change.output))
            .map(|o| o.value as i128)
            .sum();
        i64::try_from(spent - output).map_err(|_| BuildError::ValueOverflow)
    }

    /// Pairs the spends and outputs into actions, padding with dummies.
    fn pair(self, rng: &mut Random) -> Result<Vec<(SpendInfo, OutputInfo)>, BuildError> {
        let restricted = self.restricted();
        let num_actions = self.num_actions()?;
        let owners: Vec<Option<(FullViewingKey, Scope)>> = self
            .outputs
            .iter()
            .map(|output| self.owner_of(&output.recipient))
            .collect();
        let Builder {
            note_version,
            mut spends,
            mut outputs,
            mut changes,
            ..
        } = self;
        if restricted {
            // Every action creates its note at the address of the note it
            // spends, so the pairs are made on purpose: a spend with a
            // note of value zero at its own address, a note the wallet
            // keeps with a spend of value zero the wallet controls at the
            // address of that note, a dummy spend with a note of value
            // zero at its own address. Only whole pairs are shuffled.
            for (output, owner) in outputs.into_iter().zip(owners) {
                // `num_actions` refused the outputs of other owners
                let (fvk, scope) = owner.ok_or(BuildError::CrossAddressDisabled)?;
                changes.push(ChangeInfo { output, fvk, scope });
            }
            let mut actions = Vec::with_capacity(num_actions);
            for spend in spends {
                let output = OutputInfo::fabricated_for_spend(spend.note.recipient());
                actions.push((spend, output));
            }
            for ChangeInfo { output, fvk, scope } in changes {
                let rho = Nullifier::from_fp(rng.base());
                let note = rng.note(output.recipient, 0, rho, note_version);
                let spend = SpendInfo {
                    // the wallet controls this spend: it is signed as the
                    // real ones are, by the spend authorizing key of `fvk`
                    dummy_sk: None,
                    fvk,
                    scope,
                    note,
                    merkle_path: SpendInfo::dummy_path(rng),
                };
                actions.push((spend, output));
            }
            while actions.len() < num_actions {
                let spend = SpendInfo::dummy(rng, note_version);
                let output = OutputInfo::zero(spend.note.recipient());
                actions.push((spend, output));
            }
            rng.shuffle(&mut actions);
            Ok(actions)
        } else {
            outputs.extend(changes.into_iter().map(|change| change.output));
            // Pair up the spends and outputs, extending with dummy values
            // as necessary, in an order that reveals nothing.
            while spends.len() < num_actions {
                spends.push(SpendInfo::dummy(rng, note_version));
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
    /// Proving takes about a second per action on one thread; with the
    /// `std` feature it uses the threads of the machine (see
    /// `orchard::set_max_threads`), and the bundle is the same whatever
    /// their number.
    pub fn build(
        self,
        pk: &ProvingKey,
        random: &[u8; 64],
    ) -> Result<UnauthorizedBundle, BuildError> {
        if pk.version() != self.version {
            return Err(BuildError::WrongProvingKey);
        }
        self.build_with(random, |circuits, instances, random| {
            circuit::create_proof(pk, circuits, instances, random).map_err(BuildError::Proof)
        })
    }

    /// Builds the bundle, with the proof `prove` makes of its actions.
    fn build_with(
        self,
        random: &[u8; 64],
        prove: impl FnOnce(&[ActionCircuit], &[Instance], &[u8; 64]) -> Result<Vec<u8>, BuildError>,
    ) -> Result<UnauthorizedBundle, BuildError> {
        let value_balance = self.value_balance()?;
        let (version, flags, anchor) = (self.version, self.flags, self.anchor);
        let (note_version, restricted) = (self.note_version, self.restricted());
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

            let note = rng.note(output.recipient, output.value, nf_old, note_version);
            let cmx = note.cmx();
            let mut encrypted = encrypt_note(&note, &output.memo);
            if output.randomized {
                // never in place of the ciphertext of a note with a value
                debug_assert_eq!(output.value, 0);
                encrypted.enc_ciphertext = rng.bytes();
            }
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
                disable_cross_address: restricted,
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

        let proof = prove(&circuits, &instances, &rng.bytes())?;
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

/// What a signer needs to authorize the spend of one action: see
/// [`UnauthorizedBundle::spend_auth_requests`].
///
/// `alpha` links the action to the key spending it: it is not a spending
/// secret, but it is private, and wiped when the request is dropped.
#[derive(Clone)]
pub struct SpendAuthRequest {
    /// The index of the action in the bundle.
    pub index: usize,
    /// The spend validating key `ak` of the note spent, which tells the
    /// signer which of its keys is asked for.
    pub ak: [u8; 32],
    /// The randomizer of the action: the signature is made with the spend
    /// authorizing key randomized by it
    /// ([`SpendAuthorizingKey::randomize`]).
    pub alpha: Fq,
    /// The randomized spend validating key `rk = ak + [alpha] G` of the
    /// action, which the signature must verify with.
    pub rk: [u8; 32],
}

impl Drop for SpendAuthRequest {
    fn drop(&mut self) {
        self.alpha.zeroize();
    }
}

impl core::fmt::Debug for SpendAuthRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpendAuthRequest")
            .field("index", &self.index)
            .field("ak", &self.ak)
            .field("rk", &self.rk)
            .finish_non_exhaustive()
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

    /// What signing takes for each action that spends a real note (the
    /// dummy spends the builder padded the bundle with are signed by the
    /// builder itself): the randomizer and the randomized key, for a
    /// signer that holds the spend authorizing key (see
    /// [`UnauthorizedBundle::authorize`]).
    pub fn spend_auth_requests(&self) -> Vec<SpendAuthRequest> {
        self.bundle
            .actions
            .iter()
            .zip(self.signing.iter())
            .enumerate()
            .filter(|(_, (_, parts))| parts.dummy_ask.is_none())
            .map(|(index, (action, parts))| SpendAuthRequest {
                index,
                ak: parts.ak,
                alpha: parts.alpha,
                rk: action.rk,
            })
            .collect()
    }

    /// Signs the bundle over `sighash`, the ZIP-244 signature hash of the
    /// transaction for shielded inputs: every action with the spend
    /// authorizing key of the note it spends (looked up in `asks`; dummy
    /// spends are signed with their own keys), and the bundle with its
    /// binding key. `random` must be 64 fresh uniformly random bytes.
    pub fn apply_signatures(
        self,
        sighash: &[u8; 32],
        asks: &[SpendAuthorizingKey],
        random: &[u8; 64],
    ) -> Result<Bundle, BuildError> {
        self.authorize(sighash, asks, &[], random)
    }

    /// Completes the bundle over `sighash` (the ZIP-244 signature hash of
    /// the transaction for shielded inputs) with spend authorization
    /// signatures made elsewhere: `signatures` gives, by action index
    /// ([`SpendAuthRequest::index`]), the signature of the hash with the
    /// spend authorizing key randomized by the `alpha` of the action. Each
    /// is verified with the `rk` of its action before it is accepted.
    ///
    /// The actions without a signature in `signatures` are signed here,
    /// with the key of `asks` matching the note spent, as
    /// [`UnauthorizedBundle::apply_signatures`] does; dummy spends and the
    /// binding signature always are. `random` must be 64 fresh uniformly
    /// random bytes.
    pub fn authorize(
        &self,
        sighash: &[u8; 32],
        asks: &[SpendAuthorizingKey],
        signatures: &[(usize, [u8; 64])],
        random: &[u8; 64],
    ) -> Result<Bundle, BuildError> {
        let mut rng = Random::new(random);
        let mut bundle = self.bundle.clone();
        // The signatures made elsewhere, each for a distinct action that
        // takes one.
        let mut external: Vec<Option<&[u8; 64]>> = vec![None; bundle.actions.len()];
        for (index, signature) in signatures {
            let slot = external
                .get_mut(*index)
                .ok_or(BuildError::UnexpectedSignature)?;
            if slot.is_some() || self.signing[*index].dummy_ask.is_some() {
                return Err(BuildError::UnexpectedSignature);
            }
            *slot = Some(signature);
        }
        let keys: Vec<[u8; 32]> = asks.iter().map(|ask| ask.to_ak().to_bytes()).collect();
        for ((action, parts), external) in bundle
            .actions
            .iter_mut()
            .zip(self.signing.iter())
            .zip(external)
        {
            if let Some(signature) = external {
                VerificationKey::<SpendAuth>::from_bytes(&action.rk)
                    .ok_or(BuildError::InvalidSignature)?
                    .verify(sighash, &Signature::from_bytes(signature))
                    .map_err(|_| BuildError::InvalidSignature)?;
                action.spend_auth_sig = *signature;
                continue;
            }
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
        bundle.binding_sig = bsk.sign(&rng.bytes(), sighash).to_bytes();
        Ok(bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchard::bundle::BundleRef;
    use crate::orchard::note_encryption::try_note_decryption;
    use crate::orchard::tree;

    fn seed<const N: usize>(tag: u8) -> [u8; N] {
        core::array::from_fn(|i| {
            tag.wrapping_mul(59)
                .wrapping_add((i as u8).wrapping_mul(131))
        })
    }

    /// Everything about a bundle but its proof (which the slow tests of
    /// `circuit` cover): pairing, padding, encryption, and signing, here or
    /// elsewhere.
    #[test]
    fn build_and_sign_without_proof() {
        let sk = SpendingKey::from_bytes(seed(1)).unwrap();
        let fvk = sk.to_fvk();
        let sender = fvk.address_at(0u32, Scope::External);
        let other = SpendingKey::from_bytes(seed(2)).unwrap().to_fvk();
        let recipient = other.address_at(3u32, Scope::External);
        let rho = Nullifier::from_fp(Fp::from_uniform_bytes(&seed(3)));
        let note = Note::from_parts(sender, 70_000, rho, seed(4)).unwrap();
        let leaves = [Fp::from_u64(5), note.cmx().to_fp()];
        let anchor = tree::root(&leaves).unwrap();
        let path = tree::witness(&leaves, 1).unwrap();

        for version in CircuitVersion::ALL {
            let restricted = version.supports_cross_address_restriction();
            if restricted {
                // see `restricted_bundles`
                continue;
            }
            let mut builder = Builder::new(version, Flags::ENABLED, anchor);
            builder.add_spend(&fvk, note, path).unwrap();
            assert!(!builder.restricted());
            builder
                .add_output(None, recipient, 60_000, NO_MEMO)
                .unwrap();
            assert_eq!(builder.value_balance(), Ok(10_000));
            assert_eq!(builder.num_actions(), Ok(2));
            // only the full viewing key was needed so far
            let unauthorized = builder
                .build_with(&seed(5), |circuits, instances, _| {
                    assert_eq!(circuits.len(), 2);
                    assert_eq!(instances.len(), 2);
                    assert!(
                        instances
                            .iter()
                            .all(|i| i.disable_cross_address == restricted)
                    );
                    Ok(Vec::new())
                })
                .unwrap();
            let sighash = seed::<32>(6);

            let requests = unauthorized.spend_auth_requests();
            assert_eq!(requests.len(), 1);
            let request = &requests[0];
            assert_eq!(request.ak, fvk.ak().to_bytes());
            assert_eq!(request.rk, fvk.ak().randomize(&request.alpha).to_bytes());
            assert_eq!(unauthorized.bundle().actions[request.index].rk, request.rk);
            assert!(!alloc::format!("{request:?}").contains("alpha"));

            // signed elsewhere
            let external = sk
                .to_ask()
                .randomize(&request.alpha)
                .sign(&seed(7), &sighash)
                .to_bytes();
            let check = |bundle: &Bundle| {
                let bytes = bundle.to_bytes();
                let parsed = BundleRef::parse(&bytes).unwrap().unwrap();
                assert_eq!(parsed.verify_signatures(&sighash), Ok(()));
                assert!(parsed.verify_signatures(&seed(8)).is_err());
                let found: u64 = parsed
                    .actions()
                    .filter_map(|action| {
                        let ivk = if restricted { &fvk } else { &other }.to_ivk(Scope::External);
                        try_note_decryption(&ivk, &action.output(), &action.enc_ciphertext)
                    })
                    .map(|(note, _)| note.value())
                    .sum();
                assert_eq!(found, 60_000);
            };
            let signed = unauthorized
                .authorize(&sighash, &[], &[(request.index, external)], &seed(9))
                .unwrap();
            assert_eq!(signed.actions[request.index].spend_auth_sig, external);
            check(&signed);

            // a signature that does not verify, misplaced, or missing
            let authorize = |asks: &[SpendAuthorizingKey], signatures: &[(usize, [u8; 64])]| {
                unauthorized
                    .authorize(&sighash, asks, signatures, &seed(9))
                    .map(|_| ())
            };
            let mut bad = external;
            bad[40] ^= 1;
            assert_eq!(
                authorize(&[], &[(request.index, bad)]),
                Err(BuildError::InvalidSignature)
            );
            let wrong_hash = sk
                .to_ask()
                .randomize(&request.alpha)
                .sign(&seed(7), &[0u8; 32])
                .to_bytes();
            assert_eq!(
                authorize(&[], &[(request.index, wrong_hash)]),
                Err(BuildError::InvalidSignature)
            );
            let unrandomized = sk.to_ask().randomize(&Fq::ZERO).sign(&seed(7), &sighash);
            assert_eq!(
                authorize(&[], &[(request.index, unrandomized.to_bytes())]),
                Err(BuildError::InvalidSignature)
            );
            assert_eq!(
                authorize(&[], &[(1 - request.index, external)]),
                Err(BuildError::UnexpectedSignature)
            );
            assert_eq!(
                authorize(&[], &[(2, external)]),
                Err(BuildError::UnexpectedSignature)
            );
            assert_eq!(
                authorize(&[], &[(request.index, external), (request.index, external)]),
                Err(BuildError::UnexpectedSignature)
            );
            assert_eq!(authorize(&[], &[]), Err(BuildError::MissingSigningKey));
            assert_eq!(
                authorize(&[other_ask()], &[]),
                Err(BuildError::MissingSigningKey)
            );

            // signed here: the same as before this was split
            let local = unauthorized
                .authorize(&sighash, &[other_ask(), sk.to_ask()], &[], &seed(9))
                .unwrap();
            check(&local);
            let applied = unauthorized
                .apply_signatures(&sighash, &[sk.to_ask()], &seed(9))
                .unwrap();
            assert_eq!(applied.to_bytes(), local.to_bytes());
        }
    }

    /// A bundle of the Ironwood pool, without its proof: notes of the
    /// Ironwood version, to any address unless the flags restrict it.
    #[test]
    fn ironwood_bundle_without_proof() {
        use crate::orchard::note_encryption::try_note_decryption_versioned;
        let sk = SpendingKey::from_bytes(seed(1)).unwrap();
        let fvk = sk.to_fvk();
        let sender = fvk.address_at(0u32, Scope::External);
        let other = SpendingKey::from_bytes(seed(2)).unwrap().to_fvk();
        let recipient = other.address_at(3u32, Scope::External);
        let rho = Nullifier::from_fp(Fp::from_uniform_bytes(&seed(3)));
        let note =
            Note::from_parts_versioned(sender, 70_000, rho, seed(4), NoteVersion::V3).unwrap();
        let orchard_note = Note::from_parts(sender, 70_000, rho, seed(4)).unwrap();
        assert_ne!(note.cmx(), orchard_note.cmx());
        let leaves = [Fp::from_u64(5), note.cmx().to_fp()];
        let anchor = tree::root(&leaves).unwrap();
        let path = tree::witness(&leaves, 1).unwrap();
        let orchard_leaves = [Fp::from_u64(5), orchard_note.cmx().to_fp()];
        let orchard_anchor = tree::root(&orchard_leaves).unwrap();

        // each pool spends its own notes
        let mut builder = Builder::new_ironwood(Flags::IRONWOOD_ENABLED, orchard_anchor);
        assert_eq!(
            builder.add_spend(&fvk, orchard_note, path),
            Err(BuildError::WrongNoteVersion)
        );
        let mut builder = Builder::new(CircuitVersion::PostNu6_3, Flags::ENABLED, anchor);
        assert_eq!(
            builder.add_spend(&fvk, note, path),
            Err(BuildError::WrongNoteVersion)
        );
        // the Orchard pool has no cross-address flag to set
        let orchard = Builder::new(
            CircuitVersion::PostNu6_3,
            Flags::IRONWOOD_ENABLED,
            orchard_anchor,
        );
        assert_eq!(orchard.flags, Flags::ENABLED);
        assert!(orchard.restricted());

        for (flags, restricted) in [
            (Flags::IRONWOOD_ENABLED, false),
            (Flags::IRONWOOD_ENABLED.with_cross_address(false), true),
        ] {
            let mut builder = Builder::new_ironwood(flags, anchor);
            builder.add_spend(&fvk, note, path).unwrap();
            builder
                .add_output(None, recipient, 60_000, NO_MEMO)
                .unwrap();
            if restricted {
                // as in the Orchard pool from NU6.3
                assert_eq!(
                    builder.build_with(&seed(5), |_, _, _| Ok(Vec::new())).err(),
                    Some(BuildError::CrossAddressDisabled)
                );
                continue;
            }
            assert_eq!(builder.value_balance(), Ok(10_000));
            let unauthorized = builder
                .build_with(&seed(5), |circuits, instances, _| {
                    assert_eq!(circuits.len(), 2);
                    assert!(instances.iter().all(|i| !i.disable_cross_address));
                    assert!(instances.iter().all(|i| i.enable_spend && i.enable_output));
                    Ok(Vec::new())
                })
                .unwrap();
            let sighash = seed::<32>(6);
            let signed = unauthorized
                .apply_signatures(&sighash, &[sk.to_ask()], &seed(9))
                .unwrap();
            assert_eq!(signed.flags, Flags::IRONWOOD_ENABLED);
            let bytes = signed.to_bytes();
            // an Ironwood bundle, by its flags
            assert_eq!(
                BundleRef::parse(&bytes),
                Err(crate::orchard::Error::InvalidFlags)
            );
            assert_eq!(Bundle::parse_ironwood(&bytes), Ok(Some(signed.clone())));
            let parsed = BundleRef::parse_ironwood(&bytes).unwrap().unwrap();
            assert_eq!(parsed.verify_signatures(&sighash), Ok(()));
            assert!(parsed.flags().cross_address_enabled());
            let mut rest = &bytes[..];
            assert_eq!(BundleRef::read_ironwood(&mut rest), Ok(Some(parsed)));
            assert!(rest.is_empty());
            // its notes are of the Ironwood version
            let ivk = other.to_ivk(Scope::External);
            let mut found = 0;
            for action in parsed.actions() {
                let output = action.output();
                assert!(try_note_decryption(&ivk, &output, &action.enc_ciphertext).is_none());
                if let Some((note, _)) = try_note_decryption_versioned(
                    NoteVersion::V3,
                    &ivk,
                    &output,
                    &action.enc_ciphertext,
                ) {
                    assert_eq!(note.version(), NoteVersion::V3);
                    found += note.value();
                }
            }
            assert_eq!(found, 60_000);
        }
    }

    /// The notes `ivk` reads in a bundle: their values.
    fn read(bundle: &Bundle, ivk: &crate::orchard::keys::IncomingViewingKey) -> Vec<u64> {
        use crate::orchard::note_encryption::try_note_decryption_versioned;
        let mut found: Vec<u64> = bundle
            .actions
            .iter()
            .filter_map(|action| {
                [NoteVersion::V2, NoteVersion::V3]
                    .into_iter()
                    .find_map(|v| {
                        try_note_decryption_versioned(
                            v,
                            ivk,
                            &action.output(),
                            &action.enc_ciphertext,
                        )
                    })
            })
            .map(|(note, _)| note.value())
            .collect();
        found.sort();
        found
    }

    /// Bundles without cross-address transfers (the Orchard pool from
    /// NU6.3, an Ironwood bundle with the flag cleared), as ZIP 326 has
    /// them: spend actions and output actions.
    #[test]
    fn restricted_bundles() {
        let sk = SpendingKey::from_bytes(seed(1)).unwrap();
        let fvk = sk.to_fvk();
        let sender = fvk.address_at(0u32, Scope::External);
        let change = fvk.address_at(0u32, Scope::Internal);
        let other = SpendingKey::from_bytes(seed(2)).unwrap().to_fvk();
        let recipient = other.address_at(3u32, Scope::External);
        let rho = Nullifier::from_fp(Fp::from_uniform_bytes(&seed(3)));
        let sighash = seed::<32>(6);
        let external = fvk.to_ivk(Scope::External);
        let internal = fvk.to_ivk(Scope::Internal);

        for ironwood in [false, true] {
            let version = if ironwood {
                NoteVersion::V3
            } else {
                NoteVersion::V2
            };
            let note = Note::from_parts_versioned(sender, 70_000, rho, seed(4), version).unwrap();
            let leaves = [Fp::from_u64(5), note.cmx().to_fp()];
            let anchor = tree::root(&leaves).unwrap();
            let path = tree::witness(&leaves, 1).unwrap();
            let new = || {
                if ironwood {
                    Builder::new_ironwood(Flags::IRONWOOD_ENABLED.with_cross_address(false), anchor)
                } else {
                    Builder::new(CircuitVersion::PostNu6_3, Flags::ENABLED, anchor)
                }
            };
            let build = |builder: Builder, actions: usize| {
                assert_eq!(builder.num_actions(), Ok(actions));
                builder
                    .build_with(&seed(5), |circuits, instances, _| {
                        assert_eq!(circuits.len(), actions);
                        assert!(instances.iter().all(|i| i.disable_cross_address));
                        Ok(Vec::new())
                    })
                    .unwrap()
            };

            // a spend alone: its action, and one of padding. The note of
            // value zero at the address spent from is not readable.
            let mut builder = new();
            assert!(builder.restricted());
            assert_eq!(builder.num_actions(), Ok(0));
            builder.add_spend(&fvk, note, path).unwrap();
            assert_eq!(builder.value_balance(), Ok(70_000));
            let unauthorized = build(builder, 2);
            assert_eq!(unauthorized.spend_auth_requests().len(), 1);
            let signed = unauthorized
                .apply_signatures(&sighash, &[sk.to_ask()], &seed(9))
                .unwrap();
            assert_eq!(read(&signed, &external), [0u64; 0]);
            assert_eq!(read(&signed, &internal), [0u64; 0]);

            // unpadded: the one action
            let mut builder = new();
            builder.set_bundle_type(BundleType::UNPADDED);
            assert_eq!(builder.bundle_type(), BundleType::UNPADDED);
            builder.add_spend(&fvk, note, path).unwrap();
            let unauthorized = build(builder, 1);
            assert_eq!(unauthorized.bundle().actions.len(), 1);

            // a spend and change: two actions, both signed by the wallet;
            // only the change is readable, by the internal key
            let mut builder = new();
            builder.add_spend(&fvk, note, path).unwrap();
            builder
                .add_change_output(
                    &fvk,
                    Some(fvk.to_ovk(Scope::Internal)),
                    change,
                    60_000,
                    NO_MEMO,
                )
                .unwrap();
            assert_eq!(builder.value_balance(), Ok(10_000));
            let unauthorized = build(builder, 2);
            let requests = unauthorized.spend_auth_requests();
            assert_eq!(requests.len(), 2);
            assert!(requests.iter().all(|r| r.ak == fvk.ak().to_bytes()));
            // without the key of the wallet neither action is signed
            assert_eq!(
                unauthorized
                    .authorize(&sighash, &[other_ask()], &[], &seed(9))
                    .err(),
                Some(BuildError::MissingSigningKey)
            );
            // signed elsewhere, both
            let signatures: Vec<(usize, [u8; 64])> = requests
                .iter()
                .map(|r| {
                    let sig = sk.to_ask().randomize(&r.alpha).sign(&seed(7), &sighash);
                    (r.index, sig.to_bytes())
                })
                .collect();
            let signed = unauthorized
                .authorize(&sighash, &[], &signatures, &seed(9))
                .unwrap();
            let bytes = signed.to_bytes();
            let parsed = if ironwood {
                BundleRef::parse_ironwood(&bytes)
            } else {
                BundleRef::parse(&bytes)
            }
            .unwrap()
            .unwrap();
            assert_eq!(parsed.verify_signatures(&sighash), Ok(()));
            assert_eq!(parsed.value_balance(), 10_000);
            assert_eq!(read(&signed, &external), [0u64; 0]);
            assert_eq!(read(&signed, &internal), [60_000]);
            // the change is recovered with the internal outgoing key too
            let ovk = fvk.to_ovk(Scope::Internal);
            let recovered = signed
                .actions
                .iter()
                .filter(|action| {
                    crate::orchard::note_encryption::try_output_recovery_with_ovk_versioned(
                        version,
                        &ovk,
                        &action.cv,
                        &action.output(),
                        &action.enc_ciphertext,
                        &action.out_ciphertext,
                    )
                    .is_some()
                })
                .count();
            assert_eq!(recovered, 1);

            // an output to an address of a key spending here is change
            // (three actions: the spend, and the two notes kept)
            let mut builder = new();
            builder.add_spend(&fvk, note, path).unwrap();
            builder.add_output(None, sender, 20_000, NO_MEMO).unwrap();
            builder.add_output(None, change, 30_000, NO_MEMO).unwrap();
            let signed = build(builder, 3)
                .apply_signatures(&sighash, &[sk.to_ask()], &seed(9))
                .unwrap();
            assert_eq!(read(&signed, &external), [20_000]);
            assert_eq!(read(&signed, &internal), [30_000]);

            // to any other address it is a cross-address transfer
            let mut builder = new();
            builder.add_spend(&fvk, note, path).unwrap();
            builder
                .add_output(None, recipient, 60_000, NO_MEMO)
                .unwrap();
            assert_eq!(builder.num_actions(), Err(BuildError::CrossAddressDisabled));
            assert_eq!(
                builder.build_with(&seed(5), |_, _, _| Ok(Vec::new())).err(),
                Some(BuildError::CrossAddressDisabled)
            );
            // and change is at an address of the key given
            let mut builder = new();
            assert_eq!(
                builder.add_change_output(&fvk, None, recipient, 1, NO_MEMO),
                Err(BuildError::WrongKey)
            );
            // change alone (no spend of the pool): value enters the
            // bundle, which only the transaction can forbid
            builder
                .add_change_output(&fvk, None, change, 5, NO_MEMO)
                .unwrap();
            assert_eq!(builder.value_balance(), Ok(-5));
            let unauthorized = build(builder, 2);
            assert_eq!(unauthorized.spend_auth_requests().len(), 1);

            // a coinbase bundle cannot be restricted
            let mut builder = if ironwood {
                Builder::new_ironwood(Flags::from_parts(false, true), anchor)
            } else {
                Builder::new(
                    CircuitVersion::PostNu6_3,
                    Flags::from_parts(false, true),
                    anchor,
                )
            };
            builder.set_bundle_type(BundleType::Coinbase);
            assert_eq!(
                builder.add_change_output(&fvk, None, change, 5, NO_MEMO),
                Err(BuildError::SpendsDisabled)
            );
            builder.add_output(None, recipient, 5, NO_MEMO).unwrap();
            assert_eq!(
                builder.num_actions(),
                Err(BuildError::BundleTypeNotSatisfiable)
            );
        }
    }

    /// Bundle types where cross-address transfers are allowed: padding,
    /// none, and coinbase.
    #[test]
    fn bundle_types() {
        let fvk = SpendingKey::from_bytes(seed(1)).unwrap().to_fvk();
        let recipient = fvk.address_at(7u32, Scope::External);
        let anchor = Fp::from_u64(9);
        let sighash = seed::<32>(6);
        let coinbase_flags = Flags::from_parts(false, true).with_cross_address(true);
        for (bundle_type, flags, outputs, actions) in [
            (BundleType::DEFAULT, Flags::IRONWOOD_ENABLED, 1, 2),
            (BundleType::DEFAULT, Flags::IRONWOOD_ENABLED, 3, 3),
            (BundleType::UNPADDED, Flags::IRONWOOD_ENABLED, 1, 1),
            (
                BundleType::Transactional { pad_to_minimum: 0 },
                Flags::IRONWOOD_ENABLED,
                1,
                1,
            ),
            (
                BundleType::Transactional { pad_to_minimum: 4 },
                Flags::IRONWOOD_ENABLED,
                1,
                4,
            ),
            (BundleType::Coinbase, coinbase_flags, 1, 1),
            (BundleType::Coinbase, coinbase_flags, 3, 3),
        ] {
            let mut builder = Builder::new_ironwood(flags, anchor);
            builder.set_bundle_type(bundle_type);
            assert_eq!(builder.num_actions(), Ok(0));
            for i in 0..outputs {
                builder
                    .add_output(None, recipient, 100 + i, NO_MEMO)
                    .unwrap();
            }
            assert_eq!(builder.num_actions(), Ok(actions));
            let unauthorized = builder
                .build_with(&seed(5), |circuits, instances, _| {
                    assert_eq!(circuits.len(), actions);
                    assert!(
                        instances
                            .iter()
                            .all(|i| i.enable_spend == flags.spends_enabled())
                    );
                    Ok(Vec::new())
                })
                .unwrap();
            // nothing of the wallet to sign
            assert!(unauthorized.spend_auth_requests().is_empty());
            let signed = unauthorized
                .apply_signatures(&sighash, &[], &seed(9))
                .unwrap();
            assert_eq!(signed.actions.len(), actions);
            assert_eq!(signed.flags, flags);
            let total: u64 = read(&signed, &fvk.to_ivk(Scope::External)).iter().sum();
            assert_eq!(total, (0..outputs).map(|i| 100 + i).sum::<u64>());
        }
        // a coinbase bundle has no spends, and flags that say so
        let mut builder = Builder::new_ironwood(Flags::IRONWOOD_ENABLED, anchor);
        builder.set_bundle_type(BundleType::Coinbase);
        builder.add_output(None, recipient, 1, NO_MEMO).unwrap();
        assert_eq!(
            builder.num_actions(),
            Err(BuildError::BundleTypeNotSatisfiable)
        );
        assert_eq!(
            builder.build_with(&seed(5), |_, _, _| Ok(Vec::new())).err(),
            Some(BuildError::BundleTypeNotSatisfiable)
        );
        // the Orchard pool before NU6.3 had coinbase bundles
        let mut builder = Builder::new(
            CircuitVersion::FixedPostNu6_2,
            Flags::from_parts(false, true),
            anchor,
        );
        builder.set_bundle_type(BundleType::Coinbase);
        builder.add_output(None, recipient, 1, NO_MEMO).unwrap();
        assert_eq!(builder.num_actions(), Ok(1));
    }

    fn other_ask() -> SpendAuthorizingKey {
        SpendingKey::from_bytes(seed(2)).unwrap().to_ask()
    }
}
