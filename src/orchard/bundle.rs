//! The Orchard bundle of a version 5 transaction (ZIP-225): its actions,
//! flags, value balance, anchor, proof and signatures.
//!
//! The layout is the one [`ZcashTx`](crate::zcashtx::ZcashTx) carries as
//! raw bytes in its `orchard` field:
//!
//! ```text
//! compactsize nActionsOrchard
//! nActionsOrchard * 820   cv, nullifier, rk, cmx, ephemeralKey,
//!                         encCiphertext (580), outCiphertext (80)
//! (only if nActionsOrchard > 0)
//! 1                       flagsOrchard
//! 8                       valueBalanceOrchard
//! 32                      anchorOrchard
//! compactsize + bytes     proofsOrchard
//! nActionsOrchard * 64    spendAuthSigsOrchard
//! 64                      bindingSigOrchard
//! ```
//!
//! [`BundleRef`] is a validated, zero-copy view that needs no allocation;
//! with `alloc`, `Bundle` is its owned counterpart, which a transaction
//! builder fills in and serializes.
//!
//! Signatures can be checked here; the zero-knowledge proof cannot, and a
//! bundle is only valid if it verifies too.

use super::Error;
use super::note_encryption::{ActionOutput, ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE};
use super::redpallas::{Binding, Signature, SpendAuth, VerificationKey};
use super::spec::{compact_size, read_compact_size, take, take_array};
use super::value::{ValueCommitment, binding_validating_key};

#[cfg(feature = "alloc")]
use crate::prelude::*;

/// The serialized size of an action, without its spend authorization
/// signature.
pub const ACTION_SIZE: usize = 5 * 32 + ENC_CIPHERTEXT_SIZE + OUT_CIPHERTEXT_SIZE;

/// The flags of a bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flags(u8);

impl Flags {
    /// Spends of existing notes are enabled.
    pub const SPENDS_ENABLED: u8 = 0b01;
    /// Outputs of new notes are enabled.
    pub const OUTPUTS_ENABLED: u8 = 0b10;
    /// Both spends and outputs enabled, as in every ordinary bundle.
    pub const ENABLED: Flags = Flags(Self::SPENDS_ENABLED | Self::OUTPUTS_ENABLED);

    /// The flags for a byte, or `None` if an unknown bit is set (which
    /// consensus rejects).
    pub fn from_byte(byte: u8) -> Option<Self> {
        if byte & !(Self::SPENDS_ENABLED | Self::OUTPUTS_ENABLED) != 0 {
            None
        } else {
            Some(Flags(byte))
        }
    }

    /// The flags from their two bits.
    pub fn from_parts(spends_enabled: bool, outputs_enabled: bool) -> Self {
        Flags(spends_enabled as u8 | (outputs_enabled as u8) << 1)
    }

    /// The serialized byte.
    pub fn to_byte(self) -> u8 {
        self.0
    }

    /// Whether spends are enabled (when not, every action must spend a
    /// dummy note of value zero).
    pub fn spends_enabled(self) -> bool {
        self.0 & Self::SPENDS_ENABLED != 0
    }

    /// Whether outputs are enabled (when not, every action must output a
    /// dummy note of value zero).
    pub fn outputs_enabled(self) -> bool {
        self.0 & Self::OUTPUTS_ENABLED != 0
    }
}

/// An action: the spend of one note and the creation of another. The fields
/// are kept as serialized; the typed accessors decode them.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Action {
    /// The value commitment `cv` to the value spent minus the value output.
    pub cv: [u8; 32],
    /// The nullifier of the note spent.
    pub nullifier: [u8; 32],
    /// The randomized spend validating key `rk`.
    pub rk: [u8; 32],
    /// The extracted commitment `cmx` of the note output.
    pub cmx: [u8; 32],
    /// The ephemeral public key of the note encryption.
    pub ephemeral_key: [u8; 32],
    /// The note output, encrypted to its recipient.
    pub enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    /// What lets the sender recover the note output.
    pub out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
    /// The spend authorization signature (serialized apart from the rest of
    /// the action).
    pub spend_auth_sig: [u8; 64],
}

impl core::fmt::Debug for Action {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Action")
            .field("cv", &self.cv)
            .field("nullifier", &self.nullifier)
            .field("rk", &self.rk)
            .field("cmx", &self.cmx)
            .field("ephemeral_key", &self.ephemeral_key)
            .finish_non_exhaustive()
    }
}

impl Action {
    fn from_bytes(bytes: &[u8; ACTION_SIZE], spend_auth_sig: &[u8; 64]) -> Self {
        let part = |i: usize| -> [u8; 32] { bytes[32 * i..32 * i + 32].try_into().expect("32") };
        Action {
            cv: part(0),
            nullifier: part(1),
            rk: part(2),
            cmx: part(3),
            ephemeral_key: part(4),
            enc_ciphertext: bytes[160..160 + ENC_CIPHERTEXT_SIZE]
                .try_into()
                .expect("580 bytes"),
            out_ciphertext: bytes[160 + ENC_CIPHERTEXT_SIZE..]
                .try_into()
                .expect("80 bytes"),
            spend_auth_sig: *spend_auth_sig,
        }
    }

    /// The serialization of the action, without its signature.
    pub fn to_bytes(&self) -> [u8; ACTION_SIZE] {
        let mut out = [0u8; ACTION_SIZE];
        out[..32].copy_from_slice(&self.cv);
        out[32..64].copy_from_slice(&self.nullifier);
        out[64..96].copy_from_slice(&self.rk);
        out[96..128].copy_from_slice(&self.cmx);
        out[128..160].copy_from_slice(&self.ephemeral_key);
        out[160..160 + ENC_CIPHERTEXT_SIZE].copy_from_slice(&self.enc_ciphertext);
        out[160 + ENC_CIPHERTEXT_SIZE..].copy_from_slice(&self.out_ciphertext);
        out
    }

    /// The value commitment, if it is a canonically encoded point.
    pub fn value_commitment(&self) -> Option<ValueCommitment> {
        ValueCommitment::from_bytes(&self.cv)
    }

    /// The randomized validating key, if it is a canonically encoded point.
    pub fn validating_key(&self) -> Option<VerificationKey<SpendAuth>> {
        VerificationKey::from_bytes(&self.rk)
    }

    /// The fields the decryption of the note output needs, see
    /// [`note_encryption`](super::note_encryption).
    pub fn output(&self) -> ActionOutput<'_> {
        ActionOutput {
            nullifier: &self.nullifier,
            cmx: &self.cmx,
            ephemeral_key: &self.ephemeral_key,
        }
    }

    /// Verifies the spend authorization signature over `sighash` (the
    /// ZIP-244 signature hash of the transaction for shielded inputs).
    pub fn verify_spend_auth(&self, sighash: &[u8; 32]) -> Result<(), Error> {
        self.validating_key()
            .ok_or(Error::InvalidEncoding)?
            .verify(sighash, &Signature::from_bytes(&self.spend_auth_sig))
    }
}

/// A validated view over a serialized, non-empty Orchard bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BundleRef<'a> {
    actions: &'a [[u8; ACTION_SIZE]],
    flags: Flags,
    value_balance: i64,
    anchor: [u8; 32],
    proof: &'a [u8],
    spend_auth_sigs: &'a [[u8; 64]],
    binding_sig: [u8; 64],
}

impl<'a> BundleRef<'a> {
    /// Parses the Orchard bundle of a transaction: `None` for the empty
    /// bundle (no bytes at all, or a zero action count), a view otherwise.
    /// The whole of `data` must be the bundle.
    ///
    /// Only the structure is checked: counts, lengths and flags. Points and
    /// field elements are decoded by the accessors that need them.
    pub fn parse(data: &'a [u8]) -> Result<Option<Self>, Error> {
        if data.is_empty() {
            return Ok(None);
        }
        let mut rest = data;
        let bundle = Self::read(&mut rest)?;
        if !rest.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(bundle)
    }

    /// Reads a bundle off the front of `data`, leaving what follows it.
    pub fn read(data: &mut &'a [u8]) -> Result<Option<Self>, Error> {
        let mut rest = *data;
        let count = usize::try_from(read_compact_size(&mut rest)?).map_err(|_| Error::TooLarge)?;
        if count == 0 {
            *data = rest;
            return Ok(None);
        }
        let len = count.checked_mul(ACTION_SIZE).ok_or(Error::TooLarge)?;
        let (actions, _) = take(&mut rest, len)?.as_chunks::<ACTION_SIZE>();
        let flags = Flags::from_byte(take_array::<1>(&mut rest)?[0]).ok_or(Error::InvalidFlags)?;
        let value_balance = i64::from_le_bytes(take_array(&mut rest)?);
        let anchor = take_array(&mut rest)?;
        let proof_len =
            usize::try_from(read_compact_size(&mut rest)?).map_err(|_| Error::TooLarge)?;
        let proof = take(&mut rest, proof_len)?;
        // `count * 64` cannot overflow as `count * 820` did not
        let (spend_auth_sigs, _) = take(&mut rest, count * 64)?.as_chunks::<64>();
        let binding_sig = take_array(&mut rest)?;
        *data = rest;
        Ok(Some(BundleRef {
            actions,
            flags,
            value_balance,
            anchor,
            proof,
            spend_auth_sigs,
            binding_sig,
        }))
    }

    /// The number of actions (at least one).
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    /// The action at `index`.
    pub fn action(&self, index: usize) -> Option<Action> {
        Some(Action::from_bytes(
            self.actions.get(index)?,
            self.spend_auth_sigs.get(index)?,
        ))
    }

    /// The actions, in order.
    pub fn actions(&self) -> impl ExactSizeIterator<Item = Action> + 'a {
        self.actions
            .iter()
            .zip(self.spend_auth_sigs)
            .map(|(a, s)| Action::from_bytes(a, s))
    }

    /// The flags.
    pub fn flags(&self) -> Flags {
        self.flags
    }

    /// The value balance: the value leaving the Orchard pool (negative
    /// when the bundle takes value in), in zatoshi.
    pub fn value_balance(&self) -> i64 {
        self.value_balance
    }

    /// The anchor: the root of the note commitment tree the spends are
    /// proven against.
    pub fn anchor(&self) -> &[u8; 32] {
        &self.anchor
    }

    /// The zero-knowledge proof of all the actions.
    pub fn proof(&self) -> &'a [u8] {
        self.proof
    }

    /// The binding signature.
    pub fn binding_sig(&self) -> &[u8; 64] {
        &self.binding_sig
    }

    /// The serialized length of the bundle.
    pub fn serialized_len(&self) -> usize {
        let n = self.actions.len();
        compact_size(n as u64).1
            + n * ACTION_SIZE
            + 1
            + 8
            + 32
            + compact_size(self.proof.len() as u64).1
            + self.proof.len()
            + n * 64
            + 64
    }

    /// Serializes the bundle into `out`, returning the number of bytes
    /// written.
    pub fn write_to_slice(&self, out: &mut [u8]) -> Result<usize, Error> {
        let len = self.serialized_len();
        let mut out = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;
        let mut put = |bytes: &[u8]| {
            let (head, tail) = core::mem::take(&mut out).split_at_mut(bytes.len());
            head.copy_from_slice(bytes);
            out = tail;
        };
        let (count, n) = compact_size(self.actions.len() as u64);
        put(&count[..n]);
        put(self.actions.as_flattened());
        put(&[self.flags.to_byte()]);
        put(&self.value_balance.to_le_bytes());
        put(&self.anchor);
        let (proof_len, n) = compact_size(self.proof.len() as u64);
        put(&proof_len[..n]);
        put(self.proof);
        put(self.spend_auth_sigs.as_flattened());
        put(&self.binding_sig);
        Ok(len)
    }

    /// The binding validating key the actions and the value balance imply.
    /// Fails if a value commitment is not a canonically encoded point.
    pub fn binding_validating_key(&self) -> Result<VerificationKey<Binding>, Error> {
        let mut sum = super::pallas::Point::IDENTITY;
        for action in self.actions {
            let cv = ValueCommitment::from_bytes(action[..32].try_into().expect("32 bytes"))
                .ok_or(Error::InvalidEncoding)?;
            sum = sum.add_affine(&cv.to_point());
        }
        let total = ValueCommitment::from_point(sum.to_affine());
        Ok(binding_validating_key([&total], self.value_balance))
    }

    /// Verifies the binding signature and every spend authorization
    /// signature over `sighash`, the ZIP-244 signature hash of the
    /// transaction for shielded inputs
    /// ([`ZcashTx::sighash`](crate::zcashtx::ZcashTx::sighash) with no
    /// input index).
    ///
    /// This does **not** verify the proof: a bundle with valid signatures
    /// may still be invalid.
    pub fn verify_signatures(&self, sighash: &[u8; 32]) -> Result<(), Error> {
        for action in self.actions() {
            action.verify_spend_auth(sighash)?;
        }
        self.binding_validating_key()?
            .verify(sighash, &Signature::from_bytes(&self.binding_sig))
    }

    /// Adds the binding signature and every spend authorization signature
    /// of the bundle over `sighash` to `batch`, to verify them together
    /// with others (see [`BundleRef::verify_signatures`], which this
    /// replaces once the batch is verified). Fails, leaving the batch
    /// untouched, if a key of the bundle is not validly encoded.
    #[cfg(feature = "alloc")]
    pub fn queue_signatures(
        &self,
        sighash: &[u8; 32],
        batch: &mut super::redpallas::BatchVerifier,
    ) -> Result<(), Error> {
        let binding = self.binding_validating_key()?;
        let mut keys = alloc::vec::Vec::with_capacity(self.action_count());
        for action in self.actions() {
            keys.push(action.validating_key().ok_or(Error::InvalidEncoding)?);
        }
        for (action, rk) in self.actions().zip(keys.iter()) {
            batch.queue(rk, sighash, &Signature::from_bytes(&action.spend_auth_sig));
        }
        batch.queue(&binding, sighash, &Signature::from_bytes(&self.binding_sig));
        Ok(())
    }

    /// The public inputs of the actions of the bundle, for the circuit
    /// `version`.
    #[cfg(feature = "zcash-orchard-prover")]
    pub(crate) fn instances(
        &self,
        version: super::circuit::CircuitVersion,
    ) -> Result<alloc::vec::Vec<super::circuit::Instance>, Error> {
        use super::Fp;
        use super::pallas::Affine;
        let anchor = Fp::from_bytes(&self.anchor).ok_or(Error::InvalidEncoding)?;
        let disable_cross_address = version.supports_cross_address_restriction();
        let mut instances = alloc::vec::Vec::with_capacity(self.action_count());
        for action in self.actions() {
            let point = |bytes: &[u8; 32]| {
                Affine::from_bytes(bytes)
                    .filter(|p| !bool::from(p.is_identity()))
                    .ok_or(Error::InvalidEncoding)
            };
            instances.push(super::circuit::Instance {
                anchor,
                cv_net: Affine::from_bytes(&action.cv).ok_or(Error::InvalidEncoding)?,
                nf_old: Fp::from_bytes(&action.nullifier).ok_or(Error::InvalidEncoding)?,
                rk: point(&action.rk)?,
                cmx: Fp::from_bytes(&action.cmx).ok_or(Error::InvalidEncoding)?,
                enable_spend: self.flags.spends_enabled(),
                enable_output: self.flags.outputs_enabled(),
                disable_cross_address,
            });
        }
        Ok(instances)
    }

    /// Whether the proof has a length consensus accepts for the circuit
    /// `version`: exactly what the number of actions implies from NU6.2
    /// on. Before NU6.2 the length was not a consensus rule (bytes after
    /// the proof proper were ignored, as `orchard` 0.16 still does for
    /// that version, and ZIP 257 states), so anything not shorter passes.
    #[cfg(feature = "zcash-orchard-prover")]
    pub(crate) fn proof_length_is_valid(&self, version: super::circuit::CircuitVersion) -> bool {
        let expected = super::circuit::proof_size(self.action_count());
        match version {
            super::circuit::CircuitVersion::InsecurePreNu6_2 => self.proof.len() >= expected,
            _ => self.proof.len() == expected,
        }
    }

    /// Verifies the zero-knowledge proof of the bundle with the verifying
    /// key of the circuit version in force at the height of the
    /// transaction (see
    /// [`CircuitVersion`](super::circuit::CircuitVersion)). From NU6.2 on
    /// the proof must have exactly the length the number of actions
    /// implies; before, consensus accepted longer ones, and so does this.
    ///
    /// Together with [`BundleRef::verify_signatures`] this covers what a
    /// bundle proves by itself; that the anchor is a root of the note
    /// commitment tree and that the nullifiers are unspent is for the
    /// caller to check against the chain.
    ///
    /// Several bundles are verified faster together: see
    /// [`BatchValidator`](super::circuit::BatchValidator).
    #[cfg(feature = "zcash-orchard-prover")]
    pub fn verify_proof(&self, vk: &super::circuit::VerifyingKey) -> Result<(), Error> {
        if !self.proof_length_is_valid(vk.version()) {
            return Err(Error::InvalidProof);
        }
        let instances = self.instances(vk.version())?;
        super::circuit::verify_proof(vk, &instances, self.proof).map_err(|_| Error::InvalidProof)
    }

    /// An owned copy of the bundle.
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> Bundle {
        Bundle {
            actions: self.actions().collect(),
            flags: self.flags,
            value_balance: self.value_balance,
            anchor: self.anchor,
            proof: self.proof.to_vec(),
            binding_sig: self.binding_sig,
        }
    }
}

/// An owned, non-empty Orchard bundle.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    /// The actions (at least one for the bundle to be serializable).
    pub actions: Vec<Action>,
    /// The flags.
    pub flags: Flags,
    /// The value leaving the Orchard pool, in zatoshi.
    pub value_balance: i64,
    /// The root of the note commitment tree the spends are proven against.
    pub anchor: [u8; 32],
    /// The zero-knowledge proof of all the actions.
    pub proof: Vec<u8>,
    /// The binding signature.
    pub binding_sig: [u8; 64],
}

#[cfg(feature = "alloc")]
impl Bundle {
    /// Parses the Orchard bundle of a transaction, see
    /// [`BundleRef::parse`].
    pub fn parse(data: &[u8]) -> Result<Option<Self>, Error> {
        Ok(BundleRef::parse(data)?.map(|b| b.to_owned()))
    }

    /// The serialization of the bundle, as the `orchard` field of a
    /// [`ZcashTx`](crate::zcashtx::ZcashTx) takes it. A bundle without
    /// actions serializes to the empty bundle (a single zero byte), its
    /// other fields being dropped.
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.actions.len();
        if n == 0 {
            return vec![0];
        }
        let mut out = Vec::with_capacity(9 + n * (ACTION_SIZE + 64) + 114 + self.proof.len());
        let (count, len) = compact_size(n as u64);
        out.extend_from_slice(&count[..len]);
        for action in &self.actions {
            out.extend_from_slice(&action.to_bytes());
        }
        out.push(self.flags.to_byte());
        out.extend_from_slice(&self.value_balance.to_le_bytes());
        out.extend_from_slice(&self.anchor);
        let (proof_len, len) = compact_size(self.proof.len() as u64);
        out.extend_from_slice(&proof_len[..len]);
        out.extend_from_slice(&self.proof);
        for action in &self.actions {
            out.extend_from_slice(&action.spend_auth_sig);
        }
        out.extend_from_slice(&self.binding_sig);
        out
    }
}
