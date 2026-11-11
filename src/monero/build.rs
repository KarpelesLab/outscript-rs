//! Building and signing a transaction, following `construct_tx_with_tx_key`
//! and `genRctSimple` of the reference wallet.

use purecrypto::zeroize::Zeroizing;

use super::address::Address;
use super::bulletproofs_plus::{BULLETPROOF_PLUS_MAX_OUTPUTS, BulletproofPlus};
use super::clsag::{Clsag, RingMember};
use super::extra::{PaymentId, push_additional_public_keys, push_payment_id, push_tx_public_key};
use super::ringct::commit_point;
use super::scan::{commitment_mask, derive_view_tag, encrypt_amount, encrypt_payment_id};
use super::tx::{
    EcdhInfo, Input, Output, RCT_TYPE_BULLETPROOF_PLUS, RctSignatures, Transaction,
    TransactionPrefix, relative_offsets,
};
use super::{Error, random_scalar, random_secret};
use crate::cryptonote::{
    EdwardsPoint, Scalar, derivation_to_scalar, derive_public_key, generate_key_derivation,
    generate_key_image, point_from_bytes, scalar_from_bytes, scalar_from_u64,
};
use crate::prelude::*;

/// An output to spend, with the ring that hides it.
///
/// The choice of the decoys matters for privacy, and wallets follow the
/// reference wallet's distribution: [`DecoyPicker`](super::DecoyPicker)
/// picks the candidates that way and [`build_ring`](super::build_ring)
/// makes the three ring fields here from what the daemon says of them.
/// Fetching is up to the caller.
#[derive(Clone)]
pub struct TransactionInput {
    /// The ring: the output being spent and its decoys, ordered by global
    /// index.
    pub ring: Vec<RingMember>,
    /// The global index of each ring member (among RingCT outputs), in
    /// increasing order.
    pub global_indices: Vec<u64>,
    /// The position of the output being spent in the ring.
    pub real_index: usize,
    /// The one-time secret key of the output being spent
    /// ([`AccountKeys::output_secret_key`](super::AccountKeys::output_secret_key)).
    pub secret_key: Zeroizing<[u8; 32]>,
    /// Its amount.
    pub amount: u64,
    /// The mask of its commitment (see
    /// [`OwnedOutput`](super::OwnedOutput)).
    pub mask: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for TransactionInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransactionInput")
            .field("global_indices", &self.global_indices)
            .finish_non_exhaustive()
    }
}

/// Where the change goes: an address of the sender, with the secret view key
/// of the sender's account.
///
/// The change output is derived with the view key instead of the
/// transaction key, so that it is found whatever the transaction public key
/// had to be for the other outputs.
#[derive(Clone)]
struct Change {
    address: Address,
    view_secret: Zeroizing<[u8; 32]>,
}

/// One output to make.
#[derive(Clone)]
struct Payment {
    address: Address,
    amount: u64,
    is_change: bool,
}

/// A transaction to build: inputs, destinations, change and fee.
///
/// ```
/// use outscript::monero::{
///     AccountKeys, Network, RingMember, SubaddressIndex, TransactionBuilder, TransactionInput,
///     commit,
/// };
/// use outscript::crypto::Zeroizing;
/// # use outscript::cryptonote::{cn_fast_hash, secret_key_to_public_key, sc_reduce32};
///
/// // A stand-in for a random source. Use a cryptographically secure one.
/// let mut state = [7u8; 32];
/// let mut rng = |out: &mut [u8]| {
///     for chunk in out.chunks_mut(32) {
///         state = cn_fast_hash(&state);
///         chunk.copy_from_slice(&state[..chunk.len()]);
///     }
/// };
///
/// // An output of ours: its one-time secret key, amount and mask (from
/// // scanning), in a ring with one decoy (real rings have sixteen members).
/// let secret_key = sc_reduce32(&[1u8; 32]);
/// let mask = sc_reduce32(&[2u8; 32]);
/// let ours = RingMember {
///     key: secret_key_to_public_key(&secret_key)?,
///     commitment: commit(1_000_000_000, &mask)?,
/// };
/// let decoy = RingMember {
///     key: secret_key_to_public_key(&sc_reduce32(&[3u8; 32]))?,
///     commitment: commit(5, &sc_reduce32(&[4u8; 32]))?,
/// };
///
/// let sender = AccountKeys::from_seed(&[5u8; 32])?;
/// let recipient = AccountKeys::from_seed(&[6u8; 32])?;
/// let mut builder = TransactionBuilder::new();
/// builder
///     .input(TransactionInput {
///         ring: vec![decoy, ours],
///         global_indices: vec![1000, 2000],
///         real_index: 1,
///         secret_key: Zeroizing::new(secret_key),
///         amount: 1_000_000_000,
///         mask: Zeroizing::new(mask),
///     })
///     .destination(recipient.address(Network::Mainnet), 700_000_000)
///     .change(sender.address(Network::Mainnet), sender.view_secret())
///     .fee(30_000_000);
/// let built = builder.build(&mut rng)?;
///
/// let tx = &built.transaction;
/// assert_eq!(tx.verify_balance()?, true);
/// assert_eq!(tx.verify_range_proof()?, true);
/// assert_eq!(tx.verify_ring_signatures(&[vec![decoy, ours]])?, true);
///
/// // The recipient finds the payment.
/// let found = recipient.view_keys().scan_transaction(tx, &mut |_| None)?;
/// assert_eq!(found.len(), 1);
/// assert_eq!(found[0].amount, 700_000_000);
/// assert_eq!(found[0].subaddress, SubaddressIndex::MAIN);
/// # Ok::<(), outscript::monero::Error>(())
/// ```
#[derive(Clone, Default)]
pub struct TransactionBuilder {
    inputs: Vec<TransactionInput>,
    payments: Vec<Payment>,
    change: Option<Change>,
    fee: u64,
    unlock_time: u64,
    shuffle: bool,
    /// The change address is only there to recognise the outputs that go
    /// back to the sender: no change output is added.
    no_change_output: bool,
    /// A payment id to encrypt for the recipient, in place of that of an
    /// integrated address.
    payment_id: Option<[u8; 8]>,
}

impl core::fmt::Debug for TransactionBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransactionBuilder")
            .field("inputs", &self.inputs.len())
            .field("destinations", &self.payments.len())
            .field("fee", &self.fee)
            .finish_non_exhaustive()
    }
}

/// A transaction built by [`TransactionBuilder::build`], with the secrets
/// that prove who it paid.
#[derive(Clone)]
pub struct BuiltTransaction {
    /// The signed transaction.
    pub transaction: Transaction,
    /// The transaction secret key `r`.
    pub tx_secret_key: Zeroizing<[u8; 32]>,
    /// The per-output secret keys, when the transaction has additional
    /// public keys (otherwise empty).
    pub additional_secret_keys: Vec<Zeroizing<[u8; 32]>>,
    /// For each output of the transaction, the position of its destination
    /// in the order the destinations were added (the change, if any, counts
    /// as the last one).
    pub output_order: Vec<usize>,
}

impl core::fmt::Debug for BuiltTransaction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BuiltTransaction")
            .field("transaction", &self.transaction)
            .finish_non_exhaustive()
    }
}

/// A uniformly random index below `bound` (which is small and not zero).
fn random_below(rng: &mut dyn FnMut(&mut [u8]), bound: usize) -> usize {
    let mut bytes = [0u8; 8];
    rng(&mut bytes);
    // The bias of reducing 64 random bits modulo a bound of at most 16 is
    // negligible.
    (u64::from_le_bytes(bytes) % (bound.max(1) as u64)) as usize
}

impl TransactionBuilder {
    /// A builder with nothing in it. Outputs are shuffled by default.
    pub fn new() -> Self {
        TransactionBuilder {
            shuffle: true,
            ..Default::default()
        }
    }

    /// Adds an output to spend.
    pub fn input(&mut self, input: TransactionInput) -> &mut Self {
        self.inputs.push(input);
        self
    }

    /// Adds a payment of `amount` atomic units to `address`.
    ///
    /// An integrated address sets the payment id of the transaction; there
    /// can be only one, and it needs the transaction to have a single
    /// recipient besides the change.
    pub fn destination(&mut self, address: Address, amount: u64) -> &mut Self {
        self.payments.push(Payment {
            address,
            amount,
            is_change: false,
        });
        self
    }

    /// Sends what is left of the inputs after the destinations and the fee
    /// to `address`, an address (or subaddress) of the account whose secret
    /// view key is `view_secret`.
    ///
    /// Without this, the inputs must equal the destinations plus the fee
    /// exactly. With it, a change output is always made, even of zero: a
    /// transaction needs two outputs.
    pub fn change(&mut self, address: Address, view_secret: &[u8; 32]) -> &mut Self {
        self.change = Some(Change {
            address,
            view_secret: Zeroizing::new(*view_secret),
        });
        self
    }

    /// Declares `address` as the sender's change address without asking for
    /// a change output: the destinations that pay it (the caller lists them
    /// itself, as the transaction sets of the reference wallet do) are
    /// derived with `view_secret`, as change is.
    pub(crate) fn change_among_destinations(
        &mut self,
        address: Address,
        view_secret: &[u8; 32],
    ) -> &mut Self {
        self.change(address, view_secret);
        self.no_change_output = true;
        self
    }

    /// Sets the 8-byte payment id of the transaction, as an integrated
    /// address among the destinations would.
    pub(crate) fn payment_id(&mut self, payment_id: [u8; 8]) -> &mut Self {
        self.payment_id = Some(payment_id);
        self
    }

    /// Sets the fee, in atomic units (zero by default): see
    /// [`estimate_fee`](super::estimate_fee) for what the reference wallet
    /// pays.
    pub fn fee(&mut self, fee: u64) -> &mut Self {
        self.fee = fee;
        self
    }

    /// Sets the unlock time (zero by default: no lock beyond the standard
    /// ten blocks).
    pub fn unlock_time(&mut self, unlock_time: u64) -> &mut Self {
        self.unlock_time = unlock_time;
        self
    }

    /// Whether to shuffle the outputs (the default), so that the position of
    /// the change does not give it away. Without, the outputs are in the
    /// order the destinations were added, the change last.
    pub fn shuffle_outputs(&mut self, shuffle: bool) -> &mut Self {
        self.shuffle = shuffle;
        self
    }

    /// Builds and signs the transaction: version 2, RingCT type
    /// [`RCT_TYPE_BULLETPROOF_PLUS`], outputs with view tags.
    ///
    /// As the reference wallet does:
    ///
    /// - the inputs are sorted by key image, in decreasing order;
    /// - the transaction public key is `r * G`, or `r * D` when the only
    ///   recipient besides the change is a subaddress with the spend key
    ///   `D`; when a subaddress is one of several recipients, every output
    ///   gets an additional public key;
    /// - the payment id of an integrated address is encrypted for its
    ///   recipient; a transaction with two outputs and no payment id gets an
    ///   encrypted dummy one, so that all look alike.
    ///
    /// `rng` fills its argument with cryptographically secure random bytes.
    /// All the secrets of the transaction come from it — transaction keys,
    /// commitment masks, signature nonces, the range proof's blinding — so a
    /// weak or repeating source loses funds or privacy.
    ///
    /// Fails with [`Error::InvalidAmounts`] without inputs, with fewer than
    /// two or more than [`BULLETPROOF_PLUS_MAX_OUTPUTS`] outputs, or when
    /// the amounts do not add up; [`Error::InvalidRing`] for a malformed
    /// ring or an output spent twice; [`Error::KeyMismatch`] or
    /// [`Error::CommitmentMismatch`] if an input's secret key, amount or
    /// mask do not open its ring member; [`Error::InvalidAddress`] for more
    /// than one payment id, or one with several recipients;
    /// [`Error::CryptoNote`] for keys that are not curve points or secrets
    /// that are not reduced scalars; [`Error::BadRandomness`] if `rng`
    /// yields only zeros.
    pub fn build(&self, rng: &mut dyn FnMut(&mut [u8])) -> Result<BuiltTransaction, Error> {
        // --- the amounts ---
        let mut total_in = 0u64;
        for input in &self.inputs {
            total_in = total_in
                .checked_add(input.amount)
                .ok_or(Error::InvalidAmounts)?;
        }
        let mut total_out = self.fee;
        for payment in &self.payments {
            total_out = total_out
                .checked_add(payment.amount)
                .ok_or(Error::InvalidAmounts)?;
        }
        let mut payments = self.payments.clone();
        match &self.change {
            Some(_) if self.no_change_output => {
                if total_in != total_out {
                    return Err(Error::InvalidAmounts);
                }
            }
            Some(change) => payments.push(Payment {
                address: change.address,
                amount: total_in
                    .checked_sub(total_out)
                    .ok_or(Error::InvalidAmounts)?,
                is_change: true,
            }),
            None if total_in != total_out => return Err(Error::InvalidAmounts),
            None => {}
        }
        if self.inputs.is_empty()
            || payments.len() < 2
            || payments.len() > BULLETPROOF_PLUS_MAX_OUTPUTS
        {
            return Err(Error::InvalidAmounts);
        }

        // --- the inputs, sorted by key image ---
        let mut inputs = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            let real = input.ring.get(input.real_index).ok_or(Error::InvalidRing)?;
            if input.global_indices.len() != input.ring.len() {
                return Err(Error::InvalidRing);
            }
            let key_offsets = relative_offsets(&input.global_indices)?;
            let secret = scalar_from_bytes(&input.secret_key)?;
            if EdwardsPoint::mul_base(&secret).compress() != real.key {
                return Err(Error::KeyMismatch);
            }
            let mask = scalar_from_bytes(&input.mask)?;
            if commit_point(&scalar_from_u64(input.amount), &mask).compress() != real.commitment {
                return Err(Error::CommitmentMismatch);
            }
            let key_image = generate_key_image(&real.key, &input.secret_key)?;
            inputs.push((key_image, key_offsets, input));
        }
        inputs.sort_by_key(|input| core::cmp::Reverse(input.0));
        if inputs.windows(2).any(|pair| match pair {
            [a, b] => a.0 == b.0,
            _ => false,
        }) {
            return Err(Error::InvalidRing);
        }

        // --- the outputs ---
        let mut order: Vec<usize> = (0..payments.len()).collect();
        if self.shuffle {
            // Fisher-Yates.
            for i in (1..order.len()).rev() {
                order.swap(i, random_below(rng, i + 1));
            }
        }
        let payments: Vec<Payment> = order
            .iter()
            .filter_map(|i| payments.get(*i).cloned())
            .collect();

        // The distinct recipients, besides the change address.
        let change_address = self.change.as_ref().map(|change| change.address);
        let same = |a: &Address, b: &Address| {
            a.spend_public == b.spend_public && a.view_public == b.view_public
        };
        let is_change_address =
            |address: &Address| change_address.is_some_and(|change| same(&change, address));
        let mut recipients: Vec<&Address> = Vec::new();
        for payment in &payments {
            if !is_change_address(&payment.address)
                && !recipients.iter().any(|known| same(known, &payment.address))
            {
                recipients.push(&payment.address);
            }
        }
        let subaddresses = recipients.iter().filter(|a| a.is_subaddress()).count();
        let standard = recipients.len() - subaddresses;

        // The transaction key: R = r * G, or r * D for a lone subaddress.
        let tx_secret = random_secret(rng)?;
        let r = scalar_from_bytes(&tx_secret)?;
        let tx_public = match recipients.first() {
            Some(only) if standard == 0 && subaddresses == 1 => {
                point_from_bytes(&only.spend_public)?.mul(&r).compress()
            }
            _ => EdwardsPoint::mul_base(&r).compress(),
        };
        let need_additional = subaddresses > 0 && (standard > 0 || subaddresses > 1);

        let mut outputs = Vec::with_capacity(payments.len());
        let mut ecdh_info = Vec::with_capacity(payments.len());
        let mut out_pk = Vec::with_capacity(payments.len());
        let mut out_masks = Vec::with_capacity(payments.len());
        let mut out_amounts = Vec::with_capacity(payments.len());
        let mut additional_secrets = Vec::new();
        let mut additional_publics = Vec::new();
        for (index, payment) in payments.iter().enumerate() {
            let output_index = index as u64;
            let address = &payment.address;
            let mut additional = None;
            if need_additional {
                let secret = random_secret(rng)?;
                let s = scalar_from_bytes(&secret)?;
                additional_publics.push(if address.is_subaddress() {
                    point_from_bytes(&address.spend_public)?.mul(&s).compress()
                } else {
                    EdwardsPoint::mul_base(&s).compress()
                });
                additional = Some(secret.clone());
                additional_secrets.push(secret);
            }
            let derivation = Zeroizing::new(match (&self.change, additional) {
                // The change: the sender's view key and the transaction
                // public key.
                (Some(change), _) if payment.is_change || is_change_address(address) => {
                    generate_key_derivation(&tx_public, &change.view_secret)?
                }
                (_, Some(secret)) if address.is_subaddress() => {
                    generate_key_derivation(&address.view_public, &secret)?
                }
                _ => generate_key_derivation(&address.view_public, &tx_secret)?,
            });
            let key = derive_public_key(&derivation, output_index, &address.spend_public)?;
            let shared = Zeroizing::new(derivation_to_scalar(&derivation, output_index));
            let mask = commitment_mask(&shared);
            let mask_scalar = scalar_from_bytes(&mask)?;
            outputs.push(Output {
                amount: 0,
                key,
                view_tag: Some(derive_view_tag(&derivation, output_index)),
            });
            ecdh_info.push(EcdhInfo::Compact(encrypt_amount(&shared, payment.amount)));
            out_pk.push(commit_point(&scalar_from_u64(payment.amount), &mask_scalar).compress());
            out_masks.push(mask);
            out_amounts.push(payment.amount);
        }

        // --- the extra field: public key, additional keys, payment id ---
        let mut extra = Vec::new();
        push_tx_public_key(&mut extra, &tx_public);
        if need_additional {
            push_additional_public_keys(&mut extra, &additional_publics);
        }
        let mut payment_ids = payments
            .iter()
            .filter_map(|payment| payment.address.payment_id());
        let payment_id = payment_ids.next();
        let payment_id = match (self.payment_id, payment_id) {
            (Some(_), Some(_)) => return Err(Error::InvalidAddress),
            (set, found) => set.or(found),
        };
        if payment_ids.next().is_some() {
            return Err(Error::InvalidAddress);
        }
        // The view key the payment id is encrypted for: that of the only
        // recipient, or the sender's own when there is none.
        let id_view_key = {
            let mut found: Option<&Address> = None;
            let mut several = false;
            for payment in &payments {
                let address = &payment.address;
                if payment.amount == 0
                    || is_change_address(address)
                    || found.is_some_and(|known| same(known, address))
                {
                    continue;
                }
                several |= found.is_some();
                found = Some(address);
            }
            match (found, several) {
                (_, true) => None,
                (Some(address), false) => Some(address.view_public),
                (None, false) => change_address.map(|change| change.view_public),
            }
        };
        match (payment_id, id_view_key) {
            (Some(id), Some(view_public)) => {
                let derivation = Zeroizing::new(generate_key_derivation(&view_public, &tx_secret)?);
                let encrypted = encrypt_payment_id(&derivation, &id);
                push_payment_id(&mut extra, &PaymentId::Encrypted(encrypted));
            }
            (Some(_), None) => return Err(Error::InvalidAddress),
            (None, Some(view_public)) if payments.len() <= 2 => {
                let derivation = Zeroizing::new(generate_key_derivation(&view_public, &tx_secret)?);
                let encrypted = encrypt_payment_id(&derivation, &[0u8; 8]);
                push_payment_id(&mut extra, &PaymentId::Encrypted(encrypted));
            }
            (None, _) => {}
        }

        // --- the pseudo-outputs: the last mask makes the sums equal ---
        let mut out_mask_sum = Scalar::ZERO;
        for mask in &out_masks {
            out_mask_sum = out_mask_sum.add(&scalar_from_bytes(mask)?);
        }
        let mut pseudo_masks: Vec<Scalar> = Vec::with_capacity(inputs.len());
        let mut pseudo_mask_sum = Scalar::ZERO;
        for i in 0..inputs.len() {
            let mask = if i + 1 == inputs.len() {
                out_mask_sum.sub(&pseudo_mask_sum)
            } else {
                random_scalar(rng)?
            };
            pseudo_mask_sum = pseudo_mask_sum.add(&mask);
            pseudo_masks.push(mask);
        }
        let pseudo_outs: Vec<[u8; 32]> = inputs
            .iter()
            .zip(&pseudo_masks)
            .map(|((_, _, input), mask)| {
                commit_point(&scalar_from_u64(input.amount), mask).compress()
            })
            .collect();

        // --- the range proof ---
        let masks: Zeroizing<Vec<[u8; 32]>> =
            Zeroizing::new(out_masks.iter().map(|mask| **mask).collect());
        let proof = BulletproofPlus::prove(&out_amounts, &masks, rng)?;

        let mut transaction = Transaction {
            prefix: TransactionPrefix {
                version: 2,
                unlock_time: self.unlock_time,
                inputs: inputs
                    .iter()
                    .map(|(key_image, key_offsets, _)| Input::ToKey {
                        amount: 0,
                        key_offsets: key_offsets.clone(),
                        key_image: *key_image,
                    })
                    .collect(),
                outputs,
                extra,
            },
            signatures: Vec::new(),
            rct: RctSignatures {
                rct_type: RCT_TYPE_BULLETPROOF_PLUS,
                fee: self.fee,
                ecdh_info,
                out_pk,
                pseudo_outs,
                bulletproofs_plus: vec![proof],
                ..Default::default()
            },
        };

        // --- the ring signatures ---
        let message = transaction.signature_hash();
        for (((key_image, _, input), pseudo_mask), pseudo_out) in inputs
            .iter()
            .zip(&pseudo_masks)
            .zip(&transaction.rct.pseudo_outs)
        {
            let mask_difference =
                Zeroizing::new(scalar_from_bytes(&input.mask)?.sub(pseudo_mask).to_bytes());
            let (clsag, image) = Clsag::sign(
                &message,
                &input.ring,
                input.real_index,
                &input.secret_key,
                &mask_difference,
                pseudo_out,
                rng,
            )?;
            if image != *key_image {
                return Err(Error::KeyMismatch);
            }
            transaction.rct.clsags.push(clsag);
        }

        Ok(BuiltTransaction {
            transaction,
            tx_secret_key: tx_secret,
            additional_secret_keys: additional_secrets,
            output_order: order,
        })
    }
}
