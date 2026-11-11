//! Multisignature wallets, as the reference wallet has them since version
//! 0.18 (`src/multisig`): the key exchange that makes an M-of-N account, the
//! exchange of partial key images and signing nonces, and the signing of a
//! transaction by M of the participants in turn.
//!
//! The reference wallet calls its multisig experimental, and so is this: see
//! the caveats on [`MultisigAccount`].

use alloc::collections::{BTreeMap, BTreeSet};

use purecrypto::zeroize::Zeroizing;

use super::address::{Address, Network};
use super::build::{Payment, TransactionBuilder};
use super::bulletproofs_plus::{BULLETPROOF_PLUS_MAX_OUTPUTS, BulletproofPlus};
use super::clsag::{Clsag, RingMember, multisig_challenge};
use super::extra::{PaymentId, payment_id};
use super::files::{
    ExportedOutput, MULTISIG_INFO_MAGIC, MultisigSignature, MultisigTxSet, PendingTx,
    TxConstructionData, TxDestination, TxSource, WalletCipher, archive, put_keys,
};
use super::keys::{AccountKeys, SubaddressIndex, ViewKeys, subaddress_secret_key};
use super::ringct::{commit_point, inv_eight};
use super::scan::derive_subaddress_public_key;
use super::tx::{
    EcdhInfo, Input, RCT_TYPE_BULLETPROOF_PLUS, RctSignatures, Reader, Transaction,
    TransactionPrefix, relative_offsets,
};
use super::{Error, random_scalar, random_secret};
use crate::cryptonote::{
    EdwardsPoint, Hasher, Scalar, base58, check_signature, cn_fast_hash, derivation_to_scalar,
    generate_signature, point_from_bytes, point_from_hash, push_varint, scalar_from_bytes,
    scalar_from_u64, secret_key_to_public_key,
};
use crate::prelude::*;

/// The largest number of participants a multisig account can have.
pub const MULTISIG_MAX_SIGNERS: usize = 16;

/// The prefix of the first message of the key exchange.
const KEX_MAGIC_ROUND_1: &str = "MultisigxV2R1";
/// The prefix of the messages of the later rounds.
const KEX_MAGIC_ROUND_N: &str = "MultisigxV2Rn";

type KeySet = BTreeSet<[u8; 32]>;
/// Public keys, each with the participants that share it.
type KeyOrigins = BTreeMap<[u8; 32], KeySet>;

/// A domain separator, padded with zeros to 32 bytes.
fn salt(name: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (o, b) in out.iter_mut().zip(name) {
        *o = *b;
    }
    out
}

/// `get_multisig_blinded_secret_key`: `Hs(key || "Multisig")`, so that the
/// keys a participant puts in the exchange say nothing of its own.
fn blinded_secret_key(key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut h = Hasher::new();
    h.update(key);
    h.update(&salt(b"Multisig"));
    Zeroizing::new(h.finalize_scalar())
}

/// A public key that can take part: a point of the prime-order subgroup
/// other than the identity.
fn check_public_key(key: &[u8; 32]) -> Result<EdwardsPoint, Error> {
    let point = point_from_bytes(key).map_err(|_| Error::InvalidMultisig)?;
    if point == EdwardsPoint::identity() || !bool::from(point.is_torsion_free()) {
        return Err(Error::InvalidMultisig);
    }
    Ok(point)
}

/// The binomial coefficient, for the small values of the key exchange.
fn n_choose_k(n: usize, k: usize) -> usize {
    if k > n {
        return 0;
    }
    let mut result = 1usize;
    for i in 0..k.min(n - k) {
        result = result * (n - i) / (i + 1);
    }
    result
}

/// A message of the key exchange (`multisig_kex_msg`), as the participants
/// pass them around: what `prepare_multisig`, `make_multisig` and
/// `exchange_multisig_keys` print and take.
#[derive(Clone)]
struct KexMessage {
    round: u32,
    /// The base public key of the participant who made the message.
    signing_public: [u8; 32],
    /// Round 1: the participant's share of the view key.
    secret: Zeroizing<[u8; 32]>,
    /// Later rounds: the public keys of the round.
    public_keys: Vec<[u8; 32]>,
}

impl KexMessage {
    fn hash(&self) -> [u8; 32] {
        let mut data = Zeroizing::new(Vec::new());
        let magic = if self.round == 1 {
            KEX_MAGIC_ROUND_1
        } else {
            KEX_MAGIC_ROUND_N
        };
        data.extend_from_slice(magic.as_bytes());
        data.extend_from_slice(&self.round.to_le_bytes());
        data.extend_from_slice(&self.signing_public);
        if self.round == 1 {
            data.extend_from_slice(&*self.secret);
        } else {
            for key in &self.public_keys {
                data.extend_from_slice(key);
            }
        }
        cn_fast_hash(&data)
    }

    /// The message of `round`, signed with the base secret key.
    fn encode(
        round: u32,
        signing_secret: &[u8; 32],
        public_keys: Vec<[u8; 32]>,
        secret: &[u8; 32],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<String, Error> {
        let message = KexMessage {
            round,
            signing_public: secret_key_to_public_key(signing_secret)?,
            secret: Zeroizing::new(*secret),
            public_keys,
        };
        let nonce = random_secret(rng)?;
        let signature = generate_signature(
            &message.hash(),
            &message.signing_public,
            signing_secret,
            &nonce,
        )?;
        let mut data = Zeroizing::new(Vec::new());
        let magic = if round == 1 {
            data.extend_from_slice(&*message.secret);
            KEX_MAGIC_ROUND_1
        } else {
            push_varint(&mut data, round as u64);
            push_varint(&mut data, message.public_keys.len() as u64);
            for key in &message.public_keys {
                data.extend_from_slice(key);
            }
            KEX_MAGIC_ROUND_N
        };
        data.extend_from_slice(&message.signing_public);
        data.extend_from_slice(&signature);
        let mut text = String::from(magic);
        text.push_str(&base58::encode(&data));
        Ok(text)
    }

    /// Reads and checks a message (`parse_and_validate_msg`).
    fn parse(text: &str) -> Result<Self, Error> {
        let text = text.trim();
        let (first, body) = if let Some(body) = text.strip_prefix(KEX_MAGIC_ROUND_1) {
            (true, body)
        } else if let Some(body) = text.strip_prefix(KEX_MAGIC_ROUND_N) {
            (false, body)
        } else {
            return Err(Error::InvalidMultisig);
        };
        // The text is bounded by what a message of sixteen participants
        // can hold.
        if body.len() > 1 << 20 {
            return Err(Error::InvalidMultisig);
        }
        let data = Zeroizing::new(base58::decode(body).map_err(|_| Error::InvalidMultisig)?);
        let mut r = Reader { data: &data };
        let mut read = || -> Result<(KexMessage, [u8; 64]), Error> {
            let mut message = KexMessage {
                round: 1,
                signing_public: [0u8; 32],
                secret: Zeroizing::new([0u8; 32]),
                public_keys: Vec::new(),
            };
            if first {
                *message.secret = r.key()?;
            } else {
                message.round = u32::try_from(r.varint()?).map_err(|_| Error::InvalidMultisig)?;
                message.public_keys = r.key_vec()?;
            }
            message.signing_public = r.key()?;
            let signature = r.array()?;
            if !r.data.is_empty() || (!first && message.round <= 1) {
                return Err(Error::InvalidMultisig);
            }
            Ok((message, signature))
        };
        let (message, signature) = read().map_err(|_| Error::InvalidMultisig)?;
        for key in &message.public_keys {
            check_public_key(key)?;
        }
        check_public_key(&message.signing_public)?;
        if !check_signature(&message.hash(), &message.signing_public, &signature) {
            return Err(Error::InvalidMultisig);
        }
        Ok(message)
    }
}

/// The number of rounds of the key exchange proper, for an M-of-N account:
/// `N - M + 1`. One more round follows, in which the participants confirm
/// to each other the account they arrived at.
const fn kex_rounds_required(signers: usize, threshold: usize) -> usize {
    signers - threshold + 1
}

/// `compute_multisig_aggregation_coefficient`: the factor a component of the
/// spend key is multiplied by, which keeps a participant from choosing its
/// keys to cancel the others'.
fn aggregation_coefficient(sorted_keys: &[[u8; 32]], key: &[u8; 32]) -> Scalar {
    let mut h = Hasher::new();
    h.update(key);
    for other in sorted_keys {
        h.update(other);
    }
    h.update(&salt(b"Multisig_key_agg"));
    h.finalize_to_scalar()
}

/// A key exchange in progress: how a wallet becomes one of the N
/// participants of an M-of-N account, as `prepare_multisig`,
/// `make_multisig` and `exchange_multisig_keys` of the reference wallet do.
///
/// Every participant starts from an ordinary account and
///
/// 1. sends the others its [`first_message`](Self::first_message);
/// 2. gives [`start`](Self::start) the threshold and the first messages of
///    all the others, and sends them the message it returns;
/// 3. gives [`update`](Self::update) the messages of the others for the
///    round, and sends them the message it returns — as many times as it
///    takes for [`is_ready`](Self::is_ready): `N - M` times, and once more
///    for the round in which the participants confirm the result to each
///    other;
/// 4. takes the account with [`finish`](Self::finish).
///
/// The messages carry secrets — the first one a share of the account's view
/// key, the next ones keys derived from Diffie-Hellman exchanges — and they
/// are only signed, not encrypted: the participants must exchange them over
/// channels that are confidential and authenticated. Whoever reads them all
/// can watch the account; whoever can replace them can take part in it.
///
/// ```
/// use outscript::monero::{AccountKeys, MultisigKex, Network};
/// # use outscript::cryptonote::cn_fast_hash;
/// # let mut state = [7u8; 32];
/// # let mut rng = |out: &mut [u8]| {
/// #     for chunk in out.chunks_mut(32) {
/// #         state = cn_fast_hash(&state);
/// #         chunk.copy_from_slice(&state[..chunk.len()]);
/// #     }
/// # };
///
/// // Two participants make a 2-of-2 account. `rng` fills its argument
/// // with cryptographically secure random bytes.
/// let mut alice = MultisigKex::new(&AccountKeys::from_seed(&[1u8; 32])?)?;
/// let mut bob = MultisigKex::new(&AccountKeys::from_seed(&[2u8; 32])?)?;
/// let (a1, b1) = (alice.first_message(&mut rng)?, bob.first_message(&mut rng)?);
/// let a2 = alice.start(2, &[&b1], &mut rng)?;
/// let b2 = bob.start(2, &[&a1], &mut rng)?;
/// // The confirmation round.
/// alice.update(&[&b2], &mut rng)?;
/// bob.update(&[&a2], &mut rng)?;
/// assert!(alice.is_ready() && bob.is_ready());
/// let (alice, bob) = (alice.finish()?, bob.finish()?);
/// assert_eq!(alice.address(Network::Mainnet), bob.address(Network::Mainnet));
/// # Ok::<(), outscript::monero::Error>(())
/// ```
#[derive(Clone)]
pub struct MultisigKex {
    base_secret: Zeroizing<[u8; 32]>,
    base_public: [u8; 32],
    base_common_secret: Zeroizing<[u8; 32]>,
    threshold: usize,
    /// The base public keys of the participants, sorted.
    signers: Vec<[u8; 32]>,
    multisig_secrets: Vec<Zeroizing<[u8; 32]>>,
    common_secret: Zeroizing<[u8; 32]>,
    multisig_public: [u8; 32],
    rounds_complete: usize,
    /// The keys this participant put in the last round, with who shares
    /// them.
    kex_keys: KeyOrigins,
}

impl core::fmt::Debug for MultisigKex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MultisigKex")
            .field("threshold", &self.threshold)
            .field("signers", &self.signers.len())
            .field("rounds_complete", &self.rounds_complete)
            .finish_non_exhaustive()
    }
}

impl MultisigKex {
    /// Starts from an ordinary account: its keys, blinded, are what this
    /// participant brings to the exchange.
    ///
    /// Fails with [`Error::CryptoNote`] if a key of the account is not a
    /// reduced scalar.
    pub fn new(account: &AccountKeys) -> Result<Self, Error> {
        let base_secret = blinded_secret_key(account.spend_secret());
        let base_common_secret = blinded_secret_key(account.view_secret());
        let base_public = secret_key_to_public_key(&base_secret)?;
        Ok(MultisigKex {
            base_secret,
            base_public,
            base_common_secret,
            threshold: 0,
            signers: Vec::new(),
            multisig_secrets: Vec::new(),
            common_secret: Zeroizing::new([0u8; 32]),
            multisig_public: [0u8; 32],
            rounds_complete: 0,
            kex_keys: KeyOrigins::new(),
        })
    }

    /// The public key that identifies this participant among the signers.
    pub fn signer_public(&self) -> &[u8; 32] {
        &self.base_public
    }

    /// The first message, for all the other participants
    /// (`prepare_multisig`).
    ///
    /// `rng` fills its argument with cryptographically secure random bytes
    /// (the nonce of the message's signature comes from it); it fails with
    /// [`Error::BadRandomness`] if it yields only zeros.
    pub fn first_message(&self, rng: &mut dyn FnMut(&mut [u8])) -> Result<String, Error> {
        KexMessage::encode(
            1,
            &self.base_secret,
            Vec::new(),
            &self.base_common_secret,
            rng,
        )
    }

    /// Sets the threshold and takes the first messages of the other
    /// participants (`make_multisig`); this participant's own, if it is
    /// among them, is ignored. Returns the message of the next round, for
    /// all the others.
    ///
    /// Fails with [`Error::InvalidMultisig`] for a message that is
    /// malformed, badly signed or of another round, a participant that
    /// appears twice, fewer than two or more than
    /// [`MULTISIG_MAX_SIGNERS`] participants, a threshold of zero or above
    /// the number of participants, or an exchange already started. `rng` is
    /// as for [`first_message`](Self::first_message).
    pub fn start(
        &mut self,
        threshold: u32,
        messages: &[&str],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<String, Error> {
        if self.rounds_complete != 0 {
            return Err(Error::InvalidMultisig);
        }
        let mut parsed = Vec::with_capacity(messages.len());
        let mut signers = vec![self.base_public];
        for message in messages {
            let message = KexMessage::parse(message)?;
            if message.round != 1 {
                return Err(Error::InvalidMultisig);
            }
            if message.signing_public == self.base_public {
                continue;
            }
            if signers.contains(&message.signing_public) {
                return Err(Error::InvalidMultisig);
            }
            signers.push(message.signing_public);
            parsed.push(message);
        }
        signers.sort_unstable();
        let threshold = threshold as usize;
        if signers.len() < 2
            || signers.len() > MULTISIG_MAX_SIGNERS
            || threshold == 0
            || threshold > signers.len()
        {
            return Err(Error::InvalidMultisig);
        }
        let mut next = self.clone();
        next.threshold = threshold;
        next.signers = signers;
        let message = next.round(&parsed, rng)?;
        *self = next;
        Ok(message)
    }

    /// Takes the messages of the other participants for the current round
    /// (`exchange_multisig_keys`) and returns the message of the next one,
    /// for all the others. After the last round the message returned is the
    /// same confirmation again, which nobody needs.
    ///
    /// Fails with [`Error::InvalidMultisig`] for a message that is
    /// malformed, badly signed, of another round or from someone who is not
    /// a participant, for messages that do not add up to what the round
    /// expects of every participant, or if the exchange is not started or
    /// already complete. The state is unchanged on failure. `rng` is as for
    /// [`first_message`](Self::first_message).
    pub fn update(
        &mut self,
        messages: &[&str],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<String, Error> {
        if self.rounds_complete == 0 || self.is_ready() {
            return Err(Error::InvalidMultisig);
        }
        let mut parsed = Vec::with_capacity(messages.len());
        for message in messages {
            parsed.push(KexMessage::parse(message)?);
        }
        let mut next = self.clone();
        let message = next.round(&parsed, rng)?;
        *self = next;
        Ok(message)
    }

    /// Whether the exchange is complete, confirmation included.
    pub fn is_ready(&self) -> bool {
        self.rounds_complete > 0
            && self.rounds_complete > kex_rounds_required(self.signers.len(), self.threshold)
    }

    /// The account, once the exchange is complete; [`Error::InvalidMultisig`]
    /// before.
    pub fn finish(self) -> Result<MultisigAccount, Error> {
        if !self.is_ready() {
            return Err(Error::InvalidMultisig);
        }
        let view = ViewKeys::new(&self.common_secret, &self.multisig_public)?;
        Ok(MultisigAccount {
            threshold: self.threshold,
            signers: self.signers.clone(),
            base_secret: self.base_secret.clone(),
            multisig_secrets: self.multisig_secrets.clone(),
            view,
        })
    }

    /// One round (`kex_update_impl`).
    fn round(
        &mut self,
        messages: &[KexMessage],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<String, Error> {
        let signers = self.signers.len();
        let required = kex_rounds_required(signers, self.threshold);
        let current = self.rounds_complete + 1;
        if messages.is_empty()
            || current > required + 1
            || messages.iter().any(|m| m.round as usize != current)
        {
            return Err(Error::InvalidMultisig);
        }

        // --- initialize_kex_update ---
        let mut exclude: Vec<[u8; 32]> = Vec::new();
        if self.rounds_complete == 0 {
            // The view key: the hash of everybody's share, sorted.
            let mut shares: Vec<Zeroizing<[u8; 32]>> = vec![self.base_common_secret.clone()];
            for message in messages {
                if message.signing_public != self.base_public {
                    shares.push(message.secret.clone());
                }
            }
            shares.sort_unstable_by(|a, b| a[..].cmp(&b[..]));
            let mut h = Hasher::new();
            for share in &shares {
                h.update(&**share);
            }
            *self.common_secret = h.finalize_scalar();
            if *self.common_secret == [0u8; 32] {
                return Err(Error::InvalidMultisig);
            }
            if required == 1 {
                self.multisig_secrets = vec![self.base_secret.clone()];
            }
            exclude.push(self.base_public);
        } else {
            exclude.extend(self.kex_keys.keys().copied());
        }

        // --- multisig_kex_process_round_msgs ---
        let evaluated = if self.threshold == 1 && current == required {
            KeyOrigins::new()
        } else if current <= required {
            self.evaluate_round(current, messages, &exclude)?
        } else {
            self.evaluate_confirmation(messages)?
        };
        let result = if current < required {
            // Diffie-Hellman with every key of the round.
            let secret = scalar_from_bytes(&self.base_secret)?;
            let mut derivations = KeyOrigins::new();
            for (key, origins) in evaluated {
                let derivation = check_public_key(&key)?
                    .mul(&secret)
                    .mul_by_cofactor()
                    .compress();
                derivations.insert(derivation, origins);
            }
            derivations
        } else {
            evaluated
        };

        // --- finalize_kex_update ---
        let common_public = secret_key_to_public_key(&self.common_secret)?;
        let next_keys: Vec<[u8; 32]>;
        if self.rounds_complete == required {
            // The confirmation: everybody arrived at the same account.
            if !result.contains_key(&self.multisig_public) || !result.contains_key(&common_public) {
                return Err(Error::InvalidMultisig);
            }
            next_keys = vec![self.multisig_public, common_public];
        } else if self.rounds_complete + 1 == required {
            // The last round: the spend key is the aggregate of the keys of
            // the others and this participant's own.
            let mut keys: Vec<[u8; 32]> = result.keys().copied().collect();
            let mut own = Vec::with_capacity(self.multisig_secrets.len());
            for secret in &self.multisig_secrets {
                let public = secret_key_to_public_key(secret)?;
                own.push(public);
                keys.push(public);
            }
            keys.sort_unstable();
            if keys.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(Error::InvalidMultisig);
            }
            let mut aggregate = EdwardsPoint::identity();
            for key in &keys {
                let coefficient = aggregation_coefficient(&keys, key);
                if let Some(index) = own.iter().position(|public| public == key) {
                    let secret = scalar_from_bytes(&self.multisig_secrets[index])?;
                    let secret = secret.mul(&coefficient);
                    if secret == Scalar::ZERO {
                        return Err(Error::InvalidMultisig);
                    }
                    *self.multisig_secrets[index] = secret.to_bytes();
                }
                aggregate = aggregate.add(&check_public_key(key)?.mul(&coefficient));
            }
            self.multisig_public = aggregate.compress();
            self.kex_keys.clear();
            next_keys = vec![self.multisig_public, common_public];
        } else if self.rounds_complete + 2 == required {
            // The round before the last: the shared secrets become keys.
            self.multisig_secrets.clear();
            self.kex_keys.clear();
            let mut keys = Vec::with_capacity(result.len());
            for (derivation, origins) in result {
                let secret = blinded_secret_key(&derivation);
                let public = secret_key_to_public_key(&secret)?;
                self.multisig_secrets.push(secret);
                self.kex_keys.insert(public, origins);
                keys.push(public);
            }
            next_keys = keys;
        } else {
            next_keys = result.keys().copied().collect();
            self.kex_keys = result;
        }
        self.rounds_complete += 1;
        let round = self.rounds_complete.min(required) + 1;
        KexMessage::encode(round as u32, &self.base_secret, next_keys, &[0u8; 32], rng)
    }

    /// The keys of a round of the exchange proper, with who shares each
    /// (`evaluate_multisig_kex_round_msgs`).
    fn evaluate_round(
        &self,
        round: usize,
        messages: &[KexMessage],
        exclude: &[[u8; 32]],
    ) -> Result<KeyOrigins, Error> {
        let signers = self.signers.len();
        let mut keys = KeyOrigins::new();
        for message in messages {
            if round == 1 {
                keys.entry(message.signing_public)
                    .or_default()
                    .insert(message.signing_public);
            } else {
                for key in &message.public_keys {
                    if !exclude.contains(key) {
                        keys.entry(*key).or_default().insert(message.signing_public);
                    }
                }
            }
        }
        for origins in keys.values_mut() {
            origins.remove(&self.base_public);
        }
        keys.retain(|_, origins| !origins.is_empty());

        // Every key is shared by as many of the others as the round says,
        // and every other participant brings as many keys as it should.
        let mut by_origin: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        for origins in keys.values() {
            if origins.len() < round {
                return Err(Error::InvalidMultisig);
            }
            for origin in origins {
                *by_origin.entry(*origin).or_default() += 1;
            }
        }
        let expected_others = n_choose_k(signers - 2, round - 1);
        let expected_own = n_choose_k(signers - 1, round - 1);
        if by_origin.len() < signers - 1
            || expected_others == 0
            || expected_own == 0
            || exclude.len() != expected_own
        {
            return Err(Error::InvalidMultisig);
        }
        for (origin, count) in &by_origin {
            if *count != expected_others || !self.signers.contains(origin) {
                return Err(Error::InvalidMultisig);
            }
        }
        Ok(keys)
    }

    /// The two keys of the confirmation round
    /// (`evaluate_multisig_post_kex_round_msgs`).
    fn evaluate_confirmation(&self, messages: &[KexMessage]) -> Result<KeyOrigins, Error> {
        let mut keys = KeyOrigins::new();
        for message in messages {
            for key in &message.public_keys {
                keys.entry(*key).or_default().insert(message.signing_public);
            }
        }
        let mut sets = keys.values();
        let (Some(first), Some(second), None) = (sets.next(), sets.next(), sets.next()) else {
            return Err(Error::InvalidMultisig);
        };
        if first != second {
            return Err(Error::InvalidMultisig);
        }
        let mut origins = first.clone();
        origins.insert(self.base_public);
        if origins.len() < self.signers.len()
            || origins.iter().any(|origin| !self.signers.contains(origin))
        {
            return Err(Error::InvalidMultisig);
        }
        Ok(keys)
    }
}

/// One participant's side of an M-of-N multisig account: what
/// [`MultisigKex`] ends with.
///
/// The account has an ordinary address and an ordinary view key, which all
/// the participants know: receiving and scanning are as for any account
/// ([`view_keys`](Self::view_keys)). Its spend key exists nowhere: each
/// participant holds shares of it, and M of them sign a transaction in turn.
///
/// Spending takes three steps, in the files of the reference wallet:
///
/// 1. every participant tells the others its shares of the key images of
///    the account's outputs and the public nonces it will sign with
///    ([`export_info`](Self::export_info)), and keeps the secret nonces;
/// 2. one participant proposes a transaction and signs it first
///    ([`propose`](Self::propose));
/// 3. the others sign it in turn ([`sign`](Self::sign)) until
///    [`threshold`](Self::threshold) have, which completes it.
///
/// ```no_run
/// use outscript::monero::{
///     MultisigAccount, MultisigNonces, MultisigTxSet, OutputExport,
/// };
/// # fn account() -> MultisigAccount { unimplemented!() }
/// # fn received(_: &str) -> Vec<u8> { unimplemented!() }
/// # let mut rng = |_: &mut [u8]| {};
///
/// let account = account(); // from `MultisigKex::finish`
/// let cipher = account.cipher()?;
/// // The outputs of the account, from a wallet that watches it.
/// let outputs = OutputExport::from_file(&cipher, &received("outputs"))?.outputs;
///
/// // 1. Our info for the others; the secret nonces are for us to keep.
/// let (info, nonces) = account.export_info(&outputs, &mut rng)?;
/// let info_file = info.to_file(&cipher, &mut rng)?;
/// let stored = nonces.to_bytes();
///
/// // 3. Another participant proposed a transaction: look at it, sign it.
/// let set = MultisigTxSet::from_file(&cipher, &received("multisig_monero_tx"))?;
/// for tx in &set.transactions {
///     for destination in &tx.destinations {
///         println!("{} to {}", destination.amount, destination.original);
///     }
///     println!("fee {}", tx.fee);
/// }
/// let mut nonces = MultisigNonces::from_bytes(&stored)?;
/// let signed = account.sign(&set, &outputs, &mut nonces)?;
/// // What is left of the nonces is stored before the signature leaves.
/// let stored = nonces.to_bytes();
/// let signed_file = signed.to_file(&cipher, &mut rng)?;
/// if signed.is_complete(account.threshold()) {
///     // Ready for a daemon.
///     let raw = signed.transactions[0].transaction.serialize();
/// }
/// # Ok::<(), outscript::monero::Error>(())
/// ```
///
/// # Caveats
///
/// The reference wallet marks its multisig experimental, and this follows
/// it key for key and byte for byte. It was checked against version
/// 0.18.5.4 of the reference wallet on a regtest chain, for accounts of 2
/// of 2, 2 of 3, 3 of 3, 2 of 4 and 3 of 4 participants: key exchange,
/// info exchange, and transactions proposed or co-signed here and
/// accepted by the daemon. In particular a participant is trusted
/// in what it reports of its own share of a key image: nothing proves it.
///
/// Secret keys are wiped when the value is dropped.
#[derive(Clone)]
pub struct MultisigAccount {
    threshold: usize,
    signers: Vec<[u8; 32]>,
    base_secret: Zeroizing<[u8; 32]>,
    multisig_secrets: Vec<Zeroizing<[u8; 32]>>,
    view: ViewKeys,
}

impl core::fmt::Debug for MultisigAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MultisigAccount")
            .field("threshold", &self.threshold)
            .field("signers", &self.signers)
            .field("spend_public", self.view.spend_public())
            .finish_non_exhaustive()
    }
}

impl MultisigAccount {
    /// Puts back together an account from its parts, as a wallet stores
    /// them: the threshold, the public keys of all the signers
    /// ([`signers`](Self::signers)), this participant's base secret key
    /// ([`base_secret`](Self::base_secret)) and shares of the spend key
    /// ([`multisig_secrets`](Self::multisig_secrets)), and the view keys of
    /// the account.
    ///
    /// Fails with [`Error::InvalidMultisig`] if the parts do not fit: a
    /// threshold or a number of signers out of range, a signer that is not
    /// a valid key or appears twice, a base key that is not among the
    /// signers, no share; and with [`Error::CryptoNote`] for a secret that
    /// is not a reduced scalar.
    pub fn from_parts(
        threshold: u32,
        signers: &[[u8; 32]],
        base_secret: &[u8; 32],
        multisig_secrets: &[[u8; 32]],
        view: &ViewKeys,
    ) -> Result<Self, Error> {
        let threshold = threshold as usize;
        let mut signers = signers.to_vec();
        signers.sort_unstable();
        if signers.len() < 2
            || signers.len() > MULTISIG_MAX_SIGNERS
            || threshold == 0
            || threshold > signers.len()
            || signers.windows(2).any(|pair| pair[0] == pair[1])
            || multisig_secrets.is_empty()
        {
            return Err(Error::InvalidMultisig);
        }
        for signer in &signers {
            check_public_key(signer)?;
        }
        if !signers.contains(&secret_key_to_public_key(base_secret)?) {
            return Err(Error::InvalidMultisig);
        }
        for secret in multisig_secrets {
            scalar_from_bytes(secret)?;
        }
        Ok(MultisigAccount {
            threshold,
            signers,
            base_secret: Zeroizing::new(*base_secret),
            multisig_secrets: multisig_secrets
                .iter()
                .map(|secret| Zeroizing::new(*secret))
                .collect(),
            view: view.clone(),
        })
    }

    /// The number of participants it takes to sign (M).
    pub fn threshold(&self) -> u32 {
        self.threshold as u32
    }

    /// The public keys that identify the participants (N of them), sorted.
    pub fn signers(&self) -> &[[u8; 32]] {
        &self.signers
    }

    /// The public key that identifies this participant among the signers.
    pub fn signer_public(&self) -> [u8; 32] {
        // The base secret was checked when the account was made.
        secret_key_to_public_key(&self.base_secret).unwrap_or([0u8; 32])
    }

    /// This participant's base secret key: what it signs the messages of
    /// the key exchange with. The reference wallet keeps it as the "spend
    /// key" of the multisig wallet.
    pub fn base_secret(&self) -> &[u8; 32] {
        &self.base_secret
    }

    /// This participant's shares of the spend key.
    pub fn multisig_secrets(&self) -> impl ExactSizeIterator<Item = &[u8; 32]> {
        self.multisig_secrets.iter().map(|secret| &**secret)
    }

    /// The view keys of the account, which every participant has: for
    /// addresses, subaddresses and scanning.
    pub fn view_keys(&self) -> &ViewKeys {
        &self.view
    }

    /// The address of the account on `network`.
    pub fn address(&self, network: Network) -> Address {
        self.view.address(network)
    }
}

// --- multisig info: partial key images and nonces ---

/// The number of nonces a signer puts in each signature (`kAlphaComponents`):
/// two, combined with a factor nobody controls, which is what makes it safe
/// to publish them before the transaction is known.
const ALPHA_COMPONENTS: usize = 2;

/// What a participant tells the others about one output of the account
/// (`multisig_info`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigOutputInfo {
    /// The participant.
    pub signer: [u8; 32],
    /// Public nonces for signatures spending the output: for each, `k * G`
    /// and `k * Hp(P)`, with `P` the output's one-time key.
    pub nonces: Vec<([u8; 32], [u8; 32])>,
    /// The participant's shares of the output's key image, one per share of
    /// the spend key it holds.
    pub partial_key_images: Vec<[u8; 32]>,
}

/// What a participant tells the others about the outputs of the account
/// (`export_multisig_info`, for the others to `import_multisig_info`): its
/// shares of their key images, and the public nonces the next transaction
/// will be signed with.
///
/// The outputs are those of the wallet, from the first one on, in the
/// wallet's order — the order of an [`OutputExport`](super::OutputExport)
/// of the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigInfo {
    /// The public spend key of the account.
    pub spend_public: [u8; 32],
    /// The public view key of the account.
    pub view_public: [u8; 32],
    /// The participant the info is from.
    pub signer: [u8; 32],
    /// The info, output by output.
    pub outputs: Vec<MultisigOutputInfo>,
}

impl MultisigInfo {
    /// Reads a multisig info export — the file `export_multisig_info`
    /// writes, or the `info` of the wallet RPC once decoded. The cipher is
    /// that of the multisig account ([`MultisigAccount::cipher`]).
    ///
    /// Fails with [`Error::InvalidFile`] if it is not one,
    /// [`Error::AuthenticationFailed`] if it was not made with this view
    /// key, and [`Error::InvalidMultisig`] if a nonce or a partial key
    /// image is not a point of the prime-order subgroup, or the outputs are
    /// not all from the signer the file names.
    pub fn from_file(cipher: &WalletCipher, file: &[u8]) -> Result<Self, Error> {
        let data = cipher.open(MULTISIG_INFO_MAGIC, file)?;
        let mut r = Reader { data: &data };
        archive(Self::read(&mut r))
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let spend_public = r.key()?;
        let view_public = r.key()?;
        let signer = r.key()?;
        // An output takes at least 34 bytes.
        let count = r.count(34)?;
        let mut outputs = Vec::with_capacity(count);
        for _ in 0..count {
            let output_signer = r.key()?;
            let count = r.count(64)?;
            let mut nonces = Vec::with_capacity(count);
            for _ in 0..count {
                nonces.push((r.key()?, r.key()?));
            }
            let partial_key_images = r.key_vec()?;
            if output_signer != signer {
                return Err(Error::InvalidMultisig);
            }
            for (l, r) in &nonces {
                check_subgroup(l)?;
                check_subgroup(r)?;
            }
            for image in &partial_key_images {
                check_subgroup(image)?;
            }
            outputs.push(MultisigOutputInfo {
                signer: output_signer,
                nonces,
                partial_key_images,
            });
        }
        if !r.data.is_empty() {
            return Err(Error::TrailingData);
        }
        Ok(MultisigInfo {
            spend_public,
            view_public,
            signer,
            outputs,
        })
    }

    /// Writes the multisig info export. `rng` is as for
    /// [`WalletCipher::encrypt`].
    pub fn to_file(
        &self,
        cipher: &WalletCipher,
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.spend_public);
        data.extend_from_slice(&self.view_public);
        data.extend_from_slice(&self.signer);
        push_varint(&mut data, self.outputs.len() as u64);
        for output in &self.outputs {
            data.extend_from_slice(&output.signer);
            push_varint(&mut data, output.nonces.len() as u64);
            for (l, r) in &output.nonces {
                data.extend_from_slice(l);
                data.extend_from_slice(r);
            }
            put_keys(&mut data, &output.partial_key_images);
        }
        cipher.seal(MULTISIG_INFO_MAGIC, &data, rng)
    }
}

/// A point of the prime-order subgroup (the identity included, as
/// `rct::isInMainSubgroup` has it).
fn check_subgroup(key: &[u8; 32]) -> Result<EdwardsPoint, Error> {
    let point = point_from_bytes(key).map_err(|_| Error::InvalidMultisig)?;
    if !bool::from(point.is_torsion_free()) {
        return Err(Error::InvalidMultisig);
    }
    Ok(point)
}

/// The secret nonces behind the public ones of a [`MultisigInfo`]: what
/// this participant will sign the next transaction with.
///
/// **A nonce signs once.** Signing with the same nonce twice gives this
/// participant's shares of the spend key away. So:
///
/// - these must be stored as carefully as the keys, and only until they are
///   used;
/// - [`MultisigAccount::sign`] takes the nonces it uses out of the value it
///   is given; what is left must be stored again **before** the signed set
///   leaves, and a copy from before signing must never be used again;
/// - exporting the info again makes new nonces, and the old ones are to be
///   dropped: the others will have the new public ones.
///
/// The nonces are wiped when the value is dropped.
#[derive(Clone)]
pub struct MultisigNonces {
    /// For each output of the wallet, its unused nonces.
    outputs: Vec<Vec<Zeroizing<[u8; 32]>>>,
}

impl core::fmt::Debug for MultisigNonces {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MultisigNonces")
            .field("outputs", &self.outputs.len())
            .finish_non_exhaustive()
    }
}

impl MultisigNonces {
    /// The nonces as bytes, for the wallet to store (a format of this
    /// crate's own: for each output, the count of its nonces and the
    /// nonces). They are secret.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::new());
        push_varint(&mut out, self.outputs.len() as u64);
        for nonces in &self.outputs {
            push_varint(&mut out, nonces.len() as u64);
            for nonce in nonces {
                out.extend_from_slice(&**nonce);
            }
        }
        out
    }

    /// The nonces from the bytes [`to_bytes`](Self::to_bytes) gave.
    ///
    /// Fails with [`Error::InvalidMultisig`] for anything else.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        let mut r = Reader { data };
        let mut read = || -> Result<Self, Error> {
            let count = r.count(1)?;
            let mut outputs = Vec::with_capacity(count);
            for _ in 0..count {
                let count = r.count(32)?;
                let mut nonces = Vec::with_capacity(count);
                for _ in 0..count {
                    let nonce = Zeroizing::new(r.key()?);
                    scalar_from_bytes(&nonce)?;
                    nonces.push(nonce);
                }
                outputs.push(nonces);
            }
            if !r.data.is_empty() {
                return Err(Error::TrailingData);
            }
            Ok(MultisigNonces { outputs })
        };
        read().map_err(|_| Error::InvalidMultisig)
    }

    /// Takes the nonce of output `index` whose public part `k * G` is among
    /// `used_l`, so that it cannot be used again (`get_multisig_k`).
    fn take(&mut self, index: usize, used_l: &[[u8; 32]]) -> Result<Scalar, Error> {
        let nonces = self
            .outputs
            .get_mut(index)
            .ok_or(Error::MultisigInfoNeeded)?;
        for at in 0..nonces.len() {
            let k = scalar_from_bytes(&nonces[at])?;
            if used_l.contains(&EdwardsPoint::mul_base(&k).compress()) {
                // Dropping it wipes it.
                nonces.remove(at);
                return Ok(k);
            }
        }
        Err(Error::MultisigInfoNeeded)
    }
}

/// The combinations of `k` of the `items`.
fn combinations(items: &[[u8; 32]], k: usize) -> Vec<Vec<[u8; 32]>> {
    fn go(
        items: &[[u8; 32]],
        k: usize,
        from: usize,
        current: &mut Vec<[u8; 32]>,
        out: &mut Vec<Vec<[u8; 32]>>,
    ) {
        if current.len() == k {
            out.push(current.clone());
            return;
        }
        for i in from..items.len() {
            current.push(items[i]);
            go(items, k, i + 1, current, out);
            current.pop();
        }
    }
    let mut out = Vec::new();
    go(items, k, 0, &mut Vec::new(), &mut out);
    out
}

/// The transaction secret keys of a multisig transaction, which every
/// signer derives from the entropy the proposer chose and the key images
/// of the inputs (`make_tx_secret_key_seed`, `make_tx_secret_keys`).
fn tx_secret_keys(
    entropy: &[u8; 32],
    key_images: &[[u8; 32]],
    count: usize,
) -> Vec<Zeroizing<[u8; 32]>> {
    let mut h = Hasher::new();
    h.update(&cn_fast_hash(b"multisig_tx_privkeys_seed"));
    h.update(entropy);
    for key_image in key_images {
        h.update(key_image);
    }
    let seed = Zeroizing::new(h.finalize());
    let mut chain = Zeroizing::new(cn_fast_hash(b"multisig_tx_privkeys"));
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        let mut h = Hasher::new();
        h.update(&*seed);
        h.update(&*chain);
        *chain = h.finalize_scalar();
        keys.push(chain.clone());
    }
    keys
}

/// The key image a source carries (`multisig_kLRki.ki`).
fn source_key_image(source: &TxSource) -> [u8; 32] {
    let mut key_image = [0u8; 32];
    key_image.copy_from_slice(&source.multisig_klrki[96..]);
    key_image
}

/// What every signer of a multisig transaction derives from its
/// construction data: the transaction without its ring signatures.
struct Skeleton {
    /// The sources, in the order of the inputs.
    sources: Vec<TxSource>,
    prefix: TransactionPrefix,
    ecdh_info: Vec<EcdhInfo>,
    out_pk: Vec<[u8; 32]>,
    out_masks: Vec<Zeroizing<[u8; 32]>>,
    out_amounts: Vec<u64>,
    fee: u64,
    tx_secret_key: Zeroizing<[u8; 32]>,
    additional_secret_keys: Vec<Zeroizing<[u8; 32]>>,
}

impl MultisigAccount {
    /// The encryption of the files the participants exchange: that of the
    /// account's view key, which they all have.
    ///
    /// It takes one [`cn_slow_hash`](super::cn_slow_hash): make it once.
    pub fn cipher(&self) -> Result<WalletCipher, Error> {
        WalletCipher::new(self.view.view_secret())
    }

    /// The sum of this participant's shares of the spend key.
    fn share_sum(&self) -> Result<Scalar, Error> {
        let mut sum = Scalar::ZERO;
        for secret in &self.multisig_secrets {
            sum = sum.add(&scalar_from_bytes(secret)?);
        }
        Ok(sum)
    }

    /// This participant's share of the one-time secret key of `output`:
    /// the part every participant can compute (from the view key), plus its
    /// shares of the spend key (`generate_key_image_helper` for a multisig
    /// account).
    ///
    /// Fails with [`Error::KeyMismatch`] if the output is not the
    /// account's, or not as described.
    fn secret_share(&self, output: &ExportedOutput) -> Result<Scalar, Error> {
        let index = output.internal_output_index;
        let additional = usize::try_from(index)
            .ok()
            .and_then(|index| output.additional_tx_keys.get(index));
        let expected = self.view.subaddress_spend_public(output.subaddress);
        for tx_key in core::iter::once(&output.tx_public_key).chain(additional) {
            let Ok(derivation) = self.view.key_derivation(tx_key) else {
                continue;
            };
            if derive_subaddress_public_key(&output.public_key, &derivation, index)? != expected {
                continue;
            }
            let shared = Zeroizing::new(derivation_to_scalar(&derivation, index));
            let mut secret = scalar_from_bytes(&shared)?.add(&self.share_sum()?);
            if !output.subaddress.is_main() {
                let m = subaddress_secret_key(self.view.view_secret(), output.subaddress);
                secret = secret.add(&scalar_from_bytes(&m)?);
            }
            return Ok(secret);
        }
        Err(Error::KeyMismatch)
    }

    /// What to tell the other participants about `outputs` — the outputs of
    /// the wallet from the first one on, in the wallet's order — and the
    /// secret nonces to keep (`export_multisig_info`).
    ///
    /// Every export makes new nonces for every output: the ones kept from
    /// an earlier export are to be dropped, since the others will only
    /// have the new public ones.
    ///
    /// `rng` fills its argument with cryptographically secure random
    /// bytes: the nonces come from it. A predictable or repeating source
    /// gives this participant's shares of the spend key away with the first
    /// signature. Fails with [`Error::BadRandomness`] if it yields only
    /// zeros, and [`Error::CryptoNote`] if an output key is not a curve
    /// point.
    pub fn export_info(
        &self,
        outputs: &[ExportedOutput],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(MultisigInfo, MultisigNonces), Error> {
        let signer = self.signer_public();
        let signers = self.signers.len();
        let count = n_choose_k(signers - 1, signers - self.threshold) * ALPHA_COMPONENTS;
        let mut info = Vec::with_capacity(outputs.len());
        let mut secret = Vec::with_capacity(outputs.len());
        for output in outputs {
            let hashed = point_from_hash(&output.public_key);
            point_from_bytes(&output.public_key)?;
            let mut partial_key_images = Vec::with_capacity(self.multisig_secrets.len());
            for share in &self.multisig_secrets {
                partial_key_images.push(hashed.mul(&scalar_from_bytes(share)?).compress());
            }
            let mut nonces = Vec::with_capacity(count);
            let mut kept = Vec::with_capacity(count);
            for _ in 0..count {
                let k = random_scalar(rng)?;
                nonces.push((
                    EdwardsPoint::mul_base(&k).compress(),
                    hashed.mul(&k).compress(),
                ));
                kept.push(Zeroizing::new(k.to_bytes()));
            }
            info.push(MultisigOutputInfo {
                signer,
                nonces,
                partial_key_images,
            });
            secret.push(kept);
        }
        Ok((
            MultisigInfo {
                spend_public: *self.view.spend_public(),
                view_public: self.view.view_public(),
                signer,
                outputs: info,
            },
            MultisigNonces { outputs: secret },
        ))
    }

    /// The key image of `output`, from this participant's share and those
    /// the others gave for it (`others`: the entry for this output of each
    /// other participant's [`MultisigInfo`]).
    ///
    /// Every share of the spend key must be held by this participant or by
    /// one of those whose info is given: the info of all the others always
    /// does, and that of any `threshold - 1` of them is enough. With too
    /// few, or with a participant that lies about its share — nothing
    /// proves a share — the result is not the key image, and a transaction
    /// made with it is not valid.
    ///
    /// Fails with [`Error::KeyMismatch`] if the output is not the
    /// account's.
    pub fn key_image(
        &self,
        output: &ExportedOutput,
        others: &[&MultisigOutputInfo],
    ) -> Result<[u8; 32], Error> {
        let hashed = point_from_hash(&output.public_key);
        let mut image = hashed.mul(&self.secret_share(output)?);
        // The shares already counted: this participant's own, then each
        // one added.
        let mut used = KeySet::new();
        for share in &self.multisig_secrets {
            used.insert(hashed.mul(&scalar_from_bytes(share)?).compress());
        }
        for info in others {
            for partial in &info.partial_key_images {
                if used.insert(*partial) {
                    image = image.add(&check_subgroup(partial)?);
                }
            }
        }
        Ok(image.compress())
    }

    /// Checks the change of a transaction and prepares the builder its
    /// outputs are made with.
    fn output_builder(&self, data: &TxConstructionData) -> Result<TransactionBuilder, Error> {
        if data.unlock_time != 0
            || !data.use_rct
            || !data.use_view_tags
            || data.range_proof_type != 3
            || data.bp_version != 4
        {
            return Err(Error::Unsupported);
        }
        let network = Network::Mainnet;
        let own = self
            .view
            .subaddress(network, SubaddressIndex::new(data.subaddress_account, 0));
        let pays_change = data
            .splitted_destinations
            .iter()
            .any(|destination| destination.amount > 0 && destination.same_address(&data.change));
        if data.change.amount > 0 || pays_change {
            if data.change.spend_public != own.spend_public
                || data.change.view_public != own.view_public
            {
                return Err(Error::InvalidAddress);
            }
            if data.change.amount > 0 && !pays_change {
                return Err(Error::InvalidAmounts);
            }
        }
        let mut builder = TransactionBuilder::new();
        builder.change_among_destinations(data.change.address(network), self.view.view_secret());
        if let Some(id) = data.payment_id()? {
            builder.payment_id(id);
        }
        Ok(builder)
    }

    /// The transaction a multisig transaction's construction data stands
    /// for, without its proofs and signatures: `sources` with their key
    /// images, in the order of the inputs, and the destinations in the
    /// order of the outputs (`tx_builder_ringct_t::init`).
    fn skeleton(
        &self,
        data: &TxConstructionData,
        sources: Vec<TxSource>,
        destinations: &[TxDestination],
        entropy: &[u8; 32],
    ) -> Result<Skeleton, Error> {
        if sources.is_empty() || *entropy == [0u8; 32] {
            return Err(Error::InvalidMultisig);
        }
        let builder = self.output_builder(data)?;
        let mut total_in = 0u64;
        let mut inputs = Vec::with_capacity(sources.len());
        let mut key_images = Vec::with_capacity(sources.len());
        for source in &sources {
            total_in = total_in
                .checked_add(source.amount)
                .ok_or(Error::InvalidAmounts)?;
            let indices: Vec<u64> = source.outputs.iter().map(|(index, _)| *index).collect();
            let key_image = source_key_image(source);
            // The amount and the mask the source claims open the commitment
            // of the output it spends.
            let mask = scalar_from_bytes(&source.mask)?;
            if commit_point(&scalar_from_u64(source.amount), &mask).compress()
                != source.real()?.commitment
            {
                return Err(Error::CommitmentMismatch);
            }
            inputs.push(Input::ToKey {
                amount: 0,
                key_offsets: relative_offsets(&indices)?,
                key_image,
            });
            key_images.push(key_image);
        }
        if key_images.windows(2).any(|pair| pair[0] <= pair[1]) {
            return Err(Error::InvalidRing);
        }
        let mut fee = total_in;
        let mut payments = Vec::with_capacity(destinations.len());
        for destination in destinations {
            fee = fee
                .checked_sub(destination.amount)
                .ok_or(Error::InvalidAmounts)?;
            payments.push(Payment {
                address: destination.address(Network::Mainnet),
                amount: destination.amount,
                is_change: false,
            });
        }
        if payments.len() < 2 || payments.len() > BULLETPROOF_PLUS_MAX_OUTPUTS {
            return Err(Error::InvalidAmounts);
        }
        let need_additional = builder.recipients(&payments).1;
        let count = 1 + if need_additional { payments.len() } else { 0 };
        let mut keys = tx_secret_keys(entropy, &key_images, count);
        let additional_secret_keys = keys.split_off(1);
        let tx_secret_key = keys.pop().ok_or(Error::InvalidMultisig)?;
        let made = builder.make_outputs(&payments, &tx_secret_key, &additional_secret_keys)?;
        // No two outputs may have the same key.
        for (i, output) in made.outputs.iter().enumerate() {
            if made
                .outputs
                .iter()
                .take(i)
                .any(|other| other.key == output.key)
            {
                return Err(Error::InvalidTransaction);
            }
        }
        Ok(Skeleton {
            sources,
            prefix: TransactionPrefix {
                version: 2,
                unlock_time: 0,
                inputs,
                outputs: made.outputs,
                extra: made.extra,
            },
            ecdh_info: made.ecdh_info,
            out_pk: made.out_pk,
            out_masks: made.out_masks,
            out_amounts: made.out_amounts,
            fee,
            tx_secret_key,
            additional_secret_keys,
        })
    }

    /// Proposes a multisig transaction and signs it first: what `transfer`
    /// does in a multisig wallet of the reference. The set returned goes to
    /// the other signers in turn ([`sign`](Self::sign), `sign_multisig`).
    ///
    /// - `data` says what to build: the outputs to spend with their rings,
    ///   the destinations, the change. It has the form a view-only wallet
    ///   of the account prepares ([`UnsignedTxSet`](super::UnsignedTxSet)),
    ///   whose `selected_transfers` say which outputs of the wallet the
    ///   sources are, in the same order.
    /// - `outputs` are the outputs of the wallet from the first one on, in
    ///   the wallet's order.
    /// - `infos` are the latest [`MultisigInfo`] of the other participants
    ///   that may sign, at least `threshold - 1` of them. With more, the
    ///   set carries one signing attempt per group of signers that can
    ///   complete it.
    ///
    /// The nonces this participant signs with are made here and not kept.
    /// The public nonces of the others are used up: before proposing
    /// again, the participants must exchange their info anew.
    ///
    /// `rng` fills its argument with cryptographically secure random
    /// bytes; it is as critical as for
    /// [`TransactionBuilder::build`](super::TransactionBuilder::build).
    ///
    /// Fails with:
    /// - [`Error::Unsupported`] for data that asks for another transaction
    ///   format, a non-zero unlock time, or an extra field with anything
    ///   but an 8-byte payment id;
    /// - [`Error::MultisigInfoNeeded`] if there is not the info of enough
    ///   other signers, or it lacks an output or unused nonces;
    /// - [`Error::InvalidMultisig`] for info that is not from another
    ///   participant of this account;
    /// - [`Error::MissingOutputs`] if a source is not among `outputs` where
    ///   `selected_transfers` says;
    /// - [`Error::InvalidAddress`] if the change does not go to the first
    ///   address of the account the transaction spends from;
    /// - [`Error::KeyMismatch`] or [`Error::CommitmentMismatch`] if an
    ///   output is not the account's or its amount and mask do not open its
    ///   commitment;
    /// - and as [`TransactionBuilder::build`](super::TransactionBuilder::build)
    ///   does.
    pub fn propose(
        &self,
        data: &TxConstructionData,
        outputs: &[ExportedOutput],
        infos: &[MultisigInfo],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<MultisigTxSet, Error> {
        let local = self.signer_public();
        // The other signers that can take part.
        let mut others: Vec<&MultisigInfo> = Vec::new();
        for info in infos {
            if info.spend_public != *self.view.spend_public()
                || info.view_public != self.view.view_public()
                || info.signer == local
                || !self.signers.contains(&info.signer)
                || others.iter().any(|other| other.signer == info.signer)
            {
                return Err(Error::InvalidMultisig);
            }
            others.push(info);
        }
        others.sort_unstable_by_key(|info| info.signer);
        if others.len() + 1 < self.threshold {
            return Err(Error::MultisigInfoNeeded);
        }
        if data.sources.len() != data.selected_transfers.len() {
            return Err(Error::MissingOutputs);
        }

        // The sources, each with its place in the wallet, its key image and
        // this participant's share of its secret key.
        struct Spent {
            source: TxSource,
            transfer: u64,
            index: usize,
            key_image: [u8; 32],
            secret: Scalar,
        }
        let mut spent = Vec::with_capacity(data.sources.len());
        for (source, transfer) in data.sources.iter().zip(&data.selected_transfers) {
            let index = usize::try_from(*transfer).map_err(|_| Error::MissingOutputs)?;
            let output = outputs.get(index).ok_or(Error::MissingOutputs)?;
            let real = source.real()?;
            if output.public_key != real.key {
                return Err(Error::MissingOutputs);
            }
            let secret = self.secret_share(output)?;
            let mut shares = Vec::with_capacity(others.len());
            for info in &others {
                shares.push(info.outputs.get(index).ok_or(Error::MultisigInfoNeeded)?);
            }
            let key_image = self.key_image(output, &shares)?;
            let mut source = source.clone();
            source.multisig_klrki = [0u8; 128];
            source.multisig_klrki[96..].copy_from_slice(&key_image);
            spent.push(Spent {
                source,
                transfer: *transfer,
                index,
                key_image,
                secret,
            });
        }
        let original_sources: Vec<TxSource> =
            spent.iter().map(|spent| spent.source.clone()).collect();
        spent.sort_by_key(|spent| core::cmp::Reverse(spent.key_image));

        // The destinations, shuffled.
        let mut destinations = data.splitted_destinations.clone();
        for i in (1..destinations.len()).rev() {
            let mut bytes = [0u8; 8];
            rng(&mut bytes);
            destinations.swap(i, (u64::from_le_bytes(bytes) % (i as u64 + 1)) as usize);
        }
        let entropy = random_secret(rng)?;
        let skeleton = self.skeleton(
            data,
            spent.iter().map(|spent| spent.source.clone()).collect(),
            &destinations,
            &entropy,
        )?;

        // The pseudo-outputs: the last mask makes the sums equal.
        let mut out_mask_sum = Scalar::ZERO;
        for mask in &skeleton.out_masks {
            out_mask_sum = out_mask_sum.add(&scalar_from_bytes(mask)?);
        }
        let mut pseudo_masks: Vec<Scalar> = Vec::with_capacity(spent.len());
        let mut pseudo_mask_sum = Scalar::ZERO;
        for i in 0..spent.len() {
            let mask = if i + 1 == spent.len() {
                out_mask_sum.sub(&pseudo_mask_sum)
            } else {
                random_scalar(rng)?
            };
            pseudo_mask_sum = pseudo_mask_sum.add(&mask);
            pseudo_masks.push(mask);
        }
        let pseudo_outs: Vec<[u8; 32]> = spent
            .iter()
            .zip(&pseudo_masks)
            .map(|(spent, mask)| {
                commit_point(&scalar_from_u64(spent.source.amount), mask).compress()
            })
            .collect();
        let masks: Zeroizing<Vec<[u8; 32]>> =
            Zeroizing::new(skeleton.out_masks.iter().map(|mask| **mask).collect());
        let proof = BulletproofPlus::prove(&skeleton.out_amounts, &masks, rng)?;

        // The ring signatures, with decoy responses and the place of the
        // real one left empty.
        let mut clsags = Vec::with_capacity(spent.len());
        let mut mask_differences = Vec::with_capacity(spent.len());
        for (spent, pseudo_mask) in spent.iter().zip(&pseudo_masks) {
            let real = spent.source.real()?;
            let z = scalar_from_bytes(&spent.source.mask)?.sub(pseudo_mask);
            let d = point_from_hash(&real.key).mul(&z).mul(&inv_eight());
            let real_index =
                usize::try_from(spent.source.real_output).map_err(|_| Error::InvalidRing)?;
            let mut s = Vec::with_capacity(spent.source.outputs.len());
            for j in 0..spent.source.outputs.len() {
                s.push(if j == real_index {
                    [0u8; 32]
                } else {
                    random_scalar(rng)?.to_bytes()
                });
            }
            clsags.push(Clsag {
                s,
                c1: [0u8; 32],
                d: d.compress(),
            });
            mask_differences.push(z);
        }
        let mut transaction = Transaction {
            prefix: skeleton.prefix,
            signatures: Vec::new(),
            rct: RctSignatures {
                rct_type: RCT_TYPE_BULLETPROOF_PLUS,
                fee: skeleton.fee,
                ecdh_info: skeleton.ecdh_info,
                out_pk: skeleton.out_pk,
                pseudo_outs,
                bulletproofs_plus: vec![proof],
                clsags,
                ..Default::default()
            },
        };
        let message = transaction.signature_hash();

        // One attempt per group of signers that can complete the
        // signature: this participant and `threshold - 1` of the others.
        let other_signers: Vec<[u8; 32]> = others.iter().map(|info| info.signer).collect();
        let ignore_sets = if others.len() + 1 > self.threshold {
            combinations(&other_signers, others.len() + 1 - self.threshold)
        } else {
            vec![Vec::new()]
        };
        let mut signing_keys = Vec::with_capacity(self.multisig_secrets.len());
        for share in &self.multisig_secrets {
            signing_keys.push(secret_key_to_public_key(share)?);
        }
        let mut all_used_l = KeySet::new();
        let mut multisig_signatures = Vec::with_capacity(ignore_sets.len());
        for ignore in ignore_sets {
            let mut signature = MultisigSignature {
                ignore,
                signing_keys: signing_keys.clone(),
                ..Default::default()
            };
            for (i, spent) in spent.iter().enumerate() {
                let real = spent.source.real()?;
                let hashed = point_from_hash(&real.key);
                let ring: Vec<RingMember> = spent
                    .source
                    .outputs
                    .iter()
                    .map(|(_, member)| *member)
                    .collect();
                let mut alpha = Vec::with_capacity(ALPHA_COMPONENTS);
                let mut alpha_g = Vec::with_capacity(ALPHA_COMPONENTS);
                let mut alpha_h = Vec::with_capacity(ALPHA_COMPONENTS);
                for _ in 0..ALPHA_COMPONENTS {
                    // This participant's nonce, and one of each other
                    // signer of the group (`get_multisig_composite_kLRki`).
                    let k = random_scalar(rng)?;
                    let mut l = EdwardsPoint::mul_base(&k);
                    let mut r = hashed.mul(&k);
                    for info in &others {
                        if signature.ignore.contains(&info.signer) {
                            continue;
                        }
                        let output = info
                            .outputs
                            .get(spent.index)
                            .ok_or(Error::MultisigInfoNeeded)?;
                        let (nonce_l, nonce_r) = output
                            .nonces
                            .iter()
                            .find(|(nonce_l, _)| !all_used_l.contains(nonce_l))
                            .ok_or(Error::MultisigInfoNeeded)?;
                        all_used_l.insert(*nonce_l);
                        signature.used_l.push(*nonce_l);
                        l = l.add(&check_subgroup(nonce_l)?);
                        r = r.add(&check_subgroup(nonce_r)?);
                    }
                    alpha.push(k);
                    alpha_g.push(l.compress());
                    alpha_h.push(r.compress());
                }
                let clsag = transaction.rct.clsags.get(i).ok_or(Error::InvalidRing)?;
                let pseudo_out = transaction
                    .rct
                    .pseudo_outs
                    .get(i)
                    .ok_or(Error::InvalidRing)?;
                let real_index =
                    usize::try_from(spent.source.real_output).map_err(|_| Error::InvalidRing)?;
                let challenge = multisig_challenge(
                    &message,
                    &ring,
                    real_index,
                    &spent.key_image,
                    &clsag.d,
                    pseudo_out,
                    &clsag.s,
                    &alpha_g,
                    &alpha_h,
                )?;
                let mut combined = Scalar::ZERO;
                let mut power = Scalar::ONE;
                for k in &alpha {
                    combined = combined.add(&k.mul(&power));
                    power = power.mul(&challenge.b);
                }
                // s = alpha - c * (mu_P * x + mu_C * z)
                let z = mask_differences.get(i).ok_or(Error::InvalidRing)?;
                let w = challenge
                    .mu_p
                    .mul(&spent.secret)
                    .add(&challenge.mu_c.mul(z));
                signature
                    .s
                    .push(combined.sub(&challenge.c.mul(&w)).to_bytes());
                signature.c_0.push(challenge.c1.to_bytes());
                signature.total_alpha_g.push(alpha_g);
                signature.total_alpha_h.push(alpha_h);
            }
            multisig_signatures.push(signature);
        }
        if self.threshold <= 1 {
            let signature = multisig_signatures.first().ok_or(Error::InvalidMultisig)?;
            finalize(&mut transaction, &skeleton.sources, signature)?;
        }

        // What the set records, as the reference wallet does: the sources
        // as they were given, the destinations in the order of the outputs,
        // the extra field with the payment id in the clear.
        let mut extra = transaction.prefix.extra.clone();
        if matches!(payment_id(&extra), Some(PaymentId::Encrypted(_))) {
            let clear = data.payment_id()?.unwrap_or([0u8; 8]);
            let at = extra.len().saturating_sub(8);
            if let Some(tail) = extra.get_mut(at..) {
                tail.copy_from_slice(&clear);
            }
        }
        let selected_transfers: Vec<u64> = spent.iter().map(|spent| spent.transfer).collect();
        let mut construction_data = data.clone();
        construction_data.sources = original_sources;
        construction_data.splitted_destinations = destinations;
        construction_data.selected_transfers = selected_transfers.clone();
        construction_data.extra = extra;
        let mut key_images = String::new();
        for spent in &spent {
            key_images.push('<');
            key_images.push_str(&hex::encode(spent.key_image));
            key_images.push_str("> ");
        }
        Ok(MultisigTxSet {
            transactions: vec![PendingTx {
                transaction,
                dust: 0,
                fee: skeleton.fee,
                dust_added_to_fee: false,
                change: data.change.clone(),
                selected_transfers,
                key_images,
                tx_secret_key: skeleton.tx_secret_key,
                additional_tx_secret_keys: skeleton.additional_secret_keys,
                destinations: data.destinations.clone(),
                construction_data,
                multisig_signatures,
                multisig_tx_key_entropy: *entropy,
            }],
            signers: vec![local],
        })
    }

    /// Adds this participant's signature to a multisig transaction set
    /// another participant proposed or signed (`sign_multisig`). The set
    /// returned goes to the next signer, or, once
    /// [`threshold`](Self::threshold) participants have signed, its
    /// transactions are complete and can be sent
    /// ([`MultisigTxSet::is_complete`]).
    ///
    /// - `outputs` are the outputs of the wallet from the first one on, in
    ///   the wallet's order: the set says which of them it spends.
    /// - `nonces` are the secret nonces of this participant's latest
    ///   [`export_info`](Self::export_info), whose public part the proposer
    ///   had. Those used are taken out of it — on failure too. **Store what
    ///   is left before letting the signed set out**, and never sign with a
    ///   copy from before: see [`MultisigNonces`].
    ///
    /// Every transaction of the set is rebuilt from what the set says it
    /// was made of — the sources, the destinations, the change — and must
    /// come out the same: what is signed is what the construction data
    /// shows ([`PendingTx::construction_data`](super::PendingTx)). **Check
    /// the destinations, the amounts and the fee before signing.** The
    /// change is required to go back to the account. When this signature
    /// completes a transaction, the whole of it is verified.
    ///
    /// Fails with:
    /// - [`Error::InvalidMultisig`] if this participant has signed already,
    ///   the set is complete, a transaction is not what its construction
    ///   data says, its proofs or (once complete) its signatures do not
    ///   verify, or the signing attempts are malformed;
    /// - [`Error::MultisigInfoNeeded`] if the nonces a signing attempt
    ///   calls for are not in `nonces`: the proposer did not have this
    ///   participant's latest info;
    /// - [`Error::MissingOutputs`] if an output spent is not among
    ///   `outputs` where the set says;
    /// - [`Error::Unsupported`] and [`Error::InvalidAddress`] as
    ///   [`propose`](Self::propose) does.
    pub fn sign(
        &self,
        set: &MultisigTxSet,
        outputs: &[ExportedOutput],
        nonces: &mut MultisigNonces,
    ) -> Result<MultisigTxSet, Error> {
        let local = self.signer_public();
        if set.transactions.is_empty()
            || set.signers.contains(&local)
            || set.signers.len() >= self.threshold
            || set
                .signers
                .iter()
                .any(|signer| !self.signers.contains(signer))
        {
            return Err(Error::InvalidMultisig);
        }
        let is_last = set.signers.len() + 1 >= self.threshold;
        let mut signed = set.clone();
        for pending in &mut signed.transactions {
            let data = &pending.construction_data;
            if pending.multisig_signatures.is_empty() {
                return Err(Error::InvalidMultisig);
            }
            // The transaction, rebuilt.
            let mut sources = data.sources.clone();
            sources.sort_by_key(|source| core::cmp::Reverse(source_key_image(source)));
            let skeleton = self.skeleton(
                data,
                sources,
                &data.splitted_destinations,
                &pending.multisig_tx_key_entropy,
            )?;
            let tx = &pending.transaction;
            let inputs = skeleton.sources.len();
            let same_keys = *skeleton.tx_secret_key == *pending.tx_secret_key
                && skeleton.additional_secret_keys.len() == pending.additional_tx_secret_keys.len()
                && skeleton
                    .additional_secret_keys
                    .iter()
                    .zip(&pending.additional_tx_secret_keys)
                    .all(|(a, b)| **a == **b);
            if !same_keys
                || tx.prefix != skeleton.prefix
                || tx.rct.rct_type != RCT_TYPE_BULLETPROOF_PLUS
                || tx.rct.fee != skeleton.fee
                || pending.fee != skeleton.fee
                || tx.rct.ecdh_info != skeleton.ecdh_info
                || tx.rct.out_pk != skeleton.out_pk
                || tx.rct.pseudo_outs.len() != inputs
                || tx.rct.clsags.len() != inputs
                || data.selected_transfers.len() != inputs
                || !tx.verify_balance()?
                || !tx.verify_range_proof()?
            {
                return Err(Error::InvalidMultisig);
            }
            // The outputs spent are those of the wallet the set names.
            let mut transfers = Vec::with_capacity(inputs);
            for (source, transfer) in skeleton.sources.iter().zip(&data.selected_transfers) {
                let index = usize::try_from(*transfer).map_err(|_| Error::MissingOutputs)?;
                let output = outputs.get(index).ok_or(Error::MissingOutputs)?;
                if output.public_key != source.real()?.key {
                    return Err(Error::MissingOutputs);
                }
                transfers.push(index);
            }
            let message = tx.signature_hash();
            let rings: Vec<Vec<RingMember>> = skeleton
                .sources
                .iter()
                .map(|source| source.outputs.iter().map(|(_, member)| *member).collect())
                .collect();

            for signature in &mut pending.multisig_signatures {
                if signature.ignore.contains(&local) {
                    continue;
                }
                if signature.total_alpha_g.len() != inputs
                    || signature.total_alpha_h.len() != inputs
                    || signature.c_0.len() != inputs
                    || signature.s.len() != inputs
                {
                    return Err(Error::InvalidMultisig);
                }
                // This participant's nonces for the attempt.
                let mut alphas = Vec::with_capacity(inputs);
                for transfer in &transfers {
                    let mut alpha = Vec::with_capacity(ALPHA_COMPONENTS);
                    for _ in 0..ALPHA_COMPONENTS {
                        alpha.push(nonces.take(*transfer, &signature.used_l)?);
                    }
                    alphas.push(alpha);
                }
                // The shares of the spend key nobody has signed with yet.
                let mut secret = Scalar::ZERO;
                for share in &self.multisig_secrets {
                    let public = secret_key_to_public_key(share)?;
                    if !signature.signing_keys.contains(&public) {
                        secret = secret.add(&scalar_from_bytes(share)?);
                        signature.signing_keys.push(public);
                    }
                }
                for (i, (source, alpha)) in skeleton.sources.iter().zip(&alphas).enumerate() {
                    let (Some(clsag), Some(pseudo_out), Some(ring)) = (
                        tx.rct.clsags.get(i),
                        tx.rct.pseudo_outs.get(i),
                        rings.get(i),
                    ) else {
                        return Err(Error::InvalidMultisig);
                    };
                    if signature.total_alpha_g[i].len() != ALPHA_COMPONENTS
                        || signature.total_alpha_h[i].len() != ALPHA_COMPONENTS
                        || clsag.s.len() != ring.len()
                    {
                        return Err(Error::InvalidMultisig);
                    }
                    let real_index =
                        usize::try_from(source.real_output).map_err(|_| Error::InvalidRing)?;
                    let challenge = multisig_challenge(
                        &message,
                        ring,
                        real_index,
                        &source_key_image(source),
                        &clsag.d,
                        pseudo_out,
                        &clsag.s,
                        &signature.total_alpha_g[i],
                        &signature.total_alpha_h[i],
                    )
                    .map_err(|_| Error::InvalidMultisig)?;
                    let mut combined = Scalar::ZERO;
                    let mut power = Scalar::ONE;
                    for k in alpha {
                        combined = combined.add(&k.mul(&power));
                        power = power.mul(&challenge.b);
                    }
                    // s += alpha - c * mu_P * x
                    let s = scalar_from_bytes(&signature.s[i])
                        .map_err(|_| Error::InvalidMultisig)?
                        .add(&combined)
                        .sub(&challenge.c.mul(&challenge.mu_p.mul(&secret)));
                    signature.s[i] = s.to_bytes();
                    signature.c_0[i] = challenge.c1.to_bytes();
                }
            }

            if is_last {
                // The one attempt all of whose signers have signed.
                let mut complete = pending.multisig_signatures.iter().filter(|signature| {
                    !signature.ignore.contains(&local)
                        && !signature
                            .ignore
                            .iter()
                            .any(|ignored| set.signers.contains(ignored))
                });
                let (Some(signature), None) = (complete.next(), complete.next()) else {
                    return Err(Error::InvalidMultisig);
                };
                let signature = signature.clone();
                finalize(&mut pending.transaction, &skeleton.sources, &signature)?;
                if !pending.transaction.verify(&rings)? {
                    return Err(Error::InvalidMultisig);
                }
            }
        }
        signed.signers.push(local);
        Ok(signed)
    }
}

/// Puts the responses of a completed signing attempt in the transaction
/// (`tx_builder_ringct_t::finalize_tx`).
fn finalize(
    transaction: &mut Transaction,
    sources: &[TxSource],
    signature: &MultisigSignature,
) -> Result<(), Error> {
    if signature.s.len() != sources.len()
        || signature.c_0.len() != sources.len()
        || transaction.rct.clsags.len() != sources.len()
    {
        return Err(Error::InvalidMultisig);
    }
    for (((clsag, source), s), c_0) in transaction
        .rct
        .clsags
        .iter_mut()
        .zip(sources)
        .zip(&signature.s)
        .zip(&signature.c_0)
    {
        let real_index = usize::try_from(source.real_output).map_err(|_| Error::InvalidRing)?;
        *clsag.s.get_mut(real_index).ok_or(Error::InvalidRing)? = *s;
        clsag.c1 = *c_0;
    }
    Ok(())
}

impl MultisigTxSet {
    /// Whether as many participants as `threshold` have signed: the
    /// transactions are then complete, and their serialization
    /// ([`Transaction::serialize`]) is what a daemon takes.
    pub fn is_complete(&self, threshold: u32) -> bool {
        self.signers.len() >= threshold as usize
    }
}
