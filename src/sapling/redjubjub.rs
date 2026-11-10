//! RedJubjub: the re-randomizable Schnorr signatures of Sapling (protocol
//! specification §5.4.7), in its two instantiations:
//!
//! - `SpendAuthSig`, on the spending key base: a spend is authorized by a
//!   signature of the transaction's signature hash under the randomized key
//!   `rk = ak + [α] G`, made with `rsk = ask + α`;
//! - `BindingSig`, on the value commitment randomness base: the binding
//!   signature proves that the value commitments of a bundle balance, its
//!   key being the sum of their randomness.
//!
//! Signing takes 80 random bytes from the caller; this crate has no random
//! number generator of its own. The nonce is derived from them and from the
//! message, so a repeated random string does not reveal the key as long as
//! the message differs.
//!
//! Many signatures are verified faster together, with a [`BatchVerifier`]:
//! it accepts a batch exactly when [`verify`] accepts each of its
//! signatures (but for a probability of 2⁻¹²⁸ over the verifier's random
//! bytes), which is what the consensus rules since Canopy were designed
//! for.

use super::Error;
use super::field::Fr;
use super::generators::{
    SPENDING_KEY_BASE, VALUE_COMMITMENT_RANDOMNESS_BASE, VALUE_COMMITMENT_VALUE_BASE,
};
use super::jubjub::{AffinePoint, Point};
use super::prf::blake2b;
use purecrypto::zeroize::Zeroize;

/// The two signature schemes of Sapling, which differ in their base point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigType {
    /// `SpendAuthSig`: spend authorization signatures.
    SpendAuth,
    /// `BindingSig`: binding signatures.
    Binding,
}

impl SigType {
    /// The base point `P_G` of the scheme.
    pub const fn base(self) -> AffinePoint {
        match self {
            SigType::SpendAuth => SPENDING_KEY_BASE,
            SigType::Binding => VALUE_COMMITMENT_RANDOMNESS_BASE,
        }
    }
}

/// A RedJubjub signature: `R ‖ S`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Signature(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Signature(bytes)
    }
}

/// `H*`: BLAKE2b-512 personalized `Zcash_RedJubjubH`, reduced to a scalar.
fn h_star(parts: &[&[u8]]) -> Fr {
    let mut hash = blake2b::<64>(b"Zcash_RedJubjubH", parts);
    let scalar = Fr::from_bytes_wide(&hash);
    hash.zeroize();
    scalar
}

/// The verification key `[sk] P_G` of a signing key.
pub fn verification_key(sig_type: SigType, sk: &Fr) -> Point {
    sig_type.base().to_point().mul(sk)
}

/// Re-randomizes a signing key: `sk + α`.
pub fn randomize_private(sk: &Fr, alpha: &Fr) -> Fr {
    *sk + *alpha
}

/// Re-randomizes a verification key: `vk + [α] P_G`. Constant time, as `α`
/// is secret.
pub fn randomize_public(sig_type: SigType, vk: &Point, alpha: &Fr) -> Point {
    vk.add(&sig_type.base().to_point().mul(alpha))
}

/// Signs `message` with `sk`.
///
/// `random` must be 80 bytes from a cryptographic random number generator,
/// fresh for every signature.
pub fn sign(sig_type: SigType, sk: &Fr, message: &[u8], random: &[u8; 80]) -> Signature {
    let base = sig_type.base().to_point();
    let vk = base.mul(sk).to_bytes();
    let mut r = h_star(&[random, &vk, message]);
    let r_bytes = base.mul(&r).to_bytes();
    let c = h_star(&[&r_bytes, &vk, message]);
    let s = r + c * *sk;
    r.zeroize();
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s.to_bytes());
    Signature(sig)
}

/// Verifies a signature of `message` under the verification key `vk` (a
/// compressed point).
///
/// Follows the consensus rules since Canopy (ZIP-216): `vk` and `R` must be
/// canonical encodings, `S` must be reduced, and the equation checked is
/// `[8]([S] P_G - R - [c] vk) = O`.
pub fn verify(
    sig_type: SigType,
    vk: &[u8; 32],
    message: &[u8],
    signature: &Signature,
) -> Result<(), Error> {
    let (r_bytes, s_bytes) = signature.0.split_at(32);
    let r_bytes: &[u8; 32] = r_bytes.try_into().map_err(|_| Error::InvalidSignature)?;
    let s_bytes: &[u8; 32] = s_bytes.try_into().map_err(|_| Error::InvalidSignature)?;
    let vk_point = Point::from_bytes(vk).ok_or(Error::InvalidSignature)?;
    let r = Point::from_bytes(r_bytes).ok_or(Error::InvalidSignature)?;
    let s = Fr::from_bytes(s_bytes).ok_or(Error::InvalidSignature)?;
    let c = h_star(&[r_bytes, vk, message]);
    // everything here is public
    let lhs = sig_type.base().to_point().mul_vartime(&s);
    let rhs = r.add(&vk_point.mul_vartime(&c));
    if lhs.add(&rhs.negate()).is_small_order() {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// The randomized spend validating key `rk = ak + [α] G` of a Spend.
pub fn randomized_spend_key(ak: &Point, alpha: &Fr) -> Point {
    randomize_public(SigType::SpendAuth, ak, alpha)
}

/// Authorizes a spend: signs the transaction's signature hash with
/// `rsk = ask + α`, where `α` is the randomizer `rk` was made with.
pub fn sign_spend(ask: &Fr, alpha: &Fr, sighash: &[u8; 32], random: &[u8; 80]) -> Signature {
    let mut rsk = randomize_private(ask, alpha);
    let signature = sign(SigType::SpendAuth, &rsk, sighash, random);
    rsk.zeroize();
    signature
}

/// Verifies a spend authorization signature under `rk`.
pub fn verify_spend(rk: &[u8; 32], sighash: &[u8; 32], signature: &Signature) -> Result<(), Error> {
    verify(SigType::SpendAuth, rk, sighash, signature)
}

/// The binding signing key of a bundle: the sum of the value commitment
/// randomness `rcv` of its spends minus that of its outputs.
pub fn binding_signing_key<'a>(
    spends: impl IntoIterator<Item = &'a Fr>,
    outputs: impl IntoIterator<Item = &'a Fr>,
) -> Fr {
    let sum = spends.into_iter().fold(Fr::ZERO, |acc, rcv| acc + *rcv);
    outputs.into_iter().fold(sum, |acc, rcv| acc - *rcv)
}

/// The binding validating key of a bundle: the sum of the value commitments
/// `cv` of its spends, minus those of its outputs, minus
/// `[valueBalance] V`. It equals `[bsk] R` exactly when the values balance.
pub fn binding_validating_key<'a>(
    spends: impl IntoIterator<Item = &'a Point>,
    outputs: impl IntoIterator<Item = &'a Point>,
    value_balance: i64,
) -> Point {
    let sum = spends
        .into_iter()
        .fold(Point::IDENTITY, |acc, cv| acc.add(cv));
    let sum = outputs
        .into_iter()
        .fold(sum, |acc, cv| acc.add(&cv.negate()));
    let balance = VALUE_COMMITMENT_VALUE_BASE
        .to_point()
        .mul_vartime(&Fr::from_i64(value_balance));
    sum.add(&balance.negate())
}

/// Signs the transaction's signature hash with the binding signing key.
pub fn sign_binding(bsk: &Fr, sighash: &[u8; 32], random: &[u8; 80]) -> Signature {
    sign(SigType::Binding, bsk, sighash, random)
}

/// Verifies a binding signature under the binding validating key.
pub fn verify_binding(bvk: &Point, sighash: &[u8; 32], signature: &Signature) -> Result<(), Error> {
    verify(SigType::Binding, &bvk.to_bytes(), sighash, signature)
}

/// The number of random bytes a [`BatchVerifier`] takes per signature.
pub const BATCH_RANDOM_SIZE: usize = 16;

/// The number of points a [`BatchVerifier`] multiplies together: two per
/// signature.
const BATCH_POINTS: usize = 16;

/// `Σ scalarᵢ·pointᵢ`, with the doublings shared between the terms. Not
/// constant time: for public values.
fn multiscalar_mul_vartime(terms: &[(Point, Fr)]) -> Point {
    let mut limbs = [[0u64; 4]; BATCH_POINTS];
    for (limbs, (_, scalar)) in limbs.iter_mut().zip(terms) {
        *limbs = scalar.to_raw();
    }
    let limbs = &limbs[..terms.len().min(BATCH_POINTS)];
    let top = limbs
        .iter()
        .flat_map(|l| l.iter().enumerate())
        .filter(|(_, limb)| **limb != 0)
        .map(|(i, limb)| 64 * i + 64 - limb.leading_zeros() as usize)
        .max()
        .unwrap_or(0);
    let mut acc = Point::IDENTITY;
    for bit in (0..top).rev() {
        acc = acc.double();
        for (limbs, (point, _)) in limbs.iter().zip(terms) {
            if (limbs[bit / 64] >> (bit % 64)) & 1 == 1 {
                acc = acc.add(point);
            }
        }
    }
    acc
}

/// Verifies many RedJubjub signatures together, of either scheme, with a
/// random linear combination of their verification equations:
///
/// ```text
/// [8]( [Σ zᵢ·Sᵢ] P_G − Σ [zᵢ] Rᵢ − Σ [zᵢ·cᵢ] vkᵢ ) = O
/// ```
///
/// which holds for every choice of the `zᵢ` exactly when each signature
/// satisfies the equation of [`verify`]. The `zᵢ` come from the caller's
/// random bytes, [`BATCH_RANDOM_SIZE`] per signature: they must be
/// unpredictable to whoever made the signatures, so fresh output of a
/// cryptographically secure generator, drawn after the signatures are
/// known. A batch with an invalid signature is then accepted with
/// probability 2⁻¹²⁸.
///
/// A failed batch does not say which signature is invalid: verify them one
/// by one to find out. Nothing is allocated, whatever the size of the
/// batch.
///
/// ```
/// use outscript::sapling::Fr;
/// use outscript::sapling::redjubjub::{BatchVerifier, SigType, sign, verification_key};
/// # let (random_a, random_b) = ([1u8; 80], [2u8; 80]);
/// # let (z_a, z_b) = ([3u8; 16], [4u8; 16]);
/// let sk = Fr::from_u64(1234);
/// let vk = verification_key(SigType::SpendAuth, &sk).to_bytes();
/// let a = sign(SigType::SpendAuth, &sk, b"first", &random_a);
/// let b = sign(SigType::SpendAuth, &sk, b"second", &random_b);
///
/// let mut batch = BatchVerifier::new();
/// batch.queue(SigType::SpendAuth, &vk, b"first", &a, &z_a)?;
/// batch.queue(SigType::SpendAuth, &vk, b"second", &b, &z_b)?;
/// batch.verify()?;
/// # Ok::<(), outscript::sapling::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct BatchVerifier {
    /// `Σ [zᵢ] Rᵢ + Σ [zᵢ·cᵢ] vkᵢ` over the signatures already combined.
    sum: Point,
    /// `Σ zᵢ·Sᵢ` for each scheme: spend authorization, then binding.
    s: [Fr; 2],
    /// The terms not yet in `sum`.
    pending: [(Point, Fr); BATCH_POINTS],
    n_pending: usize,
    len: usize,
}

impl Default for BatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchVerifier {
    /// An empty batch.
    pub const fn new() -> Self {
        BatchVerifier {
            sum: Point::IDENTITY,
            s: [Fr::ZERO; 2],
            pending: [(Point::IDENTITY, Fr::ZERO); BATCH_POINTS],
            n_pending: 0,
            len: 0,
        }
    }

    /// The number of signatures queued.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no signature has been queued.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn flush(&mut self) {
        let terms = &self.pending[..self.n_pending];
        self.sum = self.sum.add(&multiscalar_mul_vartime(terms));
        self.n_pending = 0;
    }

    /// Adds a signature of `message` under the verification key `vk` to the
    /// batch, with [`BATCH_RANDOM_SIZE`] fresh random bytes.
    ///
    /// Fails right away, leaving the batch as it was, if the signature
    /// could not be valid: `vk` or `R` is not the canonical encoding of a
    /// point, or `S` is not reduced. Whether the signature verifies is
    /// only known from [`verify`](Self::verify).
    pub fn queue(
        &mut self,
        sig_type: SigType,
        vk: &[u8; 32],
        message: &[u8],
        signature: &Signature,
        random: &[u8; BATCH_RANDOM_SIZE],
    ) -> Result<(), Error> {
        let (r_bytes, s_bytes) = signature.0.split_at(32);
        let r_bytes: &[u8; 32] = r_bytes.try_into().map_err(|_| Error::InvalidSignature)?;
        let s_bytes: &[u8; 32] = s_bytes.try_into().map_err(|_| Error::InvalidSignature)?;
        let vk_point = Point::from_bytes(vk).ok_or(Error::InvalidSignature)?;
        let r = Point::from_bytes(r_bytes).ok_or(Error::InvalidSignature)?;
        let s = Fr::from_bytes(s_bytes).ok_or(Error::InvalidSignature)?;
        let c = h_star(&[r_bytes, vk, message]);
        // z = 2¹²⁸ + random: 128 bits of randomness, and never zero
        let mut z = [0u8; 32];
        z[..BATCH_RANDOM_SIZE].copy_from_slice(random);
        z[BATCH_RANDOM_SIZE] = 1;
        let z = Fr::from_bytes_reduced(&z);

        if self.n_pending + 2 > BATCH_POINTS {
            self.flush();
        }
        self.pending[self.n_pending] = (r, z);
        self.pending[self.n_pending + 1] = (vk_point, z * c);
        self.n_pending += 2;
        let scheme = match sig_type {
            SigType::SpendAuth => 0,
            SigType::Binding => 1,
        };
        self.s[scheme] += z * s;
        self.len += 1;
        Ok(())
    }

    /// Checks the batch: `Ok` when every queued signature is valid (an
    /// empty batch is), [`Error::InvalidSignature`] when at least one is
    /// not.
    pub fn verify(mut self) -> Result<(), Error> {
        self.flush();
        let lhs = SigType::SpendAuth
            .base()
            .to_point()
            .mul_vartime(&self.s[0])
            .add(&SigType::Binding.base().to_point().mul_vartime(&self.s[1]));
        if lhs.add(&self.sum.negate()).is_small_order() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sapling::note::value_commitment;
    use crate::sapling::test_vectors::{for_each_row, rows};

    /// `sapling_signatures.json`: keys, randomization, and the signatures
    /// themselves, reproduced with the generator's random strings.
    #[test]
    fn sapling_signatures() {
        let nonces = rows(include_str!("testdata/redjubjub_nonces.json"));
        let mut seen = 0;
        for_each_row(
            include_str!("testdata/sapling_signatures.json"),
            |i, row| {
                seen += 1;
                let nonce = |j: usize| -> [u8; 80] {
                    hex::decode(nonces[i][j].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap()
                };
                let sk = Fr::from_bytes(&row.array("sk")).unwrap();
                let vk = verification_key(SigType::SpendAuth, &sk);
                assert_eq!(vk.to_bytes(), row.array::<32>("vk"));
                let alpha = Fr::from_bytes(&row.array("alpha")).unwrap();
                let rsk = randomize_private(&sk, &alpha);
                assert_eq!(rsk.to_bytes(), row.array::<32>("rsk"));
                let rvk = randomized_spend_key(&vk, &alpha);
                assert_eq!(rvk.to_bytes(), row.array::<32>("rvk"));
                assert_eq!(verification_key(SigType::SpendAuth, &rsk), rvk);

                let m = row.bytes("m");
                let sig = Signature(row.array("sig"));
                let rsig = Signature(row.array("rsig"));
                assert_eq!(sign(SigType::SpendAuth, &sk, &m, &nonce(0)), sig);
                assert_eq!(sign(SigType::SpendAuth, &rsk, &m, &nonce(1)), rsig);
                let sighash: [u8; 32] = m.clone().try_into().unwrap();
                assert_eq!(sign_spend(&sk, &alpha, &sighash, &nonce(1)), rsig);

                let (vk, rvk) = (vk.to_bytes(), rvk.to_bytes());
                assert_eq!(verify(SigType::SpendAuth, &vk, &m, &sig), Ok(()));
                assert_eq!(verify_spend(&rvk, &sighash, &rsig), Ok(()));
                let bad = Err(Error::InvalidSignature);
                assert_eq!(verify(SigType::SpendAuth, &vk, &m, &rsig), bad);
                assert_eq!(verify(SigType::SpendAuth, &rvk, &m, &sig), bad);
                assert_eq!(verify(SigType::Binding, &vk, &m, &sig), bad);
                assert_eq!(verify(SigType::SpendAuth, &vk, &m[..31], &sig), bad);
                for flip in [0, 31, 32, 63] {
                    let mut tampered = sig;
                    tampered.0[flip] ^= 1;
                    assert_eq!(verify(SigType::SpendAuth, &vk, &m, &tampered), bad);
                }
            },
        );
        assert_eq!(seen, 10);
    }

    #[test]
    fn non_canonical_signatures_are_rejected() {
        let sk = Fr::from_u64(42);
        let vk = verification_key(SigType::Binding, &sk).to_bytes();
        let sig = sign(SigType::Binding, &sk, b"message", &[9; 80]);
        assert_eq!(verify(SigType::Binding, &vk, b"message", &sig), Ok(()));
        // S + r is the same scalar, but not a canonical encoding
        let mut s = [0u8; 32];
        s.copy_from_slice(&sig.0[32..]);
        let mut carry = 0u16;
        let mut modulus = [0u8; 32];
        for (chunk, limb) in modulus.chunks_mut(8).zip(Fr::MODULUS) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        for (b, m) in s.iter_mut().zip(modulus) {
            let sum = u16::from(*b) + u16::from(m) + carry;
            *b = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        let mut malleated = sig;
        malleated.0[32..].copy_from_slice(&s);
        assert_eq!(
            verify(SigType::Binding, &vk, b"message", &malleated),
            Err(Error::InvalidSignature)
        );
        // an R or vk that is not a point
        let mut bad_r = sig;
        bad_r.0[..32].fill(0xff);
        assert!(verify(SigType::Binding, &vk, b"message", &bad_r).is_err());
        assert!(verify(SigType::Binding, &[0xff; 32], b"message", &sig).is_err());
        // a different random string gives another valid signature
        let other = sign(SigType::Binding, &sk, b"message", &[10; 80]);
        assert_ne!(other, sig);
        assert_eq!(verify(SigType::Binding, &vk, b"message", &other), Ok(()));
        assert!(format!("{sig:?}").starts_with("Signature("));
    }

    #[test]
    fn binding_signatures_balance_values() {
        // two spends of 70 and 50, an output of 100, 20 leaving the pool
        let rcv: [Fr; 3] = [Fr::from_u64(11), -Fr::from_u64(22), Fr::from_u64(33)];
        let spends = [value_commitment(70, &rcv[0]), value_commitment(50, &rcv[1])];
        let outputs = [value_commitment(100, &rcv[2])];
        let bsk = binding_signing_key(&rcv[..2], &rcv[2..]);
        let bvk = binding_validating_key(&spends, &outputs, 20);
        assert_eq!(verification_key(SigType::Binding, &bsk), bvk);
        let sighash = [0x5a; 32];
        let sig = sign_binding(&bsk, &sighash, &[1; 80]);
        assert_eq!(verify_binding(&bvk, &sighash, &sig), Ok(()));
        // any other balance gives another key
        let wrong = binding_validating_key(&spends, &outputs, 21);
        assert_eq!(
            verify_binding(&wrong, &sighash, &sig),
            Err(Error::InvalidSignature)
        );
        // a negative balance: 30 entering the pool
        let outputs = [value_commitment(150, &rcv[2])];
        let bvk = binding_validating_key(&spends, &outputs, -30);
        assert_eq!(verification_key(SigType::Binding, &bsk), bvk);
    }

    /// Batches agree with single verification: every signature of
    /// `sapling_signatures.json` (more than one group of points), then the
    /// same with each kind of bad signature in turn.
    #[test]
    fn batch_matches_single() {
        let z = |i: usize| -> [u8; BATCH_RANDOM_SIZE] {
            blake2b(b"outscript_test__", &[&(i as u64).to_le_bytes()])
        };
        // (scheme, key, message, signature)
        type Entry = (SigType, [u8; 32], Vec<u8>, Signature);
        let mut sigs: Vec<Entry> = Vec::new();
        for_each_row(
            include_str!("testdata/sapling_signatures.json"),
            |_, row| {
                let m = row.bytes("m");
                let spend = SigType::SpendAuth;
                sigs.push((
                    spend,
                    row.array("vk"),
                    m.clone(),
                    Signature(row.array("sig")),
                ));
                sigs.push((spend, row.array("rvk"), m, Signature(row.array("rsig"))));
            },
        );
        for i in 0..3u64 {
            let sk = Fr::from_u64(1000 + i);
            let vk = verification_key(SigType::Binding, &sk).to_bytes();
            let sig = sign(SigType::Binding, &sk, &[i as u8; 32], &[i as u8; 80]);
            sigs.insert(
                5 * i as usize,
                (SigType::Binding, vk, vec![i as u8; 32], sig),
            );
        }
        assert!(2 * sigs.len() > 2 * BATCH_POINTS);

        let run = |sigs: &[Entry]| -> Result<(), Error> {
            let mut batch = BatchVerifier::new();
            assert!(batch.is_empty());
            for (i, (sig_type, vk, m, sig)) in sigs.iter().enumerate() {
                batch.queue(*sig_type, vk, m, sig, &z(i))?;
                assert_eq!(batch.len(), i + 1);
            }
            batch.verify()
        };
        let single = |sigs: &[Entry]| -> Result<(), Error> {
            sigs.iter()
                .try_for_each(|(sig_type, vk, m, sig)| verify(*sig_type, vk, m, sig))
        };
        assert_eq!(BatchVerifier::default().verify(), Ok(()));
        assert_eq!(run(&sigs), Ok(()));
        assert_eq!(single(&sigs), Ok(()));
        for n in [1, 2, 8, 9] {
            assert_eq!(run(&sigs[..n]), Ok(()));
        }

        let bad = Err(Error::InvalidSignature);
        for target in [0, 3, 7, 16, sigs.len() - 1] {
            // a flipped bit of R (when still a point), of S, of the key,
            // of the message; the other scheme; the signature of another
            let mutations: [&dyn Fn(&mut Entry); 6] = [
                &|e| e.3.0[1] ^= 4,
                &|e| e.3.0[33] ^= 1,
                &|e| e.1[2] ^= 8,
                &|e| e.2[0] ^= 1,
                &|e| {
                    e.0 = match e.0 {
                        SigType::SpendAuth => SigType::Binding,
                        SigType::Binding => SigType::SpendAuth,
                    }
                },
                &|e| e.3 = Signature([0; 64]),
            ];
            for mutate in mutations {
                let mut tampered = sigs.clone();
                mutate(&mut tampered[target]);
                assert_eq!(run(&tampered), bad);
                assert_eq!(single(&tampered), bad);
            }
        }
        // two valid signatures, each under the other's key
        let mut swapped = sigs.clone();
        let (a, b) = (swapped[1].3, swapped[2].3);
        swapped[1].3 = b;
        swapped[2].3 = a;
        assert_eq!(run(&swapped), bad);
    }

    /// The batch equation has the cofactor of the single one: a signature
    /// whose `R` carries a small-order component is valid either way.
    #[test]
    fn batch_accepts_small_order_components() {
        let sk = Fr::from_u64(77);
        let vk = verification_key(SigType::SpendAuth, &sk).to_bytes();
        let sig = sign(SigType::SpendAuth, &sk, b"m", &[3; 80]);
        // the point of order two, (0, -1)
        let mut order_two = (-crate::sapling::Fq::ONE).to_bytes();
        order_two[31] &= 0x7f;
        let torsion = Point::from_bytes(&order_two).unwrap();
        assert!(torsion.is_small_order() && !torsion.is_identity());
        // R' = R + T changes the challenge, so re-sign by hand around it
        let r = Fr::from_u64(5);
        let r_point = SigType::SpendAuth.base().to_point().mul(&r).add(&torsion);
        let r_bytes = r_point.to_bytes();
        let c = h_star(&[&r_bytes, &vk, b"m"]);
        let mut odd = [0u8; 64];
        odd[..32].copy_from_slice(&r_bytes);
        odd[32..].copy_from_slice(&(r + c * sk).to_bytes());
        let odd = Signature(odd);
        assert_eq!(verify(SigType::SpendAuth, &vk, b"m", &odd), Ok(()));
        for z in [[0u8; 16], [1; 16], [0xff; 16]] {
            let mut batch = BatchVerifier::new();
            batch
                .queue(SigType::SpendAuth, &vk, b"m", &sig, &z)
                .unwrap();
            batch
                .queue(SigType::SpendAuth, &vk, b"m", &odd, &z)
                .unwrap();
            assert_eq!(batch.verify(), Ok(()));
        }
        // malformed encodings fail when queued and leave the batch usable
        let mut batch = BatchVerifier::new();
        let mut bad_r = sig;
        bad_r.0[..32].fill(0xff);
        let mut bad_s = sig;
        bad_s.0[32..].fill(0xff);
        let spend = SigType::SpendAuth;
        let err = Err(Error::InvalidSignature);
        assert_eq!(batch.queue(spend, &vk, b"m", &bad_r, &[0; 16]), err);
        assert_eq!(batch.queue(spend, &vk, b"m", &bad_s, &[0; 16]), err);
        assert_eq!(batch.queue(spend, &[0xff; 32], b"m", &sig, &[0; 16]), err);
        assert!(batch.is_empty());
        batch.queue(spend, &vk, b"m", &sig, &[0; 16]).unwrap();
        assert_eq!(batch.verify(), Ok(()));
    }
}
