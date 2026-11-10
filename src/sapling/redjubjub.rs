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
pub fn verify_spend(
    rk: &[u8; 32],
    sighash: &[u8; 32],
    signature: &Signature,
) -> Result<(), Error> {
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
pub fn verify_binding(
    bvk: &Point,
    sighash: &[u8; 32],
    signature: &Signature,
) -> Result<(), Error> {
    verify(SigType::Binding, &bvk.to_bytes(), sighash, signature)
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
        for_each_row(include_str!("testdata/sapling_signatures.json"), |i, row| {
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
        });
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
}
