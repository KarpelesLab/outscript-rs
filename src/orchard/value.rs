//! Value commitments: homomorphic Pedersen commitments to the net value of
//! an action, whose sum over a bundle the binding signature opens.

use purecrypto::zeroize::Zeroize;

use super::constants::{VALUE_COMMIT_R, VALUE_COMMIT_V};
use super::fields::Fq;
use super::pallas::{Affine, Point};
use super::redpallas::{Binding, SigningKey, VerificationKey};

/// The scalar for a signed value.
fn value_scalar(value: i128) -> Fq {
    let abs = Fq::from_u128(value.unsigned_abs());
    if value < 0 { abs.neg() } else { abs }
}

/// A value commitment `cv = [v] V + [rcv] R`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueCommitment(Affine);

impl ValueCommitment {
    /// Commits to `value` (the value an action spends minus the value it
    /// outputs, in zatoshi) with the randomness `rcv`. The scalar
    /// multiplications are constant-time.
    pub fn derive(value: i128, rcv: &Fq) -> Self {
        let mut v = value_scalar(value);
        let cv = VALUE_COMMIT_V
            .to_point()
            .mul(&v)
            .add(&VALUE_COMMIT_R.to_point().mul(rcv));
        v.zeroize();
        ValueCommitment(cv.to_affine())
    }

    /// The commitment for a point.
    pub fn from_point(point: Affine) -> Self {
        ValueCommitment(point)
    }

    /// The commitment as a point.
    pub fn to_point(&self) -> Affine {
        self.0
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Decodes the canonical 32-byte encoding of a point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Affine::from_bytes(bytes).map(ValueCommitment)
    }
}

/// The binding signing key of a bundle: the sum of the value commitment
/// randomness `rcv` of its actions.
pub fn binding_signing_key<'a>(rcvs: impl IntoIterator<Item = &'a Fq>) -> SigningKey<Binding> {
    let mut sum = Fq::ZERO;
    for rcv in rcvs {
        sum += *rcv;
    }
    SigningKey::from_scalar(sum)
}

/// The binding validating key of a bundle: the sum of the value commitments
/// of its actions minus the commitment `[value_balance] V` to its (public)
/// value balance. It is the public key of [`binding_signing_key`] exactly
/// when the values add up.
pub fn binding_validating_key<'a>(
    cvs: impl IntoIterator<Item = &'a ValueCommitment>,
    value_balance: i64,
) -> VerificationKey<Binding> {
    let mut sum = Point::IDENTITY;
    for cv in cvs {
        sum = sum.add_affine(&cv.0);
    }
    let balance = VALUE_COMMIT_V
        .to_point()
        .mul_vartime(&value_scalar(value_balance as i128));
    VerificationKey::from_point(sum.sub(&balance).to_affine())
}
