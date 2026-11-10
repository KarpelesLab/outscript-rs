//! RedPallas: the RedDSA signature scheme (a re-randomizable Schnorr
//! signature) instantiated on Pallas with BLAKE2b-512, as Orchard uses it
//! for spend authorization and for binding signatures.
//!
//! The two uses differ only in their base point, which the type parameter
//! of the keys and signatures selects: [`SpendAuth`] or [`Binding`].
//!
//! Many signatures (of both kinds, by any keys, over any messages) are
//! verified faster together, with a `BatchVerifier` (feature `alloc`).

use core::marker::PhantomData;

use purecrypto::ct::ConstantTimeEq;
use purecrypto::hash::Blake2bMac;
use purecrypto::zeroize::{Zeroize, ZeroizeOnDrop};

use super::Error;
use super::constants::{SPEND_AUTH_G, VALUE_COMMIT_R};
use super::fields::Fq;
use super::pallas::{Affine, Point};

mod sealed {
    pub trait Sealed {}
}

/// The kind of a RedPallas key or signature.
pub trait SigType: sealed::Sealed {
    /// The base point of the scheme.
    const BASE: Affine;
}

/// Spend authorization signatures, over the base `SpendAuthG`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendAuth {}

/// Binding signatures, over the value commitment randomness base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {}

impl sealed::Sealed for SpendAuth {}
impl sealed::Sealed for Binding {}

impl SigType for SpendAuth {
    const BASE: Affine = SPEND_AUTH_G;
}

impl SigType for Binding {
    const BASE: Affine = VALUE_COMMIT_R;
}

/// `H^*`: BLAKE2b-512 personalized with `Zcash_RedPallasH`, reduced to a
/// scalar.
fn h_star(parts: &[&[u8]]) -> Fq {
    let mut h = Blake2bMac::try_new_with_salt_personal(&[], 64, &[], b"Zcash_RedPallasH")
        .expect("valid BLAKE2b parameters");
    for part in parts {
        h.update(part);
    }
    let mut out = [0u8; 64];
    h.finalize_into(&mut out);
    let scalar = Fq::from_uniform_bytes(&out);
    out.zeroize();
    scalar
}

/// A RedPallas signing key. Wiped when dropped.
pub struct SigningKey<T: SigType> {
    sk: Fq,
    _kind: PhantomData<T>,
}

impl<T: SigType> Zeroize for SigningKey<T> {
    fn zeroize(&mut self) {
        self.sk.zeroize();
    }
}

impl<T: SigType> Drop for SigningKey<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: SigType> ZeroizeOnDrop for SigningKey<T> {}

impl<T: SigType> core::fmt::Debug for SigningKey<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

impl<T: SigType> SigningKey<T> {
    /// The signing key for a scalar.
    pub fn from_scalar(sk: Fq) -> Self {
        SigningKey {
            sk,
            _kind: PhantomData,
        }
    }

    /// Decodes the canonical 32-byte little-endian encoding of a key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Fq::from_bytes(bytes).map(Self::from_scalar)
    }

    /// The 32-byte encoding. The caller is responsible for wiping it.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }

    /// The key as a scalar.
    pub fn to_scalar(&self) -> Fq {
        self.sk
    }

    /// The verification key `[sk] BASE`.
    pub fn verification_key(&self) -> VerificationKey<T> {
        VerificationKey::from_point(T::BASE.to_point().mul(&self.sk).to_affine())
    }

    /// Signs `msg`. `random` must be 80 fresh uniformly random bytes: the
    /// nonce is derived from them, the public key and the message, so a
    /// repeated or predictable value gives the key away.
    pub fn sign(&self, random: &[u8; 80], msg: &[u8]) -> Signature<T> {
        let vk = self.verification_key().to_bytes();
        let mut nonce = h_star(&[random, &vk, msg]);
        let r = T::BASE.to_point().mul(&nonce).to_bytes();
        let c = h_star(&[&r, &vk, msg]);
        let s = (nonce + c * self.sk).to_bytes();
        nonce.zeroize();
        Signature {
            r,
            s,
            _kind: PhantomData,
        }
    }
}

impl SigningKey<SpendAuth> {
    /// This key randomized by `alpha`: `sk + alpha`.
    pub fn randomize(&self, alpha: &Fq) -> Self {
        Self::from_scalar(self.sk + *alpha)
    }
}

/// A RedPallas verification key: a point of the curve, kept with its
/// encoding.
#[derive(Clone, Copy)]
pub struct VerificationKey<T: SigType> {
    point: Affine,
    bytes: [u8; 32],
    _kind: PhantomData<T>,
}

impl<T: SigType> core::fmt::Debug for VerificationKey<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VerificationKey({:?})", self.point)
    }
}

impl<T: SigType> PartialEq for VerificationKey<T> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<T: SigType> Eq for VerificationKey<T> {}

impl<T: SigType> VerificationKey<T> {
    /// The verification key for a point.
    pub fn from_point(point: Affine) -> Self {
        VerificationKey {
            point,
            bytes: point.to_bytes(),
            _kind: PhantomData,
        }
    }

    /// Decodes the canonical 32-byte encoding of a point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Affine::from_bytes(bytes).map(|point| VerificationKey {
            point,
            bytes: *bytes,
            _kind: PhantomData,
        })
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// The key as a point.
    pub fn to_point(&self) -> Affine {
        self.point
    }

    /// Verifies `signature` over `msg`: `R` and `S` must be canonically
    /// encoded and `[S] BASE = R + [H(R || vk || msg)] vk`.
    pub fn verify(&self, msg: &[u8], signature: &Signature<T>) -> Result<(), Error> {
        let r = Affine::from_bytes(&signature.r).ok_or(Error::InvalidSignature)?;
        let s = Fq::from_bytes(&signature.s).ok_or(Error::InvalidSignature)?;
        let c = h_star(&[&signature.r, &self.bytes, msg]);
        // everything here is public
        let lhs = Point::msm_vartime(&[s, c.neg()], &[T::BASE, self.point]);
        if bool::from(lhs.ct_eq(&r.to_point())) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl VerificationKey<SpendAuth> {
    /// This key randomized by `alpha`: `vk + [alpha] SpendAuthG`.
    pub fn randomize(&self, alpha: &Fq) -> Self {
        Self::from_point(
            SPEND_AUTH_G
                .to_point()
                .mul(alpha)
                .add_affine(&self.point)
                .to_affine(),
        )
    }
}

/// A RedPallas signature: the encodings of the point `R` and the scalar `S`.
#[derive(Clone, Copy)]
pub struct Signature<T: SigType> {
    r: [u8; 32],
    s: [u8; 32],
    _kind: PhantomData<T>,
}

impl<T: SigType> core::fmt::Debug for Signature<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature({:02x?}, {:02x?})", self.r, self.s)
    }
}

impl<T: SigType> PartialEq for Signature<T> {
    fn eq(&self, other: &Self) -> bool {
        self.r == other.r && self.s == other.s
    }
}

impl<T: SigType> Eq for Signature<T> {}

impl<T: SigType> Signature<T> {
    /// Wraps the 64-byte encoding `R || S`. Nothing is checked until the
    /// signature is verified.
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Signature {
            r: bytes[..32].try_into().expect("32 bytes"),
            s: bytes[32..].try_into().expect("32 bytes"),
            _kind: PhantomData,
        }
    }

    /// The 64-byte encoding `R || S`.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r);
        out[32..].copy_from_slice(&self.s);
        out
    }
}

/// One signature of a batch: `[s] base = r + [c] vk` is to hold.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy)]
struct BatchItem {
    base: Affine,
    vk: Affine,
    r: Affine,
    s: Fq,
    c: Fq,
}

/// Verifies many RedPallas signatures at once: a random linear combination
/// of their verification equations, checked with a single multi-scalar
/// multiplication, several times faster than verifying them one by one.
///
/// A batch accepts exactly when every signature in it is valid (but for a
/// chance of about `2^-250` over the randomness given to
/// [`BatchVerifier::verify`]): Pallas has prime order, so there are no
/// signatures a batch and [`VerificationKey::verify`] disagree on. A
/// rejected batch does not tell which signature is wrong.
#[cfg(feature = "alloc")]
#[derive(Clone, Default)]
pub struct BatchVerifier {
    items: alloc::vec::Vec<BatchItem>,
    /// A signature that is not canonically encoded was queued.
    failed: bool,
}

#[cfg(feature = "alloc")]
impl core::fmt::Debug for BatchVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BatchVerifier")
            .field("signatures", &self.items.len())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "alloc")]
impl BatchVerifier {
    /// An empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of signatures queued.
    pub fn len(&self) -> usize {
        self.items.len() + self.failed as usize
    }

    /// Whether no signature was queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Adds `signature` by `vk` over `msg` to the batch.
    pub fn queue<T: SigType>(
        &mut self,
        vk: &VerificationKey<T>,
        msg: &[u8],
        signature: &Signature<T>,
    ) {
        let (Some(r), Some(s)) = (
            Affine::from_bytes(&signature.r),
            Fq::from_bytes(&signature.s),
        ) else {
            self.failed = true;
            return;
        };
        self.items.push(BatchItem {
            base: T::BASE,
            vk: vk.point,
            r,
            s,
            c: h_star(&[&signature.r, &vk.bytes, msg]),
        });
    }

    /// Whether every signature queued is valid (an empty batch is).
    /// `random` must be 64 uniformly random bytes that whoever made the
    /// signatures could not predict.
    pub fn verify(self, random: &[u8; 64]) -> Result<(), Error> {
        use alloc::vec::Vec;
        if self.failed {
            return Err(Error::InvalidSignature);
        }
        // sum z_i (R_i + [c_i] vk_i - [s_i] base_i) = 0, for random z_i
        let mut scalars: Vec<Fq> = Vec::with_capacity(2 * self.items.len() + 2);
        let mut points: Vec<Affine> = Vec::with_capacity(2 * self.items.len() + 2);
        // (the bases are few: one for each kind of signature)
        let mut bases: Vec<(Affine, Fq)> = Vec::with_capacity(2);
        for (i, item) in self.items.iter().enumerate() {
            let mut h = Blake2bMac::try_new_with_salt_personal(&[], 64, &[], b"outscript_rpbtch")
                .expect("valid BLAKE2b parameters");
            h.update(random);
            h.update(&(i as u64).to_le_bytes());
            let mut out = [0u8; 64];
            h.finalize_into(&mut out);
            let z = Fq::from_uniform_bytes(&out);
            scalars.push(z);
            points.push(item.r);
            scalars.push(z * item.c);
            points.push(item.vk);
            let term = (z * item.s).neg();
            match bases.iter_mut().find(|(base, _)| *base == item.base) {
                Some((_, scalar)) => *scalar += term,
                None => bases.push((item.base, term)),
            }
        }
        for (base, scalar) in bases {
            scalars.push(scalar);
            points.push(base);
        }
        // everything here is public
        if bool::from(Point::msm_vartime(&scalars, &points).is_identity()) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
