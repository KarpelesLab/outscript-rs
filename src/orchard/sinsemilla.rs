//! The Sinsemilla hash function and the commitment schemes built on it.
//!
//! A message is a sequence of bits, cut into 10-bit chunks (little-endian,
//! the last one padded with zeros); each chunk selects one of 1024 fixed
//! points and the hash is `Acc = (Acc + S(chunk)) + Acc` iterated from a
//! domain-specific point `Q`. The additions are *incomplete*: when one of
//! them meets an exceptional case (which nobody knows how to cause) the hash
//! is undefined and `None` is returned, as the protocol specifies.
//!
//! The chunk lookups index a table with message bits, so hashing is not
//! constant-time with respect to the message (the reference implementation
//! has the same property).

use purecrypto::ct::{Choice, ConstantTimeEq};

use super::constants::SINSEMILLA_S;
use super::fields::{Fp, Fq};
use super::pallas::{Affine, Point};

/// The number of bits of a message chunk.
pub const K: usize = 10;
/// The maximum number of chunks of a message.
pub const C: usize = 253;

/// `Q(D)`, the starting point of the hash for the domain `D`:
/// `GroupHash("z.cash:SinsemillaQ", D)`.
///
/// # Panics
/// Panics if `domain` is longer than 200 bytes.
pub fn generator_q(domain: &[u8]) -> Point {
    Point::hash_to_curve(b"z.cash:SinsemillaQ", domain)
}

/// `S(j)`, the point a chunk of value `j` selects (`j < 1024`):
/// `GroupHash("z.cash:SinsemillaS", I2LEOSP_32(j))`, from a precomputed
/// table.
pub fn generator_s(j: usize) -> Option<Affine> {
    SINSEMILLA_S.get(j).copied()
}

/// `SinsemillaHashToPoint` from the starting point `q`, or `None` if the
/// message is longer than [`C`] chunks or an addition is exceptional.
pub fn hash_to_point(q: &Affine, bits: impl IntoIterator<Item = bool>) -> Option<Point> {
    let mut acc = q.to_point();
    let mut ok = !q.is_identity();
    let mut bits = bits.into_iter();
    let mut chunks = 0;
    loop {
        let mut chunk = 0usize;
        let mut n = 0;
        for bit in bits.by_ref().take(K) {
            chunk |= (bit as usize) << n;
            n += 1;
        }
        if n == 0 {
            break;
        }
        chunks += 1;
        if chunks > C {
            return None;
        }
        let s = &SINSEMILLA_S[chunk];
        // (acc + s) + acc, each addition being undefined for two points
        // with the same x coordinate (and acc never being the identity)
        ok &= !same_x(&acc, &s.to_point());
        let r = acc.add_affine(s);
        ok &= !same_x(&r, &acc);
        acc = r.add(&acc);
        if n < K {
            break;
        }
    }
    if bool::from(ok & !acc.is_identity()) {
        Some(acc)
    } else {
        None
    }
}

/// Whether two points have the same x coordinate, or either is the
/// identity: the cases an incomplete addition is not defined for.
fn same_x(a: &Point, b: &Point) -> Choice {
    let (ax, _, az) = a.coordinates();
    let (bx, _, bz) = b.coordinates();
    (ax * bz).ct_eq(&(bx * az)) | az.is_zero() | bz.is_zero()
}

/// A Sinsemilla hash domain: a starting point `Q`.
#[derive(Clone, Copy, Debug)]
pub struct HashDomain {
    q: Affine,
}

impl HashDomain {
    /// The domain named `domain`, deriving its `Q` (two hashes to the
    /// curve; the domains Orchard uses are available precomputed, see
    /// [`MERKLE_CRH`](Self::MERKLE_CRH)).
    ///
    /// # Panics
    /// Panics if `domain` is longer than 200 bytes.
    pub fn new(domain: &[u8]) -> Self {
        HashDomain {
            q: generator_q(domain).to_affine(),
        }
    }

    /// The domain of starting point `q`.
    pub const fn from_q(q: Affine) -> Self {
        HashDomain { q }
    }

    /// The domain `z.cash:Orchard-MerkleCRH` of the note commitment tree.
    pub const MERKLE_CRH: HashDomain = HashDomain::from_q(super::constants::MERKLE_CRH_Q);

    /// The starting point `Q`.
    pub const fn q(&self) -> Affine {
        self.q
    }

    /// `SinsemillaHashToPoint` of the message, or `None` if it is longer
    /// than [`C`] chunks or an addition is exceptional.
    pub fn hash_to_point(&self, bits: impl IntoIterator<Item = bool>) -> Option<Point> {
        hash_to_point(&self.q, bits)
    }

    /// `SinsemillaHash` of the message: the x coordinate of
    /// [`hash_to_point`](Self::hash_to_point).
    pub fn hash(&self, bits: impl IntoIterator<Item = bool>) -> Option<Fp> {
        self.hash_to_point(bits).map(|p| p.to_affine().x())
    }
}

/// A Sinsemilla commitment domain: the hash domain of the message and the
/// base the randomness multiplies.
#[derive(Clone, Copy, Debug)]
pub struct CommitDomain {
    m: HashDomain,
    r: Affine,
}

impl CommitDomain {
    /// The domain named `domain`: the message is hashed under
    /// `domain || "-M"` and blinded with
    /// `GroupHash(domain || "-r", "")` (four hashes to the curve; the
    /// domains Orchard uses are available precomputed).
    ///
    /// # Panics
    /// Panics if `domain` is longer than 198 bytes.
    pub fn new(domain: &[u8]) -> Self {
        assert!(domain.len() <= 198, "domain too long");
        let mut buf = [0u8; 200];
        buf[..domain.len()].copy_from_slice(domain);
        let name = &mut buf[..domain.len() + 2];
        name[domain.len()..].copy_from_slice(b"-M");
        let m = HashDomain::new(name);
        name[domain.len()..].copy_from_slice(b"-r");
        let r = Point::hash_to_curve(name, b"").to_affine();
        CommitDomain { m, r }
    }

    /// The domain with these precomputed generators.
    pub const fn from_generators(q: Affine, r: Affine) -> Self {
        CommitDomain {
            m: HashDomain::from_q(q),
            r,
        }
    }

    /// The domain `z.cash:Orchard-NoteCommit` of note commitments.
    pub const NOTE_COMMIT: CommitDomain = CommitDomain::from_generators(
        super::constants::NOTE_COMMIT_Q,
        super::constants::NOTE_COMMIT_R,
    );

    /// The domain `z.cash:Orchard-CommitIvk` of incoming viewing keys.
    pub const COMMIT_IVK: CommitDomain = CommitDomain::from_generators(
        super::constants::COMMIT_IVK_Q,
        super::constants::COMMIT_IVK_R,
    );

    /// The hash domain of the message.
    pub const fn hash_domain(&self) -> HashDomain {
        self.m
    }

    /// The base the randomness multiplies.
    pub const fn r(&self) -> Affine {
        self.r
    }

    /// `SinsemillaCommit_r(msg)`: the hash of the message to a point plus
    /// `r` times the randomness base (in constant time with respect to
    /// `r`). `None` under the conditions of
    /// [`HashDomain::hash_to_point`].
    pub fn commit(&self, bits: impl IntoIterator<Item = bool>, r: &Fq) -> Option<Point> {
        let m = self.m.hash_to_point(bits)?;
        Some(m.add(&self.r.to_point().mul(r)))
    }

    /// `SinsemillaShortCommit_r(msg)`: the x coordinate of
    /// [`commit`](Self::commit).
    pub fn short_commit(&self, bits: impl IntoIterator<Item = bool>, r: &Fq) -> Option<Fp> {
        self.commit(bits, r).map(|p| p.to_affine().x())
    }
}

/// The first `n` bits of a little-endian byte string (`LEBS2OSP` backwards),
/// as Sinsemilla messages are made of.
pub fn le_bits(bytes: &[u8], n: usize) -> impl Iterator<Item = bool> + '_ {
    bytes
        .iter()
        .flat_map(|b| (0..8).map(move |i| (b >> i) & 1 == 1))
        .take(n)
}
