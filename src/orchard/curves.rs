//! The Pallas and Vesta elliptic curves.
//!
//! Both are `y^2 = x^3 + 5` of prime order, each over the scalar field of the
//! other: [`pallas`] is the curve Orchard's keys, commitments and signatures
//! use, [`vesta`] is the curve an Orchard proof commits its polynomials on
//! (its scalar field being the Pallas base field the circuit is written
//! over).
//!
//! Points are kept in homogeneous projective coordinates and added with the
//! complete formulas of Renes, Costello and Batina, so additions and
//! doublings have no special cases and [`Point::mul`](pallas::Point::mul)
//! runs in constant time. Functions named `_vartime` are for public inputs.

use purecrypto::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use purecrypto::hash::Blake2bMac;
use purecrypto::zeroize::Zeroize;

use super::fields::{Fp, Fq};

#[cfg(feature = "alloc")]
use crate::prelude::*;

macro_rules! pasta_curve {
    (
        $(#[$meta:meta])*
        $m:ident, base = $base:ident, scalar = $scalar:ident, id = $id:literal,
        iso_a = $iso_a:expr, z = $z:expr, theta = $theta:expr, isogeny = $iso:expr
    ) => {
        $(#[$meta])*
        pub mod $m {
            use super::*;

            /// The field the coordinates of a point are in.
            pub type Base = $base;
            /// The field of the scalars a point is multiplied by (integers
            /// modulo the order of the curve).
            pub type Scalar = $scalar;

            /// The curve constant `b` of `y^2 = x^3 + b`.
            pub const B: Base = Base::from_u64(5);

            /// `a` of the curve isogenous to this one that hashing to the
            /// curve goes through.
            const ISO_A: Base = Base::from_raw($iso_a);
            /// `b` of that curve.
            const ISO_B: Base = Base::from_u64(1265);
            /// The non-square `Z` of the simplified SWU map.
            const SWU_Z: Base = Base::from_raw($z);
            /// `sqrt(Z / ROOT_OF_UNITY)`.
            const SWU_THETA: Base = Base::from_raw($theta);
            /// The coefficients of the 3-isogeny from that curve.
            const ISOGENY: [Base; 13] = {
                let raw: [[u64; 4]; 13] = $iso;
                let mut out = [Base::ZERO; 13];
                let mut i = 0;
                while i < 13 {
                    out[i] = Base::from_raw(raw[i]);
                    i += 1;
                }
                out
            };

            #[inline(always)]
            fn mul_b3(t: &Base) -> Base {
                // 3b = 15 = 16 - 1
                t.double().double().double().double().sub(t)
            }

            /// A point in affine coordinates. The identity is represented
            /// by `(0, 0)`, which is not on the curve.
            #[derive(Clone, Copy)]
            pub struct Affine {
                x: Base,
                y: Base,
            }

            /// A point in homogeneous projective coordinates
            /// (`x = X / Z`, `y = Y / Z`).
            #[derive(Clone, Copy)]
            pub struct Point {
                x: Base,
                y: Base,
                z: Base,
            }

            impl Affine {
                /// The identity (point at infinity).
                pub const IDENTITY: Affine = Affine {
                    x: Base::ZERO,
                    y: Base::ZERO,
                };
                /// The conventional generator `(-1, 2)`.
                pub const GENERATOR: Affine = Affine {
                    x: Base::ONE.neg(),
                    y: Base::from_u64(2),
                };

                /// The point with these coordinates, or `None` if they are
                /// not on the curve.
                pub fn from_xy(x: Base, y: Base) -> Option<Affine> {
                    let p = Affine { x, y };
                    if bool::from(p.is_on_curve() & !p.is_identity()) {
                        Some(p)
                    } else {
                        None
                    }
                }

                /// The point with these coordinates, which the caller
                /// guarantees to be on the curve (or both zero for the
                /// identity). This is for tables of precomputed constants.
                pub const fn from_xy_unchecked(x: Base, y: Base) -> Affine {
                    Affine { x, y }
                }

                /// The x coordinate (zero for the identity).
                pub const fn x(&self) -> Base {
                    self.x
                }

                /// The y coordinate (zero for the identity).
                pub const fn y(&self) -> Base {
                    self.y
                }

                /// Whether this is the identity.
                pub fn is_identity(&self) -> Choice {
                    self.x.is_zero() & self.y.is_zero()
                }

                /// Whether the coordinates satisfy the curve equation (the
                /// identity counts).
                pub fn is_on_curve(&self) -> Choice {
                    (self.x.square() * self.x + B).ct_eq(&self.y.square()) | self.is_identity()
                }

                /// The opposite point.
                pub fn neg(&self) -> Affine {
                    Affine {
                        x: self.x,
                        y: self.y.neg(),
                    }
                }

                /// The image under the curve endomorphism
                /// `(x, y) -> (ZETA * x, y)`.
                pub fn endo(&self) -> Affine {
                    Affine {
                        x: self.x * Base::ZETA,
                        y: self.y,
                    }
                }

                /// This point in projective coordinates.
                pub fn to_point(&self) -> Point {
                    Point::conditional_select(
                        &Point::IDENTITY,
                        &Point {
                            x: self.x,
                            y: self.y,
                            z: Base::ONE,
                        },
                        self.is_identity(),
                    )
                }

                /// The 32-byte encoding: the x coordinate, little-endian,
                /// with the parity of y in the top bit; all zeros for the
                /// identity.
                pub fn to_bytes(&self) -> [u8; 32] {
                    let mut out = self.x.to_bytes();
                    out[31] |= self.y.is_odd().unwrap_u8() << 7;
                    out
                }

                /// Decodes [`to_bytes`](Self::to_bytes), accepting only the
                /// canonical encoding of a point (the identity included).
                pub fn from_bytes(bytes: &[u8; 32]) -> Option<Affine> {
                    let sign = bytes[31] >> 7;
                    let mut xb = *bytes;
                    xb[31] &= 0x7f;
                    let x = Base::from_bytes(&xb)?;
                    if bool::from(x.is_zero()) && sign == 0 {
                        return Some(Affine::IDENTITY);
                    }
                    // x = 0 is not on the curve (5 is not a square), so the
                    // all-zero encoding is unambiguous
                    let y = (x.square() * x + B).sqrt()?;
                    let flip = y.is_odd() ^ Choice::from(sign);
                    Some(Affine {
                        x,
                        y: Base::conditional_select(&y.neg(), &y, flip),
                    })
                }
            }

            impl ConstantTimeEq for Affine {
                fn ct_eq(&self, other: &Self) -> Choice {
                    self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
                }
            }

            impl ConditionallySelectable for Affine {
                /// `a` when `choice` is set, else `b`.
                fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                    Affine {
                        x: Base::conditional_select(&a.x, &b.x, choice),
                        y: Base::conditional_select(&a.y, &b.y, choice),
                    }
                }
            }

            impl PartialEq for Affine {
                fn eq(&self, other: &Self) -> bool {
                    bool::from(self.ct_eq(other))
                }
            }

            impl Eq for Affine {}

            impl core::fmt::Debug for Affine {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    if bool::from(self.is_identity()) {
                        f.write_str("Affine(identity)")
                    } else {
                        write!(f, "Affine({:?}, {:?})", self.x, self.y)
                    }
                }
            }

            impl Zeroize for Affine {
                fn zeroize(&mut self) {
                    self.x.zeroize();
                    self.y.zeroize();
                }
            }

            impl Point {
                /// The identity (point at infinity).
                pub const IDENTITY: Point = Point {
                    x: Base::ZERO,
                    y: Base::ONE,
                    z: Base::ZERO,
                };
                /// The conventional generator `(-1, 2)`.
                pub const GENERATOR: Point = Point {
                    x: Affine::GENERATOR.x,
                    y: Affine::GENERATOR.y,
                    z: Base::ONE,
                };

                /// Whether this is the identity.
                pub fn is_identity(&self) -> Choice {
                    self.z.is_zero()
                }

                /// The homogeneous projective coordinates `(X, Y, Z)`, with
                /// `x = X / Z` and `y = Y / Z` (`Z = 0` for the identity).
                pub const fn coordinates(&self) -> (Base, Base, Base) {
                    (self.x, self.y, self.z)
                }

                /// This point in affine coordinates (one field inversion).
                pub fn to_affine(&self) -> Affine {
                    let zinv = self.z.invert_or_zero();
                    Affine {
                        x: self.x * zinv,
                        y: self.y * zinv,
                    }
                }

                /// Converts `points` to affine coordinates with a single
                /// field inversion.
                ///
                /// # Panics
                /// Panics if `out` is shorter than `points`.
                pub fn batch_normalize(points: &[Point], out: &mut [Affine]) {
                    assert!(out.len() >= points.len(), "output too short");
                    // out[i].x holds the product of the non-zero z before i
                    let mut acc = Base::ONE;
                    for (p, o) in points.iter().zip(out.iter_mut()) {
                        o.x = acc;
                        acc = Base::conditional_select(&acc, &(acc * p.z), p.z.is_zero());
                    }
                    let mut inv = acc.invert_or_zero();
                    for (p, o) in points.iter().zip(out.iter_mut()).rev() {
                        let zero = p.z.is_zero();
                        let zinv = inv * o.x;
                        inv = Base::conditional_select(&inv, &(inv * p.z), zero);
                        *o = Affine::conditional_select(
                            &Affine::IDENTITY,
                            &Affine {
                                x: p.x * zinv,
                                y: p.y * zinv,
                            },
                            zero,
                        );
                    }
                }

                /// The 32-byte encoding, see [`Affine::to_bytes`].
                pub fn to_bytes(&self) -> [u8; 32] {
                    self.to_affine().to_bytes()
                }

                /// Decodes the 32-byte encoding, see [`Affine::from_bytes`].
                pub fn from_bytes(bytes: &[u8; 32]) -> Option<Point> {
                    Affine::from_bytes(bytes).map(|p| p.to_point())
                }

                /// `2 * self`.
                pub fn double(&self) -> Point {
                    // Renes-Costello-Batina 2015, algorithm 9 (a = 0)
                    let t0 = self.y.square();
                    let z3 = t0.double().double().double();
                    let t1 = self.y * self.z;
                    let t2 = mul_b3(&self.z.square());
                    let x3 = t2 * z3;
                    let y3 = t0 + t2;
                    let z3 = t1 * z3;
                    let t2 = t2.double() + t2;
                    let t0 = t0 - t2;
                    let y3 = x3 + t0 * y3;
                    let t1 = self.x * self.y;
                    let x3 = (t0 * t1).double();
                    Point {
                        x: x3,
                        y: y3,
                        z: z3,
                    }
                }

                /// `self + rhs`.
                pub fn add(&self, rhs: &Point) -> Point {
                    // Renes-Costello-Batina 2015, algorithm 7 (a = 0)
                    let t0 = self.x * rhs.x;
                    let t1 = self.y * rhs.y;
                    let t2 = self.z * rhs.z;
                    let t3 = (self.x + self.y) * (rhs.x + rhs.y) - (t0 + t1);
                    let t4 = (self.y + self.z) * (rhs.y + rhs.z) - (t1 + t2);
                    let y3 = (self.x + self.z) * (rhs.x + rhs.z) - (t0 + t2);
                    let t0 = t0.double() + t0;
                    let t2 = mul_b3(&t2);
                    let z3 = t1 + t2;
                    let t1 = t1 - t2;
                    let y3 = mul_b3(&y3);
                    let x3 = t3 * t1 - t4 * y3;
                    let y3 = t1 * z3 + y3 * t0;
                    let z3 = z3 * t4 + t0 * t3;
                    Point {
                        x: x3,
                        y: y3,
                        z: z3,
                    }
                }

                /// `self + rhs` for an affine `rhs`.
                pub fn add_affine(&self, rhs: &Affine) -> Point {
                    // Renes-Costello-Batina 2015, algorithm 8 (a = 0)
                    let t0 = self.x * rhs.x;
                    let t1 = self.y * rhs.y;
                    let t3 = (rhs.x + rhs.y) * (self.x + self.y) - (t0 + t1);
                    let t4 = rhs.y * self.z + self.y;
                    let y3 = rhs.x * self.z + self.x;
                    let t0 = t0.double() + t0;
                    let t2 = mul_b3(&self.z);
                    let z3 = t1 + t2;
                    let t1 = t1 - t2;
                    let y3 = mul_b3(&y3);
                    let x3 = t3 * t1 - t4 * y3;
                    let y3 = t1 * z3 + y3 * t0;
                    let z3 = z3 * t4 + t0 * t3;
                    Point::conditional_select(
                        self,
                        &Point {
                            x: x3,
                            y: y3,
                            z: z3,
                        },
                        rhs.is_identity(),
                    )
                }

                /// `-self`.
                pub fn neg(&self) -> Point {
                    Point {
                        x: self.x,
                        y: self.y.neg(),
                        z: self.z,
                    }
                }

                /// `self - rhs`.
                pub fn sub(&self, rhs: &Point) -> Point {
                    self.add(&rhs.neg())
                }

                /// The image under the curve endomorphism
                /// `(x, y) -> (ZETA * x, y)`.
                pub fn endo(&self) -> Point {
                    Point {
                        x: self.x * Base::ZETA,
                        y: self.y,
                        z: self.z,
                    }
                }

                /// `scalar * self` in constant time.
                pub fn mul(&self, scalar: &Scalar) -> Point {
                    let mut table = [Point::IDENTITY; 16];
                    table[1] = *self;
                    for i in 2..16 {
                        table[i] = if i % 2 == 0 {
                            table[i / 2].double()
                        } else {
                            table[i - 1].add(self)
                        };
                    }
                    let mut bytes = scalar.to_bytes();
                    let mut acc = Point::IDENTITY;
                    for i in (0..64).rev() {
                        acc = acc.double().double().double().double();
                        let nibble = (bytes[i / 2] >> (4 * (i % 2))) & 0xf;
                        let mut t = Point::IDENTITY;
                        for (j, entry) in table.iter().enumerate() {
                            t.conditional_assign(entry, (j as u8).ct_eq(&nibble));
                        }
                        acc = acc.add(&t);
                    }
                    bytes.zeroize();
                    acc
                }

                /// `scalar * self`, in time depending on the scalar: for
                /// public scalars only.
                pub fn mul_vartime(&self, scalar: &Scalar) -> Point {
                    let limbs = scalar.to_raw();
                    // 4-bit fixed windows: table[d] = d * self
                    let mut table = [Point::IDENTITY; 16];
                    table[1] = *self;
                    let mut filled = 1;
                    let mut acc = Point::IDENTITY;
                    let mut started = false;
                    for w in (0..64).rev() {
                        if started {
                            acc = acc.double().double().double().double();
                        }
                        let d = ((limbs[w / 16] >> (4 * (w % 16))) & 15) as usize;
                        if d != 0 {
                            // the table is filled as far as needed
                            while filled < d {
                                filled += 1;
                                table[filled] = if filled % 2 == 0 {
                                    table[filled / 2].double()
                                } else {
                                    table[filled - 1].add(self)
                                };
                            }
                            acc = if started { acc.add(&table[d]) } else { table[d] };
                            started = true;
                        }
                    }
                    acc
                }

                /// The multi-scalar multiplication
                /// `sum(scalars[i] * bases[i])`, in time depending on the
                /// scalars: for public inputs only (a verifier, or a prover's
                /// polynomial commitments, whose blinding it does not
                /// protect from timing). Extra scalars or bases are ignored.
                ///
                /// Without `alloc` this is the plain interleaved
                /// double-and-add; with it, a bucket method.
                pub fn msm_vartime(scalars: &[Scalar], bases: &[Affine]) -> Point {
                    let n = scalars.len().min(bases.len());
                    #[cfg(feature = "alloc")]
                    if n >= 32 {
                        return Self::msm_buckets(&scalars[..n], &bases[..n]);
                    }
                    let mut acc = Point::IDENTITY;
                    for i in (0..255).rev() {
                        acc = acc.double();
                        for (s, b) in scalars[..n].iter().zip(bases) {
                            if s.bit(i) {
                                acc = acc.add_affine(b);
                            }
                        }
                    }
                    acc
                }

                #[cfg(feature = "alloc")]
                fn msm_buckets(scalars: &[Scalar], bases: &[Affine]) -> Point {
                    let c = match scalars.len() {
                        0..128 => 4,
                        128..1024 => 6,
                        1024..8192 => 9,
                        8192..65536 => 12,
                        _ => 15,
                    };
                    let limbs: Vec<[u64; 4]> = scalars.iter().map(|s| s.to_raw()).collect();
                    let digit = |l: &[u64; 4], w: usize| -> usize {
                        let bit = w * c;
                        let mut v = l[bit / 64] >> (bit % 64);
                        if bit % 64 + c > 64 && bit / 64 + 1 < 4 {
                            v |= l[bit / 64 + 1] << (64 - bit % 64);
                        }
                        (v as usize) & ((1 << c) - 1)
                    };
                    let windows = 255usize.div_ceil(c);
                    let mut buckets = vec![Point::IDENTITY; (1 << c) - 1];
                    let mut acc = Point::IDENTITY;
                    for w in (0..windows).rev() {
                        for _ in 0..c {
                            acc = acc.double();
                        }
                        buckets.fill(Point::IDENTITY);
                        for (l, b) in limbs.iter().zip(bases) {
                            let d = digit(l, w);
                            if d != 0 {
                                buckets[d - 1] = buckets[d - 1].add_affine(b);
                            }
                        }
                        // sum(d * bucket[d]) by running sums
                        let mut running = Point::IDENTITY;
                        for b in buckets.iter().rev() {
                            running = running.add(b);
                            acc = acc.add(&running);
                        }
                    }
                    acc
                }

                /// The two field elements a message hashes to
                /// (`hash_to_field` of RFC 9380 with `expand_message_xmd`
                /// over BLAKE2b-512), under the domain separation tag
                /// `domain || "-" || curve name || "_XMD:BLAKE2b_SSWU_RO_"`.
                ///
                /// # Panics
                /// Panics if `domain` is longer than 200 bytes.
                pub fn hash_to_field(domain: &[u8], msg: &[u8]) -> [Base; 2] {
                    let id: &[u8] = $id.as_bytes();
                    let suffix = b"_XMD:BLAKE2b_SSWU_RO_";
                    assert!(domain.len() <= 200, "domain too long");
                    let dst_len = (domain.len() + 1 + id.len() + suffix.len()) as u8;
                    let dst = |h: &mut Blake2bMac| {
                        h.update(domain);
                        h.update(b"-");
                        h.update(id);
                        h.update(suffix);
                        h.update(&[dst_len]);
                    };
                    let mut b0 = [0u8; 64];
                    let mut h = Blake2bMac::new_unkeyed(64);
                    h.update(&[0u8; 128]);
                    h.update(msg);
                    h.update(&[0, 128, 0]);
                    dst(&mut h);
                    h.finalize_into(&mut b0);

                    let mut b1 = [0u8; 64];
                    let mut h = Blake2bMac::new_unkeyed(64);
                    h.update(&b0);
                    h.update(&[1]);
                    dst(&mut h);
                    h.finalize_into(&mut b1);

                    let mut b2 = [0u8; 64];
                    for i in 0..64 {
                        b2[i] = b0[i] ^ b1[i];
                    }
                    let mut h = Blake2bMac::new_unkeyed(64);
                    h.update(&b2);
                    h.update(&[2]);
                    dst(&mut h);
                    h.finalize_into(&mut b2);

                    // the chunks are big-endian integers
                    b1.reverse();
                    b2.reverse();
                    [Base::from_uniform_bytes(&b1), Base::from_uniform_bytes(&b2)]
                }

                /// The simplified SWU map: the affine coordinates of the
                /// point of the isogenous curve
                /// `y^2 = x^3 + ISO_A * x + 1265` that `u` maps to.
                pub fn map_to_curve_simple_swu(u: &Base) -> (Base, Base) {
                    // -ISO_B / ISO_A and -1 / Z
                    let c1 = const { ISO_B.neg().mul_const(&ISO_A.pow_const(&MODULUS_MINUS_2)) };
                    let c2 = const { Base::ONE.neg().mul_const(&SWU_Z.pow_const(&MODULUS_MINUS_2)) };
                    let z_u2 = SWU_Z * u.square();
                    let ta = z_u2.square() + z_u2;
                    let x1 = Base::conditional_select(
                        &c2,
                        &(ta.invert_or_zero() + Base::ONE),
                        ta.is_zero(),
                    ) * c1;
                    let gx1 = (x1.square() + ISO_A) * x1 + ISO_B;
                    let x2 = z_u2 * x1;
                    // r is sqrt(gx1), or sqrt(ROOT_OF_UNITY * gx1) from which
                    // theta makes sqrt(g(x2)) = sqrt((Z u^2)^3 gx1)
                    let (is_square, r) = gx1.sqrt_alt();
                    let y2 = SWU_THETA * z_u2 * *u * r;
                    let x = Base::conditional_select(&x1, &x2, is_square);
                    let y = Base::conditional_select(&r, &y2, is_square);
                    let y = Base::conditional_select(&y, &y.neg(), u.is_odd().ct_eq(&y.is_odd()));
                    (x, y)
                }

                /// Hashes a message to a point with no known discrete
                /// logarithm (`hash_to_curve` of `pasta_curves`: two
                /// simplified SWU maps onto the isogenous curve, added
                /// there, then the 3-isogeny), under the domain separation
                /// tag described at [`hash_to_field`](Self::hash_to_field).
                ///
                /// # Panics
                /// Panics if `domain` is longer than 200 bytes.
                pub fn hash_to_curve(domain: &[u8], msg: &[u8]) -> Point {
                    let [u0, u1] = Self::hash_to_field(domain, msg);
                    let (x1, y1) = Self::map_to_curve_simple_swu(&u0);
                    let (x2, y2) = Self::map_to_curve_simple_swu(&u1);
                    // the sum on the isogenous curve, in Jacobian
                    // coordinates (x = X / Z^2, y = Y / Z^3) with the
                    // denominator of the chord or tangent slope as Z; Z = 0
                    // is the identity
                    let same_x = x1.ct_eq(&x2);
                    let same = same_x & y1.ct_eq(&y2);
                    let n = Base::conditional_select(
                        &(x1.square().double() + x1.square() + ISO_A),
                        &(y2 - y1),
                        same,
                    );
                    let d = Base::conditional_select(&y1.double(), &(x2 - x1), same);
                    let d2 = d.square();
                    let d3 = d2 * d;
                    let x = n.square() - (x1 + x2) * d2;
                    let y = n * (x1 * d2 - x) - y1 * d3;
                    let z = d;
                    // the isogeny
                    let iso = &ISOGENY;
                    let z2 = z.square();
                    let z3 = z2 * z;
                    let z4 = z2.square();
                    let z6 = z3.square();
                    let num_x = ((iso[0] * x + iso[1] * z2) * x + iso[2] * z4) * x + iso[3] * z6;
                    let div_x = (z2 * x + iso[4] * z4) * x + iso[5] * z6;
                    let num_y =
                        (((iso[6] * x + iso[7] * z2) * x + iso[8] * z4) * x + iso[9] * z6) * y;
                    let div_y =
                        (((x + iso[10] * z2) * x + iso[11] * z4) * x + iso[12] * z6) * z3;
                    // (num_x / div_x, num_y / div_y), projectively
                    let out = Point {
                        x: num_x * div_y,
                        y: num_y * div_x,
                        z: div_x * div_y,
                    };
                    Point::conditional_select(&Point::IDENTITY, &out, out.z.is_zero())
                }
            }

            const MODULUS_MINUS_2: [u64; 4] = [
                Base::MODULUS[0] - 2,
                Base::MODULUS[1],
                Base::MODULUS[2],
                Base::MODULUS[3],
            ];

            impl ConstantTimeEq for Point {
                fn ct_eq(&self, other: &Self) -> Choice {
                    (self.x * other.z).ct_eq(&(other.x * self.z))
                        & (self.y * other.z).ct_eq(&(other.y * self.z))
                }
            }

            impl ConditionallySelectable for Point {
                /// `a` when `choice` is set, else `b`.
                fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                    Point {
                        x: Base::conditional_select(&a.x, &b.x, choice),
                        y: Base::conditional_select(&a.y, &b.y, choice),
                        z: Base::conditional_select(&a.z, &b.z, choice),
                    }
                }
            }

            impl PartialEq for Point {
                fn eq(&self, other: &Self) -> bool {
                    bool::from(self.ct_eq(other))
                }
            }

            impl Eq for Point {}

            impl core::fmt::Debug for Point {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "Point({:?})", self.to_affine())
                }
            }

            impl Zeroize for Point {
                fn zeroize(&mut self) {
                    self.x.zeroize();
                    self.y.zeroize();
                    self.z.zeroize();
                }
            }

            impl From<Affine> for Point {
                fn from(p: Affine) -> Point {
                    p.to_point()
                }
            }

            impl From<Point> for Affine {
                fn from(p: Point) -> Affine {
                    p.to_affine()
                }
            }

            impl core::ops::Add for Point {
                type Output = Point;
                fn add(self, rhs: Point) -> Point {
                    Point::add(&self, &rhs)
                }
            }

            impl core::ops::Add<Affine> for Point {
                type Output = Point;
                fn add(self, rhs: Affine) -> Point {
                    self.add_affine(&rhs)
                }
            }

            impl core::ops::Sub for Point {
                type Output = Point;
                fn sub(self, rhs: Point) -> Point {
                    Point::sub(&self, &rhs)
                }
            }

            impl core::ops::Neg for Point {
                type Output = Point;
                fn neg(self) -> Point {
                    Point::neg(&self)
                }
            }

            impl core::ops::Mul<Scalar> for Point {
                type Output = Point;
                /// Constant-time scalar multiplication.
                fn mul(self, rhs: Scalar) -> Point {
                    Point::mul(&self, &rhs)
                }
            }

            impl core::ops::Mul<Scalar> for Affine {
                type Output = Point;
                /// Constant-time scalar multiplication.
                fn mul(self, rhs: Scalar) -> Point {
                    Point::mul(&self.to_point(), &rhs)
                }
            }
        }
    };
}

pasta_curve! {
    /// The Pallas curve `y^2 = x^3 + 5` over [`Fp`], of order the modulus of
    /// [`Fq`]: Orchard's application curve.
    pallas, base = Fp, scalar = Fq, id = "pallas",
    iso_a = [
        0x92bb_4b0b_657a_014b,
        0xb741_3458_1a27_a59f,
        0x49be_2d72_5837_0742,
        0x1835_4a2e_b0ea_8c9c,
    ],
    z = [
        0x992d_30ec_ffff_fff4,
        0x2246_98fc_094c_f91b,
        0x0000_0000_0000_0000,
        0x4000_0000_0000_0000,
    ],
    theta = [
        0xca33_0bcc_09ac_318e,
        0x51f6_4fc4_dc88_8857,
        0x4647_aef7_82d5_cdc8,
        0x0f7b_db65_8141_79b4,
    ],
    isogeny = [
        [0x775f6034aaaaaaab, 0x4081775473d8375b, 0xe38e38e38e38e38e, 0x0e38e38e38e38e38],
        [0x8cf863b02814fb76, 0x0f93b82ee4b99495, 0x267c7ffa51cf412a, 0x3509afd51872d88e],
        [0x0eb64faef37ea4f7, 0x380af066cfeb6d69, 0x98c7d7ac3d98fd13, 0x17329b9ec5253753],
        [0xeebec06955555580, 0x8102eea8e7b06eb6, 0xc71c71c71c71c71c, 0x1c71c71c71c71c71],
        [0xc47f2ab668bcd71f, 0x9c434ac1c96b6980, 0x5a607fcce0494a79, 0x1d572e7ddc099cff],
        [0x2aa3af1eae5b6604, 0xb4abf9fb9a1fc81c, 0x1d13bf2a7f22b105, 0x325669becaecd5d1],
        [0x5ad985b5e38e38e4, 0x7642b01ad461bad2, 0x4bda12f684bda12f, 0x1a12f684bda12f68],
        [0xc67c31d8140a7dbb, 0x07c9dc17725cca4a, 0x133e3ffd28e7a095, 0x1a84d7ea8c396c47],
        [0x02e2be87d225b234, 0x1765e924f7459378, 0x303216cce1db9ff1, 0x3fb98ff0d2ddcadd],
        [0x93e53ab371c71c4f, 0x0ac03e8e134eb3e4, 0x7b425ed097b425ed, 0x025ed097b425ed09],
        [0x5a28279b1d1b42ae, 0x5941a3a4a97aa1b3, 0x0790bfb3506defb6, 0x0c02c5bcca0e6b7f],
        [0x4d90ab820b12320a, 0xd976bbfabbc5661d, 0x573b3d7f7d681310, 0x17033d3c60c68173],
        [0x992d30ecfffffde5, 0x224698fc094cf91b, 0x0000000000000000, 0x4000000000000000],
    ]
}

pasta_curve! {
    /// The Vesta curve `y^2 = x^3 + 5` over [`Fq`], of order the modulus of
    /// [`Fp`]: the curve of the polynomial commitments of an Orchard proof.
    vesta, base = Fq, scalar = Fp, id = "vesta",
    iso_a = [
        0xc515_ad72_42ea_a6b1,
        0x9673_928c_7d01_b212,
        0x8163_9c4d_96f7_8773,
        0x267f_9b2e_e592_271a,
    ],
    z = [
        0x8c46_eb20_ffff_fff4,
        0x2246_98fc_0994_a8dd,
        0x0000_0000_0000_0000,
        0x4000_0000_0000_0000,
    ],
    theta = [
        0x632c_ae98_72df_1b5d,
        0x3857_8cca_df03_ac27,
        0x53c3_808d_9e2f_2357,
        0x2b34_83a1_ee9a_382f,
    ],
    isogeny = [
        [0x43cd42c800000001, 0x0205dd51cfa0961a, 0x8e38e38e38e38e39, 0x38e38e38e38e38e3],
        [0x8b95c6aaf703bcc5, 0x216b8861ec72bd5d, 0xacecf10f5f7c09a2, 0x1d935247b4473d17],
        [0xaeac67bbeb586a3d, 0xd59d03d23b39cb11, 0xed7ee4a9cdf78f8f, 0x18760c7f7a9ad20d],
        [0xfb539a6f0000002b, 0xe1c521a795ac8356, 0x1c71c71c71c71c71, 0x31c71c71c71c71c7],
        [0xb7284f7eaf21a2e9, 0xa3ad678129b604d3, 0x1454798a5b5c56b2, 0x0a2de485568125d5],
        [0xf169c187d2533465, 0x30cd6d53df49d235, 0x0c621de8b91c242a, 0x14735171ee542778],
        [0x6bef1642aaaaaaab, 0x5601f4709a8adcb3, 0xda12f684bda12f68, 0x12f684bda12f684b],
        [0x8bee58e5fb81de63, 0x21d910aefb03b31d, 0xd6767887afbe04d1, 0x2ec9a923da239e8b],
        [0x4986913ab4443034, 0x97a3ca5c24e9ea63, 0x66d1466e9de10e64, 0x19b0d87e16e25788],
        [0x8f64842c55555533, 0x8bc32d36fb21a6a3, 0x425ed097b425ed09, 0x1ed097b425ed097b],
        [0x58dfecce86b2745e, 0x06a767bfc35b5bac, 0x9e7eb64f890a820c, 0x2f44d6c801c1b8bf],
        [0xd43d449776f99d2f, 0x926847fb9ddd76a1, 0x252659ba2b546c7e, 0x3d59f455cafc7668],
        [0x8c46eb20fffffde5, 0x224698fc0994a8dd, 0x0000000000000000, 0x4000000000000000],
    ]
}
