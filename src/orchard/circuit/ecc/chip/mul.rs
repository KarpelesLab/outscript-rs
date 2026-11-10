//! Variable-base scalar multiplication (port of
//! `halo2_gadgets::ecc::chip::mul`).

use alloc::vec::Vec;
use core::ops::{Deref, Range};

use super::{CircuitVersion, EccPoint, NonIdentityEccPoint, ScalarVar, T_Q, add};
use crate::orchard::Fp;
use crate::orchard::circuit::utilities::lookup_range_check::LookupRangeCheckConfig;
use crate::orchard::circuit::utilities::{bool_check, ternary};
use crate::orchard::halo2::circuit::{AssignedCell, Layouter, Region};
use crate::orchard::halo2::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Rotation, Selector,
};
use crate::orchard::halo2::{Error, Value};

mod complete;
pub(super) mod incomplete;
mod overflow;

/// The number of bits of a Pallas scalar (`pallas::Scalar::NUM_BITS`).
const SCALAR_NUM_BITS: usize = 255;

/// Number of bits for which complete addition needs to be used in
/// variable-base scalar multiplication
const NUM_COMPLETE_BITS: usize = 3;

// Bits used in incomplete addition. k_{254} to k_{4} inclusive
const INCOMPLETE_LEN: usize = SCALAR_NUM_BITS - 1 - NUM_COMPLETE_BITS;

// Bits k_{254} to k_{4} inclusive are used in incomplete addition.
// The `hi` half is k_{254} to k_{130} inclusive (length 125 bits).
// (It does not matter how we split them between the hi and lo halves.)
const INCOMPLETE_HI_RANGE: Range<usize> = 0..INCOMPLETE_HI_LEN;
const INCOMPLETE_HI_LEN: usize = INCOMPLETE_LEN / 2;

// Bits k_{254} to k_{4} inclusive are used in incomplete addition.
// The `lo` half is k_{129} to k_{4} inclusive (length 126 bits).
const INCOMPLETE_LO_RANGE: Range<usize> = INCOMPLETE_HI_LEN..INCOMPLETE_LEN;
const INCOMPLETE_LO_LEN: usize = INCOMPLETE_LEN - INCOMPLETE_HI_LEN;

// Bits k_{3} to k_{1} inclusive are used in complete addition.
// Bit k_{0} is handled separately.
const COMPLETE_RANGE: Range<usize> = INCOMPLETE_LEN..(INCOMPLETE_LEN + NUM_COMPLETE_BITS);

/// Configuration for variable-base scalar multiplication.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Config {
    // Selector used to check switching logic on LSB
    q_mul_lsb: Selector,
    // Configuration used in complete addition
    add_config: add::Config,
    // Configuration used for `hi` bits of the scalar
    hi_config: incomplete::Config<INCOMPLETE_HI_LEN>,
    // Configuration used for `lo` bits of the scalar
    lo_config: incomplete::Config<INCOMPLETE_LO_LEN>,
    // Configuration used for complete addition part of double-and-add algorithm
    complete_config: complete::Config,
    // Configuration used to check for overflow
    overflow_config: overflow::Config,
}

impl Config {
    pub(super) fn configure(
        meta: &mut ConstraintSystem,
        add_config: add::Config,
        lookup_config: LookupRangeCheckConfig,
        advices: [Column<Advice>; 10],
    ) -> Self {
        let hi_config = incomplete::Config::configure(
            meta, advices[9], advices[3], advices[0], advices[1], advices[4], advices[5],
        );
        let lo_config = incomplete::Config::configure(
            meta, advices[6], advices[7], advices[0], advices[1], advices[8], advices[2],
        );
        let complete_config = complete::Config::configure(meta, advices[9], add_config);
        let overflow_config =
            overflow::Config::configure(meta, lookup_config, [advices[6], advices[7], advices[8]]);

        let config = Self {
            q_mul_lsb: meta.selector(),
            add_config,
            hi_config,
            lo_config,
            complete_config,
            overflow_config,
        };

        config.create_gate(meta);

        assert_eq!(
            config.hi_config.double_and_add.x_p, config.lo_config.double_and_add.x_p,
            "x_p is shared across hi and lo halves."
        );
        assert_eq!(
            config.hi_config.y_p, config.lo_config.y_p,
            "y_p is shared across hi and lo halves."
        );

        // For both hi_config and lo_config:
        // z and lambda1 are assigned on the same row as the add_config output.
        // Therefore, z and lambda1 must not overlap with add_config.x_qr, add_config.y_qr.
        let add_config_outputs = config.add_config.output_columns();
        {
            assert!(
                !add_config_outputs.contains(&config.hi_config.z),
                "incomplete config z cannot overlap with complete addition columns."
            );
            assert!(
                !add_config_outputs.contains(&config.hi_config.double_and_add.lambda_1),
                "incomplete config lambda1 cannot overlap with complete addition columns."
            );
        }
        {
            assert!(
                !add_config_outputs.contains(&config.lo_config.z),
                "incomplete config z cannot overlap with complete addition columns."
            );
            assert!(
                !add_config_outputs.contains(&config.lo_config.double_and_add.lambda_1),
                "incomplete config lambda1 cannot overlap with complete addition columns."
            );
        }

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) {
        // If `lsb` is 0, (x, y) = (x_p, -y_p). If `lsb` is 1, (x, y) = (0,0).
        // https://p.z.cash/halo2-0.1:ecc-var-mul-lsb-gate?partial
        meta.create_gate("LSB check", |meta| {
            let q_mul_lsb = meta.query_selector(self.q_mul_lsb);

            let z_1 = meta.query_advice(self.complete_config.z_complete, Rotation::cur());
            let z_0 = meta.query_advice(self.complete_config.z_complete, Rotation::next());
            let x_p = meta.query_advice(self.add_config.x_p, Rotation::cur());
            let y_p = meta.query_advice(self.add_config.y_p, Rotation::cur());
            let base_x = meta.query_advice(self.add_config.x_p, Rotation::next());
            let base_y = meta.query_advice(self.add_config.y_p, Rotation::next());

            //    z_0 = 2 * z_1 + k_0
            // => k_0 = z_0 - 2 * z_1
            let lsb = z_0 - z_1 * Fp::from_u64(2);

            let bool_check = bool_check(lsb.clone());

            // `lsb` = 0 => (x_p, y_p) = (x, -y)
            // `lsb` = 1 => (x_p, y_p) = (0,0)
            let lsb_x = ternary(lsb.clone(), x_p.clone(), x_p - base_x);
            let lsb_y = ternary(lsb, y_p.clone(), y_p + base_y);

            // bool_check, lsb_x, lsb_y
            Constraints::with_selector(q_mul_lsb, [bool_check, lsb_x, lsb_y])
        });
    }

    pub(super) fn assign(
        &self,
        layouter: &mut Layouter<'_>,
        alpha: AssignedCell<Fp>,
        base: &NonIdentityEccPoint,
        circuit_version: CircuitVersion,
    ) -> Result<(EccPoint, ScalarVar), Error> {
        let (result, zs): (EccPoint, Vec<Z>) = layouter.assign_region(|mut region| {
            let offset = 0;

            // Case `base` into an `EccPoint` for later use.
            let base_point: EccPoint = base.clone().into();

            // Decompose `k = alpha + t_q` bitwise (big-endian bit order).
            let bits = decompose_for_scalar_mul(alpha.value());

            // Define ranges for each part of the algorithm.
            let bits_incomplete_hi = &bits[INCOMPLETE_HI_RANGE];
            let bits_incomplete_lo = &bits[INCOMPLETE_LO_RANGE];
            let lsb = bits[SCALAR_NUM_BITS - 1];

            // Initialize the accumulator `acc = [2]base` using complete addition.
            let acc =
                self.add_config
                    .assign_region(&base_point, &base_point, offset, &mut region)?;

            // Increase the offset by 1 after complete addition.
            let offset = offset + 1;

            // Initialize the running sum for scalar decomposition to zero.
            //
            // `z_init` is constrained by the fixed-column constants cell
            // (see `Region::assign_advice_from_constant`).
            let z_init =
                Z(region.assign_advice_from_constant(self.hi_config.z, offset, Fp::ZERO)?);

            // Double-and-add (incomplete addition) for the `hi` half of the scalar decomposition
            let (x_a, y_a, zs_incomplete_hi) = self.hi_config.double_and_add(
                &mut region,
                offset,
                base,
                bits_incomplete_hi,
                (X(acc.x), Y(acc.y), z_init.clone()),
                circuit_version,
            )?;

            // Double-and-add (incomplete addition) for the `lo` half of the scalar decomposition
            let z = zs_incomplete_hi.last().expect("should not be empty");
            let (x_a, y_a, zs_incomplete_lo) = self.lo_config.double_and_add(
                &mut region,
                offset,
                base,
                bits_incomplete_lo,
                (x_a, y_a, z.clone()),
                circuit_version,
            )?;

            // Move from incomplete addition to complete addition.
            // Inside incomplete::double_and_add, the offset was increased once after initialization
            // of the running sum.
            // Then, the final assignment of double-and-add was made on row + offset + 1.
            // Outside of incomplete addition, we must account for these offset increases by adding
            // 2 to the incomplete addition length.
            assert!(INCOMPLETE_LO_RANGE.len() >= INCOMPLETE_HI_RANGE.len());
            let offset = offset + INCOMPLETE_LO_RANGE.len() + 2;

            // Complete addition
            let (acc, zs_complete) = {
                let z = zs_incomplete_lo.last().expect("should not be empty");
                // Bits used in complete addition. k_{3} to k_{1} inclusive
                // The LSB k_{0} is handled separately.
                let bits_complete = &bits[COMPLETE_RANGE];
                self.complete_config.assign_region(
                    &mut region,
                    offset,
                    bits_complete,
                    &base_point,
                    x_a,
                    y_a,
                    z.clone(),
                )?
            };

            // Each iteration of the complete addition uses two rows.
            let offset = offset + COMPLETE_RANGE.len() * 2;

            // Process the least significant bit
            let z_1 = zs_complete.last().unwrap().clone();
            let (result, z_0) = self.process_lsb(&mut region, offset, base, acc, z_1, lsb)?;

            #[cfg(test)]
            // Check that the correct multiple is obtained.
            {
                use crate::orchard::Fq;

                let base = base.point();
                let alpha = alpha
                    .value()
                    .map(|alpha| Fq::from_bytes(&alpha.to_bytes()).unwrap());
                let real_mul = base
                    .zip(alpha)
                    .map(|(base, alpha)| base.to_point().mul(&alpha));
                let result = result.point();

                real_mul.zip(result).assert_if_known(|(real_mul, result)| {
                    let real_mul = real_mul.to_affine();
                    real_mul.x() == result.x() && real_mul.y() == result.y()
                });
            }

            let zs = {
                let mut zs = core::iter::empty()
                    .chain(Some(z_init))
                    .chain(zs_incomplete_hi)
                    .chain(zs_incomplete_lo)
                    .chain(zs_complete)
                    .chain(Some(z_0))
                    .collect::<Vec<_>>();
                assert_eq!(zs.len(), SCALAR_NUM_BITS + 1);

                // This reverses zs to give us [z_0, z_1, ..., z_{254}, z_{255}].
                zs.reverse();
                zs
            };

            Ok((result, zs))
        })?;

        self.overflow_config
            .overflow_check(layouter.namespace(), alpha.clone(), &zs)?;

        Ok((result, ScalarVar::BaseFieldElem(alpha)))
    }

    /// Processes the final scalar bit `k_0`.
    ///
    /// Assumptions for this sub-region:
    /// - `acc_x` and `acc_y` are already copied into this region.
    ///
    /// `x_p` and `y_p` hold the point added to the accumulator (`-base` when
    /// `lsb` is 0, the identity otherwise), and `base` on the next row.
    fn process_lsb(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        base: &NonIdentityEccPoint,
        acc: EccPoint,
        z_1: Z,
        lsb: Value<bool>,
    ) -> Result<(EccPoint, Z), Error> {
        // Enforce switching logic on LSB using a custom gate
        self.q_mul_lsb.enable(region, offset)?;

        // z_1 has been assigned at (z_complete, offset).
        // Assign z_0 = 2⋅z_1 + k_0
        let z_0 = {
            let z_0_val = z_1.value().zip(lsb).map(|(z_1, lsb)| {
                let lsb = Fp::from_u64(lsb as u64);
                *z_1 * Fp::from_u64(2) + lsb
            });
            let z_0_cell =
                region.assign_advice(self.complete_config.z_complete, offset + 1, || z_0_val)?;

            Z(z_0_cell)
        };

        // Copy in `base_x`, `base_y` to use in the LSB gate
        base.x()
            .copy_advice(region, self.add_config.x_p, offset + 1)?;
        base.y()
            .copy_advice(region, self.add_config.y_p, offset + 1)?;

        // If `lsb` is 0, return `Acc + (-P)`. If `lsb` is 1, simply return `Acc + 0`.
        let x = lsb.and_then(|lsb| {
            if !lsb {
                base.x.value().cloned()
            } else {
                Value::known(Fp::ZERO)
            }
        });

        let y = lsb.and_then(|lsb| {
            if !lsb {
                -base.y.value().cloned()
            } else {
                Value::known(Fp::ZERO)
            }
        });

        let x_cell = region.assign_advice(self.add_config.x_p, offset, || x)?;
        let y_cell = region.assign_advice(self.add_config.y_p, offset, || y)?;

        let p = EccPoint::from_coordinates_unchecked(x_cell, y_cell);

        // Return the result of the final complete addition as `[scalar]B`
        let result = self.add_config.assign_region(&p, &acc, offset, region)?;

        Ok((result, z_0))
    }
}

/// The x-coordinate of the accumulator in a double-and-add instance.
#[derive(Clone, Debug)]
struct X(AssignedCell<Fp>);

impl Deref for X {
    type Target = AssignedCell<Fp>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The y-coordinate of the accumulator in a double-and-add instance.
#[derive(Clone, Debug)]
struct Y(AssignedCell<Fp>);

impl Deref for Y {
    type Target = AssignedCell<Fp>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A cumulative sum used to decompose the scalar.
#[derive(Clone, Debug)]
struct Z(AssignedCell<Fp>);

impl Deref for Z {
    type Target = AssignedCell<Fp>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The 255 bits of `k = scalar + t_q`, most significant first.
// https://p.z.cash/halo2-0.1:ecc-var-mul-witness-decomposition
fn decompose_for_scalar_mul(scalar: Value<&Fp>) -> Vec<Value<bool>> {
    let bitstring = scalar.map(|scalar| {
        // We use `k = scalar + t_q` in the double-and-add algorithm, where
        // the scalar field `F_q = 2^254 + t_q`.
        // Note that the addition `scalar + t_q` is not reduced.
        let scalar = scalar.to_raw();
        let t_q = [T_Q as u64, (T_Q >> 64) as u64, 0, 0];
        let mut k = [0u64; 4];
        let mut carry = false;
        for i in 0..4 {
            let (sum, c1) = scalar[i].overflowing_add(t_q[i]);
            let (sum, c2) = sum.overflowing_add(carry as u64);
            k[i] = sum;
            carry = c1 || c2;
        }

        // Little-endian bit representation of `k`.
        // Take the first 255 bits.
        (0..SCALAR_NUM_BITS)
            .map(|i| (k[i / 64] >> (i % 64)) & 1 == 1)
            .collect::<Vec<_>>()
    });

    // Transpose.
    let mut bitstring = bitstring.transpose_vec(SCALAR_NUM_BITS);
    // Reverse to get big-endian bit representation.
    bitstring.reverse();
    bitstring
}
