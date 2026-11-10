//! Fixed-base multiplication by a signed short scalar (port of
//! `halo2_gadgets::ecc::chip::mul_fixed::short`).

use super::super::{
    EccPoint, EccScalarFixedShort, L_SCALAR_SHORT, MagnitudeSign, NUM_WINDOWS_SHORT,
    OrchardShortScalarBases,
};
use crate::orchard::Fp;
use crate::orchard::circuit::utilities::bool_check;
use crate::orchard::halo2::Error;
use crate::orchard::halo2::circuit::{Layouter, Region};
use crate::orchard::halo2::plonk::{ConstraintSystem, Constraints, Expression, Rotation, Selector};

/// The configuration of the short signed fixed-base multiplication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Config {
    // Selector used for fixed-base scalar mul with short signed exponent.
    q_mul_fixed_short: Selector,
    super_config: super::Config,
}

impl Config {
    pub(crate) fn configure(meta: &mut ConstraintSystem, super_config: super::Config) -> Self {
        let config = Self {
            q_mul_fixed_short: meta.selector(),
            super_config,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) {
        // Gate contains the following constraints:
        // - https://p.z.cash/halo2-0.1:ecc-fixed-mul-short-msb
        // - https://p.z.cash/halo2-0.1:ecc-fixed-mul-short-conditional-neg
        meta.create_gate("Short fixed-base mul gate", |meta| {
            let q_mul_fixed_short = meta.query_selector(self.q_mul_fixed_short);
            let y_p = meta.query_advice(self.super_config.add_config.y_p, Rotation::cur());
            let y_a = meta.query_advice(self.super_config.add_config.y_qr, Rotation::cur());
            // z_21 = k_21
            let last_window = meta.query_advice(self.super_config.u, Rotation::cur());
            let sign = meta.query_advice(self.super_config.window, Rotation::cur());

            let one = Expression::Constant(Fp::ONE);

            // Check that last window is either 0 or 1.
            let last_window_check = bool_check(last_window);
            // Check that sign is either 1 or -1.
            let sign_check = sign.clone().square() - one;

            // `(x_a, y_a)` is the result of `[m]B`, where `m` is the magnitude.
            // We conditionally negate this result using `y_p = y_a * s`, where `s` is the sign.

            // Check that the final `y_p = y_a` or `y_p = -y_a`
            //
            // This constraint is redundant / unnecessary, because `sign` is constrained
            // to -1 or 1 by `sign_check`, and `negation_check` therefore permits a strict
            // subset of the cases that this constraint permits.
            let y_check = (y_p.clone() - y_a.clone()) * (y_p.clone() + y_a.clone());

            // Check that the correct sign is witnessed s.t. sign * y_p = y_a
            let negation_check = sign * y_p - y_a;

            // last_window_check, sign_check, y_check, negation_check
            Constraints::with_selector(
                q_mul_fixed_short,
                [last_window_check, sign_check, y_check, negation_check],
            )
        });
    }

    /// Constraints `magnitude` to be at most 66 bits.
    ///
    /// The final window is separately constrained to be a single bit, which
    /// completes the 64-bit range constraint.
    fn decompose(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        magnitude_sign: MagnitudeSign,
    ) -> Result<EccScalarFixedShort, Error> {
        let (magnitude, sign) = magnitude_sign;

        // Decompose magnitude
        let running_sum = self.super_config.running_sum_config.copy_decompose(
            region,
            offset,
            magnitude.clone(),
            true,
            L_SCALAR_SHORT,
            NUM_WINDOWS_SHORT,
        )?;
        assert_eq!(running_sum.len(), NUM_WINDOWS_SHORT + 1);

        Ok(EccScalarFixedShort {
            magnitude,
            sign,
            running_sum: Some((*running_sum).clone()),
        })
    }

    /// `[magnitude * sign]base`, and the scalar with its running sum.
    pub(crate) fn assign(
        &self,
        layouter: &mut Layouter<'_>,
        scalar: &EccScalarFixedShort,
        base: &OrchardShortScalarBases,
    ) -> Result<(EccPoint, EccScalarFixedShort), Error> {
        let (scalar, acc, mul_b) = layouter.assign_region(|mut region| {
            let offset = 0;

            // Decompose the scalar
            let scalar = match scalar.running_sum {
                None => self.decompose(
                    &mut region,
                    offset,
                    (scalar.magnitude.clone(), scalar.sign.clone()),
                ),
                Some(_) => unimplemented!("reusing a decomposed scalar"),
            }?;

            let (acc, mul_b) = self.super_config.assign_region_inner(
                &mut region,
                offset,
                &(&scalar).into(),
                base,
                self.super_config.running_sum_config.q_range_check(),
                NUM_WINDOWS_SHORT,
            )?;

            Ok((scalar, acc, mul_b))
        })?;

        // Last window
        let result = layouter.assign_region(|mut region| {
            let offset = 0;
            // Add to the cumulative sum to get `[magnitude]B`.
            let magnitude_mul = self.super_config.add_config.assign_region(
                &mul_b.clone().into(),
                &acc.clone().into(),
                offset,
                &mut region,
            )?;

            // Increase offset by 1 after complete addition
            let offset = offset + 1;

            // Copy sign to `window` column
            let sign = scalar
                .sign
                .copy_advice(&mut region, self.super_config.window, offset)?;

            // Copy last window to `u` column.
            // (Although the last window is not a `u` value; we are just
            // using a free column.)
            let z_21 = scalar.running_sum.as_ref().unwrap()[21].clone();
            z_21.copy_advice(&mut region, self.super_config.u, offset)?;

            // Conditionally negate `y`-coordinate
            let y_val = sign.value().and_then(|sign| {
                if sign == &-Fp::ONE {
                    -magnitude_mul.y.value().copied()
                } else {
                    magnitude_mul.y.value().copied()
                }
            });

            // Enable mul_fixed_short selector on final row
            self.q_mul_fixed_short.enable(&mut region, offset)?;

            // Assign final `y` to `y_p` column and return final point
            let y_var = region.assign_advice(self.super_config.add_config.y_p, offset, || y_val)?;

            Ok(EccPoint::from_coordinates_unchecked(magnitude_mul.x, y_var))
        })?;

        #[cfg(test)]
        // Check that the correct multiple is obtained.
        // This inlined test is only done for valid 64-bit magnitudes
        // and valid +/- 1 signs.
        // Invalid values result in constraint failures which are
        // tested at the circuit-level.
        {
            use super::super::FixedPoint;
            use crate::orchard::Fq;

            scalar
                .magnitude
                .value()
                .zip(scalar.sign.value())
                .zip(result.point())
                .assert_if_known(|((magnitude, sign), result)| {
                    let magnitude_is_valid = magnitude.to_raw()[1..] == [0, 0, 0];
                    let sign_is_valid = sign.square() == Fp::ONE;
                    // Only check the result if the magnitude and sign are valid.
                    !(magnitude_is_valid && sign_is_valid) || {
                        let scalar = {
                            // Move magnitude from base field into scalar field
                            let magnitude = Fq::from_bytes(&magnitude.to_bytes()).unwrap();

                            // Move sign from base field into scalar field
                            let sign = if **sign == Fp::ONE { Fq::ONE } else { -Fq::ONE };

                            magnitude * sign
                        };
                        let real_mul = base.generator().to_point().mul(&scalar).to_affine();

                        real_mul.x() == result.x() && real_mul.y() == result.y()
                    }
                });
        }

        Ok((result, scalar))
    }
}
