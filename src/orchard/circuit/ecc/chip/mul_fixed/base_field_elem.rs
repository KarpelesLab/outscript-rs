//! Fixed-base multiplication by a base field element (port of
//! `halo2_gadgets::ecc::chip::mul_fixed::base_field_elem`).

use super::super::{EccBaseFieldElemFixed, EccPoint, H, NUM_WINDOWS, OrchardBaseFieldBases, T_P};
use crate::orchard::Fp;
use crate::orchard::circuit::utilities::lookup_range_check::LookupRangeCheckConfig;
use crate::orchard::circuit::utilities::{bitrange_subset, bool_check, range_check};
use crate::orchard::halo2::Error;
use crate::orchard::halo2::circuit::{AssignedCell, Layouter};
use crate::orchard::halo2::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Expression, Rotation, Selector,
};

/// The number of bits of a Pallas base field element
/// (`pallas::Base::NUM_BITS`).
const BASE_NUM_BITS: usize = 255;

/// The configuration of the fixed-base multiplication by a base field
/// element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Config {
    q_mul_fixed_base_field: Selector,
    canon_advices: [Column<Advice>; 3],
    lookup_config: LookupRangeCheckConfig,
    super_config: super::Config,
}

impl Config {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem,
        canon_advices: [Column<Advice>; 3],
        lookup_config: LookupRangeCheckConfig,
        super_config: super::Config,
    ) -> Self {
        for advice in canon_advices.iter() {
            meta.enable_equality(*advice);
        }

        let config = Self {
            q_mul_fixed_base_field: meta.selector(),
            canon_advices,
            lookup_config,
            super_config,
        };

        let add_incomplete_advices = config.super_config.add_incomplete_config.advice_columns();
        for canon_advice in config.canon_advices.iter() {
            assert!(
                !add_incomplete_advices.contains(canon_advice),
                "Deconflict canon_advice columns with incomplete addition columns."
            );
        }

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) {
        // Check that the base field element is canonical.
        // https://p.z.cash/halo2-0.1:ecc-fixed-mul-base-canonicity
        meta.create_gate("Canonicity checks", |meta| {
            let q_mul_fixed_base_field = meta.query_selector(self.q_mul_fixed_base_field);

            let alpha = meta.query_advice(self.canon_advices[0], Rotation::prev());
            // The last three bits of α.
            let z_84_alpha = meta.query_advice(self.canon_advices[2], Rotation::prev());

            // Decompose α into three pieces, in little-endian order:
            //            α = α_0 (252 bits)  || α_1 (2 bits) || α_2 (1 bit).
            //
            // α_0 is derived, not witnessed.
            let alpha_0 = {
                let two_pow_252 = Fp::from_u128(1 << 126).square();
                alpha - (z_84_alpha.clone() * two_pow_252)
            };
            let alpha_1 = meta.query_advice(self.canon_advices[1], Rotation::cur());
            let alpha_2 = meta.query_advice(self.canon_advices[2], Rotation::cur());

            let alpha_0_prime = meta.query_advice(self.canon_advices[0], Rotation::cur());
            let z_13_alpha_0_prime = meta.query_advice(self.canon_advices[0], Rotation::next());
            let z_44_alpha = meta.query_advice(self.canon_advices[1], Rotation::next());
            let z_43_alpha = meta.query_advice(self.canon_advices[2], Rotation::next());

            let decomposition_checks = {
                // Range-constrain α_1 to be 2 bits
                let alpha_1_range_check = range_check(alpha_1.clone(), 1 << 2);
                // Boolean-constrain α_2
                let alpha_2_range_check = bool_check(alpha_2.clone());
                // Check that α_1 + 2^2 α_2 = z_84_alpha
                let z_84_alpha_check =
                    z_84_alpha.clone() - (alpha_1.clone() + alpha_2.clone() * Fp::from_u64(1 << 2));

                // alpha_1_range_check, alpha_2_range_check, z_84_alpha_check
                [alpha_1_range_check, alpha_2_range_check, z_84_alpha_check]
            };

            // Check α_0_prime = α_0 + 2^130 - t_p
            let alpha_0_prime_check = {
                let two_pow_130 = Expression::Constant(Fp::from_u128(1 << 65).square());
                let t_p = Expression::Constant(Fp::from_u128(T_P));
                alpha_0_prime - (alpha_0 + two_pow_130 - t_p)
            };

            // We want to enforce canonicity of a 255-bit base field element, α.
            // That is, we want to check that 0 ≤ α < p, where p is Pallas base
            // field modulus p = 2^254 + t_p
            //                 = 2^254 + 45560315531419706090280762371685220353.
            // Note that t_p < 2^130.
            //
            // α can only be non-canonical if α_2 = 1, so the checks below are
            // gated by α_2.
            let canon_checks = {
                // If the MSB is 1, the next two bits must be 0.
                // α_0_hi_120 = z_44 - 2^120 z_84
                let alpha_0_hi_120 = {
                    let two_pow_120 = Expression::Constant(Fp::from_u128(1 << 60).square());
                    z_44_alpha.clone() - z_84_alpha * two_pow_120
                };
                // a_43 = z_43 - (2^3)z_44
                let a_43 = z_43_alpha - z_44_alpha * Fp::from_u64(H as u64);

                [
                    // MSB = 1 => alpha_1 = 0
                    alpha_2.clone() * alpha_1,
                    // MSB = 1 => alpha_0_hi_120 = 0
                    alpha_2.clone() * alpha_0_hi_120,
                    // MSB = 1 => a_43 = 0 or 1
                    alpha_2.clone() * bool_check(a_43),
                    // MSB = 1 => z_13_alpha_0_prime = 0
                    alpha_2 * z_13_alpha_0_prime,
                ]
            };

            Constraints::with_selector(
                q_mul_fixed_base_field,
                canon_checks
                    .into_iter()
                    .chain(decomposition_checks)
                    // alpha_0_prime check
                    .chain(Some(alpha_0_prime_check)),
            )
        });
    }

    /// `[scalar]base`, the scalar being a base field element.
    pub(crate) fn assign(
        &self,
        layouter: &mut Layouter<'_>,
        scalar: AssignedCell<Fp>,
        base: &OrchardBaseFieldBases,
    ) -> Result<EccPoint, Error> {
        let (scalar, acc, mul_b) = layouter.assign_region(|mut region| {
            let offset = 0;

            // Decompose scalar
            let scalar = {
                let running_sum = self.super_config.running_sum_config.copy_decompose(
                    &mut region,
                    offset,
                    scalar.clone(),
                    true,
                    BASE_NUM_BITS,
                    NUM_WINDOWS,
                )?;
                assert_eq!(running_sum.len(), NUM_WINDOWS + 1);
                EccBaseFieldElemFixed {
                    base_field_elem: running_sum[0].clone(),
                    running_sum: (*running_sum).clone(),
                }
            };

            let (acc, mul_b) = self.super_config.assign_region_inner(
                &mut region,
                offset,
                &(&scalar).into(),
                base,
                self.super_config.running_sum_config.q_range_check(),
                NUM_WINDOWS,
            )?;

            Ok((scalar, acc, mul_b))
        })?;

        // Add to the accumulator and return the final result as `[scalar]B`.
        let result = layouter.assign_region(|mut region| {
            self.super_config.add_config.assign_region(
                &mul_b.clone().into(),
                &acc.clone().into(),
                0,
                &mut region,
            )
        })?;

        #[cfg(test)]
        // Check that the correct multiple is obtained.
        {
            use super::super::FixedPoint;
            use crate::orchard::Fq;

            let scalar = &scalar
                .base_field_elem()
                .value()
                .map(|scalar| Fq::from_bytes(&scalar.to_bytes()).unwrap());
            let real_mul = scalar.map(|scalar| base.generator().to_point().mul(&scalar));
            let result = result.point();

            real_mul.zip(result).assert_if_known(|(real_mul, result)| {
                let real_mul = real_mul.to_affine();
                real_mul.x() == result.x() && real_mul.y() == result.y()
            });
        }

        // We want to enforce canonicity of a 255-bit base field element, α.
        // That is, we want to check that 0 ≤ α < p, where p is Pallas base
        // field modulus p = 2^254 + t_p
        //                 = 2^254 + 45560315531419706090280762371685220353.
        // Note that t_p < 2^130.
        //
        // We decompose α into three pieces, in little-endian order:
        //            α = α_0 (252 bits)  || α_1 (2 bits) || α_2 (1 bit).
        //
        // If the MSB α_2 = 1, then:
        // - α_2 = 1 => α_1 = 0, and
        // - α_2 = 1 => α_0 < t_p. To enforce this:
        //      - α_2 = 1 => 0 ≤ α_0 < 2^130
        //           - alpha_0_hi_120 = 0 (constrain α_0 to be 132 bits)
        //           - a_43 = 0 or 1 (constrain α_0[130..=131] to be 0)
        //      - α_2 = 1 => 0 ≤ α_0 + 2^130 - t_p < 2^130
        //           => 13 ten-bit lookups of α_0 + 2^130 - t_p
        //           => z_13_alpha_0_prime = 0
        //
        let (alpha, running_sum) = (scalar.base_field_elem, &scalar.running_sum);
        let z_43_alpha = running_sum[43].clone();
        let z_44_alpha = running_sum[44].clone();
        let z_84_alpha = running_sum[84].clone();

        // α_0 = α - z_84_alpha * 2^252
        let alpha_0 = alpha
            .value()
            .zip(z_84_alpha.value())
            .map(|(alpha, z_84_alpha)| {
                let two_pow_252 = Fp::from_u128(1 << 126).square();
                *alpha - *z_84_alpha * two_pow_252
            });

        let (alpha_0_prime, z_13_alpha_0_prime) = {
            // alpha_0_prime = alpha + 2^130 - t_p.
            let alpha_0_prime = alpha_0.map(|alpha_0| {
                let two_pow_130 = Fp::from_u128(1 << 65).square();
                let t_p = Fp::from_u128(T_P);
                alpha_0 + two_pow_130 - t_p
            });
            let zs =
                self.lookup_config
                    .witness_check(layouter.namespace(), alpha_0_prime, 13, false)?;
            let alpha_0_prime = zs[0].clone();

            (alpha_0_prime, zs[13].clone())
        };

        layouter.assign_region(|mut region| {
            // Activate canonicity check gate
            self.q_mul_fixed_base_field.enable(&mut region, 1)?;

            // Offset 0
            {
                let offset = 0;

                // Copy α
                alpha.copy_advice(&mut region, self.canon_advices[0], offset)?;

                // z_84_alpha = the top three bits of alpha.
                z_84_alpha.copy_advice(&mut region, self.canon_advices[2], offset)?;
            }

            // Offset 1
            {
                let offset = 1;
                // Copy alpha_0_prime = alpha_0 + 2^130 - t_p.
                // We constrain this in the custom gate to be derived correctly.
                alpha_0_prime.copy_advice(&mut region, self.canon_advices[0], offset)?;

                // Decompose α into three pieces,
                //     α = α_0 (252 bits)  || α_1 (2 bits) || α_2 (1 bit).
                // We only need to witness α_1 and α_2. α_0 is derived using:
                //     α_0 = α - z_84_alpha * 2^252

                // Witness the MSB α_2 = α[254]
                let alpha_1 = alpha.value().map(|alpha| bitrange_subset(alpha, 252..254));
                region.assign_advice(self.canon_advices[1], offset, || alpha_1)?;

                // Witness the MSB α_2 = α[254]
                let alpha_2 = alpha.value().map(|alpha| bitrange_subset(alpha, 254..255));
                region.assign_advice(self.canon_advices[2], offset, || alpha_2)?;
            }

            // Offset 2
            {
                let offset = 2;
                // Copy z_13_alpha_0_prime
                z_13_alpha_0_prime.copy_advice(&mut region, self.canon_advices[0], offset)?;

                // Copy z_44_alpha
                z_44_alpha.copy_advice(&mut region, self.canon_advices[1], offset)?;

                // Copy z_43_alpha
                z_43_alpha.copy_advice(&mut region, self.canon_advices[2], offset)?;
            }

            Ok(())
        })?;

        Ok(result)
    }
}
