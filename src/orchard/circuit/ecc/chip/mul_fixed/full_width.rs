//! Fixed-base multiplication by a full-width scalar (port of
//! `halo2_gadgets::ecc::chip::mul_fixed::full_width`).

use alloc::vec::Vec;

use super::super::{
    EccPoint, EccScalarFixed, FIXED_BASE_WINDOW_SIZE, H, NUM_WINDOWS, OrchardFixedBasesFull,
};
use crate::orchard::circuit::utilities::{decompose_word, range_check};
use crate::orchard::halo2::circuit::{AssignedCell, Layouter, Region};
use crate::orchard::halo2::plonk::{ConstraintSystem, Constraints, Rotation, Selector};
use crate::orchard::halo2::{Error, Value};
use crate::orchard::{Fp, Fq};

/// The number of bits of a Pallas scalar (`pallas::Scalar::NUM_BITS`).
const SCALAR_NUM_BITS: usize = 255;

/// The configuration of the full-width fixed-base multiplication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Config {
    q_mul_fixed_full: Selector,
    super_config: super::Config,
}

impl Config {
    pub(crate) fn configure(meta: &mut ConstraintSystem, super_config: super::Config) -> Self {
        let config = Self {
            q_mul_fixed_full: meta.selector(),
            super_config,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) {
        // Check that each window `k` is within 3 bits
        // https://p.z.cash/halo2-0.1:ecc-fixed-mul-full-word
        meta.create_gate("Full-width fixed-base scalar mul", |meta| {
            let q_mul_fixed_full = meta.query_selector(self.q_mul_fixed_full);
            let window = meta.query_advice(self.super_config.window, Rotation::cur());

            Constraints::with_selector(
                q_mul_fixed_full,
                self.super_config
                    // check x, check y, on-curve
                    .coords_check(meta, window.clone())
                    .into_iter()
                    // 1 * (window - 0) * (window - 1) * ... * (window - 7)
                    // window range check
                    .chain(Some(range_check(window, H))),
            )
        });
    }

    /// Witnesses the given scalar as `NUM_WINDOWS` 3-bit windows.
    ///
    /// The scalar is allowed to be non-canonical.
    fn witness(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        scalar: Value<Fq>,
    ) -> Result<EccScalarFixed, Error> {
        let windows = self.decompose_scalar_fixed::<SCALAR_NUM_BITS>(scalar, offset, region)?;

        Ok(EccScalarFixed {
            value: scalar,
            windows: Some(windows),
        })
    }

    /// Witnesses the given scalar as `NUM_WINDOWS` 3-bit windows.
    ///
    /// The scalar is allowed to be non-canonical.
    fn decompose_scalar_fixed<const SCALAR_NUM_BITS: usize>(
        &self,
        scalar: Value<Fq>,
        offset: usize,
        region: &mut Region<'_, '_>,
    ) -> Result<Vec<AssignedCell<Fp>>, Error> {
        // Enable `q_mul_fixed_full` selector
        for idx in 0..NUM_WINDOWS {
            self.q_mul_fixed_full.enable(region, offset + idx)?;
        }

        // Decompose scalar into `k-bit` windows
        let scalar_windows: Value<Vec<u8>> = scalar
            .map(|scalar| decompose_word::<Fq>(&scalar, SCALAR_NUM_BITS, FIXED_BASE_WINDOW_SIZE));

        // Transpose `Value<Vec<u8>>` into `Vec<Value<Fp>>`.
        let scalar_windows = scalar_windows
            .map(|windows| {
                windows
                    .into_iter()
                    .map(|window| Fp::from_u64(window as u64))
            })
            .transpose_vec(NUM_WINDOWS);

        // Store the scalar decomposition
        let mut windows: Vec<AssignedCell<Fp>> = Vec::with_capacity(NUM_WINDOWS);
        for (idx, window) in scalar_windows.into_iter().enumerate() {
            let window_cell =
                region.assign_advice(self.super_config.window, offset + idx, || window)?;
            windows.push(window_cell);
        }

        Ok(windows)
    }

    /// `[scalar]base`, and the scalar with its windows.
    pub(crate) fn assign(
        &self,
        layouter: &mut Layouter<'_>,
        scalar: &EccScalarFixed,
        base: &OrchardFixedBasesFull,
    ) -> Result<(EccPoint, EccScalarFixed), Error> {
        let (scalar, acc, mul_b) = layouter.assign_region(|mut region| {
            let offset = 0;

            // Lazily witness the scalar.
            let scalar = match scalar.windows {
                None => self.witness(&mut region, offset, scalar.value),
                Some(_) => unimplemented!("reusing a witnessed scalar"),
            }?;

            let (acc, mul_b) = self.super_config.assign_region_inner(
                &mut region,
                offset,
                &(&scalar).into(),
                base,
                self.q_mul_fixed_full,
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

            let real_mul = scalar
                .value
                .map(|scalar| base.generator().to_point().mul(&scalar));
            let result = result.point();

            real_mul.zip(result).assert_if_known(|(real_mul, result)| {
                let real_mul = real_mul.to_affine();
                real_mul.x() == result.x() && real_mul.y() == result.y()
            });
        }

        Ok((result, scalar))
    }
}
