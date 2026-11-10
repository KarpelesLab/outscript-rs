//! Decomposes an $n$-bit field element $\alpha$ into $W$ windows, each
//! window being a $K$-bit word, using a running sum $z$ (port of
//! `halo2_gadgets::utilities::decompose_running_sum`). $K \leq 3$.
//!     $$\alpha = k_0 + (2^K) k_1 + (2^{2K}) k_2 + ... + (2^{(W-1)K}) k_{W-1}$$
//!
//! $z_0$ is initialized as $\alpha$. Each successive $z_{i+1}$ is computed
//! as $z_{i+1} = (z_{i} - k_i) / (2^K)$, and $z_W$ is constrained to be zero
//! (in strict mode). The difference between each interstitial running sum
//! output is constrained to be $K$ bits, i.e. `range_check`($k_i$, $2^K$).
//!
//! When $K \cdot W \geq 255$ the decomposition is not unique: a canonical
//! decomposition needs an overflow check external to this gadget.

use alloc::vec;
use alloc::vec::Vec;

use super::range_check;
use crate::orchard::Fp;
use crate::orchard::halo2::circuit::{AssignedCell, Region};
use crate::orchard::halo2::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Rotation, Selector,
};
use crate::orchard::halo2::{Error, Value};

/// The running sum $[z_0, ..., z_W]$. If created in strict mode, $z_W = 0$.
#[derive(Debug)]
pub(crate) struct RunningSum(Vec<AssignedCell<Fp>>);

impl core::ops::Deref for RunningSum {
    type Target = Vec<AssignedCell<Fp>>;

    fn deref(&self) -> &Vec<AssignedCell<Fp>> {
        &self.0
    }
}

/// Configuration that provides methods for running sum decomposition.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct RunningSumConfig<const WINDOW_NUM_BITS: usize> {
    q_range_check: Selector,
    z: Column<Advice>,
}

impl<const WINDOW_NUM_BITS: usize> RunningSumConfig<WINDOW_NUM_BITS> {
    /// Returns the q_range_check selector of this [`RunningSumConfig`].
    pub(crate) fn q_range_check(&self) -> Selector {
        self.q_range_check
    }

    /// `perm` MUST include the advice column `z`.
    ///
    /// # Panics
    /// Panics if WINDOW_NUM_BITS > 3.
    ///
    /// # Side-effects
    /// `z` will be equality-enabled.
    pub(crate) fn configure(
        meta: &mut ConstraintSystem,
        q_range_check: Selector,
        z: Column<Advice>,
    ) -> Self {
        assert!(WINDOW_NUM_BITS <= 3);

        meta.enable_equality(z);

        let config = Self { q_range_check, z };

        // https://p.z.cash/halo2-0.1:decompose-short-range
        meta.create_gate("range check", |meta| {
            let q_range_check = meta.query_selector(config.q_range_check);
            let z_cur = meta.query_advice(config.z, Rotation::cur());
            let z_next = meta.query_advice(config.z, Rotation::next());
            //    z_i = 2^{K}⋅z_{i + 1} + k_i
            // => k_i = z_i - 2^{K}⋅z_{i + 1}
            let word = z_cur - z_next * Fp::from_u64(1 << WINDOW_NUM_BITS);

            Constraints::with_selector(q_range_check, Some(range_check(word, 1 << WINDOW_NUM_BITS)))
        });

        config
    }

    /// Decompose a field element alpha that is witnessed in this helper.
    ///
    /// `strict` = true constrains the final running sum to be zero, i.e.
    /// constrains alpha to be within WINDOW_NUM_BITS * num_windows bits.
    pub(crate) fn witness_decompose(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        alpha: Value<Fp>,
        strict: bool,
        word_num_bits: usize,
        num_windows: usize,
    ) -> Result<RunningSum, Error> {
        let z_0 = region.assign_advice(self.z, offset, || alpha)?;
        self.decompose(region, offset, z_0, strict, word_num_bits, num_windows)
    }

    /// Decompose an existing variable alpha that is copied into this helper.
    ///
    /// `strict` = true constrains the final running sum to be zero, i.e.
    /// constrains alpha to be within WINDOW_NUM_BITS * num_windows bits.
    pub(crate) fn copy_decompose(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        alpha: AssignedCell<Fp>,
        strict: bool,
        word_num_bits: usize,
        num_windows: usize,
    ) -> Result<RunningSum, Error> {
        let z_0 = alpha.copy_advice(region, self.z, offset)?;
        self.decompose(region, offset, z_0, strict, word_num_bits, num_windows)
    }

    /// `z_0` must be the cell at `(self.z, offset)` in `region`.
    ///
    /// # Panics
    /// Panics if there are too many windows for the given word size.
    fn decompose(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        z_0: AssignedCell<Fp>,
        strict: bool,
        word_num_bits: usize,
        num_windows: usize,
    ) -> Result<RunningSum, Error> {
        // Make sure that we do not have more windows than required for the
        // number of bits in the word. In other words, every window must
        // contain at least one bit of the word (no empty windows).
        assert!(WINDOW_NUM_BITS * num_windows < word_num_bits + WINDOW_NUM_BITS);

        // Enable selectors
        for idx in 0..num_windows {
            self.q_range_check.enable(region, offset + idx)?;
        }

        // Decompose base field element into K-bit words.
        let words = z_0
            .value()
            .map(|word| super::decompose_word::<Fp>(word, word_num_bits, WINDOW_NUM_BITS))
            .transpose_vec(num_windows);

        // Initialize empty vector to store running sum values [z_0, ..., z_W].
        let mut zs: Vec<AssignedCell<Fp>> = vec![z_0.clone()];
        let mut z = z_0;

        // Assign running sum `z_{i+1}` = (z_i - k_i) / (2^K) for i = 0..=n-1.
        // Outside of this helper, z_0 = alpha must have already been loaded
        // into the `z` column at `offset`.
        let two_pow_k_inv = Value::known(Fp::from_u64(1 << WINDOW_NUM_BITS).invert_or_zero());
        for (i, word) in words.iter().enumerate() {
            // z_next = (z_cur - word) / (2^K)
            let z_next = {
                let z_cur_val = z.value().copied();
                let word = word.map(|word| Fp::from_u64(word as u64));
                let z_next_val = (z_cur_val - word) * two_pow_k_inv;
                region.assign_advice(self.z, offset + i + 1, || z_next_val)?
            };

            // Update `z`.
            z = z_next;
            zs.push(z.clone());
        }
        assert_eq!(zs.len(), num_windows + 1);

        if strict {
            // Constrain the final running sum output to be zero.
            region.constrain_constant(zs.last().expect("z_0 is there").cell(), Fp::ZERO)?;
        }

        Ok(RunningSum(zs))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::super::test_dump::{layout_digest, pinned_digest};
    use super::*;
    use crate::orchard::halo2::circuit::{Circuit, Layouter};
    use crate::orchard::halo2::dev::MockProver;

    /// `ecc::chip::FIXED_BASE_WINDOW_SIZE`.
    const FIXED_BASE_WINDOW_SIZE: usize = 3;
    /// `ecc::chip::NUM_WINDOWS`.
    const NUM_WINDOWS: usize = 85;
    /// `ecc::chip::NUM_WINDOWS_SHORT`.
    const NUM_WINDOWS_SHORT: usize = 22;
    /// `ecc::chip::L_SCALAR_SHORT`.
    const L_SHORT: usize = 64;
    /// `pallas::Base::NUM_BITS`.
    const L_BASE: usize = 255;

    /// The `test_running_sum` circuit of the reference.
    struct MyCircuit<
        const WORD_NUM_BITS: usize,
        const WINDOW_NUM_BITS: usize,
        const NUM_WINDOWS: usize,
    > {
        alpha: Value<Fp>,
        strict: bool,
    }

    impl<const WORD_NUM_BITS: usize, const WINDOW_NUM_BITS: usize, const NUM_WINDOWS: usize> Circuit
        for MyCircuit<WORD_NUM_BITS, WINDOW_NUM_BITS, NUM_WINDOWS>
    {
        type Config = RunningSumConfig<WINDOW_NUM_BITS>;

        fn without_witnesses(&self) -> Self {
            Self {
                alpha: Value::unknown(),
                strict: self.strict,
            }
        }

        fn configure(&self, meta: &mut ConstraintSystem) -> Self::Config {
            let z = meta.advice_column();
            let q_range_check = meta.selector();
            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            RunningSumConfig::<WINDOW_NUM_BITS>::configure(meta, q_range_check, z)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: &mut Layouter<'_>,
        ) -> Result<(), Error> {
            layouter.assign_region(|mut region| {
                let offset = 0;
                let zs = config.witness_decompose(
                    &mut region,
                    offset,
                    self.alpha,
                    self.strict,
                    WORD_NUM_BITS,
                    NUM_WINDOWS,
                )?;
                let alpha = zs[0].clone();

                let offset = offset + NUM_WINDOWS + 1;

                config.copy_decompose(
                    &mut region,
                    offset,
                    alpha,
                    self.strict,
                    WORD_NUM_BITS,
                    NUM_WINDOWS,
                )?;

                Ok(())
            })
        }
    }

    type Full = MyCircuit<L_BASE, FIXED_BASE_WINDOW_SIZE, NUM_WINDOWS>;
    type Short = MyCircuit<L_SHORT, FIXED_BASE_WINDOW_SIZE, NUM_WINDOWS_SHORT>;

    /// The base field element the reference dump was made with.
    fn full_alpha() -> Fp {
        Fp::from_raw([
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            0x0f1e_2d3c_4b5a_6978,
            0x1234_5678_9abc_def0,
        ])
    }

    /// The 64-bit word the reference dump was made with.
    const SHORT_ALPHA: u64 = 0xd1b5_4a32_d192_ed03;

    #[test]
    fn test_running_sum() {
        // Base field elements: strict full decomposition should pass.
        for alpha in [full_alpha(), Fp::ZERO, -Fp::ONE, full_alpha().square()] {
            let circuit: Full = MyCircuit {
                alpha: Value::known(alpha),
                strict: true,
            };
            let prover = MockProver::run(8, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }

        // 64-bit words: strict full decomposition should pass.
        for alpha in [SHORT_ALPHA, 0, u64::MAX] {
            let circuit: Short = MyCircuit {
                alpha: Value::known(Fp::from_u64(alpha)),
                strict: true,
            };
            let prover = MockProver::run(8, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }

        // 2^66
        {
            let alpha = Fp::from_u128(1 << 66);

            // Strict partial decomposition should fail.
            let circuit: Short = MyCircuit {
                alpha: Value::known(alpha),
                strict: true,
            };
            let prover = MockProver::run(8, &circuit, vec![]).unwrap();
            let err = prover.verify().unwrap_err();
            assert_eq!(err.matches("copy constraint").count(), 2, "{err}");
            assert!(!err.contains("gate"), "{err}");

            // Non-strict partial decomposition should pass.
            let circuit: Short = MyCircuit {
                alpha: Value::known(alpha),
                strict: false,
            };
            let prover = MockProver::run(8, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    /// The gate and the layouts are those of the reference (see
    /// `utilities::test_dump`).
    #[test]
    fn running_sum_matches_reference() {
        let full: Full = MyCircuit {
            alpha: Value::known(full_alpha()),
            strict: true,
        };
        assert_eq!(
            pinned_digest(&full),
            "3095:467b6864f8d03bfa347e66d7c7ba0f722834704ed6e283fb518507365214e8d6"
        );
        assert_eq!(
            layout_digest(8, &full),
            "16015:907dd6697d261994c7159231a903d01f7036db0afb12b3aa15eef4a49ece865f"
        );

        let short: Short = MyCircuit {
            alpha: Value::known(Fp::from_u64(SHORT_ALPHA)),
            strict: true,
        };
        assert_eq!(
            layout_digest(8, &short),
            "4154:527a48d723134ac8aed386911c13d9b45cf5ec7209727358356d94c22ac0679f"
        );

        let lax: Short = MyCircuit {
            alpha: Value::known(Fp::from_u128(1 << 66)),
            strict: false,
        };
        assert_eq!(
            layout_digest(8, &lax),
            "4258:45e9e9a3d1bc95527e726d25fc354e675e058f5144e01f26c9bb2af7d1e2b94a"
        );
    }
}
