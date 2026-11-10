//! Gadget and chip for a conditional swap (port of
//! `halo2_gadgets::utilities::cond_swap`, without the `mux` additions the
//! Orchard Action circuit does not use).

use super::{bool_check, ternary};
use crate::orchard::Fp;
use crate::orchard::halo2::circuit::{AssignedCell, Layouter};
use crate::orchard::halo2::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Rotation, Selector,
};
use crate::orchard::halo2::{Error, Value};

/// A chip implementing a conditional swap.
#[derive(Clone, Debug)]
pub(crate) struct CondSwapChip {
    config: CondSwapConfig,
}

/// Configuration for the [`CondSwapChip`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CondSwapConfig {
    q_swap: Selector,
    a: Column<Advice>,
    b: Column<Advice>,
    a_swapped: Column<Advice>,
    b_swapped: Column<Advice>,
    swap: Column<Advice>,
}

#[cfg(test)]
impl CondSwapConfig {
    /// The column of the first element of the pair.
    pub(crate) fn a(&self) -> Column<Advice> {
        self.a
    }
}

impl CondSwapChip {
    /// The configuration of the chip.
    pub(crate) fn config(&self) -> &CondSwapConfig {
        &self.config
    }

    /// Given an input pair (a,b) and a `swap` boolean flag, returns
    /// (b,a) if `swap` is set, else (a,b) if `swap` is not set.
    ///
    /// The second element of the pair is required to be a witnessed
    /// value, not a variable that already exists in the circuit.
    #[allow(clippy::type_complexity)]
    pub(crate) fn swap(
        &self,
        layouter: &mut Layouter<'_>,
        pair: (AssignedCell<Fp>, Value<Fp>),
        swap: Value<bool>,
    ) -> Result<(AssignedCell<Fp>, AssignedCell<Fp>), Error> {
        let config = self.config();

        layouter.assign_region(|mut region| {
            // Enable `q_swap` selector
            config.q_swap.enable(&mut region, 0)?;

            // Copy in `a` value
            let a = pair.0.copy_advice(&mut region, config.a, 0)?;

            // Witness `b` value
            let b = region.assign_advice(config.b, 0, || pair.1)?;

            // Witness `swap` value
            let swap_val = swap.map(|swap| Fp::from_u64(swap as u64));
            region.assign_advice(config.swap, 0, || swap_val)?;

            // Conditionally swap a
            let a_swapped = {
                let a_swapped = a
                    .value()
                    .zip(b.value())
                    .zip(swap)
                    .map(|((a, b), swap)| if swap { b } else { a })
                    .cloned();
                region.assign_advice(config.a_swapped, 0, || a_swapped)?
            };

            // Conditionally swap b
            let b_swapped = {
                let b_swapped = a
                    .value()
                    .zip(b.value())
                    .zip(swap)
                    .map(|((a, b), swap)| if swap { a } else { b })
                    .cloned();
                region.assign_advice(config.b_swapped, 0, || b_swapped)?
            };

            // Return swapped pair
            Ok((a_swapped, b_swapped))
        })
    }

    /// Configures this chip for use in a circuit.
    ///
    /// # Side-effects
    /// `advices[0]` will be equality-enabled.
    pub(crate) fn configure(
        meta: &mut ConstraintSystem,
        advices: [Column<Advice>; 5],
    ) -> CondSwapConfig {
        let a = advices[0];
        // Only column a is used in an equality constraint directly by this
        // chip.
        meta.enable_equality(a);

        let q_swap = meta.selector();

        let config = CondSwapConfig {
            q_swap,
            a,
            b: advices[1],
            a_swapped: advices[2],
            b_swapped: advices[3],
            swap: advices[4],
        };

        meta.create_gate("a' = b ⋅ swap + a ⋅ (1-swap)", |meta| {
            let q_swap = meta.query_selector(q_swap);

            let a = meta.query_advice(config.a, Rotation::cur());
            let b = meta.query_advice(config.b, Rotation::cur());
            let a_swapped = meta.query_advice(config.a_swapped, Rotation::cur());
            let b_swapped = meta.query_advice(config.b_swapped, Rotation::cur());
            let swap = meta.query_advice(config.swap, Rotation::cur());

            // This checks that `a_swapped` is equal to `b` when `swap` is
            // set, but remains as `a` when `swap` is not set.
            let a_check = a_swapped - ternary(swap.clone(), b.clone(), a.clone());

            // This checks that `b_swapped` is equal to `a` when `swap` is
            // set, but remains as `b` when `swap` is not set.
            let b_check = b_swapped - ternary(swap.clone(), a, b);

            // Check `swap` is boolean.
            let bool_check = bool_check(swap);

            Constraints::with_selector(
                q_swap,
                [
                    // a check
                    a_check, // b check
                    b_check, // swap is bool
                    bool_check,
                ],
            )
        });

        config
    }

    /// Constructs a [`CondSwapChip`] given a [`CondSwapConfig`].
    pub(crate) fn construct(config: CondSwapConfig) -> Self {
        CondSwapChip { config }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::super::load_private;
    use super::super::test_dump::{layout_digest, pinned_digest};
    use super::*;
    use crate::orchard::halo2::circuit::Circuit;
    use crate::orchard::halo2::dev::MockProver;

    /// The `cond_swap` circuit of the reference.
    #[derive(Default)]
    struct MyCondSwapCircuit {
        a: Value<Fp>,
        b: Value<Fp>,
        swap: Value<bool>,
    }

    impl Circuit for MyCondSwapCircuit {
        type Config = CondSwapConfig;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(&self, meta: &mut ConstraintSystem) -> Self::Config {
            let advices = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];

            CondSwapChip::configure(meta, advices)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: &mut Layouter<'_>,
        ) -> Result<(), Error> {
            let chip = CondSwapChip::construct(config.clone());

            // Load the pair and the swap flag into the circuit.
            let a = load_private(layouter.namespace(), config.a(), self.a)?;
            // Return the swapped pair.
            let swapped_pair = chip.swap(layouter.namespace(), (a.clone(), self.b), self.swap)?;

            self.swap
                .zip(a.value().zip(self.b.as_ref()))
                .zip(swapped_pair.0.value().zip(swapped_pair.1.value()))
                .assert_if_known(|((swap, (a, b)), (a_swapped, b_swapped))| {
                    if *swap {
                        // Check that `a` and `b` have been swapped
                        (a_swapped == b) && (b_swapped == a)
                    } else {
                        // Check that `a` and `b` have not been swapped
                        (a_swapped == a) && (b_swapped == b)
                    }
                });

            Ok(())
        }
    }

    /// The witnesses the reference dumps were made with.
    fn circuit(swap: bool) -> MyCondSwapCircuit {
        MyCondSwapCircuit {
            a: Value::known(Fp::from_raw([
                0x0123_4567_89ab_cdef,
                0xfedc_ba98_7654_3210,
                0x0f1e_2d3c_4b5a_6978,
                0x1234_5678_9abc_def0,
            ])),
            b: Value::known(Fp::from_raw([
                0x1111_2222_3333_4444,
                0x5555_6666_7777_8888,
                0x9999_aaaa_bbbb_cccc,
                0x0ddd_eeee_ffff_0000,
            ])),
            swap: Value::known(swap),
        }
    }

    #[test]
    fn cond_swap() {
        for swap in [true, false] {
            let prover = MockProver::run(3, &circuit(swap), vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    /// The gate rejects a pair that is not the swapped (or unswapped) input
    /// and a flag that is not a bit.
    #[test]
    fn cond_swap_gate_is_binding() {
        let base = MockProver::run(3, &circuit(true), vec![]).unwrap();
        let row = base.selectors[0].iter().position(|on| *on).unwrap();
        for column in 0..5 {
            let mut prover = MockProver::run(3, &circuit(true), vec![]).unwrap();
            prover.advice[column][row] += Fp::ONE;
            assert!(prover.verify().is_err(), "column {column}");
        }
    }

    /// The gate and the layouts are those of the reference (see
    /// `utilities::test_dump`).
    #[test]
    fn cond_swap_matches_reference() {
        assert_eq!(
            pinned_digest(&circuit(true)),
            "1872:73aff5690973bd2fbff261ffb3fb8009d5b99d0fc9c2ffa283aec9b428479f8b"
        );
        assert_eq!(
            layout_digest(3, &circuit(true)),
            "508:b15533700792c8f45da841d958d9cb8942fa68cc70099fcb06203ccbdfa5359a"
        );
        assert_eq!(
            layout_digest(3, &circuit(false)),
            "430:99e1342ef4c78d555807fbead2f9f26dd1f7b79c2a74aeaee9a3b4058d15c18f"
        );
    }
}
