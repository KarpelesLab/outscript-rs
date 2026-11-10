//! Make use of a K-bit lookup table to decompose a field element into K-bit
//! words (port of `halo2_gadgets::utilities::lookup_range_check`, for the
//! only configuration Orchard uses: `LookupRangeCheckConfig<pallas::Base,
//! 10>`).

use alloc::vec;
use alloc::vec::Vec;
use core::ops::Range;

use super::{RangeConstrained, bitrange_subset, lebs2ip};
use crate::orchard::Fp;
use crate::orchard::constants::SINSEMILLA_S;
use crate::orchard::halo2::circuit::{AssignedCell, Layouter, Region};
use crate::orchard::halo2::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Expression, Rotation, Selector, TableColumn,
};
use crate::orchard::halo2::{Error, Value};

/// The number of bits of a word of the lookup table (`sinsemilla::K`).
pub(crate) const K: usize = crate::orchard::sinsemilla::K;

/// The number of bits a field element holds without wrapping
/// (`pallas::Base::CAPACITY`).
const CAPACITY: usize = 254;

/// The running sum $[z_0, ..., z_W]$. If created in strict mode, $z_W = 0$.
#[derive(Debug)]
pub(crate) struct RunningSum(Vec<AssignedCell<Fp>>);

impl core::ops::Deref for RunningSum {
    type Target = Vec<AssignedCell<Fp>>;

    fn deref(&self) -> &Vec<AssignedCell<Fp>> {
        &self.0
    }
}

impl RangeConstrained<AssignedCell<Fp>> {
    /// Witnesses a subset of the bits in `value` and constrains them to be
    /// the correct number of bits.
    ///
    /// # Panics
    /// Panics if `bitrange.len() >= K`.
    pub(crate) fn witness_short(
        lookup_config: &LookupRangeCheckConfig,
        layouter: &mut Layouter<'_>,
        value: Value<&Fp>,
        bitrange: Range<usize>,
    ) -> Result<Self, Error> {
        let num_bits = bitrange.len();
        assert!(num_bits < K);

        // Witness the subset and constrain it to be the correct number of
        // bits.
        lookup_config
            .witness_short_check(
                layouter,
                value.map(|value| bitrange_subset(value, bitrange)),
                num_bits,
            )
            .map(|inner| Self { inner, num_bits })
    }
}

/// Configuration that provides methods for a lookup range check.
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub(crate) struct LookupRangeCheckConfig {
    q_lookup: Selector,
    q_running: Selector,
    q_bitshift: Selector,
    running_sum: Column<Advice>,
    table_idx: TableColumn,
}

impl LookupRangeCheckConfig {
    /// The advice column of the running sums.
    pub(crate) fn running_sum(&self) -> Column<Advice> {
        self.running_sum
    }

    /// The table column of the values `[0..2^K)`.
    pub(crate) fn table_idx(&self) -> TableColumn {
        self.table_idx
    }

    /// The `running_sum` advice column breaks the field element into `K`-bit
    /// words. It is used to construct the input expression to the lookup
    /// argument.
    ///
    /// The `table_idx` fixed column contains values from [0..2^K). Looking
    /// up a value in `table_idx` constrains it to be within this range. The
    /// table can be loaded outside this helper.
    ///
    /// # Side-effects
    /// Both the `running_sum` and `constants` columns will be
    /// equality-enabled.
    pub(crate) fn configure(
        meta: &mut ConstraintSystem,
        running_sum: Column<Advice>,
        table_idx: TableColumn,
    ) -> Self {
        meta.enable_equality(running_sum);

        let q_lookup = meta.complex_selector();
        let q_running = meta.complex_selector();
        let q_bitshift = meta.selector();

        let config = LookupRangeCheckConfig {
            q_lookup,
            q_running,
            q_bitshift,
            running_sum,
            table_idx,
        };

        // https://p.z.cash/halo2-0.1:decompose-combined-lookup
        meta.lookup(|meta| {
            let q_lookup = meta.query_selector(config.q_lookup);
            let q_running = meta.query_selector(config.q_running);
            let z_cur = meta.query_advice(config.running_sum, Rotation::cur());
            let one = Expression::Constant(Fp::ONE);

            // In the case of a running sum decomposition, we recover the
            // word from the difference of the running sums:
            //    z_i = 2^{K}⋅z_{i + 1} + a_i
            // => a_i = z_i - 2^{K}⋅z_{i + 1}
            let running_sum_lookup = {
                let running_sum_word = {
                    let z_next = meta.query_advice(config.running_sum, Rotation::next());
                    z_cur.clone() - z_next * Fp::from_u64(1 << K)
                };

                q_running.clone() * running_sum_word
            };

            // In the short range check, the word is directly witnessed.
            let short_lookup = {
                let short_word = z_cur;
                let q_short = one - q_running;

                q_short * short_word
            };

            // Combine the running sum and short lookups:
            vec![(
                q_lookup * (running_sum_lookup + short_lookup),
                config.table_idx,
            )]
        });

        // For short lookups, check that the word has been shifted by the
        // correct number of bits.
        // https://p.z.cash/halo2-0.1:decompose-short-lookup
        meta.create_gate("Short lookup bitshift", |meta| {
            let q_bitshift = meta.query_selector(config.q_bitshift);
            let word = meta.query_advice(config.running_sum, Rotation::prev());
            let shifted_word = meta.query_advice(config.running_sum, Rotation::cur());
            let inv_two_pow_s = meta.query_advice(config.running_sum, Rotation::next());

            let two_pow_k = Fp::from_u64(1 << K);

            // shifted_word = word * 2^{K-s}
            //              = word * 2^K * inv_two_pow_s
            Constraints::with_selector(
                q_bitshift,
                Some(word * two_pow_k * inv_two_pow_s - shifted_word),
            )
        });

        config
    }

    /// Load the generator table into the circuit.
    ///
    /// | table_idx |     table_x    |     table_y    |
    /// ------------------------------------------------
    /// |     0     |    X(S\[0\])   |    Y(S\[0\])   |
    /// |     1     |    X(S\[1\])   |    Y(S\[1\])   |
    /// |    ...    |      ...       |       ...      |
    /// |   2^10-1  | X(S\[2^10-1\]) | Y(S\[2^10-1\]) |
    ///
    /// The reference takes the three columns as a `GeneratorTableConfig`
    /// (of the Sinsemilla chip); here they are passed one by one.
    pub(crate) fn load(
        &self,
        table_idx: TableColumn,
        table_x: TableColumn,
        table_y: TableColumn,
        layouter: &mut Layouter<'_>,
    ) -> Result<(), Error> {
        layouter.assign_table(|mut table| {
            for (index, s) in SINSEMILLA_S.iter().enumerate() {
                table.assign_cell(table_idx, index, || {
                    Value::known(Fp::from_u64(index as u64))
                })?;
                table.assign_cell(table_x, index, || Value::known(s.x()))?;
                table.assign_cell(table_y, index, || Value::known(s.y()))?;
            }
            Ok(())
        })
    }

    /// Fill `table_idx`.
    ///
    /// This is only used in testing, since the Sinsemilla chip provides a
    /// pre-loaded table in the Orchard context.
    #[cfg(test)]
    pub(crate) fn load_range_check_table(&self, layouter: &mut Layouter<'_>) -> Result<(), Error> {
        layouter.assign_table(|mut table| {
            for index in 0..(1 << K) {
                table.assign_cell(self.table_idx, index, || {
                    Value::known(Fp::from_u64(index as u64))
                })?;
            }
            Ok(())
        })
    }

    /// Constrain `x` to be a NUM_BITS word.
    ///
    /// `element` must have been assigned to `self.running_sum` at offset 0.
    pub(crate) fn short_range_check(
        &self,
        region: &mut Region<'_, '_>,
        element: AssignedCell<Fp>,
        num_bits: usize,
    ) -> Result<(), Error> {
        // Enable lookup for `element`.
        self.q_lookup.enable(region, 0)?;

        // Enable lookup for shifted element, to constrain it to 10 bits.
        self.q_lookup.enable(region, 1)?;

        // Check element has been shifted by the correct number of bits.
        self.q_bitshift.enable(region, 1)?;

        // Assign shifted `element * 2^{K - num_bits}`
        let shifted = element.value().copied() * Fp::from_u64(1 << (K - num_bits));

        region.assign_advice(self.running_sum, 1, || shifted)?;

        // Assign 2^{-num_bits} from a fixed column.
        let inv_two_pow_s = Fp::from_u64(1 << num_bits).invert_or_zero();
        region.assign_advice_from_constant(self.running_sum, 2, inv_two_pow_s)?;

        Ok(())
    }

    /// Range check on an existing cell that is copied into this helper.
    ///
    /// Returns an error if `element` is not in a column that was passed to
    /// [`ConstraintSystem::enable_equality`] during circuit configuration.
    pub(crate) fn copy_check(
        &self,
        layouter: &mut Layouter<'_>,
        element: AssignedCell<Fp>,
        num_words: usize,
        strict: bool,
    ) -> Result<RunningSum, Error> {
        layouter.assign_region(|mut region| {
            // Copy `element` and initialize running sum `z_0 = element` to
            // decompose it.
            let z_0 = element.copy_advice(&mut region, self.running_sum, 0)?;
            self.range_check(&mut region, z_0, num_words, strict)
        })
    }

    /// Range check on a value that is witnessed in this helper.
    pub(crate) fn witness_check(
        &self,
        layouter: &mut Layouter<'_>,
        value: Value<Fp>,
        num_words: usize,
        strict: bool,
    ) -> Result<RunningSum, Error> {
        layouter.assign_region(|mut region| {
            let z_0 = region.assign_advice(self.running_sum, 0, || value)?;
            self.range_check(&mut region, z_0, num_words, strict)
        })
    }

    /// If `strict` is set to "true", the field element must fit into
    /// `num_words * K` bits. In other words, the the final cumulative sum
    /// `z_{num_words}` must be zero.
    ///
    /// If `strict` is set to "false", the final `z_{num_words}` is not
    /// constrained.
    ///
    /// `element` must have been assigned to `self.running_sum` at offset 0.
    pub(crate) fn range_check(
        &self,
        region: &mut Region<'_, '_>,
        element: AssignedCell<Fp>,
        num_words: usize,
        strict: bool,
    ) -> Result<RunningSum, Error> {
        // `num_words` must fit into a single field element.
        assert!(num_words * K <= CAPACITY);

        // Chunk the first num_bits bits into K-bit words.
        let words = element
            .value()
            .map(|element| {
                (0..num_words)
                    .map(|w| {
                        let word: [bool; K] = core::array::from_fn(|i| element.bit(w * K + i));
                        Fp::from_u64(lebs2ip::<K>(&word))
                    })
                    .collect::<Vec<_>>()
            })
            .transpose_vec(num_words);

        let mut zs = vec![element.clone()];

        // Assign cumulative sum such that
        //          z_i = 2^{K}⋅z_{i + 1} + a_i
        // => z_{i + 1} = (z_i - a_i) / (2^K)
        //
        // For `element` = a_0 + 2^10 a_1 + ... + 2^{120} a_{12}}, initialize
        // z_0 = `element`. If `element` fits in 130 bits, we end up with
        // z_{13} = 0.
        let mut z = element;
        let inv_two_pow_k = Fp::from_u64(1u64 << K).invert_or_zero();
        for (idx, word) in words.iter().enumerate() {
            // Enable q_lookup on this row
            self.q_lookup.enable(region, idx)?;
            // Enable q_running on this row
            self.q_running.enable(region, idx)?;

            // z_next = (z_cur - m_cur) / 2^K
            z = {
                let z_val = z
                    .value()
                    .zip(*word)
                    .map(|(z, word)| (*z - word) * inv_two_pow_k);

                // Assign z_next
                region.assign_advice(self.running_sum, idx + 1, || z_val)?
            };
            zs.push(z.clone());
        }

        if strict {
            // Constrain the final `z` to be zero.
            region.constrain_constant(zs.last().expect("z_0 is there").cell(), Fp::ZERO)?;
        }

        Ok(RunningSum(zs))
    }

    /// Short range check on an existing cell that is copied into this
    /// helper.
    ///
    /// # Panics
    /// Panics if NUM_BITS is equal to or larger than K.
    pub(crate) fn copy_short_check(
        &self,
        layouter: &mut Layouter<'_>,
        element: AssignedCell<Fp>,
        num_bits: usize,
    ) -> Result<(), Error> {
        assert!(num_bits < K);
        layouter.assign_region(|mut region| {
            // Copy `element` to use in the k-bit lookup.
            let element = element.copy_advice(&mut region, self.running_sum, 0)?;
            self.short_range_check(&mut region, element, num_bits)
        })
    }

    /// Short range check on value that is witnessed in this helper.
    ///
    /// # Panics
    /// Panics if num_bits is larger than K.
    pub(crate) fn witness_short_check(
        &self,
        layouter: &mut Layouter<'_>,
        element: Value<Fp>,
        num_bits: usize,
    ) -> Result<AssignedCell<Fp>, Error> {
        assert!(num_bits <= K);
        layouter.assign_region(|mut region| {
            // Witness `element` to use in the k-bit lookup.
            let element = region.assign_advice(self.running_sum, 0, || element)?;

            self.short_range_check(&mut region, element.clone(), num_bits)?;

            Ok(element)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::load_private;
    use super::super::test_dump::{layout_digest, pinned_digest};
    use super::*;
    use crate::orchard::halo2::circuit::Circuit;
    use crate::orchard::halo2::dev::MockProver;

    /// The `MyLookupCircuit` of the reference.
    #[derive(Clone, Copy)]
    struct MyLookupCircuit {
        num_words: usize,
    }

    fn configure(meta: &mut ConstraintSystem) -> LookupRangeCheckConfig {
        let running_sum = meta.advice_column();
        let table_idx = meta.lookup_table_column();
        let constants = meta.fixed_column();
        meta.enable_constant(constants);

        LookupRangeCheckConfig::configure(meta, running_sum, table_idx)
    }

    impl Circuit for MyLookupCircuit {
        type Config = LookupRangeCheckConfig;

        fn without_witnesses(&self) -> Self {
            *self
        }

        fn configure(&self, meta: &mut ConstraintSystem) -> Self::Config {
            configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: &mut Layouter<'_>,
        ) -> Result<(), Error> {
            // Load table_idx
            config.load_range_check_table(layouter)?;

            // Lookup constraining element to be no longer than num_words * K
            // bits.
            let elements_and_expected_final_zs = [
                // a word that is within self.num_words * K bits long
                (
                    Fp::from_u64((1 << (self.num_words * K)) - 1),
                    Fp::ZERO,
                    true,
                ),
                // a word that is just over self.num_words * K bits long
                (Fp::from_u64(1 << (self.num_words * K)), Fp::ONE, false),
            ];

            fn expected_zs(element: Fp, num_words: usize) -> Vec<Fp> {
                let chunks = (0..num_words)
                    .map(|w| {
                        let word: [bool; K] = core::array::from_fn(|i| element.bit(w * K + i));
                        Fp::from_u64(lebs2ip::<K>(&word))
                    })
                    .collect::<Vec<_>>();
                let inv_two_pow_k = Fp::from_u64(1 << K).invert().unwrap();
                chunks.iter().fold(vec![element], |mut zs, a_i| {
                    // z_{i + 1} = (z_i - a_i) / 2^{K}
                    let z = (zs[zs.len() - 1] - *a_i) * inv_two_pow_k;
                    zs.push(z);
                    zs
                })
            }

            for (element, expected_final_z, strict) in elements_and_expected_final_zs.iter() {
                let expected_zs = expected_zs(*element, self.num_words);

                let zs = config.witness_check(
                    layouter.namespace(),
                    Value::known(*element),
                    self.num_words,
                    *strict,
                )?;

                assert_eq!(*expected_zs.last().unwrap(), *expected_final_z);

                for (expected_z, z) in expected_zs.into_iter().zip(zs.iter()) {
                    z.value().assert_if_known(|z| &&expected_z == z);
                }
            }
            Ok(())
        }
    }

    #[test]
    fn lookup_range_check() {
        let circuit = MyLookupCircuit { num_words: 6 };
        let prover = MockProver::run(11, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    /// The `MyShortRangeCheckCircuit` of the reference.
    #[derive(Clone, Copy)]
    struct MyShortRangeCheckCircuit {
        element: Value<Fp>,
        num_bits: usize,
    }

    impl Circuit for MyShortRangeCheckCircuit {
        type Config = LookupRangeCheckConfig;

        fn without_witnesses(&self) -> Self {
            MyShortRangeCheckCircuit {
                element: Value::unknown(),
                num_bits: self.num_bits,
            }
        }

        fn configure(&self, meta: &mut ConstraintSystem) -> Self::Config {
            configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: &mut Layouter<'_>,
        ) -> Result<(), Error> {
            // Load table_idx
            config.load_range_check_table(layouter)?;

            // Lookup constraining element to be no longer than num_bits.
            config.witness_short_check(layouter.namespace(), self.element, self.num_bits)?;

            Ok(())
        }
    }

    fn short(element: Fp, num_bits: usize) -> MyShortRangeCheckCircuit {
        MyShortRangeCheckCircuit {
            element: Value::known(element),
            num_bits,
        }
    }

    /// `Ok` if the circuit is satisfied, else the number of lookup arguments
    /// that fail (nothing else may; the mock prover reports the first
    /// failing row of a lookup only).
    fn failing_lookup_rows(circuit: &MyShortRangeCheckCircuit) -> Result<(), usize> {
        let prover = MockProver::run(11, circuit, vec![]).unwrap();
        match prover.verify() {
            Ok(()) => Ok(()),
            Err(e) => {
                // Nothing but the lookup fails.
                assert!(!e.contains("gate") && !e.contains("copy"), "{e}");
                Err(e.matches("lookup 0").count())
            }
        }
    }

    #[test]
    fn short_range_check() {
        // Edge case: zero bits (case 0)
        assert_eq!(failing_lookup_rows(&short(Fp::ZERO, 0)), Ok(()));

        // Edge case: K bits (case 1)
        assert_eq!(
            failing_lookup_rows(&short(Fp::from_u64((1 << K) - 1), K)),
            Ok(())
        );

        // Element within `num_bits` (case 2)
        assert_eq!(
            failing_lookup_rows(&short(Fp::from_u64((1 << 6) - 1), 6)),
            Ok(())
        );

        // Element larger than `num_bits` but within K bits: the shifted
        // word is not in the table.
        let circuit = short(Fp::from_u64(1 << 6), 6);
        assert_eq!(failing_lookup_rows(&circuit), Err(1));
        let prover = MockProver::run(11, &circuit, vec![]).unwrap();
        assert!(prover.verify().unwrap_err().contains("on row 1"));

        // Element larger than K bits: neither word is in the table (the
        // mock prover reports the first failing row of a lookup only).
        let circuit = short(Fp::from_u64(1 << K), 6);
        let prover = MockProver::run(11, &circuit, vec![]).unwrap();
        assert!(prover.verify().unwrap_err().contains("on row 0"));
        let mut prover = MockProver::run(11, &circuit, vec![]).unwrap();
        // With the first word replaced by one of the table (which breaks
        // the bitshift gate), the shifted word still fails.
        prover.advice[0][0] = Fp::ONE;
        let err = prover.verify().unwrap_err();
        assert!(err.contains("lookup 0 not satisfied on row 1"), "{err}");

        // Element which is not within `num_bits`, but which has a shifted
        // value within num_bits
        let num_bits = 6;
        let shifted = Fp::from_u64((1 << num_bits) - 1);
        // Recall that shifted = element * 2^{K-s}
        //          => element = shifted * 2^{s-K}
        let element = shifted * Fp::from_u64(1 << (K - num_bits)).invert().unwrap();
        let circuit = short(element, num_bits);
        assert_eq!(failing_lookup_rows(&circuit), Err(1));
        let prover = MockProver::run(11, &circuit, vec![]).unwrap();
        assert!(prover.verify().unwrap_err().contains("on row 0"));
    }

    /// The copying entry points and `RangeConstrained::witness_short`.
    #[derive(Clone, Copy)]
    struct CopyCircuit {
        value: Value<Fp>,
    }

    /// The value the reference dump of [`CopyCircuit`] was made with (37
    /// bits).
    const COPY_VALUE: u64 = 0x1a_5c3b_96e7;

    impl Circuit for CopyCircuit {
        type Config = LookupRangeCheckConfig;

        fn without_witnesses(&self) -> Self {
            CopyCircuit {
                value: Value::unknown(),
            }
        }

        fn configure(&self, meta: &mut ConstraintSystem) -> Self::Config {
            configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: &mut Layouter<'_>,
        ) -> Result<(), Error> {
            config.load_range_check_table(layouter)?;

            let a = load_private(layouter.namespace(), config.running_sum(), self.value)?;
            // The value fits in 4 words.
            let zs = config.copy_check(layouter.namespace(), a.clone(), 4, true)?;
            assert_eq!(zs.len(), 5);
            // Its last word has 7 bits.
            config.copy_short_check(layouter.namespace(), zs[3].clone(), 7)?;
            // Three words of it, without a bound on the rest.
            let zs = config.copy_check(layouter.namespace(), a.clone(), 3, false)?;
            assert_eq!(zs.len(), 4);
            // Bits 3..9 of it.
            let bits =
                RangeConstrained::witness_short(&config, layouter.namespace(), a.value(), 3..9)?;
            assert_eq!(bits.num_bits(), 6);
            bits.inner()
                .value()
                .zip(
                    RangeConstrained::bitrange_of(a.value(), 3..9)
                        .inner()
                        .as_ref(),
                )
                .assert_if_known(|(cell, value)| cell == value);
            bits.value()
                .inner()
                .zip(a.value())
                .assert_if_known(|(bits, a)| *bits == Fp::from_u64((a.to_raw()[0] >> 3) & 0x3f));
            Ok(())
        }
    }

    #[test]
    fn copy_checks() {
        let circuit = CopyCircuit {
            value: Value::known(Fp::from_u64(COPY_VALUE)),
        };
        let prover = MockProver::run(11, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // A value of 41 bits does not fit in 4 words, and its last word is
        // more than 7 bits.
        let circuit = CopyCircuit {
            value: Value::known(Fp::from_u64(1 << 40)),
        };
        let prover = MockProver::run(11, &circuit, vec![]).unwrap();
        let err = prover.verify().unwrap_err();
        assert!(err.contains("copy constraint"), "{err}");
    }

    /// The generator table, as the Sinsemilla chip loads it.
    #[derive(Clone, Copy)]
    struct TableCircuit;

    impl Circuit for TableCircuit {
        type Config = (LookupRangeCheckConfig, TableColumn, TableColumn);

        fn without_witnesses(&self) -> Self {
            TableCircuit
        }

        fn configure(&self, meta: &mut ConstraintSystem) -> Self::Config {
            let running_sum = meta.advice_column();
            let table_idx = meta.lookup_table_column();
            let table_x = meta.lookup_table_column();
            let table_y = meta.lookup_table_column();
            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            (
                LookupRangeCheckConfig::configure(meta, running_sum, table_idx),
                table_x,
                table_y,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: &mut Layouter<'_>,
        ) -> Result<(), Error> {
            let (config, table_x, table_y) = config;
            config.load(config.table_idx(), table_x, table_y, layouter)?;
            config.witness_check(layouter, Value::known(Fp::from_u64(0x12345)), 2, true)?;
            Ok(())
        }
    }

    /// The lookup argument, the gate and the layouts are those of the
    /// reference (see `utilities::test_dump`).
    #[test]
    fn lookup_range_check_matches_reference() {
        let circuit = MyLookupCircuit { num_words: 6 };
        assert_eq!(
            pinned_digest(&circuit),
            "1635:c56584c666b3556393b760874649306a42625bc511b70918c3b8c0f42f024005"
        );
        assert_eq!(
            layout_digest(11, &circuit),
            "82095:afbc3a0a5dfa9e6dc226b9244e9cb2f16486963b2c4c898120115b94e4b32293"
        );

        for (name, element, num_bits) in [
            (
                "80953:03d92d149f2815ff1d13ef69610ddb7ed1de4b6d8a9e4aa0b6266e5e715655aa",
                Fp::ZERO,
                0,
            ),
            (
                "81109:74970f3f33fb7e4bc1c82de4cd81dac7ddce388dfca5e41a4d3348892fd0c7d5",
                Fp::from_u64((1 << K) - 1),
                K,
            ),
            (
                "81109:bc8d708fd29bec7546a667ab9346863755748ee4f11cbe054519a863c8a507a9",
                Fp::from_u64((1 << 6) - 1),
                6,
            ),
        ] {
            assert_eq!(layout_digest(11, &short(element, num_bits)), name);
        }

        let circuit = CopyCircuit {
            value: Value::known(Fp::from_u64(COPY_VALUE)),
        };
        assert_eq!(
            layout_digest(11, &circuit),
            "82492:e466f77662a710da283c31b709c55623c35ecf24c4e475cc3bbfde1e871b474d"
        );

        assert_eq!(
            pinned_digest(&TableCircuit),
            "1635:34f20c5c2bd93169c6f3526d567328b0f1559c9daeae337ee20923bfe644e252"
        );
        assert_eq!(
            layout_digest(11, &TableCircuit),
            "405467:3dbb84fba25514bbf2280a960c0dfe8bfe474fa69f1073d8f5fca60b54db8b24"
        );
    }
}
