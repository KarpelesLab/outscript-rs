//! The Poseidon chip with an `x^5` S-box (`halo2_gadgets::poseidon::pow5`),
//! specialized to the `P128Pow5T3` permutation over `Fp`: one full round per
//! row, two partial rounds per row.

use alloc::vec::Vec;

use super::{Absorbing, ConstantLength, PaddedWord, RATE, Squeezing, State, WIDTH};
use crate::orchard::Fp;
use crate::orchard::halo2::circuit::{AssignedCell, Layouter, Region};
use crate::orchard::halo2::plonk::{
    Advice, Any, Column, ConstraintSystem, Constraints, Expression, Fixed, Rotation, Selector,
    VirtualCells,
};
use crate::orchard::halo2::{Error, Value};
use crate::orchard::poseidon::{FULL_ROUNDS, MDS, PARTIAL_ROUNDS, ROUND_CONSTANTS};

/// The inverse of the MDS matrix, by rows (`halo2_poseidon::fp::MDS_INV`).
pub(crate) const MDS_INV: [[Fp; WIDTH]; WIDTH] = [
    [
        Fp::from_raw([
            0xc6de_463c_d140_4e6b,
            0x4543_705f_35e9_8ab5,
            0xcc59_ffd0_0de8_6443,
            0x2cc0_57f3_fa14_687a,
        ]),
        Fp::from_raw([
            0x1718_4041_7cab_7576,
            0xfadb_f8ae_7ae2_4796,
            0x5fd7_2b55_df20_8385,
            0x32e7_c439_f2f9_67e5,
        ]),
        Fp::from_raw([
            0x9426_45bd_7d44_64e0,
            0x1403_db6f_5030_2040,
            0xf461_778a_bf6c_91fa,
            0x2eae_5df8_c311_5969,
        ]),
    ],
    [
        Fp::from_raw([
            0xa1ca_1516_a4a1_a6a0,
            0x13f0_74fd_e9a1_8b29,
            0xdb18_b4ae_fe68_d26d,
            0x07bf_3684_8106_7199,
        ]),
        Fp::from_raw([
            0xe824_25bc_1b23_a059,
            0xbb1d_6504_0c85_c1bf,
            0x018a_918b_9dac_5dad,
            0x2aec_6906_c63f_3cf1,
        ]),
        Fp::from_raw([
            0xe054_1adf_238e_0781,
            0x76b2_a713_9db7_1b36,
            0x1215_944a_64a2_46b2,
            0x0952_e024_3aec_2af0,
        ]),
    ],
    [
        Fp::from_raw([
            0x2a41_8d8d_73a7_c908,
            0xaef9_112e_952f_dbb5,
            0x723a_63a0_c09d_ab26,
            0x2fcb_ba6f_9159_a219,
        ]),
        Fp::from_raw([
            0x76ef_ab42_d4fb_a90b,
            0xc5e4_960d_7424_cd37,
            0xb4dd_d4b4_d645_2256,
            0x1ec7_3725_74f3_851b,
        ]),
        Fp::from_raw([
            0xadc8_933c_6f3c_72ee,
            0x87a7_435d_30f8_be81,
            0x3c26_fa4b_7d25_b1e4,
            0x0d0c_2efd_6472_f12a,
        ]),
    ],
];

/// Configuration for a [`Pow5Chip`].
#[derive(Clone, Debug)]
pub(crate) struct Pow5Config {
    pub(crate) state: [Column<Advice>; WIDTH],
    partial_sbox: Column<Advice>,
    rc_a: [Column<Fixed>; WIDTH],
    rc_b: [Column<Fixed>; WIDTH],
    s_full: Selector,
    s_partial: Selector,
    s_pad_and_add: Selector,

    half_full_rounds: usize,
    half_partial_rounds: usize,
    alpha: [u64; 4],
}

/// A Poseidon chip using an `x^5` S-box.
///
/// The chip is implemented using a single round per row for full rounds, and
/// two rounds per row for partial rounds.
#[derive(Debug)]
pub(crate) struct Pow5Chip {
    config: Pow5Config,
}

impl Pow5Chip {
    /// Configures this chip for use in a circuit.
    ///
    /// # Side-effects
    ///
    /// All columns in `state` (and in `rc_b`) will be equality-enabled.
    pub(crate) fn configure(
        meta: &mut ConstraintSystem,
        state: [Column<Advice>; WIDTH],
        partial_sbox: Column<Advice>,
        rc_a: [Column<Fixed>; WIDTH],
        rc_b: [Column<Fixed>; WIDTH],
    ) -> Pow5Config {
        // This gadget requires R_F and R_P to be even.
        const {
            assert!(RATE == WIDTH - 1);
            assert!(FULL_ROUNDS & 1 == 0);
            assert!(PARTIAL_ROUNDS & 1 == 0);
        }
        let half_full_rounds = FULL_ROUNDS / 2;
        let half_partial_rounds = PARTIAL_ROUNDS / 2;
        let (m_reg, m_inv) = (&MDS, &MDS_INV);

        // This allows state words to be initialized (by constraining them
        // equal to fixed values), and used in a permutation from an arbitrary
        // region. rc_a is used in every permutation round, while rc_b is
        // empty in the initial and final full rounds, so we use rc_b as
        // "scratch space" for fixed values.
        for column in core::iter::empty()
            .chain(state.iter().cloned().map(Column::<Any>::from))
            .chain(rc_b.iter().cloned().map(Column::<Any>::from))
        {
            meta.enable_equality(column);
        }

        let s_full = meta.selector();
        let s_partial = meta.selector();
        let s_pad_and_add = meta.selector();

        let alpha = [5, 0, 0, 0];
        let pow_5 = |v: Expression| {
            let v2 = v.clone() * v.clone();
            v2.clone() * v2 * v
        };

        meta.create_gate("full round", |meta| {
            let s_full = meta.query_selector(s_full);

            Constraints::with_selector(
                s_full,
                (0..WIDTH)
                    .map(|next_idx| {
                        let state_next = meta.query_advice(state[next_idx], Rotation::next());
                        let expr = (0..WIDTH)
                            .map(|idx| {
                                let state_cur = meta.query_advice(state[idx], Rotation::cur());
                                let rc_a = meta.query_fixed(rc_a[idx]);
                                pow_5(state_cur + rc_a) * m_reg[next_idx][idx]
                            })
                            .reduce(|acc, term| acc + term)
                            .expect("WIDTH > 0");
                        expr - state_next
                    })
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("partial rounds", |meta| {
            let cur_0 = meta.query_advice(state[0], Rotation::cur());
            let mid_0 = meta.query_advice(partial_sbox, Rotation::cur());

            let rc_a0 = meta.query_fixed(rc_a[0]);
            let rc_b0 = meta.query_fixed(rc_b[0]);

            let s_partial = meta.query_selector(s_partial);

            let mid = |idx: usize, meta: &mut VirtualCells<'_>| {
                let mid = mid_0.clone() * m_reg[idx][0];
                (1..WIDTH).fold(mid, |acc, cur_idx| {
                    let cur = meta.query_advice(state[cur_idx], Rotation::cur());
                    let rc_a = meta.query_fixed(rc_a[cur_idx]);
                    acc + (cur + rc_a) * m_reg[idx][cur_idx]
                })
            };

            let next = |idx: usize, meta: &mut VirtualCells<'_>| {
                (0..WIDTH)
                    .map(|next_idx| {
                        let next = meta.query_advice(state[next_idx], Rotation::next());
                        next * m_inv[idx][next_idx]
                    })
                    .reduce(|acc, next| acc + next)
                    .expect("WIDTH > 0")
            };

            let partial_round_linear = |idx: usize, meta: &mut VirtualCells<'_>| {
                let rc_b = meta.query_fixed(rc_b[idx]);
                mid(idx, meta) + rc_b - next(idx, meta)
            };

            // state[0] round a
            let round_a = pow_5(cur_0 + rc_a0) - mid_0.clone();
            // state[0] round b
            let round_b = {
                let mid = mid(0, meta);
                pow_5(mid + rc_b0) - next(0, meta)
            };
            let mut constraints = Vec::with_capacity(WIDTH + 1);
            constraints.push(round_a);
            constraints.push(round_b);
            for idx in 1..WIDTH {
                constraints.push(partial_round_linear(idx, meta));
            }

            Constraints::with_selector(s_partial, constraints)
        });

        meta.create_gate("pad-and-add", |meta| {
            let initial_state_rate = meta.query_advice(state[RATE], Rotation::prev());
            let output_state_rate = meta.query_advice(state[RATE], Rotation::next());

            let s_pad_and_add = meta.query_selector(s_pad_and_add);

            let pad_and_add = |idx: usize| {
                let initial_state = meta.query_advice(state[idx], Rotation::prev());
                let input = meta.query_advice(state[idx], Rotation::cur());
                let output_state = meta.query_advice(state[idx], Rotation::next());

                // We pad the input by storing the required padding in fixed
                // columns and then constraining the corresponding input
                // columns to be equal to it.
                initial_state + input - output_state
            };

            Constraints::with_selector(
                s_pad_and_add,
                (0..RATE)
                    .map(pad_and_add)
                    // The capacity element is never altered by the input.
                    .chain(Some(initial_state_rate - output_state_rate))
                    .collect::<Vec<_>>(),
            )
        });

        Pow5Config {
            state,
            partial_sbox,
            rc_a,
            rc_b,
            s_full,
            s_partial,
            s_pad_and_add,
            half_full_rounds,
            half_partial_rounds,
            alpha,
        }
    }

    /// Construct a [`Pow5Chip`].
    pub(crate) fn construct(config: Pow5Config) -> Self {
        Pow5Chip { config }
    }

    /// The configuration of the chip.
    pub(crate) fn config(&self) -> &Pow5Config {
        &self.config
    }

    /// Applies the Poseidon permutation to the given state.
    pub(crate) fn permute(
        &self,
        layouter: &mut Layouter<'_>,
        initial_state: &State<StateWord>,
    ) -> Result<State<StateWord>, Error> {
        let config = self.config();

        // "permute state"
        layouter.assign_region(|mut region| {
            // Load the initial state into this region.
            let state = Pow5State::load(&mut region, config, initial_state)?;

            let state = (0..config.half_full_rounds).try_fold(state, |state, r| {
                state.full_round(&mut region, config, r, r)
            })?;

            let state = (0..config.half_partial_rounds).try_fold(state, |state, r| {
                state.partial_round(
                    &mut region,
                    config,
                    config.half_full_rounds + 2 * r,
                    config.half_full_rounds + r,
                )
            })?;

            let state = (0..config.half_full_rounds).try_fold(state, |state, r| {
                state.full_round(
                    &mut region,
                    config,
                    config.half_full_rounds + 2 * config.half_partial_rounds + r,
                    config.half_full_rounds + config.half_partial_rounds + r,
                )
            })?;

            Ok(state.0)
        })
    }

    /// Returns the initial empty state for the domain `ConstantLength<2>`.
    pub(crate) fn initial_state(
        &self,
        layouter: &mut Layouter<'_>,
    ) -> Result<State<StateWord>, Error> {
        let config = self.config();
        // "initial state for domain ConstantLength<2>"
        let state = layouter.assign_region(|mut region| {
            let mut state = Vec::with_capacity(WIDTH);
            let mut load_state_word = |i: usize, value: Fp| -> Result<_, Error> {
                let var = region.assign_advice_from_constant(config.state[i], 0, value)?;
                state.push(StateWord(var));

                Ok(())
            };

            for i in 0..RATE {
                load_state_word(i, Fp::ZERO)?;
            }
            load_state_word(RATE, ConstantLength::initial_capacity_element())?;

            Ok(state)
        })?;

        Ok(state.try_into().expect("WIDTH words"))
    }

    /// Adds the given input to the state.
    pub(crate) fn add_input(
        &self,
        layouter: &mut Layouter<'_>,
        initial_state: &State<StateWord>,
        input: &Absorbing<PaddedWord>,
    ) -> Result<State<StateWord>, Error> {
        let config = self.config();
        // "add input for domain ConstantLength<2>"
        layouter.assign_region(|mut region| {
            config.s_pad_and_add.enable(&mut region, 1)?;

            // Load the initial state into this region.
            let initial_state: Result<Vec<_>, Error> = (0..WIDTH)
                .map(|i| {
                    initial_state[i]
                        .0
                        .copy_advice(&mut region, config.state[i], 0)
                        .map(StateWord)
                })
                .collect();
            let initial_state = initial_state?;

            // Load the input into this region.
            let input: Result<Vec<_>, Error> = input
                .expose_inner()
                .iter()
                .enumerate()
                .map(|(i, input_word)| {
                    let (cell, value) = match input_word {
                        Some(PaddedWord::Message(word)) => (word.cell(), word.value().copied()),
                        Some(PaddedWord::Padding(padding_value)) => {
                            let value = Value::known(*padding_value);
                            let cell = region.assign_fixed(config.rc_b[i], 1, || value)?.cell();
                            (cell, value)
                        }
                        _ => panic!("Input is not padded"),
                    };
                    let var = region.assign_advice(config.state[i], 1, || value)?;
                    region.constrain_equal(cell, var.cell())?;

                    Ok(StateWord(var))
                })
                .collect();
            let input = input?;

            // Constrain the output.
            let output: Result<Vec<_>, Error> = (0..WIDTH)
                .map(|i| {
                    let value = initial_state[i].0.value().copied()
                        + input
                            .get(i)
                            .map(|word| word.0.value().cloned())
                            // The capacity element is never altered by the input.
                            .unwrap_or_else(|| Value::known(Fp::ZERO));
                    region
                        .assign_advice(config.state[i], 2, || value)
                        .map(StateWord)
                })
                .collect();
            output.map(|output| output.try_into().expect("WIDTH words"))
        })
    }

    /// Extracts sponge output from the given state.
    pub(crate) fn get_output(state: &State<StateWord>) -> Squeezing<StateWord> {
        let vals = state[..RATE].to_vec();
        Squeezing::init_full(vals.try_into().expect("correct length"))
    }
}

/// A word in the Poseidon state.
#[derive(Clone, Debug)]
pub(crate) struct StateWord(pub(super) AssignedCell<Fp>);

impl From<StateWord> for AssignedCell<Fp> {
    fn from(state_word: StateWord) -> AssignedCell<Fp> {
        state_word.0
    }
}

impl From<AssignedCell<Fp>> for StateWord {
    fn from(cell_value: AssignedCell<Fp>) -> StateWord {
        StateWord(cell_value)
    }
}

/// The state of a permutation in progress.
#[derive(Debug)]
struct Pow5State([StateWord; WIDTH]);

impl Pow5State {
    fn full_round(
        self,
        region: &mut Region<'_, '_>,
        config: &Pow5Config,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round(region, config, round, offset, config.s_full, |_| {
            let q = self
                .0
                .iter()
                .enumerate()
                .map(|(idx, word)| word.0.value().map(|v| *v + ROUND_CONSTANTS[round][idx]));
            let r: Value<Vec<Fp>> = q.map(|q| q.map(|q| q.pow_vartime(&config.alpha))).collect();
            let m = &MDS;
            let state = m.iter().map(|m_i| {
                r.as_ref().map(|r| {
                    r.iter()
                        .enumerate()
                        .fold(Fp::ZERO, |acc, (j, r_j)| acc + m_i[j] * *r_j)
                })
            });

            Ok((
                round + 1,
                state.collect::<Vec<_>>().try_into().expect("WIDTH words"),
            ))
        })
    }

    fn partial_round(
        self,
        region: &mut Region<'_, '_>,
        config: &Pow5Config,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round(region, config, round, offset, config.s_partial, |region| {
            let m = &MDS;
            let p: Value<Vec<Fp>> = self.0.iter().map(|word| word.0.value().cloned()).collect();

            let r: Value<Vec<Fp>> = p.map(|p| {
                let r_0 = (p[0] + ROUND_CONSTANTS[round][0]).pow_vartime(&config.alpha);
                let r_i = p[1..]
                    .iter()
                    .enumerate()
                    .map(|(i, p_i)| *p_i + ROUND_CONSTANTS[round][i + 1]);
                core::iter::empty().chain(Some(r_0)).chain(r_i).collect()
            });

            region.assign_advice(config.partial_sbox, offset, || r.as_ref().map(|r| r[0]))?;

            let p_mid: Value<Vec<Fp>> = m
                .iter()
                .map(|m_i| {
                    r.as_ref().map(|r| {
                        m_i.iter()
                            .zip(r.iter())
                            .fold(Fp::ZERO, |acc, (m_ij, r_j)| acc + *m_ij * *r_j)
                    })
                })
                .collect();

            // Load the second round constants.
            #[allow(clippy::needless_range_loop)]
            for i in 0..WIDTH {
                region.assign_fixed(config.rc_b[i], offset, || {
                    Value::known(ROUND_CONSTANTS[round + 1][i])
                })?;
            }

            let r_mid: Value<Vec<Fp>> = p_mid.map(|p| {
                let r_0 = (p[0] + ROUND_CONSTANTS[round + 1][0]).pow_vartime(&config.alpha);
                let r_i = p[1..]
                    .iter()
                    .enumerate()
                    .map(|(i, p_i)| *p_i + ROUND_CONSTANTS[round + 1][i + 1]);
                core::iter::empty().chain(Some(r_0)).chain(r_i).collect()
            });

            let state: Vec<Value<Fp>> = m
                .iter()
                .map(|m_i| {
                    r_mid.as_ref().map(|r| {
                        m_i.iter()
                            .zip(r.iter())
                            .fold(Fp::ZERO, |acc, (m_ij, r_j)| acc + *m_ij * *r_j)
                    })
                })
                .collect();

            Ok((round + 2, state.try_into().expect("WIDTH words")))
        })
    }

    fn load(
        region: &mut Region<'_, '_>,
        config: &Pow5Config,
        initial_state: &State<StateWord>,
    ) -> Result<Self, Error> {
        let state: Result<Vec<_>, Error> = (0..WIDTH)
            .map(|i| {
                initial_state[i]
                    .0
                    .copy_advice(region, config.state[i], 0)
                    .map(StateWord)
            })
            .collect();
        state.map(|state| Pow5State(state.try_into().expect("WIDTH words")))
    }

    fn round(
        region: &mut Region<'_, '_>,
        config: &Pow5Config,
        round: usize,
        offset: usize,
        round_gate: Selector,
        round_fn: impl FnOnce(&mut Region<'_, '_>) -> Result<(usize, [Value<Fp>; WIDTH]), Error>,
    ) -> Result<Self, Error> {
        // Enable the required gate.
        round_gate.enable(region, offset)?;

        // Load the round constants.
        #[allow(clippy::needless_range_loop)]
        for i in 0..WIDTH {
            region.assign_fixed(config.rc_a[i], offset, || {
                Value::known(ROUND_CONSTANTS[round][i])
            })?;
        }

        // Compute the next round's state.
        let (_next_round, next_state) = round_fn(region)?;

        let next_state: Result<Vec<_>, Error> = (0..WIDTH)
            .map(|i| {
                let value = next_state[i];
                let var = region.assign_advice(config.state[i], offset + 1, || value)?;
                Ok(StateWord(var))
            })
            .collect();
        next_state.map(|next_state| Pow5State(next_state.try_into().expect("WIDTH words")))
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::{assert_dump, dump};
    use super::super::{Hash, L};
    use super::*;
    use crate::orchard::halo2::circuit::Circuit;
    use crate::orchard::halo2::dev::MockProver;
    use crate::orchard::poseidon;

    /// [`MDS_INV`] is the inverse the constant generation of the Poseidon
    /// paper gives, and the inverse of [`MDS`].
    #[test]
    fn mds_inv_is_the_inverse() {
        let (round_constants, mds, mds_inv) = poseidon::generate_constants();
        assert!(round_constants == ROUND_CONSTANTS);
        assert!(mds == MDS);
        assert!(mds_inv == MDS_INV);
        #[allow(clippy::needless_range_loop)]
        for i in 0..WIDTH {
            for j in 0..WIDTH {
                let e = (0..WIDTH).fold(Fp::ZERO, |acc, k| acc + MDS[i][k] * MDS_INV[k][j]);
                assert!(e == if i == j { Fp::ONE } else { Fp::ZERO });
            }
        }
    }

    fn configure(meta: &mut ConstraintSystem, constants: bool) -> Pow5Config {
        let state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let partial_sbox = meta.advice_column();
        let rc_a = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let rc_b = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        if constants {
            meta.enable_constant(rc_b[0]);
        }
        Pow5Chip::configure(meta, state, partial_sbox, rc_a, rc_b)
    }

    /// `MyPermuteCircuit` of the reference's tests.
    struct MyPermuteCircuit {
        expected: [Fp; WIDTH],
    }

    impl Circuit for MyPermuteCircuit {
        type Config = Pow5Config;

        fn without_witnesses(&self) -> Self {
            MyPermuteCircuit {
                expected: self.expected,
            }
        }

        fn configure(&self, meta: &mut ConstraintSystem) -> Pow5Config {
            configure(meta, false)
        }

        fn synthesize(&self, config: Pow5Config, layouter: &mut Layouter<'_>) -> Result<(), Error> {
            let initial_state = layouter.assign_region(|mut region| {
                let state: Result<Vec<_>, Error> = (0..WIDTH)
                    .map(|i| {
                        let value = Value::known(Fp::from_u64(i as u64));
                        let var = region.assign_advice(config.state[i], 0, || value)?;
                        Ok(StateWord(var))
                    })
                    .collect();
                Ok(state?.try_into().expect("WIDTH words"))
            })?;

            let chip = Pow5Chip::construct(config.clone());
            let final_state = chip.permute(layouter, &initial_state)?;

            layouter.assign_region(|mut region| {
                #[allow(clippy::needless_range_loop)]
                for i in 0..WIDTH {
                    let var = region
                        .assign_advice(config.state[i], 0, || Value::known(self.expected[i]))?;
                    region.constrain_equal(final_state[i].0.cell(), var.cell())?;
                }
                Ok(())
            })
        }
    }

    #[test]
    fn poseidon_permute() {
        let mut expected = [Fp::ZERO, Fp::ONE, Fp::from_u64(2)];
        poseidon::permute(&mut expected);
        let circuit = MyPermuteCircuit { expected };
        MockProver::run(6, &circuit, vec![])
            .unwrap()
            .assert_satisfied();

        expected[1] += Fp::ONE;
        let circuit = MyPermuteCircuit { expected };
        assert!(
            MockProver::run(6, &circuit, vec![])
                .unwrap()
                .verify()
                .is_err()
        );
    }

    /// `MyHashCircuit` of the reference's tests, for `ConstantLength<2>`.
    struct MyHashCircuit {
        message: Value<[Fp; L]>,
        // For the purpose of this test, witness the result.
        output: Value<Fp>,
    }

    impl Circuit for MyHashCircuit {
        type Config = Pow5Config;

        fn without_witnesses(&self) -> Self {
            MyHashCircuit {
                message: Value::unknown(),
                output: Value::unknown(),
            }
        }

        fn configure(&self, meta: &mut ConstraintSystem) -> Pow5Config {
            configure(meta, true)
        }

        fn synthesize(&self, config: Pow5Config, layouter: &mut Layouter<'_>) -> Result<(), Error> {
            let chip = Pow5Chip::construct(config.clone());

            let message = layouter.assign_region(|mut region| {
                let message: Result<Vec<_>, Error> = (0..L)
                    .map(|i| {
                        let value = self.message.map(|message_vals| message_vals[i]);
                        region.assign_advice(config.state[i], 0, || value)
                    })
                    .collect();
                Ok(message?.try_into().expect("L words"))
            })?;

            let hasher = Hash::init(chip, layouter.namespace())?;
            let output = hasher.hash(layouter.namespace(), message)?;

            layouter.assign_region(|mut region| {
                let expected_var = region.assign_advice(config.state[0], 0, || self.output)?;
                region.constrain_equal(output.cell(), expected_var.cell())
            })
        }
    }

    /// The message the reference dumps were made with.
    fn message() -> [Fp; L] {
        [
            Fp::from_u128(0x0123456789abcdef_fedcba9876543210),
            -Fp::from_u128(0x0f1e2d3c4b5a6978_8796a5b4c3d2e1f0),
        ]
    }

    #[test]
    fn poseidon_hash() {
        let mut messages = alloc::vec![message(), [Fp::ZERO, Fp::ZERO]];
        messages.push([Fp::ONE, -Fp::ONE]);
        for message in messages {
            let output = poseidon::hash(message[0], message[1]);
            let circuit = MyHashCircuit {
                message: Value::known(message),
                output: Value::known(output),
            };
            MockProver::run(6, &circuit, vec![])
                .unwrap()
                .assert_satisfied();

            // A wrong output is rejected (by the copy constraint).
            let circuit = MyHashCircuit {
                message: Value::known(message),
                output: Value::known(output + Fp::ONE),
            };
            let err = MockProver::run(6, &circuit, vec![])
                .unwrap()
                .verify()
                .unwrap_err();
            assert!(err.contains("copy"), "{err}");
        }
    }

    /// Every advice cell of the permutation region (rows 0 to 36 in this
    /// layout) is bound: changing any of them breaks a gate or a copy
    /// constraint.
    #[test]
    fn poseidon_gates_reject_tampering() {
        let message = message();
        let circuit = MyHashCircuit {
            message: Value::known(message),
            output: Value::known(poseidon::hash(message[0], message[1])),
        };
        let prover = MockProver::run(6, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
        for column in 0..4 {
            for row in 0..37 {
                // partial_sbox is only assigned on the partial round rows
                if column == 3 && !(4..32).contains(&row) {
                    continue;
                }
                let mut prover = MockProver::run(6, &circuit, vec![]).unwrap();
                prover.advice[column][row] += Fp::ONE;
                assert!(prover.verify().is_err(), "column {column} row {row}");
            }
        }
    }

    /// The constraint system and the layout are those of the reference.
    ///
    /// The expected values are the SHA-256 hashes of the dumps of a scratch
    /// project running `halo2_gadgets` 0.6.0 / `halo2_proofs` 0.4.1 on the
    /// same circuit (`Pow5Chip::configure::<P128Pow5T3>` over 3 + 1 advice
    /// and 3 + 3 fixed columns with `rc_b[0]` holding the constants, the
    /// `V1` floor planner, `Hash<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>`
    /// on [`message`]): the `{:?}` of `ConstraintSystem::pinned()` after
    /// `configure`, and the log of every call the floor planner makes on the
    /// `Assignment` backend (selectors, advice and fixed cells with their
    /// values, copy constraints), in order, formatted as
    /// [`dump`](super::super::test_util::dump) does.
    #[test]
    fn layout_matches_reference() {
        let message = message();
        let output = poseidon::hash(message[0], message[1]);
        // the output of `halo2_poseidon` for this message
        assert_eq!(
            alloc::format!("{:?}", crate::orchard::halo2::plonk::Hex(&output)),
            "0x35902e59aa32f0cc047ec4bbd81bd253c69702ea9e0863fca1c12a1c13996fab"
        );
        let circuit = MyHashCircuit {
            message: Value::known(message),
            output: Value::known(output),
        };
        let (pinned, events) = dump(&circuit);
        assert_dump(
            "pinned",
            &pinned,
            16691,
            "62b5a91985f5975af23145355906a48fcc7725d48d4565b045db8df93746d836",
        );
        assert_dump(
            "events",
            &events,
            40960,
            "ae296eb1f84dae18372aff34c19c07060f7c9e6da30ade550977a1e09d41847c",
        );
    }
}
