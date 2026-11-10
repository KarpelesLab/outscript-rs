//! A test backend that synthesizes a circuit and checks that every gate,
//! lookup and copy constraint holds on the assigned cells (the equivalent of
//! `halo2_proofs::dev::MockProver`).

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::circuit::{Assignment, Circuit};
use super::plonk::{Advice, Any, Column, ConstraintSystem, Fixed, Instance, Selector};
use super::{Error, Value};
use crate::orchard::Fp;

/// The cells of a synthesized circuit.
pub(crate) struct MockProver {
    n: usize,
    pub(crate) cs: ConstraintSystem,
    pub(crate) fixed: Vec<Vec<Fp>>,
    pub(crate) advice: Vec<Vec<Fp>>,
    pub(crate) instance: Vec<Vec<Fp>>,
    pub(crate) selectors: Vec<Vec<bool>>,
    #[allow(clippy::type_complexity)]
    pub(crate) copies: Vec<((Column<Any>, usize), (Column<Any>, usize))>,
    usable_rows: usize,
}

impl Assignment for MockProver {
    fn enable_selector(&mut self, selector: &Selector, row: usize) -> Result<(), Error> {
        if row >= self.usable_rows {
            return Err(Error::NotEnoughRows);
        }
        self.selectors[selector.0][row] = true;
        Ok(())
    }

    fn query_instance(&self, column: Column<Instance>, row: usize) -> Result<Value<Fp>, Error> {
        if row >= self.usable_rows {
            return Err(Error::NotEnoughRows);
        }
        Ok(Value::known(self.instance[column.index][row]))
    }

    fn assign_advice(
        &mut self,
        column: Column<Advice>,
        row: usize,
        to: &mut dyn FnMut() -> Value<Fp>,
    ) -> Result<(), Error> {
        if row >= self.usable_rows {
            return Err(Error::NotEnoughRows);
        }
        self.advice[column.index][row] = to().into_option().ok_or(Error::Synthesis)?;
        Ok(())
    }

    fn assign_fixed(
        &mut self,
        column: Column<Fixed>,
        row: usize,
        to: &mut dyn FnMut() -> Value<Fp>,
    ) -> Result<(), Error> {
        if row >= self.usable_rows {
            return Err(Error::NotEnoughRows);
        }
        self.fixed[column.index][row] = to().into_option().ok_or(Error::Synthesis)?;
        Ok(())
    }

    fn copy(
        &mut self,
        left_column: Column<Any>,
        left_row: usize,
        right_column: Column<Any>,
        right_row: usize,
    ) -> Result<(), Error> {
        if left_row >= self.usable_rows || right_row >= self.usable_rows {
            return Err(Error::NotEnoughRows);
        }
        for c in [left_column, right_column] {
            if !self.cs.permutation.columns.contains(&c) {
                return Err(Error::ColumnNotInPermutation);
            }
        }
        self.copies
            .push(((left_column, left_row), (right_column, right_row)));
        Ok(())
    }

    fn fill_from_row(
        &mut self,
        column: Column<Fixed>,
        row: usize,
        to: Value<Fp>,
    ) -> Result<(), Error> {
        let v = to.into_option().ok_or(Error::Synthesis)?;
        for r in row..self.usable_rows {
            self.fixed[column.index][r] = v;
        }
        Ok(())
    }
}

impl MockProver {
    /// Synthesizes `circuit` (with known witnesses) on `2^k` rows.
    pub(crate) fn run<C: Circuit>(
        k: u32,
        circuit: &C,
        instance: Vec<Vec<Fp>>,
    ) -> Result<Self, Error> {
        let n = 1usize << k;
        let mut cs = ConstraintSystem::default();
        let config = circuit.configure(&mut cs);
        let usable_rows = n - (cs.blinding_factors() + 1);
        let instance = instance
            .into_iter()
            .map(|mut col| {
                col.resize(n, Fp::ZERO);
                col
            })
            .collect::<Vec<_>>();
        assert_eq!(instance.len(), cs.num_instance_columns);
        let constants = cs.constants.clone();
        let mut prover = MockProver {
            n,
            fixed: vec![vec![Fp::ZERO; n]; cs.num_fixed_columns],
            advice: vec![vec![Fp::ZERO; n]; cs.num_advice_columns],
            instance,
            selectors: vec![vec![false; n]; cs.num_selectors],
            copies: vec![],
            usable_rows,
            cs,
        };
        super::circuit::synthesize(&mut prover, circuit, config, constants)?;
        Ok(prover)
    }

    fn cell(&self, column: Column<Any>, row: usize) -> Fp {
        match column.column_type {
            Any::Advice => self.advice[column.index][row],
            Any::Fixed => self.fixed[column.index][row],
            Any::Instance => self.instance[column.index][row],
        }
    }

    fn eval(&self, expr: &super::plonk::Expression, row: usize) -> Fp {
        let n = self.n as i64;
        let at = |rot: super::plonk::Rotation| ((row as i64 + rot.0 as i64).rem_euclid(n)) as usize;
        expr.evaluate(
            &|c| c,
            &|s| {
                if self.selectors[s.0][row] {
                    Fp::ONE
                } else {
                    Fp::ZERO
                }
            },
            &|q| self.fixed[q.column_index][at(q.rotation)],
            &|q| self.advice[q.column_index][at(q.rotation)],
            &|q| self.instance[q.column_index][at(q.rotation)],
            &|a| -a,
            &|a, b| a + b,
            &|a, b| a * b,
            &|a, f| a * f,
        )
    }

    /// Checks every gate, lookup and copy constraint; the error describes
    /// the first few failures.
    pub(crate) fn verify(&self) -> Result<(), String> {
        let mut errors = vec![];
        for gate in &self.cs.gates {
            for (i, poly) in gate.polys.iter().enumerate() {
                for row in 0..self.usable_rows {
                    if self.eval(poly, row) != Fp::ZERO {
                        errors.push(format!(
                            "gate '{}' constraint {} not satisfied on row {}",
                            gate.name, i, row
                        ));
                        break;
                    }
                }
            }
        }
        for (li, lookup) in self.cs.lookups.iter().enumerate() {
            let table: BTreeSet<Vec<[u8; 32]>> = (0..self.usable_rows)
                .map(|row| {
                    lookup
                        .table_expressions
                        .iter()
                        .map(|e| self.eval(e, row).to_bytes())
                        .collect()
                })
                .collect();
            for row in 0..self.usable_rows {
                let input: Vec<[u8; 32]> = lookup
                    .input_expressions
                    .iter()
                    .map(|e| self.eval(e, row).to_bytes())
                    .collect();
                if !table.contains(&input) {
                    errors.push(format!("lookup {} not satisfied on row {}", li, row));
                    break;
                }
            }
        }
        for ((lc, lr), (rc, rr)) in &self.copies {
            if self.cell(*lc, *lr) != self.cell(*rc, *rr) {
                errors.push(format!(
                    "copy constraint {:?}@{} = {:?}@{} not satisfied",
                    lc, lr, rc, rr
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            errors.truncate(8);
            Err(errors.join("\n"))
        }
    }

    /// Panics with the failures if the circuit is not satisfied.
    pub(crate) fn assert_satisfied(&self) {
        if let Err(e) = self.verify() {
            panic!("circuit not satisfied:\n{e}");
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::orchard::halo2::circuit::Layouter;
    use crate::orchard::halo2::plonk::{Constraints, Rotation, TableColumn};

    /// `a * b = c` with `c` public, `a` range-checked by a lookup and `b`
    /// bound to a constant.
    #[derive(Clone)]
    pub(crate) struct Mul {
        pub(crate) a: Value<Fp>,
        pub(crate) b: Fp,
    }

    #[derive(Clone)]
    pub(crate) struct MulConfig {
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
        q_mul: Selector,
        q_lookup: Selector,
        table: TableColumn,
    }

    impl Circuit for Mul {
        type Config = MulConfig;

        fn without_witnesses(&self) -> Self {
            Mul {
                a: Value::unknown(),
                b: self.b,
            }
        }

        fn configure(&self, meta: &mut ConstraintSystem) -> MulConfig {
            let advice = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];
            let instance = meta.instance_column();
            let constants = meta.fixed_column();
            meta.enable_constant(constants);
            meta.enable_equality(instance);
            for c in advice {
                meta.enable_equality(c);
            }
            let q_mul = meta.selector();
            let q_lookup = meta.complex_selector();
            let table = meta.lookup_table_column();
            meta.create_gate("mul", |meta| {
                let q = meta.query_selector(q_mul);
                let a = meta.query_advice(advice[0], Rotation::cur());
                let b = meta.query_advice(advice[1], Rotation::cur());
                let c = meta.query_advice(advice[2], Rotation::cur());
                Constraints::with_selector(q, [a * b - c])
            });
            meta.lookup(|meta| {
                let q = meta.query_selector(q_lookup);
                let a = meta.query_advice(advice[0], Rotation::cur());
                vec![(q * a, table)]
            });
            MulConfig {
                advice,
                instance,
                q_mul,
                q_lookup,
                table,
            }
        }

        fn synthesize(&self, config: MulConfig, layouter: &mut Layouter<'_>) -> Result<(), Error> {
            layouter.assign_table(|mut table| {
                for i in 0..8u64 {
                    table
                        .assign_cell(config.table, i as usize, || Value::known(Fp::from_u64(i)))?;
                }
                Ok(())
            })?;
            let b = layouter.assign_region(|mut region| {
                region.assign_advice_from_constant(config.advice[1], 0, self.b)
            })?;
            let c = layouter.assign_region(|mut region| {
                config.q_mul.enable(&mut region, 0)?;
                config.q_lookup.enable(&mut region, 0)?;
                let a = region.assign_advice(config.advice[0], 0, || self.a)?;
                let b = b.copy_advice(&mut region, config.advice[1], 0)?;
                let c = a.value().copied() * b.value().copied();
                region.assign_advice(config.advice[2], 0, || c)
            })?;
            layouter.constrain_instance(c.cell(), config.instance, 0)
        }
    }

    #[test]
    fn mock_prover_checks_gates_lookups_and_copies() {
        let ok = Mul {
            a: Value::known(Fp::from_u64(7)),
            b: Fp::from_u64(6),
        };
        let run = |c: &Mul, out: u64| {
            MockProver::run(4, c, vec![vec![Fp::from_u64(out)]])
                .unwrap()
                .verify()
        };
        assert!(run(&ok, 42).is_ok());
        // wrong public input: the copy constraint fails
        assert!(run(&ok, 43).unwrap_err().contains("copy"));
        // out of the table: the lookup fails
        let bad = Mul {
            a: Value::known(Fp::from_u64(8)),
            b: Fp::from_u64(6),
        };
        assert!(run(&bad, 48).unwrap_err().contains("lookup"));
    }
}
