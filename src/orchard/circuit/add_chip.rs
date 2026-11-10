//! The field addition chip of the Orchard circuit
//! (`orchard::circuit::gadget::add_chip`).

use crate::orchard::Fp;
use crate::orchard::halo2::Error;
use crate::orchard::halo2::circuit::{AssignedCell, Layouter};
use crate::orchard::halo2::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Rotation, Selector,
};

/// Configuration for the addition chip.
#[derive(Clone, Debug)]
pub(crate) struct AddConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    q_add: Selector,
}

/// A chip implementing a single addition constraint `c = a + b` on a single
/// row.
#[derive(Debug)]
pub(crate) struct AddChip {
    config: AddConfig,
}

impl AddChip {
    /// Configures the addition chip with the given advice columns.
    pub(crate) fn configure(
        meta: &mut ConstraintSystem,
        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
    ) -> AddConfig {
        let q_add = meta.selector();
        meta.create_gate("Field element addition: c = a + b", |meta| {
            let q_add = meta.query_selector(q_add);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());

            Constraints::with_selector(q_add, Some(a + b - c))
        });

        AddConfig { a, b, c, q_add }
    }

    /// Constructs an addition chip from the given config.
    pub(crate) fn construct(config: AddConfig) -> Self {
        Self { config }
    }

    /// Constrains `a + b` and returns the sum.
    pub(crate) fn add(
        &self,
        layouter: &mut Layouter<'_>,
        a: &AssignedCell<Fp>,
        b: &AssignedCell<Fp>,
    ) -> Result<AssignedCell<Fp>, Error> {
        // "c = a + b"
        layouter.assign_region(|mut region| {
            self.config.q_add.enable(&mut region, 0)?;

            a.copy_advice(&mut region, self.config.a, 0)?;
            b.copy_advice(&mut region, self.config.b, 0)?;

            let scalar_val = a.value().zip(b.value()).map(|(a, b)| *a + *b);
            region.assign_advice(self.config.c, 0, || scalar_val)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchard::circuit::poseidon::test_util::{assert_dump, dump};
    use crate::orchard::halo2::Value;
    use crate::orchard::halo2::circuit::Circuit;
    use crate::orchard::halo2::dev::MockProver;

    #[derive(Clone)]
    struct AddTestConfig {
        advice: [Column<Advice>; 3],
        add: AddConfig,
    }

    /// `c = a + b`, with `a`, `b` and the expected `c` witnessed.
    struct AddCircuit {
        a: Value<Fp>,
        b: Value<Fp>,
        c: Value<Fp>,
    }

    impl Circuit for AddCircuit {
        type Config = AddTestConfig;

        fn without_witnesses(&self) -> Self {
            AddCircuit {
                a: Value::unknown(),
                b: Value::unknown(),
                c: Value::unknown(),
            }
        }

        fn configure(&self, meta: &mut ConstraintSystem) -> AddTestConfig {
            let advice = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];
            for c in advice {
                meta.enable_equality(c);
            }
            let add = AddChip::configure(meta, advice[0], advice[1], advice[2]);
            AddTestConfig { advice, add }
        }

        fn synthesize(
            &self,
            config: AddTestConfig,
            layouter: &mut Layouter<'_>,
        ) -> Result<(), Error> {
            let (a, b) = layouter.assign_region(|mut region| {
                let a = region.assign_advice(config.advice[0], 0, || self.a)?;
                let b = region.assign_advice(config.advice[1], 0, || self.b)?;
                Ok((a, b))
            })?;
            let chip = AddChip::construct(config.add.clone());
            let c = chip.add(layouter.namespace(), &a, &b)?;
            layouter.assign_region(|mut region| {
                let expected = region.assign_advice(config.advice[0], 0, || self.c)?;
                region.constrain_equal(c.cell(), expected.cell())
            })
        }
    }

    fn operands() -> (Fp, Fp) {
        (
            Fp::from_u128(0x0123456789abcdef_fedcba9876543210),
            -Fp::from_u128(0x0f1e2d3c4b5a6978_8796a5b4c3d2e1f0),
        )
    }

    #[test]
    fn add_chip() {
        let (a, b) = operands();
        let circuit = |c: Fp| AddCircuit {
            a: Value::known(a),
            b: Value::known(b),
            c: Value::known(c),
        };
        MockProver::run(4, &circuit(a + b), vec![])
            .unwrap()
            .assert_satisfied();
        // a wrong sum breaks the copy constraint on the output
        let err = MockProver::run(4, &circuit(a + b + Fp::ONE), vec![])
            .unwrap()
            .verify()
            .unwrap_err();
        assert!(err.contains("copy"), "{err}");
        // and a wrong cell in the chip's row breaks the gate
        let mut prover = MockProver::run(4, &circuit(a + b), vec![]).unwrap();
        prover.advice[2][0] += Fp::ONE;
        assert!(prover.verify().unwrap_err().contains("gate"));
    }

    /// The constraint system and the layout are those of the reference: the
    /// expected values are the SHA-256 hashes of the dumps of a scratch
    /// project compiling `orchard-0.16.0/src/circuit/gadget/add_chip.rs`
    /// itself against `halo2_proofs` 0.4.1 in this same test circuit (`V1`
    /// floor planner): the `{:?}` of `ConstraintSystem::pinned()`, and the
    /// ordered log of the floor planner's calls on the `Assignment` backend
    /// (see `poseidon::test_util`).
    #[test]
    fn layout_matches_reference() {
        let (a, b) = operands();
        let circuit = AddCircuit {
            a: Value::known(a),
            b: Value::known(b),
            c: Value::known(a + b),
        };
        let (pinned, events) = dump(&circuit);
        assert_dump(
            "add_pinned",
            &pinned,
            823,
            "14220a6fd85cb1716604ea7bc4dc198842230b0c718ed5465de177d1cce89939",
        );
        assert_dump(
            "add_events",
            &events,
            958,
            "69ed138694659fc4dae09379cbc0ada92cbf1264db1e955d04ce0f753ab15f2c",
        );
    }
}
