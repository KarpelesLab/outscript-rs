//! Test helpers: dumps of a circuit's constraint system and layout in the
//! text format of the scratch reference project (which runs the same circuit
//! on `halo2_proofs` 0.4.1 and prints the same thing), so that a port can be
//! checked cell for cell against the reference.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::orchard::Fp;
use crate::orchard::halo2::circuit::{Assignment, Circuit, synthesize};
use crate::orchard::halo2::plonk::{
    Advice, Any, Column, ConstraintSystem, Fixed, Hex, Instance, PinnedConstraintSystem, Selector,
};
use crate::orchard::halo2::{Error, Value};

/// An [`Assignment`] backend logging every call of the floor planner, one
/// line each, in order:
/// `S <selector> <row>`, `A <column> <row> <value>`, `F <column> <row>
/// <value>`, `C <column> <row> <column> <row>` (copy), `L <column> <row>
/// <value>` (fill from row); columns and selectors as their `{:?}`, values as
/// `0x` and 64 hex digits (`?` if unknown).
#[derive(Default)]
struct Recorder {
    log: String,
}

fn val(v: Value<Fp>) -> String {
    match v.into_option() {
        Some(v) => format!("{:?}", Hex(&v)),
        None => String::from("?"),
    }
}

impl Assignment for Recorder {
    fn enable_selector(&mut self, selector: &Selector, row: usize) -> Result<(), Error> {
        writeln!(self.log, "S {:?} {}", selector, row).unwrap();
        Ok(())
    }

    fn query_instance(&self, _: Column<Instance>, _: usize) -> Result<Value<Fp>, Error> {
        Ok(Value::unknown())
    }

    fn assign_advice(
        &mut self,
        column: Column<Advice>,
        row: usize,
        to: &mut dyn FnMut() -> Value<Fp>,
    ) -> Result<(), Error> {
        writeln!(self.log, "A {:?} {} {}", column, row, val(to())).unwrap();
        Ok(())
    }

    fn assign_fixed(
        &mut self,
        column: Column<Fixed>,
        row: usize,
        to: &mut dyn FnMut() -> Value<Fp>,
    ) -> Result<(), Error> {
        writeln!(self.log, "F {:?} {} {}", column, row, val(to())).unwrap();
        Ok(())
    }

    fn copy(
        &mut self,
        left_column: Column<Any>,
        left_row: usize,
        right_column: Column<Any>,
        right_row: usize,
    ) -> Result<(), Error> {
        writeln!(
            self.log,
            "C {:?} {} {:?} {}",
            left_column, left_row, right_column, right_row
        )
        .unwrap();
        Ok(())
    }

    fn fill_from_row(
        &mut self,
        column: Column<Fixed>,
        row: usize,
        to: Value<Fp>,
    ) -> Result<(), Error> {
        writeln!(self.log, "L {:?} {} {}", column, row, val(to)).unwrap();
        Ok(())
    }
}

/// The `{:?}` of the pinned constraint system of `circuit` after
/// `configure`, and the log of its synthesis (see [`Recorder`]).
pub(crate) fn dump<C: Circuit>(circuit: &C) -> (String, String) {
    let mut cs = ConstraintSystem::default();
    let config = circuit.configure(&mut cs);
    let pinned = format!("{:?}", PinnedConstraintSystem(&cs));
    let mut recorder = Recorder::default();
    let constants: Vec<Column<Fixed>> = cs.constants.clone();
    synthesize(&mut recorder, circuit, config, constants).unwrap();
    (pinned, recorder.log)
}

/// Asserts that a dump has the length and the SHA-256 hash of the
/// reference's. To inspect a mismatch, set `OUTSCRIPT_DUMP_DIR` to have the
/// dump written to `<dir>/<name>.txt` and diff it with the reference's.
pub(crate) fn assert_dump(name: &str, ours: &str, len: usize, sha256: &str) {
    if let Ok(dir) = std::env::var("OUTSCRIPT_DUMP_DIR") {
        std::fs::write(format!("{dir}/{name}.txt"), ours).unwrap();
    }
    let hash = hex::encode(purecrypto::hash::sha256(ours.as_bytes()));
    assert!(
        ours.len() == len && hash == sha256,
        "{name} dump differs from the reference: {} bytes, sha256 {hash}",
        ours.len()
    );
}
