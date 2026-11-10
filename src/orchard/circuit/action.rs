//! The constraint system and the synthesis of the Action circuit (port of
//! `orchard::circuit`).

use super::ActionCircuit;
use crate::orchard::halo2::Error;
use crate::orchard::halo2::circuit::{Circuit, Layouter};
use crate::orchard::halo2::plonk::ConstraintSystem;

/// Configuration needed to use the Orchard Action circuit.
#[derive(Clone, Debug)]
pub struct Config {}

impl Circuit for ActionCircuit {
    type Config = Config;

    fn without_witnesses(&self) -> Self {
        ActionCircuit::empty(self.version)
    }

    fn configure(&self, _meta: &mut ConstraintSystem) -> Config {
        Config {}
    }

    fn synthesize(&self, _config: Config, _layouter: &mut Layouter<'_>) -> Result<(), Error> {
        // PLACEHOLDER until the gadgets are in place.
        Err(Error::Synthesis)
    }
}
