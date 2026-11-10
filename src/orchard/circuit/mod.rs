//! The Orchard Action circuit and the gadgets it is built from (feature
//! `zcash-orchard-prover`): ports of `halo2_gadgets` and of the circuit of
//! the `orchard` crate onto [`halo2`](super::halo2), laid out exactly as the
//! reference so that the verifying key is the same.

// While the port is in progress.
#![allow(dead_code)]

pub(crate) mod add_chip;
pub(crate) mod ecc;
pub(crate) mod poseidon;
pub(crate) mod sinsemilla;
pub(crate) mod utilities;
