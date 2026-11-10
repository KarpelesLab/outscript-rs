//! The Poseidon hash gadget (`halo2_gadgets::poseidon`), specialized to what
//! the Orchard Action circuit uses: the `P128Pow5T3` permutation over `Fp`
//! (width 3, rate 2) in the `ConstantLength<2>` domain, on the
//! [`Pow5Chip`].

use crate::orchard::Fp;
use crate::orchard::halo2::Error;
use crate::orchard::halo2::circuit::{AssignedCell, Layouter};

// Declared here until `circuit/mod.rs` does.
#[path = "../add_chip.rs"]
pub(crate) mod add_chip;
mod pow5;
#[cfg(test)]
pub(crate) mod test_util;

#[allow(unused_imports)]
pub(crate) use pow5::{Pow5Chip, Pow5Config, StateWord};

/// The width of the permutation.
pub(crate) const WIDTH: usize = crate::orchard::poseidon::WIDTH;
/// The rate of the sponge.
pub(crate) const RATE: usize = crate::orchard::poseidon::RATE;
/// The length of the messages hashed.
pub(crate) const L: usize = 2;

/// The type used to hold permutation state.
pub(crate) type State<F> = [F; WIDTH];

/// The type used to hold sponge rate.
type SpongeRate<F> = [Option<F>; RATE];

/// The absorbing state of the [`Sponge`].
#[derive(Debug)]
pub(crate) struct Absorbing<F>(SpongeRate<F>);

/// The squeezing state of the [`Sponge`].
#[derive(Debug)]
pub(crate) struct Squeezing<F>(SpongeRate<F>);

impl<F> Absorbing<F> {
    /// Initializes an empty sponge in the absorbing state.
    pub(crate) fn init_empty() -> Self {
        Self(core::array::from_fn(|_| None))
    }

    /// Attempts to absorb a value into the sponge state.
    ///
    /// Returns the value if it was not absorbed because the sponge is full.
    pub(crate) fn absorb(&mut self, value: F) -> Result<(), F> {
        for entry in self.0.iter_mut() {
            if entry.is_none() {
                *entry = Some(value);
                return Ok(());
            }
        }
        // Sponge is full.
        Err(value)
    }

    /// Exposes the inner state of the sponge.
    pub(crate) fn expose_inner(&self) -> &SpongeRate<F> {
        &self.0
    }
}

impl<F> Squeezing<F> {
    /// Initializes a full sponge in the squeezing state.
    pub(crate) fn init_full(vals: [F; RATE]) -> Self {
        Self(vals.map(Some))
    }

    /// Attempts to squeeze a value from the sponge state.
    ///
    /// Returns `None` if the sponge is empty.
    pub(crate) fn squeeze(&mut self) -> Option<F> {
        for entry in self.0.iter_mut() {
            if let Some(inner) = entry.take() {
                return Some(inner);
            }
        }
        // Sponge is empty.
        None
    }
}

/// The domain the hash is used in: constant input length [`L`] (`2`),
/// `halo2_poseidon::ConstantLength<2>`.
pub(crate) struct ConstantLength;

impl ConstantLength {
    /// The initial capacity element, encoding this domain.
    pub(crate) fn initial_capacity_element() -> Fp {
        // Capacity value is $length \cdot 2^64 + (o-1)$ where o is the
        // output length. We hard-code an output length of 1.
        Fp::from_u128((L as u128) << 64)
    }

    /// Returns the padding to be appended to the input.
    pub(crate) fn padding(input_len: usize) -> impl Iterator<Item = Fp> {
        assert_eq!(input_len, L);
        // For constant-input-length hashing, we pad the input with zeroes to
        // a multiple of RATE. On its own this would not be sponge-compliant
        // padding, but the Poseidon authors encode the constant length into
        // the capacity element, ensuring that inputs of different lengths do
        // not share the same permutation. (For L = 2 there is no padding.)
        let k = L.div_ceil(RATE);
        core::iter::repeat_n(Fp::ZERO, k * RATE - L)
    }
}

/// A word from the padded input to a Poseidon sponge.
#[derive(Clone, Debug)]
pub(crate) enum PaddedWord {
    /// A message word provided by the prover.
    Message(AssignedCell<Fp>),
    /// A padding word, that will be fixed in the circuit parameters.
    Padding(Fp),
}

fn poseidon_sponge(
    chip: &Pow5Chip,
    layouter: &mut Layouter<'_>,
    state: &mut State<StateWord>,
    input: Option<&Absorbing<PaddedWord>>,
) -> Result<Squeezing<StateWord>, Error> {
    if let Some(input) = input {
        *state = chip.add_input(layouter, state, input)?;
    }
    *state = chip.permute(layouter, state)?;
    Ok(Pow5Chip::get_output(state))
}

/// A Poseidon sponge, in the mode `M` ([`Absorbing`] or [`Squeezing`]).
#[derive(Debug)]
pub(crate) struct Sponge<M> {
    chip: Pow5Chip,
    mode: M,
    state: State<StateWord>,
}

impl Sponge<Absorbing<PaddedWord>> {
    /// Constructs a new duplex sponge.
    pub(crate) fn new(chip: Pow5Chip, layouter: &mut Layouter<'_>) -> Result<Self, Error> {
        chip.initial_state(layouter).map(|state| Sponge {
            chip,
            mode: Absorbing::init_empty(),
            state,
        })
    }

    /// Absorbs an element into the sponge.
    pub(crate) fn absorb(
        &mut self,
        layouter: &mut Layouter<'_>,
        value: PaddedWord,
    ) -> Result<(), Error> {
        let value = match self.mode.absorb(value) {
            Ok(()) => return Ok(()),
            Err(value) => value,
        };

        // We've already absorbed as many elements as we can
        let _ = poseidon_sponge(
            &self.chip,
            layouter.namespace(),
            &mut self.state,
            Some(&self.mode),
        )?;
        self.mode = Absorbing::init_empty();
        self.mode.absorb(value).expect("state is not full");

        Ok(())
    }

    /// Transitions the sponge into its squeezing state.
    pub(crate) fn finish_absorbing(
        mut self,
        layouter: &mut Layouter<'_>,
    ) -> Result<Sponge<Squeezing<StateWord>>, Error> {
        let mode = poseidon_sponge(
            &self.chip,
            layouter.namespace(),
            &mut self.state,
            Some(&self.mode),
        )?;

        Ok(Sponge {
            chip: self.chip,
            mode,
            state: self.state,
        })
    }
}

impl Sponge<Squeezing<StateWord>> {
    /// Squeezes an element from the sponge.
    pub(crate) fn squeeze(
        &mut self,
        layouter: &mut Layouter<'_>,
    ) -> Result<AssignedCell<Fp>, Error> {
        loop {
            if let Some(value) = self.mode.squeeze() {
                return Ok(value.into());
            }

            // We've already squeezed out all available elements
            self.mode = poseidon_sponge(&self.chip, layouter.namespace(), &mut self.state, None)?;
        }
    }
}

/// A Poseidon hash function, built around a sponge.
#[derive(Debug)]
pub(crate) struct Hash {
    sponge: Sponge<Absorbing<PaddedWord>>,
}

impl Hash {
    /// Initializes a new hasher.
    pub(crate) fn init(chip: Pow5Chip, layouter: &mut Layouter<'_>) -> Result<Self, Error> {
        Sponge::new(chip, layouter).map(|sponge| Hash { sponge })
    }

    /// Hashes the given input.
    pub(crate) fn hash(
        mut self,
        layouter: &mut Layouter<'_>,
        message: [AssignedCell<Fp>; L],
    ) -> Result<AssignedCell<Fp>, Error> {
        for value in message
            .into_iter()
            .map(PaddedWord::Message)
            .chain(ConstantLength::padding(L).map(PaddedWord::Padding))
        {
            self.sponge.absorb(layouter.namespace(), value)?;
        }
        self.sponge
            .finish_absorbing(layouter.namespace())?
            .squeeze(layouter.namespace())
    }
}
