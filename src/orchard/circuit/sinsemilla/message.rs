//! Gadget and chips for the Sinsemilla hash function: the message types of
//! the chip (port of `halo2_gadgets::sinsemilla::message`).

use alloc::vec::Vec;

use crate::orchard::Fp;
use crate::orchard::halo2::Value;
use crate::orchard::halo2::circuit::AssignedCell;
use crate::orchard::sinsemilla::{C, K};

/// The number of bits of an element of the Pallas base field
/// (`pallas::Base::NUM_BITS`).
const FIELD_NUM_BITS: usize = 255;

/// A message to be hashed.
///
/// Composed of [`MessagePiece`]s with bitlength some multiple of `K`.
#[derive(Clone, Debug)]
pub(crate) struct Message(Vec<MessagePiece>);

impl From<Vec<MessagePiece>> for Message {
    fn from(pieces: Vec<MessagePiece>) -> Self {
        // A message cannot contain more than `MAX_WORDS` (= `C`) words.
        assert!(pieces.iter().map(|piece| piece.num_words()).sum::<usize>() < C);
        Message(pieces)
    }
}

impl core::ops::Deref for Message {
    type Target = [MessagePiece];

    fn deref(&self) -> &[MessagePiece] {
        &self.0
    }
}

/// A [`MessagePiece`] of some bitlength.
///
/// The piece must fit within a base field element, which means its length
/// cannot exceed the base field's `NUM_BITS`.
#[derive(Clone, Debug)]
pub(crate) struct MessagePiece {
    cell_value: AssignedCell<Fp>,
    /// The number of K-bit words in this message piece.
    num_words: usize,
}

impl MessagePiece {
    /// Constructs a piece of `num_words` words held by `cell_value`.
    ///
    /// # Panics
    /// Panics if the piece does not fit in a base field element.
    pub(crate) fn new(cell_value: AssignedCell<Fp>, num_words: usize) -> Self {
        assert!(num_words * K < FIELD_NUM_BITS);
        Self {
            cell_value,
            num_words,
        }
    }

    /// The number of K-bit words in this message piece.
    pub(crate) fn num_words(&self) -> usize {
        self.num_words
    }

    /// The value of this message piece.
    pub(crate) fn field_elem(&self) -> Value<Fp> {
        self.cell_value.value().cloned()
    }

    /// The assigned cell of this message piece.
    pub(crate) fn cell_value(&self) -> AssignedCell<Fp> {
        self.cell_value.clone()
    }
}
