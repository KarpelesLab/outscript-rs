//! The assignment of a Sinsemilla hash (port of
//! `halo2_gadgets::sinsemilla::chip::hash_to_point`).
//!
//! The reference computes the witnesses with `Assigned` (lazily inverted
//! fractions); here inversions are eager (`0` for `1/0`), which gives the
//! same cells whenever no denominator is zero, i.e. whenever the hash is
//! defined and the circuit satisfiable.

use alloc::vec::Vec;

use super::{Message, MessagePiece, NonIdentityEccPoint, RunningSum, SinsemillaChip};
use crate::orchard::constants::SINSEMILLA_S;
use crate::orchard::halo2::circuit::{AssignedCell, Region};
use crate::orchard::halo2::{Error, Value};
use crate::orchard::sinsemilla::K;
use crate::orchard::{Fp, pallas};

impl SinsemillaChip {
    /// [Specification](https://p.z.cash/halo2-0.1:sinsemilla-constraints?partial).
    #[allow(non_snake_case)]
    pub(super) fn hash_message(
        &self,
        region: &mut Region<'_, '_>,
        Q: pallas::Affine,
        message: &Message,
    ) -> Result<(NonIdentityEccPoint, Vec<RunningSum>), Error> {
        // Coordinates of the initial point `Q` are assigned to advice
        // columns
        let (offset, x_a, y_a) = self.public_q_initialization(region, Q)?;

        let (x_a, y_a, zs_sum) = self.hash_all_pieces(region, offset, message, x_a, y_a)?;

        #[cfg(test)]
        self.check_hash_result(Q, message, &x_a, &y_a);

        x_a.value()
            .zip(y_a.value())
            .error_if_known_and(|(x_a, y_a)| bool::from(x_a.is_zero() | y_a.is_zero()))?;
        Ok((
            NonIdentityEccPoint::from_coordinates_unchecked(x_a, y_a),
            zs_sum,
        ))
    }

    /// Assign the coordinates of the initial public point `Q`.
    ///
    /// | offset | x_A | q_sinsemilla4 | fixed_y_q |
    /// --------------------------------------
    /// |   0    | x_Q |   1           |   y_Q     |
    #[allow(non_snake_case)]
    fn public_q_initialization(
        &self,
        region: &mut Region<'_, '_>,
        Q: pallas::Affine,
    ) -> Result<(usize, AssignedCell<Fp>, Value<Fp>), Error> {
        let config = self.config().clone();
        let offset = 0;

        // Get the `x`- and `y`-coordinates of the starting `Q` base.
        let x_q = Q.x();
        let y_q = Q.y();

        // Constrain the initial x_a, lambda_1, lambda_2, x_p using the
        // q_sinsemilla4 selector.
        let y_a: Value<Fp> = {
            // Enable `q_sinsemilla4` on the first row.
            config.q_sinsemilla4.enable(region, offset)?;
            region.assign_fixed(config.fixed_y_q, offset, || Value::known(y_q))?;

            Value::known(y_q)
        };

        // Constrain the initial x_q to equal the x-coordinate of the domain's
        // `Q`.
        let x_a = region.assign_advice_from_constant(config.double_and_add.x_a, offset, x_q)?;

        Ok((offset, x_a, y_a))
    }

    /// Hashes all the pieces of the message, and assigns the final `y_a`.
    #[allow(clippy::type_complexity)]
    fn hash_all_pieces(
        &self,
        region: &mut Region<'_, '_>,
        mut offset: usize,
        message: &Message,
        mut x_a: AssignedCell<Fp>,
        mut y_a: Value<Fp>,
    ) -> Result<(AssignedCell<Fp>, AssignedCell<Fp>, Vec<RunningSum>), Error> {
        let config = self.config().clone();

        let mut zs_sum: Vec<RunningSum> = Vec::new();

        // Hash each piece in the message.
        for (idx, piece) in message.iter().enumerate() {
            let final_piece = idx == message.len() - 1;

            // The value of the accumulator after this piece is processed.
            let (x, y, zs) = self.hash_piece(region, offset, piece, x_a, y_a, final_piece)?;

            // Since each message word takes one row to process, we increase
            // the offset by `piece.num_words` on each iteration.
            offset += piece.num_words();

            // Update the accumulator to the latest value.
            x_a = x;
            y_a = y;
            zs_sum.push(zs);
        }

        // Assign the final y_a.
        let y_a = {
            // Assign the final y_a.
            let y_a_cell = region.assign_advice(config.double_and_add.lambda_1, offset, || y_a)?;

            // Assign lambda_2 and x_p zero values since they are queried in
            // the gate. (The actual values do not matter since they are
            // multiplied by zero.)
            {
                region.assign_advice(config.double_and_add.lambda_2, offset, || {
                    Value::known(Fp::ZERO)
                })?;
                region
                    .assign_advice(config.double_and_add.x_p, offset, || Value::known(Fp::ZERO))?;
            }

            y_a_cell
        };

        Ok((x_a, y_a, zs_sum))
    }

    /// Hashes a message piece containing `piece.length` number of `K`-bit
    /// words.
    ///
    /// To avoid a duplicate assignment, the accumulator x-coordinate
    /// provided by the caller is not copied. This only works because
    /// `hash_piece()` is an internal API. Before this call the x-coordinate
    /// of the accumulator MUST have been already assigned within this
    /// region at the given offset.
    #[allow(clippy::type_complexity)]
    fn hash_piece(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        piece: &MessagePiece,
        mut x_a: AssignedCell<Fp>,
        mut y_a: Value<Fp>,
        final_piece: bool,
    ) -> Result<(AssignedCell<Fp>, Value<Fp>, RunningSum), Error> {
        let config = self.config().clone();

        // Selector assignments
        {
            // Enable `q_sinsemilla1` selector on every row.
            for row in 0..piece.num_words() {
                config.q_sinsemilla1.enable(region, offset + row)?;
            }

            // Set `q_sinsemilla2` fixed column to 1 on every row but the
            // last.
            for row in 0..(piece.num_words() - 1) {
                region
                    .assign_fixed(config.q_sinsemilla2, offset + row, || Value::known(Fp::ONE))?;
            }

            // Set `q_sinsemilla2` fixed column to 0 on the last row if this
            // is not the final piece, or to 2 on the last row of the final
            // piece.
            region.assign_fixed(config.q_sinsemilla2, offset + piece.num_words() - 1, || {
                Value::known(if final_piece {
                    Fp::from_u64(2)
                } else {
                    Fp::ZERO
                })
            })?;
        }

        // Message piece as K * piece.length bitstring, as K-bit words.
        let words: Value<Vec<u32>> = piece.field_elem().map(|value| {
            (0..piece.num_words())
                .map(|w| {
                    (0..K).fold(0u32, |acc, i| {
                        acc + if value.bit(w * K + i) { 1 << i } else { 0 }
                    })
                })
                .collect()
        });

        // Get (x_p, y_p) for each word.
        let generators: Value<Vec<(Fp, Fp)>> = words.clone().map(|words| {
            words
                .iter()
                .map(|word| {
                    let s = &SINSEMILLA_S[*word as usize];
                    (s.x(), s.y())
                })
                .collect()
        });

        // Convert `words` from `Value<Vec<u32>>` to `Vec<Value<u32>>`
        let words = words.transpose_vec(piece.num_words());

        // Decompose message piece into `K`-bit words.
        // This returns `piece.num_words()` number of `K`-bit words.
        // We initialize the running sum `z_0` to be the message piece, and
        // decompose it using
        //          z_{i + 1} = (z_i - m_{i + 1}) / 2^K
        let zs = {
            let mut zs = Vec::with_capacity(piece.num_words() + 1);

            // Copy message and initialize running sum `z` to decompose
            // message in-circuit
            let initial_z = piece
                .cell_value()
                .copy_advice(region, config.bits, offset)?;
            zs.push(initial_z);

            // Assign cumulative sum such that for 0 <= i < n,
            //          z_i = 2^K * z_{i + 1} + m_{i + 1}
            // => z_{i + 1} = (z_i - m_{i + 1}) / 2^K
            //
            // For a message piece m = m_1 + 2^K m_2 + ... + 2^{K(n-1)} m_n},
            // initialize z_0 = m. We end up with z_n = 0. (z_n is not
            // directly encoded as a cell value; it is implicitly taken as 0
            // by adjusting the definition of m_{i+1}.)
            let mut z = piece.field_elem();
            let inv_2_k = Value::known(Fp::from_u64(1 << K).invert_or_zero());

            // We do not assign the final z_n as it is constrained to be
            // zero.
            for (idx, word) in words[0..(words.len() - 1)].iter().enumerate() {
                let word = word.map(|word| Fp::from_u64(word as u64));
                // z_{i + 1} = (z_i - m_{i + 1}) / 2^K
                z = (z - word) * inv_2_k;
                let cell = region.assign_advice(config.bits, offset + idx + 1, || z)?;
                zs.push(cell)
            }

            zs
        };

        // The accumulator x-coordinate provided by the caller MUST have been
        // assigned within this region.

        let generators = generators.transpose_vec(piece.num_words());

        for (row, generator) in generators.iter().enumerate() {
            let x_p = generator.map(|generator| generator.0);
            let y_p = generator.map(|generator| generator.1);

            // Assign `x_p`
            region.assign_advice(config.double_and_add.x_p, offset + row, || x_p)?;

            // Compute and assign `lambda_1`
            let lambda_1 = {
                let lambda_1 = (y_a - y_p) * (x_a.value().copied() - x_p).invert();

                // Assign lambda_1
                region.assign_advice(config.double_and_add.lambda_1, offset + row, || lambda_1)?;

                lambda_1
            };

            // Compute `x_r`
            let x_r = lambda_1.square() - x_a.value().copied() - x_p;

            // Compute and assign `lambda_2`
            let lambda_2 = {
                let lambda_2 =
                    y_a * Fp::from_u64(2) * (x_a.value().copied() - x_r).invert() - lambda_1;

                region.assign_advice(config.double_and_add.lambda_2, offset + row, || lambda_2)?;

                lambda_2
            };

            // Compute and assign `x_a` for the next row.
            let x_a_new = {
                let x_a_new = lambda_2.square() - x_a.value().copied() - x_r;

                region.assign_advice(config.double_and_add.x_a, offset + row + 1, || x_a_new)?
            };

            // Compute y_a for the next row.
            let y_a_new: Value<Fp> =
                lambda_2 * (x_a.value().copied() - x_a_new.value().copied()) - y_a;

            // Update the mutable `x_a`, `y_a` variables.
            x_a = x_a_new;
            y_a = y_a_new;
        }

        Ok((x_a, y_a, zs))
    }

    /// Checks the assigned result against the native Sinsemilla hash, when
    /// the latter is defined.
    #[cfg(test)]
    #[allow(non_snake_case)]
    fn check_hash_result(
        &self,
        Q: pallas::Affine,
        message: &Message,
        x_a: &AssignedCell<Fp>,
        y_a: &AssignedCell<Fp>,
    ) {
        let field_elems: Value<Vec<(Fp, usize)>> = message
            .iter()
            .map(|piece| piece.field_elem().map(|elem| (elem, piece.num_words())))
            .fold(Value::known(Vec::new()), |acc, v| {
                acc.zip(v).map(|(mut acc, v)| {
                    acc.push(v);
                    acc
                })
            });

        field_elems
            .zip(x_a.value().zip(y_a.value()))
            .assert_if_known(|(field_elems, (x_a, y_a))| {
                // Get message as a bitstring.
                let bitstring: Vec<bool> = field_elems
                    .iter()
                    .flat_map(|(elem, num_words)| (0..K * num_words).map(move |i| elem.bit(i)))
                    .collect();

                match crate::orchard::sinsemilla::hash_to_point(&Q, bitstring) {
                    Some(expected_point) => {
                        let expected_point = expected_point.to_affine();
                        expected_point.x() == **x_a && expected_point.y() == **y_a
                    }
                    // The hash is undefined: nothing to compare with.
                    None => true,
                }
            });
    }
}
