//! Gadgets of the Action circuit (port of `orchard::circuit::gadget`).
//!
//! The chip accessors of the reference (`impl super::Config`) belong to the
//! Action circuit, and its `AddInstruction` trait is replaced by the
//! inherent `add` of [`AddChip`].

#![allow(dead_code)]

use super::add_chip::AddChip;
use super::ecc::chip::{EccChip, NullifierK, OrchardFixedBasesFull, ValueCommitV};
use super::ecc::{
    FixedPoint, FixedPointBaseField, FixedPointShort, Point, ScalarFixed, ScalarFixedShort, X,
};
use super::poseidon::{Hash as PoseidonHash, Pow5Chip as PoseidonChip};
use crate::orchard::Fp;
use crate::orchard::halo2::circuit::{AssignedCell, CellValue, Layouter};
use crate::orchard::halo2::plonk::{Advice, Column};
use crate::orchard::halo2::{Error, Value};

/// Witnesses the given value in a standalone region.
///
/// Usages of this helper are technically superfluous, as the single-cell
/// region is only ever used in equality constraints. We could eliminate them
/// with a write-on-copy abstraction (<https://github.com/zcash/halo2/issues/334>).
pub(crate) fn assign_free_advice<V: CellValue + Copy>(
    layouter: &mut Layouter<'_>,
    column: Column<Advice>,
    value: Value<V>,
) -> Result<AssignedCell<V>, Error> {
    // "load private"
    layouter.assign_region(|mut region| region.assign_advice(column, 0, || value))
}

/// `ValueCommit^Orchard` from [Section 5.4.8.3 Homomorphic Pedersen
/// commitments (Sapling and Orchard)].
///
/// [Section 5.4.8.3 Homomorphic Pedersen commitments (Sapling and Orchard)]: https://zips.z.cash/protocol/protocol.pdf#concretehomomorphiccommit
pub(crate) fn value_commit_orchard(
    layouter: &mut Layouter<'_>,
    ecc_chip: EccChip,
    v: ScalarFixedShort,
    rcv: ScalarFixed,
) -> Result<Point, Error> {
    // commitment = [v] ValueCommitV
    let (commitment, _) = {
        let value_commit_v = FixedPointShort::from_inner(ecc_chip, ValueCommitV);
        value_commit_v.mul(layouter.namespace(), v)?
    };

    // blind = [rcv] ValueCommitR
    let (blind, _rcv) = {
        let value_commit_r = OrchardFixedBasesFull::ValueCommitR;
        let value_commit_r = FixedPoint::from_inner(ecc_chip, value_commit_r);

        // [rcv] ValueCommitR
        value_commit_r.mul(layouter.namespace(), rcv)?
    };

    // [v] ValueCommitV + [rcv] ValueCommitR
    commitment.add(layouter.namespace(), &blind)
}

/// `DeriveNullifier` from [Section 4.16: Note Commitments and Nullifiers].
///
/// [Section 4.16: Note Commitments and Nullifiers]: https://zips.z.cash/protocol/protocol.pdf#commitmentsandnullifiers
#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_nullifier(
    layouter: &mut Layouter<'_>,
    poseidon_chip: PoseidonChip,
    add_chip: AddChip,
    ecc_chip: EccChip,
    rho: AssignedCell<Fp>,
    psi: &AssignedCell<Fp>,
    cm: &Point,
    nk: AssignedCell<Fp>,
) -> Result<X, Error> {
    // hash = poseidon_hash(nk, rho)
    let hash = {
        let poseidon_message = [nk, rho];
        let poseidon_hasher = PoseidonHash::init(poseidon_chip, layouter.namespace())?;
        poseidon_hasher.hash(layouter.namespace(), poseidon_message)?
    };

    // Add hash output to psi.
    // `scalar` = poseidon_hash(nk, rho) + psi.
    let scalar = add_chip.add(layouter.namespace(), &hash, psi)?;

    // Multiply scalar by NullifierK
    // `product` = [poseidon_hash(nk, rho) + psi] NullifierK.
    let product = {
        let nullifier_k = FixedPointBaseField::from_inner(ecc_chip, NullifierK);
        nullifier_k.mul(layouter.namespace(), scalar)?
    };

    // Add cm to multiplied fixed base to get nf
    // cm + [poseidon_output + psi] NullifierK
    cm.add(layouter.namespace(), &product)
        .map(|res| res.extract_p())
}

#[allow(unused_imports)]
pub(crate) use super::commit_ivk::gadgets::commit_ivk;
#[allow(unused_imports)]
pub(crate) use super::note_commit::gadgets::note_commit;

#[cfg(test)]
mod tests;
