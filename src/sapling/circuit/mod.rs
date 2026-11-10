//! The Sapling Spend and Output circuits (feature `zcash-sapling-prover`).
//!
//! [`Spend`] and [`Output`] lay out, constraint for constraint and variable
//! for variable, the circuits of `sapling-crypto` (protocol specification
//! §4.17 and Appendix A.4), which the Sapling proving parameters were
//! generated for: 98777 constraints for a Spend, 7827 for an Output. The
//! gadgets they are assembled from are private to this module.
//!
//! A circuit value holds a complete witness. Synthesizing it with
//! [`create_proof`](super::groth16::create_proof) gives a proof for the
//! statement's public inputs:
//!
//! - Spend: `rk`, `cv`, the anchor and the nullifier;
//! - Output: `cv`, `epk` and the note commitment `cmu`.
//!
//! The witness is not checked against any public input here: a witness
//! that is not consistent gives a proof that does not verify (or, when a
//! point is of small order, an error). [`prover`](super::prover) has the
//! typed interface.

mod blake2s;
mod ecc;
mod gadgets;

use crate::prelude::*;
use crate::sapling::field::{Fq, Fr};
use crate::sapling::generators::{
    NOTE_COMMITMENT_RANDOMNESS_BASE, NULLIFIER_POSITION_BASE, PROOF_GENERATION_KEY_BASE,
    SPENDING_KEY_BASE, VALUE_COMMITMENT_RANDOMNESS_BASE, VALUE_COMMITMENT_VALUE_BASE,
};
use crate::sapling::groth16::{Circuit, ConstraintSystem, SynthesisError};
use crate::sapling::jubjub::Point;
use crate::sapling::keys::ProofGenerationKey;
use ecc::{EdwardsPoint, PedersenTables, fixed_base_multiplication, pedersen_hash};
use gadgets::{AllocatedBit, AllocatedNum, Boolean, Num};
use purecrypto::zeroize::Zeroize;

pub(crate) use gadgets::multipack;

/// The number of constraints of the Spend circuit, for a tree of depth 32.
pub const SPEND_CONSTRAINTS: usize = 98777;
/// The number of constraints of the Output circuit.
pub const OUTPUT_CONSTRAINTS: usize = 7827;

/// The personalization bits of the note commitment's Pedersen hash.
const NOTE_COMMITMENT_PERSONALIZATION: [bool; 6] = [true; 6];

/// The personalization bits of the Merkle hash at `level`.
fn merkle_personalization(level: usize) -> [bool; 6] {
    core::array::from_fn(|i| (level >> i) & 1 == 1)
}

/// The number of bits of an incoming viewing key: the output of `CRH^ivk`
/// is truncated to 251 bits.
const IVK_BITS: usize = 251;

/// The witness of a Spend statement: knowledge of a note in the commitment
/// tree, of the keys that can spend it, and of the openings of the value
/// commitment and the randomized key.
///
/// The secret scalars are wiped when the value is dropped.
#[derive(Clone)]
pub struct Spend {
    /// The value of the note.
    pub value: u64,
    /// The randomness `rcv` of the value commitment.
    pub rcv: Fr,
    /// The proof generation key `(ak, nsk)` of the note's owner.
    pub proof_generation_key: ProofGenerationKey,
    /// The diversified base `g_d` of the note's address.
    pub g_d: Point,
    /// The randomness `rcm` of the note commitment.
    pub rcm: Fr,
    /// The spend authorization randomizer `α`: `rk = ak + [α] G`.
    pub alpha: Fr,
    /// The authentication path of the note commitment, from the leaf up:
    /// each sibling, and whether the node on the path is the right child
    /// (the bit of the position at that level). The Sapling parameters
    /// are for a path of 32 elements.
    pub auth_path: Vec<(Fq, bool)>,
    /// The root of the tree the path leads to.
    pub anchor: Fq,
}

impl core::fmt::Debug for Spend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Spend(..)")
    }
}

impl Drop for Spend {
    fn drop(&mut self) {
        self.value.zeroize();
        self.rcv.zeroize();
        self.rcm.zeroize();
        self.alpha.zeroize();
    }
}

/// The witness of an Output statement: knowledge of the note committed to
/// by `cmu`, of the opening of its value commitment and of the ephemeral
/// secret key.
///
/// The secret scalars are wiped when the value is dropped.
#[derive(Clone)]
pub struct Output {
    /// The value of the note.
    pub value: u64,
    /// The randomness `rcv` of the value commitment.
    pub rcv: Fr,
    /// The diversified base `g_d` of the recipient's address.
    pub g_d: Point,
    /// The diversified transmission key `pk_d` of the recipient's address.
    pub pk_d: Point,
    /// The randomness `rcm` of the note commitment.
    pub rcm: Fr,
    /// The ephemeral secret key `esk`: `epk = [esk] g_d`.
    pub esk: Fr,
}

impl core::fmt::Debug for Output {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Output(..)")
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        self.value.zeroize();
        self.rcv.zeroize();
        self.rcm.zeroize();
        self.esk.zeroize();
    }
}

/// Exposes the value commitment `cv = [value] V + [rcv] R` as two public
/// inputs and returns the 64 bits of the value.
fn expose_value_commitment<CS: ConstraintSystem>(
    cs: &mut CS,
    value: u64,
    rcv: &Fr,
) -> Result<Vec<Boolean>, SynthesisError> {
    let value_bits = gadgets::u64_into_boolean_vec_le(cs, value)?;
    let value = fixed_base_multiplication(cs, &VALUE_COMMITMENT_VALUE_BASE, &value_bits)?;
    let rcv = gadgets::fr_into_boolean_vec_le(cs, rcv)?;
    let rcv = fixed_base_multiplication(cs, &VALUE_COMMITMENT_RANDOMNESS_BASE, &rcv)?;
    let cv = value.add(cs, &rcv)?;
    cv.inputize(cs)?;
    Ok(value_bits)
}

impl Circuit for Spend {
    fn synthesize<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let tables = PedersenTables::new(4);

        // ak must be on the curve and not of small order
        let ak = EdwardsPoint::witness(cs, &self.proof_generation_key.ak.to_affine())?;
        ak.assert_not_small_order(cs)?;

        // rk = ak + [α] G
        {
            let ar = gadgets::fr_into_boolean_vec_le(cs, &self.alpha)?;
            let ar = fixed_base_multiplication(cs, &SPENDING_KEY_BASE, &ar)?;
            let rk = ak.add(cs, &ar)?;
            rk.inputize(cs)?;
        }

        // nk = [nsk] H
        let nk = {
            let nsk = gadgets::fr_into_boolean_vec_le(cs, &self.proof_generation_key.nsk)?;
            fixed_base_multiplication(cs, &PROOF_GENERATION_KEY_BASE, &nsk)?
        };

        // ivk = CRH^ivk(ak, nk), truncated
        let mut ivk_preimage = ak.repr(cs)?;
        let mut nf_preimage = Vec::with_capacity(512);
        {
            let repr_nk = nk.repr(cs)?;
            ivk_preimage.extend_from_slice(&repr_nk);
            nf_preimage.extend_from_slice(&repr_nk);
        }
        let mut ivk = blake2s::blake2s(cs, &ivk_preimage, b"Zcashivk")?;
        ivk.truncate(IVK_BITS);

        // pk_d = [ivk] g_d, for a g_d not of small order
        let g_d = EdwardsPoint::witness(cs, &self.g_d.to_affine())?;
        g_d.assert_not_small_order(cs)?;
        let pk_d = g_d.mul(cs, &ivk)?;

        // the note: value, g_d, pk_d
        let mut note_contents = Vec::with_capacity(64 + 256 + 256);
        let mut value_num = Num::zero();
        {
            let value_bits = expose_value_commitment(cs, self.value, &self.rcv)?;
            let mut coeff = Fq::ONE;
            for bit in &value_bits {
                value_num = value_num.add_bool_with_coeff(CS::one(), bit, coeff);
                coeff = coeff.double();
            }
            note_contents.extend(value_bits);
        }
        note_contents.extend(g_d.repr(cs)?);
        note_contents.extend(pk_d.repr(cs)?);

        // cm = PedersenHash(note) + [rcm] R'
        let mut cm = pedersen_hash(cs, &tables, NOTE_COMMITMENT_PERSONALIZATION, &note_contents)?;
        {
            let rcm = gadgets::fr_into_boolean_vec_le(cs, &self.rcm)?;
            let rcm = fixed_base_multiplication(cs, &NOTE_COMMITMENT_RANDOMNESS_BASE, &rcm)?;
            cm = cm.add(cs, &rcm)?;
        }

        // the path from cm to the root
        let mut position_bits = Vec::with_capacity(self.auth_path.len());
        let mut cur = *cm.get_u();
        for (i, (sibling, is_right)) in self.auth_path.iter().enumerate() {
            let cur_is_right = Boolean::from(AllocatedBit::alloc(cs, *is_right)?);
            position_bits.push(cur_is_right);
            let path_element = AllocatedNum::alloc(cs, *sibling)?;
            let (ul, ur) =
                AllocatedNum::conditionally_reverse(cs, &cur, &path_element, &cur_is_right)?;
            let mut preimage = ul.to_bits_le(cs)?;
            preimage.extend(ur.to_bits_le(cs)?);
            cur = *pedersen_hash(cs, &tables, merkle_personalization(i), &preimage)?.get_u();
        }

        // the root is the anchor, unless the value is zero
        {
            let rt = AllocatedNum::alloc(cs, self.anchor)?;
            cs.enforce(
                |lc| lc + cur.get_variable() - rt.get_variable(),
                |lc| lc + &value_num.lc(Fq::ONE),
                |lc| lc,
            );
            rt.inputize(cs)?;
        }

        // rho = cm + [position] J, nf = PRF^nf(nk, rho)
        let mut rho = cm;
        {
            let position = fixed_base_multiplication(cs, &NULLIFIER_POSITION_BASE, &position_bits)?;
            rho = rho.add(cs, &position)?;
        }
        nf_preimage.extend(rho.repr(cs)?);
        let nf = blake2s::blake2s(cs, &nf_preimage, b"Zcash_nf")?;
        gadgets::pack_into_inputs(cs, &nf)
    }
}

impl Circuit for Output {
    fn synthesize<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let tables = PedersenTables::new(4);

        let mut note_contents = expose_value_commitment(cs, self.value, &self.rcv)?;

        // epk = [esk] g_d, for a g_d not of small order
        {
            let g_d = EdwardsPoint::witness(cs, &self.g_d.to_affine())?;
            g_d.assert_not_small_order(cs)?;
            note_contents.extend(g_d.repr(cs)?);
            let esk = gadgets::fr_into_boolean_vec_le(cs, &self.esk)?;
            let epk = g_d.mul(cs, &esk)?;
            epk.inputize(cs)?;
        }

        // pk_d is not checked to be a point: only its encoding is
        // committed to
        {
            let pk_d = self.pk_d.to_affine();
            let v_contents = gadgets::fq_into_boolean_vec_le(cs, &pk_d.v())?;
            let sign_bit = Boolean::from(AllocatedBit::alloc(cs, pk_d.u().is_odd())?);
            note_contents.extend(v_contents);
            note_contents.push(sign_bit);
        }

        let mut cm = pedersen_hash(cs, &tables, NOTE_COMMITMENT_PERSONALIZATION, &note_contents)?;
        {
            let rcm = gadgets::fr_into_boolean_vec_le(cs, &self.rcm)?;
            let rcm = fixed_base_multiplication(cs, &NOTE_COMMITMENT_RANDOMNESS_BASE, &rcm)?;
            cm = cm.add(cs, &rcm)?;
        }
        cm.get_u().inputize(cs)
    }
}

#[cfg(test)]
pub(crate) mod tests;
