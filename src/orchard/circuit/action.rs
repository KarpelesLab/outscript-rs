//! The constraint system and the synthesis of the Action circuit (port of
//! `orchard::circuit` of the `orchard` crate, version 0.16.0). Everything
//! here is in the order of the reference: the order decides the layout,
//! and with it the verifying key.

use alloc::vec::Vec;

use super::add_chip::{AddChip, AddConfig};
use super::commit_ivk::{CommitIvkChip, CommitIvkConfig};
use super::ecc::chip::OrchardFixedBasesFull;
use super::ecc::chip::{CircuitVersion as EccCircuitVersion, EccChip, EccConfig};
use super::ecc::{FixedPoint, NonIdentityPoint, Point, ScalarFixed, ScalarFixedShort, ScalarVar};
use super::gadget::{self, assign_free_advice};
use super::note_commit::{NoteCommitChip, NoteCommitConfig};
use super::poseidon::{Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig};
use super::sinsemilla::OrchardHashDomains;
use super::sinsemilla::chip::{SinsemillaChip, SinsemillaConfig};
use super::sinsemilla::merkle::MerklePath;
use super::sinsemilla::merkle::chip::{MerkleChip, MerkleConfig};
use super::utilities::lookup_range_check::LookupRangeCheckConfig;
use super::{
    ANCHOR, ActionCircuit, CMX, CV_NET_X, CV_NET_Y, DISABLE_CROSS_ADDRESS, ENABLE_OUTPUT,
    ENABLE_SPEND, NF_OLD, RK_X, RK_Y,
};
use crate::orchard::Fp;
use crate::orchard::halo2::Error;
use crate::orchard::halo2::circuit::{Circuit, Layouter};
use crate::orchard::halo2::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Expression, Instance as InstanceColumn,
    Rotation, Selector,
};

/// Configuration needed to use the Orchard Action circuit.
#[derive(Clone, Debug)]
pub struct Config {
    primary: Column<InstanceColumn>,
    q_orchard: Selector,
    advices: [Column<Advice>; 10],
    add_config: AddConfig,
    ecc_config: EccConfig,
    poseidon_config: PoseidonConfig,
    merkle_config_1: MerkleConfig,
    merkle_config_2: MerkleConfig,
    sinsemilla_config_1: SinsemillaConfig,
    sinsemilla_config_2: SinsemillaConfig,
    commit_ivk_config: CommitIvkConfig,
    old_note_commit_config: NoteCommitConfig,
    new_note_commit_config: NoteCommitConfig,
}

impl Config {
    /// Configures the Orchard Action constraint system shared by every
    /// circuit version.
    fn configure(meta: &mut ConstraintSystem) -> Self {
        // Advice columns used in the Orchard circuit.
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        // Constrain v_old - v_new = magnitude * sign
        // Either v_old = 0, or calculated root = anchor
        // Constrain v_old = 0 or enable_spend = 1
        // Constrain v_new = 0 or enable_output = 1
        //
        // This gate is also reused for the same-address check; see
        // `synthesize_cross_address_checks`.
        let q_orchard = meta.selector();
        meta.create_gate("Orchard circuit checks", |meta| {
            let q_orchard = meta.query_selector(q_orchard);
            let v_old = meta.query_advice(advices[0], Rotation::cur());
            let v_new = meta.query_advice(advices[1], Rotation::cur());
            let magnitude = meta.query_advice(advices[2], Rotation::cur());
            let sign = meta.query_advice(advices[3], Rotation::cur());

            let root = meta.query_advice(advices[4], Rotation::cur());
            let anchor = meta.query_advice(advices[5], Rotation::cur());

            let enable_spend = meta.query_advice(advices[6], Rotation::cur());
            let enable_output = meta.query_advice(advices[7], Rotation::cur());

            let one = Expression::Constant(Fp::ONE);

            Constraints::with_selector(
                q_orchard,
                [
                    // v_old - v_new = magnitude * sign
                    v_old.clone() - v_new.clone() - magnitude * sign,
                    // Either v_old = 0, or root = anchor
                    v_old.clone() * (root - anchor),
                    // v_old = 0 or enable_spend = 1
                    v_old * (one.clone() - enable_spend),
                    // v_new = 0 or enable_output = 1
                    v_new * (one - enable_output),
                ],
            )
        });

        // Addition of two field elements.
        let add_config = AddChip::configure(meta, advices[7], advices[8], advices[6]);

        // Fixed columns for the Sinsemilla generator lookup table
        let table_idx = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        // Instance column used for public inputs
        let primary = meta.instance_column();
        meta.enable_equality(primary);

        // Permutation over all advice columns.
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        // Poseidon requires four advice columns, while ECC incomplete
        // addition requires six, so we could choose to configure them in
        // parallel. However, we only use a single Poseidon invocation, and
        // we have the rows to accommodate it serially. Instead, we reduce
        // the proof size by sharing fixed columns between the ECC and
        // Poseidon chips.
        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let rc_a = [lagrange_coeffs[2], lagrange_coeffs[3], lagrange_coeffs[4]];
        let rc_b = [lagrange_coeffs[5], lagrange_coeffs[6], lagrange_coeffs[7]];

        // Also use the first Lagrange coefficient column for loading global
        // constants. It's free real estate :)
        meta.enable_constant(lagrange_coeffs[0]);

        // We have a lot of free space in the right-most advice columns; use
        // one of them for all of our range checks.
        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

        // Configuration for curve point operations.
        // This uses 10 advice columns and spans the whole circuit.
        let ecc_config = EccChip::configure(meta, advices, lagrange_coeffs, range_check);

        // Configuration for the Poseidon hash.
        let poseidon_config = PoseidonChip::configure(
            meta,
            // We place the state columns after the partial_sbox column so
            // that the pad-and-add region can be laid out more efficiently.
            [advices[6], advices[7], advices[8]],
            advices[5],
            rc_a,
            rc_b,
        );

        // Configuration for a Sinsemilla hash instantiation and a Merkle
        // hash instantiation using this Sinsemilla instance. Since the
        // Sinsemilla config uses only 5 advice columns, we can fit two
        // instances side-by-side.
        let (sinsemilla_config_1, merkle_config_1) = {
            let sinsemilla_config_1 = SinsemillaChip::configure(
                meta,
                [advices[0], advices[1], advices[2], advices[3], advices[4]],
                advices[6],
                lagrange_coeffs[0],
                lookup,
                range_check,
            );
            let merkle_config_1 = MerkleChip::configure(meta, sinsemilla_config_1.clone());
            (sinsemilla_config_1, merkle_config_1)
        };

        // Another Sinsemilla + Merkle pair, on the other five columns.
        let (sinsemilla_config_2, merkle_config_2) = {
            let sinsemilla_config_2 = SinsemillaChip::configure(
                meta,
                [advices[5], advices[6], advices[7], advices[8], advices[9]],
                advices[7],
                lagrange_coeffs[1],
                lookup,
                range_check,
            );
            let merkle_config_2 = MerkleChip::configure(meta, sinsemilla_config_2.clone());
            (sinsemilla_config_2, merkle_config_2)
        };

        // Configuration to handle decomposition and canonicity checking for
        // CommitIvk.
        let commit_ivk_config = CommitIvkChip::configure(meta, advices);

        // Configuration to handle decomposition and canonicity checking for
        // NoteCommit_old.
        let old_note_commit_config =
            NoteCommitChip::configure(meta, advices, sinsemilla_config_1.clone());

        // Configuration to handle decomposition and canonicity checking for
        // NoteCommit_new.
        let new_note_commit_config =
            NoteCommitChip::configure(meta, advices, sinsemilla_config_2.clone());

        Config {
            primary,
            q_orchard,
            advices,
            add_config,
            ecc_config,
            poseidon_config,
            merkle_config_1,
            merkle_config_2,
            sinsemilla_config_1,
            sinsemilla_config_2,
            commit_ivk_config,
            old_note_commit_config,
            new_note_commit_config,
        }
    }

    fn add_chip(&self) -> AddChip {
        AddChip::construct(self.add_config.clone())
    }

    fn commit_ivk_chip(&self) -> CommitIvkChip {
        CommitIvkChip::construct(self.commit_ivk_config.clone())
    }

    fn ecc_chip(&self, circuit_version: EccCircuitVersion) -> EccChip {
        EccChip::construct(self.ecc_config, circuit_version)
    }

    fn sinsemilla_chip_1(&self) -> SinsemillaChip {
        SinsemillaChip::construct(self.sinsemilla_config_1.clone())
    }

    fn sinsemilla_chip_2(&self) -> SinsemillaChip {
        SinsemillaChip::construct(self.sinsemilla_config_2.clone())
    }

    fn merkle_chip_1(&self) -> MerkleChip {
        MerkleChip::construct(self.merkle_config_1.clone())
    }

    fn merkle_chip_2(&self) -> MerkleChip {
        MerkleChip::construct(self.merkle_config_2.clone())
    }

    fn poseidon_chip(&self) -> PoseidonChip {
        PoseidonChip::construct(self.poseidon_config.clone())
    }

    fn note_commit_chip_new(&self) -> NoteCommitChip {
        NoteCommitChip::construct(self.new_note_commit_config.clone())
    }

    fn note_commit_chip_old(&self) -> NoteCommitChip {
        NoteCommitChip::construct(self.old_note_commit_config.clone())
    }
}

/// The address points of the notes of an action, which the same-address
/// check binds together.
struct AddressPoints {
    g_d_old: NonIdentityPoint,
    pk_d_old: NonIdentityPoint,
    g_d_new: NonIdentityPoint,
    pk_d_new: NonIdentityPoint,
}

impl ActionCircuit {
    /// The variable-base multiplication variant of this circuit version.
    fn halo2_version(&self) -> EccCircuitVersion {
        if self.version.anchored_base() {
            EccCircuitVersion::AnchoredBase
        } else {
            EccCircuitVersion::InsecureUnanchoredBase
        }
    }

    #[allow(non_snake_case)]
    fn synthesize_base(
        &self,
        config: &Config,
        layouter: &mut Layouter<'_>,
    ) -> Result<AddressPoints, Error> {
        // Load the Sinsemilla generator lookup table used by the whole
        // circuit.
        SinsemillaChip::load(config.sinsemilla_config_1.clone(), layouter)?;

        // Construct the ECC chip.
        let ecc_chip = config.ecc_chip(self.halo2_version());

        // Witness private inputs that are used across multiple checks.
        let (psi_old, rho_old, cm_old, g_d_old, ak_P, nk, v_old, v_new) = {
            // Witness psi_old
            let psi_old =
                assign_free_advice(layouter, config.advices[0], self.witness(|w| w.psi_old))?;

            // Witness rho_old
            let rho_old =
                assign_free_advice(layouter, config.advices[0], self.witness(|w| w.rho_old))?;

            // Witness cm_old
            let cm_old = Point::new(ecc_chip, layouter, self.witness(|w| w.cm_old))?;

            // Witness g_d_old
            let g_d_old = NonIdentityPoint::new(ecc_chip, layouter, self.witness(|w| w.g_d_old))?;

            // Witness ak_P.
            let ak_P = NonIdentityPoint::new(ecc_chip, layouter, self.witness(|w| w.ak))?;

            // Witness nk.
            let nk = assign_free_advice(layouter, config.advices[0], self.witness(|w| w.nk))?;

            // Witness v_old.
            let v_old = assign_free_advice(layouter, config.advices[0], self.witness(|w| w.v_old))?;

            // Witness v_new.
            let v_new = assign_free_advice(layouter, config.advices[0], self.witness(|w| w.v_new))?;

            (psi_old, rho_old, cm_old, g_d_old, ak_P, nk, v_old, v_new)
        };

        // Merkle path validity check.
        let root = {
            let path = self.witness(|w| w.path);
            let merkle_inputs = MerklePath::construct(
                [config.merkle_chip_1(), config.merkle_chip_2()],
                OrchardHashDomains::MerkleCrh,
                self.witness(|w| w.pos),
                path,
            );
            let leaf = cm_old.extract_p().inner().clone();
            merkle_inputs.calculate_root(layouter, leaf)?
        };

        // Value commitment integrity.
        let v_net_magnitude_sign = {
            // Witness the magnitude and sign of v_net = v_old - v_new
            let v_net_magnitude_sign = {
                let magnitude_sign = self.witness(|w| {
                    let v_net = w.v_old as i128 - w.v_new as i128;
                    (
                        Fp::from_u64(v_net.unsigned_abs() as u64),
                        if v_net >= 0 { Fp::ONE } else { -Fp::ONE },
                    )
                });

                let magnitude = assign_free_advice(
                    layouter,
                    config.advices[9],
                    magnitude_sign.map(|m_s| m_s.0),
                )?;
                let sign = assign_free_advice(
                    layouter,
                    config.advices[9],
                    magnitude_sign.map(|m_s| m_s.1),
                )?;
                (magnitude, sign)
            };

            let v_net = ScalarFixedShort::new(ecc_chip, layouter, v_net_magnitude_sign.clone())?;
            let rcv = ScalarFixed::new(ecc_chip, layouter, self.witness(|w| w.rcv))?;

            let cv_net = gadget::value_commit_orchard(layouter, ecc_chip, v_net, rcv)?;

            // Constrain cv_net to equal public input
            layouter.constrain_instance(cv_net.inner().x().cell(), config.primary, CV_NET_X)?;
            layouter.constrain_instance(cv_net.inner().y().cell(), config.primary, CV_NET_Y)?;

            // Return the magnitude and sign so we can use them in the
            // Orchard gate.
            v_net_magnitude_sign
        };

        // Nullifier integrity.
        let nf_old = {
            let nf_old = gadget::derive_nullifier(
                layouter,
                config.poseidon_chip(),
                config.add_chip(),
                ecc_chip,
                rho_old.clone(),
                &psi_old,
                &cm_old,
                nk.clone(),
            )?;

            // Constrain nf_old to equal public input
            layouter.constrain_instance(nf_old.inner().cell(), config.primary, NF_OLD)?;

            nf_old
        };

        // Spend authority.
        {
            let alpha = ScalarFixed::new(ecc_chip, layouter, self.witness(|w| w.alpha))?;

            // alpha_commitment = [alpha] SpendAuthG
            let (alpha_commitment, _) = {
                let spend_auth_g = OrchardFixedBasesFull::SpendAuthG;
                let spend_auth_g = FixedPoint::from_inner(ecc_chip, spend_auth_g);
                spend_auth_g.mul(layouter, alpha)?
            };

            // [alpha] SpendAuthG + ak_P
            let rk = alpha_commitment.add(layouter, &ak_P)?;

            // Constrain rk to equal public input
            layouter.constrain_instance(rk.inner().x().cell(), config.primary, RK_X)?;
            layouter.constrain_instance(rk.inner().y().cell(), config.primary, RK_Y)?;
        }

        // Diversified address integrity.
        let pk_d_old = {
            let ivk = {
                let ak = ak_P.extract_p().inner().clone();
                let rivk = ScalarFixed::new(ecc_chip, layouter, self.witness(|w| w.rivk))?;

                gadget::commit_ivk(
                    config.sinsemilla_chip_1(),
                    ecc_chip,
                    config.commit_ivk_chip(),
                    layouter,
                    ak,
                    nk,
                    rivk,
                )?
            };
            let ivk = ScalarVar::from_base(ecc_chip, layouter, ivk.inner())?;

            // [ivk] g_d_old
            // The scalar value is passed through and discarded.
            let (derived_pk_d_old, _ivk) = g_d_old.mul(layouter, ivk)?;

            // Constrain derived pk_d_old to equal witnessed pk_d_old
            //
            // This equality constraint is technically superfluous, because
            // the assigned value of `derived_pk_d_old` is an equivalent
            // witness. But it's nice to see an explicit connection between
            // `derived_pk_d_old` and `pk_d_old` here.
            let pk_d_old = NonIdentityPoint::new(ecc_chip, layouter, self.witness(|w| w.pk_d_old))?;
            derived_pk_d_old.constrain_equal(layouter, &pk_d_old)?;

            pk_d_old
        };

        // Old note commitment integrity.
        {
            let rcm_old = ScalarFixed::new(ecc_chip, layouter, self.witness(|w| w.rcm_old))?;

            // g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)
            let derived_cm_old = gadget::note_commit(
                layouter,
                config.sinsemilla_chip_1(),
                config.ecc_chip(self.halo2_version()),
                config.note_commit_chip_old(),
                g_d_old.inner(),
                pk_d_old.inner(),
                v_old.clone(),
                rho_old,
                psi_old,
                rcm_old,
            )?;

            // Constrain derived cm_old to equal witnessed cm_old
            derived_cm_old.constrain_equal(layouter, &cm_old)?;
        }

        // The address of the new note.
        let g_d_new = NonIdentityPoint::new(ecc_chip, layouter, self.witness(|w| w.g_d_new))?;
        let pk_d_new = NonIdentityPoint::new(ecc_chip, layouter, self.witness(|w| w.pk_d_new))?;

        // New note commitment integrity.
        {
            // ρ^new = nf^old
            let rho_new = nf_old.inner().clone();

            // Witness psi_new
            let psi_new =
                assign_free_advice(layouter, config.advices[0], self.witness(|w| w.psi_new))?;

            let rcm_new = ScalarFixed::new(ecc_chip, layouter, self.witness(|w| w.rcm_new))?;

            // g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)
            let cm_new = gadget::note_commit(
                layouter,
                config.sinsemilla_chip_2(),
                config.ecc_chip(self.halo2_version()),
                config.note_commit_chip_new(),
                g_d_new.inner(),
                pk_d_new.inner(),
                v_new.clone(),
                rho_new,
                psi_new,
                rcm_new,
            )?;

            let cmx = cm_new.extract_p();

            // Constrain cmx to equal public input
            layouter.constrain_instance(cmx.inner().cell(), config.primary, CMX)?;
        }

        // Constrain the remaining Orchard circuit checks.
        layouter.assign_region(|mut region| {
            v_old.copy_advice(&mut region, config.advices[0], 0)?;
            v_new.copy_advice(&mut region, config.advices[1], 0)?;
            v_net_magnitude_sign
                .0
                .copy_advice(&mut region, config.advices[2], 0)?;
            v_net_magnitude_sign
                .1
                .copy_advice(&mut region, config.advices[3], 0)?;
            root.copy_advice(&mut region, config.advices[4], 0)?;
            region.assign_advice_from_instance(config.primary, ANCHOR, config.advices[5], 0)?;
            region.assign_advice_from_instance(
                config.primary,
                ENABLE_SPEND,
                config.advices[6],
                0,
            )?;
            region.assign_advice_from_instance(
                config.primary,
                ENABLE_OUTPUT,
                config.advices[7],
                0,
            )?;
            config.q_orchard.enable(&mut region, 0)
        })?;

        Ok(AddressPoints {
            g_d_old,
            pk_d_old,
            g_d_new,
            pk_d_new,
        })
    }

    /// Enforces `disableCrossAddress => (g_d^old, pk_d^old) = (g_d^new,
    /// pk_d^new)` by reusing the Orchard gate: with `v_old := flag`,
    /// `v_new := 0`, `magnitude := flag`, `sign := 1`, `root := old
    /// coordinate` and `anchor := new coordinate`, its second constraint
    /// reads `flag * (old - new) = 0`, and the others hold trivially.
    fn synthesize_cross_address_checks(
        config: &Config,
        layouter: &mut Layouter<'_>,
        addrs: &AddressPoints,
    ) -> Result<(), Error> {
        let AddressPoints {
            g_d_old,
            pk_d_old,
            g_d_new,
            pk_d_new,
        } = addrs;
        layouter.assign_region(|mut region| {
            let coordinate_checks: Vec<_> = [
                (g_d_old.inner().x(), g_d_new.inner().x()),
                (g_d_old.inner().y(), g_d_new.inner().y()),
                (pk_d_old.inner().x(), pk_d_new.inner().x()),
                (pk_d_old.inner().y(), pk_d_new.inner().y()),
            ]
            .into_iter()
            .collect();
            for (offset, (old_coord, new_coord)) in coordinate_checks.into_iter().enumerate() {
                let cross_address_disabled = region.assign_advice_from_instance(
                    config.primary,
                    DISABLE_CROSS_ADDRESS,
                    config.advices[0],
                    offset,
                )?;
                region.assign_advice_from_constant(config.advices[1], offset, Fp::ZERO)?;
                cross_address_disabled.copy_advice(&mut region, config.advices[2], offset)?;
                region.assign_advice_from_constant(config.advices[3], offset, Fp::ONE)?;
                old_coord.copy_advice(&mut region, config.advices[4], offset)?;
                new_coord.copy_advice(&mut region, config.advices[5], offset)?;
                // one (neutralize the enable_spend check)
                region.assign_advice_from_constant(config.advices[6], offset, Fp::ONE)?;
                // one (neutralize the enable_output check)
                region.assign_advice_from_constant(config.advices[7], offset, Fp::ONE)?;
                // padding
                cross_address_disabled.copy_advice(&mut region, config.advices[8], offset)?;
                cross_address_disabled.copy_advice(&mut region, config.advices[9], offset)?;
                config.q_orchard.enable(&mut region, offset)?;
            }
            Ok(())
        })
    }
}

impl Circuit for ActionCircuit {
    type Config = Config;

    fn without_witnesses(&self) -> Self {
        ActionCircuit::empty(self.version)
    }

    fn configure(&self, meta: &mut ConstraintSystem) -> Config {
        Config::configure(meta)
    }

    fn synthesize(&self, config: Config, layouter: &mut Layouter<'_>) -> Result<(), Error> {
        let addrs = self.synthesize_base(&config, layouter)?;
        if self.version.supports_cross_address_restriction() {
            Self::synthesize_cross_address_checks(&config, layouter, &addrs)?;
        }
        Ok(())
    }
}
