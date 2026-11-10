//! Fixed-base scalar multiplication (port of
//! `halo2_gadgets::ecc::chip::mul_fixed`).
//!
//! The reference takes the Lagrange coefficients, the `z` and the `u`
//! values of a base from its `FixedPoint` implementation, and computes the
//! multiple of the base of each window by a scalar multiplication. Here they
//! all come from the window table of the base ([`compute_window_table`]),
//! computed at most once per region and only when a value is needed: the
//! fixed cells at key generation, the points and `u` when proving.

use alloc::vec::Vec;
use core::cell::OnceCell;

use super::constants::{compute_window_table, fixed_u, lagrange_coeffs_of_table};
use super::{
    EccBaseFieldElemFixed, EccScalarFixed, EccScalarFixedShort, FIXED_BASE_WINDOW_SIZE, FixedPoint,
    H, NonIdentityEccPoint, add, add_incomplete,
};
use crate::orchard::circuit::utilities::decompose_running_sum::RunningSumConfig;
use crate::orchard::halo2::circuit::{AssignedCell, Region};
use crate::orchard::halo2::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Expression, Fixed, Rotation, Selector,
    VirtualCells,
};
use crate::orchard::halo2::{Error, Value};
use crate::orchard::{Fp, Fq, pallas};

pub(crate) mod base_field_elem;
pub(crate) mod full_width;
pub(crate) mod short;

/// The window table of a base, computed when first needed.
struct WindowTable<F: FixedPoint> {
    base: F,
    num_windows: usize,
    table: OnceCell<Vec<[pallas::Affine; H]>>,
}

impl<F: FixedPoint> WindowTable<F> {
    fn new(base: &F, num_windows: usize) -> Self {
        assert_eq!(base.z().len(), num_windows);
        WindowTable {
            base: *base,
            num_windows,
            table: OnceCell::new(),
        }
    }

    fn get(&self) -> &[[pallas::Affine; H]] {
        self.table
            .get_or_init(|| compute_window_table(self.base.generator(), self.num_windows))
    }
}

/// `scalar^exp`.
fn pow(scalar: Fq, exp: u64) -> Fq {
    scalar.pow_vartime(&[exp, 0, 0, 0])
}

/// The configuration shared by the fixed-base scalar multiplications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Config {
    running_sum_config: RunningSumConfig<FIXED_BASE_WINDOW_SIZE>,
    // The fixed Lagrange interpolation coefficients for `x_p`.
    lagrange_coeffs: [Column<Fixed>; H],
    // The fixed `z` for each window such that `y + z = u^2`.
    fixed_z: Column<Fixed>,
    // Decomposition of an `n-1`-bit scalar into `k`-bit windows:
    // a = a_0 + 2^k(a_1) + 2^{2k}(a_2) + ... + 2^{(n-1)k}(a_{n-1})
    window: Column<Advice>,
    // y-coordinate of accumulator (only used in the final row).
    u: Column<Advice>,
    // Configuration for `add`
    add_config: add::Config,
    // Configuration for `add_incomplete`
    add_incomplete_config: add_incomplete::Config,
}

impl Config {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn configure(
        meta: &mut ConstraintSystem,
        lagrange_coeffs: [Column<Fixed>; H],
        window: Column<Advice>,
        u: Column<Advice>,
        add_config: add::Config,
        add_incomplete_config: add_incomplete::Config,
    ) -> Self {
        meta.enable_equality(window);
        meta.enable_equality(u);

        let q_running_sum = meta.selector();
        let running_sum_config = RunningSumConfig::configure(meta, q_running_sum, window);

        let config = Self {
            running_sum_config,
            lagrange_coeffs,
            fixed_z: meta.fixed_column(),
            window,
            u,
            add_config,
            add_incomplete_config,
        };

        // Check relationships between `add_config` and `add_incomplete_config`.
        assert_eq!(
            config.add_config.x_p, config.add_incomplete_config.x_p,
            "add and add_incomplete are used internally in mul_fixed."
        );
        assert_eq!(
            config.add_config.y_p, config.add_incomplete_config.y_p,
            "add and add_incomplete are used internally in mul_fixed."
        );
        for advice in [config.window, config.u].iter() {
            assert_ne!(
                *advice, config.add_config.x_qr,
                "Do not overlap with output columns of add."
            );
            assert_ne!(
                *advice, config.add_config.y_qr,
                "Do not overlap with output columns of add."
            );
        }

        config.running_sum_coords_gate(meta);

        config
    }

    /// Check that each window in the running sum decomposition uses the
    /// correct y_p and interpolated x_p.
    ///
    /// This gate is used both in the mul_fixed::base_field_elem and
    /// mul_fixed::short helpers, which decompose the scalar using a running
    /// sum.
    ///
    /// This gate is not used in the mul_fixed::full_width helper, since the
    /// full-width scalar is witnessed directly as three-bit windows.
    fn running_sum_coords_gate(&self, meta: &mut ConstraintSystem) {
        meta.create_gate("Running sum coordinates check", |meta| {
            let q_mul_fixed_running_sum =
                meta.query_selector(self.running_sum_config.q_range_check());

            let z_cur = meta.query_advice(self.window, Rotation::cur());
            let z_next = meta.query_advice(self.window, Rotation::next());

            //    z_{i+1} = (z_i - a_i) / 2^3
            // => a_i = z_i - z_{i+1} * 2^3
            let word = z_cur - z_next * Fp::from_u64(H as u64);

            Constraints::with_selector(q_mul_fixed_running_sum, self.coords_check(meta, word))
        });
    }

    /// The constraints `check x`, `check y` and `on-curve` of a window.
    ///
    /// [Specification](https://p.z.cash/halo2-0.1:ecc-fixed-mul-coordinates).
    fn coords_check(&self, meta: &mut VirtualCells<'_>, window: Expression) -> Vec<Expression> {
        let y_p = meta.query_advice(self.add_config.y_p, Rotation::cur());
        let x_p = meta.query_advice(self.add_config.x_p, Rotation::cur());
        let z = meta.query_fixed(self.fixed_z);
        let u = meta.query_advice(self.u, Rotation::cur());

        let window_pow: Vec<Expression> = (0..H)
            .map(|pow| (0..pow).fold(Expression::Constant(Fp::ONE), |acc, _| acc * window.clone()))
            .collect();

        let interpolated_x = window_pow.iter().zip(self.lagrange_coeffs.iter()).fold(
            Expression::Constant(Fp::ZERO),
            |acc, (window_pow, coeff)| acc + (window_pow.clone() * meta.query_fixed(*coeff)),
        );

        // Check interpolation of x-coordinate
        let x_check = interpolated_x - x_p.clone();
        // Check that `y + z = u^2`, where `z` is fixed and `u`, `y` are witnessed
        let y_check = u.square() - y_p.clone() - z;
        // Check that (x, y) is on the curve
        let on_curve = y_p.square() - x_p.clone().square() * x_p - Expression::Constant(pallas::B);

        alloc::vec![
            // check x
            x_check, // check y
            y_check, // on-curve
            on_curve,
        ]
    }

    /// Assigns the fixed constants, then the windows of the scalar
    /// multiplication: returns the accumulated sum of all the windows but
    /// the last, and the multiple of the last window.
    fn assign_region_inner<F: FixedPoint>(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        scalar: &ScalarFixed,
        base: &F,
        coords_check_toggle: Selector,
        num_windows: usize,
    ) -> Result<(NonIdentityEccPoint, NonIdentityEccPoint), Error> {
        let table = WindowTable::new(base, num_windows);

        // Assign fixed columns for given fixed base
        self.assign_fixed_constants(region, offset, &table, coords_check_toggle)?;

        // Initialize accumulator
        let acc = self.initialize_accumulator(region, offset, &table, scalar)?;

        // Process all windows excluding least and most significant windows
        let acc = self.add_incomplete(region, offset, acc, &table, scalar)?;

        // Process most significant window
        let mul_b = self.process_msb(region, offset, &table, scalar)?;

        Ok((acc, mul_b))
    }

    /// [Specification](https://p.z.cash/halo2-0.1:ecc-fixed-mul-load-base).
    fn assign_fixed_constants<F: FixedPoint>(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        table: &WindowTable<F>,
        coords_check_toggle: Selector,
    ) -> Result<(), Error> {
        let mut constants: Option<Vec<[Fp; H]>> = None;
        let z = table.base.z();

        // Assign fixed columns for given fixed base
        for window in 0..table.num_windows {
            coords_check_toggle.enable(region, window + offset)?;

            // Assign x-coordinate Lagrange interpolation coefficients
            for k in 0..H {
                region.assign_fixed(self.lagrange_coeffs[k], window + offset, || {
                    let lagrange_coeffs =
                        constants.get_or_insert_with(|| lagrange_coeffs_of_table(table.get()));
                    Value::known(lagrange_coeffs[window][k])
                })?;
            }

            // Assign z-values for each window
            region.assign_fixed(self.fixed_z, window + offset, || {
                Value::known(Fp::from_u64(z[window]))
            })?;
        }

        Ok(())
    }

    /// Assigns the multiple of the base of window `w` and its `u` value.
    ///
    /// `k` is the value of the window, `k_usize` its three low bits and
    /// `window_scalar` the scalar the base is multiplied by.
    #[allow(clippy::too_many_arguments)]
    fn process_window<F: FixedPoint>(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        w: usize,
        k: Value<Fq>,
        k_usize: Value<usize>,
        window_scalar: Value<Fq>,
        table: &WindowTable<F>,
    ) -> Result<NonIdentityEccPoint, Error> {
        let mul_b = {
            // `[window_scalar]B` is the entry `k` of the window table (a
            // window holds three bits; the scalar multiplication only stands
            // for a value the constraints reject).
            let mul_b = k
                .zip(k_usize)
                .zip(window_scalar)
                .map(|((k, k_usize), scalar)| {
                    if k == Fq::from_u64(k_usize as u64) {
                        table.get()[w][k_usize]
                    } else {
                        table.base.generator().to_point().mul(&scalar).to_affine()
                    }
                });
            let x = mul_b.map(|mul_b| {
                let x = mul_b.x();
                assert!(x != Fp::ZERO);
                x
            });
            let x = region.assign_advice(self.add_config.x_p, offset + w, || x)?;

            let y = mul_b.map(|mul_b| {
                let y = mul_b.y();
                assert!(y != Fp::ZERO);
                y
            });
            let y = region.assign_advice(self.add_config.y_p, offset + w, || y)?;

            NonIdentityEccPoint::from_coordinates_unchecked(x, y)
        };

        // Assign u = (y_p + z_w).sqrt()
        let u_val = k_usize.map(|k| fixed_u(table.get()[w][k].y(), table.base.z()[w]));
        region.assign_advice(self.u, offset + w, || u_val)?;

        Ok(mul_b)
    }

    fn initialize_accumulator<F: FixedPoint>(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        table: &WindowTable<F>,
        scalar: &ScalarFixed,
    ) -> Result<NonIdentityEccPoint, Error> {
        // Recall that the message at each window `w` is represented as
        // `m_w = [(k_w + 2) ⋅ 8^w]B`.
        // When `w = 0`, we have `m_0 = [(k_0 + 2)]B`.
        let w = 0;
        let k0 = scalar.windows_field()[0];
        let k0_usize = scalar.windows_usize()[0];
        self.process_lower_bits(region, offset, w, k0, k0_usize, table)
    }

    fn add_incomplete<F: FixedPoint>(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        mut acc: NonIdentityEccPoint,
        table: &WindowTable<F>,
        scalar: &ScalarFixed,
    ) -> Result<NonIdentityEccPoint, Error> {
        let scalar_windows_field = scalar.windows_field();
        let scalar_windows_usize = scalar.windows_usize();
        assert_eq!(scalar_windows_field.len(), table.num_windows);

        for (w, (k, k_usize)) in scalar_windows_field
            .into_iter()
            .zip(scalar_windows_usize)
            .enumerate()
            // The MSB is processed separately.
            .take(table.num_windows - 1)
            // Skip k_0 (already processed).
            .skip(1)
        {
            // Compute [(k_w + 2) ⋅ 8^w]B
            //
            // This assigns the coordinates of the returned point into the
            // input cells for the incomplete addition gate, which will then
            // copy them into themselves.
            let mul_b = self.process_lower_bits(region, offset, w, k, k_usize, table)?;

            // Add to the accumulator.
            //
            // After the first loop, the accumulator will already be in the
            // input cells for the incomplete addition gate, and will be
            // copied into themselves.
            acc = self
                .add_incomplete_config
                .assign_region(&mul_b, &acc, offset + w, region)?;
        }
        Ok(acc)
    }

    /// Assigns the values used to process a window that does not contain the
    /// MSB.
    fn process_lower_bits<F: FixedPoint>(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        w: usize,
        k: Value<Fq>,
        k_usize: Value<usize>,
        table: &WindowTable<F>,
    ) -> Result<NonIdentityEccPoint, Error> {
        // `scalar = [(k_w + 2) ⋅ 8^w]
        let scalar = k.map(|k| (k + Fq::from_u64(2)) * pow(Fq::from_u64(H as u64), w as u64));

        self.process_window(region, offset, w, k, k_usize, scalar, table)
    }

    /// Assigns the values used to process the window containing the MSB.
    fn process_msb<F: FixedPoint>(
        &self,
        region: &mut Region<'_, '_>,
        offset: usize,
        table: &WindowTable<F>,
        scalar: &ScalarFixed,
    ) -> Result<NonIdentityEccPoint, Error> {
        let num_windows = table.num_windows;
        let k_usize = scalar.windows_usize()[num_windows - 1];

        // offset_acc = \sum_{j = 0}^{NUM_WINDOWS - 2} 2^{FIXED_BASE_WINDOW_SIZE*j + 1}
        let offset_acc = (0..(num_windows - 1)).fold(Fq::ZERO, |acc, w| {
            acc + pow(
                Fq::from_u64(2),
                FIXED_BASE_WINDOW_SIZE as u64 * w as u64 + 1,
            )
        });

        // `scalar = [k * 8^(NUM_WINDOWS - 1) - offset_acc]`.
        let k = scalar.windows_field()[scalar.windows_field().len() - 1];
        let scalar =
            k.map(|k| k * pow(Fq::from_u64(H as u64), (num_windows - 1) as u64) - offset_acc);

        self.process_window(region, offset, num_windows - 1, k, k_usize, scalar, table)
    }
}

/// The scalar of a fixed-base multiplication, whatever its kind.
enum ScalarFixed {
    FullWidth(EccScalarFixed),
    Short(EccScalarFixedShort),
    BaseFieldElem(EccBaseFieldElemFixed),
}

impl From<&EccScalarFixed> for ScalarFixed {
    fn from(scalar_fixed: &EccScalarFixed) -> Self {
        Self::FullWidth(scalar_fixed.clone())
    }
}

impl From<&EccScalarFixedShort> for ScalarFixed {
    fn from(scalar_fixed: &EccScalarFixedShort) -> Self {
        Self::Short(scalar_fixed.clone())
    }
}

impl From<&EccBaseFieldElemFixed> for ScalarFixed {
    fn from(base_field_elem: &EccBaseFieldElemFixed) -> Self {
        Self::BaseFieldElem(base_field_elem.clone())
    }
}

impl ScalarFixed {
    /// The scalar decomposed into `k`-bit windows.
    /// This returns window values as scalar field elements, because we use
    /// them in scalar multiplication to generate the witnesses of
    /// fixed-base scalar mul.
    fn windows_field(&self) -> Vec<Value<Fq>> {
        let running_sum_to_windows = |zs: &[AssignedCell<Fp>]| {
            (0..(zs.len() - 1))
                .map(|idx| {
                    let z_cur = zs[idx].value().copied();
                    let z_next = zs[idx + 1].value().copied();
                    let word = z_cur - z_next * Value::known(Fp::from_u64(H as u64));
                    // This assumes that the base field element fits in the
                    // scalar field.
                    word.map(|word| Fq::from_bytes(&word.to_bytes()).unwrap())
                })
                .collect::<Vec<_>>()
        };

        // The scalar field and the base field of Pallas have the same
        // number of bits.
        match self {
            Self::BaseFieldElem(scalar) => running_sum_to_windows(&scalar.running_sum),
            Self::Short(scalar) => running_sum_to_windows(
                scalar
                    .running_sum
                    .as_ref()
                    .expect("EccScalarFixedShort has been constrained"),
            ),
            Self::FullWidth(scalar) => scalar
                .windows
                .as_ref()
                .expect("EccScalarFixed has been witnessed")
                .iter()
                .map(|bits| {
                    // All the bits have been witnessed as 3-bit windows.
                    bits.value()
                        .map(|value| Fq::from_bytes(&value.to_bytes()).unwrap())
                })
                .collect::<Vec<_>>(),
        }
    }

    /// The scalar decomposed into `k`-bit windows.
    /// This returns window values as `usize`, because we use them to index
    /// into the `u` table (the three low bits of each window).
    fn windows_usize(&self) -> Vec<Value<usize>> {
        self.windows_field()
            .iter()
            .map(|window| {
                window.map(|window| {
                    (0..FIXED_BASE_WINDOW_SIZE)
                        .rev()
                        .fold(0, |acc, b| 2 * acc + usize::from(window.bit(b)))
                })
            })
            .collect::<Vec<_>>()
    }
}
