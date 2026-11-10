//! Circuit synthesis: regions, cells, the layouter and the `V1` floor
//! planner of `halo2_proofs`, which decides the row each region starts at.
//! The layout determines the fixed columns and the permutation, hence the
//! verifying key, so the planner reproduces the reference exactly.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::{self, Ordering};

use super::plonk::{Advice, Any, Column, ConstraintSystem, Fixed, Instance, Selector, TableColumn};
use super::{Error, Value};
use crate::orchard::Fp;

/// A type a cell can hold: anything with a field element representation.
pub trait CellValue: Clone {
    /// The field element stored in the cell.
    fn to_field(&self) -> Fp;
}

impl CellValue for Fp {
    fn to_field(&self) -> Fp {
        *self
    }
}

impl CellValue for bool {
    fn to_field(&self) -> Fp {
        if *self { Fp::ONE } else { Fp::ZERO }
    }
}

impl CellValue for u64 {
    fn to_field(&self) -> Fp {
        Fp::from_u64(*self)
    }
}

/// A cell of a region.
#[derive(Clone, Copy, Debug)]
pub struct Cell {
    region_index: usize,
    row_offset: usize,
    column: Column<Any>,
}

/// A cell that has been assigned, and the value it holds.
#[derive(Clone, Debug)]
pub struct AssignedCell<V = Fp> {
    value: Value<V>,
    cell: Cell,
}

impl<V> AssignedCell<V> {
    /// The value of the cell.
    pub fn value(&self) -> Value<&V> {
        self.value.as_ref()
    }

    /// The cell.
    pub fn cell(&self) -> Cell {
        self.cell
    }
}

impl<V: CellValue> AssignedCell<V> {
    /// The value of the cell as a field element.
    pub fn value_field(&self) -> Value<Fp> {
        self.value.as_ref().map(|v| v.to_field())
    }

    /// Assigns the same value to another cell and constrains both equal.
    pub fn copy_advice(
        &self,
        region: &mut Region<'_, '_>,
        column: Column<Advice>,
        offset: usize,
    ) -> Result<Self, Error> {
        let assigned_cell = region.assign_advice(column, offset, || self.value.clone())?;
        region.constrain_equal(assigned_cell.cell(), self.cell())?;
        Ok(assigned_cell)
    }
}

/// The backend a circuit is synthesized into: key generation records the
/// fixed cells and the copy constraints, proving records the advice.
pub trait Assignment {
    /// Enables a selector on a row.
    fn enable_selector(&mut self, selector: &Selector, row: usize) -> Result<(), Error>;

    /// The value of an instance cell, if known.
    fn query_instance(&self, column: Column<Instance>, row: usize) -> Result<Value<Fp>, Error>;

    /// Assigns an advice cell.
    fn assign_advice(
        &mut self,
        column: Column<Advice>,
        row: usize,
        to: &mut dyn FnMut() -> Value<Fp>,
    ) -> Result<(), Error>;

    /// Assigns a fixed cell.
    fn assign_fixed(
        &mut self,
        column: Column<Fixed>,
        row: usize,
        to: &mut dyn FnMut() -> Value<Fp>,
    ) -> Result<(), Error>;

    /// Constrains two cells to be equal.
    fn copy(
        &mut self,
        left_column: Column<Any>,
        left_row: usize,
        right_column: Column<Any>,
        right_row: usize,
    ) -> Result<(), Error>;

    /// Fills a fixed column from a row on with one value.
    fn fill_from_row(
        &mut self,
        column: Column<Fixed>,
        row: usize,
        to: Value<Fp>,
    ) -> Result<(), Error>;
}

/// A circuit: a constraint system and a way to fill it.
pub trait Circuit {
    /// What `configure` hands to `synthesize`.
    type Config: Clone;

    /// The same circuit with every witness unknown.
    fn without_witnesses(&self) -> Self;

    /// Describes the constraint system.
    fn configure(&self, meta: &mut ConstraintSystem) -> Self::Config;

    /// Assigns the circuit.
    fn synthesize(&self, config: Self::Config, layouter: &mut Layouter<'_>) -> Result<(), Error>;
}

/// A column or selector a region uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegionColumn {
    Column(Column<Any>),
    Selector(Selector),
}

impl Ord for RegionColumn {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Column(a), Self::Column(b)) => a.cmp(b),
            (Self::Selector(a), Self::Selector(b)) => a.0.cmp(&b.0),
            (Self::Column(_), Self::Selector(_)) => Ordering::Less,
            (Self::Selector(_), Self::Column(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for RegionColumn {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The columns and number of rows of a region.
#[derive(Clone, Debug)]
struct RegionShape {
    region_index: usize,
    columns: BTreeSet<RegionColumn>,
    row_count: usize,
}

impl RegionShape {
    fn touch(&mut self, column: RegionColumn, offset: usize) {
        self.columns.insert(column);
        self.row_count = cmp::max(self.row_count, offset + 1);
    }
}

/// The state of the assignment pass.
struct Plan<'a> {
    cs: &'a mut dyn Assignment,
    /// The row each region starts at.
    regions: Vec<usize>,
    /// Constants to assign in the fixed columns, and the cells they bind.
    constants: Vec<(Fp, Cell)>,
    /// The table columns already assigned.
    table_columns: Vec<TableColumn>,
    region_index: usize,
}

enum Pass<'a> {
    Measurement(Vec<RegionShape>),
    Assignment(Plan<'a>),
}

/// Lays regions out on the rows of the circuit.
pub struct Layouter<'a> {
    pass: Pass<'a>,
}

impl<'a> Layouter<'a> {
    /// Assigns a region. The closure may be called more than once.
    pub fn assign_region<A, AR>(&mut self, mut assignment: A) -> Result<AR, Error>
    where
        A: FnMut(Region<'_, 'a>) -> Result<AR, Error>,
    {
        match &mut self.pass {
            Pass::Measurement(regions) => {
                let mut shape = RegionShape {
                    region_index: regions.len(),
                    columns: BTreeSet::new(),
                    row_count: 0,
                };
                let result = assignment(Region {
                    inner: RegionInner::Shape(&mut shape),
                })?;
                regions.push(shape);
                Ok(result)
            }
            Pass::Assignment(plan) => {
                let region_index = plan.region_index;
                plan.region_index += 1;
                assignment(Region {
                    inner: RegionInner::Plan(plan, region_index),
                })
            }
        }
    }

    /// Assigns a lookup table.
    pub fn assign_table<A>(&mut self, mut assignment: A) -> Result<(), Error>
    where
        A: FnMut(Table<'_, 'a>) -> Result<(), Error>,
    {
        match &mut self.pass {
            Pass::Measurement(_) => Ok(()),
            Pass::Assignment(plan) => {
                let mut default_and_assigned = BTreeMap::new();
                assignment(Table {
                    plan,
                    default_and_assigned: &mut default_and_assigned,
                })?;
                // All columns must be fully assigned and equally long.
                let mut first_unused = 0;
                for (default_value, assigned) in default_and_assigned.values() {
                    if default_value.is_none()
                        || assigned.is_empty()
                        || !assigned.iter().all(|b| *b)
                        || (first_unused != 0 && first_unused != assigned.len())
                    {
                        return Err(Error::Synthesis);
                    }
                    first_unused = assigned.len();
                }
                for column in default_and_assigned.keys() {
                    plan.table_columns.push(*column);
                }
                for (col, (default_val, _)) in default_and_assigned {
                    plan.cs.fill_from_row(
                        col.inner(),
                        first_unused,
                        default_val.ok_or(Error::Synthesis)?,
                    )?;
                }
                Ok(())
            }
        }
    }

    /// Constrains a cell to equal an instance cell.
    pub fn constrain_instance(
        &mut self,
        cell: Cell,
        column: Column<Instance>,
        row: usize,
    ) -> Result<(), Error> {
        match &mut self.pass {
            Pass::Measurement(_) => Ok(()),
            Pass::Assignment(plan) => plan.cs.copy(
                cell.column,
                plan.regions[cell.region_index] + cell.row_offset,
                column.into(),
                row,
            ),
        }
    }

    /// The layouter itself (namespaces only label the reference's debug
    /// output).
    pub fn namespace(&mut self) -> &mut Self {
        self
    }
}

enum RegionInner<'r, 'a> {
    Shape(&'r mut RegionShape),
    Plan(&'r mut Plan<'a>, usize),
}

/// A set of rows a gadget assigns relative to its own offset zero.
pub struct Region<'r, 'a> {
    inner: RegionInner<'r, 'a>,
}

impl Region<'_, '_> {
    pub(crate) fn enable_selector(
        &mut self,
        selector: &Selector,
        offset: usize,
    ) -> Result<(), Error> {
        match &mut self.inner {
            RegionInner::Shape(shape) => {
                shape.touch(RegionColumn::Selector(*selector), offset);
                Ok(())
            }
            RegionInner::Plan(plan, region) => plan
                .cs
                .enable_selector(selector, plan.regions[*region] + offset),
        }
    }

    fn cell(&self, column: Column<Any>, offset: usize) -> Cell {
        let region_index = match &self.inner {
            RegionInner::Shape(shape) => shape.region_index,
            RegionInner::Plan(_, region) => *region,
        };
        Cell {
            region_index,
            row_offset: offset,
            column,
        }
    }

    fn assign_advice_field(
        &mut self,
        column: Column<Advice>,
        offset: usize,
        to: &mut dyn FnMut() -> Value<Fp>,
    ) -> Result<Cell, Error> {
        match &mut self.inner {
            RegionInner::Shape(shape) => {
                shape.touch(RegionColumn::Column(column.into()), offset);
            }
            RegionInner::Plan(plan, region) => {
                plan.cs
                    .assign_advice(column, plan.regions[*region] + offset, to)?;
            }
        }
        Ok(self.cell(column.into(), offset))
    }

    /// Assigns an advice cell.
    pub fn assign_advice<V: CellValue>(
        &mut self,
        column: Column<Advice>,
        offset: usize,
        mut to: impl FnMut() -> Value<V>,
    ) -> Result<AssignedCell<V>, Error> {
        let mut value = Value::unknown();
        let cell = self.assign_advice_field(column, offset, &mut || {
            let v = to();
            let value_f = v.as_ref().map(|v| v.to_field());
            value = v;
            value_f
        })?;
        Ok(AssignedCell { value, cell })
    }

    /// Assigns a constant to an advice cell and constrains it.
    pub fn assign_advice_from_constant<V: CellValue>(
        &mut self,
        column: Column<Advice>,
        offset: usize,
        constant: V,
    ) -> Result<AssignedCell<V>, Error> {
        let f = constant.to_field();
        let cell = self.assign_advice_field(column, offset, &mut || Value::known(f))?;
        self.constrain_constant(cell, f)?;
        Ok(AssignedCell {
            value: Value::known(constant),
            cell,
        })
    }

    /// Assigns the value of an instance cell to an advice cell and
    /// constrains both equal.
    pub fn assign_advice_from_instance(
        &mut self,
        instance: Column<Instance>,
        row: usize,
        advice: Column<Advice>,
        offset: usize,
    ) -> Result<AssignedCell<Fp>, Error> {
        match &mut self.inner {
            RegionInner::Shape(shape) => {
                shape.touch(RegionColumn::Column(advice.into()), offset);
                Ok(AssignedCell {
                    value: Value::unknown(),
                    cell: self.cell(advice.into(), offset),
                })
            }
            RegionInner::Plan(plan, _) => {
                let value = plan.cs.query_instance(instance, row)?;
                let cell = self.assign_advice_field(advice, offset, &mut || value)?;
                if let RegionInner::Plan(plan, _) = &mut self.inner {
                    plan.cs.copy(
                        cell.column,
                        plan.regions[cell.region_index] + cell.row_offset,
                        instance.into(),
                        row,
                    )?;
                }
                Ok(AssignedCell { value, cell })
            }
        }
    }

    /// Assigns a fixed cell.
    pub fn assign_fixed<V: CellValue>(
        &mut self,
        column: Column<Fixed>,
        offset: usize,
        mut to: impl FnMut() -> Value<V>,
    ) -> Result<AssignedCell<V>, Error> {
        let mut value = Value::unknown();
        match &mut self.inner {
            RegionInner::Shape(shape) => {
                shape.touch(RegionColumn::Column(column.into()), offset);
            }
            RegionInner::Plan(plan, region) => {
                plan.cs
                    .assign_fixed(column, plan.regions[*region] + offset, &mut || {
                        let v = to();
                        let value_f = v.as_ref().map(|v| v.to_field());
                        value = v;
                        value_f
                    })?;
            }
        }
        Ok(AssignedCell {
            value,
            cell: self.cell(column.into(), offset),
        })
    }

    /// Constrains a cell to hold a constant.
    pub fn constrain_constant(&mut self, cell: Cell, constant: Fp) -> Result<(), Error> {
        if let RegionInner::Plan(plan, _) = &mut self.inner {
            plan.constants.push((constant, cell));
        }
        Ok(())
    }

    /// Constrains two cells to be equal.
    pub fn constrain_equal(&mut self, left: Cell, right: Cell) -> Result<(), Error> {
        if let RegionInner::Plan(plan, _) = &mut self.inner {
            plan.cs.copy(
                left.column,
                plan.regions[left.region_index] + left.row_offset,
                right.column,
                plan.regions[right.region_index] + right.row_offset,
            )?;
        }
        Ok(())
    }
}

type TableState = BTreeMap<TableColumn, (Option<Value<Fp>>, Vec<bool>)>;

/// A lookup table being assigned.
pub struct Table<'r, 'a> {
    plan: &'r mut Plan<'a>,
    default_and_assigned: &'r mut TableState,
}

impl Table<'_, '_> {
    /// Assigns a cell of the table. Rows start at zero and the value at row
    /// zero also fills the rest of the column.
    pub fn assign_cell(
        &mut self,
        column: TableColumn,
        offset: usize,
        mut to: impl FnMut() -> Value<Fp>,
    ) -> Result<(), Error> {
        if self.plan.table_columns.contains(&column) {
            return Err(Error::Synthesis);
        }
        let entry = self.default_and_assigned.entry(column).or_default();
        let mut value = Value::unknown();
        self.plan.cs.assign_fixed(column.inner(), offset, &mut || {
            let res = to();
            value = res;
            res
        })?;
        match (entry.0.is_none(), offset) {
            (true, 0) => entry.0 = Some(value),
            (false, 0) => return Err(Error::Synthesis),
            _ => (),
        }
        if entry.1.len() <= offset {
            entry.1.resize(offset + 1, false);
        }
        entry.1[offset] = true;
        Ok(())
    }
}

/// Synthesizes a circuit into `cs` with the `V1` floor planner: a first
/// pass measures every region, the regions are placed (those using the most
/// advice cells first, each at the first row where its columns are free),
/// a second pass assigns them, and the constants go to the free cells of
/// the constants columns.
pub(crate) fn synthesize<C: Circuit>(
    cs: &mut dyn Assignment,
    circuit: &C,
    config: C::Config,
    constants: Vec<Column<Fixed>>,
) -> Result<(), Error> {
    // First pass: measure the regions.
    let mut measure = Layouter {
        pass: Pass::Measurement(vec![]),
    };
    circuit
        .without_witnesses()
        .synthesize(config.clone(), &mut measure)?;
    let Pass::Measurement(shapes) = measure.pass else {
        unreachable!()
    };

    let (regions, column_allocations) = slot_in_biggest_advice_first(shapes);

    // The first row no region uses.
    let first_unassigned_row = column_allocations
        .values()
        .map(|a| a.unbounded_interval_start())
        .max()
        .unwrap_or(0);

    // The free cells of the constants columns, in order.
    let mut constant_positions = vec![];
    for c in constants {
        let a = column_allocations
            .get(&RegionColumn::Column(c.into()))
            .cloned()
            .unwrap_or_default();
        for (start, end) in a.free_intervals(0, Some(first_unassigned_row)) {
            for i in start..end.expect("bounded") {
                constant_positions.push((c, i));
            }
        }
    }

    // Second pass: assign the regions.
    let mut assign = Layouter {
        pass: Pass::Assignment(Plan {
            cs,
            regions,
            constants: vec![],
            table_columns: vec![],
            region_index: 0,
        }),
    };
    circuit.synthesize(config, &mut assign)?;
    let Pass::Assignment(plan) = assign.pass else {
        unreachable!()
    };

    if constant_positions.len() < plan.constants.len() {
        return Err(Error::Synthesis);
    }
    for ((fixed_column, fixed_row), (value, advice)) in
        constant_positions.into_iter().zip(plan.constants)
    {
        plan.cs
            .assign_fixed(fixed_column, fixed_row, &mut || Value::known(value))?;
        plan.cs.copy(
            fixed_column.into(),
            fixed_row,
            advice.column,
            plan.regions[advice.region_index] + advice.row_offset,
        )?;
    }
    Ok(())
}

/// The row intervals allocated in one column: `(start, length)`, ordered
/// (and deduplicated) by start.
#[derive(Clone, Default, Debug)]
struct Allocations(BTreeMap<usize, usize>);

impl Allocations {
    /// The row after the last allocated interval.
    fn unbounded_interval_start(&self) -> usize {
        self.0
            .iter()
            .next_back()
            .map(|(start, length)| start + length)
            .unwrap_or(0)
    }

    /// The free intervals `(start, end)` from `start` up to `end` (or
    /// without bound: the last interval then has no end).
    fn free_intervals(&self, start: usize, end: Option<usize>) -> Vec<(usize, Option<usize>)> {
        let mut out = vec![];
        let mut row = start;
        for (&r_start, &r_length) in self.0.iter() {
            if end.map(|end| r_start >= end).unwrap_or(false) {
                // Skipped without advancing, as the reference does.
                continue;
            }
            if row < r_start {
                out.push((row, Some(r_start)));
            }
            row = cmp::max(row, r_start + r_length);
        }
        if end.map(|end| row < end).unwrap_or(true) {
            out.push((row, end));
        }
        out
    }
}

type CircuitAllocations = BTreeMap<RegionColumn, Allocations>;

/// The first row at or after `start` where a region of `region_length` rows
/// fits in all of `region_columns`; allocates it.
fn first_fit_region(
    column_allocations: &mut CircuitAllocations,
    region_columns: &[RegionColumn],
    region_length: usize,
    start: usize,
    slack: Option<usize>,
) -> Option<usize> {
    let (c, remaining_columns) = match region_columns.split_first() {
        Some(cols) => cols,
        None => return Some(start),
    };
    let end = slack.map(|slack| start + region_length + slack);

    // Iterate over the unallocated non-empty intervals in c that intersect
    // [start, end).
    let spaces = column_allocations
        .entry(*c)
        .or_default()
        .free_intervals(start, end);
    for (space_start, space_end) in spaces {
        // Do we have enough room for this column of the region in this
        // interval?
        let s_slack =
            space_end.map(|end| (end as isize - space_start as isize) - region_length as isize);
        if s_slack.unwrap_or(0) >= 0 {
            let row = first_fit_region(
                column_allocations,
                remaining_columns,
                region_length,
                space_start,
                s_slack.map(|s| s as usize),
            );
            if let Some(row) = row {
                column_allocations
                    .get_mut(c)
                    .expect("inserted above")
                    .0
                    .entry(row)
                    .or_insert(region_length);
                return Some(row);
            }
        }
    }
    None
}

/// Positions the regions greedily, in the given order.
fn slot_in(region_shapes: Vec<RegionShape>) -> (Vec<(usize, RegionShape)>, CircuitAllocations) {
    let mut column_allocations = CircuitAllocations::new();
    let regions = region_shapes
        .into_iter()
        .map(|region| {
            // Sorted, as the set iterates in order.
            let region_columns: Vec<_> = region.columns.iter().cloned().collect();
            let region_start = first_fit_region(
                &mut column_allocations,
                &region_columns,
                region.row_count,
                0,
                None,
            )
            .expect("We can always fit a region somewhere");
            (region_start, region)
        })
        .collect();
    (regions, column_allocations)
}

/// Sorts the regions by advice area (columns times rows), largest first,
/// and positions them greedily. The order of regions of equal area is that
/// of the pattern-defeating quicksort of Rust 1.56 to 1.80, which the
/// reference pins.
fn slot_in_biggest_advice_first(
    region_shapes: Vec<RegionShape>,
) -> (Vec<usize>, CircuitAllocations) {
    let sort_key = |shape: &RegionShape| {
        // Count the number of advice columns.
        let advice_cols = shape
            .columns
            .iter()
            .filter(|c| matches!(c, RegionColumn::Column(c) if c.column_type == Any::Advice))
            .count();
        // Sort by advice area (since this has the most contention).
        advice_cols * shape.row_count
    };
    let keys: Vec<usize> = region_shapes.iter().map(sort_key).collect();
    let order = super::pdqsort::sorted_order(&keys);
    let mut shapes: Vec<Option<RegionShape>> = region_shapes.into_iter().map(Some).collect();
    let sorted_regions: Vec<RegionShape> = order
        .into_iter()
        .rev()
        .map(|i| shapes[i].take().expect("a permutation"))
        .collect();

    let (regions, column_allocations) = slot_in(sorted_regions);
    let mut starts = vec![0; regions.len()];
    for (start, region) in regions {
        starts[region.region_index] = start;
    }
    (starts, column_allocations)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(i: usize, cols: &[usize], rows: usize) -> RegionShape {
        RegionShape {
            region_index: i,
            columns: cols
                .iter()
                .map(|c| RegionColumn::Column(Column::new(*c, Any::Advice)))
                .collect(),
            row_count: rows,
        }
    }

    /// The `test_slot_in` case of `halo2_proofs`.
    #[test]
    fn slot_in_matches_reference() {
        let regions = vec![
            shape(0, &[0, 1], 15),
            shape(1, &[2], 10),
            shape(2, &[2, 0], 10),
        ];
        let starts: Vec<usize> = slot_in(regions).0.into_iter().map(|(i, _)| i).collect();
        assert_eq!(starts, [0, 0, 15]);
    }
}
