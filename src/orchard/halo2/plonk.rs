//! The description of a PLONKish circuit: columns, gates, lookups and the
//! permutation argument, as `halo2_proofs::plonk::ConstraintSystem` builds
//! it. The order in which columns and queries are created is part of the
//! verifying key, so everything here follows the reference step for step.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::{Ordering, max};
use core::fmt;
use core::ops::{Add, Mul, Neg, Sub};

use crate::orchard::Fp;

/// A row offset relative to the row a gate is evaluated at.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rotation(pub i32);

impl Rotation {
    /// The current row.
    pub const fn cur() -> Rotation {
        Rotation(0)
    }

    /// The previous row.
    pub const fn prev() -> Rotation {
        Rotation(-1)
    }

    /// The next row.
    pub const fn next() -> Rotation {
        Rotation(1)
    }
}

impl fmt::Debug for Rotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Rotation").field(&self.0).finish()
    }
}

/// The kind of a column.
pub trait ColumnType: 'static + Sized + Copy + fmt::Debug + PartialEq + Eq + Into<Any> {}

/// A column of the circuit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Column<C: ColumnType> {
    pub(crate) index: usize,
    pub(crate) column_type: C,
}

impl<C: ColumnType> Column<C> {
    pub(crate) fn new(index: usize, column_type: C) -> Self {
        Column { index, column_type }
    }

    /// The index of the column among those of its kind.
    pub fn index(&self) -> usize {
        self.index
    }

    /// The kind of the column.
    pub fn column_type(&self) -> &C {
        &self.column_type
    }
}

impl<C: ColumnType> Ord for Column<C> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.column_type.into().cmp(&other.column_type.into()) {
            Ordering::Equal => self.index.cmp(&other.index),
            order => order,
        }
    }
}

impl<C: ColumnType> PartialOrd for Column<C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// An advice (witness) column.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Advice;

/// A fixed column.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fixed;

/// An instance (public input) column.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Instance;

/// A column of any kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Any {
    /// An advice column.
    Advice,
    /// A fixed column.
    Fixed,
    /// An instance column.
    Instance,
}

impl Any {
    fn rank(self) -> u8 {
        match self {
            Any::Instance => 0,
            Any::Advice => 1,
            Any::Fixed => 2,
        }
    }
}

impl Ord for Any {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Any {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ColumnType for Advice {}
impl ColumnType for Fixed {}
impl ColumnType for Instance {}
impl ColumnType for Any {}

impl From<Advice> for Any {
    fn from(_: Advice) -> Any {
        Any::Advice
    }
}

impl From<Fixed> for Any {
    fn from(_: Fixed) -> Any {
        Any::Fixed
    }
}

impl From<Instance> for Any {
    fn from(_: Instance) -> Any {
        Any::Instance
    }
}

macro_rules! column_into_any {
    ($t:ident) => {
        impl From<Column<$t>> for Column<Any> {
            fn from(c: Column<$t>) -> Column<Any> {
                Column {
                    index: c.index,
                    column_type: Any::$t,
                }
            }
        }
        impl TryFrom<Column<Any>> for Column<$t> {
            type Error = &'static str;
            fn try_from(any: Column<Any>) -> Result<Self, Self::Error> {
                match any.column_type {
                    Any::$t => Ok(Column {
                        index: any.index,
                        column_type: $t,
                    }),
                    _ => Err("wrong column type"),
                }
            }
        }
    };
}
column_into_any!(Advice);
column_into_any!(Fixed);
column_into_any!(Instance);

/// A selector: a virtual fixed column of zeros and ones that switches gates
/// on. A simple selector (the flag) may be merged with others into one real
/// column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selector(pub(crate) usize, pub(crate) bool);

impl Selector {
    /// Enables the selector at an offset of a region.
    pub fn enable(
        &self,
        region: &mut super::circuit::Region<'_, '_>,
        offset: usize,
    ) -> Result<(), super::Error> {
        region.enable_selector(self, offset)
    }

    /// Whether the selector is simple.
    pub fn is_simple(&self) -> bool {
        self.1
    }
}

/// A query of a fixed column.
#[derive(Copy, Clone, Debug)]
pub struct FixedQuery {
    pub(crate) index: usize,
    pub(crate) column_index: usize,
    pub(crate) rotation: Rotation,
}

/// A query of an advice column.
#[derive(Copy, Clone, Debug)]
pub struct AdviceQuery {
    pub(crate) index: usize,
    pub(crate) column_index: usize,
    pub(crate) rotation: Rotation,
}

/// A query of an instance column.
#[derive(Copy, Clone, Debug)]
pub struct InstanceQuery {
    pub(crate) index: usize,
    pub(crate) column_index: usize,
    pub(crate) rotation: Rotation,
}

/// A fixed column of a lookup table.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TableColumn {
    inner: Column<Fixed>,
}

impl TableColumn {
    pub(crate) fn inner(&self) -> Column<Fixed> {
        self.inner
    }
}

/// A field element printed as `halo2_proofs` prints it (`0x` and 64 hex
/// digits, most significant first).
pub(crate) struct Hex<'a>(pub(crate) &'a Fp);

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let l = self.0.to_raw();
        write!(f, "0x{:016x}{:016x}{:016x}{:016x}", l[3], l[2], l[1], l[0])
    }
}

/// A low-degree polynomial expression over the cells of a row and its
/// neighbours.
#[derive(Clone)]
pub enum Expression {
    /// A constant.
    Constant(Fp),
    /// A selector (replaced by a fixed column expression during key
    /// generation).
    Selector(Selector),
    /// A fixed column cell.
    Fixed(FixedQuery),
    /// An advice column cell.
    Advice(AdviceQuery),
    /// An instance column cell.
    Instance(InstanceQuery),
    /// The negation of an expression.
    Negated(Box<Expression>),
    /// The sum of two expressions.
    Sum(Box<Expression>, Box<Expression>),
    /// The product of two expressions.
    Product(Box<Expression>, Box<Expression>),
    /// An expression times a constant.
    Scaled(Box<Expression>, Fp),
}

impl Expression {
    /// Evaluates the expression with the given leaf and node operations.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate<T>(
        &self,
        constant: &impl Fn(Fp) -> T,
        selector_column: &impl Fn(Selector) -> T,
        fixed_column: &impl Fn(FixedQuery) -> T,
        advice_column: &impl Fn(AdviceQuery) -> T,
        instance_column: &impl Fn(InstanceQuery) -> T,
        negated: &impl Fn(T) -> T,
        sum: &impl Fn(T, T) -> T,
        product: &impl Fn(T, T) -> T,
        scaled: &impl Fn(T, Fp) -> T,
    ) -> T {
        macro_rules! ev {
            ($e:expr) => {
                $e.evaluate(
                    constant,
                    selector_column,
                    fixed_column,
                    advice_column,
                    instance_column,
                    negated,
                    sum,
                    product,
                    scaled,
                )
            };
        }
        match self {
            Expression::Constant(scalar) => constant(*scalar),
            Expression::Selector(selector) => selector_column(*selector),
            Expression::Fixed(query) => fixed_column(*query),
            Expression::Advice(query) => advice_column(*query),
            Expression::Instance(query) => instance_column(*query),
            Expression::Negated(a) => negated(ev!(a)),
            Expression::Sum(a, b) => {
                let a = ev!(a);
                let b = ev!(b);
                sum(a, b)
            }
            Expression::Product(a, b) => {
                let a = ev!(a);
                let b = ev!(b);
                product(a, b)
            }
            Expression::Scaled(a, f) => scaled(ev!(a), *f),
        }
    }

    /// The degree of the expression.
    pub fn degree(&self) -> usize {
        match self {
            Expression::Constant(_) => 0,
            Expression::Selector(_) => 1,
            Expression::Fixed(_) => 1,
            Expression::Advice(_) => 1,
            Expression::Instance(_) => 1,
            Expression::Negated(poly) => poly.degree(),
            Expression::Sum(a, b) => max(a.degree(), b.degree()),
            Expression::Product(a, b) => a.degree() + b.degree(),
            Expression::Scaled(poly, _) => poly.degree(),
        }
    }

    /// The square of the expression.
    pub fn square(self) -> Self {
        self.clone() * self
    }

    fn contains_simple_selector(&self) -> bool {
        self.evaluate(
            &|_| false,
            &|selector| selector.is_simple(),
            &|_| false,
            &|_| false,
            &|_| false,
            &|a| a,
            &|a, b| a || b,
            &|a, b| a || b,
            &|a, _| a,
        )
    }

    fn extract_simple_selector(&self) -> Option<Selector> {
        let op = |a, b| match (a, b) {
            (Some(a), None) | (None, Some(a)) => Some(a),
            (Some(_), Some(_)) => panic!("two simple selectors cannot be in the same expression"),
            _ => None,
        };
        self.evaluate(
            &|_| None,
            &|selector| {
                if selector.is_simple() {
                    Some(selector)
                } else {
                    None
                }
            },
            &|_| None,
            &|_| None,
            &|_| None,
            &|a| a,
            &op,
            &op,
            &|a, _| a,
        )
    }
}

impl fmt::Debug for Expression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expression::Constant(scalar) => f.debug_tuple("Constant").field(&Hex(scalar)).finish(),
            Expression::Selector(selector) => f.debug_tuple("Selector").field(selector).finish(),
            Expression::Fixed(q) => f
                .debug_struct("Fixed")
                .field("query_index", &q.index)
                .field("column_index", &q.column_index)
                .field("rotation", &q.rotation)
                .finish(),
            Expression::Advice(q) => f
                .debug_struct("Advice")
                .field("query_index", &q.index)
                .field("column_index", &q.column_index)
                .field("rotation", &q.rotation)
                .finish(),
            Expression::Instance(q) => f
                .debug_struct("Instance")
                .field("query_index", &q.index)
                .field("column_index", &q.column_index)
                .field("rotation", &q.rotation)
                .finish(),
            Expression::Negated(poly) => f.debug_tuple("Negated").field(poly).finish(),
            Expression::Sum(a, b) => f.debug_tuple("Sum").field(a).field(b).finish(),
            Expression::Product(a, b) => f.debug_tuple("Product").field(a).field(b).finish(),
            Expression::Scaled(poly, scalar) => f
                .debug_tuple("Scaled")
                .field(poly)
                .field(&Hex(scalar))
                .finish(),
        }
    }
}

impl Neg for Expression {
    type Output = Expression;
    fn neg(self) -> Self::Output {
        Expression::Negated(Box::new(self))
    }
}

impl Add for Expression {
    type Output = Expression;
    fn add(self, rhs: Expression) -> Expression {
        if self.contains_simple_selector() || rhs.contains_simple_selector() {
            panic!("attempted to use a simple selector in an addition");
        }
        Expression::Sum(Box::new(self), Box::new(rhs))
    }
}

impl Sub for Expression {
    type Output = Expression;
    fn sub(self, rhs: Expression) -> Expression {
        if self.contains_simple_selector() || rhs.contains_simple_selector() {
            panic!("attempted to use a simple selector in a subtraction");
        }
        Expression::Sum(Box::new(self), Box::new(-rhs))
    }
}

impl Mul for Expression {
    type Output = Expression;
    fn mul(self, rhs: Expression) -> Expression {
        if self.contains_simple_selector() && rhs.contains_simple_selector() {
            panic!("attempted to multiply two expressions containing simple selectors");
        }
        Expression::Product(Box::new(self), Box::new(rhs))
    }
}

impl Mul<Fp> for Expression {
    type Output = Expression;
    fn mul(self, rhs: Fp) -> Expression {
        Expression::Scaled(Box::new(self), rhs)
    }
}

/// The constraints of a gate sharing a selector, as
/// `halo2_proofs::plonk::Constraints::with_selector`.
pub struct Constraints;

impl Constraints {
    /// Each constraint multiplied by the selector expression.
    pub fn with_selector(
        selector: Expression,
        constraints: impl IntoIterator<Item = Expression>,
    ) -> Vec<Expression> {
        constraints
            .into_iter()
            .map(|c| selector.clone() * c)
            .collect()
    }
}

/// A gate: polynomial identities that must vanish on every row.
#[derive(Clone, Debug)]
pub(crate) struct Gate {
    #[allow(dead_code)]
    pub(crate) name: &'static str,
    pub(crate) polys: Vec<Expression>,
}

/// The columns bound by copy constraints.
#[derive(Debug, Clone)]
pub(crate) struct PermutationArgument {
    pub(crate) columns: Vec<Column<Any>>,
}

impl PermutationArgument {
    pub(crate) fn required_degree(&self) -> usize {
        3
    }

    fn add_column(&mut self, column: Column<Any>) {
        if !self.columns.contains(&column) {
            self.columns.push(column);
        }
    }
}

/// A lookup argument: each row's input expressions must be a row of the
/// table expressions.
#[derive(Clone, Debug)]
pub(crate) struct LookupArgument {
    pub(crate) input_expressions: Vec<Expression>,
    pub(crate) table_expressions: Vec<Expression>,
}

impl LookupArgument {
    pub(crate) fn required_degree(&self) -> usize {
        assert_eq!(self.input_expressions.len(), self.table_expressions.len());
        let mut input_degree = 1;
        for expr in self.input_expressions.iter() {
            input_degree = max(input_degree, expr.degree());
        }
        let mut table_degree = 1;
        for expr in self.table_expressions.iter() {
            table_degree = max(table_degree, expr.degree());
        }
        max(4, 2 + input_degree + table_degree)
    }
}

/// The description of a circuit: its columns, gates, lookups and copy
/// constraint columns.
#[derive(Debug, Clone)]
pub struct ConstraintSystem {
    pub(crate) num_fixed_columns: usize,
    pub(crate) num_advice_columns: usize,
    pub(crate) num_instance_columns: usize,
    pub(crate) num_selectors: usize,
    pub(crate) selector_map: Vec<Column<Fixed>>,
    pub(crate) gates: Vec<Gate>,
    pub(crate) advice_queries: Vec<(Column<Advice>, Rotation)>,
    num_advice_queries: Vec<usize>,
    pub(crate) instance_queries: Vec<(Column<Instance>, Rotation)>,
    pub(crate) fixed_queries: Vec<(Column<Fixed>, Rotation)>,
    pub(crate) permutation: PermutationArgument,
    pub(crate) lookups: Vec<LookupArgument>,
    pub(crate) constants: Vec<Column<Fixed>>,
    pub(crate) minimum_degree: Option<usize>,
}

impl Default for ConstraintSystem {
    fn default() -> ConstraintSystem {
        ConstraintSystem {
            num_fixed_columns: 0,
            num_advice_columns: 0,
            num_instance_columns: 0,
            num_selectors: 0,
            selector_map: vec![],
            gates: vec![],
            fixed_queries: Vec::new(),
            advice_queries: Vec::new(),
            num_advice_queries: Vec::new(),
            instance_queries: Vec::new(),
            permutation: PermutationArgument { columns: vec![] },
            lookups: Vec::new(),
            constants: vec![],
            minimum_degree: None,
        }
    }
}

/// The gate polynomials, printed as one flat list.
struct PinnedGates<'a>(&'a [Gate]);

impl fmt::Debug for PinnedGates<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().flat_map(|gate| gate.polys.iter()))
            .finish()
    }
}

/// The permutation argument under the name the reference prints.
struct PinnedPermutation<'a>(&'a PermutationArgument);

impl fmt::Debug for PinnedPermutation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Argument")
            .field("columns", &self.0.columns)
            .finish()
    }
}

/// A lookup argument under the name the reference prints.
struct PinnedLookup<'a>(&'a LookupArgument);

impl fmt::Debug for PinnedLookup<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Argument")
            .field("input_expressions", &self.0.input_expressions)
            .field("table_expressions", &self.0.table_expressions)
            .finish()
    }
}

struct PinnedLookups<'a>(&'a [LookupArgument]);

impl fmt::Debug for PinnedLookups<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(PinnedLookup))
            .finish()
    }
}

/// The part of a constraint system a verifying key commits to, printed
/// exactly as `halo2_proofs` prints its `PinnedConstraintSystem`.
pub(crate) struct PinnedConstraintSystem<'a>(pub(crate) &'a ConstraintSystem);

impl fmt::Debug for PinnedConstraintSystem<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cs = self.0;
        f.debug_struct("PinnedConstraintSystem")
            .field("num_fixed_columns", &cs.num_fixed_columns)
            .field("num_advice_columns", &cs.num_advice_columns)
            .field("num_instance_columns", &cs.num_instance_columns)
            .field("num_selectors", &cs.num_selectors)
            .field("gates", &PinnedGates(&cs.gates))
            .field("advice_queries", &cs.advice_queries)
            .field("instance_queries", &cs.instance_queries)
            .field("fixed_queries", &cs.fixed_queries)
            .field("permutation", &PinnedPermutation(&cs.permutation))
            .field("lookups", &PinnedLookups(&cs.lookups))
            .field("constants", &cs.constants)
            .field("minimum_degree", &cs.minimum_degree)
            .finish()
    }
}

impl ConstraintSystem {
    /// Makes a fixed column available for the constants of the circuit.
    pub fn enable_constant(&mut self, column: Column<Fixed>) {
        if !self.constants.contains(&column) {
            self.constants.push(column);
            self.enable_equality(column);
        }
    }

    /// Lets the cells of a column take part in copy constraints.
    pub fn enable_equality<C: Into<Column<Any>>>(&mut self, column: C) {
        let column = column.into();
        self.query_any_index(column, Rotation::cur());
        self.permutation.add_column(column);
    }

    /// Adds a lookup argument; returns its index.
    pub fn lookup(
        &mut self,
        table_map: impl FnOnce(&mut VirtualCells<'_>) -> Vec<(Expression, TableColumn)>,
    ) -> usize {
        let mut cells = VirtualCells::new(self);
        let (input_expressions, table_expressions) = table_map(&mut cells)
            .into_iter()
            .map(|(input, table)| {
                if input.contains_simple_selector() {
                    panic!("expression containing simple selector supplied to lookup argument");
                }
                let table = cells.query_fixed(table.inner());
                (input, table)
            })
            .unzip();
        let index = self.lookups.len();
        self.lookups.push(LookupArgument {
            input_expressions,
            table_expressions,
        });
        index
    }

    fn query_fixed_index(&mut self, column: Column<Fixed>) -> usize {
        for (index, fixed_query) in self.fixed_queries.iter().enumerate() {
            if fixed_query == &(column, Rotation::cur()) {
                return index;
            }
        }
        let index = self.fixed_queries.len();
        self.fixed_queries.push((column, Rotation::cur()));
        index
    }

    pub(crate) fn query_advice_index(&mut self, column: Column<Advice>, at: Rotation) -> usize {
        for (index, advice_query) in self.advice_queries.iter().enumerate() {
            if advice_query == &(column, at) {
                return index;
            }
        }
        let index = self.advice_queries.len();
        self.advice_queries.push((column, at));
        self.num_advice_queries[column.index] += 1;
        index
    }

    fn query_instance_index(&mut self, column: Column<Instance>, at: Rotation) -> usize {
        for (index, instance_query) in self.instance_queries.iter().enumerate() {
            if instance_query == &(column, at) {
                return index;
            }
        }
        let index = self.instance_queries.len();
        self.instance_queries.push((column, at));
        index
    }

    fn query_any_index(&mut self, column: Column<Any>, at: Rotation) -> usize {
        match column.column_type {
            Any::Advice => self.query_advice_index(Column::new(column.index, Advice), at),
            Any::Fixed => self.query_fixed_index(Column::new(column.index, Fixed)),
            Any::Instance => self.query_instance_index(Column::new(column.index, Instance), at),
        }
    }

    /// The index of an existing query of `column` at the current row.
    ///
    /// # Panics
    /// Panics if the column was never queried at the current row.
    pub(crate) fn get_any_query_index(&self, column: Column<Any>) -> usize {
        let at = Rotation::cur();
        let found = match column.column_type {
            Any::Advice => self
                .advice_queries
                .iter()
                .position(|q| q == &(Column::new(column.index, Advice), at)),
            Any::Fixed => self
                .fixed_queries
                .iter()
                .position(|q| q == &(Column::new(column.index, Fixed), at)),
            Any::Instance => self
                .instance_queries
                .iter()
                .position(|q| q == &(Column::new(column.index, Instance), at)),
        };
        found.expect("query exists")
    }

    /// Sets the minimum degree of the circuit.
    pub fn set_minimum_degree(&mut self, degree: usize) {
        self.minimum_degree = Some(degree);
    }

    /// Adds a gate. Every returned expression must be zero on every row.
    ///
    /// # Panics
    /// Panics if the gate has no constraint.
    pub fn create_gate<Iter: IntoIterator<Item = Expression>>(
        &mut self,
        name: &'static str,
        constraints: impl FnOnce(&mut VirtualCells<'_>) -> Iter,
    ) {
        let mut cells = VirtualCells::new(self);
        let polys: Vec<Expression> = constraints(&mut cells).into_iter().collect();
        assert!(
            !polys.is_empty(),
            "Gates must contain at least one constraint."
        );
        self.gates.push(Gate { name, polys });
    }

    /// Replaces the selectors by fixed columns, merging simple selectors
    /// that are never active on the same row. Returns the new constraint
    /// system and the values of the new fixed columns.
    pub(crate) fn compress_selectors(mut self, selectors: Vec<Vec<bool>>) -> (Self, Vec<Vec<Fp>>) {
        assert_eq!(selectors.len(), self.num_selectors);

        // The maximum degree of the gates each simple selector is in.
        let mut degrees = vec![0; selectors.len()];
        for expr in self.gates.iter().flat_map(|gate| gate.polys.iter()) {
            if let Some(selector) = expr.extract_simple_selector() {
                degrees[selector.0] = max(degrees[selector.0], expr.degree());
            }
        }

        let max_degree = self.degree();
        let mut new_columns = vec![];
        let (polys, selector_assignment) = compress_selectors_process(
            selectors
                .into_iter()
                .zip(degrees)
                .enumerate()
                .map(|(i, (activations, max_degree))| SelectorDescription {
                    selector: i,
                    activations,
                    max_degree,
                })
                .collect(),
            max_degree,
            || {
                let column = self.fixed_column();
                new_columns.push(column);
                Expression::Fixed(FixedQuery {
                    index: self.query_fixed_index(column),
                    column_index: column.index,
                    rotation: Rotation::cur(),
                })
            },
        );

        let mut selector_map = vec![None; selector_assignment.len()];
        let mut selector_replacements = vec![None; selector_assignment.len()];
        for assignment in selector_assignment {
            selector_replacements[assignment.selector] = Some(assignment.expression);
            selector_map[assignment.selector] = Some(new_columns[assignment.combination_index]);
        }

        self.selector_map = selector_map.into_iter().map(|a| a.unwrap()).collect();
        let selector_replacements: Vec<Expression> = selector_replacements
            .into_iter()
            .map(|a| a.unwrap())
            .collect();

        fn replace_selectors(
            expr: &mut Expression,
            selector_replacements: &[Expression],
            must_be_nonsimple: bool,
        ) {
            *expr = expr.evaluate(
                &Expression::Constant,
                &|selector| {
                    if must_be_nonsimple {
                        // Simple selectors are prohibited from appearing in
                        // lookup argument inputs.
                        assert!(!selector.is_simple());
                    }
                    selector_replacements[selector.0].clone()
                },
                &Expression::Fixed,
                &Expression::Advice,
                &Expression::Instance,
                &|a| -a,
                &|a, b| a + b,
                &|a, b| a * b,
                &|a, f| a * f,
            );
        }

        for expr in self.gates.iter_mut().flat_map(|gate| gate.polys.iter_mut()) {
            replace_selectors(expr, &selector_replacements, false);
        }
        for expr in self.lookups.iter_mut().flat_map(|lookup| {
            lookup
                .input_expressions
                .iter_mut()
                .chain(lookup.table_expressions.iter_mut())
        }) {
            replace_selectors(expr, &selector_replacements, true);
        }

        (self, polys)
    }

    /// Allocates a simple selector.
    pub fn selector(&mut self) -> Selector {
        let index = self.num_selectors;
        self.num_selectors += 1;
        Selector(index, true)
    }

    /// Allocates a selector that may be used anywhere in an expression and
    /// is never merged with others.
    pub fn complex_selector(&mut self) -> Selector {
        let index = self.num_selectors;
        self.num_selectors += 1;
        Selector(index, false)
    }

    /// Allocates a column of a lookup table.
    pub fn lookup_table_column(&mut self) -> TableColumn {
        TableColumn {
            inner: self.fixed_column(),
        }
    }

    /// Allocates a fixed column.
    pub fn fixed_column(&mut self) -> Column<Fixed> {
        let tmp = Column::new(self.num_fixed_columns, Fixed);
        self.num_fixed_columns += 1;
        tmp
    }

    /// Allocates an advice column.
    pub fn advice_column(&mut self) -> Column<Advice> {
        let tmp = Column::new(self.num_advice_columns, Advice);
        self.num_advice_columns += 1;
        self.num_advice_queries.push(0);
        tmp
    }

    /// Allocates an instance column.
    pub fn instance_column(&mut self) -> Column<Instance> {
        let tmp = Column::new(self.num_instance_columns, Instance);
        self.num_instance_columns += 1;
        tmp
    }

    /// The degree of the constraint system (the maximum degree of its
    /// custom gates and arguments).
    pub fn degree(&self) -> usize {
        let mut degree = self.permutation.required_degree();
        degree = max(
            degree,
            self.lookups
                .iter()
                .map(|l| l.required_degree())
                .max()
                .unwrap_or(1),
        );
        degree = max(
            degree,
            self.gates
                .iter()
                .flat_map(|gate| gate.polys.iter().map(|poly| poly.degree()))
                .max()
                .unwrap_or(0),
        );
        max(degree, self.minimum_degree.unwrap_or(1))
    }

    /// The number of rows at the end of each column that hold blinding
    /// factors.
    pub fn blinding_factors(&self) -> usize {
        // All of the prover's advice columns are evaluated at no more than
        // `factors` distinct points.
        let factors = *self.num_advice_queries.iter().max().unwrap_or(&1);
        // At least 3 for the permutation and lookup arguments, one more so
        // the evaluations at x hide the polynomial, and one more to offset
        // the multiopen evaluation at x_3.
        max(3, factors) + 2
    }

    /// The minimum number of rows a circuit of this shape needs.
    pub fn minimum_rows(&self) -> usize {
        self.blinding_factors() + 3
    }
}

/// The cells a gate is being defined over.
pub struct VirtualCells<'a> {
    meta: &'a mut ConstraintSystem,
}

impl<'a> VirtualCells<'a> {
    fn new(meta: &'a mut ConstraintSystem) -> Self {
        VirtualCells { meta }
    }

    /// Queries a selector at the current row.
    pub fn query_selector(&mut self, selector: Selector) -> Expression {
        Expression::Selector(selector)
    }

    /// Queries a fixed column at the current row.
    pub fn query_fixed(&mut self, column: Column<Fixed>) -> Expression {
        Expression::Fixed(FixedQuery {
            index: self.meta.query_fixed_index(column),
            column_index: column.index,
            rotation: Rotation::cur(),
        })
    }

    /// Queries an advice column at a relative row.
    pub fn query_advice(&mut self, column: Column<Advice>, at: Rotation) -> Expression {
        Expression::Advice(AdviceQuery {
            index: self.meta.query_advice_index(column, at),
            column_index: column.index,
            rotation: at,
        })
    }

    /// Queries an instance column at a relative row.
    pub fn query_instance(&mut self, column: Column<Instance>, at: Rotation) -> Expression {
        Expression::Instance(InstanceQuery {
            index: self.meta.query_instance_index(column, at),
            column_index: column.index,
            rotation: at,
        })
    }

    /// Queries a column of any kind at a relative row.
    ///
    /// # Panics
    /// Panics on a fixed column at another row than the current one.
    pub fn query_any<C: Into<Column<Any>>>(&mut self, column: C, at: Rotation) -> Expression {
        let column = column.into();
        match column.column_type {
            Any::Advice => self.query_advice(Column::new(column.index, Advice), at),
            Any::Fixed => {
                if at != Rotation::cur() {
                    panic!("Fixed columns can only be queried at the current rotation");
                }
                self.query_fixed(Column::new(column.index, Fixed))
            }
            Any::Instance => self.query_instance(Column::new(column.index, Instance), at),
        }
    }
}

struct SelectorDescription {
    selector: usize,
    activations: Vec<bool>,
    max_degree: usize,
}

struct SelectorAssignment {
    selector: usize,
    combination_index: usize,
    expression: Expression,
}

/// `halo2_proofs::plonk::circuit::compress_selectors::process`: greedily
/// merges selectors that are never active together into shared fixed
/// columns, within the degree bound.
fn compress_selectors_process(
    mut selectors: Vec<SelectorDescription>,
    max_degree: usize,
    mut allocate_fixed_column: impl FnMut() -> Expression,
) -> (Vec<Vec<Fp>>, Vec<SelectorAssignment>) {
    if selectors.is_empty() {
        return (vec![], vec![]);
    }
    let n = selectors[0].activations.len();
    assert!(selectors.iter().all(|a| a.activations.len() == n));

    let mut combination_assignments = vec![];
    let mut selector_assignments = vec![];

    // All provided selectors of degree 0 are assumed to be either concrete
    // selectors or do not appear in a gate. Let's address these first.
    selectors.retain(|selector| {
        if selector.max_degree == 0 {
            let expression = allocate_fixed_column();
            let combination_assignment = selector
                .activations
                .iter()
                .map(|b| if *b { Fp::ONE } else { Fp::ZERO })
                .collect::<Vec<_>>();
            let combination_index = combination_assignments.len();
            combination_assignments.push(combination_assignment);
            selector_assignments.push(SelectorAssignment {
                selector: selector.selector,
                combination_index,
                expression,
            });
            false
        } else {
            true
        }
    });

    // All of the remaining selectors are simple. Selectors that are active
    // on a common row exclude each other.
    let mut exclusion_matrix = (0..selectors.len())
        .map(|i| vec![false; i])
        .collect::<Vec<_>>();
    for (i, rows) in selectors
        .iter()
        .map(|selector| &selector.activations)
        .enumerate()
    {
        for (j, other_selector) in selectors.iter().enumerate().take(i) {
            if rows
                .iter()
                .zip(other_selector.activations.iter())
                .any(|(l, r)| l & r)
            {
                exclusion_matrix[i][j] = true;
            }
        }
    }

    let mut added = vec![false; selectors.len()];
    for (i, selector) in selectors.iter().enumerate() {
        if added[i] {
            continue;
        }
        added[i] = true;
        assert!(selector.max_degree <= max_degree);
        // This is used to keep track of the largest degree gate involved in
        // the combination so far.
        let mut d = selector.max_degree - 1;
        let mut combination = vec![selector];
        let mut combination_added = vec![i];

        'try_selectors: for (j, selector) in selectors.iter().enumerate().skip(i + 1) {
            if d + combination.len() == max_degree {
                break 'try_selectors;
            }
            if added[j] {
                continue 'try_selectors;
            }
            for &i in combination_added.iter() {
                if exclusion_matrix[j][i] {
                    continue 'try_selectors;
                }
            }
            let new_d = max(d, selector.max_degree - 1);
            if new_d + combination.len() + 1 > max_degree {
                continue 'try_selectors;
            }
            d = new_d;
            combination.push(selector);
            combination_added.push(j);
            added[j] = true;
        }

        let mut combination_assignment = vec![Fp::ZERO; n];
        let combination_len = combination.len();
        let combination_index = combination_assignments.len();
        let query = allocate_fixed_column();

        let mut assigned_root = Fp::ONE;
        selector_assignments.extend(combination.into_iter().map(|selector| {
            // The expression is nonzero only where the fixed column holds
            // this selector's root.
            let mut expression = query.clone();
            let mut root = Fp::ONE;
            for _ in 0..combination_len {
                if root != assigned_root {
                    expression = expression * (Expression::Constant(root) - query.clone());
                }
                root += Fp::ONE;
            }
            for (combination, selector) in combination_assignment
                .iter_mut()
                .zip(selector.activations.iter())
            {
                if *selector {
                    *combination = assigned_root;
                }
            }
            assigned_root += Fp::ONE;
            SelectorAssignment {
                selector: selector.selector,
                combination_index,
                expression,
            }
        }));
        combination_assignments.push(combination_assignment);
    }

    (combination_assignments, selector_assignments)
}
