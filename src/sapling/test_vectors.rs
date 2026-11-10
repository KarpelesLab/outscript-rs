//! The official test vectors, from
//! <https://github.com/zcash/zcash-test-vectors> (`test-vectors/json`), kept
//! verbatim under `testdata/`, and helpers to read them.

use serde_json::Value;

/// The data rows of a zcash-test-vectors JSON file: an array of arrays whose
/// first two rows are the source and the column names.
pub(crate) fn rows(json: &str) -> Vec<Vec<Value>> {
    let all: Vec<Vec<Value>> = serde_json::from_str(json).expect("valid JSON");
    assert!(all.len() > 2);
    all[2..].to_vec()
}

/// The column names of a zcash-test-vectors JSON file.
pub(crate) fn columns(json: &str) -> Vec<String> {
    let all: Vec<Vec<Value>> = serde_json::from_str(json).expect("valid JSON");
    all[1][0]
        .as_str()
        .unwrap()
        .split(", ")
        .map(str::to_owned)
        .collect()
}

/// One row of a vector file, addressed by column name.
pub(crate) struct Row<'a> {
    pub columns: &'a [String],
    pub values: &'a [Value],
}

impl Row<'_> {
    fn value(&self, name: &str) -> &Value {
        let i = self
            .columns
            .iter()
            .position(|c| c == name)
            .unwrap_or_else(|| panic!("no column {name}"));
        &self.values[i]
    }

    /// A hex column as bytes.
    pub fn bytes(&self, name: &str) -> Vec<u8> {
        hex::decode(self.value(name).as_str().expect("a string")).expect("hex")
    }

    /// A hex column as a fixed-size array.
    pub fn array<const N: usize>(&self, name: &str) -> [u8; N] {
        self.bytes(name).try_into().expect("length")
    }

    /// An optional hex column (`null` when absent).
    pub fn opt_array<const N: usize>(&self, name: &str) -> Option<[u8; N]> {
        let v = self.value(name);
        (!v.is_null()).then(|| self.array(name))
    }

    /// An integer column.
    pub fn u64(&self, name: &str) -> u64 {
        self.value(name).as_u64().expect("an integer")
    }
}

/// Runs `f` over every row of a vector file.
pub(crate) fn for_each_row(json: &str, mut f: impl FnMut(usize, Row<'_>)) {
    let columns = columns(json);
    for (i, values) in rows(json).iter().enumerate() {
        assert_eq!(values.len(), columns.len());
        f(
            i,
            Row {
                columns: &columns,
                values,
            },
        );
    }
}

mod generators {
    use super::*;
    use crate::sapling::generators::*;

    #[test]
    fn sapling_generators() {
        let json = include_str!("testdata/sapling_generators.json");
        let mut seen = 0;
        for_each_row(json, |_, row| {
            seen += 1;
            let expect = [
                ("skb", SPENDING_KEY_BASE),
                ("pkb", PROOF_GENERATION_KEY_BASE),
                ("npb", NULLIFIER_POSITION_BASE),
                ("wprb", NOTE_COMMITMENT_RANDOMNESS_BASE),
                ("vcvb", VALUE_COMMITMENT_VALUE_BASE),
                ("vcrb", VALUE_COMMITMENT_RANDOMNESS_BASE),
                ("pb0", PEDERSEN_HASH_GENERATORS[0]),
                ("pb1", PEDERSEN_HASH_GENERATORS[1]),
                ("pb2", PEDERSEN_HASH_GENERATORS[2]),
                ("pb3", PEDERSEN_HASH_GENERATORS[3]),
            ];
            for (name, point) in expect {
                assert_eq!(point.to_bytes(), row.array::<32>(name), "{name}");
            }
        });
        assert_eq!(seen, 1);
    }
}
