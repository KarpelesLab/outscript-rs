//! Tests of the Orchard module, most of them running the official
//! `zcash-test-vectors` files (kept verbatim under `testdata/`).

use serde_json::Value;

mod curves;
mod gen_tables;
mod hashes;
mod keys;
mod notes;
mod unified;

/// The rows of a test vector file, without its two header rows.
pub(crate) fn vectors(json: &str) -> Vec<Vec<Value>> {
    let rows: Vec<Vec<Value>> = serde_json::from_str(json).unwrap();
    rows.into_iter().skip(2).collect()
}

/// A hex string field.
pub(crate) fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

/// A hex string field of a fixed length.
pub(crate) fn arr<const N: usize>(v: &Value) -> [u8; N] {
    bytes(v).try_into().unwrap()
}
