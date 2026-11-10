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

/// Cross-checks against values generated with the reference implementation
/// (`testdata/sapling_reference.json`, made by
/// `testdata/sapling_reference_gen.rs` on top of `zcash/sapling-crypto`): the
/// official vectors predate ZIP-212 and only cover a tree of depth 4.
mod reference {
    use super::*;
    use crate::sapling::field::Fr;
    use crate::sapling::keys::PaymentAddress;
    use crate::sapling::note::{Note, Rseed, value_commitment};
    use crate::sapling::note_encryption::*;
    use crate::sapling::tree::{DEPTH, Frontier, Witness};
    use crate::sapling::zip32::{COIN_TYPE_MAIN, ExtendedSpendingKey};

    const JSON: &str = include_str!("testdata/sapling_reference.json");

    fn note_rows() -> (Vec<String>, Vec<Vec<Value>>) {
        let mut all = rows(JSON);
        all.pop(); // the tree
        (columns(JSON), all)
    }

    #[test]
    fn zip212_notes() {
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        let (columns, all) = note_rows();
        assert_eq!(all.len(), 4);
        for (i, values) in all.iter().enumerate() {
            let row = Row {
                columns: &columns,
                values,
            };
            let xsk =
                ExtendedSpendingKey::from_seed_account(&seed, COIN_TYPE_MAIN, i as u32).unwrap();
            assert_eq!(*xsk.to_bytes(), row.array::<169>("xsk"));
            let xfvk = xsk.to_extended_full_viewing_key();
            let (_, address) = xfvk.default_address().unwrap();
            assert_eq!(address.to_bytes(), row.array::<43>("address"));
            let (_, internal) = xsk.internal().unwrap().default_address().unwrap();
            assert_eq!(internal.to_bytes(), row.array::<43>("internal_address"));
            assert_eq!(
                PaymentAddress::from_bytes(&row.array("address")),
                Ok(address)
            );

            let value = row.u64("value");
            let note = Note::new(address, value, Rseed::AfterZip212(row.array("rseed")));
            assert_eq!(note.rcm().to_bytes(), row.array::<32>("rcm"));
            let rcv = Fr::from_bytes(&row.array("rcv")).unwrap();
            let cv = value_commitment(value, &rcv).to_bytes();
            assert_eq!(cv, row.array::<32>("cv"));
            let cmu = note.cmu();
            assert_eq!(cmu, row.array::<32>("cmu"));
            let fvk = xfvk.full_viewing_key();
            assert_eq!(
                note.nullifier(fvk.nk(), row.u64("position")),
                row.array::<32>("nf")
            );

            let memo = [row.u64("memo_byte") as u8; MEMO_SIZE];
            let (epk, c_enc) = encrypt_note(&note, &memo).unwrap();
            assert_eq!(epk, row.array::<32>("epk"));
            assert_eq!(c_enc, row.array::<580>("c_enc"));
            let ock = outgoing_cipher_key(fvk.ovk(), &cv, &cmu, &epk);
            let esk = note.rseed().esk().unwrap();
            let c_out = encrypt_outgoing(&ock, address.pk_d(), &esk);
            assert_eq!(c_out, row.array::<80>("c_out"));

            let on = Zip212Enforcement::On;
            let ivk = fvk.ivk();
            assert_eq!(
                try_note_decryption(&ivk, &epk, &cmu, &c_enc, on),
                Some((note, memo))
            );
            let compact: [u8; COMPACT_NOTE_SIZE] = c_enc[..52].try_into().unwrap();
            assert_eq!(
                try_compact_note_decryption(&ivk, &epk, &cmu, &compact, on),
                Some(note)
            );
            assert_eq!(
                try_output_recovery_with_ovk(fvk.ovk(), &cv, &cmu, &epk, &c_enc, &c_out, on),
                Some((note, memo))
            );
        }
    }

    /// A tree of the consensus depth: the root after each of eleven appends
    /// and the authentication path of the first leaf at the end.
    #[test]
    fn depth_32_tree() {
        let (columns, all) = note_rows();
        let cmus: Vec<[u8; 32]> = all
            .iter()
            .map(|values| {
                Row {
                    columns: &columns,
                    values,
                }
                .array("cmu")
            })
            .collect();
        let tree_row = rows(JSON).pop().unwrap();
        assert_eq!(tree_row[0], "tree");
        let nodes = |v: &Value| -> Vec<[u8; 32]> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|n| {
                    hex::decode(n.as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap()
                })
                .collect()
        };
        let roots = nodes(&tree_row[1]);
        let path = nodes(&tree_row[2]);
        assert_eq!((roots.len(), path.len()), (11, DEPTH));

        let mut tree = Frontier::<DEPTH>::new();
        let mut witness: Option<Witness> = None;
        for (k, root) in roots.iter().enumerate() {
            let leaf = &cmus[k % 4];
            match witness.as_mut() {
                Some(w) => {
                    w.append(leaf).unwrap();
                    tree.append(leaf).unwrap();
                }
                None => witness = Some(tree.append_witnessed(leaf).unwrap()),
            }
            assert_eq!(tree.root(), *root, "root {k}");
        }
        let witness = witness.unwrap();
        let merkle_path = witness.path();
        assert_eq!(merkle_path.position, 0);
        assert_eq!(merkle_path.siblings.to_vec(), path);
        assert_eq!(merkle_path.verify(&cmus[0], &roots[10]), Ok(()));
    }
}
