// Generator of sapling_reference.json. Not part of the crate: build it as
// its own package next to a checkout of https://github.com/zcash/sapling-crypto
// (commit 88a7946b4a3066787776e11f0a502654167e022d, version 0.9.0) with:
//
//   [dependencies]
//   sapling-crypto = { path = "../sapling-crypto", default-features = false, features = ["std"] }
//   zcash_note_encryption = { version = "0.5.1", features = ["pre-zip-212"] }
//   zip32 = "0.3"
//   incrementalmerkletree = { version = "0.9", features = ["legacy-api"] }
//   rand = { version = "0.10", features = ["std_rng"] }
//   hex = "0.4"
//
// and redirect its output to sapling_reference.json.

//! Generates cross-check values with the reference implementation
//! (zcash/sapling-crypto): ZIP-212 notes and their encryption, and a
//! depth-32 note commitment tree.

use incrementalmerkletree::Position;
use rand::{rngs::StdRng, SeedableRng};
use sapling_crypto::{
    note_encryption::{sapling_note_encryption, SaplingDomain, Zip212Enforcement},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    zip32::ExtendedSpendingKey,
    CommitmentTree, IncrementalWitness, Node, Rseed,
};
use zcash_note_encryption::Domain;
use zip32::{ChildIndex, Scope};

fn h(b: &[u8]) -> String {
    format!("\"{}\"", hex::encode(b))
}

fn main() {
    let _ = SaplingDomain::new(Zip212Enforcement::On);
    let mut rng = StdRng::seed_from_u64(0);
    let seed: Vec<u8> = (0u8..32).collect();
    let master = ExtendedSpendingKey::master(&seed).unwrap();
    println!("[");
    println!("    [\"Generated with the reference implementation, https://github.com/zcash/sapling-crypto (see refgen in the commit message): ZIP-212 notes of the accounts m/32'/133'/i' of the seed 000102..1f\"],");
    println!("    [\"xsk, address, internal_address, value, rseed, rcv, position, memo_byte, rcm, cv, cmu, nf, epk, c_enc, c_out\"],");
    let mut cmus = vec![];
    for i in 0u32..4 {
        let path = [
            ChildIndex::hardened(32),
            ChildIndex::hardened(133),
            ChildIndex::hardened(i),
        ];
        let xsk = ExtendedSpendingKey::from_path(&master, &path).unwrap();
        let dfvk = xsk.to_diversifiable_full_viewing_key();
        let (_, address) = dfvk.default_address();
        let (_, internal) = dfvk.change_address();
        let value = 1_000_000u64 * (i as u64 + 1) + i as u64;
        let rseed_bytes = [0x10 + i as u8; 32];
        let mut rcv_bytes = [0u8; 32];
        rcv_bytes[0] = 3 + i as u8;
        rcv_bytes[17] = 0x5a;
        let rcv = ValueCommitTrapdoor::from_bytes(rcv_bytes).unwrap();
        let position = 77u64 * (i as u64) + (1u64 << (8 * i));
        let memo_byte = 0xa0 + i as u8;
        let note = address.create_note(NoteValue::from_raw(value), Rseed::AfterZip212(rseed_bytes));
        let cv = ValueCommitment::derive(NoteValue::from_raw(value), rcv);
        let cmu = note.cmu();
        let nf = note.nf(&dfvk.to_nk(Scope::External), position);
        let ovk = dfvk.to_ovk(Scope::External);
        let enc = sapling_note_encryption(Some(ovk), note.clone(), [memo_byte; 512], &mut rng);
        let epk = SaplingDomain::epk_bytes(enc.epk());
        let c_enc = enc.encrypt_note_plaintext();
        let c_out = enc.encrypt_outgoing_plaintext(&cv, &cmu, &mut rng);
        cmus.push(cmu);
        println!(
            "    [{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}],",
            h(&xsk.to_bytes()),
            h(&address.to_bytes()),
            h(&internal.to_bytes()),
            value,
            h(&rseed_bytes),
            h(&rcv_bytes),
            position,
            memo_byte,
            h(&note.rcm().to_bytes()),
            h(&cv.to_bytes()),
            h(&cmu.to_bytes()),
            h(&nf.0),
            h(epk.as_ref()),
            h(c_enc.as_ref()),
            h(&c_out),
        );
    }
    // a depth-32 tree of these commitments, repeated: the root after each
    // append and the path of the first leaf at the end
    let mut tree = CommitmentTree::empty();
    let mut witness: Option<IncrementalWitness> = None;
    let mut roots = vec![];
    for k in 0..11 {
        let node = Node::from_cmu(&cmus[k % 4]);
        tree.append(node).unwrap();
        if let Some(w) = witness.as_mut() {
            w.append(node).unwrap();
        } else {
            witness = Some(IncrementalWitness::from_tree(tree.clone()).unwrap());
        }
        roots.push(h(&tree.root().to_bytes()));
    }
    let w = witness.unwrap();
    let path = w.path().unwrap();
    assert_eq!(path.position(), Position::from(0));
    let elems: Vec<String> = path.path_elems().iter().map(|n| h(&n.to_bytes())).collect();
    println!("    [\"tree\", [{}], [{}]]", roots.join(", "), elems.join(", "));
    println!("]");
}
