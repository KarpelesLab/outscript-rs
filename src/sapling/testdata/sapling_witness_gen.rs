// Generator of sapling_witness_reference.json, and reference checks used
// while developing (the `zivks` strings of keys.rs, RedJubjub signatures).
// Not part of the crate: build it as its own package with
//
//   [dependencies]
//   sapling-crypto = "0.9"
//   zcash_primitives = "0.31"
//   incrementalmerkletree = { version = "0.9", features = ["legacy-api"] }
//   bech32 = "0.11"
//   hex = "0.4"
//   redjubjub = "0.9"
//   rand_core = "0.10"
//   blake2b_simd = "1"
//
// `ref2 witness 5 12` prints the steps of sapling_witness_reference.json,
// one JSON object per line.

//! Reference values for the outscript Sapling tests, from the upstream crates.
use std::io::BufRead;

use incrementalmerkletree::frontier::CommitmentTree;
use incrementalmerkletree::witness::IncrementalWitness;
use sapling_crypto::Node;
use zcash_primitives::merkle_tree::{write_commitment_tree, write_incremental_witness};

/// Deterministic byte stream: BLAKE2b(seed || counter). For tests only.
struct DetRng {
    ctr: u64,
    buf: Vec<u8>,
}

impl rand_core::TryRng for DetRng {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for d in dst.iter_mut() {
            if self.buf.is_empty() {
                let h = blake2b_simd::Params::new()
                    .hash_length(64)
                    .to_state()
                    .update(b"ref2 batch randomness")
                    .update(&self.ctr.to_le_bytes())
                    .finalize();
                self.ctr += 1;
                self.buf = h.as_bytes().to_vec();
            }
            *d = self.buf.pop().unwrap();
        }
        Ok(())
    }
}
impl rand_core::TryCryptoRng for DetRng {}

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).expect("hex").try_into().expect("32 bytes")
}

/// `witness <n_before> <n_after>`: a depth-32 Sapling tree of deterministic
/// leaves; the leaf at index n_before is witnessed, then n_after leaves are
/// appended. Prints the leaves' seed scheme, the witness serialization at
/// each step (librustzcash's write_incremental_witness), the path and root.
fn witness(n_before: u64, n_after: u64) {
    let leaf = |i: u64| -> Node {
        // a canonical field element: the integer 1000 + i
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&(1000 + i).to_le_bytes());
        Option::from(Node::from_bytes(b)).expect("canonical")
    };
    let mut tree: CommitmentTree<Node, 32> = CommitmentTree::empty();
    for i in 0..=n_before {
        tree.append(leaf(i)).unwrap();
    }
    let mut w = IncrementalWitness::from_tree(tree.clone()).expect("non-empty");
    let dump = |w: &IncrementalWitness<Node, 32>, tree: &CommitmentTree<Node, 32>| {
        let mut ser = Vec::new();
        write_incremental_witness(w, &mut ser).unwrap();
        let mut tser = Vec::new();
        write_commitment_tree(tree, &mut tser).unwrap();
        let path = w.path().expect("path");
        let siblings: Vec<String> = path
            .path_elems()
            .iter()
            .map(|n| hex::encode(n.to_bytes()))
            .collect();
        println!(
            "{{\"size\": {}, \"witness\": \"{}\", \"tree\": \"{}\", \"root\": \"{}\", \"position\": {}, \"path\": [{}]}}",
            u64::from(w.tip_position()) + 1,
            hex::encode(&ser),
            hex::encode(&tser),
            hex::encode(w.root().to_bytes()),
            u64::from(path.position()),
            siblings
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert_eq!(w.root(), tree.root());
    };
    dump(&w, &tree);
    for i in 0..n_after {
        let l = leaf(n_before + 1 + i);
        tree.append(l).unwrap();
        w.append(l).unwrap();
        dump(&w, &tree);
    }
}

/// `zivks <ivk hex>`: the Bech32 encoding zcashd gives an incoming viewing
/// key (key_io.cpp: the 32-byte ivk, 8-to-5 bits, Bech32 with the network's
/// SAPLING_INCOMING_VIEWING_KEY prefix).
fn zivks(hrp: &str, ivk: &str) {
    let hrp = bech32::Hrp::parse(hrp).expect("hrp");
    let s = bech32::encode::<bech32::Bech32>(hrp, &h32(ivk)).expect("encode");
    println!("{s}");
}

/// `verify-sigs`: lines of `<spend|binding> <vk> <msg hex> <sig>` on stdin,
/// verified one by one and as a batch with the redjubjub crate.
fn verify_sigs() {
    use redjubjub::{batch, Binding, Signature, SpendAuth, VerificationKey, VerificationKeyBytes};
    let mut v = batch::Verifier::new();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.is_empty() {
            continue;
        }
        let vk = h32(p[1]);
        let msg = hex::decode(p[2]).unwrap();
        let sig: [u8; 64] = hex::decode(p[3]).unwrap().try_into().unwrap();
        let ok = match p[0] {
            "spend" => {
                let vkb = VerificationKeyBytes::<SpendAuth>::from(vk);
                let sig = Signature::<SpendAuth>::from(sig);
                v.queue((vkb, sig, &msg));
                VerificationKey::try_from(vkb)
                    .and_then(|k| k.verify(&msg, &sig))
                    .is_ok()
            }
            _ => {
                let vkb = VerificationKeyBytes::<Binding>::from(vk);
                let sig = Signature::<Binding>::from(sig);
                v.queue((vkb, sig, &msg));
                VerificationKey::try_from(vkb)
                    .and_then(|k| k.verify(&msg, &sig))
                    .is_ok()
            }
        };
        println!("{}", if ok { "OK" } else { "FAIL" });
    }
    let ok = v.verify(DetRng { ctr: 0, buf: Vec::new() }).is_ok();
    println!("batch {}", if ok { "OK" } else { "FAIL" });
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("witness") => witness(args[1].parse().unwrap(), args[2].parse().unwrap()),
        Some("zivks") => zivks(&args[1], &args[2]),
        Some("verify-sigs") => verify_sigs(),
        _ => eprintln!("usage: ref2 witness <before> <after> | zivks <hrp> <ivk> | verify-sigs"),
    }
}
