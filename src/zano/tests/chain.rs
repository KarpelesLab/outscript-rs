//! Tests against transactions of Zano's main network, and the tools the
//! fixtures were picked and made with (ignored tests that read a directory
//! of `<txid>.hex` files named by `ZANO_TX_DIR`).

use super::super::*;
use crate::prelude::*;

fn tool_dir() -> Option<std::path::PathBuf> {
    std::env::var("ZANO_TX_DIR").ok().map(Into::into)
}

fn hex_files(dir: &std::path::Path, extension: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) == Some(extension) {
            ids.push(path.file_stem().unwrap().to_str().unwrap().to_string());
        }
    }
    ids.sort();
    ids
}

fn load_tx(dir: &std::path::Path, id: &str) -> Option<Transaction> {
    let text = std::fs::read_to_string(dir.join(format!("{id}.hex"))).ok()?;
    Transaction::from_bytes(&hex::decode(text.trim()).ok()?).ok()
}

fn names(items: &[Variant]) -> String {
    let mut names: Vec<&str> = items.iter().map(Variant::name).collect();
    names.dedup();
    names.join(",")
}

/// Parses every transaction of the directory, checks that it serializes
/// back to the same bytes and hashes to its name, and prints what it holds.
#[test]
#[ignore = "needs ZANO_TX_DIR"]
fn tool_survey() {
    let Some(dir) = tool_dir() else { return };
    let mut failures = 0;
    for id in hex_files(&dir, "hex") {
        let text = std::fs::read_to_string(dir.join(format!("{id}.hex"))).unwrap();
        let bytes = hex::decode(text.trim()).unwrap();
        let tx = match Transaction::from_bytes(&bytes) {
            Ok(tx) => tx,
            Err(e) => {
                println!("{id} PARSE ERROR {e:?} first bytes {:02x?}", &bytes[..8]);
                failures += 1;
                continue;
            }
        };
        let ok = tx.to_bytes() == bytes && hex::encode(tx.prefix_hash()) == id;
        if !ok {
            failures += 1;
        }
        let ado = tx
            .asset_operation()
            .map(|ado| format!(" ado=op{}v{}", ado.operation_type, ado.version))
            .unwrap_or_default();
        println!(
            "{id} v{} hf{} len={} ok={ok} in[{}]={} out[{}]={} extra={} att={} sig={} proofs={}{ado}",
            tx.version,
            tx.hardfork_id,
            bytes.len(),
            tx.vin.len(),
            names(&tx.vin),
            tx.vout.len(),
            names(&tx.vout),
            names(&tx.extra),
            names(&tx.attachment),
            names(&tx.signatures),
            names(&tx.proofs),
        );
    }
    assert_eq!(failures, 0);
}

/// The inputs of a transaction that have a ring: index, amount (zero for a
/// confidential input) and the references of the ring, global indices made
/// absolute.
fn ring_refs(tx: &Transaction) -> Vec<(usize, u64, Vec<String>)> {
    let mut out = Vec::new();
    for (index, input) in tx.vin.iter().enumerate() {
        let (amount, offsets) = match input {
            Variant::ToKey(input) => (input.amount, &input.key_offsets),
            Variant::ZcInput(input) => (0, &input.key_offsets),
            _ => continue,
        };
        let mut absolute = 0u64;
        let refs = offsets
            .iter()
            .map(|offset| match offset {
                Variant::Uint64(offset) => {
                    absolute += offset;
                    absolute.to_string()
                }
                Variant::RefById(r) => format!("ref:{}:{}", hex::encode(r.hash), r.n),
                other => panic!("unexpected ring reference {other:?}"),
            })
            .collect();
        out.push((index, amount, refs));
    }
    out
}

/// Writes `<txid>.inputs` for the transactions of the directory: one line
/// per input with a ring (`index amount ref,ref,...`).
#[test]
#[ignore = "needs ZANO_TX_DIR"]
fn tool_dump_inputs() {
    let Some(dir) = tool_dir() else { return };
    for id in hex_files(&dir, "hex") {
        let target = dir.join(format!("{id}.inputs"));
        if target.exists() {
            continue;
        }
        let Some(tx) = load_tx(&dir, &id) else {
            continue;
        };
        let lines: Vec<String> = ring_refs(&tx)
            .into_iter()
            .map(|(index, amount, refs)| format!("{index} {amount} {}", refs.join(",")))
            .collect();
        std::fs::write(target, lines.join("\n")).unwrap();
    }
}

/// Parses a `.rings` file: per input with a ring, its members (lines
/// `index stealth concealing commitment asset`).
pub(super) fn parse_rings(text: &str) -> Vec<Vec<RingMember>> {
    let mut rings: Vec<(usize, Vec<RingMember>)> = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let index: usize = fields[0].parse().unwrap();
        let member = RingMember {
            global_index: 0,
            stealth_address: super::h32(fields[1]),
            concealing_point: super::h32(fields[2]),
            amount_commitment: super::h32(fields[3]),
            blinded_asset_id: super::h32(fields[4]),
        };
        match rings.last_mut() {
            Some((last, ring)) if *last == index => ring.push(member),
            _ => rings.push((index, vec![member])),
        }
    }
    rings.into_iter().map(|(_, ring)| ring).collect()
}

pub(super) fn ggx_ring(ring: &[RingMember]) -> Vec<ClsagGgxInput> {
    ring.iter()
        .map(|m| ClsagGgxInput {
            stealth_address: m.stealth_address,
            amount_commitment: m.amount_commitment,
            blinded_asset_id: m.blinded_asset_id,
        })
        .collect()
}

/// Turns `<txid>.ringsrc` (lines `index txid n`, made by the fetch script
/// from `.inputs`) into `<txid>.rings`, reading the referenced outputs from
/// the transactions of the directory.
#[test]
#[ignore = "needs ZANO_TX_DIR"]
fn tool_build_rings() {
    let Some(dir) = tool_dir() else { return };
    for id in hex_files(&dir, "ringsrc") {
        let mut lines = Vec::new();
        let source_text = std::fs::read_to_string(dir.join(format!("{id}.ringsrc"))).unwrap();
        for line in source_text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let source = load_tx(&dir, fields[1]).expect("source transaction");
            let n: usize = fields[2].parse().unwrap();
            let zero = [0u8; 32];
            let (stealth, concealing, commitment, asset) = match &source.vout[n] {
                Variant::OutBare(out) => match &*out.target {
                    Variant::ToKeyTarget(target) => (target.key, zero, zero, zero),
                    other => panic!("unexpected target {other:?}"),
                },
                out => {
                    let out = out.zarcanum_out().expect("confidential output");
                    (
                        out.stealth_address,
                        out.concealing_point,
                        out.amount_commitment,
                        out.blinded_asset_id,
                    )
                }
            };
            lines.push(format!(
                "{} {} {} {} {}",
                fields[0],
                hex::encode(stealth),
                hex::encode(concealing),
                hex::encode(commitment),
                hex::encode(asset)
            ));
        }
        std::fs::write(dir.join(format!("{id}.rings")), lines.join("\n")).unwrap();
    }
}

/// Verifies the proof-of-stake blocks of `pos.jsonl` (collected with the
/// stake modifier and difficulty the daemon gave before each).
#[test]
#[ignore = "needs ZANO_TX_DIR"]
fn tool_pos() {
    let Some(dir) = tool_dir() else { return };
    for line in std::fs::read_to_string(dir.join("pos.jsonl"))
        .unwrap()
        .lines()
    {
        let block: serde_json::Value = serde_json::from_str(line).unwrap();
        let id = block["tx"].as_str().unwrap();
        let tx = load_tx(&dir, id).unwrap();
        let Ok(rings) = std::fs::read_to_string(dir.join(format!("{id}.rings"))) else {
            continue;
        };
        let sm = hex::decode(block["details"]["sm"].as_str().unwrap()).unwrap();
        let stake = StakeContext {
            block_id: super::h32(block["id"].as_str().unwrap()),
            timestamp: block["timestamp"].as_u64().unwrap(),
            last_pow_id: sm[..32].try_into().unwrap(),
            last_pos_kernel_id: sm[32..].try_into().unwrap(),
            pos_difficulty: block["details"]["pos_basic_difficulty"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            ring: parse_rings(&rings).remove(0),
        };
        let reward = block["base_reward"].as_u64().unwrap();
        let context = VerifyContext::new(&[&[]])
            .block_reward(reward)
            .stake(&stake);
        println!(
            "{} {id} {:?} | {} {} {} {} {}",
            block["height"],
            tx.verify(&context),
            hex::encode(stake.block_id),
            stake.timestamp,
            hex::encode(&sm),
            stake.pos_difficulty,
            reward
        );
    }
}

/// Prints the asset operation of the transactions named by `ZANO_TXIDS`
/// (comma separated), and what verifying their proofs says.
#[test]
#[ignore = "needs ZANO_TX_DIR"]
fn tool_asset_operations() {
    let Some(dir) = tool_dir() else { return };
    for id in std::env::var("ZANO_TXIDS").unwrap_or_default().split(',') {
        let Some(tx) = load_tx(&dir, id) else {
            continue;
        };
        println!("{id}: proofs {:?}", tx.try_verify_proofs(0));
        let Some(ado) = tx.asset_operation() else {
            continue;
        };
        println!(
            "  op {} version {} asset {:?} target {:?} amount {:?} salt {:?} commitment {:?}",
            ado.operation_type,
            ado.version,
            ado.asset_id.map(hex::encode),
            ado.target_asset_id().map(hex::encode),
            ado.amount,
            ado.asset_id_salt,
            ado.amount_commitment.map(hex::encode),
        );
        if let Some(d) = &ado.descriptor {
            println!(
                "  descriptor v{} ticker {:?} name {:?} meta {:?} max {} supply {} dp {} owner {} eth {:?} hidden {}",
                d.version,
                String::from_utf8_lossy(&d.ticker),
                String::from_utf8_lossy(&d.full_name),
                String::from_utf8_lossy(&d.meta_info),
                d.total_max_supply,
                d.current_supply,
                d.decimal_point,
                hex::encode(d.owner),
                d.owner_eth_pub_key.map(hex::encode),
                d.hidden_supply,
            );
        }
        println!("  asset operation {:?}", tx.verify_asset_operation(None));
    }
}

/// Verifies every transaction of the directory that has a `.rings` file (or
/// no input with a ring), with the block data of `blocks.jsonl`.
#[test]
#[ignore = "needs ZANO_TX_DIR"]
fn tool_verify() {
    let Some(dir) = tool_dir() else { return };
    // txid -> (base reward, total fee)
    let mut blocks = std::collections::HashMap::new();
    let block_lines = std::fs::read_to_string(dir.join("blocks.jsonl")).unwrap();
    for line in block_lines.lines() {
        let block: serde_json::Value = serde_json::from_str(line).unwrap();
        for tx in block["txs"].as_array().unwrap() {
            blocks.insert(
                tx.as_str().unwrap().to_string(),
                (
                    block["base_reward"].as_u64().unwrap(),
                    block["total_fee"].as_u64().unwrap(),
                ),
            );
        }
    }
    let mut counts = std::collections::BTreeMap::new();
    for id in hex_files(&dir, "hex") {
        let Some(tx) = load_tx(&dir, &id) else {
            continue;
        };
        let Some((base_reward, total_fee)) = blocks.get(&id) else {
            continue;
        };
        let rings = match std::fs::read_to_string(dir.join(format!("{id}.rings"))) {
            Ok(text) => parse_rings(&text),
            Err(_) if ring_refs(&tx).is_empty() => Vec::new(),
            Err(_) => {
                // No rings: the proofs alone.
                if tx.version >= 2 && !tx.is_coinbase() {
                    let ado = tx.asset_operation().map(|ado| ado.operation_type);
                    let asset = match tx.verify_asset_operation(None) {
                        Err(VerifyError::MissingAssetDescriptor) => "needs-descriptor".to_string(),
                        other => format!("{other:?}"),
                    };
                    let kind = format!(
                        "v{} proofs-only outs={} proofs={} ado={ado:?} {asset}",
                        tx.version,
                        tx.vout.len().min(5),
                        tx.verify_proofs(),
                    );
                    if !tx.verify_proofs() {
                        println!("{id} {kind}");
                    }
                    *counts.entry(kind).or_insert(0usize) += 1;
                }
                continue;
            }
        };
        let ggx: Vec<Vec<ClsagGgxInput>> = rings.iter().map(|r| ggx_ring(r)).collect();
        let refs: Vec<&[ClsagGgxInput]> = ggx.iter().map(Vec::as_slice).collect();
        let reward = match (tx.is_coinbase(), tx.version) {
            (false, _) => 0,
            (true, ..=1) => base_reward + total_fee,
            (true, _) => *base_reward,
        };
        let context = VerifyContext::new(&refs).block_reward(reward);
        let result = tx.verify(&context);
        let kind = format!(
            "v{} {} outs={} {:?}",
            tx.version,
            if tx.is_pos_coinbase() {
                "pos"
            } else if tx.is_coinbase() {
                "pow"
            } else {
                "tx"
            },
            tx.vout.len().min(5),
            result
        );
        if result.is_err() {
            println!("{id} {kind}");
        }
        *counts.entry(kind).or_insert(0usize) += 1;
    }
    for (kind, count) in counts {
        println!("{count:5} {kind}");
    }
}
