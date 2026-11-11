//! Tests against transactions of Zano's main network, and the tools the
//! fixtures were picked and made with (ignored tests that read a directory
//! of `<txid>.hex` files named by `ZANO_TX_DIR`).
//!
//! The directory is what `testdata/zano_fetch.py` dumps from a daemon (see
//! its header for the files): this module has no network client.
//! `tool_chain` checks everything in it, `tool_build_transfer` builds and
//! signs a transfer from it.

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
            // The fetch script adds the global index; older files lack it.
            global_index: fields.get(5).map_or(0, |index| index.parse().unwrap()),
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

/// The compact form of a `.rings` file the fixtures use: for each member,
/// the index of its input, then its stealth address, concealing point,
/// amount commitment and blinded asset id.
fn rings_to_binary(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        out.push(fields[0].parse::<u8>().unwrap());
        for field in &fields[1..5] {
            out.extend_from_slice(&super::h32(field));
        }
    }
    out
}

/// Reads the compact rings of a fixture: per input with a ring, its
/// members.
pub(super) fn rings_from_binary(bytes: &[u8]) -> Vec<Vec<RingMember>> {
    let mut rings: Vec<(u8, Vec<RingMember>)> = Vec::new();
    for record in bytes.as_chunks::<129>().0 {
        let key = |n: usize| -> [u8; 32] { record[1 + 32 * n..33 + 32 * n].try_into().unwrap() };
        let member = RingMember {
            global_index: 0,
            stealth_address: key(0),
            concealing_point: key(1),
            amount_commitment: key(2),
            blinded_asset_id: key(3),
        };
        match rings.last_mut() {
            Some((last, ring)) if *last == record[0] => ring.push(member),
            _ => rings.push((record[0], vec![member])),
        }
    }
    rings.into_iter().map(|(_, ring)| ring).collect()
}

/// Copies the transactions named by `ZANO_EXPORT` (`name:txid,...`) and
/// their rings into the directory `ZANO_FIXTURE_DIR`, and prints what the
/// chain says of each.
#[test]
#[ignore = "needs ZANO_TX_DIR"]
fn tool_export_fixtures() {
    let Some(dir) = tool_dir() else { return };
    let target = std::path::PathBuf::from(std::env::var("ZANO_FIXTURE_DIR").unwrap());
    std::fs::create_dir_all(&target).unwrap();
    let block_lines = std::fs::read_to_string(dir.join("blocks.jsonl")).unwrap();
    let blocks: Vec<serde_json::Value> = block_lines
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for entry in std::env::var("ZANO_EXPORT").unwrap().split(',') {
        let (name, prefix) = entry.split_once(':').unwrap();
        let id = hex_files(&dir, "hex")
            .into_iter()
            .find(|id| id.starts_with(prefix))
            .expect("transaction");
        let text = std::fs::read_to_string(dir.join(format!("{id}.hex"))).unwrap();
        std::fs::write(
            target.join(format!("{name}.bin")),
            hex::decode(text.trim()).unwrap(),
        )
        .unwrap();
        let rings = std::fs::read_to_string(dir.join(format!("{id}.rings")));
        if let Ok(rings) = &rings {
            std::fs::write(target.join(format!("{name}.rings")), rings_to_binary(rings)).unwrap();
        }
        let block = blocks.iter().find(|block| {
            block["txs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tx| tx.as_str() == Some(&id))
        });
        match block {
            Some(block) => println!(
                "FIXTURE {name} {id} height={} block={} base_reward={} total_fee={} rings={}",
                block["height"],
                block["id"].as_str().unwrap(),
                block["base_reward"],
                block["total_fee"],
                rings.is_ok(),
            ),
            None => println!("FIXTURE {name} {id} rings={}", rings.is_ok()),
        }
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
        let context = VerifyContext::new(&[]).block_reward(reward).stake(&stake);
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

/// One block of the `blocks.jsonl` the fetch script writes.
struct DumpBlock {
    height: u64,
    id: [u8; 32],
    pos: bool,
    timestamp: u64,
    difficulty: u128,
    total_fee: u64,
    /// The cumulative size the reward depends on.
    size: u64,
    /// The median size of the 400 blocks before (fetched for blocks over
    /// the full reward zone only; zero otherwise).
    median: u64,
    blob: Vec<u8>,
    /// The ids of the transactions, the first one of the block first.
    txs: Vec<String>,
}

fn load_blocks(dir: &std::path::Path) -> Vec<DumpBlock> {
    let Ok(text) = std::fs::read_to_string(dir.join("blocks.jsonl")) else {
        return Vec::new();
    };
    let mut blocks: Vec<DumpBlock> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let block: serde_json::Value = serde_json::from_str(line).unwrap();
            // Dumps of the earlier tools have no block blobs.
            let blob = hex::decode(block["blob"].as_str()?).unwrap();
            Some(DumpBlock {
                height: block["height"].as_u64().unwrap(),
                id: super::h32(block["id"].as_str().unwrap()),
                pos: block["type"].as_u64().unwrap() == 0,
                timestamp: block["timestamp"].as_u64().unwrap(),
                difficulty: block["difficulty"].as_str().unwrap().parse().unwrap(),
                total_fee: block["total_fee"].as_u64().unwrap(),
                size: block["size"].as_u64().unwrap(),
                median: block["median"].as_u64().unwrap_or(0),
                blob,
                txs: block["txs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| id.as_str().unwrap().to_string())
                    .collect(),
            })
        })
        .collect();
    blocks.sort_by_key(|block| block.height);
    blocks.dedup_by_key(|block| block.height);
    blocks
}

/// The asset descriptors of `assets.jsonl` (what `get_assets_list` gives:
/// the descriptors as they are now), by asset id.
fn load_assets(dir: &std::path::Path) -> std::collections::HashMap<[u8; 32], AssetDescriptorBase> {
    let mut assets = std::collections::HashMap::new();
    let Ok(text) = std::fs::read_to_string(dir.join("assets.jsonl")) else {
        return assets;
    };
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let asset: serde_json::Value = serde_json::from_str(line).unwrap();
        let text = |name: &str| asset[name].as_str().unwrap_or_default().as_bytes().to_vec();
        let eth = asset["owner_eth_pub_key"].as_str().unwrap_or_default();
        let descriptor = AssetDescriptorBase {
            total_max_supply: asset["total_max_supply"].as_u64().unwrap(),
            current_supply: asset["current_supply"].as_u64().unwrap(),
            decimal_point: asset["decimal_point"].as_u64().unwrap() as u8,
            ticker: text("ticker"),
            full_name: text("full_name"),
            meta_info: text("meta_info"),
            owner: super::h32(asset["owner"].as_str().unwrap()),
            hidden_supply: asset["hidden_supply"].as_bool().unwrap_or(false),
            version: u8::from(!eth.is_empty()),
            owner_eth_pub_key: (!eth.is_empty())
                .then(|| hex::decode(eth).unwrap().try_into().unwrap()),
            etc: Vec::new(),
        };
        assets.insert(super::h32(asset["asset_id"].as_str().unwrap()), descriptor);
    }
    assets
}

/// What `tool_chain` counts.
#[derive(Default)]
struct Report {
    counts: std::collections::BTreeMap<String, usize>,
    failures: Vec<String>,
}

impl Report {
    fn count(&mut self, what: impl Into<String>) {
        *self.counts.entry(what.into()).or_insert(0) += 1;
    }

    fn fail(&mut self, what: String) {
        println!("FAILURE {what}");
        self.failures.push(what);
    }
}

/// The part of the Zarcanum stake proof that does not need the stake
/// modifier: the range proof of `E` and the ring signature over the block
/// id. (The three Schnorr proofs take the kernel hash, which only a daemon
/// that kept the kernel hash of the proof-of-stake block before can give.)
pub(super) fn zarcanum_without_kernel(
    tx: &Transaction,
    block_id: &[u8; 32],
    ring: &[RingMember],
) -> bool {
    let (Some(Variant::ZcInput(input)), Some(Variant::ZarcanumSig(sig))) =
        (tx.vin.get(1), tx.signatures.first())
    else {
        return false;
    };
    let native_1div8 =
        super::super::crypto::mul_vartime(&scalar_1div8(), &generator_h()).compress();
    ring.len() == input.key_offsets.len()
        && verify_bppe(&sig.e_range_proof, &[sig.e])
        && verify_clsag_ggxxg(
            block_id,
            ring,
            &sig.pseudo_out_amount_commitment,
            &native_1div8,
            &sig.c_point,
            &input.key_image,
            &sig.clsag_ggxxg,
        )
}

/// The stake modifier, followed from the first block on: it is known for a
/// block only if every block before it is in the dump.
struct ModifierChain {
    next_height: u64,
    last_pow_id: Option<[u8; 32]>,
    last_pos_kernel_id: [u8; 32],
}

/// Checks everything of the dump of `zano_fetch.py`: every block parses,
/// serializes back to the same bytes and hashes to the id the daemon gives;
/// every transaction does, and verifies with the rings the daemon gave —
/// the first transactions of the blocks with the reward the size of the
/// block allows, the stakes with the block id and, where the dump starts at
/// the first block, the stake modifier and the difficulty.
///
/// Prints what it saw (versions, kinds, the tags of every container) and
/// fails if anything did not check.
#[test]
#[ignore = "needs ZANO_TX_DIR"]
fn tool_chain() {
    let Some(dir) = tool_dir() else { return };
    let blocks = load_blocks(&dir);
    let assets = load_assets(&dir);
    let mut report = Report::default();
    let mut tags = std::collections::BTreeMap::new();
    let mut modifier = Some(ModifierChain {
        next_height: 0,
        last_pow_id: None,
        last_pos_kernel_id: POS_STARTER_KERNEL_HASH,
    });
    // A wallet nobody paid: it must find nothing.
    let stranger = Wallet::from_spend_secret(&[3u8; 32], 0).unwrap();
    let (mut hints, mut hint_matches, mut hinted_outs) = (0usize, 0usize, 0usize);
    let verbose = std::env::var("ZANO_VERBOSE").is_ok();

    for dumped in &blocks {
        let at = format!("block {}", dumped.height);
        let block = match Block::from_bytes(&dumped.blob) {
            Ok(block) => block,
            Err(e) => {
                report.fail(format!("{at}: does not parse: {e:?}"));
                modifier = None;
                continue;
            }
        };
        report.count("blocks");
        report.count(format!(
            "blocks: major version {} {}",
            block.header.major_version,
            if block.is_pos() { "PoS" } else { "PoW" }
        ));
        if block.to_bytes() != dumped.blob {
            report.fail(format!("{at}: serializes to other bytes"));
        }
        if block.id() != dumped.id {
            report.fail(format!("{at}: id {}", hex::encode(block.id())));
        }
        if block.is_pos() != dumped.pos
            || block.height() != Some(dumped.height)
            || block.header.timestamp != dumped.timestamp
            || block.tx_hashes.len() + 1 != dumped.txs.len()
        {
            report.fail(format!("{at}: kind, height, timestamp or transactions"));
        }
        if block.header.flags & !BLOCK_FLAG_POS != 0 {
            report.count(format!("blocks: flags {:#x}", block.header.flags));
        }
        let (version, hardfork_id) = mainnet_tx_version(dumped.height);
        let miner_version = block.miner_tx.version;
        // The first transactions of the first blocks have version 0 or 1.
        if miner_version != version && !(version == 1 && miner_version == 0) {
            report.fail(format!(
                "{at}: first transaction of version {miner_version}"
            ));
        }
        if version >= TRANSACTION_VERSION_POST_HF5 && block.miner_tx.hardfork_id != hardfork_id {
            // Builds below 600 know hard fork 6 without hard fork 7, and
            // follow a chain of their own above block 3 833 000.
            if (block.miner_tx.hardfork_id, hardfork_id) == (HARDFORK_06, HARDFORK_07) {
                report.count("blocks of the chain of hard fork 6 without 7 (builds below 600)");
            } else {
                report.fail(format!("{at}: hard fork id {}", block.miner_tx.hardfork_id));
            }
        }

        let reward = block_reward(dumped.height, dumped.median, dumped.size);
        if dumped.size > BLOCK_GRANTED_FULL_REWARD_ZONE {
            report.count("blocks over the full reward zone");
            println!(
                "{at}: size {} median {} reward {reward:?}",
                dumped.size, dumped.median
            );
        }
        let Some(reward) = reward else {
            report.fail(format!("{at}: too large for a reward"));
            continue;
        };
        // The fees go to the first transaction before hard fork 4 only.
        let created = if miner_version <= TRANSACTION_VERSION_PRE_HF4 {
            reward + dumped.total_fee
        } else {
            reward
        };

        // The stake modifier of this block, if the chain is known up to it.
        modifier = modifier.filter(|m| m.next_height == dumped.height);
        let known_modifier = modifier
            .as_ref()
            .and_then(|m| Some((m.last_pow_id?, m.last_pos_kernel_id)));
        if let (true, Some((pow, pos)), true) = (dumped.pos, known_modifier, verbose) {
            println!(
                "MODIFIER {} {}{}",
                dumped.height,
                hex::encode(pow),
                hex::encode(pos)
            );
        }

        for (n, id) in dumped.txs.iter().enumerate() {
            let at = format!("block {} tx {id}", dumped.height);
            let Ok(text) = std::fs::read_to_string(dir.join(format!("{id}.hex"))) else {
                report.count("transactions missing from the dump");
                continue;
            };
            let bytes = hex::decode(text.trim()).unwrap();
            let tx = match Transaction::from_bytes(&bytes) {
                Ok(tx) => tx,
                Err(e) => {
                    report.fail(format!("{at}: does not parse: {e:?}"));
                    continue;
                }
            };
            report.count("transactions");
            if tx.to_bytes() != bytes {
                report.fail(format!("{at}: serializes to other bytes"));
            }
            if hex::encode(tx.prefix_hash()) != *id {
                report.fail(format!("{at}: id {}", hex::encode(tx.prefix_hash())));
            }
            match Transaction::from_bytes_for_scan(&bytes) {
                Ok(scanned)
                    if scanned.prefix_bytes() == tx.prefix_bytes()
                        && scanned.attachment == tx.attachment => {}
                _ => report.fail(format!("{at}: the scanning parser differs")),
            }
            if n == 0 && tx != block.miner_tx {
                report.fail(format!("{at}: not the first transaction of its block"));
            }
            if n > 0 && tx.version != version {
                report.count(format!(
                    "transactions of version {} where {version} is built",
                    tx.version
                ));
            }
            for (container, items) in [
                ("vin", &tx.vin),
                ("vout", &tx.vout),
                ("extra", &tx.extra),
                ("attachment", &tx.attachment),
                ("signatures", &tx.signatures),
                ("proofs", &tx.proofs),
            ] {
                for item in items {
                    let key = format!("v{} {container} {} {}", tx.version, item.tag(), item.name());
                    *tags.entry(key).or_insert(0usize) += 1;
                    let inner = match item {
                        Variant::ToKey(input) => &input.etc_details,
                        Variant::ZcInput(input) => &input.etc_details,
                        _ => continue,
                    };
                    for detail in inner {
                        let key = format!(
                            "v{} etc_details {} {}",
                            tx.version,
                            detail.tag(),
                            detail.name()
                        );
                        *tags.entry(key).or_insert(0usize) += 1;
                    }
                }
            }
            for out in &tx.vout {
                if let Variant::OutBare(out) = out
                    && !matches!(&*out.target, Variant::ToKeyTarget(_))
                {
                    let key = format!("v{} target {}", tx.version, out.target.name());
                    *tags.entry(key).or_insert(0usize) += 1;
                }
            }

            // Scanning: a wallet nobody paid finds nothing, and the hints
            // of the transaction match its derivation once in 65536.
            if let Some(key) = tx.tx_pub_key()
                && let Ok(derivation) = stranger.key_derivation(&key)
            {
                let mine = derivation_hint(&derivation).to_le_bytes();
                let mut own = 0;
                for entry in &tx.extra {
                    if let Variant::DerivationHint(hint) = entry {
                        own += 1;
                        hint_matches += usize::from(hint.as_slice() == mine.as_slice());
                    }
                }
                hints += own;
                if own > 0 {
                    hinted_outs += tx.vout.len();
                    if own > tx.vout.len() {
                        report.count("transactions with more hints than outputs");
                    }
                }
                match stranger.scan_tx(&tx) {
                    Ok(found) if !found.found() => {}
                    other => report.fail(format!("{at}: a stranger scans {other:?}")),
                }
            }

            // Verification.
            let ring_inputs = ring_refs(&tx).len();
            let rings = match std::fs::read_to_string(dir.join(format!("{id}.rings"))) {
                Ok(text) => parse_rings(&text),
                Err(_) => Vec::new(),
            };
            if !tx.is_coinbase() && tx.signatures.is_empty() {
                // Below its checkpoints a daemon drops signatures,
                // attachments and proofs.
                report.count(format!(
                    "pruned by the daemon (no signatures): v{}, not verified",
                    tx.version
                ));
                continue;
            }
            if rings.len() != ring_inputs {
                report.count("transactions without their rings (not verified)");
                continue;
            }
            let kind = if tx.is_pos_coinbase() {
                "PoS coinbase"
            } else if tx.is_coinbase() {
                "PoW coinbase"
            } else if tx.asset_operation().is_some() {
                "asset operation"
            } else {
                "transfer"
            };
            let zarcanum_stake = tx.is_pos_coinbase() && tx.version > TRANSACTION_VERSION_PRE_HF4;
            let ggx: Vec<Vec<ClsagGgxInput>> = rings
                .iter()
                .skip(usize::from(zarcanum_stake))
                .map(|ring| ggx_ring(ring))
                .collect();
            let refs: Vec<&[ClsagGgxInput]> = ggx.iter().map(Vec::as_slice).collect();
            let mut context = VerifyContext::new(&refs);
            if tx.is_coinbase() {
                context = context.block_reward(created);
            }
            let previous = tx
                .asset_operation()
                .and_then(|ado| assets.get(&ado.target_asset_id()?));
            if let Some(previous) = previous {
                context = context.asset_descriptor(previous);
            }
            let mut how = "";
            let result = if zarcanum_stake {
                // Without the kernel hash of the proof-of-stake block
                // before: everything but the three Schnorr proofs.
                how = " (without the kernel)";
                match tx.try_verify_proofs(created) {
                    Ok(()) if zarcanum_without_kernel(&tx, &dumped.id, &rings[0]) => Ok(()),
                    Ok(()) => Err(VerifyError::Stake),
                    Err(e) => Err(e),
                }
            } else if tx.is_pos_coinbase() {
                let (last_pow_id, last_pos_kernel_id, difficulty) = match known_modifier {
                    Some((pow, pos)) => {
                        how = " (with the kernel)";
                        (pow, pos, dumped.difficulty)
                    }
                    None => {
                        how = " (without the kernel)";
                        ([0; 32], [0; 32], 0)
                    }
                };
                let stake = StakeContext {
                    block_id: dumped.id,
                    timestamp: dumped.timestamp,
                    last_pow_id,
                    last_pos_kernel_id,
                    pos_difficulty: difficulty,
                    ring: Vec::new(),
                };
                tx.verify(&context.stake(&stake))
            } else {
                tx.verify(&context)
            };
            let operation = tx
                .asset_operation()
                .map(|ado| format!(" op {} v{}", ado.operation_type, ado.version))
                .unwrap_or_default();
            match result {
                Ok(()) => report.count(format!("verified: v{} {kind}{operation}{how}", tx.version)),
                // The daemon has the descriptor of an asset as it is now:
                // an operation of hard fork 4 needs the supply before it,
                // and any the owner of its time.
                Err(e @ (VerifyError::AssetOperation | VerifyError::AssetOwnership))
                    if tx.try_verify_proofs(0).is_ok()
                        && refs
                            .iter()
                            .enumerate()
                            .all(|(index, ring)| tx.verify_input(index, ring)) =>
                {
                    report.count(format!(
                        "verified but the asset operation, which needs the descriptor of its \
                         time: v{}{operation} {e:?}",
                        tx.version
                    ));
                }
                Err(VerifyError::MissingAssetDescriptor) => {
                    report.count(format!(
                        "verified but the asset operation, whose asset the daemon does not \
                         list: v{}{operation}",
                        tx.version
                    ));
                }
                Err(e) => report.fail(format!(
                    "{at}: v{} {kind}{operation}{how}: {e:?}",
                    tx.version
                )),
            }
            let largest = rings.iter().map(Vec::len).max().unwrap_or(0);
            if largest > 0 {
                report.count(format!(
                    "ring size (largest of the transaction) {largest:3}"
                ));
            }
            if rings.len() > 4 {
                report.count("transactions with more than four ring inputs");
            }
        }

        // The stake modifier of the next block.
        if let Some(chain) = &mut modifier {
            chain.next_height += 1;
            if !dumped.pos {
                chain.last_pow_id = Some(dumped.id);
            } else if let (Some(last_pow_id), Some(key_image)) =
                (chain.last_pow_id, block.stake_key_image())
            {
                let stake = StakeContext {
                    timestamp: dumped.timestamp,
                    last_pow_id,
                    last_pos_kernel_id: chain.last_pos_kernel_id,
                    ..Default::default()
                };
                chain.last_pos_kernel_id = stake.kernel_hash(key_image);
            } else {
                modifier = None;
            }
        }
    }

    for (tag, count) in &tags {
        println!("TAG {count:6} {tag}");
    }
    for (what, count) in &report.counts {
        println!("{count:6} {what}");
    }
    println!(
        "{hints} derivation hints over {hinted_outs} outputs, {hint_matches} of them a stranger's \
         (one in 65536 expected: {:.2})",
        hints as f64 / 65536.0
    );
    println!("{} failures", report.failures.len());
    for failure in &report.failures {
        println!("  {failure}");
    }
    assert!(report.failures.is_empty());
}

/// Copies the blocks named by `ZANO_EXPORT_BLOCKS` (`name:height,...`) into
/// the directory `ZANO_FIXTURE_DIR`, and prints what the tests need of
/// each.
#[test]
#[ignore = "needs ZANO_TX_DIR"]
fn tool_export_blocks() {
    let Some(dir) = tool_dir() else { return };
    let (Ok(target), Ok(export)) = (
        std::env::var("ZANO_FIXTURE_DIR"),
        std::env::var("ZANO_EXPORT_BLOCKS"),
    ) else {
        return;
    };
    let target = std::path::PathBuf::from(target);
    std::fs::create_dir_all(&target).unwrap();
    let blocks = load_blocks(&dir);
    for entry in export.split(',') {
        let (name, height) = entry.split_once(':').unwrap();
        let height: u64 = height.parse().unwrap();
        let block = blocks.iter().find(|b| b.height == height).expect("block");
        std::fs::write(target.join(format!("{name}.bin")), &block.blob).unwrap();
        println!(
            "BLOCK {name} height={height} id={} pos={} timestamp={} difficulty={} size={} \
             median={} total_fee={} txs={}",
            hex::encode(block.id),
            block.pos,
            block.timestamp,
            block.difficulty,
            block.size,
            block.median,
            block.total_fee,
            block.txs.len(),
        );
    }
}

/// Bytes from the system's random source, for the tools that sign.
fn system_random(buf: &mut [u8]) {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(buf))
        .expect("the system's random source");
}

/// An output of the dump that belongs to the wallet.
pub(super) struct Owned {
    pub(super) tx_id: String,
    pub(super) tx_pub_key: [u8; 32],
    pub(super) out: ReceivedOutput,
    pub(super) member: RingMember,
    pub(super) key_image: [u8; 32],
}

/// Scans one transaction for the confidential outputs of `wallet`, with
/// their key images. `global_indices` has the global index of each output
/// of the transaction.
pub(super) fn owned_outputs(
    wallet: &Wallet,
    tx_id: &str,
    tx: &Transaction,
    global_indices: &[u64],
) -> Vec<Owned> {
    let Ok(found) = wallet.scan_tx(tx) else {
        return Vec::new();
    };
    let Some(tx_pub_key) = found.tx_pub_key else {
        return Vec::new();
    };
    let derivation = wallet.key_derivation(&tx_pub_key).unwrap();
    let mut owned = Vec::new();
    for out in found.outputs {
        let index = out.output_index as usize;
        let Some(on_chain) = tx.vout[index].zarcanum_out() else {
            continue;
        };
        let Some(global_index) = global_indices.get(index) else {
            continue;
        };
        let secret = crate::cryptonote::derive_secret_key(
            &derivation,
            out.output_index,
            wallet.spend_secret_key().expect("a spend key"),
        )
        .unwrap();
        owned.push(Owned {
            tx_id: tx_id.to_string(),
            tx_pub_key,
            key_image: crate::cryptonote::generate_key_image(&out.stealth_address, &secret)
                .unwrap(),
            member: RingMember {
                global_index: *global_index,
                stealth_address: on_chain.stealth_address,
                concealing_point: on_chain.concealing_point,
                amount_commitment: on_chain.amount_commitment,
                blinded_asset_id: on_chain.blinded_asset_id,
            },
            out,
        });
    }
    owned
}

/// What a transfer is made from: where the money goes and what the chain
/// is at.
pub(super) struct TransferPlan {
    pub(super) destination: Address,
    pub(super) amount: u64,
    pub(super) fee: u64,
    /// The version of the transaction and the hard fork id it states.
    pub(super) version: u64,
    pub(super) hardfork_id: u8,
    /// The size of the rings, the real output included.
    pub(super) ring_size: usize,
}

/// Builds and signs the transfer `plan` describes, of the native coin, from
/// `owned` outputs, the change going back to the wallet, with rings made of
/// the `decoys` the daemon gave; verifies it, and gives it back.
pub(super) fn transfer_from_daemon_data(
    wallet: &Wallet,
    rng: &mut dyn FnMut(&mut [u8]),
    owned: &[Owned],
    decoys: &[RandomOut],
    plan: &TransferPlan,
) -> Result<Transaction, String> {
    let needed = plan.amount.checked_add(plan.fee).ok_or("amount overflow")?;
    let per_ring = plan.ring_size.saturating_sub(1);
    // The largest outputs first, as few inputs as possible.
    let mut candidates: Vec<&Owned> = owned.iter().filter(|o| o.out.is_native).collect();
    candidates.sort_by_key(|o| core::cmp::Reverse(o.out.amount));
    let mut spent = Vec::new();
    let mut total = 0u64;
    for candidate in candidates {
        if total >= needed {
            break;
        }
        total += candidate.out.amount;
        spent.push(candidate);
    }
    if total < needed {
        return Err(format!("{total} available, {needed} needed"));
    }

    // Decoys the daemon allows, none of them ours, each used once.
    let mut pool: Vec<&RandomOut> = decoys
        .iter()
        .filter(|decoy| decoy.is_allowed())
        .filter(|decoy| {
            owned
                .iter()
                .all(|o| o.member.global_index != decoy.member.global_index)
        })
        .collect();
    pool.sort_by_key(|decoy| decoy.member.global_index);
    pool.dedup_by_key(|decoy| decoy.member.global_index);
    // Shuffled, so that which decoys go together says nothing.
    for i in (1..pool.len()).rev() {
        let mut bytes = [0u8; 8];
        rng(&mut bytes);
        pool.swap(i, (u64::from_le_bytes(bytes) % (i as u64 + 1)) as usize);
    }
    if pool.len() < spent.len() * per_ring {
        return Err(format!(
            "{} decoys, {} needed",
            pool.len(),
            spent.len() * per_ring
        ));
    }

    let mut by_index = std::collections::HashMap::new();
    let mut inputs = Vec::new();
    for (n, source) in spent.iter().enumerate() {
        let mut ring = vec![source.member];
        ring.extend(
            pool[n * per_ring..(n + 1) * per_ring]
                .iter()
                .map(|decoy| decoy.member),
        );
        for member in &ring {
            by_index.insert(member.global_index, *member);
        }
        inputs.push(TransferInput {
            amount: source.out.amount,
            asset_id: source.out.asset_id,
            amount_blinding_mask: source.out.amount_blinding_mask,
            asset_id_blinding_mask: source.out.asset_id_blinding_mask,
            real_out_tx_key: source.tx_pub_key,
            real_out_index: source.out.output_index,
            real_global_index: source.member.global_index,
            ring,
        });
    }
    let mut dests = vec![TransferDest {
        address: plan.destination,
        asset_id: NATIVE_COIN_ASSET_ID,
        amount: plan.amount,
    }];
    if total > needed {
        dests.push(TransferDest {
            address: wallet.address(),
            asset_id: NATIVE_COIN_ASSET_ID,
            amount: total - needed,
        });
    }
    let built = wallet
        .build_transfer(
            rng,
            &inputs,
            &dests,
            plan.version,
            u64::from(plan.hardfork_id),
        )
        .map_err(|e| format!("building: {e:?}"))?;

    // What a daemon would check of it, as far as this module can.
    let tx = Transaction::from_bytes(&built.tx.to_bytes()).map_err(|e| format!("{e:?}"))?;
    let rings: Vec<Vec<ClsagGgxInput>> = ring_refs(&tx)
        .into_iter()
        .map(|(_, _, refs)| {
            let ring: Vec<RingMember> = refs
                .iter()
                .map(|index| by_index[&index.parse::<u64>().unwrap()])
                .collect();
            ggx_ring(&ring)
        })
        .collect();
    let refs: Vec<&[ClsagGgxInput]> = rings.iter().map(Vec::as_slice).collect();
    tx.verify(&VerifyContext::new(&refs))
        .map_err(|e| format!("the transaction does not verify: {e:?}"))?;
    if tx.fee() != Some(plan.fee) {
        return Err(format!("fee {:?}", tx.fee()));
    }
    let spent_images: Vec<[u8; 32]> = spent.iter().map(|o| o.key_image).collect();
    if !tx.vin.iter().all(|input| {
        input
            .key_image()
            .is_some_and(|ki| spent_images.contains(ki))
    }) {
        return Err("key images differ from the scanned ones".into());
    }
    Ok(tx)
}

/// Everything short of broadcasting: scans the dump for the outputs of the
/// wallet whose secret spend key is in `ZANO_SPEND_SECRET` (hex), leaves
/// out those a transaction of the dump spends, picks decoys among the
/// `random_outs.json` of the dump (`zano_fetch.py DIR decoys 200`), builds
/// and signs the transfer of `ZANO_AMOUNT` atomic units to `ZANO_DEST`
/// with the fee `ZANO_FEE` (0.01 coin if unset), verifies it, and prints it
/// in hex for `sendrawtransaction`. Nothing is sent.
///
/// The transaction states the hard fork of the height of `info.json` — 7
/// on the main network. A daemon of a build below 600 knows hard fork 6
/// only and follows another chain above block 3 833 000, whose
/// transactions state 6: `ZANO_HARDFORK_ID=6` builds for it.
///
/// The dump must hold the transactions that paid the wallet (their blocks,
/// fetched with `zano_fetch.py DIR blocks START:COUNT`, or the
/// transactions themselves with `zano_fetch.py DIR tx TXID`), and should
/// hold every later block if the wallet may have spent since: an output
/// spent in a block the dump lacks would be spent again, and the daemon
/// would refuse the transaction.
#[test]
#[ignore = "needs ZANO_TX_DIR, ZANO_SPEND_SECRET, ZANO_DEST and ZANO_AMOUNT"]
fn tool_build_transfer() {
    let Some(dir) = tool_dir() else { return };
    let (Ok(secret), Ok(destination), Ok(amount)) = (
        std::env::var("ZANO_SPEND_SECRET"),
        std::env::var("ZANO_DEST"),
        std::env::var("ZANO_AMOUNT"),
    ) else {
        return;
    };
    let wallet = Wallet::from_spend_secret(&super::h32(secret.trim()), 0).unwrap();
    let info = std::fs::read_to_string(dir.join("info.json")).expect("info.json");
    let info: serde_json::Value = serde_json::from_str(&info).unwrap();
    let (version, mut hardfork_id) = mainnet_tx_version(info["height"].as_u64().unwrap());
    if let Ok(id) = std::env::var("ZANO_HARDFORK_ID") {
        hardfork_id = id.trim().parse().expect("ZANO_HARDFORK_ID");
    }
    println!("version {version}, hard fork id {hardfork_id}");
    let plan = TransferPlan {
        destination: destination.trim().parse().expect("ZANO_DEST"),
        amount: amount.trim().parse().expect("ZANO_AMOUNT"),
        fee: std::env::var("ZANO_FEE")
            .map(|fee| fee.trim().parse().expect("ZANO_FEE"))
            .unwrap_or(10_000_000_000),
        version,
        hardfork_id,
        ring_size: 16,
    };
    println!("wallet {}", wallet.address());

    let decoys = parse_random_outs_reply(&std::fs::read(dir.join("random_outs.json")).unwrap())
        .expect("random_outs.json");
    let decoys: Vec<RandomOut> = decoys
        .into_iter()
        .filter(|outs| outs.amount == 0)
        .flat_map(|outs| outs.outs)
        .collect();

    let mut owned = Vec::new();
    let mut spent_images = std::collections::HashSet::new();
    for id in hex_files(&dir, "hex") {
        let Some(tx) = load_tx(&dir, &id) else {
            continue;
        };
        spent_images.extend(tx.vin.iter().filter_map(Variant::key_image).copied());
        let Ok(indices) = std::fs::read_to_string(dir.join(format!("{id}.gidx"))) else {
            continue;
        };
        let indices: Vec<u64> = indices
            .split_whitespace()
            .map(|index| index.parse().unwrap())
            .collect();
        owned.extend(owned_outputs(&wallet, &id, &tx, &indices));
    }
    owned.retain(|o| !spent_images.contains(&o.key_image));
    for o in &owned {
        println!(
            "unspent: {} of {} in {} output {} (global index {})",
            o.out.amount,
            if o.out.is_native {
                "ZANO"
            } else {
                "another asset"
            },
            o.tx_id,
            o.out.output_index,
            o.member.global_index
        );
    }

    let tx = transfer_from_daemon_data(&wallet, &mut system_random, &owned, &decoys, &plan)
        .unwrap_or_else(|e| panic!("{e}"));
    println!("transaction {}", hex::encode(tx.prefix_hash()));
    println!("verified here; to broadcast it: sendrawtransaction {{\"tx_as_hex\": ...}}");
    println!("TX {}", hex::encode(tx.to_bytes()));
}

/// An output as its recipient or the daemon decodes it: address, index,
/// amount, asset id and payment id.
type DecodedOut = (String, u64, u64, [u8; 32], u64);

/// A transfer of two assets this module builds and signs for a block at
/// `height`, from outputs made up for the occasion, and what the two
/// wallets it pays find in it: `(address, output, amount, asset id,
/// payment id)`.
fn probe_transfer(height: u64) -> (FinalizedTx, Vec<DecodedOut>) {
    use super::assets::{pay, ring_around};
    use crate::cryptonote::{EdwardsPoint, scalar_from_u64};

    let wallet = super::wallet();
    let recipient = Wallet::generate(&mut super::stream(31), 0).unwrap();
    let asset = AssetDescriptorBase {
        ticker: b"PROBE".to_vec(),
        full_name: b"Probe asset".to_vec(),
        total_max_supply: 1_000_000,
        owner: *wallet.spend_public_key(),
        ..Default::default()
    }
    .asset_id(None);
    let tx_secret = scalar_from_u64(0x0bad_cafe);
    let tx_pub = EdwardsPoint::mul_base(&tx_secret).compress();
    let derivation = wallet.key_derivation(&tx_pub).unwrap();
    let inputs: Vec<TransferInput> = [(asset, 500u64), (NATIVE_COIN_ASSET_ID, 3_000_000_000_000)]
        .iter()
        .enumerate()
        .map(|(n, (asset_id, amount))| {
            let out = pay(&wallet, &tx_secret, n as u64, asset_id, *amount);
            let found = wallet
                .scan_output(&derivation, n as u64, &out)
                .unwrap()
                .unwrap();
            let global_index = 1000 + 7 * n as u64;
            TransferInput {
                amount: found.amount,
                asset_id: found.asset_id,
                amount_blinding_mask: found.amount_blinding_mask,
                asset_id_blinding_mask: found.asset_id_blinding_mask,
                real_out_tx_key: tx_pub,
                real_out_index: n as u64,
                real_global_index: global_index,
                ring: ring_around(
                    RingMember {
                        global_index,
                        stealth_address: out.stealth_address,
                        concealing_point: out.concealing_point,
                        amount_commitment: out.amount_commitment,
                        blinded_asset_id: out.blinded_asset_id,
                    },
                    16,
                ),
            }
        })
        .collect();
    let mut integrated = recipient.address();
    integrated.set_payment_id(&[0xaa, 0xbb, 0xcc]).unwrap();
    let fee = 10_000_000_000;
    let dests = [
        TransferDest {
            address: integrated,
            asset_id: asset,
            amount: 300,
        },
        TransferDest {
            address: wallet.address(),
            asset_id: asset,
            amount: 200,
        },
        TransferDest {
            address: recipient.address(),
            asset_id: NATIVE_COIN_ASSET_ID,
            amount: 1_000_000_000_000,
        },
        TransferDest {
            address: wallet.address(),
            asset_id: NATIVE_COIN_ASSET_ID,
            amount: 2_000_000_000_000 - fee,
        },
    ];
    let built = wallet
        .build_transfer_at_height(&mut super::stream(height), &inputs, &dests, height)
        .unwrap();
    let mut expected = Vec::new();
    for party in [&recipient, &wallet] {
        let found = party.scan_tx(&built.tx).unwrap();
        for (out, payment_id) in found.outputs.iter().zip(&found.output_payment_ids) {
            expected.push((
                party.address().to_string(),
                out.output_index,
                out.amount,
                out.asset_id,
                *payment_id,
            ));
        }
    }
    expected.sort();
    assert_eq!(expected.len(), 4);
    (built, expected)
}

/// The message and the key pair of the signature the daemon is asked to
/// validate.
fn probe_signature() -> (&'static [u8], [u8; 32], [u8; 64]) {
    let message: &[u8] = b"outscript zano signature probe";
    let wallet = super::wallet();
    let sig = crate::cryptonote::generate_signature(
        &crate::cryptonote::cn_fast_hash(message),
        wallet.spend_public_key(),
        wallet.spend_secret_key().unwrap(),
        &[0x5a; 32],
    )
    .unwrap();
    (message, *wallet.spend_public_key(), sig)
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let mut word = [0u8; 3];
        word[..chunk.len()].copy_from_slice(chunk);
        let n = u32::from_be_bytes([0, word[0], word[1], word[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The heights the probes are built for: transaction versions 2, 3 and 4.
const PROBE_HEIGHTS: [u64; 3] = [3_000_000, 3_500_000, 3_900_000];

/// Writes questions for a daemon into the dump, which
/// `zano_fetch.py DIR ask` puts to it (read-only methods: nothing is
/// relayed) and `tool_daemon_replies` then checks:
///
/// - `ask_decrypt_<height>.json`: `decrypt_tx_details` of a transfer of two
///   assets this module built and signed, with its transaction secret key
///   and the addresses it pays — the daemon parses the transaction,
///   computes its id and decodes every output as the sender;
/// - `ask_signature.json`: `validate_signature` of a signature by
///   [`generate_signature`](crate::cryptonote::generate_signature).
#[test]
#[ignore = "needs ZANO_TX_DIR"]
fn tool_daemon_requests() {
    let Some(dir) = tool_dir() else { return };
    for height in PROBE_HEIGHTS {
        let (built, expected) = probe_transfer(height);
        let mut addresses: Vec<&String> = expected.iter().map(|e| &e.0).collect();
        addresses.dedup();
        let request = serde_json::json!({
            "method": "decrypt_tx_details",
            "params": {
                "tx_blob": hex::encode(built.tx.to_bytes()),
                "tx_secret_key": hex::encode(built.one_time_key),
                "outputs_addresses": addresses,
                "strict_output_addresses_match": false,
            }
        });
        std::fs::write(
            dir.join(format!("ask_decrypt_{height}.json")),
            request.to_string(),
        )
        .unwrap();
    }
    let (message, public, sig) = probe_signature();
    let request = serde_json::json!({
        "method": "validate_signature",
        "params": { "buff": base64(message), "sig": hex::encode(sig), "pkey": hex::encode(public) }
    });
    std::fs::write(dir.join("ask_signature.json"), request.to_string()).unwrap();
}

/// Checks what the daemon answered the questions of
/// `tool_daemon_requests` (`ask_*.json.reply`).
#[test]
#[ignore = "needs ZANO_TX_DIR"]
fn tool_daemon_replies() {
    let Some(dir) = tool_dir() else { return };
    let reply = |name: &str| -> Option<serde_json::Value> {
        let text = std::fs::read_to_string(dir.join(format!("{name}.json.reply"))).ok()?;
        Some(serde_json::from_str(&text).unwrap())
    };
    for height in PROBE_HEIGHTS {
        let Some(reply) = reply(&format!("ask_decrypt_{height}")) else {
            continue;
        };
        let (built, expected) = probe_transfer(height);
        let result = &reply["result"];
        assert_eq!(result["status"], "OK", "{reply}");
        assert_eq!(
            result["verified_tx_id"].as_str().unwrap(),
            hex::encode(built.tx_id)
        );
        let mut decoded: Vec<DecodedOut> = result["decoded_outputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|out| {
                (
                    out["address"].as_str().unwrap().to_string(),
                    out["out_index"].as_u64().unwrap(),
                    out["amount"].as_u64().unwrap(),
                    super::h32(out["asset_id"].as_str().unwrap()),
                    out["payment_id"].as_u64().unwrap_or(0),
                )
            })
            .collect();
        decoded.sort();
        assert_eq!(decoded, expected, "height {height}");
        println!(
            "the daemon decodes the version {} transfer {} as this module does: {} outputs",
            built.tx.version,
            hex::encode(built.tx_id),
            decoded.len()
        );
    }
    if let Some(reply) = reply("ask_signature") {
        assert_eq!(reply["result"]["status"], "OK", "{reply}");
        println!(
            "the daemon validates the signature (format {})",
            reply["result"]["sig_format"]
        );
    }
}
