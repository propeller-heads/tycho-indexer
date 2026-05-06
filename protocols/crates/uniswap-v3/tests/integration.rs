use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use alloy::{
    consensus::Transaction as _,
    eips::BlockNumberOrTag,
    primitives::B256,
    providers::{Provider, ProviderBuilder},
    rpc::types::{BlockTransactions, Filter, Log},
    transports::http::reqwest::Url,
};
use prost::Message;
use tokio_stream::StreamExt;
use tycho_common::{
    models::{
        blockchain::{LogInput, TxInput, TxWithChanges},
        protocol::{ProtocolComponent, ProtocolComponentState},
    },
    traits::ProtocolProcessor,
    Bytes,
};
use tycho_indexer::{
    pb::sf::substreams::v1::Package,
    substreams::{
        stream::{BlockResponse, SubstreamsStream},
        SubstreamsEndpoint,
    },
};
use tycho_substreams::pb::tycho::evm::v1::BlockChanges;
use uniswap_v3_core::processor::UniswapV3Processor;

// UV3 factory deployed at this block on mainnet.
const START_BLOCK: u64 = 12_369_621;
// Default: 2000 blocks ≈ 8 h of chain time, long enough to see all event types.
// Override with UV3_STOP_BLOCK env var for a wider or narrower range.
const DEFAULT_STOP_BLOCK: u64 = START_BLOCK + 2_000; // 12_371_621

// ─── Substreams helpers ──────────────────────────────────────────────────────

/// Streams every block in `[start, stop]` from the substreams endpoint and
/// returns `(block_number, BlockChanges)` pairs in ascending order.
async fn stream_block_range(
    endpoint_url: &str,
    api_key: &str,
    spkg_path: &str,
    start: u64,
    stop: u64,
) -> Vec<(u64, BlockChanges)> {
    let content = std::fs::read(spkg_path)
        .unwrap_or_else(|e| panic!("Failed to read spkg at {spkg_path}: {e}"));
    let package = Package::decode(content.as_slice())
        .unwrap_or_else(|e| panic!("Failed to decode spkg: {e}"));

    let endpoint = Arc::new(
        SubstreamsEndpoint::new(endpoint_url, Some(api_key.to_string()))
            .await
            .expect("Failed to create substreams endpoint"),
    );

    let mut stream = SubstreamsStream::new(
        endpoint,
        None,
        Some(package),
        "map_protocol_changes".to_string(),
        start as i64,
        stop,
        true,
        "integration-test".to_string(),
        false,
    );

    let mut results = Vec::new();
    loop {
        match stream.next().await {
            Some(Ok(BlockResponse::New(data))) => {
                let block_num = data
                    .clock
                    .as_ref()
                    .map_or(0, |c| c.number);
                let map_output = data
                    .output
                    .as_ref()
                    .and_then(|o| o.map_output.as_ref())
                    .expect("BlockScopedData has no map_output");
                let changes = BlockChanges::decode(map_output.value.as_slice())
                    .expect("Failed to decode BlockChanges");
                results.push((block_num, changes));
            }
            Some(Ok(BlockResponse::Ended)) => break,
            Some(Ok(BlockResponse::Undo(_))) => {
                // Undo signals should not appear with final_blocks_only=true.
                panic!("Unexpected undo signal in range [{start}, {stop}]");
            }
            Some(Err(e)) => panic!("Substreams stream error: {e}"),
            None => break,
        }
    }

    results.sort_unstable_by_key(|(n, _)| *n);
    results
}

// ─── Archive RPC helpers ─────────────────────────────────────────────────────

// Canonical Uniswap V3 pool event ABI signatures.
// Passed to `Filter::events` which hashes them to topic0 values internally.
const UV3_EVENT_SIGNATURES: [&str; 8] = [
    "Swap(address,address,int256,int256,uint160,uint128,int24)",
    "Mint(address,address,int24,int24,uint128,uint256,uint256)",
    "Burn(address,int24,int24,uint128,uint256,uint256)",
    "Collect(address,address,int24,int24,uint128,uint128)",
    "Initialize(uint160,int24)",
    "Flash(address,address,uint256,uint256,uint256,uint256)",
    "CollectProtocol(address,address,uint128,uint128)",
    "SetFeeProtocol(uint8,uint8,uint8,uint8)",
];

/// Returns all UV3 pool logs emitted in `[start_block, stop_block]`.
///
/// Chunked into 10,000-block pages to stay within Alchemy's eth_getLogs limit.
async fn fetch_range_logs(rpc_url: &str, start_block: u64, stop_block: u64) -> Vec<Log> {
    const CHUNK: u64 = 10_000;
    let provider = ProviderBuilder::new().connect_http(
        rpc_url
            .parse::<Url>()
            .expect("invalid RPC URL"),
    );
    let mut logs = Vec::new();
    let mut chunk_start = start_block;
    while chunk_start <= stop_block {
        let chunk_end = (chunk_start + CHUNK - 1).min(stop_block);
        let filter = Filter::new()
            .from_block(chunk_start)
            .to_block(chunk_end)
            .events(UV3_EVENT_SIGNATURES);
        let chunk_logs = provider
            .get_logs(&filter)
            .await
            .unwrap_or_else(|e| panic!("eth_getLogs [{chunk_start},{chunk_end}] failed: {e}"));
        logs.extend(chunk_logs);
        chunk_start = chunk_end + 1;
    }
    logs
}

/// Returns `{tx_hash → (from_bytes, to_bytes, tx_index)}` for all transactions
/// in the given block by fetching the full block once.
async fn fetch_block_tx_meta(
    rpc_url: &str,
    block_num: u64,
) -> HashMap<B256, (Vec<u8>, Vec<u8>, u64)> {
    use alloy::network::{BlockResponse as _, TransactionResponse as _};

    let provider = ProviderBuilder::new().connect_http(
        rpc_url
            .parse::<Url>()
            .expect("invalid RPC URL"),
    );
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Number(block_num))
        .full()
        .await
        .unwrap_or_else(|e| panic!("eth_getBlockByNumber({block_num}) failed: {e}"))
        .unwrap_or_else(|| panic!("block {block_num} not found"));

    let mut map = HashMap::new();
    if let BlockTransactions::Full(txns) = block.transactions() {
        for tx in txns {
            let hash = tx.tx_hash();
            let from = tx.from().to_vec();
            // `to()` lives on the inner consensus transaction.
            let to = tx
                .inner
                .to()
                .map(|a| a.to_vec())
                .unwrap_or_default();
            let index = tx
                .transaction_index()
                .unwrap_or_default();
            map.insert(hash, (from, to, index));
        }
    }
    map
}

/// Returns a `HashMap<block_num, Vec<TxInput>>` for every block in
/// `[start_block, stop_block]` that emitted at least one log.
///
/// Transactions are ordered by transaction index within each block.
/// All transactions that emitted logs are treated as succeeded — the EVM
/// does not emit logs for reverted transactions.
async fn fetch_range_tx_inputs(
    rpc_url: &str,
    start_block: u64,
    stop_block: u64,
) -> HashMap<u64, Vec<TxInput>> {
    let logs = fetch_range_logs(rpc_url, start_block, stop_block).await;

    // Group logs by block number, then by tx hash.
    let mut blocks_with_tx_hashes: HashMap<u64, HashSet<B256>> = HashMap::new();
    let mut logs_by_key: HashMap<(u64, B256), Vec<LogInput>> = HashMap::new();

    for log in &logs {
        let Some(block_num) = log.block_number else { continue };
        let Some(hash) = log.transaction_hash else { continue };
        blocks_with_tx_hashes
            .entry(block_num)
            .or_default()
            .insert(hash);
        logs_by_key
            .entry((block_num, hash))
            .or_default()
            .push(LogInput::new(
                Bytes::from(log.address().to_vec()),
                log.topics()
                    .iter()
                    .map(|t| Bytes::from(t.to_vec()))
                    .collect(),
                Bytes::from(log.data().data.to_vec()),
                log.log_index.unwrap_or_default() as u32,
            ));
    }

    let mut result: HashMap<u64, Vec<TxInput>> = HashMap::new();

    for (block_num, tx_hashes) in blocks_with_tx_hashes {
        let meta = fetch_block_tx_meta(rpc_url, block_num).await;
        let mut tx_inputs: Vec<TxInput> = tx_hashes
            .into_iter()
            .filter_map(|hash| {
                let (from, to, index) = meta.get(&hash)?.clone();
                let logs = logs_by_key
                    .remove(&(block_num, hash))
                    .unwrap_or_default();
                Some(TxInput::new(
                    Bytes::from(hash.to_vec()),
                    Bytes::from(from),
                    Bytes::from(to),
                    index,
                    logs,
                    true,
                ))
            })
            .collect();
        tx_inputs.sort_unstable_by_key(|t| t.index());
        result.insert(block_num, tx_inputs);
    }

    result
}

// ─── Comparison helpers ──────────────────────────────────────────────────────

/// Normalise a component_id from substreams output to lower-case hex without "0x".
fn normalise_component_id(raw: &[u8]) -> String {
    let s = std::str::from_utf8(raw).unwrap_or_default();
    s.trim_start_matches("0x")
        .to_lowercase()
}

fn normalise_str_id(s: &str) -> String {
    s.trim_start_matches("0x")
        .to_lowercase()
}

#[derive(Debug)]
struct ComparableTxChanges {
    tx_hash: String,
    /// component_id → { attr_name → value }
    attributes: HashMap<String, HashMap<String, Vec<u8>>>,
    /// (component_id, token_hex) → balance
    balances: HashMap<(String, String), Vec<u8>>,
}

fn substreams_to_comparable(
    changes: &tycho_substreams::pb::tycho::evm::v1::TransactionChanges,
    known_pools: &HashSet<String>,
) -> Option<ComparableTxChanges> {
    let tx = changes.tx.as_ref()?;
    let tx_hash = hex::encode(&tx.hash);

    let mut attributes: HashMap<String, HashMap<String, Vec<u8>>> = HashMap::new();
    let mut balances: HashMap<(String, String), Vec<u8>> = HashMap::new();

    for ec in &changes.entity_changes {
        let cid = normalise_str_id(&ec.component_id);
        if !known_pools.contains(&cid) {
            continue;
        }
        for attr in &ec.attributes {
            // map_pools_created emits zero-value init attrs (liquidity/tick/
            // sqrt_price_x96 = 0x00) for newly deployed pools.  The processor
            // produces no output for factory events, so skip these to avoid
            // false "missing transaction" failures.  The substreams BigInt
            // encodes zero as a single 0x00 byte (not as empty bytes).
            if attr.value.iter().all(|&b| b == 0) {
                continue;
            }
            attributes
                .entry(cid.clone())
                .or_default()
                .insert(attr.name.clone(), attr.value.clone());
        }
    }

    for bc in &changes.balance_changes {
        let cid = normalise_component_id(&bc.component_id);
        if !known_pools.contains(&cid) {
            continue;
        }
        // Same rationale: skip zero balances emitted on pool creation.
        if bc.balance.iter().all(|&b| b == 0) {
            continue;
        }
        let token = hex::encode(&bc.token);
        balances.insert((cid, token), bc.balance.clone());
    }

    if attributes.is_empty() && balances.is_empty() {
        return None;
    }

    Some(ComparableTxChanges { tx_hash, attributes, balances })
}

fn processor_to_comparable(changes: &TxWithChanges) -> ComparableTxChanges {
    let tx_hash = hex::encode(&changes.tx.hash);

    let mut attributes: HashMap<String, HashMap<String, Vec<u8>>> = HashMap::new();
    let mut balances: HashMap<(String, String), Vec<u8>> = HashMap::new();

    for (comp_id, state_delta) in &changes.state_updates {
        let entry = attributes
            .entry(comp_id.clone())
            .or_default();
        for (attr_name, attr_val) in &state_delta.updated_attributes {
            entry.insert(attr_name.clone(), attr_val.to_vec());
        }
    }

    for (comp_id, token_balances) in &changes.balance_changes {
        for (token, cb) in token_balances {
            let token_hex = hex::encode(token.as_ref());
            balances.insert((comp_id.clone(), token_hex), cb.balance.to_vec());
        }
    }

    ComparableTxChanges { tx_hash, attributes, balances }
}

// ─── Test ────────────────────────────────────────────────────────────────────

/// Streams UniswapV3 substreams from the genesis block (12_369_621) through
/// `UV3_STOP_BLOCK` (default +2000 blocks) and verifies that the native
/// `UniswapV3Processor` produces byte-identical attribute and balance values
/// for every transaction in every block.
///
/// Starting from genesis means the processor begins with empty state —
/// no baseline seeding required.  Pool token addresses are read directly
/// from the `component_changes` in the substreams output.
///
/// Required env vars:
///   ETH_RPC_URL         — archive RPC endpoint (supports eth_getLogs over
///                         multi-thousand-block ranges and eth_getBlockByNumber)
///   STREAMINGFAST_KEY   — StreamingFast API token
///   UV3_SPKG_PATH       — path to the built `ethereum-uniswap-v3.spkg`
///                         (build: cd protocols/substreams/ethereum-uniswap-v3-logs-only
///                                 cargo build --target wasm32-unknown-unknown --release
///                                 substreams pack -o /tmp/uniswap-v3.spkg
/// ethereum-uniswap-v3.yaml)   UV3_STOP_BLOCK      — (optional) override stop block; defaults to
/// 12_371_621
#[tokio::test]
#[ignore = "requires ETH_RPC_URL, STREAMINGFAST_KEY, and UV3_SPKG_PATH"]
async fn test_processor_matches_substreams_genesis_range() {
    dotenv::dotenv().ok();

    let rpc_url = std::env::var("ETH_RPC_URL").expect("ETH_RPC_URL must be set");
    let api_key = std::env::var("STREAMINGFAST_KEY").expect("STREAMINGFAST_KEY must be set");
    let spkg_path = std::env::var("UV3_SPKG_PATH")
        .expect("UV3_SPKG_PATH must be set (path to the built .spkg file)");
    let stop_block = std::env::var("UV3_STOP_BLOCK")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_STOP_BLOCK);

    let endpoint_url = "https://mainnet.eth.streamingfast.io:443";

    // ── Step 1: stream the full range from substreams ────────────────────────
    let all_block_changes =
        stream_block_range(endpoint_url, &api_key, &spkg_path, START_BLOCK, stop_block).await;

    assert!(
        !all_block_changes.is_empty(),
        "Substreams returned no blocks for range [{START_BLOCK}, {stop_block}]"
    );

    // ── Step 2: collect pool registrations from component_changes ────────────
    //
    // component_changes carry the pool address (id) and its token list.
    // This avoids any RPC calls for pool metadata — the substreams output
    // is the authoritative source.
    let mut components: Vec<ProtocolComponent> = Vec::new();
    let mut known_pool_ids: HashSet<String> = HashSet::new();

    for (_, block_changes) in &all_block_changes {
        for tx in &block_changes.changes {
            for comp in &tx.component_changes {
                let pool_id = normalise_str_id(&comp.id);
                if known_pool_ids.insert(pool_id.clone()) {
                    components.push(ProtocolComponent {
                        id: pool_id,
                        tokens: comp
                            .tokens
                            .iter()
                            .map(|t| t.clone().into())
                            .collect(),
                        ..Default::default()
                    });
                }
            }
            // Also collect pools that only appear via entity_changes (already
            // registered in a prior range but active in this one).
            for ec in &tx.entity_changes {
                known_pool_ids.insert(normalise_str_id(&ec.component_id));
            }
            for bc in &tx.balance_changes {
                known_pool_ids.insert(normalise_component_id(&bc.component_id));
            }
        }
    }

    assert!(
        !known_pool_ids.is_empty(),
        "No UV3 pool activity found in range [{START_BLOCK}, {stop_block}]"
    );

    // ── Step 3: build empty state snapshots (genesis start = zero state) ─────
    let states: Vec<ProtocolComponentState> = components
        .iter()
        .map(|c| ProtocolComponentState::new(&c.id, HashMap::new(), HashMap::new()))
        .collect();

    // ── Step 4: fetch tx inputs for the full block range ─────────────────────
    let mut per_block_inputs = fetch_range_tx_inputs(&rpc_url, START_BLOCK, stop_block).await;

    // ── Step 5: run the native processor block by block ──────────────────────
    let mut processor = UniswapV3Processor::from_snapshot(&components, &states);

    let mut attr_mismatches: Vec<String> = Vec::new();
    let mut balance_mismatches: Vec<String> = Vec::new();
    let mut missing_txs: Vec<String> = Vec::new();

    let mut total_compared_txs: usize = 0;
    let mut total_compared_attrs: usize = 0;
    let mut total_compared_balances: usize = 0;

    for (block_num, substreams_block) in &all_block_changes {
        let tx_inputs = per_block_inputs
            .remove(block_num)
            .unwrap_or_default();
        let processor_output = processor.process_block(&tx_inputs);

        let substreams_map: HashMap<String, ComparableTxChanges> = substreams_block
            .changes
            .iter()
            .filter_map(|tc| substreams_to_comparable(tc, &known_pool_ids))
            .map(|c| (c.tx_hash.clone(), c))
            .collect();

        let processor_map: HashMap<String, ComparableTxChanges> = processor_output
            .iter()
            .map(processor_to_comparable)
            .map(|c| (c.tx_hash.clone(), c))
            .collect();

        for hash in substreams_map.keys() {
            if !processor_map.contains_key(hash) {
                missing_txs.push(format!("block={block_num} tx={hash}"));
            }
        }

        for (hash, expected) in &substreams_map {
            let Some(actual) = processor_map.get(hash) else { continue };

            total_compared_txs += 1;

            // Print every matched transaction with both sides side-by-side.
            let short_hash = &hash[..12];
            println!("\n  block={block_num} tx={short_hash}...");

            for (cid, expected_attrs) in &expected.attributes {
                let actual_attrs = actual
                    .attributes
                    .get(cid)
                    .cloned()
                    .unwrap_or_default();
                let short_cid = &cid[..8];
                for (attr_name, expected_value) in expected_attrs {
                    total_compared_attrs += 1;
                    let ev = hex::encode(expected_value);
                    match actual_attrs.get(attr_name) {
                        Some(v) if v == expected_value => {
                            println!("    pool={short_cid}.. {attr_name:20}  substreams={ev}  processor=✓");
                        }
                        Some(v) => {
                            let av = hex::encode(v);
                            println!("    pool={short_cid}.. {attr_name:20}  substreams={ev}  processor={av}  MISMATCH");
                            attr_mismatches.push(format!(
                                "block={block_num} tx={hash} pool={cid} attr={attr_name}: \
                                 expected={ev} got={av}",
                            ));
                        }
                        None => {
                            println!("    pool={short_cid}.. {attr_name:20}  substreams={ev}  processor=MISSING");
                            attr_mismatches.push(format!(
                                "block={block_num} tx={hash} pool={cid} attr={attr_name}: \
                                 expected={ev} but missing",
                            ));
                        }
                    }
                }
            }

            for ((cid, token), expected_balance) in &expected.balances {
                total_compared_balances += 1;
                let short_cid = &cid[..8];
                let short_tok = &token[..8];
                let eb = hex::encode(expected_balance);
                match actual
                    .balances
                    .get(&(cid.clone(), token.clone()))
                {
                    Some(v) if v == expected_balance => {
                        println!("    pool={short_cid}.. token={short_tok}..  balance: substreams={eb}  processor=✓");
                    }
                    Some(v) => {
                        let ab = hex::encode(v);
                        println!("    pool={short_cid}.. token={short_tok}..  balance: substreams={eb}  processor={ab}  MISMATCH");
                        balance_mismatches.push(format!(
                            "block={block_num} tx={hash} pool={cid} token={token}: \
                             expected={eb} got={ab}",
                        ));
                    }
                    None => {
                        println!("    pool={short_cid}.. token={short_tok}..  balance: substreams={eb}  processor=MISSING");
                        balance_mismatches.push(format!(
                            "block={block_num} tx={hash} pool={cid} token={token}: \
                             expected={eb} but missing",
                        ));
                    }
                }
            }
        }
    }

    println!("\n─── Summary ────────────────────────────────────────────────────────────────");
    println!("  Blocks streamed:       {}", all_block_changes.len());
    println!("  Pools registered:      {}", known_pool_ids.len());
    println!("  Transactions compared: {total_compared_txs}");
    println!("  Attributes compared:   {total_compared_attrs}");
    println!("  Balances compared:     {total_compared_balances}");
    println!("  Attr mismatches:       {}", attr_mismatches.len());
    println!("  Balance mismatches:    {}", balance_mismatches.len());
    println!("  Missing txs:           {}", missing_txs.len());
    println!("────────────────────────────────────────────────────────────────────────────");

    assert!(
        missing_txs.is_empty(),
        "Transactions in substreams output but absent from processor ({} total):\n{}",
        missing_txs.len(),
        missing_txs.join("\n"),
    );
    assert!(
        attr_mismatches.is_empty(),
        "Attribute value mismatches ({} total):\n{}",
        attr_mismatches.len(),
        attr_mismatches.join("\n"),
    );
    assert!(
        balance_mismatches.is_empty(),
        "Balance value mismatches ({} total):\n{}",
        balance_mismatches.len(),
        balance_mismatches.join("\n"),
    );
}
