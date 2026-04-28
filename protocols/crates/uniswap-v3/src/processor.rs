use std::collections::{HashMap, HashSet};

use num_bigint::{BigInt, Sign};
use tycho_substreams::prelude::{
    Attribute, BalanceChange, ChangeType, EntityChanges, Transaction as TychoTransaction,
    TransactionChanges, TransactionChangesBuilder,
};

use crate::{
    balance::event_to_balance_deltas,
    events::{decode_log, Pool, PoolEvent, TxRef},
    liquidity::{event_to_current_tick, event_to_liquidity_delta, LiquidityChangeKind},
    output::event_to_attribute_updates,
    ticks::event_to_tick_deltas,
};

// --- Input types ---

pub struct LogInput {
    pub address: Vec<u8>,
    pub topics: Vec<Vec<u8>>,
    pub data: Vec<u8>,
    pub log_index: u32,
}

pub struct TxInput {
    pub hash: Vec<u8>,
    pub from: Vec<u8>,
    pub to: Vec<u8>,
    pub index: u64,
    pub logs: Vec<LogInput>,
    pub succeeded: bool,
}

// --- Bootstrap input types ---

pub struct ComponentSnapshot {
    pub id: String,
    pub tokens: Vec<Vec<u8>>,
}

pub struct StateSnapshot {
    pub component_id: String,
    pub attributes: HashMap<String, Vec<u8>>,
    pub balances: HashMap<Vec<u8>, Vec<u8>>,
}

// --- Processor ---

pub struct UniswapV3Processor {
    pools: HashMap<String, Pool>,
    balances: HashMap<(String, String), BigInt>,
    tick_liquidity: HashMap<(String, i32), BigInt>,
    current_tick: HashMap<String, i64>,
    pool_liquidity: HashMap<String, BigInt>,
    baseline_tick_keys: HashSet<(String, i32)>,
}

impl UniswapV3Processor {
    pub fn from_tycho_snapshot(
        components: &[ComponentSnapshot],
        states: &[StateSnapshot],
    ) -> Self {
        let mut pools = HashMap::new();
        let mut balances = HashMap::new();
        let mut tick_liquidity = HashMap::new();
        let mut current_tick = HashMap::new();
        let mut pool_liquidity = HashMap::new();
        let mut baseline_tick_keys = HashSet::new();

        for comp in components {
            if comp.tokens.len() < 2 {
                continue;
            }
            let pool = Pool {
                address: hex::decode(&comp.id).unwrap_or_default(),
                token0: comp.tokens[0].clone(),
                token1: comp.tokens[1].clone(),
            };
            pools.insert(comp.id.clone(), pool);
        }

        for state in states {
            let pool_id = &state.component_id;

            if let Some(tick_bytes) = state.attributes.get("tick") {
                let tick_val = BigInt::from_signed_bytes_be(tick_bytes);
                let (sign, digits) = tick_val.to_u64_digits();
                let magnitude = digits.first().copied().unwrap_or(0) as i64;
                let tick_i64 = if sign == Sign::Minus { -magnitude } else { magnitude };
                current_tick.insert(pool_id.clone(), tick_i64);
            }

            if let Some(liq_bytes) = state.attributes.get("liquidity") {
                pool_liquidity
                    .insert(pool_id.clone(), BigInt::from_signed_bytes_be(liq_bytes));
            }

            for (attr_name, attr_val) in &state.attributes {
                if let Some(rest) = attr_name.strip_prefix("ticks/") {
                    if let Some(idx_str) = rest.strip_suffix("/net-liquidity") {
                        if let Ok(idx) = idx_str.parse::<i32>() {
                            let key = (pool_id.clone(), idx);
                            tick_liquidity
                                .insert(key.clone(), BigInt::from_signed_bytes_be(attr_val));
                            baseline_tick_keys.insert(key);
                        }
                    }
                }
            }

            for (token_bytes, balance_bytes) in &state.balances {
                let token_hex = hex::encode(token_bytes);
                let balance = BigInt::from_bytes_be(Sign::Plus, balance_bytes);
                balances.insert((pool_id.clone(), token_hex), balance);
            }
        }

        Self { pools, balances, tick_liquidity, current_tick, pool_liquidity, baseline_tick_keys }
    }

    pub fn process_iteration(&mut self, txs: &[TxInput]) -> Vec<TransactionChanges> {
        let mut tx_builders: HashMap<Vec<u8>, (u64, TransactionChangesBuilder)> = HashMap::new();

        for tx in txs {
            if !tx.succeeded {
                continue;
            }

            let tx_ref = TxRef {
                hash: tx.hash.clone(),
                from: tx.from.clone(),
                to: tx.to.clone(),
                index: tx.index,
            };

            let mut events: Vec<PoolEvent> = Vec::new();
            for log in &tx.logs {
                let pool_hex = hex::encode(&log.address);
                let pool = match self.pools.get(&pool_hex) {
                    Some(p) => p,
                    None => continue,
                };
                let ordinal = tx.index * 100_000 + log.log_index as u64;
                let pb_log = log_input_to_pb(log, ordinal);
                if let Some(event) = decode_log(&pb_log, pool, &tx_ref) {
                    events.push(event);
                }
            }

            if events.is_empty() {
                continue;
            }

            if !tx_builders.contains_key(&tx.hash) {
                let tycho_tx = TychoTransaction {
                    hash: tx.hash.clone(),
                    from: tx.from.clone(),
                    to: tx.to.clone(),
                    index: tx.index,
                };
                tx_builders.insert(
                    tx.hash.clone(),
                    (tx.index, TransactionChangesBuilder::new(&tycho_tx)),
                );
            }

            for event in events {
                let (_, builder) = tx_builders.get_mut(&tx.hash).unwrap();
                self.apply_event(event, builder);
            }
        }

        let mut ordered: Vec<(u64, TransactionChangesBuilder)> =
            tx_builders.into_values().collect();
        ordered.sort_unstable_by_key(|(idx, _)| *idx);
        ordered.into_iter().filter_map(|(_, b)| b.build()).collect()
    }

    fn apply_event(&mut self, event: PoolEvent, builder: &mut TransactionChangesBuilder) {
        let pool_hex = hex::encode(&event.pool_address);

        if let Some(new_tick) = event_to_current_tick(&event) {
            self.current_tick.insert(pool_hex.clone(), new_tick);
        }

        for delta in event_to_balance_deltas(&event) {
            let token_hex = hex::encode(&delta.token);
            let key = (pool_hex.clone(), token_hex);
            let running = self.balances.entry(key).or_default();
            *running += &delta.delta;
            let clamped =
                if *running < BigInt::default() { BigInt::default() } else { running.clone() };
            builder.add_balance_change(&BalanceChange {
                component_id: event.pool_address.clone(),
                token: delta.token.clone(),
                balance: clamped.to_bytes_be().1,
            });
        }

        for tick_delta in event_to_tick_deltas(&event) {
            let key = (pool_hex.clone(), tick_delta.tick_index);
            let existed_before = self.tick_liquidity.contains_key(&key)
                || self.baseline_tick_keys.contains(&key);
            let running = self.tick_liquidity.entry(key.clone()).or_default();
            *running += &tick_delta.liquidity_net_delta;
            let new_val = running.clone();

            let change_type = if !existed_before {
                ChangeType::Creation
            } else if new_val == BigInt::default() {
                ChangeType::Deletion
            } else {
                ChangeType::Update
            };

            builder.add_entity_change(&EntityChanges {
                component_id: pool_hex.clone(),
                attributes: vec![Attribute {
                    name: format!("ticks/{}/net-liquidity", tick_delta.tick_index),
                    value: new_val.to_signed_bytes_be(),
                    change: change_type.into(),
                }],
            });
        }

        let cur_tick = *self.current_tick.get(&pool_hex).unwrap_or(&0);
        if let Some(liq_delta) = event_to_liquidity_delta(cur_tick, &event) {
            let running = self.pool_liquidity.entry(pool_hex.clone()).or_default();
            match liq_delta.kind {
                LiquidityChangeKind::Delta => *running += &liq_delta.value,
                LiquidityChangeKind::Absolute => *running = liq_delta.value.clone(),
            }
            builder.add_entity_change(&EntityChanges {
                component_id: pool_hex.clone(),
                attributes: vec![Attribute {
                    name: "liquidity".to_string(),
                    value: running.to_signed_bytes_be(),
                    change: ChangeType::Update.into(),
                }],
            });
        }

        for attr_update in event_to_attribute_updates(&event) {
            let comp_id = hex::encode(&attr_update.pool_address);
            let change_type =
                if attr_update.is_creation { ChangeType::Creation } else { ChangeType::Update };
            builder.add_entity_change(&EntityChanges {
                component_id: comp_id,
                attributes: vec![Attribute {
                    name: attr_update.name,
                    value: attr_update.value,
                    change: change_type.into(),
                }],
            });
        }
    }
}

fn log_input_to_pb(
    log: &LogInput,
    ordinal: u64,
) -> substreams_ethereum::pb::eth::v2::Log {
    substreams_ethereum::pb::eth::v2::Log {
        address: log.address.clone(),
        topics: log.topics.clone(),
        data: log.data.clone(),
        ordinal,
        ..Default::default()
    }
}
