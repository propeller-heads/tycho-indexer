use std::collections::HashMap;

use anyhow::Result;
use itertools::Itertools;
use substreams::{
    pb::substreams::StoreDeltas,
    store::{StoreGet, StoreGetProto, StoreGetString},
};
use substreams_ethereum::pb::eth;
use tycho_substreams::{
    balances::aggregate_balances_changes, contract::extract_contract_changes_builder, prelude::*,
};

use crate::{
    common::{
        address_from_word, all_pairs, is_zero, pair_store_key, slot_key,
        stateless_contract_address, EIP1967_IMPL_SLOT,
    },
    config::DeploymentConfig,
};

/// TesseraSwap `slot0` — the engine address; a write is an engine hot-swap.
const ENGINE_SLOT: u64 = 0;

/// Aggregates components, tracked-contract storage, balances and re-simulation markers into
/// the final `BlockChanges`.
#[substreams::handlers::map]
pub fn map_protocol_changes(
    params: String,
    block: eth::v2::Block,
    grouped_components: BlockTransactionProtocolComponents,
    deltas: BlockBalanceDeltas,
    components_store: StoreGetProto<ProtocolComponent>,
    pairs_store: StoreGetString,
    treasury_store: StoreGetString,
    balance_store: StoreDeltas,
) -> Result<BlockChanges> {
    let config: DeploymentConfig = serde_qs::from_str(&params)?;
    let mut transaction_changes: HashMap<u64, TransactionChangesBuilder> = HashMap::new();

    // The params fallback covers runs whose initial block is patched past the constructor
    // write (the testing harness); a real sync always has the store populated.
    let treasury = treasury_store
        .get_last("treasury")
        .and_then(|t| hex::decode(t).ok())
        .unwrap_or_else(|| config.treasury.clone());

    add_new_components(&grouped_components, &treasury, &mut transaction_changes);

    aggregate_balances_changes(balance_store, deltas)
        .into_iter()
        .for_each(|(_, (tx, balances))| {
            let builder = transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChangesBuilder::new(&tx));
            balances
                .values()
                .for_each(|token_bc_map| {
                    token_bc_map.values().for_each(|bc| {
                        builder.add_balance_change(bc);
                    })
                });
        });

    // Full storage + code of the stateful venue contracts: the two stable addresses from
    // params, plus every pair contract, discovered at component creation and resolved through
    // the components store (visible in-block, so a pair's creation code and init storage are
    // captured in its creation transaction). The contracts a pair delegatecalls into are
    // code-only and are not indexed at all — see `extract_delegate_targets`.
    extract_contract_changes_builder(
        &block,
        |addr| {
            addr == config.tesseraswap.as_slice() ||
                addr == config.engine.as_slice() ||
                components_store
                    .get_last(pair_store_key(addr))
                    .is_some()
        },
        &mut transaction_changes,
    );

    extract_treasury_changes(
        &block,
        &config,
        &components_store,
        &pairs_store,
        &mut transaction_changes,
    );
    extract_engine_changes(
        &block,
        &config,
        &components_store,
        &pairs_store,
        &mut transaction_changes,
    );
    extract_delegate_targets(&block, &config, &components_store, &mut transaction_changes);
    mark_pairs_updated(&config, &components_store, &pairs_store, &mut transaction_changes);

    Ok(BlockChanges {
        block: Some((&block).into()),
        changes: transaction_changes
            .drain()
            .sorted_unstable_by_key(|(index, _)| *index)
            .filter_map(|(_, builder)| builder.build())
            .collect::<Vec<_>>(),
        storage_changes: vec![],
    })
}

/// Adds newly created pair components and their default dynamic attributes.
fn add_new_components(
    grouped_components: &BlockTransactionProtocolComponents,
    treasury: &[u8],
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    for tx_component in &grouped_components.tx_components {
        let tx = tx_component.tx.as_ref().unwrap();
        let builder = transaction_changes
            .entry(tx.index)
            .or_insert_with(|| TransactionChangesBuilder::new(tx));
        for component in &tx_component.components {
            builder.add_protocol_component(component);
            builder.add_entity_change(&EntityChanges {
                component_id: component.id.clone(),
                attributes: vec![
                    Attribute {
                        name: "update_marker".to_string(),
                        value: vec![1u8],
                        change: ChangeType::Creation.into(),
                    },
                    Attribute {
                        name: "balance_owner".to_string(),
                        value: treasury.to_vec(),
                        change: ChangeType::Creation.into(),
                    },
                ],
            });
        }
    }
}

/// Refreshes the `balance_owner` attribute on every pair whenever TesseraSwap's treasury slot
/// is written (rotation — observed once on Base, block 37,737,344).
fn extract_treasury_changes(
    block: &eth::v2::Block,
    config: &DeploymentConfig,
    components_store: &StoreGetProto<ProtocolComponent>,
    pairs_store: &StoreGetString,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    let treasury_slot = slot_key(config.treasury_slot);
    // Computed lazily on the first treasury write so blocks without one do nothing.
    let mut pairs: Option<Vec<String>> = None;
    for tx in block.transactions() {
        for call in tx
            .calls
            .iter()
            .filter(|c| !c.state_reverted)
        {
            for change in &call.storage_changes {
                if change.address != config.tesseraswap ||
                    change.key != treasury_slot ||
                    is_zero(&change.new_value)
                {
                    continue;
                }
                let treasury = address_from_word(&change.new_value);
                let pairs = pairs.get_or_insert_with(|| {
                    all_pairs(components_store, pairs_store)
                        .into_iter()
                        .map(|c| c.id)
                        .collect()
                });
                if pairs.is_empty() {
                    continue;
                }
                let transaction: Transaction = tx.into();
                let builder = transaction_changes
                    .entry(transaction.index)
                    .or_insert_with(|| TransactionChangesBuilder::new(&transaction));
                for pair in pairs.iter() {
                    builder.add_entity_change(&EntityChanges {
                        component_id: pair.clone(),
                        attributes: vec![Attribute {
                            name: "balance_owner".to_string(),
                            value: treasury.clone(),
                            change: ChangeType::Update.into(),
                        }],
                    });
                    builder.mark_component_as_updated(pair);
                }
            }
        }
    }
}

/// Surfaces an engine hot-swap (TesseraSwap `slot0` write) as an `engine` attribute on every
/// pair. The engine is a stateful contract that is part of every component's contract list, so
/// a replacement cannot be followed dynamically — this attribute exists for monitoring to alert
/// on (never observed on Base; `changeTesseraEngine` has not been called since deployment).
fn extract_engine_changes(
    block: &eth::v2::Block,
    config: &DeploymentConfig,
    components_store: &StoreGetProto<ProtocolComponent>,
    pairs_store: &StoreGetString,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    let engine_slot = slot_key(ENGINE_SLOT);
    let mut pairs: Option<Vec<String>> = None;
    for tx in block.transactions() {
        for call in tx
            .calls
            .iter()
            .filter(|c| !c.state_reverted)
        {
            for change in &call.storage_changes {
                // old_value == 0 is the constructor write, before any pair exists.
                if change.address != config.tesseraswap ||
                    change.key != engine_slot ||
                    is_zero(&change.old_value)
                {
                    continue;
                }
                let engine = address_from_word(&change.new_value);
                let pairs = pairs.get_or_insert_with(|| {
                    all_pairs(components_store, pairs_store)
                        .into_iter()
                        .map(|c| c.id)
                        .collect()
                });
                let transaction: Transaction = tx.into();
                let builder = transaction_changes
                    .entry(transaction.index)
                    .or_insert_with(|| TransactionChangesBuilder::new(&transaction));
                for pair in pairs.iter() {
                    builder.add_entity_change(&EntityChanges {
                        component_id: pair.clone(),
                        attributes: vec![Attribute {
                            name: "engine".to_string(),
                            value: engine.clone(),
                            change: ChangeType::Update.into(),
                        }],
                    });
                    builder.mark_component_as_updated(pair);
                }
            }
        }
    }
}

/// Publishes the contracts a pair delegatecalls into as `stateless_contract_addr_{i}` attributes:
///
/// * `_0` — the pair implementation (EIP-1967 slot), written at pair init and on every upgrade;
/// * `_1` — the pricing lib (`pair_lib_slot`), assigned after creation and on lib upgrades;
/// * `_2` — the write-path contract (`pair_write_path_slot`), assigned after creation.
///
/// These contracts are code-only: they are deployed top-level by rotating EOAs at blocks unrelated
/// to any pair, so their creation cannot be witnessed here, and a component's contract list is
/// fixed at creation, so they could not be attached to the component later even if it were. The
/// attribute path sidesteps both: the consumer fetches the code via `eth_getCode` when it loads
/// the pool (and, in `tycho-simulation`, again whenever one of these attributes changes), so an
/// implementation upgrade is followed with no params change, spkg release or re-sync.
///
/// Consumers read the indices contiguously, so `_2` only becomes visible once `_1` has been
/// assigned. On Base the lib is always assigned before the write-path contract, and a pair
/// without a lib cannot quote anyway.
fn extract_delegate_targets(
    block: &eth::v2::Block,
    config: &DeploymentConfig,
    components_store: &StoreGetProto<ProtocolComponent>,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    let lib_slot = slot_key(config.pair_lib_slot);
    let write_path_slot = slot_key(config.pair_write_path_slot);
    for tx in block.transactions() {
        for call in tx
            .calls
            .iter()
            .filter(|c| !c.state_reverted)
        {
            for change in &call.storage_changes {
                if is_zero(&change.new_value) {
                    continue;
                }
                let name = if change.key == EIP1967_IMPL_SLOT.as_slice() {
                    "stateless_contract_addr_0"
                } else if change.key == lib_slot {
                    "stateless_contract_addr_1"
                } else if change.key == write_path_slot {
                    "stateless_contract_addr_2"
                } else {
                    continue;
                };
                let Some(component) = components_store.get_last(pair_store_key(&change.address))
                else {
                    continue;
                };
                // A zero → non-zero write is the slot's first assignment (pair init for the
                // implementation slot, the follow-up admin transaction for the other two).
                let change_type = if is_zero(&change.old_value) {
                    ChangeType::Creation
                } else {
                    ChangeType::Update
                };
                let transaction: Transaction = tx.into();
                let builder = transaction_changes
                    .entry(transaction.index)
                    .or_insert_with(|| TransactionChangesBuilder::new(&transaction));
                builder.add_entity_change(&EntityChanges {
                    component_id: component.id.clone(),
                    attributes: vec![Attribute {
                        name: name.to_string(),
                        value: stateless_contract_address(&address_from_word(&change.new_value)),
                        change: change_type.into(),
                    }],
                });
                builder.mark_component_as_updated(&component.id);
            }
        }
    }
}

/// Marks pairs for re-simulation from tracked-contract changes: a change to a shared contract
/// (TesseraSwap, engine) marks every pair; a change to a pair contract marks that pair. Prices
/// post into each pair every block, so in steady state every pair re-simulates every block —
/// that is the venue repricing, not noise.
fn mark_pairs_updated(
    config: &DeploymentConfig,
    components_store: &StoreGetProto<ProtocolComponent>,
    pairs_store: &StoreGetString,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    let mut pairs: Option<Vec<String>> = None;
    for builder in transaction_changes.values_mut() {
        let mut mark_all = false;
        let mut mark_ids: Vec<String> = Vec::new();
        for addr in builder.changed_contracts() {
            if addr == config.tesseraswap.as_slice() || addr == config.engine.as_slice() {
                mark_all = true;
                break;
            }
            if let Some(component) = components_store.get_last(pair_store_key(addr)) {
                mark_ids.push(component.id);
            }
        }
        if mark_all {
            let pairs = pairs.get_or_insert_with(|| {
                all_pairs(components_store, pairs_store)
                    .into_iter()
                    .map(|c| c.id)
                    .collect()
            });
            for pair in pairs.iter() {
                builder.mark_component_as_updated(pair);
            }
        } else {
            for id in mark_ids {
                builder.mark_component_as_updated(&id);
            }
        }
    }
}
