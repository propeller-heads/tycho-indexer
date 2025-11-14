//! Template for Protocols with contract factories
//!
//! This template provides foundational maps and store substream modules for indexing a
//! protocol where each component (e.g., pool) is deployed to a separate contract. Each
//! contract is expected to escrow its ERC-20 token balances.
//!
//! If your protocol supports native ETH, you may need to adjust the balance tracking
//! logic in `map_relative_component_balance` to account for native token handling.
//!
//! ## Assumptions
//! - Assumes each pool has a single newly deployed contract linked to it
//! - Assumes pool identifier equals the deployed contract address
//! - Assumes any price or liquidity updated correlates with a pools contract storage update.
//!
//! ## Alternative Module
//! If your protocol uses a vault-like contract to manage balances, or if pools are
//! registered within a singleton contract, refer to the `ethereum-template-singleton`
//! substream for an appropriate alternative.
//!
//! ## Warning
//! This template provides a general framework for indexing a protocol. However, it is
//! likely that you will need to adapt the steps to suit your specific use case. Use the
//! provided code with care and ensure you fully understand each step before proceeding
//! with your implementation.
//!
//! ## Example Use Case
//! For an Uniswap-like protocol where each liquidity pool is deployed as a separate
//! contract, you can use this template to:
//! - Track relative component balances (e.g., ERC-20 token balances in each pool).
//! - Index individual pool contracts as they are created by the factory contract.
//!
//! Adjustments to the template may include:
//! - Handling native ETH balances alongside token balances.
//! - Customizing indexing logic for specific factory contract behavior.
use crate::pool_factories;
use anyhow::Result;
use itertools::Itertools;
use std::collections::HashMap;
use substreams::{pb::substreams::StoreDeltas, prelude::*};
use substreams_ethereum::{pb::eth, Event};
use tycho_substreams::{
    abi::erc20, balances::aggregate_balances_changes, contract::extract_contract_changes_builder,
    prelude::*,
};

/// Find and create all relevant protocol components
///
/// This method maps over blocks and instantiates ProtocolComponents with a unique ids
/// as well as all necessary metadata for routing and encoding.
#[substreams::handlers::map]
fn map_protocol_components(block: eth::v2::Block) -> Result<BlockTransactionProtocolComponents> {
    // TODO: add flag to emit only once
    Ok(BlockTransactionProtocolComponents {
        tx_components: block
            .transactions()
            .filter_map(|tx| {
                let components = tx
                    .logs_with_calls()
                    .filter_map(|(log, call)| {
                        pool_factories::maybe_create_component(call.call, log, tx)
                    })
                    .collect::<Vec<_>>();

                if !components.is_empty() {
                    Some(TransactionProtocolComponents { tx: Some(tx.into()), components })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>(),
    })
}

/// Stores all protocol components in a store.
///
/// Stores information about components in a key value store. This is only necessary if
/// you need to access the whole set of components within your indexing logic.
///
/// Popular use cases are:
/// - Checking if a contract belongs to a component. In this case suggest to use an address as the
///   store key so lookup operations are O(1).
/// - Tallying up relative balances changes to calcualte absolute erc20 token balances per
///   component.
///
/// Usually you can skip this step if:
/// - You are interested in a static set of components only
/// - Your protocol emits balance change events with absolute values
#[substreams::handlers::store]
fn store_protocol_components(
    map_protocol_components: BlockTransactionProtocolComponents,
    store: StoreSetRaw,
) {
    map_protocol_components
        .tx_components
        .into_iter()
        .for_each(|tx_pc| {
            tx_pc
                .components
                .into_iter()
                .for_each(|pc| {
                    // Assumes that the component id is a hex encoded contract address
                    let key = pc.id.clone();
                    // we store the components tokens
                    // TODO: proper error handling
                    let val = serde_sibor::to_bytes(&pc.tokens).unwrap();
                    store.set(0, key, &val);
                })
        });
}

/// Extracts balances per component
///
/// This template function uses ERC20 transfer events to extract balances. It
/// assumes that each component is deployed at a dedicated contract address. If a
/// transaction involving the component is detected, its balance is updated accordingly.
#[substreams::handlers::map]
pub fn map_component_balance(
    block: eth::v2::Block,
    _store: StoreGetRaw,
) -> Result<BlockChanges, substreams::errors::Error> {
    // substreams::log::println("map_component_balance");
    let mut block_entity_changes: BlockChanges =
        BlockChanges { block: Some((&block).into()), changes: vec![] };

    let mut tx_changes: HashMap<Vec<u8>, PartialChanges> = HashMap::new();

    handle_sync(&block, &mut tx_changes);

    let mut tx_entity_changes_map = HashMap::new();
    for partial_changes in tx_changes.values() {
        substreams::log::println(format!("partial_changes: {:?}", partial_changes));
        substreams::log::println(format!(
            "partial_changes_2: {:?}",
            partial_changes
                .clone()
                .consolidate_entity_changes()
        ));
        tx_entity_changes_map.insert(
            partial_changes.transaction.hash.clone(),
            TransactionChanges {
                tx: Some(partial_changes.transaction.clone()),
                contract_changes: vec![],
                entity_changes: partial_changes
                    .clone()
                    .consolidate_entity_changes(),
                balance_changes: vec![],
                component_changes: vec![],
            },
        );
    }

    block_entity_changes.changes = tx_entity_changes_map
        .into_values()
        .collect();

    Ok(block_entity_changes)
}

const STORAGE_SLOT_TOTAL_SHARES: [u8; 32] =
    hex!("e3b4b636e601189b5f4c6742edf2538ac12bb61ed03e6da26949d69838fa447e");
const STORAGE_SLOT_POOLED_ETH: [u8; 32] =
    hex!("ed310af23f61f96daefbcd140b306c0bdbf8c178398299741687b90e794772b0");
const STORAGE_SLOT_WRAPPED_ETH: [u8; 32] =
    hex!("0000000000000000000000000000000000000000000000000000000000000002");
const STORAGE_SLOT_STAKE_LIMIT: [u8; 32] =
    hex!("a3678de4a579be090bed1177e0a24f77cc29d181ac22fd7688aca344d8938015");

const ST_ETH_ADDRESS: [u8; 20] = hex!("17144556fd3424EDC8Fc8A4C940B2D04936d17eb");
const WST_ETH_ADDRESS: [u8; 20] = hex!("7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0");
const ZERO_STAKING_LIMIT: &str = "000000000000000000000000";

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
struct ComponentKey<T> {
    component_id: String,
    name: T,
}

impl<T> ComponentKey<T> {
    fn new(component_id: String, name: T) -> Self {
        ComponentKey { component_id, name }
    }
}
#[derive(Clone, Debug)]
struct PartialChanges {
    transaction: Transaction,
    entity_changes: HashMap<ComponentKey<String>, Attribute>,
}

impl PartialChanges {
    // Consolidate the entity changes into a vector of EntityChanges. Initially, the entity changes
    // are in a map to prevent duplicates. For each transaction, we need to have only one final
    // state change, per state. Example:
    // If we have two sync events for the same pool (in the same tx), we need to have only one final
    // state change for the reserves. This will be the last sync event, as it is the final state
    // of the pool after the transaction.
    fn consolidate_entity_changes(self) -> Vec<EntityChanges> {
        self.entity_changes
            .into_iter()
            .map(|(key, attribute)| (key.component_id, attribute))
            .into_group_map()
            .into_iter()
            .map(|(component_id, attributes)| EntityChanges { component_id, attributes })
            .collect()
    }
}

fn handle_sync(block: &eth::v2::Block, tx_changes: &mut HashMap<Vec<u8>, PartialChanges>) {
    for _tx in block.transactions() {
        for call in _tx.calls.iter() {
            if call.address == ST_ETH_ADDRESS {
                let mut comp_id = Hex::encode(ST_ETH_ADDRESS);
                comp_id.insert_str(0, "0x");
                let tx_change = tx_changes
                    .entry(_tx.hash.clone())
                    .or_insert_with(|| PartialChanges {
                        transaction: _tx.into(),
                        entity_changes: HashMap::new(),
                    });
                for storage_change in call.storage_changes.iter() {
                    if storage_change.key == STORAGE_SLOT_TOTAL_SHARES {
                        tx_change.entity_changes.insert(
                            ComponentKey::new(comp_id.clone(), "total_shares".to_owned()),
                            Attribute {
                                name: "total_shares".to_owned(),
                                value: storage_change.new_value.clone(),
                                change: ChangeType::Update.into(),
                            },
                        );
                    } else if storage_change.key == STORAGE_SLOT_POOLED_ETH {
                        tx_change.entity_changes.insert(
                            ComponentKey::new(comp_id.clone(), "total_pooled_eth".to_owned()),
                            Attribute {
                                name: "total_pooled_eth".to_owned(),
                                value: storage_change.new_value.clone(),
                                change: ChangeType::Update.into(),
                            },
                        );
                    } else if storage_change.key == STORAGE_SLOT_STAKE_LIMIT {
                        let stake_limit_new_hex = hex::encode(storage_change.new_value.clone());
                        let (staking_status, staking_limit) = if stake_limit_new_hex.get(0..24) ==
                            Some(ZERO_STAKING_LIMIT) &&
                            stake_limit_new_hex.get(32..56) != Some(ZERO_STAKING_LIMIT)
                        {
                            (StakingStatus::Unlimited, BigInt::zero())
                        } else if stake_limit_new_hex.get(32..56) == Some(ZERO_STAKING_LIMIT) {
                            (StakingStatus::Paused, BigInt::zero())
                        } else {
                            (
                                StakingStatus::Limited,
                                BigInt::from(
                                    num_bigint::BigInt::parse_bytes(
                                        stake_limit_new_hex
                                            .get(0..24)
                                            .unwrap()
                                            .as_bytes(),
                                        16,
                                    )
                                    .unwrap(),
                                ),
                            )
                        };

                        tx_change.entity_changes.insert(
                            ComponentKey::new(comp_id.clone(), "staking_status".to_owned()),
                            Attribute {
                                name: "staking_status".to_owned(),
                                value: staking_status.as_str_name().into(),
                                change: ChangeType::Update.into(),
                            },
                        );
                        tx_change.entity_changes.insert(
                            ComponentKey::new(comp_id.clone(), "staking_limit".to_owned()),
                            Attribute {
                                name: "staking_limit".to_owned(),
                                value: staking_limit.to_signed_bytes_be(),
                                change: ChangeType::Update.into(),
                            },
                        );
                    }
                }
            } else if call.address == WST_ETH_ADDRESS {
                let mut comp_id = Hex::encode(WST_ETH_ADDRESS);
                comp_id.insert_str(0, "0x");
                let tx_change = tx_changes
                    .entry(_tx.hash.clone())
                    .or_insert_with(|| PartialChanges {
                        transaction: _tx.into(),
                        entity_changes: HashMap::new(),
                    });
                for storage_change in call.storage_changes.iter() {
                    if storage_change.key == STORAGE_SLOT_WRAPPED_ETH {
                        tx_change.entity_changes.insert(
                            ComponentKey::new(comp_id.clone(), "total_wstETH".to_owned()),
                            Attribute {
                                name: "total_wstETH".to_owned(),
                                value: storage_change.new_value.clone(),
                                change: ChangeType::Update.into(),
                            },
                        );
                    }
                }
            }
        }
    }
}

/// Aggregates relative balances values into absolute values
///
/// Aggregate the relative balances in an additive store since tycho-indexer expects
/// absolute balance inputs.
///
/// ## Note:
/// This method should usually not require any changes.
#[substreams::handlers::store]
pub fn store_balances(deltas: BlockBalanceDeltas, store: StoreAddBigInt) {
    tycho_substreams::balances::store_balance_changes(deltas, store);
}

/// Aggregates protocol components and balance changes by transaction.
///
/// This is the main method that will aggregate all changes as well as extract all
/// relevant contract storage deltas.
///
/// ## Note:
/// You may have to change this method if your components have any default dynamic
/// attributes, or if you need any additional static contracts indexed.
#[substreams::handlers::map]
fn map_protocol_changes(
    block: eth::v2::Block,
    new_components: BlockTransactionProtocolComponents,
    components_store: StoreGetRaw,
    balance_store: StoreDeltas,
    deltas: BlockBalanceDeltas,
) -> Result<BlockChanges, substreams::errors::Error> {
    // We merge contract changes by transaction (identified by transaction index)
    // making it easy to sort them at the very end.
    let mut transaction_changes: HashMap<_, TransactionChangesBuilder> = HashMap::new();

    // Aggregate newly created components per tx
    new_components
        .tx_components
        .iter()
        .for_each(|tx_component| {
            // initialise builder if not yet present for this tx
            let tx = tx_component.tx.as_ref().unwrap();
            let builder = transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChangesBuilder::new(tx));

            // iterate over individual components created within this tx
            tx_component
                .components
                .iter()
                .for_each(|component| {
                    builder.add_protocol_component(component);
                    // TODO: In case you require to add any dynamic attributes to the
                    //  component you can do so here:
                    /*
                        builder.add_entity_change(&EntityChanges {
                            component_id: component.id.clone(),
                            attributes: default_attributes.clone(),
                        });
                    */
                });
        });

    // Aggregate absolute balances per transaction.
    aggregate_balances_changes(balance_store, deltas)
        .into_iter()
        .for_each(|(_, (tx, balances))| {
            let builder = transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChangesBuilder::new(&tx));
            balances
                .values()
                .for_each(|token_bc_map| {
                    token_bc_map
                        .values()
                        .for_each(|bc| builder.add_balance_change(bc))
                });
        });

    // Extract and insert any storage changes that happened for any of the components.
    extract_contract_changes_builder(
        &block,
        |addr| {
            // we assume that the store holds contract addresses as keys and if it
            // contains a value, that contract is of relevance.
            // TODO: if you have any additional static contracts that need to be indexed,
            //  please add them here.
            components_store
                .get_last(hex::encode(addr))
                .is_some()
        },
        &mut transaction_changes,
    );

    // Process all `transaction_changes` for final output in the `BlockChanges`,
    //  sorted by transaction index (the key).
    Ok(BlockChanges {
        block: Some((&block).into()),
        changes: transaction_changes
            .drain()
            .sorted_unstable_by_key(|(index, _)| *index)
            .filter_map(|(_, builder)| builder.build())
            .collect::<Vec<_>>(),
    })
}
