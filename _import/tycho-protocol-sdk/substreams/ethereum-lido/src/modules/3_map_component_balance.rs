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
use crate::pool_factories::StakingStatus;
use anyhow::Result;
use itertools::Itertools;
use std::collections::HashMap;
use substreams::{hex, prelude::*, Hex};
use substreams_ethereum::pb::eth;
use tycho_substreams::prelude::*;

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
