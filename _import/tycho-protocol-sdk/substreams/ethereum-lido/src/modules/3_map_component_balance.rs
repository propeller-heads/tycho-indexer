use crate::pool_factories::StakingStatus;
use anyhow::Result;
use itertools::Itertools;
use std::collections::HashMap;
use substreams::{hex, prelude::*};
use substreams_ethereum::pb::eth::{
    self,
    v2::{Call, StorageChange},
};
use tycho_substreams::prelude::*;

use crate::modules::map_protocol_components::StakingStatus;

const STORAGE_SLOT_TOTAL_SHARES: [u8; 32] =
    hex!("e3b4b636e601189b5f4c6742edf2538ac12bb61ed03e6da26949d69838fa447e");
const STORAGE_SLOT_POOLED_ETH: [u8; 32] =
    hex!("ed310af23f61f96daefbcd140b306c0bdbf8c178398299741687b90e794772b0");
const STORAGE_SLOT_WRAPPED_ETH: [u8; 32] =
    hex!("0000000000000000000000000000000000000000000000000000000000000002");
const STORAGE_SLOT_STAKE_LIMIT: [u8; 32] =
    hex!("a3678de4a579be090bed1177e0a24f77cc29d181ac22fd7688aca344d8938015");

pub const ST_ETH_ADDRESS: [u8; 20] = hex!("17144556fd3424EDC8Fc8A4C940B2D04936d17eb");
const ST_ETH_ADDRESS_COMPONENT_ID: &str = "0x17144556fd3424edc8fc8a4c940b2d04936d17eb";
pub const WST_ETH_ADDRESS: [u8; 20] = hex!("7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0");
const WST_ETH_ADDRESS_COMPONENT_ID: &str = "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0";
const ZERO_STAKING_LIMIT: &str = "000000000000000000000000";
pub const ETH_ADDRESS: [u8; 20] = hex!("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE");
const ETH_ADDRESS_COMPONENT_ID: &str = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";

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
    let mut block_entity_changes: BlockChanges =
        BlockChanges { block: Some((&block).into()), changes: vec![] };

    let mut tx_changes: HashMap<Vec<u8>, PartialChanges> = HashMap::new();

    handle_sync(&block, &mut tx_changes);

    let mut tx_entity_changes_map = HashMap::new();

    for partial_changes in tx_changes.values() {
        tx_entity_changes_map.insert(
            partial_changes.transaction.hash.clone(),
            TransactionChanges {
                tx: Some(partial_changes.transaction.clone()),
                contract_changes: vec![],
                entity_changes: partial_changes
                    .clone()
                    .consolidate_entity_changes(),
                balance_changes: partial_changes
                    .clone()
                    .consolidate_balance_changes(),
                component_changes: vec![],
            },
        );
    }

    block_entity_changes.changes = tx_entity_changes_map
        .into_values()
        .collect();

    Ok(block_entity_changes)
}

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
    balance_changes: HashMap<ComponentKey<Vec<u8>>, BalanceChange>,
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

    fn consolidate_balance_changes(self) -> Vec<BalanceChange> {
        self.balance_changes
            .into_iter()
            .map(|(key, attribute)| (key.component_id, attribute))
            .into_group_map()
            .into_iter()
            .flat_map(|(_, attributes)| attributes)
            .collect()
    }
}

fn handle_sync(block: &eth::v2::Block, tx_changes: &mut HashMap<Vec<u8>, PartialChanges>) {
    for tx in block.transactions() {
        for call in tx.calls.iter() {
            let (entity_changes, balance_changes) = if call.address == ST_ETH_ADDRESS {
                st_eth_entity_changes(call)
            } else if call.address == WST_ETH_ADDRESS {
                (wst_eth_entity_changes(call), HashMap::new())
            } else {
                (HashMap::new(), HashMap::new())
            };

            if entity_changes.is_empty() {
                continue;
            }

            let tx_change = tx_changes
                .entry(tx.hash.clone())
                .or_insert_with(|| PartialChanges {
                    transaction: tx.into(),
                    entity_changes: HashMap::new(),
                    balance_changes: HashMap::new(),
                });

            tx_change
                .entity_changes
                .extend(entity_changes);

            tx_change
                .balance_changes
                .extend(balance_changes);
        }
    }
}

fn staking_status_and_limit(storage_change: &StorageChange) -> (StakingStatus, BigInt) {
    let stake_limit_new_hex = hex::encode(storage_change.new_value.clone());
    if stake_limit_new_hex.get(0..24) == Some(ZERO_STAKING_LIMIT) &&
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
    }
}

fn st_eth_entity_changes(
    call: &Call,
) -> (HashMap<ComponentKey<String>, Attribute>, HashMap<ComponentKey<Vec<u8>>, BalanceChange>) {
    let mut entity_changes: HashMap<ComponentKey<String>, Attribute> = HashMap::new();

    let mut balance_changes = HashMap::new();

    for storage_change in call.storage_changes.iter() {
        if storage_change.key == STORAGE_SLOT_TOTAL_SHARES {
            let (key, attr) =
                create_entity_change("total_shares", storage_change.new_value.clone(), false);
            entity_changes.insert(key, attr);
        } else if storage_change.key == STORAGE_SLOT_POOLED_ETH {
            let (key, attr) =
                create_entity_change("total_pooled_eth", storage_change.new_value.clone(), false);

            entity_changes.insert(key, attr.clone());

            balance_changes.insert(
                ComponentKey::new(
                    ETH_ADDRESS_COMPONENT_ID.to_owned(),
                    "total_pooled_eth".as_bytes().to_owned(),
                ),
                BalanceChange {
                    token: ETH_ADDRESS.into(),
                    balance: attr.value,
                    component_id: ETH_ADDRESS.to_vec(),
                },
            );
        } else if storage_change.key == STORAGE_SLOT_STAKE_LIMIT {
            let (staking_status, staking_limit) = staking_status_and_limit(storage_change);
            let (key, attr) =
                create_entity_change("staking_status", staking_status.as_str_name().into(), false);
            entity_changes.insert(key, attr);
            let (key, attr) =
                create_entity_change("staking_limit", staking_limit.to_signed_bytes_be(), false);
            entity_changes.insert(key, attr);
        };
    }
    (entity_changes, balance_changes)
}

fn wst_eth_entity_changes(call: &Call) -> HashMap<ComponentKey<String>, Attribute> {
    let mut entity_changes: HashMap<ComponentKey<String>, Attribute> = HashMap::new();
    for storage_change in call.storage_changes.iter() {
        if storage_change.key == STORAGE_SLOT_WRAPPED_ETH {
            let (key, attr) =
                create_entity_change("total_wstETH", storage_change.new_value.clone(), true);
            entity_changes.insert(key, attr);
        }
    }
    entity_changes
}

fn create_entity_change(
    name: &str,
    value: Vec<u8>,
    wrapped: bool,
) -> (ComponentKey<String>, Attribute) {
    (
        ComponentKey::new(
            if wrapped { WST_ETH_ADDRESS_COMPONENT_ID } else { ST_ETH_ADDRESS_COMPONENT_ID }
                .to_owned(),
            name.to_owned(),
        ),
        Attribute { name: name.to_owned(), value, change: ChangeType::Update.into() },
    )
}
