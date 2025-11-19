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
    let mut transaction_changes: HashMap<_, TransactionChangesBuilder> = HashMap::new();

    handle_sync(&block, &mut transaction_changes);

    Ok(BlockChanges {
        block: Some((&block).into()),
        changes: transaction_changes
            .drain()
            .sorted_unstable_by_key(|(index, _)| *index)
            .filter_map(|(_, builder)| builder.build())
            .collect::<Vec<_>>(),
    })
}

fn handle_sync(
    block: &eth::v2::Block,
    transaction_changes: &mut HashMap<u32, TransactionChangesBuilder>,
) {
    for tx in block.transactions() {
        for call in tx.calls.iter() {
            let builder = transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChangesBuilder::new(&(tx.into())));

            if call.address == ST_ETH_ADDRESS {
                st_eth_entity_changes(call, builder)
            } else if call.address == WST_ETH_ADDRESS {
                wst_eth_entity_changes(call, builder)
            } else {
                continue
            };
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

fn st_eth_entity_changes(call: &Call, builder: &mut TransactionChangesBuilder) {
    for storage_change in call.storage_changes.iter() {
        if storage_change.key == STORAGE_SLOT_TOTAL_SHARES {
            builder.add_entity_change(&EntityChanges {
                component_id: ST_ETH_ADDRESS_COMPONENT_ID.to_owned(),
                attributes: vec![create_entity_change(
                    "total_shares",
                    storage_change.new_value.clone(),
                )],
            });
        } else if storage_change.key == STORAGE_SLOT_POOLED_ETH {
            let attr = create_entity_change("total_pooled_eth", storage_change.new_value.clone());
            builder.add_entity_change(&EntityChanges {
                component_id: ST_ETH_ADDRESS_COMPONENT_ID.to_owned(),
                attributes: vec![attr.clone()],
            });

            builder.add_balance_change(&BalanceChange {
                    token: ETH_ADDRESS.into(),
                    balance: attr.value,
                    component_id: ETH_ADDRESS.to_vec(),
            });
        } else if storage_change.key == STORAGE_SLOT_STAKE_LIMIT {
            let (staking_status, staking_limit) = staking_status_and_limit(storage_change);

            builder.add_entity_change(&EntityChanges {
                component_id: ST_ETH_ADDRESS_COMPONENT_ID.to_owned(),
                attributes: vec![
                    create_entity_change("staking_status", staking_status.as_str_name().into()),
                    create_entity_change("staking_limit", staking_limit.to_signed_bytes_be()),
                ],
            });
        };
    }
}

fn wst_eth_entity_changes(call: &Call, builder: &mut TransactionChangesBuilder) {
    for storage_change in call.storage_changes.iter() {
        if storage_change.key == STORAGE_SLOT_WRAPPED_ETH {
            builder.add_entity_change(&EntityChanges {
                component_id: WST_ETH_ADDRESS_COMPONENT_ID.to_owned(),
                attributes: vec![create_entity_change(
                    "total_wstETH",
                    storage_change.new_value.clone(),
                )],
            });
        }
    }
}

fn create_entity_change(name: &str, value: Vec<u8>) -> Attribute {
    Attribute { name: name.to_owned(), value, change: ChangeType::Update.into() }
}
