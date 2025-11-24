use anyhow::Result;
use itertools::Itertools;
use std::collections::HashMap;
use substreams::{hex, prelude::*};
use substreams_ethereum::pb::eth::{
    self,
    v2::{Call, StorageChange},
};
use tycho_substreams::prelude::*;

use crate::{
    modules::map_protocol_components::StakingStatus, ETH_ADDRESS, ST_ETH_ADDRESS,
    ST_ETH_ADDRESS_OUTER_COMPONENT_ID, WST_ETH_ADDRESS, WST_ETH_ADDRESS_COMPONENT_ID,
};

const STORAGE_SLOT_TOTAL_SHARES: [u8; 32] =
    hex!("e3b4b636e601189b5f4c6742edf2538ac12bb61ed03e6da26949d69838fa447e");
const STORAGE_SLOT_POOLED_ETH: [u8; 32] =
    hex!("ed310af23f61f96daefbcd140b306c0bdbf8c178398299741687b90e794772b0");
const STORAGE_SLOT_WRAPPED_ETH: [u8; 32] =
    hex!("0000000000000000000000000000000000000000000000000000000000000002");
const STORAGE_SLOT_STAKE_LIMIT: [u8; 32] =
    hex!("a3678de4a579be090bed1177e0a24f77cc29d181ac22fd7688aca344d8938015");

const ZERO_STAKING_LIMIT: &str = "000000000000000000000000";

/// Extracts balances per component
///
/// This template function uses ERC20 transfer events to extract balances. It
/// assumes that each component is deployed at a dedicated contract address. If a
/// transaction involving the component is detected, its balance is updated accordingly.
#[substreams::handlers::map]
pub fn map_component_balance(
    block: eth::v2::Block,
    protocol_components: BlockTransactionProtocolComponents,
) -> Result<BlockChanges, substreams::errors::Error> {
    let mut transaction_changes: HashMap<u32, TransactionChangesBuilder> = HashMap::new();

    protocol_components
        .tx_components
        .iter()
        .for_each(|tx_component| {
            let tx = tx_component.tx.as_ref().unwrap();
            let builder = transaction_changes
                .entry(tx.index as u32)
                .or_insert_with(|| TransactionChangesBuilder::new(tx));

            tx_component
                .components
                .iter()
                .for_each(|c| {
                    builder.add_protocol_component(c);
                });
        });

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
                component_id: ST_ETH_ADDRESS_OUTER_COMPONENT_ID.to_owned(),
                attributes: vec![create_entity_change(
                    "total_shares",
                    storage_change.new_value.clone(),
                )],
            });
        } else if storage_change.key == STORAGE_SLOT_POOLED_ETH {
            let attr = create_entity_change("total_pooled_eth", storage_change.new_value.clone());
            builder.add_entity_change(&EntityChanges {
                component_id: ST_ETH_ADDRESS_OUTER_COMPONENT_ID.to_owned(),
                attributes: vec![attr.clone()],
            });

            let balance = BigInt::from_unsigned_bytes_be(&storage_change.new_value);

            // If the absolute balance is negative, we set it to zero.
            let big_endian_bytes_balance = if balance < BigInt::zero() {
                BigInt::zero().to_bytes_be().1
            } else {
                balance.to_bytes_be().1
            };

            builder.add_balance_change(&BalanceChange {
                token: ETH_ADDRESS.to_vec(),
                balance: big_endian_bytes_balance,
                component_id: ST_ETH_ADDRESS_OUTER_COMPONENT_ID
                    .as_bytes()
                    .to_vec(),
            });
        } else if storage_change.key == STORAGE_SLOT_STAKE_LIMIT {
            let (staking_status, staking_limit) = staking_status_and_limit(storage_change);

            builder.add_entity_change(&EntityChanges {
                component_id: ST_ETH_ADDRESS_OUTER_COMPONENT_ID.to_owned(),
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
