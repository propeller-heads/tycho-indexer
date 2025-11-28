use crate::{
    abi::{rocket_dao_protocol_proposal, rocket_minipool_queue, rocket_network_balances},
    constants::{
        DEPOSIT_SETTINGS_SLOTS, ETH_ADDRESS, QUEUE_END_SLOTS, QUEUE_START_SLOTS,
        QUEUE_VARIABLE_END_SLOT, ROCKET_DAO_MINIPOOL_QUEUE_ADDRESS,
        ROCKET_DAO_PROTOCOL_PROPOSAL_ADDRESS, ROCKET_NETWORK_BALANCES_ADDRESS,
        ROCKET_POOL_COMPONENT_ID, ROCKET_STORAGE_ADDRESS,
    },
    utils::get_changed_attributes,
};
use anyhow::Result;
use itertools::Itertools;
use std::collections::HashMap;
use substreams::pb::substreams::StoreDeltas;
use substreams_ethereum::{pb::eth, Event};
use tycho_substreams::{
    balances::aggregate_balances_changes,
    models::{
        BlockBalanceDeltas, BlockChanges, BlockTransactionProtocolComponents, EntityChanges,
        TransactionChangesBuilder,
    },
    prelude::BalanceChange,
};

/// Aggregates protocol component, balance and attribute changes by transaction.
///
/// This is the main method that will aggregate all changes as well as extract all
/// relevant contract storage deltas.
#[substreams::handlers::map]
fn map_protocol_changes(
    block: eth::v2::Block,
    protocol_components: BlockTransactionProtocolComponents,
    deltas: BlockBalanceDeltas,
    liquidity_store: StoreDeltas,
) -> Result<BlockChanges, substreams::errors::Error> {
    // We merge contract changes by transaction (identified by transaction index)
    // making it easy to sort them at the very end.
    let mut transaction_changes: HashMap<_, TransactionChangesBuilder> = HashMap::new();

    // Update protocol component changes per transaction.
    update_protocol_components(protocol_components, &mut transaction_changes)?;

    // Update absolute Eth balances per transaction.
    update_protocol_liquidity(deltas, liquidity_store, &mut transaction_changes);

    // Update network balance updates per transaction.
    update_network_balance(&block, &mut transaction_changes);

    // Update protocol settings updates per transaction.
    update_protocol_settings(&block, &mut transaction_changes);

    // Update minipool queue sizes per transaction.
    update_minipool_queue_sizes(&block, &mut transaction_changes);

    // Process all `transaction_changes` for final output in the `BlockChanges`,
    //  sorted by transaction index (the key).
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

/// Updates protocol liquidity changes per transaction.
fn update_protocol_liquidity(
    deltas: BlockBalanceDeltas,
    store: StoreDeltas,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    aggregate_balances_changes(store, deltas)
        .into_iter()
        .for_each(|(_, (tx, balances))| {
            let builder = transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChangesBuilder::new(&tx));

            balances
                .into_values()
                .for_each(|token_lc_map| {
                    token_lc_map
                        .into_values()
                        .for_each(|lc| {
                            builder.add_entity_change(&EntityChanges {
                                component_id: ROCKET_POOL_COMPONENT_ID.to_owned(),
                                attributes: vec![tycho_substreams::models::Attribute {
                                    name: "liquidity".to_owned(),
                                    value: lc.balance,
                                    change: tycho_substreams::models::ChangeType::Update.into(),
                                }],
                            });
                        })
                });
        });
}

/// Updates protocol component changes per transaction.
fn update_protocol_components(
    protocol_components: BlockTransactionProtocolComponents,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) -> Result<()> {
    protocol_components
        .tx_components
        .iter()
        .try_for_each(|tx_component| {
            let tx = tx_component
                .tx
                .as_ref()
                .ok_or(anyhow::anyhow!("Transaction missing in protocol components"))?;

            let builder = transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChangesBuilder::new(tx));

            for c in &tx_component.components {
                builder.add_protocol_component(c);
            }
            Ok(())
        })
}

/// Extracts Rocket Pool network balance updates from the block logs.
fn update_network_balance(
    block: &eth::v2::Block,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    for log in block.logs() {
        // If the log is not from the Rocket Network Balances contract, skip it.
        if log.log.address != ROCKET_NETWORK_BALANCES_ADDRESS {
            continue;
        }

        if let Some(balance_update) =
            rocket_network_balances::events::BalancesUpdated::match_and_decode(log)
        {
            let tx = log.receipt.transaction;

            let builder = transaction_changes
                .entry(tx.index as u64)
                .or_insert_with(|| TransactionChangesBuilder::new(&(tx.into())));

            let eth_bc = BalanceChange {
                token: ETH_ADDRESS.to_vec(),
                balance: balance_update
                    .total_eth
                    .to_signed_bytes_be(),
                component_id: ROCKET_POOL_COMPONENT_ID
                    .as_bytes()
                    .to_vec(),
            };

            let attributes = vec![
                tycho_substreams::models::Attribute {
                    name: "reth_supply".to_string(),
                    value: balance_update
                        .reth_supply
                        .to_signed_bytes_be(),
                    change: tycho_substreams::models::ChangeType::Update.into(),
                },
                tycho_substreams::models::Attribute {
                    name: "total_eth".to_string(),
                    value: balance_update
                        .total_eth
                        .to_signed_bytes_be(),
                    change: tycho_substreams::models::ChangeType::Update.into(),
                },
            ];

            builder.add_balance_change(&eth_bc);
            builder.add_entity_change(&EntityChanges {
                component_id: ROCKET_POOL_COMPONENT_ID.to_owned(),
                attributes,
            });
        }
    }
}

/// Extracts protocol settings updates from the block logs.
///
/// Note: that the protocol settings updates can only be triggered by executing DAO proposals, hence
/// it is sufficient to first check for the `ProposalExecuted` event and only then check the
/// associated storage changes.
fn update_protocol_settings(
    block: &eth::v2::Block,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    for log in block.logs() {
        // If the log is not a ProposalExecuted event from the DAO Proposal contract, skip it as no
        // protocol settings could have changed.
        if !(log.log.address != ROCKET_DAO_PROTOCOL_PROPOSAL_ADDRESS &&
            rocket_dao_protocol_proposal::events::ProposalExecuted::match_log(log.log))
        {
            continue;
        }

        let tx = log.receipt.transaction;

        let builder = transaction_changes
            .entry(tx.index as u64)
            .or_insert_with(|| TransactionChangesBuilder::new(&(tx.into())));

        let attributes = tx
            .calls
            .iter()
            .filter(|call| call.address == ROCKET_STORAGE_ADDRESS)
            .flat_map(|call| get_changed_attributes(&call.storage_changes, &DEPOSIT_SETTINGS_SLOTS))
            .collect::<Vec<_>>();

        if !attributes.is_empty() {
            builder.add_entity_change(&EntityChanges {
                component_id: ROCKET_POOL_COMPONENT_ID.to_owned(),
                attributes,
            });
        }
    }
}

/// Updates minipool queue sizes based on queue events.
///
/// Listens for MinipoolEnqueued, MinipoolDequeued, and MinipoolRemoved events from the
/// RocketMinipoolQueue contract and fetches the updated queue storage values from RocketStorage.
/// - MinipoolEnqueued: fetches the variable queue end slot (only variable queue is used now)
/// - MinipoolDequeued: fetches all queue start slots
/// - MinipoolRemoved: fetches all queue end slots
fn update_minipool_queue_sizes(
    block: &eth::v2::Block,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    for log in block.logs() {
        // Only process events from the RocketMinipoolQueue contract
        if log.log.address != ROCKET_DAO_MINIPOOL_QUEUE_ADDRESS {
            continue;
        }

        let tx = log.receipt.transaction;

        // Determine which storage slots to check based on the event type
        let storage_slots: &[_] =
            if rocket_minipool_queue::events::MinipoolEnqueued::match_log(log.log) {
                // MinipoolEnqueued: fetch the variable queue end slot
                &[QUEUE_VARIABLE_END_SLOT]
            } else if rocket_minipool_queue::events::MinipoolDequeued::match_log(log.log) {
                // MinipoolDequeued: fetch all start slots
                &QUEUE_START_SLOTS
            } else if rocket_minipool_queue::events::MinipoolRemoved::match_log(log.log) {
                // MinipoolRemoved: fetch all end slots
                &QUEUE_END_SLOTS
            } else {
                continue;
            };

        // Extract changed attributes from RocketStorage contract storage changes
        let attributes = tx
            .calls
            .iter()
            .filter(|call| call.address == ROCKET_STORAGE_ADDRESS)
            .flat_map(|call| get_changed_attributes(&call.storage_changes, storage_slots))
            .collect::<Vec<_>>();

        if !attributes.is_empty() {
            let builder = transaction_changes
                .entry(tx.index as u64)
                .or_insert_with(|| TransactionChangesBuilder::new(&(tx.into())));

            builder.add_entity_change(&EntityChanges {
                component_id: ROCKET_POOL_COMPONENT_ID.to_owned(),
                attributes,
            });
        }
    }
}
