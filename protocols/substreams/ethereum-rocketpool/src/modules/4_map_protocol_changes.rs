use crate::{
    abi::{rocket_dao_protocol_proposal, rocket_network_balances},
    constants::{
        ROCKET_DAO_PROTOCOL_PROPOSAL_ADDRESS, ROCKET_DAO_PROTOCOL_SETTINGS_DEPOSIT_ADDRESS,
        ROCKET_NETWORK_BALANCES_ADDRESS, ROCKET_POOL_COMPONENT_ID, TRACKED_STORAGE_LOCATIONS,
    },
    utils::get_changed_attributes,
};
use itertools::Itertools;
use std::collections::HashMap;
use substreams::{errors::Error, pb::substreams::StoreDeltas};
use substreams_ethereum::{pb::eth, Event};
use tycho_substreams::{
    balances::aggregate_balances_changes,
    models::{
        BlockBalanceDeltas, BlockChanges, BlockTransactionProtocolComponents, EntityChanges,
        TransactionChangesBuilder,
    },
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
    balance_store: StoreDeltas,
) -> Result<BlockChanges, substreams::errors::Error> {
    // We merge contract changes by transaction (identified by transaction index)
    // making it easy to sort them at the very end.
    let mut transaction_changes: HashMap<_, TransactionChangesBuilder> = HashMap::new();

    // Update protocol component changes per transaction.
    update_protocol_components(protocol_components, &mut transaction_changes)?;

    // Update absolute Eth balances per transaction.
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

    // Update network balance updates per transaction.
    update_network_balance(&block, &mut transaction_changes);

    // Update protocol settings updates per transaction.
    update_protocol_settings(&block, &mut transaction_changes);

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

/// Updates protocol component changes per transaction.
fn update_protocol_components(
    protocol_components: BlockTransactionProtocolComponents,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) -> Result<(), Error> {
    protocol_components
        .tx_components
        .iter()
        .map(|tx_component| {
            let tx = tx_component
                .tx
                .as_ref()
                .ok_or(anyhow::anyhow!("Transaction missing in protocol components"))?;

            let builder = transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChangesBuilder::new(tx));

            tx_component
                .components
                .iter()
                .for_each(|c| {
                    builder.add_protocol_component(c);
                });

            Ok::<_, substreams::errors::Error>(())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(())
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
        if !rocket_dao_protocol_proposal::events::ProposalExecuted::match_log(log.log) ||
            log.log.address != ROCKET_DAO_PROTOCOL_PROPOSAL_ADDRESS
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
            .filter(|call| call.address == ROCKET_DAO_PROTOCOL_SETTINGS_DEPOSIT_ADDRESS)
            .flat_map(|call| {
                get_changed_attributes(&call.storage_changes, &TRACKED_STORAGE_LOCATIONS)
            })
            .collect::<Vec<_>>();

        if !attributes.is_empty() {
            builder.add_entity_change(&EntityChanges {
                component_id: ROCKET_POOL_COMPONENT_ID.to_owned(),
                attributes,
            });
        }
    }
}
