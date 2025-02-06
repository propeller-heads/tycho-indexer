//! Template for Protocols with singleton contract
//!
//! This template provides a starting point for protocols that follow a singleton
//! pattern. Usually these protocols employ a fixed set of contracts instead of
//! deploying new contracts per component.
//!
//! ## Alternative Module
//! If your protocol uses individual contracts deployed with a factory to manage
//! components and balances, refer to the `ethereum-template-factory` substream for an
//! appropriate alternative.
//!
//! ## Warning
//! This template provides a general framework for indexing a protocol. However, it is
//! likely that you will need to adapt the steps to suit your specific use case. Use the
//! provided code with care and ensure you fully understand each step before proceeding
//! with your implementation
use crate::{pool_factories, pool_factories::DeploymentConfig};
use anyhow::Result;
use itertools::Itertools;
use prost::Message;
use std::collections::HashMap;
use substreams::{pb::substreams::StoreDeltas, prelude::*};
use substreams_ethereum::{block_view::CallView, pb::eth, Event};
use tycho_substreams::{
    balances::aggregate_balances_changes, contract::extract_contract_changes_builder, prelude::*,
};

/// Find and create all relevant protocol components
///
/// This method maps over blocks and instantiates ProtocolComponents with a unique ids
/// as well as all necessary metadata for routing and encoding.
#[substreams::handlers::map]
fn map_protocol_components(
    params: String,
    block: eth::v2::Block,
) -> Result<BlockTransactionProtocolComponents> {
    let config = serde_qs::from_str(params.as_str())?;
    Ok(BlockTransactionProtocolComponents {
        tx_components: block
            .transactions()
            .filter_map(|tx| {
                let components = tx
                    .logs_with_calls()
                    .filter_map(|(log, call)| {
                        // TODO: ensure this method is implemented correctly
                        pool_factories::maybe_create_component(call.call, log, tx, &config)
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

#[substreams::handlers::store]
fn store_protocol_tokens(
    map_protocol_components: BlockTransactionProtocolComponents,
    store: StoreSetInt64,
) {
    map_protocol_components
        .tx_components
        .into_iter()
        .for_each(|tx_pc| {
            tx_pc
                .components
                .into_iter()
                .for_each(|pc| {
                    pc.tokens.iter().for_each(|token| {
                        let token_addr_hex = hex::encode(token);
                        store.set(0, &token_addr_hex, &1);
                    })
                })
        });
}

/// Extracts balance changes per component
///
/// This template function inspects ERC20 transfer events to/from the singleton contract
/// to extract balance changes. If a transfer to the component is detected, it's
/// balanced is increased and if a balance from the component is detected its balance
/// is decreased.
///
/// ## Note:
/// - If your protocol emits events that let you calculate balance deltas more efficiently you may
///   want to use those instead of raw transfers.
/// - Changes are necessary if your protocol uses native ETH or your component burns or mints tokens
///   without emitting transfer events.
/// - You may want to ignore LP tokens if your protocol emits transfer events for these here.
#[substreams::handlers::map]
fn map_relative_component_balance(
    params: String,
    block: eth::v2::Block,
    store: StoreGetInt64,
) -> Result<BlockBalanceDeltas> {
    let config: DeploymentConfig = serde_qs::from_str(params.as_str())?;
    let res = block
        .transactions()
        .flat_map(|tx| {
            tx.logs_with_calls()
                .filter_map(|(log, call)| {
                    let token_addr_hex = hex::encode(&log.address);
                    if !store.has_last(&token_addr_hex) {
                        return None;
                    }

                    crate::abi::erc20::events::Transfer::match_and_decode(log).map(|transfer| {
                        let to_addr = transfer.to.as_slice();
                        let from_addr = transfer.from.as_slice();
                        if let Some(component_id) = extract_component_id_from_call(call) {
                            if to_addr == config.vault_address {
                                return Some(BalanceDelta {
                                    ord: log.ordinal,
                                    tx: Some(tx.into()),
                                    token: log.address.to_vec(),
                                    delta: transfer.value.to_signed_bytes_be(),
                                    component_id: component_id.encode_to_vec(),
                                });
                            } else if from_addr == config.vault_address {
                                return Some(BalanceDelta {
                                    ord: log.ordinal,
                                    tx: Some(tx.into()),
                                    token: log.address.to_vec(),
                                    delta: (transfer.value.neg()).to_signed_bytes_be(),
                                    component_id: component_id.encode_to_vec(),
                                });
                            }
                        }
                        None
                    })
                })
                .flatten()
        })
        .collect::<Vec<_>>();

    Ok(BlockBalanceDeltas { balance_deltas: res })
}

// TODO: given a relevant balance changing call associate it with the respective
//  component
fn extract_component_id_from_call(_call: CallView) -> Option<String> {
    todo!()
}

/// Aggregates relative balances values into absolute values
///
/// Aggregate the relative balances in an additive store since tycho-indexer expects
/// absolute balance inputs.
///
/// ## Note:
/// This method should usually not require any changes.
#[substreams::handlers::store]
pub fn store_component_balances(deltas: BlockBalanceDeltas, store: StoreAddBigInt) {
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
    params: String,
    block: eth::v2::Block,
    new_components: BlockTransactionProtocolComponents,
    balance_store: StoreDeltas,
    deltas: BlockBalanceDeltas,
) -> Result<BlockChanges, substreams::errors::Error> {
    let config: DeploymentConfig = serde_qs::from_str(params.as_str())?;
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
            let mut contract_changes = InterimContractChange::new(&config.vault_address, false);
            balances
                .values()
                .for_each(|token_bc_map| {
                    token_bc_map.values().for_each(|bc| {
                        // track component balance
                        builder.add_balance_change(bc);
                        // track vault contract balance
                        contract_changes
                            .upsert_token_balance(bc.token.as_slice(), bc.balance.as_slice())
                    })
                });
            builder.add_contract_changes(&contract_changes);
        });

    // Extract and insert any storage changes that happened for any of the components.
    extract_contract_changes_builder(
        &block,
        |addr| {
            // we assume that the store holds contract addresses as keys and if it
            // contains a value, that contract is of relevance.
            // TODO: if you have any additional static contracts that need to be indexed,
            //  please add them here.
            addr == config.vault_address
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
