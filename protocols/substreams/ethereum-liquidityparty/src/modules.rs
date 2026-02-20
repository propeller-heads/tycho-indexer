use crate::params::{decode_addrs, encode_addr, encode_addrs, Params};
use crate::{contract_bytecode, pool_factories};
use anyhow::Result;
use std::collections::HashMap;
use substreams::{pb::substreams::StoreDeltas, prelude::*};
use substreams_ethereum::{pb::eth, Event};
use tycho_substreams::abi::erc20;
use tycho_substreams::{
    balances::aggregate_balances_changes, contract::extract_contract_changes_builder, prelude::*,
};

/// Find and create all relevant protocol components
///
/// This method maps over blocks and instantiates ProtocolComponents with a unique ids
/// as well as all necessary metadata for routing and encoding.
#[substreams::handlers::map]
fn map_protocol_components(
    param_string: String,
    block: eth::v2::Block,
) -> Result<BlockTransactionProtocolComponents> {
    let params = Params::parse(&param_string)?;
    Ok(BlockTransactionProtocolComponents {
        tx_components: block
            .transactions()
            .filter_map(|tx| {
                let components = tx
                    .logs_with_calls()
                    .filter_map(|(log, call)| {
                        pool_factories::maybe_create_component(&params, call.call, log, tx)
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
                    let val = encode_addrs(&pc.tokens);
                    store.set(0, key, &val);
                })
        });
}

/// Extracts balance changes per component
///
/// This template function uses ERC20 transfer events to extract balance changes. It
/// assumes that each component is deployed at a dedicated contract address. If a
/// transfer to the component is detected, its balance is increased and if a transfer
/// from the component is detected its balance is decreased.
///
/// ## Note:
/// Changes are necessary if your protocol uses native ETH, uses a vault contract or if
/// your component burn or mint tokens without emitting transfer events.
///
/// You may want to ignore LP tokens if your protocol emits transfer events for these
/// here.
#[substreams::handlers::map]
fn map_relative_component_balance(
    block: eth::v2::Block,
    store: StoreGetString,
) -> Result<BlockBalanceDeltas, anyhow::Error> {
    let res = block
        .logs()
        .filter_map(|log| {
            erc20::events::Transfer::match_and_decode(log).map(|transfer| {
                let to_addr = encode_addr(transfer.to.as_slice());
                let from_addr = encode_addr(transfer.from.as_slice());
                let tx = log.receipt.transaction;
                if let Some(val) = store.get_last(&to_addr) {
                    let component_tokens: Vec<Vec<u8>> = decode_addrs(&val).unwrap();
                    if component_tokens.contains(&log.address().to_vec()) {
                        return Some(BalanceDelta {
                            ord: log.ordinal(),
                            tx: Some(tx.into()),
                            token: log.address().to_vec(),
                            delta: transfer.value.to_signed_bytes_be(),
                            component_id: to_addr.as_bytes().to_vec(),
                        });
                    }
                } else if let Some(val) = store.get_last(&from_addr) {
                    let component_tokens: Vec<Vec<u8>> = decode_addrs(&val).unwrap();
                    if component_tokens.contains(&log.address().to_vec()) {
                        return Some(BalanceDelta {
                            ord: log.ordinal(),
                            tx: Some(tx.into()),
                            token: log.address().to_vec(),
                            delta: (transfer.value.neg()).to_signed_bytes_be(),
                            component_id: from_addr.as_bytes().to_vec(),
                        });
                    }
                }
                None
            })
        })
        .flatten()
        .collect::<Vec<_>>();

    Ok(BlockBalanceDeltas { balance_deltas: res })
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
    param_string: String,
    block: eth::v2::Block,
    new_components: BlockTransactionProtocolComponents,
    deltas: BlockBalanceDeltas,
    components_store: StoreGetString,
    balance_store: StoreDeltas, // Note, this map module is using the `deltas` mode for the store.
) -> Result<BlockChanges> {
    let params = Params::parse(&param_string)?;

    // We merge contract changes by transaction (identified by transaction index)
    // making it easy to sort them at the very end.
    let mut transaction_changes: HashMap<_, TransactionChangesBuilder> = HashMap::new();

    // Emit the bytecode for pool implementation contracts in the first block.
    // NOTE: I tried setting components in the ProtocolComponent and also sending entrypoints, but
    // always received an error when the block tried to flush to DB that the Account was missing
    // for an implementation contract. Our pool creation transaction is also the transaction that
    // funds the pool, so maybe there is a race condition on the creation of the Accounts?
    // As a workaround, we hardcoded the deployed bytecode into contract_bytecode.rs and emit the
    // contract update explicitly on the first discovery of any pool creation.
    if block.number == params.start_block {
        // Get the first transaction to attach the impl contracts to
        if new_components.tx_components.is_empty() {
            return Err(anyhow::anyhow!(
                "No new components found in start block {}. At least one pool must be created in \
                the start block to emit implementation contract bytecode.",
                params.start_block
            ));
        }
        if let Some(first_tx_component) = new_components.tx_components.first() {
            let tx = first_tx_component.tx.as_ref().unwrap();
            let builder = transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChangesBuilder::new(tx));

            // Add extra contracts
            for (address, bytecode) in contract_bytecode::LIQP_EXTRA_CONTRACTS.iter() {
                let mut contract_change = InterimContractChange::new(address, true);
                contract_change.set_code(bytecode);
                builder.add_contract_changes(&contract_change);
            }
        }
    }

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
            let addr_str = encode_addr(addr);
            // we assume that the store holds contract addresses as keys and if it
            // contains a value, that contract is of relevance.
            components_store
                .get_last(addr_str)
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
            .filter_map(|(_, builder)| builder.build())
            .collect::<Vec<_>>(),
        storage_changes: vec![],
    })
}
