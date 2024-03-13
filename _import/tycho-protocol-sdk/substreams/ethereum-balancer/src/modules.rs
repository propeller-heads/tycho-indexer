use crate::{abi, pool_factories};
use anyhow::Result;
use itertools::Itertools;
use std::collections::HashMap;
use substreams::hex;
use substreams::pb::substreams::StoreDeltas;
use substreams::store::{
    StoreAdd, StoreAddBigInt, StoreAddInt64, StoreGet, StoreGetInt64, StoreNew,
};
use substreams_ethereum::pb::eth;
use substreams_ethereum::Event;
use tycho_substreams::balances;
use tycho_substreams::contract::extract_contract_changes;
use tycho_substreams::pb::tycho::evm::v1::{
    self as tycho, BalanceDelta, BlockBalanceDeltas, BlockTransactionProtocolComponents,
    TransactionProtocolComponents,
};

const VAULT_ADDRESS: &[u8] = &hex!("BA12222222228d8Ba445958a75a0704d566BF2C8");

/// This struct purely exists to spoof the `PartialEq` trait for `Transaction` so we can use it in
///  a later groupby operation.
#[derive(Debug)]
struct TransactionWrapper(tycho::Transaction);

impl PartialEq for TransactionWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.0.hash == other.0.hash
    }
}

#[substreams::handlers::map]
pub fn map_pools_created(block: eth::v2::Block) -> Result<BlockTransactionProtocolComponents> {
    // Gather contract changes by indexing `PoolCreated` events and analysing the `Create` call
    // We store these as a hashmap by tx hash since we need to agg by tx hash later
    Ok(BlockTransactionProtocolComponents {
        tx_components: block
            .transactions()
            .filter_map(|tx| {
                let components = tx
                    .logs_with_calls()
                    .filter(|(_, call)| !call.call.state_reverted)
                    .filter_map(|(log, call)| {
                        pool_factories::address_map(
                            call.call.address.as_slice(),
                            log,
                            call.call,
                            &tycho::Transaction {
                                hash: tx.hash.clone(),
                                from: tx.from.clone(),
                                to: tx.to.clone(),
                                index: tx.index.into(),
                            },
                        )
                    })
                    .collect::<Vec<_>>();

                if !components.is_empty() {
                    Some(TransactionProtocolComponents {
                        tx: Some(tycho::Transaction {
                            hash: tx.hash.clone(),
                            from: tx.from.clone(),
                            to: tx.to.clone(),
                            index: Into::<u64>::into(tx.index),
                        }),
                        components,
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>(),
    })
}

/// Simply stores the `ProtocolComponent`s with the pool id as the key
#[substreams::handlers::store]
pub fn store_pools_created(map: BlockTransactionProtocolComponents, store: StoreAddInt64) {
    store.add_many(
        0,
        &map.tx_components
            .iter()
            .flat_map(|tx_components| &tx_components.components)
            .map(|component| format!("pool:{0}", component.id))
            .collect::<Vec<_>>(),
        1,
    );
}

/// Since the `PoolBalanceChanged` and `Swap` events administer only deltas, we need to leverage a map and a
///  store to be able to tally up final balances for tokens in a pool.
#[substreams::handlers::map]
pub fn map_balance_deltas(
    block: eth::v2::Block,
    store: StoreGetInt64,
) -> Result<BlockBalanceDeltas, anyhow::Error> {
    let balance_deltas = block
        .logs()
        .filter(|log| log.address() == VAULT_ADDRESS)
        .flat_map(|vault_log| {
            let mut deltas = Vec::new();

            if let Some(ev) =
                abi::vault::events::PoolBalanceChanged::match_and_decode(vault_log.log)
            {
                let component_id = format!(
                    "0x{}",
                    String::from_utf8(ev.pool_id[..20].to_vec()).unwrap()
                )
                .as_bytes()
                .to_vec();

                if store
                    .get_last(format!("pool:{}", hex::encode(&component_id)))
                    .is_some()
                {
                    for (token, delta) in ev.tokens.iter().zip(ev.deltas.iter()) {
                        deltas.push(BalanceDelta {
                            ord: vault_log.ordinal(),
                            tx: Some(tycho::Transaction {
                                hash: vault_log.receipt.transaction.hash.clone(),
                                from: vault_log.receipt.transaction.from.clone(),
                                to: vault_log.receipt.transaction.to.clone(),
                                index: vault_log.receipt.transaction.index.into(),
                            }),
                            token: token.to_vec(),
                            delta: delta.to_signed_bytes_be(),
                            component_id: component_id.clone(),
                        });
                    }
                }
            } else if let Some(ev) = abi::vault::events::Swap::match_and_decode(vault_log.log) {
                let component_id = format!(
                    "0x{}",
                    String::from_utf8(ev.pool_id[..20].to_vec()).unwrap()
                )
                .as_bytes()
                .to_vec();

                if store
                    .get_last(format!("pool:{}", hex::encode(&component_id)))
                    .is_some()
                {
                    deltas.extend_from_slice(&[
                        BalanceDelta {
                            ord: vault_log.ordinal(),
                            tx: Some(tycho::Transaction {
                                hash: vault_log.receipt.transaction.hash.clone(),
                                from: vault_log.receipt.transaction.from.clone(),
                                to: vault_log.receipt.transaction.to.clone(),
                                index: vault_log.receipt.transaction.index.into(),
                            }),
                            token: ev.token_in.to_vec(),
                            delta: ev.amount_in.to_signed_bytes_be(),
                            component_id: component_id.clone(),
                        },
                        BalanceDelta {
                            ord: vault_log.ordinal(),
                            tx: Some(tycho::Transaction {
                                hash: vault_log.receipt.transaction.hash.clone(),
                                from: vault_log.receipt.transaction.from.clone(),
                                to: vault_log.receipt.transaction.to.clone(),
                                index: vault_log.receipt.transaction.index.into(),
                            }),
                            token: ev.token_out.to_vec(),
                            delta: ev.amount_out.neg().to_signed_bytes_be(),
                            component_id,
                        },
                    ]);
                }
            }

            deltas
        })
        .collect::<Vec<_>>();

    Ok(BlockBalanceDeltas { balance_deltas })
}

/// It's significant to include both the `pool_id` and the `token_id` for each balance delta as the
///  store key to ensure that there's a unique balance being tallied for each.
#[substreams::handlers::store]
pub fn store_balance_changes(deltas: BlockBalanceDeltas, store: StoreAddBigInt) {
    balances::store_balance_changes(deltas, store);
}

/// This is the main map that handles most of the indexing of this substream.
/// Every contract change is grouped by transaction index via the `transaction_contract_changes`
///  map. Each block of code will extend the `TransactionContractChanges` struct with the
///  cooresponding changes (balance, component, contract), inserting a new one if it doesn't exist.
///  At the very end, the map can easily be sorted by index to ensure the final `BlockContractChanges`
///  is ordered by transactions properly.
#[substreams::handlers::map]
pub fn map_changes(
    block: eth::v2::Block,
    grouped_components: BlockTransactionProtocolComponents,
    deltas: BlockBalanceDeltas,
    components_store: StoreGetInt64,
    balance_store: StoreDeltas, // Note, this map module is using the `deltas` mode for the store.
) -> Result<tycho::BlockContractChanges> {
    // We merge contract changes by transaction (identified by transaction index) making it easy to
    //  sort them at the very end.
    let mut transaction_contract_changes: HashMap<_, tycho::TransactionContractChanges> =
        HashMap::new();

    // `ProtocolComponents` are gathered from `map_pools_created` which just need a bit of work to
    //   convert into `TransactionContractChanges`
    grouped_components
        .tx_components
        .iter()
        .for_each(|tx_component| {
            let tx = tx_component.tx.as_ref().unwrap();
            transaction_contract_changes
                .entry(tx.index)
                .or_insert_with(|| tycho::TransactionContractChanges::new(&tx))
                .component_changes
                .extend_from_slice(&tx_component.components);
        });

    // Balance changes are gathered by the `StoreDelta` based on `PoolBalanceChanged` creating
    //  `BlockBalanceDeltas`. We essentially just process the changes that occurred to the `store` this
    //  block. Then, these balance changes are merged onto the existing map of tx contract changes,
    //  inserting a new one if it doesn't exist.
    balances::aggregate_balances_changes(balance_store, deltas)
        .into_iter()
        .for_each(|(_, (tx, balances))| {
            transaction_contract_changes
                .entry(tx.index)
                .or_insert_with(|| tycho::TransactionContractChanges::new(&tx))
                .balance_changes
                .extend(balances.into_iter().map(|(_, change)| change));
        });

    // Extract and insert any storage changes that happened for any of the components.
    extract_contract_changes(
        &block,
        |addr| {
            components_store
                .get_last(format!("pool:{0}", hex::encode(&addr)))
                .is_some()
        },
        &mut transaction_contract_changes,
    );

    // Process all `transaction_contract_changes` for final output in the `BlockContractChanges`,
    //  sorted by transaction index (the key).
    Ok(tycho::BlockContractChanges {
        block: Some(tycho::Block {
            number: block.number,
            hash: block.hash.clone(),
            parent_hash: block
                .header
                .as_ref()
                .expect("Block header not present")
                .parent_hash
                .clone(),
            ts: block.timestamp_seconds(),
        }),
        changes: transaction_contract_changes
            .drain()
            .sorted_unstable_by_key(|(index, _)| *index)
            .filter_map(|(_, change)| {
                if change.contract_changes.is_empty()
                    && change.component_changes.is_empty()
                    && change.balance_changes.is_empty()
                {
                    None
                } else {
                    Some(change)
                }
            })
            .collect::<Vec<_>>(),
    })
}
