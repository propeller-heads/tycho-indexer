use crate::{
    abi::weeth::functions::{Unwrap, Wrap, WrapWithPermit},
    consts::{
        EETH_ADDRESS, ETH_ADDRESS, LIQUIDITY_POOL_ADDRESS, LIQUIDITY_POOL_CREATION_BLOCK,
        LIQUIDITY_POOL_CREATION_TX, REDEMPTION_MANAGER_ADDRESS, WEETH_ADDRESS,
        WEETH_CREATION_BLOCK, WEETH_CREATION_TX,
    },
    storage::{get_changed_attributes, EETH_POOL_TRACKED_SLOTS, WEETH_POOL_TRACKED_SLOTS},
};
use anyhow::{Ok, Result};
use itertools::Itertools;
use std::collections::HashMap;
use substreams::{pb::substreams::StoreDeltas, prelude::*};
use substreams_ethereum::{
    pb::eth::{
        self,
        v2::{StorageChange, TransactionTrace},
    },
    Function,
};
use substreams_helper::hex::Hexable;
use tycho_substreams::{
    balances::aggregate_balances_changes, block_storage::get_block_storage_changes, prelude::*,
};

/// Find and create all relevant protocol components
///
/// This method maps over blocks and instantiates ProtocolComponents with a unique ids
/// as well as all necessary metadata for routing and encoding.
#[substreams::handlers::map]
fn map_protocol_components(block: eth::v2::Block) -> Result<BlockChanges> {
    let mut new_pools: Vec<TransactionChanges> = vec![];
    if block.number == WEETH_CREATION_BLOCK {
        if let Some(tx) = block
            .transactions()
            .find(|tx| tx.hash == WEETH_CREATION_TX)
        {
            new_pools.push(TransactionChanges {
                tx: Some(tx.into()),
                entity_changes: vec![EntityChanges {
                    component_id: format!("0x{}", hex::encode(WEETH_ADDRESS)),
                    attributes: vec![
                        Attribute {
                            name: "totalValueOutOfLp".to_string(),
                            value: BigInt::from(0).to_signed_bytes_be(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "totalValueInLp".to_string(),
                            value: BigInt::from(0).to_signed_bytes_be(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "totalShares".to_string(),
                            value: BigInt::from(0).to_signed_bytes_be(),
                            change: ChangeType::Creation.into(),
                        },
                    ],
                }],
                component_changes: vec![ProtocolComponent {
                    id: format!("0x{}", hex::encode(WEETH_ADDRESS)),
                    tokens: vec![WEETH_ADDRESS.into(), EETH_ADDRESS.into()],
                    contracts: vec![],
                    static_att: vec![],
                    change: ChangeType::Creation.into(),
                    protocol_type: Some(ProtocolType {
                        name: "ethereum_etherfi_pool".into(),
                        financial_type: FinancialType::Swap.into(),
                        attribute_schema: Vec::new(),
                        implementation_type: ImplementationType::Custom.into(),
                    }),
                }],
                ..Default::default()
            });
        }
    }
    if block.number == LIQUIDITY_POOL_CREATION_BLOCK {
        if let Some(tx) = block
            .transactions()
            .find(|tx| tx.hash == LIQUIDITY_POOL_CREATION_TX)
        {
            new_pools.push(TransactionChanges {
                tx: Some(tx.into()),
                entity_changes: vec![EntityChanges {
                    component_id: format!("0x{}", hex::encode(EETH_ADDRESS)),
                    attributes: vec![
                        Attribute {
                            name: "totalValueOutOfLp".to_string(),
                            value: BigInt::from(0).to_signed_bytes_be(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "totalValueInLp".to_string(),
                            value: BigInt::from(0).to_signed_bytes_be(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "totalShares".to_string(),
                            value: BigInt::from(0).to_signed_bytes_be(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "ethAmountLockedForWithdrawl".to_string(),
                            value: BigInt::from(0).to_signed_bytes_be(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "liquidityPoolNativeBalance".to_string(),
                            value: BigInt::from(0).to_signed_bytes_be(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "ethRedemptionInfo".to_string(),
                            value: BigInt::from(0).to_signed_bytes_be(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "ethBucketLimiter".to_string(),
                            value: BigInt::from(0).to_signed_bytes_be(),
                            change: ChangeType::Creation.into(),
                        },
                    ],
                }],
                component_changes: vec![ProtocolComponent {
                    id: format!("0x{}", hex::encode(EETH_ADDRESS)),
                    tokens: vec![EETH_ADDRESS.into(), ETH_ADDRESS.into()],
                    contracts: vec![],
                    static_att: vec![],
                    change: ChangeType::Creation.into(),
                    protocol_type: Some(ProtocolType {
                        name: "ethereum_etherfi_pool".into(),
                        financial_type: FinancialType::Swap.into(),
                        attribute_schema: Vec::new(),
                        implementation_type: ImplementationType::Custom.into(),
                    }),
                }],
                ..Default::default()
            });
        }
    }
    Ok(BlockChanges { block: Some((&block).into()), changes: new_pools, ..Default::default() })
}

/// Simply stores the `ProtocolComponent`s with the pool address as the key and the pool id as value
#[substreams::handlers::store]
pub fn store_components(changes: BlockChanges, store: StoreSetString) {
    changes
        .changes
        .into_iter()
        .for_each(|change| {
            change
                .component_changes
                .into_iter()
                .for_each(|pc| store.set(0, pc.id.clone(), &pc.id))
        });
}

#[substreams::handlers::map]
fn map_relative_balances(
    block: eth::v2::Block,
    components_store: StoreGetString,
) -> Result<BlockBalanceDeltas> {
    let mut deltas: Vec<BalanceDelta> = block
        .transactions()
        .flat_map(|tx| {
            let mut tx_balance_deltas = vec![];
            if components_store
                .get_last(format!("0x{}", hex::encode(WEETH_ADDRESS)))
                .is_some()
            {
                tx_balance_deltas.extend(emit_balance_deltas_for_weeth(tx));
            }
            if components_store
                .get_last(format!("0x{}", hex::encode(EETH_ADDRESS)))
                .is_some()
            {
                tx_balance_deltas.extend(emit_balance_deltas_for_eeth(tx));
            }
            tx_balance_deltas
        })
        .collect();
    // Keep it consistent with how it's inserted in the store. This step is important
    // because we use a zip on the store deltas and balance deltas later.
    deltas.sort_unstable_by_key(|a| a.ord);
    Ok(BlockBalanceDeltas { balance_deltas: deltas })
}

fn emit_balance_deltas_for_weeth(tx_trace: &TransactionTrace) -> Vec<BalanceDelta> {
    // tokens: eETH and weETH, but we only track eeth balance here for accurate pool tvl
    // decode function calls:
    //  weETH.wrap, weETH.wrapWithPermit: eeth+
    //  weETH.unwrap: eeth-
    let mut deltas = vec![];
    for call in tx_trace
        .calls()
        .filter(|call| !call.call.state_reverted && call.call.address == WEETH_ADDRESS)
    {
        if let Some(wrap) = Wrap::match_and_decode(call) {
            deltas.push(BalanceDelta {
                ord: call.call.end_ordinal,
                tx: Some(tx_trace.into()),
                token: EETH_ADDRESS.to_vec(),
                delta: wrap.e_eth_amount.to_signed_bytes_be(),
                component_id: WEETH_ADDRESS
                    .to_hex()
                    .as_bytes()
                    .to_vec(),
            });
        }
        if let Some(wrap) = WrapWithPermit::match_and_decode(call) {
            deltas.push(BalanceDelta {
                ord: call.call.end_ordinal,
                tx: Some(tx_trace.into()),
                token: EETH_ADDRESS.to_vec(),
                delta: wrap.e_eth_amount.to_signed_bytes_be(),
                component_id: WEETH_ADDRESS
                    .to_hex()
                    .as_bytes()
                    .to_vec(),
            });
        }
        if Unwrap::match_and_decode(call).is_some() {
            let eeth_amount = Unwrap::output_call(call.call).expect("Failed to decode unwrap call");
            deltas.push(BalanceDelta {
                ord: call.call.end_ordinal,
                tx: Some(tx_trace.into()),
                token: EETH_ADDRESS.to_vec(),
                delta: eeth_amount.neg().to_signed_bytes_be(),
                component_id: WEETH_ADDRESS
                    .to_hex()
                    .as_bytes()
                    .to_vec(),
            });
        }
    }
    deltas
}

fn emit_balance_deltas_for_eeth(tx_trace: &TransactionTrace) -> Vec<BalanceDelta> {
    // tokens: eeth and eth, we only track eth balance here
    // liquidityPool.deposit: eth+
    // redemptionManager.redeemEEth: eth-
    let mut deltas = vec![];
    for call in tx_trace
        .calls()
        .filter(|call| !call.call.state_reverted)
    {
        for balance_change in &call.call.balance_changes {
            if balance_change.address == LIQUIDITY_POOL_ADDRESS.to_vec() {
                let delta = BigInt::from_unsigned_bytes_be(
                    &balance_change
                        .new_value
                        .clone()
                        .unwrap_or_default()
                        .bytes,
                ) - BigInt::from_unsigned_bytes_be(
                    &balance_change
                        .old_value
                        .clone()
                        .unwrap_or_default()
                        .bytes,
                );
                deltas.push(BalanceDelta {
                    ord: call.call.end_ordinal,
                    tx: Some(tx_trace.into()),
                    token: ETH_ADDRESS.to_vec(),
                    delta: delta.to_signed_bytes_be(),
                    component_id: EETH_ADDRESS
                        .to_hex()
                        .as_bytes()
                        .to_vec(),
                });
            }
        }
    }
    deltas
}

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
    block: eth::v2::Block,
    new_components: BlockChanges,
    components_store: StoreGetString,
    deltas: BlockBalanceDeltas,
    balance_store: StoreDeltas,
) -> Result<BlockChanges, substreams::errors::Error> {
    // We merge contract changes by transaction (identified by transaction index)
    // making it easy to sort them at the very end.
    let mut transaction_changes: HashMap<u64, TransactionChangesBuilder> = HashMap::new();

    for change in new_components.changes.into_iter() {
        let tx = change.tx.as_ref().unwrap();
        let builder = transaction_changes
            .entry(tx.index)
            .or_insert_with(|| TransactionChangesBuilder::new(tx));
        change
            .component_changes
            .iter()
            .for_each(|c| {
                builder.add_protocol_component(c);
            });
        change
            .entity_changes
            .iter()
            .for_each(|c| {
                builder.add_entity_change(c);
            });
    }

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
                    token_bc_map.values().for_each(|bc| {
                        if bc.component_id ==
                            EETH_ADDRESS
                                .to_hex()
                                .as_bytes()
                                .to_vec() &&
                            components_store
                                .get_last(format!("0x{}", hex::encode(EETH_ADDRESS)))
                                .is_some()
                        {
                            builder.add_entity_change(&EntityChanges {
                                component_id: format!("0x{}", hex::encode(EETH_ADDRESS)),
                                attributes: vec![Attribute {
                                    name: "liquidityPoolNativeBalance".into(),
                                    value: BigInt::from_unsigned_bytes_be(&bc.balance)
                                        .to_signed_bytes_be(),
                                    change: ChangeType::Update.into(),
                                }],
                            });
                        }
                        builder.add_balance_change(bc)
                    })
                });
        });

    let block_storage_changes = get_block_storage_changes(&block);

    if components_store
        .get_last(format!("0x{}", hex::encode(WEETH_ADDRESS)))
        .is_some()
    {
        weeth_entity_changes(&block_storage_changes, &mut transaction_changes)?;
    }
    if components_store
        .get_last(format!("0x{}", hex::encode(EETH_ADDRESS)))
        .is_some()
    {
        eeth_entity_changes(&block_storage_changes, &mut transaction_changes)?;
    }

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

fn weeth_entity_changes(
    storage_changes: &Vec<TransactionStorageChanges>,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) -> Result<()> {
    for change in storage_changes {
        let tx = match &change.tx {
            Some(tx) => tx,
            None => continue,
        };
        let builder = transaction_changes
            .entry(tx.index)
            .or_insert_with(|| TransactionChangesBuilder::new(tx));

        let filtered_storage_changes: Vec<StorageChange> = change
            .storage_changes
            .iter()
            .filter(|storage_change| {
                storage_change.address == LIQUIDITY_POOL_ADDRESS.to_vec() ||
                    storage_change.address == EETH_ADDRESS.to_vec()
            })
            .flat_map(|storage_change| {
                storage_change
                    .slots
                    .iter()
                    .map(|slot| StorageChange {
                        address: storage_change.address.clone(),
                        key: slot.slot.clone(),
                        old_value: slot.previous_value.clone(),
                        new_value: slot.value.clone(),
                        ordinal: 0,
                    })
            })
            .collect();

        let changed_attributes = get_changed_attributes(
            &filtered_storage_changes,
            WEETH_POOL_TRACKED_SLOTS
                .to_vec()
                .iter()
                .collect(),
        );

        builder.add_entity_change(&EntityChanges {
            component_id: format!("0x{}", hex::encode(WEETH_ADDRESS)),
            attributes: changed_attributes,
        });
    }
    Ok(())
}

fn eeth_entity_changes(
    storage_changes: &Vec<TransactionStorageChanges>,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) -> Result<()> {
    for change in storage_changes {
        let tx = match &change.tx {
            Some(tx) => tx,
            None => continue,
        };
        let builder = transaction_changes
            .entry(tx.index)
            .or_insert_with(|| TransactionChangesBuilder::new(tx));

        let filtered_storage_changes: Vec<StorageChange> = change
            .storage_changes
            .iter()
            .filter(|storage_change| {
                storage_change.address == LIQUIDITY_POOL_ADDRESS.to_vec() ||
                    storage_change.address == EETH_ADDRESS.to_vec() ||
                    storage_change.address == REDEMPTION_MANAGER_ADDRESS.to_vec()
            })
            .flat_map(|storage_change| {
                storage_change
                    .slots
                    .iter()
                    .map(|slot| StorageChange {
                        address: storage_change.address.clone(),
                        key: slot.slot.clone(),
                        old_value: slot.previous_value.clone(),
                        new_value: slot.value.clone(),
                        ordinal: 0,
                    })
            })
            .collect();

        let changed_attributes = get_changed_attributes(
            &filtered_storage_changes,
            EETH_POOL_TRACKED_SLOTS
                .to_vec()
                .iter()
                .collect(),
        );

        builder.add_entity_change(&EntityChanges {
            component_id: format!("0x{}", hex::encode(EETH_ADDRESS)),
            attributes: changed_attributes,
        });
    }
    Ok(())
}
