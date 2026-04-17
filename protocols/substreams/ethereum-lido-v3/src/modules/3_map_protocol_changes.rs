use anyhow::{anyhow, Result};
use itertools::Itertools;
use std::collections::HashMap;
use substreams::{
    pb::substreams::StoreDeltas,
    scalar::BigInt,
    store::{StoreGet, StoreGetBigInt},
};
use substreams_ethereum::pb::eth;
use tycho_substreams::{
    models::{BalanceChange, BlockChanges, ChangeType, EntityChanges, TransactionChangesBuilder},
    prelude::BlockTransactionProtocolComponents,
};

use crate::{
    constants::{
        BUFFERED_ETHER_ATTR, CL_BALANCE_ATTR, CL_VALIDATORS_ATTR, DEPOSITED_VALIDATORS_ATTR,
        ETH_ADDRESS, EXTERNAL_SHARES_ATTR, STAKING_STATE_ATTR, STETH_ADDRESS, STETH_COMPONENT_ID,
        TOTAL_SHARES_ATTR, WSTETH_COMPONENT_ID,
    },
    state::{InitialState, LidoProtocolState},
    utils::{attribute_with_bigint, bigint_from_store_value},
};

#[substreams::handlers::map]
pub fn map_protocol_changes(
    params: String,
    block: eth::v2::Block,
    protocol_components: BlockTransactionProtocolComponents,
    storage_deltas: StoreDeltas,
    storage_store: StoreGetBigInt,
) -> Result<BlockChanges> {
    let initial_state = InitialState::parse(&params)?;
    let mut transaction_changes: HashMap<u64, TransactionChangesBuilder> = HashMap::new();

    if !protocol_components
        .tx_components
        .is_empty()
    {
        initialize_protocol_components(
            &initial_state,
            protocol_components,
            &mut transaction_changes,
        )?;
    } else {
        handle_state_updates(&block, &storage_deltas, &storage_store, &mut transaction_changes)?;
    }

    Ok(BlockChanges {
        block: Some((&block).into()),
        changes: transaction_changes
            .drain()
            .sorted_unstable_by_key(|(index, _)| *index)
            .filter_map(|(_, builder)| builder.build())
            .collect(),
        storage_changes: vec![],
    })
}

fn initialize_protocol_components(
    initial_state: &InitialState,
    protocol_components: BlockTransactionProtocolComponents,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) -> Result<()> {
    let state = LidoProtocolState::from_initial(initial_state)?;

    let tx_component = protocol_components
        .tx_components
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Missing activation transaction component"))?;
    let tx = tx_component
        .tx
        .as_ref()
        .ok_or_else(|| anyhow!("Activation transaction missing"))?;

    let builder = transaction_changes
        .entry(tx.index)
        .or_insert_with(|| TransactionChangesBuilder::new(tx));

    for component in tx_component.components {
        builder.add_protocol_component(&component);
    }

    builder.add_entity_change(&EntityChanges {
        component_id: STETH_COMPONENT_ID.to_string(),
        attributes: state.steth_creation_attributes(),
    });
    builder.add_entity_change(&EntityChanges {
        component_id: WSTETH_COMPONENT_ID.to_string(),
        attributes: state.shared_creation_attributes(),
    });

    let internal_ether = state
        .internal_ether()
        .to_signed_bytes_be();
    builder.add_balance_change(&BalanceChange {
        token: ETH_ADDRESS.to_vec(),
        balance: internal_ether.clone(),
        component_id: STETH_COMPONENT_ID.as_bytes().to_vec(),
    });
    builder.add_balance_change(&BalanceChange {
        token: STETH_ADDRESS.to_vec(),
        balance: internal_ether,
        component_id: WSTETH_COMPONENT_ID.as_bytes().to_vec(),
    });

    Ok(())
}

fn handle_state_updates(
    block: &eth::v2::Block,
    storage_deltas: &StoreDeltas,
    storage_store: &StoreGetBigInt,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) -> Result<()> {
    let mut sorted_deltas = storage_deltas
        .deltas
        .iter()
        .filter(|delta| {
            delta
                .key
                .starts_with(&format!("{STETH_COMPONENT_ID}:"))
        })
        .collect::<Vec<_>>();
    sorted_deltas.sort_by_key(|delta| delta.ordinal);

    if sorted_deltas.is_empty() {
        return Ok(());
    }

    let mut current_state = LidoProtocolState {
        total_shares: get_initial_value_for_block(
            &sorted_deltas,
            storage_store,
            TOTAL_SHARES_ATTR,
        )?,
        external_shares: get_initial_value_for_block(
            &sorted_deltas,
            storage_store,
            EXTERNAL_SHARES_ATTR,
        )?,
        buffered_ether: get_initial_value_for_block(
            &sorted_deltas,
            storage_store,
            BUFFERED_ETHER_ATTR,
        )?,
        deposited_validators: get_initial_value_for_block(
            &sorted_deltas,
            storage_store,
            DEPOSITED_VALIDATORS_ATTR,
        )?,
        cl_balance: get_initial_value_for_block(&sorted_deltas, storage_store, CL_BALANCE_ATTR)?,
        cl_validators: get_initial_value_for_block(
            &sorted_deltas,
            storage_store,
            CL_VALIDATORS_ATTR,
        )?,
        staking_state: get_initial_value_for_block(
            &sorted_deltas,
            storage_store,
            STAKING_STATE_ATTR,
        )?,
    };

    for delta in &sorted_deltas {
        let attr_name = delta
            .key
            .split(':')
            .next_back()
            .ok_or_else(|| anyhow!("Unexpected store key format: {}", delta.key))?;
        let attr_value = bigint_from_store_value(&delta.new_value)?;
        current_state.apply_attribute(attr_name, attr_value.clone())?;

        let tx = transaction_for_ordinal(block, delta.ordinal)
            .ok_or_else(|| anyhow!("No transaction found for ordinal {}", delta.ordinal))?;
        let builder = transaction_changes
            .entry(tx.index as u64)
            .or_insert_with(|| TransactionChangesBuilder::new(&(tx.into())));

        if attr_name == STAKING_STATE_ATTR {
            builder.add_entity_change(&EntityChanges {
                component_id: STETH_COMPONENT_ID.to_string(),
                attributes: vec![attribute_with_bigint(
                    STAKING_STATE_ATTR,
                    &attr_value,
                    ChangeType::Update,
                )],
            });
        } else {
            let attribute = attribute_with_bigint(attr_name, &attr_value, ChangeType::Update);
            builder.add_entity_change(&EntityChanges {
                component_id: STETH_COMPONENT_ID.to_string(),
                attributes: vec![attribute.clone()],
            });
            builder.add_entity_change(&EntityChanges {
                component_id: WSTETH_COMPONENT_ID.to_string(),
                attributes: vec![attribute],
            });
        }

        let is_last_delta_for_ordinal = sorted_deltas
            .iter()
            .rfind(|candidate| candidate.ordinal == delta.ordinal)
            .map(|last_delta| std::ptr::eq(*last_delta, *delta))
            .unwrap_or(false);

        if !is_last_delta_for_ordinal {
            continue;
        }

        let shared_update_attributes = current_state.shared_update_attributes();
        builder.add_entity_change(&EntityChanges {
            component_id: STETH_COMPONENT_ID.to_string(),
            attributes: shared_update_attributes.clone(),
        });
        builder.add_entity_change(&EntityChanges {
            component_id: WSTETH_COMPONENT_ID.to_string(),
            attributes: shared_update_attributes,
        });

        let internal_ether = current_state
            .internal_ether()
            .to_signed_bytes_be();
        builder.add_balance_change(&BalanceChange {
            token: ETH_ADDRESS.to_vec(),
            balance: internal_ether.clone(),
            component_id: STETH_COMPONENT_ID.as_bytes().to_vec(),
        });
        builder.add_balance_change(&BalanceChange {
            token: STETH_ADDRESS.to_vec(),
            balance: internal_ether,
            component_id: WSTETH_COMPONENT_ID.as_bytes().to_vec(),
        });
    }

    Ok(())
}

fn get_initial_value_for_block(
    deltas: &[&substreams::pb::substreams::StoreDelta],
    storage_store: &StoreGetBigInt,
    suffix: &str,
) -> Result<BigInt> {
    if let Some(first_delta) = deltas
        .iter()
        .filter(|delta| delta.key.ends_with(suffix))
        .min_by_key(|delta| delta.ordinal)
    {
        return bigint_from_store_value(&first_delta.old_value);
    }

    Ok(storage_store
        .get_last(format!("{STETH_COMPONENT_ID}:{suffix}"))
        .unwrap_or_else(|| BigInt::from(0)))
}

fn transaction_for_ordinal(
    block: &eth::v2::Block,
    ordinal: u64,
) -> Option<&eth::v2::TransactionTrace> {
    block.transactions().find(|tx| {
        tx.calls
            .iter()
            .any(|call| call.begin_ordinal <= ordinal && call.end_ordinal >= ordinal)
    })
}
