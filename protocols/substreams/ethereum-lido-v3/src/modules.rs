use anyhow::{anyhow, Result};
use itertools::Itertools;
use std::collections::HashMap;
use substreams_ethereum::pb::eth;
use tycho_substreams::{
    models::{
        BlockChanges, ChangeType, EntityChanges, ImplementationType, ProtocolComponent,
        TransactionChangesBuilder,
    },
    prelude::{BlockTransactionProtocolComponents, TransactionProtocolComponents},
};

use crate::{
    constants::{
        BUFFERED_ETHER_AND_DEPOSITED_VALIDATORS_ATTR,
        BUFFERED_ETHER_AND_DEPOSITED_VALIDATORS_POSITION, CL_BALANCE_AND_CL_VALIDATORS_ATTR,
        CL_BALANCE_AND_CL_VALIDATORS_POSITION, ETH_ADDRESS, STAKING_STATE_ATTR,
        STAKING_STATE_POSITION, STETH_ADDRESS, STETH_COMPONENT_ID,
        TOKEN_TO_TRACK_TOTAL_POOLED_ETH_ATTR, TOTAL_AND_EXTERNAL_SHARES_ATTR,
        TOTAL_AND_EXTERNAL_SHARES_POSITION, WSTETH_ADDRESS, WSTETH_COMPONENT_ID,
    },
    state::InitialState,
    utils::attribute_with_bytes,
};

#[substreams::handlers::map]
pub fn map_protocol_components(
    params: String,
    block: eth::v2::Block,
) -> Result<BlockTransactionProtocolComponents> {
    let initial_state = InitialState::parse(&params)?;

    if block.number != initial_state.start_block {
        return Ok(BlockTransactionProtocolComponents { tx_components: vec![] });
    }

    let tx = block
        .transactions()
        .next()
        .ok_or_else(|| anyhow!("Activation block has no transactions"))?;

    Ok(BlockTransactionProtocolComponents {
        tx_components: vec![TransactionProtocolComponents {
            tx: Some(tx.into()),
            components: create_components(),
        }],
    })
}

fn create_components() -> Vec<ProtocolComponent> {
    vec![
        ProtocolComponent::new(STETH_COMPONENT_ID)
            .with_tokens(&[STETH_ADDRESS, ETH_ADDRESS])
            .with_attributes(&[(TOKEN_TO_TRACK_TOTAL_POOLED_ETH_ATTR, ETH_ADDRESS.as_ref())])
            .as_swap_type("lido_v3_pool", ImplementationType::Custom),
        ProtocolComponent::new(WSTETH_COMPONENT_ID)
            .with_tokens(&[STETH_ADDRESS, WSTETH_ADDRESS])
            .with_attributes(&[(TOKEN_TO_TRACK_TOTAL_POOLED_ETH_ATTR, STETH_ADDRESS.as_ref())])
            .as_swap_type("lido_v3_pool", ImplementationType::Custom),
    ]
}

#[substreams::handlers::map]
pub fn map_protocol_changes(
    params: String,
    block: eth::v2::Block,
    protocol_components: BlockTransactionProtocolComponents,
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
        handle_state_updates(&block, &mut transaction_changes);
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
        attributes: initial_state.steth_creation_attributes()?,
    });
    builder.add_entity_change(&EntityChanges {
        component_id: WSTETH_COMPONENT_ID.to_string(),
        attributes: initial_state.wsteth_creation_attributes()?,
    });

    Ok(())
}

fn handle_state_updates(
    block: &eth::v2::Block,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    for tx in block.transactions() {
        for call in tx
            .calls
            .iter()
            .filter(|call| !call.state_reverted)
        {
            for storage_change in call
                .storage_changes
                .iter()
                .filter(|change| change.address == STETH_ADDRESS)
            {
                let Some((attr_name, shared_between_components)) =
                    tracked_attribute(&storage_change.key)
                else {
                    continue;
                };

                let builder = transaction_changes
                    .entry(tx.index as u64)
                    .or_insert_with(|| TransactionChangesBuilder::new(&(tx.into())));

                builder.add_entity_change(&EntityChanges {
                    component_id: STETH_COMPONENT_ID.to_string(),
                    attributes: vec![attribute_with_bytes(
                        attr_name,
                        &storage_change.new_value,
                        ChangeType::Update,
                    )],
                });

                if shared_between_components {
                    builder.add_entity_change(&EntityChanges {
                        component_id: WSTETH_COMPONENT_ID.to_string(),
                        attributes: vec![attribute_with_bytes(
                            attr_name,
                            &storage_change.new_value,
                            ChangeType::Update,
                        )],
                    });
                }
            }
        }
    }
}

fn tracked_attribute(slot: &[u8]) -> Option<(&'static str, bool)> {
    if slot == TOTAL_AND_EXTERNAL_SHARES_POSITION {
        Some((TOTAL_AND_EXTERNAL_SHARES_ATTR, true))
    } else if slot == BUFFERED_ETHER_AND_DEPOSITED_VALIDATORS_POSITION {
        Some((BUFFERED_ETHER_AND_DEPOSITED_VALIDATORS_ATTR, true))
    } else if slot == CL_BALANCE_AND_CL_VALIDATORS_POSITION {
        Some((CL_BALANCE_AND_CL_VALIDATORS_ATTR, true))
    } else if slot == STAKING_STATE_POSITION {
        Some((STAKING_STATE_ATTR, false))
    } else {
        None
    }
}
