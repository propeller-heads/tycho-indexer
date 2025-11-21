use crate::pb::uniswap::v4::angstrom::AngstromConfig;
use substreams::store::{StoreGet, StoreGetProto};
use substreams_helper::hex::Hexable;
use tycho_substreams::prelude::*;

#[substreams::handlers::map]
pub fn map_angstrom_enriched_block_changes(
    angstrom_address: String,
    store: StoreGetProto<AngstromConfig>,
    block_changes: BlockChanges,
) -> Result<BlockChanges, substreams::errors::Error> {
    let enriched_changes = _enrich_block_changes(angstrom_address, &store, block_changes);

    Ok(enriched_changes)
}

pub fn _enrich_block_changes(
    angstrom_address: String,
    store: &StoreGetProto<AngstromConfig>,
    mut protocol_changes: BlockChanges,
) -> BlockChanges {
    // Process each transaction's changes
    for tx_changes in &mut protocol_changes.changes {
        // Enrich component creations with Angstrom hook identifier
        for protocol_component in &mut tx_changes.component_changes {
            if protocol_component.change == i32::from(ChangeType::Creation) {
                // Check if this component has a hooks attribute
                if let Some(hooks_attr) = protocol_component
                    .static_att
                    .iter()
                    .find(|attr| attr.name == "hooks")
                {
                    let hook_address = hooks_attr.value.to_hex();
                    // Check if this hook address is the only Angstrom hook
                    if hook_address.to_lowercase() == angstrom_address {
                        substreams::log::debug!("Angstrom pool created: {}", protocol_component.id);
                        protocol_component
                            .static_att
                            .push(Attribute {
                                name: "hook_identifier".to_string(),
                                value: "angstrom_v1".as_bytes().to_vec(),
                                change: ChangeType::Creation.into(),
                            });
                    }
                }
            }
        }
        for entity_change in &mut tx_changes.entity_changes {
            // if yes, it will be an angstrom pool
            if let Some(fees) = store.get_last(&entity_change.component_id) {
                let angstrom_config = vec![
                    Attribute {
                        name: "angstrom_unlocked_fee".to_string(),
                        value: fees.unlocked_fee,
                        change: ChangeType::Update.into(),
                    },
                    Attribute {
                        name: "angstrom_protocol_unlocked_fee".to_string(),
                        value: fees.protocol_unlocked_fee,
                        change: ChangeType::Update.into(),
                    },
                    Attribute {
                        name: "angstrom_removed_pool".to_string(),
                        value: if fees.pool_removed { vec![1] } else { vec![0] },
                        change: ChangeType::Update.into(),
                    },
                ];
                entity_change
                    .attributes
                    .extend(angstrom_config);
            }
        }
    }

    protocol_changes
}
