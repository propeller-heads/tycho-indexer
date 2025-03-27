use itertools::Itertools;
use substreams::scalar::BigInt;
use substreams_helper::hex::Hexable;
use tycho_substreams::models::{
    Attribute, BalanceChange, BlockChanges, ChangeType, EntityChanges, FinancialType,
    ImplementationType, ProtocolComponent, ProtocolType, TransactionChanges,
};

use crate::{
    pb::ekubo::{
        block_transaction_events::transaction_events::{pool_log::Event, PoolLog},
        BlockTransactionEvents,
    },
    pool_config::PoolConfig,
};

#[substreams::handlers::map]
fn map_components(block_tx_events: BlockTransactionEvents) -> BlockChanges {
    BlockChanges {
        block: None,
        changes: block_tx_events
            .block_transaction_events
            .into_iter()
            .filter_map(|tx_events| {
                let (components, entities, balance_changes): (Vec<_>, Vec<_>, Vec<_>) = tx_events
                    .pool_logs
                    .into_iter()
                    .filter_map(maybe_create_component)
                    .multiunzip();

                (!components.is_empty()).then(|| TransactionChanges {
                    tx: Some(tx_events.transaction.unwrap().into()),
                    balance_changes: balance_changes
                        .into_iter()
                        .flatten()
                        .collect(),
                    contract_changes: vec![],
                    entity_changes: entities,
                    component_changes: components,
                })
            })
            .collect(),
    }
}

fn maybe_create_component(
    log: PoolLog,
) -> Option<(ProtocolComponent, EntityChanges, Vec<BalanceChange>)> {
    if let Event::PoolInitialized(pi) = log.event.unwrap() {
        let config = PoolConfig::from(<[u8; 32]>::try_from(pi.config).unwrap());
        let component_id = log.pool_id.to_hex();

        return Some((
            ProtocolComponent {
                id: component_id.clone(),
                tokens: vec![pi.token0.clone(), pi.token1.clone()],
                contracts: vec![],
                change: ChangeType::Creation.into(),
                protocol_type: Some(ProtocolType {
                    name: "ekubo".to_string(),
                    financial_type: FinancialType::Swap.into(),
                    implementation_type: ImplementationType::Custom.into(),
                    attribute_schema: vec![],
                }),
                // Order of attributes matters (used in store_pool_details)
                static_att: vec![
                    Attribute {
                        change: ChangeType::Creation.into(),
                        name: "token0".to_string(),
                        value: pi.token0.clone(),
                    },
                    Attribute {
                        change: ChangeType::Creation.into(),
                        name: "token1".to_string(),
                        value: pi.token1.clone(),
                    },
                    Attribute {
                        change: ChangeType::Creation.into(),
                        name: "fee".to_string(),
                        value: config.fee,
                    },
                    Attribute {
                        change: ChangeType::Creation.into(),
                        name: "tick_spacing".to_string(),
                        value: config.tick_spacing,
                    },
                    Attribute {
                        change: ChangeType::Creation.into(),
                        name: "extension".to_string(),
                        value: config.extension,
                    },
                    Attribute {
                        change: ChangeType::Creation.into(),
                        name: "extension_id".to_string(),
                        value: pi.extension.to_be_bytes().to_vec(),
                    },
                ],
            },
            EntityChanges {
                component_id: component_id.clone(),
                attributes: vec![
                    Attribute {
                        change: ChangeType::Creation.into(),
                        name: "liquidity".to_string(),
                        value: 0_u128.to_be_bytes().to_vec(),
                    },
                    Attribute {
                        change: ChangeType::Creation.into(),
                        name: "tick".to_string(),
                        value: pi.tick.to_be_bytes().to_vec(),
                    },
                    Attribute {
                        change: ChangeType::Creation.into(),
                        name: "sqrt_ratio".to_string(),
                        value: pi.sqrt_ratio,
                    },
                ],
            },
            vec![
                BalanceChange {
                    component_id: component_id.clone().into_bytes(),
                    token: pi.token0,
                    balance: BigInt::zero().to_signed_bytes_be(),
                },
                BalanceChange {
                    component_id: component_id.into_bytes(),
                    token: pi.token1,
                    balance: BigInt::zero().to_signed_bytes_be(),
                },
            ],
        ));
    }

    None
}
