use anyhow::Result;
use substreams::{hex, scalar::BigInt};
use substreams_ethereum::pb::{
    eth,
    eth::v2::{Call, Log, TransactionTrace},
};
use tycho_substreams::{
    models::{
        Attribute, ChangeType, FinancialType, ImplementationType, ProtocolComponent, ProtocolType,
    },
    prelude::*,
};

use crate::modules::map_component_balance::{ETH_ADDRESS, ST_ETH_ADDRESS, WST_ETH_ADDRESS};

/// Create all relevant protocol components
///
/// This method instantiates hardcoded ProtocolComponents for the first block,
///  with a unique ids as well as all necessary metadata for routing and encoding.
#[substreams::handlers::map]
fn map_protocol_components(block: eth::v2::Block) -> Result<BlockTransactionProtocolComponents> {
    // TODO: add flag to emit only once
    Ok(BlockTransactionProtocolComponents {
        tx_components: block
            .transactions()
            .filter_map(|tx| {
                let components = tx
                    .logs_with_calls()
                    .filter_map(|(log, call)| maybe_create_component(call.call, log, tx))
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

#[derive(Clone, Copy, Debug)]
pub enum StakingStatus {
    Limited = 0,
    Paused = 1,
    Unlimited = 2,
}

impl StakingStatus {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            StakingStatus::Limited => "Limited",
            StakingStatus::Paused => "Paused",
            StakingStatus::Unlimited => "Unlimited",
        }
    }
}

pub const ST_ETH_ADDRESS_OUTER: [u8; 20] = hex!("ae7ab96520DE3A18E5e111B5EaAb095312D7fE84");

/// Potentially constructs a new ProtocolComponent given a call
///
/// This method is given each individual call within a transaction, the corresponding
/// logs emitted during that call as well as the full transaction trace.
pub fn maybe_create_component(
    call: &Call,
    _log: &Log,
    _tx: &TransactionTrace,
) -> Option<ProtocolComponent> {
    if *call.address == ST_ETH_ADDRESS {
        Some(ProtocolComponent {
            id: "stETH".to_string(),
            tokens: vec![ST_ETH_ADDRESS_OUTER.into(), ETH_ADDRESS.into()],
            contracts: vec![ST_ETH_ADDRESS_OUTER.into(), ST_ETH_ADDRESS.into()],
            static_att: vec![
                Attribute {
                    name: "total_shares".to_string(),
                    value: BigInt::from(0).to_signed_bytes_be(),
                    change: ChangeType::Creation.into(),
                },
                Attribute {
                    name: "total_pooled_eth".to_string(),
                    value: BigInt::from(0).to_signed_bytes_be(),
                    change: ChangeType::Creation.into(),
                },
                Attribute {
                    name: "staking_status".to_string(),
                    value: StakingStatus::Limited
                        .as_str_name()
                        .into(),
                    change: ChangeType::Creation.into(),
                },
                Attribute {
                    name: "staking_limit".to_string(),
                    value: BigInt::from(0).to_signed_bytes_be(),
                    change: ChangeType::Creation.into(),
                },
            ],
            change: ChangeType::Creation.into(),
            protocol_type: Some(ProtocolType {
                name: "stETH".to_string(),
                financial_type: FinancialType::Swap.into(),
                attribute_schema: vec![],
                implementation_type: ImplementationType::Vm.into(),
            }),
        })
    } else if *call.address == WST_ETH_ADDRESS {
        Some(ProtocolComponent {
            id: "wstETH".to_string(),
            tokens: vec![ST_ETH_ADDRESS_OUTER.into(), WST_ETH_ADDRESS.into()],
            contracts: vec![WST_ETH_ADDRESS.into()],
            static_att: vec![Attribute {
                name: "total_wstETH".to_string(),
                value: BigInt::from(0).to_signed_bytes_be(),
                change: ChangeType::Creation.into(),
            }],
            change: ChangeType::Creation.into(),
            protocol_type: Some(ProtocolType {
                name: "wstETH".to_string(),
                financial_type: FinancialType::Swap.into(),
                attribute_schema: vec![],
                implementation_type: ImplementationType::Vm.into(),
            }),
        })
    } else {
        None
    }
}
