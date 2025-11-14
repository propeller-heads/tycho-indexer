use substreams::{hex, scalar::BigInt};
use substreams_ethereum::pb::eth::v2::{Call, Log, TransactionTrace};
use tycho_substreams::models::{
    Attribute, ChangeType, FinancialType, ImplementationType, ProtocolComponent, ProtocolType,
};

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

/// Potentially constructs a new ProtocolComponent given a call
///
/// This method is given each individual call within a transaction, the corresponding
/// logs emitted during that call as well as the full transaction trace.
pub fn maybe_create_component(
    call: &Call,
    _log: &Log,
    _tx: &TransactionTrace,
) -> Option<ProtocolComponent> {
    match *call.address {
        hex!("17144556fd3424EDC8Fc8A4C940B2D04936d17eb") => Some(ProtocolComponent {
            id: "stETH".to_string(),
            tokens: vec![
                hex!("ae7ab96520DE3A18E5e111B5EaAb095312D7fE84").into(),
                hex!("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE").into(),
            ],
            contracts: vec![
                hex!("ae7ab96520DE3A18E5e111B5EaAb095312D7fE84").into(),
                hex!("17144556fd3424EDC8Fc8A4C940B2D04936d17eb").into(),
            ],
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
        }),
        hex!("7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0") => Some(ProtocolComponent {
            id: "wstETH".to_string(),
            tokens: vec![
                hex!("ae7ab96520DE3A18E5e111B5EaAb095312D7fE84").into(),
                hex!("7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0").into(),
            ],
            contracts: vec![hex!("7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0").into()],
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
        }),
        _ => None,
    }
}
