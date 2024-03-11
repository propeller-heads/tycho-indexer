use substreams_ethereum::pb::eth::v2::{Call, Log};
use substreams_ethereum::{Event, Function};

use crate::abi;
use crate::pb;
use crate::pb::tycho::evm::v1::{FinancialType, ImplementationType, ProtocolType, Transaction};
use pb::tycho::evm::v1::{self as tycho};
use substreams::hex;

use substreams::scalar::BigInt;

/// This trait defines some helpers for serializing and deserializing `Vec<BigInt` which is needed
///  to be able to encode the `normalized_weights` and `weights` `Attribute`s. This should also be
///  handled by any downstream application.
trait SerializableVecBigInt {
    fn serialize_bytes(&self) -> Vec<u8>;
    #[allow(dead_code)]
    fn deserialize_bytes(bytes: &[u8]) -> Vec<BigInt>;
}

impl SerializableVecBigInt for Vec<BigInt> {
    fn serialize_bytes(&self) -> Vec<u8> {
        self.iter()
            .flat_map(|big_int| big_int.to_signed_bytes_be())
            .collect()
    }
    fn deserialize_bytes(bytes: &[u8]) -> Vec<BigInt> {
        bytes
            .chunks_exact(32)
            .map(BigInt::from_signed_bytes_be)
            .collect::<Vec<BigInt>>()
    }
}

/// This is the main function that handles the creation of `ProtocolComponent`s with `Attribute`s
///  based on the specific factory address. There's 3 factory groups that are represented here:
///  - Weighted Pool Factories
///  - Linear Pool Factories
///  - Stable Pool Factories
/// (Balancer does have a bit more (esp. in the deprecated section) that could be implemented as
///  desired.)
/// We use the specific ABIs to decode both the log event and cooresponding call to gather
///  `PoolCreated` event information alongside the `Create` calldata that provide us details to
///  fufill both the required details + any extra `Attributes`
/// Ref: https://docs.balancer.fi/reference/contracts/deployment-addresses/mainnet.html
pub fn address_map(
    pool_factory_address: &[u8],
    log: &Log,
    call: &Call,
    tx: &Transaction,
) -> Option<tycho::ProtocolComponent> {
    match *pool_factory_address {
        hex!("897888115Ada5773E02aA29F775430BFB5F34c51") => {
            let create_call =
                abi::weighted_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::weighted_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: create_call.tokens,
                contracts: vec![pool_factory_address.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "WeightedPoolFactory".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "normalized_weights".into(),
                        value: create_call.normalized_weights.serialize_bytes(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],
                change: tycho::ChangeType::Creation.into(),
                protocol_type: Some(ProtocolType {
                    name: "balancer".to_string(),
                    financial_type: FinancialType::Swap.into(),
                    attribute_schema: vec![],
                    implementation_type: ImplementationType::Vm.into(),
                }),
                tx: Some(tx.clone()),
            })
        }
        hex!("DB8d758BCb971e482B2C45f7F8a7740283A1bd3A") => {
            let create_call =
                abi::composable_stable_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::composable_stable_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: create_call.tokens,
                contracts: vec![pool_factory_address.into(), pool_created.pool],
                static_att: vec![tycho::Attribute {
                    name: "pool_type".into(),
                    value: "ComposableStablePoolFactory".into(),
                    change: tycho::ChangeType::Creation.into(),
                }],
                change: tycho::ChangeType::Creation.into(),
                protocol_type: Some(ProtocolType {
                    name: "balancer".to_string(),
                    financial_type: FinancialType::Swap.into(),
                    attribute_schema: vec![],
                    implementation_type: ImplementationType::Vm.into(),
                }),
                tx: Some(tx.clone()),
            })
        }
        hex!("813EE7a840CE909E7Fea2117A44a90b8063bd4fd") => {
            let create_call =
                abi::erc_linear_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::erc_linear_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: vec![create_call.main_token, create_call.wrapped_token],
                contracts: vec![pool_factory_address.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "ERC4626LinearPoolFactory".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "upper_target".into(),
                        value: create_call.upper_target.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    // Note, `lower_target` is generally hardcoded for all pools, not located in call data
                    // Note, rate provider might be provided as `create.protocol_id`, but as a BigInt. needs investigation
                ],
                change: tycho::ChangeType::Creation.into(),
                protocol_type: Some(ProtocolType {
                    name: "balancer".to_string(),
                    financial_type: FinancialType::Swap.into(),
                    attribute_schema: vec![],
                    implementation_type: ImplementationType::Vm.into(),
                }),
                tx: Some(tx.clone()),
            })
        }
        hex!("5F43FBa61f63Fa6bFF101a0A0458cEA917f6B347") => {
            let create_call =
                abi::euler_linear_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::euler_linear_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: vec![create_call.main_token, create_call.wrapped_token],
                contracts: vec![pool_factory_address.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "EulerLinearPoolFactory".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "upper_target".into(),
                        value: create_call.upper_target.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],
                change: tycho::ChangeType::Creation.into(),
                protocol_type: Some(ProtocolType {
                    name: "balancer".to_string(),
                    financial_type: FinancialType::Swap.into(),
                    attribute_schema: vec![],
                    implementation_type: ImplementationType::Vm.into(),
                }),
                tx: Some(tx.clone()),
            })
        }
        // ❌ Reading the deployed factory for Gearbox showcases that it's currently disabled
        // hex!("39A79EB449Fc05C92c39aA6f0e9BfaC03BE8dE5B") => {
        //     let create_call =
        //         abi::gearbox_linear_pool_factory::functions::Create::match_and_decode(call)?;
        //     let pool_created =
        //         abi::gearbox_linear_pool_factory::events::PoolCreated::match_and_decode(log)?;

        //     Some(tycho::ProtocolComponent {
        //         id: hex::encode(&pool_created.pool),
        //         tokens: vec![create_call.main_token, create_call.wrapped_token],
        //         contracts: vec![pool_addr.into(), pool_created.pool],
        //         static_att: vec![
        //             tycho::Attribute {
        //                 name: "pool_type".into(),
        //                 value: "GearboxLinearPoolFactory".into(),
        //                 change: tycho::ChangeType::Creation.into(),
        //             },
        //             tycho::Attribute {
        //                 name: "upper_target".into(),
        //                 value: create_call.upper_target.to_signed_bytes_be(),
        //                 change: tycho::ChangeType::Creation.into(),
        //             },
        //         ],
        //         change: tycho::ChangeType::Creation.into(),
        //     })
        // }
        // ❌ The `ManagedPoolFactory` is a bit ✨ unique ✨, so we'll leave it commented out for now
        // Take a look at it's `Create` call to see how the params are structured.
        // hex!("BF904F9F340745B4f0c4702c7B6Ab1e808eA6b93") => {
        //     let create_call = abi::managed_pool_factory::functions::Create::match_and_decode(call)?;
        //     let pool_created =
        //         abi::managed_pool_factory::events::PoolCreated::match_and_decode(log)?;

        //     Some(tycho::ProtocolComponent {
        //         id: hex::encode(&pool_created.pool),
        //         tokens: create_call.tokens,
        //         contracts: vec![pool_addr.into(), pool_created.pool],
        //         static_att: vec![
        //             tycho::Attribute {
        //                 name: "pool_type".into(),
        //                 value: "ManagedPoolFactory".into(),
        //                 change: tycho::ChangeType::Creation.into(),
        //             },
        //         ],
        //         change: tycho::ChangeType::Creation.into(),
        //     })
        // }
        hex!("4E11AEec21baF1660b1a46472963cB3DA7811C89") => {
            let create_call =
                abi::silo_linear_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::silo_linear_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: vec![create_call.main_token, create_call.wrapped_token],
                contracts: vec![pool_factory_address.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "SiloLinearPoolFactory".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "upper_target".into(),
                        value: create_call.upper_target.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],
                change: tycho::ChangeType::Creation.into(),
                protocol_type: Some(ProtocolType {
                    name: "balancer".to_string(),
                    financial_type: FinancialType::Swap.into(),
                    attribute_schema: vec![],
                    implementation_type: ImplementationType::Vm.into(),
                }),
                tx: Some(tx.clone()),
            })
        }
        hex!("5F5222Ffa40F2AEd6380D022184D6ea67C776eE0") => {
            let create_call =
                abi::yearn_linear_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::yearn_linear_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: vec![create_call.main_token, create_call.wrapped_token],
                contracts: vec![pool_factory_address.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "YearnLinearPoolFactory".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "upper_target".into(),
                        value: create_call.upper_target.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],
                change: tycho::ChangeType::Creation.into(),
                protocol_type: Some(ProtocolType {
                    name: "balancer".to_string(),
                    financial_type: FinancialType::Swap.into(),
                    attribute_schema: vec![],
                    implementation_type: ImplementationType::Vm.into(),
                }),
                tx: Some(tx.clone()),
            })
        }
        // The `WeightedPool2TokenFactory` is a deprecated contract but we've included it since one
        //  of the highest TVL pools, 80BAL-20WETH, is able to be tracked.
        hex!("A5bf2ddF098bb0Ef6d120C98217dD6B141c74EE0") => {
            let create_call =
                abi::weighted_pool_tokens_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::weighted_pool_tokens_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: create_call.tokens,
                contracts: vec![pool_factory_address.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "WeightedPool2TokensFactory".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "weights".into(),
                        value: create_call.weights.serialize_bytes(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],
                change: tycho::ChangeType::Creation.into(),
                protocol_type: Some(ProtocolType {
                    name: "balancer".to_string(),
                    financial_type: FinancialType::Swap.into(),
                    attribute_schema: vec![],
                    implementation_type: ImplementationType::Vm.into(),
                }),
                tx: Some(tx.clone()),
            })
        }
        _ => None,
    }
}
