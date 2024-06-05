use crate::abi;
use substreams::{hex, scalar::BigInt};
use substreams_ethereum::{
    pb::eth::v2::{Call, Log},
    Event, Function,
};
use tycho_substreams::prelude::*;

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
/// based on the specific factory address. There's 3 factory groups that are represented here:
///  - Weighted Pool Factories
///  - Linear Pool Factories
///  - Stable Pool Factories
///
/// (Balancer does have a bit more (esp. in the deprecated section) that could be implemented as
/// desired.)
/// We use the specific ABIs to decode both the log event and corresponding call to gather
/// `PoolCreated` event information alongside the `Create` call data that provide us details to
/// fulfill both the required details + any extra `Attributes`
/// Ref: https://docs.balancer.fi/reference/contracts/deployment-addresses/mainnet.html
pub fn address_map(
    pool_factory_address: &[u8],
    log: &Log,
    call: &Call,
    tx: &Transaction,
) -> Option<ProtocolComponent> {
    match *pool_factory_address {
        hex!("897888115Ada5773E02aA29F775430BFB5F34c51") => {
            let create_call =
                abi::weighted_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::weighted_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(
                ProtocolComponent::at_contract(&pool_created.pool, tx)
                    .with_tokens(&create_call.tokens)
                    .with_attributes(&[
                        ("pool_type", "WeightedPoolFactory".as_bytes()),
                        (
                            "normalized_weights",
                            &create_call
                                .normalized_weights
                                .serialize_bytes(),
                        ),
                    ])
                    .as_swap_type("balancer_pool", ImplementationType::Vm),
            )
        }
        hex!("DB8d758BCb971e482B2C45f7F8a7740283A1bd3A") => {
            let create_call =
                abi::composable_stable_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::composable_stable_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(
                ProtocolComponent::at_contract(&pool_created.pool, tx)
                    .with_tokens(&create_call.tokens)
                    .with_attributes(&[("pool_type", "ComposableStablePoolFactory".as_bytes())])
                    .as_swap_type("balancer_pool", ImplementationType::Vm),
            )
        }
        hex!("813EE7a840CE909E7Fea2117A44a90b8063bd4fd") => {
            let create_call =
                abi::erc_linear_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::erc_linear_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(
                ProtocolComponent::at_contract(&pool_created.pool, tx)
                    .with_tokens(&[create_call.main_token, create_call.wrapped_token])
                    .with_attributes(&[
                        ("pool_type", "ERC4626LinearPoolFactory".as_bytes()),
                        (
                            "upper_target",
                            &create_call
                                .upper_target
                                .to_signed_bytes_be(),
                        ),
                    ])
                    .as_swap_type("balancer_pool", ImplementationType::Vm),
            )
        }
        hex!("5F43FBa61f63Fa6bFF101a0A0458cEA917f6B347") => {
            let create_call =
                abi::euler_linear_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::euler_linear_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(
                ProtocolComponent::at_contract(&pool_created.pool, tx)
                    .with_tokens(&[create_call.main_token, create_call.wrapped_token])
                    .with_attributes(&[
                        ("pool_type", "EulerLinearPoolFactory".as_bytes()),
                        (
                            "upper_target",
                            &create_call
                                .upper_target
                                .to_signed_bytes_be(),
                        ),
                    ])
                    .as_swap_type("balancer_pool", ImplementationType::Vm),
            )
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
        // ❌ The `ManagedPoolFactory` is a bit ✨ unique ✨, so we'll leave it commented out for
        // now Take a look at it's `Create` call to see how the params are structured.
        // hex!("BF904F9F340745B4f0c4702c7B6Ab1e808eA6b93") => {
        //     let create_call =
        // abi::managed_pool_factory::functions::Create::match_and_decode(call)?;
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

            Some(
                ProtocolComponent::at_contract(&pool_created.pool, tx)
                    .with_tokens(&[create_call.main_token, create_call.wrapped_token])
                    .with_attributes(&[
                        ("pool_type", "SiloLinearPoolFactory".as_bytes()),
                        (
                            "upper_target",
                            &create_call
                                .upper_target
                                .to_signed_bytes_be(),
                        ),
                    ])
                    .as_swap_type("balancer_pool", ImplementationType::Vm),
            )
        }
        hex!("5F5222Ffa40F2AEd6380D022184D6ea67C776eE0") => {
            let create_call =
                abi::yearn_linear_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::yearn_linear_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(
                ProtocolComponent::at_contract(&pool_created.pool, tx)
                    .with_tokens(&[create_call.main_token, create_call.wrapped_token])
                    .with_attributes(&[
                        ("pool_type", "YearnLinearPoolFactory".as_bytes()),
                        (
                            "upper_target",
                            &create_call
                                .upper_target
                                .to_signed_bytes_be(),
                        ),
                    ])
                    .as_swap_type("balancer_pool", ImplementationType::Vm),
            )
        }
        // The `WeightedPool2TokenFactory` is a deprecated contract, but we've included
        // it to be able to track one of the highest TVL pools: 80BAL-20WETH.
        hex!("A5bf2ddF098bb0Ef6d120C98217dD6B141c74EE0") => {
            let create_call =
                abi::weighted_pool_tokens_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::weighted_pool_tokens_factory::events::PoolCreated::match_and_decode(log)?;

            Some(
                ProtocolComponent::at_contract(&pool_created.pool, tx)
                    .with_tokens(&create_call.tokens)
                    .with_attributes(&[
                        ("pool_type", "WeightedPool2TokensFactory".as_bytes()),
                        ("weights", &create_call.weights.serialize_bytes()),
                    ])
                    .as_swap_type("balancer_pool", ImplementationType::Vm),
            )
        }
        _ => None,
    }
}
