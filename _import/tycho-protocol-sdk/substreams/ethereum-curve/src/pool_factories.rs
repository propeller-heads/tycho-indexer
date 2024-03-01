use substreams_ethereum::pb::eth::v2::{Call, Log};
use substreams_ethereum::{Event, Function};

use crate::abi;
use crate::pb;
use pb::tycho::evm::v1::{self as tycho};
use substreams::{hex, log};

use substreams::scalar::BigInt;

const EMPTY_BYTES32: [u8; 32] = [0; 32];
const EMPTY_ADDRESS: [u8; 20] = hex!("0000000000000000000000000000000000000000");

const CRYPTO_SWAP_REGISTRY: [u8; 20] = hex!("897888115Ada5773E02aA29F775430BFB5F34c51");
const MAIN_REGISTRY: [u8; 20] = hex!("90E00ACe148ca3b23Ac1bC8C240C2a7Dd9c2d7f5");
const CRYPTO_POOL_FACTORY: [u8; 20] = hex!("F18056Bbd320E96A48e3Fbf8bC061322531aac99");
const META_POOL_FACTORY: [u8; 20] = hex!("B9fC157394Af804a3578134A6585C0dc9cc990d4");

/// This trait defines some helpers for serializing and deserializing `Vec<BigInt` which is needed
///  to be able to encode the `normalized_weights` and `weights` `Attribute`s. This should also be
///  handled by any downstream application.
trait SerializableVecBigInt {
    fn serialize_bytes(&self) -> Vec<u8>;
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
            .map(|chunk| BigInt::from_signed_bytes_be(chunk))
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
    call_address: &[u8; 20],
    log: &Log,
    call: &Call,
) -> Option<tycho::ProtocolComponent> {
    match *call_address {
        CRYPTO_SWAP_REGISTRY => {
            let pool_added = abi::crypto_swap_registry::events::PoolAdded::match_and_decode(log)?;

            let add_pool = abi::crypto_swap_registry::functions::AddPool1::match_and_decode(call)
                .map(|add_pool| abi::crypto_swap_registry::functions::AddPool3 {
                    pool: add_pool.pool,
                    lp_token: add_pool.lp_token,
                    gauge: add_pool.gauge,
                    zap: add_pool.zap,
                    n_coins: add_pool.n_coins,
                    name: add_pool.name,
                    base_pool: EMPTY_ADDRESS.clone().into(),
                    has_positive_rebasing_tokens: false,
                })
                .or_else(|| {
                    abi::crypto_swap_registry::functions::AddPool2::match_and_decode(call).map(
                        |add_pool| abi::crypto_swap_registry::functions::AddPool3 {
                            pool: add_pool.pool,
                            lp_token: add_pool.lp_token,
                            gauge: add_pool.gauge,
                            zap: add_pool.zap,
                            n_coins: add_pool.n_coins,
                            name: add_pool.name,
                            base_pool: add_pool.base_pool,
                            has_positive_rebasing_tokens: false,
                        },
                    )
                })
                .or_else(|| {
                    abi::crypto_swap_registry::functions::AddPool3::match_and_decode(call)
                })?;

            // We need to perform an eth_call in order to actually get the pool's tokens
            let coins_function = abi::crypto_swap_registry::functions::GetCoins {
                pool: add_pool.pool,
            };

            let coins = coins_function.call(CRYPTO_SWAP_REGISTRY.to_vec())?;
            let trimmed_coins: Vec<_> = coins
                .get(0..add_pool.n_coins.to_i32() as usize)
                .unwrap_or(&[])
                .to_vec();

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_added.pool),
                tokens: trimmed_coins,
                contracts: vec![call_address.into(), pool_added.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "CryptoSwap".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "name".into(),
                        value: add_pool.name.into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "lp_token".into(),
                        value: add_pool.lp_token.into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],

                change: tycho::ChangeType::Creation.into(),
            })
        }
        MAIN_REGISTRY => {
            let pool_created = abi::main_registry::events::PoolAdded::match_and_decode(log)?;
            let add_pool =
                abi::main_registry::functions::AddPoolWithoutUnderlying::match_and_decode(call)
                    .map(|add_pool| abi::main_registry::functions::AddPool {
                        pool: add_pool.pool,
                        lp_token: add_pool.lp_token,
                        rate_info: add_pool.rate_info,
                        decimals: add_pool.decimals,
                        n_coins: add_pool.n_coins,
                        underlying_decimals: BigInt::from(0), // not needed
                        has_initial_a: add_pool.has_initial_a,
                        is_v1: add_pool.is_v1,
                        name: add_pool.name,
                    })
                    .or_else(|| {
                        abi::main_registry::functions::AddMetapool1::match_and_decode(call).map(
                            |add_pool| abi::main_registry::functions::AddPool {
                                pool: add_pool.pool,
                                lp_token: add_pool.lp_token,
                                rate_info: EMPTY_BYTES32.clone(),
                                decimals: add_pool.decimals,
                                n_coins: add_pool.n_coins,
                                underlying_decimals: BigInt::from(0), // not needed
                                has_initial_a: true,
                                is_v1: false,
                                name: add_pool.name,
                            },
                        )
                    })
                    .or_else(|| {
                        abi::main_registry::functions::AddMetapool2::match_and_decode(call).map(
                            |add_pool| abi::main_registry::functions::AddPool {
                                pool: add_pool.pool,
                                lp_token: add_pool.lp_token,
                                rate_info: EMPTY_BYTES32.clone(),
                                decimals: add_pool.decimals,
                                n_coins: add_pool.n_coins,
                                underlying_decimals: BigInt::from(0), // not needed
                                has_initial_a: true,
                                is_v1: false,
                                name: add_pool.name,
                            },
                        )
                    })
                    .or_else(|| abi::main_registry::functions::AddPool::match_and_decode(call))?;

            // We need to perform an eth_call in order to actually get the pool's tokens
            let coins_function = abi::crypto_swap_registry::functions::GetCoins {
                pool: add_pool.pool,
            };

            let coins = coins_function.call(CRYPTO_SWAP_REGISTRY.to_vec())?;
            let trimmed_coins: Vec<_> = coins
                .get(0..add_pool.n_coins.to_i32() as usize)
                .unwrap_or(&[])
                .to_vec();

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: trimmed_coins,
                contracts: vec![call_address.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "MainRegistry".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "name".into(),
                        value: add_pool.name.into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "lp_token".into(),
                        value: add_pool.lp_token.into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],
                change: tycho::ChangeType::Creation.into(),
            })
        }
        CRYPTO_POOL_FACTORY => {
            let pool_added =
                abi::crypto_pool_factory::events::CryptoPoolDeployed::match_and_decode(log)?;
            let deploy_call =
                abi::crypto_pool_factory::functions::DeployPool::match_and_decode(call)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&call.return_data),
                tokens: pool_added.coins.into(),
                contracts: vec![call_address.into(), call.return_data.clone()],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "CryptoPool".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "name".into(),
                        value: pool_added.a.to_string().into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "lp_token".into(),
                        value: pool_added.gamma.to_string().into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "mid_fee".into(),
                        value: deploy_call.mid_fee.to_string().into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "out_fee".into(),
                        value: deploy_call.out_fee.to_string().into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "allowed_extra_profit".into(),
                        value: deploy_call.allowed_extra_profit.to_string().into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "fee_gamma".into(),
                        value: deploy_call.fee_gamma.to_string().into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "adjustment_step".into(),
                        value: deploy_call.adjustment_step.to_string().into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "admin_fee".into(),
                        value: deploy_call.admin_fee.to_string().into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "ma_half_time".into(),
                        value: deploy_call.ma_half_time.to_string().into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "initial_price".into(),
                        value: deploy_call.initial_price.to_string().into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],
                change: tycho::ChangeType::Creation.into(),
            })
        }
        META_POOL_FACTORY => {
            if let Some(pool_added) =
                abi::meta_pool_factory::events::PlainPoolDeployed::match_and_decode(log)
            {
                let add_pool =
                    abi::meta_pool_factory::functions::DeployPlainPool1::match_and_decode(call)
                        .map(
                            |add_pool| abi::meta_pool_factory::functions::DeployPlainPool3 {
                                name: add_pool.name,
                                symbol: add_pool.symbol,
                                coins: add_pool.coins,
                                a: add_pool.a,
                                fee: add_pool.fee,
                                asset_type: BigInt::from(0),
                                implementation_idx: BigInt::from(0),
                            },
                        )
                        .or_else(|| {
                            abi::meta_pool_factory::functions::DeployPlainPool2::match_and_decode(
                                call,
                            )
                            .map(|add_pool| {
                                abi::meta_pool_factory::functions::DeployPlainPool3 {
                                    name: add_pool.name,
                                    symbol: add_pool.symbol,
                                    coins: add_pool.coins,
                                    a: add_pool.a,
                                    fee: add_pool.fee,
                                    asset_type: add_pool.asset_type,
                                    implementation_idx: BigInt::from(0),
                                }
                            })
                        })
                        .or_else(|| {
                            abi::meta_pool_factory::functions::DeployPlainPool3::match_and_decode(
                                call,
                            )
                        })?;
                Some(tycho::ProtocolComponent {
                    id: hex::encode(&call.return_data),
                    tokens: pool_added.coins.into(),
                    contracts: vec![call_address.into(), call.return_data.clone()],
                    static_att: vec![
                        tycho::Attribute {
                            name: "pool_type".into(),
                            value: "PlainPool".into(),
                            change: tycho::ChangeType::Creation.into(),
                        },
                        tycho::Attribute {
                            name: "name".into(),
                            value: add_pool.name.into(),
                            change: tycho::ChangeType::Creation.into(),
                        },
                        tycho::Attribute {
                            name: "fee".into(),
                            value: add_pool.fee.to_string().into(),
                            change: tycho::ChangeType::Creation.into(),
                        },
                        tycho::Attribute {
                            name: "a".into(),
                            value: add_pool.a.to_string().into(),
                            change: tycho::ChangeType::Creation.into(),
                        },
                    ],
                    change: tycho::ChangeType::Creation.into(),
                })
            } else if let Some(pool_added) =
                abi::meta_pool_factory::events::MetaPoolDeployed::match_and_decode(log)
            {
                let add_pool =
                    abi::meta_pool_factory::functions::DeployMetapool1::match_and_decode(call)
                        .map(
                            |add_pool| abi::meta_pool_factory::functions::DeployMetapool2 {
                                base_pool: add_pool.base_pool,
                                name: add_pool.name,
                                symbol: add_pool.symbol,
                                coin: add_pool.coin,
                                a: add_pool.a,
                                fee: add_pool.fee,
                                implementation_idx: BigInt::from(0),
                            },
                        )
                        .or_else(|| {
                            abi::meta_pool_factory::functions::DeployMetapool2::match_and_decode(
                                call,
                            )
                        })?;
                Some(tycho::ProtocolComponent {
                    id: hex::encode(&call.return_data),
                    tokens: vec![pool_added.coin, add_pool.base_pool.clone()],
                    contracts: vec![
                        call_address.into(),
                        call.return_data.clone(),
                        add_pool.base_pool.clone(),
                    ],
                    static_att: vec![tycho::Attribute {
                        name: "pool_type".into(),
                        value: "MetaPool".into(),
                        change: tycho::ChangeType::Creation.into(),
                    }],
                    change: tycho::ChangeType::Creation.into(),
                })
            } else {
                None
            }
        }
        _ => None,
    }
}
