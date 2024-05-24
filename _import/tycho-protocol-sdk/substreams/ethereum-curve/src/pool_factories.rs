use substreams_ethereum::{
    pb::eth::v2::{Call, Log, TransactionTrace},
    Event, Function,
};

use crate::abi;
use substreams::hex;
use tycho_substreams::prelude::*;

use substreams::scalar::BigInt;

const META_REGISTRY: [u8; 20] = hex!("F98B45FA17DE75FB1aD0e7aFD971b0ca00e379fC");

const CRYPTO_POOL_FACTORY: [u8; 20] = hex!("F18056Bbd320E96A48e3Fbf8bC061322531aac99");
const META_POOL_FACTORY: [u8; 20] = hex!("B9fC157394Af804a3578134A6585C0dc9cc990d4");
const META_POOL_FACTORY_OLD: [u8; 20] = hex!("0959158b6040D32d04c301A72CBFD6b39E21c9AE");
const CRYPTO_SWAP_NG_FACTORY: [u8; 20] = hex!("6A8cbed756804B16E05E741eDaBd5cB544AE21bf");
const TRICRYPTO_FACTORY: [u8; 20] = hex!("0c0e5f2fF0ff18a3be9b835635039256dC4B4963");
const STABLESWAP_FACTORY: [u8; 20] = hex!("4F8846Ae9380B90d2E71D5e3D042dff3E7ebb40d");

const WETH_ADDRESS: [u8; 20] = hex!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
const ETH_ADDRESS: [u8; 20] = hex!("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE");

/// This trait defines some helpers for serializing and deserializing `Vec<BigInt>` which is needed
///  to be able to encode some of the `Attribute`s. This should also be handled by any downstream
///  application.
#[allow(dead_code)]
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

/// Converts address bytes into a string containing a leading `0x`.
fn address_to_bytes_with_0x(address: &[u8; 20]) -> Vec<u8> {
    format!("0x{}", hex::encode(address)).into_bytes()
}

/// Function that swaps `WETH` addresses for `ETH` address for specific factory types that decide
///  to use `WETH` address even though native `ETH` is stored. This is also extra weird bc ETH
///  doesn't even have a real address, so we use the standard `0xEEEee...`.
fn swap_weth_for_eth(tokens: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    if tokens.contains(&WETH_ADDRESS.into()) {
        tokens
            .into_iter()
            .map(|token| if token == WETH_ADDRESS { ETH_ADDRESS.into() } else { token })
            .collect::<Vec<_>>()
    } else {
        tokens
    }
}

/// This massive function matches factory address to specific logic to construct
///  `ProtocolComponent`s. While, most of the logic is readily replicable, several factories differ
///  in information density resulting in needing other information sources such as decoding calls
///  or even making RPC calls to provide extra details.
///
/// Each `ProtocolComponent` contains the following static attributes:
/// - `pool_type`: The type of pool, such as `crypto_pool`, `plain_pool`, `metapool`, etc.
/// - `name`: The name of the pool.
/// - `factory_name`: The name of the factory that created the pool.
/// - `factory`: The address of the factory that created the pool.
///
/// The basic flow of this function is as follows:
/// - Match the factory address
/// - Decode the relevant event from the log
/// - Attempt to decode the cooresponding function call (based on the permutation of the ABI)
/// - Optionally make an RPC call to produce further information (see metapools)
/// - Construct the cooresponding `ProtocolComponent`
pub fn address_map(
    call_address: &[u8; 20],
    log: &Log,
    call: &Call,
    tx: &TransactionTrace,
) -> Option<ProtocolComponent> {
    match *call_address {
        CRYPTO_POOL_FACTORY => {
            let pool_added =
                abi::crypto_pool_factory::events::CryptoPoolDeployed::match_and_decode(log)?;

            let tokens = swap_weth_for_eth(pool_added.coins.into());

            let component_id = &call.return_data[12..];

            Some(ProtocolComponent {
                id: hex::encode(component_id),
                tx: Some(Transaction {
                    to: tx.to.clone(),
                    from: tx.from.clone(),
                    hash: tx.hash.clone(),
                    index: tx.index.into(),
                }),
                tokens,
                contracts: vec![component_id.into()],
                static_att: vec![
                    Attribute {
                        name: "pool_type".into(),
                        value: "crypto_pool".into(),
                        change: ChangeType::Creation.into(),
                    },
                    Attribute {
                        name: "name".into(),
                        value: pool_added.a.to_string().into(),
                        change: ChangeType::Creation.into(),
                    },
                    Attribute {
                        name: "factory_name".into(),
                        value: "crypto_pool".into(),
                        change: ChangeType::Creation.into(),
                    },
                    Attribute {
                        name: "factory".into(),
                        value: address_to_bytes_with_0x(&CRYPTO_POOL_FACTORY),
                        change: ChangeType::Creation.into(),
                    },
                ],
                change: ChangeType::Creation.into(),
                protocol_type: Some(ProtocolType {
                    name: "curve_pool".into(),
                    financial_type: FinancialType::Swap.into(),
                    attribute_schema: Vec::new(),
                    implementation_type: ImplementationType::Vm.into(),
                }),
            })
        }
        META_POOL_FACTORY => {
            if let Some(pool_added) =
                abi::meta_pool_factory::events::PlainPoolDeployed::match_and_decode(log)
            {
                let add_pool =
                    abi::meta_pool_factory::functions::DeployPlainPool1::match_and_decode(call)
                        .map(|add_pool| abi::meta_pool_factory::functions::DeployPlainPool3 {
                            name: add_pool.name,
                            symbol: add_pool.symbol,
                            coins: add_pool.coins,
                            a: add_pool.a,
                            fee: add_pool.fee,
                            asset_type: BigInt::from(0),
                            implementation_idx: BigInt::from(0),
                        })
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

                // The return data of several of these calls contain the actual component id
                let component_id = &call.return_data[12..];

                Some(ProtocolComponent {
                    id: hex::encode(component_id),
                    tx: Some(Transaction {
                        to: tx.to.clone(),
                        from: tx.from.clone(),
                        hash: tx.hash.clone(),
                        index: tx.index.into(),
                    }),
                    tokens: pool_added.coins.into(),
                    contracts: vec![component_id.into()],
                    static_att: vec![
                        Attribute {
                            name: "pool_type".into(),
                            value: "PlainPool".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "name".into(),
                            value: add_pool.name.into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory_name".into(),
                            value: "meta_pool".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory".into(),
                            value: address_to_bytes_with_0x(&META_POOL_FACTORY),
                            change: ChangeType::Creation.into(),
                        },
                    ],
                    change: ChangeType::Creation.into(),
                    protocol_type: Some(ProtocolType {
                        name: "curve_pool".into(),
                        financial_type: FinancialType::Swap.into(),
                        attribute_schema: Vec::new(),
                        implementation_type: ImplementationType::Vm.into(),
                    }),
                })
            } else if let Some(pool_added) =
                abi::meta_pool_factory::events::MetaPoolDeployed::match_and_decode(log)
            {
                let add_pool =
                    abi::meta_pool_factory::functions::DeployMetapool1::match_and_decode(call)
                        .map(|add_pool| abi::meta_pool_factory::functions::DeployMetapool2 {
                            base_pool: add_pool.base_pool,
                            name: add_pool.name,
                            symbol: add_pool.symbol,
                            coin: add_pool.coin,
                            a: add_pool.a,
                            fee: add_pool.fee,
                            implementation_idx: BigInt::from(0),
                        })
                        .or_else(|| {
                            abi::meta_pool_factory::functions::DeployMetapool2::match_and_decode(
                                call,
                            )
                        })?;

                let component_id = &call.return_data[12..];

                // The `add_pool.base_pool` may only refer to the contract of the base pool and not
                //  the token itself. This means we **have** to make an RPC call to the
                //  `meta_registry` in order to get the real LP token address.
                let get_lp_token =
                    abi::meta_registry::functions::GetLpToken1 { pool: add_pool.base_pool.clone() };
                let lp_token = get_lp_token.call(META_REGISTRY.to_vec())?;

                Some(ProtocolComponent {
                    id: hex::encode(component_id),
                    tx: Some(Transaction {
                        to: tx.to.clone(),
                        from: tx.from.clone(),
                        hash: tx.hash.clone(),
                        index: tx.index.into(),
                    }),
                    tokens: vec![pool_added.coin, lp_token],
                    contracts: vec![component_id.into(), add_pool.base_pool],
                    static_att: vec![
                        Attribute {
                            name: "pool_type".into(),
                            value: "metapool".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "name".into(),
                            value: add_pool.name.into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory_name".into(),
                            value: "meta_pool".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory".into(),
                            value: address_to_bytes_with_0x(&META_POOL_FACTORY),
                            change: ChangeType::Creation.into(),
                        },
                    ],
                    change: ChangeType::Creation.into(),
                    protocol_type: Some(ProtocolType {
                        name: "curve_pool".into(),
                        financial_type: FinancialType::Swap.into(),
                        attribute_schema: Vec::new(),
                        implementation_type: ImplementationType::Vm.into(),
                    }),
                })
            } else {
                None
            }
        }
        META_POOL_FACTORY_OLD => {
            if let Some(pool_added) =
                abi::meta_pool_factory::events::MetaPoolDeployed::match_and_decode(log)
            {
                let add_pool =
                    abi::meta_pool_factory::functions::DeployMetapool1::match_and_decode(call)
                        .map(|add_pool| abi::meta_pool_factory::functions::DeployMetapool2 {
                            base_pool: add_pool.base_pool,
                            name: add_pool.name,
                            symbol: add_pool.symbol,
                            coin: add_pool.coin,
                            a: add_pool.a,
                            fee: add_pool.fee,
                            implementation_idx: BigInt::from(0),
                        })
                        .or_else(|| {
                            abi::meta_pool_factory::functions::DeployMetapool2::match_and_decode(
                                call,
                            )
                        })?;

                let component_id = &call.return_data[12..];

                let get_lp_token =
                    abi::meta_registry::functions::GetLpToken1 { pool: add_pool.base_pool.clone() };
                let lp_token = get_lp_token.call(META_REGISTRY.to_vec())?;

                Some(ProtocolComponent {
                    id: hex::encode(component_id),
                    tx: Some(Transaction {
                        to: tx.to.clone(),
                        from: tx.from.clone(),
                        hash: tx.hash.clone(),
                        index: tx.index.into(),
                    }),
                    tokens: vec![pool_added.coin, lp_token],
                    contracts: vec![component_id.into(), add_pool.base_pool],
                    static_att: vec![
                        Attribute {
                            name: "pool_type".into(),
                            value: "metapool".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "name".into(),
                            value: add_pool.name.into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory_name".into(),
                            value: "meta_pool".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory".into(),
                            value: address_to_bytes_with_0x(&META_POOL_FACTORY),
                            change: ChangeType::Creation.into(),
                        },
                    ],
                    change: ChangeType::Creation.into(),
                    protocol_type: Some(ProtocolType {
                        name: "curve_pool".into(),
                        financial_type: FinancialType::Swap.into(),
                        attribute_schema: Vec::new(),
                        implementation_type: ImplementationType::Vm.into(),
                    }),
                })
            } else {
                None
            }
        }
        CRYPTO_SWAP_NG_FACTORY => {
            if let Some(pool_added) =
                abi::crypto_swap_ng_factory::events::PlainPoolDeployed::match_and_decode(log)
            {
                let add_pool =
                    abi::crypto_swap_ng_factory::functions::DeployPlainPool::match_and_decode(
                        call,
                    )?;
                let component_id = &call.return_data[12..];
                Some(ProtocolComponent {
                    id: hex::encode(component_id),
                    tx: Some(Transaction {
                        to: tx.to.clone(),
                        from: tx.from.clone(),
                        hash: tx.hash.clone(),
                        index: tx.index.into(),
                    }),
                    tokens: pool_added.coins.into(),
                    contracts: vec![component_id.into()],
                    static_att: vec![
                        Attribute {
                            name: "pool_type".into(),
                            value: "plain_pool".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "name".into(),
                            value: add_pool.name.into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory_name".into(),
                            value: "crypto_swap_ng".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory".into(),
                            value: address_to_bytes_with_0x(&CRYPTO_SWAP_NG_FACTORY),
                            change: ChangeType::Creation.into(),
                        },
                    ],
                    change: ChangeType::Creation.into(),
                    protocol_type: Some(ProtocolType {
                        name: "curve_pool".into(),
                        financial_type: FinancialType::Swap.into(),
                        attribute_schema: Vec::new(),
                        implementation_type: ImplementationType::Vm.into(),
                    }),
                })
            } else if let Some(pool_added) =
                abi::crypto_swap_ng_factory::events::MetaPoolDeployed::match_and_decode(log)
            {
                let add_pool =
                    abi::crypto_swap_ng_factory::functions::DeployMetapool::match_and_decode(call)?;
                let component_id = &call.return_data[12..];

                let get_lp_token =
                    abi::meta_registry::functions::GetLpToken1 { pool: add_pool.base_pool.clone() };
                let lp_token = get_lp_token.call(META_REGISTRY.to_vec())?;

                Some(ProtocolComponent {
                    id: hex::encode(component_id),
                    tx: Some(Transaction {
                        to: tx.to.clone(),
                        from: tx.from.clone(),
                        hash: tx.hash.clone(),
                        index: tx.index.into(),
                    }),
                    tokens: vec![pool_added.coin, lp_token],
                    contracts: vec![component_id.into(), pool_added.base_pool],
                    static_att: vec![
                        Attribute {
                            name: "pool_type".into(),
                            value: "metapool".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "name".into(),
                            value: add_pool.name.into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory_name".into(),
                            value: "crypto_swap_ng".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory".into(),
                            value: address_to_bytes_with_0x(&CRYPTO_SWAP_NG_FACTORY),
                            change: ChangeType::Creation.into(),
                        },
                    ],
                    change: ChangeType::Creation.into(),
                    protocol_type: Some(ProtocolType {
                        name: "curve_pool".into(),
                        financial_type: FinancialType::Swap.into(),
                        attribute_schema: Vec::new(),
                        implementation_type: ImplementationType::Vm.into(),
                    }),
                })
            } else {
                None
            }
        }
        TRICRYPTO_FACTORY => {
            if let Some(pool_added) =
                abi::tricrypto_factory::events::TricryptoPoolDeployed::match_and_decode(log)
            {
                let tokens = swap_weth_for_eth(pool_added.coins.into());

                Some(ProtocolComponent {
                    id: hex::encode(&pool_added.pool),
                    tx: Some(Transaction {
                        to: tx.to.clone(),
                        from: tx.from.clone(),
                        hash: tx.hash.clone(),
                        index: tx.index.into(),
                    }),
                    tokens,
                    contracts: vec![pool_added.pool.into()],
                    static_att: vec![
                        Attribute {
                            name: "pool_type".into(),
                            value: "trycrypto".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "name".into(),
                            value: pool_added.name.into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory_name".into(),
                            value: "tricrypto".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory".into(),
                            value: address_to_bytes_with_0x(&TRICRYPTO_FACTORY),
                            change: ChangeType::Creation.into(),
                        },
                    ],
                    change: ChangeType::Creation.into(),
                    protocol_type: Some(ProtocolType {
                        name: "curve_pool".into(),
                        financial_type: FinancialType::Swap.into(),
                        attribute_schema: Vec::new(),
                        implementation_type: ImplementationType::Vm.into(),
                    }),
                })
            } else {
                None
            }
        }
        STABLESWAP_FACTORY => {
            if let Some(pool_added) =
                abi::stableswap_factory::events::PlainPoolDeployed::match_and_decode(log)
            {
                let add_pool = if let Some(pool) =
                    abi::stableswap_factory::functions::DeployPlainPool1::match_and_decode(call)
                {
                    abi::stableswap_factory::functions::DeployPlainPool3 {
                        name: pool.name,
                        symbol: pool.symbol,
                        coins: pool.coins,
                        a: pool.a,
                        fee: pool.fee,
                        asset_type: BigInt::from(0),
                        implementation_idx: BigInt::from(0),
                    }
                } else if let Some(pool) =
                    abi::stableswap_factory::functions::DeployPlainPool2::match_and_decode(call)
                {
                    abi::stableswap_factory::functions::DeployPlainPool3 {
                        name: pool.name,
                        symbol: pool.symbol,
                        coins: pool.coins,
                        a: pool.a,
                        fee: pool.fee,
                        asset_type: BigInt::from(0),
                        implementation_idx: BigInt::from(0),
                    }
                } else if let Some(pool) =
                    abi::stableswap_factory::functions::DeployPlainPool3::match_and_decode(call)
                {
                    pool
                } else {
                    return None;
                };
                let component_id = &call.return_data[12..];
                Some(ProtocolComponent {
                    id: hex::encode(component_id),
                    tx: Some(Transaction {
                        to: tx.to.clone(),
                        from: tx.from.clone(),
                        hash: tx.hash.clone(),
                        index: tx.index.into(),
                    }),
                    tokens: pool_added.coins.into(),
                    contracts: vec![component_id.into()],
                    static_att: vec![
                        Attribute {
                            name: "pool_type".into(),
                            value: "plain".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "name".into(),
                            value: add_pool.name.into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory_name".into(),
                            value: "stable_swap".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory".into(),
                            value: address_to_bytes_with_0x(&CRYPTO_SWAP_NG_FACTORY),
                            change: ChangeType::Creation.into(),
                        },
                    ],
                    change: ChangeType::Creation.into(),
                    protocol_type: Some(ProtocolType {
                        name: "curve".into(),
                        financial_type: FinancialType::Swap.into(),
                        attribute_schema: Vec::new(),
                        implementation_type: ImplementationType::Vm.into(),
                    }),
                })
            } else if let Some(pool_added) =
                abi::stableswap_factory::events::MetaPoolDeployed::match_and_decode(log)
            {
                let add_pool = if let Some(pool) =
                    abi::stableswap_factory::functions::DeployMetapool1::match_and_decode(call)
                {
                    abi::stableswap_factory::functions::DeployMetapool2 {
                        base_pool: pool.base_pool,
                        name: pool.name,
                        symbol: pool.symbol,
                        coin: pool.coin,
                        a: pool.a,
                        fee: pool.fee,
                        implementation_idx: BigInt::from(0),
                    }
                } else if let Some(pool) =
                    abi::stableswap_factory::functions::DeployMetapool2::match_and_decode(call)
                {
                    pool
                } else {
                    return None;
                };
                let component_id = &call.return_data[12..];

                let get_lp_token =
                    abi::meta_registry::functions::GetLpToken1 { pool: add_pool.base_pool.clone() };
                let lp_token = get_lp_token.call(META_REGISTRY.to_vec())?;

                Some(ProtocolComponent {
                    id: hex::encode(component_id),
                    tx: Some(Transaction {
                        to: tx.to.clone(),
                        from: tx.from.clone(),
                        hash: tx.hash.clone(),
                        index: tx.index.into(),
                    }),
                    tokens: vec![pool_added.coin, lp_token],
                    contracts: vec![component_id.into(), pool_added.base_pool],
                    static_att: vec![
                        Attribute {
                            name: "pool_type".into(),
                            value: "metapool".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "name".into(),
                            value: add_pool.name.into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory_name".into(),
                            value: "stable_swap".into(),
                            change: ChangeType::Creation.into(),
                        },
                        Attribute {
                            name: "factory".into(),
                            value: address_to_bytes_with_0x(&STABLESWAP_FACTORY),
                            change: ChangeType::Creation.into(),
                        },
                    ],
                    change: ChangeType::Creation.into(),
                    protocol_type: Some(ProtocolType {
                        name: "curve".into(),
                        financial_type: FinancialType::Swap.into(),
                        attribute_schema: Vec::new(),
                        implementation_type: ImplementationType::Vm.into(),
                    }),
                })
            } else {
                None
            }
        }
        _ => None,
    }
}
