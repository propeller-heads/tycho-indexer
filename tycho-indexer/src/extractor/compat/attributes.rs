use std::collections::{HashMap, HashSet};

use ethers::types::U256;
use tycho_core::Bytes;

use crate::extractor::evm::{BlockChanges, ProtocolStateDelta};

const USV3_MANDATORY_ATTRIBUTES: [&str; 3] = ["liquidity", "tick", "sqrt_price_x96"];
const USV2_MANDATORY_ATTRIBUTES: [&str; 2] = ["reserve0", "reserve1"];

/// Post processor function that adds missing attributes to all new created components.
pub fn add_default_attributes(mut changes: BlockChanges, attributes: &[&str]) -> BlockChanges {
    for tx in &mut changes.txs_with_update {
        for c_id in tx.protocol_components.keys() {
            if let Some(state) = tx.protocol_states.get_mut(c_id) {
                for mandatory_attr in attributes {
                    if !state
                        .updated_attributes
                        .contains_key(mandatory_attr.to_owned())
                    {
                        state
                            .updated_attributes
                            .insert(mandatory_attr.to_string(), Bytes::from(U256::zero()));
                    }
                }
            } else {
                let mut default_attr = HashMap::new();
                for mandatory_attr in attributes {
                    default_attr.insert(mandatory_attr.to_string(), Bytes::from(U256::zero()));
                }
                tx.protocol_states.insert(
                    c_id.clone(),
                    ProtocolStateDelta {
                        component_id: c_id.clone(),
                        updated_attributes: default_attr,
                        deleted_attributes: HashSet::new(),
                    },
                );
            }
        }
    }
    changes
}

/// Post processor function that adds missing attributes to all new created uniswapV3 pools.
pub fn add_default_attributes_uniswapv3(changes: BlockChanges) -> BlockChanges {
    // TODO: Remove it while this is handled directly in the substreams modules.
    add_default_attributes(changes, &USV3_MANDATORY_ATTRIBUTES)
}

/// Post processor function that adds missing attributes to all new created uniswapV2 pools.
pub fn add_default_attributes_uniswapv2(changes: BlockChanges) -> BlockChanges {
    // TODO: Remove it while this is handled directly in the substreams modules.
    add_default_attributes(changes, &USV2_MANDATORY_ATTRIBUTES)
}

#[cfg(test)]
mod test {
    use crate::extractor::{
        compat::attributes::{add_default_attributes, USV3_MANDATORY_ATTRIBUTES},
        evm::Transaction,
    };
    use ethers::types::{H160, H256};
    use std::{
        collections::{HashMap, HashSet},
        str::FromStr,
    };
    use tycho_core::{models::Chain, Bytes};

    use crate::extractor::{evm, evm::TxWithChanges};

    const BLOCK_HASH_0: &str = "0x98b4a4fef932b1862be52de218cc32b714a295fae48b775202361a6fa09b66eb";
    const CREATED_CONTRACT: &str = "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc";

    #[test]
    fn test_add_default_attributes() {
        // Test that uniswap V3 post processor insert mandatory attributes with a default value on
        // new pools detected.
        let changes = evm::BlockChanges::new(
            "native:test".to_owned(),
            Chain::Ethereum,
            evm::Block {
                number: 0,
                chain: Chain::Ethereum,
                hash: BLOCK_HASH_0.parse().unwrap(),
                parent_hash: BLOCK_HASH_0.parse().unwrap(),
                ts: "2020-01-01T01:00:00".parse().unwrap(),
            },
            0,
            false,
            vec![TxWithChanges {
                tx: Transaction::new(
                    H256::zero(),
                    BLOCK_HASH_0.parse().unwrap(),
                    H160::zero(),
                    Some(H160::zero()),
                    10,
                ),
                protocol_states: HashMap::from([(
                    CREATED_CONTRACT.to_string(),
                    evm::ProtocolStateDelta {
                        component_id: CREATED_CONTRACT.to_string(),
                        updated_attributes: HashMap::from([(
                            "tick".to_string(),
                            Bytes::from(1_u64.to_be_bytes()),
                        )]),
                        deleted_attributes: HashSet::new(),
                    },
                )]),
                balance_changes: HashMap::new(),
                protocol_components: HashMap::from([(
                    CREATED_CONTRACT.to_string(),
                    evm::ProtocolComponent {
                        id: CREATED_CONTRACT.to_string(),
                        protocol_system: "test".to_string(),
                        protocol_type_name: "Pool".to_string(),
                        chain: Chain::Ethereum,
                        tokens: vec![
                            H160::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(),
                            H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
                        ],
                        contract_ids: vec![],
                        creation_tx: Default::default(),
                        static_attributes: Default::default(),
                        created_at: Default::default(),
                        change: Default::default(),
                    },
                )]),
                account_updates: Default::default(),
            }],
        );

        let expected = evm::BlockChanges::new(
            "native:test".to_owned(),
            Chain::Ethereum,
            changes.block,
            0,
            changes.revert,
            vec![TxWithChanges {
                tx: changes
                    .txs_with_update
                    .first()
                    .unwrap()
                    .tx,
                protocol_states: HashMap::from([(
                    CREATED_CONTRACT.to_string(),
                    evm::ProtocolStateDelta {
                        component_id: CREATED_CONTRACT.to_string(),
                        updated_attributes: HashMap::from([
                            ("tick".to_string(), Bytes::from(1_u64.to_be_bytes())),
                            ("sqrt_price_x96".to_string(), Bytes::from(H256::zero())),
                            ("liquidity".to_string(), Bytes::from(H256::zero())),
                        ]),
                        deleted_attributes: HashSet::new(),
                    },
                )]),
                balance_changes: HashMap::new(),
                protocol_components: changes
                    .txs_with_update
                    .first()
                    .unwrap()
                    .protocol_components
                    .clone(),
                account_updates: Default::default(),
            }],
        );

        let updated_changes = add_default_attributes(changes, &USV3_MANDATORY_ATTRIBUTES);

        assert_eq!(updated_changes, expected);
    }

    #[test]
    fn test_add_default_attributes_no_new_pools() {
        // Test that uniswap V3 post processor does nothing when no new pools are detected.
        let changes = evm::BlockChanges::new(
            "native:test".to_owned(),
            Chain::Ethereum,
            evm::Block {
                number: 0,
                chain: Chain::Ethereum,
                hash: BLOCK_HASH_0.parse().unwrap(),
                parent_hash: BLOCK_HASH_0.parse().unwrap(),
                ts: "2020-01-01T01:00:00".parse().unwrap(),
            },
            0,
            false,
            vec![TxWithChanges {
                tx: Transaction::new(
                    H256::zero(),
                    BLOCK_HASH_0.parse().unwrap(),
                    H160::zero(),
                    Some(H160::zero()),
                    10,
                ),
                protocol_states: HashMap::from([(
                    CREATED_CONTRACT.to_string(),
                    evm::ProtocolStateDelta {
                        component_id: CREATED_CONTRACT.to_string(),
                        updated_attributes: HashMap::from([(
                            "tick".to_string(),
                            Bytes::from(1_u64.to_be_bytes()),
                        )]),
                        deleted_attributes: HashSet::new(),
                    },
                )]),
                balance_changes: HashMap::new(),
                protocol_components: HashMap::new(),
                account_updates: Default::default(),
            }],
        );

        let updated_changes = add_default_attributes(changes.clone(), &USV3_MANDATORY_ATTRIBUTES);

        assert_eq!(updated_changes, changes);
    }
}
