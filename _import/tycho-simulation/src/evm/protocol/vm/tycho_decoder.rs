use std::{
    collections::HashMap,
    path::PathBuf,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_primitives::{Address, B256, U256};
use tracing::info;
use tycho_client::feed::{synchronizer::ComponentWithState, Header};
use tycho_core::Bytes;

use crate::{
    evm::engine_db::{simulation_db::BlockHeader, tycho_db::PreCachedDB, SHARED_TYCHO_DB},
    models::Token,
    protocol::{errors::InvalidSnapshotError, models::TryFromWithBlock},
};

use super::{state::EVMPoolState, state_builder::EVMPoolStateBuilder};

impl From<Header> for BlockHeader {
    fn from(header: Header) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        BlockHeader {
            number: header.number,
            hash: B256::new(
                header
                    .hash
                    .as_ref()
                    .try_into()
                    .expect("Hash must be 32 bytes"),
            ),
            timestamp: now,
        }
    }
}

impl TryFromWithBlock<ComponentWithState> for EVMPoolState<PreCachedDB> {
    type Error = InvalidSnapshotError;

    /// Decodes a `ComponentWithState` into an `EVMPoolState`.
    ///
    /// Errors with a `InvalidSnapshotError`.
    async fn try_from_with_block(
        snapshot: ComponentWithState,
        block: Header,
        all_tokens: &HashMap<Bytes, Token>,
    ) -> Result<Self, Self::Error> {
        let id = snapshot.component.id.clone();
        let tokens = snapshot.component.tokens.clone();

        let block = BlockHeader::from(block);
        let balances = snapshot
            .state
            .balances
            .iter()
            .map(|(k, v)| (Address::from_slice(k), U256::from_be_slice(v)))
            .collect();
        let balance_owner = snapshot
            .state
            .attributes
            .get("balance_owner")
            .map(|bytes: &Bytes| Address::from_slice(bytes.as_ref()));

        let manual_updates = snapshot
            .component
            .static_attributes
            .contains_key("manual_updates");

        // Decode involved contracts
        let mut stateless_contracts = HashMap::new();
        let mut index = 0;

        loop {
            let address_key = format!("stateless_contract_addr_{}", index);
            if let Some(encoded_address_bytes) = snapshot
                .state
                .attributes
                .get(&address_key)
            {
                let encoded_address = hex::encode(encoded_address_bytes);
                // Stateless contracts address are UTF-8 encoded
                let address_hex = encoded_address
                    .strip_prefix("0x")
                    .unwrap_or(&encoded_address);

                let decoded = match hex::decode(address_hex) {
                    Ok(decoded_bytes) => match String::from_utf8(decoded_bytes) {
                        Ok(decoded_string) => decoded_string,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                };

                let code_key = format!("stateless_contract_code_{}", index);
                let code = snapshot
                    .state
                    .attributes
                    .get(&code_key)
                    .map(|value| value.to_vec());

                stateless_contracts.insert(decoded, code);
                index += 1;
            } else {
                break;
            }
        }

        let involved_contracts = snapshot
            .component
            .contract_ids
            .iter()
            .map(|bytes: &Bytes| Address::from_slice(bytes.as_ref()))
            .collect();

        let protocol_name = snapshot
            .component
            .protocol_system
            .strip_prefix("vm:")
            .unwrap_or({
                snapshot
                    .component
                    .protocol_system
                    .as_str()
            });
        let adapter_file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/evm/protocol/vm/assets")
            .join(to_adapter_file_name(protocol_name));
        let adapter_contract_address =
            Address::from_str(&format!("{:0>40}", hex::encode(protocol_name)))
                .expect("Can't convert protocol name to address");

        let mut pool_state_builder = EVMPoolStateBuilder::new(
            id.clone(),
            tokens.clone(),
            balances,
            block,
            adapter_contract_address,
        )
        .adapter_contract_path(adapter_file_path)
        .involved_contracts(involved_contracts)
        .stateless_contracts(stateless_contracts)
        .manual_updates(manual_updates);

        if let Some(balance_owner) = balance_owner {
            pool_state_builder = pool_state_builder.balance_owner(balance_owner)
        };

        let mut pool_state = pool_state_builder
            .build(SHARED_TYCHO_DB.clone())
            .await
            .map_err(InvalidSnapshotError::VMError)?;

        pool_state.set_spot_prices(all_tokens)?;
        info!("Finished creating balancer pool with id {}", &id);

        Ok(pool_state)
    }
}

/// Converts a protocol system name to the name of the adapter file. For example, `balancer_v2`
/// would be converted to `BalancerV2SwapAdapter.evm.runtime`.
fn to_adapter_file_name(protocol_system: &str) -> String {
    protocol_system
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<String>() +
        "SwapAdapter.evm.runtime"
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        evm::{
            engine_db::{create_engine, engine_db_interface::EngineDatabaseInterface},
            tycho_models::AccountUpdate,
        },
        protocol::models::TryFromWithBlock,
    };
    use chrono::DateTime;
    use num_bigint::ToBigUint;
    use revm::primitives::{AccountInfo, Address, Bytecode, KECCAK_EMPTY};
    use serde_json::Value;
    use std::{collections::HashSet, fs, path::Path, str::FromStr};
    use tycho_core::{
        dto::{Chain, ChangeType, ProtocolComponent, ResponseProtocolState},
        Bytes,
    };

    #[test]
    fn test_to_adapter_file_name() {
        assert_eq!(to_adapter_file_name("balancer_v2"), "BalancerV2SwapAdapter.evm.runtime");
        assert_eq!(to_adapter_file_name("uniswap_v3"), "UniswapV3SwapAdapter.evm.runtime");
    }

    fn vm_component() -> ProtocolComponent {
        let creation_time = DateTime::from_timestamp(1622526000, 0)
            .unwrap()
            .naive_utc(); //Sample timestamp

        let mut static_attributes: HashMap<String, Bytes> = HashMap::new();
        static_attributes.insert("manual_updates".to_string(), Bytes::from_str("0x01").unwrap());

        let dai_addr = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();
        let bal_addr = Bytes::from_str("0xba100000625a3754423978a60c9317c58a424e3d").unwrap();
        let tokens = vec![dai_addr, bal_addr];

        ProtocolComponent {
            id: "0x4626d81b3a1711beb79f4cecff2413886d461677000200000000000000000011".to_string(),
            protocol_system: "vm:balancer_v2".to_string(),
            protocol_type_name: "balancer_v2_pool".to_string(),
            chain: Chain::Ethereum,
            tokens,
            contract_ids: vec![
                Bytes::from_str("0xBA12222222228d8Ba445958a75a0704d566BF2C8").unwrap()
            ],
            static_attributes,
            change: ChangeType::Creation,
            creation_tx: Bytes::from_str("0x0000").unwrap(),
            created_at: creation_time,
        }
    }

    fn header() -> Header {
        Header {
            number: 1,
            hash: Bytes::from(vec![0; 32]),
            parent_hash: Bytes::from(vec![0; 32]),
            revert: false,
        }
    }

    fn load_balancer_account_data() -> Vec<AccountUpdate> {
        let project_root = env!("CARGO_MANIFEST_DIR");
        let asset_path =
            Path::new(project_root).join("tests/assets/decoder/balancer_snapshot.json");
        let json_data = fs::read_to_string(asset_path).expect("Failed to read test asset");
        let data: Value = serde_json::from_str(&json_data).expect("Failed to parse JSON");

        let accounts: Vec<AccountUpdate> = serde_json::from_value(data["accounts"].clone())
            .expect("Expected accounts to match AccountUpdate structure");
        accounts
    }

    #[tokio::test]
    async fn test_try_from_with_block() {
        let attributes: HashMap<String, Bytes> = vec![
            (
                "balance_owner".to_string(),
                Bytes::from_str("0xBA12222222228d8Ba445958a75a0704d566BF2C8").unwrap(),
            ),
            ("reserve1".to_string(), Bytes::from(200_u64.to_le_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        let tokens = [
            Token::new(
                "0x6b175474e89094c44da98b954eedeac495271d0f",
                18,
                "DAI",
                10_000.to_biguint().unwrap(),
            ),
            Token::new(
                "0xba100000625a3754423978a60c9317c58a424e3d",
                18,
                "BAL",
                10_000.to_biguint().unwrap(),
            ),
        ]
        .into_iter()
        .map(|t| (t.address.clone(), t))
        .collect::<HashMap<_, _>>();
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "0x4626d81b3a1711beb79f4cecff2413886d461677000200000000000000000011"
                    .to_owned(),
                attributes,
                balances: [
                    (
                        Bytes::from("0x6b175474e89094c44da98b954eedeac495271d0f"),
                        Bytes::from("0x01"),
                    ),
                    (
                        Bytes::from("0xba100000625a3754423978a60c9317c58a424e3d"),
                        Bytes::from("0x01"),
                    ),
                ]
                .into_iter()
                .collect(),
            },
            component: vm_component(),
        };
        // Initialize engine with balancer storage
        let block = header();
        let accounts = load_balancer_account_data();
        let db = SHARED_TYCHO_DB.clone();
        let engine = create_engine(db.clone(), false).unwrap();
        for account in accounts.clone() {
            engine.state.init_account(
                account.address,
                AccountInfo {
                    balance: account.balance.unwrap_or_default(),
                    nonce: 0u64,
                    code_hash: KECCAK_EMPTY,
                    code: account
                        .code
                        .clone()
                        .map(|arg0: Vec<u8>| Bytecode::new_raw(arg0.into())),
                },
                None,
                false,
            );
        }
        db.update(accounts, Some(block.into()));

        let res = EVMPoolState::try_from_with_block(snapshot, header(), &tokens)
            .await
            .unwrap();

        assert_eq!(
            res.get_balance_owner(),
            Some(Address::from_str("0xBA12222222228d8Ba445958a75a0704d566BF2C8").unwrap())
        );
        let mut exp_involved_contracts = HashSet::new();
        exp_involved_contracts
            .insert(Address::from_str("0xBA12222222228d8Ba445958a75a0704d566BF2C8").unwrap());
        assert_eq!(res.get_involved_contracts(), exp_involved_contracts);
        assert!(res.get_manual_updates());
    }
}
