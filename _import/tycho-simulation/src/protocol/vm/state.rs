// Necessary for the init_account method to be in scope
#![allow(unused_imports)]
// TODO: remove skip for clippy dead_code check
#![allow(dead_code)]

use crate::{
    evm::{
        engine_db_interface::EngineDatabaseInterface,
        simulation::{SimulationEngine, SimulationParameters},
        simulation_db::BlockHeader,
        tycho_db::PreCachedDB,
    },
    models::ERC20Token,
    protocol::vm::{
        constants::{ADAPTER_ADDRESS, EXTERNAL_ACCOUNT, MAX_BALANCE},
        engine::{create_engine, SHARED_TYCHO_DB},
        errors::ProtosimError,
        protosim_contract::ProtosimContract,
        utils::{get_code_for_address, get_contract_bytecode},
    },
};
use chrono::Utc;
use ethers::{
    abi::{decode, Address as EthAddress, ParamType},
    prelude::U256,
    types::{Res, H160},
    utils::to_checksum,
};
use revm::{
    precompile::{Address, Bytes},
    primitives::{alloy_primitives::Keccak256, keccak256, AccountInfo, Bytecode, B256},
    DatabaseRef,
};
use std::{collections::HashMap, fmt::Debug, sync::Arc};
use tokio::sync::RwLock;
#[derive(Clone)]
pub struct EVMPoolState<D: DatabaseRef + EngineDatabaseInterface + Clone> {
    /// The pool's identifier
    pub id: String,
    /// The pools tokens
    pub tokens: Vec<ERC20Token>,
    /// The current block, will be used to set vm context
    pub block: BlockHeader,
    /// The pools token balances
    pub balances: HashMap<H160, U256>,
    /// The contract address for where protocol balances are stored (i.e. a vault contract).
    /// If given, balances will be overwritten here instead of on the pool contract during
    /// simulations
    pub balance_owner: Option<H160>, // TODO: implement this in ENG-3758
    /// The address to bytecode map of all stateless contracts used by the protocol
    /// for simulations. If the bytecode is None, an RPC call is done to get the code from our node
    pub stateless_contracts: HashMap<String, Option<Vec<u8>>>,
    /// If set, vm will emit detailed traces about the execution
    pub trace: bool,
    engine: Option<SimulationEngine<D>>,
    /// The adapter contract. This is used to run simulations
    adapter_contract: Option<ProtosimContract<D>>,
    adapter_contract_path: String,
}

impl EVMPoolState<PreCachedDB> {
    pub async fn new(
        id: String,
        tokens: Vec<ERC20Token>,
        block: BlockHeader,
        balances: HashMap<H160, U256>,
        adapter_contract_path: String, // TODO: include this in the adpater contrcat thinsg
        stateless_contracts: HashMap<String, Option<Vec<u8>>>,
        trace: bool,
    ) -> Result<Self, ProtosimError> {
        let mut state = EVMPoolState {
            id,
            tokens,
            block,
            adapter_contract_path,
            balances,
            balance_owner: None,
            stateless_contracts,
            trace,
            engine: None,
            adapter_contract: None,
        };
        state
            .set_engine()
            .await
            .expect("Unable to set engine");
        state.adapter_contract = Some(ProtosimContract::new(
            *ADAPTER_ADDRESS,
            state
                .engine
                .clone()
                .expect("Engine not set"),
        )?);
        Ok(state)
    }

    async fn set_engine(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.engine.is_none() {
            let token_addresses = self
                .tokens
                .iter()
                .map(|token| to_checksum(&token.address, None))
                .collect();
            let engine: SimulationEngine<_> =
                create_engine(SHARED_TYCHO_DB.clone(), token_addresses, self.trace).await;
            engine.state.init_account(
                "0x0000000000000000000000000000000000000000"
                    .parse()
                    .unwrap(),
                AccountInfo {
                    balance: Default::default(),
                    nonce: 0,
                    code_hash: Default::default(),
                    code: None,
                },
                None,
                false,
            );
            engine.state.init_account(
                Address::parse_checksummed("0x0000000000000000000000000000000000000004", None)
                    .expect("Invalid checksum for external account address"),
                AccountInfo {
                    balance: Default::default(),
                    nonce: 0,
                    code_hash: Default::default(),
                    code: None,
                },
                None,
                false,
            );
            let adapter_contract_code = get_contract_bytecode(&self.adapter_contract_path)
                .map(|bytecode_vec| Some(Bytecode::new_raw(bytecode_vec.into())))
                .map_err(|_| {
                    ProtosimError::DecodingError(
                        "Error in converting adapter contract bytecode".into(),
                    )
                })?;

            engine.state.init_account(
                Address::parse_checksummed(ADAPTER_ADDRESS.to_string(), None)
                    .expect("Invalid checksum for external account address"),
                AccountInfo {
                    balance: *MAX_BALANCE,
                    nonce: 0,
                    code_hash: B256::from(keccak256(
                        &adapter_contract_code
                            .clone()
                            .ok_or(ProtosimError::EncodingError("Can't encode code hash".into()))?
                            .bytes(),
                    )),
                    code: adapter_contract_code,
                },
                None,
                false,
            );

            for (address, bytecode) in self.stateless_contracts.iter() {
                let code: &Option<Vec<u8>> = if bytecode.is_none() {
                    let addr_str = format!("{:?}", address);
                    if addr_str.starts_with("call") {
                        let addr = self.get_address_from_call(&engine, &addr_str);
                        &get_code_for_address(&addr?.to_string(), None).await?
                    } else {
                        bytecode
                    }
                } else {
                    bytecode
                };
                engine.state.init_account(
                    address.parse().unwrap(),
                    AccountInfo {
                        balance: Default::default(),
                        nonce: 0,
                        code_hash: B256::from(keccak256(&code.clone().ok_or(
                            ProtosimError::EncodingError("Can't encode code hash".into()),
                        )?)),
                        code: code
                            .clone()
                            .map(|vec| Bytecode::new_raw(Bytes::from(vec))),
                    },
                    None,
                    false,
                );
            }
            self.engine = Some(engine);
            Ok(())
        } else {
            Ok(())
        }
    }

    fn get_address_from_call(
        &self,
        engine: &SimulationEngine<PreCachedDB>,
        decoded: &str,
    ) -> Result<Address, ProtosimError> {
        let method_name = decoded
            .split(':')
            .last()
            .ok_or_else(|| ProtosimError::DecodingError("Invalid decoded string format".into()))?;

        let selector = {
            let mut hasher = Keccak256::new();
            hasher.update(method_name.as_bytes());
            let result = hasher.finalize();
            result[..4].to_vec()
        };

        let to_address = decoded
            .split(':')
            .nth(1)
            .ok_or_else(|| ProtosimError::DecodingError("Invalid decoded string format".into()))?;

        let timestamp = Utc::now()
            .naive_utc()
            .and_utc()
            .timestamp() as u64;

        let parsed_address: Address = to_address
            .parse()
            .map_err(|_| ProtosimError::DecodingError("Invalid address format".into()))?;

        let sim_params = SimulationParameters {
            data: selector.to_vec().into(),
            to: parsed_address,
            block_number: self.block.number,
            timestamp,
            overrides: Some(HashMap::new()),
            caller: *EXTERNAL_ACCOUNT,
            value: 0.into(),
            gas_limit: None,
        };

        let sim_result = engine
            .simulate(&sim_params)
            .map_err(ProtosimError::SimulationFailure)?;

        let address = decode(&[ParamType::Address], &sim_result.result)
            .expect("Decoding failed")
            .into_iter()
            .next()
            .ok_or_else(|| {
                ProtosimError::DecodingError("Expected an address in the result".into())
            })?;

        address
            .to_string()
            .parse()
            .map_err(|_| ProtosimError::DecodingError("Expected an Address".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        evm::{simulation_db::BlockHeader, tycho_models::AccountUpdate},
        models::ERC20Token,
        protocol::{
            vm::{models::Capability, utils::maybe_coerce_error},
            BytesConvertible,
        },
    };
    use ethers::{
        prelude::{H256, U256},
        types::Address as EthAddress,
        utils::hex::traits::FromHex,
    };
    use serde_json::Value;
    use std::{
        collections::{HashMap, HashSet},
        fs::File,
        io::Read,
        path::Path,
        str::FromStr,
    };
    use tokio::runtime::Runtime;
    use tycho_core::{dto::ChangeType, Bytes};

    #[tokio::test]
    async fn test_set_engine_initialization() {
        let id = "test_pool".to_string();
        let tokens = vec![
            ERC20Token::new(
                "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                6,
                "USDC",
                U256::from(10_000),
            ),
            ERC20Token::new(
                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                18,
                "WETH",
                U256::from(10_000),
            ),
        ];

        let block = BlockHeader { number: 12345, ..Default::default() };
        let mut stateless_contracts: HashMap<String, Option<Vec<u8>>> = HashMap::new();
        stateless_contracts.insert("0x0000000000000000000000000000000000000004".to_string(), None);

        let pool_state = EVMPoolState::<PreCachedDB>::new(
            id.clone(),
            tokens,
            block,
            HashMap::new(),
            "src/protocol/vm/assets/BalancerV2SwapAdapter.evm.runtime".to_string(),
            stateless_contracts.clone(),
            true,
        )
        .await;

        assert!(pool_state.engine.is_some(), "Engine should be initialized");
    }
}
