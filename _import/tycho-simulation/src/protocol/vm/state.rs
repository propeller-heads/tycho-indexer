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
        models::Capability,
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
use itertools::Itertools;
use revm::{
    precompile::{Address, Bytes},
    primitives::{
        alloy_primitives::Keccak256, keccak256, AccountInfo, Bytecode, B256, KECCAK_EMPTY,
    },
    DatabaseRef,
};
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    sync::Arc,
};
use tokio::sync::RwLock;
#[derive(Clone)]
pub struct VMPoolState<D: DatabaseRef + EngineDatabaseInterface + Clone> {
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
    /// The supported capabilities of this pool
    pub capabilities: HashSet<Capability>,
    engine: Option<SimulationEngine<D>>,
    /// The adapter contract. This is used to run simulations
    adapter_contract: Option<ProtosimContract<D>>,
    adapter_contract_path: String,
}

impl VMPoolState<PreCachedDB> {
    pub async fn new(
        id: String,
        tokens: Vec<ERC20Token>,
        block: BlockHeader,
        balances: HashMap<H160, U256>,
        adapter_contract_path: String,
        stateless_contracts: HashMap<String, Option<Vec<u8>>>,
        trace: bool,
    ) -> Result<Self, ProtosimError> {
        let mut state = VMPoolState {
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
            capabilities: HashSet::new(),
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
        state.set_capabilities().await;
        Ok(state)
    }

    async fn set_engine(&mut self) -> Result<(), ProtosimError> {
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
                    code_hash: KECCAK_EMPTY,
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
                    code_hash: KECCAK_EMPTY,
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
                        adapter_contract_code
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

    /// Gets the address of the code - mostly used for dynamic proxy implementations. For example,
    /// some protocols have some dynamic math implementation that is given by the factory. When
    /// we swap on the pools for such protocols, it will call the factory to get the implementation
    /// and use it for the swap.
    /// This method simulates the call to the pool, which gives us the address of the
    /// implementation.
    ///
    /// # See Also
    /// [Dynamic Address Resolution Example](https://github.com/propeller-heads/propeller-protocol-lib/blob/main/docs/indexing/reserved-attributes.md#description-2)
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

    /// Ensures the pool supports the given capability
    fn ensure_capability(&self, capability: Capability) -> Result<(), ProtosimError> {
        if !self.capabilities.contains(&capability) {
            return Err(ProtosimError::UnsupportedCapability(capability.to_string()));
        }
        Ok(())
    }
    async fn set_capabilities(&mut self) {
        let mut capabilities = Vec::new();

        // Generate all permutations of tokens and retrieve capabilities
        for tokens_pair in self.tokens.iter().permutations(2) {
            // Manually unpack the inner vector
            if let [t0, t1] = &tokens_pair[..] {
                let caps = self
                    .adapter_contract
                    .clone()
                    .expect("Adapter contract not initialized")
                    .get_capabilities(self.id.clone()[2..].to_string(), t0.address, t1.address)
                    .await
                    .expect("Failed to get capabilities");
                capabilities.push(caps);
            }
        }

        // Find the maximum capabilities length
        let max_capabilities = capabilities
            .iter()
            .map(|c| c.len())
            .max()
            .unwrap_or(0);

        // Intersect all capability sets
        let common_capabilities: HashSet<_> = capabilities
            .iter()
            .fold(capabilities[0].clone(), |acc, cap| acc.intersection(cap).cloned().collect());

        self.capabilities = common_capabilities;

        // Check for mismatches in capabilities
        if self.capabilities.len() < max_capabilities {
            println!(
                "Warning: Pool {} has different capabilities depending on the token pair!",
                self.id
            );
        }
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
        let id = "0x4315fd1afc25cc2ebc72029c543293f9fd833eeb305e2e30159459c827733b1b".to_string();
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
        let pool_state = VMPoolState::<PreCachedDB>::new(
            id.clone(),
            tokens,
            block,
            HashMap::new(),
            "src/protocol/vm/assets/BalancerV2SwapAdapter.evm.runtime".to_string(),
            HashMap::new(),
            false,
        )
        .await;

        assert!(pool_state.unwrap().engine.is_some(), "Engine should be initialized");
    }

    async fn setup_db(asset_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let file = File::open(asset_path)?;
        let data: Value = serde_json::from_reader(file)?;

        let accounts: Vec<AccountUpdate> = serde_json::from_value(data["accounts"].clone())
            .expect("Expected accounts to match AccountUpdate structure");

        let db = SHARED_TYCHO_DB.clone();
        let engine: SimulationEngine<_> = create_engine(db.clone(), vec![], false).await;

        let block = BlockHeader {
            number: 20463609,
            hash: H256::from_str(
                "0x4315fd1afc25cc2ebc72029c543293f9fd833eeb305e2e30159459c827733b1b",
            )?,
            timestamp: 1722875891,
        };

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
        let db_write = db.write();
        db_write
            .await
            .update(accounts, Some(block))
            .await;

        Ok(())
    }

    #[tokio::test]
    async fn test_init() {
        setup_db("src/protocol/vm/assets/balancer_contract_storage_block_20463609.json".as_ref())
            .await
            .unwrap();
        let dai = ERC20Token::new(
            "0x6b175474e89094c44da98b954eedeac495271d0f",
            18,
            "DAI",
            U256::from(10_000),
        );
        let bal = ERC20Token::new(
            "0xba100000625a3754423978a60c9317c58a424e3d",
            18,
            "BAL",
            U256::from(10_000),
        );

        let tokens = vec![dai.clone(), bal.clone()];
        let block = BlockHeader {
            number: 18485417,
            hash: H256::from_str(
                "0x28d41d40f2ac275a4f5f621a636b9016b527d11d37d610a45ac3a821346ebf8c",
            )
            .expect("Invalid block hash"),
            timestamp: 0,
        };

        let pool_id: String =
            "0x4626d81b3a1711beb79f4cecff2413886d461677000200000000000000000011".into();
        let pool_state = VMPoolState::<PreCachedDB>::new(
            pool_id.clone(),
            tokens,
            block,
            HashMap::from([
                (dai.address, U256::from("178754012737301807104")),
                (bal.address, U256::from("91082987763369885696")),
            ]),
            "src/protocol/vm/assets/BalancerV2SwapAdapter.evm.runtime".to_string(),
            HashMap::new(),
            false,
        )
        .await;

        let pool_state_initialized = pool_state.unwrap();

        let expected_capabilities = vec![
            Capability::SellSide,
            Capability::BuySide,
            Capability::PriceFunction,
            Capability::HardLimits,
        ]
        .into_iter()
        .collect::<HashSet<_>>();

        let capabilities_adapter_contract = pool_state_initialized
            .clone()
            .adapter_contract
            .unwrap()
            .get_capabilities(pool_id[2..].to_string(), dai.address, bal.address)
            .await
            .unwrap();

        assert_eq!(capabilities_adapter_contract, expected_capabilities.clone());

        let capabilities_state = pool_state_initialized
            .clone()
            .capabilities;

        assert_eq!(capabilities_state, expected_capabilities.clone());

        for capability in expected_capabilities.clone() {
            assert!(pool_state_initialized
                .clone()
                .ensure_capability(capability)
                .is_ok());
        }

        assert!(pool_state_initialized
            .clone()
            .ensure_capability(Capability::MarginalPrice)
            .is_err());

        // // Assert spot prices TODO: in 3757
        // assert_eq!(
        //     pool.spot_prices,
        //     HashMap::from([
        //         ((bal.clone(), dai.clone()),
        // Decimal::from_str("7.071503245428245871486924221").unwrap()),         ((dai.
        // clone(), bal.clone()), Decimal::from_str("0.1377789143190479049114331557").unwrap())
        //     ])
        // );
    }
}
