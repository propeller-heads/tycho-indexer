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
use ethabi::Hash;
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
        alloy_primitives::Keccak256, keccak256, AccountInfo, Bytecode, B256, KECCAK_EMPTY, U256 as rU256
    },
    DatabaseRef,
};
use std::{collections::HashMap, fmt::Debug, sync::Arc};
use std::cmp::max;
use std::collections::HashSet;
use tokio::sync::RwLock;
use crate::protocol::vm::erc20_overwrite_factory::{ERC20OverwriteFactory, Overwrites};
use crate::protocol::vm::models::Capability;
use crate::protocol::vm::utils::SlotHash;


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
    pub balance_owner: Option<H160>,
    /// Spot prices of the pool by token pair
    pub spot_prices: HashMap<(ERC20Token, ERC20Token), f64>,
    /// The supported capabilities of this pool
    pub capabilities: HashSet<Capability>,
    /// Storage overwrites that will be applied to all simulations. They will be cleared
    //  when ``clear_all_cache`` is called, i.e. usually at each block. Hence, the name.
    pub block_lasting_overwrites: HashMap<H160, Overwrites>,
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

impl VMPoolState<PreCachedDB> {
    pub async fn new(
        id: String,
        tokens: Vec<ERC20Token>,
        block: BlockHeader,
        balances: HashMap<H160, U256>,
        spot_prices: HashMap<(ERC20Token, ERC20Token), f64>,
        adapter_contract_path: String,
        capabilities: HashSet<Capability>,
        block_lasting_overwrites: HashMap<H160, Overwrites>,
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
            spot_prices,
            capabilities,
            block_lasting_overwrites,
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
        state.set_spot_prices().await?;

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

    async fn set_spot_prices(&mut self) -> Result<(), ProtosimError> {
        // TODO: ensure capabilities

        for tokens_pair in self.tokens.iter().permutations(2) {
            // Manually unpack the inner vector
            if let [t0, t1] = &tokens_pair[..] {
                let sell_amount_limit = self
                    .get_sell_amount_limit((*t0).clone(), (*t1).clone())
                    .await;
                println!("Sell amount limit: {}", sell_amount_limit);
                let price_result = self
                    .adapter_contract
                    .clone()
                    .expect("Adapter contract not set")
                    .price(
                        self.id.clone()[2..].to_string(),
                        t0.address,
                        t1.address,
                        vec![sell_amount_limit],
                        self.block.number,
                       self.block_lasting_overwrites,
                    )
                    .await?;
                println!("Price result: {:?}", price_result);
                // TODO: handle scaled price here when we have capabilities
                self.spot_prices.insert(
                    ((*t0).clone(), (*t1).clone()),
                    price_result
                        .first()
                        .expect("Expected a u64")
                        .clone(),
                );
            }
        }
        Ok(())
    }

    async fn get_sell_amount_limit(&self, sell_token: ERC20Token, buy_token: ERC20Token) -> U256 {
        let binding = self
            .adapter_contract
            .clone()
            .expect("Adapter contract not set");
        let limits = binding
            .get_limits(
                self.id.clone()[2..].to_string(),
                sell_token.address,
                buy_token.address,
                self.block.number,
               Some(self.get_overwrites(&sell_token, &buy_token, Some(U256::from_big_endian(&(*MAX_BALANCE / rU256::from(100)).to_be_bytes()))).await),
            ).await;

        let sell_amount_limit = limits.expect("Expected a (u64, u64)").0;
        sell_amount_limit
    }

    pub async fn get_overwrites(
        &self,
        sell_token: &ERC20Token,
        buy_token: &ERC20Token,
        max_amount: Option<U256>,
    ) -> HashMap<H160, Overwrites> {
        let token_overwrites = self.get_token_overwrites(sell_token, buy_token, max_amount).await;

        // Merge `block_lasting_overwrites` with `token_overwrites`
            let mut overwrites =self.block_lasting_overwrites.clone();
        // TODO: is this merge enough?? See here for python version protosim_py.python.protosim_py.evm.pool_state._merge
        for (address, inner_map) in token_overwrites {
            overwrites.entry(address)
                .or_insert_with(HashMap::new)
                .extend(inner_map)
        }
        overwrites
    }

    async fn get_token_overwrites(
        &self,
        sell_token: &ERC20Token,
        buy_token: &ERC20Token,
        max_amount: Option<U256>,
    ) -> HashMap<H160, Overwrites> {
        let mut res: Vec<HashMap<H160, Overwrites>> = Vec::new();
        if !self.capabilities.contains(&Capability::TokenBalanceIndependent) {
            res.push(self.get_balance_overwrites());
        }
        let max_amount = if max_amount.is_none() {
            self.get_sell_amount_limit((*sell_token).clone(), (*buy_token).clone()).await
        } else {
            max_amount.expect("Failed to get max amount")
        };

        let mut overwrites = ERC20OverwriteFactory::new(sell_token.address.clone(),(SlotHash::from_low_u64_be(0), SlotHash::from_low_u64_be(1)));

        overwrites.set_balance(max_amount, H160::from_slice(&*EXTERNAL_ACCOUNT.0));

        // Set allowance for ADAPTER_ADDRESS to max_amount
        overwrites.set_allowance(max_amount, H160::from_slice(&*EXTERNAL_ACCOUNT.0), H160::from_slice(&*ADAPTER_ADDRESS.0));

        res.push(overwrites.get_protosim_overwrites());

        // Merge all overwrites into a single HashMap
        // TODO: is this merge enough?? See here for python version protosim_py.python.protosim_py.evm.pool_state._merge
        res.into_iter().fold(HashMap::new(), |mut acc, overwrite| {
            for (address, inner_map) in overwrite {
                acc.entry(address)
                    .or_insert_with(HashMap::new)
                    .extend(inner_map);
            }
            acc
        })
    }

    fn get_balance_overwrites(&self) -> HashMap<H160, Overwrites>{
        let mut balance_overwrites: HashMap<H160, Overwrites> = HashMap::new();
        let address = self.balance_owner.unwrap_or(self.id.parse().expect("Pool ID is not an address"));

        for token in &self.tokens {
            let mut overwrites = ERC20OverwriteFactory::new(token.address.clone(), (SlotHash::from_low_u64_be(0), SlotHash::from_low_u64_be(1)));
            overwrites.set_balance(
                    self.balances
                        .get(&token.address)
                        .cloned()
                        .unwrap_or_default(),

                address,
            );
            balance_overwrites.extend(overwrites.get_protosim_overwrites());
        }

        balance_overwrites
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
        core::k256::elliptic_curve::consts::U25,
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
        let pool_state = VMPoolState::<PreCachedDB>::new(
            id.clone(),
            tokens,
            block,
            HashMap::new(),
            HashMap::new(),
            "src/protocol/vm/assets/BalancerV2SwapAdapter.evm.runtime".to_string(),
            HashSet::new(),
            HashMap::new(),
            HashMap::new(),
            true,
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

    async fn setup_pool_state() -> VMPoolState<PreCachedDB> {
        setup_db("src/protocol/vm/assets/balancer_contract_storage_block_20463609.json".as_ref())
            .await
            .expect("Failed to set up database");

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

        VMPoolState::<PreCachedDB>::new(
            pool_id,
            tokens,
            block,
            HashMap::from([
                (dai.address, U256::from("178754012737301807104")),
                (bal.address, U256::from("91082987763369885696")),
            ]),
            HashMap::new(),
            "src/protocol/vm/assets/BalancerV2SwapAdapter.evm.runtime".to_string(),
            HashSet::new(),
            HashMap::new(),
            HashMap::new(),
            false,
        )
        .await
        .expect("Failed to initialize pool state")
    }

    #[tokio::test]
    async fn test_init() {
        setup_db("src/protocol/vm/assets/balancer_contract_storage_block_20463609.json".as_ref())
            .await
            .unwrap();

        let pool_state = setup_pool_state().await;

        let capabilities = pool_state
            .clone()
            .adapter_contract
            .unwrap()
            .get_capabilities(
                pool_state.id[2..].to_string(),
                pool_state.tokens[0].address,
                pool_state.tokens[1].address,
            )
            .await
            .unwrap();

        assert_eq!(
            capabilities,
            vec![
                Capability::SellSide,
                Capability::BuySide,
                Capability::PriceFunction,
                Capability::HardLimits,
            ]
            .into_iter()
            .collect::<HashSet<_>>()
        );

        let dai_bal_spot_price = pool_state.spot_prices.get(&(pool_state.tokens[0].clone(), pool_state.tokens[1].clone())).unwrap();
        let bal_dai_spot_price = pool_state.spot_prices.get(&(pool_state.tokens[1].clone(), pool_state.tokens[0].clone())).unwrap();
        assert_eq!(*dai_bal_spot_price, 0.1377789143190479049114331557);
        assert_eq!(*bal_dai_spot_price, 7.071503245428245871486924221);
    }

    #[tokio::test]
    async fn test_get_sell_amount_limit() {
        let pool_state = setup_pool_state().await;
        let dai_limit = pool_state
            .get_sell_amount_limit(pool_state.tokens[0].clone(), pool_state.tokens[1].clone())
            .await;
        assert_eq!(dai_limit, U256::from_dec_str("100279494253364362835").unwrap());

        let bal_limit = pool_state
            .get_sell_amount_limit(pool_state.tokens[1].clone(), pool_state.tokens[0].clone())
            .await;
        assert_eq!(bal_limit, U256::from_dec_str("13997408640689987484").unwrap());
    }
}
