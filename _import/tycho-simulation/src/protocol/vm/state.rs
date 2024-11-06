// TODO: remove skip for clippy dead_code check
#![allow(dead_code)]

use std::{
    any::Any,
    collections::{HashMap, HashSet},
};

use chrono::Utc;
use ethers::{
    abi::{decode, ParamType},
    prelude::U256,
    types::H160,
    utils::to_checksum,
};
use itertools::Itertools;
use revm::{
    primitives::{
        alloy_primitives::Keccak256, keccak256, AccountInfo, Address as rAddress, Bytecode, Bytes,
        B256, KECCAK_EMPTY, U256 as rU256,
    },
    DatabaseRef,
};
use tracing::warn;

use tycho_core::dto::ProtocolStateDelta;

use crate::{
    evm::{
        simulation::{SimulationEngine, SimulationParameters},
        simulation_db::BlockHeader,
        tycho_db::PreCachedDB,
    },
    models::ERC20Token,
    protocol::{
        errors::{SimulationError, TransitionError},
        events::{EVMLogMeta, LogIndex},
        models::GetAmountOutResult,
        state::{ProtocolEvent, ProtocolSim},
        vm::{
            constants::{ADAPTER_ADDRESS, EXTERNAL_ACCOUNT, MAX_BALANCE},
            engine::{create_engine, SHARED_TYCHO_DB},
            erc20_overwrite_factory::{ERC20OverwriteFactory, Overwrites},
            models::Capability,
            tycho_simulation_contract::TychoSimulationContract,
            utils::{get_code_for_contract, get_contract_bytecode, SlotId},
        },
    },
};

// Necessary for the init_account method to be in scope
#[allow(unused_imports)]
use crate::evm::engine_db_interface::EngineDatabaseInterface;

#[derive(Clone, Debug)]
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
    pub spot_prices: HashMap<(H160, H160), f64>,
    /// The supported capabilities of this pool
    pub capabilities: HashSet<Capability>,
    /// Storage overwrites that will be applied to all simulations. They will be cleared
    //  when ``clear_all_cache`` is called, i.e. usually at each block. Hence, the name.
    pub block_lasting_overwrites: HashMap<rAddress, Overwrites>,
    /// A set of all contract addresses involved in the simulation of this pool."""
    pub involved_contracts: HashSet<H160>,
    /// Allows the specification of custom storage slots for token allowances and
    /// balances. This is particularly useful for token contracts involved in protocol
    /// logic that extends beyond simple transfer functionality.
    pub token_storage_slots: HashMap<H160, (SlotId, SlotId)>,
    /// The address to bytecode map of all stateless contracts used by the protocol
    /// for simulations. If the bytecode is None, an RPC call is done to get the code from our node
    pub stateless_contracts: HashMap<String, Option<Vec<u8>>>,
    /// If set, vm will emit detailed traces about the execution
    pub trace: bool,
    engine: Option<SimulationEngine<D>>,
    /// The adapter contract. This is used to run simulations
    adapter_contract: Option<TychoSimulationContract<D>>,
}

impl VMPoolState<PreCachedDB> {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        id: String,
        tokens: Vec<ERC20Token>,
        block: BlockHeader,
        balances: HashMap<H160, U256>,
        balance_owner: Option<H160>,
        adapter_contract_path: String,
        capabilities: HashSet<Capability>,
        block_lasting_overwrites: HashMap<rAddress, Overwrites>,
        involved_contracts: HashSet<H160>,
        token_storage_slots: HashMap<H160, (SlotId, SlotId)>,
        stateless_contracts: HashMap<String, Option<Vec<u8>>>,
        trace: bool,
    ) -> Result<Self, SimulationError> {
        let mut state = VMPoolState {
            id,
            tokens,
            block,
            balances,
            balance_owner,
            spot_prices: HashMap::new(),
            capabilities,
            block_lasting_overwrites,
            involved_contracts,
            token_storage_slots,
            stateless_contracts,
            trace,
            engine: None,
            adapter_contract: None,
        };
        state
            .set_engine(adapter_contract_path)
            .await?;
        state.adapter_contract = Some(TychoSimulationContract::new(
            *ADAPTER_ADDRESS,
            state
                .engine
                .clone()
                .ok_or_else(|| SimulationError::NotInitialized("Simulation engine".to_string()))?,
        )?);
        state.set_capabilities().await?;
        // TODO: add init_token_storage_slots() in 3796
        Ok(state)
    }

    async fn set_engine(&mut self, adapter_contract_path: String) -> Result<(), SimulationError> {
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
                rAddress::parse_checksummed("0x0000000000000000000000000000000000000004", None)
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
            let adapter_contract_code =
                get_contract_bytecode(&adapter_contract_path).map_err(SimulationError::AbiError)?;

            engine.state.init_account(
                rAddress::parse_checksummed(ADAPTER_ADDRESS.to_string(), None)
                    .expect("Invalid checksum for external account address"),
                AccountInfo {
                    balance: *MAX_BALANCE,
                    nonce: 0,
                    code_hash: B256::from(keccak256(adapter_contract_code.clone().bytes())),
                    code: Some(adapter_contract_code),
                },
                None,
                false,
            );

            for (address, bytecode) in self.stateless_contracts.iter() {
                let (code, code_hash) = if bytecode.is_none() {
                    let mut addr_str = format!("{:?}", address);
                    if addr_str.starts_with("call") {
                        addr_str = self
                            .get_address_from_call(&engine, &addr_str)?
                            .to_string();
                    }
                    let code = get_code_for_contract(&addr_str, None).await?;
                    let code_hash = B256::from(keccak256(code.clone().bytes()));
                    (Some(code), code_hash)
                } else {
                    let code =
                        Bytecode::new_raw(Bytes::from(bytecode.clone().ok_or_else(|| {
                            SimulationError::DecodingError(
                                "Byte code from stateless contracts is None".into(),
                            )
                        })?));
                    let code_hash = B256::from(keccak256(code.clone().bytes()));
                    (Some(code), code_hash)
                };
                engine.state.init_account(
                    address.parse().unwrap(),
                    AccountInfo { balance: Default::default(), nonce: 0, code_hash, code },
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
    ) -> Result<rAddress, SimulationError> {
        let method_name = decoded
            .split(':')
            .last()
            .ok_or_else(|| {
                SimulationError::DecodingError("Invalid decoded string format".into())
            })?;

        let selector = {
            let mut hasher = Keccak256::new();
            hasher.update(method_name.as_bytes());
            let result = hasher.finalize();
            result[..4].to_vec()
        };

        let to_address = decoded
            .split(':')
            .nth(1)
            .ok_or_else(|| {
                SimulationError::DecodingError("Invalid decoded string format".into())
            })?;

        let timestamp = Utc::now()
            .naive_utc()
            .and_utc()
            .timestamp() as u64;

        let parsed_address: rAddress = to_address
            .parse()
            .map_err(|_| SimulationError::DecodingError("Invalid address format".into()))?;

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
            .map_err(SimulationError::SimulationFailure)?;

        let address = decode(&[ParamType::Address], &sim_result.result)
            .map_err(|_| SimulationError::DecodingError("Failed to decode ABI".into()))?
            .into_iter()
            .next()
            .ok_or_else(|| {
                SimulationError::DecodingError(
                    "Couldn't retrieve address from simulation for stateless contracts".into(),
                )
            })?;

        address
            .to_string()
            .parse()
            .map_err(|_| SimulationError::DecodingError("Couldn't parse address to string".into()))
    }

    /// Ensures the pool supports the given capability
    fn ensure_capability(&self, capability: Capability) -> Result<(), SimulationError> {
        if !self.capabilities.contains(&capability) {
            return Err(SimulationError::NotFound(format!(
                "capability {:?}",
                capability.to_string()
            )));
        }
        Ok(())
    }

    async fn set_capabilities(&mut self) -> Result<(), SimulationError> {
        let mut capabilities = Vec::new();

        // Generate all permutations of tokens and retrieve capabilities
        for tokens_pair in self.tokens.iter().permutations(2) {
            // Manually unpack the inner vector
            if let [t0, t1] = &tokens_pair[..] {
                let caps = self
                    .adapter_contract
                    .clone()
                    .ok_or_else(|| SimulationError::NotInitialized("Adapter contract".to_string()))?
                    .get_capabilities(self.id.clone()[2..].to_string(), t0.address, t1.address)
                    .await?;
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
            warn!(
                "Warning: Pool {} has different capabilities depending on the token pair!",
                self.id
            );
        }
        Ok(())
    }

    pub async fn set_spot_prices(
        &mut self,
        tokens: Vec<ERC20Token>,
    ) -> Result<(), SimulationError> {
        self.ensure_capability(Capability::PriceFunction)?;
        for [sell_token, buy_token] in tokens
            .iter()
            .permutations(2)
            .map(|p| [p[0], p[1]])
        {
            let sell_amount_limit = self
                .get_sell_amount_limit(vec![(*sell_token).clone(), (*buy_token).clone()])
                .await?;
            let price_result = self
                .adapter_contract
                .clone()
                .ok_or_else(|| SimulationError::NotInitialized("Adapter contract".to_string()))?
                .price(
                    self.id.clone()[2..].to_string(),
                    sell_token.address,
                    buy_token.address,
                    vec![sell_amount_limit / U256::from(100)],
                    self.block.number,
                    Some(self.block_lasting_overwrites.clone()),
                )
                .await?;

            let price = if self
                .capabilities
                .contains(&Capability::ScaledPrice)
            {
                *price_result.first().ok_or_else(|| {
                    SimulationError::DecodingError("Spot price is not a u64".to_string())
                })?
            } else {
                let unscaled_price = price_result.first().ok_or_else(|| {
                    SimulationError::DecodingError("Spot price is not a u64".to_string())
                })?;
                *unscaled_price * 10f64.powi(sell_token.decimals as i32) /
                    10f64.powi(buy_token.decimals as i32)
            };

            self.spot_prices
                .insert((sell_token.address, buy_token.address), price);
        }
        Ok(())
    }

    /// Retrieves the sell amount limit for a given pair of tokens, where the first token is treated
    /// as the sell token and the second as the buy token. The order of tokens in the input vector
    /// is significant and determines the direction of the price query.
    async fn get_sell_amount_limit(
        &mut self,
        tokens: Vec<ERC20Token>,
    ) -> Result<U256, SimulationError> {
        let binding = self
            .adapter_contract
            .clone()
            .ok_or_else(|| SimulationError::NotInitialized("Adapter contract".to_string()))?;
        let limits = binding
            .get_limits(
                self.id.clone()[2..].to_string(),
                tokens[0].address,
                tokens[1].address,
                self.block.number,
                Some(
                    self.get_overwrites(
                        tokens,
                        U256::from_big_endian(
                            &(*MAX_BALANCE / rU256::from(100)).to_be_bytes::<32>(),
                        ),
                    )
                    .await?,
                ),
            )
            .await;

        Ok(limits?.0)
    }

    pub async fn get_overwrites(
        &mut self,
        tokens: Vec<ERC20Token>,
        max_amount: U256,
    ) -> Result<HashMap<rAddress, Overwrites>, SimulationError> {
        let token_overwrites = self
            .get_token_overwrites(tokens, max_amount)
            .await?;

        // Merge `block_lasting_overwrites` with `token_overwrites`
        let merged_overwrites =
            self.merge(&self.block_lasting_overwrites.clone(), &token_overwrites);
        self.block_lasting_overwrites = merged_overwrites.clone();
        Ok(merged_overwrites)
    }

    async fn get_token_overwrites(
        &self,
        tokens: Vec<ERC20Token>,
        max_amount: U256,
    ) -> Result<HashMap<rAddress, Overwrites>, SimulationError> {
        let sell_token = &tokens[0].clone();
        let mut res: Vec<HashMap<rAddress, Overwrites>> = Vec::new();
        if !self
            .capabilities
            .contains(&Capability::TokenBalanceIndependent)
        {
            res.push(self.get_balance_overwrites(tokens)?);
        }
        let mut overwrites = ERC20OverwriteFactory::new(
            rAddress::from_slice(&sell_token.address.0),
            *self
                .token_storage_slots
                .get(&sell_token.address)
                .unwrap_or(&(SlotId::from(0), SlotId::from(1))),
        );

        overwrites.set_balance(max_amount, H160::from_slice(&*EXTERNAL_ACCOUNT.0));

        // Set allowance for ADAPTER_ADDRESS to max_amount
        overwrites.set_allowance(
            max_amount,
            H160::from_slice(&*ADAPTER_ADDRESS.0),
            H160::from_slice(&*EXTERNAL_ACCOUNT.0),
        );

        res.push(overwrites.get_overwrites());

        // Merge all overwrites into a single HashMap
        Ok(res
            .into_iter()
            .fold(HashMap::new(), |acc, overwrite| {
                self.merge(&acc, &overwrite);
                acc
            }))
    }

    fn get_balance_overwrites(
        &self,
        tokens: Vec<ERC20Token>,
    ) -> Result<HashMap<rAddress, Overwrites>, SimulationError> {
        let mut balance_overwrites: HashMap<rAddress, Overwrites> = HashMap::new();
        let address = match self.balance_owner {
            Some(address) => Ok(address),
            None => self
                .id
                .parse()
                .map_err(|_| SimulationError::EncodingError("Pool ID is not an address".into())),
        }?;

        for token in &tokens {
            let slots = if self
                .involved_contracts
                .contains(&token.address)
            {
                self.token_storage_slots
                    .get(&token.address)
                    .cloned()
                    .ok_or_else(|| {
                        SimulationError::EncodingError("Token storage slots not found".into())
                    })?
            } else {
                (SlotId::from(0), SlotId::from(1))
            };

            let mut overwrites = ERC20OverwriteFactory::new(rAddress::from(token.address.0), slots);
            overwrites.set_balance(
                self.balances
                    .get(&token.address)
                    .cloned()
                    .unwrap_or_default(),
                address,
            );
            balance_overwrites.extend(overwrites.get_overwrites());
        }
        Ok(balance_overwrites)
    }

    fn merge(
        &self,
        target: &HashMap<rAddress, Overwrites>,
        source: &HashMap<rAddress, Overwrites>,
    ) -> HashMap<rAddress, Overwrites> {
        let mut merged = target.clone();

        for (key, source_inner) in source {
            merged
                .entry(*key)
                .or_default()
                .extend(source_inner.clone());
        }

        merged
    }
}

impl ProtocolSim for VMPoolState<PreCachedDB> {
    fn fee(&self) -> f64 {
        todo!()
    }

    fn spot_price(&self, base: &ERC20Token, quote: &ERC20Token) -> Result<f64, SimulationError> {
        self.spot_prices
            .get(&(base.address, quote.address))
            .cloned()
            .ok_or(SimulationError::NotFound("Spot prices".to_string()))
    }

    fn get_amount_out(
        &self,
        _amount_in: U256,
        _token_in: &ERC20Token,
        _token_out: &ERC20Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        todo!()
    }

    fn delta_transition(
        &mut self,
        _delta: ProtocolStateDelta,
    ) -> Result<(), TransitionError<String>> {
        todo!()
    }

    fn event_transition(
        &mut self,
        _protocol_event: Box<dyn ProtocolEvent>,
        _log: &EVMLogMeta,
    ) -> Result<(), TransitionError<LogIndex>> {
        todo!()
    }

    fn clone_box(&self) -> Box<dyn ProtocolSim> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn eq(&self, other: &dyn ProtocolSim) -> bool {
        if let Some(other_state) = other
            .as_any()
            .downcast_ref::<VMPoolState<PreCachedDB>>()
        {
            self.id == other_state.id
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        evm::{simulation_db::BlockHeader, tycho_models::AccountUpdate},
        models::ERC20Token,
        protocol::vm::models::Capability,
    };
    use ethers::{
        prelude::{H256, U256},
        types::Address as EthAddress,
    };
    use serde_json::Value;
    use std::{
        collections::{HashMap, HashSet},
        fs::File,
        path::Path,
        str::FromStr,
    };

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
                (
                    EthAddress::from(dai.address.0),
                    U256::from_dec_str("178754012737301807104").unwrap(),
                ),
                (
                    EthAddress::from(bal.address.0),
                    U256::from_dec_str("91082987763369885696").unwrap(),
                ),
            ]),
            Some(EthAddress::from_str("0xBA12222222228d8Ba445958a75a0704d566BF2C8").unwrap()),
            "src/protocol/vm/assets/BalancerV2SwapAdapter.evm.runtime".to_string(),
            HashSet::new(),
            HashMap::new(),
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

        let expected_capabilities = vec![
            Capability::SellSide,
            Capability::BuySide,
            Capability::PriceFunction,
            Capability::HardLimits,
        ]
        .into_iter()
        .collect::<HashSet<_>>();

        let capabilities_adapter_contract = pool_state
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

        assert_eq!(capabilities_adapter_contract, expected_capabilities.clone());

        let capabilities_state = pool_state.clone().capabilities;

        assert_eq!(capabilities_state, expected_capabilities.clone());

        for capability in expected_capabilities.clone() {
            assert!(pool_state
                .clone()
                .ensure_capability(capability)
                .is_ok());
        }

        assert!(pool_state
            .clone()
            .ensure_capability(Capability::MarginalPrice)
            .is_err());
    }

    #[tokio::test]
    async fn test_get_sell_amount_limit() {
        let mut pool_state = setup_pool_state().await;
        let dai_limit = pool_state
            .get_sell_amount_limit(vec![pool_state.tokens[0].clone(), pool_state.tokens[1].clone()])
            .await
            .unwrap();
        assert_eq!(dai_limit, U256::from_dec_str("100279494253364362835").unwrap());

        let bal_limit = pool_state
            .get_sell_amount_limit(vec![pool_state.tokens[1].clone(), pool_state.tokens[0].clone()])
            .await
            .unwrap();
        assert_eq!(bal_limit, U256::from_dec_str("13997408640689987484").unwrap());
    }

    #[tokio::test]
    async fn test_set_spot_prices() {
        let mut pool_state = setup_pool_state().await;

        pool_state
            .set_spot_prices(pool_state.tokens.clone())
            .await
            .unwrap();

        let dai_bal_spot_price = pool_state
            .spot_prices
            .get(&(pool_state.tokens[0].address, pool_state.tokens[1].address))
            .unwrap();
        let bal_dai_spot_price = pool_state
            .spot_prices
            .get(&(pool_state.tokens[1].address, pool_state.tokens[0].address))
            .unwrap();
        assert_eq!(dai_bal_spot_price, &0.137_778_914_319_047_9);
        assert_eq!(bal_dai_spot_price, &7.071_503_245_428_246);
    }
}
