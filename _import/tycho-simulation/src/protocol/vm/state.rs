use std::{
    any::Any,
    collections::{HashMap, HashSet},
};

use alloy_primitives::Address;
use chrono::Utc;
use ethers::{
    abi::{decode, ParamType},
    prelude::U256,
    types::H160,
    utils::to_checksum,
};
use itertools::Itertools;
use revm::{
    precompile::{Address as rAddress, Bytes},
    primitives::{
        alloy_primitives::Keccak256, keccak256, AccountInfo, Bytecode, B256, KECCAK_EMPTY,
        U256 as rU256,
    },
    DatabaseRef,
};
use tracing::{info, warn};

use tycho_core::dto::ProtocolStateDelta;

use crate::{
    evm::{
        engine_db_interface::EngineDatabaseInterface,
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

#[derive(Clone, Debug)]
pub struct VMPoolState<D: DatabaseRef + EngineDatabaseInterface + Clone> {
    /// The pool's identifier
    pub id: String,
    /// The pool's token's addresses
    pub tokens: Vec<H160>,
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
    /// when ``clear_all_cache`` is called, i.e. usually at each block. Hence, the name.
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
    /// Indicates if the protocol uses custom update rules and requires update
    /// triggers to recalculate spot prices ect. Default is to update on all changes on
    /// the pool.
    pub manual_updates: bool,
    engine: Option<SimulationEngine<D>>,
    /// The adapter contract. This is used to run simulations
    adapter_contract: Option<TychoSimulationContract<D>>,
}

impl VMPoolState<PreCachedDB> {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        id: String,
        tokens: Vec<H160>,
        block: BlockHeader,
        balances: HashMap<H160, U256>,
        balance_owner: Option<H160>,
        adapter_contract_path: String,
        involved_contracts: HashSet<H160>,
        stateless_contracts: HashMap<String, Option<Vec<u8>>>,
        manual_updates: bool,
        trace: bool,
    ) -> Result<Self, SimulationError> {
        let mut state = VMPoolState {
            id,
            tokens,
            block,
            balances,
            balance_owner,
            spot_prices: HashMap::new(),
            capabilities: HashSet::new(),
            block_lasting_overwrites: HashMap::new(),
            involved_contracts,
            token_storage_slots: HashMap::new(),
            stateless_contracts,
            trace,
            engine: None,
            adapter_contract: None,
            manual_updates,
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
        state.set_capabilities()?;
        // TODO: add init_token_storage_slots() in 3796
        Ok(state)
    }

    async fn set_engine(&mut self, adapter_contract_path: String) -> Result<(), SimulationError> {
        if self.engine.is_none() {
            let token_addresses = self
                .tokens
                .iter()
                .map(|addr| to_checksum(addr, None))
                .collect();
            let engine: SimulationEngine<_> =
                create_engine(SHARED_TYCHO_DB.clone(), token_addresses, self.trace)?;
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

            // // Initialize the balance owner if it is set
            if let Some(balance_owner) = self.balance_owner {
                engine.state.init_account(
                    rAddress::from(balance_owner.0),
                    AccountInfo {
                        balance: Default::default(),
                        nonce: 0,
                        code_hash: KECCAK_EMPTY,
                        code: None,
                    },
                    None,
                    false,
                );
            }

            for (address, bytecode) in self.stateless_contracts.iter() {
                let (code, code_hash) = if bytecode.is_none() {
                    let mut addr_str = format!("{:?}", address);
                    if addr_str.starts_with("call") {
                        addr_str = self
                            .get_address_from_call(&engine, &addr_str)?
                            .to_string();
                    }
                    let code = get_code_for_contract(&addr_str, None).await?;
                    (Some(code.clone()), code.hash_slow())
                } else {
                    let code =
                        Bytecode::new_raw(Bytes::from(bytecode.clone().ok_or_else(|| {
                            SimulationError::DecodingError(
                                "Byte code from stateless contracts is None".into(),
                            )
                        })?));
                    (Some(code.clone()), code.hash_slow())
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
            .map_err(SimulationError::SimulationEngineError)?;

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

    fn set_capabilities(&mut self) -> Result<(), SimulationError> {
        let mut capabilities = Vec::new();

        // Generate all permutations of tokens and retrieve capabilities
        for tokens_pair in self.tokens.iter().permutations(2) {
            // Manually unpack the inner vector
            if let [t0, t1] = tokens_pair[..] {
                let caps = self
                    .adapter_contract
                    .clone()
                    .ok_or_else(|| SimulationError::NotInitialized("Adapter contract".to_string()))?
                    .get_capabilities(self.id.clone()[2..].to_string(), *t0, *t1)?;
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

    pub fn set_spot_prices(&mut self, tokens: Vec<ERC20Token>) -> Result<(), SimulationError> {
        info!("Setting spot prices for pool {}", self.id);
        self.ensure_capability(Capability::PriceFunction)?;
        for [sell_token, buy_token] in tokens
            .iter()
            .permutations(2)
            .map(|p| [p[0], p[1]])
        {
            let overwrites = Some(self.get_overwrites(
                vec![(*sell_token).clone().address, (*buy_token).clone().address],
                U256::from_big_endian(&(*MAX_BALANCE / rU256::from(100)).to_be_bytes::<32>()),
            )?);
            let sell_amount_limit = self.get_sell_amount_limit(
                vec![(sell_token.address), (buy_token.address)],
                overwrites.clone(),
            )?;
            info!("Got sell amount limit for spot prices {:?}", &sell_amount_limit);
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
                    overwrites,
                )?;

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
    fn get_sell_amount_limit(
        &self,
        tokens: Vec<H160>,
        overwrites: Option<HashMap<Address, HashMap<U256, U256>>>,
    ) -> Result<U256, SimulationError> {
        let binding = self
            .adapter_contract
            .clone()
            .ok_or_else(|| SimulationError::NotInitialized("Adapter contract".to_string()))?;
        let limits = binding.get_limits(
            self.id.clone()[2..].to_string(),
            tokens[0],
            tokens[1],
            self.block.number,
            overwrites,
        );

        Ok(limits?.0)
    }

    fn get_overwrites(
        &self,
        tokens: Vec<H160>,
        max_amount: U256,
    ) -> Result<HashMap<rAddress, Overwrites>, SimulationError> {
        let token_overwrites = self.get_token_overwrites(tokens, max_amount)?;

        // Merge `block_lasting_overwrites` with `token_overwrites`
        let merged_overwrites =
            self.merge(&self.block_lasting_overwrites.clone(), &token_overwrites);

        Ok(merged_overwrites)
    }

    fn get_token_overwrites(
        &self,
        tokens: Vec<H160>,
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
            rAddress::from_slice(&sell_token.0),
            *self
                .token_storage_slots
                .get(sell_token)
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
            .fold(HashMap::new(), |acc, overwrite| self.merge(&acc, &overwrite)))
    }

    fn get_balance_overwrites(
        &self,
        tokens: Vec<H160>,
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
            let slots = if self.involved_contracts.contains(token) {
                self.token_storage_slots
                    .get(token)
                    .cloned()
                    .ok_or_else(|| {
                        SimulationError::EncodingError("Token storage slots not found".into())
                    })?
            } else {
                (SlotId::from(0), SlotId::from(1))
            };

            let mut overwrites = ERC20OverwriteFactory::new(rAddress::from(token.0), slots);
            overwrites.set_balance(
                self.balances
                    .get(token)
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
        amount_in: U256,
        token_in: &ERC20Token,
        token_out: &ERC20Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        let sell_token = token_in.address;
        let buy_token = token_out.address;
        let sell_amount = amount_in;
        let overwrites = self.get_overwrites(
            vec![sell_token, buy_token],
            U256::from_big_endian(&(*MAX_BALANCE / rU256::from(100)).to_be_bytes::<32>()),
        )?;
        let sell_amount_limit =
            self.get_sell_amount_limit(vec![sell_token, buy_token], Some(overwrites.clone()))?;
        let (sell_amount_respecting_limit, sell_amount_exceeds_limit) = if self
            .capabilities
            .contains(&Capability::HardLimits) &&
            sell_amount_limit < sell_amount
        {
            (sell_amount_limit, true)
        } else {
            (sell_amount, false)
        };

        let overwrites_with_sell_limit =
            self.get_overwrites(vec![sell_token, buy_token], sell_amount_limit)?;
        let complete_overwrites = self.merge(&overwrites, &overwrites_with_sell_limit);
        let pool_id = self.id.clone();

        let (trade, state_changes) = self
            .adapter_contract
            .as_ref()
            .ok_or_else(|| SimulationError::NotInitialized("Adapter contract".to_string()))?
            .swap(
                pool_id[2..].to_string(),
                sell_token,
                buy_token,
                false,
                sell_amount_respecting_limit,
                self.block.number,
                Some(complete_overwrites),
            )?;

        let mut new_state = self.clone();

        // Apply state changes to the new state
        for (address, state_update) in state_changes {
            if let Some(storage) = state_update.storage {
                let block_overwrites = new_state
                    .block_lasting_overwrites
                    .entry(address)
                    .or_default();
                for (slot, value) in storage {
                    let slot = U256::from_dec_str(&slot.to_string()).map_err(|_| {
                        SimulationError::DecodingError("Failed to decode slot index".to_string())
                    })?;
                    let value = U256::from_dec_str(&value.to_string()).map_err(|_| {
                        SimulationError::DecodingError(
                            "Failed to decode slot overwrite".to_string(),
                        )
                    })?;
                    block_overwrites.insert(slot, value);
                }
            }
        }

        // Update spot prices
        let new_price = trade.price;
        if new_price != 0.0f64 {
            new_state
                .spot_prices
                .insert((sell_token, buy_token), new_price);
            new_state
                .spot_prices
                .insert((buy_token, sell_token), 1.0f64 / new_price);
        }

        let buy_amount = trade.received_amount;

        if sell_amount_exceeds_limit {
            return Err(SimulationError::SellAmountTooHigh(
                // // Partial buy amount and gas used TODO: make this better
                // buy_amount,
                // trade.gas_used,
                // new_state,
                // sell_amount_limit,
            ));
        }
        Ok(GetAmountOutResult::new(buy_amount, trade.gas_used, Box::new(new_state.clone())))
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        tokens: Vec<ERC20Token>,
    ) -> Result<(), TransitionError<String>> {
        if self.manual_updates {
            // Directly check for "update_marker" in `updated_attributes`
            if let Some(marker) = delta
                .updated_attributes
                .get("update_marker")
            {
                // Assuming `marker` is of type `Bytes`, check its value for "truthiness"
                if !marker.is_empty() && marker[0] != 0 {
                    self.set_spot_prices(tokens)?;
                }
            }
        } else {
            self.set_spot_prices(tokens)?;
        }

        Ok(())
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

    fn as_any_mut(&mut self) -> &mut dyn Any {
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

    use crate::{
        evm::{simulation_db::BlockHeader, tycho_models::AccountUpdate},
        protocol::vm::models::Capability,
    };

    fn dai() -> ERC20Token {
        ERC20Token::new("0x6B175474E89094C44Da98b954EedeAC495271d0F", 18, "DAI", U256::from(10_000))
    }

    fn bal() -> ERC20Token {
        ERC20Token::new("0xba100000625a3754423978a60c9317c58a424e3D", 18, "BAL", U256::from(10_000))
    }

    async fn setup_db(asset_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let file = File::open(asset_path)?;
        let data: Value = serde_json::from_reader(file)?;

        let accounts: Vec<AccountUpdate> = serde_json::from_value(data["accounts"].clone())
            .expect("Expected accounts to match AccountUpdate structure");

        let db = SHARED_TYCHO_DB.clone();
        let engine: SimulationEngine<_> = create_engine(
            db.clone(),
            vec![to_checksum(&dai().address, None), to_checksum(&bal().address, None)],
            false,
        )?;

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
        db.update(accounts, Some(block)).await;

        Ok(())
    }

    async fn setup_pool_state() -> VMPoolState<PreCachedDB> {
        setup_db("src/protocol/vm/assets/balancer_contract_storage_block_20463609.json".as_ref())
            .await
            .expect("Failed to set up database");

        let dai_addr = dai().address;
        let bal_addr = bal().address;

        let tokens = vec![dai_addr, bal_addr];
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
        dbg!(&tokens);
        VMPoolState::<PreCachedDB>::new(
            pool_id,
            tokens,
            block,
            HashMap::from([
                (
                    EthAddress::from(dai_addr.0),
                    U256::from_dec_str("178754012737301807104").unwrap(),
                ),
                (EthAddress::from(bal_addr.0), U256::from_dec_str("91082987763369885696").unwrap()),
            ]),
            Some(EthAddress::from_str("0xBA12222222228d8Ba445958a75a0704d566BF2C8").unwrap()),
            "src/protocol/vm/assets/BalancerSwapAdapter.evm.runtime".to_string(),
            HashSet::new(),
            HashMap::new(),
            false,
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
                pool_state.tokens[0],
                pool_state.tokens[1],
            )
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
    async fn test_get_amount_out() -> Result<(), Box<dyn std::error::Error>> {
        setup_db("src/protocol/vm/assets/balancer_contract_storage_block_20463609.json".as_ref())
            .await?;

        let pool_state = setup_pool_state().await;

        let result = pool_state
            .get_amount_out(U256::from_dec_str("1000000000000000000").unwrap(), &dai(), &bal())
            .unwrap();
        let new_state = result
            .new_state
            .as_any()
            .downcast_ref::<VMPoolState<PreCachedDB>>()
            .unwrap();
        assert_eq!(result.amount, U256::from_dec_str("137780051463393923").unwrap());
        assert_eq!(result.gas, U256::from_dec_str("102770").unwrap());
        assert_ne!(new_state.spot_prices, pool_state.spot_prices);
        assert!(pool_state
            .block_lasting_overwrites
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_amount_out_dust() {
        setup_db("src/protocol/vm/assets/balancer_contract_storage_block_20463609.json".as_ref())
            .await
            .unwrap();

        let pool_state = setup_pool_state().await;

        let result = pool_state
            .get_amount_out(U256::from(1), &dai(), &bal())
            .unwrap();

        let new_state = result
            .new_state
            .as_any()
            .downcast_ref::<VMPoolState<PreCachedDB>>()
            .unwrap();
        assert_eq!(result.amount, U256::from(0));
        assert_eq!(result.gas, U256::from(68656));
        assert_eq!(new_state.spot_prices, pool_state.spot_prices)
    }

    #[tokio::test]
    async fn test_get_amount_out_sell_limit() {
        setup_db("src/protocol/vm/assets/balancer_contract_storage_block_20463609.json".as_ref())
            .await
            .unwrap();

        let pool_state = setup_pool_state().await;

        let result = pool_state.get_amount_out(
            // sell limit is 100279494253364362835
            U256::from_dec_str("100379494253364362835").unwrap(),
            &dai(),
            &bal(),
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                assert!(matches!(e, SimulationError::SellAmountTooHigh()));
            }
            _ => panic!("Test failed: was expecting an Err value"),
        };
    }

    #[tokio::test]
    async fn test_get_sell_amount_limit() {
        let pool_state = setup_pool_state().await;
        let overwrites = pool_state
            .get_overwrites(
                vec![pool_state.tokens[0], pool_state.tokens[1]],
                U256::from_big_endian(&(*MAX_BALANCE / rU256::from(100)).to_be_bytes::<32>()),
            )
            .unwrap();
        let dai_limit = pool_state
            .get_sell_amount_limit(vec![dai().address, bal().address], Some(overwrites.clone()))
            .unwrap();
        assert_eq!(dai_limit, U256::from_dec_str("100279494253364362835").unwrap());

        // let bal_limit = pool_state
        //     .get_sell_amount_limit(
        //         vec![pool_state.tokens[1], pool_state.tokens[0]],
        //         Some(overwrites),
        //     )
        //     .unwrap();
        // assert_eq!(bal_limit, U256::from_dec_str("13997408640689987484").unwrap());
    }

    #[tokio::test]
    async fn test_set_spot_prices() {
        let mut pool_state = setup_pool_state().await;

        pool_state
            .set_spot_prices(vec![bal(), dai()])
            .unwrap();

        let dai_bal_spot_price = pool_state
            .spot_prices
            .get(&(pool_state.tokens[0], pool_state.tokens[1]))
            .unwrap();
        let bal_dai_spot_price = pool_state
            .spot_prices
            .get(&(pool_state.tokens[1], pool_state.tokens[0]))
            .unwrap();
        assert_eq!(dai_bal_spot_price, &0.137_778_914_319_047_9);
        assert_eq!(bal_dai_spot_price, &7.071_503_245_428_246);
    }
}
