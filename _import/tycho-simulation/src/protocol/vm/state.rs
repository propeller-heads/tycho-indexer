// TODO: remove skip for clippy dead_code check
#![allow(dead_code)]

use std::any::Any;
use tracing::warn;

use crate::{
    evm::{
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
        utils::{get_code_for_contract, get_contract_bytecode},
    },
};
// Necessary for the init_account method to be in scope
#[allow(unused_imports)]
use crate::evm::engine_db_interface::EngineDatabaseInterface;
use crate::protocol::vm::{
    erc20_overwrite_factory::{ERC20OverwriteFactory, Overwrites},
    models::Capability,
    utils::SlotId,
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
use std::collections::{HashMap, HashSet};
use tycho_core::dto::ProtocolStateDelta;

// Necessary for the init_account method to be in scope
#[allow(unused_imports)]
use crate::protocol::{
    errors::{TradeSimulationError, TransitionError},
    events::{EVMLogMeta, LogIndex},
    models::GetAmountOutResult,
    state::{ProtocolEvent, ProtocolSim},
};

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
    engine: Option<SimulationEngine<D>>,
    /// The adapter contract. This is used to run simulations
    adapter_contract: Option<ProtosimContract<D>>,
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
    ) -> Result<Self, ProtosimError> {
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
        state.adapter_contract = Some(ProtosimContract::new(
            *ADAPTER_ADDRESS,
            state
                .engine
                .clone()
                .ok_or_else(ProtosimError::EngineNotSet)?,
        )?);
        state.set_capabilities().await?;
        // TODO: add init_token_storage_slots() in 3796
        Ok(state)
    }

    async fn set_engine(&mut self, adapter_contract_path: String) -> Result<(), ProtosimError> {
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
            let adapter_contract_code = get_contract_bytecode(&adapter_contract_path)?;

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
                            ProtosimError::DecodingError("Expected bytecode".into())
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
    ) -> Result<rAddress, ProtosimError> {
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

        let parsed_address: rAddress = to_address
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

        let address = decode(&[ParamType::Address], &sim_result.result)?
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

    async fn set_capabilities(&mut self) -> Result<(), ProtosimError> {
        let mut capabilities = Vec::new();

        // Generate all permutations of tokens and retrieve capabilities
        for tokens_pair in self.tokens.iter().permutations(2) {
            // Manually unpack the inner vector
            if let [t0, t1] = &tokens_pair[..] {
                let caps = self
                    .adapter_contract
                    .clone()
                    .ok_or_else(|| {
                        ProtosimError::UninitializedAdapter(
                            "Adapter contract must be initialized before setting capabilities"
                                .to_string(),
                        )
                    })?
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

    pub async fn set_spot_prices(&mut self, tokens: Vec<ERC20Token>) -> Result<(), ProtosimError> {
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
                .ok_or_else(|| {
                    ProtosimError::UninitializedAdapter(
                        "Adapter contract must be initialized before setting capabilities"
                            .to_string(),
                    )
                })?
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
                *price_result
                    .first()
                    .ok_or_else(|| ProtosimError::DecodingError("Expected a u64".to_string()))?
            } else {
                let unscaled_price = price_result
                    .first()
                    .ok_or_else(|| ProtosimError::DecodingError("Expected a u64".to_string()))?;
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
    ) -> Result<U256, ProtosimError> {
        let binding = self
            .adapter_contract
            .clone()
            .ok_or_else(|| {
                ProtosimError::UninitializedAdapter(
                    "Adapter contract must be initialized before setting capabilities".to_string(),
                )
            })?;
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
    ) -> Result<HashMap<rAddress, Overwrites>, ProtosimError> {
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
    ) -> Result<HashMap<rAddress, Overwrites>, ProtosimError> {
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

        res.push(overwrites.get_protosim_overwrites());

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
    ) -> Result<HashMap<rAddress, Overwrites>, ProtosimError> {
        let mut balance_overwrites: HashMap<rAddress, Overwrites> = HashMap::new();
        let address = match self.balance_owner {
            Some(address) => Ok(address),
            None => self
                .id
                .parse()
                .map_err(|_| ProtosimError::EncodingError("Pool ID is not an address".into())),
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
                        ProtosimError::EncodingError("Token storage slots not found".into())
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
            balance_overwrites.extend(overwrites.get_protosim_overwrites());
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

    async fn get_amount_out(
        &self,
        sell_token: ERC20Token,
        sell_amount: U256,
        buy_token: ERC20Token,
    ) -> Result<(U256, U256, VMPoolState<PreCachedDB>), ProtosimError> {
        if self
            .capabilities
            .contains(&Capability::HardLimits)
        {
            let sell_amount_limit = self
                .clone()
                .get_sell_amount_limit(vec![sell_token.clone(), buy_token.clone()])
                .await?;
            println!("sell_amount_limit {:?}", sell_amount_limit);
            if sell_amount_limit < sell_amount {
                let (partial_buy_amount, partial_gas_used, new_state) = self
                    .get_amount_out_no_limit_check(
                        sell_token.clone(),
                        sell_amount_limit,
                        buy_token.clone(),
                    )
                    .await?;
                return Err(ProtosimError::SellAmountTooHigh(
                    partial_buy_amount,
                    partial_gas_used,
                    new_state,
                    sell_amount_limit,
                ));
            }
        }
        self.get_amount_out_no_limit_check(sell_token, sell_amount, buy_token)
            .await
    }

    async fn get_amount_out_no_limit_check(
        &self,
        sell_token: ERC20Token,
        sell_amount: U256,
        buy_token: ERC20Token,
    ) -> Result<(U256, U256, VMPoolState<PreCachedDB>), ProtosimError> {
        let sell_amount_limit = self
            .clone()
            .get_sell_amount_limit(vec![sell_token.clone(), buy_token.clone()])
            .await?;

        let overwrites = self
            .clone()
            .get_overwrites(vec![sell_token.clone(), buy_token.clone()], sell_amount_limit)
            .await?;

        let pool_id = self.clone().id;

        let (trade, state_changes) = self
            .adapter_contract
            .clone()
            .ok_or_else(|| {
                ProtosimError::UninitializedAdapter(
                    "Adapter contract must be initialized before setting capabilities".to_string(),
                )
            })?
            .swap(
                pool_id[2..].to_string(),
                sell_token.clone().address,
                buy_token.clone().address,
                false,
                sell_amount,
                self.block.number,
                Some(overwrites),
            )
            .await?;

        let mut new_state = self.clone();

        // Apply state changes to the new state
        for (address, state_update) in state_changes {
            if let Some(storage) = state_update.storage {
                for (slot, value) in storage {
                    let slot_str = slot.to_string();
                    let value_str = value.to_string();

                    new_state
                        .block_lasting_overwrites
                        .entry(address)
                        .or_default()
                        .insert(
                            U256::from_dec_str(&slot_str).map_err(|_| {
                                ProtosimError::DecodingError(
                                    "Failed to decode slot index".to_string(),
                                )
                            })?,
                            U256::from_dec_str(&value_str).map_err(|_| {
                                ProtosimError::DecodingError(
                                    "Failed to decode slot overwrite".to_string(),
                                )
                            })?,
                        );
                }
            }
        }

        // Update spot prices
        let new_price = trade.price;
        if new_price != 0.0f64 {
            new_state
                .spot_prices
                .insert((sell_token.address, buy_token.address), new_price);
            new_state
                .spot_prices
                .insert((buy_token.address, sell_token.address), 1.0f64 / new_price);
        }

        let buy_amount = trade.received_amount;
        Ok((buy_amount, trade.gas_used, new_state))
    }
}

impl ProtocolSim for VMPoolState<PreCachedDB> {
    fn fee(&self) -> f64 {
        todo!()
    }

    fn spot_price(&self, base: &ERC20Token, quote: &ERC20Token) -> f64 {
        *self
            .spot_prices
            .get(&(base.address, quote.address))
            .expect("Spot price not found")
    }

    fn get_amount_out(
        &self,
        _amount_in: U256,
        _token_in: &ERC20Token,
        _token_out: &ERC20Token,
    ) -> Result<GetAmountOutResult, TradeSimulationError> {
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
    use std::{
        collections::{HashMap, HashSet},
        fs::File,
        path::Path,
        str::FromStr,
    };

    use ethers::{
        prelude::{H256, U256},
        types::Address as EthAddress,
    };
    use serde_json::Value;

    use crate::{
        evm::{simulation_db::BlockHeader, tycho_models::AccountUpdate},
        models::ERC20Token,
        protocol::vm::models::Capability,
    };

    use super::*;

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
        let db_write = db.write().await;
        db_write
            .update(accounts, Some(block))
            .await;

        let onchain_bytecode = revm::precompile::Bytes::from(ethers::utils::hex::decode("608060405234801561000f575f80fd5b50600436106100a6575f3560e01c8063395093511161006e578063395093511461011f57806370a082311461013257806395d89b411461015a578063a457c2d714610162578063a9059cbb14610175578063dd62ed3e14610188575f80fd5b806306fdde03146100aa578063095ea7b3146100c857806318160ddd146100eb57806323b872dd146100fd578063313ce56714610110575b5f80fd5b6100b261019b565b6040516100bf91906105b9565b60405180910390f35b6100db6100d636600461061f565b61022b565b60405190151581526020016100bf565b6002545b6040519081526020016100bf565b6100db61010b366004610647565b610244565b604051601281526020016100bf565b6100db61012d36600461061f565b610267565b6100ef610140366004610680565b6001600160a01b03165f9081526020819052604090205490565b6100b2610288565b6100db61017036600461061f565b610297565b6100db61018336600461061f565b6102f2565b6100ef6101963660046106a0565b6102ff565b6060600380546101aa906106d1565b80601f01602080910402602001604051908101604052809291908181526020018280546101d6906106d1565b80156102215780601f106101f857610100808354040283529160200191610221565b820191905f5260205f20905b81548152906001019060200180831161020457829003601f168201915b5050505050905090565b5f33610238818585610329565b60019150505b92915050565b5f336102518582856103dc565b61025c85858561043e565b506001949350505050565b5f3361023881858561027983836102ff565b6102839190610709565b610329565b6060600480546101aa906106d1565b5f33816102a482866102ff565b9050838110156102e557604051632983c0c360e21b81526001600160a01b038616600482015260248101829052604481018590526064015b60405180910390fd5b61025c8286868403610329565b5f3361023881858561043e565b6001600160a01b039182165f90815260016020908152604080832093909416825291909152205490565b6001600160a01b0383166103525760405163e602df0560e01b81525f60048201526024016102dc565b6001600160a01b03821661037b57604051634a1406b160e11b81525f60048201526024016102dc565b6001600160a01b038381165f8181526001602090815260408083209487168084529482529182902085905590518481527f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92591015b60405180910390a3505050565b5f6103e784846102ff565b90505f198114610438578181101561042b57604051637dc7a0d960e11b81526001600160a01b038416600482015260248101829052604481018390526064016102dc565b6104388484848403610329565b50505050565b6001600160a01b03831661046757604051634b637e8f60e11b81525f60048201526024016102dc565b6001600160a01b0382166104905760405163ec442f0560e01b81525f60048201526024016102dc565b61049b8383836104a0565b505050565b6001600160a01b0383166104ca578060025f8282546104bf9190610709565b9091555061053a9050565b6001600160a01b0383165f908152602081905260409020548181101561051c5760405163391434e360e21b81526001600160a01b038516600482015260248101829052604481018390526064016102dc565b6001600160a01b0384165f9081526020819052604090209082900390555b6001600160a01b03821661055657600280548290039055610574565b6001600160a01b0382165f9081526020819052604090208054820190555b816001600160a01b0316836001600160a01b03167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040516103cf91815260200190565b5f6020808352835180828501525f5b818110156105e4578581018301518582016040015282016105c8565b505f604082860101526040601f19601f8301168501019250505092915050565b80356001600160a01b038116811461061a575f80fd5b919050565b5f8060408385031215610630575f80fd5b61063983610604565b946020939093013593505050565b5f805f60608486031215610659575f80fd5b61066284610604565b925061067060208501610604565b9150604084013590509250925092565b5f60208284031215610690575f80fd5b61069982610604565b9392505050565b5f80604083850312156106b1575f80fd5b6106ba83610604565b91506106c860208401610604565b90509250929050565b600181811c908216806106e557607f821691505b60208210810361070357634e487b7160e01b5f52602260045260245ffd5b50919050565b8082018082111561023e57634e487b7160e01b5f52601160045260245ffdfea2646970667358221220dfc123d5852c9246ea16b645b377b4436e2f778438195cc6d6c435e8c73a20e764736f6c63430008140033000000000000000000000000000000000000000000000000000000000000000000")?);
        let code = Bytecode::new_raw(onchain_bytecode);
        let contract_acc_info = AccountInfo::new(rU256::from(0), 0, code.hash_slow(), code);

        // Adding permanent storage for balance and approval - necessary for amount out calculation
        let mut storage = HashMap::default();
        // balance of EOA
        storage.insert(
            rU256::from_str(
                "110136159478993350616340414857413728709904511599989695046923576775517543504731",
            )
            .unwrap(),
            rU256::from_str("2500000000000000000000000000000000000").unwrap(),
        );
        // allowance for Adapter contract to spend EOA's DAI
        storage.insert(
            rU256::from_str(
                "58546993237423525698686728856645416951692145960565761888391937184176623942864",
            )
            .unwrap(),
            rU256::from_str("2500000000000000000000000000000000000").unwrap(),
        );
        let dai = ERC20Token::new(
            "0x6b175474e89094c44da98b954eedeac495271d0f",
            18,
            "DAI",
            U256::from(10_000),
        );
        db_write.init_account(
            rAddress::from_slice(dai.address.as_bytes()),
            contract_acc_info,
            Some(storage),
            true,
        );
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
    async fn test_get_amount_out() {
        setup_db("src/protocol/vm/assets/balancer_contract_storage_block_20463609.json".as_ref())
            .await
            .unwrap();

        let pool_state = setup_pool_state().await;

        let (amount_out, gas_used, new_state) = pool_state
            .get_amount_out(
                pool_state.tokens[0].clone(),
                U256::from_dec_str("1000000000000000000").unwrap(),
                pool_state.tokens[1].clone(),
            )
            .await
            .unwrap();

        assert_eq!(amount_out, U256::from_dec_str("137780051463393923").unwrap());
        assert_eq!(gas_used, U256::from_dec_str("89623").unwrap());
        assert_ne!(new_state.spot_prices, pool_state.spot_prices);
        // Assert 3 entries in block lasting overwrites: one for the in token, one for the out
        // token, and one for the balancer vault.
        assert_eq!(new_state.block_lasting_overwrites.len(), 3);
    }

    #[tokio::test]
    async fn test_get_amount_out_sell_limit() {
        setup_db("src/protocol/vm/assets/balancer_contract_storage_block_20463609.json".as_ref())
            .await
            .unwrap();

        let pool_state = setup_pool_state().await;

        let result = pool_state
            .get_amount_out(
                pool_state.tokens[0].clone(),
                // sell limit is 100279494253364362835
                U256::from_dec_str("100379494253364362835").unwrap(),
                pool_state.tokens[1].clone(),
            )
            .await;

        assert!(result.is_err());
        match result {
            Err(e) => {
                assert!(matches!(e, ProtosimError::SellAmountTooHigh(_, _, _, _)));
            }
            _ => panic!("Test failed: was expecting an Err value"),
        };
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
