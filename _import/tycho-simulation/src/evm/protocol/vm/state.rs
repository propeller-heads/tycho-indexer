use std::{
    any::Any,
    collections::{HashMap, HashSet},
};

use alloy_primitives::Address;
use ethers::{prelude::U256, types::H160};
use itertools::Itertools;
use revm::{precompile::Address as rAddress, primitives::U256 as rU256, DatabaseRef};
use tracing::info;

use tycho_core::dto::ProtocolStateDelta;

use crate::{
    evm::{
        engine_db::{
            engine_db_interface::EngineDatabaseInterface, simulation_db::BlockHeader,
            tycho_db::PreCachedDB,
        },
        ContractCompiler, SlotId,
    },
    models::ERC20Token,
    protocol::{
        errors::{SimulationError, TransitionError},
        events::{EVMLogMeta, LogIndex},
        models::GetAmountOutResult,
        state::{ProtocolEvent, ProtocolSim},
    },
};

use super::{
    constants::{ADAPTER_ADDRESS, EXTERNAL_ACCOUNT, MAX_BALANCE},
    erc20_overwrite_factory::{ERC20OverwriteFactory, Overwrites},
    models::Capability,
    tycho_simulation_contract::TychoSimulationContract,
    utils::{hexstring_to_vec, ERC20Slots},
};

#[derive(Clone, Debug)]
pub struct EVMPoolState<D: EngineDatabaseInterface + Clone>
where
    <D as DatabaseRef>::Error: std::fmt::Debug,
    <D as EngineDatabaseInterface>::Error: std::fmt::Debug,
{
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
    /// Each entry also specify the compiler with which the target contract was compiled. This is
    /// later used to compute storage slot for maps.
    pub token_storage_slots: HashMap<H160, (ERC20Slots, ContractCompiler)>,
    /// Indicates if the protocol uses custom update rules and requires update
    /// triggers to recalculate spot prices ect. Default is to update on all changes on
    /// the pool.
    pub manual_updates: bool,
    /// The adapter contract. This is used to run simulations
    adapter_contract: TychoSimulationContract<D>,
}

impl EVMPoolState<PreCachedDB> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        tokens: Vec<H160>,
        block: BlockHeader,
        balances: HashMap<H160, U256>,
        balance_owner: Option<H160>,
        spot_prices: HashMap<(H160, H160), f64>,
        capabilities: HashSet<Capability>,
        block_lasting_overwrites: HashMap<rAddress, Overwrites>,
        involved_contracts: HashSet<H160>,
        token_storage_slots: HashMap<H160, (ERC20Slots, ContractCompiler)>,
        manual_updates: bool,
        adapter_contract: TychoSimulationContract<PreCachedDB>,
    ) -> Self {
        Self {
            id,
            tokens,
            block,
            balances,
            balance_owner,
            spot_prices,
            capabilities,
            block_lasting_overwrites,
            involved_contracts,
            token_storage_slots,
            manual_updates,
            adapter_contract,
        }
    }

    /// Ensures the pool supports the given capability
    fn ensure_capability(&self, capability: Capability) -> Result<(), SimulationError> {
        if !self.capabilities.contains(&capability) {
            return Err(SimulationError::FatalError(format!(
                "capability {:?} not supported",
                capability.to_string()
            )));
        }
        Ok(())
    }

    pub fn set_spot_prices(&mut self, tokens: Vec<ERC20Token>) -> Result<(), SimulationError> {
        info!("Setting spot prices for pool {}", self.id.clone());
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
            let pool_id_vec = hexstring_to_vec(&self.id.clone())?;
            let price_result = self.adapter_contract.price(
                pool_id_vec,
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
                    SimulationError::FatalError("Spot price is not a u64".to_string())
                })?
            } else {
                let unscaled_price = price_result.first().ok_or_else(|| {
                    SimulationError::FatalError("Spot price is not a u64".to_string())
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
        let pool_id_vec = hexstring_to_vec(&self.id.clone())?;
        let limits = self.adapter_contract.get_limits(
            pool_id_vec,
            tokens[0],
            tokens[1],
            self.block.number,
            overwrites,
        );

        Ok(limits?.0)
    }

    fn clear_all_cache(&mut self, tokens: Vec<ERC20Token>) -> Result<(), SimulationError> {
        self.adapter_contract
            .engine
            .clear_temp_storage();
        self.block_lasting_overwrites.clear();
        self.set_spot_prices(tokens)?;
        Ok(())
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

        let (slots, compiler) = self
            .token_storage_slots
            .get(sell_token)
            .cloned()
            .unwrap_or((
                ERC20Slots::new(SlotId::from(0), SlotId::from(1)),
                ContractCompiler::Solidity,
            ));

        let mut overwrites = ERC20OverwriteFactory::new(
            rAddress::from_slice(&sell_token.0),
            slots.clone(),
            compiler,
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
            None => self.id.parse().map_err(|_| {
                SimulationError::FatalError(
                    "Failed to get balance overwrites: Pool ID is not an address".into(),
                )
            }),
        }?;

        for token in &tokens {
            let (slots, compiler) = if self.involved_contracts.contains(token) {
                self.token_storage_slots
                    .get(token)
                    .cloned()
                    .ok_or_else(|| {
                        SimulationError::FatalError(
                            "Failed to get balance overwrites: Token storage slots not found"
                                .into(),
                        )
                    })?
            } else {
                (ERC20Slots::new(SlotId::from(0), SlotId::from(1)), ContractCompiler::Solidity)
            };

            let mut overwrites =
                ERC20OverwriteFactory::new(rAddress::from(token.0), slots, compiler);
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

impl ProtocolSim for EVMPoolState<PreCachedDB> {
    fn fee(&self) -> f64 {
        todo!()
    }

    fn spot_price(&self, base: &ERC20Token, quote: &ERC20Token) -> Result<f64, SimulationError> {
        self.spot_prices
            .get(&(base.address, quote.address))
            .cloned()
            .ok_or(SimulationError::FatalError(format!(
                "Spot price not found for base token {} and quote token {}",
                base.address, quote.address
            )))
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
        let pool_id_vec = hexstring_to_vec(&pool_id).unwrap();

        let (trade, state_changes) = self.adapter_contract.swap(
            pool_id_vec,
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
                        SimulationError::FatalError("Failed to decode slot index".to_string())
                    })?;
                    let value = U256::from_dec_str(&value.to_string()).map_err(|_| {
                        SimulationError::FatalError("Failed to decode slot overwrite".to_string())
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
            return Err(SimulationError::InvalidInput(
                format!("Sell amount exceeds limit {}", sell_amount_limit),
                Some(GetAmountOutResult::new(
                    buy_amount,
                    trade.gas_used,
                    Box::new(new_state.clone()),
                )),
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
                    self.clear_all_cache(tokens)?;
                }
            }
        } else {
            self.clear_all_cache(tokens)?;
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
            .downcast_ref::<EVMPoolState<PreCachedDB>>()
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

    use super::super::{models::Capability, state_builder::EVMPoolStateBuilder};

    use std::str::FromStr;

    use ethers::{prelude::H256, types::Address as EthAddress, utils::to_checksum};
    use revm::primitives::{AccountInfo, Bytecode, KECCAK_EMPTY};
    use serde_json::Value;

    use crate::evm::{
        engine_db::{create_engine, SHARED_TYCHO_DB},
        simulation::SimulationEngine,
        tycho_models::AccountUpdate,
    };

    fn dai() -> ERC20Token {
        ERC20Token::new("0x6b175474e89094c44da98b954eedeac495271d0f", 18, "DAI", U256::from(10_000))
    }

    fn bal() -> ERC20Token {
        ERC20Token::new("0xba100000625a3754423978a60c9317c58a424e3d", 18, "BAL", U256::from(10_000))
    }

    async fn setup_pool_state() -> EVMPoolState<PreCachedDB> {
        let data_str = include_str!("assets/balancer_contract_storage_block_20463609.json");
        let data: Value = serde_json::from_str(data_str).expect("Failed to parse JSON");

        let accounts: Vec<AccountUpdate> = serde_json::from_value(data["accounts"].clone())
            .expect("Expected accounts to match AccountUpdate structure");

        let db = SHARED_TYCHO_DB.clone();
        let engine: SimulationEngine<_> = create_engine(db.clone(), false).unwrap();

        let block = BlockHeader {
            number: 20463609,
            hash: H256::from_str(
                "0x4315fd1afc25cc2ebc72029c543293f9fd833eeb305e2e30159459c827733b1b",
            )
            .unwrap(),
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
        db.update(accounts, Some(block));

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

        let stateless_contracts = HashMap::from([(
            String::from("0x3de27efa2f1aa663ae5d458857e731c129069f29"),
            Some(Vec::new()),
        )]);

        EVMPoolStateBuilder::new(pool_id, tokens, block)
            .balances(HashMap::from([
                (
                    EthAddress::from(dai_addr.0),
                    U256::from_dec_str("178754012737301807104").unwrap(),
                ),
                (EthAddress::from(bal_addr.0), U256::from_dec_str("91082987763369885696").unwrap()),
            ]))
            .balance_owner(
                EthAddress::from_str("0xBA12222222228d8Ba445958a75a0704d566BF2C8").unwrap(),
            )
            .adapter_contract_path(
                "src/evm/protocol/vm/assets/BalancerSwapAdapter.evm.runtime".to_string(),
            )
            .stateless_contracts(stateless_contracts)
            .build()
            .await
            .expect("Failed to build pool state")
    }

    #[tokio::test]
    async fn test_init() {
        let pool_state = setup_pool_state().await;

        let expected_capabilities = vec![
            Capability::SellSide,
            Capability::BuySide,
            Capability::PriceFunction,
            Capability::HardLimits,
        ]
        .into_iter()
        .collect::<HashSet<_>>();

        let pool_id_vec = hexstring_to_vec(&pool_state.id).unwrap();

        let capabilities_adapter_contract = pool_state
            .adapter_contract
            .get_capabilities(pool_id_vec, pool_state.tokens[0], pool_state.tokens[1])
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

        // Verify all tokens are initialized in the engine
        let engine_accounts = pool_state
            .adapter_contract
            .engine
            .state
            .clone()
            .get_account_storage();
        for token in pool_state.tokens.clone() {
            let token_address = rAddress::parse_checksummed(to_checksum(&token, None), None)
                .expect("valid checksum");
            let account = engine_accounts
                .get_account_info(&token_address)
                .unwrap();
            assert_eq!(account.balance, rU256::from(0));
            assert_eq!(account.nonce, 0u64);
            assert_eq!(account.code_hash, KECCAK_EMPTY);
            assert!(account.code.is_some());
        }

        // Verify external account is initialized in the engine
        let external_account = engine_accounts
            .get_account_info(&EXTERNAL_ACCOUNT)
            .unwrap();
        assert_eq!(external_account.balance, rU256::from(*MAX_BALANCE));
        assert_eq!(external_account.nonce, 0u64);
        assert_eq!(external_account.code_hash, KECCAK_EMPTY);
        assert!(external_account.code.is_none());
    }

    #[tokio::test]
    async fn test_get_amount_out() -> Result<(), Box<dyn std::error::Error>> {
        let pool_state = setup_pool_state().await;

        let result = pool_state
            .get_amount_out(U256::from_dec_str("1000000000000000000").unwrap(), &dai(), &bal())
            .unwrap();
        let new_state = result
            .new_state
            .as_any()
            .downcast_ref::<EVMPoolState<PreCachedDB>>()
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
        let pool_state = setup_pool_state().await;

        let result = pool_state
            .get_amount_out(U256::from(1), &dai(), &bal())
            .unwrap();

        let new_state = result
            .new_state
            .as_any()
            .downcast_ref::<EVMPoolState<PreCachedDB>>()
            .unwrap();
        assert_eq!(result.amount, U256::from(0));
        assert_eq!(result.gas, U256::from(68656));
        assert_eq!(new_state.spot_prices, pool_state.spot_prices)
    }

    #[tokio::test]
    async fn test_get_amount_out_sell_limit() {
        let pool_state = setup_pool_state().await;

        let result = pool_state.get_amount_out(
            // sell limit is 100279494253364362835
            U256::from_dec_str("100379494253364362835").unwrap(),
            &dai(),
            &bal(),
        );

        assert!(result.is_err());

        match result {
            Err(SimulationError::InvalidInput(msg1, amount_out_result)) => {
                assert_eq!(msg1, "Sell amount exceeds limit 100279494253364362835");
                assert!(amount_out_result.is_some());
            }
            _ => panic!("Test failed: was expecting an Err(SimulationError::RetryDifferentInput(_, _)) value"),
        }
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
