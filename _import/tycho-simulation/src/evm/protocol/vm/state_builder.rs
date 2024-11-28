use std::collections::{HashMap, HashSet};

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
    primitives::{alloy_primitives::Keccak256, AccountInfo, Bytecode, KECCAK_EMPTY},
};
use tracing::warn;

use crate::{
    evm::{
        engine_db::{
            create_engine, engine_db_interface::EngineDatabaseInterface,
            simulation_db::BlockHeader, tycho_db::PreCachedDB, SHARED_TYCHO_DB,
        },
        simulation::{SimulationEngine, SimulationParameters},
        token, ContractCompiler,
    },
    protocol::errors::SimulationError,
};

use super::{
    constants::{ADAPTER_ADDRESS, EXTERNAL_ACCOUNT, MAX_BALANCE},
    models::Capability,
    state::EVMPoolState,
    tycho_simulation_contract::TychoSimulationContract,
    utils::{get_code_for_contract, hexstring_to_vec, load_erc20_bytecode, ERC20Slots},
};

#[derive(Debug)]
/// `VMPoolStateBuilder` is a builder pattern implementation for creating instances of
/// `VMPoolState`.
///
/// This struct provides a flexible way to construct `VMPoolState` objects with
/// multiple optional parameters. It handles the validation of required fields and applies default
/// values for optional parameters where necessary.
/// # Example
/// Constructing a `VMPoolState` with only the required parameters:
/// ```rust
/// use ethers::types::H160;
/// use crate::evm::simulation_db::BlockHeader;
/// use crate::protocol::errors::SimulationError;
///
/// #[tokio::main]
/// async fn main() -> Result<(), SimulationError> {
///     // Required parameters
///     let pool_id = "0xabc123".to_string();
///     let tokens = vec![H160::zero()];
///     let block = BlockHeader {
///         number: 1,
///         hash: Default::default(),
///         timestamp: 1632456789,
///     };
///     
///     // Optional: Add token balances
///     let mut balances = HashMap::new();
///     balances.insert(H160::zero(), U256::from(1000));
///
///     // Build the VMPoolState
///     let pool_state = VMPoolStateBuilder::new(pool_id, tokens, block)
///         .balances(balances)
///         .build()
///         .await?;
///
///     println!("Successfully created VMPoolState: {:?}", pool_state);
///     Ok(())
/// }
/// ```
pub struct VMPoolStateBuilder {
    id: String,
    tokens: Vec<H160>,
    block: BlockHeader,
    balances: Option<HashMap<H160, U256>>,
    balance_owner: Option<H160>,
    capabilities: Option<HashSet<Capability>>,
    involved_contracts: Option<HashSet<H160>>,
    stateless_contracts: Option<HashMap<String, Option<Vec<u8>>>>,
    token_storage_slots: Option<HashMap<H160, (ERC20Slots, ContractCompiler)>>,
    manual_updates: Option<bool>,
    trace: Option<bool>,
    engine: Option<SimulationEngine<PreCachedDB>>,
    adapter_contract: Option<TychoSimulationContract<PreCachedDB>>,
    adapter_contract_path: Option<String>,
}

impl VMPoolStateBuilder {
    pub fn new(id: String, tokens: Vec<H160>, block: BlockHeader) -> Self {
        Self {
            id,
            tokens,
            block,
            balances: None,
            balance_owner: None,
            capabilities: None,
            involved_contracts: None,
            stateless_contracts: None,
            token_storage_slots: None,
            manual_updates: None,
            trace: None,
            engine: None,
            adapter_contract: None,
            adapter_contract_path: None,
        }
    }

    pub fn balances(mut self, balances: HashMap<H160, U256>) -> Self {
        self.balances = Some(balances);
        self
    }

    pub fn balance_owner(mut self, balance_owner: H160) -> Self {
        self.balance_owner = Some(balance_owner);
        self
    }

    pub fn capabilities(mut self, capabilities: HashSet<Capability>) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    pub fn involved_contracts(mut self, involved_contracts: HashSet<H160>) -> Self {
        self.involved_contracts = Some(involved_contracts);
        self
    }

    pub fn stateless_contracts(
        mut self,
        stateless_contracts: HashMap<String, Option<Vec<u8>>>,
    ) -> Self {
        self.stateless_contracts = Some(stateless_contracts);
        self
    }

    pub fn token_storage_slots(
        mut self,
        token_storage_slots: HashMap<H160, (ERC20Slots, ContractCompiler)>,
    ) -> Self {
        self.token_storage_slots = Some(token_storage_slots);
        self
    }

    pub fn manual_updates(mut self, manual_updates: bool) -> Self {
        self.manual_updates = Some(manual_updates);
        self
    }

    pub fn trace(mut self, trace: bool) -> Self {
        self.trace = Some(trace);
        self
    }

    pub fn engine(mut self, engine: SimulationEngine<PreCachedDB>) -> Self {
        self.engine = Some(engine);
        self
    }

    pub fn adapter_contract(
        mut self,
        adapter_contract: TychoSimulationContract<PreCachedDB>,
    ) -> Self {
        self.adapter_contract = Some(adapter_contract);
        self
    }

    pub fn adapter_contract_path(mut self, adapter_contract_path: String) -> Self {
        self.adapter_contract_path = Some(adapter_contract_path);
        self
    }

    /// Build the final VMPoolState object
    pub async fn build(mut self) -> Result<EVMPoolState<PreCachedDB>, SimulationError> {
        let engine = if let Some(engine) = &self.engine {
            engine.clone()
        } else {
            self.get_default_engine().await?
        };

        if self.adapter_contract.is_none() {
            self.adapter_contract = Some(TychoSimulationContract::new_swap_adapter(
                *ADAPTER_ADDRESS,
                self.adapter_contract_path
                    .as_ref()
                    .ok_or_else(|| {
                        SimulationError::FatalError("Adapter contract path not set".to_string())
                    })?,
                engine.clone(),
            )?)
        };

        self.init_token_storage_slots()?;
        let capabilities = if let Some(capabilities) = &self.capabilities {
            capabilities.clone()
        } else {
            self.get_default_capabilities()?
        };
        Ok(EVMPoolState::new(
            self.id,
            self.tokens,
            self.block,
            self.balances.unwrap_or_default(),
            self.balance_owner,
            HashMap::new(),
            capabilities,
            HashMap::new(),
            self.involved_contracts
                .unwrap_or_default(),
            self.token_storage_slots
                .unwrap_or_default(),
            self.manual_updates.unwrap_or(false),
            self.adapter_contract.ok_or_else(|| {
                SimulationError::FatalError(
                    "Failed to get build engine: Adapter contract not initialized".to_string(),
                )
            })?,
        ))
    }

    async fn get_default_engine(
        &mut self,
    ) -> Result<SimulationEngine<PreCachedDB>, SimulationError> {
        let engine = create_engine(SHARED_TYCHO_DB.clone(), self.trace.unwrap_or(false))?;

        // Mock the ERC20 contract at the given token addresses.
        let mocked_contract_bytecode: Bytecode = load_erc20_bytecode()?;
        for token_address in &self.tokens {
            let info = AccountInfo {
                balance: Default::default(),
                nonce: 0,
                code_hash: KECCAK_EMPTY,
                code: Some(mocked_contract_bytecode.clone()),
            };
            engine.state.init_account(
                Address::parse_checksummed(to_checksum(token_address, None), None).map_err(
                    |_| {
                        SimulationError::FatalError(
                            "Failed to get default engine: Checksum for token address must be valid".into(),
                        )
                    },
                )?,
                info,
                None,
                false,
            );
        }

        engine.state.init_account(
            *EXTERNAL_ACCOUNT,
            AccountInfo { balance: *MAX_BALANCE, nonce: 0, code_hash: KECCAK_EMPTY, code: None },
            None,
            false,
        );

        if let Some(stateless_contracts) = &self.stateless_contracts {
            for (address, bytecode) in stateless_contracts.iter() {
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
                            SimulationError::FatalError(
                                "Failed to get default engine: Byte code from stateless contracts is None".into(),
                            )
                        })?));
                    (Some(code.clone()), code.hash_slow())
                };
                engine.state.init_account(
                    rAddress::parse_checksummed(
                        to_checksum(
                            &address.parse().map_err(|_| {
                                SimulationError::FatalError(
                                    format!("Failed to get default engine: Couldn't parse address into string {}", address),
                                )
                            })?,
                            None,
                        ),
                        None,
                    )
                    .expect("Invalid checksum for external account address"),
                    AccountInfo { balance: Default::default(), nonce: 0, code_hash, code },
                    None,
                    false,
                );
            }
        }
        Ok(engine)
    }

    fn init_token_storage_slots(&mut self) -> Result<(), SimulationError> {
        for t in self.tokens.iter() {
            if self
                .involved_contracts
                .as_ref()
                .is_some_and(|contracts| contracts.contains(t)) &&
                !self
                    .token_storage_slots
                    .as_ref()
                    .is_some_and(|token_storage| token_storage.contains_key(t))
            {
                self.token_storage_slots
                    .get_or_insert(HashMap::new())
                    .insert(
                        *t,
                        token::brute_force_slots(
                            t,
                            &self.block,
                            self.engine
                                .as_ref()
                                .expect("engine should be set"),
                        )?,
                    );
            }
        }
        Ok(())
    }

    fn get_default_capabilities(&mut self) -> Result<HashSet<Capability>, SimulationError> {
        let mut capabilities = Vec::new();

        // Generate all permutations of tokens and retrieve capabilities
        for tokens_pair in self.tokens.iter().permutations(2) {
            // Manually unpack the inner vector
            if let [t0, t1] = tokens_pair[..] {
                let caps = self
                    .adapter_contract
                    .clone()
                    .ok_or_else(|| {
                        SimulationError::FatalError(
                            "Failed to get default capabilities: Adapter contract not initialized"
                                .to_string(),
                        )
                    })?
                    .get_capabilities(hexstring_to_vec(&self.id)?, *t0, *t1)?;
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

        // Check for mismatches in capabilities
        if common_capabilities.len() < max_capabilities {
            warn!(
                "Warning: Pool {} has different capabilities depending on the token pair!",
                self.id
            );
        }
        Ok(common_capabilities)
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
                SimulationError::FatalError(
                    "Failed to get address from call: Could not decode method name from call"
                        .into(),
                )
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
                SimulationError::FatalError(
                    "Failed to get address from call: Could not decode to_address from call".into(),
                )
            })?;

        let timestamp = Utc::now()
            .naive_utc()
            .and_utc()
            .timestamp() as u64;

        let parsed_address: rAddress = to_address.parse().map_err(|_| {
            SimulationError::FatalError(format!(
                "Failed to get address from call: Invalid address format: {}",
                to_address
            ))
        })?;

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
            .map_err(|err| SimulationError::FatalError(err.to_string()))?;

        let address = decode(&[ParamType::Address], &sim_result.result)
            .map_err(|_| {
                SimulationError::FatalError(
                    "Failed to get address from call: Failed to decode address list from simulation result".into(),
                )
            })?
            .into_iter()
            .next()
            .ok_or_else(|| {
                SimulationError::FatalError(
                    "Failed to get address from call: Couldn't retrieve address from simulation for stateless contracts".into(),
                )
            })?;

        address
            .to_string()
            .parse()
            .map_err(|_| {
                SimulationError::FatalError(format!(
                    "Failed to get address from call: Couldn't parse address to string: {}",
                    address
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use ethers::types::H256;

    #[test]
    fn test_build_without_required_fields() {
        let id = "pool_1".to_string();
        let tokens = vec![H160::zero()];
        let block = BlockHeader { number: 1, hash: H256::default(), timestamp: 234 };

        let result = tokio_test::block_on(VMPoolStateBuilder::new(id, tokens, block).build());

        assert!(result.is_err());
        match result.unwrap_err() {
            SimulationError::FatalError(field) => {
                assert_eq!(field, "Adapter contract path not set")
            }
            _ => panic!("Unexpected error type"),
        }
    }

    #[test]
    fn test_engine_setup() {
        let id = "pool_1".to_string();
        let token2 = H160::from_str("0000000000000000000000000000000000000002").unwrap();
        let token3 = H160::from_str("0000000000000000000000000000000000000003").unwrap();
        let tokens = vec![token2, token3];
        let block = BlockHeader { number: 1, hash: H256::default(), timestamp: 234 };

        let mut builder = VMPoolStateBuilder::new(id, tokens, block);

        let engine = tokio_test::block_on(builder.get_default_engine()).unwrap();

        assert!(engine
            .state
            .get_account_storage()
            .account_present(&Address::from_slice(token2.as_bytes())));
        assert!(engine
            .state
            .get_account_storage()
            .account_present(&Address::from_slice(token3.as_bytes())));
    }
}
