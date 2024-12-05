use alloy_primitives::Address;
use std::{collections::HashMap, str::FromStr};

use ethers::{
    abi::{Abi, Token},
    types::{H160, U256},
};
use lazy_static::lazy_static;
use revm::DatabaseRef;
use serde_json::from_str;

use crate::{
    evm::{
        engine_db::{engine_db_interface::EngineDatabaseInterface, simulation_db::BlockHeader},
        simulation::SimulationEngine,
        ContractCompiler, SlotId,
    },
    protocol::errors::SimulationError,
};

use super::{
    constants::EXTERNAL_ACCOUNT, tycho_simulation_contract::TychoSimulationContract,
    utils::get_storage_slot_index_at_key,
};

#[derive(Clone, Debug, PartialEq)]
/// A struct representing ERC20 tokens storage slots.
pub struct ERC20Slots {
    // Base slot for the balance map
    pub balance_map: SlotId,
    // Base slot for the allowance map
    pub allowance_map: SlotId,
}

impl ERC20Slots {
    pub fn new(balance: SlotId, allowance: SlotId) -> Self {
        Self { balance_map: balance, allowance_map: allowance }
    }
}

pub type Overwrites = HashMap<SlotId, U256>;

pub struct ERC20OverwriteFactory {
    token_address: Address,
    overwrites: Overwrites,
    balance_slot: SlotId,
    allowance_slot: SlotId,
    total_supply_slot: SlotId,
    compiler: ContractCompiler,
}

impl ERC20OverwriteFactory {
    pub fn new(
        token_address: Address,
        token_slots: ERC20Slots,
        compiler: ContractCompiler,
    ) -> Self {
        ERC20OverwriteFactory {
            token_address,
            overwrites: HashMap::new(),
            balance_slot: token_slots.balance_map,
            allowance_slot: token_slots.allowance_map,
            total_supply_slot: SlotId::from(2),
            compiler,
        }
    }

    pub fn set_balance(&mut self, balance: U256, owner: Address) {
        let storage_index = get_storage_slot_index_at_key(owner, self.balance_slot, self.compiler);
        self.overwrites
            .insert(storage_index, balance);
    }

    pub fn set_allowance(&mut self, allowance: U256, spender: Address, owner: Address) {
        let owner_slot = get_storage_slot_index_at_key(owner, self.allowance_slot, self.compiler);
        let storage_index = get_storage_slot_index_at_key(spender, owner_slot, self.compiler);
        self.overwrites
            .insert(storage_index, allowance);
    }

    // TODO: remove skip when we check if this is needed
    #[allow(dead_code)]
    pub fn set_total_supply(&mut self, supply: U256) {
        self.overwrites
            .insert(self.total_supply_slot, supply);
    }

    pub fn get_overwrites(&self) -> HashMap<Address, Overwrites> {
        let mut result = HashMap::new();
        result.insert(self.token_address, self.overwrites.clone());
        result
    }
}

const MARKER_VALUE: u128 = 3141592653589793238462643383;
const SPENDER: &str = "08d967bb0134F2d07f7cfb6E246680c53927DD30";
lazy_static! {
    static ref ERC20_ABI: Abi = {
        let abi_file_path = "src/evm/protocol/vm/assets/ERC20.abi";
        let abi_json = std::fs::read_to_string(abi_file_path).expect("Failed to read ABI file");
        from_str(&abi_json).expect("Failed to parse ABI JSON")
    };
}

/// Brute-force detection of storage slots for token balances and allowances.
///
/// This function attempts to determine the storage slots used by a token contract
/// for storing balance and allowance values. It systematically tests different
/// storage locations by overwriting slots and checking whether the overwritten
/// value produces the expected result when making calls to `balanceOf` or `allowance`.
///
/// # Parameters
///
/// * `token_addr` - A reference to the token's address (`H160`).
/// * `block` - The block header at which the simulation is executed.
/// * `engine` - The simulation engine used to simulate the blockchain environment.
///
/// # Returns
///
/// A `Result` containing:
/// - `Ok((ERC20Slots, ContractCompiler))`: A tuple of detected storage slots (`ERC20Slots`) for
///   balances and allowances, and the compiler type (`ContractCompiler`) used for the token
///   contract.
/// - `Err(TokenError)`: if the function fails to detect a valid slot for either balances or
///   allowances after checking the first 100 slots.
///
/// # Notes
///
/// - This function tests slots in the range 0–99 for both balance and allowance detection.
/// - The simulation engine is used to overwrite storage slots and simulate contract calls with the
///   `balanceOf` and `allowance` functions.
/// - Different compiler configurations (`Solidity` and `Vyper`) are tested to determine the correct
///   storage layout of the contract.
///
/// # Implementation Details
///
/// - The function first searches for the balance slot by iterating through potential slots and
///   testing both compiler configurations.
/// - Once the balance slot is found, it uses the detected compiler to search for the allowance
///   slot, which is dependent on the balance slot.
pub fn brute_force_slots<D: EngineDatabaseInterface + Clone>(
    token_addr: &Address,
    block: &BlockHeader,
    engine: &SimulationEngine<D>,
) -> Result<(ERC20Slots, ContractCompiler), SimulationError>
where
    <D as DatabaseRef>::Error: std::fmt::Debug,
    <D as EngineDatabaseInterface>::Error: std::fmt::Debug,
{
    let token_contract =
        TychoSimulationContract::new(*token_addr, engine.clone(), ERC20_ABI.clone()).unwrap();

    let mut compiler = ContractCompiler::Solidity;

    let mut balance_slot = None;
    for i in 0..100 {
        for compiler_flag in [ContractCompiler::Solidity, ContractCompiler::Vyper] {
            let mut overwrite_factory = ERC20OverwriteFactory::new(
                *token_addr,
                ERC20Slots::new(i.into(), 1.into()),
                compiler_flag,
            );
            overwrite_factory.set_balance(MARKER_VALUE.into(), *EXTERNAL_ACCOUNT);

            let res = token_contract
                .call(
                    "balanceOf",
                    vec![Token::Address(H160::from_slice(&*EXTERNAL_ACCOUNT.0))],
                    block.number,
                    Some(block.timestamp),
                    Some(overwrite_factory.get_overwrites()),
                    Some(*EXTERNAL_ACCOUNT),
                    U256::zero(),
                )
                .unwrap();

            if res.return_value[0] == Token::Uint(MARKER_VALUE.into()) {
                balance_slot = Some(i);
                compiler = compiler_flag;
                break;
            }
        }
    }

    if balance_slot.is_none() {
        return Err(SimulationError::FatalError(format!(
            "Couldn't bruteforce balance for token {:?}",
            token_addr.to_string()
        )));
    }

    let mut allowance_slot = None;
    for i in 0..100 {
        let mut overwrite_factory = ERC20OverwriteFactory::new(
            *token_addr,
            ERC20Slots::new(0.into(), i.into()),
            compiler, /* At this point we know the compiler becase we managed to find the
                       * balance slot */
        );

        overwrite_factory.set_allowance(
            MARKER_VALUE.into(),
            Address::from_str(SPENDER).unwrap(),
            *EXTERNAL_ACCOUNT,
        );

        let res = token_contract
            .call(
                "allowance",
                vec![
                    Token::Address(H160::from_slice(&*EXTERNAL_ACCOUNT.0)),
                    Token::Address(H160::from_str(SPENDER).unwrap()),
                ],
                block.number,
                Some(block.timestamp),
                Some(overwrite_factory.get_overwrites()),
                Some(*EXTERNAL_ACCOUNT),
                U256::zero(),
            )
            .unwrap();

        if res.return_value[0] == Token::Uint(MARKER_VALUE.into()) {
            allowance_slot = Some(i);
            break;
        }
    }

    if allowance_slot.is_none() {
        return Err(SimulationError::FatalError(format!(
            "Couldn't bruteforce allowance for token {:?}",
            token_addr.to_string()
        )));
    }

    Ok((ERC20Slots::new(balance_slot.unwrap().into(), allowance_slot.unwrap().into()), compiler))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use chrono::NaiveDateTime;
    use ethers::providers::{Http, Provider};

    use crate::evm::engine_db::simulation_db::SimulationDB;

    fn setup_factory() -> ERC20OverwriteFactory {
        let token_address: Address = Address::from_slice(
            &hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                .expect("Invalid token address"),
        );

        let slots = ERC20Slots::new(SlotId::from(5), SlotId::from(6));
        ERC20OverwriteFactory::new(token_address, slots, ContractCompiler::Solidity)
    }

    #[test]
    fn test_set_balance() {
        let mut factory = setup_factory();
        let owner = Address::random();
        let balance = U256::from(1000);

        factory.set_balance(balance, owner);

        assert_eq!(factory.overwrites.len(), 1);
        assert!(factory
            .overwrites
            .values()
            .any(|&v| v == balance));
    }

    #[test]
    fn test_set_allowance() {
        let mut factory = setup_factory();
        let owner = Address::random();
        let spender = Address::random();
        let allowance = U256::from(500);

        factory.set_allowance(allowance, spender, owner);

        assert_eq!(factory.overwrites.len(), 1);
        assert!(factory
            .overwrites
            .values()
            .any(|&v| v == allowance));
    }

    #[test]
    fn test_set_total_supply() {
        let mut factory = setup_factory();
        let supply = U256::from(1_000_000);

        factory.set_total_supply(supply);

        assert_eq!(factory.overwrites.len(), 1);
        assert_eq!(factory.overwrites[&factory.total_supply_slot], supply);
    }

    #[test]
    fn test_get_overwrites() {
        let mut factory = setup_factory();
        let supply = U256::from(1_000_000);
        factory.set_total_supply(supply);

        let overwrites = factory.get_overwrites();

        assert_eq!(overwrites.len(), 1);
        assert!(overwrites.contains_key(&factory.token_address));
        assert_eq!(overwrites[&factory.token_address].len(), 1);
        assert_eq!(overwrites[&factory.token_address][&factory.total_supply_slot], supply);
    }

    #[test]
    fn test_brute_force_slot_solidity() {
        let client = Provider::<Http>::try_from(std::env::var("ETH_RPC_URL").unwrap()).unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let client = Arc::new(client);
        let state = SimulationDB::new(client, Some(Arc::new(runtime)), None);

        let eng = SimulationEngine::new(state, false);
        let block = BlockHeader {
            number: 20_000_000,
            timestamp: NaiveDateTime::parse_from_str("2024-06-01T22:36:47", "%Y-%m-%dT%H:%M:%S")
                .unwrap()
                .and_utc()
                .timestamp() as u64,
            ..Default::default()
        };

        let (slots, compiler) = brute_force_slots(
            &Address::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
            &block,
            &eng,
        )
        .unwrap();

        assert_eq!(ERC20Slots::new(9.into(), 10.into()), slots);
        assert_eq!(ContractCompiler::Solidity, compiler);
    }

    #[test]
    fn test_brute_force_slot_vyper() {
        let client = Provider::<Http>::try_from(std::env::var("ETH_RPC_URL").unwrap()).unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let client = Arc::new(client);
        let state = SimulationDB::new(client, Some(Arc::new(runtime)), None);

        let eng = SimulationEngine::new(state, false);
        let block = BlockHeader {
            number: 20_000_000,
            timestamp: NaiveDateTime::parse_from_str("2024-06-01T22:36:47", "%Y-%m-%dT%H:%M:%S")
                .unwrap()
                .and_utc()
                .timestamp() as u64,
            ..Default::default()
        };

        let (slots, compiler) = brute_force_slots(
            &Address::from_str("0xa5588f7cdf560811710a2d82d3c9c99769db1dcb").unwrap(),
            &block,
            &eng,
        )
        .unwrap();

        assert_eq!(ERC20Slots::new(38.into(), 39.into()), slots);
        assert_eq!(ContractCompiler::Vyper, compiler);
    }
}
