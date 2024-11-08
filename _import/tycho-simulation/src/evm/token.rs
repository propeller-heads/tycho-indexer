use crate::protocol::vm::{
    constants::EXTERNAL_ACCOUNT, erc20_overwrite_factory::ERC20OverwriteFactory,
    tycho_simulation_contract::TychoSimulationContract, utils::ERC20Slots,
};
use ethers::{
    abi::{Abi, Token},
    types::{H160, U256},
};
use lazy_static::lazy_static;
use revm::{primitives::Address, DatabaseRef};
use serde_json::from_str;
use std::str::FromStr;
use thiserror::Error;

use super::{simulation::SimulationEngine, simulation_db::BlockHeader, ContractCompiler};

const MARKER_VALUE: u128 = 3141592653589793238462643383;
const SPENDER: &str = "08d967bb0134F2d07f7cfb6E246680c53927DD30";
lazy_static! {
    static ref ERC20_ABI: Abi = {
        let abi_file_path = "src/protocol/vm/assets/ERC20.abi";
        let abi_json = std::fs::read_to_string(abi_file_path).expect("Failed to read ABI file");
        from_str(&abi_json).expect("Failed to parse ABI JSON")
    };
}

/// An error r
#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Couldn't bruteforce {0} for token {1}")]
    BruteForceFailed(String, String),
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
pub fn brute_force_slots<D: DatabaseRef + Clone>(
    token_addr: &H160,
    block: &BlockHeader,
    engine: &SimulationEngine<D>,
) -> Result<(ERC20Slots, ContractCompiler), TokenError>
where
    <D as DatabaseRef>::Error: std::fmt::Debug,
{
    let token_contract = TychoSimulationContract::new(
        Address::from_slice(token_addr.as_bytes()),
        engine.clone(),
        ERC20_ABI.clone(),
    )
    .unwrap();

    let external_account = H160::from_slice(&*EXTERNAL_ACCOUNT.0);

    let mut compiler = ContractCompiler::Solidity;

    let mut balance_slot = None;
    for i in 0..100 {
        for compiler_flag in [ContractCompiler::Solidity, ContractCompiler::Vyper] {
            let mut overwrite_factory = ERC20OverwriteFactory::new(
                Address::from_slice(token_addr.as_bytes()),
                ERC20Slots::new(i.into(), 1.into()),
                compiler_flag,
            );
            overwrite_factory.set_balance(MARKER_VALUE.into(), external_account);

            let res = token_contract
                .call(
                    "balanceOf",
                    vec![Token::Address(external_account)],
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
        return Err(TokenError::BruteForceFailed("balance".to_string(), token_addr.to_string()));
    }

    let mut allowance_slot = None;
    for i in 0..100 {
        let mut overwrite_factory = ERC20OverwriteFactory::new(
            Address::from_slice(token_addr.as_bytes()),
            ERC20Slots::new(0.into(), i.into()),
            compiler, /* At this point we know the compiler becase we managed to find the
                       * balance slot */
        );

        overwrite_factory.set_allowance(
            MARKER_VALUE.into(),
            H160::from_str(SPENDER).unwrap(),
            external_account,
        );

        let res = token_contract
            .call(
                "allowance",
                vec![
                    Token::Address(external_account),
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
        return Err(TokenError::BruteForceFailed("allowance".to_string(), token_addr.to_string()));
    }

    Ok((ERC20Slots::new(balance_slot.unwrap().into(), allowance_slot.unwrap().into()), compiler))
}

#[cfg(test)]
mod test {
    use std::{str::FromStr, sync::Arc};

    use chrono::NaiveDateTime;
    use ethers::{
        providers::{Http, Provider},
        types::H160,
    };

    use crate::{
        evm::{
            simulation::SimulationEngine,
            simulation_db::{BlockHeader, SimulationDB},
            ContractCompiler,
        },
        protocol::vm::utils::ERC20Slots,
    };

    use super::brute_force_slots;

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
            &H160::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
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
            &H160::from_str("0xa5588f7cdf560811710a2d82d3c9c99769db1dcb").unwrap(),
            &block,
            &eng,
        )
        .unwrap();

        assert_eq!(ERC20Slots::new(38.into(), 39.into()), slots);
        assert_eq!(ContractCompiler::Vyper, compiler);
    }
}
