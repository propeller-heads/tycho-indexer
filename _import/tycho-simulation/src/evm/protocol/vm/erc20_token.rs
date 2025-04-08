use std::{collections::HashMap, fmt::Debug, str::FromStr};

use alloy::{
    primitives::{Address, U256},
    sol_types::SolValue,
};
use lazy_static::lazy_static;

use super::utils::get_storage_slot_index_at_key;
use crate::evm::{ContractCompiler, SlotId};

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

pub(crate) type Overwrites = HashMap<SlotId, U256>;

// Storage slots constants for TokenProxy contract
lazy_static! {
    pub static ref IMPLEMENTATION_SLOT: SlotId =
        U256::from_str("0x6677C72CDEB41ACAF2B17EC8A6E275C4205F27DBFE4DE34EBAF2E928A7E610DB")
            .unwrap();
    static ref BALANCES_MAPPING_POSITION: SlotId =
        U256::from_str("0x474F5FD57EE674F7B6851BC6F07E751B49076DFB356356985B9DAF10E9ABC941")
            .unwrap();
    static ref HAS_CUSTOM_BALANCE_POSITION: SlotId =
        U256::from_str("0x7EAD8EDE9DBB385B0664952C7462C9938A5821E6F78E859DA2E683216E99411B")
            .unwrap();
    static ref CUSTOM_APPROVAL_MAPPING_POSITION: SlotId =
        U256::from_str("0x71A54E125991077003BEF7E7CA57369C919DAC6D2458895F1EAB4D03960F4AEB")
            .unwrap();
    static ref HAS_CUSTOM_APPROVAL_MAPPING_POSITION: SlotId =
        U256::from_str("0x9F0C1BC0E9C3078F9AD5FC59C8606416B3FABCBD4C8353FED22937C66C866CE3")
            .unwrap();
    static ref CUSTOM_NAME_POSITION: SlotId =
        U256::from_str("0xCC1E513FB5BDA80DC466AD9D44DF38805A8DEE4C82B3C6DF3D9B25D3D5355D1C")
            .unwrap();
    static ref CUSTOM_SYMBOL_POSITION: SlotId =
        U256::from_str("0xDC17DD3380A9A034A702A2B2B1C6C25D39EBF0E89796E0D15E1E04D23E3BB221")
            .unwrap();
    static ref CUSTOM_DECIMALS_POSITION: SlotId =
        U256::from_str("0xADD486B234562DE9AC745F036F538CDA2547EF6DBB4DA3FA1C017625F888A8E8")
            .unwrap();
    static ref CUSTOM_TOTAL_SUPPLY_POSITION: SlotId =
        U256::from_str("0x6014AF1E8E9BB2844581B2FA9E5E3620181C3192EEFD3258319AEC23538DA9F5")
            .unwrap();
    static ref HAS_CUSTOM_METADATA_POSITION: SlotId =
        U256::from_str("0x9F37243DE61714BE9CC00628D4B9BF9897AE670218AF52ADE6D192B4339D7616")
            .unwrap();
}

pub(crate) struct TokenProxyOverwriteFactory {
    token_address: Address,
    overwrites: Overwrites,
    compiler: ContractCompiler,
}

#[allow(dead_code)]
impl TokenProxyOverwriteFactory {
    pub fn new(token_address: Address, proxy_address: Option<Address>) -> Self {
        let mut instance = Self {
            token_address,
            overwrites: HashMap::new(),
            compiler: ContractCompiler::Solidity,
        };

        if let Some(proxy_addr) = proxy_address {
            instance.set_implementation(proxy_addr);
        }

        instance
    }

    pub fn set_implementation(&mut self, implementation: Address) {
        self.overwrites
            .insert(*IMPLEMENTATION_SLOT, U256::from_be_slice(implementation.as_slice()));
    }

    pub fn set_balance(&mut self, balance: U256, owner: Address) {
        // Set the balance in the custom storage slot
        let storage_index =
            get_storage_slot_index_at_key(owner, *BALANCES_MAPPING_POSITION, self.compiler);
        self.overwrites
            .insert(storage_index, balance);

        // Set the has_custom_balance flag to true
        let has_balance_index =
            get_storage_slot_index_at_key(owner, *HAS_CUSTOM_BALANCE_POSITION, self.compiler);
        self.overwrites
            .insert(has_balance_index, U256::from(1)); // true in Solidity
    }

    pub fn set_allowance(&mut self, allowance: U256, spender: Address, owner: Address) {
        // Set the allowance in the custom storage slot
        let owner_slot =
            get_storage_slot_index_at_key(owner, *CUSTOM_APPROVAL_MAPPING_POSITION, self.compiler);
        let storage_index = get_storage_slot_index_at_key(spender, owner_slot, self.compiler);
        self.overwrites
            .insert(storage_index, allowance);

        // Set the has_custom_approval flag to true
        let has_approval_index = get_storage_slot_index_at_key(
            owner,
            *HAS_CUSTOM_APPROVAL_MAPPING_POSITION,
            self.compiler,
        );
        self.overwrites
            .insert(has_approval_index, U256::from(1)); // true in Solidity
    }

    pub fn set_total_supply(&mut self, supply: U256) {
        self.overwrites
            .insert(*CUSTOM_TOTAL_SUPPLY_POSITION, supply);
    }

    /// Sets the has_custom_metadata flag for a given key
    fn set_metadata_flag(&mut self, key: &str) {
        let key_bytes = string_to_storage_bytes(key);
        let mapping_slot_bytes: [u8; 32] = HAS_CUSTOM_METADATA_POSITION.to_be_bytes();
        let has_metadata_index = self
            .compiler
            .compute_map_slot(&key_bytes, &mapping_slot_bytes);
        self.overwrites
            .insert(has_metadata_index, U256::from(1)); // true in Solidity
    }

    pub fn set_name(&mut self, name: &str) {
        // Store the name value
        let name_value = U256::from_be_bytes(string_to_storage_bytes(name));
        self.overwrites
            .insert(*CUSTOM_NAME_POSITION, name_value);

        // Set the has_custom_metadata flag for name to true
        self.set_metadata_flag("name");
    }

    pub fn set_symbol(&mut self, symbol: &str) {
        // Store the symbol value
        let symbol_value = U256::from_be_bytes(string_to_storage_bytes(symbol));
        self.overwrites
            .insert(*CUSTOM_SYMBOL_POSITION, symbol_value);

        // Set the has_custom_metadata flag for symbol to true
        self.set_metadata_flag("symbol");
    }

    pub fn set_decimals(&mut self, decimals: u8) {
        self.overwrites
            .insert(*CUSTOM_DECIMALS_POSITION, U256::from(decimals));

        // Set the has_custom_metadata flag for decimals to true
        self.set_metadata_flag("decimals");
    }

    pub fn get_overwrites(&self) -> HashMap<Address, Overwrites> {
        let mut result = HashMap::new();
        result.insert(self.token_address, self.overwrites.clone());
        result
    }
}

/// Converts a string to a 32-byte array for storage, truncating if necessary
pub fn string_to_storage_bytes(s: &str) -> [u8; 32] {
    let mut padded = [0u8; 32];
    let len = s.len().min(31);
    padded[..len].copy_from_slice(&s.as_bytes()[..len]);
    padded[31] = (len * 2) as u8; // Length * 2 for short strings
    padded
}

lazy_static! {
    static ref MARKER_VALUE: U256 = U256::from(3141592653589793238462643383u128);
    static ref SPENDER: Address = Address::from_slice(
        &hex::decode("08d967bb0134F2d07f7cfb6E246680c53927DD30")
            .expect("Invalid string for spender"),
    );
}
type U256Return = U256;

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
pub(crate) fn brute_force_slots<D: EngineDatabaseInterface + Clone + Debug>(
    token_addr: &Address,
    block: &BlockHeader,
    engine: &SimulationEngine<D>,
) -> Result<(ERC20Slots, ContractCompiler), SimulationError>
where
    <D as DatabaseRef>::Error: Debug,
    <D as EngineDatabaseInterface>::Error: Debug,
{
    let token_contract = TychoSimulationContract::new(*token_addr, engine.clone()).unwrap();

    let mut compiler = ContractCompiler::Solidity;

    let mut balance_slot = None;
    for i in 0..100 {
        for compiler_flag in [ContractCompiler::Solidity, ContractCompiler::Vyper] {
            let mut overwrite_factory = ERC20OverwriteFactory::new(
                *token_addr,
                ERC20Slots::new(U256::from(i), U256::from(1)),
                compiler_flag,
            );
            overwrite_factory.set_balance(*MARKER_VALUE, *EXTERNAL_ACCOUNT);

            let res = token_contract
                .call(
                    "balanceOf(address)",
                    *EXTERNAL_ACCOUNT,
                    block.number,
                    Some(block.timestamp),
                    Some(overwrite_factory.get_overwrites()),
                    Some(*EXTERNAL_ACCOUNT),
                    U256::from(0u64),
                    None,
                )?
                .return_value;
            let decoded: U256Return = U256Return::abi_decode(&res).map_err(|e| {
                SimulationError::FatalError(format!("Failed to decode swap return value: {e:?}"))
            })?;
            if decoded == *MARKER_VALUE {
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
            ERC20Slots::new(U256::from(0), U256::from(i)),
            compiler, /* At this point we know the compiler because we managed to find the
                       * balance slot */
        );

        overwrite_factory.set_allowance(*MARKER_VALUE, *SPENDER, *EXTERNAL_ACCOUNT);

        let res = token_contract
            .call(
                "allowance(address,address)",
                (*EXTERNAL_ACCOUNT, *SPENDER),
                block.number,
                Some(block.timestamp),
                Some(overwrite_factory.get_overwrites()),
                Some(*EXTERNAL_ACCOUNT),
                U256::from(0u64),
                None,
            )?
            .return_value;
        let decoded: U256Return = U256Return::abi_decode(&res).map_err(|e| {
            SimulationError::FatalError(format!("Failed to decode swap return value: {e:?}"))
        })?;
        if decoded == *MARKER_VALUE {
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

    Ok((
        ERC20Slots::new(U256::from(balance_slot.unwrap()), U256::from(allowance_slot.unwrap())),
        compiler,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_metadata_slot(key: &str) -> SlotId {
        let key_bytes = string_to_storage_bytes(key);
        let mapping_slot_bytes: [u8; 32] = HAS_CUSTOM_METADATA_POSITION.to_be_bytes();
        ContractCompiler::Solidity.compute_map_slot(&key_bytes, &mapping_slot_bytes)
    }

    #[test]
    fn test_token_proxy_factory_new() {
        let token_address = Address::random();
        let factory = TokenProxyOverwriteFactory::new(token_address, None);
        assert_eq!(factory.token_address, token_address);
        assert!(factory.overwrites.is_empty());
    }

    #[test]
    fn test_token_proxy_factory_with_implementation() {
        let token_address = Address::random();
        let implementation = Address::random();
        let factory = TokenProxyOverwriteFactory::new(token_address, Some(implementation));

        // Check if implementation was set correctly
        let mut expected_bytes = [0u8; 32];
        expected_bytes[12..].copy_from_slice(implementation.as_slice());
        let expected_value = U256::from_be_bytes(expected_bytes);

        assert_eq!(factory.overwrites[&*IMPLEMENTATION_SLOT], expected_value);
    }

    #[test]
    fn test_token_proxy_set_balance() {
        let mut factory = TokenProxyOverwriteFactory::new(Address::random(), None);
        let owner = Address::random();
        let balance = U256::from(1000);

        factory.set_balance(balance, owner);

        // Check balance storage
        let storage_index =
            get_storage_slot_index_at_key(owner, *BALANCES_MAPPING_POSITION, factory.compiler);
        assert_eq!(factory.overwrites[&storage_index], balance);

        // Check has_custom_balance flag
        let has_balance_index =
            get_storage_slot_index_at_key(owner, *HAS_CUSTOM_BALANCE_POSITION, factory.compiler);
        assert_eq!(factory.overwrites[&has_balance_index], U256::from(1));
    }

    #[test]
    fn test_token_proxy_set_allowance() {
        let mut factory = TokenProxyOverwriteFactory::new(Address::random(), None);
        let owner = Address::random();
        let spender = Address::random();
        let allowance = U256::from(500);

        factory.set_allowance(allowance, spender, owner);

        // Check allowance storage
        let owner_slot = get_storage_slot_index_at_key(
            owner,
            *CUSTOM_APPROVAL_MAPPING_POSITION,
            factory.compiler,
        );
        let storage_index = get_storage_slot_index_at_key(spender, owner_slot, factory.compiler);
        assert_eq!(factory.overwrites[&storage_index], allowance);

        // Check has_custom_approval flag
        let has_approval_index = get_storage_slot_index_at_key(
            owner,
            *HAS_CUSTOM_APPROVAL_MAPPING_POSITION,
            factory.compiler,
        );
        assert_eq!(factory.overwrites[&has_approval_index], U256::from(1));
    }

    #[test]
    fn test_token_proxy_set_total_supply() {
        let mut factory = TokenProxyOverwriteFactory::new(Address::random(), None);
        let supply = U256::from(1_000_000);

        factory.set_total_supply(supply);

        assert_eq!(factory.overwrites[&*CUSTOM_TOTAL_SUPPLY_POSITION], supply);
    }

    #[test]
    fn test_token_proxy_set_name() {
        let mut factory = TokenProxyOverwriteFactory::new(Address::random(), None);
        let name = "Test Token";

        factory.set_name(name);

        // Check name storage
        let mut expected_bytes = [0u8; 32];
        let name_bytes = name.as_bytes();
        expected_bytes[..name_bytes.len()].copy_from_slice(name_bytes);
        expected_bytes[31] = (name_bytes.len() * 2) as u8; // Length * 2 for short strings
        let expected_value = U256::from_be_bytes(expected_bytes);
        assert_eq!(factory.overwrites[&*CUSTOM_NAME_POSITION], expected_value);

        // Check has_custom_metadata flag
        let has_metadata_index = get_metadata_slot("name");
        assert_eq!(factory.overwrites[&has_metadata_index], U256::from(1));
    }

    #[test]
    fn test_token_proxy_set_symbol() {
        let mut factory = TokenProxyOverwriteFactory::new(Address::random(), None);
        let symbol = "TEST";

        factory.set_symbol(symbol);

        // Check symbol storage
        let mut expected_bytes = [0u8; 32];
        let symbol_bytes = symbol.as_bytes();
        expected_bytes[..symbol_bytes.len()].copy_from_slice(symbol_bytes);
        expected_bytes[31] = (symbol_bytes.len() * 2) as u8; // Length * 2 for short strings
        let expected_value = U256::from_be_bytes(expected_bytes);
        assert_eq!(factory.overwrites[&*CUSTOM_SYMBOL_POSITION], expected_value);

        // Check has_custom_metadata flag
        let has_metadata_index = get_metadata_slot("symbol");
        assert_eq!(factory.overwrites[&has_metadata_index], U256::from(1));
    }

    #[test]
    fn test_token_proxy_set_decimals() {
        let mut factory = TokenProxyOverwriteFactory::new(Address::random(), None);
        let decimals = 18u8;

        factory.set_decimals(decimals);

        assert_eq!(factory.overwrites[&*CUSTOM_DECIMALS_POSITION], U256::from(decimals));

        // Check has_custom_metadata flag
        let has_metadata_index = get_metadata_slot("decimals");
        assert_eq!(factory.overwrites[&has_metadata_index], U256::from(1));
    }

    #[test]
    fn test_token_proxy_get_overwrites() {
        let mut factory = TokenProxyOverwriteFactory::new(Address::random(), None);
        let supply = U256::from(1_000_000);
        factory.set_total_supply(supply);

        let overwrites = factory.get_overwrites();

        assert_eq!(overwrites.len(), 1);
        assert!(overwrites.contains_key(&factory.token_address));
        assert_eq!(overwrites[&factory.token_address][&*CUSTOM_TOTAL_SUPPLY_POSITION], supply);
    }

    #[test]
    fn test_token_proxy_set_long_name_truncated() {
        let mut factory = TokenProxyOverwriteFactory::new(Address::random(), None);
        let name = "This is a very long token name that exceeds 31 bytes";

        factory.set_name(name);

        // Check name storage for truncated string
        let mut expected_bytes = [0u8; 32];
        expected_bytes[..31].copy_from_slice(&name.as_bytes()[..31]);
        expected_bytes[31] = 62; // 31 * 2 for short strings
        let expected_value = U256::from_be_bytes(expected_bytes);
        assert_eq!(factory.overwrites[&*CUSTOM_NAME_POSITION], expected_value);

        // Check has_custom_metadata flag
        let has_metadata_index = get_metadata_slot("name");
        assert_eq!(factory.overwrites[&has_metadata_index], U256::from(1));
    }

    #[test]
    fn test_token_proxy_set_long_symbol_truncated() {
        let mut factory = TokenProxyOverwriteFactory::new(Address::random(), None);
        let symbol = "This is a very long token symbol that exceeds 31 bytes";

        factory.set_symbol(symbol);

        // Check symbol storage for truncated string
        let mut expected_bytes = [0u8; 32];
        expected_bytes[..31].copy_from_slice(&symbol.as_bytes()[..31]);
        expected_bytes[31] = 62; // 31 * 2 for short strings
        let expected_value = U256::from_be_bytes(expected_bytes);
        assert_eq!(factory.overwrites[&*CUSTOM_SYMBOL_POSITION], expected_value);

        // Check has_custom_metadata flag
        let has_metadata_index = get_metadata_slot("symbol");
        assert_eq!(factory.overwrites[&has_metadata_index], U256::from(1));
    }

    #[test]
    fn test_string_to_storage_bytes() {
        // Test short string
        let short = "Test";
        let bytes = string_to_storage_bytes(short);
        assert_eq!(bytes[..4], short.as_bytes()[..4]);
        assert_eq!(bytes[31], 8); // 4 * 2 for length

        // Test long string (should be truncated)
        let long = "This is a very long string that exceeds 31 bytes";
        let bytes = string_to_storage_bytes(long);
        assert_eq!(bytes[..31], long.as_bytes()[..31]);
        assert_eq!(bytes[31], 62); // 31 * 2 for length
    }

    #[test]
    fn test_set_metadata_flag() {
        let mut factory = TokenProxyOverwriteFactory::new(Address::random(), None);

        // Test setting metadata flag for a key
        factory.set_metadata_flag("test_key");

        // Verify the flag was set correctly
        let key_bytes = string_to_storage_bytes("test_key");
        let mapping_slot_bytes: [u8; 32] = HAS_CUSTOM_METADATA_POSITION.to_be_bytes();
        let has_metadata_index =
            ContractCompiler::Solidity.compute_map_slot(&key_bytes, &mapping_slot_bytes);
        assert_eq!(factory.overwrites[&has_metadata_index], U256::from(1));
    }
}
