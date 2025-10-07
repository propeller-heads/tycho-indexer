use alloy::{
    hex,
    primitives::{map::AddressHashMap, Address},
    rpc::types::{state::AccountOverride, Block},
};
use serde_json::json;
use tycho_execution::encoding::models::Transaction;

/// Parameters for Tenderly simulation
#[derive(Debug, Clone, Default)]
pub struct TenderlySimParams {
    pub from: Option<String>,
    pub contract_address: Option<String>,
    pub value: Option<String>,
    pub raw_function_input: Option<String>,
    pub network: Option<String>,
    pub block: Option<String>,
    pub block_index: Option<String>,
    pub header_block_number: Option<String>,
    pub gas: Option<String>,
    pub gas_price: Option<String>,
}

/// Build a Tenderly simulator URL with the given parameters
///
/// Generates a URL pointing to the Tenderly simulator configured with the provided parameters.
/// Parameters can be provided directly via `overrides` or extracted from the `tx` and `block`
/// arguments.
///
/// # Arguments
///
/// * `overrides` - Simulation parameters to override defaults with
/// * `tx` - Transaction object from which data can be extracted if not provided in `overrides`
/// * `block` - Block object from which data can be extracted if not provided in `overrides`
/// * `caller` - The address calling the transaction
/// * `state_overrides` - State overrides for balance and allowance slots
///
/// # Returns
///
/// A string representing the URL pointing to the Tenderly simulator with the defined parameters
pub fn build_tenderly_url(
    overrides: &TenderlySimParams,
    tx: Option<&Transaction>,
    block: Option<&Block>,
    caller: Address,
    state_overrides: Option<&AddressHashMap<AccountOverride>>,
) -> String {
    // Extract transaction data
    let (tx_to, tx_value, tx_data) = if let Some(transaction) = tx {
        let to_addr = format!("0x{}", hex::encode(&transaction.to));
        let value = transaction.value.to_string();
        let data = format!("0x{}", hex::encode(&transaction.data));
        (Some(to_addr), Some(value), Some(data))
    } else {
        (None, None, None)
    };

    // Extract block number
    let block_number = block.map(|b| b.header.number.to_string());

    // Build parameters with overrides taking priority
    let from = overrides
        .from
        .clone()
        .unwrap_or_else(|| format!("0x{:x}", caller));

    let contract_address = overrides
        .contract_address
        .clone()
        .or(tx_to)
        .unwrap_or_default();

    let value = overrides
        .value
        .clone()
        .or(tx_value)
        .unwrap_or_else(|| "0".to_string());

    let raw_function_input = overrides
        .raw_function_input
        .clone()
        .or(tx_data)
        .unwrap_or_default();

    // Default to Ethereum mainnet (chain ID 1)
    let network = overrides
        .network
        .clone()
        .unwrap_or_else(|| "1".to_string());

    let block_param = overrides
        .block
        .clone()
        .or(block_number)
        .unwrap_or_default();

    // Build query parameters
    let mut params = vec![
        ("from", from),
        ("to", contract_address),
        ("value", value),
        ("rawFunctionInput", raw_function_input),
        ("network", network),
        ("block", block_param),
    ];

    // Add optional parameters if present
    if let Some(block_index) = &overrides.block_index {
        params.push(("blockIndex", block_index.clone()));
    }
    if let Some(header_block_number) = &overrides.header_block_number {
        params.push(("headerBlockNumber", header_block_number.clone()));
    }
    if let Some(gas) = &overrides.gas {
        params.push(("gas", gas.clone()));
    }
    if let Some(gas_price) = &overrides.gas_price {
        params.push(("gasPrice", gas_price.clone()));
    }

    // Add state overrides if provided
    if let Some(overrides_map) = state_overrides {
        let state_overrides_json = encode_state_overrides(overrides_map);
        params.push(("stateOverrides", state_overrides_json));
    }

    // URL encode parameters
    let query_string = params
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    format!("https://dashboard.tenderly.co/tvinagre/project/simulator/new?{}", query_string)
}

/// Encode state overrides to JSON format for Tenderly
///
/// Converts the AddressHashMap of AccountOverrides to a JSON string suitable for
/// Tenderly's stateOverrides parameter.
fn encode_state_overrides(overrides: &AddressHashMap<AccountOverride>) -> String {
    let mut state_obj = serde_json::Map::new();

    for (address, account_override) in overrides {
        let mut account_obj = serde_json::Map::new();

        // Add balance if present
        if let Some(balance) = &account_override.balance {
            account_obj.insert("balance".to_string(), json!(format!("0x{:x}", balance)));
        }

        // Add state diff (storage slots) if present
        if let Some(state_diff) = &account_override.state_diff {
            let mut storage_obj = serde_json::Map::new();
            for (slot, value) in state_diff {
                storage_obj.insert(format!("0x{:x}", slot), json!(format!("0x{:x}", value)));
            }
            account_obj.insert("storage".to_string(), json!(storage_obj));
        }

        state_obj.insert(format!("0x{:x}", address), json!(account_obj));
    }

    serde_json::to_string(&state_obj).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;
    use tycho_execution::encoding::models::Transaction;

    use super::*;

    #[test]
    fn test_build_url_with_transaction() {
        let tx = Transaction {
            to: vec![0xde, 0xad, 0xbe, 0xef].into(),
            value: num_bigint::BigUint::from(1000u32),
            data: vec![0x12, 0x34, 0x56, 0x78],
        };

        let caller = address!("f847a638E44186F3287ee9F8cAF73FF4d4B80784");
        let overrides = TenderlySimParams::default();

        let url = build_tenderly_url(&overrides, Some(&tx), None, caller, None);

        assert!(url.contains("from=0xf847a638e44186f3287ee9f8caf73ff4d4b80784"));
        assert!(url.contains("to=0xdeadbeef"));
        assert!(url.contains("value=1000"));
        assert!(url.contains("rawFunctionInput=0x12345678"));
    }

    #[test]
    fn test_build_url_with_overrides() {
        let caller = address!("0000000000000000000000000000000000000000");
        let overrides = TenderlySimParams {
            from: Some("0x1234567890123456789012345678901234567890".to_string()),
            contract_address: Some("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string()),
            value: Some("500".to_string()),
            network: Some("5".to_string()),
            ..Default::default()
        };

        let url = build_tenderly_url(&overrides, None, None, caller, None);

        assert!(url.contains("from=0x1234567890123456789012345678901234567890"));
        assert!(url.contains("to=0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"));
        assert!(url.contains("value=500"));
        assert!(url.contains("network=5"));
    }

    #[test]
    fn test_build_url_with_block() {
        let caller = address!("0000000000000000000000000000000000000000");
        let overrides =
            TenderlySimParams { block: Some("12345678".to_string()), ..Default::default() };

        let url = build_tenderly_url(&overrides, None, None, caller, None);

        assert!(url.contains("block=12345678"));
    }

    #[test]
    fn test_build_url_with_state_overrides() {
        use alloy::primitives::{b256, U256};

        let caller = address!("f847a638E44186F3287ee9F8cAF73FF4d4B80784");
        let overrides = TenderlySimParams::default();

        let token_address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
        let balance_slot =
            b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let balance_value = U256::from(1000000u64);

        let mut state_overrides = AddressHashMap::default();
        state_overrides.insert(
            token_address,
            AccountOverride::default().with_state_diff(vec![(balance_slot, balance_value.into())]),
        );

        let url = build_tenderly_url(&overrides, None, None, caller, Some(&state_overrides));

        // Verify the URL contains state overrides
        assert!(url.contains("stateOverrides="));
        // Verify it contains the token address (lowercase)
        assert!(url.contains("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"));
        // Verify it contains the storage key
        assert!(url.contains("storage"));
    }
}
