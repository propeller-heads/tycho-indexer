use std::collections::HashMap;

use alloy::{
    primitives::{Address, Bytes as AlloyBytes},
    rpc::{
        client::ClientBuilder,
        types::{BlockId, TransactionRequest},
    },
    sol,
    sol_types::SolCall,
};
use async_trait::async_trait;
use tycho_common::{models::token::Token, simulation::protocol_sim::ProtocolSim, Bytes};
use tycho_simulation::evm::protocol::uniswap_v2::state::UniswapV2State;

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
    }
}

/// Execute batched contract calls using JSON-RPC batch requests
///
/// This function takes a list of (component_id, calls) pairs and executes
/// all the contract calls in a single batch RPC request for efficiency.
/// Returns a map from component_id to the results for that component.
///
/// # Arguments
///
/// * `rpc_url` - The HTTP RPC endpoint URL
/// * `component_calls` - List of (component_id, calls) pairs
/// * `block_id` - The block number to query at
async fn execute_batched_calls(
    rpc_url: &str,
    component_calls: &[(Bytes, Vec<(Address, AlloyBytes)>)],
    block_id: u64,
) -> Result<HashMap<Bytes, Vec<alloy::primitives::U256>>, Box<dyn std::error::Error + Send + Sync>>
{
    if component_calls.is_empty() {
        return Ok(HashMap::new());
    }
    let client = ClientBuilder::default().http(rpc_url.parse()?);
    let mut batch = client.new_batch();
    let block_id = BlockId::from(block_id);

    // Track which futures belong to which component
    let mut component_futures: Vec<(Bytes, Vec<_>)> = Vec::new();

    for (component_id, calls) in component_calls {
        let mut futures = Vec::new();
        for (contract_address, call_data) in calls {
            let tx = TransactionRequest::default()
                .to(*contract_address)
                .input(call_data.clone().into());
            let fut = batch.add_call("eth_call", &(tx, block_id))?;
            futures.push(fut);
        }

        component_futures.push((component_id.clone(), futures));
    }
    batch.send().await?;

    let mut results = HashMap::new();
    for (component_id, futures) in component_futures {
        let mut component_results = Vec::new();
        for fut in futures {
            let bytes: AlloyBytes = fut.await?;
            let balance = alloy::primitives::U256::from_be_slice(bytes.as_ref());
            component_results.push(balance);
        }
        results.insert(component_id, component_results);
    }

    Ok(results)
}

/// Trait for validating protocol states against on-chain data
///
/// This trait uses a two-phase approach to enable batching of RPC calls:
/// 1. `prepare_validation_calls`: Determines what RPC calls to make for a component
/// 2. `validate_with_results`: Compares the results against the state
#[async_trait]
pub trait Validator: ProtocolSim {
    /// Prepare validation calls for a component
    ///
    /// Returns a list of (contract_address, call_data) pairs representing the contract
    /// calls that need to be made to validate the given component. The call data should
    /// be ABI-encoded function calls (e.g., balanceOf, etc.).
    ///
    /// # Arguments
    ///
    /// * `component_id` - The component/pool address
    /// * `tokens` - The tokens in the component
    ///
    /// # Returns
    ///
    /// Returns a vector of (contract_address, call_data) tuples representing
    /// the contract calls that need to be made, or an error if preparation fails.
    fn prepare_validation_calls(
        &self,
        component_id: &Bytes,
        tokens: &[Token],
    ) -> Result<Vec<(Address, AlloyBytes)>, Box<dyn std::error::Error + Send + Sync>>;

    /// Validate with batched results
    ///
    /// Takes the results from batched RPC calls and validates them against the state.
    /// The results must be in the same order as returned by `prepare_validation_calls`.
    ///
    /// # Arguments
    ///
    /// * `component_id` - The component/pool address
    /// * `tokens` - The tokens in the pool
    /// * `results` - The results from the batched RPC calls
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if validation passes, `Ok(false)` if validation fails,
    /// or `Err` if there was an error during validation.
    fn validate_with_results(
        &self,
        component_id: &Bytes,
        tokens: &[Token],
        results: &[alloy::primitives::U256],
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}

/// Batch validation for multiple components across any protocol types
///
/// This function validates multiple components in a single batched RPC request.
///
/// # Arguments
///
/// * `rpc_url` - The HTTP RPC endpoint URL
/// * `components` - List of (state, component_id, tokens) tuples to validate
/// * `block_id` - The block number to query at
///
/// # Returns
///
/// Returns a vector of validation results in the same order as the input components.
/// Each result is `Ok(true)` if validation passed, `Ok(false)` if it failed,
/// or `Err` if there was an error.
pub async fn batch_validate_components(
    rpc_url: &str,
    components: &[(&dyn Validator, Bytes, Vec<Token>)],
    block_id: u64,
) -> Vec<Result<bool, Box<dyn std::error::Error + Send + Sync>>> {
    if components.is_empty() {
        return Vec::new();
    }

    // Prepare calls for each component individually
    let mut component_calls = Vec::with_capacity(components.len());

    for (state, component_id, tokens) in components {
        match state.prepare_validation_calls(component_id, tokens) {
            Ok(calls) => {
                component_calls.push((component_id.clone(), calls));
            }
            Err(e) => {
                return components
                    .iter()
                    .map(|_| Err(format!("Failed to prepare calls: {}", e).into()))
                    .collect();
            }
        }
    }

    // Execute all calls in a single batch, getting results organized by component_id
    let results_map = match execute_batched_calls(rpc_url, &component_calls, block_id).await {
        Ok(results) => results,
        Err(e) => {
            return components
                .iter()
                .map(|_| Err(format!("Batch RPC call failed: {}", e).into()))
                .collect();
        }
    };

    // Validate each component with its results
    let mut results = Vec::with_capacity(components.len());

    for (state, component_id, tokens) in components {
        match results_map.get(component_id) {
            Some(component_results) => {
                let validation_result =
                    state.validate_with_results(component_id, tokens, component_results);
                results.push(validation_result);
            }
            None => {
                results.push(Err(format!(
                    "No results found for component {}",
                    hex::encode(component_id)
                )
                .into()));
            }
        }
    }

    results
}

#[async_trait]
impl Validator for UniswapV2State {
    fn prepare_validation_calls(
        &self,
        component_id: &Bytes,
        tokens: &[Token],
    ) -> Result<Vec<(Address, AlloyBytes)>, Box<dyn std::error::Error + Send + Sync>> {
        if tokens.len() != 2 {
            return Err(format!(
                "UniswapV2 component {} must have 2 tokens, got {}",
                hex::encode(component_id),
                tokens.len()
            )
            .into());
        }

        let pool_address = Address::from_slice(&component_id[..20]);
        let token_0_address = Address::from_slice(&tokens[0].address[..20]);
        let token_1_address = Address::from_slice(&tokens[1].address[..20]);

        // Encode balanceOf calls for both tokens
        let call_0 = IERC20::balanceOfCall { account: pool_address }.abi_encode();
        let call_1 = IERC20::balanceOfCall { account: pool_address }.abi_encode();
        let calls = vec![(token_0_address, call_0.into()), (token_1_address, call_1.into())];
        Ok(calls)
    }

    fn validate_with_results(
        &self,
        component_id: &Bytes,
        tokens: &[Token],
        results: &[alloy::primitives::U256],
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if tokens.len() != 2 {
            return Err("UniswapV2 pool must have 2 tokens".into());
        }

        if results.len() != 2 {
            return Err(format!(
                "Expected 2 results for UniswapV2 validation, got {}",
                results.len()
            )
            .into());
        }

        let balance_0 = results[0];
        let balance_1 = results[1];

        let reserves_match = self.reserve0 == balance_0 && self.reserve1 == balance_1;

        if !reserves_match {
            tracing::warn!(
                component_id = %hex::encode(component_id),
                state_reserve0 = %self.reserve0,
                state_reserve1 = %self.reserve1,
                onchain_balance0 = %balance_0,
                onchain_balance1 = %balance_1,
                token_0 = %tokens[0].symbol,
                token_1 = %tokens[1].symbol,
                "UniswapV2 reserve validation failed: state reserves do not match on-chain balances"
            );
        }

        Ok(reserves_match)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::primitives::U256;
    use tycho_common::models::Chain;

    use super::*;

    #[tokio::test]
    #[ignore] // This test requires an RPC connection
    async fn test_batch_validate_multiple_components() {
        let block_id = 23775987;

        // Component with correct reserves
        let pool_id_1 = "0x132BC4EA9E5282889fDcfE7Bc7A91Ea901a686D6";
        let token_0_addr_1 = "0xa9D54F37EbB99f83B603Cc95fc1a5f3907AacCfd";
        let token_1_addr_1 = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

        let token_0_1 = Token::new(
            &Bytes::from_str(token_0_addr_1).unwrap(),
            "PIKA",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let token_1_1 = Token::new(
            &Bytes::from_str(token_1_addr_1).unwrap(),
            "WETH",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        let state_1 = UniswapV2State::new(
            U256::from(7791135770602459893220844917132_u128),
            U256::from(80274590426947493401_u128),
        );
        let component_id_1 = Bytes::from_str(pool_id_1).unwrap();
        let tokens_1 = vec![token_0_1, token_1_1];

        // Component with incorrect reserves to show validation failure
        let state_2 = UniswapV2State::new(U256::from(1000), U256::from(2000));
        let component_id_2 = Bytes::from_str(pool_id_1).unwrap(); // Same component but wrong state
        let tokens_2 = tokens_1.clone();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL environment variable must be set for this test");

        // Batch validate both components
        let components = vec![
            (&state_1 as &dyn Validator, component_id_1.clone(), tokens_1.clone()),
            (&state_2 as &dyn Validator, component_id_2.clone(), tokens_2.clone()),
        ];

        let results = batch_validate_components(&rpc_url, &components, block_id).await;

        assert_eq!(results.len(), 2, "Should get results for both components");

        // First component should pass (correct reserves)
        assert!(results[0].as_ref().unwrap(), "Component 1 validation should pass");

        // Second component should fail (incorrect reserves)
        assert!(!results[1].as_ref().unwrap(), "Component 2 validation should fail");
    }
}
