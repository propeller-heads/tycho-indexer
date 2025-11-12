use std::sync::Arc;

use alloy::{network::Ethereum, primitives::Address, providers::RootProvider, sol};
use async_trait::async_trait;
use tycho_common::{models::token::Token, simulation::protocol_sim::ProtocolSim, Bytes};

use crate::evm::protocol::uniswap_v2::state::UniswapV2State;

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
    }
}

/// Trait for validating protocol states against on-chain data
#[async_trait]
pub trait Validator: ProtocolSim {
    /// Validates the protocol state against on-chain data at a specific block
    ///
    /// # Arguments
    ///
    /// * `provider` - The RPC provider to use for on-chain queries
    /// * `block_id` - The block number to query at
    /// * `component_id` - The component/pool address
    /// * `tokens` - The tokens in the pool
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if validation passes, `Ok(false)` if validation fails,
    /// or `Err` if there was an error during validation
    async fn validate(
        &self,
        provider: Arc<RootProvider<Ethereum>>,
        block_id: u64,
        component_id: &Bytes,
        tokens: &[Token],
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}

/// Helper function to validate a ProtocolSim state if it implements Validator
///
/// This function attempts to cast the ProtocolSim to known types that implement Validator.
/// If the type implements Validator, it validates and returns the result.
/// If the type doesn't implement Validator, it returns None.
pub async fn try_validate(
    state: &dyn ProtocolSim,
    provider: Arc<RootProvider<Ethereum>>,
    block_id: u64,
    component_id: &Bytes,
    tokens: &[Token],
) -> Option<Result<bool, Box<dyn std::error::Error + Send + Sync>>> {
    // Try to cast to types that implement Validator
    if let Some(uniswap_v2) = state
        .as_any()
        .downcast_ref::<UniswapV2State>()
    {
        return Some(
            uniswap_v2
                .validate(provider, block_id, component_id, tokens)
                .await,
        );
    }

    // Add more types here as they implement custom validation
    // For now, all other types return None (no validation)

    None
}

#[async_trait]
impl Validator for UniswapV2State {
    /// Validate that the reserves in the state match the on-chain token balances
    async fn validate(
        &self,
        provider: Arc<RootProvider<Ethereum>>,
        block_id: u64,
        component_id: &Bytes,
        tokens: &[Token],
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if tokens.len() != 2 {
            return Err("UniswapV2 pool must have 2 tokens".into());
        }

        let pool_address = Address::from_slice(&component_id[..20]);
        let token_0 = &tokens[0];
        let token_1 = &tokens[1];

        let token_0_address = Address::from_slice(&token_0.address[..20]);
        let token_1_address = Address::from_slice(&token_1.address[..20]);

        let token_0_contract = IERC20::new(token_0_address, provider.clone());
        let token_1_contract = IERC20::new(token_1_address, provider.clone());

        // Get on-chain balances at the specified block
        let balance_0 = token_0_contract
            .balanceOf(pool_address)
            .block(block_id.into())
            .call()
            .await?;

        let balance_1 = token_1_contract
            .balanceOf(pool_address)
            .block(block_id.into())
            .call()
            .await?;

        let reserves_match = self.reserve0 == balance_0 && self.reserve1 == balance_1;

        if !reserves_match {
            tracing::warn!(
                component_id = %hex::encode(component_id),
                state_reserve0 = %self.reserve0,
                state_reserve1 = %self.reserve1,
                onchain_balance0 = %balance_0,
                onchain_balance1 = %balance_1,
                token_0 = %token_0.symbol,
                token_1 = %token_1.symbol,
                "UniswapV2 reserve validation failed: state reserves do not match on-chain balances"
            );
        }

        Ok(reserves_match)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::{network::Ethereum, primitives::U256, providers::ProviderBuilder};
    use tycho_common::models::Chain;

    use super::*;

    #[tokio::test]
    #[ignore] // This test requires an RPC connection
    async fn test_uniswap_v2_validator() {
        let block_id = 23775987;
        let pool_id = "0x132BC4EA9E5282889fDcfE7Bc7A91Ea901a686D6";
        let token_0_addr = "0xa9D54F37EbB99f83B603Cc95fc1a5f3907AacCfd";
        let token_1_addr = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

        let token_0 = Token::new(
            &Bytes::from_str(token_0_addr).unwrap(),
            "PIKA",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let token_1 = Token::new(
            &Bytes::from_str(token_1_addr).unwrap(),
            "WETH",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL environment variable must be set for this test");

        let provider: RootProvider<Ethereum> =
            ProviderBuilder::default().connect_http(rpc_url.parse().unwrap());

        // Reserves taken from onchain
        let state = UniswapV2State::new(
            U256::from(7791135770602459893220844917132_u128),
            U256::from(80274590426947493401_u128),
        );

        let result = state
            .validate(
                Arc::new(provider),
                block_id,
                &Bytes::from_str(pool_id).unwrap(),
                &[token_0, token_1],
            )
            .await;

        assert!(result.unwrap(), "Validation should pass with correct reserves");
    }

    #[tokio::test]
    #[ignore] // This test requires an RPC connection
    async fn test_uniswap_v2_validator_mismatch() {
        let block_id = 23775987;
        let pool_id = "0x132BC4EA9E5282889fDcfE7Bc7A91Ea901a686D6";
        let token_0_addr = "0xa9D54F37EbB99f83B603Cc95fc1a5f3907AacCfd";
        let token_1_addr = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

        let token_0 = Token::new(
            &Bytes::from_str(token_0_addr).unwrap(),
            "PIKA",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let token_1 = Token::new(
            &Bytes::from_str(token_1_addr).unwrap(),
            "WETH",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL environment variable must be set for this test");

        let provider: RootProvider<Ethereum> =
            ProviderBuilder::default().connect_http(rpc_url.parse().unwrap());

        // Create state with incorrect reserves
        let state = UniswapV2State::new(U256::from(1000), U256::from(2000));

        let result = state
            .validate(
                Arc::new(provider),
                block_id,
                &Bytes::from_str(pool_id).unwrap(),
                &[token_0, token_1],
            )
            .await;

        assert!(!result.unwrap(), "Validation should fail with incorrect reserves");
    }
}
