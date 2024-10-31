// TODO: remove skip for clippy dead_code check
#![allow(dead_code)]

use crate::{
    evm::account_storage::StateUpdate,
    protocol::vm::{
        erc20_overwrite_factory::Overwrites, errors::ProtosimError, models::Capability,
        protosim_contract::ProtosimContract,
    },
};
use ethers::{
    abi::{Address, Token},
    types::U256,
};
use revm::{primitives::Address as rAddress, DatabaseRef};
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub struct Trade {
    received_amount: U256,
    gas_used: U256,
    price: f64,
}

/// An implementation of `ProtosimContract` specific to the `AdapterContract` ABI interface,
/// providing methods for price calculations, token swaps, capability checks, and more.
///
/// This struct facilitates interaction with the `AdapterContract` by encoding and decoding data
/// according to its ABI specification. Each method corresponds to a function in the adapter
/// contract's interface, enabling seamless integration with Protosim’s simulation environment.
///
/// # Methods
/// - `price`: Calculates price information for a token pair within the adapter.
/// - `swap`: Simulates a token swap operation, returning details about the trade and state updates.
/// - `get_limits`: Retrieves the trade limits for a given token pair.
/// - `get_capabilities`: Checks the capabilities of the adapter for a specific token pair.
/// - `min_gas_usage`: Queries the minimum gas usage required for operations within the adapter.
impl<D: DatabaseRef + std::clone::Clone> ProtosimContract<D>
where
    D::Error: std::fmt::Debug,
{
    pub async fn price(
        &self,
        pair_id: String,
        sell_token: Address,
        buy_token: Address,
        amounts: Vec<U256>,
        block: u64,
        overwrites: Option<HashMap<rAddress, Overwrites>>,
    ) -> Result<Vec<f64>, ProtosimError> {
        let args = vec![
            self.hexstring_to_bytes(&pair_id)?,
            Token::Address(sell_token),
            Token::Address(buy_token),
            Token::Array(
                amounts
                    .into_iter()
                    .map(Token::Uint)
                    .collect(),
            ),
        ];

        let res = self
            .call("price", args, block, None, overwrites, None, U256::zero())
            .await?
            .return_value;
        let price = self.calculate_price(res[0].clone())?;
        Ok(price)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn swap(
        &self,
        pair_id: String,
        sell_token: Address,
        buy_token: Address,
        is_buy: bool,
        amount: U256,
        block: u64,
        overwrites: Option<HashMap<rAddress, HashMap<U256, U256>>>,
    ) -> Result<(Trade, HashMap<revm::precompile::Address, StateUpdate>), ProtosimError> {
        let args = vec![
            self.hexstring_to_bytes(&pair_id)?,
            Token::Address(sell_token),
            Token::Address(buy_token),
            Token::Bool(is_buy),
            Token::Uint(amount),
        ];

        let res = self
            .call("swap", args, block, None, overwrites, None, U256::zero())
            .await?;
        let received_amount = res.return_value[0]
            .clone()
            .into_uint()
            .unwrap();
        let gas_used = res.return_value[1]
            .clone()
            .into_uint()
            .unwrap();
        let price = self
            .calculate_price(res.return_value[2].clone())
            .unwrap()[0];

        Ok((Trade { received_amount, gas_used, price }, res.simulation_result.state_updates))
    }

    pub async fn get_limits(
        &self,
        pair_id: String,
        sell_token: Address,
        buy_token: Address,
        block: u64,
        overwrites: Option<HashMap<rAddress, HashMap<U256, U256>>>,
    ) -> Result<(U256, U256), ProtosimError> {
        let args = vec![
            self.hexstring_to_bytes(&pair_id)?,
            Token::Address(sell_token),
            Token::Address(buy_token),
        ];

        let res = self
            .call("getLimits", args, block, None, overwrites, None, U256::zero())
            .await?
            .return_value;

        if let Some(Token::Array(inner)) = res.first() {
            if let (Some(Token::Uint(value1)), Some(Token::Uint(value2))) =
                (inner.first(), inner.get(1))
            {
                return Ok((*value1, *value2));
            }
        }

        Err(ProtosimError::DecodingError("Unexpected response format".into()))
    }

    pub async fn get_capabilities(
        &self,
        pair_id: String,
        sell_token: Address,
        buy_token: Address,
    ) -> Result<HashSet<Capability>, ProtosimError> {
        let args = vec![
            self.hexstring_to_bytes(&pair_id)?,
            Token::Address(sell_token),
            Token::Address(buy_token),
        ];

        let res = self
            .call("getCapabilities", args, 1, None, None, None, U256::zero())
            .await?
            .return_value;
        let capabilities: HashSet<Capability> = match res.first() {
            Some(Token::Array(inner_tokens)) => inner_tokens
                .iter()
                .filter_map(|token| match token {
                    Token::Uint(value) => Capability::from_uint(*value).ok(),
                    _ => None,
                })
                .collect(),
            _ => HashSet::new(),
        };

        Ok(capabilities)
    }

    pub async fn min_gas_usage(&self) -> Result<u64, ProtosimError> {
        let res = self
            .call("minGasUsage", vec![], 1, None, None, None, U256::zero())
            .await?
            .return_value;
        Ok(res[0]
            .clone()
            .into_uint()
            .unwrap()
            .as_u64())
    }

    fn hexstring_to_bytes(&self, pair_id: &str) -> Result<Token, ProtosimError> {
        let bytes = hex::decode(pair_id).map_err(|_| {
            ProtosimError::EncodingError(format!("Invalid hex string: {}", pair_id))
        })?;
        Ok(Token::FixedBytes(bytes))
    }

    fn calculate_price(&self, value: Token) -> Result<Vec<f64>, ProtosimError> {
        if let Token::Array(fractions) = value {
            // Map over each `Token::Tuple` in the array
            fractions
                .into_iter()
                .map(|fraction_token| {
                    if let Token::Tuple(ref components) = fraction_token {
                        let numerator = components[0]
                            .clone()
                            .into_uint()
                            .unwrap();
                        let denominator = components[1]
                            .clone()
                            .into_uint()
                            .unwrap();
                        if denominator.is_zero() {
                            Err(ProtosimError::DecodingError("Denominator is zero".to_string()))
                        } else {
                            Ok((numerator.as_u128() as f64) / (denominator.as_u128() as f64))
                        }
                    } else {
                        Err(ProtosimError::DecodingError("Invalid fraction tuple".to_string()))
                    }
                })
                .collect()
        } else {
            Err(ProtosimError::DecodingError("Expected Token::Array".to_string()))
        }
    }
}
