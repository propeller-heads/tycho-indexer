// TODO: remove skip for clippy dead_code check
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use ethers::{
    abi::{Address, Token},
    types::U256,
};
use revm::{primitives::Address as rAddress, DatabaseRef};

use crate::{
    evm::account_storage::StateUpdate,
    protocol::{
        errors::SimulationError,
        vm::{
            erc20_overwrite_factory::Overwrites, models::Capability,
            tycho_simulation_contract::TychoSimulationContract,
        },
    },
};

#[derive(Debug)]
pub struct Trade {
    pub received_amount: U256,
    pub gas_used: U256,
    pub price: f64,
}

/// An implementation of `TychoSimulationContract` specific to the `AdapterContract` ABI interface,
/// providing methods for price calculations, token swaps, capability checks, and more.
///
/// This struct facilitates interaction with the `AdapterContract` by encoding and decoding data
/// according to its ABI specification. Each method corresponds to a function in the adapter
/// contract's interface, enabling seamless integration with tycho's simulation environment.
///
/// # Methods
/// - `price`: Calculates price information for a token pair within the adapter.
/// - `swap`: Simulates a token swap operation, returning details about the trade and state updates.
/// - `get_limits`: Retrieves the trade limits for a given token pair.
/// - `get_capabilities`: Checks the capabilities of the adapter for a specific token pair.
/// - `min_gas_usage`: Queries the minimum gas usage required for operations within the adapter.
impl<D: DatabaseRef + std::clone::Clone> TychoSimulationContract<D>
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
    ) -> Result<Vec<f64>, SimulationError> {
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
    ) -> Result<(Trade, HashMap<revm::precompile::Address, StateUpdate>), SimulationError> {
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

        let (received_amount, gas_used, price) = if let Token::Tuple(return_value) =
            res.return_value[0].clone()
        {
            let received_amount = match &return_value[0] {
                Token::Uint(amount) => *amount,
                _ => {
                    return Err(SimulationError::DecodingError(
                        "Expected a uint for received_amount".into(),
                    ));
                }
            };

            let gas_used = match &return_value[1] {
                Token::Uint(gas) => *gas,
                _ => {
                    return Err(SimulationError::DecodingError(
                        "Expected a uint for gas_used".into(),
                    ));
                }
            };

            let price_token = match &return_value[2] {
                Token::Tuple(elements) => Token::Array(vec![Token::Tuple(elements.clone())]),
                _ => {
                    return Err(SimulationError::DecodingError(
                        "Expected a tuple for price_token".into(),
                    ));
                }
            };
            let price = self
                .calculate_price(price_token)?
                .first()
                .cloned()
                .ok_or(SimulationError::DecodingError(
                    "Expected at least one element in the calculated price".into(),
                ))?;

            Ok((received_amount, gas_used, price))
        } else {
            Err(SimulationError::DecodingError("Expected return_value to be a Token::Tuple".into()))
        }?;

        Ok((Trade { received_amount, gas_used, price }, res.simulation_result.state_updates))
    }

    pub async fn get_limits(
        &self,
        pair_id: String,
        sell_token: Address,
        buy_token: Address,
        block: u64,
        overwrites: Option<HashMap<rAddress, HashMap<U256, U256>>>,
    ) -> Result<(U256, U256), SimulationError> {
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

        Err(SimulationError::DecodingError("Unexpected response format".into()))
    }

    pub async fn get_capabilities(
        &self,
        pair_id: String,
        sell_token: Address,
        buy_token: Address,
    ) -> Result<HashSet<Capability>, SimulationError> {
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

    pub async fn min_gas_usage(&self) -> Result<u64, SimulationError> {
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

    fn hexstring_to_bytes(&self, pair_id: &str) -> Result<Token, SimulationError> {
        let bytes = hex::decode(pair_id).map_err(|_| {
            SimulationError::EncodingError(format!("Invalid hex string: {}", pair_id))
        })?;
        Ok(Token::FixedBytes(bytes))
    }

    fn calculate_price(&self, value: Token) -> Result<Vec<f64>, SimulationError> {
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
                            Err(SimulationError::DecodingError("Denominator is zero".to_string()))
                        } else {
                            Ok((numerator.as_u128() as f64) / (denominator.as_u128() as f64))
                        }
                    } else {
                        Err(SimulationError::DecodingError("Invalid fraction tuple".to_string()))
                    }
                })
                .collect()
        } else {
            Err(SimulationError::DecodingError("Expected Token::Array".to_string()))
        }
    }
}
