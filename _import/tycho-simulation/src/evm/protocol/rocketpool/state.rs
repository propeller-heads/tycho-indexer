use std::{any::Any, collections::HashMap};

use alloy::primitives::U256;
use num_bigint::BigUint;
use tycho_common::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::{
        errors::{SimulationError, TransitionError},
        protocol_sim::{Balances, GetAmountOutResult, ProtocolSim},
    },
    Bytes,
};
use tycho_ethereum::BytesCodec;

use crate::evm::protocol::{
    rocketpool::ETH_ADDRESS,
    safe_math::{safe_add_u256, safe_div_u256, safe_mul_u256, safe_sub_u256},
    u256_num::{biguint_to_u256, u256_to_biguint, u256_to_f64},
};

const DEPOSIT_FEE_BASE: f64 = 1e18;

#[derive(Clone, Debug, PartialEq)]
pub struct RocketPoolState {
    pub reth_supply: U256,
    pub total_eth: U256,
    pub liquidity: U256,
    /// Deposit fee as %, scaled by DEPOSIT_FEE_BASE, such as 5000000000000000 represents 0.5% fee.
    pub deposit_fee: U256,
    pub deposits_enabled: bool,
    pub minimum_deposit: U256,
    pub maximum_deposit_pool_size: U256,
}

impl RocketPoolState {
    pub fn new(
        reth_supply: U256,
        total_eth: U256,
        liquidity: U256,
        deposit_fee: U256,
        deposit_enabled: bool,
        minimum_deposit: U256,
        maximum_deposit_pool_size: U256,
    ) -> Self {
        Self {
            reth_supply,
            total_eth,
            liquidity,
            deposit_fee,
            deposits_enabled: deposit_enabled,
            minimum_deposit,
            maximum_deposit_pool_size,
        }
    }

    /// Calculates rETH amount out for a given ETH deposit amount.
    fn get_reth_value(&self, eth_amount: U256) -> Result<U256, SimulationError> {
        // fee = ethIn * deposit_fee / DEPOSIT_FEE_BASE
        let fee = safe_div_u256(
            safe_mul_u256(eth_amount, self.deposit_fee)?,
            U256::from(DEPOSIT_FEE_BASE),
        )?;
        let net_eth = safe_sub_u256(eth_amount, fee)?;

        // rethOut = netEth * rethSupply / totalEth
        safe_div_u256(safe_mul_u256(net_eth, self.reth_supply)?, self.total_eth)
    }

    /// Calculates ETH amount out for a given rETH burn amount.
    /// Matches Solidity: `ethOut = rethIn * totalEth / rethSupply`
    fn get_eth_value(&self, reth_amount: U256) -> Result<U256, SimulationError> {
        safe_div_u256(safe_mul_u256(reth_amount, self.total_eth)?, self.reth_supply)
    }

    fn depositing_eth(token_in: &Bytes) -> bool {
        token_in.as_ref() == ETH_ADDRESS
    }

    /// Returns the deposit fee adjusted by the base (e.g., 0.005 for 0.5%)
    fn deposit_fee_as_f64(&self) -> Result<f64, SimulationError> {
        Ok(u256_to_f64(self.deposit_fee)? / DEPOSIT_FEE_BASE)
    }

    fn assert_deposits_enabled(&self) -> Result<(), SimulationError> {
        if !self.deposits_enabled {
            Err(SimulationError::InvalidInput(
                "Deposits are currently disabled in RocketPool".to_string(),
                None,
            ))
        } else {
            Ok(())
        }
    }
}

impl ProtocolSim for RocketPoolState {
    fn fee(&self) -> f64 {
        unimplemented!("RocketPool has asymmetric fees; use spot_price or get_amount_out instead")
    }

    fn spot_price(&self, base: &Token, _quote: &Token) -> Result<f64, SimulationError> {
        let is_depositing_eth = RocketPoolState::depositing_eth(&base.address);

        let res = if is_depositing_eth {
            self.assert_deposits_enabled()?;
            let fee = self.deposit_fee_as_f64()?;
            u256_to_f64(self.reth_supply)? / u256_to_f64(self.total_eth)? * (1.0 - fee)
        } else {
            u256_to_f64(self.total_eth)? / u256_to_f64(self.reth_supply)?
        };

        Ok(res)
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        _token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        let amount_in = biguint_to_u256(&amount_in);
        let is_depositing_eth = RocketPoolState::depositing_eth(&token_in.address);

        let amount_out = if is_depositing_eth {
            self.assert_deposits_enabled()?;

            if amount_in < self.minimum_deposit {
                return Err(SimulationError::InvalidInput(
                    format!(
                        "Deposit amount {} is less than the minimum deposit of {}",
                        amount_in, self.minimum_deposit
                    ),
                    None,
                ));
            }

            let new_total_eth = safe_add_u256(self.total_eth, amount_in)?;
            if new_total_eth > self.maximum_deposit_pool_size {
                return Err(SimulationError::InvalidInput(
                    format!(
                        "Deposit would exceed maximum pool size of {}",
                        self.maximum_deposit_pool_size
                    ),
                    None,
                ));
            }

            self.get_reth_value(amount_in)?
        } else {
            let eth_out = self.get_eth_value(amount_in)?;

            if eth_out >= self.liquidity {
                return Err(SimulationError::RecoverableError(
                    "Not enough ETH in the pool to support this withdrawal".to_string(),
                ));
            }

            eth_out
        };

        let mut new_state = self.clone();
        if is_depositing_eth {
            new_state.total_eth = safe_add_u256(new_state.total_eth, amount_in)?;
            new_state.reth_supply = safe_add_u256(new_state.reth_supply, amount_out)?;
            new_state.liquidity = safe_add_u256(new_state.liquidity, amount_in)?;
        } else {
            new_state.total_eth = safe_sub_u256(new_state.total_eth, amount_out)?;
            new_state.reth_supply = safe_sub_u256(new_state.reth_supply, amount_in)?;
            new_state.liquidity = safe_sub_u256(new_state.liquidity, amount_out)?;
        };

        let gas_used = if is_depositing_eth { 209_000u32 } else { 134_000u32 };

        Ok(GetAmountOutResult::new(
            u256_to_biguint(amount_out),
            BigUint::from(gas_used),
            Box::new(new_state),
        ))
    }

    fn get_limits(
        &self,
        sell_token: Bytes,
        _buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        let is_depositing_eth = Self::depositing_eth(&sell_token);

        if is_depositing_eth {
            // ETH -> rETH: max sell = remaining capacity, max buy = rETH value of that
            let max_eth_sell = safe_sub_u256(self.maximum_deposit_pool_size, self.total_eth)?;
            let max_reth_buy = self.get_reth_value(max_eth_sell)?;
            Ok((u256_to_biguint(max_eth_sell), u256_to_biguint(max_reth_buy)))
        } else {
            // rETH -> ETH: max buy = liquidity, max sell = rETH needed to get that ETH
            // Inverse of get_eth_value: rethIn = ethOut * rethSupply / totalEth
            let max_eth_buy = self.liquidity;
            let max_reth_sell =
                safe_div_u256(safe_mul_u256(max_eth_buy, self.reth_supply)?, self.total_eth)?;
            Ok((u256_to_biguint(max_reth_sell), u256_to_biguint(max_eth_buy)))
        }
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        self.total_eth = delta
            .updated_attributes
            .get("total_eth")
            .map_or(self.total_eth, U256::from_bytes);
        self.reth_supply = delta
            .updated_attributes
            .get("reth_supply")
            .map_or(self.reth_supply, U256::from_bytes);

        self.liquidity = delta
            .updated_attributes
            .get("liquidity")
            .map_or(self.liquidity, U256::from_bytes);

        self.deposits_enabled = delta
            .updated_attributes
            .get("deposits_enabled")
            .map_or(self.deposits_enabled, |val| !U256::from_bytes(val).is_zero());
        self.deposit_fee = delta
            .updated_attributes
            .get("deposit_fee")
            .map_or(self.deposit_fee, U256::from_bytes);
        self.minimum_deposit = delta
            .updated_attributes
            .get("minimum_deposit")
            .map_or(self.minimum_deposit, U256::from_bytes);
        self.maximum_deposit_pool_size = delta
            .updated_attributes
            .get("maximum_deposit_pool_size")
            .map_or(self.maximum_deposit_pool_size, U256::from_bytes);

        Ok(())
    }

    // TODO - consider using a trait default implementation
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
        if let Some(other_state) = other.as_any().downcast_ref::<Self>() {
            self == other_state
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        str::FromStr,
    };

    use approx::assert_ulps_eq;
    use num_bigint::BigUint;
    use rstest::rstest;
    use tycho_common::{
        dto::ProtocolStateDelta,
        hex_bytes::Bytes,
        models::{token::Token, Chain},
        simulation::{
            errors::SimulationError,
            protocol_sim::{Balances, ProtocolSim},
        },
    };

    use super::*;

    /// Helper function to create a RocketPoolState with sensible default parameters for testing
    fn create_test_rocketpool_state() -> RocketPoolState {
        RocketPoolState::new(
            U256::from(100e18),  // 100 rETH supply
            U256::from(95e18),   // 95 ETH total
            U256::from(50e18),   // 50 ETH liquidity
            U256::from(5e15),    // 0.5% deposit fee (5e15 / 1e18)
            true,                // deposits enabled
            U256::from(1e16),    // 0.01 ETH minimum deposit
            U256::from(5000e18), // 5000 ETH maximum pool size
        )
    }

    fn eth_token() -> Token {
        Token::new(&Bytes::from(ETH_ADDRESS), "ETH", 18, 0, &[Some(100_000)], Chain::Ethereum, 100)
    }

    fn reth_token() -> Token {
        Token::new(
            &Bytes::from_str("0xae78736Cd615f374D3085123A210448E74Fc6393").unwrap(),
            "rETH",
            18,
            0,
            &[Some(100_000)],
            Chain::Ethereum,
            100,
        )
    }

    #[test]
    fn test_get_amount_out_deposit_eth() {
        let state = create_test_rocketpool_state();
        let eth = eth_token();
        let reth = reth_token();

        // Deposit 1 ETH
        let amount_in = BigUint::from(1e18 as u64); // 1 ETH

        let res = state
            .get_amount_out(amount_in.clone(), &eth, &reth)
            .unwrap();

        // Expected calculation (matching Solidity integer math):
        // fee = 1e18 * 5e15 / 1e18 = 5e15 (0.005 ETH)
        // net_eth = 1e18 - 5e15 = 995e15
        // reth_out = 995e15 * 100e18 / 95e18 = 1047368421052631578 (truncated)
        let expected_reth_out = BigUint::from(1047368421052631578u64);
        assert_eq!(res.amount, expected_reth_out);

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketPoolState>()
            .unwrap();

        // Verify exact state updates
        // new_total_eth = 95e18 + 1e18 = 96e18
        assert_eq!(new_state.total_eth, U256::from(96e18));
        // new_reth_supply = 100e18 + 1047368421052631578
        assert_eq!(new_state.reth_supply, U256::from_str("101047368421052631578").unwrap());
        // new_liquidity = 50e18 + 1e18 = 51e18
        assert_eq!(new_state.liquidity, U256::from(51e18));
    }

    #[test]
    fn test_get_amount_out_withdraw_reth() {
        let state = create_test_rocketpool_state();
        let eth = eth_token();
        let reth = reth_token();

        // Withdraw 1 rETH
        let amount_in = BigUint::from(1e18 as u64); // 1 rETH

        let res = state
            .get_amount_out(amount_in.clone(), &reth, &eth)
            .unwrap();

        // Expected calculation (matching Solidity integer math):
        // eth_out = reth_in * total_eth / reth_supply
        // eth_out = 1e18 * 95e18 / 100e18 = 950000000000000000 (0.95 ETH)
        let expected_eth_out = BigUint::from(0.95e18 as u64);
        assert_eq!(res.amount, expected_eth_out);

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketPoolState>()
            .unwrap();

        // Verify exact state updates
        // new_total_eth = 95e18 - 0.95e18 = 94.05e18
        assert_eq!(new_state.total_eth, U256::from(94.05e18));
        // new_reth_supply = 100e18 - 1e18 = 99e18
        assert_eq!(new_state.reth_supply, U256::from(99e18));
        // new_liquidity = 50e18 - 0.95e18 = 49.05e18
        assert_eq!(new_state.liquidity, U256::from(49.05e18));
    }

    #[test]
    fn test_get_amount_out_deposits_disabled() {
        let state = RocketPoolState::new(
            U256::from(100u64),
            U256::from(100u64),
            U256::from(50u64),
            U256::from(0u64),
            false, // deposits disabled
            U256::from(0u64),
            U256::from(1000u64),
        );

        let eth = eth_token();
        let reth = reth_token();
        let amount_in = BigUint::from(10u64);

        let res = state.get_amount_out(amount_in, &eth, &reth);

        assert!(res.is_err());
        assert!(matches!(res, Err(SimulationError::InvalidInput(_, _))));
    }

    #[test]
    fn test_get_amount_out_below_minimum_deposit() {
        let state = create_test_rocketpool_state();
        let eth = eth_token();
        let reth = reth_token();

        // Amount below minimum deposit (minimum is 0.01 ETH = 1e16)
        let amount_in = BigUint::from(1e15 as u64); // 0.001 ETH < 0.01 ETH minimum

        let res = state.get_amount_out(amount_in, &eth, &reth);

        assert!(res.is_err());
        assert!(matches!(res, Err(SimulationError::InvalidInput(_, _))));
    }

    #[test]
    fn test_get_amount_out_exceeds_max_pool_size() {
        let state = RocketPoolState::new(
            U256::from(100u64),
            U256::from(100u64),
            U256::from(50u64),
            U256::from(0u64),
            true,
            U256::from(0u64),
            U256::from(110u64), // Max pool size only 110
        );

        let eth = eth_token();
        let reth = reth_token();
        let amount_in = BigUint::from(20u64); // Would exceed 110

        let res = state.get_amount_out(amount_in, &eth, &reth);

        assert!(res.is_err());
        assert!(matches!(res, Err(SimulationError::InvalidInput(_, _))));
    }

    #[test]
    fn test_get_amount_out_insufficient_liquidity() {
        let state = RocketPoolState::new(
            U256::from(100u64),
            U256::from(100u64),
            U256::from(5u64), // Only 5 liquidity
            U256::from(0u64),
            true,
            U256::from(0u64),
            U256::from(1000u64),
        );

        let eth = eth_token();
        let reth = reth_token();
        let amount_in = BigUint::from(10u64); // Would need more than 5 liquidity

        let res = state.get_amount_out(amount_in, &reth, &eth);

        assert!(res.is_err());
        assert!(matches!(res, Err(SimulationError::RecoverableError(_))));
    }

    #[rstest]
    #[case(true)] // ETH -> rETH
    #[case(false)] // rETH -> ETH
    fn test_spot_price(#[case] is_deposit: bool) {
        let state = create_test_rocketpool_state();
        let eth = eth_token();
        let reth = reth_token();

        let res = if is_deposit {
            state.spot_price(&eth, &reth).unwrap()
        } else {
            state.spot_price(&reth, &eth).unwrap()
        };

        if is_deposit {
            // ETH -> rETH: reth_supply/total_eth * (1 - fee)
            // = (100/95) * (1 - 0.005) = 1.052631578947368421 * 0.995 = 1.0473684210526315789
            let expected = (100.0_f64 / 95.0) * (1.0 - 0.005);
            assert_ulps_eq!(res, expected);
        } else {
            // rETH -> ETH: total_eth/reth_supply = 95/100 = 0.95
            assert_ulps_eq!(res, 0.95);
        }
    }

    #[test]
    fn test_fee() {
        let state = create_test_rocketpool_state();

        // Catch the unimplemented panic
        let result = std::panic::catch_unwind(|| state.fee());

        assert!(result.is_err());
    }

    #[test]
    fn test_delta_transition() {
        let mut state = create_test_rocketpool_state();

        // Update all fields including deposits_enabled (true -> false)
        let attributes: HashMap<String, Bytes> = vec![
            ("total_eth".to_string(), Bytes::from(U256::from(200u64).to_be_bytes_vec())),
            ("reth_supply".to_string(), Bytes::from(U256::from(180u64).to_be_bytes_vec())),
            ("liquidity".to_string(), Bytes::from(U256::from(100u64).to_be_bytes_vec())),
            ("deposits_enabled".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
            ("deposit_fee".to_string(), Bytes::from(U256::from(1e16).to_be_bytes_vec())),
            ("minimum_deposit".to_string(), Bytes::from(U256::from(10u64).to_be_bytes_vec())),
            (
                "maximum_deposit_pool_size".to_string(),
                Bytes::from(U256::from(10000u64).to_be_bytes_vec()),
            ),
        ]
        .into_iter()
        .collect();

        let delta = ProtocolStateDelta {
            component_id: "RocketPool".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(),
        };

        let balances =
            Balances { component_balances: HashMap::new(), account_balances: HashMap::new() };

        let res = state.delta_transition(delta, &HashMap::new(), &balances);

        assert!(res.is_ok());
        assert_eq!(state.total_eth, U256::from(200u64));
        assert_eq!(state.reth_supply, U256::from(180u64));
        assert_eq!(state.liquidity, U256::from(100u64));
        assert!(!state.deposits_enabled);
        assert_eq!(state.deposit_fee, U256::from(1e16));
        assert_eq!(state.minimum_deposit, U256::from(10u64));
        assert_eq!(state.maximum_deposit_pool_size, U256::from(10000u64));
    }

    #[test]
    fn test_delta_transition_partial_update() {
        let mut state = create_test_rocketpool_state();

        // Save all original values
        let original_total_eth = state.total_eth;
        let original_reth_supply = state.reth_supply;
        let original_liquidity = state.liquidity;
        let original_deposits_enabled = state.deposits_enabled;
        let original_minimum_deposit = state.minimum_deposit;
        let original_maximum_deposit_pool_size = state.maximum_deposit_pool_size;

        // Only update deposit_fee
        let attributes: HashMap<String, Bytes> = vec![(
            "deposit_fee".to_string(),
            Bytes::from(U256::from(1e16).to_be_bytes_vec()), // 1%
        )]
        .into_iter()
        .collect();

        let delta = ProtocolStateDelta {
            component_id: "State1".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(),
        };

        let res = state.delta_transition(delta, &HashMap::new(), &Balances::default());

        assert!(res.is_ok());

        // Verify deposit_fee was updated
        assert_eq!(state.deposit_fee, U256::from(1e16));

        // Verify all other fields remain unchanged
        assert_eq!(state.total_eth, original_total_eth);
        assert_eq!(state.reth_supply, original_reth_supply);
        assert_eq!(state.liquidity, original_liquidity);
        assert_eq!(state.deposits_enabled, original_deposits_enabled);
        assert_eq!(state.minimum_deposit, original_minimum_deposit);
        assert_eq!(state.maximum_deposit_pool_size, original_maximum_deposit_pool_size);
    }

    #[test]
    fn test_get_limits_deposit() {
        let state = create_test_rocketpool_state();

        // Deposit: selling ETH, buying rETH
        let (max_sell, max_buy) = state
            .get_limits(eth_token().address, reth_token().address)
            .unwrap();

        // max_sell = max_pool_size - total_eth = 5000e18 - 95e18 = 4905e18
        let expected_max_sell = BigUint::from_str("4905000000000000000000").unwrap();
        assert_eq!(max_sell, expected_max_sell);

        // max_buy = get_reth_value(max_sell)
        // fee = 4905e18 * 5e15 / 1e18 = 24.525e18
        // net_eth = 4905e18 - 24.525e18 = 4880.475e18
        // max_buy = 4880.475e18 * 100e18 / 95e18 = 5137342105263157894736
        let expected_max_buy = BigUint::from_str("5137342105263157894736").unwrap();
        assert_eq!(max_buy, expected_max_buy);
    }

    #[test]
    fn test_get_limits_withdrawal() {
        let state = create_test_rocketpool_state();

        // Withdrawal: selling rETH, buying ETH
        let (max_sell, max_buy) = state
            .get_limits(reth_token().address, eth_token().address)
            .unwrap();

        // max_buy = liquidity = 50e18
        let expected_max_buy = BigUint::from_str("50000000000000000000").unwrap();
        assert_eq!(max_buy, expected_max_buy);

        // max_sell = max_buy * reth_supply / total_eth = 50e18 * 100e18 / 95e18
        let expected_max_sell = BigUint::from_str("52631578947368421052").unwrap();
        assert_eq!(max_sell, expected_max_sell);
    }
}
