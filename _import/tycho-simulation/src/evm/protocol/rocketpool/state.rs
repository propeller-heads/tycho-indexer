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
    rocketpool::{ETH_ADDRESS, ROCKET_POOL_COMPONENT_ID},
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
    /// Returns the fee applied on deposits (ETH -> rETH) as a decimal.
    /// The withdrawals (rETH -> ETH) have no fee.
    fn fee(&self) -> f64 {
        // TODO: This needs to be handled gracefully - the trait should return Result
        self.deposit_fee_as_f64()
            .expect("deposit_fee conversion to f64 failed")
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
        balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        self.total_eth = delta
            .updated_attributes
            .get("total_eth")
            .map_or(self.total_eth, |val| U256::from_bytes(val));

        self.reth_supply = delta
            .updated_attributes
            .get("reth_supply")
            .map_or(self.reth_supply, |val| U256::from_bytes(val));

        // TODO - check if we are correctly fetching the liquidity from the right component
        self.liquidity = balances
            .component_balances
            .get(ROCKET_POOL_COMPONENT_ID)
            .map_or(self.liquidity, |component_tokens_balances| {
                component_tokens_balances
                    .get(&Bytes::from(ETH_ADDRESS))
                    .map_or(self.liquidity, |component_eth_balance| {
                        U256::from_bytes(component_eth_balance)
                    })
            });

        self.deposits_enabled = delta
            .updated_attributes
            .get("deposits_enabled")
            .map_or(self.deposits_enabled, |val| !U256::from_bytes(val).is_zero());
        self.deposit_fee = delta
            .updated_attributes
            .get("deposit_fee")
            .map_or(self.deposit_fee, |val| U256::from_bytes(val));
        self.minimum_deposit = delta
            .updated_attributes
            .get("minimum_deposit")
            .map_or(self.minimum_deposit, |val| U256::from_bytes(val));
        self.maximum_deposit_pool_size = delta
            .updated_attributes
            .get("maximum_deposit_pool_size")
            .map_or(self.maximum_deposit_pool_size, |val| U256::from_bytes(val));

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

    use alloy::hex;
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
            U256::from_str("100000000000000000000").unwrap(), // 100 rETH supply
            U256::from_str("95000000000000000000").unwrap(),  /* 95 ETH total (slightly less
                                                               * than rETH for exchange rate >
                                                               * 1) */
            U256::from_str("50000000000000000000").unwrap(), // 50 ETH liquidity
            U256::from_str("5000000000000000").unwrap(),     // 0.5% deposit fee (5e15 / 1e18)
            true,                                            // deposits enabled
            U256::from_str("10000000000000000").unwrap(),    // 0.01 ETH minimum deposit
            U256::from_str("5000000000000000000000").unwrap(), // 5000 ETH maximum pool size
        )
    }

    fn eth_token() -> Token {
        Token::new(
            &Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            "ETH",
            18,
            0,
            &[Some(100_000)],
            Chain::Ethereum,
            100,
        )
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
        let amount_in = BigUint::from_str("1000000000000000000").unwrap();

        let res = state
            .get_amount_out(amount_in.clone(), &eth, &reth)
            .unwrap();

        // Amount out should be approximately reth_supply/total_eth * (1 - fee) * amount_in
        // = 100/95 * 0.995 * 1 ETH ≈ 1.047 rETH
        assert!(res.amount > BigUint::from(0u64));

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketPoolState>()
            .unwrap();

        // Verify state was updated
        assert!(new_state.total_eth > state.total_eth);
        assert!(new_state.reth_supply > state.reth_supply);
        assert!(new_state.liquidity > state.liquidity);
    }

    #[test]
    fn test_get_amount_out_withdraw_reth() {
        let state = create_test_rocketpool_state();
        let eth = eth_token();
        let reth = reth_token();

        // Withdraw 1 rETH
        let amount_in = BigUint::from_str("1000000000000000000").unwrap();

        let res = state
            .get_amount_out(amount_in.clone(), &reth, &eth)
            .unwrap();

        // Amount out should be approximately total_eth/reth_supply * amount_in
        // = 95/100 * 1 rETH = 0.95 ETH
        assert!(res.amount > BigUint::from(0u64));

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketPoolState>()
            .unwrap();

        // Verify state was updated (withdrawal reduces values)
        assert!(new_state.total_eth < state.total_eth);
        assert!(new_state.reth_supply < state.reth_supply);
        assert!(new_state.liquidity < state.liquidity);
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

        // Amount below minimum deposit (0.01 ETH = 10^16)
        let amount_in = BigUint::from_str("1000000000000000").unwrap(); // 0.001 ETH

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

        assert!(res > 0.0);
        if is_deposit {
            // ETH -> rETH: should be reth_supply/total_eth * (1 - fee)
            // = 100/95 * 0.995 ≈ 1.047
            assert!(res > 1.0);
        } else {
            // rETH -> ETH: should be total_eth/reth_supply = 95/100 = 0.95
            assert_ulps_eq!(res, 0.95);
        }
    }

    #[test]
    fn test_fee() {
        let state = create_test_rocketpool_state();

        let res = state.fee();

        // 0.5% fee = 0.005
        assert_ulps_eq!(res, 0.005);
    }

    #[test]
    fn test_delta_transition() {
        let mut state = create_test_rocketpool_state();

        let eth_address = Bytes::from(hex!("0000000000000000000000000000000000000000"));
        let component_id = "0xdd3f50f8a6cafbe9b31a427582963f465e745af8";

        let attributes: HashMap<String, Bytes> = vec![
            ("total_eth".to_string(), Bytes::from(U256::from(200u64).to_be_bytes_vec())),
            ("reth_supply".to_string(), Bytes::from(U256::from(180u64).to_be_bytes_vec())),
        ]
        .into_iter()
        .collect();

        let delta = ProtocolStateDelta {
            component_id: component_id.to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(),
        };

        let mut component_balances = HashMap::new();
        component_balances.insert(
            component_id.to_string(),
            HashMap::from([(eth_address, Bytes::from(U256::from(100u64).to_be_bytes_vec()))]),
        );
        let balances = Balances { component_balances, account_balances: HashMap::new() };

        let res = state.delta_transition(delta, &HashMap::new(), &balances);

        assert!(res.is_ok());
        assert_eq!(state.total_eth, U256::from(200u64));
        assert_eq!(state.reth_supply, U256::from(180u64));
        assert_eq!(state.liquidity, U256::from(100u64));
    }

    #[test]
    fn test_delta_transition_partial_update() {
        let mut state = create_test_rocketpool_state();
        let original_total_eth = state.total_eth;
        let original_reth_supply = state.reth_supply;

        // Only update deposit_fee
        let attributes: HashMap<String, Bytes> = vec![(
            "deposit_fee".to_string(),
            Bytes::from(
                U256::from_str("10000000000000000")
                    .unwrap()
                    .to_be_bytes_vec(),
            ), // 1%
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
        // These should remain unchanged
        assert_eq!(state.total_eth, original_total_eth);
        assert_eq!(state.reth_supply, original_reth_supply);
        // Fee should be updated to 1% (10000000000000000 / 1e18 = 0.01)
        assert_eq!(state.deposit_fee, U256::from_str("10000000000000000").unwrap());
        assert_ulps_eq!(state.fee(), 0.01);
    }

    #[test]
    fn test_get_limits_deposit() {
        // Use smaller values to avoid f64 precision issues
        let state = RocketPoolState::new(
            U256::from(1000u64), // rETH supply
            U256::from(950u64),  // total ETH
            U256::from(500u64),  // liquidity
            U256::from(0u64),    // no fee for simplicity
            true,
            U256::from(0u64),
            U256::from(10000u64), // max pool size
        );

        let eth_address = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let reth_address = Bytes::from_str("0xae78736Cd615f374D3085123A210448E74Fc6393").unwrap();

        let (max_sell, max_buy) = state
            .get_limits(eth_address, reth_address)
            .unwrap();

        // Max sell = max_pool_size - total_eth = 10000 - 950 = 9050
        assert_eq!(max_sell, BigUint::from(9050u64));
        // Max buy = max_sell * spot_price = 9050 * (1000/950) ≈ 9526
        assert!(max_buy > BigUint::from(0u64));
    }

    #[test]
    fn test_get_limits_withdrawal() {
        // Use smaller values to avoid f64 precision issues
        let state = RocketPoolState::new(
            U256::from(1000u64), // rETH supply
            U256::from(950u64),  // total ETH
            U256::from(500u64),  // liquidity
            U256::from(0u64),    // no fee
            true,
            U256::from(0u64),
            U256::from(10000u64),
        );

        let eth_address = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let reth_address = Bytes::from_str("0xae78736Cd615f374D3085123A210448E74Fc6393").unwrap();

        let (max_sell, max_buy) = state
            .get_limits(reth_address, eth_address)
            .unwrap();

        // Max buy (ETH) should be limited by liquidity = 500
        assert_eq!(max_buy, BigUint::from(500u64));
        // Max sell = liquidity * spot_price = 500 * (950/1000) = 475
        assert!(max_sell > BigUint::from(0u64));
    }
}
