use std::{any::Any, collections::HashMap};

use alloy::primitives::U256;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
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
    safe_math::{safe_add_u256, safe_sub_u256},
    u256_num::{biguint_to_u256, u256_to_biguint, u256_to_f64},
    utils::solidity_math::mul_div,
};

const DEPOSIT_FEE_BASE: u128 = 1_000_000_000_000_000_000; // 1e18

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RocketpoolState {
    pub reth_supply: U256,
    pub total_eth: U256,
    /// ETH available in the deposit pool contract
    pub deposit_contract_balance: U256,
    /// ETH available in the rETH contract
    pub reth_contract_liquidity: U256,
    /// Deposit fee as %, scaled by DEPOSIT_FEE_BASE, such as 500000000000000 represents 0.05% fee.
    pub deposit_fee: U256,
    pub deposits_enabled: bool,
    pub min_deposit_amount: U256,
    pub max_deposit_pool_size: U256,
    /// Whether assigning deposits is enabled (allows using queue capacity)
    pub deposit_assigning_enabled: bool,
    /// Maximum number of assignments per deposit
    pub deposit_assign_maximum: U256,
    /// The base number of assignments to try per deposit
    pub deposit_assign_socialised_maximum: U256,
    /// Total ETH requested across express + standard megapool queues
    pub megapool_queue_requested_total: U256,
    /// Round-robin index for express/standard queue assignment
    pub megapool_queue_index: U256,
    /// How many express assignments per standard assignment (e.g., 4)
    pub express_queue_rate: U256,
}

impl RocketpoolState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reth_supply: U256,
        total_eth: U256,
        deposit_contract_balance: U256,
        reth_contract_liquidity: U256,
        deposit_fee: U256,
        deposits_enabled: bool,
        min_deposit_amount: U256,
        max_deposit_pool_size: U256,
        deposit_assigning_enabled: bool,
        deposit_assign_maximum: U256,
        deposit_assign_socialised_maximum: U256,
        megapool_queue_requested_total: U256,
        megapool_queue_index: U256,
        express_queue_rate: U256,
    ) -> Self {
        Self {
            reth_supply,
            total_eth,
            deposit_contract_balance,
            reth_contract_liquidity,
            deposit_fee,
            deposits_enabled,
            min_deposit_amount,
            max_deposit_pool_size,
            deposit_assigning_enabled,
            deposit_assign_maximum,
            deposit_assign_socialised_maximum,
            megapool_queue_requested_total,
            megapool_queue_index,
            express_queue_rate,
        }
    }

    /// Calculates rETH amount out for a given ETH deposit amount.
    fn get_reth_value(&self, eth_amount: U256) -> Result<U256, SimulationError> {
        let fee = mul_div(eth_amount, self.deposit_fee, U256::from(DEPOSIT_FEE_BASE))?;
        let net_eth = safe_sub_u256(eth_amount, fee)?;
        mul_div(net_eth, self.reth_supply, self.total_eth)
    }

    /// Calculates ETH amount out for a given rETH burn amount.
    fn get_eth_value(&self, reth_amount: U256) -> Result<U256, SimulationError> {
        mul_div(reth_amount, self.total_eth, self.reth_supply)
    }

    fn is_depositing_eth(token_in: &Bytes) -> bool {
        token_in.as_ref() == ETH_ADDRESS
    }

    fn assert_deposits_enabled(&self) -> Result<(), SimulationError> {
        if !self.deposits_enabled {
            Err(SimulationError::RecoverableError(
                "Deposits are currently disabled in Rocketpool".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Returns the total effective capacity of the megapool queues.
    /// This is the total ETH requested across express and standard queues,
    /// tracked directly by the protocol via `deposit.pool.requested.total`.
    fn get_effective_capacity(&self) -> U256 {
        self.megapool_queue_requested_total
    }

    /// Returns the maximum deposit capacity considering both the base pool size
    /// and the megapool queue capacity (if deposit_assigning_enabled).
    fn get_max_deposit_capacity(&self) -> Result<U256, SimulationError> {
        if self.deposit_assigning_enabled {
            safe_add_u256(self.max_deposit_pool_size, self.get_effective_capacity())
        } else {
            Ok(self.max_deposit_pool_size)
        }
    }

    /// Returns the excess balance available for withdrawals from the deposit pool.
    /// Excess = deposit_contract_balance - megapool_queue_requested_total
    fn get_deposit_pool_excess_balance(&self) -> Result<U256, SimulationError> {
        let queue_capacity = self.get_effective_capacity();
        if queue_capacity >= self.deposit_contract_balance {
            Ok(U256::ZERO)
        } else {
            safe_sub_u256(self.deposit_contract_balance, queue_capacity)
        }
    }

    /// Returns total available liquidity for withdrawals.
    fn get_total_available_for_withdrawal(&self) -> Result<U256, SimulationError> {
        let deposit_pool_excess = self.get_deposit_pool_excess_balance()?;
        safe_add_u256(self.reth_contract_liquidity, deposit_pool_excess)
    }

    /// Approximates ETH assigned from the deposit pool after a deposit.
    ///
    /// In Saturn v4, `_assignMegapools(count)` dequeues up to `count` entries from the
    /// express/standard queues (capped at `deposit_assign_maximum`). Each entry has a variable
    /// ETH amount. We approximate the total assigned as
    /// `min(deposit_contract_balance, megapool_queue_requested_total)`.
    ///
    /// Note: `deposit_assign_maximum` limits the *number* of entries processed, not the ETH
    /// amount. Without knowing per-entry sizes, we can't use it to tighten the bound.
    fn calculate_assign_deposits(&self) -> U256 {
        if !self.deposit_assigning_enabled ||
            self.megapool_queue_requested_total
                .is_zero()
        {
            return U256::ZERO;
        }

        self.deposit_contract_balance
            .min(self.megapool_queue_requested_total)
    }
}

#[typetag::serde]
impl ProtocolSim for RocketpoolState {
    fn fee(&self) -> f64 {
        unimplemented!("Rocketpool has asymmetric fees; use spot_price or get_amount_out instead")
    }

    fn spot_price(&self, _base: &Token, quote: &Token) -> Result<f64, SimulationError> {
        let is_depositing_eth = RocketpoolState::is_depositing_eth(&quote.address);
        let amount = U256::from(1e18);

        let base_per_quote = if is_depositing_eth {
            self.assert_deposits_enabled()?;
            self.get_reth_value(amount)?
        } else {
            self.get_eth_value(amount)?
        };

        let base_per_quote = u256_to_f64(base_per_quote)? / 1e18;
        Ok(1.0 / base_per_quote)
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        _token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        let amount_in = biguint_to_u256(&amount_in);
        let is_depositing_eth = RocketpoolState::is_depositing_eth(&token_in.address);

        let amount_out = if is_depositing_eth {
            self.assert_deposits_enabled()?;

            if amount_in < self.min_deposit_amount {
                return Err(SimulationError::InvalidInput(
                    format!(
                        "Deposit amount {} is less than the minimum deposit of {}",
                        amount_in, self.min_deposit_amount
                    ),
                    None,
                ));
            }

            let capacity_needed = safe_add_u256(self.deposit_contract_balance, amount_in)?;
            let max_capacity = self.get_max_deposit_capacity()?;
            if capacity_needed > max_capacity {
                return Err(SimulationError::InvalidInput(
                    format!(
                        "Deposit would exceed maximum pool size (capacity needed: {}, max: {})",
                        capacity_needed, max_capacity
                    ),
                    None,
                ));
            }

            self.get_reth_value(amount_in)?
        } else {
            let eth_out = self.get_eth_value(amount_in)?;

            let total_available = self.get_total_available_for_withdrawal()?;
            if eth_out > total_available {
                return Err(SimulationError::RecoverableError(format!(
                    "Withdrawal {} exceeds available liquidity {}",
                    eth_out, total_available
                )));
            }

            eth_out
        };

        let mut new_state = self.clone();
        if is_depositing_eth {
            new_state.deposit_contract_balance =
                safe_add_u256(new_state.deposit_contract_balance, amount_in)?;

            let eth_assigned = new_state.calculate_assign_deposits();
            if eth_assigned > U256::ZERO {
                new_state.deposit_contract_balance =
                    safe_sub_u256(new_state.deposit_contract_balance, eth_assigned)?;
                new_state.megapool_queue_requested_total =
                    safe_sub_u256(new_state.megapool_queue_requested_total, eth_assigned)?;
            }
        } else {
            #[allow(clippy::collapsible_else_if)]
            if amount_out <= new_state.reth_contract_liquidity {
                new_state.reth_contract_liquidity =
                    safe_sub_u256(new_state.reth_contract_liquidity, amount_out)?;
            } else {
                let needed_from_deposit_pool =
                    safe_sub_u256(amount_out, new_state.reth_contract_liquidity)?;
                new_state.deposit_contract_balance =
                    safe_sub_u256(new_state.deposit_contract_balance, needed_from_deposit_pool)?;
                new_state.reth_contract_liquidity = U256::ZERO;
            }
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
        let is_depositing_eth = Self::is_depositing_eth(&sell_token);

        if is_depositing_eth {
            let max_capacity = self.get_max_deposit_capacity()?;
            let max_eth_sell = safe_sub_u256(max_capacity, self.deposit_contract_balance)?;
            let max_reth_buy = self.get_reth_value(max_eth_sell)?;
            Ok((u256_to_biguint(max_eth_sell), u256_to_biguint(max_reth_buy)))
        } else {
            let max_eth_buy = self.get_total_available_for_withdrawal()?;
            let max_reth_sell = mul_div(max_eth_buy, self.reth_supply, self.total_eth)?;
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
        self.deposit_contract_balance = delta
            .updated_attributes
            .get("deposit_contract_balance")
            .map_or(self.deposit_contract_balance, U256::from_bytes);
        self.reth_contract_liquidity = delta
            .updated_attributes
            .get("reth_contract_liquidity")
            .map_or(self.reth_contract_liquidity, U256::from_bytes);
        self.deposits_enabled = delta
            .updated_attributes
            .get("deposits_enabled")
            .map_or(self.deposits_enabled, |val| !U256::from_bytes(val).is_zero());
        self.deposit_assigning_enabled = delta
            .updated_attributes
            .get("deposit_assigning_enabled")
            .map_or(self.deposit_assigning_enabled, |val| !U256::from_bytes(val).is_zero());
        self.deposit_fee = delta
            .updated_attributes
            .get("deposit_fee")
            .map_or(self.deposit_fee, U256::from_bytes);
        self.min_deposit_amount = delta
            .updated_attributes
            .get("min_deposit_amount")
            .map_or(self.min_deposit_amount, U256::from_bytes);
        self.max_deposit_pool_size = delta
            .updated_attributes
            .get("max_deposit_pool_size")
            .map_or(self.max_deposit_pool_size, U256::from_bytes);
        self.deposit_assign_maximum = delta
            .updated_attributes
            .get("deposit_assign_maximum")
            .map_or(self.deposit_assign_maximum, U256::from_bytes);
        self.deposit_assign_socialised_maximum = delta
            .updated_attributes
            .get("deposit_assign_socialised_maximum")
            .map_or(self.deposit_assign_socialised_maximum, U256::from_bytes);
        self.megapool_queue_requested_total = delta
            .updated_attributes
            .get("megapool_queue_requested_total")
            .map_or(self.megapool_queue_requested_total, U256::from_bytes);
        self.megapool_queue_index = delta
            .updated_attributes
            .get("megapool_queue_index")
            .map_or(self.megapool_queue_index, U256::from_bytes);
        self.express_queue_rate = delta
            .updated_attributes
            .get("express_queue_rate")
            .map_or(self.express_queue_rate, U256::from_bytes);

        Ok(())
    }

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

    fn query_pool_swap(
        &self,
        params: &tycho_common::simulation::protocol_sim::QueryPoolSwapParams,
    ) -> Result<tycho_common::simulation::protocol_sim::PoolSwap, SimulationError> {
        crate::evm::query_pool_swap::query_pool_swap(self, params)
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

    /// Helper function to create a RocketpoolState with easy-to-compute defaults for testing.
    /// - Exchange rate: 1 rETH = 2 ETH (100 rETH backed by 200 ETH)
    /// - Deposit fee: 40%
    /// - Deposit contract balance: 50 ETH
    /// - rETH contract liquidity: 0 ETH
    /// - Max pool size: 1000 ETH
    /// - Assign deposits enabled: false
    /// - Express queue rate: 4
    fn create_state() -> RocketpoolState {
        RocketpoolState::new(
            U256::from(100e18), // reth_supply: 100 rETH
            U256::from(200e18), /* total_eth: 200 ETH (1 rETH =
                                 * 2 ETH) */
            U256::from(50e18), // deposit_contract_balance: 50 ETH
            U256::ZERO,        // reth_contract_liquidity: 0 ETH
            U256::from(400_000_000_000_000_000u64), // deposit_fee: 40% (0.4e18)
            true,              // deposits_enabled
            U256::ZERO,        // min_deposit_amount
            U256::from(1000e18), // max_deposit_pool_size: 1000 ETH
            false,             // deposit_assigning_enabled
            U256::ZERO,        // deposit_assign_maximum
            U256::ZERO,        // deposit_assign_socialised_maximum
            U256::ZERO,        // megapool_queue_requested_total
            U256::ZERO,        // megapool_queue_index
            U256::from(4u64),  // express_queue_rate: 4
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

    // ============ Effective Capacity Tests ============

    #[test]
    fn test_effective_capacity_empty() {
        let state = create_state();
        assert_eq!(state.get_effective_capacity(), U256::ZERO);
    }

    #[test]
    fn test_effective_capacity_with_requested_total() {
        let mut state = create_state();
        state.megapool_queue_requested_total = U256::from(100e18);
        assert_eq!(state.get_effective_capacity(), U256::from(100e18));
    }

    // ============ Max Deposit Capacity Tests ============

    #[test]
    fn test_max_capacity_assign_disabled() {
        let state = create_state();
        assert_eq!(
            state
                .get_max_deposit_capacity()
                .unwrap(),
            U256::from(1000e18)
        );
    }

    #[test]
    fn test_max_capacity_assign_enabled_empty_queue() {
        let mut state = create_state();
        state.deposit_assigning_enabled = true;
        assert_eq!(
            state
                .get_max_deposit_capacity()
                .unwrap(),
            U256::from(1000e18)
        );
    }

    #[test]
    fn test_max_capacity_assign_enabled_with_queue() {
        let mut state = create_state();
        state.deposit_assigning_enabled = true;
        state.megapool_queue_requested_total = U256::from(500e18);
        // 1000 + 500 = 1500 ETH
        assert_eq!(
            state
                .get_max_deposit_capacity()
                .unwrap(),
            U256::from(1500e18)
        );
    }

    // ============ Delta Transition Tests ============

    #[test]
    fn test_delta_transition_basic() {
        let mut state = create_state();

        let attributes: HashMap<String, Bytes> = [
            ("total_eth", U256::from(300u64)),
            ("reth_supply", U256::from(150u64)),
            ("deposit_contract_balance", U256::from(100u64)),
            ("reth_contract_liquidity", U256::from(20u64)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), Bytes::from(v.to_be_bytes_vec())))
        .collect();

        let delta = ProtocolStateDelta {
            component_id: "Rocketpool".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(),
        };

        state
            .delta_transition(delta, &HashMap::new(), &Balances::default())
            .unwrap();

        assert_eq!(state.total_eth, U256::from(300u64));
        assert_eq!(state.reth_supply, U256::from(150u64));
        assert_eq!(state.deposit_contract_balance, U256::from(100u64));
        assert_eq!(state.reth_contract_liquidity, U256::from(20u64));
    }

    #[test]
    fn test_delta_transition_megapool_fields() {
        let mut state = create_state();

        let attributes: HashMap<String, Bytes> = [
            ("megapool_queue_requested_total", U256::from(1000u64)),
            ("megapool_queue_index", U256::from(42u64)),
            ("express_queue_rate", U256::from(5u64)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), Bytes::from(v.to_be_bytes_vec())))
        .collect();

        let delta = ProtocolStateDelta {
            component_id: "Rocketpool".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(),
        };

        state
            .delta_transition(delta, &HashMap::new(), &Balances::default())
            .unwrap();

        assert_eq!(state.megapool_queue_requested_total, U256::from(1000u64));
        assert_eq!(state.megapool_queue_index, U256::from(42u64));
        assert_eq!(state.express_queue_rate, U256::from(5u64));
    }

    // ============ Spot Price Tests ============

    #[test]
    fn test_spot_price_deposit() {
        let state = create_state();
        let price = state
            .spot_price(&eth_token(), &reth_token())
            .unwrap();
        assert_ulps_eq!(price, 0.5);
    }

    #[test]
    fn test_spot_price_withdraw() {
        let state = create_state();
        let price = state
            .spot_price(&reth_token(), &eth_token())
            .unwrap();
        assert_ulps_eq!(price, 1.0 / 0.3);
    }

    #[test]
    fn test_fee_panics() {
        let state = create_state();
        let result = std::panic::catch_unwind(|| state.fee());
        assert!(result.is_err());
    }

    // ============ Get Limits Tests ============

    #[test]
    fn test_limits_deposit() {
        let state = create_state();
        let (max_sell, max_buy) = state
            .get_limits(eth_token().address, reth_token().address)
            .unwrap();
        // max_sell = 1000 - 50 = 950 ETH
        assert_eq!(max_sell, BigUint::from(950_000_000_000_000_000_000u128));
        // max_buy = 950 * 0.6 * 100/200 = 285 rETH
        assert_eq!(max_buy, BigUint::from(285_000_000_000_000_000_000u128));
    }

    #[test]
    fn test_limits_withdrawal() {
        let state = create_state();
        let (max_sell, max_buy) = state
            .get_limits(reth_token().address, eth_token().address)
            .unwrap();
        // max_buy = liquidity = 50 ETH
        assert_eq!(max_buy, BigUint::from(50_000_000_000_000_000_000u128));
        // max_sell = 50 * 100/200 = 25 rETH
        assert_eq!(max_sell, BigUint::from(25_000_000_000_000_000_000u128));
    }

    #[test]
    fn test_limits_with_megapool_queue() {
        let mut state = create_state();
        state.max_deposit_pool_size = U256::from(100e18);
        state.deposit_assigning_enabled = true;
        state.megapool_queue_requested_total = U256::from(62e18);

        let (max_sell, _) = state
            .get_limits(eth_token().address, reth_token().address)
            .unwrap();
        // max_capacity = 100 + 62 = 162 ETH; max_sell = 162 - 50 = 112 ETH
        assert_eq!(max_sell, BigUint::from(112_000_000_000_000_000_000u128));
    }

    // ============ Get Amount Out - Happy Path Tests ============

    #[test]
    fn test_deposit_eth() {
        let state = create_state();
        // Deposit 10 ETH: fee=4, net=6 → 6*100/200 = 3 rETH
        let res = state
            .get_amount_out(
                BigUint::from(10_000_000_000_000_000_000u128),
                &eth_token(),
                &reth_token(),
            )
            .unwrap();

        assert_eq!(res.amount, BigUint::from(3_000_000_000_000_000_000u128));

        // Collateral buffer: target = 200e18 * 1e16 / 1e18 = 2e18.
        // Shortfall = 2e18 - 0 = 2e18. to_reth = min(10, 2) = 2, to_vault = 8.
        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketpoolState>()
            .unwrap();
        assert_eq!(new_state.deposit_contract_balance, U256::from(60e18));
    }

    #[test]
    fn test_withdraw_reth() {
        let state = create_state();
        // Withdraw 10 rETH: 10*200/100 = 20 ETH
        let res = state
            .get_amount_out(
                BigUint::from(10_000_000_000_000_000_000u128),
                &reth_token(),
                &eth_token(),
            )
            .unwrap();

        assert_eq!(res.amount, BigUint::from(20_000_000_000_000_000_000u128));

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketpoolState>()
            .unwrap();
        assert_eq!(new_state.deposit_contract_balance, U256::from(30e18));
    }

    // ============ Get Amount Out - Error Cases Tests ============

    #[test]
    fn test_deposit_disabled() {
        let mut state = create_state();
        state.deposits_enabled = false;
        let res = state.get_amount_out(BigUint::from(10u64), &eth_token(), &reth_token());
        assert!(matches!(res, Err(SimulationError::RecoverableError(_))));
    }

    #[test]
    fn test_deposit_below_minimum() {
        let mut state = create_state();
        state.min_deposit_amount = U256::from(100u64);
        let res = state.get_amount_out(BigUint::from(50u64), &eth_token(), &reth_token());
        assert!(matches!(res, Err(SimulationError::InvalidInput(_, _))));
    }

    #[test]
    fn test_deposit_exceeds_max_pool() {
        let mut state = create_state();
        state.max_deposit_pool_size = U256::from(60e18);
        let res = state.get_amount_out(
            BigUint::from(20_000_000_000_000_000_000u128),
            &eth_token(),
            &reth_token(),
        );
        assert!(matches!(res, Err(SimulationError::InvalidInput(_, _))));
    }

    #[test]
    fn test_withdrawal_insufficient_liquidity() {
        let state = create_state();
        let res = state.get_amount_out(
            BigUint::from(30_000_000_000_000_000_000u128),
            &reth_token(),
            &eth_token(),
        );
        assert!(matches!(res, Err(SimulationError::RecoverableError(_))));
    }

    #[test]
    fn test_withdrawal_limited_by_queue() {
        let mut state = create_state();
        state.deposit_contract_balance = U256::from(100e18);
        state.megapool_queue_requested_total = U256::from(62e18);

        // excess = 100 - 62 = 38 ETH; try withdraw 20 rETH = 40 ETH > 38
        let res = state.get_amount_out(
            BigUint::from(20_000_000_000_000_000_000u128),
            &reth_token(),
            &eth_token(),
        );
        assert!(matches!(res, Err(SimulationError::RecoverableError(_))));

        // Withdraw 15 rETH = 30 ETH <= 38 should work
        let res = state
            .get_amount_out(
                BigUint::from(15_000_000_000_000_000_000u128),
                &reth_token(),
                &eth_token(),
            )
            .unwrap();
        assert_eq!(res.amount, BigUint::from(30_000_000_000_000_000_000u128));
    }

    #[test]
    fn test_withdrawal_uses_both_pools() {
        let mut state = create_state();
        state.reth_contract_liquidity = U256::from(10e18);
        state.deposit_contract_balance = U256::from(50e18);

        // Withdraw 15 rETH = 30 ETH (more than reth_contract_liquidity of 10 ETH)
        let res = state
            .get_amount_out(
                BigUint::from(15_000_000_000_000_000_000u128),
                &reth_token(),
                &eth_token(),
            )
            .unwrap();

        assert_eq!(res.amount, BigUint::from(30_000_000_000_000_000_000u128));

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketpoolState>()
            .unwrap();
        assert_eq!(new_state.reth_contract_liquidity, U256::ZERO);
        assert_eq!(new_state.deposit_contract_balance, U256::from(30e18));
    }

    // ============ Assign Deposits Tests ============

    #[test]
    fn test_assign_deposits_with_queue() {
        let mut state = create_state();
        state.deposit_contract_balance = U256::from(100e18);
        state.deposit_assigning_enabled = true;
        state.megapool_queue_requested_total = U256::from(40e18);

        let res = state
            .get_amount_out(
                BigUint::from(10_000_000_000_000_000_000u128),
                &eth_token(),
                &reth_token(),
            )
            .unwrap();

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketpoolState>()
            .unwrap();
        // 100 + 10 = 110 balance, min(110, 40) = 40 assigned
        // final balance = 110 - 40 = 70
        assert_eq!(new_state.deposit_contract_balance, U256::from(70e18));
        assert_eq!(new_state.megapool_queue_requested_total, U256::ZERO);
    }

    #[test]
    fn test_assign_deposits_empty_queue() {
        let mut state = create_state();
        state.deposit_assigning_enabled = true;

        let res = state
            .get_amount_out(
                BigUint::from(10_000_000_000_000_000_000u128),
                &eth_token(),
                &reth_token(),
            )
            .unwrap();

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketpoolState>()
            .unwrap();
        // No queue, no assignment: 50 + 10 = 60
        assert_eq!(new_state.deposit_contract_balance, U256::from(60e18));
    }

    #[test]
    fn test_assign_deposits_disabled() {
        let mut state = create_state();
        state.deposit_assigning_enabled = false;
        state.megapool_queue_requested_total = U256::from(100e18);

        let res = state
            .get_amount_out(
                BigUint::from(10_000_000_000_000_000_000u128),
                &eth_token(),
                &reth_token(),
            )
            .unwrap();

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketpoolState>()
            .unwrap();
        // Assign disabled, no assignment: 50 + 10 = 60
        assert_eq!(new_state.deposit_contract_balance, U256::from(60e18));
    }

    // ============ Live Post-Saturn Transaction Tests ============

    /// State at block 24480104 (just before first post-Saturn deposit).
    /// Verified against on-chain data via cast calls at this block.
    fn create_state_at_block_24480104() -> RocketpoolState {
        RocketpoolState::new(
            U256::from_str_radix("489a96a246a2e92bbbd1", 16).unwrap(), // reth_supply
            U256::from_str_radix("540e645ee4119f4d8b9e", 16).unwrap(), // total_eth
            U256::from_str_radix("8dcfa9d0071987bb", 16).unwrap(),     // deposit_contract_balance
            U256::from_str_radix("c28d2e1d64f99ea24", 16).unwrap(),    // reth_contract_liquidity
            U256::from_str_radix("1c6bf52634000", 16).unwrap(),        // deposit_fee (0.05%)
            true,                                                      // deposits_enabled
            U256::from_str_radix("2386f26fc10000", 16).unwrap(),       // min_deposit_amount
            U256::from_str_radix("4f68ca6d8cd91c6000000", 16).unwrap(), // max_deposit_pool_size
            true,                                                      // deposit_assigning_enabled
            U256::from(90u64),                                         // deposit_assign_maximum
            U256::ZERO, // deposit_assign_socialised_maximum
            U256::from_str_radix("4a60532ad51bf000000", 16).unwrap(), /* megapool_queue_requested_total */
            U256::ZERO,                                               // megapool_queue_index
            U256::from(4u64),                                         // express_queue_rate
        )
    }

    /// Test against real post-Saturn deposit transaction.
    /// Tx 0xe0f1db165b621cb1e50b629af9d47e064be464fbcc7f2bcba3df1d27dbb916be at block 24480105.
    /// User deposited 85 ETH and received 73382345660413064855 rETH (0.05% fee applied).
    ///
    /// Note on post-state: On-chain, the 85 ETH went entirely to the rETH collateral buffer
    /// (deposit_contract_balance unchanged at 10218572790464350139). Our simulation
    /// conservatively adds the full amount to deposit_contract_balance. This is a known
    /// approximation — the output amount is exact, but post-state balance distribution differs.
    #[test]
    fn test_live_deposit_post_saturn() {
        let state = create_state_at_block_24480104();

        let deposit_amount = BigUint::from(85_000_000_000_000_000_000u128);
        let res = state
            .get_amount_out(deposit_amount, &eth_token(), &reth_token())
            .unwrap();

        // Output amount: exact match with on-chain result
        let expected_reth_out = BigUint::from(73_382_345_660_413_064_855u128);
        assert_eq!(res.amount, expected_reth_out);

        // Post-state: document known divergence from on-chain behavior.
        // On-chain, processDeposit() routes ETH to rETH contract first (collateral buffer),
        // so deposit_contract_balance was unchanged. Our simulation adds to
        // deposit_contract_balance and then subtracts via queue assignment. The total_eth
        // and reth_supply (oracle-managed) are always unchanged, which is correct.
        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketpoolState>()
            .unwrap();
        assert_eq!(new_state.total_eth, state.total_eth);
        assert_eq!(new_state.reth_supply, state.reth_supply);
    }

    /// Test against real post-Saturn burn transaction.
    /// Block 24481338: user burned 2515686112138065226 rETH and received 2912504376202664754 ETH.
    #[test]
    fn test_live_burn_post_saturn() {
        let state = create_state_at_block_24480104();

        let burn_amount = BigUint::from(2_515_686_112_138_065_226u128);
        let res = state
            .get_amount_out(burn_amount, &reth_token(), &eth_token())
            .unwrap();

        // Output amount: exact match with on-chain result
        let expected_eth_out = BigUint::from(2_912_504_376_202_664_754u128);
        assert_eq!(res.amount, expected_eth_out);

        // Post-state: verify oracle values unchanged and liquidity decreased
        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketpoolState>()
            .unwrap();
        assert_eq!(new_state.total_eth, state.total_eth);
        assert_eq!(new_state.reth_supply, state.reth_supply);
        // Withdrawal should reduce available liquidity
        assert!(
            new_state.reth_contract_liquidity < state.reth_contract_liquidity ||
                new_state.deposit_contract_balance < state.deposit_contract_balance
        );
    }
}
