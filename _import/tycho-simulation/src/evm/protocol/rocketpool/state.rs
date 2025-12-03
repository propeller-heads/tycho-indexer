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
    safe_math::{safe_add_u256, safe_mul_u256, safe_sub_u256},
    u256_num::{biguint_to_u256, u256_to_biguint, u256_to_f64},
    utils::solidity_math::mul_div,
};

const DEPOSIT_FEE_BASE: u128 = 1_000_000_000_000_000_000; // 1e18

// Minipool deposit amounts in wei
const FULL_DEPOSIT_USER_AMOUNT: u128 = 16_000_000_000_000_000_000; // 16 ETH
const HALF_DEPOSIT_USER_AMOUNT: u128 = 16_000_000_000_000_000_000; // 16 ETH
const VARIABLE_DEPOSIT_AMOUNT: u128 = 31_000_000_000_000_000_000; // 31 ETH

// Queue capacity for wrap-around calculation (from RocketMinipoolQueue contract)
// capacity = 2^255 (max uint256 / 2)
fn queue_capacity() -> U256 {
    U256::from(1) << 255
}

#[derive(Clone, Debug, PartialEq)]
pub struct RocketPoolState {
    pub reth_supply: U256,
    pub total_eth: U256,
    /// ETH available in the deposit pool contract
    pub deposit_contract_balance: U256,
    /// ETH available in the rETH contract
    pub reth_contract_liquidity: U256,
    /// Deposit fee as %, scaled by DEPOSIT_FEE_BASE, such as 5000000000000000 represents 0.5% fee.
    pub deposit_fee: U256,
    pub deposits_enabled: bool,
    pub minimum_deposit: U256,
    pub maximum_deposit_pool_size: U256,
    /// Whether assigning deposits is enabled (allows using minipool queue capacity)
    pub deposit_assigning_enabled: bool,
    /// Maximum number of minipool assignments per deposit
    pub deposit_assign_maximum: U256,
    /// The base minimum number of minipools to try to assign per deposit
    pub deposit_assign_socialised_maximum: U256,
    /// Minipool queue indices for full deposits (legacy)
    pub queue_full_start: U256,
    pub queue_full_end: U256,
    /// Minipool queue indices for half deposits (legacy)
    pub queue_half_start: U256,
    pub queue_half_end: U256,
    /// Minipool queue indices for variable deposits
    pub queue_variable_start: U256,
    pub queue_variable_end: U256,
}

impl RocketPoolState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reth_supply: U256,
        total_eth: U256,
        deposit_contract_balance: U256,
        reth_contract_liquidity: U256,
        deposit_fee: U256,
        deposits_enabled: bool,
        minimum_deposit: U256,
        maximum_deposit_pool_size: U256,
        deposit_assigning_enabled: bool,
        deposit_assign_maximum: U256,
        deposit_assign_socialised_maximum: U256,
        queue_full_start: U256,
        queue_full_end: U256,
        queue_half_start: U256,
        queue_half_end: U256,
        queue_variable_start: U256,
        queue_variable_end: U256,
    ) -> Self {
        Self {
            reth_supply,
            total_eth,
            deposit_contract_balance,
            reth_contract_liquidity,
            deposit_fee,
            deposits_enabled,
            minimum_deposit,
            maximum_deposit_pool_size,
            deposit_assigning_enabled,
            deposit_assign_maximum,
            deposit_assign_socialised_maximum,
            queue_full_start,
            queue_full_end,
            queue_half_start,
            queue_half_end,
            queue_variable_start,
            queue_variable_end,
        }
    }

    /// Calculates rETH amount out for a given ETH deposit amount.
    fn get_reth_value(&self, eth_amount: U256) -> Result<U256, SimulationError> {
        // fee = ethIn * deposit_fee / DEPOSIT_FEE_BASE
        let fee = mul_div(eth_amount, self.deposit_fee, U256::from(DEPOSIT_FEE_BASE))?;
        let net_eth = safe_sub_u256(eth_amount, fee)?;

        // rethOut = netEth * rethSupply / totalEth
        mul_div(net_eth, self.reth_supply, self.total_eth)
    }

    /// Calculates ETH amount out for a given rETH burn amount.
    fn get_eth_value(&self, reth_amount: U256) -> Result<U256, SimulationError> {
        // ethOut = rethIn * totalEth / rethSupply
        mul_div(reth_amount, self.total_eth, self.reth_supply)
    }

    fn is_depositing_eth(token_in: &Bytes) -> bool {
        token_in.as_ref() == ETH_ADDRESS
    }

    fn assert_deposits_enabled(&self) -> Result<(), SimulationError> {
        if !self.deposits_enabled {
            Err(SimulationError::RecoverableError(
                "Deposits are currently disabled in RocketPool".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Calculates the length of a queue given its start and end indices.
    /// Handles wrap-around when end < start.
    fn get_queue_length(start: U256, end: U256) -> U256 {
        if end < start {
            // Wrap-around case: end = end + capacity
            end + queue_capacity() - start
        } else {
            end - start
        }
    }

    /// Calculates the total effective capacity of the minipool queues.
    ///
    /// Formula from RocketMinipoolQueue.getEffectiveCapacity():
    /// full_queue_length * FULL_DEPOSIT_USER_AMOUNT
    /// + half_queue_length * HALF_DEPOSIT_USER_AMOUNT
    /// + variable_queue_length * VARIABLE_DEPOSIT_AMOUNT
    fn get_effective_capacity(&self) -> Result<U256, SimulationError> {
        let full_length = Self::get_queue_length(self.queue_full_start, self.queue_full_end);
        let half_length = Self::get_queue_length(self.queue_half_start, self.queue_half_end);
        let variable_length =
            Self::get_queue_length(self.queue_variable_start, self.queue_variable_end);

        let full_capacity = safe_mul_u256(full_length, U256::from(FULL_DEPOSIT_USER_AMOUNT))?;
        let half_capacity = safe_mul_u256(half_length, U256::from(HALF_DEPOSIT_USER_AMOUNT))?;
        let variable_capacity =
            safe_mul_u256(variable_length, U256::from(VARIABLE_DEPOSIT_AMOUNT))?;

        safe_add_u256(safe_add_u256(full_capacity, half_capacity)?, variable_capacity)
    }

    /// Returns the maximum deposit capacity considering both the base pool size
    /// and the minipool queue effective capacity (if deposit_assigning_enabled).
    fn get_max_deposit_capacity(&self) -> Result<U256, SimulationError> {
        if self.deposit_assigning_enabled {
            let effective_capacity = self.get_effective_capacity()?;
            safe_add_u256(self.maximum_deposit_pool_size, effective_capacity)
        } else {
            Ok(self.maximum_deposit_pool_size)
        }
    }

    /// Returns the excess balance available for withdrawals from the deposit pool.
    ///
    /// Formula from RocketDepositPool.getExcessBalance():
    /// if minipoolCapacity >= balance: return 0
    /// else: return balance - minipoolCapacity
    fn get_deposit_pool_excess_balance(&self) -> Result<U256, SimulationError> {
        let minipool_capacity = self.get_effective_capacity()?;
        if minipool_capacity >= self.deposit_contract_balance {
            Ok(U256::ZERO)
        } else {
            safe_sub_u256(self.deposit_contract_balance, minipool_capacity)
        }
    }

    /// Returns total available liquidity for withdrawals.
    /// This is the sum of reth_contract_liquidity and the deposit pool excess balance.
    fn get_total_available_for_withdrawal(&self) -> Result<U256, SimulationError> {
        let deposit_pool_excess = self.get_deposit_pool_excess_balance()?;
        safe_add_u256(self.reth_contract_liquidity, deposit_pool_excess)
    }

    /// Returns true if there are any legacy minipools in the queue (full or half queues non-empty).
    fn contains_legacy(&self) -> bool {
        let full_length = Self::get_queue_length(self.queue_full_start, self.queue_full_end);
        let half_length = Self::get_queue_length(self.queue_half_start, self.queue_half_end);
        full_length + half_length > U256::ZERO
    }

    /// Calculates the number of minipools to dequeue and the resulting ETH to assign given a
    /// deposit. Returns (minipools_dequeued, eth_assigned) or panics for legacy queue.
    ///
    /// This method assumes deposit has already been added to deposit_contract_balance.
    ///
    /// Logic from _assignDepositsNew:
    /// - scalingCount = deposit_amount / variableDepositAmount
    /// - totalEthCount = new_balance / variableDepositAmount
    /// - assignments = socialisedMax + scalingCount
    /// - assignments = min(assignments, totalEthCount, maxAssignments, variable_queue_length)
    /// - eth_assigned = assignments * variableDepositAmount
    fn calculate_assign_deposits(
        &self,
        deposit_amount: U256,
    ) -> Result<(U256, U256), SimulationError> {
        if !self.deposit_assigning_enabled {
            return Ok((U256::ZERO, U256::ZERO));
        }

        // The simulation does not support legacy minipool queues (full/half) assignments.
        // This decision is made to limit unnecessary complexity in the simulation logic as
        // since the V1.2 upgrade, minipools can no longer be added to legacy queues,
        // and at the time of the upgrade, legacy queues were already empty.
        if self.contains_legacy() {
            return Err(SimulationError::FatalError(
                "Legacy minipool queue (full/half) contains items - not implemented".to_string(),
            ));
        }

        let variable_deposit = U256::from(VARIABLE_DEPOSIT_AMOUNT);

        // Calculate assignments
        let scaling_count = deposit_amount / variable_deposit;
        let total_eth_count = self.deposit_contract_balance / variable_deposit;
        let mut assignments = self.deposit_assign_socialised_maximum + scaling_count;

        // Cap at total ETH available
        if assignments > total_eth_count {
            assignments = total_eth_count;
        }

        // Cap at max assignments
        if assignments > self.deposit_assign_maximum {
            assignments = self.deposit_assign_maximum;
        }

        // Cap at available queue length
        let variable_queue_length =
            Self::get_queue_length(self.queue_variable_start, self.queue_variable_end);
        if assignments > variable_queue_length {
            assignments = variable_queue_length;
        }

        let eth_assigned = safe_mul_u256(assignments, variable_deposit)?;

        Ok((assignments, eth_assigned))
    }
}

impl ProtocolSim for RocketPoolState {
    fn fee(&self) -> f64 {
        unimplemented!("RocketPool has asymmetric fees; use spot_price or get_amount_out instead")
    }

    fn spot_price(&self, base: &Token, _quote: &Token) -> Result<f64, SimulationError> {
        let is_depositing_eth = RocketPoolState::is_depositing_eth(&base.address);
        // As the protocol has no slippage, we can use a fixed amount for spot price calculation
        let amount = U256::from(1e18);

        let res = if is_depositing_eth {
            self.assert_deposits_enabled()?;
            self.get_reth_value(amount)?
        } else {
            self.get_eth_value(amount)?
        };

        let res = u256_to_f64(res)? / 1e18;

        Ok(res)
    }

    #[allow(clippy::collapsible_else_if)]
    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        _token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        let amount_in = biguint_to_u256(&amount_in);
        let is_depositing_eth = RocketPoolState::is_depositing_eth(&token_in.address);

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
        // Note: total_eth and reth_supply are not updated as they are managed by an oracle.
        if is_depositing_eth {
            new_state.deposit_contract_balance =
                safe_add_u256(new_state.deposit_contract_balance, amount_in)?;

            // Process assign deposits - dequeue minipools and withdraw ETH from vault
            let (assignments, eth_assigned) = new_state.calculate_assign_deposits(amount_in)?;
            if assignments > U256::ZERO {
                new_state.deposit_contract_balance =
                    safe_sub_u256(new_state.deposit_contract_balance, eth_assigned)?;
                new_state.queue_variable_start =
                    safe_add_u256(new_state.queue_variable_start, assignments)?;
            }
        } else {
            if amount_out <= new_state.reth_contract_liquidity {
                // If there is sufficient liquidity in rETH contract, withdraw directly
                new_state.reth_contract_liquidity =
                    safe_sub_u256(new_state.reth_contract_liquidity, amount_out)?;
            } else {
                // Otherwise, use liquidity from the deposit pool contract
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
            // ETH -> rETH: max sell = maxDepositPoolSize +
            // + effectiveCapacity (if assignDepositsEnabled) - deposit_contract_balance
            let max_capacity = self.get_max_deposit_capacity()?;
            let max_eth_sell = safe_sub_u256(max_capacity, self.deposit_contract_balance)?;
            let max_reth_buy = self.get_reth_value(max_eth_sell)?;
            Ok((u256_to_biguint(max_eth_sell), u256_to_biguint(max_reth_buy)))
        } else {
            // rETH -> ETH: max buy = total available for withdrawal
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
        self.minimum_deposit = delta
            .updated_attributes
            .get("minimum_deposit")
            .map_or(self.minimum_deposit, U256::from_bytes);
        self.maximum_deposit_pool_size = delta
            .updated_attributes
            .get("maximum_deposit_pool_size")
            .map_or(self.maximum_deposit_pool_size, U256::from_bytes);
        self.deposit_assign_maximum = delta
            .updated_attributes
            .get("deposit_assign_maximum")
            .map_or(self.deposit_assign_maximum, U256::from_bytes);
        self.deposit_assign_socialised_maximum = delta
            .updated_attributes
            .get("deposit_assign_socialised_maximum")
            .map_or(self.deposit_assign_socialised_maximum, U256::from_bytes);

        self.queue_full_start = delta
            .updated_attributes
            .get("queue_full_start")
            .map_or(self.queue_full_start, U256::from_bytes);
        self.queue_full_end = delta
            .updated_attributes
            .get("queue_full_end")
            .map_or(self.queue_full_end, U256::from_bytes);
        self.queue_half_start = delta
            .updated_attributes
            .get("queue_half_start")
            .map_or(self.queue_half_start, U256::from_bytes);
        self.queue_half_end = delta
            .updated_attributes
            .get("queue_half_end")
            .map_or(self.queue_half_end, U256::from_bytes);
        self.queue_variable_start = delta
            .updated_attributes
            .get("queue_variable_start")
            .map_or(self.queue_variable_start, U256::from_bytes);
        self.queue_variable_end = delta
            .updated_attributes
            .get("queue_variable_end")
            .map_or(self.queue_variable_end, U256::from_bytes);

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
    use num_traits::ToPrimitive;
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

    /// Helper function to create a RocketPoolState with easy-to-compute defaults for testing
    /// Mutate fields for specific tests.
    /// - Exchange rate: 1 rETH = 2 ETH (100 rETH backed by 200 ETH)
    /// - Deposit fee: 40%
    /// - Deposit contract balance: 50 ETH
    /// - rETH contract liquidity: 0 ETH
    /// - Max pool size: 1000 ETH
    /// - Assign deposits enabled: false
    fn create_state() -> RocketPoolState {
        RocketPoolState::new(
            U256::from(100e18),                     // reth_supply: 100 rETH
            U256::from(200e18),                     // total_eth: 200 ETH (1 rETH = 2 ETH)
            U256::from(50e18),                      // deposit_contract_balance: 50 ETH
            U256::ZERO,                             // reth_contract_liquidity: 0 ETH
            U256::from(400_000_000_000_000_000u64), // deposit_fee: 40% (0.4e18)
            true,                                   // deposits_enabled
            U256::ZERO,                             // minimum_deposit
            U256::from(1000e18),                    // maximum_deposit_pool_size: 1000 ETH
            false,                                  // deposit_assigning_enabled
            U256::ZERO,                             // deposit_assign_maximum
            U256::ZERO,                             // deposit_assign_socialised_maximum
            U256::ZERO,                             // queue_full_start
            U256::ZERO,                             // queue_full_end
            U256::ZERO,                             // queue_half_start
            U256::ZERO,                             // queue_half_end
            U256::ZERO,                             // queue_variable_start
            U256::ZERO,                             // queue_variable_end
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

    // ============ Queue Length Tests ============

    #[test]
    fn test_queue_length_normal() {
        let length = RocketPoolState::get_queue_length(U256::from(10), U256::from(15));
        assert_eq!(length, U256::from(5));
    }

    #[test]
    fn test_queue_length_empty() {
        let length = RocketPoolState::get_queue_length(U256::from(10), U256::from(10));
        assert_eq!(length, U256::ZERO);
    }

    #[test]
    fn test_queue_length_wrap_around() {
        let capacity = queue_capacity();
        let start = capacity - U256::from(5);
        let end = U256::from(3);
        let length = RocketPoolState::get_queue_length(start, end);
        // 3 + 2^255 - (2^255 - 5) = 8
        assert_eq!(length, U256::from(8));
    }

    // ============ Effective Capacity Tests ============

    #[test]
    fn test_effective_capacity_empty() {
        let state = create_state();
        assert_eq!(state.get_effective_capacity().unwrap(), U256::ZERO);
    }

    #[test]
    fn test_effective_capacity_full_queue() {
        let mut state = create_state();
        state.queue_full_end = U256::from(2); // 2 * 16 ETH = 32 ETH
        assert_eq!(state.get_effective_capacity().unwrap(), U256::from(32e18));
    }

    #[test]
    fn test_effective_capacity_half_queue() {
        let mut state = create_state();
        state.queue_half_end = U256::from(3); // 3 * 16 ETH = 48 ETH
        assert_eq!(state.get_effective_capacity().unwrap(), U256::from(48e18));
    }

    #[test]
    fn test_effective_capacity_variable_queue() {
        let mut state = create_state();
        state.queue_variable_end = U256::from(2); // 2 * 31 ETH = 62 ETH
        assert_eq!(state.get_effective_capacity().unwrap(), U256::from(62e18));
    }

    #[test]
    fn test_effective_capacity_combined() {
        let mut state = create_state();
        state.queue_full_end = U256::from(2); // 32 ETH
        state.queue_half_end = U256::from(3); // 48 ETH
        state.queue_variable_end = U256::from(1); // 31 ETH
                                                  // Total: 111 ETH
        assert_eq!(state.get_effective_capacity().unwrap(), U256::from(111e18));
    }

    // ============ Max Deposit Capacity Tests ============

    #[test]
    fn test_max_capacity_assign_disabled() {
        let state = create_state();
        let max = state
            .get_max_deposit_capacity()
            .unwrap();
        assert_eq!(max, U256::from(1000e18));
    }

    #[test]
    fn test_max_capacity_assign_enabled_empty_queue() {
        let mut state = create_state();
        state.deposit_assigning_enabled = true;
        let max = state
            .get_max_deposit_capacity()
            .unwrap();
        assert_eq!(max, U256::from(1000e18));
    }

    #[test]
    fn test_max_capacity_assign_enabled_with_queue() {
        let mut state = create_state();
        state.deposit_assigning_enabled = true;
        state.queue_variable_end = U256::from(10); // 310 ETH extra
        let max = state
            .get_max_deposit_capacity()
            .unwrap();
        // 1000 + 310 = 1310 ETH
        assert_eq!(max, U256::from(1310e18));
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
            component_id: "RocketPool".to_owned(),
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
    fn test_delta_transition_queue_fields() {
        let mut state = create_state();

        let attributes: HashMap<String, Bytes> = [
            ("deposit_assigning_enabled", U256::from(1u64)),
            ("queue_variable_end", U256::from(5u64)),
            ("queue_full_end", U256::from(3u64)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), Bytes::from(v.to_be_bytes_vec())))
        .collect();

        let delta = ProtocolStateDelta {
            component_id: "RocketPool".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(),
        };

        state
            .delta_transition(delta, &HashMap::new(), &Balances::default())
            .unwrap();

        assert!(state.deposit_assigning_enabled);
        assert_eq!(state.queue_variable_end, U256::from(5u64));
        assert_eq!(state.queue_full_end, U256::from(3u64));
    }

    // ============ Spot Price Tests ============

    #[test]
    fn test_spot_price_deposit() {
        let state = create_state();
        // ETH -> rETH: (1 - 0.4 fee) * 100/200 = 0.6 * 0.5 = 0.3
        let price = state
            .spot_price(&eth_token(), &reth_token())
            .unwrap();
        assert_ulps_eq!(price, 0.3);
    }

    #[test]
    fn test_spot_price_withdraw() {
        let state = create_state();
        // rETH -> ETH: 200/100 = 2.0
        let price = state
            .spot_price(&reth_token(), &eth_token())
            .unwrap();
        assert_ulps_eq!(price, 2.0);
    }

    /// Creates RocketPoolState from real on-chain data at block 23929406.
    fn create_state_at_block_23929406() -> RocketPoolState {
        RocketPoolState::new(
            U256::from_str_radix("4df2cf698437b72b8937", 16).unwrap(), // reth_supply
            U256::from_str_radix("59c8a9cb90db4a5aa85e", 16).unwrap(), // total_eth
            U256::from_str_radix("11e245d1725f73941", 16).unwrap(),    // deposit_contract_balance
            U256::from_str_radix("b6e43509", 16).unwrap(),             // reth_contract_liquidity
            U256::from_str_radix("1c6bf52634000", 16).unwrap(),        // deposit_fee (0.05%)
            true,                                                      // deposits_enabled
            U256::from_str_radix("2386f26fc10000", 16).unwrap(),       // minimum_deposit
            U256::from_str_radix("3cfc82e37e9a7400000", 16).unwrap(),  // maximum_deposit_pool_size
            true,                                                      // deposit_assigning_enabled
            U256::from_str_radix("5a", 16).unwrap(),                   // deposit_assign_maximum
            U256::from_str_radix("2", 16).unwrap(), // deposit_assign_socialised_maximum
            U256::from_str_radix("1bf", 16).unwrap(), // queue_full_start (empty)
            U256::from_str_radix("1bf", 16).unwrap(), // queue_full_end
            U256::from_str_radix("3533", 16).unwrap(), // queue_half_start (empty)
            U256::from_str_radix("3533", 16).unwrap(), // queue_half_end
            U256::from_str_radix("6d45", 16).unwrap(), // queue_variable_start
            U256::from_str_radix("6de3", 16).unwrap(), // queue_variable_end
        )
    }

    /// Test spot price against real getEthValue(1e18) result at block 23929406
    /// rETH -> ETH: 1151835724202334991 wei per rETH
    #[test]
    fn test_live_spot_price_reth_to_eth_23929406() {
        let state = create_state_at_block_23929406();

        let price = state
            .spot_price(&reth_token(), &eth_token())
            .unwrap();

        // Expected: 1151835724202334991 / 1e18 = 1.151835724202334991
        let expected = 1.151835724202335;
        assert_ulps_eq!(price, expected, max_ulps = 10);
    }

    /// Test spot price against real getRethValue(1e18) result at block 23929406
    /// ETH -> rETH: 868179358382477931 wei per ETH
    #[test]
    fn test_live_spot_price_eth_to_reth_23929406() {
        let state = create_state_at_block_23929406();

        // Calculate expected price considering deposit fee
        let price = state
            .spot_price(&eth_token(), &reth_token())
            .unwrap();

        // Expected is calculated without fee: 868179358382477931 / 1e18 = 0.868179358382477931
        let expected_without_fee = 0.868179358382478;
        let fee = state.deposit_fee.to_f64().unwrap() / DEPOSIT_FEE_BASE as f64;
        let expected = expected_without_fee * (1.0 - fee);

        assert_ulps_eq!(price, expected, max_ulps = 10);
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
    fn test_limits_with_extended_capacity() {
        let mut state = create_state();
        state.maximum_deposit_pool_size = U256::from(100e18);
        state.deposit_assigning_enabled = true;
        state.queue_variable_end = U256::from(2); // 62 ETH extra

        let (max_sell, _) = state
            .get_limits(eth_token().address, reth_token().address)
            .unwrap();

        // max_capacity = 100 + 62 = 162 ETH
        // max_sell = 162 - 50 = 112 ETH
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

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketPoolState>()
            .unwrap();
        // liquidity: 50 + 10 = 60
        assert_eq!(new_state.deposit_contract_balance, U256::from(60e18));
        // total_eth and reth_supply unchanged (managed by oracle)
        assert_eq!(new_state.total_eth, U256::from(200e18));
        assert_eq!(new_state.reth_supply, U256::from(100e18));
    }

    #[test]
    fn test_deposit_within_extended_capacity() {
        let mut state = create_state();
        state.deposit_contract_balance = U256::from(990e18);
        state.maximum_deposit_pool_size = U256::from(1000e18);
        state.deposit_assigning_enabled = true;
        state.queue_variable_end = U256::from(1); // 31 ETH extra

        // Deposit 20 ETH: 990 + 20 = 1010 > 1000 base, but <= 1031 extended
        // fee = 20 * 0.4 = 8, net = 12 → 12*100/200 = 6 rETH
        let res = state
            .get_amount_out(
                BigUint::from(20_000_000_000_000_000_000u128),
                &eth_token(),
                &reth_token(),
            )
            .unwrap();

        assert_eq!(res.amount, BigUint::from(6_000_000_000_000_000_000u128));

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketPoolState>()
            .unwrap();
        // liquidity: 990 + 20 = 1010
        assert_eq!(new_state.deposit_contract_balance, U256::from(1010e18));
        // total_eth and reth_supply unchanged (managed by oracle)
        assert_eq!(new_state.total_eth, U256::from(200e18));
        assert_eq!(new_state.reth_supply, U256::from(100e18));
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
            .downcast_ref::<RocketPoolState>()
            .unwrap();
        // liquidity: 50 - 20 = 30
        assert_eq!(new_state.deposit_contract_balance, U256::from(30e18));
        // total_eth and reth_supply unchanged (managed by oracle)
        assert_eq!(new_state.total_eth, U256::from(200e18));
        assert_eq!(new_state.reth_supply, U256::from(100e18));
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
        state.minimum_deposit = U256::from(100u64);

        let res = state.get_amount_out(BigUint::from(50u64), &eth_token(), &reth_token());
        assert!(matches!(res, Err(SimulationError::InvalidInput(_, _))));
    }

    #[test]
    fn test_deposit_exceeds_max_pool() {
        let mut state = create_state();
        state.maximum_deposit_pool_size = U256::from(60e18); // Only 10 ETH room

        let res = state.get_amount_out(
            BigUint::from(20_000_000_000_000_000_000u128),
            &eth_token(),
            &reth_token(),
        );
        assert!(matches!(res, Err(SimulationError::InvalidInput(_, _))));
    }

    #[test]
    fn test_deposit_queue_ignored_when_disabled() {
        let mut state = create_state();
        state.deposit_contract_balance = U256::from(990e18);
        state.maximum_deposit_pool_size = U256::from(1000e18);
        state.deposit_assigning_enabled = false;
        state.queue_variable_end = U256::from(10); // Would add 310 ETH if enabled

        // Deposit 20 ETH: 990 + 20 = 1010 > 1000 (queue ignored)
        let res = state.get_amount_out(
            BigUint::from(20_000_000_000_000_000_000u128),
            &eth_token(),
            &reth_token(),
        );
        assert!(matches!(res, Err(SimulationError::InvalidInput(_, _))));
    }

    #[test]
    fn test_deposit_exceeds_extended_capacity() {
        let mut state = create_state();
        state.deposit_contract_balance = U256::from(990e18);
        state.maximum_deposit_pool_size = U256::from(1000e18);
        state.deposit_assigning_enabled = true;
        state.queue_variable_end = U256::from(1); // 31 ETH extra, max = 1031

        // Deposit 50 ETH: 990 + 50 = 1040 > 1031
        let res = state.get_amount_out(
            BigUint::from(50_000_000_000_000_000_000u128),
            &eth_token(),
            &reth_token(),
        );
        assert!(matches!(res, Err(SimulationError::InvalidInput(_, _))));
    }

    #[test]
    fn test_withdrawal_insufficient_liquidity() {
        let state = create_state(); // 50 ETH liquidity, withdraw needs 20 ETH per 10 rETH

        // Try to withdraw 30 rETH = 60 ETH > 50 liquidity
        let res = state.get_amount_out(
            BigUint::from(30_000_000_000_000_000_000u128),
            &reth_token(),
            &eth_token(),
        );
        assert!(matches!(res, Err(SimulationError::RecoverableError(_))));
    }

    #[test]
    fn test_withdrawal_limited_by_minipool_queue() {
        let mut state = create_state();
        state.deposit_contract_balance = U256::from(100e18);
        // Queue has 2 variable minipools = 62 ETH capacity
        state.queue_variable_end = U256::from(2);
        // excess_balance = 100 - 62 = 38 ETH

        // Try to withdraw 20 rETH = 40 ETH > 38 excess balance (but < 100 liquidity)
        let res = state.get_amount_out(
            BigUint::from(20_000_000_000_000_000_000u128),
            &reth_token(),
            &eth_token(),
        );
        assert!(matches!(res, Err(SimulationError::RecoverableError(_))));

        // Withdraw 15 rETH = 30 ETH <= 38 excess balance should work
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
    fn test_withdrawal_zero_excess_balance() {
        let mut state = create_state();
        state.deposit_contract_balance = U256::from(62e18);
        // Queue has 2 variable minipools = 62 ETH capacity
        state.queue_variable_end = U256::from(2);
        // excess_balance = 62 - 62 = 0 ETH

        // Any withdrawal should fail
        let res = state.get_amount_out(
            BigUint::from(1_000_000_000_000_000_000u128),
            &reth_token(),
            &eth_token(),
        );
        assert!(matches!(res, Err(SimulationError::RecoverableError(_))));
    }

    #[test]
    fn test_withdrawal_uses_both_pools() {
        let mut state = create_state();
        state.reth_contract_liquidity = U256::from(10e18);
        state.deposit_contract_balance = U256::from(50e18);
        // No queue, so full 50 ETH is excess balance
        // Total available: 10 + 50 = 60 ETH

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
            .downcast_ref::<RocketPoolState>()
            .unwrap();

        // reth_contract_liquidity drained to 0
        assert_eq!(new_state.reth_contract_liquidity, U256::ZERO);
        // deposit_contract_balance: 50 - (30 - 10) = 30 ETH
        assert_eq!(new_state.deposit_contract_balance, U256::from(30e18));
    }

    #[test]
    fn test_limits_withdrawal_with_queue() {
        let mut state = create_state();
        state.deposit_contract_balance = U256::from(100e18);
        // Queue has 2 variable minipools = 62 ETH capacity
        state.queue_variable_end = U256::from(2);

        let (max_sell, max_buy) = state
            .get_limits(reth_token().address, eth_token().address)
            .unwrap();

        // max_buy = excess_balance = 100 - 62 = 38 ETH
        assert_eq!(max_buy, BigUint::from(38_000_000_000_000_000_000u128));
        // max_sell = 38 * 100/200 = 19 rETH
        assert_eq!(max_sell, BigUint::from(19_000_000_000_000_000_000u128));
    }

    // ============ Assign Deposits Tests ============

    #[test]
    fn test_assign_deposits_dequeues_minipools() {
        let mut state = create_state();
        state.deposit_contract_balance = U256::from(100e18);
        state.deposit_assigning_enabled = true;
        state.deposit_assign_maximum = U256::from(10u64);
        state.deposit_assign_socialised_maximum = U256::from(2u64);
        state.queue_variable_end = U256::from(5); // 5 minipools in queue

        // Deposit 62 ETH (2 * 31 ETH)
        // scalingCount = 62 / 31 = 2
        // totalEthCount = (100 + 62) / 31 = 5
        // assignments = socialised(2) + scaling(2) = 4
        // capped at min(4, 5, 10, 5) = 4
        // eth_assigned = 4 * 31 = 124 ETH
        // new_liquidity = 100 + 62 - 124 = 38 ETH
        let res = state
            .get_amount_out(
                BigUint::from(62_000_000_000_000_000_000u128),
                &eth_token(),
                &reth_token(),
            )
            .unwrap();

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketPoolState>()
            .unwrap();

        assert_eq!(new_state.deposit_contract_balance, U256::from(38e18));
        assert_eq!(new_state.queue_variable_start, U256::from(4u64));
    }

    #[test]
    fn test_assign_deposits_capped_by_queue_length() {
        let mut state = create_state();
        state.deposit_contract_balance = U256::from(100e18);
        state.deposit_assigning_enabled = true;
        state.deposit_assign_maximum = U256::from(10u64);
        state.deposit_assign_socialised_maximum = U256::from(5u64);
        state.queue_variable_end = U256::from(2); // Only 2 minipools in queue

        // Deposit 62 ETH
        // assignments = 5 + 2 = 7, but capped at queue length of 2
        // eth_assigned = 2 * 31 = 62 ETH
        // new_liquidity = 100 + 62 - 62 = 100 ETH
        let res = state
            .get_amount_out(
                BigUint::from(62_000_000_000_000_000_000u128),
                &eth_token(),
                &reth_token(),
            )
            .unwrap();

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketPoolState>()
            .unwrap();

        assert_eq!(new_state.deposit_contract_balance, U256::from(100e18));
        assert_eq!(new_state.queue_variable_start, U256::from(2u64));
    }

    #[test]
    fn test_assign_deposits_capped_by_max_assignments() {
        let mut state = create_state();
        state.deposit_contract_balance = U256::from(100e18);
        state.deposit_assigning_enabled = true;
        state.deposit_assign_maximum = U256::from(1u64); // Only 1 assignment allowed
        state.deposit_assign_socialised_maximum = U256::from(5u64);
        state.queue_variable_end = U256::from(10);

        // Deposit 62 ETH
        // assignments = 5 + 2 = 7, but capped at max of 1
        // eth_assigned = 1 * 31 = 31 ETH
        // new_liquidity = 100 + 62 - 31 = 131 ETH
        let res = state
            .get_amount_out(
                BigUint::from(62_000_000_000_000_000_000u128),
                &eth_token(),
                &reth_token(),
            )
            .unwrap();

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketPoolState>()
            .unwrap();

        assert_eq!(new_state.deposit_contract_balance, U256::from(131e18));
        assert_eq!(new_state.queue_variable_start, U256::from(1u64));
    }

    #[test]
    fn test_assign_deposits_capped_by_total_eth() {
        let mut state = create_state();
        state.deposit_contract_balance = U256::from(10e18); // Low liquidity
        state.deposit_assigning_enabled = true;
        state.deposit_assign_maximum = U256::from(10u64);
        state.deposit_assign_socialised_maximum = U256::from(5u64);
        state.queue_variable_end = U256::from(10);

        // Deposit 31 ETH
        // totalEthCount = (10 + 31) / 31 = 1
        // assignments = 5 + 1 = 6, but capped at totalEthCount of 1
        // eth_assigned = 1 * 31 = 31 ETH
        // new_liquidity = 10 + 31 - 31 = 10 ETH
        let res = state
            .get_amount_out(
                BigUint::from(31_000_000_000_000_000_000u128),
                &eth_token(),
                &reth_token(),
            )
            .unwrap();

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketPoolState>()
            .unwrap();

        assert_eq!(new_state.deposit_contract_balance, U256::from(10e18));
        assert_eq!(new_state.queue_variable_start, U256::from(1u64));
    }

    #[test]
    fn test_assign_deposits_legacy_queue_error() {
        let mut state = create_state();
        state.deposit_assigning_enabled = true;
        state.queue_full_end = U256::from(1); // Legacy queue has items

        let res = state.get_amount_out(
            BigUint::from(10_000_000_000_000_000_000u128),
            &eth_token(),
            &reth_token(),
        );

        assert!(matches!(res, Err(SimulationError::FatalError(_))));
    }

    #[test]
    fn test_assign_deposits_empty_queue_no_change() {
        let mut state = create_state();
        state.deposit_assigning_enabled = true;
        state.deposit_assign_maximum = U256::from(10u64);
        state.deposit_assign_socialised_maximum = U256::from(2u64);
        // queue_variable_end = 0, so queue is empty

        // Deposit 10 ETH - no minipools to dequeue
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
            .downcast_ref::<RocketPoolState>()
            .unwrap();

        // liquidity: 50 + 10 = 60 (no withdrawal)
        assert_eq!(new_state.deposit_contract_balance, U256::from(60e18));
        assert_eq!(new_state.queue_variable_start, U256::ZERO);
    }

    // ============ Live Transaction Tests ============

    /// Test against real transaction deposit on RocketPool
    /// 0x6213b6c235c52d2132711c18a1c66934832722fd71c098e843bc792ecdbd11b3 where user deposited
    /// exactly 4.5 ETH and received 3.905847020555141679 rETH 1 minipool was assigned (31 ETH
    /// withdrawn from pool)
    #[test]
    fn test_live_deposit_tx_6213b6c2() {
        let state = RocketPoolState::new(
            U256::from_str_radix("4ec08ba071647b927594", 16).unwrap(), // reth_supply
            U256::from_str_radix("5aafbb189fbbc1704662", 16).unwrap(), // total_eth
            U256::from_str_radix("17a651238b0dbf892", 16).unwrap(),    // deposit_contract_balance
            U256::from(781003199),                                     // reth_contract_liquidity
            U256::from_str_radix("1c6bf52634000", 16).unwrap(),        // deposit_fee (0.05%)
            true,                                                      // deposits_enabled
            U256::from_str_radix("2386f26fc10000", 16).unwrap(),       // minimum_deposit
            U256::from_str_radix("3cfc82e37e9a7400000", 16).unwrap(),  // maximum_deposit_pool_size
            true,                                                      // deposit_assigning_enabled
            U256::from_str_radix("5a", 16).unwrap(),                   // deposit_assign_maximum
            U256::from_str_radix("2", 16).unwrap(), // deposit_assign_socialised_maximum
            U256::from_str_radix("1bf", 16).unwrap(), // queue_full_start (empty: start == end)
            U256::from_str_radix("1bf", 16).unwrap(), // queue_full_end
            U256::from_str_radix("3533", 16).unwrap(), // queue_half_start (empty: start == end)
            U256::from_str_radix("3533", 16).unwrap(), // queue_half_end
            U256::from_str_radix("6d43", 16).unwrap(), // queue_variable_start
            U256::from_str_radix("6dde", 16).unwrap(), // queue_variable_end
        );

        // User deposited exactly 4.5 ETH
        let deposit_amount = BigUint::from(4_500_000_000_000_000_000u128);

        let res = state
            .get_amount_out(deposit_amount, &eth_token(), &reth_token())
            .unwrap();

        println!("calculated rETH out: {}", res.amount);
        let expected_reth_out = BigUint::from(3_905_847_020_555_141_679u128);
        assert_eq!(res.amount, expected_reth_out);

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketPoolState>()
            .unwrap();

        // Expected final balance to reduce by 31 ETH (1 minipool assigned)
        let expected_balance = U256::from_str_radix("0aa2289fdd01f892", 16).unwrap();
        assert_eq!(new_state.deposit_contract_balance, expected_balance);

        // Expected queue_variable_start to advance by 1 (1 minipool assigned)
        let expected_queue_start = U256::from_str_radix("6d44", 16).unwrap();
        assert_eq!(new_state.queue_variable_start, expected_queue_start);

        // Other state variables unchanged
        assert_eq!(new_state.total_eth, state.total_eth);
        assert_eq!(new_state.reth_supply, state.reth_supply);
        assert_eq!(new_state.deposit_fee, state.deposit_fee);
        assert_eq!(new_state.deposits_enabled, state.deposits_enabled);
        assert_eq!(new_state.minimum_deposit, state.minimum_deposit);
        assert_eq!(new_state.maximum_deposit_pool_size, state.maximum_deposit_pool_size);
        assert_eq!(new_state.deposit_assigning_enabled, state.deposit_assigning_enabled);
        assert_eq!(new_state.deposit_assign_maximum, state.deposit_assign_maximum);
        assert_eq!(
            new_state.deposit_assign_socialised_maximum,
            state.deposit_assign_socialised_maximum
        );
        assert_eq!(new_state.queue_full_start, state.queue_full_start);
        assert_eq!(new_state.queue_full_end, state.queue_full_end);
        assert_eq!(new_state.queue_half_start, state.queue_half_start);
        assert_eq!(new_state.queue_half_end, state.queue_half_end);
        assert_eq!(new_state.queue_variable_end, state.queue_variable_end);
    }

    /// Test against real withdrawal (burn) transaction on
    /// RocketPool0xf0f615f5dcf40d6ba1168da654a9ea8a0e855e489a34f4ffc3c7d2ad165f0bd6 where user
    /// burned 20.873689741238146923 rETH and received 24.000828571949999998 ETH
    #[test]
    fn test_live_withdraw_tx_block_23736567() {
        let state = RocketPoolState::new(
            U256::from_str_radix("516052628fbe875ffff0", 16).unwrap(), // reth_supply
            U256::from_str_radix("5d9143622860d8bdacea", 16).unwrap(), // total_eth
            U256::from_str_radix("1686dc9300da8004d", 16).unwrap(),    // deposit_contract_balance
            U256::from_str_radix("14d141273efab8a43", 16).unwrap(),    // reth_contract_liquidity
            U256::from_str_radix("1c6bf52634000", 16).unwrap(),        // deposit_fee (0.05%)
            true,                                                      // deposits_enabled
            U256::from_str_radix("2386f26fc10000", 16).unwrap(),       // minimum_deposit
            U256::from_str_radix("3cfc82e37e9a7400000", 16).unwrap(),  // maximum_deposit_pool_size
            true,                                                      // deposit_assigning_enabled
            U256::from_str_radix("5a", 16).unwrap(),                   // deposit_assign_maximum
            U256::from_str_radix("2", 16).unwrap(), // deposit_assign_socialised_maximum
            U256::from_str_radix("1bf", 16).unwrap(), // queue_full_start (empty)
            U256::from_str_radix("1bf", 16).unwrap(), // queue_full_end
            U256::from_str_radix("3533", 16).unwrap(), // queue_half_start (empty)
            U256::from_str_radix("3533", 16).unwrap(), // queue_half_end
            U256::from_str_radix("6d34", 16).unwrap(), // queue_variable_start
            U256::from_str_radix("6dd0", 16).unwrap(), // queue_variable_end
        );

        // User burned exactly 20873689741238146923 rETH
        let burn_amount = BigUint::from(20_873_689_741_238_146_923u128);

        let res = state
            .get_amount_out(burn_amount, &reth_token(), &eth_token())
            .unwrap();

        // Expected ETH out: 24000828571949999998 wei
        let expected_eth_out = BigUint::from(24_000_828_571_949_999_998u128);
        assert_eq!(res.amount, expected_eth_out);

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<RocketPoolState>()
            .unwrap();

        // Verify liquidity was updated correctly
        let expected_liquidity = U256::from_str_radix("74d8b62c5", 16).unwrap();
        assert_eq!(new_state.reth_contract_liquidity, expected_liquidity);

        // Other state variables unchanged
        assert_eq!(new_state.total_eth, state.total_eth);
        assert_eq!(new_state.reth_supply, state.reth_supply);
        assert_eq!(new_state.queue_variable_start, state.queue_variable_start);
        assert_eq!(new_state.queue_variable_end, state.queue_variable_end);
    }
}
