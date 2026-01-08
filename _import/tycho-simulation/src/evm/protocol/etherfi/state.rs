use std::collections::HashMap;

use alloy::primitives::U256;
use hex_literal::hex;
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

use crate::evm::protocol::{
    u256_num::{biguint_to_u256, u256_to_biguint, u256_to_f64},
    utils::solidity_math::mul_div,
};

pub const EETH_ADDRESS: [u8; 20] = hex!("35fA164735182de50811E8e2E824cFb9B6118ac2");
pub const WEETH_ADDRESS: [u8; 20] = hex!("Cd5fE23C85820F7B72D0926FC9b05b43E359b7ee");
pub const ETH_ADDRESS: [u8; 20] = hex!("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE");
pub const BASIS_POINT_SCALE: u64 = 10000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtherfiState {
    total_value_out_of_lp: U256,
    total_value_in_lp: U256,
    total_shares: U256,
    eth_amount_locked_for_withdrawl: U256,
    liquidity_pool_native_balance: U256,
    eth_redemption_info: RedemptionInfo,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RedemptionInfo {
    limit: BucketLimit,
    exit_fee_split_to_treasury_in_bps: u16,
    exit_fee_in_bps: u16,
    low_watermark_in_bps_of_tvl: u16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BucketLimit {
    // The maximum capacity of the bucket, in consumable units (eg. tokens)
    capacity: u64,
    // The remaining capacity in the bucket, that can be consumed
    remaining: u64,
    // The timestamp of the last time the bucket was refilled
    last_refill: u64,
    // The rate at which the bucket refills, in units per second
    refill_rate: u64,
}

impl EtherfiState {
    pub fn new(
        total_value_out_of_lp: U256,
        total_value_in_lp: U256,
        total_shares: U256,
        eth_amount_locked_for_withdrawl: U256,
        eth_redemption_info: RedemptionInfo,
        liquidity_pool_native_balance: U256,
    ) -> Self {
        EtherfiState {
            total_value_out_of_lp,
            total_value_in_lp,
            total_shares,
            eth_amount_locked_for_withdrawl,
            liquidity_pool_native_balance,
            eth_redemption_info,
        }
    }

    fn shares_for_amount(&self, amount: U256) -> Result<U256, SimulationError> {
        let total_pooled_ether = self.total_value_in_lp + self.total_value_out_of_lp;
        if total_pooled_ether == U256::ZERO {
            return Ok(U256::ZERO)
        }
        Ok(amount * self.total_shares / total_pooled_ether)
    }

    fn amount_for_share(&self, share: U256) -> Result<U256, SimulationError> {
        if self.total_shares == U256::ZERO {
            return Ok(U256::ZERO)
        }
        let total_pooled_ether = self.total_value_in_lp + self.total_value_out_of_lp;
        Ok(share * total_pooled_ether / self.total_shares)
    }
}

impl BucketLimit {
    pub(crate) fn from_u256(value: U256) -> Self {
        let mask = U256::from(u64::MAX);
        Self {
            capacity: (value & mask).to::<u64>(),
            remaining: ((value >> 64u32) & mask).to::<u64>(),
            last_refill: ((value >> 128u32) & mask).to::<u64>(),
            refill_rate: ((value >> 192u32) & mask).to::<u64>(),
        }
    }
}

impl RedemptionInfo {
    pub(crate) fn from_u256(limit: BucketLimit, value: U256) -> Self {
        let mask = U256::from(u64::from(u16::MAX));
        let exit_fee_split_to_treasury_in_bps = (value & mask).to::<u16>();
        let exit_fee_in_bps = ((value >> 16u32) & mask).to::<u16>();
        let low_watermark_in_bps_of_tvl = ((value >> 32u32) & mask).to::<u16>();
        Self {
            limit,
            exit_fee_split_to_treasury_in_bps,
            exit_fee_in_bps,
            low_watermark_in_bps_of_tvl,
        }
    }
}

impl ProtocolSim for EtherfiState {
    fn fee(&self) -> f64 {
        0 as f64
    }

    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError> {
        let base_unit = U256::from(10).pow(U256::from(base.decimals));
        let quote_unit = U256::from(10).pow(U256::from(quote.decimals));

        if base.address.as_ref() == EETH_ADDRESS && quote.address.as_ref() == WEETH_ADDRESS {
            let amount_out = self.shares_for_amount(base_unit)?;
            let amount_out_f64 = u256_to_f64(amount_out)?;
            let quote_unit_f64 = u256_to_f64(quote_unit)?;
            Ok(amount_out_f64 / quote_unit_f64)
        } else if base.address.as_ref() == WEETH_ADDRESS && quote.address.as_ref() == EETH_ADDRESS {
            let amount_out = self.amount_for_share(base_unit)?;
            let amount_out_f64 = u256_to_f64(amount_out)?;
            let quote_unit_f64 = u256_to_f64(quote_unit)?;
            Ok(amount_out_f64 / quote_unit_f64)
        } else if base.address.as_ref() == ETH_ADDRESS && quote.address.as_ref() == EETH_ADDRESS {
            let amount_out = self.shares_for_amount(base_unit)?;
            let amount_out_f64 = u256_to_f64(amount_out)?;
            let quote_unit_f64 = u256_to_f64(quote_unit)?;
            Ok(amount_out_f64 / quote_unit_f64)
        } else if base.address.as_ref() == EETH_ADDRESS && quote.address.as_ref() == ETH_ADDRESS {
            let amount_out = self.amount_for_share(base_unit)?;
            let amount_out_f64 = u256_to_f64(amount_out)?;
            let quote_unit_f64 = u256_to_f64(quote_unit)?;
            Ok(amount_out_f64 / quote_unit_f64)
        } else {
            Err(SimulationError::FatalError("unsupported spot price".to_string()))
        }
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        let new_state = self.clone();
        let amount_in = biguint_to_u256(&amount_in);
        if token_in.address.as_ref() == ETH_ADDRESS && token_out.address.as_ref() == EETH_ADDRESS {
            // eth --> eeth
            let amount_out = u256_to_biguint(self.shares_for_amount(amount_in)?);
            return Ok(GetAmountOutResult::new(amount_out, BigUint::ZERO, Box::new(new_state)))
        }

        if token_in.address.as_ref() == EETH_ADDRESS && token_out.address.as_ref() == ETH_ADDRESS {
            // eeth --> eth
            let liquid_eth_amount =
                self.liquidity_pool_native_balance - self.eth_amount_locked_for_withdrawl;
            let low_watermark = mul_div(
                self.total_value_in_lp + self.total_value_out_of_lp,
                U256::from(
                    self.eth_redemption_info
                        .low_watermark_in_bps_of_tvl,
                ),
                U256::from(BASIS_POINT_SCALE),
            )?;
            if liquid_eth_amount < low_watermark || liquid_eth_amount - low_watermark < amount_in {
                return Err(SimulationError::FatalError("Exceeded total redeemable amount".into()))
            } else {
                // BucketLimiter.canConsume
            }
            let eeth_shares = self.shares_for_amount(amount_in)?;
            let eth_amount_out = self.amount_for_share(mul_div(
                eeth_shares,
                U256::from(BASIS_POINT_SCALE) -
                    U256::from(self.eth_redemption_info.exit_fee_in_bps),
                U256::from(BASIS_POINT_SCALE),
            )?)?;
            let amount_out = u256_to_biguint(eth_amount_out);
            return Ok(GetAmountOutResult::new(amount_out, BigUint::ZERO, Box::new(new_state)))
        }

        if token_in.address.as_ref() == EETH_ADDRESS && token_out.address.as_ref() == WEETH_ADDRESS
        {
            // eeth --> weeth
            let amount_out = u256_to_biguint(self.shares_for_amount(amount_in)?);
            return Ok(GetAmountOutResult::new(amount_out, BigUint::ZERO, Box::new(new_state)))
        }

        if token_in.address.as_ref() == WEETH_ADDRESS && token_out.address.as_ref() == EETH_ADDRESS
        {
            // weeth --> eeth
            let amount_out = u256_to_biguint(self.amount_for_share(amount_in)?);
            return Ok(GetAmountOutResult::new(amount_out, BigUint::ZERO, Box::new(new_state)))
        }

        Err(SimulationError::FatalError("unsupported swap".to_string()))
    }

    fn get_limits(
        &self,
        sell_token: Bytes,
        buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        if sell_token.as_ref() == WEETH_ADDRESS && buy_token.as_ref() == EETH_ADDRESS {
            let max_weeth_amount = self.shares_for_amount(self.total_shares)?;
            let max_eeth_amount = self.total_shares;
            return Ok((u256_to_biguint(max_weeth_amount), u256_to_biguint(max_eeth_amount)));
        }

        if sell_token.as_ref() == EETH_ADDRESS && buy_token.as_ref() == ETH_ADDRESS {
            let liquid_eth_amount =
                self.liquidity_pool_native_balance - self.eth_amount_locked_for_withdrawl;
            let low_watermark = mul_div(
                self.total_value_in_lp + self.total_value_out_of_lp,
                U256::from(
                    self.eth_redemption_info
                        .low_watermark_in_bps_of_tvl,
                ),
                U256::from(BASIS_POINT_SCALE),
            )?;
            if liquid_eth_amount < low_watermark {
                return Ok((u256_to_biguint(liquid_eth_amount), BigUint::ZERO));
            }
            let max_eeth_amount = self.total_value_in_lp + self.total_value_out_of_lp;
            let eeth_shares = self.shares_for_amount(max_eeth_amount)?;
            let eth_amount_out = self.amount_for_share(mul_div(
                eeth_shares,
                U256::from(BASIS_POINT_SCALE) -
                    U256::from(self.eth_redemption_info.exit_fee_in_bps),
                U256::from(BASIS_POINT_SCALE),
            )?)?;
            return Ok((u256_to_biguint(max_eeth_amount), u256_to_biguint(eth_amount_out)));
        }

        if sell_token.as_ref() == EETH_ADDRESS && buy_token.as_ref() == WEETH_ADDRESS {
            let max = U256::from(1) << 256;
            return Ok((u256_to_biguint(max), u256_to_biguint(max)));
        }

        if sell_token.as_ref() == ETH_ADDRESS && buy_token.as_ref() == EETH_ADDRESS {
            let max = U256::from(1) << 256;
            return Ok((u256_to_biguint(max), u256_to_biguint(max)));
        }

        Err(SimulationError::FatalError("unsupported swap".to_string()))
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        if let Some(total_value_out_of_lp) = delta
            .updated_attributes
            .get("totalValueOutOfLp")
        {
            self.total_value_out_of_lp = U256::from_be_slice(total_value_out_of_lp);
        }
        if let Some(total_value_in_lp) = delta
            .updated_attributes
            .get("totalValueInLp")
        {
            self.total_value_in_lp = U256::from_be_slice(total_value_in_lp);
        }
        if let Some(total_shares) = delta
            .updated_attributes
            .get("totalShares")
        {
            self.total_shares = U256::from_be_slice(total_shares);
        }
        if let Some(eth_amount_locked_for_withdrawl) = delta
            .updated_attributes
            .get("ethAmountLockedForWithdrawl")
        {
            self.eth_amount_locked_for_withdrawl =
                U256::from_be_slice(eth_amount_locked_for_withdrawl);
        }
        if let Some(liquidity_pool_native_balance) = delta
            .updated_attributes
            .get("liquidity_pool_native_balance")
        {
            self.liquidity_pool_native_balance = U256::from_be_slice(liquidity_pool_native_balance);
        }
        let eth_bucket_limiter = delta
            .updated_attributes
            .get("ethBucketLimiter")
            .map(|value| U256::from_be_slice(value));
        let eth_redemption_info = delta
            .updated_attributes
            .get("ethRedemptionInfo")
            .map(|value| U256::from_be_slice(value));
        if let (Some(eth_bucket_limiter), Some(eth_redemption_info)) =
            (eth_bucket_limiter, eth_redemption_info)
        {
            self.eth_redemption_info = RedemptionInfo::from_u256(
                BucketLimit::from_u256(eth_bucket_limiter),
                eth_redemption_info,
            );
        }

        Ok(())
    }

    fn clone_box(&self) -> Box<dyn ProtocolSim> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
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
