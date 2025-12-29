use alloy::primitives::U256;
use hex_literal::hex;
use num_bigint::BigUint;
use serde::Deserialize;
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
    u256_num::{biguint_to_u256, u256_to_biguint},
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

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct RedemptionInfo {
    limit: BucketLimit,
    exit_fee_split_to_treasury_in_bps: u16,
    exit_fee_in_bps: u16,
    low_watermark_in_bps_of_tvl: u16,
}

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
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
    fn new() -> Self {
        EtherfiState {
            total_value_out_of_lp: todo!(),
            total_value_in_lp: todo!(),
            total_shares: todo!(),
            eth_amount_locked_for_withdrawl: todo!(),
            eth_redemption_info: todo!(),
            liquidity_pool_native_balance: todo!(),
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
        let total_pooled_ether = self.total_value_in_lp + self.total_value_out_of_lp;
        if self.total_shares == U256::ZERO {
            return Ok(U256::ZERO)
        }
        Ok(share * total_pooled_ether / self.total_shares)
    }

    fn process_weeth_pool_swap(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        token_out: &Token,
    ) -> Result<BigUint, SimulationError> {
        let amount_in = biguint_to_u256(&amount_in);
        if token_in.address.0.to_vec() == ETH_ADDRESS &&
            token_out.address.0.to_vec() == EETH_ADDRESS
        {
            // liquidityPool.deposit
            Ok(u256_to_biguint(self.shares_for_amount(amount_in)?))
        } else {
            // redemptionManager.redeemEEth
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
                return Err(SimulationError::FatalError("canRedeem".into()))
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

            Ok(u256_to_biguint(eth_amount_out))
        }
    }

    fn process_eeth_pool_swap(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        token_out: &Token,
    ) -> Result<BigUint, SimulationError> {
        let amount_in = biguint_to_u256(&amount_in);
        if token_in.address.0.to_vec() == EETH_ADDRESS &&
            token_out.address.0.to_vec() == WEETH_ADDRESS
        {
            // weETH.wrap, weETH.wrapWithPermit
            let total_pooled_ether = self.total_value_in_lp + self.total_value_out_of_lp;
            Ok(u256_to_biguint(amount_in * self.total_shares / total_pooled_ether))
        } else {
            // weETH.unwrap
            let total_pooled_ether = self.total_value_in_lp + self.total_value_out_of_lp;
            Ok(u256_to_biguint(amount_in * total_pooled_ether / self.total_shares))
        }
    }
}

impl ProtocolSim for EtherfiState {
    fn fee(&self) -> f64 {
        0 as f64
    }

    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError> {
        todo!()
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        todo!()
    }

    fn get_limits(
        &self,
        sell_token: Bytes,
        buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        todo!()
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        tokens: &std::collections::HashMap<Bytes, Token>,
        balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        todo!()
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
        todo!()
    }
}
