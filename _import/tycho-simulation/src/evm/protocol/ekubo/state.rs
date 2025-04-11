use std::{any::Any, collections::HashMap, fmt::Debug};

use alloy_primitives::Address;
use evm_ekubo_sdk::{
    math::uint::U256,
    quoting::types::{NodeKey, TokenAmount},
};
use num_bigint::BigUint;
use tycho_common::{dto::ProtocolStateDelta, Bytes};

use super::{
    attributes::{sale_rate_deltas_from_attributes, ticks_from_attributes},
    pool::{
        base::BasePool, full_range::FullRangePool, oracle::OraclePool, twamm::TwammPool, EkuboPool,
    },
};
use crate::{
    evm::protocol::u256_num::u256_to_f64,
    models::{Balances, Token},
    protocol::{
        errors::{SimulationError, TransitionError},
        models::GetAmountOutResult,
        state::ProtocolSim,
    },
};

#[enum_delegate::implement(EkuboPool)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EkuboState {
    Base(BasePool),
    FullRange(FullRangePool),
    Oracle(OraclePool),
    Twamm(TwammPool),
}

fn sqrt_price_q128_to_f64(x: U256, (token0_decimals, token1_decimals): (usize, usize)) -> f64 {
    let token_correction = 10f64.powi(token0_decimals as i32 - token1_decimals as i32);

    let price = u256_to_f64(alloy_primitives::U256::from_limbs(x.0)) / 2.0f64.powi(128);
    price.powi(2) * token_correction
}

impl ProtocolSim for EkuboState {
    fn fee(&self) -> f64 {
        self.key().config.fee as f64 / (2f64.powi(64))
    }

    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError> {
        let sqrt_ratio = self.sqrt_ratio();
        let (base_decimals, quote_decimals) = (base.decimals, quote.decimals);

        Ok(if base < quote {
            sqrt_price_q128_to_f64(sqrt_ratio, (base_decimals, quote_decimals))
        } else {
            1.0f64 / sqrt_price_q128_to_f64(sqrt_ratio, (quote_decimals, base_decimals))
        })
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        _token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        let token_amount = TokenAmount {
            token: U256::from_big_endian(&token_in.address),
            amount: amount_in.try_into().map_err(|_| {
                SimulationError::InvalidInput("amount in must fit into a i128".to_string(), None)
            })?,
        };

        let quote = self.quote(token_amount)?;

        let res = GetAmountOutResult {
            amount: BigUint::try_from(quote.calculated_amount).map_err(|_| {
                SimulationError::FatalError("output amount must be non-negative".to_string())
            })?,
            gas: quote.gas.into(),
            new_state: Box::new(quote.new_state),
        };

        if quote.consumed_amount != token_amount.amount {
            return Err(SimulationError::InvalidInput(
                format!("pool does not have enough liquidity to support complete swap. input amount: {}, consumed amount: {}", token_amount.amount, quote.consumed_amount),
                Some(res),
            ));
        }

        Ok(res)
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        if let Some(liquidity) = delta
            .updated_attributes
            .get("liquidity")
        {
            self.set_liquidity(liquidity.clone().into());
        }

        if let Some(sqrt_price) = delta
            .updated_attributes
            .get("sqrt_ratio")
        {
            self.set_sqrt_ratio(U256::from_big_endian(sqrt_price));
        }

        match self {
            Self::Base(p) => {
                // The exact tick is only required for CL pools
                if let Some(tick) = delta.updated_attributes.get("tick") {
                    p.set_active_tick(tick.clone().into());
                }

                ticks_from_attributes(
                    delta
                        .updated_attributes
                        .into_iter()
                        .chain(
                            delta
                                .deleted_attributes
                                .into_iter()
                                .map(|key| (key, Bytes::new())),
                        ),
                )
                .map_err(TransitionError::DecodeError)?
                .into_iter()
                .for_each(|changed_tick| {
                    p.set_tick(changed_tick);
                });
            }
            Self::FullRange(_) | Self::Oracle(_) => {}
            Self::Twamm(p) => {
                if let Some(token0_sale_rate) = delta
                    .updated_attributes
                    .get("token0_sale_rate")
                {
                    p.set_token0_sale_rate(token0_sale_rate.clone().into());
                }

                if let Some(token1_sale_rate) = delta
                    .updated_attributes
                    .get("token1_sale_rate")
                {
                    p.set_token1_sale_rate(token1_sale_rate.clone().into());
                }

                if let Some(last_execution_time) = delta
                    .updated_attributes
                    .get("last_execution_time")
                {
                    p.set_last_execution_time(last_execution_time.clone().into());
                }

                let last_execution_time = p.last_execution_time();

                sale_rate_deltas_from_attributes(
                    delta
                        .updated_attributes
                        .into_iter()
                        .chain(
                            delta
                                .deleted_attributes
                                .into_iter()
                                .map(|key| (key, Bytes::new())),
                        ),
                    last_execution_time,
                )
                .map_err(TransitionError::DecodeError)?
                .for_each(|changed_delta| {
                    p.set_sale_rate_delta(changed_delta);
                });
            }
        }

        self.finish_transition()
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
        other
            .as_any()
            .downcast_ref::<EkuboState>()
            .is_some_and(|other_state| self == other_state)
    }

    fn get_limits(
        &self,
        sell_token: Address,
        _buy_token: Address,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        // TODO Update once exact out is supported
        Ok((
            self.get_limit(U256::from_big_endian(sell_token.as_slice()))?
                .into(),
            BigUint::ZERO,
        ))
    }
}

#[cfg(test)]
mod tests {
    use rstest::*;
    use rstest_reuse::apply;

    use super::*;
    use crate::evm::protocol::ekubo::test_cases::*;

    #[apply(all_cases)]
    fn test_delta_transition(case: TestCase) {
        let mut state = case.state_before_transition;

        state
            .delta_transition(
                ProtocolStateDelta {
                    updated_attributes: case.transition_attributes,
                    ..Default::default()
                },
                &HashMap::default(),
                &Balances::default(),
            )
            .expect("executing transition");

        assert_eq!(state, case.state);
    }

    #[apply(all_cases)]
    fn test_get_amount_out(case: TestCase) {
        let (token0, token1) = (case.token0(), case.token1());
        let (amount_in, expected_out) = case.swap_token0;

        let res = case
            .state
            .get_amount_out(amount_in, &token0, &token1)
            .expect("computing quote");

        assert_eq!(res.amount, expected_out);
    }

    #[apply(all_cases)]
    fn test_get_limits(case: TestCase) {
        use std::ops::Deref;

        let (token0, token1) = (case.token0(), case.token1());
        let state = case.state;

        let max_amount_in = state
            .get_limits(
                Address::from_word(
                    token0
                        .address
                        .deref()
                        .try_into()
                        .unwrap(),
                ),
                Address::from_word(
                    token1
                        .address
                        .deref()
                        .try_into()
                        .unwrap(),
                ),
            )
            .expect("computing limits for token0")
            .0;

        assert_eq!(max_amount_in, case.expected_limit_token0);

        state
            .get_amount_out(max_amount_in, &token0, &token1)
            .expect("quoting with limit");
    }
}
