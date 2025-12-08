use std::{any::Any, collections::HashMap};

use num_bigint::BigUint;
use num_traits::Zero;
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
    safe_math::{safe_div_u256, safe_mul_u256},
    u256_num::{biguint_to_u256, u256_to_biguint, u256_to_f64},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LidoPoolType {
    StEth,
    WStEth,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StakingStatus {
    Limited = 0,
    Paused = 1,
    Unlimited = 2,
}

impl StakingStatus {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            StakingStatus::Limited => "Limited",
            StakingStatus::Paused => "Paused",
            StakingStatus::Unlimited => "Unlimited",
        }
    }
}

// see here https://github.com/lidofinance/core/blob/cca04b42123735714d8c60a73c2f7af949e989db/contracts/0.4.24/lib/StakeLimitUtils.sol#L38
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeLimitState {
    pub staking_status: StakingStatus,
    pub staking_limit: BigUint,
}

impl StakeLimitState {
    fn get_limit(&self) -> BigUint {
        // https://github.com/lidofinance/core/blob/cca04b42123735714d8c60a73c2f7af949e989db/contracts/0.4.24/lib/StakeLimitUtils.sol#L98
        println!("self.staking_status: {:?}", self.staking_status);
        match self.staking_status {
            StakingStatus::Limited => self.staking_limit.clone(),
            StakingStatus::Paused => BigUint::zero(),
            StakingStatus::Unlimited => BigUint::from(u128::MAX),
        }
    }
}

pub const ST_ETH_ADDRESS_PROXY: &str = "0xae7ab96520de3a18e5e111b5eaab095312d7fe84";
pub const WST_ETH_ADDRESS: &str = "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0";
pub const ETH_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
pub const DEFAULT_GAS: u64 = 60000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LidoState {
    pub pool_type: LidoPoolType,
    pub total_shares: BigUint,
    pub total_pooled_eth: BigUint,
    pub total_wrapped_st_eth: Option<BigUint>,
    pub id: Bytes,
    pub native_address: Bytes,
    pub stake_limits_state: StakeLimitState,
    pub tokens: [Bytes; 2],
    pub token_to_track_total_pooled_eth: Bytes,
}

impl LidoState {
    fn steth_swap(&self, amount_in: BigUint) -> Result<GetAmountOutResult, SimulationError> {
        let shares = safe_div_u256(
            safe_mul_u256(biguint_to_u256(&amount_in), biguint_to_u256(&self.total_shares))?,
            biguint_to_u256(&self.total_pooled_eth),
        )?;

        let amount_out = safe_div_u256(
            safe_mul_u256(shares, biguint_to_u256(&self.total_pooled_eth))?,
            biguint_to_u256(&self.total_shares),
        )?;

        Ok(GetAmountOutResult {
            amount: u256_to_biguint(amount_out),
            gas: BigUint::from(DEFAULT_GAS),
            new_state: Box::new(Self {
                pool_type: self.pool_type.clone(),
                total_shares: self.total_shares.clone() + u256_to_biguint(shares),
                total_pooled_eth: self.total_pooled_eth.clone() + amount_in,
                total_wrapped_st_eth: None,
                id: self.id.clone(),
                native_address: self.native_address.clone(),
                stake_limits_state: self.stake_limits_state.clone(),
                tokens: self.tokens.clone(),
                token_to_track_total_pooled_eth: self
                    .token_to_track_total_pooled_eth
                    .clone(),
            }),
        })
    }

    fn wrap_steth(&self, amount_in: BigUint) -> Result<GetAmountOutResult, SimulationError> {
        if amount_in.is_zero() {
            return Err(SimulationError::InvalidInput("Cannot wrap 0 stETH ".to_string(), None))
        }

        let amount_out = u256_to_biguint(safe_div_u256(
            safe_mul_u256(biguint_to_u256(&amount_in), biguint_to_u256(&self.total_shares))?,
            biguint_to_u256(&self.total_pooled_eth),
        )?);

        let new_total_wrapped_st_eth = self
            .total_wrapped_st_eth
            .as_ref()
            .expect("total_wrapped_st_eth must be present for wrapped staked ETH pool") +
            &amount_out;

        Ok(GetAmountOutResult {
            amount: amount_out.clone(),
            gas: BigUint::from(DEFAULT_GAS),
            new_state: Box::new(Self {
                pool_type: self.pool_type.clone(),
                total_shares: self.total_shares.clone(),
                total_pooled_eth: self.total_pooled_eth.clone(),
                total_wrapped_st_eth: Some(new_total_wrapped_st_eth),
                id: self.id.clone(),
                native_address: self.native_address.clone(),
                stake_limits_state: self.stake_limits_state.clone(),
                tokens: self.tokens.clone(),
                token_to_track_total_pooled_eth: self
                    .token_to_track_total_pooled_eth
                    .clone(),
            }),
        })
    }

    fn unwrap_steth(&self, amount_in: BigUint) -> Result<GetAmountOutResult, SimulationError> {
        if amount_in.is_zero() {
            return Err(SimulationError::InvalidInput("Cannot unwrap 0 wstETH ".to_string(), None))
        }

        let amount_out = u256_to_biguint(safe_div_u256(
            safe_mul_u256(biguint_to_u256(&amount_in), biguint_to_u256(&self.total_pooled_eth))?,
            biguint_to_u256(&self.total_shares),
        )?);

        let new_total_wrapped_st_eth = self
            .total_wrapped_st_eth
            .as_ref()
            .expect("total_wrapped_st_eth must be present for wrapped staked ETH pool") -
            &amount_in;

        Ok(GetAmountOutResult {
            amount: amount_out.clone(),
            gas: BigUint::from(DEFAULT_GAS),
            new_state: Box::new(Self {
                pool_type: self.pool_type.clone(),
                total_shares: self.total_shares.clone(),
                total_pooled_eth: self.total_pooled_eth.clone(),
                total_wrapped_st_eth: Some(new_total_wrapped_st_eth),
                id: self.id.clone(),
                native_address: self.native_address.clone(),
                stake_limits_state: self.stake_limits_state.clone(),
                tokens: self.tokens.clone(),
                token_to_track_total_pooled_eth: self
                    .token_to_track_total_pooled_eth
                    .clone(),
            }),
        })
    }

    fn st_eth_limits(
        &self,
        sell_token: Bytes,
        buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        if buy_token == Bytes::from(ST_ETH_ADDRESS_PROXY) && sell_token == Bytes::from(ETH_ADDRESS)
        {
            let limit = self.stake_limits_state.get_limit();
            Ok((limit.clone(), limit))
        } else if buy_token == Bytes::from(ETH_ADDRESS) &&
            sell_token == Bytes::from(ST_ETH_ADDRESS_PROXY)
        {
            Ok((BigUint::zero(), BigUint::zero()))
        } else {
            Err(SimulationError::InvalidInput(
                format!(
                    "Get_limits: Invalid combination of tokens for type {:?}: {:?}, {:?}",
                    self.pool_type, buy_token, sell_token
                ),
                None,
            ))
        }
    }

    fn wst_eth_limits(
        &self,
        sell_token: Bytes,
        buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        if buy_token == Bytes::from(ST_ETH_ADDRESS_PROXY) &&
            sell_token == Bytes::from(WST_ETH_ADDRESS)
        {
            //amount of wsteth
            Ok((
                self.total_wrapped_st_eth
                    .clone()
                    .expect("total_wrapped_st_eth must be present for wrapped staked ETH pool"),
                self.total_wrapped_st_eth
                    .clone()
                    .expect("total_wrapped_st_eth must be present for wrapped staked ETH pool"),
            ))
        } else if buy_token == Bytes::from(WST_ETH_ADDRESS) &&
            sell_token == Bytes::from(ST_ETH_ADDRESS_PROXY)
        {
            // total_shares - wstETH

            let limit_for_wrapping = &self.total_shares -
                self.total_wrapped_st_eth
                    .as_ref()
                    .expect("total_wrapped_st_eth must be present for wrapped staked ETH pool");

            Ok((limit_for_wrapping.clone(), limit_for_wrapping))
        } else {
            Err(SimulationError::InvalidInput(
                format!(
                    "Invalid combination of tokens for type {:?}: {:?}, {:?}",
                    self.pool_type, buy_token, sell_token
                ),
                None,
            ))
        }
    }

    fn st_eth_delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
    ) -> Result<(), TransitionError<String>> {
        self.total_shares = BigUint::from_bytes_be(
            delta
                .updated_attributes
                .get("total_shares")
                .ok_or(TransitionError::MissingAttribute(
                    "total_shares field is missing".to_owned(),
                ))?,
        );

        let staking_status = delta
            .updated_attributes
            .get("staking_status")
            .ok_or(TransitionError::MissingAttribute(
                "Staking_status field is missing".to_owned(),
            ))?;

        let staking_status_parsed = if let Ok(status_as_str) = std::str::from_utf8(staking_status) {
            match status_as_str {
                "Limited" => StakingStatus::Limited,
                "Paused" => StakingStatus::Paused,
                "Unlimited" => StakingStatus::Unlimited,
                _ => {
                    return Err(TransitionError::DecodeError(
                        "status_as_str parsed to invalid status".to_owned(),
                    ))
                }
            }
        } else {
            return Err(TransitionError::DecodeError("status_as_str cannot be parsed".to_owned()))
        };

        let staking_limit = delta
            .updated_attributes
            .get("staking_limit")
            .ok_or(TransitionError::MissingAttribute(
                "Staking_limit field is missing".to_owned(),
            ))?;

        self.stake_limits_state = StakeLimitState {
            staking_status: staking_status_parsed,
            staking_limit: BigUint::from_bytes_be(staking_limit),
        };
        Ok(())
    }

    fn st_eth_balance_transition(&mut self, balances: &HashMap<Bytes, Bytes>) {
        for (token, balance) in balances.iter() {
            if token == &self.token_to_track_total_pooled_eth {
                self.total_pooled_eth = BigUint::from_bytes_be(balance)
            }
        }
    }

    fn wst_eth_delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
    ) -> Result<(), TransitionError<String>> {
        self.total_shares = BigUint::from_bytes_be(
            delta
                .updated_attributes
                .get("total_shares")
                .ok_or(TransitionError::MissingAttribute(
                    "total_shares field is missing".to_owned(),
                ))?,
        );
        self.total_wrapped_st_eth = Some(BigUint::from_bytes_be(
            delta
                .updated_attributes
                .get("total_wstETH")
                .ok_or(TransitionError::MissingAttribute(
                    "total_wstETH field is missing".to_owned(),
                ))?,
        ));

        Ok(())
    }

    fn wst_eth_balance_transition(&mut self, balances: &HashMap<Bytes, Bytes>) {
        for (token, balance) in balances.iter() {
            if token == &self.token_to_track_total_pooled_eth {
                self.total_pooled_eth = BigUint::from_bytes_be(balance)
            }
        }
    }
}

impl ProtocolSim for LidoState {
    fn fee(&self) -> f64 {
        // there is no fee when swapping
        0.0
    }

    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError> {
        match self.pool_type {
            LidoPoolType::StEth => {
                if base.address == Bytes::from(ETH_ADDRESS) &&
                    quote.address == Bytes::from(ST_ETH_ADDRESS_PROXY)
                {
                    let total_shares_f64 = u256_to_f64(biguint_to_u256(&self.total_shares))?;
                    let total_pooled_eth_f64 =
                        u256_to_f64(biguint_to_u256(&self.total_pooled_eth))?;

                    Ok(total_pooled_eth_f64 / total_shares_f64 * total_shares_f64 /
                        total_pooled_eth_f64)
                } else {
                    Err(SimulationError::InvalidInput(
                        format!(
                            "Spot_price: Invalid combination of tokens for type {:?}: {:?}, {:?}",
                            self.pool_type, base, quote
                        ),
                        None,
                    ))
                }
            }
            LidoPoolType::WStEth => {
                if base.address == Bytes::from(ST_ETH_ADDRESS_PROXY) &&
                    quote.address == Bytes::from(WST_ETH_ADDRESS)
                {
                    let total_shares_f64 = u256_to_f64(biguint_to_u256(&self.total_shares))?;
                    let total_pooled_eth_f64 =
                        u256_to_f64(biguint_to_u256(&self.total_pooled_eth))?;

                    Ok(total_shares_f64 / total_pooled_eth_f64)
                } else if base.address == Bytes::from(WST_ETH_ADDRESS) &&
                    quote.address == Bytes::from(ST_ETH_ADDRESS_PROXY)
                {
                    let total_shares_f64 = u256_to_f64(biguint_to_u256(&self.total_shares))?;
                    let total_pooled_eth_f64 =
                        u256_to_f64(biguint_to_u256(&self.total_pooled_eth))?;

                    Ok(total_pooled_eth_f64 / total_shares_f64)
                } else {
                    Err(SimulationError::InvalidInput(
                        format!(
                            "Invalid combination of tokens for type {:?}: {:?}, {:?}",
                            self.pool_type, base, quote
                        ),
                        None,
                    ))
                }
            }
        }
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        // check the pool type and the token in and token out
        // if it's stETH type and the token out is ETH this is not allowed
        // call the corresponding swap method
        match self.pool_type {
            LidoPoolType::StEth => {
                if token_in.address == Bytes::from(ETH_ADDRESS) &&
                    token_out.address == Bytes::from(ST_ETH_ADDRESS_PROXY)
                {
                    Ok(self.steth_swap(amount_in)?)
                } else {
                    Err(SimulationError::InvalidInput(
                        format!(
                            "Invalid combination of tokens for type {:?}: {:?}, {:?}",
                            self.pool_type, token_in, token_out
                        ),
                        None,
                    ))
                }
            }
            LidoPoolType::WStEth => {
                if token_in.address == Bytes::from(ST_ETH_ADDRESS_PROXY) &&
                    token_out.address == Bytes::from(WST_ETH_ADDRESS)
                {
                    self.wrap_steth(amount_in)
                } else if token_in.address == Bytes::from(WST_ETH_ADDRESS) &&
                    token_out.address == Bytes::from(ST_ETH_ADDRESS_PROXY)
                {
                    self.unwrap_steth(amount_in)
                } else {
                    Err(SimulationError::InvalidInput(
                        format!(
                            "Invalid combination of tokens for type {:?}: {:?}, {:?}",
                            self.pool_type, token_in, token_out
                        ),
                        None,
                    ))
                }
            }
        }
    }

    fn get_limits(
        &self,
        sell_token: Bytes,
        buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        // If it's the stETH type:
        //   - and the buy token is ETH, the limits are 0
        //   - sell token is ETH: use the StakeLimitState
        // If it's wstETH: rely on the total supply
        match self.pool_type {
            LidoPoolType::StEth => self.st_eth_limits(sell_token, buy_token),
            LidoPoolType::WStEth => self.wst_eth_limits(sell_token, buy_token),
        }
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        for (component_id, balances) in balances.component_balances.iter() {
            if component_id == ST_ETH_ADDRESS_PROXY {
                self.st_eth_balance_transition(balances)
            } else if component_id == WST_ETH_ADDRESS {
                self.wst_eth_balance_transition(balances)
            } else {
                return Err(TransitionError::DecodeError(format!(
                    "Invalid component id or wrong pool type: {:?}",
                    component_id,
                )))
            }
        }

        if delta.component_id == ST_ETH_ADDRESS_PROXY {
            self.st_eth_delta_transition(delta)
        } else if delta.component_id == WST_ETH_ADDRESS {
            self.wst_eth_delta_transition(delta)
        } else {
            Err(TransitionError::DecodeError(format!(
                "Invalid component id in delta: {:?}",
                delta.component_id
            )))
        }
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
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr};

    use num_bigint::BigUint;
    use rstest::rstest;
    use tycho_common::{
        hex_bytes::Bytes,
        models::{token::Token, Chain},
    };

    use super::*;

    fn from_hex_str_to_biguint(input: &str) -> BigUint {
        let bytes = hex::decode(input).unwrap();
        BigUint::from_bytes_be(&bytes)
    }

    fn lido_state_steth() -> LidoState {
        let total_shares_start = from_hex_str_to_biguint(
            "00000000000000000000000000000000000000000005dc41ec2e3ba19cf3ea6d",
        );
        let total_pooled_eth_start = from_hex_str_to_biguint("072409d75ebf50c5534125");
        let staking_limit = from_hex_str_to_biguint("1fc3842bd1f071c00000");

        LidoState {
            pool_type: LidoPoolType::StEth,
            total_shares: total_shares_start.clone(),
            total_pooled_eth: total_pooled_eth_start.clone(),
            total_wrapped_st_eth: None,
            id: ST_ETH_ADDRESS_PROXY.into(),
            native_address: ETH_ADDRESS.into(),
            stake_limits_state: StakeLimitState {
                staking_status: crate::evm::protocol::lido::state::StakingStatus::Limited,
                staking_limit,
            },
            tokens: [
                Bytes::from("0x0000000000000000000000000000000000000000"),
                Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
            ],
            token_to_track_total_pooled_eth: Bytes::from(ETH_ADDRESS),
        }
    }

    fn lido_state_wsteth() -> LidoState {
        let total_shares_start = from_hex_str_to_biguint(
            "00000000000000000000000000000000000000000005dc41ec2e3ba19cf3ea6d",
        );
        let total_pooled_eth_start = from_hex_str_to_biguint("072409d75ebf50c5534125");
        let total_wsteth_start = from_hex_str_to_biguint(
            "00000000000000000000000000000000000000000002be110f2a220611513da6",
        );

        LidoState {
            pool_type: LidoPoolType::WStEth,
            total_shares: total_shares_start,
            total_pooled_eth: total_pooled_eth_start.clone(),
            total_wrapped_st_eth: Some(total_wsteth_start),
            id: ST_ETH_ADDRESS_PROXY.into(),
            native_address: ETH_ADDRESS.into(),
            stake_limits_state: StakeLimitState {
                staking_status: crate::evm::protocol::lido::state::StakingStatus::Limited,
                staking_limit: BigUint::zero(),
            },
            tokens: [
                Bytes::from("0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"),
                Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
            ],
            token_to_track_total_pooled_eth: Bytes::from(ST_ETH_ADDRESS_PROXY),
        }
    }

    fn bytes_st_eth() -> Bytes {
        Bytes::from(ST_ETH_ADDRESS_PROXY)
    }

    fn bytes_wst_eth() -> Bytes {
        Bytes::from(WST_ETH_ADDRESS)
    }

    fn bytes_eth() -> Bytes {
        Bytes::from(ETH_ADDRESS)
    }

    fn token_st_eth() -> Token {
        Token::new(
            &Bytes::from_str(ST_ETH_ADDRESS_PROXY).unwrap(),
            "stETH",
            18,
            0,
            &[Some(44000)],
            Chain::Ethereum,
            10,
        )
    }

    fn token_wst_eth() -> Token {
        Token::new(
            &Bytes::from_str(WST_ETH_ADDRESS).unwrap(),
            "wstETH",
            18,
            0,
            &[Some(44000)],
            Chain::Ethereum,
            10,
        )
    }

    fn token_eth() -> Token {
        Token::new(
            &Bytes::from_str(ETH_ADDRESS).unwrap(),
            "ETH",
            18,
            0,
            &[Some(44000)],
            Chain::Ethereum,
            100,
        )
    }

    #[test]
    fn test_lido_get_amount_out() {
        // total pooled eth: 0x072409d75ebf50c5534125, 8632667470434094430765349
        // total shares: 0x00000000000000000000000000000000000000000005dc41ec2e3ba19cf3ea6d
        // tx 0x1953b525c8640c2709e984ebc28bb1f2180dd72759bb2aac7413e94b602b0d53
        // total_shares_after: 0x00000000000000000000000000000000000000000005dc41ec487a31b7865d5e
        // total pooled eth after: 0x072409d77eb9c55db21616
        let token_eth = token_eth();
        let token_st_eth = token_st_eth();
        let state = lido_state_steth();

        let amount_in = BigUint::from_str("9001102957532401").unwrap();
        let res = state
            .get_amount_out(amount_in.clone(), &token_eth, &token_st_eth)
            .unwrap();

        let exp = BigUint::from_str("9001102957532400").unwrap(); // diff in total pooled eth; rounding error
        assert_eq!(res.amount, exp);

        let total_shares_after = from_hex_str_to_biguint(
            "00000000000000000000000000000000000000000005dc41ec487a31b7865d5e",
        );

        let total_pooled_eth_after = from_hex_str_to_biguint("072409d77eb9c55db21616");

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<LidoState>()
            .unwrap();
        assert_eq!(new_state.total_shares, total_shares_after);
        assert_eq!(new_state.total_pooled_eth, total_pooled_eth_after);
    }

    #[test]
    fn test_lido_wrapping_get_amount_out() {
        // total pooled eth: 072409d88cbb5e48a01616
        // total shares: 00000000000000000000000000000000000000000005dc41ed2611c5fd46f034
        // tx 0xce9418dd0e74cdf738362bee9428da73c047049c34f28ff8a18b19f047c27c53
        // ws eth before 00000000000000000000000000000000000000000002be10e0f61dc56f6f85dc
        // ws eth after 00000000000000000000000000000000000000000002be11ccda98eef241c759

        let token_st_eth = token_st_eth();
        let token_wst_eth = token_wst_eth();
        let mut state = lido_state_wsteth();

        let total_wsteth_start = from_hex_str_to_biguint(
            "00000000000000000000000000000000000000000002be10e0f61dc56f6f85dc",
        );
        state.total_wrapped_st_eth = Some(total_wsteth_start);

        let total_pooled_eth = from_hex_str_to_biguint("072409d88cbb5e48a01616");
        state.total_pooled_eth = total_pooled_eth;

        let total_shares = from_hex_str_to_biguint(
            "00000000000000000000000000000000000000000005dc41ed2611c5fd46f034",
        );
        state.total_shares = total_shares;

        let amount_in = BigUint::from_str("20711588703656141053").unwrap();
        let res = state
            .get_amount_out(amount_in.clone(), &token_st_eth, &token_wst_eth)
            .unwrap();
        let exp = BigUint::from_str("16997846311821787517").unwrap();
        assert_eq!(res.amount, exp);

        let total_wsteth_after = from_hex_str_to_biguint(
            "00000000000000000000000000000000000000000002be11ccda98eef241c759",
        );
        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<LidoState>()
            .unwrap();
        assert_eq!(new_state.total_wrapped_st_eth, Some(total_wsteth_after));

        assert!(state
            .get_amount_out(BigUint::zero(), &token_st_eth, &token_wst_eth)
            .is_err());
    }

    #[test]

    fn test_lido_unwrapping_get_amount_out() {
        //new data
        // total pooled eth: 0x072409d75ebf50c5534125, 8632667470434094430765349
        // total shares: 0x00000000000000000000000000000000000000000005dc41ec2e3ba19cf3ea6d
        // tx 0xa49316d76b7cf2ba9f81c7b84868faaa6306eef5a15f194f55b3675bce89367a
        // ws eth after 0x00000000000000000000000000000000000000000002be10e0f61dc56f6f85dc
        // ws eth before 0x00000000000000000000000000000000000000000002be110f2a220611513da6

        let token_st_eth = token_st_eth();
        let token_wst_eth = token_wst_eth();
        let mut state = lido_state_wsteth();

        let total_wsteth_start = from_hex_str_to_biguint(
            "00000000000000000000000000000000000000000002be110f2a220611513da6",
        );
        state.total_wrapped_st_eth = Some(total_wsteth_start);

        let amount_in = BigUint::from_str("3329290700173981642").unwrap();
        let res = state
            .get_amount_out(amount_in.clone(), &token_wst_eth, &token_st_eth)
            .unwrap();
        let exp = BigUint::from_str("4056684499432944068").unwrap();
        assert_eq!(res.amount, exp);

        let total_wsteth_after = from_hex_str_to_biguint(
            "00000000000000000000000000000000000000000002be10e0f61dc56f6f85dc",
        );

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<LidoState>()
            .unwrap();

        assert_eq!(new_state.total_wrapped_st_eth, Some(total_wsteth_after));
    }

    #[test]
    fn test_lido_spot_price() {
        let token_st_eth = token_st_eth();
        let token_wst_eth = token_wst_eth();
        let token_eth = token_eth();

        let st_state = lido_state_steth();
        let wst_state = lido_state_wsteth();

        let res = st_state
            .spot_price(&token_eth, &token_st_eth)
            .unwrap();
        let exp = 1.0000000000000002;
        assert_eq!(res, exp);

        let res = st_state.spot_price(&token_st_eth, &token_wst_eth);
        assert!(res.is_err());

        let res = wst_state
            .spot_price(&token_st_eth, &token_wst_eth)
            .unwrap();
        assert_eq!(res, 0.8206925386086495);

        let res = wst_state
            .spot_price(&token_wst_eth, &token_st_eth)
            .unwrap();
        assert_eq!(res, 1.2184831139019945);

        let res = wst_state.spot_price(&token_eth, &token_st_eth);
        assert!(res.is_err());
    }

    #[test]
    fn test_lido_get_limits() {
        let token_st_eth = bytes_st_eth();
        let token_wst_eth = bytes_wst_eth();
        let token_eth = bytes_eth();

        let st_state = lido_state_steth();
        let wst_state = lido_state_wsteth();

        let res = st_state
            .get_limits(token_eth.clone(), token_st_eth.clone())
            .unwrap();
        let exp = (
            st_state
                .stake_limits_state
                .staking_limit
                .clone(),
            st_state
                .stake_limits_state
                .staking_limit
                .clone(),
        );
        assert_eq!(res, exp);

        let res = st_state
            .get_limits(token_st_eth.clone(), token_eth.clone())
            .unwrap();
        let exp = (BigUint::zero(), BigUint::zero());
        assert_eq!(res, exp);

        let res = st_state.get_limits(token_wst_eth.clone(), token_eth.clone());
        assert!(res.is_err());

        let res = wst_state
            .get_limits(token_st_eth.clone(), token_wst_eth.clone())
            .unwrap();
        let allowed_to_wrap = wst_state.total_shares.clone() -
            wst_state
                .total_wrapped_st_eth
                .clone()
                .unwrap();
        let exp = (allowed_to_wrap.clone(), allowed_to_wrap);

        assert_eq!(res, exp);

        let res = wst_state
            .get_limits(token_wst_eth.clone(), token_st_eth.clone())
            .unwrap();
        let total_wrapped = wst_state
            .total_wrapped_st_eth
            .clone()
            .unwrap();
        let exp = (total_wrapped.clone(), total_wrapped);

        assert_eq!(res, exp);

        let res = wst_state.get_limits(token_wst_eth.clone(), token_eth.clone());
        assert!(res.is_err());
    }

    #[test]
    fn test_lido_st_delta_transition() {
        let mut st_state = lido_state_steth();

        let total_shares_after =
            "0x00000000000000000000000000000000000000000005d9d75ae42b4ba9c04d1a";
        let staking_status_after = "0x4c696d69746564";
        let staking_limit_after = "0x1fc3842bd1f071c00000";

        let mut updated_attributes: HashMap<String, Bytes> = HashMap::new();
        updated_attributes.insert("total_shares".to_owned(), Bytes::from(total_shares_after));
        updated_attributes.insert("staking_status".to_owned(), Bytes::from(staking_status_after));
        updated_attributes.insert("staking_limit".to_owned(), Bytes::from(staking_limit_after));

        let staking_state_delta = ProtocolStateDelta {
            component_id: ST_ETH_ADDRESS_PROXY.to_owned(),
            updated_attributes,
            deleted_attributes: HashSet::new(),
        };

        let mut component_balances = HashMap::new();
        let mut component_balances_inner = HashMap::new();
        component_balances_inner.insert(
            Bytes::from_str(ETH_ADDRESS).unwrap(),
            Bytes::from_str("0x072409d88cbb5e48a01616").unwrap(),
        );
        component_balances.insert(ST_ETH_ADDRESS_PROXY.to_owned(), component_balances_inner);

        let balances = Balances { component_balances, account_balances: HashMap::new() };

        st_state
            .delta_transition(staking_state_delta.clone(), &HashMap::new(), &balances)
            .unwrap();

        let exp = LidoState {
            pool_type: LidoPoolType::StEth,
            total_shares: BigUint::from_bytes_be(
                &hex::decode("00000000000000000000000000000000000000000005d9d75ae42b4ba9c04d1a")
                    .unwrap(),
            ),
            total_pooled_eth: from_hex_str_to_biguint("072409d88cbb5e48a01616"),
            total_wrapped_st_eth: None,
            id: ST_ETH_ADDRESS_PROXY.into(),
            native_address: ETH_ADDRESS.into(),
            stake_limits_state: StakeLimitState {
                staking_status: crate::evm::protocol::lido::state::StakingStatus::Limited,
                staking_limit: BigUint::from_bytes_be(
                    &hex::decode("1fc3842bd1f071c00000").unwrap(),
                ),
            },
            tokens: [
                Bytes::from("0x0000000000000000000000000000000000000000"),
                Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
            ],
            token_to_track_total_pooled_eth: Bytes::from(ETH_ADDRESS),
        };
        assert_eq!(st_state, exp);
    }

    #[rstest]
    #[case::missing_total_shares("total_shares")]
    #[case::missing_staking_status("staking_status")]
    #[case::missing_staking_limit("staking_limit")]
    fn test_lido_st_delta_transition_missing_arg(#[case] missing_attribute: &str) {
        let mut st_state = lido_state_steth();

        let total_shares_after =
            "0x00000000000000000000000000000000000000000005d9d75ae42b4ba9c04d1a";
        let staking_status_after = "0x4c696d69746564";
        let staking_limit_after = "0x1fc3842bd1f071c00000";

        let mut updated_attributes: HashMap<String, Bytes> = HashMap::new();
        updated_attributes.insert("total_shares".to_owned(), Bytes::from(total_shares_after));
        updated_attributes.insert("staking_status".to_owned(), Bytes::from(staking_status_after));
        updated_attributes.insert("staking_limit".to_owned(), Bytes::from(staking_limit_after));

        let mut staking_state_delta = ProtocolStateDelta {
            component_id: ST_ETH_ADDRESS_PROXY.to_owned(),
            updated_attributes,
            deleted_attributes: HashSet::new(),
        };

        let balances =
            Balances { component_balances: HashMap::new(), account_balances: HashMap::new() };

        staking_state_delta
            .updated_attributes
            .remove(missing_attribute);

        assert!(st_state
            .delta_transition(staking_state_delta.clone(), &HashMap::new(), &balances)
            .is_err());
    }

    #[test]
    fn test_lido_wst_delta_transition() {
        let mut wst_state = lido_state_wsteth();

        let total_shares_after =
            "0x00000000000000000000000000000000000000000005d9d75ae42b4ba9c04d1a";
        let total_ws_eth_after =
            "0x00000000000000000000000000000000000000000002ba6f7b9af3c7a7b749e2";

        let mut updated_attributes: HashMap<String, Bytes> = HashMap::new();
        updated_attributes.insert("total_shares".to_owned(), Bytes::from(total_shares_after));
        updated_attributes.insert("total_wstETH".to_owned(), Bytes::from(total_ws_eth_after));

        let staking_state_delta = ProtocolStateDelta {
            component_id: WST_ETH_ADDRESS.to_owned(),
            updated_attributes,
            deleted_attributes: HashSet::new(),
        };

        let mut component_balances = HashMap::new();
        let mut component_balances_inner = HashMap::new();
        component_balances_inner.insert(
            Bytes::from_str(ST_ETH_ADDRESS_PROXY).unwrap(),
            Bytes::from_str("0x072409d88cbb5e48a01616").unwrap(),
        );
        component_balances.insert(WST_ETH_ADDRESS.to_owned(), component_balances_inner);

        let balances = Balances { component_balances, account_balances: HashMap::new() };

        wst_state
            .delta_transition(staking_state_delta, &HashMap::new(), &balances)
            .unwrap();

        let exp = LidoState {
            pool_type: LidoPoolType::WStEth,
            total_shares: BigUint::from_bytes_be(
                &hex::decode("00000000000000000000000000000000000000000005d9d75ae42b4ba9c04d1a")
                    .unwrap(),
            ),
            total_pooled_eth: from_hex_str_to_biguint("072409d88cbb5e48a01616"),
            total_wrapped_st_eth: Some(BigUint::from_bytes_be(
                &hex::decode("00000000000000000000000000000000000000000002ba6f7b9af3c7a7b749e2")
                    .unwrap(),
            )),
            id: ST_ETH_ADDRESS_PROXY.into(),
            native_address: ETH_ADDRESS.into(),
            stake_limits_state: wst_state.stake_limits_state.clone(),
            tokens: [
                Bytes::from("0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"),
                Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
            ],
            token_to_track_total_pooled_eth: Bytes::from(ST_ETH_ADDRESS_PROXY),
        };

        assert_eq!(wst_state, exp);
    }

    #[rstest]
    #[case::missing_total_shares("total_shares")]
    #[case::missing_total_ws_eth("total_wstETH")]
    fn test_lido_wst_delta_transition_missing_arg(#[case] missing_attribute: &str) {
        let mut wst_state = lido_state_wsteth();

        let total_shares_after =
            "0x00000000000000000000000000000000000000000005d9d75ae42b4ba9c04d1a";
        let total_ws_eth_after =
            "0x00000000000000000000000000000000000000000002ba6f7b9af3c7a7b749e2";

        let mut updated_attributes: HashMap<String, Bytes> = HashMap::new();
        updated_attributes.insert("total_shares".to_owned(), Bytes::from(total_shares_after));
        updated_attributes.insert("total_wstETH".to_owned(), Bytes::from(total_ws_eth_after));

        let mut staking_state_delta = ProtocolStateDelta {
            component_id: WST_ETH_ADDRESS.to_owned(),
            updated_attributes,
            deleted_attributes: HashSet::new(),
        };

        let balances =
            Balances { component_balances: HashMap::new(), account_balances: HashMap::new() };

        staking_state_delta
            .updated_attributes
            .remove(missing_attribute);

        assert!(wst_state
            .delta_transition(staking_state_delta.clone(), &HashMap::new(), &balances)
            .is_err());
    }
}
