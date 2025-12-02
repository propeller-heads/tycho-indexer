use std::{any::Any, collections::HashMap};

use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use tycho_common::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::{
        errors::{SimulationError, TransitionError},
        protocol_sim::{Balances, GetAmountOutResult, ProtocolSim},
    },
    Bytes,
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
    pub stake_limits_state: StakeLimitState, //only needed for steth
}

// impl LidoState {
//     fn steth_swap(
//         &self,
//         amount_in: BigUint,
//         total_pooled_eth: BigUint,
//         total_shares: BigUint,
//     ) -> BigUint {
//         todo!()
//     }

//     fn wsteth_swap(&self, token_in: Bytes, token_out: Bytes, amount_in: BigUint) {
//         todo!()
//     }
// }

impl ProtocolSim for LidoState {
    fn fee(&self) -> f64 {
        // there is no fee when swapping
        0.0
    }

    // price_stETH_per_wstETH = totalPooledEther / totalShares
    // price_ETH_per_wstETH   = totalPooledEther / totalShares
    // price_stETH_per_share = totalPooledEther / totalShares

    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError> {
        match self.pool_type {
            LidoPoolType::StEth => {
                if base.address == Bytes::from(ETH_ADDRESS) &&
                    quote.address == Bytes::from(ST_ETH_ADDRESS_PROXY)
                {
                    Ok(1.0)
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
                    Ok((self.total_shares.clone() / self.total_pooled_eth.clone())
                        .to_f64()
                        .unwrap())
                } else if base.address == Bytes::from(WST_ETH_ADDRESS) &&
                    quote.address == Bytes::from(ST_ETH_ADDRESS_PROXY)
                {
                    Ok((self.total_pooled_eth.clone() / self.total_shares.clone())
                        .to_f64()
                        .unwrap())
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
                    let total_pooled_eth = self.total_pooled_eth.clone();
                    let total_shares = self.total_shares.clone();
                    let shares =
                        amount_in.clone() * (total_shares.clone() / total_pooled_eth.clone());
                    let amount_out = shares.clone() * (total_pooled_eth / total_shares);
                    Ok(GetAmountOutResult {
                        amount: amount_out,
                        gas: BigUint::from(DEFAULT_GAS),
                        new_state: Box::new(Self {
                            pool_type: self.pool_type.clone(),
                            total_shares: self.total_shares.clone() + shares,
                            total_pooled_eth: self.total_pooled_eth.clone() + amount_in,
                            total_wrapped_st_eth: None,
                            id: self.id.clone(),
                            native_address: self.native_address.clone(),
                            stake_limits_state: self.stake_limits_state.clone(), /* this has to
                                                                                  * be
                                                                                  * updated I think */
                        }),
                    })
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
                    let amount_out = if self.total_pooled_eth.is_zero() {
                        amount_in
                    } else {
                        amount_in * (self.total_shares.clone() / self.total_pooled_eth.clone())
                    };
                    Ok(GetAmountOutResult {
                        amount: amount_out.clone(),
                        gas: BigUint::from(DEFAULT_GAS),
                        new_state: Box::new(Self {
                            pool_type: self.pool_type.clone(),
                            total_shares: self.total_shares.clone(),
                            total_pooled_eth: self.total_pooled_eth.clone(),
                            total_wrapped_st_eth: Some(
                                self.total_wrapped_st_eth
                                    .clone()
                                    .unwrap() +
                                    amount_out,
                            ),
                            id: self.id.clone(),
                            native_address: self.native_address.clone(),
                            stake_limits_state: self.stake_limits_state.clone(),
                        }),
                    })
                } else if token_in.address == Bytes::from(WST_ETH_ADDRESS) &&
                    token_out.address == Bytes::from(ST_ETH_ADDRESS_PROXY)
                {
                    let amount_out =
                        amount_in * self.total_pooled_eth.clone() / self.total_shares.clone();

                    Ok(GetAmountOutResult {
                        amount: amount_out.clone(),
                        gas: BigUint::from(DEFAULT_GAS),
                        new_state: Box::new(Self {
                            pool_type: self.pool_type.clone(),
                            total_shares: self.total_shares.clone(),
                            total_pooled_eth: self.total_pooled_eth.clone(),
                            total_wrapped_st_eth: Some(
                                self.total_wrapped_st_eth
                                    .clone()
                                    .unwrap() -
                                    amount_out,
                            ),
                            id: self.id.clone(),
                            native_address: self.native_address.clone(),
                            stake_limits_state: self.stake_limits_state.clone(),
                        }),
                    })
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
        buy_token: Bytes,
        sell_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        // If it's the stETH type:
        //   - and the buy token is ETH, the limits are 0
        //   - sell token is ETH: use the StakeLimitState
        // If it's wstETH: rely on the total supply (I think)
        match self.pool_type {
            LidoPoolType::StEth => {
                if buy_token == Bytes::from(ST_ETH_ADDRESS_PROXY) &&
                    sell_token == Bytes::from(ETH_ADDRESS)
                {
                    let limit = self.stake_limits_state.get_limit();
                    Ok((limit.clone(), limit))
                } else if buy_token == Bytes::from(ETH_ADDRESS) &&
                    sell_token == Bytes::from(ST_ETH_ADDRESS_PROXY)
                {
                    Ok((self.total_pooled_eth.clone(), self.total_shares.clone()))
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
            LidoPoolType::WStEth => {
                if buy_token == Bytes::from(ST_ETH_ADDRESS_PROXY) &&
                    sell_token == Bytes::from(WST_ETH_ADDRESS)
                {
                    // total_shares - wstETH
                    let limit_for_wrapping = self.total_shares.clone() -
                        self.total_wrapped_st_eth
                            .clone()
                            .unwrap();
                    Ok((limit_for_wrapping.clone(), limit_for_wrapping))
                } else if buy_token == Bytes::from(WST_ETH_ADDRESS) &&
                    sell_token == Bytes::from(ST_ETH_ADDRESS_PROXY)
                {
                    //amount of wsteth
                    Ok((
                        self.total_wrapped_st_eth
                            .clone()
                            .unwrap(),
                        self.total_wrapped_st_eth
                            .clone()
                            .unwrap(),
                    ))
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
        }
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        if delta.component_id == ST_ETH_ADDRESS_PROXY {
            self.total_pooled_eth = BigUint::from_bytes_be(
                delta
                    .updated_attributes
                    .get("total_pooled_eth")
                    .unwrap(),
            );
            self.total_shares = BigUint::from_bytes_be(
                delta
                    .updated_attributes
                    .get("total_shares")
                    .unwrap(),
            );

            let staking_status = delta
                .updated_attributes
                .get("staking_status")
                .ok_or(TransitionError::MissingAttribute(
                    "Staking_status field is missing".to_owned(),
                ))?;

            let staking_status_parsed =
                if let Ok(status_as_str) = std::str::from_utf8(staking_status) {
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
                    return Err(TransitionError::DecodeError(
                        "status_as_str cannot be parsed".to_owned(),
                    ))
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
        } else if delta.component_id == WST_ETH_ADDRESS {
            self.total_pooled_eth = BigUint::from_bytes_be(
                delta
                    .updated_attributes
                    .get("total_pooled_eth")
                    .unwrap(),
            );
            self.total_shares = BigUint::from_bytes_be(
                delta
                    .updated_attributes
                    .get("total_shares")
                    .unwrap(),
            );
            self.total_shares = BigUint::from_bytes_be(
                delta
                    .updated_attributes
                    .get("total_wstETH")
                    .unwrap(),
            );
        }

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
}
