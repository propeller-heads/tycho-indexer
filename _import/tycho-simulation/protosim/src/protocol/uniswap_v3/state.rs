use ethers::types::{Sign, I256, U256};

use crate::{
    models::ERC20Token,
    protocol::{
        errors::{TradeSimulationError, TradeSimulationErrorKind, TransitionError},
        events::{check_log_idx, EVMLogMeta, LogIndex},
        models::GetAmountOutResult,
        state::ProtocolSim,
    },
};
use crate::safe_math::{safe_add_u256, safe_sub_u256};

use super::{
    enums::FeeAmount,
    events::UniswapV3Event,
    liquidity_math,
    sqrt_price_math::sqrt_price_q96_to_f64,
    swap_math,
    tick_list::{TickInfo, TickList},
    tick_math,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniswapV3State {
    liquidity: u128,
    sqrt_price: U256,
    fee: FeeAmount,
    tick: i32,
    ticks: TickList,
    log_index: LogIndex,
}

#[derive(Debug)]
struct SwapState {
    amount_remaining: I256,
    amount_calculated: I256,
    sqrt_price: U256,
    tick: i32,
    liquidity: u128,
}

#[derive(Debug)]
struct StepComputation {
    sqrt_price_start: U256,
    tick_next: i32,
    initialized: bool,
    sqrt_price_next: U256,
    amount_in: U256,
    amount_out: U256,
    fee_amount: U256,
}

// TODO: these attributes allow updating the state after a swap
#[allow(dead_code)]
struct SwapResults {
    amount_calculated: I256,
    sqrt_price: U256,
    liquidity: u128,
    tick: i32,
    gas_used: U256,
}

impl UniswapV3State {
    pub fn new(
        liquidity: u128,
        sqrt_price: U256,
        fee: FeeAmount,
        tick: i32,
        ticks: Vec<TickInfo>,
    ) -> Self {
        let spacing = UniswapV3State::get_spacing(fee);
        let tick_list = TickList::from(spacing, ticks);
        UniswapV3State {
            liquidity,
            sqrt_price,
            fee,
            tick,
            ticks: tick_list,
            log_index: (0, 0),
        }
    }

    fn get_spacing(fee: FeeAmount) -> u16 {
        match fee {
            FeeAmount::Lowest => 1,
            FeeAmount::Low => 10,
            FeeAmount::Medium => 60,
            FeeAmount::High => 200,
        }
    }

    pub fn transition(
        &mut self,
        event: &UniswapV3Event,
        log_meta: &EVMLogMeta,
    ) -> Result<(), TransitionError<LogIndex>> {
        check_log_idx(self.log_index, log_meta)?;
        match event {
            UniswapV3Event::Mint(data) => {
                let amount = data.amount as i128;
                self.handle_liquidity_change(data.tick_lower, data.tick_upper, amount);
            }
            UniswapV3Event::Burn(data) => {
                let amount = data.amount as i128;
                self.handle_liquidity_change(data.tick_lower, data.tick_upper, -amount);
            }
            UniswapV3Event::Swap(data) => {
                self.liquidity = data.liquidity;
                self.tick = data.tick;
                self.sqrt_price = data.sqrt_price;
            }
        }
        Ok(())
    }

    fn handle_liquidity_change(&mut self, lower: i32, upper: i32, amount: i128) {
        if amount != 0 {
            if lower <= self.tick && self.tick < upper {
                // self.liquidity is always positive
                if amount < 0 {
                    self.liquidity -= amount.unsigned_abs();
                } else {
                    self.liquidity += amount as u128;
                }
            }
            self.ticks.apply_liquidity_change(lower, upper, amount);
        }
    }

    fn swap(
        &self,
        zero_for_one: bool,
        amount_specified: I256,
        sqrt_price_limit: Option<U256>,
    ) -> Result<SwapResults, TradeSimulationError> {
        if self.liquidity == 0 {
            return Err(TradeSimulationError::new(
                TradeSimulationErrorKind::NoLiquidity,
                None,
            ));
        }
        let price_limit = if let Some(limit) = sqrt_price_limit {
            limit
        } else if zero_for_one {
            safe_add_u256(tick_math::MIN_SQRT_RATIO, U256::one())?
        } else {
            safe_sub_u256(tick_math::MAX_SQRT_RATIO, U256::one())?
        };

        if zero_for_one {
            assert!(price_limit > tick_math::MIN_SQRT_RATIO);
            assert!(price_limit < self.sqrt_price);
        } else {
            assert!(price_limit < tick_math::MAX_SQRT_RATIO);
            assert!(price_limit > self.sqrt_price);
        }

        let exact_input = amount_specified > I256::zero();

        let mut state = SwapState {
            amount_remaining: amount_specified,
            amount_calculated: I256::zero(),
            sqrt_price: self.sqrt_price,
            tick: self.tick,
            liquidity: self.liquidity,
        };
        let mut gas_used = U256::from(130_000);

        while state.amount_remaining != I256::zero() && state.sqrt_price != price_limit {
            let (mut next_tick, initialized) = match self
                .ticks
                .next_initialized_tick_within_one_word(state.tick, zero_for_one)
            {
                Ok((tick, init)) => (tick, init),
                Err(tick_err) => match tick_err.kind {
                    super::tick_list::TickListErrorKind::TicksExeeded => {
                        return Err(TradeSimulationError::new(
                            TradeSimulationErrorKind::InsufficientData,
                            Some(GetAmountOutResult::new(
                                state.amount_calculated.abs().into_raw(),
                                gas_used,
                            )),
                        ));
                    }
                    _ => {
                        return Err(TradeSimulationError::new(
                            TradeSimulationErrorKind::Unkown,
                            None,
                        ));
                    }
                },
            };

            next_tick = next_tick.clamp(tick_math::MIN_TICK, tick_math::MAX_TICK);

            let sqrt_price_next = tick_math::get_sqrt_ratio_at_tick(next_tick)?;
                         let (sqrt_price, amount_in, amount_out, fee_amount) = if let Ok((sqrt_price, amount_in, amount_out, fee_amount)) = swap_math::compute_swap_step(
                state.sqrt_price,
                UniswapV3State::get_sqrt_ratio_target(sqrt_price_next, price_limit, zero_for_one),
                state.liquidity,
                state.amount_remaining,
                self.fee as u32,) { (sqrt_price, amount_in, amount_out, fee_amount) } else { todo!() };
            // let Ok((sqrt_price, amount_in, amount_out, fee_amount)) = swap_math::compute_swap_step(
            //     state.sqrt_price,
            //     UniswapV3State::get_sqrt_ratio_target(sqrt_price_next?, price_limit, zero_for_one),
            //     state.liquidity,
            //     state.amount_remaining,
            //     self.fee as u32,
            // );
            state.sqrt_price = sqrt_price;
            let sqrt_price_next = sqrt_price_next;

            let step = StepComputation {
                sqrt_price_start: state.sqrt_price,
                tick_next: next_tick,
                initialized,
                sqrt_price_next,
                amount_in,
                amount_out,
                fee_amount,
            };
            if exact_input {
                state.amount_remaining -= I256::checked_from_sign_and_abs(
                        Sign::Positive,
                        safe_add_u256(step.amount_in ,step.fee_amount)?,
                    )
                    .unwrap();
                state.amount_calculated -= I256::checked_from_sign_and_abs(Sign::Positive, step.amount_out).unwrap();
            } else {
                state.amount_remaining += I256::checked_from_sign_and_abs(Sign::Positive, step.amount_out).unwrap();
                state.amount_calculated += I256::checked_from_sign_and_abs(
                        Sign::Positive,
                        safe_add_u256(step.amount_in ,step.fee_amount)?,
                    )
                    .unwrap();
            }
            if state.sqrt_price == step.sqrt_price_next {
                if step.initialized {
                    let liquidity_raw = self.ticks.get_tick(step.tick_next).unwrap().net_liquidity;
                    let liquidity_net = if zero_for_one {
                        -liquidity_raw
                    } else {
                        liquidity_raw
                    };
                    state.liquidity =
                        liquidity_math::add_liquidity_delta(state.liquidity, liquidity_net);
                }
                state.tick = if zero_for_one {
                    step.tick_next - 1
                } else {
                    step.tick_next
                };
            } else if state.sqrt_price != step.sqrt_price_start {
                state.tick = tick_math::get_tick_at_sqrt_ratio(state.sqrt_price)?;
            }
            gas_used = safe_add_u256(gas_used,U256::from(2000))?;
        }
        Ok(SwapResults {
            amount_calculated: state.amount_calculated,
            sqrt_price: state.sqrt_price,
            liquidity: state.liquidity,
            tick: state.tick,
            gas_used,
        })
    }

    fn get_sqrt_ratio_target(
        sqrt_price_next: U256,
        sqrt_price_limit: U256,
        zero_for_one: bool,
    ) -> U256 {
        let cond1 = if zero_for_one {
            sqrt_price_next < sqrt_price_limit
        } else {
            sqrt_price_next > sqrt_price_limit
        };

        if cond1 {
            sqrt_price_limit
        } else {
            sqrt_price_next
        }
    }
}

impl ProtocolSim for UniswapV3State {
    fn fee(&self) -> f64 {
        (self.fee as u32) as f64 / 1_000_000.0
    }

    fn spot_price(&self, a: &ERC20Token, b: &ERC20Token) -> f64 {
        if a < b {
            sqrt_price_q96_to_f64(self.sqrt_price, a.decimals as u32, b.decimals as u32)
        } else {
            1.0f64 / sqrt_price_q96_to_f64(self.sqrt_price, b.decimals as u32, a.decimals as u32)
        }
    }

    fn get_amount_out(
        &self,
        amount_in: U256,
        token_a: &ERC20Token,
        token_b: &ERC20Token,
    ) -> Result<GetAmountOutResult, TradeSimulationError> {
        let zero_for_one = token_a < token_b;
        let amount_specified = I256::checked_from_sign_and_abs(Sign::Positive, amount_in).unwrap();

        let result = self.swap(zero_for_one, amount_specified, None)?;

        Ok(GetAmountOutResult::new(
            result.amount_calculated.abs().into_raw(),
            result.gas_used,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ethers::types::{H160, H256};
    use rstest::rstest;

    use crate::protocol::uniswap_v3::events::{SwapEvent, BurnEvent, MintEvent};
    use crate::safe_math::safe_mul_u256;

    use super::*;

    #[test]
    fn test_get_amount_out_full_range_liquidity() {
        let token_x = ERC20Token::new("0x6b175474e89094c44da98b954eedeac495271d0f", 18, "X");
        let token_y = ERC20Token::new("0xf1ca9cb74685755965c7458528a36934df52a3ef", 18, "Y");

        let pool = UniswapV3State::new(
            8330443394424070888454257,
            U256::from_dec_str("188562464004052255423565206602").unwrap(),
            FeeAmount::Medium,
            17342,
            vec![TickInfo::new(0, 0), TickInfo::new(46080, 0)],
        );
        let sell_amount = U256::from(11000)* U256::exp10(18);
        let expected = U256::from_dec_str("61927070842678722935941").unwrap();

        let res = pool
            .get_amount_out(sell_amount, &token_x, &token_y)
            .unwrap();

        assert_eq!(res.amount, expected);
    }

    struct SwapTestCase {
        symbol: &'static str,
        sell: U256,
        exp: U256,
    }

    #[test]
    fn test_get_amount_out() {
        let wbtc = ERC20Token::new("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", 8, "WBTC");
        let weth = ERC20Token::new("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 18, "WETH");
        let pool = UniswapV3State::new(
            377952820878029838,
            U256::from_dec_str("28437325270877025820973479874632004").unwrap(),
            FeeAmount::Low,
            255830,
            vec![
                TickInfo::new(255760, 1759015528199933i128),
                TickInfo::new(255770, 6393138051835308i128),
                TickInfo::new(255780, 228206673808681i128),
                TickInfo::new(255820, 1319490609195820i128),
                TickInfo::new(255830, 678916926147901i128),
                TickInfo::new(255840, 12208947683433103i128),
                TickInfo::new(255850, 1177970713095301i128),
                TickInfo::new(255860, 8752304680520407i128),
                TickInfo::new(255880, 1486478248067104i128),
                TickInfo::new(255890, 1878744276123248i128),
                TickInfo::new(255900, 77340284046725227i128),
            ],
        );
        let cases = vec![
            SwapTestCase {
                symbol: "WBTC",
                sell: U256::from_dec_str("500000000").unwrap(),
                exp: U256::from_dec_str("64352395915550406461").unwrap(),
            },
            SwapTestCase {
                symbol: "WBTC",
                sell: U256::from_dec_str("550000000").unwrap(),
                exp: U256::from_dec_str("70784271504035662865").unwrap(),
            },
            SwapTestCase {
                symbol: "WBTC",
                sell: U256::from_dec_str("600000000").unwrap(),
                exp: U256::from_dec_str("77215534856185613494").unwrap(),
            },
            SwapTestCase {
                symbol: "WBTC",
                sell: U256::from_dec_str("1000000000").unwrap(),
                exp: U256::from_dec_str("128643569649663616249").unwrap(),
            },
            SwapTestCase {
                symbol: "WBTC",
                sell: U256::from_dec_str("3000000000").unwrap(),
                exp: U256::from_dec_str("385196519076234662939").unwrap(),
            },
            SwapTestCase {
                symbol: "WETH",
                sell: U256::from_dec_str("64000000000000000000").unwrap(),
                exp: U256::from_dec_str("496294784").unwrap(),
            },
            SwapTestCase {
                symbol: "WETH",
                sell: U256::from_dec_str("70000000000000000000").unwrap(),
                exp: U256::from_dec_str("542798479").unwrap(),
            },
            SwapTestCase {
                symbol: "WETH",
                sell: U256::from_dec_str("77000000000000000000").unwrap(),
                exp: U256::from_dec_str("597047757").unwrap(),
            },
            SwapTestCase {
                symbol: "WETH",
                sell: U256::from_dec_str("128000000000000000000").unwrap(),
                exp: U256::from_dec_str("992129037").unwrap(),
            },
            SwapTestCase {
                symbol: "WETH",
                sell: U256::from_dec_str("385000000000000000000").unwrap(),
                exp: U256::from_dec_str("2978713582").unwrap(),
            },
        ];

        for case in cases {
            let (token_a, token_b) = if case.symbol == "WBTC" {
                (&wbtc, &weth)
            } else {
                (&weth, &wbtc)
            };
            let res = pool.get_amount_out(case.sell, token_a, token_b).unwrap();

            assert_eq!(res.amount, case.exp);
        }
    }

    #[test]
    fn test_err_with_partial_trade() {
        let dai = ERC20Token::new("0x6b175474e89094c44da98b954eedeac495271d0f", 18, "DAI");
        let usdc = ERC20Token::new("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6, "USDC");
        let pool = UniswapV3State::new(
            73015811375239994,
            U256::from_dec_str("148273042406850898575413").unwrap(),
            FeeAmount::High,
            -263789,
            vec![
                TickInfo::new(-269600, 3612326326695492i128),
                TickInfo::new(-268800, 1487613939516867i128),
                TickInfo::new(-267800, 1557587121322546i128),
                TickInfo::new(-267400, 424592076717375i128),
                TickInfo::new(-267200, 11691597431643916i128),
                TickInfo::new(-266800, -218742815100986i128),
                TickInfo::new(-266600, 1118947532495477i128),
                TickInfo::new(-266200, 1233064286622365i128),
                TickInfo::new(-265000, 4252603063356107i128),
                TickInfo::new(-263200, -351282010325232i128),
                TickInfo::new(-262800, -2352011819117842i128),
                TickInfo::new(-262600, -424592076717375i128),
                TickInfo::new(-262200, -11923662433672566i128),
                TickInfo::new(-261600, -2432911749667741i128),
                TickInfo::new(-260200, -4032727022572273i128),
                TickInfo::new(-260000, -22889492064625028i128),
                TickInfo::new(-259400, -1557587121322546i128),
                TickInfo::new(-259200, -1487613939516867i128),
                TickInfo::new(-258400, -400137022888262i128),
            ],
        );
        let amount_in = U256::from_dec_str("50000000000").unwrap();
        let exp = U256::from_dec_str("6820591625999718100883").unwrap();

        let err = pool.get_amount_out(amount_in, &usdc, &dai).unwrap_err();
        let res = err.partial_result.unwrap();

        assert_eq!(err.kind, TradeSimulationErrorKind::InsufficientData);
        assert_eq!(res.amount, exp);
    }


    fn logmeta()-> EVMLogMeta{
        EVMLogMeta {
            from: H160::from_str("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599").unwrap(),
            block_number: 1,
            block_hash: H256::from_str(
                "0x8b1cc9f28716bc7c994db5442dd9bb53b90b73f2f6ef7956fd16ab59ecc6f7ad",
            )
            .unwrap(),
            transaction_index: 1,
            transaction_hash: H256::from_str(
                "0x8a9b8d0cbbace89ea6d8e70f5a1f69a4ae129b11dccd6d13e96eee71a5c0e446",
            )
            .unwrap(),
            log_index: 1,
        }
    }

    #[rstest]
    #[case::mint_existing_ticks(
        MintEvent::new(
            255760,
            255900,
            200,
        ).into(), 
        (255760, Some(10200)), 
        (255900, Some(-10200)),
        10000200,
    )]
    #[case::burn_existing_ticks(
        BurnEvent::new(
            255760,
            255900,
            200,
        ).into(), 
        (255760, Some(9800)), 
        (255900, Some(-9800)),
        9999800,
    )]
    #[case::mint_new_tick(
        MintEvent::new(
            255770,
            255900,
            200,
        ).into(), 
        (255770, Some(200)), 
        (255900, Some(-10200)),
        10000200,
    )]
    #[case::burn_new_tick(
        BurnEvent::new(
            255770,
            255900,
            200,
        ).into(), 
        (255770, Some(-200)), 
        (255900, Some(-9800)),
        9999800
    )]
    fn test_transition_liquidity(
        #[case] event: UniswapV3Event,
        #[case] exp_lower: (i32, Option<i128>),
        #[case] exp_upper: (i32, Option<i128>),
        #[case] exp_pool_liq: u128,
    ) {
        let mut pool = UniswapV3State::new(
            10000000,
            U256::from_dec_str("28437325270877025820973479874632004").unwrap(),
            FeeAmount::Low,
            255830,
            vec![TickInfo::new(255760, 10000), TickInfo::new(255900, -10000)],
        );
        
        pool.transition(&event, &logmeta()).unwrap();

        if let (tick, Some(liq_lower)) = exp_lower {
            assert_eq!(pool.ticks.get_tick(tick).unwrap().net_liquidity, liq_lower)
        }

        if let (tick, Some(liq_upper)) = exp_upper {
            assert_eq!(pool.ticks.get_tick(tick).unwrap().net_liquidity, liq_upper)
        }

        assert_eq!(pool.liquidity, exp_pool_liq)
    }
    
    #[test]
    fn test_transition_swap(){
        let mut pool = UniswapV3State::new(
            1000,
            U256::from_dec_str("1000").unwrap(),
            FeeAmount::Low,
            100,
            vec![TickInfo::new(255760, 10000), TickInfo::new(255900, -10000)],
        );
        let event = SwapEvent::new(U256::from(1001), 2000, 120).into();

        pool.transition(&event, &logmeta()).unwrap();

        assert_eq!(pool.sqrt_price, U256::from(1001));
        assert_eq!(pool.liquidity, 2000);
        assert_eq!(pool.tick, 120);
    }

}
