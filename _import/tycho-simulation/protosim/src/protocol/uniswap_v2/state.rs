use ethers::types::U256;

use tycho_types::{dto::ProtocolStateDelta, hex_bytes::Bytes};

use crate::{
    models::ERC20Token,
    protocol::{
        errors::{TradeSimulationError, TradeSimulationErrorKind, TransitionError},
        events::{check_log_idx, EVMLogMeta, LogIndex},
        models::GetAmountOutResult,
        state::ProtocolSim,
    },
    safe_math::{safe_add_u256, safe_div_u256, safe_mul_u256},
};

use super::{events::UniswapV2Sync, reserve_price::spot_price_from_reserves};

use super::super::uniswap_v3::state::bytes_as_u256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UniswapV2State {
    pub reserve0: U256,
    pub reserve1: U256,
    pub log_index: LogIndex,
}

impl UniswapV2State {
    /// New UniswapV2State
    ///
    /// Create a new instance of UniswapV2State with the given reserves.
    ///
    /// # Arguments
    ///
    /// * `reserve0` - Reserve of token 0.
    /// * `reserve1` - Reserve of token 1.
    pub fn new(reserve0: U256, reserve1: U256) -> Self {
        UniswapV2State { reserve0, reserve1, log_index: (0, 0) }
    }

    pub fn event_transition(
        &mut self,
        msg: &UniswapV2Sync,
        log_meta: &EVMLogMeta,
    ) -> Result<(), TransitionError<LogIndex>> {
        check_log_idx(self.log_index, log_meta)?;
        self.reserve0 = msg.reserve0;
        self.reserve1 = msg.reserve1;
        self.log_index = log_meta.index();
        Ok(())
    }
}

impl ProtocolSim for UniswapV2State {
    /// Returns the fee for the protocol
    ///
    /// # Returns
    ///
    /// * `f64` - Protocol fee.
    fn fee(&self) -> f64 {
        0.003
    }

    /// Returns the pools spot price
    ///
    /// # Arguments
    ///
    /// * `base` - Base token
    /// * `quote` - Quote token
    ///
    /// # Returns
    ///
    /// * `f64` - Spot price of the tokens.
    fn spot_price(&self, base: &ERC20Token, quote: &ERC20Token) -> f64 {
        if base < quote {
            spot_price_from_reserves(
                self.reserve0,
                self.reserve1,
                base.decimals as u32,
                quote.decimals as u32,
            )
        } else {
            spot_price_from_reserves(
                self.reserve1,
                self.reserve0,
                base.decimals as u32,
                quote.decimals as u32,
            )
        }
    }

    /// Returns the amount of output for a given amount of input
    ///
    /// # Arguments
    ///
    /// * `amount_in` - The amount of input for the trade.
    /// * `token_in` - The input token ERC20 token.
    /// * `token_out` - The output token ERC20 token.
    ///
    /// # Returns
    ///
    /// * `Result<GetAmountOutResult, TradeSimulationError>` - A `Result` containing the amount of
    ///   output and the slippage of the trade, or an error.
    fn get_amount_out(
        &self,
        amount_in: U256,
        token_in: &ERC20Token,
        token_out: &ERC20Token,
    ) -> Result<GetAmountOutResult, TradeSimulationError> {
        if amount_in == U256::zero() {
            return Result::Err(TradeSimulationError::new(
                TradeSimulationErrorKind::InsufficientAmount,
                None,
            ));
        }
        let zero2one = token_in.address < token_out.address;
        let reserve_sell = if zero2one { self.reserve0 } else { self.reserve1 };
        let reserve_buy = if zero2one { self.reserve1 } else { self.reserve0 };

        if reserve_sell == U256::zero() || reserve_buy == U256::zero() {
            return Result::Err(TradeSimulationError::new(
                TradeSimulationErrorKind::NoLiquidity,
                None,
            ));
        }

        let amount_in_with_fee = safe_mul_u256(amount_in, U256::from(997))?;
        let numerator = safe_mul_u256(amount_in_with_fee, reserve_buy)?;
        let denominator =
            safe_add_u256(safe_mul_u256(reserve_sell, U256::from(1000))?, amount_in_with_fee)?;

        let amount_out = safe_div_u256(numerator, denominator)?;

        Ok(GetAmountOutResult::new(amount_out, U256::from(120_000)))
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
    ) -> Result<(), TransitionError<String>> {
        // reserve0 and reserve1 are considered required attributes and are expected in every delta
        // we process
        self.reserve0 = bytes_as_u256(
            delta
                .updated_attributes
                .get("reserve0")
                .ok_or(TransitionError::MissingAttribute("reserve0".to_string()))?,
        )
        .map_err(|err| TransitionError::DecodeError(err.to_string()))?;
        self.reserve1 = bytes_as_u256(
            delta
                .updated_attributes
                .get("reserve1")
                .ok_or(TransitionError::MissingAttribute("reserve1".to_string()))?,
        )
        .map_err(|err| TransitionError::DecodeError(err.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        str::FromStr,
    };

    use super::*;
    use approx::assert_ulps_eq;
    use ethers::types::{H160, H256};
    use rstest::rstest;

    fn u256(s: &str) -> U256 {
        U256::from_dec_str(s).unwrap()
    }

    #[rstest]
    #[case::same_dec(
        u256("6770398782322527849696614"),
        u256("5124813135806900540214"),
        18,
        18,
        u256("10000000000000000000000"),
        u256("7535635391574243447")
    )]
    #[case::diff_dec(
        u256("33372357002392258830279"),
        u256("43356945776493"),
        18,
        6,
        u256("10000000000000000000"),
        u256("12949029867")
    )]
    fn test_get_amount_out(
        #[case] r0: U256,
        #[case] r1: U256,
        #[case] t0d: usize,
        #[case] t1d: usize,
        #[case] amount_in: U256,
        #[case] exp: U256,
    ) {
        let t0 = ERC20Token::new("0x0000000000000000000000000000000000000000", t0d, "T0");
        let t1 = ERC20Token::new("0x0000000000000000000000000000000000000001", t1d, "T0");
        let state = UniswapV2State::new(r0, r1);

        let res = state
            .get_amount_out(amount_in, &t0, &t1)
            .unwrap();

        assert_eq!(res.amount, exp);
    }

    #[test]
    fn test_get_amount_out_overflow() {
        let r0 = u256("33372357002392258830279");
        let r1 = u256("43356945776493");
        let amount_in = U256::max_value();
        let t0d = 18;
        let t1d = 16;
        let t0 = ERC20Token::new("0x0000000000000000000000000000000000000000", t0d, "T0");
        let t1 = ERC20Token::new("0x0000000000000000000000000000000000000001", t1d, "T0");
        let state = UniswapV2State::new(r0, r1);

        let res = state.get_amount_out(amount_in, &t0, &t1);
        assert!(res.is_err());
        assert_eq!(res.err().unwrap().kind, TradeSimulationErrorKind::U256Overflow)
    }

    #[rstest]
    #[case(true, 0.0008209719947624441f64)]
    #[case(false, 1218.0683462769755f64)]
    fn test_spot_price(#[case] zero_to_one: bool, #[case] exp: f64) {
        let state = UniswapV2State::new(u256("36925554990922"), u256("30314846538607556521556"));
        let usdc = ERC20Token::new("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6, "USDC");
        let weth = ERC20Token::new("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 ", 18, "WETH");

        let res = if zero_to_one {
            state.spot_price(&usdc, &weth)
        } else {
            state.spot_price(&weth, &usdc)
        };

        assert_ulps_eq!(res, exp);
    }

    #[test]
    fn test_fee() {
        let state = UniswapV2State::new(u256("36925554990922"), u256("30314846538607556521556"));

        let res = state.fee();

        assert_ulps_eq!(res, 0.003);
    }

    #[test]
    fn test_event_transition() {
        let mut state = UniswapV2State::new(u256("1000"), u256("1000"));
        let event = UniswapV2Sync::new(u256("1500"), u256("2000"));
        let log_meta = EVMLogMeta::new(
            H160::from_str("0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5").unwrap(),
            1,
            H256::from_str("0xe4ea49424508471a7f83633fe97dbbee641ddecb106e187896b27e09d0d05e1c")
                .unwrap(),
            1,
            H256::from_str("0xe64a78e6e0fe611ecbf8e079ecb032985f5f08a5d9acba5910f27ec8be8095a9")
                .unwrap(),
            1,
        );

        state
            .event_transition(&event, &log_meta)
            .unwrap();

        assert_eq!(state.reserve0, u256("1500"));
        assert_eq!(state.reserve1, u256("2000"));
        assert_eq!(state.log_index, log_meta.index());
    }

    #[test]
    fn test_delta_transition() {
        let mut state = UniswapV2State::new(u256("1000"), u256("1000"));
        let attributes: HashMap<String, Bytes> = vec![
            ("reserve0".to_string(), Bytes::from(1500_u64.to_le_bytes().to_vec())),
            ("reserve1".to_string(), Bytes::from(2000_u64.to_le_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        let delta = ProtocolStateDelta {
            component_id: "State1".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(), // usv2 doesn't have any deletable attributes
        };

        let res = state.delta_transition(delta);

        assert!(res.is_ok());
        assert_eq!(state.reserve0, u256("1500"));
        assert_eq!(state.reserve1, u256("2000"));
    }

    #[test]
    fn test_delta_transition_missing_attribute() {
        let mut state = UniswapV2State::new(u256("1000"), u256("1000"));
        let attributes: HashMap<String, Bytes> =
            vec![("reserve0".to_string(), Bytes::from(1500_u64.to_be_bytes().to_vec()))]
                .into_iter()
                .collect();
        let delta = ProtocolStateDelta {
            component_id: "State1".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(),
        };

        let res = state.delta_transition(delta);

        assert!(res.is_err());
        // assert it errors for the missing reserve1 attribute delta
        match res {
            Err(e) => {
                assert!(matches!(e, TransitionError::MissingAttribute(ref x) if x=="reserve1"))
            }
            _ => panic!("Test failed: was expecting an Err value"),
        };
    }
}
