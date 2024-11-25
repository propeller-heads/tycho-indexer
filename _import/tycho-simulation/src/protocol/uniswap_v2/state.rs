use std::any::Any;

use ethers::types::U256;

use crate::{
    models::ERC20Token,
    protocol::{
        errors::{SimulationError, TransitionError},
        events::{check_log_idx, EVMLogMeta, LogIndex},
        models::GetAmountOutResult,
        state::{ProtocolEvent, ProtocolSim},
    },
    safe_math::{safe_add_u256, safe_div_u256, safe_mul_u256, safe_sub_u256},
};
use tycho_core::dto::ProtocolStateDelta;
use tycho_ethereum::BytesCodec;

use super::{events::UniswapV2Sync, reserve_price::spot_price_from_reserves};

#[derive(Clone, Debug, PartialEq, Eq)]
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
    fn spot_price(&self, base: &ERC20Token, quote: &ERC20Token) -> Result<f64, SimulationError> {
        if base < quote {
            Ok(spot_price_from_reserves(
                self.reserve0,
                self.reserve1,
                base.decimals as u32,
                quote.decimals as u32,
            ))
        } else {
            Ok(spot_price_from_reserves(
                self.reserve1,
                self.reserve0,
                base.decimals as u32,
                quote.decimals as u32,
            ))
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
    ) -> Result<GetAmountOutResult, SimulationError> {
        if amount_in == U256::zero() {
            return Err(SimulationError::RetryDifferentInput(
                "Amount in cannot be zero".to_string(),
            ));
        }
        let zero2one = token_in.address < token_out.address;
        let reserve_sell = if zero2one { self.reserve0 } else { self.reserve1 };
        let reserve_buy = if zero2one { self.reserve1 } else { self.reserve0 };

        if reserve_sell == U256::zero() || reserve_buy == U256::zero() {
            return Err(SimulationError::RetryLater("No liquidity".to_string()));
        }

        let amount_in_with_fee = safe_mul_u256(amount_in, U256::from(997))?;
        let numerator = safe_mul_u256(amount_in_with_fee, reserve_buy)?;
        let denominator =
            safe_add_u256(safe_mul_u256(reserve_sell, U256::from(1000))?, amount_in_with_fee)?;

        let amount_out = safe_div_u256(numerator, denominator)?;
        let mut new_state = self.clone();
        if zero2one {
            new_state.reserve0 = safe_add_u256(self.reserve0, amount_in)?;
            new_state.reserve1 = safe_sub_u256(self.reserve1, amount_out)?;
        } else {
            new_state.reserve0 = safe_sub_u256(self.reserve0, amount_out)?;
            new_state.reserve1 = safe_add_u256(self.reserve1, amount_in)?;
        };
        Ok(GetAmountOutResult::new(amount_out, U256::from(120_000), Box::new(new_state)))
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: Vec<ERC20Token>,
    ) -> Result<(), TransitionError<String>> {
        // reserve0 and reserve1 are considered required attributes and are expected in every delta
        // we process
        self.reserve0 = U256::from_bytes(
            delta
                .updated_attributes
                .get("reserve0")
                .ok_or(TransitionError::MissingAttribute("reserve0".to_string()))?,
        );
        self.reserve1 = U256::from_bytes(
            delta
                .updated_attributes
                .get("reserve1")
                .ok_or(TransitionError::MissingAttribute("reserve1".to_string()))?,
        );
        Ok(())
    }
    fn event_transition(
        &mut self,
        protocol_event: Box<dyn ProtocolEvent>,
        log_meta: &EVMLogMeta,
    ) -> Result<(), TransitionError<LogIndex>> {
        if let Some(sync_event) = protocol_event
            .as_any()
            .downcast_ref::<UniswapV2Sync>()
        {
            check_log_idx(self.log_index, log_meta)?;
            self.reserve0 = sync_event.reserve0;
            self.reserve1 = sync_event.reserve1;
            self.log_index = log_meta.index();
            Ok(())
        } else {
            Err(TransitionError::InvalidEventType())
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
        if let Some(other_state) = other
            .as_any()
            .downcast_ref::<UniswapV2State>()
        {
            self.reserve0 == other_state.reserve0 && self.reserve1 == other_state.reserve1
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        collections::{HashMap, HashSet},
        str::FromStr,
    };

    use approx::assert_ulps_eq;
    use ethers::types::{H160, H256};
    use rstest::rstest;

    use tycho_core::hex_bytes::Bytes;

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
        #[case] token_0_decimals: usize,
        #[case] token_1_decimals: usize,
        #[case] amount_in: U256,
        #[case] exp: U256,
    ) {
        let t0 = ERC20Token::new(
            "0x0000000000000000000000000000000000000000",
            token_0_decimals,
            "T0",
            U256::from(10_000),
        );
        let t1 = ERC20Token::new(
            "0x0000000000000000000000000000000000000001",
            token_1_decimals,
            "T0",
            U256::from(10_000),
        );
        let state = UniswapV2State::new(r0, r1);

        let res = state
            .get_amount_out(amount_in, &t0, &t1)
            .unwrap();

        assert_eq!(res.amount, exp);
        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<UniswapV2State>()
            .unwrap();
        assert_eq!(new_state.reserve0, r0 + amount_in);
        assert_eq!(new_state.reserve1, r1 - exp);
        // Assert that the old state is unchanged
        assert_eq!(state.reserve0, r0);
        assert_eq!(state.reserve1, r1);
    }

    #[test]
    fn test_get_amount_out_overflow() {
        let r0 = u256("33372357002392258830279");
        let r1 = u256("43356945776493");
        let amount_in = U256::max_value();
        let t0d = 18;
        let t1d = 16;
        let t0 = ERC20Token::new(
            "0x0000000000000000000000000000000000000000",
            t0d,
            "T0",
            U256::from(10_000),
        );
        let t1 = ERC20Token::new(
            "0x0000000000000000000000000000000000000001",
            t1d,
            "T0",
            U256::from(10_000),
        );
        let state = UniswapV2State::new(r0, r1);

        let res = state.get_amount_out(amount_in, &t0, &t1);
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(matches!(err, SimulationError::FatalError(_)));
    }

    #[rstest]
    #[case(true, 0.0008209719947624441f64)]
    #[case(false, 1218.0683462769755f64)]
    fn test_spot_price(#[case] zero_to_one: bool, #[case] exp: f64) {
        let state = UniswapV2State::new(u256("36925554990922"), u256("30314846538607556521556"));
        let usdc = ERC20Token::new(
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            6,
            "USDC",
            U256::from(10_000),
        );
        let weth = ERC20Token::new(
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 ",
            18,
            "WETH",
            U256::from(10_000),
        );

        let res = if zero_to_one {
            state.spot_price(&usdc, &weth).unwrap()
        } else {
            state.spot_price(&weth, &usdc).unwrap()
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
        let event = Box::new(UniswapV2Sync::new(u256("1500"), u256("2000")));
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
            .event_transition(event, &log_meta)
            .unwrap();

        assert_eq!(state.reserve0, u256("1500"));
        assert_eq!(state.reserve1, u256("2000"));
        assert_eq!(state.log_index, log_meta.index());
    }

    #[test]
    fn test_delta_transition() {
        let mut state = UniswapV2State::new(u256("1000"), u256("1000"));
        let attributes: HashMap<String, Bytes> = vec![
            ("reserve0".to_string(), Bytes::from(1500_u64.to_be_bytes().to_vec())),
            ("reserve1".to_string(), Bytes::from(2000_u64.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        let delta = ProtocolStateDelta {
            component_id: "State1".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(), // usv2 doesn't have any deletable attributes
        };

        let res = state.delta_transition(delta, vec![]);

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

        let res = state.delta_transition(delta, vec![]);

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
