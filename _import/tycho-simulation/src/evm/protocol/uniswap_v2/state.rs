use std::any::Any;

use num_bigint::{BigUint, ToBigUint};

use crate::{
    models::ERC20Token,
    protocol::{
        errors::{SimulationError, TransitionError},
        events::LogIndex,
        models::GetAmountOutResult,
        state::ProtocolSim,
    },
    safe_math::{safe_add_biguint, safe_div_biguint, safe_mul_biguint, safe_sub_biguint},
};
use tycho_core::dto::ProtocolStateDelta;

use super::reserve_price::spot_price_from_reserves;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniswapV2State {
    pub reserve0: BigUint,
    pub reserve1: BigUint,
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
    pub fn new(reserve0: BigUint, reserve1: BigUint) -> Self {
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
                &self.reserve0,
                &self.reserve1,
                base.decimals as u32,
                quote.decimals as u32,
            ))
        } else {
            Ok(spot_price_from_reserves(
                &self.reserve1,
                &self.reserve0,
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
        amount_in: BigUint,
        token_in: &ERC20Token,
        token_out: &ERC20Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        if amount_in == BigUint::ZERO {
            return Err(SimulationError::InvalidInput("Amount in cannot be zero".to_string(), None));
        }
        let zero2one = token_in.address < token_out.address;
        let reserve_sell = if zero2one { &self.reserve0 } else { &self.reserve1 };
        let reserve_buy = if zero2one { &self.reserve1 } else { &self.reserve0 };

        if reserve_sell == &BigUint::ZERO || reserve_buy == &BigUint::ZERO {
            return Err(SimulationError::RecoverableError("No liquidity".to_string()));
        }

        let amount_in_with_fee = safe_mul_biguint(
            &amount_in,
            &997.to_biguint()
                .expect("Expected an unsigned integer for fee"),
        )?;
        let numerator = safe_mul_biguint(&amount_in_with_fee, reserve_buy)?;
        let denominator = safe_add_biguint(
            &safe_mul_biguint(
                reserve_sell,
                &1000
                    .to_biguint()
                    .expect("Expected an unsigned integer for multiplier"),
            )?,
            &amount_in_with_fee,
        )?;

        let amount_out = safe_div_biguint(&numerator, &denominator)?;
        let mut new_state = self.clone();
        if zero2one {
            new_state.reserve0 = safe_add_biguint(&self.reserve0, &amount_in)?;
            new_state.reserve1 = safe_sub_biguint(&self.reserve1, &amount_out)?;
        } else {
            new_state.reserve0 = safe_sub_biguint(&self.reserve0, &amount_out)?;
            new_state.reserve1 = safe_add_biguint(&self.reserve1, &amount_in)?;
        };
        Ok(GetAmountOutResult::new(
            amount_out,
            120_000
                .to_biguint()
                .expect("Expected an unsigned integer as gas value"),
            Box::new(new_state),
        ))
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: Vec<ERC20Token>,
    ) -> Result<(), TransitionError<String>> {
        // reserve0 and reserve1 are considered required attributes and are expected in every delta
        // we process
        self.reserve0 = BigUint::from_bytes_be(
            delta
                .updated_attributes
                .get("reserve0")
                .ok_or(TransitionError::MissingAttribute("reserve0".to_string()))?,
        );
        self.reserve1 = BigUint::from_bytes_be(
            delta
                .updated_attributes
                .get("reserve1")
                .ok_or(TransitionError::MissingAttribute("reserve1".to_string()))?,
        );
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

    use std::collections::{HashMap, HashSet};

    use approx::assert_ulps_eq;
    use rstest::rstest;
    use std::str::FromStr;

    use tycho_core::hex_bytes::Bytes;

    #[rstest]
    #[case::same_dec(
    BigUint::from_str("6770398782322527849696614").unwrap(),
    BigUint::from_str("5124813135806900540214").unwrap(),
        18,
        18,
    BigUint::from_str("10000000000000000000000").unwrap(),
    BigUint::from_str("7535635391574243447").unwrap()
    )]
    #[case::diff_dec(
    BigUint::from_str("33372357002392258830279").unwrap(),
    BigUint::from_str("43356945776493").unwrap(),
        18,
        6,
    BigUint::from_str("10000000000000000000").unwrap(),
    BigUint::from_str("12949029867").unwrap()
    )]
    fn test_get_amount_out(
        #[case] r0: BigUint,
        #[case] r1: BigUint,
        #[case] token_0_decimals: usize,
        #[case] token_1_decimals: usize,
        #[case] amount_in: BigUint,
        #[case] exp: BigUint,
    ) {
        let t0 = ERC20Token::new(
            "0x0000000000000000000000000000000000000000",
            token_0_decimals,
            "T0",
            10_000.to_biguint().unwrap(),
        );
        let t1 = ERC20Token::new(
            "0x0000000000000000000000000000000000000001",
            token_1_decimals,
            "T0",
            10_000.to_biguint().unwrap(),
        );
        let state = UniswapV2State::new(r0.clone(), r1.clone());

        let res = state
            .get_amount_out(amount_in.clone(), &t0, &t1)
            .unwrap();

        assert_eq!(res.amount, exp);
        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<UniswapV2State>()
            .unwrap();
        assert_eq!(new_state.reserve0, &r0 + amount_in);
        assert_eq!(new_state.reserve1, &r1 - exp);
        // Assert that the old state is unchanged
        assert_eq!(state.reserve0, r0);
        assert_eq!(state.reserve1, r1);
    }

    #[rstest]
    #[case(true, 0.0008209719947624441f64)]
    #[case(false, 1218.0683462769755f64)]
    fn test_spot_price(#[case] zero_to_one: bool, #[case] exp: f64) {
        let state = UniswapV2State::new(
            BigUint::from_str("36925554990922").unwrap(),
            BigUint::from_str("30314846538607556521556").unwrap(),
        );
        let usdc = ERC20Token::new(
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            6,
            "USDC",
            10_000.to_biguint().unwrap(),
        );
        let weth = ERC20Token::new(
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 ",
            18,
            "WETH",
            10_000.to_biguint().unwrap(),
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
        let state = UniswapV2State::new(
            BigUint::from_str("36925554990922").unwrap(),
            BigUint::from_str("30314846538607556521556").unwrap(),
        );

        let res = state.fee();

        assert_ulps_eq!(res, 0.003);
    }

    #[test]
    fn test_delta_transition() {
        let mut state = UniswapV2State::new(1000.to_biguint().unwrap(), 1000.to_biguint().unwrap());
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
        assert_eq!(state.reserve0, 1500.to_biguint().unwrap());
        assert_eq!(state.reserve1, 2000.to_biguint().unwrap());
    }

    #[test]
    fn test_delta_transition_missing_attribute() {
        let mut state = UniswapV2State::new(1000.to_biguint().unwrap(), 1000.to_biguint().unwrap());
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
