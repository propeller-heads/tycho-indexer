use std::{any::Any, collections::HashMap};

use alloy::primitives::U256;
use num_bigint::BigUint;
use tycho_common::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::{
        errors::{SimulationError, TransitionError},
        protocol_sim::{Balances, GetAmountOutResult, Price, ProtocolSim, Trade},
    },
    Bytes,
};

use crate::evm::protocol::{
    cpmm::protocol::{
        cpmm_delta_transition, cpmm_fee, cpmm_get_amount_out, cpmm_get_limits, cpmm_spot_price,
        cpmm_swap_to_price, ProtocolFee,
    },
    safe_math::{safe_add_u256, safe_sub_u256},
    u256_num::{biguint_to_u256, u256_to_biguint},
};

const UNISWAP_V2_FEE_BPS: u32 = 30; // 0.3% fee
const FEE_PRECISION: U256 = U256::from_limbs([1000, 0, 0, 0]);
const FEE_NUMERATOR: U256 = U256::from_limbs([997, 0, 0, 0]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniswapV2State {
    pub reserve0: U256,
    pub reserve1: U256,
}

impl UniswapV2State {
    /// Creates a new instance of `UniswapV2State` with the given reserves.
    ///
    /// # Arguments
    ///
    /// * `reserve0` - Reserve of token 0.
    /// * `reserve1` - Reserve of token 1.
    pub fn new(reserve0: U256, reserve1: U256) -> Self {
        UniswapV2State { reserve0, reserve1 }
    }
}

impl ProtocolSim for UniswapV2State {
    fn fee(&self) -> f64 {
        cpmm_fee(UNISWAP_V2_FEE_BPS)
    }

    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError> {
        cpmm_spot_price(base, quote, self.reserve0, self.reserve1)
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        let amount_in = biguint_to_u256(&amount_in);
        let zero2one = token_in.address < token_out.address;
        let amount_out = cpmm_get_amount_out(
            amount_in,
            zero2one,
            self.reserve0,
            self.reserve1,
            UNISWAP_V2_FEE_BPS,
        )?;
        let mut new_state = self.clone();
        let (reserve0_mut, reserve1_mut) = (&mut new_state.reserve0, &mut new_state.reserve1);
        if zero2one {
            *reserve0_mut = safe_add_u256(self.reserve0, amount_in)?;
            *reserve1_mut = safe_sub_u256(self.reserve1, amount_out)?;
        } else {
            *reserve0_mut = safe_sub_u256(self.reserve0, amount_out)?;
            *reserve1_mut = safe_add_u256(self.reserve1, amount_in)?;
        };
        Ok(GetAmountOutResult::new(
            u256_to_biguint(amount_out),
            BigUint::from(120_000u32),
            Box::new(new_state),
        ))
    }

    fn get_limits(
        &self,
        sell_token: Bytes,
        buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        cpmm_get_limits(sell_token, buy_token, self.reserve0, self.reserve1)
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        let (reserve0_mut, reserve1_mut) = (&mut self.reserve0, &mut self.reserve1);
        cpmm_delta_transition(delta, reserve0_mut, reserve1_mut)
    }

    fn swap_to_price(
        &self,
        token_in: &Bytes,
        token_out: &Bytes,
        target_price: Price,
    ) -> Result<Trade, SimulationError> {
        let zero2one = token_in < token_out;
        let (reserve_in, reserve_out) =
            if zero2one { (self.reserve0, self.reserve1) } else { (self.reserve1, self.reserve0) };

        let fee = ProtocolFee::new(FEE_NUMERATOR, FEE_PRECISION);
        cpmm_swap_to_price(reserve_in, reserve_out, target_price, fee)
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
            let (self_reserve0, self_reserve1) = (self.reserve0, self.reserve1);
            let (other_reserve0, other_reserve1) = (other_state.reserve0, other_state.reserve1);
            self_reserve0 == other_reserve0 &&
                self_reserve1 == other_reserve1 &&
                self.fee() == other_state.fee()
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
    use num_traits::One;
    use rstest::rstest;
    use tycho_common::{
        dto::ProtocolStateDelta,
        hex_bytes::Bytes,
        models::{token::Token, Chain},
        simulation::{
            errors::{SimulationError, TransitionError},
            protocol_sim::{Balances, ProtocolSim},
        },
    };

    use super::*;
    use crate::evm::protocol::u256_num::biguint_to_u256;

    #[rstest]
    #[case::same_dec(
        U256::from_str("6770398782322527849696614").unwrap(),
        U256::from_str("5124813135806900540214").unwrap(),
        18,
        18,
    BigUint::from_str("10000000000000000000000").unwrap(),
    BigUint::from_str("7535635391574243447").unwrap()
    )]
    #[case::diff_dec(
        U256::from_str("33372357002392258830279").unwrap(),
        U256::from_str("43356945776493").unwrap(),
        18,
        6,
    BigUint::from_str("10000000000000000000").unwrap(),
    BigUint::from_str("12949029867").unwrap()
    )]
    fn test_get_amount_out(
        #[case] r0: U256,
        #[case] r1: U256,
        #[case] token_0_decimals: u32,
        #[case] token_1_decimals: u32,
        #[case] amount_in: BigUint,
        #[case] exp: BigUint,
    ) {
        let t0 = Token::new(
            &Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            "T0",
            token_0_decimals,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let t1 = Token::new(
            &Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            "T0",
            token_1_decimals,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let state = UniswapV2State::new(r0, r1);

        let res = state
            .get_amount_out(amount_in.clone(), &t0, &t1)
            .unwrap();

        assert_eq!(res.amount, exp);
        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<UniswapV2State>()
            .unwrap();
        assert_eq!(new_state.reserve0, r0 + biguint_to_u256(&amount_in));
        assert_eq!(new_state.reserve1, r1 - biguint_to_u256(&exp));
        // Assert that the old state is unchanged
        assert_eq!(state.reserve0, r0);
        assert_eq!(state.reserve1, r1);
    }

    #[test]
    fn test_get_amount_out_overflow() {
        let r0 = U256::from_str("33372357002392258830279").unwrap();
        let r1 = U256::from_str("43356945776493").unwrap();
        let amount_in = (BigUint::one() << 256) - BigUint::one(); // U256 max value
        let t0d = 18;
        let t1d = 16;
        let t0 = Token::new(
            &Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            "T0",
            t0d,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let t1 = Token::new(
            &Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            "T0",
            t1d,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
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
        let state = UniswapV2State::new(
            U256::from_str("36925554990922").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
        );
        let usdc = Token::new(
            &Bytes::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(),
            "USDC",
            6,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let weth = Token::new(
            &Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
            "WETH",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
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
            U256::from_str("36925554990922").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
        );

        let res = state.fee();

        assert_ulps_eq!(res, 0.003);
    }

    #[test]
    fn test_delta_transition() {
        let mut state =
            UniswapV2State::new(U256::from_str("1000").unwrap(), U256::from_str("1000").unwrap());
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

        let res = state.delta_transition(delta, &HashMap::new(), &Balances::default());

        assert!(res.is_ok());
        assert_eq!(state.reserve0, U256::from_str("1500").unwrap());
        assert_eq!(state.reserve1, U256::from_str("2000").unwrap());
    }

    #[test]
    fn test_delta_transition_missing_attribute() {
        let mut state =
            UniswapV2State::new(U256::from_str("1000").unwrap(), U256::from_str("1000").unwrap());
        let attributes: HashMap<String, Bytes> =
            vec![("reserve0".to_string(), Bytes::from(1500_u64.to_be_bytes().to_vec()))]
                .into_iter()
                .collect();
        let delta = ProtocolStateDelta {
            component_id: "State1".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(),
        };

        let res = state.delta_transition(delta, &HashMap::new(), &Balances::default());

        assert!(res.is_err());
        // assert it errors for the missing reserve1 attribute delta
        match res {
            Err(e) => {
                assert!(matches!(e, TransitionError::MissingAttribute(ref x) if x=="reserve1"))
            }
            _ => panic!("Test failed: was expecting an Err value"),
        };
    }

    #[test]
    fn test_get_limits_price_impact() {
        let state =
            UniswapV2State::new(U256::from_str("1000").unwrap(), U256::from_str("100000").unwrap());

        let (amount_in, _) = state
            .get_limits(
                Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
                Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            )
            .unwrap();

        let token_0 = Token::new(
            &Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            "T0",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let token_1 = Token::new(
            &Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            "T1",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        let result = state
            .get_amount_out(amount_in.clone(), &token_0, &token_1)
            .unwrap();
        let new_state = result
            .new_state
            .as_any()
            .downcast_ref::<UniswapV2State>()
            .unwrap();

        let initial_price = state
            .spot_price(&token_0, &token_1)
            .unwrap();
        let new_price = new_state
            .spot_price(&token_0, &token_1)
            .unwrap()
            .floor();

        let expected_price = initial_price / 10.0;
        assert!(expected_price == new_price, "Price impact not 90%.");
    }

    #[test]
    fn test_swap_to_price_below_spot() {
        // Pool with reserve0=2000000, reserve1=1000000
        // Current price: reserve1/reserve0 = 1000000/2000000 = 0.5 token_out per token_in
        let state = UniswapV2State::new(U256::from(2_000_000u32), U256::from(1_000_000u32));

        let token_in = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let token_out = Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap();

        // Target price: 2/5 = 0.4 token_out per token_in (lower than current 0.5)
        // Selling token_in decreases price from 0.5 down to 0.4
        let target_price = Price::new(BigUint::from(2u32), BigUint::from(5u32));

        let trade = state
            .swap_to_price(&token_in, &token_out, target_price)
            .unwrap();

        assert!(trade.amount_in > BigUint::ZERO, "Should require some input amount");

        // Verify that swapping this amount brings us close to the target price
        let token_in_obj =
            Token::new(&token_in, "T0", 18, 0, &[Some(10_000)], Chain::Ethereum, 100);
        let token_out_obj =
            Token::new(&token_out, "T1", 18, 0, &[Some(10_000)], Chain::Ethereum, 100);

        let result = state
            .get_amount_out(trade.amount_in, &token_in_obj, &token_out_obj)
            .unwrap();
        let new_state = result
            .new_state
            .as_any()
            .downcast_ref::<UniswapV2State>()
            .unwrap();

        // Check that we got some output
        assert!(result.amount > BigUint::ZERO);

        // The new reserves should reflect the target price
        // Price = reserve1/reserve0, so if price = 0.4, then reserve0/reserve1 = 2.5
        let new_reserve_ratio =
            new_state.reserve0.to::<u128>() as f64 / new_state.reserve1.to::<u128>() as f64;
        let expected_ratio = 2.5;

        // Allow for some difference due to fees and rounding
        assert!(
            (new_reserve_ratio - expected_ratio).abs() < 0.01,
            "New reserve ratio {new_reserve_ratio} should be close to expected {expected_ratio}"
        );
    }

    #[test]
    fn test_swap_to_price_unreachable() {
        // Pool with 2:1 ratio
        let state = UniswapV2State::new(U256::from(2_000_000u32), U256::from(1_000_000u32));

        let token_in = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let token_out = Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap();

        // Target price is unreachable (should return zero)
        // Current pool price: reserve_out/reserve_in = 1000000/2000000 = 0.5 token_out per
        // token_in Target: 1/1 = 1.0 token_out per token_in
        // Selling token_in decreases pool price, so we can't reach 1.0 from 0.5
        let target_price = Price::new(BigUint::from(1u32), BigUint::from(1u32));

        let trade = state
            .swap_to_price(&token_in, &token_out, target_price)
            .unwrap();

        assert_eq!(
            trade.amount_in,
            BigUint::ZERO,
            "Should require zero input amount when target price is unreachable"
        );
        assert_eq!(
            trade.amount_out,
            BigUint::ZERO,
            "Should return zero output amount when target price is unreachable"
        );
    }

    #[test]
    fn test_swap_to_price_at_spot_price() {
        let state = UniswapV2State::new(U256::from(2_000_000u32), U256::from(1_000_000u32));

        let token_in = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let token_out = Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap();

        // Calculate spot price with fee (token_out/token_in):
        // Marginal price = (FEE_NUMERATOR * reserve_out) / (FEE_PRECISION * reserve_in)
        let spot_price_num = U256::from(1_000_000u32) * FEE_NUMERATOR;
        let spot_price_den = U256::from(2_000_000u32) * FEE_PRECISION;

        let target_price =
            Price::new(u256_to_biguint(spot_price_num), u256_to_biguint(spot_price_den));

        let trade = state
            .swap_to_price(&token_in, &token_out, target_price)
            .unwrap();

        // At exact spot price, we should return zero amount
        assert!(trade.amount_in == BigUint::ZERO, "At spot price should require zero input amount");
        assert!(
            trade.amount_out == BigUint::ZERO,
            "At spot price should return zero output amount"
        );
    }

    #[test]
    fn test_swap_to_price_slightly_below_spot() {
        let state = UniswapV2State::new(U256::from(2_000_000u32), U256::from(1_000_000u32));

        let token_in = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let token_out = Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap();

        // Calculate spot price with fee and subtract small amount to move slightly below
        // Current spot (token_out/token_in with fees): (FEE_NUMERATOR * reserve_out) /
        // (FEE_PRECISION * reserve_in) Target: slightly below current spot (multiply numerator by
        // 99999/100000)
        let spot_price_num = U256::from(1_000_000u32) * FEE_NUMERATOR * U256::from(99_999u32);
        let spot_price_den = U256::from(2_000_000u32) * FEE_PRECISION * U256::from(100_000u32);

        let target_price =
            Price::new(u256_to_biguint(spot_price_num), u256_to_biguint(spot_price_den));

        let trade = state
            .swap_to_price(&token_in, &token_out, target_price)
            .unwrap();

        assert!(
            trade.amount_in > BigUint::ZERO,
            "Should return non-zero amount for target slightly below spot"
        );
    }

    #[test]
    fn test_swap_to_price_returns_output_amount() {
        let state = UniswapV2State::new(U256::from(2_000_000u32), U256::from(1_000_000u32));

        let token_in = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let token_out = Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap();

        // Target price: 2/5 = 0.4 token_out per token_in (lower than current 0.5)
        let target_price = Price::new(BigUint::from(2u32), BigUint::from(5u32));

        // Get the trade needed to reach target price
        let trade_swap_to_price = state
            .swap_to_price(&token_in, &token_out, target_price.clone())
            .unwrap();

        // Get the trade at the target price
        let trade_query_supply = state
            .swap_to_price(&token_in, &token_out, target_price)
            .unwrap();

        assert_eq!(
            trade_query_supply.amount_out, trade_swap_to_price.amount_out,
            "query_supply should return the same output amount as swap_to_price"
        );
        assert!(trade_query_supply.amount_out > BigUint::ZERO, "Supply should be non-zero");
    }

    #[test]
    fn test_swap_to_price_large_pool() {
        // Test with realistic large reserves
        let state = UniswapV2State::new(
            U256::from_str("6770398782322527849696614").unwrap(),
            U256::from_str("5124813135806900540214").unwrap(),
        );

        let token_in = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let token_out = Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap();

        // Current price (token_out/token_in) = reserve1/reserve0
        // To target a slightly lower price (move price down 10%), we can use:
        // target_price = (reserve1 * 9) / (reserve0 * 10)
        // This avoids floating point precision issues with large numbers
        let price_numerator = u256_to_biguint(state.reserve1) * BigUint::from(9u32);
        let price_denominator = u256_to_biguint(state.reserve0) * BigUint::from(10u32);

        let target_price = Price::new(price_numerator, price_denominator);

        let trade = state
            .swap_to_price(&token_in, &token_out, target_price)
            .unwrap();

        assert!(trade.amount_in > BigUint::ZERO, "Should require some input amount");
        assert!(trade.amount_out > BigUint::ZERO, "Should get some output");
    }

    #[test]
    fn test_swap_to_price_basic() {
        let state = UniswapV2State::new(U256::from(1_000_000u32), U256::from(2_000_000u32));

        let token_in = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let token_out = Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap();

        let target_price = Price::new(BigUint::from(2u32), BigUint::from(3u32));

        let trade = state
            .swap_to_price(&token_in, &token_out, target_price)
            .unwrap();
        assert!(trade.amount_in > BigUint::ZERO, "Amount in should be non-zero");
        assert!(trade.amount_out > BigUint::ZERO, "Amount out should be non-zero");
    }

    #[test]
    fn test_swap_to_price_validates_actual_output() {
        // Test that query_supply validates actual_output >= expected_output
        let state = UniswapV2State::new(
            U256::from(1_000_000u128) * U256::from(1_000_000_000_000_000_000u128),
            U256::from(2_000_000u128) * U256::from(1_000_000_000_000_000_000u128),
        );

        let token_in = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let token_out = Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap();

        // Current pool price: 2M/1M = 2.0 token_out per token_in
        // Target: slightly lower (e.g., 1.95:1 = 1_950_000/1_000_000)
        // This is reachable by selling token_in
        let target_price = Price::new(BigUint::from(1_950_000u128), BigUint::from(1_000_000u128));

        let trade = state
            .swap_to_price(&token_in, &token_out, target_price.clone())
            .unwrap();
        assert!(trade.amount_out > BigUint::ZERO, "Should return amount out for valid price");
        assert!(trade.amount_in > BigUint::ZERO, "Should return amount in for valid price");
    }

    #[test]
    fn test_swap_around_spot_price() {
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        let reserve_0 = U256::from_str("735952457913070155214197").unwrap();
        let reserve_1 = U256::from_str("735997725943000000000000").unwrap();

        let pool = UniswapV2State::new(reserve_0, reserve_1);

        // Reserves: reserve_0 = DAI, reserve_1 = USDC (DAI address < USDC address)
        let reserve_usdc = reserve_1;
        let reserve_dai = reserve_0;

        // Calculate spot price (USDC/DAI with fee)
        let spot_price_dai_per_usdc_num = reserve_dai
            .checked_mul(U256::from(1000u32))
            .unwrap();
        let spot_price_dai_per_usdc_den = reserve_usdc
            .checked_mul(U256::from(1003u32))
            .unwrap();

        // Test 1: Price above reachable limit (more DAI per USDC than pool can provide) -should
        // return zero Multiply by 1001/1000 to go above reachable limit
        let above_limit_num = spot_price_dai_per_usdc_num
            .checked_mul(U256::from(1001u32))
            .unwrap();
        let above_limit_den = spot_price_dai_per_usdc_den
            .checked_mul(U256::from(1000u32))
            .unwrap();

        let trade_above_limit = pool
            .swap_to_price(
                &usdc,
                &dai,
                Price::new(u256_to_biguint(above_limit_num), u256_to_biguint(above_limit_den)),
            )
            .unwrap();
        assert_eq!(
            trade_above_limit.amount_out,
            BigUint::ZERO,
            "Should return zero for price above reachable limit"
        );

        // Test 2: Price just below reachable limit - should return non-zero
        // Multiply by 100_000/100_001 to go slightly below (more reachable)
        let below_limit_num = spot_price_dai_per_usdc_num
            .checked_mul(U256::from(100_000u32))
            .unwrap();
        let below_limit_den = spot_price_dai_per_usdc_den
            .checked_mul(U256::from(100_001u32))
            .unwrap();

        let trade_below_limit = pool
            .swap_to_price(
                &usdc,
                &dai,
                Price::new(u256_to_biguint(below_limit_num), u256_to_biguint(below_limit_den)),
            )
            .unwrap();

        assert!(
            trade_below_limit.amount_out > BigUint::ZERO,
            "Should return non-zero for reachable price"
        );

        // Verify with actual swap
        let token_usdc = Token::new(&usdc, "USDC", 6, 0, &[Some(10_000)], Chain::Ethereum, 100);
        let token_dai = Token::new(&dai, "DAI", 18, 0, &[Some(10_000)], Chain::Ethereum, 100);

        let actual_result = pool
            .get_amount_out(trade_below_limit.amount_in.clone(), &token_usdc, &token_dai)
            .unwrap();

        assert_eq!(
            biguint_to_u256(&actual_result.amount),
            U256::from(366839007208379339u128),
            "Should return non-zero amount"
        );
        assert!(
            actual_result.amount >= trade_below_limit.amount_out,
            "Actual swap should give at least predicted amount"
        );
    }
}
