use ethers::types::U256;

use crate::{
    models::ERC20Token,
    protocol::{
        errors::{TradeSimulationError, TradeSimulationErrorKind},
        models::GetAmountOutResult,
        state::ProtocolSim,
    },
};

use super::reserve_price::spot_price_from_reserves;

#[derive(Clone, Copy)]
pub struct UniswapV2State {
    pub reserve0: U256,
    pub reserve1: U256,
}

impl UniswapV2State {
    pub fn new(reserve0: U256, reserve1: U256) -> Self {
        UniswapV2State { reserve0, reserve1 }
    }
}

impl ProtocolSim for UniswapV2State {
    fn fee(&self) -> f64 {
        0.003
    }

    fn spot_price(&self, a: &ERC20Token, b: &ERC20Token) -> f64 {
        if a < b {
            spot_price_from_reserves(
                self.reserve0,
                self.reserve1,
                a.decimals as u32,
                b.decimals as u32,
            )
        } else {
            spot_price_from_reserves(
                self.reserve1,
                self.reserve0,
                a.decimals as u32,
                b.decimals as u32,
            )
        }
    }

    fn get_amount_out(
        &self,
        amount_in: U256,
        token_a: &ERC20Token,
        token_b: &ERC20Token,
    ) -> Result<GetAmountOutResult, TradeSimulationError> {
        if amount_in == U256::zero() {
            return Result::Err(TradeSimulationError::new(
                TradeSimulationErrorKind::InsufficientAmount,
                None,
            ));
        }
        let zero2one = token_a.address < token_b.address;
        let reserve_sell = if zero2one {
            self.reserve0
        } else {
            self.reserve1
        };
        let reserve_buy = if zero2one {
            self.reserve1
        } else {
            self.reserve0
        };

        if reserve_sell == U256::zero() || reserve_buy == U256::zero() {
            return Result::Err(TradeSimulationError::new(
                TradeSimulationErrorKind::NoLiquidity,
                None,
            ));
        }

        let amount_in_with_fee = amount_in * U256::from(997);
        let numerator = amount_in_with_fee * reserve_buy;
        let denominator = reserve_sell * U256::from(1000) + amount_in_with_fee;

        let amount_out = numerator / denominator;

        Ok(GetAmountOutResult::new(amount_out, U256::from(120_000)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use approx::assert_ulps_eq;
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

        let res = state.get_amount_out(amount_in, &t0, &t1).unwrap();

        assert_eq!(res.amount, exp);
    }

    #[rstest]
    #[case(true, 1218.0683462769755f64)]
    #[case(false, 0.0008209719947624441f64)]
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
}
