use alloy::primitives::U256;

use crate::evm::protocol::cpmm::protocol::CPMMProtocol;

const PANCAKESWAP_V2_FEE: u32 = 25; // 0.25% fee

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PancakeswapV2State {
    pub reserve0: U256,
    pub reserve1: U256,
}

impl PancakeswapV2State {
    /// Creates a new instance of `PancakeswapV2State` with the given reserves.
    ///
    /// # Arguments
    ///
    /// * `reserve0` - Reserve of token 0.
    /// * `reserve1` - Reserve of token 1.
    pub fn new(reserve0: U256, reserve1: U256) -> Self {
        PancakeswapV2State { reserve0, reserve1 }
    }
}

impl CPMMProtocol for PancakeswapV2State {
    fn get_fee_bps(&self) -> u32 {
        PANCAKESWAP_V2_FEE
    }

    fn get_reserves(&self) -> (U256, U256) {
        (self.reserve0, self.reserve1)
    }

    fn get_reserves_mut(&mut self) -> (&mut U256, &mut U256) {
        (&mut self.reserve0, &mut self.reserve1)
    }

    fn new(reserve0: U256, reserve1: U256) -> Self {
        Self::new(reserve0, reserve1)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        str::FromStr,
    };

    use approx::assert_ulps_eq;
    use num_bigint::{BigUint, ToBigUint};
    use num_traits::One;
    use rstest::rstest;
    use tycho_common::{dto::ProtocolStateDelta, hex_bytes::Bytes};

    use super::*;
    use crate::{
        models::{Balances, Token},
        protocol::{
            errors::{SimulationError, TransitionError},
            state::ProtocolSim,
        },
    };

    #[test]
    fn test_get_amount_out() {
        // Values based on mainnet WETH/USDC pool swap at transaction
        // 0x6b3193b0ce348cf45d2c70a6481d8088f58ee22ba41502b611a2b045f4464c9f
        let t0 = Token::new(
            "0x0000000000000000000000000000000000000000",
            18,
            "WETH",
            10_000.to_biguint().unwrap(),
        );
        let t1 = Token::new(
            "0x0000000000000000000000000000000000000001",
            6,
            "USDC",
            10_000.to_biguint().unwrap(),
        );
        let reserve0 = U256::from_str("114293490733").unwrap();
        let reserve1 = U256::from_str("69592908201923870949").unwrap();
        let state = PancakeswapV2State::new(reserve0, reserve1);
        let amount_in = BigUint::from_str("13088600769481610").unwrap();

        let res = state
            .get_amount_out(amount_in.clone(), &t1, &t0)
            .unwrap();

        let exp = BigUint::from_str("21437847").unwrap();
        assert_eq!(res.amount, exp);
        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<PancakeswapV2State>()
            .unwrap();
        assert_eq!(new_state.reserve0, U256::from_str("114272052886").unwrap());
        assert_eq!(new_state.reserve1, U256::from_str("69605996802693352559").unwrap());
        // Assert that the old state is unchanged
        assert_eq!(state.reserve0, reserve0);
        assert_eq!(state.reserve1, reserve1);
    }

    #[test]
    fn test_get_amount_out_overflow() {
        let r0 = U256::from_str("33372357002392258830279").unwrap();
        let r1 = U256::from_str("43356945776493").unwrap();
        let amount_in = (BigUint::one() << 256) - BigUint::one(); // U256 max value
        let t0d = 18;
        let t1d = 16;
        let t0 = Token::new(
            "0x0000000000000000000000000000000000000000",
            t0d,
            "T0",
            10_000.to_biguint().unwrap(),
        );
        let t1 = Token::new(
            "0x0000000000000000000000000000000000000001",
            t1d,
            "T0",
            10_000.to_biguint().unwrap(),
        );
        let state = PancakeswapV2State::new(r0, r1);

        let res = state.get_amount_out(amount_in, &t0, &t1);
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(matches!(err, SimulationError::FatalError(_)));
    }

    #[rstest]
    #[case(true, 0.0008209719947624441f64)]
    #[case(false, 1218.0683462769755f64)]
    fn test_spot_price(#[case] zero_to_one: bool, #[case] exp: f64) {
        let state = PancakeswapV2State::new(
            U256::from_str("36925554990922").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
        );
        let usdc = Token::new(
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            6,
            "USDC",
            10_000.to_biguint().unwrap(),
        );
        let weth = Token::new(
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
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
        let state = PancakeswapV2State::new(
            U256::from_str("36925554990922").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
        );

        let res = state.fee();

        assert_ulps_eq!(res, 0.0025); // 0.25% fee
    }

    #[test]
    fn test_delta_transition() {
        let mut state = PancakeswapV2State::new(
            U256::from_str("1000").unwrap(),
            U256::from_str("1000").unwrap(),
        );
        let attributes: HashMap<String, Bytes> = vec![
            ("reserve0".to_string(), Bytes::from(1500_u64.to_be_bytes().to_vec())),
            ("reserve1".to_string(), Bytes::from(2000_u64.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        let delta = ProtocolStateDelta {
            component_id: "State1".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(),
        };

        let res = state.delta_transition(delta, &HashMap::new(), &Balances::default());

        assert!(res.is_ok());
        assert_eq!(state.reserve0, U256::from_str("1500").unwrap());
        assert_eq!(state.reserve1, U256::from_str("2000").unwrap());
    }

    #[test]
    fn test_delta_transition_missing_attribute() {
        let mut state = PancakeswapV2State::new(
            U256::from_str("1000").unwrap(),
            U256::from_str("1000").unwrap(),
        );
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
        match res {
            Err(e) => {
                assert!(matches!(e, TransitionError::MissingAttribute(ref x) if x=="reserve1"))
            }
            _ => panic!("Test failed: was expecting an Err value"),
        };
    }

    #[test]
    fn test_get_limits_price_impact() {
        let state = PancakeswapV2State::new(
            U256::from_str("1000").unwrap(),
            U256::from_str("100000").unwrap(),
        );

        let (amount_in, _) = state
            .get_limits(
                Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
                Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            )
            .unwrap();

        let token_0 = Token::new(
            "0x0000000000000000000000000000000000000000",
            18,
            "T0",
            10_000.to_biguint().unwrap(),
        );
        let token_1 = Token::new(
            "0x0000000000000000000000000000000000000001",
            18,
            "T1",
            10_000.to_biguint().unwrap(),
        );

        let result = state
            .get_amount_out(amount_in.clone(), &token_0, &token_1)
            .unwrap();
        let new_state = result
            .new_state
            .as_any()
            .downcast_ref::<PancakeswapV2State>()
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
}
