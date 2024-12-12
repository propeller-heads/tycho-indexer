//! Basic data structures
//!
//! This module contains basic models that are shared across many
//! components of the crate, including Token, Swap and SwapSequence.
//!
//! Tokens provide instructions on how to handle prices and amounts,
//! while Swap and SwapSequence are usually used as results types.
use alloy_primitives::U256;
use std::{
    convert::TryFrom,
    hash::{Hash, Hasher},
};

use num_bigint::BigUint;
use tycho_core::Bytes;

use crate::utils::hexstring_to_vec;
use tycho_core::dto::ResponseToken;

#[derive(Clone, Debug, Eq)]
pub struct Token {
    /// The address of the token on the blockchain network
    pub address: Bytes,
    /// The number of decimal places that the token uses
    pub decimals: usize,
    /// The symbol of the token
    pub symbol: String,
    /// The amount of gas it takes to transfer the token
    pub gas: BigUint,
}

impl Token {
    /// Constructor for ERC20Token
    ///
    /// Creates a new ERC20 token struct
    ///
    /// ## Parameters
    /// - `address`: token address as string
    /// - `decimals`: token decimal as usize
    /// - `symbol`: token symbol as string
    /// - `gas`: token gas as U256
    ///
    /// ## Return
    /// Return a new ERC20 token struct
    ///
    /// ## Panic
    /// - Panics if the token address string is not in valid format
    pub fn new(address: &str, decimals: usize, symbol: &str, gas: BigUint) -> Self {
        let addr = Bytes::from(
            hexstring_to_vec(address)
                .unwrap_or_else(|_| panic!("Invalid token address: {:?}", address)),
        );
        let sym = symbol.to_string();
        Token { address: addr, decimals, symbol: sym, gas }
    }

    /// One
    /// Get one token in U256 format
    ///
    /// ## Return
    /// Return one token as U256
    pub fn one(&self) -> U256 {
        U256::from(10).pow(U256::from(self.decimals))
    }
}

impl PartialOrd for Token {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.address.partial_cmp(&other.address)
    }
}

impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl Hash for Token {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.address.hash(state);
    }
}

impl TryFrom<ResponseToken> for Token {
    type Error = std::num::TryFromIntError;

    fn try_from(value: ResponseToken) -> Result<Self, Self::Error> {
        Ok(Self {
            address: value.address,
            decimals: value.decimals.try_into()?,
            symbol: value.symbol,
            gas: BigUint::from(
                value
                    .gas
                    .into_iter()
                    .flatten()
                    .collect::<Vec<u64>>()
                    .iter()
                    .min()
                    .copied()
                    .expect("Expected a value in gas"),
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigUint;

    #[test]
    fn test_constructor() {
        let token = Token::new(
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            6,
            "USDC",
            10000.to_biguint().unwrap(),
        );

        assert_eq!(token.symbol, "USDC");
        assert_eq!(token.decimals, 6);
        assert_eq!(format!("{:#x}", token.address), "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
    }

    #[test]
    fn test_cmp() {
        let usdc = Token::new(
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            6,
            "USDC",
            10000.to_biguint().unwrap(),
        );
        let usdc2 = Token::new(
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            6,
            "USDC2",
            10000.to_biguint().unwrap(),
        );
        let weth = Token::new(
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            18,
            "WETH",
            15000.to_biguint().unwrap(),
        );

        assert!(usdc < weth);
        assert_eq!(usdc, usdc2);
    }

    #[test]
    fn test_one() {
        let usdc = Token::new(
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            6,
            "USDC",
            10000.to_biguint().unwrap(),
        );

        assert_eq!(usdc.one(), U256::from(1000000));
    }
}
