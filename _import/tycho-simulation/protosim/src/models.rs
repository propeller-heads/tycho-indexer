use std::str::FromStr;

use ethers::types::{H160, U256};

#[derive(Clone, Debug, Eq)]
pub struct ERC20Token {
    pub address: H160,
    pub decimals: usize,
    pub symbol: String,
}

impl ERC20Token {
    pub fn new(address: &str, decimals: usize, symbol: &str) -> Self {
        let addr = H160::from_str(address).expect("Failed to parse token address");
        let sym = symbol.to_string();
        ERC20Token {
            address: addr,
            decimals: decimals,
            symbol: sym,
        }
    }

    pub fn one(&self) -> U256 {
        U256::exp10(self.decimals)
    }
}

impl PartialOrd for ERC20Token {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.address.partial_cmp(&other.address)
    }
}

impl PartialEq for ERC20Token {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

#[derive(Debug)]
pub struct Swap {
    token_in: H160,
    amount_in: U256,
    token_out: H160,
    amount_out: U256,
    address: H160,
}

impl Swap {
    pub fn new(
        token_in: H160,
        amount_in: U256,
        token_out: H160,
        amount_out: U256,
        address: H160,
    ) -> Self {
        Swap {
            token_in,
            amount_in,
            token_out,
            amount_out,
            address,
        }
    }

    pub fn token_out(&self) -> H160 {
        self.token_out
    }

    pub fn token_in(&self) -> H160 {
        self.token_in
    }

    pub fn amount_out(&self) -> U256 {
        return self.amount_out;
    }

    pub fn amount_in(&self) -> U256 {
        return self.amount_in;
    }

    pub fn address(&self) -> H160 {
        self.address
    }
}

#[derive(Debug)]
pub struct SwapSequence {
    actions: Vec<Swap>,
    gas: U256,
}

impl SwapSequence {
    pub fn new(swaps: Vec<Swap>, gas: U256) -> Self {
        SwapSequence {
            actions: swaps,
            gas: gas,
        }
    }

    pub fn swaps(self) -> Vec<Swap> {
        self.actions
    }

    pub fn gas(&self) -> U256 {
        self.gas
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constructor() {
        let token = ERC20Token::new("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6, "USDC");

        assert_eq!(token.symbol, "USDC");
        assert_eq!(token.decimals, 6);
        assert_eq!(
            format!("{:#x}", token.address),
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        );
    }

    #[test]
    fn test_cmp() {
        let usdc = ERC20Token::new("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6, "USDC");
        let usdc2 = ERC20Token::new("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6, "USDC2");
        let weth = ERC20Token::new("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 18, "WETH");

        assert!(usdc < weth);
        assert_eq!(usdc, usdc2);
    }

    #[test]
    fn test_one() {
        let usdc = ERC20Token::new("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6, "USDC");

        assert_eq!(usdc.one().as_u64(), 1000000);
    }
}
