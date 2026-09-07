//! Helpers shared by the price level stream tests.

use std::{collections::HashMap, str::FromStr};

use tycho_common::{
    models::{token::Token, Chain},
    Bytes,
};

/// The FermiSwapper router, one of the default venues.
pub(super) const PAMM: &str = "0x5979458912f80b96d30d4220af8e2e4925a33320";
pub(super) const WBTC: &str = "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599";
pub(super) const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
pub(super) const WETH: &str = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";

pub(super) fn token(address: &str, symbol: &str, decimals: u32) -> Token {
    Token::new(
        &Bytes::from_str(address).unwrap(),
        symbol,
        decimals,
        0,
        &[Some(10_000)],
        Chain::Ethereum,
        100,
    )
}

pub(super) fn tokens() -> HashMap<Bytes, Token> {
    [token(WBTC, "WBTC", 8), token(USDC, "USDC", 6), token(WETH, "WETH", 18)]
        .into_iter()
        .map(|token| (token.address.clone(), token))
        .collect()
}
