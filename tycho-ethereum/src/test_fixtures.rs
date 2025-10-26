//! Common test fixtures and utilities for tycho-ethereum tests
//!
//! This module contains shared test constants, helper functions, and fixtures
//! that can be used across multiple test files in the crate.

use std::{collections::HashMap, str::FromStr, sync::LazyLock};

use alloy::{hex::FromHex, primitives::B256};
use tycho_common::{
    models::{blockchain::Block, Address, Chain},
    Bytes,
};

use crate::BytesCodec;

// Common test block constants
pub const TEST_BLOCK_NUMBER: u64 = 23475728;
pub const TEST_BLOCK_HASH: &str =
    "0x7f70ac678819e24c4947a3a95fdab886083892a18ba1a962ebaac31455584042";

// Common Ethereum mainnet contract addresses for testing
pub const BALANCER_VAULT_STR: &str = "0xba12222222228d8ba445958a75a0704d566bf2c8";
pub const STETH_STR: &str = "0xae7ab96520de3a18e5e111b5eaab095312d7fe84";
pub const DAI_STR: &str = "0x6b175474e89094c44da98b954eedeac495271d0f";
pub const WBTC_STR: &str = "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599";
pub const USDC_STR: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
pub const WETH_STR: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

// Common token addresses array
pub const TOKEN_ADDRESSES: [&str; 5] = [BALANCER_VAULT_STR, STETH_STR, DAI_STR, WBTC_STR, USDC_STR];

// Known token holders for testing (addresses with large balances)
// Using USV4 pool manager as a holder with known large balances
pub const TOKEN_HOLDER_ADDR: &str = "0x000000000004444c5dc75cB358380D2e3dE08A90";

// WETH holder - Uniswap V2 WETH-USDC pair has significant WETH balance
pub const WETH_HOLDER_ADDR: &str = "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc";

/// Lazily-initialized map of token addresses to their known holders and balances.
/// This is useful for TokenOwnerStore setup in tests.
pub static TOKEN_HOLDERS: LazyLock<HashMap<Address, (Bytes, Bytes)>> = LazyLock::new(|| {
    HashMap::from([
        (
            // USDC holder
            Address::from_str(USDC_STR).unwrap(),
            (
                Bytes::from_str(TOKEN_HOLDER_ADDR).unwrap(),
                Bytes::from_str("0x43f6e8f16703").unwrap(), // Large balance
            ),
        ),
        (
            // WETH holder
            Address::from_str(WETH_STR).unwrap(),
            (
                Bytes::from_str(WETH_HOLDER_ADDR).unwrap(),
                Bytes::from_str("0x2386f26fc10000").unwrap(), /* ~0.01 WETH (large enough for
                                                               * testing) */
            ),
        ),
    ])
});

pub static TEST_SLOTS: LazyLock<HashMap<Bytes, Bytes>> = LazyLock::new(|| {
    HashMap::from([
        (
            Bytes::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            Bytes::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
        ),
        (
            Bytes::from_str("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap(),
            Bytes::from_str("00000000000000000000006048a8c631fb7e77eca533cf9c29784e482391e700")
                .unwrap(),
        ),
        (
            Bytes::from_str("00015ea75c6f99b2e8663793de8ab1ce7c52e3295bf307bbf9990d4af56f7035")
                .unwrap(),
            Bytes::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
        ),
    ])
});

/// Test fixture for creating blocks and RPC clients
pub struct TestFixture {
    pub block: Block,
    pub node_url: String,
}

impl TestFixture {
    /// Creates a new test fixture with the default test block
    pub fn new() -> Self {
        let node_url = std::env::var("RPC_URL").expect("RPC_URL must be set for testing");
        let block = Self::create_test_block();
        Self { block, node_url }
    }

    /// Creates the default test block
    fn create_test_block() -> Block {
        let block_hash = B256::from_hex(TEST_BLOCK_HASH).expect("expected valid block hash");
        Block::new(
            TEST_BLOCK_NUMBER,
            Chain::Ethereum,
            block_hash.to_bytes(),
            Default::default(),
            Default::default(),
        )
    }
}

impl Default for TestFixture {
    fn default() -> Self {
        Self::new()
    }
}
