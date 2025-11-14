//! Common test fixtures and utilities for tycho-ethereum tests
//!
//! This module contains shared test constants, helper functions, and fixtures
//! that can be used across multiple test files in the crate.

use std::{collections::HashMap, str::FromStr, sync::LazyLock};

use alloy::{
    primitives::B256,
    rpc::client::{ClientBuilder, ReqwestClient},
};
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
pub const USDT_STR: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
pub const WETH_STR: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

// Common token addresses array
pub const TOKEN_ADDRESSES: [&str; 5] = [BALANCER_VAULT_STR, STETH_STR, DAI_STR, WBTC_STR, USDC_STR];

// Contract-specific test constants for expected slot counts at TEST_BLOCK_NUMBER
pub const BALANCER_VAULT_EXPECTED_SLOTS: usize = 47690;
pub const STETH_EXPECTED_SLOTS: usize = 789526;

// Known token holders for testing (addresses with large balances)
// Using USV4 pool manager as a holder with known large balances
pub const USDC_HOLDER_ADDR: &str = "0x000000000004444c5dc75cB358380D2e3dE08A90";
pub const USDC_HOLDER_BALANCE: u64 = 74743132960379_u64; // Balance at the test block

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
                Bytes::from_str(USDC_HOLDER_ADDR).unwrap(),
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

pub static TEST_SLOTS: LazyLock<HashMap<B256, B256>> = LazyLock::new(|| {
    HashMap::from([
        (
            B256::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            B256::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
        ),
        (
            B256::from_str("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap(),
            B256::from_str("00000000000000000000006048a8c631fb7e77eca533cf9c29784e482391e700")
                .unwrap(),
        ),
        (
            B256::from_str("00015ea75c6f99b2e8663793de8ab1ce7c52e3295bf307bbf9990d4af56f7035")
                .unwrap(),
            B256::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
        ),
    ])
});

static RPC_CLIENT: LazyLock<ReqwestClient> = LazyLock::new(|| {
    let url = std::env::var("RPC_URL")
        .expect("RPC_URL must be set for testing")
        .parse()
        .expect("Invalid RPC_URL");
    ClientBuilder::default().http(url)
});

/// Test fixture for creating blocks and RPC clients
pub struct TestFixture {
    pub block: Block,
    pub inner_rpc: ReqwestClient,
    pub url: String,
}

impl TestFixture {
    /// Creates a new test fixture with the default test block and rpc url parsed from env
    pub fn new() -> Self {
        let chain = Chain::Ethereum;

        // Clone the static RPC client to support reuse across tests
        let inner_rpc = RPC_CLIENT.clone();

        // wait for 1 second to avoid rate limiting
        // TODO: improve rate limiting handling
        std::thread::sleep(std::time::Duration::from_secs(5));

        let block_hash = B256::from_str(TEST_BLOCK_HASH).expect("expected valid block hash");
        let block = Block::new(
            TEST_BLOCK_NUMBER,
            chain,
            block_hash.to_bytes(),
            Default::default(),
            Default::default(),
        );

        let url = std::env::var("RPC_URL").expect("RPC_URL must be set for testing");
        Self { block, inner_rpc, url }
    }
}

impl Default for TestFixture {
    fn default() -> Self {
        Self::new()
    }
}
