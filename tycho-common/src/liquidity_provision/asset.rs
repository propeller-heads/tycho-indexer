//! LP asset types for representing concentrated liquidity positions.

use num_bigint::BigUint;

use crate::{
    action::asset::{Asset, PredicateDescriptor},
    models::token::Token,
    Bytes,
};

/// NFT-based position for concentrated liquidity protocols.
///
/// Represents positions like UniswapV3 where liquidity is concentrated
/// within specific price ranges and ownership is tracked via NFTs.
#[derive(Debug, Clone)]
pub struct ConcentratedLiquidityNFT {
    /// The protocol managing this position.
    pub protocol: ProtocolType,
    /// Identifier of the liquidity pool.
    pub pool_id: Bytes,
    /// Unique identifier for this position (NFT token ID).
    pub position_id: Bytes,
    /// Price range where this liquidity is active.
    pub tick_range: TickRange,
    /// Amount of liquidity in the position.
    pub liquidity_amount: BigUint,
    /// The tokens in the pool.
    pub tokens: Vec<Token>,
}

/// Price range for concentrated liquidity positions.
#[derive(Debug, Clone, PartialEq)]
pub struct TickRange {
    /// Lower price tick boundary.
    pub tick_lower: i32,
    /// Upper price tick boundary.
    pub tick_upper: i32,
}

/// Protocol type enumeration.
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolType {
    UniswapV3,
    // Add more concentrated liquidity protocols as needed
}

impl ConcentratedLiquidityNFT {
    /// Create a new concentrated liquidity NFT position.
    pub fn new(
        protocol: ProtocolType,
        pool_id: Bytes,
        position_id: Bytes,
        tick_range: TickRange,
        liquidity_amount: BigUint,
        tokens: Vec<Token>,
    ) -> Self {
        Self { protocol, pool_id, position_id, tick_range, liquidity_amount, tokens }
    }

    /// Check if this position is currently active (within price range).
    pub fn is_active(&self, current_tick: i32) -> bool {
        self.tick_range
            .contains_tick(current_tick)
    }
}

impl Asset for ConcentratedLiquidityNFT {
    fn kind(&self) -> &'static str {
        "concentrated_liquidity_nft"
    }

    fn type_id(&self) -> &Bytes {
        &self.pool_id
    }

    fn instance_id(&self) -> Option<&Bytes> {
        Some(&self.position_id)
    }

    fn amount(&self) -> Option<&BigUint> {
        Some(&self.liquidity_amount)
    }

    fn predicate_descriptor(&self, _owner: &Bytes) -> PredicateDescriptor {
        todo!("Implement predicate descriptor for concentrated liquidity NFTs")
    }
}

impl TickRange {
    /// Create a new tick range.
    pub fn new(tick_lower: i32, tick_upper: i32) -> Self {
        Self { tick_lower, tick_upper }
    }

    /// Check if a tick is within this range.
    pub fn contains_tick(&self, tick: i32) -> bool {
        tick >= self.tick_lower && tick < self.tick_upper
    }

    /// Create a full-range tick range (common constant).
    pub fn full_range() -> Self {
        Self {
            tick_lower: i32::MIN / 2, // Avoid overflow issues
            tick_upper: i32::MAX / 2,
        }
    }
}
