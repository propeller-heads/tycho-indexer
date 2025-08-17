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
    /// Identifier of the liquidity pool.
    component_id: Bytes,
    /// Unique identifier for this position (NFT token ID).
    position_id: Bytes,
    /// Price range where this liquidity is active.
    tick_range: TickRange,
    /// Amount of liquidity in the position.
    liquidity_amount: BigUint,
}

/// Price range for concentrated liquidity positions.
#[derive(Debug, Clone, PartialEq)]
pub struct TickRange {
    /// Lower price tick boundary.
    tick_lower: i32,
    /// Upper price tick boundary.
    tick_upper: i32,
}

impl ConcentratedLiquidityNFT {
    /// Create a new concentrated liquidity NFT position.
    pub fn new(
        component_id: Bytes,
        position_id: Bytes,
        tick_range: TickRange,
        liquidity_amount: BigUint,
    ) -> Result<Self, crate::simulation::errors::SimulationError> {
        use crate::simulation::errors::SimulationError;

        // Validate liquidity amount
        if liquidity_amount == BigUint::from(0u32) {
            return Err(SimulationError::InvalidInput(
                "Liquidity amount must be greater than 0".into(),
                None,
            ));
        }

        // Validate tick range
        tick_range.validate()?;

        Ok(Self { component_id, position_id, tick_range, liquidity_amount })
    }

    /// Get the pool identifier.
    pub fn pool_id(&self) -> &Bytes {
        &self.component_id
    }

    /// Get the position identifier.
    pub fn position_id(&self) -> &Bytes {
        &self.position_id
    }

    /// Get the tick range.
    pub fn tick_range(&self) -> &TickRange {
        &self.tick_range
    }

    /// Get the liquidity amount.
    pub fn liquidity_amount(&self) -> &BigUint {
        &self.liquidity_amount
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
        &self.component_id
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
    /// Create a new tick range with validation.
    pub fn new(
        tick_lower: i32,
        tick_upper: i32,
    ) -> Result<Self, crate::simulation::errors::SimulationError> {
        use crate::simulation::errors::SimulationError;

        if tick_lower >= tick_upper {
            return Err(SimulationError::InvalidInput(
                format!(
                    "tick_lower ({}) must be less than tick_upper ({})",
                    tick_lower, tick_upper
                ),
                None,
            ));
        }

        const MAX_TICK: i32 = 887272;
        const MIN_TICK: i32 = -887272;

        if tick_lower < MIN_TICK || tick_upper > MAX_TICK {
            return Err(SimulationError::InvalidInput(
                format!("Tick values must be between {} and {}", MIN_TICK, MAX_TICK),
                None,
            ));
        }

        Ok(Self { tick_lower, tick_upper })
    }

    /// Create a new tick range without validation (for internal use).
    pub(crate) fn new_unchecked(tick_lower: i32, tick_upper: i32) -> Self {
        Self { tick_lower, tick_upper }
    }

    /// Get the lower tick boundary.
    pub fn tick_lower(&self) -> i32 {
        self.tick_lower
    }

    /// Get the upper tick boundary.
    pub fn tick_upper(&self) -> i32 {
        self.tick_upper
    }

    /// Check if a tick is within this range.
    pub fn contains_tick(&self, tick: i32) -> bool {
        tick >= self.tick_lower && tick < self.tick_upper
    }

    /// Create a full-range tick range (common constant).
    pub fn full_range() -> Self {
        Self::new_unchecked(
            i32::MIN / 2, // Avoid overflow issues
            i32::MAX / 2,
        )
    }

    /// Validate this tick range.
    pub fn validate(&self) -> Result<(), crate::simulation::errors::SimulationError> {
        use crate::simulation::errors::SimulationError;

        if self.tick_lower >= self.tick_upper {
            return Err(SimulationError::InvalidInput(
                format!(
                    "tick_lower ({}) must be less than tick_upper ({})",
                    self.tick_lower, self.tick_upper
                ),
                None,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{token::Token, Chain};

    fn create_test_token(symbol: &str, address: &str) -> Token {
        Token::new(&address.into(), symbol, 18, 0, &[Some(21000u64)], Chain::Ethereum, 100)
    }

    #[test]
    fn test_tick_range_valid() {
        // Test valid tick range
        let tick_range = TickRange::new(-1000, 1000).unwrap();
        assert_eq!(tick_range.tick_lower(), -1000);
        assert_eq!(tick_range.tick_upper(), 1000);

        // Test contains_tick
        assert!(tick_range.contains_tick(-500));
        assert!(tick_range.contains_tick(0));
        assert!(tick_range.contains_tick(999));
        assert!(tick_range.contains_tick(-1000)); // Lower bound is inclusive in contains_tick
        assert!(!tick_range.contains_tick(1000)); // Upper bound is exclusive
        assert!(!tick_range.contains_tick(-1001));
        assert!(!tick_range.contains_tick(1001));

        // Test full range
        let full_range = TickRange::full_range();
        assert!(full_range.tick_lower() < full_range.tick_upper());
    }

    #[test]
    fn test_tick_range_invalid() {
        // Test invalid tick ranges
        let invalid_ranges = [
            (1000, -1000),      // upper < lower
            (100, 100),         // upper == lower
            (-2_000_000, 1000), // lower too small
            (1000, 2_000_000),  // upper too large
        ];

        for (lower, upper) in &invalid_ranges {
            let result = TickRange::new(*lower, *upper);
            assert!(result.is_err(), "Expected error for tick range ({}, {})", lower, upper);
        }
    }

    #[test]
    fn test_concentrated_liquidity_nft_valid() {
        let tick_range = TickRange::new(-1000, 1000).unwrap();

        let nft = ConcentratedLiquidityNFT::new(
            crate::Bytes::from("0xpool".as_bytes()),
            crate::Bytes::from("0xposition".as_bytes()),
            tick_range.clone(),
            BigUint::from(1000u32),
        )
        .unwrap();

        // Test getters
        assert_eq!(nft.pool_id(), &crate::Bytes::from("0xpool".as_bytes()));
        assert_eq!(nft.position_id(), &crate::Bytes::from("0xposition".as_bytes()));
        assert_eq!(nft.tick_range(), &tick_range);
        assert_eq!(nft.liquidity_amount(), &BigUint::from(1000u32));

        // Test is_active
        assert!(nft.is_active(-500));
        assert!(nft.is_active(0));
        assert!(nft.is_active(999));
        assert!(!nft.is_active(-1001));
        assert!(!nft.is_active(1001));
    }

    #[test]
    fn test_concentrated_liquidity_nft_invalid() {
        let token1 = create_test_token("USDC", "0x1111111111111111111111111111111111111111");
        let token2 = create_test_token("ETH", "0x2222222222222222222222222222222222222222");
        let tick_range = TickRange::new(-1000, 1000).unwrap();

        // Test zero liquidity amount
        let zero_liquidity = ConcentratedLiquidityNFT::new(
            crate::Bytes::from("0xpool".as_bytes()),
            crate::Bytes::from("0xposition".as_bytes()),
            tick_range.clone(),
            BigUint::from(0u32),
        );
        assert!(zero_liquidity.is_err());

        // Test with invalid tick range
        let invalid_tick_range = TickRange::new(1000, -1000); // This should fail in TickRange::new
        assert!(invalid_tick_range.is_err());
    }

    #[test]
    fn test_asset_implementation() {
        let tick_range = TickRange::new(-1000, 1000).unwrap();

        let nft = ConcentratedLiquidityNFT::new(
            crate::Bytes::from("0xpool".as_bytes()),
            crate::Bytes::from("0xposition".as_bytes()),
            tick_range,
            BigUint::from(1000u32),
        )
        .unwrap();

        // Test Asset trait implementation
        assert_eq!(nft.kind(), "concentrated_liquidity_nft");
        assert_eq!(nft.type_id(), &crate::Bytes::from("0xpool".as_bytes()));
        assert_eq!(nft.instance_id(), Some(&crate::Bytes::from("0xposition".as_bytes())));
        assert_eq!(nft.amount(), Some(&BigUint::from(1000u32)));
    }
}
