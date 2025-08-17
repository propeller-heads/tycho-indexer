//! Core liquidity provision actions.

use std::fmt;

use num_bigint::BigUint;

use crate::{
    action::{
        asset::Asset,
        context::ActionContext,
        liquidity_provision::asset::{ConcentratedLiquidityNFT, TickRange},
        simulate::{Action, ActionOutput, DefaultInputs, SimulateForward},
    },
    asset::erc20::{ERC20Asset, ERC20DefaultOutputs},
    simulation::errors::SimulationError,
};
// =============================================================================
// Actions for Full Range LP (ERC20 LP Tokens)
// =============================================================================

/// Action for adding liquidity to full-range pools (UniswapV2, Curve, Balancer).
/// Produces ERC20 LP tokens.
#[derive(Debug)]
pub struct AddLiquidityFullRange;

/// Action for removing liquidity from full-range pools.
/// Consumes ERC20 LP tokens, produces underlying tokens.
#[derive(Debug)]
pub struct RemoveLiquidityFullRange;

// =============================================================================
// Actions for Concentrated Liquidity (NFT Positions)
// =============================================================================

/// Action for adding concentrated liquidity (UniswapV3-style).
/// Produces NFT positions with specific tick ranges.
#[derive(Debug)]
pub struct AddLiquidityConcentrated;

/// Action for removing concentrated liquidity.
/// Consumes NFT positions, produces underlying tokens.
#[derive(Debug)]
pub struct RemoveLiquidityConcentrated;

/// Action for collecting fees from concentrated liquidity positions.
#[derive(Debug)]
pub struct CollectFeesConcentrated;

// =============================================================================
// Parameters
// =============================================================================

/// Parameters for adding full-range liquidity.
#[derive(Debug, Clone)]
pub struct AddLiquidityFullRangeParameters;

/// Parameters for adding concentrated liquidity.
#[derive(Debug, Clone)]
pub struct AddLiquidityConcentratedParameters {
    /// Price range for the concentrated position.
    tick_range: TickRange,
}

impl AddLiquidityConcentratedParameters {
    /// Create new parameters with the specified tick range.
    pub fn new(tick_range: TickRange) -> Result<Self, SimulationError> {
        tick_range.validate()?;
        Ok(Self { tick_range })
    }

    /// Create new parameters with full range (tick bounds covering entire price range).
    pub fn full_range() -> Self {
        Self { tick_range: TickRange::full_range() }
    }

    /// Get the tick range.
    pub fn tick_range(&self) -> &TickRange {
        &self.tick_range
    }

    /// Set a new tick range with validation.
    pub fn with_tick_range(mut self, tick_range: TickRange) -> Result<Self, SimulationError> {
        tick_range.validate()?;
        self.tick_range = tick_range;
        Ok(self)
    }
}

/// Parameters for removing liquidity.
#[derive(Debug, Clone)]
pub struct RemoveLiquidityParameters {
    /// How much liquidity to remove.
    amount: LiquidityAmount,
}

impl RemoveLiquidityParameters {
    /// Create new parameters to remove a specific amount of liquidity.
    pub fn exact_amount(amount: BigUint) -> Result<Self, SimulationError> {
        if amount == BigUint::from(0u32) {
            return Err(SimulationError::InvalidInput(
                "Liquidity amount must be greater than 0".into(),
                None,
            ));
        }
        Ok(Self { amount: LiquidityAmount::Exact(amount) })
    }

    /// Create new parameters to remove all liquidity from the position.
    pub fn remove_all() -> Self {
        Self { amount: LiquidityAmount::All }
    }

    /// Get the liquidity amount.
    pub fn amount(&self) -> &LiquidityAmount {
        &self.amount
    }
}

/// Parameters for collecting fees from concentrated positions.
#[derive(Debug, Clone)]
pub struct CollectFeesConcentratedParameters;

// =============================================================================
// Supporting Types
// =============================================================================

/// Amount specification for liquidity removal.
#[derive(Debug, Clone)]
pub enum LiquidityAmount {
    /// Specific amount of LP tokens or liquidity.
    Exact(BigUint),
    /// Remove entire position.
    All,
}

/// Result of adding concentrated liquidity.
#[derive(Debug, Clone)]
pub struct ConcentratedLiquidityResult {
    /// The NFT position created.
    position: ConcentratedLiquidityNFT,
    /// Any refunded tokens (unused inputs).
    refunds: Vec<ERC20Asset>,
    /// Gas consumed in the operation.
    gas_used: BigUint,
}

impl ConcentratedLiquidityResult {
    /// Create a new concentrated liquidity result.
    pub fn new(
        position: ConcentratedLiquidityNFT,
        refunds: Vec<ERC20Asset>,
        gas_used: BigUint,
    ) -> Self {
        Self { position, refunds, gas_used }
    }

    /// Get the NFT position created.
    pub fn position(&self) -> &ConcentratedLiquidityNFT {
        &self.position
    }

    /// Get any refunded tokens.
    pub fn refunds(&self) -> &[ERC20Asset] {
        &self.refunds
    }

    /// Get the gas consumed.
    pub fn gas_used(&self) -> &BigUint {
        &self.gas_used
    }
}

impl ActionOutput for ConcentratedLiquidityResult {
    fn used(&self) -> impl Iterator<Item = Box<dyn Asset>> {
        Vec::new().into_iter()
    }

    fn produced(&self) -> impl Iterator<Item = Box<dyn Asset>> {
        Vec::new().into_iter()
    }
}

// =============================================================================
// Action Implementations
// =============================================================================

impl Action for AddLiquidityFullRange {
    type Parameters = AddLiquidityFullRangeParameters;
    type Inputs = DefaultInputs<ERC20Asset>;
    type Outputs = ERC20DefaultOutputs; // Produced LP tokens + refunds
}

impl Action for AddLiquidityConcentrated {
    type Parameters = AddLiquidityConcentratedParameters;
    type Inputs = DefaultInputs<ERC20Asset>;
    type Outputs = ConcentratedLiquidityResult; // Mixed types: NFT position + ERC20 refunds
}

impl Action for RemoveLiquidityFullRange {
    type Parameters = RemoveLiquidityParameters;
    type Inputs = DefaultInputs<ERC20Asset>; // LP token to remove
    type Outputs = ERC20DefaultOutputs; // Used LP tokens + produced underlying tokens & incentives
}

impl Action for RemoveLiquidityConcentrated {
    type Parameters = RemoveLiquidityParameters;
    type Inputs = DefaultInputs<ConcentratedLiquidityNFT>; // NFT position to remove
    type Outputs = ERC20DefaultOutputs; // Produced underlying tokens & incentives
}

impl Action for CollectFeesConcentrated {
    type Parameters = CollectFeesConcentratedParameters;
    type Inputs = DefaultInputs<ConcentratedLiquidityNFT>; // NFT position to collect from
    type Outputs = ERC20DefaultOutputs; // Fee tokens & incentives received
}

// =============================================================================
// High-level Traits
// =============================================================================

/// High-level interface for full-range liquidity provision (ERC20 LP tokens).
pub trait FullRangeLiquidityProvider: fmt::Debug + Send + Sync + 'static {
    /// Add liquidity to a full-range pool.
    fn add_liquidity(
        &self,
        context: &ActionContext,
        inputs: &[ERC20Asset],
    ) -> Result<(ERC20DefaultOutputs, Box<Self>), SimulationError>;

    /// Remove liquidity from a full-range pool.
    fn remove_liquidity(
        &self,
        context: &ActionContext,
        params: &RemoveLiquidityParameters,
        lp_token: &ERC20Asset,
    ) -> Result<(ERC20DefaultOutputs, Box<Self>), SimulationError>;
}

/// High-level interface for concentrated liquidity provision (NFT positions).
pub trait ConcentratedLiquidityProvider: fmt::Debug + Send + Sync + 'static {
    /// Add concentrated liquidity to create a new NFT position.
    fn add_liquidity(
        &self,
        context: &ActionContext,
        params: &AddLiquidityConcentratedParameters,
        inputs: &[ERC20Asset],
    ) -> Result<(ConcentratedLiquidityResult, Box<Self>), SimulationError>;

    /// Remove liquidity from NFT position.
    fn remove_liquidity(
        &self,
        context: &ActionContext,
        params: &RemoveLiquidityParameters,
        position: &ConcentratedLiquidityNFT,
    ) -> Result<(ERC20DefaultOutputs, Box<Self>), SimulationError>;

    /// Collect fees from NFT position.
    fn collect_fees(
        &self,
        context: &ActionContext,
        params: &CollectFeesConcentratedParameters,
        position: &ConcentratedLiquidityNFT,
    ) -> Result<(ERC20DefaultOutputs, Box<Self>), SimulationError>;
}

// =============================================================================
// Adapter Implementations
// =============================================================================

/// Adapter for full-range liquidity providers.
#[derive(Debug)]
pub struct FullRangeLiquidityProviderWrapper<T> {
    /// The underlying action implementation.
    wrapped: Box<T>,
}

impl<T> FullRangeLiquidityProviderWrapper<T> {
    /// Create a new wrapper around an action implementation.
    pub fn new(wrapped: Box<T>) -> Self {
        Self { wrapped }
    }
}

impl<T> FullRangeLiquidityProvider for FullRangeLiquidityProviderWrapper<T>
where
    T: SimulateForward<AddLiquidityFullRange>
        + SimulateForward<RemoveLiquidityFullRange>
        + fmt::Debug
        + Send
        + Sync
        + 'static,
{
    fn add_liquidity(
        &self,
        context: &ActionContext,
        inputs: &[ERC20Asset],
    ) -> Result<(ERC20DefaultOutputs, Box<Self>), SimulationError> {
        let params = AddLiquidityFullRangeParameters;
        let default_inputs = DefaultInputs(inputs.to_vec());
        let (outputs, new_state): (ERC20DefaultOutputs, Box<T>) =
            <T as SimulateForward<AddLiquidityFullRange>>::simulate_forward(
                &*self.wrapped,
                context,
                &params,
                &default_inputs,
            )?;

        Ok((outputs, Box::new(Self { wrapped: new_state })))
    }

    fn remove_liquidity(
        &self,
        context: &ActionContext,
        params: &RemoveLiquidityParameters,
        lp_token: &ERC20Asset,
    ) -> Result<(ERC20DefaultOutputs, Box<Self>), SimulationError> {
        let (outputs, new_state): (ERC20DefaultOutputs, Box<T>) =
            <T as SimulateForward<RemoveLiquidityFullRange>>::simulate_forward(
                &*self.wrapped,
                context,
                params,
                &DefaultInputs(vec![lp_token.clone()]),
            )?;

        Ok((outputs, Box::new(Self { wrapped: new_state })))
    }
}

/// Adapter for concentrated liquidity providers.
#[derive(Debug)]
pub struct ConcentratedLiquidityProviderWrapper<T> {
    /// The underlying action implementation.
    wrapped: Box<T>,
}

impl<T> ConcentratedLiquidityProviderWrapper<T> {
    /// Create a new wrapper around an action implementation.
    pub fn new(wrapped: Box<T>) -> Self {
        Self { wrapped }
    }
}

impl<T> ConcentratedLiquidityProvider for ConcentratedLiquidityProviderWrapper<T>
where
    T: SimulateForward<AddLiquidityConcentrated>
        + SimulateForward<RemoveLiquidityConcentrated>
        + SimulateForward<CollectFeesConcentrated>
        + fmt::Debug
        + Send
        + Sync
        + 'static,
{
    fn add_liquidity(
        &self,
        context: &ActionContext,
        params: &AddLiquidityConcentratedParameters,
        inputs: &[ERC20Asset],
    ) -> Result<(ConcentratedLiquidityResult, Box<Self>), SimulationError> {
        let default_inputs = DefaultInputs(inputs.to_vec());
        let (result, new_state): (ConcentratedLiquidityResult, Box<T>) =
            <T as SimulateForward<AddLiquidityConcentrated>>::simulate_forward(
                &*self.wrapped,
                context,
                params,
                &default_inputs,
            )?;

        Ok((result, Box::new(Self { wrapped: new_state })))
    }

    fn remove_liquidity(
        &self,
        context: &ActionContext,
        params: &RemoveLiquidityParameters,
        position: &ConcentratedLiquidityNFT,
    ) -> Result<(ERC20DefaultOutputs, Box<Self>), SimulationError> {
        let (outputs, new_state): (ERC20DefaultOutputs, Box<T>) =
            <T as SimulateForward<RemoveLiquidityConcentrated>>::simulate_forward(
                &*self.wrapped,
                context,
                params,
                &DefaultInputs(vec![position.clone()]),
            )?;

        Ok((outputs, Box::new(Self { wrapped: new_state })))
    }

    fn collect_fees(
        &self,
        context: &ActionContext,
        params: &CollectFeesConcentratedParameters,
        position: &ConcentratedLiquidityNFT,
    ) -> Result<(ERC20DefaultOutputs, Box<Self>), SimulationError> {
        let (outputs, new_state): (ERC20DefaultOutputs, Box<T>) =
            <T as SimulateForward<CollectFeesConcentrated>>::simulate_forward(
                &*self.wrapped,
                context,
                params,
                &DefaultInputs(vec![position.clone()]),
            )?;

        Ok((outputs, Box::new(Self { wrapped: new_state })))
    }
}

// =============================================================================
// Helper Implementations
// =============================================================================

impl LiquidityAmount {
    /// Check if this represents removing the entire position.
    pub fn is_full_withdrawal(&self) -> bool {
        matches!(self, LiquidityAmount::All)
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
    fn test_add_liquidity_concentrated_parameters() {
        let tick_range = TickRange::new(-1000, 1000).unwrap();

        // Test successful creation
        let params = AddLiquidityConcentratedParameters::new(tick_range.clone()).unwrap();
        assert_eq!(params.tick_range(), &tick_range);

        // Test full range creation
        let full_range_params = AddLiquidityConcentratedParameters::full_range();
        assert!(
            full_range_params
                .tick_range()
                .tick_lower() <
                full_range_params
                    .tick_range()
                    .tick_upper()
        );

        // Test with_tick_range
        let new_tick_range = TickRange::new(-500, 500).unwrap();
        let updated = params
            .with_tick_range(new_tick_range.clone())
            .unwrap();
        assert_eq!(updated.tick_range(), &new_tick_range);
    }

    #[test]
    fn test_add_liquidity_concentrated_parameters_invalid() {
        // Test invalid tick range
        let invalid_tick_range = TickRange::new(1000, -1000); // upper < lower
        assert!(invalid_tick_range.is_err());

        if let Ok(tick_range) = TickRange::new(-1000, 1000) {
            let params = AddLiquidityConcentratedParameters::new(tick_range);
            assert!(params.is_ok());
        }
    }

    #[test]
    fn test_remove_liquidity_parameters() {
        // Test exact amount
        let amount = BigUint::from(1000u32);
        let params = RemoveLiquidityParameters::exact_amount(amount.clone()).unwrap();
        if let LiquidityAmount::Exact(exact_amount) = params.amount() {
            assert_eq!(exact_amount, &amount);
        } else {
            panic!("Expected Exact amount");
        }

        // Test remove all
        let params = RemoveLiquidityParameters::remove_all();
        assert!(params.amount().is_full_withdrawal());

        // Test invalid amount (zero)
        let zero_params = RemoveLiquidityParameters::exact_amount(BigUint::from(0u32));
        assert!(zero_params.is_err());
    }

    #[test]
    fn test_concentrated_liquidity_result() {
        let token1 = create_test_token("USDC", "0x1111111111111111111111111111111111111111");
        let token2 = create_test_token("ETH", "0x2222222222222222222222222222222222222222");
        let tick_range = TickRange::new(-1000, 1000).unwrap();

        let position = ConcentratedLiquidityNFT::new(
            crate::Bytes::from("0xpool".as_bytes()),
            crate::Bytes::from("0xposition".as_bytes()),
            tick_range,
            BigUint::from(1000u32),
        )
        .unwrap();

        let refunds = vec![];
        let gas_used = BigUint::from(50000u32);

        let result = ConcentratedLiquidityResult::new(position, refunds.clone(), gas_used.clone());

        assert_eq!(result.refunds().len(), refunds.len());
        assert_eq!(result.gas_used(), &gas_used);
        assert!(result.position().liquidity_amount() == &BigUint::from(1000u32));
    }
}
