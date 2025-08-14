//! Core liquidity provision actions.

use std::fmt;

use num_bigint::BigUint;

use crate::{
    action::{
        asset::Asset,
        context::ActionContext,
        simulate::{Action, ActionOutput, DefaultInputs, SimulateForward},
    },
    asset::erc20::{ERC20Asset, ERC20DefaultOutputs},
    liquidity_provision::asset::{ConcentratedLiquidityNFT, TickRange},
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
    pub tick_range: TickRange,
}

/// Parameters for removing liquidity.
#[derive(Debug, Clone)]
pub struct RemoveLiquidityParameters {
    /// How much liquidity to remove.
    pub amount: LiquidityAmount,
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
    pub position: ConcentratedLiquidityNFT,
    /// Any refunded tokens (unused inputs).
    pub refunds: Vec<ERC20Asset>,
    /// Gas consumed in the operation.
    pub gas_used: BigUint,
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
