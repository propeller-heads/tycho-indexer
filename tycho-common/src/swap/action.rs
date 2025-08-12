//! Swap action implementation bridging low-level actions and high-level Swappable interface.
//!
//! This module provides the concrete implementation that connects the generic action system
//! with the domain-specific swapping interface, enabling protocol implementations to be
//! used through the standardized `Swappable` trait.

use std::fmt::{Debug, Formatter};

use crate::{
    action::{
        asset::Asset,
        simulate::{Action, DefaultInputs, DefaultOutputs, SimulateForward},
    },
    asset::erc20::ERC20Asset,
    models::token::Token,
    simulation::errors::SimulationError,
    swap::{
        approximation::{LimitsApproximator, MarginalPriceApproximator},
        AmountLimits, LimitsParameters, MarginalPriceParameters, QuoteParameters, SwapQuote,
        Swappable,
    },
};

/// Zero-sized type representing the swap action.
///
/// Serves as a marker type for the action system, defining the structure
/// of swap operations without containing any data.
pub struct Swap;

/// Parameters for swap action execution.
///
/// Specifies the target output token for the swap operation.
/// The input token and amount are provided through the action inputs.
#[derive(Clone)]
pub struct SwapParameters {
    /// The token expected as output from the swap.
    output_token: Token,
}

impl SwapParameters {
    /// Create new swap parameters with the specified output token.
    pub fn new(output_token: Token) -> Self {
        Self { output_token }
    }

    /// Get the output token.
    pub fn output_token(&self) -> &Token {
        &self.output_token
    }
}

impl Action for Swap {
    type Parameters = SwapParameters;
    type Inputs = DefaultInputs<ERC20Asset>;
    type Outputs = DefaultOutputs<ERC20Asset>;
}

/// Adapter that bridges action-based implementations to the Swappable interface.
///
/// Wraps low-level action implementations and approximation logic to provide
/// the high-level methods expected by the `Swappable` trait. This enables
/// protocol-specific implementations to be used through a standardized interface.
pub struct SwappableWrapper<T, P, L> {
    /// The underlying action implementation that handles swap execution.
    wrapped: Box<T>,
    /// Approximator for calculating marginal prices from the wrapped implementation.
    price_approximator: P,
    /// Approximator for determining swap amount limits from the wrapped implementation.
    limits_approximator: L,
}

impl<T: Debug, P, L> Debug for SwappableWrapper<T, P, L> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.wrapped, f)
    }
}

impl<T, P, L> Swappable for SwappableWrapper<T, P, L>
where
    T: SimulateForward<Swap> + Debug + Send + Sync + 'static,
    P: MarginalPriceApproximator<T> + Clone + Send + Sync + 'static,
    L: LimitsApproximator<T> + Clone + Send + Sync + 'static,
{
    fn minimum_fee(&self, params: MarginalPriceParameters) -> Result<f64, SimulationError> {
        let bid = self.marginal_price(params)?;
        let ask = self.marginal_price(params.flip())?;
        Ok((bid - ask).abs())
    }

    fn marginal_price(&self, params: MarginalPriceParameters) -> Result<f64, SimulationError> {
        Ok(self
            .price_approximator
            .approximate(self.wrapped.as_ref(), &params)?)
    }

    fn quote(&self, quote_parameters: QuoteParameters) -> Result<SwapQuote, SimulationError> {
        let params = SwapParameters::new(quote_parameters.output.clone());
        let inputs = DefaultInputs(vec![ERC20Asset::new(
            quote_parameters.input.clone(),
            quote_parameters.amount,
        )]);
        let (res, new_state) =
            self.wrapped
                .simulate_forward(quote_parameters.context, &params, &inputs)?;

        let output = res.produced().last().ok_or_else(|| {
            SimulationError::FatalError(
                "Underlying SwapAction produced no asset outputs".to_string(),
            )
        })?;
        let amount = output
            .amount()
            .cloned()
            .ok_or_else(|| {
                SimulationError::FatalError("Underlying SwapAction produced no amount".to_string())
            })?;
        Ok(SwapQuote::new(
            amount,
            res.gas_spent().clone(),
            Box::new(Self {
                wrapped: new_state,
                price_approximator: self.price_approximator.clone(),
                limits_approximator: self.limits_approximator.clone(),
            }),
        ))
    }

    fn get_limits(&self, params: LimitsParameters) -> Result<AmountLimits, SimulationError> {
        Ok(self
            .limits_approximator
            .approximate(self.wrapped.as_ref(), &params)?)
    }
}
