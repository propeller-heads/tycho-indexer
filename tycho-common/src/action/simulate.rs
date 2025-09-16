//! Core simulation traits for the action system.
//!
//! This module defines the fundamental traits that enable type-safe simulation of
//! on-chain actions with proper state management and standardized input/output handling.

use num_bigint::BigUint;

use crate::{
    action::{asset::Asset, context::ActionContext},
    simulation::errors::SimulationError,
};

/// Defines a structure for action results
///
/// An action result should at least specify how much it ended up using as well as how
/// much it produced. This is useful if e.g. not all inputs could be used (for example
/// for lp action the tokens must be supplied in a very specific ration which often may
/// leave some tokens for the user).
pub trait ActionOutput: Clone {
    fn used(&self) -> impl Iterator<Item = Box<dyn Asset>>;
    fn produced(&self) -> impl Iterator<Item = Box<dyn Asset>>;
}

/// Defines the structure of an on-chain action.
///
/// Actions are the fundamental building blocks of the simulation system. They specify
/// the type relationships between execution parameters, required inputs, and expected outputs
/// without defining the actual execution logic.
pub trait Action {
    /// Configuration parameters specific to the action type.
    /// These remain constant for a given action instance.
    type Parameters;

    /// Assets or data required to execute the action.
    /// These are consumed or transformed during execution.
    type Inputs: Clone + IntoIterator<Item = Box<dyn Asset>>;

    /// Results produced by the action execution.
    /// Include both asset outputs and execution metadata.
    type Outputs: ActionOutput;
}

/// Stateless simulation of actions.
///
/// Implementations provide read-only simulation that doesn't modify the underlying state.
/// Useful for price queries, feasibility checks, and other non-mutating operations.
pub trait Simulate<A: Action> {
    /// Execute the action simulation without state changes.
    ///
    /// Returns the expected outputs of the action without modifying the implementor's state.
    /// Multiple calls with the same inputs should produce identical results.
    fn simulate(
        &self,
        context: &ActionContext,
        params: &A::Parameters,
        inputs: &A::Inputs,
    ) -> Result<A::Outputs, SimulationError>;
}

/// Stateful simulation of actions with state transitions.
///
/// Implementations simulate actions that modify state and return both the execution results
/// and the new state. This enables simulation of action sequences and state-dependent behavior.
pub trait SimulateForward<A: Action> {
    /// Execute the action simulation with state progression.
    ///
    /// Returns both the action outputs and a new instance representing the post-execution state.
    /// The returned state should be used for subsequent action simulations in a sequence.
    fn simulate_forward(
        &self,
        context: &ActionContext,
        params: &A::Parameters,
        inputs: &A::Inputs,
    ) -> Result<(A::Outputs, Box<Self>), SimulationError>;
}

/// Standard input structure for actions that consume assets.
///
/// Provides a common pattern for actions that require a list of assets as input.
/// The wrapped vector contains the assets to be consumed or transformed.
#[derive(Clone)]
pub struct DefaultInputs<A: Asset>(pub Vec<A>);

impl<A: Asset + 'static> IntoIterator for DefaultInputs<A> {
    type Item = Box<dyn Asset>;
    type IntoIter = std::iter::Map<std::vec::IntoIter<A>, fn(A) -> Box<dyn Asset>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .into_iter()
            .map(|a| Box::new(a) as Box<dyn Asset>)
    }
}

/// Standard output structure for asset-producing actions.
///
/// Captures the complete result of an action execution including asset flows
/// and gas consumption for comprehensive simulation tracking.
#[derive(Clone)]
pub struct DefaultOutputs<I: Asset, O: Asset> {
    /// Assets consumed during action execution.
    used: Vec<I>,

    /// Assets produced as a result of the action.
    produced: Vec<O>,

    /// Total gas consumed by the action execution.
    gas_spent: BigUint,
}

impl<I: Asset, O: Asset> DefaultOutputs<I, O> {
    /// Create new default outputs.
    pub fn new(used: Vec<I>, produced: Vec<O>, gas_spent: BigUint) -> Self {
        Self { used, produced, gas_spent }
    }

    /// Get the assets that were consumed during execution.
    pub fn used(&self) -> &Vec<I> {
        &self.used
    }

    /// Get the assets that were produced during execution.
    pub fn produced(&self) -> &Vec<O> {
        &self.produced
    }

    /// Get the total gas consumed during execution.
    pub fn gas_spent(&self) -> &BigUint {
        &self.gas_spent
    }
}

impl<I, O> ActionOutput for DefaultOutputs<I, O>
where
    I: Asset + Clone + 'static,
    O: Asset + Clone + 'static,
{
    fn used(&self) -> impl Iterator<Item = Box<dyn Asset>> {
        self.used
            .clone()
            .into_iter()
            .map(|a| Box::new(a) as Box<dyn Asset>)
    }

    fn produced(&self) -> impl Iterator<Item = Box<dyn Asset>> {
        self.produced
            .clone()
            .into_iter()
            .map(|a| Box::new(a) as Box<dyn Asset>)
    }
}
