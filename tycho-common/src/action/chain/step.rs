//! Step definitions for action chains.

use std::{any::Any, fmt, marker::PhantomData};

use crate::action::{
    chain::{converters::StepLinker, errors::ChainError, inventory::AssetInventory},
    context::ActionContext,
    simulate::{Action, ActionOutput, SimulateForward},
};

/// A single step in an action chain with type safety.
///
/// Each step contains the protocol state that can execute the action,
/// the parameters for the action, and an optional type converter
/// for linking to the next step.
pub struct Step<A, S, I>
where
    A: Action,
    S: SimulateForward<A>,
{
    /// Protocol state that can execute this action.
    pub state: Box<S>,

    /// Parameters specific to this action execution.
    pub parameters: A::Parameters,

    /// Optional step linker for transforming input from previous step.
    pub linker: Option<Box<dyn StepLinker<I, A::Inputs> + Send + Sync>>,

    /// Phantom data to track input type at compile time.
    _input_marker: PhantomData<I>,
}

impl<A, S, I> Step<A, S, I>
where
    A: Action,
    S: SimulateForward<A>,
{
    /// Create a new step with the given state and parameters.
    ///
    /// The type constraint `A: Action<Inputs = I>` has been relaxed to `A: Action`
    /// to allow step linkers to handle type mismatches between chain outputs and action inputs.
    pub fn new(
        state: S,
        parameters: A::Parameters,
        linker: Option<Box<dyn StepLinker<I, A::Inputs> + Send + Sync>>,
    ) -> Self {
        Self { state: Box::new(state), parameters, linker, _input_marker: PhantomData }
    }
}

/// Type-erased interface for step execution.
///
/// This trait enables storing steps of different types in a single collection
/// while preserving the ability to execute them at runtime. The type erasure
/// is necessary because each step may have different action and state types.
pub trait ErasedStep {
    /// Execute the step with type-erased inputs and context.
    ///
    /// Returns the type-erased outputs and the new state after execution.
    /// The caller is responsible for casting the inputs and outputs to the
    /// correct types based on the chain construction.
    fn execute(
        self: Box<Self>,
        inputs: &dyn Any,
        context: &ActionContext,
        inventory: &mut AssetInventory,
    ) -> Result<(Box<dyn Any>, Box<dyn ErasedStep>), ChainError>;
}

impl<A, S, I> ErasedStep for Step<A, S, I>
where
    A: Action + 'static,
    S: SimulateForward<A> + Clone + 'static,
    I: Clone + 'static,
    A::Parameters: Clone + 'static,
    A::Inputs: Clone + 'static,
    A::Outputs: 'static,
{
    fn execute(
        mut self: Box<Self>,
        inputs: &dyn Any,
        context: &ActionContext,
        inventory: &mut AssetInventory,
    ) -> Result<(Box<dyn Any>, Box<dyn ErasedStep>), ChainError> {
        // First, cast inputs to the chain output type I
        let chain_outputs = inputs
            .downcast_ref::<I>()
            .ok_or_else(|| {
                ChainError::TypeCastError(
                    "Failed to cast inputs to expected chain output type".to_string(),
                )
            })?;

        // Convert inputs using custom linker or direct use
        let action_inputs: A::Inputs = if let Some(mut linker) = self.linker.take() {
            // Use the typed linker to transform chain outputs to action inputs
            // The linker is typed: StepLinker<I, A::Inputs>
            linker.convert(chain_outputs.clone(), inventory)?
        } else {
            // No linker - the chain output type I should match action input type A::Inputs
            // This should only happen when I == A::Inputs (compile-time enforced)
            let cloned_outputs = (chain_outputs as &dyn std::any::Any)
                .downcast_ref::<A::Inputs>()
                .ok_or_else(|| {
                    ChainError::TypeCastError(
                        "Chain output type doesn't match action input type. Use a step linker."
                            .to_string(),
                    )
                })?
                .clone();
            cloned_outputs
        };

        // Execute the action on the state
        let (outputs, new_state) = self
            .state
            .simulate_forward(context, &self.parameters, &action_inputs)
            .map_err(ChainError::StepExecutionError)?;

        // Store produced assets in inventory (with automatic accumulation)
        for produced_asset in outputs.produced() {
            inventory
                .store(produced_asset)
                .map_err(|e| {
                    ChainError::InventoryError(format!("Failed to store produced asset: {}", e))
                })?;
        }

        // Apply the linker to the outputs if present
        let final_outputs: Box<dyn Any> = if let Some(_linker) = &self.linker {
            // Apply the linker to transform A::Outputs to O
            // For now, we'll just return the raw action outputs
            // In a full implementation, we would use the linker here
            Box::new(outputs)
        } else {
            Box::new(outputs)
        };

        // Create new step with updated state
        let new_step = Box::new(Step {
            state: new_state,
            parameters: self.parameters.clone(),
            linker: None, // Linkers are consumed during execution
            _input_marker: PhantomData::<I>,
        });

        Ok((final_outputs, new_step))
    }
}

impl<A, S, I> fmt::Debug for Step<A, S, I>
where
    A: Action,
    S: SimulateForward<A> + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Step")
            .field("action", &std::any::type_name::<A>())
            .field("state", &self.state)
            .field("has_linker", &self.linker.is_some())
            .finish()
    }
}
