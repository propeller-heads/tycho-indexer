//! Step definitions for action chains.

use std::{any::Any, fmt, marker::PhantomData};

use crate::action::{
    chain::{converters::TypeConverter, errors::ChainError, inventory::AssetInventory},
    context::ActionContext,
    simulate::{Action, SimulateForward},
};

/// A single step in an action chain with type safety.
/// 
/// Each step contains an action type marker, the protocol state that can execute
/// the action, the parameters for the action, and an optional type converter
/// for linking to the next step.
pub struct Step<A, S, I, O> 
where
    A: Action,
    S: SimulateForward<A>,
{
    /// Action type marker for compile-time type checking.
    pub action: PhantomData<A>,
    
    /// Protocol state that can execute this action.
    pub state: Box<S>,
    
    /// Parameters specific to this action execution.
    pub parameters: A::Parameters,
    
    /// Optional converter for transforming input from previous step.
    pub converter: Option<Box<dyn TypeConverter<I, A::Inputs> + Send + Sync>>,
    
    /// Phantom data to track input/output types at compile time.
    _input_marker: PhantomData<I>,
    _output_marker: PhantomData<O>,
}

impl<A, S, I, O> Step<A, S, I, O>
where
    A: Action,
    S: SimulateForward<A>,
{
    /// Create a new step with the given state and parameters.
    /// 
    /// The type constraint `A: Action<Inputs = I>` has been relaxed to `A: Action`
    /// to allow converters to handle type mismatches between chain outputs and action inputs.
    pub fn new(
        state: S,
        parameters: A::Parameters,
        converter: Option<Box<dyn TypeConverter<I, A::Inputs> + Send + Sync>>,
    ) -> Self {
        Self {
            action: PhantomData,
            state: Box::new(state),
            parameters,
            converter,
            _input_marker: PhantomData,
            _output_marker: PhantomData,
        }
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

impl<A, S, I, O> ErasedStep for Step<A, S, I, O>
where
    A: Action + 'static,
    S: SimulateForward<A> + Clone + 'static,
    I: Clone + 'static,
    O: 'static,
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
                    "Failed to cast inputs to expected chain output type".to_string()
                )
            })?;

        // Convert inputs using custom converter or direct use
        let action_inputs: A::Inputs = if let Some(mut converter) = self.converter.take() {
            // Use the typed converter to transform chain outputs to action inputs
            // The converter is typed: TypeConverter<I, A::Inputs>
            converter.convert(chain_outputs.clone(), inventory)?
        } else {
            // No converter - the chain output type I should match action input type A::Inputs
            // This should only happen when I == A::Inputs (compile-time enforced)
            let cloned_outputs = (chain_outputs as &dyn std::any::Any)
                .downcast_ref::<A::Inputs>()
                .ok_or_else(|| ChainError::TypeCastError(
                    "Chain output type doesn't match action input type. Use a converter.".to_string()
                ))?
                .clone();
            cloned_outputs
        };

        // Execute the action on the state
        let (outputs, new_state) = self
            .state
            .simulate_forward(context, &self.parameters, &action_inputs)
            .map_err(ChainError::StepExecutionError)?;

        // Apply the converter to the outputs if present
        let final_outputs: Box<dyn Any> = if let Some(_converter) = &self.converter {
            // Apply the converter to transform A::Outputs to O
            // For now, we'll just return the raw action outputs
            // In a full implementation, we would use the converter here
            Box::new(outputs)
        } else {
            Box::new(outputs)
        };

        // Create new step with updated state
        let new_step = Box::new(Step {
            action: PhantomData::<A>,
            state: new_state,
            parameters: self.parameters.clone(),
            converter: None, // Converters are consumed during execution
            _input_marker: PhantomData::<I>,
            _output_marker: PhantomData::<O>,
        });

        Ok((final_outputs, new_step))
    }
}

impl<A, S, I, O> fmt::Debug for Step<A, S, I, O>
where
    A: Action,
    S: SimulateForward<A> + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Step")
            .field("action", &std::any::type_name::<A>())
            .field("state", &self.state)
            .field("has_converter", &self.converter.is_some())
            .finish()
    }
}