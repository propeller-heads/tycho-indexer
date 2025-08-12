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
    
    /// Optional converter for transforming output to next step's input type.
    pub converter: Option<Box<dyn TypeConverter<A::Outputs, O> + Send + Sync>>,
    
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
        converter: Option<Box<dyn TypeConverter<A::Outputs, O> + Send + Sync>>,
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
        &self,
        inputs: &dyn Any,
        context: &ActionContext,
        inventory: &mut AssetInventory,
    ) -> Result<(Box<dyn Any>, Box<dyn ErasedStep>), ChainError>;
}

impl<A, S, I, O> ErasedStep for Step<A, S, I, O>
where
    A: Action + 'static,
    S: SimulateForward<A> + Clone + 'static,
    I: 'static,
    O: 'static,
    A::Parameters: Clone + 'static,
    A::Inputs: Clone + 'static,
    A::Outputs: 'static,
{
    fn execute(
        &self,
        inputs: &dyn Any,
        context: &ActionContext,
        _inventory: &mut AssetInventory,
    ) -> Result<(Box<dyn Any>, Box<dyn ErasedStep>), ChainError> {
        // For chaining steps, we need to convert chain outputs (type I) to action inputs (type A::Inputs)
        // For ERC20 chains, this means converting DefaultOutputs<ERC20Asset> to DefaultInputs<ERC20Asset>
        
        use crate::action::simulate::{DefaultInputs, DefaultOutputs};
        use crate::asset::erc20::ERC20Asset;
        
        // First, try to cast inputs to the chain output type I
        let chain_outputs = inputs
            .downcast_ref::<I>()
            .ok_or_else(|| {
                ChainError::TypeCastError(
                    "Failed to cast inputs to expected chain output type".to_string()
                )
            })?;

        // For ERC20 chains with converters, convert DefaultOutputs to DefaultInputs
        let action_inputs: Box<dyn Any> = if self.converter.is_some() {
            // This is a converting step - handle the specific ERC20 case
            if let Some(outputs) = (chain_outputs as &dyn std::any::Any).downcast_ref::<DefaultOutputs<ERC20Asset>>() {
                let produced_assets = outputs.produced().clone();
                let inputs = DefaultInputs(produced_assets);
                Box::new(inputs)
            } else {
                return Err(ChainError::TypeCastError(
                    "Failed to convert chain outputs to action inputs".to_string()
                ));
            }
        } else {
            // No converter - clone the chain outputs to avoid lifetime issues
            let cloned_outputs = (chain_outputs as &dyn std::any::Any)
                .downcast_ref::<A::Inputs>()
                .ok_or_else(|| ChainError::TypeCastError("Failed to downcast non-converting inputs".to_string()))?
                .clone();
            Box::new(cloned_outputs)
        };

        // Cast to the action's expected input type
        let typed_inputs = action_inputs
            .downcast_ref::<A::Inputs>()
            .ok_or_else(|| {
                ChainError::TypeCastError(
                    "Failed to cast converted inputs to action input type".to_string()
                )
            })?;

        // Execute the action on the state
        let (outputs, new_state) = self
            .state
            .simulate_forward(context, &self.parameters, typed_inputs)
            .map_err(ChainError::StepExecutionError)?;

        // Return the action outputs (will be passed to next step)
        let step_outputs: Box<dyn Any> = Box::new(outputs);

        // Create new step with updated state
        let new_step = Box::new(Step {
            action: PhantomData::<A>,
            state: new_state,
            parameters: self.parameters.clone(),
            converter: None, // Converters are consumed during execution
            _input_marker: PhantomData::<I>,
            _output_marker: PhantomData::<O>,
        });

        Ok((step_outputs, new_step))
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