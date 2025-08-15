//! Chain execution engine for running action sequences.

use std::{any::Any, marker::PhantomData};

use crate::action::{
    chain::{errors::ChainError, inventory::AssetInventory, step::ErasedStep},
    context::ActionContext,
};

/// An executable chain of actions with type safety.
///
/// The chain maintains the input and output types at compile time while storing
/// the actual steps in a type-erased format for runtime execution. This allows
/// chains to be constructed with type safety and executed efficiently.
pub struct ActionChain<InputType, OutputType> {
    /// Type-erased steps to be executed in sequence.
    steps: Vec<Box<dyn ErasedStep>>,

    /// Asset inventory for storing assets between steps.
    inventory: AssetInventory,

    /// Phantom markers for compile-time type tracking.
    _input_marker: PhantomData<InputType>,
    _output_marker: PhantomData<OutputType>,
}

impl<I, O> ActionChain<I, O> {
    /// Create a new action chain with the given steps.
    pub(crate) fn new(steps: Vec<Box<dyn ErasedStep>>) -> Self {
        Self {
            steps,
            inventory: AssetInventory::new(),
            _input_marker: PhantomData,
            _output_marker: PhantomData,
        }
    }

    pub(crate) fn with_inventory(
        steps: Vec<Box<dyn ErasedStep>>,
        inventory: AssetInventory,
    ) -> Self {
        Self { steps, inventory, _input_marker: PhantomData, _output_marker: PhantomData }
    }

    /// Execute the entire chain with the given inputs and context.
    ///
    /// Each step is executed in sequence, with the output of one step becoming
    /// the input to the next step. The asset inventory is maintained throughout
    /// the execution and can be used by type converters.
    pub fn execute(
        mut self,
        inputs: I,
        context: &ActionContext,
    ) -> Result<ChainExecutionResult<O>, ChainError>
    where
        I: 'static,
        O: 'static,
    {
        if self.steps.is_empty() {
            return Err(ChainError::ConfigurationError("Cannot execute empty chain".to_string()));
        }

        let mut current_inputs: Box<dyn Any> = Box::new(inputs);
        let mut executed_steps = Vec::new();

        // Execute each step in sequence
        for step in self.steps {
            let (outputs, new_step) =
                step.execute(current_inputs.as_ref(), context, &mut self.inventory)?;

            executed_steps.push(new_step);
            current_inputs = outputs;
        }

        // Cast the final outputs to the expected type
        let final_outputs = current_inputs
            .downcast::<O>()
            .map_err(|_| {
                ChainError::TypeCastError(
                    "Failed to cast final outputs to expected type".to_string(),
                )
            })?;

        Ok(ChainExecutionResult {
            outputs: *final_outputs,
            updated_chain: ActionChain {
                steps: executed_steps,
                inventory: self.inventory,
                _input_marker: PhantomData,
                _output_marker: PhantomData,
            },
        })
    }

    /// Get a reference to the asset inventory.
    pub fn inventory(&self) -> &AssetInventory {
        &self.inventory
    }

    /// Get a mutable reference to the asset inventory.
    pub fn inventory_mut(&mut self) -> &mut AssetInventory {
        &mut self.inventory
    }

    /// Get the number of steps in the chain.
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// Result of executing an action chain.
///
/// Contains the final outputs of the chain execution and an updated chain
/// with the new state after all steps have been executed.
pub struct ChainExecutionResult<OutputType> {
    /// The final outputs produced by the chain.
    pub outputs: OutputType,

    /// The updated chain with new states after execution.
    pub updated_chain: ActionChain<OutputType, OutputType>,
}

impl<O> ChainExecutionResult<O> {
    /// Get the outputs from the chain execution.
    pub fn outputs(&self) -> &O {
        &self.outputs
    }

    /// Get the updated chain after execution.
    pub fn updated_chain(&self) -> &ActionChain<O, O> {
        &self.updated_chain
    }

    /// Consume the result and return the outputs.
    pub fn into_outputs(self) -> O {
        self.outputs
    }

    /// Consume the result and return the updated chain.
    pub fn into_updated_chain(self) -> ActionChain<O, O> {
        self.updated_chain
    }

    /// Destructure the result into outputs and updated chain.
    pub fn into_parts(self) -> (O, ActionChain<O, O>) {
        (self.outputs, self.updated_chain)
    }
}
