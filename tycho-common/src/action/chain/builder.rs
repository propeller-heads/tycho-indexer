//! Type-safe builder for constructing action chains.

use std::marker::PhantomData;

use crate::action::{
    chain::{
        converters::{TypeConverter, ErasedTypeConverter},
        executor::ActionChain,
        step::{ErasedStep, Step},
    },
    simulate::{Action, SimulateForward},
};

/// Type-safe builder for constructing chains of actions.
/// 
/// Uses phantom types to track the input and output types of the chain at compile
/// time, ensuring that steps can only be added when their input type matches the
/// current chain output type.
pub struct ChainBuilder<InputType, CurrentType> {
    /// Type-erased steps that will be executed in sequence.
    steps: Vec<Box<dyn ErasedStep>>,
    
    /// Phantom marker for the original input type of the chain.
    _input_marker: PhantomData<InputType>,
    
    /// Phantom marker for the current output type of the chain.
    _current_marker: PhantomData<CurrentType>,
}

impl<I: 'static, C: Clone + 'static> ChainBuilder<I, C> {
    /// Add a new step to the chain with a custom converter.
    /// 
    /// The step can now handle type mismatches between the current chain output type C
    /// and the action's input type A::Inputs through runtime conversion.
    pub fn add_step_with_converter<A, S, NewOutput>(
        mut self,
        state: S,
        parameters: A::Parameters,
        converter: impl ErasedTypeConverter + 'static,
    ) -> ChainBuilder<I, NewOutput>
    where
        A: Action + 'static,
        S: SimulateForward<A> + Clone + 'static,
        A::Parameters: Clone + 'static,
        A::Inputs: Clone + 'static,
        A::Outputs: Send + Sync + 'static,
        NewOutput: 'static,
        C: 'static,
    {
        let boxed_converter: Box<dyn ErasedTypeConverter> = Box::new(converter);
            
        let step = Step::<A, S, C, NewOutput>::new(state, parameters, Some(boxed_converter));
        self.steps.push(Box::new(step));
        
        ChainBuilder {
            steps: self.steps,
            _input_marker: PhantomData,
            _current_marker: PhantomData,
        }
    }
    
    /// Build the final action chain.
    /// 
    /// The chain can be built when the current output type matches or can be
    /// converted to the desired end type.
    pub fn build(self) -> ActionChain<I, C> {
        ActionChain::new(self.steps)
    }
}

/// Specialized implementation for ERC20 chains that can use add_step with OutputsToInputs conversion.
impl<I: 'static> ChainBuilder<I, crate::action::simulate::DefaultOutputs<crate::asset::erc20::ERC20Asset>> {
    /// Add a step with default OutputsToInputs conversion for ERC20 chains.
    /// 
    /// This is the standard method for chaining ERC20 actions where the output of one
    /// action becomes the input to the next action (e.g., swap chains).
    /// Uses ERC20 OutputsToInputs converter by default.
    pub fn add_step<A, S>(
        self,
        state: S,
        parameters: A::Parameters,
    ) -> ChainBuilder<I, crate::action::simulate::DefaultOutputs<crate::asset::erc20::ERC20Asset>>
    where
        A: Action<Inputs = crate::action::simulate::DefaultInputs<crate::asset::erc20::ERC20Asset>, Outputs = crate::action::simulate::DefaultOutputs<crate::asset::erc20::ERC20Asset>> + 'static,
        S: SimulateForward<A> + Clone + 'static,
        A::Parameters: Clone + 'static,
    {
        // Create a step that internally handles the OutputsToInputs conversion
        let step = Step::<A, S, crate::action::simulate::DefaultOutputs<crate::asset::erc20::ERC20Asset>, crate::action::simulate::DefaultOutputs<crate::asset::erc20::ERC20Asset>>::new(
            state, 
            parameters, 
            Some(Box::new(crate::action::chain::converters::PassThrough::<crate::action::simulate::DefaultOutputs<crate::asset::erc20::ERC20Asset>>::new()))
        );
        
        ChainBuilder {
            steps: {
                let mut new_steps = self.steps;
                new_steps.push(Box::new(step));
                new_steps
            },
            _input_marker: PhantomData,
            _current_marker: PhantomData,
        }
    }
}

/// Initial builder constructor for starting a new chain.
impl ChainBuilder<(), ()> {
    /// Create a new chain builder.
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            _input_marker: PhantomData,
            _current_marker: PhantomData,
        }
    }
    
    /// Start the chain with the first step.
    /// 
    /// This establishes the input and initial output types for the chain.
    pub fn start_with<A, S>(
        self,
        state: S,
        parameters: A::Parameters,
    ) -> ChainBuilder<A::Inputs, A::Outputs>
    where
        A: Action + 'static,
        S: SimulateForward<A> + Clone + 'static,
        A::Parameters: Clone + 'static,
        A::Inputs: Clone + 'static,
        A::Outputs: 'static,
    {
        let step = Step::<A, S, A::Inputs, A::Outputs>::new(state, parameters, None);
        
        ChainBuilder {
            steps: vec![Box::new(step)],
            _input_marker: PhantomData,
            _current_marker: PhantomData,
        }
    }
}

impl Default for ChainBuilder<(), ()> {
    fn default() -> Self {
        Self::new()
    }
}