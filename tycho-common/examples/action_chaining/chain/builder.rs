//! Type-safe builder for constructing action chains.

use std::marker::PhantomData;

use tycho_common::{
    action::simulate::{Action, DefaultInputs, SimulateForward},
    asset::erc20::{ERC20Asset, ERC20DefaultOutputs},
};

use super::{
    converters::StepLinker,
    executor::ActionChain,
    step::{ErasedStep, Step},
    AssetInventory,
};

/// Type-safe builder for constructing chains of actions.
///
/// Uses phantom types to track the input and output types of the chain at compile
/// time, ensuring that steps can only be added when their input type matches the
/// current chain output type.
pub struct ChainBuilder<InputType, CurrentType> {
    /// Type-erased steps that will be executed in sequence.
    steps: Vec<Box<dyn ErasedStep>>,

    inventory: Option<AssetInventory>,

    /// Phantom marker for the original input type of the chain.
    _input_marker: PhantomData<InputType>,

    /// Phantom marker for the current output type of the chain.
    _current_marker: PhantomData<CurrentType>,
}

impl<I: 'static, C: Clone + 'static> ChainBuilder<I, C> {
    /// Add a new step to the chain with a custom linker.
    ///
    /// The step can now handle type mismatches between the current chain output type C
    /// and the action's input type A::Inputs through runtime conversion.
    pub fn add_step_with_linker<A, S>(
        mut self,
        state: S,
        parameters: A::Parameters,
        linker: impl StepLinker<C, A::Inputs> + Send + Sync + 'static,
    ) -> ChainBuilder<I, A::Outputs>
    where
        A: Action + 'static,
        S: SimulateForward<A> + Clone + 'static,
        A::Parameters: Clone + 'static,
        A::Inputs: Clone + 'static,
        A::Outputs: Clone + 'static,
        // usually the output of the previous step, which is converted to this step
        //  input using a step linker. But can also be just the input of this step
        // (in this case the step linker would be None)
        C: Clone + 'static,
    {
        let boxed_linker: Box<dyn StepLinker<C, A::Inputs> + Send + Sync> = Box::new(linker);

        let step = Step::<A, S, C>::new(state, parameters, Some(boxed_linker));
        self.steps.push(Box::new(step));

        ChainBuilder {
            steps: self.steps,
            _input_marker: PhantomData,
            _current_marker: PhantomData,
            inventory: self.inventory,
        }
    }

    pub fn with_inventory(mut self, inventory: AssetInventory) -> ChainBuilder<I, C> {
        self.inventory = Some(inventory);
        self
    }

    /// Build the final action chain.
    ///
    /// The chain can be built when the current output type matches or can be
    /// converted to the desired end type.
    pub fn build(self) -> ActionChain<I, C> {
        if let Some(inventory) = self.inventory {
            ActionChain::with_inventory(self.steps, inventory)
        } else {
            ActionChain::new(self.steps)
        }
    }
}

/// Specialized implementation for ERC20 chains that can use add_step with OutputsToInputs
/// conversion.
impl<I: 'static> ChainBuilder<I, ERC20DefaultOutputs> {
    /// Add a step with default OutputsToInputs conversion for ERC20 chains.
    ///
    /// This is the standard method for chaining ERC20 actions where the output of one
    /// action becomes the input to the next action (e.g., swap chains).
    /// Uses ERC20 OutputsToInputs linker by default.
    pub fn add_step<A, S>(
        self,
        state: S,
        parameters: A::Parameters,
    ) -> ChainBuilder<I, ERC20DefaultOutputs>
    where
        A: Action<Inputs = DefaultInputs<ERC20Asset>, Outputs = ERC20DefaultOutputs> + 'static,
        S: SimulateForward<A> + Clone + 'static,
        A::Parameters: Clone + 'static,
    {
        // Create a step that converts DefaultOutputs to DefaultInputs via OutputsToInputs
        let linker = super::converters::OutputsToInputs::<ERC20Asset>::new();
        let boxed_linker: Box<dyn StepLinker<ERC20DefaultOutputs, A::Inputs> + Send + Sync> =
            Box::new(linker);

        let step = Step::<A, S, ERC20DefaultOutputs>::new(state, parameters, Some(boxed_linker));

        ChainBuilder {
            steps: {
                let mut new_steps = self.steps;
                new_steps.push(Box::new(step));
                new_steps
            },
            _input_marker: PhantomData,
            _current_marker: PhantomData,
            inventory: self.inventory,
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
            inventory: None,
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
        let step = Step::<A, S, A::Inputs>::new(state, parameters, None);

        ChainBuilder {
            steps: vec![Box::new(step)],
            _input_marker: PhantomData,
            _current_marker: PhantomData,
            inventory: self.inventory,
        }
    }
}

impl Default for ChainBuilder<(), ()> {
    fn default() -> Self {
        Self::new()
    }
}
