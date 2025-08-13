//! Type conversion system for linking action steps in chains.

use std::marker::PhantomData;

use crate::{
    action::{
        asset::Asset,
        chain::{errors::ChainError, inventory::AssetInventory},
        simulate::{DefaultInputs, DefaultOutputs},
    },
    asset::erc20::ERC20Asset,
};

/// Trait for converting between different input/output types in action chains.
/// 
/// Type converters enable linking actions with incompatible input/output types
/// by providing transformation logic and optionally interacting with the asset
/// inventory to store or retrieve assets between steps.
pub trait TypeConverter<From, To> {
    /// Convert input of type `From` to output of type `To`.
    /// 
    /// May interact with the inventory to store assets for later retrieval
    /// or retrieve previously stored assets for combination with current input.
    fn convert(
        &mut self,
        input: From,
        inventory: &mut AssetInventory,
    ) -> Result<To, ChainError>;
}


/// Identity converter that passes input through unchanged.
/// 
/// This is the default converter used when action input/output types match
/// exactly and no conversion is needed. Does not interact with the inventory.
#[derive(Debug, Clone)]
pub struct PassThrough<T> {
    _marker: PhantomData<T>,
}

impl<T> PassThrough<T> {
    /// Create a new pass-through converter.
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<T> Default for PassThrough<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> TypeConverter<T, T> for PassThrough<T> {
    fn convert(
        &mut self,
        input: T,
        _inventory: &mut AssetInventory,
    ) -> Result<T, ChainError> {
        Ok(input)
    }
}


/// Converter that transforms DefaultOutputs to DefaultInputs by extracting produced assets.
/// 
/// This is commonly needed in swap chains where the output of one swap becomes
/// the input to the next swap. Takes the produced assets from the outputs and
/// creates a new DefaultInputs containing those assets.
#[derive(Debug, Clone)]
pub struct OutputsToInputs<A: Asset> {
    _marker: PhantomData<A>,
}

impl<A: Asset> OutputsToInputs<A> {
    /// Create a new outputs-to-inputs converter.
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<A: Asset> Default for OutputsToInputs<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Asset + Clone> TypeConverter<DefaultOutputs<A>, DefaultInputs<A>> for OutputsToInputs<A> {
    fn convert(
        &mut self,
        input: DefaultOutputs<A>,
        _inventory: &mut AssetInventory,
    ) -> Result<DefaultInputs<A>, ChainError> {
        // Extract the produced assets and use them as inputs for the next step
        let produced_assets = input.produced().clone();
        Ok(DefaultInputs(produced_assets))
    }
}

/// Type alias for ERC20 outputs-to-inputs converter.
pub type ERC20OutputsToInputs = OutputsToInputs<ERC20Asset>;

/// Converter that combines swap outputs with assets from inventory.
/// 
/// This converter takes ERC20 swap outputs and combines them with a specified
/// token retrieved from the inventory to create inputs for liquidity provision.
#[derive(Debug, Clone)]
pub struct SwapOutputsPlusInventory {
    /// The token to retrieve from inventory.
    pub inventory_token: crate::models::token::Token,
    /// The amount to retrieve from inventory.
    pub inventory_amount: num_bigint::BigUint,
}

impl SwapOutputsPlusInventory {
    /// Create a new converter that will retrieve the specified token from inventory.
    pub fn new(inventory_token: crate::models::token::Token, inventory_amount: num_bigint::BigUint) -> Self {
        Self {
            inventory_token,
            inventory_amount,
        }
    }
}

impl TypeConverter<DefaultOutputs<ERC20Asset>, DefaultInputs<ERC20Asset>> for SwapOutputsPlusInventory {
    fn convert(
        &mut self,
        input: DefaultOutputs<ERC20Asset>,
        _inventory: &mut AssetInventory,
    ) -> Result<DefaultInputs<ERC20Asset>, ChainError> {
        // Get the produced assets from the swap output
        let mut combined_assets = input.produced().clone();
        
        // Create the inventory asset instead of retrieving (for simplicity in demo)
        let inventory_asset = ERC20Asset::new(self.inventory_token.clone(), self.inventory_amount.clone());
        combined_assets.push(inventory_asset);
        
        Ok(DefaultInputs(combined_assets))
    }
}

