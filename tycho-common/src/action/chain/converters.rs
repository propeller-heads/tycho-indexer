//! Step linking system for connecting action steps in chains.

use std::marker::PhantomData;

use crate::{
    action::{
        asset::Asset,
        chain::{errors::ChainError, inventory::AssetInventory},
        simulate::{DefaultInputs, DefaultOutputs},
    },
    asset::erc20::{ERC20Asset, ERC20DefaultOutputs},
};

/// Trait for linking different input/output types in action chains.
///
/// Step linkers enable connecting actions with incompatible input/output types
/// by providing transformation logic and optionally interacting with the asset
/// inventory to store or retrieve assets between steps.
pub trait StepLinker<From, To> {
    /// Convert input of type `From` to output of type `To`.
    ///
    /// May interact with the inventory to store assets for later retrieval
    /// or retrieve previously stored assets for combination with current input.
    fn convert(&mut self, input: From, inventory: &mut AssetInventory) -> Result<To, ChainError>;
}

/// Identity linker that passes input through unchanged.
///
/// This is the default linker used when action input/output types match
/// exactly and no conversion is needed. Does not interact with the inventory.
#[derive(Debug, Clone)]
pub struct PassThrough<T> {
    _marker: PhantomData<T>,
}

impl<T> PassThrough<T> {
    /// Create a new pass-through linker.
    pub fn new() -> Self {
        Self { _marker: PhantomData }
    }
}

impl<T> Default for PassThrough<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> StepLinker<T, T> for PassThrough<T> {
    fn convert(&mut self, input: T, _inventory: &mut AssetInventory) -> Result<T, ChainError> {
        Ok(input)
    }
}

/// Linker that transforms DefaultOutputs to DefaultInputs by extracting produced assets.
///
/// This is commonly needed in swap chains where the output of one swap becomes
/// the input to the next swap. Takes the produced assets from the outputs and
/// creates a new DefaultInputs containing those assets.
#[derive(Debug, Clone)]
pub struct OutputsToInputs<A: Asset> {
    _marker: PhantomData<A>,
}

impl<A: Asset> OutputsToInputs<A> {
    /// Create a new outputs-to-inputs linker.
    pub fn new() -> Self {
        Self { _marker: PhantomData }
    }
}

impl<A: Asset> Default for OutputsToInputs<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Asset + Clone, B: Asset + Clone> StepLinker<DefaultOutputs<A, B>, DefaultInputs<B>>
    for OutputsToInputs<A>
{
    fn convert(
        &mut self,
        input: DefaultOutputs<A, B>,
        _inventory: &mut AssetInventory,
    ) -> Result<DefaultInputs<B>, ChainError> {
        // Extract the produced assets and use them as inputs for the next step
        let produced_assets = input.produced().clone();
        Ok(DefaultInputs(produced_assets))
    }
}

/// Type alias for ERC20 outputs-to-inputs linker.
pub type ERC20OutputsToInputs = OutputsToInputs<ERC20Asset>;

/// Linker that combines swap outputs with assets from inventory.
///
/// This linker takes ERC20 swap outputs and combines them with a specified
/// token retrieved from the inventory to create inputs for liquidity provision.
#[derive(Debug, Clone)]
pub struct SwapOutputsPlusInventory {
    /// The token to retrieve from inventory.
    pub inventory_token: crate::models::token::Token,
    /// The amount to retrieve from inventory.
    pub inventory_amount: num_bigint::BigUint,
}

impl SwapOutputsPlusInventory {
    /// Create a new linker that will retrieve the specified token from inventory.
    pub fn new(
        inventory_token: crate::models::token::Token,
        inventory_amount: num_bigint::BigUint,
    ) -> Self {
        Self { inventory_token, inventory_amount }
    }
}

impl StepLinker<ERC20DefaultOutputs, DefaultInputs<ERC20Asset>> for SwapOutputsPlusInventory {
    fn convert(
        &mut self,
        input: ERC20DefaultOutputs,
        inventory: &mut AssetInventory,
    ) -> Result<DefaultInputs<ERC20Asset>, ChainError> {
        // Get the produced assets from the swap output
        let mut combined_assets = input.produced().clone();

        // Try to retrieve the requested asset from inventory
        if let Some(inventory_asset) = inventory.retrieve("erc20", &self.inventory_token.address) {
            // Check if we have enough amount in inventory
            if let Some(available_amount) = inventory_asset.amount() {
                if available_amount >= &self.inventory_amount {
                    // We have enough, create asset with requested amount
                    let requested_asset = ERC20Asset::new(
                        self.inventory_token.clone(),
                        self.inventory_amount.clone(),
                    );
                    combined_assets.push(requested_asset);

                    // If there's remaining amount, put it back in inventory
                    let remaining_amount = available_amount - &self.inventory_amount;
                    if remaining_amount > num_bigint::BigUint::from(0u32) {
                        let remaining_asset =
                            ERC20Asset::new(self.inventory_token.clone(), remaining_amount);
                        inventory
                            .store(Box::new(remaining_asset))
                            .map_err(|e| {
                                ChainError::InventoryError(format!(
                                    "Failed to store remaining asset: {}",
                                    e
                                ))
                            })?;
                    }
                } else {
                    return Err(ChainError::InventoryError(format!(
                        "Insufficient inventory: requested {}, available {}",
                        self.inventory_amount, available_amount
                    )));
                }
            } else {
                return Err(ChainError::InventoryError(
                    "Non-fungible asset cannot be partially retrieved".to_string(),
                ));
            }
        } else {
            return Err(ChainError::InventoryError(format!(
                "Asset {} not found in inventory",
                hex::encode(&self.inventory_token.address)
            )));
        }

        Ok(DefaultInputs(combined_assets))
    }
}
