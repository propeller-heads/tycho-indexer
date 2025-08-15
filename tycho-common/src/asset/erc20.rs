//! ERC20 token asset implementation.

use num_bigint::BigUint;

use crate::{
    action::{
        asset::{Asset, AssetError, PredicateDescriptor},
        simulate::DefaultOutputs,
    },
    models::token::Token,
    Bytes,
};

/// Represents an ERC20 token with a specific amount.
///
/// This is a concrete implementation of the `Asset` trait for ERC20 tokens,
/// enabling them to be used as inputs and outputs in action simulations.
#[derive(Debug, Clone)]
pub struct ERC20Asset {
    /// The token specification including address, decimals, and symbol.
    token: Token,
    /// The amount of tokens in the smallest unit (wei for ETH).
    amount: BigUint,
}

impl ERC20Asset {
    /// Create a new ERC20 asset with the specified token and amount.
    pub fn new(token: Token, amount: BigUint) -> Self {
        Self { token, amount }
    }

    /// Get the token specification.
    pub fn token(&self) -> &Token {
        &self.token
    }
}

impl Asset for ERC20Asset {
    fn kind(&self) -> &'static str {
        "erc20"
    }

    fn type_id(&self) -> &Bytes {
        &self.token.address
    }

    fn instance_id(&self) -> Option<&Bytes> {
        None
    }

    fn amount(&self) -> Option<&BigUint> {
        Some(&self.amount)
    }

    fn predicate_descriptor(&self, _owner: &Bytes) -> PredicateDescriptor {
        todo!()
    }

    fn accumulate(&self, other: &dyn Asset) -> Result<Box<dyn Asset>, AssetError> {
        // Check if other asset is compatible for accumulation
        if self.kind() != other.kind() {
            return Err(AssetError::IncompatibleKind(
                self.kind().to_string(),
                other.kind().to_string(),
            ));
        }

        if self.type_id() != other.type_id() {
            return Err(AssetError::IncompatibleType(
                hex::encode(self.type_id()),
                hex::encode(other.type_id()),
            ));
        }

        // Try to downcast other to ERC20Asset to access amount
        let other_amount = other
            .amount()
            .ok_or(AssetError::NotFungible)?;

        // Add amounts
        let combined_amount = &self.amount + other_amount;

        // Create new ERC20Asset with combined amount
        let combined_asset = ERC20Asset::new(self.token.clone(), combined_amount);

        Ok(Box::new(combined_asset))
    }
}

pub type ERC20DefaultOutputs = DefaultOutputs<ERC20Asset, ERC20Asset>;
