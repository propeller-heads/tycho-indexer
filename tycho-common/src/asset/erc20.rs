//! ERC20 token asset implementation.

use num_bigint::BigUint;

use crate::{
    action::asset::{Asset, PredicateDescriptor},
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
}
