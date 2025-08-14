//! Asset abstraction for the action system.
//!
//! This module provides a unified interface for representing different types of blockchain assets
//! including fungible tokens, NFTs, and other value-bearing objects that can be transferred
//! or consumed in on-chain actions.

use num_bigint::BigUint;
use thiserror::Error;

use crate::Bytes;

/// Descriptor for validating asset ownership or state.
///
/// Contains the necessary data to construct a blockchain predicate that can verify
/// specific conditions about an asset, typically used for ownership validation.
pub struct PredicateDescriptor {
    /// The contract address that can validate the predicate.
    contract: Bytes,

    /// The calldata to send to the contract for validation.
    data: Bytes,

    /// The expected return value that indicates successful validation.
    expected: Bytes,
}

#[derive(Error, Debug)]
pub enum AssetError {
    #[error("Can't accumulate a non fungible asset")]
    NotFungible,
}

/// Unified interface for blockchain assets.
///
/// Provides a common abstraction over different asset types (ERC20, ERC721, ERC1155, etc.)
/// enabling the action system to work with diverse asset types in a type-safe manner.
pub trait Asset {
    /// Get the asset type identifier as a static string.
    /// Examples: "ERC20", "ERC721", "ERC1155", "Native"
    fn kind(&self) -> &'static str;

    /// Get the primary identifier for this asset type.
    /// For tokens, this is typically the contract address.
    fn type_id(&self) -> &Bytes;

    /// Get the specific instance identifier within the asset type.
    /// Used for NFTs (token ID) or other assets with unique instances.
    /// Returns `None` for fungible assets like ERC20 tokens.
    fn instance_id(&self) -> Option<&Bytes>;

    /// Get the amount of this asset.
    /// Returns `None` for non-quantifiable assets (e.g., some NFTs).
    /// For fungible tokens, this represents the token amount in smallest units.
    fn amount(&self) -> Option<&BigUint>;

    /// Generate a predicate descriptor for verifying asset ownership or state.
    ///
    /// The predicate can be used to construct blockchain calls that validate
    /// whether the specified owner has the required relationship with this asset.
    fn predicate_descriptor(&self, owner: &Bytes) -> PredicateDescriptor;

    /// Accumulates quantities of two fungible assets into a single one.
    ///
    /// Will error for non-fungible assets.
    fn accumulate(&self) -> Result<Box<dyn Asset>, AssetError> {
        Err(AssetError::NotFungible)
    }
}
