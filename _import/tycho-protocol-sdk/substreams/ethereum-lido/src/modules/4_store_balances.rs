//! Template for Protocols with contract factories
//!
//! This template provides foundational maps and store substream modules for indexing a
//! protocol where each component (e.g., pool) is deployed to a separate contract. Each
//! contract is expected to escrow its ERC-20 token balances.
//!
//! If your protocol supports native ETH, you may need to adjust the balance tracking
//! logic in `map_relative_component_balance` to account for native token handling.
//!
//! ## Assumptions
//! - Assumes each pool has a single newly deployed contract linked to it
//! - Assumes pool identifier equals the deployed contract address
//! - Assumes any price or liquidity updated correlates with a pools contract storage update.
//!
//! ## Alternative Module
//! If your protocol uses a vault-like contract to manage balances, or if pools are
//! registered within a singleton contract, refer to the `ethereum-template-singleton`
//! substream for an appropriate alternative.
//!
//! ## Warning
//! This template provides a general framework for indexing a protocol. However, it is
//! likely that you will need to adapt the steps to suit your specific use case. Use the
//! provided code with care and ensure you fully understand each step before proceeding
//! with your implementation.
//!
//! ## Example Use Case
//! For an Uniswap-like protocol where each liquidity pool is deployed as a separate
//! contract, you can use this template to:
//! - Track relative component balances (e.g., ERC-20 token balances in each pool).
//! - Index individual pool contracts as they are created by the factory contract.
//!
//! Adjustments to the template may include:
//! - Handling native ETH balances alongside token balances.
//! - Customizing indexing logic for specific factory contract behavior.
use substreams::prelude::*;
use tycho_substreams::prelude::*;

/// Aggregates relative balances values into absolute values
///
/// Aggregate the relative balances in an additive store since tycho-indexer expects
/// absolute balance inputs.
///
/// ## Note:
/// This method should usually not require any changes.
#[substreams::handlers::store]
pub fn store_balances(deltas: BlockBalanceDeltas, store: StoreAddBigInt) {
    tycho_substreams::balances::store_balance_changes(deltas, store);
}
