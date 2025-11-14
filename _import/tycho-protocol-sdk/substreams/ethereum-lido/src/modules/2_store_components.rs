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

/// Stores all protocol components in a store.
///
/// Stores information about components in a key value store. This is only necessary if
/// you need to access the whole set of components within your indexing logic.
///
/// Popular use cases are:
/// - Checking if a contract belongs to a component. In this case suggest to use an address as the
///   store key so lookup operations are O(1).
/// - Tallying up relative balances changes to calcualte absolute erc20 token balances per
///   component.
///
/// Usually you can skip this step if:
/// - You are interested in a static set of components only
/// - Your protocol emits balance change events with absolute values
#[substreams::handlers::store]
fn store_protocol_components(
    map_protocol_components: BlockTransactionProtocolComponents,
    store: StoreSetRaw,
) {
    map_protocol_components
        .tx_components
        .into_iter()
        .for_each(|tx_pc| {
            tx_pc
                .components
                .into_iter()
                .for_each(|pc| {
                    // Assumes that the component id is a hex encoded contract address
                    let key = pc.id.clone();
                    // we store the components tokens
                    // TODO: proper error handling
                    // substreams::log::println(format!("pc.tokens: {:?}", pc.tokens));
                    let val = serde_sibor::to_bytes(&pc.tokens).unwrap();
                    store.set(0, key, &val);
                })
        });
}
