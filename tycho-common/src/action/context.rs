//! Execution context for action simulations.
//!
//! This module provides the runtime environment information needed to execute actions
//! accurately within the blockchain state context.

use std::collections::HashSet;

use crate::{models::blockchain::Block, Bytes};

/// Runtime context for action execution.
///
/// Contains the environmental state and constraints that affect how actions
/// are simulated. This ensures simulations account for block-specific conditions
/// and transaction context.
pub struct ActionContext {
    /// The blockchain block in which the action is being simulated.
    /// Used for accessing block-specific data like timestamp, gas limits, and base fees.
    current_block: Block,

    /// The identity of the user executing the action, if available.
    /// Used for access control and address-specific behavior in protocols.
    user_identity: Option<Bytes>,

    /// Set of component identifiers that have been accessed in the current simulation.
    /// Tracks pools, contracts, and other protocol components to support gas accounting
    /// and dependency analysis in complex action sequences.
    previously_accessed: HashSet<Bytes>,
}

impl ActionContext {
    /// Create a new action context.
    pub fn new(
        current_block: Block,
        user_identity: Option<Bytes>,
        previously_accessed: HashSet<Bytes>,
    ) -> Self {
        Self { current_block, user_identity, previously_accessed }
    }
}
