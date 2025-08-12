//! Action trait system for modeling on-chain interactions.
//!
//! This module provides a composable trait system for simulating on-chain actions in a
//! type-safe and extensible manner. The system addresses limitations of earlier interfaces
//! that constrained protocol implementations to simple one-to-one operations.
//!
//! ## Motivation
//!
//! The original system provided only the `Swappable` trait, which worked well for basic
//! AMM operations but proved inadequate as protocols evolved. Many protocols required
//! capabilities that didn't fit the single-input, single-output swap model:
//!
//! - **Multi-output swaps** - Liquidations that split one token into multiple outputs
//! - **Multi-input operations** - LPing requiring multiple input tokens
//! - **Composite DeFi actions** - Operations combining lending, swapping, and staking
//!
//! The action system provides the flexibility these protocols need while maintaining
//! backward compatibility through adapter patterns.
//!
//! ## Core Architecture
//!
//! The action system follows a layered approach:
//!
//! 1. **Actions** - Define the structure of operations (parameters, inputs, outputs)
//! 2. **Simulation** - Provide execution logic for actions with state management
//! 3. **High-level traits** - Offer domain-specific interfaces (like `Swappable`)
//!
//! ## Extensibility
//!
//! New action types can be implemented by:
//!
//! - Defining an `Action` type with appropriate associated types
//! - Implementing `Simulate` or `SimulateForward` for execution logic
//! - Creating high-level wrapper traits for domain-specific functionality
//!
//! The system supports arbitrary input/output combinations through `Vec<Asset>` collections,
//! enabling protocols to model complex multi-token operations that were impossible with
//! earlier single-token interfaces.
//!
//! ## Usage Patterns
//!
//! Actions can be executed in two modes:
//! - **Stateless**: Using `Simulate` for read-only operations
//! - **Stateful**: Using `SimulateForward` for operations that modify state
//!
//! The system supports complex workflows through composition and provides
//! standardized error handling via `SimulationError`.

pub mod asset;
pub mod chain;
pub mod context;
pub mod simulate;
