//! Action chaining system for composing multi-step DeFi operations.
//!
//! This module provides a type-safe builder pattern for creating chains of actions
//! that can be executed sequentially with state transitions. The system supports
//! asset inventory management and type conversions between steps.
//!
//! ## Core Concepts
//!
//! - **ChainBuilder**: Type-safe builder for constructing action chains
//! - **Step**: Individual action with state and parameters
//! - **AssetInventory**: Storage for assets between chain steps
//! - **TypeConverter**: Interface for converting between action input/output types
//!
//! ## Example
//!
//! ```rust
//! use std::marker::PhantomData;
//! 
//! let chain = ChainBuilder::new()
//!     .add_step::<Swap, _, _>(
//!         PhantomData,
//!         uniswap_pool,
//!         SwapParameters::new(eth_token),
//!         None
//!     )
//!     .build();
//! ```

pub mod builder;
pub mod converters;
pub mod errors;
pub mod executor;
pub mod inventory;
pub mod step;

pub use builder::ChainBuilder;
pub use converters::{ERC20OutputsToInputs, OutputsToInputs, PassThrough, TypeConverter};
pub use errors::ChainError;
pub use executor::ActionChain;
pub use inventory::AssetInventory;
pub use step::{ErasedStep, Step};