//! Error types for the action chaining system.

use thiserror::Error;

use crate::simulation::errors::SimulationError;

/// Errors that can occur during action chain construction or execution.
#[derive(Error, Debug)]
pub enum ChainError {
    /// Type conversion between action steps failed.
    #[error("Type conversion failed: {0}")]
    ConversionError(String),
    
    /// Step execution failed with a simulation error.
    #[error("Step execution failed: {0}")]  
    StepExecutionError(#[from] SimulationError),
    
    /// Insufficient or missing assets in inventory.
    #[error("Insufficient inventory assets: {0}")]
    InventoryError(String),
    
    /// Chain construction or execution failed due to invalid configuration.
    #[error("Chain configuration error: {0}")]
    ConfigurationError(String),
    
    /// Type casting failed during execution.
    #[error("Type casting failed: {0}")]
    TypeCastError(String),
}