//! Liquidity provision interface built on the action trait system.
//!
//! This module provides standardized interfaces for liquidity provision operations
//! across different DEX protocols including UniswapV2, UniswapV3, Curve, and Balancer.
//!
//! The system addresses limitations of simpler interfaces that couldn't handle:
//! - Multi-token operations (more than 2 tokens)
//! - Position-based liquidity (NFT positions)
//! - Separate fee collection
//! - Complex pool mechanics

pub mod action;
pub mod asset;
