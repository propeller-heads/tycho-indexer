//! Pair Properties and ProtocolState
//!
//! This module contains the `ProtocolComponent` struct, which represents the
//! properties of a trading pair. It also contains the `Pair` struct, which
//! represents a trading pair with its properties and corresponding state.
//!
//! Additionally, it contains the `GetAmountOutResult` struct, which
//! represents the result of getting the amount out of a trading pair.
//!
//! The `ProtocolComponent` struct has two fields: `address` and `tokens`.
//! `address` is the address of the trading pair and `tokens` is a vector
//! of `ERC20Token` representing the tokens of the trading pair.
//!
//! Generally this struct contains immutable properties of the pair. These
//! are attributes that will never change - not even through governance.
//!
//! This is in contrast to `ProtocolState`, which includes ideally only
//! attributes that can change.
//!
//! The `Pair` struct combines the former two: `ProtocolComponent` and
//! `ProtocolState` into a single struct.
//!
//! # Note:
//! It's worth emphasizin that although the term "pair" used in this
//! module refers to a trading pair, it does not necessarily imply two
//! tokens only. Some pairs might have more than two tokens.
use std::{collections::HashMap, future::Future};

use num_bigint::BigUint;

use tycho_core::Bytes;

use tycho_client::feed::Header;

use crate::models::Token;

use super::state::ProtocolSim;

/// ProtocolComponent struct represents the properties of a trading pair
///
/// # Fields
///
/// * `address`: String, the address of the trading pair
/// * `tokens`: `Vec<ERC20Token>`, the tokens of the trading pair
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolComponent {
    pub address: Bytes,
    pub tokens: Vec<Token>,
}

impl ProtocolComponent {
    pub fn new(address: Bytes, mut tokens: Vec<Token>) -> Self {
        tokens.sort_unstable_by_key(|t| t.address.clone());
        ProtocolComponent { address, tokens }
    }
}

pub trait TryFromWithBlock<T> {
    type Error;

    fn try_from_with_block(
        value: T,
        block: Header,
        all_tokens: &HashMap<Bytes, Token>,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send + Sync
    where
        Self: Sized;
}

/// GetAmountOutResult struct represents the result of getting the amount out of a trading pair
///
/// # Fields
///
/// * `amount`: BigUint, the amount of the trading pair
/// * `gas`: BigUint, the gas of the trading pair
#[derive(Debug)]
pub struct GetAmountOutResult {
    pub amount: BigUint,
    pub gas: BigUint,
    pub new_state: Box<dyn ProtocolSim>,
}

impl GetAmountOutResult {
    /// Constructs a new GetAmountOutResult struct with the given amount and gas
    pub fn new(amount: BigUint, gas: BigUint, new_state: Box<dyn ProtocolSim>) -> Self {
        GetAmountOutResult { amount, gas, new_state }
    }

    /// Aggregates the given GetAmountOutResult struct to the current one.
    /// It updates the amount with the other's amount and adds the other's gas to the current one's
    /// gas.
    pub fn aggregate(&mut self, other: &Self) {
        self.amount = other.amount.clone();
        self.gas += &other.gas;
    }
}

#[derive(Debug)]
pub struct BlockUpdate {
    pub block_number: u64,
    /// The current state of all pools
    pub states: HashMap<String, Box<dyn ProtocolSim>>,
    /// The new pairs that were added in this block
    pub new_pairs: HashMap<String, ProtocolComponent>,
    /// The pairs that were removed in this block
    pub removed_pairs: HashMap<String, ProtocolComponent>,
}

impl BlockUpdate {
    pub fn new(
        block_number: u64,
        states: HashMap<String, Box<dyn ProtocolSim>>,
        new_pairs: HashMap<String, ProtocolComponent>,
    ) -> Self {
        BlockUpdate { block_number, states, new_pairs, removed_pairs: HashMap::new() }
    }

    pub fn set_removed_pairs(mut self, pairs: HashMap<String, ProtocolComponent>) -> Self {
        self.removed_pairs = pairs;
        self
    }
}
