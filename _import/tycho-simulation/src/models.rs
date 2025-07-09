//! Basic data structures
//!
//! This module contains basic models that are shared across many
//! components of the crate.
//!
//! Tokens provide instructions on how to handle prices and amounts.
use std::collections::HashMap;

use tycho_common::Bytes;

#[derive(Default)]
pub struct Balances {
    pub component_balances: HashMap<String, HashMap<Bytes, Bytes>>,
    pub account_balances: HashMap<Bytes, HashMap<Bytes, Bytes>>,
}
