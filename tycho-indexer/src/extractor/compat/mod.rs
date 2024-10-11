//! This module collects compatibility components
//!
//! Usually changes or modifications required due to bugs in downstream substreams packages
//! that would require an expensive re-sync or similar.

mod attributes;
mod balances;

pub use attributes::{
    add_default_attributes_uniswapv2, add_default_attributes_uniswapv3, trim_curve_component_token,
};
pub use balances::{ignore_self_balances, transcode_ambient_balances, transcode_usv2_balances};
