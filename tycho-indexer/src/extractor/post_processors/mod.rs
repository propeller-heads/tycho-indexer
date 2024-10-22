//! This module collects post processor components
//!
//! Usually changes or modifications required due to bugs in downstream substreams packages
//! that would require an expensive re-sync or similar. The post processors allow us to
//! avoid this by applying the necessary changes to the data after it has been extracted.

mod attributes;
mod balances;

pub use attributes::{add_default_attributes_uniswapv3, trim_curve_component_token};
pub use balances::{ignore_self_balances, transcode_ambient_balances};
