use std::{
    collections::{HashMap, HashSet},
    sync::LazyLock,
};

use tycho_common::{models::Chain, Bytes};

use crate::encoding::errors::EncodingError;

pub const DEFAULT_EXECUTORS_JSON: &str = include_str!("../../../config/executor_addresses.json");
pub const DEFAULT_ROUTERS_JSON: &str = include_str!("../../../config/router_addresses.json");
pub const PROTOCOL_SPECIFIC_CONFIG: &str =
    include_str!("../../../config/protocol_specific_addresses.json");

/// Default router addresses keyed by chain, parsed from `config/router_addresses.json`.
pub static DEFAULT_ROUTER_ADDRESSES: LazyLock<HashMap<Chain, Bytes>> = LazyLock::new(|| {
    serde_json::from_str(DEFAULT_ROUTERS_JSON).expect("valid router_addresses.json")
});

/// Returns the default Tycho router address for `chain`, or an error if none is configured.
pub fn get_router_address(chain: &Chain) -> Result<&'static Bytes, EncodingError> {
    DEFAULT_ROUTER_ADDRESSES
        .get(chain)
        .ok_or_else(|| {
            EncodingError::FatalError(format!(
                "No default router address found for chain {chain:?}"
            ))
        })
}

/// The number of blocks in the future for which to fetch Angstrom Attestations
///
/// It is important to note that fetching more blocks will send more attestations to the
/// Tycho Router, resulting in a higher gas usage. Fetching fewer blocks may result in attestations
/// expiring if the transaction is not sent fast enough.
pub const ANGSTROM_DEFAULT_BLOCKS_IN_FUTURE: u64 = 5;

/// These protocols support the optimization of grouping swaps.
///
/// This requires special encoding to send call data of multiple swaps to a single executor,
/// as if it were a single swap. The protocol likely uses flash accounting to save gas on token
/// transfers.
pub static GROUPABLE_PROTOCOLS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert("uniswap_v4");
    set.insert("uniswap_v4_hooks");
    set.insert("vm:balancer_v3");
    set.insert("ekubo_v2");
    set.insert("ekubo_v3");
    set
});

/// These groupable protocols use simple concatenation instead of PLE when forming swap groups.
pub static NON_PLE_ENCODED_PROTOCOLS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert("ekubo_v2");
    set.insert("ekubo_v3");
    set
});
