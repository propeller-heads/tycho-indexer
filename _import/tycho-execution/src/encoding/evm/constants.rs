use std::{collections::HashSet, sync::LazyLock};

pub const DEFAULT_EXECUTORS_JSON: &str = include_str!("../../../config/executor_addresses.json");

/// These protocols support the optimization of grouping swaps.
///
/// This requires special encoding to send call data of multiple swaps to a single executor,
/// as if it were a single swap. The protocol likely uses flash accounting to save gas on token
/// transfers.
pub static GROUPABLE_PROTOCOLS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert("uniswap_v4");
    set.insert("balancer_v3");
    set.insert("ekubo");
    set
});
