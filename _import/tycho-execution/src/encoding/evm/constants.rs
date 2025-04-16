use std::{collections::HashSet, sync::LazyLock};

pub const DEFAULT_EXECUTORS_JSON: &str = include_str!("../../../config/executor_addresses.json");
pub const DEFAULT_ROUTERS_JSON: &str = include_str!("../../../config/router_addresses.json");
pub const PROTOCOL_SPECIFIC_CONFIG: &str =
    include_str!("../../../config/protocol_specific_addresses.json");

/// These protocols support the optimization of grouping swaps.
///
/// This requires special encoding to send call data of multiple swaps to a single executor,
/// as if it were a single swap. The protocol likely uses flash accounting to save gas on token
/// transfers.
pub static GROUPABLE_PROTOCOLS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert("uniswap_v4");
    set.insert("vm:balancer_v3");
    set.insert("ekubo_v2");
    set
});

/// These protocols support the optimization of transferring straight from the user.
pub static IN_TRANSFER_OPTIMIZABLE_PROTOCOLS: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| {
        let mut set = HashSet::new();
        set.insert("uniswap_v2");
        set.insert("sushiswap_v2");
        set.insert("pancakeswap_v2");
        set.insert("uniswap_v3");
        set.insert("pancakeswap_v3");
        set.insert("ekubo_v2");
        set
    });

// These protocols do not support chained swaps from the same protocol. This is the case for uniswap
// v3 because of the callback logic. The only way for this to work it would be to call the second
// swap during the callback of the first swap. This is currently not supported.
pub static PROTOCOLS_NOT_OPTIMIZED_CHAINED_SWAPS: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| {
        let mut set = HashSet::new();
        set.insert("uniswap_v3");
        set.insert("pancakeswap_v3");
        set
    });
