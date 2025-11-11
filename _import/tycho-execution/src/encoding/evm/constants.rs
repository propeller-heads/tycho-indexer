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
    set.insert("uniswap_v4_hooks");
    set.insert("vm:balancer_v3");
    set.insert("ekubo_v2");
    set
});

/// These protocols need an external in transfer to the pool. This transfer can be from the router,
/// from the user or from the previous pool. Any protocols that are not defined here expect funds to
/// be in the router at the time of swap and do the transfer themselves from `msg.sender`
pub static IN_TRANSFER_REQUIRED_PROTOCOLS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert("uniswap_v2");
    set.insert("sushiswap_v2");
    set.insert("pancakeswap_v2");
    set.insert("uniswap_v3");
    set.insert("pancakeswap_v3");
    set.insert("uniswap_v4");
    set.insert("uniswap_v4_hooks");
    set.insert("ekubo_v2");
    set.insert("vm:maverick_v2");
    set.insert("vm:balancer_v3");
    set.insert("aerodrome_slipstreams");
    set
});

/// The protocols here are a subset of the ones defined in IN_TRANSFER_REQUIRED_PROTOCOLS. The in
/// transfer needs to be performed inside the callback logic. This means, the tokens can not be sent
/// directly from the previous pool into a pool of this protocol. The tokens need to be sent to the
/// router and only then transferred into the pool. This is the case for uniswap v3 because of the
/// callback logic. The only way for this to work it would be to call the second swap during the
/// callback of the first swap. This is currently not supported.
pub static CALLBACK_CONSTRAINED_PROTOCOLS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert("uniswap_v3");
    set.insert("pancakeswap_v3");
    set.insert("uniswap_v4");
    set.insert("uniswap_v4_hooks");
    set.insert("ekubo_v2");
    set.insert("vm:balancer_v3");
    set.insert("aerodrome_slipstreams");
    set
});

/// These groupable protocols use simple concatenation instead of PLE when forming swap groups.
pub static NON_PLE_ENCODED_PROTOCOLS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert("ekubo_v2");
    set
});
