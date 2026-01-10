use std::{collections::HashSet, sync::LazyLock};

pub const DEFAULT_EXECUTORS_JSON: &str = include_str!("../../../config/executor_addresses.json");
pub const DEFAULT_ROUTERS_JSON: &str = include_str!("../../../config/router_addresses.json");
pub const PROTOCOL_SPECIFIC_CONFIG: &str =
    include_str!("../../../config/protocol_specific_addresses.json");

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
    set
});

/// These protocols expect funds to be in the router at the time of swap and do the transfer
/// themselves from `msg.sender`.
/// Any protocols that are not defined here need an external in transfer to the pool.
/// This transfer can be from the router, from the user or from the previous pool.
pub static FUNDS_IN_ROUTER_PROTOCOLS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert("vm:balancer_v2");
    set.insert("vm:curve");
    set.insert("rfq:bebop");
    set.insert("rfq:hashflow");
    set.insert("rocketpool");
    set.insert("erc4626");
    set.insert("lido");
    set
});

/// The in transfer needs to be performed inside the callback logic. This means, the tokens can not
/// be sent directly from the previous pool into a pool of this protocol. The tokens need to be sent
/// to the router and only then transferred into the pool. This is the case for uniswap v3 because
/// of the callback logic. The only way for this to work it would be to call the second swap during
/// the callback of the first swap. This is currently not supported.
/// The protocols here are disjoint from the ones defined in FUNDS_IN_ROUTER_PROTOCOLS.
pub static CALLBACK_CONSTRAINED_PROTOCOLS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert("uniswap_v3");
    set.insert("pancakeswap_v3");
    set.insert("uniswap_v4");
    set.insert("uniswap_v4_hooks");
    set.insert("ekubo_v2");
    set.insert("vm:balancer_v3");
    set.insert("fluid_v1");
    set.insert("aerodrome_slipstreams");
    set
});

/// These groupable protocols use simple concatenation instead of PLE when forming swap groups.
pub static NON_PLE_ENCODED_PROTOCOLS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert("ekubo_v2");
    set
});
