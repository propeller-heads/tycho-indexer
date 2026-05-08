use num_bigint::BigUint;

use crate::encoding::models::{Solution, Strategy};

/// Default gas cost for an ERC-20 `transferFrom` or `transfer`. Used as fallback when the token
/// has no measured gas cost.
pub const DEFAULT_TOKEN_TRANSFER_GAS: u64 = 60_000;

/// Gas cost for an ERC-20 `approve`.
pub const TOKEN_APPROVAL_GAS: u64 = 45_000;

/// Callback-based protocols: the input `transferFrom` happens inside the callback, which is
/// inside `swap()`. The gas is thus already included in `get_amount_out`.
pub const PROTOCOLS_CALLBACK: &[&str] = &[
    "uniswap_v3",
    "pancakeswap_v3",
    "uniswap_v4",
    "uniswap_v4_hooks",
    "ekubo_v2",
    "ekubo_v3",
    "aerodrome_slipstreams",
    "velodrome_slipstreams",
    "vm:balancer_v3",
];

/// ProtocolWillDebit: the router must `approve(protocol)` before swapping.
/// The protocol's `transferFrom` is inside `swap()` and already in the gas computation of
/// `get_amount_out`, but the approval is not.
pub const PROTOCOLS_NEEDING_APPROVAL: &[&str] = &[
    "vm:balancer_v2",
    "vm:curve",
    "rfq:bebop",
    "rfq:hashflow",
    "rfq:liquorice",
    "rfq:metric",
    "erc4626",
];

/// `outputToRouter = true`: the pool sends output to the router, which then does an extra
/// `_transferOut` to the receiver.
pub const PROTOCOLS_OUTPUT_TO_ROUTER: &[&str] = &["vm:curve", "rocketpool", "fluid_v1", "weth"];

/// Estimates the total gas cost for executing a `Solution`.
///
/// Sums, for every swap in the solution:
///
/// - **Pool gas** (`swap.estimated_gas()`): the simulation-reported cost of the protocol's `swap()`
///   call, which might already include any transfers the pool performs internally (see
///   `estimate_transfer_overhead` for the conventions).
/// - **Transfer overhead**: the input transfer, approval, and output transfer gas that is NOT
///   captured by `get_amount_out`, computed via `estimate_transfer_overhead`.
/// - Missing: **router overhead** (entry-point dispatch, fee deduction, settlement). This will be
///   added soon.
///
/// The `strategy` argument is currently unused: every swap is costed independently, as if the
/// solution were a sequence of single swaps. Sequential strategies might skip intermediate
/// transfers (the previous pool sends output directly to the next pool), which makes this estimate
/// an upper bound for sequential routes. A strategy-aware estimate that accounts for those
/// optimized transfers will come in the future.
pub(crate) fn estimate_gas_usage(solution: &Solution, _strategy: Strategy) -> BigUint {
    let mut total_gas = BigUint::ZERO;
    for swap in solution.swaps() {
        // TODO: sequential swap with optimized transfers
        let swap_transfer_overhead = estimate_transfer_overhead(
            &swap.component().protocol_system,
            swap.token_in(),
            swap.token_out(),
        );
        total_gas += swap_transfer_overhead + swap.estimated_gas();
    }
    total_gas
}

fn transfer_gas(token: &tycho_common::models::token::Token) -> BigUint {
    let measured = token.gas_usage();
    if measured == BigUint::ZERO {
        BigUint::from(DEFAULT_TOKEN_TRANSFER_GAS)
    } else {
        measured
    }
}

/// Gas overhead for token transfers NOT captured by `get_amount_out`.
///
/// `get_amount_out` includes pool computation gas plus any transfers the pool performs during
/// `swap()`. The convention is:
///
/// - Input transfer is in `get_amount_out` when the pool handles it inside `swap()`: callback
///   protocols (user pays pool directly in the callback) and ProtocolWillDebit (vault pulls from
///   router via `transferFrom`). For other protocols (e.g. UniV2) the Dispatcher transfers tokens
///   to the pool before calling `executor.swap()`, so it's NOT included in `get_amount_out`.
/// - Output transfer (pool -> receiver/router) is always included in `get_amount_out`.
///
/// This function adds what's missing:
///
/// - **Input**: for non-callback protocols, the `transferFrom` that happens before
///   `executor.swap()`.
/// - **Approval**: the router's `approve(vault)` for ProtocolWillDebit protocols (Balancer V2,
///   Curve, etc.).
/// - **Output**: the extra `_transferOut(router, receiver)` for protocols with `outputToRouter =
///   true`.
fn estimate_transfer_overhead(
    protocol_system: &str,
    token_in: &tycho_common::models::token::Token,
    token_out: &tycho_common::models::token::Token,
) -> BigUint {
    let mut overhead = BigUint::ZERO;

    // Input transfer: only needed when it happens outside swap().
    // Callback protocols handle it inside the callback (part of swap gas).
    if !PROTOCOLS_CALLBACK.contains(&protocol_system) {
        overhead += transfer_gas(token_in);
    }

    if PROTOCOLS_NEEDING_APPROVAL.contains(&protocol_system) {
        overhead += BigUint::from(TOKEN_APPROVAL_GAS);
    }

    // Output transfer: router -> receiver (only when outputToRouter).
    if PROTOCOLS_OUTPUT_TO_ROUTER.contains(&protocol_system) {
        overhead += transfer_gas(token_out);
    }

    overhead
}
