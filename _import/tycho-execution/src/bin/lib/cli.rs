pub use clap::Parser;
pub const DEFAULT_ROUTER_ADDRESS: &str = "0xaa820C29648D5EA543d712cC928377Bd7206a0E7";

#[derive(Parser)]
/// Encode swap transactions for the Tycho router
///
/// Reads a JSON object from stdin with the following structure:
/// ```json
/// {
///     "sender": "0x...",
///     "receiver": "0x...",
///     "given_token": "0x...",
///     "given_amount": "123...",
///     "checked_token": "0x...",
///     "exact_out": false,
///     "slippage": 0.01,
///     "expected_amount": "123...",
///     "check_amount": "123...",
///     "swaps": [{
///         "component": {
///             "id": "...",
///             "protocol_system": "...",
///             "protocol_type_name": "...",
///             "chain": "ethereum",
///             "tokens": ["0x..."],
///             "contract_ids": ["0x..."],
///             "static_attributes": {"key": "0x..."}
///         },
///         "token_in": "0x...",
///         "token_out": "0x...",
///         "split": 1.0
///     }],
///     "router_address": "0x...",
///     "direct_execution": false
/// }
/// ```
pub struct Cli {
    /// Router contract address to use for encoding transactions
    #[arg(default_value = DEFAULT_ROUTER_ADDRESS)]
    pub router_address: String,

    /// Private key for signing approvals (required when direct_execution is false)
    #[arg(short, long)]
    pub private_key: Option<String>,
}
