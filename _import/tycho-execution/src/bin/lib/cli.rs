pub use clap::Parser;

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
    /// Private key for signing approvals (required when direct_execution is false)
    #[arg(short)]
    pub private_key: Option<String>,

    /// Path to the executor addresses configuration file
    #[arg(short)]
    pub config_path: Option<String>,
}
