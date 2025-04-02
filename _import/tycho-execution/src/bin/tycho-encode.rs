use std::io::{self, Read};

use clap::{Parser, Subcommand};
use tycho_common::{hex_bytes::Bytes, models::Chain};
use tycho_execution::encoding::{
    evm::encoder_builder::EVMEncoderBuilder, models::Solution, tycho_encoder::TychoEncoder,
};

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
///     "checked_amount": "123...",
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
///         "split": 0.0
///     }],
///     "router_address": "0x..."
/// }
/// ```
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    #[arg(short, long)]
    executors_file_path: Option<String>,
    #[arg(short, long)]
    router_address: Option<Bytes>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Use the Tycho router encoding strategy
    TychoRouter,
    /// Use the Tycho router encoding strategy with Permit2 approval and token in transfer
    TychoRouterPermit2 {
        #[arg(short, long)]
        swapper_pk: String,
    },
    /// Use the direct execution encoding strategy
    DirectExecution,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let chain = Chain::Ethereum;

    // Read from stdin until EOF
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|e| format!("Failed to read from stdin: {}", e))?;

    if buffer.trim().is_empty() {
        return Err("No input provided. Expected JSON input on stdin.".into());
    }
    let solution: Solution = serde_json::from_str(&buffer)?;

    let mut builder = EVMEncoderBuilder::new().chain(chain);

    if let Some(config_path) = cli.executors_file_path {
        builder = builder.executors_file_path(config_path);
    }
    if let Some(router_address) = cli.router_address {
        builder = builder.router_address(router_address);
    }

    builder = match cli.command {
        Commands::TychoRouter => builder.initialize_tycho_router()?,
        Commands::TychoRouterPermit2 { swapper_pk } => {
            builder.initialize_tycho_router_with_permit2(swapper_pk)?
        }
        Commands::DirectExecution => builder.initialize_direct_execution()?,
    };
    let encoder = builder.build()?;
    let transactions = encoder.encode_router_calldata(vec![solution])?;
    let encoded = serde_json::json!({
        "to": format!("0x{}", hex::encode(&transactions[0].to)),
        "value": format!("0x{}", hex::encode(transactions[0].value.to_bytes_be())),
        "data": format!("0x{}", hex::encode(&transactions[0].data)),
    });
    // Output the encoded result as JSON to stdout
    println!(
        "{}",
        serde_json::to_string(&encoded)
            .map_err(|e| format!("Failed to serialize output: {}", e))?
    );

    Ok(())
}
