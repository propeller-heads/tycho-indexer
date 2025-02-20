use std::io::{self, Read};

use clap::{Parser, Subcommand};
use serde_json::Value;
use tycho_core::models::Chain;
use tycho_execution::encoding::{
    errors::EncodingError, evm::encoder_builder::EVMEncoderBuilder, models::Solution,
    tycho_encoder::TychoEncoder,
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
}

#[derive(Subcommand)]
pub enum Commands {
    /// Use the Tycho router encoding strategy
    TychoRouter {
        #[arg(short, long)]
        config_path: Option<String>,
        #[arg(short, long)]
        swapper_pk: String,
    },
    /// Use the direct execution encoding strategy
    DirectExecution {
        #[arg(short, long)]
        config_path: Option<String>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Read from stdin until EOF
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|e| format!("Failed to read from stdin: {}", e))?;

    if buffer.trim().is_empty() {
        return Err("No input provided. Expected JSON input on stdin.".into());
    }

    // Encode the solution
    let encoded = match cli.command {
        Commands::TychoRouter { config_path, swapper_pk } => {
            encode_swaps(&buffer, config_path, Some(swapper_pk), true)?
        }
        Commands::DirectExecution { config_path } => {
            encode_swaps(&buffer, config_path, None, false)?
        }
    };
    // Output the encoded result as JSON to stdout
    println!(
        "{}",
        serde_json::to_string(&encoded)
            .map_err(|e| format!("Failed to serialize output: {}", e))?
    );

    Ok(())
}

fn encode_swaps(
    input: &str,
    config_path: Option<String>,
    swapper_pk: Option<String>,
    use_tycho_router: bool,
) -> Result<Value, EncodingError> {
    let solution: Solution = serde_json::from_str(input)?;
    let chain = Chain::Ethereum;

    let mut builder = EVMEncoderBuilder::new().chain(chain);
    builder = if use_tycho_router {
        let private_key = swapper_pk.ok_or(EncodingError::FatalError(
            "Swapper private key is required for tycho_router".to_string(),
        ))?;
        builder.tycho_router(private_key, config_path)?
    } else {
        builder.direct_execution(config_path)?
    };
    let encoder = builder.build()?;

    let transactions = encoder.encode_router_calldata(vec![solution])?;

    Ok(serde_json::json!({
        "to": format!("0x{}", hex::encode(&transactions[0].to)),
        "value": format!("0x{}", hex::encode(transactions[0].value.to_bytes_be())),
        "data": format!("0x{}", hex::encode(&transactions[0].data)),
    }))
}
