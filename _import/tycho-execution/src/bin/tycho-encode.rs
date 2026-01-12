use std::{
    fs,
    io::{self, Read},
};

use alloy::sol_types::SolValue;
use clap::{Parser, Subcommand};
use tycho_common::{hex_bytes::Bytes, models::Chain};
use tycho_execution::encoding::{
    errors::EncodingError,
    evm::{
        approvals::permit2::PermitSingle,
        encoder_builders::{TychoExecutorEncoderBuilder, TychoRouterEncoderBuilder},
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
    },
    models::{Solution, UserTransferType},
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
/// }
/// ```
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    #[arg(short, long)]
    chain: Chain,
    #[arg(short, long)]
    executors_file_path: Option<String>,
    #[arg(short, long)]
    router_address: Option<Bytes>,
    #[arg(short, long)]
    user_transfer_type: Option<UserTransferType>,
    #[arg(short, long)]
    swapper_pk: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Use Tycho router encoding
    TychoRouter,
    /// Use direct execution encoding
    TychoExecutor,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    // Read from stdin until EOF
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|e| format!("Failed to read from stdin: {e}"))?;

    if buffer.trim().is_empty() {
        return Err("No input provided. Expected JSON input on stdin.".into());
    }
    let solution: Solution = serde_json::from_str(&buffer)?;

    let chain = cli.chain;
    let encoder: Box<dyn TychoEncoder> = match cli.command {
        Commands::TychoRouter => {
            let mut builder = TychoRouterEncoderBuilder::new().chain(chain);
            let executors_addresses: Option<String> =
                if let Some(config_path) = cli.executors_file_path {
                    Some(fs::read_to_string(&config_path).map_err(|e| {
                        EncodingError::FatalError(format!(
                            "Error reading executors file from {config_path:?}: {e}",
                        ))
                    })?)
                } else {
                    None
                };
            let swap_encoder_registry = SwapEncoderRegistry::new(Chain::Ethereum)
                .add_default_encoders(executors_addresses)?;
            builder = builder.swap_encoder_registry(swap_encoder_registry);
            if let Some(router_address) = cli.router_address {
                builder = builder.router_address(router_address);
            }
            if let Some(user_transfer_type) = cli.user_transfer_type {
                builder = builder.user_transfer_type(user_transfer_type);
            }
            #[allow(deprecated)]
            if let Some(swapper_pk) = cli.swapper_pk {
                builder = builder.swapper_pk(swapper_pk);
            }
            builder.build()?
        }
        Commands::TychoExecutor => TychoExecutorEncoderBuilder::new().build()?,
    };

    let encoded_solutions = encoder.encode_solutions(vec![solution])?;
    let encoded = serde_json::json!({
            "swaps": format!("0x{}", hex::encode(&encoded_solutions[0].swaps)),
            "interacting_with": format!("0x{}", hex::encode(&encoded_solutions[0].interacting_with)),
            "function_signature": format!("{}",&encoded_solutions[0].function_signature),
            "n_tokens": format!("{}", &encoded_solutions[0].n_tokens),
            "permit": match encoded_solutions[0].permit.as_ref() {
        Some(permit) => {
            match PermitSingle::try_from(permit) {
                Ok(sol_permit) => format!("0x{}", hex::encode(sol_permit.abi_encode())),
                Err(_) => String::new(),
            }
        }
        None => String::new(),
    },
        });
    // Output the encoded result as JSON to stdout
    println!(
        "{}",
        serde_json::to_string(&encoded).map_err(|e| format!("Failed to serialize output: {e}"))?
    );

    Ok(())
}
