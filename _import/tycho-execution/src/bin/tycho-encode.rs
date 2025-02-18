use std::io::{self, Read};

use clap::Parser;
use serde_json::Value;
use tycho_core::dto::Chain;
use tycho_execution::encoding::{models::Solution, tycho_encoder::TychoEncoder};

mod lib {
    pub mod cli;
}

use lib::cli::Cli;
use tycho_execution::encoding::{errors::EncodingError, evm::encoder_builder::EVMEncoderBuilder};

use crate::lib::cli::Commands;

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
        Commands::TychoRouter { config_path, private_key } => {
            encode_swaps(&buffer, config_path, Some(private_key), true)?
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
    private_key: Option<String>,
    use_tycho_router: bool,
) -> Result<Value, EncodingError> {
    let solution: Solution = serde_json::from_str(input)?;
    let chain = Chain::Ethereum;

    let encoder = if use_tycho_router {
        let private_key = private_key.ok_or(EncodingError::FatalError(
            "Private key is required for tycho_router".to_string(),
        ))?;
        EVMEncoderBuilder::tycho_router(chain, private_key, config_path)?.build()?
    } else {
        EVMEncoderBuilder::direct_execution(chain, config_path)?.build()?
    };

    let transactions = encoder.encode_router_calldata(vec![solution])?;

    Ok(serde_json::json!({
        "to": format!("0x{}", hex::encode(&transactions[0].to)),
        "value": format!("0x{}", hex::encode(transactions[0].value.to_bytes_be())),
        "data": format!("0x{}", hex::encode(&transactions[0].data)),
    }))
}
