use std::io::{self, Read};

use clap::Parser;
use serde_json::Value;
use tycho_core::dto::Chain;
use tycho_execution::encoding::{
    evm::{
        strategy_encoder::strategy_encoder_registry::EVMStrategyEncoderRegistry,
        tycho_encoder::EVMTychoEncoder,
    },
    models::Solution,
    strategy_encoder::StrategyEncoderRegistry,
    tycho_encoder::TychoEncoder,
};

mod lib {
    pub mod cli;
}

use lib::cli::Cli;

const DEFAULT_EXECUTORS_FILE_PATH: &str = "src/encoding/config/executor_addresses.json";

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
    let encoded = encode_swaps(&buffer, &cli.router_address, cli.private_key)?;

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
    router_address: &str,
    private_key: Option<String>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let solution: Solution = serde_json::from_str(input)?;

    let strategy_selector =
        EVMStrategyEncoderRegistry::new(Chain::Ethereum, DEFAULT_EXECUTORS_FILE_PATH, private_key)?;
    let encoder = EVMTychoEncoder::new(strategy_selector, router_address.to_string())?;
    let transactions = encoder.encode_router_calldata(vec![solution])?;

    Ok(serde_json::json!({
        "to": format!("0x{}", hex::encode(&transactions[0].to)),
        "value": format!("0x{}", hex::encode(transactions[0].value.to_bytes_be())),
        "data": format!("0x{}", hex::encode(&transactions[0].data)),
    }))
}
