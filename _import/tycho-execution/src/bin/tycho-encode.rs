use std::io::{self, Read};

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
    pub mod help;
}

const DEFAULT_ROUTER_ADDRESS: &str = "0xaa820C29648D5EA543d712cC928377Bd7206a0E7";
const DEFAULT_EXECUTORS_FILE_PATH: &str = "src/encoding/config/executor_addresses.json";
const DEFAULT_PRIVATE_KEY: &str =
    "0x938f4da9d3a947a4a6c53cfd8fcdd876641d6a4519243820b648af0bc3e67f7c";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Show help text if requested
    if args.len() > 1 && (args[1] == "-h" || args[1] == "--help") {
        println!("{}", lib::help::HELP_TEXT);
        return Ok(());
    }

    let router_address = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or(DEFAULT_ROUTER_ADDRESS);

    let private_key = args
        .get(2)
        .map(|s| s.to_string())
        .or_else(|| Some(DEFAULT_PRIVATE_KEY.to_string()));

    // Read from stdin until EOF
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|e| format!("Failed to read from stdin: {}", e))?;

    if buffer.trim().is_empty() {
        eprintln!("Error: No input provided");
        eprintln!("{}", lib::help::HELP_TEXT);
        std::process::exit(1);
    }

    // Encode the solution
    let encoded = encode_swaps(&buffer, router_address, private_key)?;

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
