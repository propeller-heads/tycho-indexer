use std::io::{self, Read};

use serde_json::Value;
use tycho_core::dto::Chain;
use tycho_execution::encoding::{
    evm::{
        strategy_encoder::strategy_encoder_registry::EVMStrategyEncoderRegistry,
        tycho_encoder::EVMTychoEncoder,
    },
    strategy_encoder::StrategyEncoderRegistry,
    tycho_encoder::TychoEncoder,
};

mod lib {
    pub mod help;
    pub mod parse;
}

const DEFAULT_ROUTER_ADDRESS: &str = "0x1234567890123456789012345678901234567890";
const DEFAULT_EXECUTORS_FILE_PATH: &str = "src/encoding/config/executor_addresses.json";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // Parse the JSON input to verify it's valid
    serde_json::from_str::<Value>(&buffer)
        .map_err(|e| format!("Failed to parse JSON input: {}", e))?;

    // Encode the solution
    let encoded = encode_swaps(&buffer, router_address)?;

    // Output the encoded result as JSON to stdout
    println!(
        "{}",
        serde_json::to_string(&encoded)
            .map_err(|e| format!("Failed to serialize output: {}", e))?
    );

    Ok(())
}

fn encode_swaps(input: &str, router_address: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let input_json: Value = serde_json::from_str(input)?;
    let solution = lib::parse::parse_solution(input_json)?;

    let strategy_selector =
        EVMStrategyEncoderRegistry::new(Chain::Ethereum, DEFAULT_EXECUTORS_FILE_PATH, None)?;
    let encoder = EVMTychoEncoder::new(strategy_selector, router_address.to_string())?;
    let transactions = encoder.encode_router_calldata(vec![solution])?;

    Ok(serde_json::json!({
        "to": format!("0x{}", hex::encode(&transactions[0].to)),
        "value": format!("0x{}", hex::encode(transactions[0].value.to_bytes_be())),
        "data": format!("0x{}", hex::encode(&transactions[0].data)),
    }))
}
