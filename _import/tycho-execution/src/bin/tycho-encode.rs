use std::{
    io::{self, Read},
    str::FromStr,
};

use chrono::Utc;
use hex;
use num_bigint::BigUint;
use serde_json::Value;
use tycho_core::{
    dto::{Chain as DtoChain, ProtocolComponent},
    Bytes,
};
use tycho_execution::encoding::{
    evm::{
        strategy_encoder::strategy_encoder_registry::EVMStrategyEncoderRegistry,
        tycho_encoder::EVMTychoEncoder,
    },
    models::{Solution, Swap},
    strategy_encoder::StrategyEncoderRegistry,
    tycho_encoder::TychoEncoder,
};

const DEFAULT_ROUTER_ADDRESS: &str = "0x1234567890123456789012345678901234567890";
const HELP_TEXT: &str = "\
USAGE:
    tycho-encode [ROUTER_ADDRESS]

ARGS:
    ROUTER_ADDRESS    The address of the router contract [default: 0x1234567890123456789012345678901234567890]

The program reads a JSON object from stdin containing the swap details and outputs the encoded transaction.
The JSON object should have the following structure:
{
    \"sender\": \"0x...\",
    \"receiver\": \"0x...\",
    \"given_token\": \"0x...\",
    \"given_amount\": \"123...\",
    \"checked_token\": \"0x...\",
    \"exact_out\": false,
    \"slippage\": 0.01,
    \"expected_amount\": \"123...\",
    \"check_amount\": \"123...\",
    \"swaps\": [{
        \"component\": {
            \"id\": \"...\",
            \"protocol_system\": \"...\",
            \"protocol_type_name\": \"...\",
            \"chain\": \"ethereum\",
            \"tokens\": [\"0x...\"],
            \"contract_ids\": [\"0x...\"],
            \"static_attributes\": {\"key\": \"0x...\"}
        },
        \"token_in\": \"0x...\",
        \"token_out\": \"0x...\",
        \"split\": 1.0
    }],
    \"router_address\": \"0x...\",
    \"direct_execution\": false
}";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Show help text if requested
    if args.len() > 1 && (args[1] == "-h" || args[1] == "--help") {
        println!("{}", HELP_TEXT);
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
        eprintln!("{}", HELP_TEXT);
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

fn parse_solution(input: Value) -> Result<Solution, Box<dyn std::error::Error>> {
    let obj = input
        .as_object()
        .ok_or("Input must be a JSON object")?;

    Ok(Solution {
        sender: parse_bytes(
            obj.get("sender")
                .ok_or("sender is required")?,
        )?,
        receiver: parse_bytes(
            obj.get("receiver")
                .ok_or("receiver is required")?,
        )?,
        given_token: parse_bytes(
            obj.get("given_token")
                .ok_or("given_token is required")?,
        )?,
        given_amount: parse_biguint(
            obj.get("given_amount")
                .ok_or("given_amount is required")?,
        )?,
        checked_token: parse_bytes(
            obj.get("checked_token")
                .ok_or("checked_token is required")?,
        )?,
        exact_out: obj
            .get("exact_out")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        slippage: obj
            .get("slippage")
            .and_then(|v| v.as_f64()),
        expected_amount: obj
            .get("expected_amount")
            .map(parse_biguint)
            .transpose()?,
        check_amount: obj
            .get("check_amount")
            .map(parse_biguint)
            .transpose()?,
        swaps: parse_swaps(
            obj.get("swaps")
                .ok_or("swaps is required")?,
        )?,
        router_address: obj
            .get("router_address")
            .map(parse_bytes)
            .transpose()?,
        native_action: None, // TODO: Implement if needed
        direct_execution: obj
            .get("direct_execution")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

fn parse_bytes(value: &Value) -> Result<Bytes, Box<dyn std::error::Error>> {
    let s = value
        .as_str()
        .ok_or("Expected string for bytes")?;
    Ok(Bytes::from_str(s)?)
}

fn parse_biguint(value: &Value) -> Result<BigUint, Box<dyn std::error::Error>> {
    let s = value
        .as_str()
        .ok_or("Expected string for BigUint")?;
    Ok(BigUint::from_str(s)?)
}

fn parse_swaps(value: &Value) -> Result<Vec<Swap>, Box<dyn std::error::Error>> {
    let arr = value
        .as_array()
        .ok_or("Expected array for swaps")?;
    let mut swaps = Vec::new();

    for swap in arr {
        let obj = swap
            .as_object()
            .ok_or("Swap must be an object")?;
        swaps.push(Swap {
            component: parse_protocol_component(
                obj.get("component")
                    .ok_or("component is required")?,
            )?,
            token_in: parse_bytes(
                obj.get("token_in")
                    .ok_or("token_in is required")?,
            )?,
            token_out: parse_bytes(
                obj.get("token_out")
                    .ok_or("token_out is required")?,
            )?,
            split: obj
                .get("split")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0),
        });
    }

    Ok(swaps)
}

fn parse_protocol_component(obj: &Value) -> Result<ProtocolComponent, Box<dyn std::error::Error>> {
    let obj = obj
        .as_object()
        .ok_or("Expected object for ProtocolComponent")?;

    Ok(ProtocolComponent {
        id: obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("id is required")?
            .to_string(),
        protocol_system: obj
            .get("protocol_system")
            .and_then(|v| v.as_str())
            .ok_or("protocol_system is required")?
            .to_string(),
        protocol_type_name: obj
            .get("protocol_type_name")
            .and_then(|v| v.as_str())
            .ok_or("protocol_type_name is required")?
            .to_string(),
        chain: obj
            .get("chain")
            .and_then(|v| v.as_str())
            .map(|s| match s.to_lowercase().as_str() {
                "ethereum" => DtoChain::Ethereum,
                "starknet" => DtoChain::Starknet,
                "zksync" => DtoChain::ZkSync,
                "arbitrum" => DtoChain::Arbitrum,
                _ => DtoChain::Ethereum, // Default to Ethereum
            })
            .unwrap_or(DtoChain::Ethereum),
        tokens: obj
            .get("tokens")
            .and_then(|v| v.as_array())
            .ok_or("tokens is required")?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| Bytes::from_str(s).unwrap())
            })
            .collect::<Option<Vec<_>>>()
            .ok_or("Invalid token address format")?,
        contract_ids: obj
            .get("contract_ids")
            .and_then(|v| v.as_array())
            .ok_or("contract_ids is required")?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| Bytes::from_str(s).unwrap())
            })
            .collect::<Option<Vec<_>>>()
            .ok_or("Invalid contract address format")?,
        static_attributes: obj
            .get("static_attributes")
            .and_then(|v| v.as_object())
            .ok_or("static_attributes is required")?
            .iter()
            .map(|(k, v)| {
                Ok((
                    k.clone(),
                    Bytes::from_str(
                        v.as_str()
                            .ok_or("Invalid attribute value")?,
                    )?,
                ))
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()?,
        change: obj
            .get("change")
            .and_then(|v| v.as_str())
            .map(|s| match s.to_lowercase().as_str() {
                "update" => tycho_core::dto::ChangeType::Update,
                "deletion" => tycho_core::dto::ChangeType::Deletion,
                "creation" => tycho_core::dto::ChangeType::Creation,
                _ => tycho_core::dto::ChangeType::Unspecified,
            })
            .unwrap_or(tycho_core::dto::ChangeType::Update),
        creation_tx: Bytes::from_str(
            obj.get("creation_tx")
                .and_then(|v| v.as_str())
                .unwrap_or("0x"),
        )?,
        created_at: obj
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .unwrap()
                    .naive_utc()
            })
            .unwrap_or_else(|| Utc::now().naive_utc()),
    })
}

fn encode_swaps(input: &str, router_address: &str) -> Result<Value, Box<dyn std::error::Error>> {
    // Parse the input JSON
    let input_json: Value = serde_json::from_str(input)?;

    // Extract the chain from the input JSON
    let chain = input_json
        .get("chain")
        .and_then(|v| v.as_str())
        .map(|s| match s.to_lowercase().as_str() {
            "ethereum" => DtoChain::Ethereum,
            "starknet" => DtoChain::Starknet,
            "zksync" => DtoChain::ZkSync,
            "arbitrum" => DtoChain::Arbitrum,
            _ => DtoChain::Ethereum, // Default to Ethereum
        })
        .unwrap_or(DtoChain::Ethereum);

    // Parse the solution from the input JSON
    let mut solution = parse_solution(input_json)?;
    solution.direct_execution = true;

    // Create the strategy encoder based on the chain
    let strategy_encoder: Value = match chain {
        DtoChain::Ethereum => {
            // Create encoder and encode the solution with empty executors file path
            let strategy_selector = EVMStrategyEncoderRegistry::new(DtoChain::Ethereum, "", None)?;
            let encoder = EVMTychoEncoder::new(strategy_selector, router_address.to_string())?;
            let transactions = encoder.encode_router_calldata(vec![solution])?;

            let result: Result<Value, Box<dyn std::error::Error>> = Ok(serde_json::json!({
                "to": format!("0x{}", hex::encode(&transactions[0].to)),
                "value": format!("0x{}", hex::encode(transactions[0].value.to_bytes_be())),
                "data": format!("0x{}", hex::encode(&transactions[0].data)),
            }));
            result
        }
        _ => Err(format!("Unsupported chain: {:?}", chain).into()),
    }?;

    Ok(strategy_encoder)
}
