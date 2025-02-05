use std::str::FromStr;

use chrono::Utc;
use num_bigint::BigUint;
use serde_json::Value;
use tycho_core::{
    dto::{Chain, ProtocolComponent},
    Bytes,
};
use tycho_execution::encoding::models::{NativeAction, Solution, Swap};

pub fn parse_solution(input: Value) -> Result<Solution, Box<dyn std::error::Error>> {
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
        native_action: obj
            .get("native_action")
            .and_then(|v| v.as_str())
            .map(|s| match s.to_lowercase().as_str() {
                "wrap" => Some(NativeAction::Wrap),
                "unwrap" => Some(NativeAction::Unwrap),
                _ => None, // Default to None
            })
            .flatten(),
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
                "ethereum" => Chain::Ethereum,
                "starknet" => Chain::Starknet,
                "zksync" => Chain::ZkSync,
                "arbitrum" => Chain::Arbitrum,
                _ => Chain::Ethereum, // Default to Ethereum
            })
            .unwrap_or(Chain::Ethereum),
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
