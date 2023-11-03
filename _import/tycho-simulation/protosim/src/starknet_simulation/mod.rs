use cairo_vm::felt::Felt252;
use starknet_in_rust::utils::{Address, ClassHash};

pub mod rpc_reader;
pub mod simulation;

pub fn felt_str(val: &str) -> Felt252 {
    let base = if val.starts_with("0x") { 16_u32 } else { 10_u32 };
    let stripped_val = val.strip_prefix("0x").unwrap_or(val);

    Felt252::parse_bytes(stripped_val.as_bytes(), base).expect("Failed to parse input")
}

pub fn address_str(val: &str) -> Address {
    Address(felt_str(val))
}

pub fn class_hash_str(val: &str) -> ClassHash {
    felt_str(val).to_be_bytes()
}
