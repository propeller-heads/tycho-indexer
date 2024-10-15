use cairo_vm::felt::{Felt252, ParseFeltError};
use num_traits::Num;
use starknet_in_rust::utils::{Address, ClassHash};

pub mod rpc_reader;
pub mod simulation;

pub fn felt_str(val: &str) -> Result<Felt252, ParseFeltError> {
    let base = if val.starts_with("0x") { 16 } else { 10 };
    let stripped_val = val.trim_start_matches("0x");

    Felt252::from_str_radix(stripped_val, base)
}

pub fn address_str(val: &str) -> Result<Address, ParseFeltError> {
    felt_str(val).map(Address)
}

pub fn class_hash_str(val: &str) -> Result<ClassHash, ParseFeltError> {
    let felt = felt_str(val)?;
    Ok(felt.to_be_bytes())
}
