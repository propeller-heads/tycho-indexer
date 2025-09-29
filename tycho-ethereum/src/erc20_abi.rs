use alloy::{
    dyn_abi::{DynSolValue, FunctionExt, JsonAbiExt},
    json_abi::{Function, JsonAbi},
    primitives::{Address, U256},
};

const ERC20_ABI_STR: &str = include_str!("./token_pre_processor/abi/erc20.json");

pub fn get_erc20_abi() -> Result<JsonAbi, Box<dyn std::error::Error + Send + Sync>> {
    serde_json::from_str(ERC20_ABI_STR)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
}

pub fn get_erc20_function(
    function_name: &str,
) -> Result<Function, Box<dyn std::error::Error + Send + Sync>> {
    let abi = get_erc20_abi()?;
    let function = abi
        .function(function_name)
        .ok_or_else(|| format!("{} function not found in ABI", function_name))?
        .first()
        .ok_or_else(|| format!("{} function has no variants", function_name))?;
    Ok(function.clone())
}

pub fn encode_balance_of(
    account: Address,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let function = get_erc20_function("balanceOf")?;
    let calldata = function.abi_encode_input(&[DynSolValue::Address(account)])?;
    Ok(calldata)
}

pub fn encode_transfer(
    to: Address,
    amount: U256,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let function = get_erc20_function("transfer")?;
    let calldata =
        function.abi_encode_input(&[DynSolValue::Address(to), DynSolValue::Uint(amount, 256)])?;
    Ok(calldata)
}

pub fn encode_approve(
    spender: Address,
    amount: U256,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let function = get_erc20_function("approve")?;
    let calldata = function
        .abi_encode_input(&[DynSolValue::Address(spender), DynSolValue::Uint(amount, 256)])?;
    Ok(calldata)
}

pub fn encode_symbol() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let function = get_erc20_function("symbol")?;
    let calldata = function.abi_encode_input(&[])?;
    Ok(calldata)
}

pub fn encode_decimals() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let function = get_erc20_function("decimals")?;
    let calldata = function.abi_encode_input(&[])?;
    Ok(calldata)
}

pub fn decode_symbol(data: &[u8]) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let function = get_erc20_function("symbol")?;
    let decoded = function.abi_decode_output(data)?;
    if let Some(DynSolValue::String(symbol)) = decoded.first() {
        Ok(symbol.clone())
    } else {
        Err("Symbol function returned unexpected type".into())
    }
}

pub fn decode_decimals(data: &[u8]) -> Result<u8, Box<dyn std::error::Error + Send + Sync>> {
    let function = get_erc20_function("decimals")?;
    let decoded = function.abi_decode_output(data)?;
    if let Some(DynSolValue::Uint(decimals, _)) = decoded.first() {
        Ok(decimals.to::<u8>())
    } else {
        Err("Decimals function returned unexpected type".into())
    }
}
