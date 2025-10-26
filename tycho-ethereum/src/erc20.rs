use alloy::{
    core::sol,
    primitives::{Address, U256},
    sol_types::SolCall,
};

// ERC20 interface definition
// Copied from EIP-20: https://eips.ethereum.org/EIPS/eip-20
sol! {
    function name() public view returns (string);
    function symbol() public view returns (string);
    function decimals() public view returns (uint8);
    function totalSupply() public view returns (uint256);
    function balanceOf(address _owner) public view returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);
}

/// Encode balanceOf(address) call
pub fn encode_balance_of(owner: Address) -> Vec<u8> {
    balanceOfCall { _owner: owner }.abi_encode()
}

/// Encode transfer(address,uint256) call
pub fn encode_transfer(to: Address, value: U256) -> Vec<u8> {
    transferCall { _to: to, _value: value }.abi_encode()
}

/// Encode approve(address,uint256) call
pub fn encode_approve(spender: Address, value: U256) -> Vec<u8> {
    approveCall { _spender: spender, _value: value }.abi_encode()
}

/// Encode symbol() call
pub fn encode_symbol() -> Vec<u8> {
    symbolCall {}.abi_encode()
}

/// Encode decimals() call
pub fn encode_decimals() -> Vec<u8> {
    decimalsCall {}.abi_encode()
}

/// Decode symbol() return value
pub(crate) fn decode_symbol(
    data: &[u8],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    symbolCall::abi_decode_returns(data)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
}

/// Decode decimals() return value
pub fn decode_decimals(data: &[u8]) -> Result<u8, Box<dyn std::error::Error + Send + Sync>> {
    decimalsCall::abi_decode_returns(data)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_decimals() {
        let val = U256::from(255);
        let decimals = decode_decimals(&val.to_be_bytes::<32>()).unwrap();
        assert_eq!(decimals, 255);
    }

    #[test]
    fn test_decode_decimals_does_not_panic() {
        let val = U256::from(1024);
        let res = decode_decimals(&val.to_be_bytes::<32>());
        assert!(res.is_err());
    }
}
