use alloy::core::sol;

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
