use crate::protocol::errors::SimulationError;
use alloy_primitives::Address;
use tycho_core::Bytes;

/// Safely converts a `Bytes` object to an `Address` object.
///
/// Checks the length of the `Bytes` before attempting to convert, and returns a `SimulationError`
/// if not 20 bytes long.
pub(crate) fn bytes_to_erc20_address(address: &Bytes) -> Result<Address, SimulationError> {
    if address.len() == 20 {
        Ok(Address::from_slice(address))
    } else {
        Err(SimulationError::InvalidInput(
            format!("Invalid ERC20 token address: {:?}", address),
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hexstring_to_vec;
    #[test]
    fn test_bytes_to_erc20_address_0x() {
        let address =
            Bytes::from(hexstring_to_vec("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap());
        assert_eq!(
            bytes_to_erc20_address(&address).unwrap(),
            Address::from_slice(&hex::decode("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap())
        );
    }

    #[test]
    fn test_bytes_to_erc20_address_invalid() {
        let address = Bytes::from(hex::decode("C02aaA").unwrap());
        assert!(bytes_to_erc20_address(&address).is_err());
    }
}
