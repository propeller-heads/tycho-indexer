use ethers::{
    abi::{encode, Abi, ParamType, Token},
    core::types::{U256},
    prelude::*,
};
use revm::{
    db::DatabaseRef,
    primitives::{alloy_primitives::Keccak256, Address},
};
use std::{
    collections::{HashMap},
    str::FromStr,
};
use ethers::abi::decode;
use thiserror::Error;

use crate::{
    evm_simulation::simulation::{SimulationEngine, SimulationParameters, SimulationResult},
    protocol::vm::utils::load_swap_abi,
};

#[derive(Error, Debug)]
pub enum SimulationError {
    #[error("Runtime Error: {0}")]
    RuntimeError(String),

    #[error("Revert Error: {0}")]
    RevertError(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),

    #[error("ABI loading error: {0}")]
    AbiError(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),
}

impl From<std::io::Error> for SimulationError {
    fn from(err: std::io::Error) -> SimulationError {
        SimulationError::AbiError(err.to_string())
    }
}

type TStateOverwrites = HashMap<Address, HashMap<u64, U256>>;

#[derive(Debug)]
struct Trade {
    received_amount: f64,
    gas_used: f64,
    price: f64,
}

struct ProtoSimResponse {
    return_value: Vec<H160>,
    simulation_result: SimulationResult,
}

struct ProtoSimContract<D: DatabaseRef + std::clone::Clone> {
    abi: Abi,
    address: Address,
    engine: SimulationEngine<D>,
}

impl<D: DatabaseRef + std::clone::Clone> ProtoSimContract<D> {
    pub fn new(address: Address, engine: SimulationEngine<D>) -> Result<Self, SimulationError> {
        let abi = load_swap_abi()?;
        Ok(Self { address, abi, engine })
    }
    fn encode_input(&self, fname: &str, args: Vec<String>) -> Result<Vec<u8>, SimulationError> {
        let function = self
            .abi
            .functions
            .get(fname)
            .and_then(|funcs| funcs.first())
            .ok_or_else(|| {
                SimulationError::EncodingError(format!(
                    "Function name {} not found in the ABI",
                    fname.to_string()
                ))
            })?;

        if function.inputs.len() != args.len() {
            return Err(SimulationError::EncodingError("Invalid argument count".to_string()));
        }

        // ethers::abi::encode only takes &[Token] as input,
        // so we need to convert arguments to tokens based on the ABI types
        let tokens: Vec<Token> = function
            .inputs
            .iter()
            .zip(args.into_iter())
            .map(|(param, arg_value)| self.convert_to_token(&param.kind, arg_value))
            .collect::<Result<Vec<_>, _>>()?;

        let input_types: String = function
            .inputs
            .iter()
            .map(|input| input.kind.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let selector = {
            let mut hasher = Keccak256::new();
            hasher.update(format!("{}({})", fname, input_types));
            let result = hasher.finalize();
            result[..4].to_vec()
        };

        let encoded = encode(&tokens);
        let mut result = Vec::with_capacity(4 + encoded.len());
        result.extend_from_slice(&selector);
        result.extend(encoded);

        Ok(result)
    }

    /// Converts a string argument to an `ethers::abi::Token` based on its corresponding
    /// `ParamType`.
    ///
    /// This function takes an argument in string format and a `ParamType` that describes the
    /// expected type of the argument according to the Ethereum ABI. It parses the string and
    /// converts it into the corresponding `Token`.
    fn convert_to_token(
        &self,
        param_type: &ParamType,
        arg_value: String,
    ) -> Result<Token, SimulationError> {
        match param_type {
            ParamType::Address => {
                let addr = H160::from_str(&arg_value).map_err(|_| {
                    SimulationError::EncodingError(format!("Invalid address: {}", arg_value))
                })?;
                Ok(Token::Address(addr))
            }
            ParamType::Uint(_) => {
                let value = U256::from_dec_str(&arg_value).map_err(|_| {
                    SimulationError::EncodingError(format!("Invalid uint: {}", arg_value))
                })?;
                Ok(Token::Uint(value))
            }
            ParamType::FixedBytes(size) => {
                let bytes = hex::decode(arg_value.clone()).map_err(|_| {
                    SimulationError::EncodingError(format!("Invalid bytes: {}", arg_value))
                })?;
                if bytes.len() == *size {
                    Ok(Token::FixedBytes(bytes))
                } else {
                    Err(SimulationError::EncodingError("Invalid bytes length".to_string()))
                }
            }
            ParamType::Bytes => {
                let bytes = hex::decode(arg_value.clone()).map_err(|_| {
                    SimulationError::EncodingError(format!("Invalid bytes: {}", arg_value))
                })?;
                Ok(Token::Bytes(bytes))
            }
            ParamType::Array(inner) => {
                let elements: Vec<String> = arg_value
                    .split(',')
                    .map(String::from)
                    .collect();
                let tokens = elements
                    .into_iter()
                    .map(|elem| self.convert_to_token(inner, elem))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Token::Array(tokens))
            }
            ParamType::Tuple(types) => {
                let elements: Vec<String> = arg_value
                    .split(',')
                    .map(String::from)
                    .collect();
                if elements.len() != types.len() {
                    return Err(SimulationError::EncodingError(format!(
                        "Invalid tuple length. Expected {}, got {}",
                        types.len(),
                        elements.len()
                    )));
                }
                let tokens = elements
                    .into_iter()
                    .zip(types.iter())
                    .map(|(elem, typ)| self.convert_to_token(typ, elem))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Token::Tuple(tokens))
            }
            _ => Err(SimulationError::EncodingError("Unsupported type".to_string())),
        }
    }

    pub fn decode_output(&self, fname: &str, encoded: Vec<u8>) -> Result<Vec<Token>, SimulationError> {
        todo!()
    }

    pub async fn call(
        &self,
        fname: &str,
        args: Vec<H160>,
        block_number: U256,
        timestamp: Option<u64>,
        overrides: Option<TStateOverwrites>,
        caller: Option<Address>,
        value: U256,
    ) -> Result<ProtoSimResponse, SimulationError> {
        todo!()
    }

    pub fn simulate(
        &self,
        params: SimulationParameters,
    ) -> Result<SimulationResult, SimulationError> {
        todo!()
        // use self.engine.simulate(&params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::primitives::{hex, AccountInfo, Address, Bytecode, B256, U256 as rU256};
    use rstest::rstest;
    use std::str::FromStr;

    #[derive(Debug, Clone)]
    struct MockDatabase;

    impl DatabaseRef for MockDatabase {
        type Error = String;

        fn basic_ref(
            &self,
            address: revm::precompile::Address,
        ) -> Result<Option<AccountInfo>, Self::Error> {
            todo!()
        }

        fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
            todo!()
        }

        fn storage_ref(
            &self,
            address: revm::precompile::Address,
            index: rU256,
        ) -> Result<rU256, Self::Error> {
            todo!()
        }

        fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
            todo!()
        }
    }
    fn create_contract() -> ProtoSimContract<MockDatabase> {
        let address = Address::ZERO;
        let engine = SimulationEngine::new(MockDatabase, false);
        ProtoSimContract::new(address, engine).unwrap()
    }

    #[rstest]
    #[case::address(
        ParamType::Address,
    "0x0000000000000000000000000000000000000001",
        Token::Address(H160::from_str("0x0000000000000000000000000000000000000001").unwrap())
    )]
    #[case::uint(ParamType::Uint(256), "1000", Token::Uint(U256::from(1000u64)))]
    #[case::fixed_bytes(
        ParamType::FixedBytes(4),
    "12345678",
        Token::FixedBytes(vec![0x12, 0x34, 0x56, 0x78])
    )]
    #[case::bytes(
        ParamType::Bytes,
    "12345678",
        Token::Bytes(vec![0x12, 0x34, 0x56, 0x78])
    )]
    #[case::array(
        ParamType::Array(Box::new(ParamType::Uint(256))),
    "100,200,300",
        Token::Array(vec![
        Token::Uint(U256::from(100u64)),
        Token::Uint(U256::from(200u64)),
        Token::Uint(U256::from(300u64)),
        ])
    )]
    #[case::tuple(
        ParamType::Tuple(vec![
        ParamType::Uint(256),
        ParamType::Address,
        ]),
    "1000,0x0000000000000000000000000000000000000001",
        Token::Tuple(vec![
        Token::Uint(U256::from(1000u64)),
        Token::Address(H160::from_str("0x0000000000000000000000000000000000000001").unwrap()),
        ])
    )]
    fn test_convert_to_token_parameterized(
        #[case] param_type: ParamType,
        #[case] arg_value: &str,
        #[case] expected_token: Token,
    ) {
        let contract = create_contract();
        let token = contract
            .convert_to_token(&param_type, arg_value.to_string())
            .unwrap();
        assert_eq!(token, expected_token);
    }

    #[test]
    fn test_convert_to_token_invalid_address() {
        let contract = create_contract();
        let param_type = ParamType::Address;
        let arg_value = "invalid_address".to_string();
        let result = contract.convert_to_token(&param_type, arg_value);

        assert!(result.is_err());
    }

    #[test]
    fn test_encode_input_get_capabilities() {
        let contract = create_contract();

        // Arguments for the 'getCapabilities' function
        let pool_id =
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string();
        let sell_token = "0000000000000000000000000000000000000002".to_string();
        let buy_token = "0000000000000000000000000000000000000003".to_string();

        let encoded_input =
            contract.encode_input("getCapabilities", vec![pool_id, sell_token, buy_token]);

        assert!(encoded_input.is_ok());
        let encoded_result = encoded_input.unwrap();

        // The expected selector for "getCapabilities(bytes32,address,address)"
        let expected_selector = hex!("48bd7dfd");
        assert_eq!(&encoded_result[..4], &expected_selector[..]);

        let expected_pool_id =
            hex!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let expected_sell_token =
            hex!("0000000000000000000000000000000000000000000000000000000000000002"); // padded to 32 bytes
        let expected_buy_token =
            hex!("0000000000000000000000000000000000000000000000000000000000000003"); // padded to 32 bytes

        assert_eq!(&encoded_result[4..36], &expected_pool_id); // 32 bytes for poolId
        assert_eq!(&encoded_result[36..68], &expected_sell_token); // 32 bytes for address (padded)
        assert_eq!(&encoded_result[68..100], &expected_buy_token); // 32 bytes for address (padded)
    }
}
