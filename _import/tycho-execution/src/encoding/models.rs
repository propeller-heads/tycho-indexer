use hex;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use tycho_common::{
    models::{protocol::ProtocolComponent, Chain as TychoCommonChain},
    Bytes,
};

use crate::encoding::{errors::EncodingError, serde_primitives::biguint_string};

/// Represents a solution containing details describing an order, and  instructions for filling
/// the order.
#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct Solution {
    /// Address of the sender.
    pub sender: Bytes,
    /// Address of the receiver.
    pub receiver: Bytes,
    /// The token being sold (exact in) or bought (exact out).
    pub given_token: Bytes,
    /// Amount of the given token.
    #[serde(with = "biguint_string")]
    pub given_amount: BigUint,
    /// The token being bought (exact in) or sold (exact out).
    pub checked_token: Bytes,
    /// False if the solution is an exact input solution. Currently only exact input solutions are
    /// supported.
    #[serde(default)]
    pub exact_out: bool,
    /// Minimum amount to be checked for the solution to be valid.
    #[serde(with = "biguint_string")]
    pub checked_amount: BigUint,
    /// List of swaps to fulfill the solution.
    pub swaps: Vec<Swap>,
    /// If set, the corresponding native action will be executed.
    pub native_action: Option<NativeAction>,
}

/// Represents an action to be performed on the native token either before or after the swap.
///
/// `Wrap` means that the native token will be wrapped before the first swap, and `Unwrap`
/// means that the native token will be unwrapped after the last swap, before being sent to the
/// receiver.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAction {
    Wrap,
    Unwrap,
}

/// Represents a swap operation to be performed on a pool.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Swap {
    /// Protocol component from tycho indexer
    pub component: ProtocolComponent,
    /// Token being input into the pool.
    pub token_in: Bytes,
    /// Token being output from the pool.
    pub token_out: Bytes,
    /// Decimal of the amount to be swapped in this operation (for example, 0.5 means 50%)
    #[serde(default)]
    pub split: f64,
}

impl Swap {
    pub fn new<T: Into<ProtocolComponent>>(
        component: T,
        token_in: Bytes,
        token_out: Bytes,
        split: f64,
    ) -> Self {
        Self { component: component.into(), token_in, token_out, split }
    }
}

/// Represents a transaction to be executed.
///
/// # Fields
/// * `to`: Address of the contract to call with the calldata
/// * `value`: Native token value to be sent with the transaction.
/// * `data`: Encoded calldata for the transaction.
/// * `selector`: Only relevant for direct executions. The selector of the function to be called.
#[derive(Clone, Debug)]
pub struct Transaction {
    pub to: Bytes,
    pub value: BigUint,
    pub data: Vec<u8>,
}

/// Represents a solution that has been encoded for execution.
///
/// # Fields
/// * `swaps`: Encoded swaps to be executed.
/// * `interacting_with`: Address of the contract to be called.
/// * `selector`: The selector of the function to be called.
/// * `n_tokens`: Number of tokens in the swap.
/// * `permit`: Optional permit for the swap (if permit2 is enabled).
/// * `signature`: Optional signature for the swap (if permit2 is enabled).
#[derive(Clone, Debug)]
pub struct EncodedSolution {
    pub swaps: Vec<u8>,
    pub interacting_with: Bytes,
    pub selector: String,
    pub n_tokens: usize,
    pub permit: Option<PermitSingle>,
    pub signature: Option<Vec<u8>>,
}

/// Represents a single permit for permit2.
///
/// # Fields
/// * `details`: The details of the permit, such as token, amount, expiration, and nonce.
/// * `spender`: The address authorized to spend the tokens.
/// * `sig_deadline`: The deadline (as a timestamp) for the permit signature
#[derive(Debug, Clone)]
pub struct PermitSingle {
    pub details: PermitDetails,
    pub spender: Bytes,
    pub sig_deadline: BigUint,
}

/// Details of a permit.
///
/// # Fields
/// * `token`: The token address for which the permit is granted.
/// * `amount`: The amount of tokens approved for spending.
/// * `expiration`: The expiration time (as a timestamp) for the permit.
/// * `nonce`: The unique nonce to prevent replay attacks.
#[derive(Debug, Clone)]
pub struct PermitDetails {
    pub token: Bytes,
    pub amount: BigUint,
    pub expiration: BigUint,
    pub nonce: BigUint,
}

impl PartialEq for PermitSingle {
    fn eq(&self, other: &Self) -> bool {
        self.details == other.details && self.spender == other.spender
        // sig_deadline is intentionally ignored
    }
}

impl PartialEq for PermitDetails {
    fn eq(&self, other: &Self) -> bool {
        self.token == other.token && self.amount == other.amount && self.nonce == other.nonce
        // expiration is intentionally ignored
    }
}

/// Represents necessary attributes for encoding an order.
///
/// # Fields
///
/// * `receiver`: Address of the receiver of the out token after the swaps are completed.
/// * `exact_out`: true if the solution is a buy order, false if it is a sell order.
/// * `router_address`: Address of the router contract to be used for the swaps. Zero address if
///   solution does not require router address.
/// * `group_token_in`: Token to be used as the input for the group swap.
/// * `group_token_out`: Token to be used as the output for the group swap.
/// * `transfer`: Type of transfer to be performed. See `TransferType` for more details.
#[derive(Clone, Debug)]
pub struct EncodingContext {
    pub receiver: Bytes,
    pub exact_out: bool,
    pub router_address: Option<Bytes>,
    pub group_token_in: Bytes,
    pub group_token_out: Bytes,
    pub transfer_type: TransferType,
}

/// Represents the type of transfer to be performed into the pool.
///
/// # Fields
///
/// * `TransferFrom`: Transfer the token from the sender to the protocol/router.
/// * `Transfer`: Transfer the token from the router into the protocol.
/// * `None`: No transfer is needed. Tokens are already in the pool.
#[repr(u8)]
#[derive(Clone, Debug, PartialEq)]
pub enum TransferType {
    TransferFrom = 0,
    Transfer = 1,
    None = 2,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Chain {
    pub id: u64,
    pub name: String,
}

impl From<TychoCommonChain> for Chain {
    fn from(chain: TychoCommonChain) -> Self {
        match chain {
            TychoCommonChain::Ethereum => Chain { id: 1, name: chain.to_string() },
            TychoCommonChain::ZkSync => Chain { id: 324, name: chain.to_string() },
            TychoCommonChain::Arbitrum => Chain { id: 42161, name: chain.to_string() },
            TychoCommonChain::Starknet => Chain { id: 0, name: chain.to_string() },
            TychoCommonChain::Base => Chain { id: 8453, name: chain.to_string() },
            TychoCommonChain::Unichain => Chain { id: 130, name: chain.to_string() },
        }
    }
}

impl Chain {
    fn decode_hex(&self, hex_str: &str, err_msg: &str) -> Result<Bytes, EncodingError> {
        Ok(Bytes::from(
            hex::decode(hex_str).map_err(|_| EncodingError::FatalError(err_msg.to_string()))?,
        ))
    }

    pub fn native_token(&self) -> Result<Bytes, EncodingError> {
        let decode_err_msg = "Failed to decode native token";
        match self.id {
            1 | 8453 | 42161 => {
                self.decode_hex("0000000000000000000000000000000000000000", decode_err_msg)
            }
            324 => self.decode_hex("000000000000000000000000000000000000800A", decode_err_msg),
            130 => self.decode_hex("0000000000000000000000000000000000000000", decode_err_msg),
            _ => Err(EncodingError::InvalidInput(format!(
                "Native token not set for chain {:?}. Double check the chain is supported.",
                self.name
            ))),
        }
    }

    pub fn wrapped_token(&self) -> Result<Bytes, EncodingError> {
        let decode_err_msg = "Failed to decode wrapped token";
        match self.id {
            1 => self.decode_hex("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", decode_err_msg),
            8453 => self.decode_hex("4200000000000000000000000000000000000006", decode_err_msg),
            324 => self.decode_hex("5AEa5775959fBC2557Cc8789bC1bf90A239D9a91", decode_err_msg),
            42161 => self.decode_hex("82aF49447D8a07e3bd95BD0d56f35241523fBab1", decode_err_msg),
            130 => self.decode_hex("4200000000000000000000000000000000000006", decode_err_msg),
            _ => Err(EncodingError::InvalidInput(format!(
                "Wrapped token not set for chain {:?}. Double check the chain is supported.",
                self.name
            ))),
        }
    }
}

mod tests {
    use super::*;

    struct MockProtocolComponent {
        id: String,
        protocol_system: String,
    }

    impl From<MockProtocolComponent> for ProtocolComponent {
        fn from(component: MockProtocolComponent) -> Self {
            ProtocolComponent {
                id: component.id,
                protocol_system: component.protocol_system,
                tokens: vec![],
                protocol_type_name: "".to_string(),
                chain: Default::default(),
                contract_addresses: vec![],
                static_attributes: Default::default(),
                change: Default::default(),
                creation_tx: Default::default(),
                created_at: Default::default(),
            }
        }
    }

    #[test]
    fn test_swap_new() {
        let component = MockProtocolComponent {
            id: "i-am-an-id".to_string(),
            protocol_system: "uniswap_v2".to_string(),
        };
        let swap = Swap::new(component, Bytes::from("0x12"), Bytes::from("34"), 0.5);
        assert_eq!(swap.token_in, Bytes::from("0x12"));
        assert_eq!(swap.token_out, Bytes::from("0x34"));
        assert_eq!(swap.component.protocol_system, "uniswap_v2");
        assert_eq!(swap.component.id, "i-am-an-id");
    }
}
