use hex;
use num_bigint::BigUint;
use tycho_core::{
    dto::{Chain as TychoCoreChain, ProtocolComponent},
    Bytes,
};

use crate::encoding::errors::EncodingError;

#[derive(Clone, Default, Debug)]
pub struct Solution {
    /// Address of the sender.
    pub sender: Bytes,
    /// Address of the receiver.
    pub receiver: Bytes,
    /// The token being sold (exact in) or bought (exact out).
    pub given_token: Bytes,
    /// Amount of the given token.
    pub given_amount: BigUint,
    /// The token being bought (exact in) or sold (exact out).
    pub checked_token: Bytes,
    /// False if the solution is an exact input solution. Currently only exact input solutions are
    /// supported.
    pub exact_out: bool,
    // If set, it will be applied to expected_amount
    pub slippage: Option<f64>,
    /// Expected amount of the bought token (exact in) or sold token (exact out).
    pub expected_amount: Option<BigUint>,
    /// Minimum amount to be checked for the solution to be valid.
    /// If not set, the check will not be performed.
    pub check_amount: Option<BigUint>,
    /// List of swaps to fulfill the solution.
    pub swaps: Vec<Swap>,
    // If not set, then the Tycho Router will be used
    pub router_address: Option<Bytes>,
    // If set, the corresponding native action will be executed.
    pub native_action: Option<NativeAction>,
    /// If set to true, the solution will be encoded to be sent directly to the Executor and
    /// skip the router. The user is responsible for managing necessary approvals and token
    /// transfers.
    pub direct_execution: bool,
}

#[derive(Clone, PartialEq, Debug)]
pub enum NativeAction {
    Wrap,
    Unwrap,
}

#[derive(Clone, Debug)]
pub struct Swap {
    /// Protocol component from tycho indexer
    pub component: ProtocolComponent,
    /// Token being input into the pool.
    pub token_in: Bytes,
    /// Token being output from the pool.
    pub token_out: Bytes,
    /// Percentage of the amount to be swapped in this operation (for example, 0.5 means 50%)
    pub split: f64,
}

#[derive(Clone, Debug)]
pub struct Transaction {
    // Address of the contract to call with the calldata
    pub to: Bytes,
    // ETH value to be sent with the transaction.
    pub value: BigUint,
    // Encoded calldata for the transaction.
    pub data: Vec<u8>,
}

pub struct EncodingContext {
    pub receiver: Bytes,
    pub exact_out: bool,
    pub router_address: Bytes,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ChainId(pub u64);

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Chain {
    pub id: ChainId,
    pub name: String,
}

impl ChainId {
    pub fn id(&self) -> u64 {
        self.0
    }
}

impl From<TychoCoreChain> for ChainId {
    fn from(chain: TychoCoreChain) -> Self {
        match chain {
            TychoCoreChain::Ethereum => ChainId(1),
            TychoCoreChain::ZkSync => ChainId(324),
            TychoCoreChain::Arbitrum => ChainId(42161),
            TychoCoreChain::Starknet => ChainId(0),
        }
    }
}

impl From<TychoCoreChain> for Chain {
    fn from(chain: TychoCoreChain) -> Self {
        Chain { id: chain.into(), name: chain.to_string() }
    }
}

impl Chain {
    pub fn native_token(&self) -> Result<Bytes, EncodingError> {
        match self.id.id() {
            1 => Ok(Bytes::from(hex::decode("0000000000000000000000000000000000000000").map_err(
                |_| EncodingError::FatalError("Failed to decode native token".to_string()),
            )?)),
            _ => Err(EncodingError::InvalidInput(format!(
                "Native token not set for chain {:?}. Double check the chain is supported.",
                self.name
            ))),
        }
    }
    pub fn wrapped_token(&self) -> Result<Bytes, EncodingError> {
        match self.id.id() {
            1 => Ok(Bytes::from(hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").map_err(
                |_| EncodingError::FatalError("Failed to decode wrapped token".to_string()),
            )?)),
            _ => Err(EncodingError::InvalidInput(format!(
                "Wrapped token not set for chain {:?}. Double check the chain is supported.",
                self.name
            ))),
        }
    }
}
