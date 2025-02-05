use num_bigint::BigUint;
use tycho_core::{
    dto::{Chain as TychoCoreChain, ProtocolComponent},
    Bytes,
};

use crate::encoding::{
    constants::{NATIVE_ADDRESSES, WRAPPED_ADDRESSES},
    errors::EncodingError,
};

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
    pub native_token: Bytes,
    pub wrapped_token: Bytes,
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

impl Chain {
    pub fn from_tycho_core_chain(
        chain: TychoCoreChain,
        native_token: Option<Bytes>,
        wrapped_token: Option<Bytes>,
    ) -> Result<Self, EncodingError> {
        let native_token_address = match native_token {
            Some(token) => token,
            None => NATIVE_ADDRESSES.get(&chain)
                .cloned()
                .ok_or_else(|| EncodingError::InvalidInput(format!(
                    "Native token does not have a default address for chain {:?}. Please pass the native token address",
                    chain
                )))?,
        };

        let wrapped_token_address = match wrapped_token {
            Some(token) => token,
            None => WRAPPED_ADDRESSES.get(&chain)
                .cloned()
                .ok_or_else(|| EncodingError::InvalidInput(format!(
                    "Wrapped token does not have a default address for chain {:?}. Please pass the wrapped token address",
                    chain
                )))?,
        };
        Ok(Chain {
            id: chain.into(),
            name: chain.to_string(),
            native_token: native_token_address,
            wrapped_token: wrapped_token_address,
        })
    }
}
