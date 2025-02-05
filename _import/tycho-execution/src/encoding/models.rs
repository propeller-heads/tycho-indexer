use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use tycho_core::{dto::ProtocolComponent, Bytes};

use crate::encoding::serde_primitives::{biguint_string, biguint_string_option};

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
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
    // If set, it will be applied to expected_amount
    pub slippage: Option<f64>,
    /// Expected amount of the bought token (exact in) or sold token (exact out).
    #[serde(with = "biguint_string_option")]
    pub expected_amount: Option<BigUint>,
    /// Minimum amount to be checked for the solution to be valid.
    /// If not set, the check will not be performed.
    #[serde(with = "biguint_string_option")]
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
    #[serde(default)]
    pub direct_execution: bool,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAction {
    Wrap,
    Unwrap,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Swap {
    /// Protocol component from tycho indexer
    pub component: ProtocolComponent,
    /// Token being input into the pool.
    pub token_in: Bytes,
    /// Token being output from the pool.
    pub token_out: Bytes,
    /// Percentage of the amount to be swapped in this operation (for example, 0.5 means 50%)
    #[serde(default)]
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
