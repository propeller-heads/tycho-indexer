use num_bigint::BigUint;
use tycho_core::{dto::ProtocolComponent, Bytes};

#[derive(Clone)]
#[allow(dead_code)]
pub struct Solution {
    /// True if the solution is an exact output solution.
    pub exact_out: bool,
    /// The token being sold (exact in) or bought (exact out).
    pub given_token: Bytes,
    /// Amount of the given token.
    pub given_amount: BigUint,
    /// The token being bought (exact in) or sold (exact out).
    pub checked_token: Bytes,
    /// Expected amount of the bought token (exact in) or sold token (exact out).
    pub expected_amount: BigUint,
    /// Minimum amount to be checked for the solution to be valid.
    /// If not set, the check will not be performed.
    pub check_amount: Option<BigUint>,
    /// Address of the sender.
    pub sender: Bytes,
    /// Address of the receiver.
    pub receiver: Bytes,
    /// List of swaps to fulfill the solution.
    pub swaps: Vec<Swap>,
    /// If set to true, the solution will be encoded to be sent directly to the SwapExecutor and
    /// skip the router. The user is responsible for managing necessary approvals and token
    /// transfers.
    pub straight_to_pool: bool,
    // if not set, then the Propeller Router will be used
    pub router_address: Option<Bytes>,
    // if set, it will be applied to check_amount
    pub slippage: Option<f64>,
    // if set, the corresponding native action will be executed
    pub native_action: Option<NativeAction>,
}

#[derive(Clone, PartialEq)]
#[allow(dead_code)]
pub enum NativeAction {
    Wrap,
    Unwrap,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct Swap {
    /// Protocol component from tycho indexer
    pub component: ProtocolComponent,
    /// Token being input into the pool.
    pub token_in: Bytes,
    /// Token being output from the pool.
    pub token_out: Bytes,
    /// Fraction of the amount to be swapped in this operation.
    pub split: f64,
}

#[allow(dead_code)]
pub struct Transaction {
    pub data: Vec<u8>,
    // ETH value to be sent with the transaction.
    pub value: BigUint,
    // Address of the contract to call with the calldata
    pub to: Bytes,
}

#[allow(dead_code)]
pub struct EncodingContext {
    pub receiver: Bytes,
    pub exact_out: bool,
    pub router_address: Bytes,
}
