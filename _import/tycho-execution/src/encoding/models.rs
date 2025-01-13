use alloy_primitives::Address;
use num_bigint::BigUint;
use tycho_core::{dto::ProtocolComponent, Bytes};

pub struct Solution {
    pub orders: Vec<Order>,
    // if not set, then the Propeller Router will be used
    pub router_address: Option<Address>,
}

pub struct Order {
    /// True if the order is an exact output order.
    pub exact_out: bool,
    /// The token being sold (exact in) or bought (exact out).
    given_token: Bytes,
    /// Amount of the given token.
    pub given_amount: BigUint,
    /// The token being bought (exact in) or sold (exact out).
    checked_token: Bytes,
    /// Amount of the checked token.
    checked_amount: BigUint,
    /// Address of the sender.
    sender: Bytes,
    /// Address of the receiver.
    pub receiver: Bytes,
    /// List of swaps to fulfill the order.
    pub swaps: Vec<Swap>,
    /// Whether to include router calldata (true) or just swap data (false).
    add_router_calldata: bool,

    pub slippage: f64,
    pub min_checked_amount: Option<BigUint>,
}

#[derive(Clone)]
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

// maybe this struct is useful - keeping it here for now (maybe we could collapse this with another
// struct)
pub struct EncodingContext {
    pub receiver: Address,
    pub exact_out: bool,
    pub router_address: Address,
}

pub enum ActionType {
    SingleExactIn = 1,
    SingleExactOut = 2,
    SequentialExactIn = 3,
    SequentialExactOut = 4,
    SplitIn = 5,
}
