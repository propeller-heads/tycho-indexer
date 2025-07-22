use clap::ValueEnum;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use tycho_common::{
    models::protocol::ProtocolComponent, simulation::protocol_sim::ProtocolSim, Bytes,
};

use crate::encoding::serde_primitives::biguint_string;

/// Specifies the method for transferring user funds into Tycho execution.
///
/// Options:
///
/// - `TransferFromPermit2`: Use Permit2 for token transfer.
///     - You must manually approve the Permit2 contract and sign the permit object externally
///       (outside `tycho-execution`).
///
/// - `TransferFrom`: Use standard ERC-20 approval and `transferFrom`.
///     - You must approve the Tycho Router contract to spend your tokens via standard `approve()`
///       calls.
///
/// - `None`: No transfer will be performed.
///     - Assumes the tokens are already present in the Tycho Router.
///     - **Warning**: This is an advanced mode. Ensure your logic guarantees that the tokens are
///       already in the router at the time of execution.
///     - The Tycho router is **not** designed to safely hold tokens. If tokens are not transferred
///       and used in the **same transaction**, they will be permanently lost.
#[derive(Clone, Debug, PartialEq, ValueEnum)]
pub enum UserTransferType {
    TransferFromPermit2,
    TransferFrom,
    None,
}

/// Represents a solution containing details describing an order, and  instructions for filling
/// the order.
#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct Solution<'a> {
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
    pub swaps: Vec<Swap<'a>>,
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
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Swap<'a> {
    /// Protocol component from tycho indexer
    pub component: ProtocolComponent,
    /// Token being input into the pool.
    pub token_in: Bytes,
    /// Token being output from the pool.
    pub token_out: Bytes,
    /// Decimal of the amount to be swapped in this operation (for example, 0.5 means 50%)
    #[serde(default)]
    pub split: f64,
    /// Optional user data to be passed to encoding.
    pub user_data: Option<Bytes>,
    /// Optional protocol state used to perform the swap.
    #[serde(skip)]
    pub protocol_state: Option<&'a Box<dyn ProtocolSim>>,
}

impl<'a> Swap<'a> {
    pub fn new<T: Into<ProtocolComponent>>(
        component: T,
        token_in: Bytes,
        token_out: Bytes,
        split: f64,
        user_data: Option<Bytes>,
        protocol_state: Option<&'a Box<dyn ProtocolSim>>,
    ) -> Self {
        Self { component: component.into(), token_in, token_out, split, user_data, protocol_state }
    }
}

impl<'a> PartialEq for Swap<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.component == other.component &&
            self.token_in == other.token_in &&
            self.token_out == other.token_out &&
            self.split == other.split &&
            self.user_data == other.user_data
        // Skip protocol_state comparison since trait objects don't implement PartialEq
    }
}

/// Represents a transaction to be executed.
///
/// # Fields
/// * `to`: Address of the contract to call with the calldata
/// * `value`: Native token value to be sent with the transaction.
/// * `data`: Encoded calldata for the transaction.
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
/// * `function_signature`: The signature of the function to be called.
/// * `n_tokens`: Number of tokens in the swap.
/// * `permit`: Optional permit for the swap (if permit2 is enabled).
#[derive(Clone, Debug)]
pub struct EncodedSolution {
    pub swaps: Vec<u8>,
    pub interacting_with: Bytes,
    pub function_signature: String,
    pub n_tokens: usize,
    pub permit: Option<PermitSingle>,
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
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TransferType {
    TransferFrom = 0,
    Transfer = 1,
    None = 2,
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
        let user_data = Some(Bytes::from("0x1234"));
        let swap = Swap::new(
            component,
            Bytes::from("0x12"),
            Bytes::from("34"),
            0.5,
            user_data.clone(),
            None,
        );
        assert_eq!(swap.token_in, Bytes::from("0x12"));
        assert_eq!(swap.token_out, Bytes::from("0x34"));
        assert_eq!(swap.component.protocol_system, "uniswap_v2");
        assert_eq!(swap.component.id, "i-am-an-id");
        assert_eq!(swap.split, 0.5);
        assert_eq!(swap.user_data, user_data);
    }
}
