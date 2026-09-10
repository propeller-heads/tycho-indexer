use std::collections::HashMap;

use tycho_common::{models::Chain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    models::{EncodingContext, Swap},
};

/// How a [`SwapEncoder`] obtains the data it encodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuoteBehavior {
    /// No network round trip.
    None,
    /// Blocks on a quote request; quotes are independent of each other.
    Blocking,
    /// Blocks on a quote request; quotes must be requested in route order — the protocol
    /// rejects a quote executed after a quote that was issued later (e.g. a nonce that must be
    /// strictly increasing per trader).
    BlockingOrdered,
}

impl QuoteBehavior {
    /// Whether `encode_swap` blocks on a quote request.
    pub fn blocks_on_quote(&self) -> bool {
        match self {
            QuoteBehavior::None => false,
            QuoteBehavior::Blocking | QuoteBehavior::BlockingOrdered => true,
        }
    }
}

/// A trait for protocol-specific swap encoding, where each implementation should handle the
/// encoding logic for swaps on a specific protocol.
pub trait SwapEncoder: Sync + Send {
    /// Creates a new swap encoder for a specific protocol.
    ///
    /// # Arguments
    /// * `executor_address` - The address of the contract that will execute the swap
    /// * `chain` - The chain on which the swap will be executed
    /// * `config` - Additional configuration parameters for the encoder, like vault or registry
    ///   address
    fn new(
        executor_address: Bytes,
        chain: Chain,
        config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError>
    where
        Self: Sized;

    /// Encodes a swap for execution on the protocol.
    ///
    /// # Arguments
    /// * `swap` - The swap details including the protocol component, token in, token out, and split
    /// * `encoding_context` - Additional context needed for encoding (receiver of the tokens,
    ///   router address, etc.)
    ///
    /// # Returns
    /// The encoded swap data as bytes, directly executable on the executor contract
    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError>;

    /// Returns the address of the protocol-specific executor contract.
    fn executor_address(&self) -> &Bytes;

    /// How `encode_swap` obtains its swap data.
    ///
    /// The returned variant tells whether `encode_swap` blocks on a network round trip and
    /// whether its quote requests must run in route order.
    fn quote_behavior(&self) -> QuoteBehavior {
        QuoteBehavior::None
    }

    /// Creates a cloned instance of the swap encoder.
    ///
    /// This allows the encoder to be cloned when it is being used as a `Box<dyn SwapEncoder>`.
    fn clone_box(&self) -> Box<dyn SwapEncoder>;
}

impl Clone for Box<dyn SwapEncoder> {
    fn clone(&self) -> Box<dyn SwapEncoder> {
        self.clone_box()
    }
}
