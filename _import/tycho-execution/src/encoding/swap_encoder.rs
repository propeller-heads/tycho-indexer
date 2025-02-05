use crate::encoding::{
    errors::EncodingError,
    models::{EncodingContext, Swap},
};

/// This trait must be implemented in order to encode a single swap for a specific protocol.
pub trait SwapEncoder: Sync + Send {
    fn new(executor_address: String) -> Self
    where
        Self: Sized;

    /// Encodes a swap and its relevant context information into call data for a specific protocol.
    fn encode_swap(
        &self,
        swap: Swap,
        encoding_context: EncodingContext,
    ) -> Result<Vec<u8>, EncodingError>;

    /// The address of the executor that will be used to swap through a specific protocol.
    fn executor_address(&self) -> &str;

    /// The selector of the executor function that will be called in order to perform a swap.
    fn executor_selector(&self) -> &str;

    /// Clones the swap encoder as a trait object.
    /// This allows the encoder to be cloned when it is being used as a `Box<dyn SwapEncoder>`.
    fn clone_box(&self) -> Box<dyn SwapEncoder>;
}

impl Clone for Box<dyn SwapEncoder> {
    fn clone(&self) -> Box<dyn SwapEncoder> {
        self.clone_box()
    }
}
