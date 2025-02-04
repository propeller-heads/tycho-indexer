use crate::encoding::{
    errors::EncodingError,
    models::{EncodingContext, Swap},
};
pub trait SwapEncoder: Sync + Send {
    fn new(executor_address: String) -> Self
    where
        Self: Sized;
    fn encode_swap(
        &self,
        swap: Swap,
        encoding_context: EncodingContext,
    ) -> Result<Vec<u8>, EncodingError>;
    fn executor_address(&self) -> &str;
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
