use crate::encoding::{
    errors::EncodingError,
    models::{EncodingContext, Swap},
};
#[allow(dead_code)]
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
}
