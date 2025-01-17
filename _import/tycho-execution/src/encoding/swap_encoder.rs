use anyhow::Error;

use crate::encoding::models::{EncodingContext, Swap};

#[allow(dead_code)]
pub trait SwapEncoder: Sync + Send {
    fn new(executor_address: String) -> Self
    where
        Self: Sized;
    fn encode_swap(&self, swap: Swap, encoding_context: EncodingContext) -> Result<Vec<u8>, Error>;
    fn executor_address(&self) -> &str;
}
