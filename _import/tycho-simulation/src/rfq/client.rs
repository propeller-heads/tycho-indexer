use async_trait::async_trait;
use futures::stream::BoxStream;
use tycho_client::feed::synchronizer::StateSyncMessage;

use crate::rfq::{
    errors::RFQError,
    indicatively_priced::SignedQuote,
    models::{GetAmountOutParams, TimestampHeader},
};

#[async_trait]
pub trait RFQClient: Send + Sync {
    /// Returns a stream of updates tagged with the provider name.
    fn stream(&self) -> BoxStream<'static, (String, StateSyncMessage<TimestampHeader>)>;

    // This method is responsible for fetching the binding quote from the RFQ API. Use sender and
    // receiver from GetAmountOutParams to ask for the quote
    async fn request_binding_quote(
        &self,
        params: &GetAmountOutParams,
    ) -> Result<SignedQuote, RFQError>;

    fn clone_box(&self) -> Box<dyn RFQClient>;
}
