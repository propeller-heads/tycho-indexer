use thiserror::Error;
use uuid::Uuid;

use crate::models::ExtractorIdentity;

#[derive(Error, Debug)]
pub enum WebsocketError {
    #[error("Extractor not found: {0}")]
    ExtractorNotFound(ExtractorIdentity),

    #[error("Subscription not found: {0}")]
    SubscriptionNotFound(Uuid),

    #[error("Failed to parse JSON: {1}, msg: {0}")]
    ParseError(String, #[source] serde_json::Error),

    #[error("Failed to subscribe to extractor: {0}")]
    SubscribeError(ExtractorIdentity),

    #[error("Failed to compress message for subscription: {0}, error: {1}")]
    CompressionError(Uuid, #[source] std::io::Error),
}
