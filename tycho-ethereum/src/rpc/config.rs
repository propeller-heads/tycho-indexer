/// Configuration for RPC provider retry behavior
#[derive(Clone, Debug)]
pub struct RPCRetryConfig {
    /// Maximum number of retry attempts for failed requests (default: 3)
    pub max_retries: usize,
    /// Initial backoff delay in milliseconds (default: 100ms)
    pub initial_backoff_ms: u64,
    /// Maximum backoff delay in milliseconds (default: 5000ms)
    pub max_backoff_ms: u64,
}

impl RPCRetryConfig {
    pub fn new(max_retries: usize, initial_backoff_ms: u64, max_backoff_ms: u64) -> Self {
        Self { max_retries, initial_backoff_ms, max_backoff_ms }
    }
}

impl Default for RPCRetryConfig {
    fn default() -> Self {
        Self { max_retries: 3, initial_backoff_ms: 100, max_backoff_ms: 5000 }
    }
}

// perf: consider how to optimize these configurable for preventing rate limiting.
#[derive(Clone, Debug)]
pub struct RPCBatchingConfig {
    /// Whether batching is supported by the RPC provider. Most providers support batching.
    pub supported: bool,
    /// Maximum number of general (e.g., code) requests per batch.
    pub max_batch_size: usize,
    pub max_storage_slot_batch_size: usize,
}

impl Default for RPCBatchingConfig {
    fn default() -> Self {
        let max_storage_slot_batch_size =
            std::env::var("TYCHO_BATCH_ACCOUNT_EXTRACTOR_STORAGE_MAX_BATCH_SIZE")
                .unwrap_or_else(|_| "1000".to_string())
                .parse::<usize>()
                .unwrap_or(1000);

        Self { supported: true, max_batch_size: 50, max_storage_slot_batch_size }
    }
}
