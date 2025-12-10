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

/// Configuration for RPC request batching behavior.
#[derive(Clone, Debug, Default)]
pub enum RPCBatchingConfig {
    /// Batching is not supported by the provider.
    #[default]
    Disabled,
    /// Batching is supported with configurable batch size and per-method overrides.
    Enabled {
        /// Maximum number of requests per batch, unless overridden by specific method limits.
        max_batch_size: usize,
        /// Optional override for the maximum number of `eth_getStorageAt` requests per batch.
        /// If `None`, the default value of `max_batch_size` should be used.
        storage_slot_max_batch_size_override: Option<usize>,
        // perf: consider adding other per-method batch size limits if needed and improving
        // override logic
    },
}

impl RPCBatchingConfig {
    /// Creates an enabled batching config with storage slot batch size of 1000 and the batch size
    /// of 50 for other methods that use batching.
    pub fn enabled_with_defaults() -> Self {
        Self::Enabled { max_batch_size: 50, storage_slot_max_batch_size_override: Some(1000) }
    }

    /// Returns the max batch size if batching is enabled, `None` otherwise.
    pub fn max_batch_size(&self) -> Option<usize> {
        match self {
            Self::Enabled { max_batch_size, .. } => Some(*max_batch_size),
            Self::Disabled => None,
        }
    }

    /// Returns the effective max batch size for `eth_getStorageAt` requests.
    /// Uses `storage_slot_max_batch_size_override` if set, otherwise falls back to
    /// `max_batch_size`. Returns `None` if batching is disabled.
    pub fn storage_slot_max_batch_size(&self) -> Option<usize> {
        match self {
            Self::Enabled { max_batch_size, storage_slot_max_batch_size_override } => {
                Some(storage_slot_max_batch_size_override.unwrap_or(*max_batch_size))
            }
            Self::Disabled => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[test]
    fn test_max_batch_size_enabled() {
        let enabled = RPCBatchingConfig::Enabled {
            max_batch_size: 50,
            storage_slot_max_batch_size_override: None,
        };
        assert_eq!(enabled.max_batch_size(), Some(50));
    }

    #[test]
    fn test_max_batch_size_disabled() {
        assert_eq!(RPCBatchingConfig::Disabled.max_batch_size(), None);
    }

    #[test]
    fn test_storage_slot_max_batch_size_returns_none_when_disabled() {
        assert_eq!(RPCBatchingConfig::Disabled.storage_slot_max_batch_size(), None);
    }

    #[test]
    fn test_storage_slot_max_batch_size_falls_back_to_max_batch_size_when_no_override() {
        let config = RPCBatchingConfig::Enabled {
            max_batch_size: 50,
            storage_slot_max_batch_size_override: None,
        };
        assert_eq!(config.storage_slot_max_batch_size(), Some(50));
    }

    #[rstest]
    #[case::override_higher_than_max(50, 1000)]
    #[case::override_lower_than_max(1000, 50)]
    fn test_storage_slot_max_batch_size_uses_override(
        #[case] max_batch_size: usize,
        #[case] override_size: usize,
    ) {
        let config = RPCBatchingConfig::Enabled {
            max_batch_size,
            storage_slot_max_batch_size_override: Some(override_size),
        };
        assert_eq!(config.storage_slot_max_batch_size(), Some(override_size));
    }
}
