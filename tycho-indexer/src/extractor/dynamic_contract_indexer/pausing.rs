//! Pausing reasons for DCI and HooksDCI components.
//!
//! This module defines the `PausingReason` enum which represents why a component
//! has been paused during indexing.

use std::collections::{HashMap, HashSet};

use deepsize::DeepSizeOf;
use serde::Deserialize;
use tycho_common::models::{blockchain::TxWithChanges, ComponentId};

/// Represents the reason why a component has been paused.
///
/// The pausing attribute is stored as a single byte in the component's state:
/// - `0x01` (Substreams): Paused by the SDK/substreams (external pause request)
/// - `0x02` (TracingError): Paused due to DCI tracing failures
/// - `0x03` (MetadataError): Paused due to HooksDCI metadata generation failures
///
/// When a component is paused with `Substreams` reason (0x01), the indexer should
/// skip all processing (tracing, metadata generation, etc.) for that component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, DeepSizeOf)]
pub(crate) enum PausingReason {
    /// Paused by SDK/substreams - indicates external pause request.
    /// Components paused with this reason should be fully skipped by DCI and HooksDCI.
    Substreams = 1,
    /// Paused due to DCI tracing errors.
    TracingError = 2,
    /// Paused due to HooksDCI metadata generation errors.
    MetadataError = 3,
}

impl PausingReason {
    /// The attribute name used to store the pausing reason in component state.
    pub const ATTRIBUTE_NAME: &'static str = "paused";

    /// Returns `true` if this is an SDK/substreams pause reason.
    ///
    /// Components paused with this reason should be fully skipped by the indexer.
    #[inline]
    pub fn is_sdk_paused(&self) -> bool {
        matches!(self, PausingReason::Substreams)
    }

    /// Attempts to parse a pausing reason from a byte slice (typically from state attributes).
    ///
    /// Returns `Ok(PausingReason)` if the bytes represent a valid pausing reason,
    /// or an error with details suitable for logging.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, PausingReasonError> {
        if bytes.is_empty() {
            return Err(PausingReasonError::EmptyBytes);
        }
        // The pausing reason is stored as a single byte
        Self::try_from(bytes[0])
    }

    /// Checks if the given bytes represent an SDK pause (reason 0x01).
    ///
    /// This is a convenience method for quickly checking if a component should be skipped.
    #[inline]
    pub fn is_sdk_paused_bytes(bytes: &[u8]) -> bool {
        Self::try_from_bytes(bytes)
            .ok()
            .is_some_and(|r| r.is_sdk_paused())
    }
}

impl TryFrom<u8> for PausingReason {
    type Error = PausingReasonError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PausingReason::Substreams),
            2 => Ok(PausingReason::TracingError),
            3 => Ok(PausingReason::MetadataError),
            _ => Err(PausingReasonError::InvalidReason(value)),
        }
    }
}

impl From<PausingReason> for u8 {
    fn from(reason: PausingReason) -> Self {
        reason as u8
    }
}

impl From<PausingReason> for tycho_common::Bytes {
    fn from(reason: PausingReason) -> Self {
        vec![reason as u8].into()
    }
}

/// Error type for invalid pausing reasons.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PausingReasonError {
    #[error("Invalid pausing reason: {0}")]
    InvalidReason(u8),
    #[error("Empty bytes for pausing reason")]
    EmptyBytes,
}

/// Strategy for determining when to pause/unpause components based on tracing results.
///
/// This enum defines the behavior for pause/unpause decisions after tracing entrypoints.
/// Different protocols may need different strategies depending on whether they have
/// redundant entrypoints or require each entrypoint to succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TracingPauseStrategy {
    /// Pause only when ALL entrypoints for a component fail.
    /// Unpause when all entrypoints succeed.
    ///
    /// Best for protocols with redundant entrypoints (e.g., UniswapV4 hooks) where
    /// a component should only be paused if none of its entrypoints can be traced.
    #[default]
    AllFail,

    /// Pause when ANY single entrypoint for a component fails.
    /// Unpause when all entrypoints succeed.
    ///
    /// Best for protocols where each entrypoint is critical and any failure
    /// indicates a problem that should pause the component.
    AnyFail,
}

/// Decision from evaluating a pause strategy based on tracing results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseDecision {
    /// Component should be paused
    Pause,
    /// Component should be unpaused
    Unpause,
    /// No action should be taken (mixed results or incomplete data)
    NoAction,
}

impl TracingPauseStrategy {
    /// Evaluates whether a component should be paused based on tracing results.
    ///
    /// # Arguments
    /// * `traced_count` - Total number of entrypoints traced for this component
    /// * `success_count` - Number of successful traces
    /// * `failure_count` - Number of failed traces
    ///
    /// # Returns
    /// * `PauseDecision::Pause` - Component should be paused
    /// * `PauseDecision::Unpause` - Component should be unpaused
    /// * `PauseDecision::NoAction` - No action (mixed results for AllFail, or no traces)
    pub fn evaluate(
        &self,
        traced_count: usize,
        success_count: usize,
        failure_count: usize,
    ) -> PauseDecision {
        if traced_count == 0 {
            return PauseDecision::NoAction;
        }

        let all_succeeded = success_count == traced_count;

        match self {
            TracingPauseStrategy::AllFail => {
                let all_failed = failure_count == traced_count;
                if all_failed {
                    PauseDecision::Pause
                } else if all_succeeded {
                    PauseDecision::Unpause
                } else {
                    PauseDecision::NoAction
                }
            }
            TracingPauseStrategy::AnyFail => {
                if failure_count > 0 {
                    PauseDecision::Pause
                } else if all_succeeded {
                    PauseDecision::Unpause
                } else {
                    PauseDecision::NoAction
                }
            }
        }
    }
}

/// Extracts SDK pause/unpause updates from transaction changes.
///
/// Scans state updates for "paused" attribute changes:
/// - Components with "paused" attribute set to `[1]` (SDK pause) → paused
/// - Components with "paused" attribute set to `[0]` or empty → unpaused
/// - Components with "paused" in `deleted_attributes` → unpaused
///
/// Uses a HashMap to track the last pause state for each component, ensuring
/// correct ordering when a component changes state multiple times in a block.
///
/// # Assumptions
/// Assumes `txs_with_update` is sorted by transaction execution order within the block.
/// The last update for a given component in the slice determines its final pause state.
///
/// # Returns
/// A tuple of (paused_components, unpaused_components) as HashSets of ComponentId.
pub(crate) fn extract_sdk_pause_updates(
    txs_with_update: &[TxWithChanges],
) -> (HashSet<ComponentId>, HashSet<ComponentId>) {
    let mut pause_states: HashMap<ComponentId, bool> = HashMap::new();

    for tx in txs_with_update {
        for (component_id, state_delta) in tx.state_updates.iter() {
            // Check for SDK pause/unpause via "paused" attribute value
            if let Some(paused_value) = state_delta
                .updated_attributes
                .get(PausingReason::ATTRIBUTE_NAME)
            {
                if PausingReason::is_sdk_paused_bytes(paused_value.as_ref()) {
                    // SDK pause: "paused" attribute set to [0x1]
                    pause_states.insert(component_id.clone(), true);
                } else if paused_value.is_zero() || paused_value.is_empty() {
                    // SDK unpause via setting to 0x0 (for backwards compatibility)
                    pause_states.insert(component_id.clone(), false);
                }
            }

            // Check for unpause: "paused" attribute deleted
            if state_delta
                .deleted_attributes
                .contains(PausingReason::ATTRIBUTE_NAME)
            {
                pause_states.insert(component_id.clone(), false);
            }
        }
    }

    pause_states.into_iter().fold(
        (HashSet::new(), HashSet::new()),
        |(mut paused, mut unpaused), (component_id, is_paused)| {
            if is_paused {
                paused.insert(component_id);
            } else {
                unpaused.insert(component_id);
            }
            (paused, unpaused)
        },
    )
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use tycho_common::Bytes;

    use super::*;

    #[rstest]
    #[case::substreams(PausingReason::Substreams, 1)]
    #[case::tracing_error(PausingReason::TracingError, 2)]
    #[case::metadata_error(PausingReason::MetadataError, 3)]
    fn test_pausing_reason_values(#[case] reason: PausingReason, #[case] expected: u8) {
        assert_eq!(u8::from(reason), expected);
    }

    #[rstest]
    #[case::substreams(1, Ok(PausingReason::Substreams))]
    #[case::tracing_error(2, Ok(PausingReason::TracingError))]
    #[case::metadata_error(3, Ok(PausingReason::MetadataError))]
    #[case::invalid_zero(0, Err(PausingReasonError::InvalidReason(0)))]
    #[case::invalid_four(4, Err(PausingReasonError::InvalidReason(4)))]
    #[case::invalid_max(255, Err(PausingReasonError::InvalidReason(255)))]
    fn test_pausing_reason_try_from_u8(
        #[case] input: u8,
        #[case] expected: Result<PausingReason, PausingReasonError>,
    ) {
        assert_eq!(PausingReason::try_from(input), expected);
    }

    #[rstest]
    #[case::substreams(&[1], Ok(PausingReason::Substreams))]
    #[case::tracing_error(&[2], Ok(PausingReason::TracingError))]
    #[case::metadata_error(&[3], Ok(PausingReason::MetadataError))]
    #[case::empty(&[], Err(PausingReasonError::EmptyBytes))]
    #[case::invalid_zero(&[0], Err(PausingReasonError::InvalidReason(0)))]
    #[case::invalid_four(&[4], Err(PausingReasonError::InvalidReason(4)))]
    #[case::multi_byte_uses_first(&[1, 2, 3], Ok(PausingReason::Substreams))]
    fn test_pausing_reason_try_from_bytes(
        #[case] input: &[u8],
        #[case] expected: Result<PausingReason, PausingReasonError>,
    ) {
        assert_eq!(PausingReason::try_from_bytes(input), expected);
    }

    #[rstest]
    #[case::substreams(PausingReason::Substreams, true)]
    #[case::tracing_error(PausingReason::TracingError, false)]
    #[case::metadata_error(PausingReason::MetadataError, false)]
    fn test_is_sdk_paused(#[case] reason: PausingReason, #[case] expected: bool) {
        assert_eq!(reason.is_sdk_paused(), expected);
    }

    #[rstest]
    #[case::sdk_paused(&[1], true)]
    #[case::tracing_error(&[2], false)]
    #[case::metadata_error(&[3], false)]
    #[case::empty(&[], false)]
    #[case::invalid(&[0], false)]
    fn test_is_sdk_paused_bytes(#[case] input: &[u8], #[case] expected: bool) {
        assert_eq!(PausingReason::is_sdk_paused_bytes(input), expected);
    }

    #[rstest]
    #[case::substreams(PausingReason::Substreams, &[1])]
    #[case::tracing_error(PausingReason::TracingError, &[2])]
    #[case::metadata_error(PausingReason::MetadataError, &[3])]
    fn test_pausing_reason_to_bytes(#[case] reason: PausingReason, #[case] expected: &[u8]) {
        let bytes: Bytes = reason.into();
        assert_eq!(bytes.as_ref(), expected);
    }

    #[rstest]
    #[case::substreams(PausingReason::Substreams)]
    #[case::tracing_error(PausingReason::TracingError)]
    #[case::metadata_error(PausingReason::MetadataError)]
    fn test_roundtrip_conversion(#[case] reason: PausingReason) {
        let bytes: Bytes = reason.into();
        let decoded = PausingReason::try_from_bytes(bytes.as_ref());
        assert_eq!(decoded, Ok(reason));
    }

    mod extract_sdk_pause_updates_tests {
        use std::collections::{HashMap, HashSet};

        use tycho_common::models::{
            blockchain::{Transaction, TxWithChanges},
            protocol::ProtocolComponentStateDelta,
        };

        use super::*;

        fn get_transaction(version: u8) -> Transaction {
            Transaction::new(
                Bytes::from(version).lpad(32, 0),
                Bytes::from(version).lpad(32, 0),
                Bytes::from(version).lpad(20, 0),
                Some(Bytes::from(version).lpad(20, 0)),
                version as u64,
            )
        }

        #[test]
        fn test_paused() {
            // Create block changes with a component being paused (reason 0x01 = SDK pause)
            let tx = get_transaction(1);
            let mut state_updates = HashMap::new();
            let mut updated_attributes = HashMap::new();
            updated_attributes.insert("paused".to_string(), Bytes::from(vec![1u8]));

            state_updates.insert(
                "component_1".to_string(),
                ProtocolComponentStateDelta::new("component_1", updated_attributes, HashSet::new()),
            );

            let tx_with_changes = TxWithChanges { tx, state_updates, ..Default::default() };

            let (paused, unpaused) = extract_sdk_pause_updates(&[tx_with_changes]);

            assert_eq!(paused.len(), 1);
            assert!(paused.contains("component_1"));
            assert!(unpaused.is_empty());
        }

        #[test]
        fn test_unpaused() {
            // Create block changes with a component being unpaused (paused attribute deleted)
            let tx = get_transaction(1);
            let mut state_updates = HashMap::new();
            let mut deleted_attributes = HashSet::new();
            deleted_attributes.insert("paused".to_string());

            state_updates.insert(
                "component_1".to_string(),
                ProtocolComponentStateDelta {
                    component_id: "component_1".to_string(),
                    updated_attributes: HashMap::new(),
                    deleted_attributes,
                },
            );

            let tx_with_changes = TxWithChanges { tx, state_updates, ..Default::default() };

            let (paused, unpaused) = extract_sdk_pause_updates(&[tx_with_changes]);

            assert!(paused.is_empty());
            assert_eq!(unpaused.len(), 1);
            assert!(unpaused.contains("component_1"));
        }

        #[test]
        fn test_unpaused_via_zero_value() {
            // Create block changes with a component being unpaused via setting paused to 0x00
            // (compatibility mode for SDK)
            let tx = get_transaction(1);
            let mut state_updates = HashMap::new();
            let mut updated_attributes = HashMap::new();
            updated_attributes.insert("paused".to_string(), Bytes::from(vec![0u8]));

            state_updates.insert(
                "component_1".to_string(),
                ProtocolComponentStateDelta::new("component_1", updated_attributes, HashSet::new()),
            );

            let tx_with_changes = TxWithChanges { tx, state_updates, ..Default::default() };

            let (paused, unpaused) = extract_sdk_pause_updates(&[tx_with_changes]);

            assert!(paused.is_empty());
            assert_eq!(unpaused.len(), 1);
            assert!(unpaused.contains("component_1"));
        }

        #[test]
        fn test_unpaused_via_empty_value() {
            // Create block changes with a component being unpaused via setting paused to empty
            // (compatibility mode for SDK)
            let tx = get_transaction(1);
            let mut state_updates = HashMap::new();
            let mut updated_attributes = HashMap::new();
            updated_attributes.insert("paused".to_string(), Bytes::from(vec![]));

            state_updates.insert(
                "component_1".to_string(),
                ProtocolComponentStateDelta::new("component_1", updated_attributes, HashSet::new()),
            );

            let tx_with_changes = TxWithChanges { tx, state_updates, ..Default::default() };

            let (paused, unpaused) = extract_sdk_pause_updates(&[tx_with_changes]);

            assert!(paused.is_empty());
            assert_eq!(unpaused.len(), 1);
            assert!(unpaused.contains("component_1"));
        }

        #[test]
        fn test_ignores_non_sdk_pause_reasons() {
            // Create block changes with a component paused with reason 0x02 (TracingError)
            // This should NOT be treated as SDK pause
            let tx = get_transaction(1);
            let mut state_updates = HashMap::new();
            let mut updated_attributes = HashMap::new();
            updated_attributes.insert("paused".to_string(), Bytes::from(vec![2u8]));

            state_updates.insert(
                "component_1".to_string(),
                ProtocolComponentStateDelta::new("component_1", updated_attributes, HashSet::new()),
            );

            let tx_with_changes = TxWithChanges { tx, state_updates, ..Default::default() };

            let (paused, unpaused) = extract_sdk_pause_updates(&[tx_with_changes]);

            // Reason 0x02 is not SDK pause, so both should be empty
            assert!(paused.is_empty());
            assert!(unpaused.is_empty());
        }

        #[test]
        fn test_last_write_wins() {
            // Create block changes where a component is paused and then unpaused in the same
            // block
            let tx1 = get_transaction(1);
            let tx2 = get_transaction(2);

            let mut state_updates1 = HashMap::new();
            let mut updated_attributes1 = HashMap::new();
            updated_attributes1.insert("paused".to_string(), Bytes::from(vec![1u8]));
            state_updates1.insert(
                "component_1".to_string(),
                ProtocolComponentStateDelta::new(
                    "component_1",
                    updated_attributes1,
                    HashSet::new(),
                ),
            );

            let mut state_updates2 = HashMap::new();
            let mut deleted_attributes = HashSet::new();
            deleted_attributes.insert("paused".to_string());
            state_updates2.insert(
                "component_1".to_string(),
                ProtocolComponentStateDelta {
                    component_id: "component_1".to_string(),
                    updated_attributes: HashMap::new(),
                    deleted_attributes,
                },
            );

            let tx_with_changes1 =
                TxWithChanges { tx: tx1, state_updates: state_updates1, ..Default::default() };
            let tx_with_changes2 =
                TxWithChanges { tx: tx2, state_updates: state_updates2, ..Default::default() };

            let (paused, unpaused) =
                extract_sdk_pause_updates(&[tx_with_changes1, tx_with_changes2]);

            // Last write wins: component was unpaused in tx2
            assert!(paused.is_empty());
            assert_eq!(unpaused.len(), 1);
            assert!(unpaused.contains("component_1"));
        }
    }

    mod tracing_pause_strategy_tests {
        use super::*;

        #[test]
        fn test_default_is_all_fail() {
            assert_eq!(TracingPauseStrategy::default(), TracingPauseStrategy::AllFail);
        }

        #[rstest]
        #[case::zero_traces(0, 0, 0, PauseDecision::NoAction)]
        #[case::all_succeed_1(1, 1, 0, PauseDecision::Unpause)]
        #[case::all_succeed_3(3, 3, 0, PauseDecision::Unpause)]
        #[case::all_fail_1(1, 0, 1, PauseDecision::Pause)]
        #[case::all_fail_3(3, 0, 3, PauseDecision::Pause)]
        #[case::mixed_1_success_1_fail(2, 1, 1, PauseDecision::NoAction)]
        #[case::mixed_2_success_1_fail(3, 2, 1, PauseDecision::NoAction)]
        #[case::mixed_1_success_2_fail(3, 1, 2, PauseDecision::NoAction)]
        fn test_all_fail_strategy(
            #[case] traced: usize,
            #[case] success: usize,
            #[case] failure: usize,
            #[case] expected: PauseDecision,
        ) {
            let strategy = TracingPauseStrategy::AllFail;
            assert_eq!(strategy.evaluate(traced, success, failure), expected);
        }

        #[rstest]
        #[case::zero_traces(0, 0, 0, PauseDecision::NoAction)]
        #[case::all_succeed_1(1, 1, 0, PauseDecision::Unpause)]
        #[case::all_succeed_3(3, 3, 0, PauseDecision::Unpause)]
        #[case::one_fail_of_1(1, 0, 1, PauseDecision::Pause)]
        #[case::one_fail_of_3(3, 2, 1, PauseDecision::Pause)]
        #[case::two_fail_of_3(3, 1, 2, PauseDecision::Pause)]
        #[case::all_fail_3(3, 0, 3, PauseDecision::Pause)]
        fn test_any_fail_strategy(
            #[case] traced: usize,
            #[case] success: usize,
            #[case] failure: usize,
            #[case] expected: PauseDecision,
        ) {
            let strategy = TracingPauseStrategy::AnyFail;
            assert_eq!(strategy.evaluate(traced, success, failure), expected);
        }

        #[rstest]
        #[case::all_fail_lowercase("all_fail", TracingPauseStrategy::AllFail)]
        #[case::any_fail_lowercase("any_fail", TracingPauseStrategy::AnyFail)]
        fn test_serde_deserialization(#[case] input: &str, #[case] expected: TracingPauseStrategy) {
            let json = format!("\"{}\"", input);
            let parsed: TracingPauseStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, expected);
        }

        #[test]
        fn test_serde_default_in_struct() {
            // Test that default works when embedded in a struct
            #[derive(Deserialize)]
            struct TestConfig {
                #[serde(default)]
                strategy: TracingPauseStrategy,
            }

            let config: TestConfig = serde_json::from_str("{}").unwrap();
            assert_eq!(config.strategy, TracingPauseStrategy::AllFail);
        }
    }
}
