//! Pausing reasons for DCI and HooksDCI components.
//!
//! This module defines the `PausingReason` enum which represents why a component
//! has been paused during indexing.

/// Represents the reason why a component has been paused.
///
/// The pausing attribute is stored as a single byte in the component's state:
/// - `0x01` (Substreams): Paused by the SDK/substreams (external pause request)
/// - `0x02` (TracingError): Paused due to DCI tracing failures
/// - `0x03` (MetadataError): Paused due to HooksDCI metadata generation failures
///
/// When a component is paused with `Substreams` reason (0x01), the indexer should
/// skip all processing (tracing, metadata generation, etc.) for that component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Returns `Some(PausingReason)` if the bytes represent a valid pausing reason,
    /// `None` otherwise.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        // The pausing reason is stored as a single byte
        Self::try_from(bytes[0]).ok()
    }

    /// Checks if the given bytes represent an SDK pause (reason 0x01).
    ///
    /// This is a convenience method for quickly checking if a component should be skipped.
    #[inline]
    pub fn is_sdk_paused_bytes(bytes: &[u8]) -> bool {
        Self::from_bytes(bytes).is_some_and(|r| r.is_sdk_paused())
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
pub enum PausingReasonError {
    #[error("Invalid pausing reason: {0}")]
    InvalidReason(u8),
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
    #[case::substreams(&[1], Some(PausingReason::Substreams))]
    #[case::tracing_error(&[2], Some(PausingReason::TracingError))]
    #[case::metadata_error(&[3], Some(PausingReason::MetadataError))]
    #[case::empty(&[], None)]
    #[case::invalid_zero(&[0], None)]
    #[case::invalid_four(&[4], None)]
    #[case::multi_byte_uses_first(&[1, 2, 3], Some(PausingReason::Substreams))]
    fn test_pausing_reason_from_bytes(
        #[case] input: &[u8],
        #[case] expected: Option<PausingReason>,
    ) {
        assert_eq!(PausingReason::from_bytes(input), expected);
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
        let decoded = PausingReason::from_bytes(bytes.as_ref());
        assert_eq!(decoded, Some(reason));
    }
}
