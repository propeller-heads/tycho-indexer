use crate::params::{ParamValue, RequestParamError};
use std::borrow::Cow;

/// The various kinds of errors that can occur during simulation.
/// Reverts, for example.
#[derive(Debug)]
pub enum Error {
    /// Normal EVM revert.
    /// The simulation ignores these because reverts can not cause any problematic effects.
    Revert {
        reason: Cow<'static, str>,
    },
    /// Intentionally exit execution of the model early because it is currently
    /// or generally not worth continuing for the given parameter combination.
    Ignore {
        reason: Cow<'static, str>,
    },
    /// Communicate a problem, like a potential bug in the model.
    Warning {
        reason: Cow<'static, str>,
    },
    RequestParamError(RequestParamError),
    /// Requested [key](Error::TLoadShouldHavePreviousTStore::key) not found in transient storage
    TLoadShouldHavePreviousTStore {
        key: Cow<'static, str>,
    },
    /// Requested [key](Error::TLoadShouldBeConvertibleInto::key) found in transient storage
    /// but [value](Error::TLoadShouldBeConvertibleInto::value) can't be converted into desired type.
    TLoadShouldBeConvertibleInto {
        key: Cow<'static, str>,
        value: ParamValue,
    },
}

impl Error {
    pub fn revert<T: Into<Cow<'static, str>>>(reason: T) -> Self {
        Self::Revert {
            reason: reason.into(),
        }
    }

    pub fn warning<T: Into<Cow<'static, str>>>(reason: T) -> Self {
        Self::Warning {
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestParamError(x) => std::fmt::Display::fmt(x, f),
            Self::Revert { reason } => write!(f, "revert: {reason}"),
            Self::Ignore { reason } => write!(f, "ignore: {reason}"),
            Self::Warning { reason } => write!(f, "warning: {reason}"),
            Self::TLoadShouldHavePreviousTStore { key } => {
                write!(f, "`TLOAD` without previous `TSTORE` for key `{key}`")
            }
            Self::TLoadShouldBeConvertibleInto { key, value } => write!(
                f,
                "the transient storage slot with key `{key}` whose value is `{value:?}` is not convertable into the desired type"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<RequestParamError> for Error {
    fn from(inner: RequestParamError) -> Error {
        Error::RequestParamError(inner)
    }
}
