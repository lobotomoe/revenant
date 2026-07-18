//! The Revenant error hierarchy.
//!
//! A single enum covers every failure kind -- auth, server, TLS, PDF, config,
//! certificate, and a general fallback. Keeping them as variants of one enum --
//! rather than a trait-object hierarchy -- lets callers `match` on the failure
//! kind, which is how the retry and batch-abort logic decides what to do.

use revenant_sign_tls::TlsError;

/// Any failure surfaced by the Revenant library.
#[derive(Debug, thiserror::Error)]
pub enum RevenantError {
    /// Authentication failed (bad username/password, account lockout).
    #[error("{0}")]
    Auth(String),

    /// The signing server returned an error result.
    #[error("{0}")]
    Server(String),

    /// A TLS or connection-level failure.
    ///
    /// `retryable` marks transient faults (timeouts, resets) that the retry
    /// loop may re-attempt, versus permanent ones (cipher mismatch) where it
    /// must not.
    #[error("{message}")]
    Tls { message: String, retryable: bool },

    /// A PDF structure, parsing, or building error.
    #[error("{0}")]
    Pdf(String),

    /// A configuration validation error.
    #[error("{0}")]
    Config(String),

    /// A certificate parsing or extraction error.
    #[error("{0}")]
    Certificate(String),

    /// A general failure with no more specific kind (the base `RevenantError`).
    #[error("{0}")]
    Other(String),
}

impl RevenantError {
    /// Construct a non-retryable TLS error.
    #[must_use]
    pub fn tls(message: impl Into<String>) -> Self {
        RevenantError::Tls {
            message: message.into(),
            retryable: false,
        }
    }

    /// Construct a retryable TLS error (timeout, connection failure).
    #[must_use]
    pub fn tls_retryable(message: impl Into<String>) -> Self {
        RevenantError::Tls {
            message: message.into(),
            retryable: true,
        }
    }

    /// Whether the operation that produced this error may be safely retried.
    ///
    /// Only transient TLS errors are retryable: auth failures, server
    /// rejections, and PDF errors are never retried because re-attempting cannot
    /// change the outcome.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            RevenantError::Tls {
                retryable: true,
                ..
            }
        )
    }

    /// Whether this is a TLS/connection-level failure.
    ///
    /// The transport auto-detection falls back from standard HTTPS to legacy
    /// TLS on exactly these errors: an HTTP status error or config error means
    /// the server was reached, so retrying over a different cipher cannot help.
    #[must_use]
    pub fn is_tls(&self) -> bool {
        matches!(self, RevenantError::Tls { .. })
    }
}

/// Convert a low-level legacy-TLS error into the library error type, preserving
/// the retryable classification.
impl From<TlsError> for RevenantError {
    fn from(err: TlsError) -> Self {
        RevenantError::Tls {
            retryable: err.is_retryable(),
            message: err.to_string(),
        }
    }
}

/// The standard result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, RevenantError>;
