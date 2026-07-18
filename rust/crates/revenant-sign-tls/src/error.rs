//! Error type for the legacy TLS client.

use std::io;

/// A failure while establishing or using a legacy (TLS 1.0 / RC4-MD5) connection.
///
/// [`is_retryable`](Self::is_retryable) distinguishes transient failures
/// (timeouts, connection resets) that the caller's retry loop may safely
/// re-attempt from permanent faults (cipher mismatch, malformed handshake)
/// where retrying is pointless.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The TCP connection could not be established or was lost. Retryable.
    #[error("connection to {host}:{port} failed: {source}")]
    Connect {
        host: String,
        port: u16,
        #[source]
        source: io::Error,
    },

    /// A wall-clock or socket timeout elapsed. Retryable.
    #[error("timed out after {timeout_secs}s talking to {host}:{port}")]
    Timeout {
        host: String,
        port: u16,
        timeout_secs: u64,
    },

    /// The TLS handshake failed (unexpected message, bad record, alert). Not retryable.
    #[error("TLS handshake with {host}:{port} failed: {reason}")]
    Handshake {
        host: String,
        port: u16,
        reason: String,
    },

    /// A record-layer or protocol violation after the handshake. Not retryable.
    #[error("TLS protocol error: {0}")]
    Protocol(String),

    /// The peer's certificate could not be parsed to extract its RSA public key.
    #[error("cannot parse server certificate: {0}")]
    Certificate(String),

    /// The response exceeded the configured size limit.
    #[error("response from {host}:{port} exceeds {limit} byte limit")]
    ResponseTooLarge {
        host: String,
        port: u16,
        limit: usize,
    },

    /// The URL could not be parsed into host/port/path.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
}

impl TlsError {
    /// Whether the caller may safely retry the operation that produced this error.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, TlsError::Connect { .. } | TlsError::Timeout { .. })
    }
}
