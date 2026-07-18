//! The transport abstraction the signing core depends on.
//!
//! The high-level signing logic talks to a remote signature service through this
//! trait alone, so it stays transport-agnostic. The only implementation today is
//! [`SoapSigningTransport`](super::soap_transport::SoapSigningTransport), but a
//! REST or gRPC backend could slot in without touching the signing core.

use std::time::Duration;

use crate::Result;

/// A remote digital-signature service.
///
/// Implementations sign data on a remote appliance and return a DER-encoded
/// CMS/PKCS#7 signature. All three methods authenticate with a username and
/// password and are bounded by `timeout`.
pub trait SigningTransport {
    /// The service endpoint URL, when the implementation has one.
    ///
    /// Used by the signing layer for certificate enumeration; defaults to
    /// `None` for transports that are not URL-addressable.
    fn url(&self) -> Option<&str> {
        None
    }

    /// Sign arbitrary data. The server hashes `data` internally and returns a
    /// CMS/PKCS#7 signature with the proper digest and `messageDigest`
    /// attributes.
    ///
    /// # Errors
    ///
    /// Returns [`RevenantError::Auth`](crate::RevenantError::Auth) on bad
    /// credentials, or another [`RevenantError`](crate::RevenantError) on
    /// server or transport failure.
    fn sign_data(
        &self,
        data: &[u8],
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>>;

    /// Sign a pre-computed hash. The server signs exactly the bytes provided
    /// (it does not re-hash), returning a detached CMS/PKCS#7 signature.
    ///
    /// # Errors
    ///
    /// See [`sign_data`](Self::sign_data).
    fn sign_hash(
        &self,
        hash: &[u8],
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>>;

    /// Sign a complete PDF document. The server hashes the whole PDF internally
    /// and returns a detached CMS/PKCS#7 signature.
    ///
    /// # Errors
    ///
    /// See [`sign_data`](Self::sign_data).
    fn sign_pdf_detached(
        &self,
        pdf: &[u8],
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>>;

    /// Enumerate the signer's certificates, returning DER-encoded X.509 bytes.
    ///
    /// This is an optional capability used for identity discovery: a transport
    /// that can list the user's certificates lets the signer be identified
    /// without a dummy signing round-trip. The default returns an empty list,
    /// meaning "not supported" -- callers then fall back to signing. An
    /// implementation that genuinely fails (auth, server, transport) returns an
    /// error, which the caller distinguishes from the empty "unsupported" case.
    ///
    /// # Errors
    ///
    /// Returns [`RevenantError::Auth`](crate::RevenantError::Auth) on bad
    /// credentials, or another [`RevenantError`](crate::RevenantError) on
    /// server or transport failure.
    fn enum_certificates(
        &self,
        _username: &str,
        _password: &str,
        _timeout: Duration,
    ) -> Result<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }
}
