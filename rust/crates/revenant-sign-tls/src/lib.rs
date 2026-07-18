//! A from-scratch TLS 1.0 client speaking only `TLS_RSA_WITH_RC4_128_MD5`
//! (and its SHA-1 sibling `TLS_RSA_WITH_RC4_128_SHA`).
//!
//! Some CoSign appliances -- notably EKENG's `ca.gov.am` -- terminate TLS on an
//! ancient stack that negotiates nothing newer than TLS 1.0 with RC4, a cipher
//! suite removed from OpenSSL 3.x and unsupported by rustls, native-tls, and
//! every other maintained Rust TLS library. The Python client leans on
//! `tlslite-ng` and the TypeScript client on `node-forge` to speak it; this
//! crate is the Rust equivalent, implementing the minimal [RFC 2246] handshake
//! and record layer needed for the round trip.
//!
//! # Scope and non-goals
//!
//! This is **not** a general-purpose TLS library and must never be used as one.
//! It implements only the RC4 cipher suites, does not verify the server
//! certificate (the target appliances present certs no modern chain would
//! accept, and are reached over a government intranet), and supports only the
//! RSA key-exchange path. RC4 is cryptographically broken (RFC 7465); this code
//! exists solely for backward compatibility with legacy appliances that offer
//! nothing else.
//!
//! # Usage
//!
//! ```no_run
//! use std::time::Duration;
//! use revenant_sign_tls::{request, Method};
//!
//! let resp = request(
//!     Method::Post,
//!     "https://ca.gov.am:8080/SAPIWS/DSS.asmx",
//!     Some(b"<soap:Envelope>...</soap:Envelope>"),
//!     &[("Content-Type", "text/xml; charset=utf-8")],
//!     Duration::from_secs(120),
//! )?;
//! assert_eq!(resp.status, 200);
//! # Ok::<(), revenant_sign_tls::TlsError>(())
//! ```
//!
//! [RFC 2246]: https://www.rfc-editor.org/rfc/rfc2246

#![forbid(unsafe_code)]

mod handshake;
mod http;
mod prf;
mod record;

pub mod error;

pub use error::TlsError;

use std::time::Duration;

/// HTTP method for a legacy-TLS request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

/// A parsed HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code (e.g. `200`).
    pub status: u16,
    /// Reason phrase from the status line (e.g. `"OK"`).
    pub reason: String,
    /// Response headers as received, in order.
    pub headers: Vec<(String, String)>,
    /// Raw response body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Look up a header value case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether the status code is in the 2xx success range.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Send a single HTTP/1.0 request over a legacy (TLS 1.0 + RC4) connection.
///
/// The `url` must be `https://`. `extra_headers` are appended after the
/// automatic `Host`, `Connection: close`, and (for a body) `Content-Length`
/// headers. The whole exchange -- connect, handshake, and response read -- is
/// bounded by `timeout`.
///
/// # Errors
///
/// Returns [`TlsError`] on connection failure, handshake failure, protocol
/// violation, or when the response exceeds the size or time limit.
pub fn request(
    method: Method,
    url: &str,
    body: Option<&[u8]>,
    extra_headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<HttpResponse, TlsError> {
    http::request(method, url, body, extra_headers, timeout)
}
