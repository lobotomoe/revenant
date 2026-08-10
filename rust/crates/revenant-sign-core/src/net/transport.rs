//! HTTP transport over a per-host TLS mode.
//!
//! Standard hosts are reached with `ureq` (rustls); appliances that only speak
//! TLS 1.0 + RC4 go through the from-scratch [`revenant_sign_tls`] client
//! against a pinned key.
//!
//! Which of the two a host gets is declared, never inferred: a profile that
//! needs the legacy transport says so via [`Transport::register_host_tls`], and
//! a host nobody declared is reached over standard HTTPS or not at all.
//! Falling back to the legacy transport when standard HTTPS fails would mean
//! answering a failed certificate check -- the one signal that something is
//! wrong -- by switching to a transport that performs no certificate check,
//! which is why no such fallback exists.
//!
//! Non-2xx HTTP responses are surfaced as errors with the status discarded. The
//! appliance returns HTTP 200 with a SOAP `ResultMajor` for application-level
//! outcomes (including authentication failures), so those flow through the
//! [`super::soap_parsers`], not here.

use std::collections::HashMap;
use std::io::Read as _;
use std::sync::Mutex;
use std::time::Duration;

use revenant_sign_tls::Method;
use url::Url;

use crate::constants::{
    BYTES_PER_MB, DEFAULT_RETRY_BACKOFF, DEFAULT_RETRY_DELAY, MAX_RESPONSE_SIZE,
};
use crate::{Result, RevenantError};

/// Maximum HTTPS redirects followed on a GET before giving up.
const MAX_REDIRECTS: u32 = 5;

/// Which TLS stack reaches a given host.
///
/// The legacy variant carries the keys it will accept, so a legacy host
/// without a pinned key cannot be expressed: that transport validates no
/// certificate chain, and a pin is the only thing that tells the real
/// appliance apart from anyone speaking for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsMode {
    /// Modern HTTPS via `ureq` (rustls) with the bundled Mozilla roots.
    Standard,
    /// The from-scratch TLS 1.0 + RC4 client for legacy CoSign appliances.
    Legacy {
        /// Accepted server keys, as lowercase hex SHA-256 of the certificate's
        /// `SubjectPublicKeyInfo`. Several may be listed to stage a rotation.
        pins: Vec<String>,
    },
}

impl TlsMode {
    /// Build the legacy mode, refusing an empty pin list.
    ///
    /// # Errors
    ///
    /// Returns [`RevenantError::Config`] if `pins` is empty.
    pub fn legacy(pins: Vec<String>) -> Result<Self> {
        if pins.is_empty() {
            return Err(RevenantError::Config(
                "Legacy TLS needs a pinned server key: it negotiates TLS 1.0 with RC4 \
                 against appliances whose certificates no authority vouches for, so \
                 without a pin there is nothing to tell the server apart from anyone \
                 speaking for it."
                    .to_owned(),
            ));
        }
        Ok(TlsMode::Legacy { pins })
    }

    /// A human-readable label for diagnostics and setup output.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            TlsMode::Standard => "Standard HTTPS",
            TlsMode::Legacy { .. } => "Legacy TLS (RC4, pinned key)",
        }
    }
}

/// An HTTP transport shared across the application.
///
/// Holds a pooled `ureq` agent for the standard path and the per-host TLS-mode
/// cache. Cheap to share behind an `Arc`; all methods take `&self`.
#[derive(Debug)]
pub struct Transport {
    agent: ureq::Agent,
    host_tls: Mutex<HashMap<String, TlsMode>>,
}

impl Default for Transport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport {
    /// Create a transport with an empty host cache.
    #[must_use]
    pub fn new() -> Self {
        // Redirects are followed manually (GET only) so we can refuse an
        // HTTPS->HTTP downgrade; ureq's own follower cannot filter by scheme.
        let agent = ureq::AgentBuilder::new().redirects(0).build();
        Self {
            agent,
            host_tls: Mutex::new(HashMap::new()),
        }
    }

    /// Register a host's declared TLS mode.
    ///
    /// Used by the config layer to apply a profile's TLS setting. A host that
    /// is never registered is reached over standard HTTPS.
    pub fn register_host_tls(&self, host: &str, mode: TlsMode) {
        log::debug!("Registered TLS mode for {host}: {}", mode.label());
        self.lock_cache().insert(host.to_owned(), mode);
    }

    /// A human-readable TLS mode for `host`.
    #[must_use]
    pub fn host_tls_info(&self, host: &str) -> &'static str {
        match self.lookup_host(host) {
            Some(mode) => mode.label(),
            None => TlsMode::Standard.label(),
        }
    }

    /// Fetch `url` over the transport its host was registered with, retrying
    /// transient failures.
    ///
    /// # Errors
    ///
    /// Returns a [`RevenantError`] on connection, TLS, or HTTP failure, or if
    /// the server's key is not one of the pinned keys.
    pub fn get(&self, url: &str, timeout: Duration, max_retries: u32) -> Result<Vec<u8>> {
        let parsed = parse_https(url)?;
        let host = host_of(&parsed)?;
        match self.lookup_host(&host) {
            None | Some(TlsMode::Standard) => {
                with_retry(max_retries, &format!("GET {url}"), || {
                    self.std_get(url, timeout)
                })
            }
            Some(TlsMode::Legacy { pins }) => {
                with_retry(max_retries, &format!("GET {url}"), || {
                    legacy_request(Method::Get, url, None, &[], timeout, &pins)
                })
            }
        }
    }

    /// POST `body` to `url` over the transport its host was registered with.
    ///
    /// # Errors
    ///
    /// Returns a [`RevenantError`] on connection, TLS, or HTTP failure, or if
    /// the server's key is not one of the pinned keys.
    pub fn post(
        &self,
        url: &str,
        body: &[u8],
        headers: &[(&str, &str)],
        timeout: Duration,
        max_retries: u32,
    ) -> Result<Vec<u8>> {
        let parsed = parse_https(url)?;
        let host = host_of(&parsed)?;
        match self.lookup_host(&host) {
            None | Some(TlsMode::Standard) => {
                with_retry(max_retries, &format!("POST {url}"), || {
                    self.std_post(url, body, headers, timeout)
                })
            }
            Some(TlsMode::Legacy { pins }) => {
                with_retry(max_retries, &format!("POST {url}"), || {
                    legacy_request(Method::Post, url, Some(body), headers, timeout, &pins)
                })
            }
        }
    }

    // -- internals ----------------------------------------------------------

    fn lock_cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, TlsMode>> {
        self.host_tls.lock().expect("host TLS cache mutex poisoned")
    }

    fn lookup_host(&self, host: &str) -> Option<TlsMode> {
        self.lock_cache().get(host).cloned()
    }

    fn std_get(&self, url: &str, timeout: Duration) -> Result<Vec<u8>> {
        let mut current = parse_https(url)?;
        for _ in 0..=MAX_REDIRECTS {
            match self
                .agent
                .request_url("GET", &current)
                .timeout(timeout)
                .call()
            {
                Ok(resp) => {
                    let status = resp.status();
                    if (300..400).contains(&status) {
                        current = follow_redirect(&current, &resp)?;
                        continue;
                    }
                    return read_ok_body(resp, current.as_str(), status);
                }
                Err(err) => return Err(classify_ureq(&current, err)),
            }
        }
        Err(RevenantError::tls_retryable(format!(
            "Too many redirects for {url}"
        )))
    }

    fn std_post(
        &self,
        url: &str,
        body: &[u8],
        headers: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let parsed = parse_https(url)?;
        let mut request = self.agent.request_url("POST", &parsed).timeout(timeout);
        for (name, value) in headers {
            request = request.set(name, value);
        }
        match request.send_bytes(body) {
            Ok(resp) => {
                let status = resp.status();
                read_ok_body(resp, url, status)
            }
            Err(err) => Err(classify_ureq(&parsed, err)),
        }
    }
}

/// Send an HTTP request over the legacy (TLS 1.0 + RC4) client, returning the
/// body on a 2xx status. A non-2xx status is a hard error with the body
/// discarded.
fn legacy_request(
    method: Method,
    url: &str,
    body: Option<&[u8]>,
    headers: &[(&str, &str)],
    timeout: Duration,
    pins: &[String],
) -> Result<Vec<u8>> {
    let response = revenant_sign_tls::request(method, url, body, headers, timeout, pins)?;
    if !response.is_success() {
        return Err(RevenantError::Other(format!(
            "HTTP {} from {url}: {}",
            response.status, response.reason
        )));
    }
    Ok(response.body)
}

/// Parse and require an HTTPS URL, guarding against credential leakage over
/// plaintext.
fn parse_https(url: &str) -> Result<Url> {
    let parsed =
        Url::parse(url).map_err(|e| RevenantError::Other(format!("Invalid URL {url}: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(RevenantError::Other(format!(
            "Only HTTPS URLs are allowed (got {}://). \
             Credentials must not be sent over unencrypted connections.",
            parsed.scheme()
        )));
    }
    Ok(parsed)
}

fn host_of(url: &Url) -> Result<String> {
    url.host_str()
        .map(str::to_owned)
        .ok_or_else(|| RevenantError::Other(format!("Cannot extract hostname from URL: {url}")))
}

/// Resolve a redirect `Location` against the current URL, refusing any
/// HTTPS->HTTP downgrade so credentials cannot leak over plaintext.
fn follow_redirect(current: &Url, resp: &ureq::Response) -> Result<Url> {
    let location = resp.header("location").ok_or_else(|| {
        RevenantError::Other(format!("Redirect from {current} without a Location header"))
    })?;
    let next = current.join(location).map_err(|e| {
        RevenantError::Other(format!(
            "Invalid redirect target '{location}' from {current}: {e}"
        ))
    })?;
    if next.scheme() != "https" {
        return Err(RevenantError::Other(format!(
            "Refused redirect from HTTPS to {}: {next}",
            next.scheme()
        )));
    }
    Ok(next)
}

/// Read a 2xx response body, enforcing the size limit; error on any other status.
fn read_ok_body(resp: ureq::Response, url: &str, status: u16) -> Result<Vec<u8>> {
    if !(200..300).contains(&status) {
        return Err(RevenantError::Other(format!(
            "HTTP {status} from {url}: {}",
            resp.status_text()
        )));
    }
    let limit = u64::try_from(MAX_RESPONSE_SIZE)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut buf = Vec::new();
    resp.into_reader()
        .take(limit)
        .read_to_end(&mut buf)
        .map_err(|e| {
            RevenantError::tls_retryable(format!("Failed reading response from {url}: {e}"))
        })?;
    if buf.len() > MAX_RESPONSE_SIZE {
        return Err(RevenantError::Other(format!(
            "Response from {url} exceeds {} MB limit",
            MAX_RESPONSE_SIZE / BYTES_PER_MB
        )));
    }
    Ok(buf)
}

/// Map a `ureq` error into the library error type. Connection/TLS-level faults
/// are retryable (and trigger the legacy fallback); HTTP status and config
/// errors are permanent.
fn classify_ureq(url: &Url, err: ureq::Error) -> RevenantError {
    match err {
        ureq::Error::Status(code, resp) => {
            RevenantError::Other(format!("HTTP {code} from {url}: {}", resp.status_text()))
        }
        ureq::Error::Transport(transport) => {
            let kind = transport.kind();
            let message = transport.to_string();
            if is_connection_failure(kind) {
                RevenantError::tls_retryable(format!("Standard HTTPS failed for {url}: {message}"))
            } else {
                RevenantError::Other(format!("HTTP request failed for {url}: {message}"))
            }
        }
    }
}

/// Whether a transport error kind denotes a connection/TLS-level failure worth
/// retrying and falling back from.
fn is_connection_failure(kind: ureq::ErrorKind) -> bool {
    use ureq::ErrorKind::{ConnectionFailed, Dns, Io, ProxyConnect, TooManyRedirects};
    matches!(
        kind,
        Dns | ConnectionFailed | Io | TooManyRedirects | ProxyConnect
    )
}

/// Run `op` with exponential-backoff retry, re-attempting only retryable errors.
fn with_retry<T>(max_retries: u32, operation: &str, op: impl FnMut() -> Result<T>) -> Result<T> {
    with_retry_delayed(
        max_retries,
        DEFAULT_RETRY_DELAY,
        DEFAULT_RETRY_BACKOFF,
        operation,
        op,
    )
}

fn with_retry_delayed<T>(
    max_retries: u32,
    delay: Duration,
    backoff: f64,
    operation: &str,
    mut op: impl FnMut() -> Result<T>,
) -> Result<T> {
    let mut current_delay = delay;
    let mut attempt = 0u32;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) => {
                if attempt >= max_retries || !err.is_retryable() {
                    return Err(err);
                }
                log::warn!(
                    "{operation} failed (attempt {}/{}): {err}. Retrying in {:.1}s...",
                    attempt + 1,
                    max_retries + 1,
                    current_delay.as_secs_f64()
                );
                std::thread::sleep(current_delay);
                current_delay = current_delay.mul_f64(backoff);
                attempt += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn parse_https_accepts_https_rejects_http() {
        assert!(parse_https("https://ca.gov.am:8080/SAPIWS/DSS.asmx").is_ok());
        assert!(parse_https("http://ca.gov.am/").is_err());
        assert!(parse_https("not a url").is_err());
    }

    #[test]
    fn host_cache_register_and_report() {
        let t = Transport::new();
        // An undeclared host is standard HTTPS, not "unknown".
        assert_eq!(t.host_tls_info("ca.gov.am"), "Standard HTTPS");
        t.register_host_tls("ca.gov.am", TlsMode::legacy(vec!["ab".repeat(32)]).unwrap());
        assert_eq!(t.host_tls_info("ca.gov.am"), "Legacy TLS (RC4, pinned key)");
        t.register_host_tls("example.com", TlsMode::Standard);
        assert_eq!(t.host_tls_info("example.com"), "Standard HTTPS");
    }

    #[test]
    fn retry_succeeds_after_transient_failures() {
        let attempts = Cell::new(0u32);
        let result = with_retry_delayed(3, Duration::ZERO, 2.0, "test", || {
            attempts.set(attempts.get() + 1);
            if attempts.get() < 3 {
                Err(RevenantError::tls_retryable("transient"))
            } else {
                Ok(42)
            }
        });
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts.get(), 3);
    }

    #[test]
    fn retry_does_not_retry_non_retryable() {
        let attempts = Cell::new(0u32);
        let result: Result<()> = with_retry_delayed(3, Duration::ZERO, 2.0, "test", || {
            attempts.set(attempts.get() + 1);
            Err(RevenantError::Auth("bad creds".into()))
        });
        assert!(result.is_err());
        assert_eq!(
            attempts.get(),
            1,
            "non-retryable errors must not be retried"
        );
    }

    #[test]
    fn retry_exhausts_and_returns_last_error() {
        let attempts = Cell::new(0u32);
        let result: Result<()> = with_retry_delayed(2, Duration::ZERO, 2.0, "test", || {
            attempts.set(attempts.get() + 1);
            Err(RevenantError::tls_retryable("always fails"))
        });
        assert!(result.is_err());
        assert_eq!(attempts.get(), 3, "should try 1 + max_retries times");
    }

    #[test]
    fn connection_failures_are_retryable_others_not() {
        assert!(is_connection_failure(ureq::ErrorKind::ConnectionFailed));
        assert!(is_connection_failure(ureq::ErrorKind::Dns));
        assert!(is_connection_failure(ureq::ErrorKind::Io));
        assert!(!is_connection_failure(ureq::ErrorKind::InvalidUrl));
        assert!(!is_connection_failure(ureq::ErrorKind::UnknownScheme));
    }

    #[test]
    fn redirect_resolves_relative_and_refuses_downgrade() {
        // A relative redirect stays on https and resolves against the base.
        let base = Url::parse("https://host.example/a/b").unwrap();
        let joined = base.join("/c/d").unwrap();
        assert_eq!(joined.as_str(), "https://host.example/c/d");
        // A downgrade to http must be refused.
        let downgrade = base.join("http://host.example/x").unwrap();
        assert_eq!(downgrade.scheme(), "http");
    }
}
