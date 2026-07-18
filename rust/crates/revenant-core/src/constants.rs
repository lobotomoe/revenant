//! Application-wide constants.
//!
//! Centralizes every timeout, size limit, and protocol magic value.

use std::time::Duration;

/// Package version, sourced from Cargo at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// -- Timeouts ---------------------------------------------------------------

/// SOAP signing operation timeout.
pub const DEFAULT_TIMEOUT_SOAP: Duration = Duration::from_secs(120);
/// SOAP signing timeout in whole seconds -- the form stored in `config.json`
/// and carried on a [`crate::config::ServerProfile`], where timeouts are
/// integer seconds rather than a `Duration`.
pub const DEFAULT_TIMEOUT_SOAP_SECS: u32 = 120;
/// HTTP GET timeout (discovery / WSDL / TSL fetch).
pub const DEFAULT_TIMEOUT_HTTP_GET: Duration = Duration::from_secs(15);
/// HTTP POST timeout (SOAP requests).
pub const DEFAULT_TIMEOUT_HTTP_POST: Duration = Duration::from_secs(120);
/// Legacy TLS connection timeout.
pub const DEFAULT_TIMEOUT_LEGACY_TLS: Duration = Duration::from_secs(30);

/// Minimum user-configurable timeout (seconds).
pub const MIN_TIMEOUT_SECS: u64 = 1;
/// Maximum user-configurable timeout (seconds).
pub const MAX_TIMEOUT_SECS: u64 = 3600;

// -- Size units and limits --------------------------------------------------

/// Bytes per megabyte.
pub const BYTES_PER_MB: usize = 1024 * 1024;
/// Maximum HTTP/TLS response body size (50 MB).
pub const MAX_RESPONSE_SIZE: usize = 50 * BYTES_PER_MB;
/// Socket receive buffer size.
pub const RECV_BUFFER_SIZE: usize = 8192;
/// PDF size above which signing gets flaky on the appliance (35 MB).
pub const PDF_WARN_SIZE: usize = 35 * BYTES_PER_MB;

// -- Retry ------------------------------------------------------------------

/// Maximum retry attempts on transient failures.
pub const DEFAULT_MAX_RETRIES: u32 = 3;
/// Initial delay between retries.
pub const DEFAULT_RETRY_DELAY: Duration = Duration::from_secs(1);
/// Exponential backoff multiplier for the retry delay.
pub const DEFAULT_RETRY_BACKOFF: f64 = 2.0;

// -- Protocol ---------------------------------------------------------------

/// Minimum base64 length distinguishing a CMS signature from an error string.
pub const MIN_SIGNATURE_B64_LEN: usize = 50;
/// XML preview truncation length for error messages (characters).
pub const XML_PREVIEW_LENGTH: usize = 300;
/// SHA-1 digest size in bytes.
pub const SHA1_DIGEST_SIZE: usize = 20;
/// PDF file magic bytes.
pub const PDF_MAGIC: &[u8] = b"%PDF-";

// -- Environment variable names ---------------------------------------------

pub const ENV_URL: &str = "REVENANT_URL";
pub const ENV_TIMEOUT: &str = "REVENANT_TIMEOUT";
pub const ENV_USER: &str = "REVENANT_USER";
pub const ENV_PASS: &str = "REVENANT_PASS";
pub const ENV_NAME: &str = "REVENANT_NAME";

// -- Signature defaults -----------------------------------------------------

/// Default position preset for embedded signatures.
pub const DEFAULT_POSITION: &str = "bottom-right";

// -- TSL / chain validation -------------------------------------------------

/// Trust Service List cache time-to-live (24 hours).
pub const TSL_CACHE_TTL: Duration = Duration::from_secs(86400);
/// Maximum age of a cached TSL that may still be used as a fallback when a fresh
/// fetch fails (7 days). Beyond this the stale list is discarded and trust
/// degrades to indeterminate, so a blocked TSL endpoint cannot pin clients to an
/// arbitrarily old trust list indefinitely.
pub const TSL_MAX_STALE: Duration = Duration::from_secs(7 * 86400);
/// TSL fetch timeout.
pub const TSL_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum AIA intermediate certificate fetches per chain.
pub const MAX_AIA_FETCHES: u32 = 5;
