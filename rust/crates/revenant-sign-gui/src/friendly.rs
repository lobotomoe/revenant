//! Map raw technical error text to plain-language, localized hints.
//!
//! Network and HTTP failures carry opaque wording ("timed out", "HTTP 401",
//! "connection to host:443 failed: ...") that means little to a signer. This
//! mirrors the Python client's `_FRIENDLY_ERRORS` table: the first matching
//! substring wins and its localized message is shown; unmatched errors pass
//! through unchanged so no information is lost.
//!
//! The *patterns* deliberately differ from the Python table because the Rust
//! core speaks a different HTTP/TLS stack. Python matched `requests`/`urllib`
//! wording ("Cannot connect", "SSL error", "Name or service not known"); the
//! Rust core (ureq + the legacy TLS crate) emits its own strings. Each pattern
//! below is anchored to text the core actually produces:
//! - `TlsError` Display: "timed out after ...", "connection to ... failed: ...",
//!   "TLS handshake with ... failed", "TLS protocol error: ...".
//! - `std::io::Error` text embedded in the above: "Connection refused",
//!   "failed to lookup address information" (DNS, all platforms).
//! - `Transport` Display: "HTTP {code} from {url}: ...", "Standard HTTPS failed
//!   for {url}: ...", "HTTP request failed for {url}: ...".

use crate::i18n::Localizer;

/// Ordered `(substring, message-key)` pairs. Order matters: more specific
/// patterns precede broader ones, because the first substring found in the raw
/// error wins.
///
/// - DNS ("lookup address") and refusal ("Connection refused") come before the
///   generic "connection to" catch-all, since both are nested inside that same
///   `TlsError::Connect` message.
/// - "HTTP 403"/"HTTP 401" precede "HTTP 5"/"HTTP 4" so the specific codes are
///   not swallowed by the broad prefix.
const FRIENDLY_ERRORS: &[(&str, &str)] = &[
    (
        "timed out",
        "gui.server_is_not_responding_check_your_internet_conne_cd87621d",
    ),
    (
        "lookup address",
        "gui.server_address_not_found_check_the_server_url",
    ),
    (
        "Connection refused",
        "gui.server_is_not_available_it_may_be_down_for_maintenance",
    ),
    (
        "TLS handshake",
        "gui.secure_connection_failed_contact_your_system_administrator",
    ),
    (
        "TLS protocol error",
        "gui.secure_connection_failed_contact_your_system_administrator",
    ),
    (
        "HTTP 403",
        "gui.access_denied_your_account_may_not_have_permission_to_sign",
    ),
    (
        "HTTP 401",
        "gui.authentication_rejected_check_your_username_and_password",
    ),
    (
        "HTTP 5",
        "gui.server_error_the_signing_service_may_be_temporaril_d8163695",
    ),
    (
        "HTTP 4",
        "gui.request_rejected_by_server_contact_your_system_administrator",
    ),
    (
        "connection to",
        "gui.cannot_connect_to_the_server_check_your_internet_connection",
    ),
    (
        "Standard HTTPS failed for",
        "gui.cannot_connect_to_the_server_check_your_internet_connection",
    ),
    (
        "HTTP request failed for",
        "gui.cannot_connect_to_the_server_check_your_internet_connection",
    ),
];

/// Translate `raw` to a friendly localized message when a known pattern matches;
/// otherwise return `raw` unchanged.
pub(crate) fn friendly(l10n: &Localizer, raw: &str) -> String {
    for (pattern, key) in FRIENDLY_ERRORS {
        if raw.contains(pattern) {
            return l10n.t(key).to_owned();
        }
    }
    raw.to_owned()
}

#[cfg(test)]
mod tests {
    use super::friendly;
    use crate::i18n::Localizer;

    fn en() -> Localizer {
        Localizer::new("en")
    }

    /// Every pattern maps to its key's localized text, exercising the real
    /// error strings the core emits.
    #[test]
    fn maps_core_error_strings() {
        let l10n = en();
        let cases = [
            (
                "timed out after 30s talking to sign.example:443",
                "gui.server_is_not_responding_check_your_internet_conne_cd87621d",
            ),
            (
                "connection to sign.example:443 failed: failed to lookup address information: nodename nor servname provided, or not known",
                "gui.server_address_not_found_check_the_server_url",
            ),
            (
                "connection to sign.example:443 failed: Connection refused (os error 61)",
                "gui.server_is_not_available_it_may_be_down_for_maintenance",
            ),
            (
                "TLS handshake with sign.example:443 failed: cipher mismatch",
                "gui.secure_connection_failed_contact_your_system_administrator",
            ),
            (
                "HTTP 403 from https://sign.example: Forbidden",
                "gui.access_denied_your_account_may_not_have_permission_to_sign",
            ),
            (
                "HTTP 401 from https://sign.example: Unauthorized",
                "gui.authentication_rejected_check_your_username_and_password",
            ),
            (
                "HTTP 503 from https://sign.example: Service Unavailable",
                "gui.server_error_the_signing_service_may_be_temporaril_d8163695",
            ),
            (
                "HTTP 400 from https://sign.example: Bad Request",
                "gui.request_rejected_by_server_contact_your_system_administrator",
            ),
            (
                "connection to sign.example:443 failed: Network is unreachable (os error 51)",
                "gui.cannot_connect_to_the_server_check_your_internet_connection",
            ),
        ];
        for (raw, key) in cases {
            assert_eq!(friendly(&l10n, raw), l10n.t(key), "for raw: {raw}");
        }
    }

    /// An unrecognized error is returned verbatim rather than swallowed.
    #[test]
    fn passes_unknown_errors_through() {
        let l10n = en();
        let raw = "the PDF is already signed and locked";
        assert_eq!(friendly(&l10n, raw), raw);
    }
}
