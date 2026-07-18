//! Server profiles for CoSign appliances.
//!
//! A profile bundles connection details, identity-discovery strategies, and
//! signature-appearance metadata for a specific CoSign deployment. Built-in
//! profiles are defined here; custom servers become ad-hoc [`ServerProfile`]
//! instances via [`ServerProfile::custom`].
//!
//! Profiles are pure data with no I/O and no shared state -- the mutable config
//! (which profile is active, the saved URL/timeout) lives in the config store.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::constants::DEFAULT_TIMEOUT_SOAP_SECS;
use crate::error::RevenantError;
use crate::net::TlsMode;

/// Which signer-info field a [`CertField`] extracts its value from.
///
/// A closed enum rather than a free string: the set of extractable sources is
/// fixed by the signer-info shape, and keeping it typed lets the extraction
/// layer `match` exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CertFieldSource {
    /// The certificate common name / display name.
    #[default]
    Name,
    /// The full distinguished name.
    Dn,
    /// The organization (O) component.
    Organization,
    /// The email address.
    Email,
}

/// How to extract and display a value from certificate / signer info.
///
/// Used for account display and as a building block for signature-appearance
/// fields. When `regex` is set, capture group 1 is extracted; otherwise the
/// whole source value is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertField {
    /// Stable identifier, referenced by [`SigField::cert_field`].
    pub id: String,
    /// Human-readable label, e.g. "Name" or "SSN".
    pub label: String,
    /// Which signer-info field to read from.
    pub source: CertFieldSource,
    /// Optional extraction regex; capture group 1 is taken when present.
    pub regex: Option<String>,
}

/// An auto-generated signature-appearance value (as opposed to one derived from
/// the certificate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAuto {
    /// The signing date.
    Date,
}

/// The value source for a signature-appearance line.
///
/// A sum type rather than two independent `Option`s: a line's value is *either*
/// certificate-derived *or* auto-generated, never both and never neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigFieldValue {
    /// The value read from the [`CertField`] with this id.
    Cert(String),
    /// An auto-generated value.
    Auto(SigAuto),
}

/// A single line in the rendered PDF signature appearance: a value source and an
/// optional prefix label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigField {
    /// Where the line's value comes from.
    pub value: SigFieldValue,
    /// Optional prefix label in the appearance.
    pub label: Option<String>,
}

impl SigField {
    /// A field whose value comes from the certificate field with this id.
    fn from_cert(id: &str) -> Self {
        SigField {
            value: SigFieldValue::Cert(id.to_owned()),
            label: None,
        }
    }

    /// A certificate-derived field with an explicit prefix label.
    fn from_cert_labeled(id: &str, label: &str) -> Self {
        SigField {
            value: SigFieldValue::Cert(id.to_owned()),
            label: Some(label.to_owned()),
        }
    }

    /// An auto-generated field.
    fn auto(kind: SigAuto) -> Self {
        SigField {
            value: SigFieldValue::Auto(kind),
            label: None,
        }
    }
}

/// A signer-identity discovery strategy a profile supports.
///
/// A closed enum rather than free strings: the discovery layer `match`es it
/// exhaustively, so an unsupported method cannot be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMethod {
    /// Discover the identity by querying the signing server.
    Server,
    /// Enter the identity by hand.
    Manual,
}

/// Describes a CoSign server deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerProfile {
    /// Machine name / lookup key (e.g. "ekeng", "custom").
    pub name: String,
    /// Human-readable name for display.
    pub display_name: String,
    /// SOAP endpoint URL.
    pub url: String,
    /// Request timeout in whole seconds.
    pub timeout: u32,
    /// Supported identity-discovery methods, in preference order.
    pub identity_methods: Vec<IdentityMethod>,
    /// Which TLS stack the appliance requires.
    pub tls_mode: TlsMode,
    /// Substrings identifying this deployment's CA certificate.
    pub ca_cert_markers: Vec<String>,
    /// Account-lockout threshold; 0 means "unknown / not enforced".
    pub max_auth_attempts: u32,
    /// Certificate fields to display and extract.
    pub cert_fields: Vec<CertField>,
    /// Signature-appearance layout.
    pub sig_fields: Vec<SigField>,
    /// Signature-appearance font id.
    pub font: String,
    /// One-line CLI description for this profile.
    pub cli_description: String,
    /// Trust Service List URL for chain validation, if the deployment has one.
    pub tsl_url: Option<String>,
}

impl ServerProfile {
    /// Whether this profile supports the given identity-discovery method.
    #[must_use]
    pub fn has_identity_method(&self, method: IdentityMethod) -> bool {
        self.identity_methods.contains(&method)
    }
}

/// The two identity-discovery methods every profile supports by default.
fn default_identity_methods() -> Vec<IdentityMethod> {
    vec![IdentityMethod::Server, IdentityMethod::Manual]
}

// -- Built-in profiles ------------------------------------------------------

/// The `ekeng` profile key.
pub const EKENG: &str = "ekeng";

/// Built-in profiles, keyed by [`ServerProfile::name`]. A `BTreeMap` so that
/// "available profiles" listings (used in error messages) are deterministically
/// sorted.
pub static BUILTIN_PROFILES: LazyLock<BTreeMap<&'static str, ServerProfile>> =
    LazyLock::new(|| {
        let mut profiles = BTreeMap::new();
        profiles.insert(EKENG, ekeng_profile());
        profiles
    });

/// The EKENG (Armenian Government) appliance profile.
fn ekeng_profile() -> ServerProfile {
    ServerProfile {
        name: EKENG.to_owned(),
        display_name: "EKENG (Armenian Government)".to_owned(),
        url: "https://ca.gov.am:8080/SAPIWS/DSS.asmx".to_owned(),
        timeout: 120,
        identity_methods: default_identity_methods(),
        tls_mode: TlsMode::Legacy,
        // Second marker is "ԵԿԵՆԳ" (EKENG in Armenian).
        ca_cert_markers: vec![
            "ekeng".to_owned(),
            "\u{0567}\u{056f}\u{0565}\u{0576}\u{0563}".to_owned(),
        ],
        max_auth_attempts: 5,
        cert_fields: vec![
            CertField {
                id: "name".to_owned(),
                label: "Name".to_owned(),
                source: CertFieldSource::Name,
                regex: Some(r"^(.+?)\s+\d{5,}$".to_owned()),
            },
            // SSN is intentional -- Social Services Number.
            CertField {
                id: "gov_id".to_owned(),
                label: "SSN".to_owned(),
                source: CertFieldSource::Name,
                regex: Some(r"(\d{5,})$".to_owned()),
            },
            CertField {
                id: "email".to_owned(),
                label: "Email".to_owned(),
                source: CertFieldSource::Email,
                regex: None,
            },
        ],
        sig_fields: vec![
            SigField::from_cert("name"),
            SigField::from_cert_labeled("gov_id", "SSN"),
            SigField::auto(SigAuto::Date),
        ],
        font: "ghea-grapalat".to_owned(),
        cli_description: "Cross-platform CLI for ARX CoSign electronic signatures (EKENG profile)."
            .to_owned(),
        tsl_url: Some("https://www.gov.am/files/TSL/AM-TL-1.xml".to_owned()),
    }
}

impl ServerProfile {
    /// Look up a built-in profile by name (case-insensitive, whitespace-trimmed).
    ///
    /// # Errors
    /// [`RevenantError::Config`] if no built-in profile matches.
    pub fn builtin(name: &str) -> Result<Self, RevenantError> {
        let key = name.trim().to_lowercase();
        BUILTIN_PROFILES.get(key.as_str()).cloned().ok_or_else(|| {
            let available = BUILTIN_PROFILES
                .keys()
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            RevenantError::Config(format!("Unknown profile {name:?}. Available: {available}"))
        })
    }

    /// Create an ad-hoc profile for a custom server URL.
    ///
    /// Identity methods default to server + manual. The scheme must be `https` --
    /// plaintext `http` would expose credentials in transit and is rejected.
    ///
    /// # Errors
    /// [`RevenantError::Config`] if the URL scheme is not `https` or it has no host.
    pub fn custom(url: &str, timeout: u32) -> Result<Self, RevenantError> {
        let parsed = url::Url::parse(url)
            .map_err(|e| RevenantError::Config(format!("Invalid URL {url:?}: {e}")))?;

        match parsed.scheme() {
            "https" => {}
            "http" => {
                return Err(RevenantError::Config(
                    "HTTP URLs are not supported. Use https:// to protect credentials in transit."
                        .to_owned(),
                ));
            }
            other => {
                return Err(RevenantError::Config(format!(
                    "Invalid URL scheme {other:?}. Use https://."
                )));
            }
        }

        // No explicit hostless check is needed: the WHATWG `url` parser rejects
        // an empty host for special schemes at parse time above, so any URL
        // reaching here already has a host.

        Ok(ServerProfile {
            name: "custom".to_owned(),
            display_name: format!("Custom ({url})"),
            url: url.to_owned(),
            timeout,
            identity_methods: default_identity_methods(),
            tls_mode: TlsMode::Standard,
            ca_cert_markers: Vec::new(),
            max_auth_attempts: 0,
            cert_fields: Vec::new(),
            sig_fields: Vec::new(),
            font: "noto-sans".to_owned(),
            cli_description: String::new(),
            tsl_url: None,
        })
    }

    /// Create a custom profile with the default SOAP timeout.
    ///
    /// # Errors
    /// As [`ServerProfile::custom`].
    pub fn custom_default(url: &str) -> Result<Self, RevenantError> {
        Self::custom(url, DEFAULT_TIMEOUT_SOAP_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ekeng_profile_matches_spec() {
        let ekeng = ServerProfile::builtin("ekeng").expect("ekeng is built in");
        assert_eq!(ekeng.name, "ekeng");
        assert_eq!(ekeng.url, "https://ca.gov.am:8080/SAPIWS/DSS.asmx");
        assert_eq!(ekeng.timeout, 120);
        assert_eq!(ekeng.tls_mode, TlsMode::Legacy);
        assert_eq!(ekeng.max_auth_attempts, 5);
        assert_eq!(ekeng.font, "ghea-grapalat");
        assert_eq!(
            ekeng.tsl_url.as_deref(),
            Some("https://www.gov.am/files/TSL/AM-TL-1.xml")
        );
        assert!(ekeng.has_identity_method(IdentityMethod::Server));
        assert!(ekeng.has_identity_method(IdentityMethod::Manual));
        // Armenian marker round-trips.
        assert!(ekeng
            .ca_cert_markers
            .iter()
            .any(|m| m == "\u{0567}\u{056f}\u{0565}\u{0576}\u{0563}"));
        assert_eq!(ekeng.cert_fields.len(), 3);
        assert_eq!(ekeng.sig_fields.len(), 3);
    }

    #[test]
    fn get_profile_is_case_insensitive_and_trims() {
        assert!(ServerProfile::builtin("  EKENG  ").is_ok());
        assert!(ServerProfile::builtin("Ekeng").is_ok());
    }

    #[test]
    fn get_profile_unknown_lists_available() {
        let err = ServerProfile::builtin("nope").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Unknown profile"));
        assert!(msg.contains("ekeng"));
    }

    #[test]
    fn custom_profile_requires_https() {
        let https = ServerProfile::custom_default("https://example.com/DSS.asmx")
            .expect("https is accepted");
        assert_eq!(https.name, "custom");
        assert_eq!(https.tls_mode, TlsMode::Standard);
        assert_eq!(https.timeout, 120);
        assert_eq!(https.display_name, "Custom (https://example.com/DSS.asmx)");

        let http_err = ServerProfile::custom_default("http://example.com/DSS.asmx").unwrap_err();
        assert!(http_err.to_string().contains("HTTP URLs are not supported"));

        let ftp_err = ServerProfile::custom_default("ftp://example.com/x").unwrap_err();
        assert!(ftp_err.to_string().contains("Invalid URL scheme"));
    }

    #[test]
    fn custom_profile_rejects_hostless_url() {
        // "https://" has an empty authority; the WHATWG url parser rejects it
        // outright ("empty host"), so a hostless endpoint never yields a profile.
        assert!(ServerProfile::custom_default("https://").is_err());
    }
}
