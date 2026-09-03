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
    /// Stable identifier, referenced by [`SigFieldValue::Cert`].
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

/// Where a server profile's certificate-chain trust anchors come from.
///
/// A deployment establishes trust in exactly one way, so this is a sum type
/// rather than overlapping optional fields. It is plain data (DER bytes / a URL)
/// so profiles carry no PKI dependency; the verification layer interprets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustAnchors {
    /// No configured anchors -- chain validation is left indeterminate ("trust
    /// not checked"). The correct state for a deployment whose CA cannot yet be
    /// authoritatively pinned.
    None,
    /// A pinned, bundled set of trusted CA certificates (DER). Offline and
    /// out-of-band -- the authoritative way to trust a deployment whose issuing
    /// CAs are not in a usable public trust list. An empty set behaves as
    /// [`None`](TrustAnchors::None).
    Pinned(Vec<Vec<u8>>),
    /// Fetch anchors from an ETSI Trust Service List at this URL. For deployments
    /// that publish a live, maintained TSL.
    Tsl(String),
}

/// Describes a CoSign server deployment.
///
/// Non-exhaustive: profiles are meant to come from [`ServerProfile::builtin`]
/// or [`ServerProfile::custom_default`], which fill in every capability the
/// deployment implies. Marking it so keeps a later field addition -- the kind
/// that turned 3.x into 4.0 -- out of the breaking-change budget.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// Whether this deployment issues Latin-only logins, making a non-ASCII
    /// entry a keyboard-layout slip rather than a credential. Off unless a
    /// deployment is known to work that way -- the SOAP envelope escapes and
    /// encodes credentials as UTF-8, so the transport imposes no such limit.
    pub ascii_credentials_only: bool,
    /// Certificate fields to display and extract.
    pub cert_fields: Vec<CertField>,
    /// Signature-appearance layout.
    pub sig_fields: Vec<SigField>,
    /// Signature-appearance font id.
    pub font: String,
    /// One-line CLI description for this profile.
    pub cli_description: String,
    /// Where this deployment's certificate-chain trust anchors come from.
    pub trust: TrustAnchors,
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
        // The appliance presents a self-signed factory certificate
        // (CN=CoSign, issued by AR Ltd., valid 2006-2032) that names neither
        // the host nor any authority anyone can check. Its key identifies it.
        tls_mode: TlsMode::Legacy {
            pins: vec![
                "0c00d213f7945bfec24402f8b76ff25f23bc613e58e38aef34e40adcbf9ea6e4".to_owned(),
            ],
        },
        // Second marker is "ԵԿԵՆԳ" (EKENG in Armenian).
        ca_cert_markers: vec![
            "ekeng".to_owned(),
            "\u{0567}\u{056f}\u{0565}\u{0576}\u{0563}".to_owned(),
        ],
        max_auth_attempts: 5,
        // EKENG logins are Latin letters and digits. A Cyrillic or Armenian
        // entry is the keyboard layout, not the account, and spending one of
        // the five attempts above to prove it risks locking the account.
        ascii_credentials_only: true,
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
        // EKENG signatures chain to "Staff of Government of RA Root CA", which is
        // NOT in the Armenian TSL (a separate, citizen-ID PKI) -- and that TSL is
        // years past its NextUpdate anyway. So trust is pinned, not TSL-fetched.
        trust: TrustAnchors::Pinned(ekeng_trust_anchors()),
    }
}

/// The pinned CA trust anchors for the EKENG deployment.
///
/// EKENG-issued signatures chain to the self-signed "Staff of Government of RA
/// Root CA" (O=Staff of Government of RA, C=AM; valid 2009-2038), which is a
/// separate PKI from the CAs in the Armenian TSL. The bundled DER was obtained
/// from the government's own publication (`https://www.gov.am/CAStaff/GovRootCA.crt`,
/// via a browser -- the host is behind a bot manager that blocks plain fetches)
/// and pinned after verifying it: SHA-256 `671c272eaf581886e549fbd2d2879188b3aee1c6188a33a65ef8ccfa457ee2bc`,
/// and -- decisively -- its public key verifies the signature on a real leaf the
/// appliance returned, which a tampered download could not.
fn ekeng_trust_anchors() -> Vec<Vec<u8>> {
    const STAFF_GOV_RA_ROOT_CA: &[u8] =
        include_bytes!("anchors/staff_of_government_of_ra_root_ca.der");
    vec![STAFF_GOV_RA_ROOT_CA.to_vec()]
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
            ascii_credentials_only: false,
            cert_fields: Vec::new(),
            sig_fields: Vec::new(),
            font: "noto-sans".to_owned(),
            cli_description: String::new(),
            trust: TrustAnchors::None,
        })
    }

    /// Create a custom profile with the default SOAP timeout.
    ///
    /// # Errors
    /// As [`ServerProfile::custom`].
    pub fn custom_default(url: &str) -> Result<Self, RevenantError> {
        Self::custom(url, DEFAULT_TIMEOUT_SOAP_SECS)
    }

    /// An ad-hoc profile for a custom server reached over a declared TLS mode.
    ///
    /// Use this for an appliance that needs the legacy transport: build the
    /// mode with [`TlsMode::legacy`], which refuses an empty pin list.
    ///
    /// # Errors
    ///
    /// [`RevenantError::Config`] if the URL is not a valid `https://` URL.
    pub fn custom_with_tls(
        url: &str,
        timeout: u32,
        tls_mode: TlsMode,
    ) -> Result<Self, RevenantError> {
        let mut profile = Self::custom(url, timeout)?;
        profile.tls_mode = tls_mode;
        Ok(profile)
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
        let TlsMode::Legacy { pins } = &ekeng.tls_mode else {
            panic!("ekeng must declare legacy TLS");
        };
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].len(), 64);
        assert_eq!(ekeng.max_auth_attempts, 5);
        assert!(ekeng.ascii_credentials_only);
        assert_eq!(ekeng.font, "ghea-grapalat");
        // EKENG uses pinned trust anchors (the dead TSL is not a usable source).
        assert!(matches!(ekeng.trust, TrustAnchors::Pinned(_)));
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
    fn ekeng_pins_the_verified_government_root() {
        use sha2::Digest as _;

        let anchors = ekeng_trust_anchors();
        assert_eq!(anchors.len(), 1, "EKENG should pin exactly one root");
        // Pin the exact, authenticated "Staff of Government of RA Root CA" so an
        // accidental swap of the bundled DER is caught.
        let fingerprint = hex::encode(sha2::Sha256::digest(&anchors[0]));
        assert_eq!(
            fingerprint,
            "671c272eaf581886e549fbd2d2879188b3aee1c6188a33a65ef8ccfa457ee2bc"
        );
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
        // Nothing is known about a custom deployment's account naming, so no
        // character class is assumed for its credentials.
        assert!(!https.ascii_credentials_only);
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
