//! High-level, config-resolving entry points for signing and verification.
//!
//! Takes an injected [`ConfigStore`] and a shared [`Transport`] rather than
//! reaching for process-global state, so profile resolution, TLS registration,
//! transport creation, and appearance defaults are handled in one place without
//! hidden globals. For lower-level control, call [`crate::signing`] directly
//! with a [`SoapSigningTransport`].

mod verify;

use std::sync::Arc;
use std::time::Duration;

use crate::appearance::{extract_cert_fields, extract_display_fields};
use crate::config::{register_profile_tls_mode, ConfigStore, ServerProfile, SignerInfo};
use crate::constants::DEFAULT_TIMEOUT_SOAP;
use crate::net::{SoapSigningTransport, Transport};
use crate::pki::CertInfo;
use crate::signing::{sign_pdf_detached, sign_pdf_embedded, EmbeddedSignatureOptions};
use crate::{Result, RevenantError};

pub use verify::{verify_detached, verify_pdf, verify_pdf_all};

/// Which server to sign against.
///
/// `profile` and `url` are mutually exclusive; leaving both unset falls back to
/// the saved active profile. An unset `timeout` resolves from the profile, the
/// saved config, then the built-in default.
#[derive(Debug, Clone, Default)]
pub struct ServerChoice<'a> {
    /// A built-in profile name (e.g. `"ekeng"`).
    pub profile: Option<&'a str>,
    /// A custom SOAP endpoint URL.
    pub url: Option<&'a str>,
    /// Request timeout override.
    pub timeout: Option<Duration>,
}

/// Sign a PDF with an embedded signature, resolving server and appearance
/// defaults from the profile and saved identity.
///
/// Server resolution (first match wins): an explicit `profile`, an explicit
/// `url`, then the saved active profile. When `options.name`, `options.font`, or
/// `options.fields` are unset they are filled from the saved signer identity and
/// the resolved profile.
///
/// # Errors
///
/// Returns [`RevenantError::Config`] if no server URL can be resolved or both a
/// profile and URL are given; otherwise a signing or PDF error from
/// [`sign_pdf_embedded`].
pub fn sign(
    store: &ConfigStore,
    transport: &Arc<Transport>,
    pdf: &[u8],
    username: &str,
    password: &str,
    server: &ServerChoice<'_>,
    options: EmbeddedSignatureOptions,
) -> Result<Vec<u8>> {
    let profile = resolve_profile(store, server)?;
    let (url, timeout) = resolve_url_and_timeout(store, profile.as_ref(), server)?;

    let mut options = options;
    options.name = options.name.or_else(|| store.signer_name());
    options.font = options
        .font
        .or_else(|| profile.as_ref().map(|p| p.font.clone()));
    if options.fields.is_none() && options.visible {
        options.fields = resolve_sig_fields(store, profile.as_ref());
    }

    let soap = setup_transport(transport, &url, profile.as_ref());
    sign_pdf_embedded(pdf, &soap, username, password, timeout, &options)
}

/// Sign a PDF and return a detached CMS/PKCS#7 signature.
///
/// Server resolution is identical to [`sign`].
///
/// # Errors
///
/// Returns [`RevenantError::Config`] if no server URL can be resolved or both a
/// profile and URL are given; otherwise a signing or PDF error from
/// [`sign_pdf_detached`].
pub fn sign_detached(
    store: &ConfigStore,
    transport: &Arc<Transport>,
    pdf: &[u8],
    username: &str,
    password: &str,
    server: &ServerChoice<'_>,
) -> Result<Vec<u8>> {
    let profile = resolve_profile(store, server)?;
    let (url, timeout) = resolve_url_and_timeout(store, profile.as_ref(), server)?;
    let soap = setup_transport(transport, &url, profile.as_ref());
    sign_pdf_detached(pdf, &soap, username, password, timeout)
}

/// Resolve a [`ServerProfile`] from the choice, or the saved active profile.
fn resolve_profile(
    store: &ConfigStore,
    choice: &ServerChoice<'_>,
) -> Result<Option<ServerProfile>> {
    if choice.profile.is_some() && choice.url.is_some() {
        return Err(RevenantError::Config(
            "Cannot specify both 'profile' and 'url'. Use one or the other.".to_owned(),
        ));
    }
    if let Some(name) = choice.profile {
        return Ok(Some(ServerProfile::builtin(name)?));
    }
    if let Some(url) = choice.url {
        return Ok(Some(ServerProfile::custom_default(url)?));
    }
    Ok(store.active_profile())
}

/// Resolve the final endpoint URL and timeout: explicit choice > profile >
/// saved config > default.
fn resolve_url_and_timeout(
    store: &ConfigStore,
    profile: Option<&ServerProfile>,
    choice: &ServerChoice<'_>,
) -> Result<(String, Duration)> {
    let explicit_url = choice
        .url
        .filter(|u| !u.is_empty())
        .map(str::to_owned)
        .or_else(|| profile.map(|p| p.url.clone()));

    let mut timeout: Option<Duration> = choice
        .timeout
        .or_else(|| profile.map(|p| Duration::from_secs(u64::from(p.timeout))));

    let url = if let Some(url) = explicit_url {
        url
    } else {
        // No explicit or profile URL: fall back to the saved config, which also
        // supplies the timeout when the caller/profile left it unset.
        let cfg = store.server_config().ok_or_else(|| {
            RevenantError::Config(
                "No server URL configured. Pass url=\"https://...\" or profile=\"ekeng\", \
                 or run `revenant setup` to save a profile."
                    .to_owned(),
            )
        })?;
        timeout = timeout.or_else(|| Some(cfg.timeout_duration()));
        cfg.url
    };
    Ok((url, timeout.unwrap_or(DEFAULT_TIMEOUT_SOAP)))
}

/// Resolve the signature-appearance display fields from the saved active profile
/// and signer identity, or `None` when nothing is configured or the profile
/// carries no field layout.
///
/// The standalone form used by front-ends (the CLI) that display fields outside
/// a full [`sign`] call; [`sign`] uses the internal two-argument form directly.
#[must_use]
pub fn resolve_signature_fields(store: &ConfigStore) -> Option<Vec<String>> {
    let profile = store.active_profile();
    resolve_sig_fields(store, profile.as_ref())
}

/// Resolve the signature-appearance display fields from a profile and the saved
/// signer identity, or `None` when the profile carries no field layout.
fn resolve_sig_fields(store: &ConfigStore, profile: Option<&ServerProfile>) -> Option<Vec<String>> {
    let profile = profile?;
    if profile.sig_fields.is_empty() {
        return None;
    }
    let signer = cert_info_from_signer(store.signer_info());
    let cert_values = extract_cert_fields(&profile.cert_fields, &signer);
    Some(extract_display_fields(&profile.sig_fields, &cert_values))
}

/// Register the profile's TLS mode with the shared transport, then build the
/// SOAP signing transport for the endpoint.
fn setup_transport(
    transport: &Arc<Transport>,
    url: &str,
    profile: Option<&ServerProfile>,
) -> SoapSigningTransport {
    if let Some(p) = profile {
        register_profile_tls_mode(transport, p);
    }
    SoapSigningTransport::new(Arc::clone(transport), url)
}

/// Bridge the persisted config identity ([`SignerInfo`]) to the PKI extraction
/// view ([`CertInfo`]) the appearance layer consumes.
///
/// The two types carry the same fields but belong to decoupled layers (config
/// persistence vs. certificate extraction); this adapter is the single seam
/// between them, kept here in the orchestration layer that needs both rather
/// than coupling config to PKI or vice versa.
fn cert_info_from_signer(info: SignerInfo) -> CertInfo {
    CertInfo {
        name: info.name,
        email: info.email,
        organization: info.organization,
        dn: info.dn,
        not_before: info.not_before,
        not_after: info.not_after,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{test_store, SignerInfo, EKENG};

    fn choice(profile: Option<&'static str>, url: Option<&'static str>) -> ServerChoice<'static> {
        ServerChoice {
            profile,
            url,
            timeout: None,
        }
    }

    #[test]
    fn resolve_profile_rejects_profile_and_url_together() {
        let (_dir, store) = test_store();
        let err = resolve_profile(&store, &choice(Some("ekeng"), Some("https://x/y"))).unwrap_err();
        assert!(matches!(err, RevenantError::Config(_)));
        assert!(err.to_string().contains("Cannot specify both"));
    }

    #[test]
    fn resolve_profile_named_and_custom() {
        let (_dir, store) = test_store();
        let named = resolve_profile(&store, &choice(Some("ekeng"), None))
            .unwrap()
            .unwrap();
        assert_eq!(named.name, "ekeng");

        let custom = resolve_profile(&store, &choice(None, Some("https://example.com/DSS.asmx")))
            .unwrap()
            .unwrap();
        assert_eq!(custom.name, "custom");
        assert_eq!(custom.tls_mode, crate::net::TlsMode::Standard);

        // No choice, no saved config -> no profile.
        assert!(resolve_profile(&store, &choice(None, None))
            .unwrap()
            .is_none());
    }

    #[test]
    fn resolve_url_and_timeout_prefers_profile_then_errors_when_absent() {
        let (_dir, store) = test_store();
        let ekeng = ServerProfile::builtin(EKENG).unwrap();
        let (url, timeout) =
            resolve_url_and_timeout(&store, Some(&ekeng), &choice(None, None)).unwrap();
        assert_eq!(url, ekeng.url);
        assert_eq!(timeout, Duration::from_secs(u64::from(ekeng.timeout)));

        // No profile, no saved config -> ConfigError.
        let err = resolve_url_and_timeout(&store, None, &choice(None, None)).unwrap_err();
        assert!(matches!(err, RevenantError::Config(_)));
        assert!(err.to_string().contains("No server URL configured"));
    }

    #[test]
    fn resolve_url_falls_back_to_saved_config() {
        let (_dir, store) = test_store();
        store
            .save_server_config(&ServerProfile::builtin(EKENG).unwrap())
            .unwrap();
        let (url, timeout) = resolve_url_and_timeout(&store, None, &choice(None, None)).unwrap();
        assert_eq!(url, "https://ca.gov.am:8080/SAPIWS/DSS.asmx");
        assert_eq!(timeout, Duration::from_secs(120));
    }

    #[test]
    fn explicit_timeout_overrides_profile() {
        let (_dir, store) = test_store();
        let ekeng = ServerProfile::builtin(EKENG).unwrap();
        let server = ServerChoice {
            profile: None,
            url: None,
            timeout: Some(Duration::from_secs(7)),
        };
        let (_url, timeout) = resolve_url_and_timeout(&store, Some(&ekeng), &server).unwrap();
        assert_eq!(timeout, Duration::from_secs(7));
    }

    #[test]
    fn sig_fields_resolve_from_ekeng_profile_and_identity() {
        let (_dir, store) = test_store();
        store
            .save_signer_info(&SignerInfo {
                name: Some("Anna Petrosyan 1234567890".to_owned()),
                email: Some("anna@example.am".to_owned()),
                ..SignerInfo::default()
            })
            .unwrap();
        let ekeng = ServerProfile::builtin(EKENG).unwrap();
        let fields = resolve_sig_fields(&store, Some(&ekeng)).expect("ekeng has sig fields");

        // name field strips the trailing SSN digits; the SSN field is labeled;
        // and the auto date is always appended.
        assert!(fields.iter().any(|f| f == "Anna Petrosyan"));
        assert!(fields.iter().any(|f| f.contains("SSN: 1234567890")));
        assert!(fields.iter().any(|f| f.starts_with("Date: ")));
    }

    #[test]
    fn sig_fields_none_for_profileless_or_fieldless() {
        let (_dir, store) = test_store();
        assert!(resolve_sig_fields(&store, None).is_none());
    }

    #[test]
    fn cert_info_bridge_copies_all_fields() {
        let info = SignerInfo {
            name: Some("N".to_owned()),
            email: Some("e@x".to_owned()),
            organization: Some("Org".to_owned()),
            dn: Some("CN=N".to_owned()),
            not_before: Some("2020-01-01T00:00:00Z".to_owned()),
            not_after: Some("2030-01-01T00:00:00Z".to_owned()),
        };
        let cert = cert_info_from_signer(info);
        assert_eq!(cert.name.as_deref(), Some("N"));
        assert_eq!(cert.email.as_deref(), Some("e@x"));
        assert_eq!(cert.organization.as_deref(), Some("Org"));
        assert_eq!(cert.dn.as_deref(), Some("CN=N"));
        assert_eq!(cert.not_before.as_deref(), Some("2020-01-01T00:00:00Z"));
        assert_eq!(cert.not_after.as_deref(), Some("2030-01-01T00:00:00Z"));
    }
}
