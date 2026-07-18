//! Signer-identity extraction from certificates and CMS/PKCS#7 signatures.
//!
//! Recovers signer identity -- name (CN), email, organization, full subject DN,
//! and validity dates -- from a raw X.509 certificate, the first certificate in
//! a CMS signature, or every signature embedded in a signed PDF. It also drives
//! a live signing transport to discover identity from the server, and summarizes
//! the full certificate set of a CMS blob for the `info` command.

use std::collections::HashSet;
use std::time::Duration;

use x509_cert::Certificate;

use super::{cert, expiry};
use crate::cms::{extract_cms_from_byterange, find_byteranges};
use crate::net::SigningTransport;
use crate::{Result, RevenantError};

/// Signer identity extracted from a certificate.
///
/// Distinct from [`crate::config::SignerInfo`] (which persists the same fields):
/// this is the extraction-time view produced by the PKI layer, kept decoupled
/// from the config layer. Validity dates are ISO 8601 (RFC 3339) strings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertInfo {
    pub name: Option<String>,
    pub email: Option<String>,
    pub organization: Option<String>,
    pub dn: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

impl CertInfo {
    /// Build signer info from a raw DER-encoded X.509 certificate.
    ///
    /// # Errors
    ///
    /// Returns [`RevenantError::Certificate`] if the certificate cannot be parsed.
    pub fn from_x509_der(cert_der: &[u8]) -> Result<Self> {
        let cert = cert::parse_der(cert_der)?;
        Ok(cert_info_of(&cert))
    }

    /// Build signer info from the first certificate in a CMS/PKCS#7 blob.
    ///
    /// Uses lenient ASN.1 parsing, so it handles certificates whose DN fields are
    /// BMPString-encoded (as EKENG's CA emits).
    ///
    /// # Errors
    ///
    /// Returns [`RevenantError::Certificate`] if the CMS cannot be parsed or
    /// carries no certificate.
    pub fn from_cms(cms_der: &[u8]) -> Result<Self> {
        let certs = cert::all_certs_from_cms(cms_der)?;
        let first = certs.first().ok_or_else(|| {
            RevenantError::Certificate("No certificate subject found in CMS blob.".to_owned())
        })?;
        Ok(cert_info_of(first))
    }

    /// Extract signer identity from every distinct signature in a signed PDF.
    ///
    /// Locates each `/ByteRange`, extracts its CMS blob, and reads the signer
    /// certificate. Signatures whose CMS cannot be parsed are skipped (logged at
    /// debug); duplicate signers (identical subject DN) are collapsed so a document
    /// signed twice by the same key reports one identity. Results preserve document
    /// order.
    ///
    /// # Errors
    ///
    /// Returns [`RevenantError::Certificate`] if the PDF has no embedded signature
    /// or none of its signatures yield a parseable certificate.
    pub fn all_from_pdf(pdf_bytes: &[u8]) -> Result<Vec<Self>> {
        let byteranges = find_byteranges(pdf_bytes)?;
        if byteranges.is_empty() {
            return Err(RevenantError::Certificate(
                "No embedded signature found in this PDF.".to_owned(),
            ));
        }

        let mut results = Vec::new();
        let mut seen_dns: HashSet<String> = HashSet::new();
        for br in &byteranges {
            let info = match extract_cms_from_byterange(pdf_bytes, br.len1, br.off2)
                .and_then(|cms| Self::from_cms(&cms))
            {
                Ok(info) => info,
                Err(e) => {
                    log::debug!("Skipping signature (extraction failed): {e}");
                    continue;
                }
            };
            // Only signatures carrying a non-empty subject DN count, and each DN
            // is reported once.
            if let Some(dn) = info.dn.clone().filter(|d| !d.is_empty()) {
                if seen_dns.insert(dn) {
                    results.push(info);
                }
            }
        }

        if results.is_empty() {
            return Err(RevenantError::Certificate(
                "Could not extract any certificate info from PDF signatures.".to_owned(),
            ));
        }
        Ok(results)
    }
}

/// A summary of one certificate in a CMS/PKCS#7 blob, for the `info` command.
///
/// Unlike [`CertInfo`] (signer-identity view), this carries the issuer and
/// serial number as well, for the per-certificate listing the `info` command prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmsCertSummary {
    /// Subject distinguished name.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Serial number in base-10.
    pub serial: String,
    /// `notBefore` as an ISO 8601 string, if parseable.
    pub not_before: Option<String>,
    /// `notAfter` as an ISO 8601 string, if parseable.
    pub not_after: Option<String>,
}

/// Summarize every certificate in a CMS/PKCS#7 blob, in encounter order.
///
/// Returns an empty vector when the CMS carries no certificates (the caller
/// decides how to report that).
///
/// # Errors
///
/// Returns [`RevenantError::Certificate`] if the CMS cannot be parsed.
pub fn summarize_cms_certificates(cms_der: &[u8]) -> Result<Vec<CmsCertSummary>> {
    let certs = cert::all_certs_from_cms(cms_der)?;
    Ok(certs
        .iter()
        .map(|cert| CmsCertSummary {
            subject: cert::subject_dn(cert),
            issuer: cert::issuer_dn(cert),
            serial: cert::serial_decimal(cert),
            not_before: cert::not_before_iso(cert),
            not_after: cert::not_after_iso(cert),
        })
        .collect())
}

/// Build [`CertInfo`] from a parsed certificate, warning on a validity problem.
fn cert_info_of(cert: &Certificate) -> CertInfo {
    let not_before = cert::not_before_iso(cert);
    let not_after = cert::not_after_iso(cert);
    warn_on_validity(not_before.as_deref(), not_after.as_deref());

    CertInfo {
        name: cert::common_name(cert),
        email: cert::email(cert),
        organization: cert::organization(cert),
        dn: Some(cert::subject_dn(cert)),
        not_before,
        not_after,
    }
}

/// Discover the signer's identity from a live signing service.
///
/// Prefers certificate enumeration (which returns the certificate directly,
/// with no signing side effect); if the transport does not support it or it
/// yields nothing, falls back to signing a dummy all-zero SHA-1 hash and
/// reading the identity from the returned CMS. Authentication failures always
/// propagate immediately -- a wrong password must not be masked by the
/// dummy-hash fallback.
///
/// # Errors
///
/// Returns [`RevenantError::Auth`] on bad credentials, or another
/// [`RevenantError`] if the server rejects the request or the returned
/// certificate cannot be parsed.
pub fn discover_identity_from_server(
    transport: &dyn SigningTransport,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<CertInfo> {
    // Preferred path: enumerate certificates (no signing round-trip).
    match transport.enum_certificates(username, password, timeout) {
        Ok(certs) => {
            if let Some(first) = certs.first() {
                log::debug!("Identity discovered via enum-certificates");
                return CertInfo::from_x509_der(first);
            }
            log::debug!("enum-certificates returned no certificates");
        }
        Err(e) => {
            // A wrong password must surface, not fall through to a second call.
            if matches!(e, RevenantError::Auth(_)) {
                return Err(e);
            }
            log::debug!("enum-certificates unavailable, falling back to dummy-hash: {e}");
        }
    }

    // Fallback: sign a dummy hash and read the cert from the CMS.
    log::debug!("Discovering identity via dummy-hash signing");
    let dummy_hash = [0u8; crate::constants::SHA1_DIGEST_SIZE];
    let cms_der = transport.sign_hash(&dummy_hash, username, password, timeout)?;
    CertInfo::from_cms(&cms_der)
}

/// Log a warning if the certificate is not yet valid or has already expired.
fn warn_on_validity(not_before: Option<&str>, not_after: Option<&str>) {
    if let Some(nb) = not_before {
        if expiry::not_yet_valid(nb) == Some(true) {
            log::warn!("Certificate is not yet valid (notBefore: {nb})");
            return;
        }
    }
    if let Some(na) = not_after {
        if expiry::days_remaining(na).is_some_and(|days| days < 0) {
            log::warn!("Certificate has expired (notAfter: {na})");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_DER: &[u8] = include_bytes!("testdata/root.der");
    const CMS_LEAF_DIRECT: &[u8] = include_bytes!("testdata/cms_leaf_direct.der");

    #[test]
    fn from_x509_reads_identity() {
        let info = CertInfo::from_x509_der(ROOT_DER).unwrap();
        assert_eq!(info.name.as_deref(), Some("Test Root CA"));
        assert_eq!(info.dn.as_deref(), Some("CN=Test Root CA"));
        assert!(info.not_before.is_some());
        assert!(info.not_after.is_some());
    }

    #[test]
    fn from_cms_reads_signer() {
        let info = CertInfo::from_cms(CMS_LEAF_DIRECT).unwrap();
        assert_eq!(info.name.as_deref(), Some("Test Signer Direct"));
    }

    #[test]
    fn summarize_reads_subject_issuer_serial_validity() {
        let summaries = summarize_cms_certificates(CMS_LEAF_DIRECT).unwrap();
        let first = summaries.first().expect("at least one certificate");
        assert!(first.subject.contains("Test Signer Direct"), "{first:?}");
        assert!(first.issuer.contains("Test Root CA"), "{first:?}");
        // Serial renders as a non-empty run of decimal digits.
        assert!(!first.serial.is_empty());
        assert!(first.serial.bytes().all(|b| b.is_ascii_digit()));
        assert!(first.not_before.is_some());
        assert!(first.not_after.is_some());
    }

    #[test]
    fn summarize_rejects_garbage() {
        let err = summarize_cms_certificates(b"not a cms").unwrap_err();
        assert!(matches!(err, RevenantError::Certificate(_)));
    }

    #[test]
    fn extract_all_from_pdf_errors_without_signature() {
        let err = CertInfo::all_from_pdf(b"%PDF-1.4\n%%EOF\n").unwrap_err();
        assert!(matches!(err, RevenantError::Certificate(_)));
        assert!(err.to_string().contains("No embedded signature"));
    }

    #[test]
    fn from_x509_rejects_garbage() {
        let err = CertInfo::from_x509_der(b"not a cert").unwrap_err();
        assert!(matches!(err, RevenantError::Certificate(_)));
    }

    #[test]
    fn from_cms_rejects_garbage() {
        let err = CertInfo::from_cms(b"not a cms blob").unwrap_err();
        assert!(matches!(err, RevenantError::Certificate(_)));
    }

    /// How the mock transport's `enum_certificates` behaves.
    enum EnumBehavior {
        /// Return these DER certificates.
        Certs(Vec<Vec<u8>>),
        /// Fail with an authentication error (must propagate).
        AuthError,
        /// Fail with a non-auth error (should fall through to dummy-hash).
        ServerError,
    }

    /// A signing transport with scripted responses for the discovery paths.
    struct MockTransport {
        enum_behavior: EnumBehavior,
        /// CMS returned by the dummy-hash fallback.
        sign_hash_cms: Vec<u8>,
    }

    impl SigningTransport for MockTransport {
        fn sign_data(&self, _: &[u8], _: &str, _: &str, _: Duration) -> Result<Vec<u8>> {
            unreachable!("discovery never calls sign_data")
        }
        fn sign_hash(&self, _: &[u8], _: &str, _: &str, _: Duration) -> Result<Vec<u8>> {
            Ok(self.sign_hash_cms.clone())
        }
        fn sign_pdf_detached(&self, _: &[u8], _: &str, _: &str, _: Duration) -> Result<Vec<u8>> {
            unreachable!("discovery never calls sign_pdf_detached")
        }
        fn enum_certificates(&self, _: &str, _: &str, _: Duration) -> Result<Vec<Vec<u8>>> {
            match &self.enum_behavior {
                EnumBehavior::Certs(certs) => Ok(certs.clone()),
                EnumBehavior::AuthError => Err(RevenantError::Auth("bad password".to_owned())),
                EnumBehavior::ServerError => {
                    Err(RevenantError::Server("enum not supported".to_owned()))
                }
            }
        }
    }

    fn dummy_timeout() -> Duration {
        Duration::from_secs(5)
    }

    #[test]
    fn discover_prefers_enum_certificates() {
        let transport = MockTransport {
            enum_behavior: EnumBehavior::Certs(vec![ROOT_DER.to_vec()]),
            sign_hash_cms: Vec::new(), // must not be reached
        };
        let info = discover_identity_from_server(&transport, "u", "p", dummy_timeout()).unwrap();
        assert_eq!(info.name.as_deref(), Some("Test Root CA"));
    }

    #[test]
    fn discover_falls_back_to_dummy_hash_when_enum_empty() {
        let transport = MockTransport {
            enum_behavior: EnumBehavior::Certs(Vec::new()),
            sign_hash_cms: CMS_LEAF_DIRECT.to_vec(),
        };
        let info = discover_identity_from_server(&transport, "u", "p", dummy_timeout()).unwrap();
        assert_eq!(info.name.as_deref(), Some("Test Signer Direct"));
    }

    #[test]
    fn discover_falls_back_when_enum_errors_nonauth() {
        let transport = MockTransport {
            enum_behavior: EnumBehavior::ServerError,
            sign_hash_cms: CMS_LEAF_DIRECT.to_vec(),
        };
        let info = discover_identity_from_server(&transport, "u", "p", dummy_timeout()).unwrap();
        assert_eq!(info.name.as_deref(), Some("Test Signer Direct"));
    }

    #[test]
    fn discover_propagates_auth_error_from_enum() {
        let transport = MockTransport {
            enum_behavior: EnumBehavior::AuthError,
            // If discovery wrongly fell through, this would hide the auth error.
            sign_hash_cms: CMS_LEAF_DIRECT.to_vec(),
        };
        let err = discover_identity_from_server(&transport, "u", "p", dummy_timeout()).unwrap_err();
        assert!(matches!(err, RevenantError::Auth(_)));
    }
}
