//! Standalone inspection of a CMS/PKCS#7 blob.
//!
//! Reports what can be learned from a detached signature alone -- signer
//! identity, digest algorithm, and LTV status -- without the original signed
//! data to verify against. Used by the `cert` inspection command when only a
//! `.p7s` file is available.

use super::asn1::{ASN1_SEQUENCE_TAG, MIN_CMS_SIZE};
use super::digest::{extract_digest_info, DigestAlgorithm};
use super::ltv::check_ltv_status;
use crate::pki::CertInfo;

/// The result of inspecting a CMS blob in isolation.
#[derive(Debug, Clone)]
pub struct CmsInspection {
    pub signer: Option<CertInfo>,
    pub digest_algorithm: Option<DigestAlgorithm>,
    pub ltv_enabled: bool,
    pub cms_size: usize,
    pub details: Vec<String>,
}

impl CmsInspection {
    /// Result for a blob that fails the structural precheck: every field empty,
    /// carrying a single explanatory detail line.
    fn invalid(cms_size: usize, detail: String) -> Self {
        CmsInspection {
            signer: None,
            digest_algorithm: None,
            ltv_enabled: false,
            cms_size,
            details: vec![detail],
        }
    }
}

/// Extract the signer's certificate identity from a CMS blob, or `None` on any
/// failure (best-effort).
#[must_use]
pub fn extract_signer_info(cms_der: &[u8]) -> Option<CertInfo> {
    CertInfo::from_cms(cms_der).ok()
}

/// Inspect a CMS/PKCS#7 blob without verifying it against any original data.
///
/// Extracts certificate info, digest algorithm, and LTV status, accumulating a
/// human-readable `details` list for display.
#[must_use]
pub fn inspect_cms_blob(cms_der: &[u8]) -> CmsInspection {
    let cms_size = cms_der.len();

    if cms_size < MIN_CMS_SIZE {
        return CmsInspection::invalid(
            cms_size,
            format!("CMS too small ({cms_size} bytes) -- likely corrupt"),
        );
    }

    if cms_der.first() != Some(&ASN1_SEQUENCE_TAG) {
        return CmsInspection::invalid(
            cms_size,
            "Not a valid CMS blob (expected ASN.1 SEQUENCE)".to_owned(),
        );
    }

    let mut details = vec![format!("CMS blob: {cms_size} bytes, valid ASN.1 structure")];

    let signer = extract_signer_info(cms_der);
    if let Some(info) = signer.as_ref() {
        push_field(&mut details, "Signer", info.name.as_deref());
        push_field(&mut details, "Organization", info.organization.as_deref());
        push_field(&mut details, "Email", info.email.as_deref());
    }

    let digest_info = extract_digest_info(cms_der);
    let digest_algorithm = digest_info.map(|(algo, _digest)| algo);
    if let Some(algo) = digest_algorithm {
        details.push(format!("Digest algorithm: {}", algo.name().to_uppercase()));
    }

    let ltv = check_ltv_status(cms_der);
    let ltv_label = if ltv.ltv_enabled() {
        "LTV enabled"
    } else {
        "Not LTV enabled"
    };
    details.push(format!("LTV: {ltv_label}"));
    details.extend(ltv.details.iter().map(|d| format!("  {d}")));

    CmsInspection {
        signer,
        digest_algorithm,
        ltv_enabled: ltv.ltv_enabled(),
        cms_size,
        details,
    }
}

/// Append `"{label}: {value}"` iff the value is present and non-empty.
fn push_field(details: &mut Vec<String>, label: &str, value: Option<&str>) {
    if let Some(text) = value {
        if !text.is_empty() {
            details.push(format!("{label}: {text}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMS_LEAF_DIRECT: &[u8] = include_bytes!("../pki/testdata/cms_leaf_direct.der");
    const CMS_WITH_ARCHIVAL: &[u8] = include_bytes!("../pki/testdata/cms_with_archival.der");

    #[test]
    fn rejects_too_small() {
        let inspection = inspect_cms_blob(b"tiny");
        assert_eq!(inspection.cms_size, 4);
        assert!(inspection.signer.is_none());
        assert!(inspection.details[0].contains("too small"));
    }

    #[test]
    fn rejects_non_sequence() {
        // 100+ bytes but not starting with 0x30.
        let blob = vec![0x02u8; 150];
        let inspection = inspect_cms_blob(&blob);
        assert!(inspection.details[0].contains("Not a valid CMS blob"));
    }

    #[test]
    fn inspects_real_signature() {
        let inspection = inspect_cms_blob(CMS_LEAF_DIRECT);
        assert_eq!(inspection.digest_algorithm, Some(DigestAlgorithm::Sha256));
        assert!(!inspection.ltv_enabled);
        let signer = inspection.signer.expect("signer identity extracted");
        assert_eq!(signer.name.as_deref(), Some("Test Signer Direct"));
        assert!(inspection
            .details
            .iter()
            .any(|d| d == "Signer: Test Signer Direct"));
        assert!(inspection
            .details
            .iter()
            .any(|d| d == "Digest algorithm: SHA256"));
        assert!(inspection
            .details
            .iter()
            .any(|d| d == "LTV: Not LTV enabled"));
    }

    #[test]
    fn reports_ltv_when_present() {
        let inspection = inspect_cms_blob(CMS_WITH_ARCHIVAL);
        assert!(inspection.ltv_enabled);
        assert!(inspection.details.iter().any(|d| d == "LTV: LTV enabled"));
    }
}
