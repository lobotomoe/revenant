//! LTV (Long Term Validation) status detection for CMS signatures.
//!
//! Checks whether a CMS/PKCS#7 signature embeds the revocation data (CRLs or
//! OCSP responses) that long-term validation needs. EKENG CoSign signatures are
//! **not** LTV-enabled -- they embed no revocation data, which is expected, not
//! a defect. This is a read-only scan; it never verifies signatures.

use const_oid::ObjectIdentifier;
use x509_cert::attr::Attributes;

use super::signed_data_from_der;

/// Adobe `RevocationInfoArchival` attribute OID.
const OID_REVOCATION_INFO_ARCHIVAL: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113583.1.1.8");
/// CAdES `id-smime-aa-ets-revocationRefs`.
const OID_REVOCATION_REFS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.22");
/// CAdES `id-smime-aa-ets-revocationValues`.
const OID_REVOCATION_VALUES: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.24");

/// Result of an LTV status check on a CMS signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LtvStatus {
    pub has_crl: bool,
    pub has_ocsp: bool,
    pub has_revocation_archival: bool,
    pub details: Vec<String>,
}

impl LtvStatus {
    /// Whether any long-term-validation revocation data (CRL or OCSP) is
    /// embedded. Derived from the individual flags rather than stored, so it
    /// cannot drift out of sync with them.
    #[must_use]
    pub fn ltv_enabled(&self) -> bool {
        self.has_crl || self.has_ocsp || self.has_revocation_archival
    }
}

/// The human-readable label for a revocation-related attribute OID, or `None`
/// if the OID is not one we recognize.
fn revocation_label(oid: &ObjectIdentifier) -> Option<&'static str> {
    match *oid {
        OID_REVOCATION_INFO_ARCHIVAL => Some("Adobe RevocationInfoArchival"),
        OID_REVOCATION_REFS => Some("CAdES revocation references"),
        OID_REVOCATION_VALUES => Some("CAdES revocation values"),
        _ => None,
    }
}

/// Scan one attribute set for revocation OIDs, appending a `"{kind} attribute:
/// {label}"` detail for each recognized one. Returns whether the Adobe
/// `RevocationInfoArchival` attribute was present.
fn scan_revocation_attrs(attrs: &Attributes, kind: &str, details: &mut Vec<String>) -> bool {
    let mut has_archival = false;
    for attr in attrs.iter() {
        if let Some(label) = revocation_label(&attr.oid) {
            details.push(format!("{kind} attribute: {label}"));
            if attr.oid == OID_REVOCATION_INFO_ARCHIVAL {
                has_archival = true;
            }
        }
    }
    has_archival
}

/// Check whether a CMS signature contains LTV data.
///
/// Inspects the `SignedData` for embedded CRLs and the signer's signed/unsigned
/// attributes for revocation OIDs. Always returns a status (never errors): an
/// unparsable blob yields all-false with an explanatory detail line.
#[must_use]
pub fn check_ltv_status(cms_der: &[u8]) -> LtvStatus {
    let mut details = Vec::new();

    let Ok(signed_data) = signed_data_from_der(cms_der) else {
        details.push("Cannot parse CMS structure for LTV check".to_owned());
        return LtvStatus {
            has_crl: false,
            has_ocsp: false,
            has_revocation_archival: false,
            details,
        };
    };

    let mut has_crl = false;
    let mut has_ocsp = false;
    let mut has_revocation_archival = false;

    if let Some(crls) = signed_data.crls.as_ref() {
        let count = crls.0.len();
        if count > 0 {
            has_crl = true;
            details.push(format!("Embedded CRLs: {count}"));
        }
    }

    if let Some(signer_info) = signed_data.signer_infos.0.iter().next() {
        let mut archival = false;
        if let Some(attrs) = signer_info.signed_attrs.as_ref() {
            archival |= scan_revocation_attrs(attrs, "Signed", &mut details);
        }
        if let Some(attrs) = signer_info.unsigned_attrs.as_ref() {
            archival |= scan_revocation_attrs(attrs, "Unsigned", &mut details);
        }
        if archival {
            has_revocation_archival = true;
            has_ocsp = true;
        }
    }

    if !(has_crl || has_ocsp || has_revocation_archival) {
        details.push("No embedded revocation data (CRL/OCSP)".to_owned());
    }

    LtvStatus {
        has_crl,
        has_ocsp,
        has_revocation_archival,
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMS_PLAIN: &[u8] = include_bytes!("../pki/testdata/cms_leaf_direct.der");
    const CMS_WITH_CRL: &[u8] = include_bytes!("../pki/testdata/cms_with_crl.der");
    const CMS_WITH_ARCHIVAL: &[u8] = include_bytes!("../pki/testdata/cms_with_archival.der");

    #[test]
    fn plain_signature_is_not_ltv() {
        let status = check_ltv_status(CMS_PLAIN);
        assert!(!status.ltv_enabled());
        assert!(!status.has_crl);
        assert!(!status.has_ocsp);
        assert!(status
            .details
            .iter()
            .any(|d| d.contains("No embedded revocation data")));
    }

    #[test]
    fn detects_embedded_crl() {
        let status = check_ltv_status(CMS_WITH_CRL);
        assert!(status.has_crl);
        assert!(status.ltv_enabled());
        assert!(status
            .details
            .iter()
            .any(|d| d.starts_with("Embedded CRLs:")));
    }

    #[test]
    fn detects_revocation_archival_attribute() {
        let status = check_ltv_status(CMS_WITH_ARCHIVAL);
        assert!(status.has_revocation_archival);
        assert!(status.has_ocsp);
        assert!(status.ltv_enabled());
        assert!(status
            .details
            .iter()
            .any(|d| d.contains("Adobe RevocationInfoArchival")));
    }

    #[test]
    fn unparsable_blob_reports_cannot_parse() {
        let status = check_ltv_status(b"garbage");
        assert!(!status.ltv_enabled());
        assert!(status
            .details
            .iter()
            .any(|d| d.contains("Cannot parse CMS structure")));
    }
}
