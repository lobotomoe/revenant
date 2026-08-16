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
    /// A CRL is embedded directly in the `SignedData.crls` field.
    pub has_crl: bool,
    /// A standalone OCSP response was found. The Adobe `RevocationInfoArchival`
    /// container may itself carry OCSP responses, but its contents are not
    /// itemized here -- an archival container is reported via
    /// `has_revocation_archival`, so this stays `false` for it.
    pub has_ocsp: bool,
    /// The Adobe `RevocationInfoArchival` attribute is present, wherever it was
    /// found. Presence alone is not evidence -- see `has_unauthenticated_material`.
    pub has_revocation_archival: bool,
    /// Where the revocation material was found, which is what decides whether it
    /// counts for anything.
    pub material: RevocationMaterial,
    pub details: Vec<String>,
}

/// Where a signature's revocation material came from.
///
/// The distinction is the whole point: RFC 5652 puts the signature over the
/// signed attributes, so the `crls` field and the unsigned attributes sit
/// outside it and a third party can add either to a finished document without
/// invalidating the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationMaterial {
    /// No revocation material at all.
    None,
    /// Present, but only where anyone could have put it.
    Unauthenticated,
    /// Present in the signer's signed attributes, so the signer committed to it.
    Signed,
}

impl LtvStatus {
    /// Whether the signer embedded long-term-validation revocation data.
    ///
    /// Only material inside the signed attributes counts. The `crls` field and
    /// the unsigned attributes sit outside the signature -- RFC 5652 signs the
    /// signed attributes, not the surrounding structure -- so a third party can
    /// add either to a finished document without invalidating it. Presence there
    /// is reported through `has_unauthenticated_material` and never counted.
    ///
    /// True means the signer embedded revocation evidence, not that the evidence
    /// was checked against the signer's chain; that validation does not exist yet.
    #[must_use]
    pub fn ltv_enabled(&self) -> bool {
        self.material == RevocationMaterial::Signed
    }

    /// Whether revocation material is present that nothing vouches for.
    #[must_use]
    pub fn has_unauthenticated_material(&self) -> bool {
        self.material == RevocationMaterial::Unauthenticated
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
/// `note` is appended to each reported line, so material found outside the
/// signature says so where the operator reads it rather than only in a flag.
fn scan_revocation_attrs(
    attrs: &Attributes,
    kind: &str,
    note: &str,
    details: &mut Vec<String>,
) -> bool {
    let mut has_archival = false;
    for attr in attrs.iter() {
        if let Some(label) = revocation_label(&attr.oid) {
            details.push(format!("{kind} attribute: {label}{note}"));
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
            material: RevocationMaterial::None,
            details,
        };
    };

    let mut has_crl = false;
    // We do not currently itemize standalone OCSP responses; the Adobe archival
    // container (below) is tracked separately and never conflated with OCSP.
    let has_ocsp = false;
    let mut has_revocation_archival = false;

    let mut material = RevocationMaterial::None;

    // The crls field sits beside the signature rather than inside it, so its
    // contents prove nothing about what the signer intended.
    if let Some(crls) = signed_data.crls.as_ref() {
        let count = crls.0.len();
        if count > 0 {
            has_crl = true;
            material = RevocationMaterial::Unauthenticated;
            details.push(format!(
                "Embedded CRLs: {count} (outside the signature, not counted)"
            ));
        }
    }

    if let Some(signer_info) = signed_data.signer_infos.0.iter().next() {
        if let Some(attrs) = signer_info.signed_attrs.as_ref() {
            if scan_revocation_attrs(attrs, "Signed", "", &mut details) {
                has_revocation_archival = true;
                material = RevocationMaterial::Signed;
            }
        }
        // Unsigned attributes are not covered by the signature: a third party can
        // staple one onto a finished document. Reported, never counted.
        if let Some(attrs) = signer_info.unsigned_attrs.as_ref() {
            if scan_revocation_attrs(
                attrs,
                "Unsigned",
                " (outside the signature, not counted)",
                &mut details,
            ) {
                has_revocation_archival = true;
                if material == RevocationMaterial::None {
                    material = RevocationMaterial::Unauthenticated;
                }
            }
        }
    }

    if material != RevocationMaterial::Signed {
        details.push("No signed revocation data (CRL/OCSP)".to_owned());
    }

    LtvStatus {
        has_crl,
        has_ocsp,
        has_revocation_archival,
        material,
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMS_PLAIN: &[u8] = include_bytes!("../pki/testdata/cms_leaf_direct.der");
    const CMS_WITH_CRL: &[u8] = include_bytes!("../pki/testdata/cms_with_crl.der");
    const CMS_WITH_ARCHIVAL: &[u8] = include_bytes!("../pki/testdata/cms_with_archival.der");
    const CMS_UNSIGNED_ARCHIVAL: &[u8] =
        include_bytes!("../pki/testdata/cms_with_unsigned_archival.der");

    #[test]
    fn plain_signature_is_not_ltv() {
        let status = check_ltv_status(CMS_PLAIN);
        assert!(!status.ltv_enabled());
        assert!(!status.has_crl);
        assert!(!status.has_ocsp);
        assert!(status
            .details
            .iter()
            .any(|d| d.contains("No signed revocation data")));
    }

    #[test]
    fn embedded_crls_are_reported_but_not_counted() {
        // The crls field is not part of what the signer signed: RFC 5652 puts the
        // signature over the signed attributes. Anyone can add entries here.
        let status = check_ltv_status(CMS_WITH_CRL);
        assert!(status.has_crl);
        assert!(!status.ltv_enabled(), "unsigned material must not count");
        assert!(status.has_unauthenticated_material());
        assert!(status
            .details
            .iter()
            .any(|d| d.contains("outside the signature")));
    }

    #[test]
    fn an_unsigned_archival_attribute_is_not_evidence() {
        // The reported attack: unsigned attributes are outside the signature, so
        // a third party can staple one onto a finished document and the signature
        // still verifies. Nothing there speaks for the signer.
        let status = check_ltv_status(CMS_UNSIGNED_ARCHIVAL);

        assert!(!status.ltv_enabled(), "unsigned material must not count");
        assert!(status.has_unauthenticated_material());
        assert!(status
            .details
            .iter()
            .any(|d| d.contains("outside the signature")));
    }

    #[test]
    fn detects_revocation_archival_attribute() {
        let status = check_ltv_status(CMS_WITH_ARCHIVAL);
        assert!(status.has_revocation_archival);
        assert!(status.ltv_enabled());
        // The archival container is not itemized, so its mere presence must not
        // be reported as a standalone OCSP response.
        assert!(!status.has_ocsp);
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
