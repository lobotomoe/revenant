//! ETSI Trust Service List (TSL) parser and cache.
//!
//! Parses TSL XML documents (ETSI TS 119 612) into the set of trust-anchor
//! certificates a country publishes for qualified electronic signatures, used
//! for PKI chain validation.
//!
//! The [`cache`] submodule centralizes trust-store caching in an injectable
//! [`TrustStoreCache`] -- the same DI seam used by the config layer -- so
//! callers own the cache and tests exercise every path (fresh hit, miss,
//! stale-on-error) without the network.

mod cache;

use std::time::Instant;

use base64::Engine as _;

use crate::xml::{find_all_nodes, find_all_values, find_node, find_value, parse_dom};
use crate::{Result, RevenantError};

pub use cache::{fetch_trust_store, TrustStoreCache};

/// Service type suffix marking a qualified certificate authority.
const CA_SERVICE_TYPE: &str = "CA/QC";
/// Service status suffixes that denote an active (trusted) service.
const ACTIVE_STATUSES: [&str; 3] = ["granted", "accredited", "undersupervision"];
/// Marker separating the service-type URI prefix from its meaningful suffix.
const SVCTYPE_MARKER: &str = "/Svctype/";

/// A trusted service entry extracted from a TSL.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub subject_name: String,
    pub service_name: String,
    pub service_type: String,
    pub status: String,
    pub cert_der: Vec<u8>,
}

/// Parsed trust anchors from a TSL, with metadata.
///
/// `fetched_at` is a monotonic [`Instant`], so cache-freshness checks are immune
/// to wall-clock adjustments.
#[derive(Debug, Clone)]
pub struct TrustStore {
    pub anchors: Vec<TrustAnchor>,
    pub ca_anchors: Vec<TrustAnchor>,
    pub scheme_operator: String,
    pub tsl_url: String,
    pub fetched_at: Instant,
}

/// Parse an ETSI TSL XML document into a [`TrustStore`]. Pure -- no I/O.
///
/// # Errors
///
/// Returns [`RevenantError::Other`] if the bytes are not valid UTF-8 XML.
pub fn parse_tsl(xml_bytes: &[u8], tsl_url: &str) -> Result<TrustStore> {
    let xml = std::str::from_utf8(xml_bytes)
        .map_err(|e| RevenantError::Other(format!("TSL is not valid UTF-8: {e}")))?;
    let root = parse_dom(xml)
        .map_err(|e| RevenantError::Other(format!("Failed to parse TSL XML: {e}")))?;

    let scheme_operator = find_node(&root, "SchemeOperatorName")
        .and_then(|node| find_value(node, "Name"))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "Unknown".to_owned());

    let mut services = Vec::new();
    find_all_nodes(&root, "ServiceInformation", &mut services);

    let mut anchors = Vec::new();
    for svc in services {
        let type_uri = find_value(svc, "ServiceTypeIdentifier").unwrap_or_default();
        let service_type = service_type_suffix(&type_uri);

        let service_name = find_node(svc, "ServiceName")
            .and_then(|node| find_value(node, "Name"))
            .unwrap_or_default();

        let status = status_suffix(&find_value(svc, "ServiceStatus").unwrap_or_default());
        if !is_active_status(&status) {
            log::debug!("Skipping inactive service {service_name} (status={status})");
            continue;
        }

        // A service's certs all share the first published subject name.
        let subject_name = find_value(svc, "X509SubjectName").unwrap_or_default();

        let mut cert_b64s = Vec::new();
        find_all_values(svc, "X509Certificate", &mut cert_b64s);
        for b64 in cert_b64s {
            match decode_cert_b64(&b64) {
                Ok(cert_der) => anchors.push(TrustAnchor {
                    subject_name: subject_name.clone(),
                    service_name: service_name.clone(),
                    service_type: service_type.clone(),
                    status: status.clone(),
                    cert_der,
                }),
                Err(_) => log::warn!("Failed to decode certificate in service {service_name}"),
            }
        }
    }

    let ca_anchors: Vec<TrustAnchor> = anchors
        .iter()
        .filter(|anchor| anchor.service_type == CA_SERVICE_TYPE)
        .cloned()
        .collect();

    log::info!(
        "Parsed TSL: {} anchors ({} CA), operator={scheme_operator}",
        anchors.len(),
        ca_anchors.len(),
    );

    Ok(TrustStore {
        anchors,
        ca_anchors,
        scheme_operator,
        tsl_url: tsl_url.to_owned(),
        fetched_at: Instant::now(),
    })
}

/// Extract the meaningful suffix of a service-type URI, e.g.
/// `.../Svctype/CA/QC` -> `CA/QC`.
fn service_type_suffix(uri: &str) -> String {
    match uri.find(SVCTYPE_MARKER) {
        Some(idx) => uri[idx + SVCTYPE_MARKER.len()..].to_owned(),
        None => uri.to_owned(),
    }
}

/// Extract the status keyword of a status URI, e.g. `.../Svcstatus/granted`
/// -> `granted`.
fn status_suffix(uri: &str) -> String {
    match uri.rfind('/') {
        Some(idx) => uri[idx + 1..].to_owned(),
        None => uri.to_owned(),
    }
}

fn is_active_status(status: &str) -> bool {
    let lower = status.to_lowercase();
    ACTIVE_STATUSES.contains(&lower.as_str())
}

/// Decode a certificate's base64, tolerating the embedded newlines TSLs use to
/// wrap long values but rejecting genuinely invalid content.
fn decode_cert_b64(b64: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    let compact: String = b64.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(compact.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CA_B64: &str = "MIICyTCCAbGgAwIBAgIUc+D/OLA1d/dW5cFrQg2HviXUFzowDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVzdCBDQSAxMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowFDESMBAGA1UEAwwJVGVzdCBDQSAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwNzyFsFN8OAvo2l99sjHg/PXt7OoGpDCywCFRq+NGcDhX7VemYoNESXNooYR2kU8rCOcKEOqi/l3ez87UKF9C2HDgs4+j/L9tuTUzGOcUTfBidSH99psSGJvUefg9pqq1j+D22wIL37JMBnW8ZxfkvXTlETCguURSaEkbm9tHMwx5l1Kd0PYiYLv+oU+ThQSa05Y8+Hd4bImolAZzA8WNqR469KF2SePq/rV6G8U1l6pYBEKdEAOXVNFq6sT/p0dN/CPwyant7bZXRcqejyG9UZrkuTniOJlL1LGxSI/J0JKkvAJgsAdqJOCk4mVneMmU3aYUM4UdoL0ZPQP3IqcpwIDAQABoxMwETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAIyXXHFwIszwMoxYTe3SCOdtlE6bAwOEqaZBODLVXjNqgV16QvwVV2eL2Jox3Ya7ErVk7NsnRW2N8l1+mO5vF8a5aUxXdyyJ+Ht0PNkr3rmc739OgUzZgLikFVwJxpbADNuYC3gkWEDmBn4V08HW8x/yfFCPMLSTl9qpqUmjEpWPvJsMN9D1Vp9WaI1vAT5PSU8zzLeCQfRVFH6rrnsBRE2PUnmfx+r22M8yZl3cAlyciMyobdQtRy/KFru8/LXpWXKut/ZqC8aMoAuZJwJhhHFH2QrvIkav6Aqus8LBf6KNfhT96gnfI4N8/4UrmY/kEzapJPz414vJTb6S2bviK6";

    /// Build a one-service TSL document; `subject` omits `X509SubjectName` when
    /// `None`.
    fn tsl_xml(
        operator: &str,
        service: &str,
        status: &str,
        cert_b64: &str,
        subject: Option<&str>,
    ) -> Vec<u8> {
        let subject_el = subject.map_or_else(String::new, |s| {
            format!("<DigitalId><X509SubjectName>{s}</X509SubjectName></DigitalId>")
        });
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation><SchemeOperatorName><Name xml:lang="en">{operator}</Name></SchemeOperatorName></SchemeInformation>
  <TrustServiceProviderList><TrustServiceProvider><TSPServices><TSPService><ServiceInformation>
    <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
    <ServiceName><Name xml:lang="en">{service}</Name></ServiceName>
    <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/{status}</ServiceStatus>
    <ServiceDigitalIdentity>
      <DigitalId><X509Certificate>{cert_b64}</X509Certificate></DigitalId>
      {subject_el}
    </ServiceDigitalIdentity>
  </ServiceInformation></TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList>
</TrustServiceStatusList>"#
        )
        .into_bytes()
    }

    #[test]
    fn parse_minimal_tsl() {
        let xml = tsl_xml(
            "Test Operator",
            "Test CA",
            "granted",
            TEST_CA_B64,
            Some("CN=Test CA 1"),
        );
        let store = parse_tsl(&xml, "https://example.com/tsl.xml").unwrap();
        assert_eq!(store.scheme_operator, "Test Operator");
        assert_eq!(store.tsl_url, "https://example.com/tsl.xml");
        assert_eq!(store.anchors.len(), 1);
        assert_eq!(store.ca_anchors.len(), 1);

        let anchor = &store.ca_anchors[0];
        assert_eq!(anchor.service_name, "Test CA");
        assert_eq!(anchor.service_type, "CA/QC");
        assert_eq!(anchor.status, "granted");
        assert_eq!(anchor.subject_name, "CN=Test CA 1");
        assert!(!anchor.cert_der.is_empty());
    }

    #[test]
    fn parse_empty_tsl() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation><SchemeOperatorName><Name xml:lang="en">Empty</Name></SchemeOperatorName></SchemeInformation>
</TrustServiceStatusList>"#;
        let store = parse_tsl(xml, "").unwrap();
        assert_eq!(store.scheme_operator, "Empty");
        assert!(store.anchors.is_empty());
        assert!(store.ca_anchors.is_empty());
    }

    #[test]
    fn skips_inactive_services() {
        let xml = tsl_xml("Test", "Some CA", "withdrawn", "AAAA", None);
        assert!(parse_tsl(&xml, "").unwrap().anchors.is_empty());
    }

    #[test]
    fn malformed_xml_is_error() {
        assert!(parse_tsl(b"not xml at all", "").is_err());
    }

    #[test]
    fn invalid_base64_cert_is_skipped() {
        let xml = tsl_xml("Test", "Some CA", "granted", "!!!not-valid-base64!!!", None);
        assert!(parse_tsl(&xml, "").unwrap().anchors.is_empty());
    }

    #[test]
    fn missing_subject_name_parses_with_empty() {
        let xml = tsl_xml("Test", "Some CA", "granted", TEST_CA_B64, None);
        let store = parse_tsl(&xml, "").unwrap();
        assert_eq!(store.anchors.len(), 1);
        assert_eq!(store.anchors[0].subject_name, "");
    }

    #[test]
    fn service_type_suffix_without_marker_returns_uri() {
        assert_eq!(
            service_type_suffix("http://example.com/something"),
            "http://example.com/something"
        );
    }
}
