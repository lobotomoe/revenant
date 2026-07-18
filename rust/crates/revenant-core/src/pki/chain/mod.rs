//! PKI certificate chain validation against a Trust Service List.
//!
//! Extracts every certificate from a CMS SignedData blob, builds the chain from
//! the signer up (SKI/AKI matching, fetching missing intermediates via AIA),
//! and checks it against the trust anchors from a TSL. The chain-construction
//! and verification mechanics live in [`steps`]; this file is the orchestration.
//!
//! The result is deliberately tri-state ([`TrustStatus`]): `Trusted` (a trusted
//! anchor and the signatures verify), `Untrusted` (no trusted anchor in the
//! chain), or `Indeterminate` (the CMS could not be parsed, or an anchor matched
//! by key id but the cryptographic verification could not be completed). Chain
//! validation is best-effort and never aborts the surrounding verification.

mod steps;

use x509_cert::Certificate;

use super::cert;
use super::tsl::{TrustStore, TrustStoreCache};
use crate::constants::TSL_CACHE_TTL;
use crate::net::Transport;
use steps::{build_chain, fetch_intermediate, find_matching_anchor, verify_chain_crypto};

/// The trust verdict for a certificate chain.
///
/// Tri-state and best-effort: [`Trusted`](TrustStatus::Trusted) means a trusted
/// anchor was found and the chain's signatures verify; [`Untrusted`](TrustStatus::Untrusted)
/// means no trusted anchor is present; [`Indeterminate`](TrustStatus::Indeterminate)
/// means trust could not be decided (an unparseable CMS, or an anchor matched by
/// key id but cryptographic verification did not complete).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus {
    Trusted,
    Untrusted,
    Indeterminate,
}

/// Result of PKI certificate chain validation.
#[derive(Debug, Clone)]
pub struct ChainResult {
    /// The trust verdict for the chain.
    pub trust: TrustStatus,
    /// Service name of the matched trust anchor, if any.
    pub trust_anchor: Option<String>,
    pub chain_depth: usize,
    pub details: Vec<String>,
}

impl ChainResult {
    fn indeterminate(detail: impl Into<String>) -> Self {
        ChainResult {
            trust: TrustStatus::Indeterminate,
            trust_anchor: None,
            chain_depth: 0,
            details: vec![detail.into()],
        }
    }
}

/// Validate the certificate chain in a CMS blob against a trust store.
#[must_use]
pub fn validate_chain(
    transport: &Transport,
    cms_der: &[u8],
    trust_store: &TrustStore,
) -> ChainResult {
    validate_chain_inner(
        cms_der,
        trust_store,
        |url| fetch_intermediate(transport, url),
        verify_chain_crypto,
    )
}

/// High-level: fetch the trust store for a profile's TSL URL, then validate.
#[must_use]
pub fn validate_chain_for_profile(
    transport: &Transport,
    cache: &TrustStoreCache,
    cms_der: &[u8],
    tsl_url: &str,
) -> ChainResult {
    let store = cache.get_or_fetch(transport, tsl_url, TSL_CACHE_TTL);
    chain_result_for_store(transport, cms_der, store.as_ref())
}

fn chain_result_for_store(
    transport: &Transport,
    cms_der: &[u8],
    store: Option<&TrustStore>,
) -> ChainResult {
    match store {
        Some(store) => validate_chain(transport, cms_der, store),
        None => ChainResult::indeterminate("Chain: trust store unavailable"),
    }
}

/// The validation pipeline, with the network fetch and the cryptographic
/// verifier injected so every branch is unit-tested without a live transport.
fn validate_chain_inner(
    cms_der: &[u8],
    trust_store: &TrustStore,
    fetch: impl Fn(&str) -> Option<Certificate>,
    verify: impl Fn(&[Certificate], &[Certificate]) -> Result<(), String>,
) -> ChainResult {
    let Ok(cms_certs) = cert::all_certs_from_cms(cms_der) else {
        return ChainResult::indeterminate("Chain: failed to parse CMS certificates");
    };
    let Some(leaf) = cms_certs.first() else {
        return ChainResult::indeterminate("Chain: no certificates in CMS");
    };

    let mut details = vec![format!("Chain: signer cert: {}", cert::subject_dn(leaf))];

    // Pool = CMS certs + trust-anchor certs; the leaf stays at index 0.
    let mut pool = cms_certs;
    pool.extend(
        trust_store
            .ca_anchors
            .iter()
            .filter_map(|anchor| cert::parse_der(&anchor.cert_der).ok()),
    );

    let chain = build_chain(pool, &fetch);
    let chain_depth = chain.len();
    if chain_depth > 1 {
        let subjects: Vec<String> = chain.iter().map(cert::subject_dn).collect();
        details.push(format!(
            "Chain: depth {chain_depth}: {}",
            subjects.join(" -> ")
        ));
    }

    let Some(anchor_name) = find_matching_anchor(&chain, trust_store) else {
        details.push(format!(
            "Chain: no trusted CA found (operator: {})",
            trust_store.scheme_operator
        ));
        return ChainResult {
            trust: TrustStatus::Untrusted,
            trust_anchor: None,
            chain_depth,
            details,
        };
    };

    let anchors: Vec<Certificate> = trust_store
        .ca_anchors
        .iter()
        .filter_map(|anchor| cert::parse_der(&anchor.cert_der).ok())
        .collect();

    match verify(&chain, &anchors) {
        Ok(()) => {
            details.push(format!(
                "Chain: trusted ({anchor_name}, {})",
                trust_store.scheme_operator
            ));
            ChainResult {
                trust: TrustStatus::Trusted,
                trust_anchor: Some(anchor_name),
                chain_depth,
                details,
            }
        }
        Err(err) => {
            log::debug!("Cryptographic chain verification failed: {err}");
            details.push(format!(
                "Chain: anchor matched ({anchor_name}) but cryptographic verification failed"
            ));
            ChainResult {
                trust: TrustStatus::Indeterminate,
                trust_anchor: Some(anchor_name),
                chain_depth,
                details,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::tsl::TrustAnchor;
    use std::time::Instant;

    const CMS_LEAF_DIRECT: &[u8] = include_bytes!("../testdata/cms_leaf_direct.der");
    const CMS_LEAF_ROOT2: &[u8] = include_bytes!("../testdata/cms_leaf_root2.der");
    const CMS_CHAIN3: &[u8] = include_bytes!("../testdata/cms_chain3.der");
    const ROOT_DER: &[u8] = include_bytes!("../testdata/root.der");

    fn trust_store_with(anchor_der: &[u8], subject_name: &str, service_name: &str) -> TrustStore {
        let anchor = TrustAnchor {
            subject_name: subject_name.to_owned(),
            service_name: service_name.to_owned(),
            service_type: "CA/QC".to_owned(),
            status: "granted".to_owned(),
            cert_der: anchor_der.to_vec(),
        };
        TrustStore {
            anchors: vec![anchor.clone()],
            ca_anchors: vec![anchor],
            scheme_operator: "Test Operator".to_owned(),
            tsl_url: "https://example.com".to_owned(),
            fetched_at: Instant::now(),
        }
    }

    #[test]
    fn extracts_all_certs_from_cms() {
        let certs = cert::all_certs_from_cms(CMS_CHAIN3).unwrap();
        assert!(certs.len() >= 3, "got {}", certs.len());
    }

    #[test]
    fn validate_chain_trusted() {
        let store = trust_store_with(ROOT_DER, "CN=Test Root CA", "TestRootCA");
        let result = validate_chain(&Transport::new(), CMS_LEAF_DIRECT, &store);
        assert_eq!(result.trust, TrustStatus::Trusted);
        assert_eq!(result.trust_anchor.as_deref(), Some("TestRootCA"));
        assert!(result.chain_depth >= 2);
    }

    #[test]
    fn validate_chain_untrusted() {
        // Signed by root2, but the store only trusts root.
        let store = trust_store_with(ROOT_DER, "CN=Test Root CA", "TestRootCA");
        let result = validate_chain(&Transport::new(), CMS_LEAF_ROOT2, &store);
        assert_eq!(result.trust, TrustStatus::Untrusted);
        assert_eq!(result.trust_anchor, None);
    }

    #[test]
    fn validate_chain_no_certs_is_indeterminate() {
        let store = trust_store_with(ROOT_DER, "CN=Test Root CA", "TestRootCA");
        let result = validate_chain(&Transport::new(), b"\x30\x00", &store);
        assert_eq!(result.trust, TrustStatus::Indeterminate);
        assert_eq!(result.chain_depth, 0);
    }

    #[test]
    fn validate_chain_parse_failure_is_indeterminate() {
        let store = trust_store_with(ROOT_DER, "CN=Test Root CA", "TestRootCA");
        let result = validate_chain(&Transport::new(), b"not cms at all", &store);
        assert_eq!(result.trust, TrustStatus::Indeterminate);
        assert!(result.details[0].to_lowercase().contains("failed to parse"));
    }

    #[test]
    fn crypto_failure_falls_back_to_indeterminate() {
        let store = trust_store_with(ROOT_DER, "CN=Test Root CA", "TestRootCA");
        let result = validate_chain_inner(
            CMS_LEAF_DIRECT,
            &store,
            |_| None,
            |_chain, _anchors| Err("forced failure".to_owned()),
        );
        assert_eq!(result.trust, TrustStatus::Indeterminate); // fallback, not trusted
        assert_eq!(result.trust_anchor.as_deref(), Some("TestRootCA"));
        assert!(result
            .details
            .iter()
            .any(|d| d.contains("cryptographic verification failed")));
    }

    #[test]
    fn chain_result_for_missing_store_is_indeterminate() {
        let result = chain_result_for_store(&Transport::new(), b"\x30\x00", None);
        assert_eq!(result.trust, TrustStatus::Indeterminate);
        assert!(result.details[0].contains("unavailable"));
    }
}
