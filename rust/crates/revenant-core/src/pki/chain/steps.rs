//! Chain-construction and verification steps.
//!
//! The mechanics behind the [`super`] validation pipeline: building the chain
//! by SKI/AKI matching (fetching missing intermediates via AIA), matching a
//! trust anchor, and verifying each link cryptographically with `x509-verify`.

use x509_cert::Certificate;
use x509_verify::VerifyingKey;

use super::super::cert;
use super::super::tsl::TrustStore;
use crate::constants::{DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT_HTTP_GET, MAX_AIA_FETCHES};
use crate::net::Transport;

/// Hard cap on chain length, guarding against a cycle in issuer references.
const MAX_CHAIN_DEPTH: usize = 20;

/// Build a chain from the signer (pool index 0) upward via SKI/AKI matching,
/// fetching missing intermediates through AIA. Returns the ordered chain from
/// leaf to the highest issuer reachable.
pub(super) fn build_chain(
    mut pool: Vec<Certificate>,
    fetch: impl Fn(&str) -> Option<Certificate>,
) -> Vec<Certificate> {
    let mut chain_idx = vec![0usize];
    let mut current = 0usize;
    let mut fetched = 0u32;

    for _ in 0..MAX_CHAIN_DEPTH {
        if cert::is_self_signed(&pool[current]) {
            break;
        }
        let Some(aki) = cert::authority_key_id(&pool[current]) else {
            break;
        };

        let mut issuer = pool_index_by_ski(&pool, &aki, current);

        if issuer.is_none() && fetched < MAX_AIA_FETCHES {
            for url in cert::aia_ca_issuer_urls(&pool[current]) {
                let Some(fetched_cert) = fetch(&url) else {
                    continue;
                };
                fetched += 1;
                let matches = cert::subject_key_identifier(&fetched_cert).as_deref() == Some(&aki);
                let idx = pool.len();
                pool.push(fetched_cert);
                if matches {
                    issuer = Some(idx);
                    break;
                }
            }
        }

        let Some(issuer) = issuer else {
            break;
        };
        chain_idx.push(issuer);
        current = issuer;
    }

    chain_idx.into_iter().map(|i| pool[i].clone()).collect()
}

/// Index of a certificate in the pool whose SKI equals `key_id`, other than
/// `exclude`.
fn pool_index_by_ski(pool: &[Certificate], key_id: &[u8], exclude: usize) -> Option<usize> {
    pool.iter().enumerate().position(|(i, candidate)| {
        i != exclude && cert::subject_key_identifier(candidate).as_deref() == Some(key_id)
    })
}

/// Find which trust anchor the chain terminates at: first by SKI equality with
/// any chain cert, then by issuer-DN substring.
pub(super) fn find_matching_anchor(
    chain: &[Certificate],
    trust_store: &TrustStore,
) -> Option<String> {
    if chain.is_empty() {
        return None;
    }

    for cert in chain {
        let Some(cert_ski) = cert::subject_key_identifier(cert) else {
            continue;
        };
        for anchor in &trust_store.ca_anchors {
            if let Ok(anchor_cert) = cert::parse_der(&anchor.cert_der) {
                if cert::subject_key_identifier(&anchor_cert).as_deref() == Some(&cert_ski) {
                    return Some(anchor.service_name.clone());
                }
            }
        }
    }

    for cert in chain {
        let issuer_dn = cert::issuer_dn(cert);
        for anchor in &trust_store.ca_anchors {
            if !anchor.subject_name.is_empty() && issuer_dn.contains(&anchor.subject_name) {
                return Some(anchor.service_name.clone());
            }
        }
    }

    None
}

/// Fetch a single intermediate certificate via an AIA URL, or `None` on any
/// failure (best-effort). AIA URLs are frequently plain HTTP, which the
/// HTTPS-only transport refuses -- such fetches simply fail.
pub(super) fn fetch_intermediate(transport: &Transport, url: &str) -> Option<Certificate> {
    log::debug!("Fetching intermediate cert from {url}");
    match transport.get(url, DEFAULT_TIMEOUT_HTTP_GET, DEFAULT_MAX_RETRIES) {
        Ok(der) => cert::parse_der(&der).ok(),
        Err(err) => {
            log::debug!("Failed to fetch intermediate from {url}: {err}");
            None
        }
    }
}

/// Cryptographically verify a built chain: every adjacent link's signature, the
/// validity window of each certificate, and that the top links to a trust
/// anchor. `Err` carries a human-readable reason and downgrades the result.
pub(super) fn verify_chain_crypto(
    chain: &[Certificate],
    anchors: &[Certificate],
) -> Result<(), String> {
    let Some(top) = chain.last() else {
        return Err("empty chain".to_owned());
    };

    for cert in chain {
        if !cert::is_currently_valid(cert) {
            return Err(format!(
                "certificate outside its validity period: {}",
                cert::subject_dn(cert)
            ));
        }
    }

    // Every certificate above the leaf issues the one below it, so each must be a
    // CA authorized to sign certificates (RFC 5280), and its pathLenConstraint
    // must permit the number of intermediates beneath it. This stops a
    // wrongly issued end-entity certificate from being accepted as an intermediate.
    for (index, issuer) in chain.iter().enumerate().skip(1) {
        if !cert::is_ca_cert(issuer) {
            return Err(format!(
                "chain certificate is not a valid CA: {}",
                cert::subject_dn(issuer)
            ));
        }
        if let Some(max_intermediates) = cert::ca_path_len(issuer) {
            // Certs strictly between this issuer and the leaf (indices 1..index).
            let intermediates_below = index - 1;
            if intermediates_below > usize::from(max_intermediates) {
                return Err(format!(
                    "pathLenConstraint violated at {}: {intermediates_below} intermediate(s) below a limit of {max_intermediates}",
                    cert::subject_dn(issuer)
                ));
            }
        }
    }

    for pair in chain.windows(2) {
        // pair = [subject, issuer]: the issuer's key must verify the subject.
        verify_signed_by(&pair[1], &pair[0])?;
    }

    for anchor in anchors {
        if certs_equal(anchor, top) || verify_signed_by(anchor, top).is_ok() {
            return Ok(());
        }
    }
    Err("chain does not terminate at a trusted anchor".to_owned())
}

/// Whether `issuer`'s public key verifies `subject`'s signature.
fn verify_signed_by(issuer: &Certificate, subject: &Certificate) -> Result<(), String> {
    let key = VerifyingKey::try_from(issuer).map_err(|e| format!("unusable issuer key: {e}"))?;
    key.verify(subject)
        .map_err(|e| format!("signature verification failed: {e}"))
}

fn certs_equal(a: &Certificate, b: &Certificate) -> bool {
    use der::Encode;
    matches!((a.to_der(), b.to_der()), (Ok(x), Ok(y)) if x == y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::tsl::TrustAnchor;
    use std::time::Instant;

    const ROOT_DER: &[u8] = include_bytes!("../testdata/root.der");
    const INTER_DER: &[u8] = include_bytes!("../testdata/intermediate.der");
    const LEAF_DER: &[u8] = include_bytes!("../testdata/leaf.der");
    const LEAF_DIRECT_DER: &[u8] = include_bytes!("../testdata/leaf_direct.der");
    const LEAF_AIA_DER: &[u8] = include_bytes!("../testdata/leaf_aia.der");
    const ROOT2_DER: &[u8] = include_bytes!("../testdata/root2.der");
    const NO_AKI_DER: &[u8] = include_bytes!("../testdata/no_aki.der");

    fn cert(der: &[u8]) -> Certificate {
        cert::parse_der(der).unwrap()
    }

    fn no_fetch(_url: &str) -> Option<Certificate> {
        None
    }

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
    fn builds_full_chain_from_pool() {
        let pool = vec![cert(LEAF_DER), cert(INTER_DER), cert(ROOT_DER)];
        assert_eq!(build_chain(pool, no_fetch).len(), 3);
    }

    #[test]
    fn self_signed_only_is_depth_one() {
        assert_eq!(build_chain(vec![cert(ROOT_DER)], no_fetch).len(), 1);
    }

    #[test]
    fn no_aki_stops_at_depth_one() {
        assert_eq!(build_chain(vec![cert(NO_AKI_DER)], no_fetch).len(), 1);
    }

    #[test]
    fn builds_chain_via_aia_fetch() {
        // Pool has only the AIA leaf and the root; the intermediate must be
        // fetched via AIA.
        let pool = vec![cert(LEAF_AIA_DER), cert(ROOT_DER)];
        let chain = build_chain(pool, |url| {
            assert_eq!(url, "http://example.com/inter.crt");
            Some(cert(INTER_DER))
        });
        assert!(chain.len() >= 2, "got {}", chain.len());
    }

    #[test]
    fn matches_anchor_by_ski() {
        let store = trust_store_with(ROOT_DER, "CN=Test Root CA", "TestRootCA");
        assert_eq!(
            find_matching_anchor(&[cert(ROOT_DER)], &store).as_deref(),
            Some("TestRootCA")
        );
    }

    #[test]
    fn matches_anchor_by_issuer_dn_substring() {
        // The anchor cert is the root (SKI won't match the leaf), but its
        // subject_name is a substring of the leaf's issuer DN -- exercising the
        // second matching stage (issuer-DN substring), which is intentional.
        let store = trust_store_with(ROOT_DER, "CN=Test Intermediate", "InterAnchor");
        assert_eq!(
            find_matching_anchor(&[cert(LEAF_DER)], &store).as_deref(),
            Some("InterAnchor")
        );
    }

    #[test]
    fn no_matching_anchor_returns_none() {
        let store = trust_store_with(ROOT_DER, "CN=Nonexistent CA", "X");
        assert_eq!(find_matching_anchor(&[cert(LEAF_DER)], &store), None);
    }

    #[test]
    fn empty_chain_matches_nothing() {
        let store = trust_store_with(ROOT_DER, "CN=Test Root CA", "TestRootCA");
        assert_eq!(find_matching_anchor(&[], &store), None);
    }

    #[test]
    fn crypto_verifies_direct_leaf() {
        assert!(verify_chain_crypto(&[cert(LEAF_DIRECT_DER)], &[cert(ROOT_DER)]).is_ok());
    }

    #[test]
    fn crypto_verifies_three_level_chain() {
        let chain = [cert(LEAF_DER), cert(INTER_DER)];
        assert!(verify_chain_crypto(&chain, &[cert(ROOT_DER)]).is_ok());
    }

    #[test]
    fn crypto_rejects_wrong_anchor() {
        assert!(verify_chain_crypto(&[cert(LEAF_DIRECT_DER)], &[cert(ROOT2_DER)]).is_err());
    }

    #[test]
    fn ca_role_is_enforced() {
        // Real CAs qualify; an end-entity leaf does not.
        assert!(cert::is_ca_cert(&cert(ROOT_DER)));
        assert!(cert::is_ca_cert(&cert(INTER_DER)));
        assert!(!cert::is_ca_cert(&cert(LEAF_DER)));
        // A chain whose "issuer" is actually a non-CA leaf is rejected even
        // before signature math (here the leaf cannot issue itself).
        let err = verify_chain_crypto(&[cert(LEAF_DER), cert(LEAF_DER)], &[cert(ROOT_DER)]);
        assert!(err.is_err());
    }
}
