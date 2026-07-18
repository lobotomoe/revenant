//! Signature verification wired to a network-backed certificate-chain validator.
//!
//! The [`crate::pdf::verify`] layer is deliberately offline and pure: it takes an
//! optional [`ChainValidator`] closure rather than reaching for a transport.
//! This module supplies that closure, backed by a live [`Transport`] and a
//! [`TrustStoreCache`], so callers get chain validation against a profile's
//! Trust Service List. Passing `tsl_url = None` runs the fully offline checks.

use crate::net::Transport;
use crate::pdf::{
    verify_all_embedded_signatures, verify_detached_signature, verify_embedded_signature,
    ChainValidator, VerificationResult,
};
use crate::pki::{validate_chain_for_profile, TrustStoreCache};
use crate::Result;

/// Run `f` with a chain validator bound to `tsl_url`, or with `None` when no TSL
/// is given. The validator fetches (and caches) the trust store on demand and
/// validates the signer's chain against it; it never aborts the surrounding
/// verification -- an unreachable TSL yields an indeterminate chain result.
fn with_chain_validator<R>(
    transport: &Transport,
    cache: &TrustStoreCache,
    tsl_url: Option<&str>,
    f: impl FnOnce(Option<&ChainValidator<'_>>) -> R,
) -> R {
    match tsl_url {
        Some(tsl) => {
            let validator =
                move |cms: &[u8]| Some(validate_chain_for_profile(transport, cache, cms, tsl));
            f(Some(&validator))
        }
        None => f(None),
    }
}

/// Verify the last embedded signature in a PDF, optionally validating the chain
/// against a profile's TSL.
///
/// `expected_hash` is the exact hash sent to the appliance (post-sign path);
/// pass `None` to verify against the CMS-declared digest instead.
pub fn verify_pdf(
    transport: &Transport,
    cache: &TrustStoreCache,
    pdf: &[u8],
    expected_hash: Option<&[u8]>,
    tsl_url: Option<&str>,
) -> VerificationResult {
    with_chain_validator(transport, cache, tsl_url, |validator| {
        verify_embedded_signature(pdf, expected_hash, validator)
    })
}

/// Verify every embedded signature in a PDF, optionally validating each chain
/// against a profile's TSL.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`](crate::RevenantError::Pdf) if the PDF has no
/// embedded signatures.
pub fn verify_pdf_all(
    transport: &Transport,
    cache: &TrustStoreCache,
    pdf: &[u8],
    tsl_url: Option<&str>,
) -> Result<Vec<VerificationResult>> {
    with_chain_validator(transport, cache, tsl_url, |validator| {
        verify_all_embedded_signatures(pdf, validator)
    })
}

/// Verify a detached CMS/PKCS#7 signature against the original data, optionally
/// validating the chain against a profile's TSL.
pub fn verify_detached(
    transport: &Transport,
    cache: &TrustStoreCache,
    data: &[u8],
    cms_der: &[u8],
    tsl_url: Option<&str>,
) -> VerificationResult {
    with_chain_validator(transport, cache, tsl_url, |validator| {
        verify_detached_signature(data, cms_der, validator)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::{
        compute_byterange_hash, insert_cms, prepare_pdf_with_sig_field, PrepareOptions, PreparedPdf,
    };
    use crate::pki::TrustStatus;

    const BLANK_LETTER: &[u8] = include_bytes!("../pdf/testdata/blank_letter.pdf");

    /// Prepare + fake-sign a PDF, returning (signed_pdf, sha1_of_byterange).
    fn prepare_and_fake_sign() -> (Vec<u8>, [u8; 20]) {
        let opts = PrepareOptions {
            name: Some("Verify Wiring"),
            ..Default::default()
        };
        let PreparedPdf {
            bytes: prepared,
            contents_hex_offset: hex_start,
            contents_hex_len: hex_len,
        } = prepare_pdf_with_sig_field(BLANK_LETTER, &opts).unwrap();
        let hash = compute_byterange_hash(&prepared, hex_start, hex_len).unwrap();
        let mut cms = vec![0x30, 0x81, 0xC8];
        cms.extend(std::iter::repeat_n(0xAB, 200));
        let signed = insert_cms(&prepared, hex_start, hex_len, &cms).unwrap();
        (signed, hash)
    }

    #[test]
    fn verify_pdf_without_tsl_is_offline_and_intact() {
        let (signed, hash) = prepare_and_fake_sign();
        let transport = Transport::new();
        let cache = TrustStoreCache::new();
        let result = verify_pdf(&transport, &cache, &signed, Some(&hash), None);
        // The fake CMS has intact byte-range integrity, but no real signature,
        // so full cryptographic validity does not hold.
        assert!(result.integrity_ok(), "{:?}", result.details);
        assert!(!result.valid());
        // No TSL -> chain not attempted.
        assert_eq!(result.trust_status, Some(TrustStatus::Indeterminate));
    }

    #[test]
    fn verify_pdf_all_without_tsl_returns_one_result() {
        let (signed, _hash) = prepare_and_fake_sign();
        let transport = Transport::new();
        let cache = TrustStoreCache::new();
        let results = verify_pdf_all(&transport, &cache, &signed, None).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].structure_ok);
    }

    #[test]
    fn verify_detached_without_tsl_matches_declared_digest() {
        // The committed CMS fixture signs SHA-256("test data").
        const CMS_LEAF: &[u8] = include_bytes!("../pki/testdata/cms_leaf_direct.der");
        let transport = Transport::new();
        let cache = TrustStoreCache::new();
        let result = verify_detached(&transport, &cache, b"test data", CMS_LEAF, None);
        assert!(result.structure_ok, "{:?}", result.details);
        assert!(result.hash_ok, "{:?}", result.details);
    }
}
