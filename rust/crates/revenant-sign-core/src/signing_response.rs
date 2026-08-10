//! Proof that a signing service returned a signature over what was submitted.
//!
//! A signing call that reports success while handing back bytes nobody checked
//! is, from the caller's side, indistinguishable from one that worked -- the
//! failure only surfaces later, in whatever verifier the document eventually
//! reaches. So every response a workflow is about to return passes through here
//! first: the CMS must parse, carry the signer's certificate, and verify as a
//! signature over exactly the bytes that were sent.
//!
//! This deliberately says nothing about *who* signed. Whether the certificate is
//! one worth trusting is a chain question, answered separately and reported
//! rather than enforced; binding the response to the request is the part that
//! has to hold for every profile, online or offline.
//!
//! Submitting a document and submitting its digest are different situations, so
//! they are different functions. With the content in hand the binding can be
//! proven. With only a digest it cannot: what a service signs in response to a
//! pre-computed digest is service-defined, and services differ. That gap is
//! reported rather than papered over.

use crate::cms::{extract_digest_info, verify_signer_signature};
use crate::pdf::verify_detached_signature;
use crate::{Result, RevenantError};

/// Reject a response that is not a valid signature over exactly `content`.
///
/// # Errors
///
/// Returns [`RevenantError::SigningResponse`] when the response is not a
/// signature, or does not cover the submitted bytes.
pub(crate) fn check_response_over_content(
    cms_der: &[u8],
    content: &[u8],
    operation: &str,
) -> Result<()> {
    let result = verify_detached_signature(content, cms_der, None);
    if result.valid() {
        log::debug!(
            "{operation}: response verified against {} submitted bytes",
            content.len()
        );
        return Ok(());
    }

    let detail = result.details.join("\n  ");
    log::error!("{operation}: response verification failed: {detail}");
    Err(RevenantError::SigningResponse(format!(
        "{operation}: the signing service's response is not a valid signature over \
         the {} bytes submitted:\n  {detail}\nNothing was saved.",
        content.len()
    )))
}

/// Reject a response that is not a genuine signature, and report what it binds.
///
/// Only a digest was submitted, so there is no content to verify the signature
/// against and no way to prove the response covers the document that digest came
/// from. What is provable -- that the response is a real signature by the
/// certificate it carries -- is required. What is not provable is reported: if
/// the signed `messageDigest` differs from the digest submitted, the service did
/// not treat it as a pre-computed digest, and the signature must not be attached
/// to the document it was taken from.
///
/// # Errors
///
/// Returns [`RevenantError::SigningResponse`] when the response is not a
/// verifiable signature.
pub(crate) fn check_response_over_digest(
    cms_der: &[u8],
    digest: &[u8],
    operation: &str,
) -> Result<()> {
    let signature = verify_signer_signature(cms_der, None);
    if !signature.is_valid() {
        return Err(RevenantError::SigningResponse(format!(
            "{operation}: the signing service returned a response that is not a \
             verifiable signature ({}). Nothing was saved.",
            signature.describe()
        )));
    }

    // A signature that verified without content signed its signed attributes, and
    // those must carry exactly one well-formed messageDigest -- the verifier
    // rejects them otherwise. Its absence here means two readings of the same CMS
    // disagree, which is our bug, not a service quirk.
    let Some((_, signed_digest)) = extract_digest_info(cms_der) else {
        return Err(RevenantError::SigningResponse(format!(
            "{operation}: the response verified as a signature but declares no \
             messageDigest; the CMS could not be read consistently. Nothing was saved."
        )));
    };

    if signed_digest == digest {
        log::debug!("{operation}: response binds the submitted digest");
        return Ok(());
    }

    log::warn!(
        "{operation}: the signing service signed the submitted digest as content \
         rather than treating it as a pre-computed digest -- the response binds {}, \
         not the {} that was submitted. It is a valid signature, but not one that can \
         be attached to the document that digest came from; use sign_data on the \
         document itself for that.",
        hex::encode(&signed_digest),
        hex::encode(digest)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::sign_cms_detached;

    fn filler_cms() -> Vec<u8> {
        let mut cms = vec![0x30, 0x81, 0xC8];
        cms.extend(std::iter::repeat_n(0xAB, 200));
        cms
    }

    #[test]
    fn accepts_a_signature_over_the_submitted_bytes() {
        let content = b"the exact bytes that were submitted";
        let cms = sign_cms_detached(content);
        assert!(check_response_over_content(&cms, content, "sign_data").is_ok());
    }

    #[test]
    fn rejects_a_signature_over_different_bytes() {
        let cms = sign_cms_detached(b"some other document");
        let err = check_response_over_content(&cms, b"what we asked for", "sign_data").unwrap_err();
        assert!(matches!(err, RevenantError::SigningResponse(_)));
        assert!(err.to_string().contains("17 bytes submitted"));
    }

    #[test]
    fn rejects_filler_bytes_shaped_like_der() {
        let err = check_response_over_content(&filler_cms(), b"content", "sign_pdf_detached")
            .unwrap_err();
        assert!(matches!(err, RevenantError::SigningResponse(_)));
    }

    #[test]
    fn rejects_a_truncated_response() {
        let cms = sign_cms_detached(b"content");
        let err = check_response_over_content(&cms[..cms.len() / 2], b"content", "sign_data")
            .unwrap_err();
        assert!(matches!(err, RevenantError::SigningResponse(_)));
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let content = b"the exact bytes that were submitted";
        let mut cms = sign_cms_detached(content);
        // Flip one bit deep in the signature value, leaving the structure intact.
        let last = cms.len() - 1;
        cms[last] ^= 0x01;
        let err = check_response_over_content(&cms, content, "sign_data").unwrap_err();
        assert!(matches!(err, RevenantError::SigningResponse(_)));
    }

    #[test]
    fn a_digest_response_must_still_be_a_real_signature() {
        let err = check_response_over_digest(&filler_cms(), &[0u8; 20], "sign_hash").unwrap_err();
        assert!(matches!(err, RevenantError::SigningResponse(_)));
    }

    #[test]
    fn a_digest_response_that_binds_something_else_is_accepted_but_not_silently() {
        // The test signer hashes what it is handed, exactly as the production
        // appliance does with a submitted digest: the signature is genuine, and
        // binds sha256(digest) rather than the digest. That is reported, not
        // rejected -- the caller asked to sign these bytes, and they were signed.
        let digest = [0xABu8; 20];
        let cms = sign_cms_detached(&digest);
        assert!(check_response_over_digest(&cms, &digest, "sign_hash").is_ok());

        let (_, bound) = extract_digest_info(&cms).expect("signer declares a messageDigest");
        assert_ne!(
            bound, digest,
            "the response must not bind the digest itself"
        );
    }
}
