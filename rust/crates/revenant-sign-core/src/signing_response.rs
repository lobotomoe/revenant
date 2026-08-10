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

use crate::cms::verify_signer_signature;
use crate::pdf::verify_detached_signature;
use crate::{Result, RevenantError};

/// Reject a signing response that cannot be proven to be a usable signature.
///
/// `signed_content` is the exact byte string submitted for signing, when the
/// request determines it; the response must then verify as a signature over
/// those bytes. `None` belongs only where the submitted material does not
/// determine the signed content -- the signature itself is still verified, but
/// nothing ties it to a particular document.
///
/// # Errors
///
/// Returns [`RevenantError::SigningResponse`] when the response is not a
/// signature, or does not cover the submitted bytes.
pub(crate) fn check_signing_response(
    cms_der: &[u8],
    signed_content: Option<&[u8]>,
    operation: &str,
) -> Result<()> {
    let Some(content) = signed_content else {
        let signature = verify_signer_signature(cms_der, None);
        if signature.is_valid() {
            log::debug!("{operation}: response signature verified");
            return Ok(());
        }
        return Err(RevenantError::SigningResponse(format!(
            "{operation}: the signing service returned a response that is not a \
             verifiable signature ({}). Nothing was saved.",
            signature.describe()
        )));
    };

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::sign_cms_detached;

    #[test]
    fn accepts_a_signature_over_the_submitted_bytes() {
        let content = b"the exact bytes that were submitted";
        let cms = sign_cms_detached(content);
        assert!(check_signing_response(&cms, Some(content), "sign_data").is_ok());
    }

    #[test]
    fn rejects_a_signature_over_different_bytes() {
        let cms = sign_cms_detached(b"some other document");
        let err =
            check_signing_response(&cms, Some(b"what we asked for"), "sign_data").unwrap_err();
        assert!(matches!(err, RevenantError::SigningResponse(_)));
        assert!(err.to_string().contains("17 bytes submitted"));
    }

    #[test]
    fn rejects_filler_bytes_shaped_like_der() {
        let mut cms = vec![0x30, 0x81, 0xC8];
        cms.extend(std::iter::repeat_n(0xAB, 200));
        let err = check_signing_response(&cms, Some(b"content"), "sign_pdf_detached").unwrap_err();
        assert!(matches!(err, RevenantError::SigningResponse(_)));
    }

    #[test]
    fn rejects_a_truncated_response() {
        let cms = sign_cms_detached(b"content");
        let err = check_signing_response(&cms[..cms.len() / 2], Some(b"content"), "sign_data")
            .unwrap_err();
        assert!(matches!(err, RevenantError::SigningResponse(_)));
    }

    #[test]
    fn without_submitted_content_the_signature_alone_must_still_verify() {
        let cms = sign_cms_detached(b"anything at all");
        assert!(check_signing_response(&cms, None, "sign_hash").is_ok());

        let mut filler = vec![0x30, 0x81, 0xC8];
        filler.extend(std::iter::repeat_n(0xAB, 200));
        let err = check_signing_response(&filler, None, "sign_hash").unwrap_err();
        assert!(matches!(err, RevenantError::SigningResponse(_)));
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let content = b"the exact bytes that were submitted";
        let mut cms = sign_cms_detached(content);
        // Flip one bit deep in the signature value, leaving the structure intact.
        let last = cms.len() - 1;
        cms[last] ^= 0x01;
        let err = check_signing_response(&cms, Some(content), "sign_data").unwrap_err();
        assert!(matches!(err, RevenantError::SigningResponse(_)));
    }
}
