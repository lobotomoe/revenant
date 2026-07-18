//! SOAP implementation of the [`SigningTransport`] trait, plus the standalone
//! server-side verify and certificate-enumeration operations.
//!
//! Input is validated before hitting the network -- empty data, wrong hash
//! length, and non-PDF input fail fast (fail-loud) rather than wasting a round
//! trip on a request the appliance will reject.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;

use crate::constants::{DEFAULT_MAX_RETRIES, PDF_MAGIC, SHA1_DIGEST_SIZE};
use crate::net::protocol::SigningTransport;
use crate::net::soap::send_soap;
use crate::net::soap_envelope::{
    build_enum_certificates_envelope, build_sign_envelope, build_sign_hash_envelope,
    build_verify_envelope, SIGNATURE_TYPE_CMS, SIGNATURE_TYPE_FIELD_VERIFY,
};
use crate::net::soap_parsers::{
    parse_enum_certificates_response, parse_sign_response, parse_verify_response,
    ServerVerifyResult,
};
use crate::net::transport::Transport;
use crate::{Result, RevenantError};

/// DSS operation names for the `SOAPAction` header.
const ACTION_SIGN: &str = "DssSign";
const ACTION_VERIFY: &str = "DssVerify";

fn to_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A [`SigningTransport`] backed by a CoSign DSS SOAP endpoint.
#[derive(Debug)]
pub struct SoapSigningTransport {
    transport: Arc<Transport>,
    url: String,
}

impl SoapSigningTransport {
    /// Create a transport for `url`, sharing the given [`Transport`] (and its
    /// host-TLS cache) with the rest of the application.
    #[must_use]
    pub fn new(transport: Arc<Transport>, url: impl Into<String>) -> Self {
        Self {
            transport,
            url: url.into(),
        }
    }

    fn send_and_parse(&self, envelope: &str, timeout: Duration) -> Result<Vec<u8>> {
        // Signing is not idempotent: never auto-retry (max_retries = 0), or a
        // lost response could make the appliance sign the document twice.
        let response = send_soap(
            self.transport.as_ref(),
            &self.url,
            envelope,
            ACTION_SIGN,
            timeout,
            0,
        )?;
        let cms = parse_sign_response(&response)?;
        log::info!("Received CMS signature: {} bytes", cms.len());
        Ok(cms)
    }
}

impl SigningTransport for SoapSigningTransport {
    fn url(&self) -> Option<&str> {
        Some(&self.url)
    }

    fn sign_data(
        &self,
        data: &[u8],
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(RevenantError::Other("Cannot sign empty data.".to_owned()));
        }
        log::info!("Signing data via SOAP: {} bytes", data.len());
        let envelope =
            build_sign_envelope(username, password, SIGNATURE_TYPE_CMS, &to_base64(data));
        self.send_and_parse(&envelope, timeout)
    }

    fn sign_hash(
        &self,
        hash: &[u8],
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        if hash.len() != SHA1_DIGEST_SIZE {
            return Err(RevenantError::Other(format!(
                "Expected {SHA1_DIGEST_SIZE}-byte SHA-1 hash, got {} bytes.",
                hash.len()
            )));
        }
        log::debug!("Signing SHA-1 hash via SOAP: {} bytes", hash.len());
        let envelope =
            build_sign_hash_envelope(username, password, SIGNATURE_TYPE_CMS, &to_base64(hash));
        self.send_and_parse(&envelope, timeout)
    }

    fn sign_pdf_detached(
        &self,
        pdf: &[u8],
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        if !pdf.starts_with(PDF_MAGIC) {
            return Err(RevenantError::Pdf(
                "Input does not appear to be a PDF file.".to_owned(),
            ));
        }
        log::info!("Signing PDF (detached) via SOAP: {} bytes", pdf.len());
        let envelope = build_sign_envelope(username, password, SIGNATURE_TYPE_CMS, &to_base64(pdf));
        self.send_and_parse(&envelope, timeout)
    }

    fn enum_certificates(
        &self,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<Vec<Vec<u8>>> {
        enum_certificates(
            self.transport.as_ref(),
            &self.url,
            username,
            password,
            timeout,
        )
    }
}

/// Verify a signed PDF server-side via `DssVerify`. Never fails -- every error
/// is captured in the returned [`ServerVerifyResult`]. No authentication needed.
#[must_use]
pub fn verify_pdf_server(
    transport: &Transport,
    url: &str,
    pdf: &[u8],
    timeout: Duration,
) -> ServerVerifyResult {
    log::info!("Server-side verify: {} bytes, url={url}", pdf.len());
    let envelope = build_verify_envelope(&to_base64(pdf), SIGNATURE_TYPE_FIELD_VERIFY);
    match send_soap(
        transport,
        url,
        &envelope,
        ACTION_VERIFY,
        timeout,
        DEFAULT_MAX_RETRIES,
    ) {
        Ok(response) => parse_verify_response(&response),
        Err(e) => {
            log::warn!("Server verify failed: {e}");
            ServerVerifyResult::Failed(e.to_string())
        }
    }
}

/// Enumerate the user's certificates via the SAPI enum-certificates operation.
/// Returns DER-encoded X.509 certificates.
///
/// # Errors
///
/// Returns [`RevenantError::Auth`] on bad credentials, or another
/// [`RevenantError`] on server or transport failure.
pub fn enum_certificates(
    transport: &Transport,
    url: &str,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<Vec<Vec<u8>>> {
    log::info!("Enumerating certificates: url={url}");
    let envelope = build_enum_certificates_envelope(username, password);
    // Enumeration is idempotent -- safe to retry, unlike signing.
    let response = send_soap(
        transport,
        url,
        &envelope,
        ACTION_SIGN,
        timeout,
        DEFAULT_MAX_RETRIES,
    )?;
    parse_enum_certificates_response(&response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport() -> SoapSigningTransport {
        SoapSigningTransport::new(
            Arc::new(Transport::new()),
            "https://ca.gov.am/SAPIWS/DSS.asmx",
        )
    }

    #[test]
    fn url_is_reported() {
        assert_eq!(transport().url(), Some("https://ca.gov.am/SAPIWS/DSS.asmx"));
    }

    #[test]
    fn sign_data_rejects_empty_input() {
        let err = transport()
            .sign_data(b"", "u", "p", Duration::from_secs(1))
            .unwrap_err();
        assert!(matches!(err, RevenantError::Other(_)));
    }

    #[test]
    fn sign_hash_rejects_wrong_length() {
        let err = transport()
            .sign_hash(b"too-short", "u", "p", Duration::from_secs(1))
            .unwrap_err();
        assert!(matches!(err, RevenantError::Other(_)));
    }

    #[test]
    fn sign_pdf_rejects_non_pdf() {
        let err = transport()
            .sign_pdf_detached(b"not a pdf", "u", "p", Duration::from_secs(1))
            .unwrap_err();
        assert!(matches!(err, RevenantError::Pdf(_)));
    }
}
