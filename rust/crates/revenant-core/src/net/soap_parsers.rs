//! Parsers for CoSign DSS SOAP responses.
//!
//! Responses are walked by local tag name (namespace prefixes stripped) over a
//! minimal DOM built on `quick-xml`, which never expands external or custom
//! entities and so is immune to entity-expansion (billion-laughs) attacks.

use base64::Engine as _;

use crate::constants::{MIN_SIGNATURE_B64_LEN, XML_PREVIEW_LENGTH};
use crate::xml::{find_all_values, find_attribute, find_value, parse_dom, Node};
use crate::{Result, RevenantError};

/// Minor-result suffix that marks an authentication failure.
const AUTH_MINOR_SUFFIX: &str = ":AuthenticationError";
/// Best-effort message fragments used only when the server omits the precise
/// `:AuthenticationError` minor code. Kept specific so an unrelated failure that
/// merely mentions "password" (e.g. "password store unavailable") is not
/// misreported as bad credentials, prompting a pointless re-login.
const AUTH_MESSAGE_HINTS: [&str; 6] = [
    "invalid password",
    "wrong password",
    "incorrect password",
    "invalid user name",
    "user name or password",
    "authentication failed",
];
/// How many characters of a malformed response to keep for the error preview,
/// before redaction and final truncation.
const RAW_PREVIEW_CHARS: usize = 500;

/// Decode base64, tolerating the embedded whitespace/newlines servers often use
/// to wrap long values -- the strict `base64` engine would otherwise reject them.
fn decode_b64(s: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(compact.as_bytes())
}

/// Whether a failure result denotes an authentication problem.
fn is_auth_error(result_minor: Option<&str>, msg: &str) -> bool {
    if result_minor.is_some_and(|m| m.ends_with(AUTH_MINOR_SUFFIX)) {
        return true;
    }
    let lower = msg.to_lowercase();
    AUTH_MESSAGE_HINTS.iter().any(|hint| lower.contains(hint))
}

/// Redact credential-bearing elements and truncate a malformed response for
/// safe inclusion in an error message. The password never appears, even if the
/// server echoed the request back.
fn redact_and_truncate(xml: &str) -> String {
    let preview: String = xml.chars().take(RAW_PREVIEW_CHARS).collect();
    let redacted = redact_tag_content(&preview, "LogonPassword");
    let redacted = redact_tag_content(&redacted, "Name");
    redacted.chars().take(XML_PREVIEW_LENGTH).collect()
}

/// Replace the text content of every `<[prefix:]tag>...</...>` element with
/// `[REDACTED]`, leaving other markup intact. Closing tags and unrelated
/// elements are skipped, so nothing spurious is inserted.
fn redact_tag_content(s: &str, tag: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(open_end) = find_open_tag(rest, tag) {
        out.push_str(&rest[..open_end]); // keep "<...tag>"
        let after = &rest[open_end..];
        let cut = after.find('<').unwrap_or(after.len());
        out.push_str("[REDACTED]");
        rest = &after[cut..];
    }
    out.push_str(rest);
    out
}

/// Byte offset just past the next opening tag whose local name equals `tag`,
/// skipping closing tags and unrelated elements.
fn find_open_tag(s: &str, tag: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = s[from..].find('<') {
        let lt = from + rel;
        let after_lt = &s[lt + 1..];
        if after_lt.starts_with('/') {
            from = lt + 1;
            continue;
        }
        let gt_rel = after_lt.find('>')?;
        let inner = &after_lt[..gt_rel];
        let local = inner.rsplit(':').next().unwrap_or(inner);
        let local_name = local.split_whitespace().next().unwrap_or(local);
        let past_gt = lt + 1 + gt_rel + 1;
        if local_name == tag {
            return Some(past_gt);
        }
        from = past_gt;
    }
    None
}

fn parse_dom_or_error(xml: &str) -> Result<Node> {
    parse_dom(xml).map_err(|e| {
        let preview = redact_and_truncate(xml);
        RevenantError::Other(format!("Invalid XML response: {e}\nRaw: {preview}"))
    })
}

/// Message precedence for a non-success response: message, then minor, then
/// major, else "Unknown error".
fn failure_message(
    result_message: Option<String>,
    result_minor: Option<&str>,
    result_major: Option<String>,
) -> String {
    result_message
        .or_else(|| result_minor.map(str::to_owned))
        .or(result_major)
        .unwrap_or_else(|| "Unknown error".to_owned())
}

/// Parse a `DssSign` response, returning the DER-encoded CMS signature.
///
/// # Errors
///
/// Returns [`RevenantError::Auth`] on an authentication failure,
/// [`RevenantError::Server`] on any other server rejection, and
/// [`RevenantError::Other`] on malformed XML or base64.
pub fn parse_sign_response(xml: &str) -> Result<Vec<u8>> {
    let root = parse_dom_or_error(xml)?;
    let result_major = find_value(&root, "ResultMajor");
    let result_minor = find_value(&root, "ResultMinor");
    let result_message = find_value(&root, "ResultMessage");

    // Prefer the signature-specific element; `Base64Data` is only a fallback, so
    // an echoed input document never gets mistaken for the signature.
    let cms_b64 = ["Base64Signature", "Base64Data"]
        .into_iter()
        .find_map(|tag| find_value(&root, tag).filter(|v| v.len() > MIN_SIGNATURE_B64_LEN));

    if result_major
        .as_deref()
        .is_some_and(|m| m.ends_with(":Success"))
    {
        let b64 = cms_b64.ok_or_else(|| {
            RevenantError::Server("Server returned Success but no signature data.".to_owned())
        })?;
        return decode_b64(&b64)
            .map_err(|e| RevenantError::Other(format!("Invalid Base64 in server response: {e}")));
    }

    let msg = failure_message(result_message, result_minor.as_deref(), result_major);
    if is_auth_error(result_minor.as_deref(), &msg) {
        return Err(RevenantError::Auth(format!("Authentication failed: {msg}")));
    }
    Err(RevenantError::Server(format!("Signing failed: {msg}")))
}

/// Parse an enum-certificates response into DER-encoded X.509 certificates.
///
/// # Errors
///
/// Returns [`RevenantError::Auth`] / [`RevenantError::Server`] on a server
/// rejection, or [`RevenantError::Other`] on malformed XML.
pub fn parse_enum_certificates_response(xml: &str) -> Result<Vec<Vec<u8>>> {
    let root = parse_dom_or_error(xml)?;
    let result_major = find_value(&root, "ResultMajor");
    let result_minor = find_value(&root, "ResultMinor");
    let result_message = find_value(&root, "ResultMessage");

    if result_major
        .as_deref()
        .is_some_and(|m| m.ends_with(":Success"))
    {
        let mut b64s = Vec::new();
        find_all_values(&root, "AvailableCertificate", &mut b64s);
        let mut certs = Vec::with_capacity(b64s.len());
        for b64 in b64s {
            match decode_b64(&b64) {
                Ok(der) => certs.push(der),
                Err(e) => log::warn!("Skipping malformed certificate Base64: {e}"),
            }
        }
        return Ok(certs);
    }

    let msg = failure_message(result_message, result_minor.as_deref(), result_major);
    if is_auth_error(result_minor.as_deref(), &msg) {
        return Err(RevenantError::Auth(format!("Authentication failed: {msg}")));
    }
    Err(RevenantError::Server(format!(
        "enum-certificates failed: {msg}"
    )))
}

/// The outcome of a server-side `DssVerify`.
#[derive(Debug, Clone)]
pub enum ServerVerifyResult {
    /// The server verified the signature, reporting the signer details it found.
    Verified {
        signer_name: Option<String>,
        sign_time: Option<String>,
        certificate_status: Option<String>,
    },
    /// Verification did not succeed, or the server was unreachable or returned an
    /// error; carries a human-readable reason.
    Failed(String),
}

/// Parse a `DssVerify` response. Never fails -- every error is captured in the
/// returned [`ServerVerifyResult`].
#[must_use]
pub fn parse_verify_response(xml: &str) -> ServerVerifyResult {
    let root = match parse_dom(xml) {
        Ok(root) => root,
        Err(e) => return ServerVerifyResult::Failed(format!("Invalid XML response: {e}")),
    };

    let result_major = find_value(&root, "ResultMajor");
    let result_message = find_value(&root, "ResultMessage");
    let signer_name = find_attribute(&root, "SignedFieldInfo", "SignerName");
    let sign_time = find_attribute(&root, "SignedFieldInfo", "SignatureTime");
    let certificate_status = find_attribute(&root, "FieldStatus", "CertificateStatus");

    if result_major
        .as_deref()
        .is_some_and(|m| m.ends_with(":Success"))
    {
        return ServerVerifyResult::Verified {
            signer_name,
            sign_time,
            certificate_status,
        };
    }

    let error = result_message.unwrap_or_else(|| "Server returned non-success result".to_owned());
    ServerVerifyResult::Failed(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGN_SUCCESS: &str = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <SignResponse xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
      <Result>
        <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:Success</ResultMajor>
      </Result>
      <SignatureObject>
        <Base64Signature>TUlJQ2FiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU4=</Base64Signature>
      </SignatureObject>
    </SignResponse>
  </soap:Body>
</soap:Envelope>"#;

    #[test]
    fn sign_success_returns_decoded_signature() {
        let cms = parse_sign_response(SIGN_SUCCESS).unwrap();
        assert_eq!(
            cms,
            decode_b64("TUlJQ2FiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU4=").unwrap()
        );
    }

    #[test]
    fn base64_with_embedded_newlines_decodes() {
        let long = "TUlJQ2FiY2RlZmdoaWprbG1ub3Bx\ncnN0dXZ3eHl6QUJDREVGR0hJSktMTU4=";
        let xml = format!(
            r"<Env><Result><ResultMajor>x:Success</ResultMajor></Result><Base64Data>{long}</Base64Data></Env>"
        );
        let cms = parse_sign_response(&xml).unwrap();
        assert_eq!(cms, decode_b64(long).unwrap());
    }

    #[test]
    fn sign_auth_error_maps_to_auth() {
        let xml = r"<Env><Result>
            <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError</ResultMajor>
            <ResultMinor>urn:com:arx:AuthenticationError</ResultMinor>
            <ResultMessage>Invalid password</ResultMessage>
        </Result></Env>";
        let err = parse_sign_response(xml).unwrap_err();
        assert!(matches!(err, RevenantError::Auth(_)), "got {err:?}");
    }

    #[test]
    fn auth_heuristic_is_specific() {
        // Message-only auth hint (no minor code) is detected...
        assert!(is_auth_error(None, "Invalid password for user"));
        assert!(is_auth_error(None, "Authentication failed"));
        // ...but an unrelated failure that merely mentions "password" is not.
        assert!(!is_auth_error(
            None,
            "Signing key password store unavailable"
        ));
        assert!(!is_auth_error(None, "Internal appliance failure"));
        // The precise minor code always wins.
        assert!(is_auth_error(
            Some("urn:com:arx:AuthenticationError"),
            "anything"
        ));
    }

    #[test]
    fn sign_server_error_maps_to_server() {
        let xml = r"<Env><Result>
            <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:ResponderError</ResultMajor>
            <ResultMessage>Internal appliance failure</ResultMessage>
        </Result></Env>";
        let err = parse_sign_response(xml).unwrap_err();
        match err {
            RevenantError::Server(m) => assert!(m.contains("Internal appliance failure")),
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn sign_success_without_signature_is_server_error() {
        let xml = r"<Env><Result><ResultMajor>x:Success</ResultMajor></Result></Env>";
        assert!(matches!(
            parse_sign_response(xml).unwrap_err(),
            RevenantError::Server(_)
        ));
    }

    #[test]
    fn enum_certificates_collects_all() {
        let a = base64::engine::general_purpose::STANDARD.encode(b"cert-a");
        let b = base64::engine::general_purpose::STANDARD.encode(b"cert-b");
        let xml = format!(
            r"<Env><Result><ResultMajor>x:Success</ResultMajor></Result>
            <AvailableCertificate>{a}</AvailableCertificate>
            <AvailableCertificate>{b}</AvailableCertificate></Env>"
        );
        let certs = parse_enum_certificates_response(&xml).unwrap();
        assert_eq!(certs, vec![b"cert-a".to_vec(), b"cert-b".to_vec()]);
    }

    #[test]
    fn verify_success_extracts_attributes() {
        let xml = r#"<Env>
            <Result><ResultMajor>x:Success</ResultMajor></Result>
            <SignedFieldInfo SignerName="John Doe 12345" SignatureTime="2026-01-02T03:04:05Z"/>
            <FieldStatus CertificateStatus="valid"/>
        </Env>"#;
        let result = parse_verify_response(xml);
        let ServerVerifyResult::Verified {
            signer_name,
            sign_time,
            certificate_status,
        } = result
        else {
            panic!("expected Verified, got {result:?}");
        };
        assert_eq!(signer_name.as_deref(), Some("John Doe 12345"));
        assert_eq!(sign_time.as_deref(), Some("2026-01-02T03:04:05Z"));
        assert_eq!(certificate_status.as_deref(), Some("valid"));
    }

    #[test]
    fn verify_failure_captures_message_without_raising() {
        let xml = r"<Env><Result>
            <ResultMajor>x:RequesterError</ResultMajor>
            <ResultMessage>Document not signed</ResultMessage>
        </Result></Env>";
        let result = parse_verify_response(xml);
        let ServerVerifyResult::Failed(error) = result else {
            panic!("expected Failed, got {result:?}");
        };
        assert_eq!(error, "Document not signed");
    }

    #[test]
    fn verify_malformed_xml_is_captured() {
        let result = parse_verify_response("<Env><unclosed>");
        let ServerVerifyResult::Failed(error) = result else {
            panic!("expected Failed, got {result:?}");
        };
        assert!(error.contains("Invalid XML"));
    }

    #[test]
    fn redaction_hides_password_and_name() {
        let xml = "<a><arx:LogonPassword>hunter2</arx:LogonPassword><Name>Secret User</Name></a>";
        let out = redact_tag_content(xml, "LogonPassword");
        let out = redact_tag_content(&out, "Name");
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("Secret User"));
        assert!(out.contains("<arx:LogonPassword>[REDACTED]</arx:LogonPassword>"));
        assert!(out.contains("<Name>[REDACTED]</Name>"));
    }

    #[test]
    fn redaction_leaves_other_elements_intact() {
        let xml = "<a><Base64Data>keepme</Base64Data><Name>x</Name></a>";
        let out = redact_tag_content(xml, "Name");
        assert!(out.contains("<Base64Data>keepme</Base64Data>"));
        assert!(out.contains("<Name>[REDACTED]</Name>"));
    }
}
