//! SOAP envelope builders for CoSign DSS requests.
//!
//! The exact indentation and namespace layout are byte-exact and proven against
//! the live appliance; reformatting them is a needless risk. All user-supplied
//! strings are XML-escaped internally -- callers pass raw values.

/// Detached CMS/PKCS#7 signature (RFC 3369).
pub const SIGNATURE_TYPE_CMS: &str = "urn:ietf:rfc:3369";
/// XML digital signature (RFC 3275).
pub const SIGNATURE_TYPE_XMLDSIG: &str = "urn:ietf:rfc:3275";
/// PDF signature-field verification (ARX SAPI extension).
pub const SIGNATURE_TYPE_FIELD_VERIFY: &str =
    "http://arx.com/SAPIWS/DSS/1.0/signature-field-verify";
/// Certificate enumeration (ARX SAPI extension).
pub const SIGNATURE_TYPE_ENUM_CERTS: &str = "http://arx.com/SAPIWS/DSS/1.0/enum-certificates";

/// Escape the five XML special characters in user input.
///
/// `&` must be replaced first so the ampersands introduced by the later
/// replacements are not double-escaped.
#[must_use]
pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Build the common `DssSign` envelope shared by the sign and enum-certificates
/// requests. `input_documents` is an already-formed XML fragment;
/// `extra_namespaces` adds declarations to the envelope element (e.g. the
/// `xmlns:ds` used by the hash request).
fn build_soap_envelope(
    username: &str,
    password: &str,
    sig_type: &str,
    input_documents: &str,
    extra_namespaces: &str,
) -> String {
    let safe_user = xml_escape(username);
    let safe_pass = xml_escape(password);
    let safe_type = xml_escape(sig_type);
    let ns_part = if extra_namespaces.is_empty() {
        String::new()
    } else {
        format!("\n               {extra_namespaces}")
    };
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:arx="http://arx.com/SAPIWS/DSS/1.0"{ns_part}>
  <soap:Body>
    <DssSign xmlns="http://arx.com/SAPIWS/DSS/1.0/">
      <SignRequest xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
        <OptionalInputs>
          <ClaimedIdentity>
            <Name>{safe_user}</Name>
            <SupportingInfo>
              <arx:LogonPassword>{safe_pass}</arx:LogonPassword>
            </SupportingInfo>
          </ClaimedIdentity>
          <SignatureType>{safe_type}</SignatureType>
        </OptionalInputs>
        <InputDocuments>
          {input_documents}
        </InputDocuments>
      </SignRequest>
    </DssSign>
  </soap:Body>
</soap:Envelope>"#
    )
}

/// Build the envelope for signing a PDF or arbitrary data.
///
/// The appliance validates `MimeType` and rejects non-PDF types, so even a raw
/// ByteRange chunk is declared as `application/pdf`.
#[must_use]
pub fn build_sign_envelope(
    username: &str,
    password: &str,
    sig_type: &str,
    data_b64: &str,
) -> String {
    let input_docs = format!(
        r#"<Document><Base64Data MimeType="application/pdf">{}</Base64Data></Document>"#,
        xml_escape(data_b64)
    );
    build_soap_envelope(username, password, sig_type, &input_docs, "")
}

/// Build the envelope for signing a pre-computed SHA-1 hash.
#[must_use]
pub fn build_sign_hash_envelope(
    username: &str,
    password: &str,
    sig_type: &str,
    hash_b64: &str,
) -> String {
    let input_docs = format!(
        concat!(
            "<DocumentHash>",
            r#"<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>"#,
            "<ds:DigestValue>{}</ds:DigestValue>",
            "</DocumentHash>"
        ),
        xml_escape(hash_b64)
    );
    let extra_ns = r#"xmlns:ds="http://www.w3.org/2000/09/xmldsig#""#;
    build_soap_envelope(username, password, sig_type, &input_docs, extra_ns)
}

/// Build the envelope for enumerating the user's certificates.
///
/// Authentication is required, but nothing is signed.
#[must_use]
pub fn build_enum_certificates_envelope(username: &str, password: &str) -> String {
    build_soap_envelope(username, password, SIGNATURE_TYPE_ENUM_CERTS, "", "")
}

/// Build the `DssVerify` envelope for server-side signature verification.
///
/// No authentication is required -- the server checks the document's
/// cryptographic signature, not the caller's identity.
#[must_use]
pub fn build_verify_envelope(pdf_b64: &str, sig_type: &str) -> String {
    let safe_type = xml_escape(sig_type);
    let safe_pdf = xml_escape(pdf_b64);
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:arx="http://arx.com/SAPIWS/DSS/1.0">
  <soap:Body>
    <DssVerify xmlns="http://arx.com/SAPIWS/DSS/1.0/">
      <VerifyRequest xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
        <OptionalInputs>
          <SignatureType>{safe_type}</SignatureType>
        </OptionalInputs>
        <InputDocuments>
          <Document><Base64Data MimeType="application/pdf">{safe_pdf}</Base64Data></Document>
        </InputDocuments>
      </VerifyRequest>
    </DssVerify>
  </soap:Body>
</soap:Envelope>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_escape_handles_all_five_and_avoids_double_escaping() {
        assert_eq!(
            xml_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
        // The ampersand from an earlier replacement is not re-escaped.
        assert_eq!(xml_escape("<&"), "&lt;&amp;");
    }

    #[test]
    fn sign_envelope_is_byte_exact() {
        let got = build_sign_envelope("alice", "secret", SIGNATURE_TYPE_CMS, "QUJD");
        let expected = r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:arx="http://arx.com/SAPIWS/DSS/1.0">
  <soap:Body>
    <DssSign xmlns="http://arx.com/SAPIWS/DSS/1.0/">
      <SignRequest xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
        <OptionalInputs>
          <ClaimedIdentity>
            <Name>alice</Name>
            <SupportingInfo>
              <arx:LogonPassword>secret</arx:LogonPassword>
            </SupportingInfo>
          </ClaimedIdentity>
          <SignatureType>urn:ietf:rfc:3369</SignatureType>
        </OptionalInputs>
        <InputDocuments>
          <Document><Base64Data MimeType="application/pdf">QUJD</Base64Data></Document>
        </InputDocuments>
      </SignRequest>
    </DssSign>
  </soap:Body>
</soap:Envelope>"#;
        assert_eq!(got, expected);
    }

    #[test]
    fn sign_hash_envelope_declares_ds_namespace() {
        let got = build_sign_hash_envelope("u", "p", SIGNATURE_TYPE_CMS, "aGFzaA==");
        let expected = r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:arx="http://arx.com/SAPIWS/DSS/1.0"
               xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <soap:Body>
    <DssSign xmlns="http://arx.com/SAPIWS/DSS/1.0/">
      <SignRequest xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
        <OptionalInputs>
          <ClaimedIdentity>
            <Name>u</Name>
            <SupportingInfo>
              <arx:LogonPassword>p</arx:LogonPassword>
            </SupportingInfo>
          </ClaimedIdentity>
          <SignatureType>urn:ietf:rfc:3369</SignatureType>
        </OptionalInputs>
        <InputDocuments>
          <DocumentHash><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>aGFzaA==</ds:DigestValue></DocumentHash>
        </InputDocuments>
      </SignRequest>
    </DssSign>
  </soap:Body>
</soap:Envelope>"#;
        assert_eq!(got, expected);
    }

    #[test]
    fn verify_envelope_uses_field_verify_type() {
        let got = build_verify_envelope("UERG", SIGNATURE_TYPE_FIELD_VERIFY);
        assert!(got.contains("<DssVerify xmlns=\"http://arx.com/SAPIWS/DSS/1.0/\">"));
        assert!(got.contains(
            "<SignatureType>http://arx.com/SAPIWS/DSS/1.0/signature-field-verify</SignatureType>"
        ));
        assert!(got.contains(
            r#"<Document><Base64Data MimeType="application/pdf">UERG</Base64Data></Document>"#
        ));
    }

    #[test]
    fn credentials_are_escaped_in_envelope() {
        let got = build_sign_envelope("a<b", "p&w\"", SIGNATURE_TYPE_CMS, "ZA==");
        assert!(got.contains("<Name>a&lt;b</Name>"));
        assert!(got.contains("<arx:LogonPassword>p&amp;w&quot;</arx:LogonPassword>"));
    }
}
