"""SOAP envelope builders for CoSign API requests."""

from __future__ import annotations

from xml.sax.saxutils import escape as _xml_escape

SIGNATURE_TYPE_CMS = "urn:ietf:rfc:3369"
SIGNATURE_TYPE_XMLDSIG = "urn:ietf:rfc:3275"
SIGNATURE_TYPE_FIELD_VERIFY = "http://arx.com/SAPIWS/DSS/1.0/signature-field-verify"
SIGNATURE_TYPE_ENUM_CERTS = "http://arx.com/SAPIWS/DSS/1.0/enum-certificates"


def xml_escape(s: str) -> str:
    """Escape XML special characters in user input."""
    return _xml_escape(s, {'"': "&quot;", "'": "&apos;"})


def _build_soap_envelope(
    username: str,
    password: str,
    sig_type: str,
    input_documents: str,
    extra_namespaces: str = "",
) -> str:
    """
    Build a SOAP envelope for CoSign signing requests.

    All user-supplied strings (username, password, sig_type) are XML-escaped
    internally -- callers do NOT need to escape them.

    Args:
        username: Revenant username (escaped internally).
        password: Revenant password (escaped internally).
        sig_type: Signature type URN (e.g., SIGNATURE_TYPE_CMS).
        input_documents: XML fragment for <InputDocuments> content.
        extra_namespaces: Additional xmlns declarations for the envelope.

    Returns:
        Complete SOAP envelope as string.
    """
    safe_user = xml_escape(username)
    safe_pass = xml_escape(password)
    safe_type = xml_escape(sig_type)
    ns_part = f"\n               {extra_namespaces}" if extra_namespaces else ""
    return f"""\
<?xml version="1.0" encoding="utf-8"?>
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
</soap:Envelope>"""


def build_sign_envelope(username: str, password: str, sig_type: str, data_b64: str) -> str:
    """Build SOAP envelope for signing a PDF document or arbitrary data.

    NOTE: CoSign server validates MimeType and rejects non-PDF types.
    Even for raw bytes (ByteRange chunk), the server requires
    ``application/pdf``.
    """
    input_docs = (
        f'<Document><Base64Data MimeType="application/pdf">'
        f"{xml_escape(data_b64)}</Base64Data></Document>"
    )
    return _build_soap_envelope(username, password, sig_type, input_docs)


def build_sign_hash_envelope(username: str, password: str, sig_type: str, hash_b64: str) -> str:
    """Build SOAP envelope for signing a pre-computed hash."""
    input_docs = (
        "<DocumentHash>"
        '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'
        f"<ds:DigestValue>{xml_escape(hash_b64)}</ds:DigestValue>"
        "</DocumentHash>"
    )
    extra_ns = 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
    return _build_soap_envelope(username, password, sig_type, input_docs, extra_ns)


def build_enum_certificates_envelope(username: str, password: str) -> str:
    """Build SOAP envelope for enumerating user certificates.

    Uses the SAPI ``enum-certificates`` operation to retrieve the user's
    X.509 certificates without signing anything.  Auth is required.
    """
    return _build_soap_envelope(username, password, SIGNATURE_TYPE_ENUM_CERTS, "")


def build_verify_envelope(pdf_b64: str, sig_type: str = SIGNATURE_TYPE_FIELD_VERIFY) -> str:
    """Build a SOAP envelope for DssVerify.

    No authentication is required for verification -- the server checks
    the cryptographic signature on the document, not the caller's identity.

    Args:
        pdf_b64: Base64-encoded signed PDF.
        sig_type: Signature type URN. Use FIELD_VERIFY for PDF signature
            field verification, XMLDSIG for XML signatures,
            CMS for detached buffer verification.

    Returns:
        Complete SOAP envelope as string.
    """
    safe_type = xml_escape(sig_type)
    return f"""\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:arx="http://arx.com/SAPIWS/DSS/1.0">
  <soap:Body>
    <DssVerify xmlns="http://arx.com/SAPIWS/DSS/1.0/">
      <VerifyRequest xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
        <OptionalInputs>
          <SignatureType>{safe_type}</SignatureType>
        </OptionalInputs>
        <InputDocuments>
          <Document><Base64Data MimeType="application/pdf">{xml_escape(pdf_b64)}</Base64Data></Document>
        </InputDocuments>
      </VerifyRequest>
    </DssVerify>
  </soap:Body>
</soap:Envelope>"""
