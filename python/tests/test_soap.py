"""Tests for revenant.network.soap — SOAP builders, XML parsing, helpers."""

import base64
from unittest.mock import patch

import pytest

from revenant.errors import AuthError, RevenantError, ServerError
from revenant.network.soap import (
    SIGNATURE_TYPE_CMS,
    SIGNATURE_TYPE_ENUM_CERTS,
    SIGNATURE_TYPE_FIELD_VERIFY,
    build_enum_certificates_envelope,
    build_sign_envelope,
    build_sign_hash_envelope,
    build_verify_envelope,
    parse_enum_certificates_response,
    parse_sign_response,
    parse_verify_response,
    send_soap,
    xml_escape,
)

# ── Constants ───────────────────────────────────────────────────────


def test_signature_type_cms():
    assert "3369" in SIGNATURE_TYPE_CMS


# ── send_soap ──────────────────────────────────────────────────────


def test_send_soap_basic():
    """send_soap sends correct headers, body, and timeout to http_post."""
    with patch("revenant.network.soap.http_post", return_value=b"<response/>") as mock_post:
        result = send_soap("https://example.com", "<envelope/>")

    mock_post.assert_called_once_with(
        "https://example.com",
        b"<envelope/>",
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": "http://arx.com/SAPIWS/DSS/1.0/DssSign",
        },
        timeout=120,
    )
    assert result == "<response/>"


def test_send_soap_custom_action():
    """send_soap should use custom action in SOAPAction header."""
    with patch("revenant.network.soap.http_post", return_value=b"<response/>") as mock_post:
        send_soap("https://example.com", "<envelope/>", action="DssVerify")

    call_kwargs = mock_post.call_args
    headers = call_kwargs.kwargs["headers"]
    assert headers["SOAPAction"] == "http://arx.com/SAPIWS/DSS/1.0/DssVerify"


def test_send_soap_custom_timeout():
    """send_soap should pass custom timeout to http_post."""
    with patch("revenant.network.soap.http_post", return_value=b"<response/>") as mock_post:
        send_soap("https://example.com", "<envelope/>", timeout=30)

    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args
    assert call_kwargs.kwargs["timeout"] == 30


def test_send_soap_utf8_response():
    """send_soap should correctly decode UTF-8 response with non-ASCII chars."""
    response_text = "<r>\u041e\u0442\u0432\u0435\u0442</r>"
    with patch("revenant.network.soap.http_post", return_value=response_text.encode("utf-8")):
        result = send_soap("https://example.com", "<envelope/>")

    assert result == response_text


def test_send_soap_invalid_utf8():
    """send_soap should use replacement characters for invalid UTF-8 bytes."""
    with patch("revenant.network.soap.http_post", return_value=b"\xff\xfe<broken/>"):
        result = send_soap("https://example.com", "<envelope/>")

    assert "\ufffd" in result
    assert "<broken/>" in result


# ── xml_escape ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("input_str", "expected"),
    [
        ("hello", "hello"),
        ("a&b", "a&amp;b"),
        ("<tag>", "&lt;tag&gt;"),
        ("a\"b'c", "a&quot;b&apos;c"),
        ('<a&"b">', "&lt;a&amp;&quot;b&quot;&gt;"),
    ],
    ids=["plain", "amp", "lt_gt", "quotes", "combined"],
)
def test_xml_escape(input_str, expected):
    assert xml_escape(input_str) == expected


# ── SOAP envelope builders ─────────────────────────────────────────


def test_sign_envelope_builder():
    envelope = build_sign_envelope("user1", "pass1", SIGNATURE_TYPE_CMS, "AAAA")
    assert "user1" in envelope
    assert "pass1" in envelope
    assert "AAAA" in envelope
    assert "DssSign" in envelope


def test_sign_hash_envelope_builder():
    envelope = build_sign_hash_envelope("user2", "pass2", SIGNATURE_TYPE_CMS, "BBBB")
    assert "user2" in envelope
    assert "DocumentHash" in envelope
    assert "BBBB" in envelope
    assert "sha1" in envelope


def test_envelope_escapes_xml_chars():
    """Builder should escape XML special characters in credentials."""
    envelope = build_sign_envelope("user<>&\"'", "pass<>&\"'", SIGNATURE_TYPE_CMS, "DATA")
    assert "user&lt;&gt;&amp;&quot;&apos;" in envelope
    assert "pass&lt;&gt;&amp;&quot;&apos;" in envelope


@pytest.mark.parametrize(
    ("input_str", "expected"),
    [
        ("", ""),
        ("\x00\x01\x02", "\x00\x01\x02"),  # control chars pass through (xml_escape doesn't strip)
        ("a" * 10000, "a" * 10000),  # very long string
        ("\n\t\r", "\n\t\r"),  # whitespace preserved
    ],
    ids=["empty", "control_chars", "long_string", "whitespace"],
)
def test_xml_escape_edge_cases(input_str, expected):
    assert xml_escape(input_str) == expected


def test_sign_envelope_empty_credentials():
    """Empty username/password should produce a valid envelope (server validates)."""
    envelope = build_sign_envelope("", "", SIGNATURE_TYPE_CMS, "DATA")
    assert "<Name></Name>" in envelope
    assert "LogonPassword></arx:LogonPassword>" in envelope


# ── parse_sign_response ─────────────────────────────────────────────


def _make_success_response(cms_b64):
    """Build a minimal SOAP response XML with Success and a signature."""
    return f"""\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DssSignResult xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
      <Result>
        <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:Success</ResultMajor>
      </Result>
      <SignatureObject>
        <Base64Signature>{cms_b64}</Base64Signature>
      </SignatureObject>
    </DssSignResult>
  </soap:Body>
</soap:Envelope>"""


def test_parse_success():
    # Create a fake CMS (just random bytes, > 50 chars in base64)
    fake_cms = b"\x30" * 100
    cms_b64 = base64.b64encode(fake_cms).decode()
    result = parse_sign_response(_make_success_response(cms_b64))
    assert result == fake_cms


def test_parse_auth_error():
    xml = """\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DssSignResult xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
      <Result>
        <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError</ResultMajor>
        <ResultMessage>Invalid user name or password</ResultMessage>
      </Result>
    </DssSignResult>
  </soap:Body>
</soap:Envelope>"""
    with pytest.raises(AuthError, match="password"):
        parse_sign_response(xml)


def test_parse_server_error():
    xml = """\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DssSignResult xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
      <Result>
        <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:ResponderError</ResultMajor>
        <ResultMessage>Internal server error</ResultMessage>
      </Result>
    </DssSignResult>
  </soap:Body>
</soap:Envelope>"""
    with pytest.raises(ServerError, match="Internal server error"):
        parse_sign_response(xml)


def test_parse_success_no_signature():
    """Success response but no Base64 data should raise ServerError."""
    xml = """\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DssSignResult xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
      <Result>
        <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:Success</ResultMajor>
      </Result>
    </DssSignResult>
  </soap:Body>
</soap:Envelope>"""
    with pytest.raises(ServerError, match="no signature"):
        parse_sign_response(xml)


def test_parse_broken_xml():
    with pytest.raises(RevenantError, match="Invalid XML"):
        parse_sign_response("this is not xml at all <<<<")


def test_parse_empty_response():
    with pytest.raises(RevenantError):
        parse_sign_response("")


def test_parse_unknown_error():
    """No ResultMessage, no known fields => 'Unknown error'."""
    xml = """\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DssSignResult xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
      <Result>
        <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:SomeOtherError</ResultMajor>
      </Result>
    </DssSignResult>
  </soap:Body>
</soap:Envelope>"""
    with pytest.raises(ServerError):
        parse_sign_response(xml)


# ── build_verify_envelope ─────────────────────────────────────────


def test_verify_envelope_structure():
    envelope = build_verify_envelope("AAAA==")
    assert "DssVerify" in envelope
    assert "VerifyRequest" in envelope
    assert "AAAA==" in envelope
    assert SIGNATURE_TYPE_FIELD_VERIFY in envelope
    # No authentication elements
    assert "ClaimedIdentity" not in envelope
    assert "LogonPassword" not in envelope


def test_verify_envelope_custom_sig_type():
    envelope = build_verify_envelope("AAAA==", sig_type=SIGNATURE_TYPE_CMS)
    assert SIGNATURE_TYPE_CMS in envelope


# ── parse_verify_response ─────────────────────────────────────────


def _make_verify_success(signer="Test User 123", time="2026-01-01T00:00:00Z"):
    return f"""\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DssVerifyResponse xmlns="http://arx.com/SAPIWS/DSS/1.0/">
      <DssVerifyResult xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
        <Result>
          <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:Success</ResultMajor>
          <ResultMinor>urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:onAllDocuments</ResultMinor>
        </Result>
        <OptionalOutputs>
          <SAPIFieldsInfo xmlns="http://arx.com/SAPIWS/DSS/1.0">
            <SignedFieldInfo SignerName="{signer}" IsSigned="true" SignatureTime="{time}">
              <Certificate>AAAA</Certificate>
            </SignedFieldInfo>
            <FieldStatus SignatureStatus="0" CertificateStatus="OK" />
          </SAPIFieldsInfo>
        </OptionalOutputs>
      </DssVerifyResult>
    </DssVerifyResponse>
  </soap:Body>
</soap:Envelope>"""


def test_parse_verify_success():
    result = parse_verify_response(_make_verify_success())
    assert result.valid is True
    assert result.signer_name == "Test User 123"
    assert result.sign_time == "2026-01-01T00:00:00Z"
    assert result.certificate_status == "OK"
    assert result.error is None


def test_parse_verify_error():
    xml = """\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DssVerifyResult xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
      <Result>
        <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:ResponderError</ResultMajor>
        <ResultMessage>Exception occured</ResultMessage>
      </Result>
    </DssVerifyResult>
  </soap:Body>
</soap:Envelope>"""
    result = parse_verify_response(xml)
    assert result.valid is False
    assert result.error == "Exception occured"


def test_parse_verify_broken_xml():
    """Malformed XML should not raise, should return error result."""
    result = parse_verify_response("not xml <<<<")
    assert result.valid is False
    assert result.error is not None
    assert "Invalid XML" in result.error


def test_parse_verify_empty():
    result = parse_verify_response("")
    assert result.valid is False
    assert result.error is not None


# ── verify_pdf_server ────────────────────────────────────────────


def test_verify_pdf_server_success():
    from revenant.network.soap_transport import verify_pdf_server

    with patch("revenant.network.soap_transport.send_soap", return_value=_make_verify_success()):
        result = verify_pdf_server("https://example.com/DSS.asmx", b"%PDF-1.0 test", timeout=30)

    assert result.valid is True
    assert result.signer_name == "Test User 123"


def test_verify_pdf_server_connection_error():
    from revenant.network.soap_transport import verify_pdf_server

    with patch(
        "revenant.network.soap_transport.send_soap",
        side_effect=OSError("Connection timed out"),
    ):
        result = verify_pdf_server("https://example.com/DSS.asmx", b"%PDF-1.0 test", timeout=30)

    assert result.valid is False
    assert "timed out" in (result.error or "")


# ── enum-certificates ────────────────────────────────────────────


def test_enum_certificates_envelope_builder():
    envelope = build_enum_certificates_envelope("user1", "pass1")
    assert "user1" in envelope
    assert "pass1" in envelope
    assert SIGNATURE_TYPE_ENUM_CERTS in envelope
    assert "DssSign" in envelope
    # No document content
    assert "Base64Data" not in envelope
    assert "DocumentHash" not in envelope


def test_parse_enum_certificates_success():
    # Two fake DER certs as base64
    cert1_b64 = base64.b64encode(b"\x30\x82\x01\x00" + b"\xaa" * 252).decode()
    cert2_b64 = base64.b64encode(b"\x30\x82\x01\x00" + b"\xbb" * 252).decode()
    xml = f"""\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DssSignResult xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
      <Result>
        <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:Success</ResultMajor>
      </Result>
      <OptionalOutputs xmlns="http://arx.com/SAPIWS/DSS/1.0">
        <AvailableCertificate>{cert1_b64}</AvailableCertificate>
        <AvailableCertificate>{cert2_b64}</AvailableCertificate>
      </OptionalOutputs>
    </DssSignResult>
  </soap:Body>
</soap:Envelope>"""
    certs = parse_enum_certificates_response(xml)
    assert len(certs) == 2
    assert certs[0] == b"\x30\x82\x01\x00" + b"\xaa" * 252
    assert certs[1] == b"\x30\x82\x01\x00" + b"\xbb" * 252


def test_parse_enum_certificates_auth_error():
    xml = """\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DssSignResult xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
      <Result>
        <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError</ResultMajor>
        <ResultMessage>Invalid user name or password</ResultMessage>
      </Result>
    </DssSignResult>
  </soap:Body>
</soap:Envelope>"""
    with pytest.raises(AuthError, match="password"):
        parse_enum_certificates_response(xml)


def test_parse_enum_certificates_empty():
    """Success but no certificates should return empty list."""
    xml = """\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DssSignResult xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
      <Result>
        <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:Success</ResultMajor>
      </Result>
    </DssSignResult>
  </soap:Body>
</soap:Envelope>"""
    certs = parse_enum_certificates_response(xml)
    assert certs == []


def test_parse_enum_certificates_broken_xml():
    with pytest.raises(RevenantError, match="Invalid XML"):
        parse_enum_certificates_response("this is not xml <<<<")


def test_parse_enum_certificates_server_error():
    xml = """\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DssSignResult xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
      <Result>
        <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:ResponderError</ResultMajor>
        <ResultMessage>Not supported</ResultMessage>
      </Result>
    </DssSignResult>
  </soap:Body>
</soap:Envelope>"""
    with pytest.raises(ServerError, match="Not supported"):
        parse_enum_certificates_response(xml)


def test_enum_certificates_transport():
    """Test enum_certificates module-level function."""
    from revenant.network.soap_transport import enum_certificates

    cert_b64 = base64.b64encode(b"\x30\x82\x01\x00" + b"\xcc" * 252).decode()
    mock_response = f"""\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DssSignResult xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
      <Result>
        <ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:Success</ResultMajor>
      </Result>
      <OptionalOutputs xmlns="http://arx.com/SAPIWS/DSS/1.0">
        <AvailableCertificate>{cert_b64}</AvailableCertificate>
      </OptionalOutputs>
    </DssSignResult>
  </soap:Body>
</soap:Envelope>"""

    with patch("revenant.network.soap_transport.send_soap", return_value=mock_response):
        certs = enum_certificates("https://example.com/DSS.asmx", "user", "pass", 30)

    assert len(certs) == 1
    assert certs[0] == b"\x30\x82\x01\x00" + b"\xcc" * 252


# ── SoapSigningTransport ──────────────────────────────────────────


def test_soap_transport_url():
    """SoapSigningTransport should expose URL."""
    from revenant.network.soap_transport import SoapSigningTransport

    t = SoapSigningTransport("https://example.com/DSS.asmx")
    assert t.url == "https://example.com/DSS.asmx"


def test_soap_transport_sign_data():
    """sign_data should send SOAP request and return CMS."""
    from revenant.network.soap_transport import SoapSigningTransport

    fake_cms = b"\x30\x82\x01\x00" + b"\xab" * 252
    cms_b64 = base64.b64encode(fake_cms).decode()

    t = SoapSigningTransport("https://example.com/DSS.asmx")
    with patch(
        "revenant.network.soap_transport.send_soap", return_value=_make_success_response(cms_b64)
    ):
        result = t.sign_data(b"hello world", "user", "pass", 30)

    assert result == fake_cms


def test_soap_transport_sign_data_empty():
    """sign_data with empty data should raise PDFError."""
    from revenant.network.soap_transport import SoapSigningTransport

    t = SoapSigningTransport("https://example.com/DSS.asmx")
    with pytest.raises(Exception, match="empty"):
        t.sign_data(b"", "user", "pass", 30)


def test_soap_transport_sign_hash():
    """sign_hash should send SOAP request and return CMS."""
    from revenant.network.soap_transport import SoapSigningTransport

    fake_cms = b"\x30\x82\x01\x00" + b"\xab" * 252
    cms_b64 = base64.b64encode(fake_cms).decode()
    valid_hash = b"\x00" * 20  # SHA-1 size

    t = SoapSigningTransport("https://example.com/DSS.asmx")
    with patch(
        "revenant.network.soap_transport.send_soap", return_value=_make_success_response(cms_b64)
    ):
        result = t.sign_hash(valid_hash, "user", "pass", 30)

    assert result == fake_cms


def test_soap_transport_sign_hash_wrong_size():
    """sign_hash with wrong hash size should raise RevenantError."""
    from revenant.network.soap_transport import SoapSigningTransport

    t = SoapSigningTransport("https://example.com/DSS.asmx")
    with pytest.raises(RevenantError, match="Expected 20-byte"):
        t.sign_hash(b"\x00" * 10, "user", "pass", 30)


def test_soap_transport_sign_pdf_detached():
    """sign_pdf_detached should send PDF as SOAP and return CMS."""
    from revenant.network.soap_transport import SoapSigningTransport

    fake_cms = b"\x30\x82\x01\x00" + b"\xab" * 252
    cms_b64 = base64.b64encode(fake_cms).decode()
    fake_pdf = b"%PDF-1.4\nfake content\n%%EOF\n"

    t = SoapSigningTransport("https://example.com/DSS.asmx")
    with patch(
        "revenant.network.soap_transport.send_soap", return_value=_make_success_response(cms_b64)
    ):
        result = t.sign_pdf_detached(fake_pdf, "user", "pass", 30)

    assert result == fake_cms


def test_soap_transport_sign_pdf_detached_non_pdf():
    """sign_pdf_detached with non-PDF input should raise PDFError."""
    from revenant.errors import PDFError
    from revenant.network.soap_transport import SoapSigningTransport

    t = SoapSigningTransport("https://example.com/DSS.asmx")
    with pytest.raises(PDFError, match="does not appear to be a PDF"):
        t.sign_pdf_detached(b"not a pdf", "user", "pass", 30)
