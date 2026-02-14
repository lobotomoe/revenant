"""Tests for identity discovery — cert extraction (core) and server discovery (network)."""

from unittest.mock import MagicMock, patch

import pytest

from revenant.core import cert_info
from revenant.errors import AuthError, CertificateError, RevenantError, ServerError, TLSError
from revenant.network import discovery

# ── Shared mock builders ─────────────────────────────────────────────

# OID to display-name mapping for DN string construction
_OID_NAMES = {"2.5.4.3": "CN", "2.5.4.10": "O", "1.2.840.113549.1.9.1": "Email"}


def _build_mock_subject(cn=None, email=None, org=None):
    """Build a mock asn1crypto subject with RDN sequence.

    Shared by both CMS (ContentInfo) and X.509 (Certificate) mock builders.
    """
    rdns = []
    dn_parts = []
    for oid, value in (("2.5.4.3", cn), ("1.2.840.113549.1.9.1", email), ("2.5.4.10", org)):
        if value is not None:
            attr = MagicMock()
            attr.__getitem__ = lambda self, k, _oid=oid, _val=value: (
                MagicMock(dotted=_oid) if k == "type" else MagicMock(native=_val)
            )
            rdn = MagicMock()
            rdn.__iter__ = lambda self, _attr=attr: iter([_attr])
            rdns.append(rdn)
            dn_parts.append(f"{_OID_NAMES.get(oid, oid)}={value}")

    rdn_sequence = MagicMock()
    rdn_sequence.__iter__ = lambda self: iter(rdns)

    subject = MagicMock()
    subject.chosen = rdn_sequence
    subject.human_friendly = ", ".join(dn_parts)
    return subject


def _make_mock_signed_data(cn=None, email=None, org=None):
    """Build a mock asn1crypto ContentInfo with given subject fields."""
    subject = _build_mock_subject(cn, email, org)

    cert = MagicMock()
    cert.subject = subject

    cert_choice = MagicMock()
    cert_choice.chosen = cert

    certs = MagicMock()
    certs.__len__ = lambda self: 1
    certs.__getitem__ = lambda self, i: cert_choice

    signed_data = MagicMock()
    signed_data.__getitem__ = lambda self, k: certs if k == "certificates" else None

    content_info = MagicMock()
    content_info.__getitem__ = lambda self, k: signed_data if k == "content" else None

    return content_info


def test_extract_cert_info_full_fields():
    """Should extract CN, email, organization from certificate."""
    content_info = _make_mock_signed_data(
        cn="John Doe 123456789", email="john@example.com", org="Example Corp"
    )

    with patch("revenant.core.cert_info.asn1_cms.ContentInfo") as mock_cls:
        mock_cls.load.return_value = content_info
        info = cert_info.extract_cert_info_from_cms(b"\x30\x82\x01\x00")
        assert info["name"] == "John Doe 123456789"
        assert info["email"] == "john@example.com"
        assert info["organization"] == "Example Corp"
        assert info["dn"] is not None
        assert "CN=John Doe" in info["dn"]


def test_extract_cert_info_unicode_name():
    """asn1crypto handles BMPString/Unicode natively."""
    content_info = _make_mock_signed_data(
        cn="Aleksandr Kraiz 3105951040",
        email="test@example.com",
        org="Staff of Government of RA",
    )

    with patch("revenant.core.cert_info.asn1_cms.ContentInfo") as mock_cls:
        mock_cls.load.return_value = content_info
        info = cert_info.extract_cert_info_from_cms(b"\x30\x82\x01\x00")
        assert info["name"] == "Aleksandr Kraiz 3105951040"
        assert info["email"] == "test@example.com"
        assert info["organization"] == "Staff of Government of RA"


def test_extract_cert_info_parse_failure():
    """Should raise CertificateError if PKCS#7 parsing fails."""
    with patch("revenant.core.cert_info.asn1_cms.ContentInfo") as mock_cls:
        mock_cls.load.side_effect = ValueError("bad DER")
        with pytest.raises(CertificateError, match="Failed to parse CMS/PKCS#7"):
            cert_info.extract_cert_info_from_cms(b"\x30\x82\x01\x00")


def test_extract_cert_info_no_certs():
    """Should raise RevenantError if no certificates in blob."""
    certs = MagicMock()
    certs.__len__ = lambda self: 0
    certs.__bool__ = lambda self: False

    signed_data = MagicMock()
    signed_data.__getitem__ = lambda self, k: certs if k == "certificates" else None

    content_info = MagicMock()
    content_info.__getitem__ = lambda self, k: signed_data if k == "content" else None

    with patch("revenant.core.cert_info.asn1_cms.ContentInfo") as mock_cls:
        mock_cls.load.return_value = content_info
        with pytest.raises(CertificateError, match="No certificate subject"):
            cert_info.extract_cert_info_from_cms(b"\x30\x82\x01\x00")


def test_extract_cert_info_partial_fields():
    """Should handle missing optional fields gracefully."""
    content_info = _make_mock_signed_data(cn="Just A Name")

    with patch("revenant.core.cert_info.asn1_cms.ContentInfo") as mock_cls:
        mock_cls.load.return_value = content_info
        info = cert_info.extract_cert_info_from_cms(b"\x30\x82\x01\x00")
        assert info["name"] == "Just A Name"
        assert info["email"] is None
        assert info["organization"] is None


# ── extract_cert_info_from_x509 ─────────────────────────────────────


def _make_mock_x509_cert(cn=None, email=None, org=None):
    """Build a mock asn1crypto X.509 Certificate with given subject fields."""
    cert = MagicMock()
    cert.subject = _build_mock_subject(cn, email, org)
    return cert


def test_extract_cert_info_from_x509():
    """Should extract fields from a DER-encoded X.509 certificate."""
    mock_cert = _make_mock_x509_cert(cn="Jane Doe 987654", email="jane@example.com", org="Test Org")

    with patch("revenant.core.cert_info.asn1_x509.Certificate") as mock_cls:
        mock_cls.load.return_value = mock_cert
        info = cert_info.extract_cert_info_from_x509(b"\x30\x82\x01\x00")
        assert info["name"] == "Jane Doe 987654"
        assert info["email"] == "jane@example.com"
        assert info["organization"] == "Test Org"
        assert info["dn"] is not None
        assert "CN=Jane Doe" in info["dn"]


def test_extract_cert_info_from_x509_parse_failure():
    """Should raise CertificateError if X.509 parsing fails."""
    with patch("revenant.core.cert_info.asn1_x509.Certificate") as mock_cls:
        mock_cls.load.side_effect = ValueError("bad DER")
        with pytest.raises(CertificateError, match=r"Failed to parse X\.509"):
            cert_info.extract_cert_info_from_x509(b"\x00\x00")


# ── ping_server ──────────────────────────────────────────────────────


def test_ping_server_cosign_success():
    """CoSign endpoint should be detected from WSDL content."""
    mock_wsdl = b"<wsdl:definitions><DssSign/><SAPIWS/></wsdl:definitions>"

    with patch.object(discovery, "http_get", return_value=mock_wsdl):
        ok, info = discovery.ping_server("https://example.com/SAPIWS/DSS.asmx")
        assert ok is True
        assert "CoSign" in info


def test_ping_server_generic_wsdl():
    """Generic WSDL (not CoSign) should still return True but with caveat."""
    mock_wsdl = b"<wsdl:definitions>generic service</wsdl:definitions>"

    with patch.object(discovery, "http_get", return_value=mock_wsdl):
        ok, info = discovery.ping_server("https://example.com/service")
        assert ok is True
        assert "may not be CoSign" in info


def test_ping_server_not_wsdl():
    """Non-WSDL response should return False."""
    mock_html = b"<html><body>Not a service</body></html>"

    with patch.object(discovery, "http_get", return_value=mock_html):
        ok, info = discovery.ping_server("https://example.com")
        assert ok is False
        assert "Not a recognized" in info


def test_ping_server_tls_error():
    """TLS error should be reported."""
    with patch.object(discovery, "http_get", side_effect=TLSError("SSL handshake failed")):
        ok, info = discovery.ping_server("https://example.com")
        assert ok is False
        assert "SSL" in info or "handshake" in info


def test_ping_server_connection_error():
    """Connection error should be reported."""
    with patch.object(discovery, "http_get", side_effect=RevenantError("Connection refused")):
        ok, info = discovery.ping_server("https://example.com")
        assert ok is False
        assert "Connection failed" in info


def test_ping_server_adds_wsdl_param():
    """Should append ?WSDL to URL if not present."""
    with patch.object(discovery, "http_get", return_value=b"<wsdl:definitions/>") as mock:
        discovery.ping_server("https://example.com/DSS.asmx")
        mock.assert_called_once()
        called_url = mock.call_args[0][0]
        assert "?WSDL" in called_url


# ── discover_identity_from_server ────────────────────────────────────

_MOCK_IDENTITY = {
    "name": "Test User",
    "email": "test@example.com",
    "organization": None,
    "dn": "CN=Test User",
}


def test_discover_identity_via_enum_certificates():
    """Should prefer enum-certificates over dummy-hash signing."""
    mock_transport = MagicMock()
    mock_transport.url = "https://example.com/DSS.asmx"

    with (
        patch(
            "revenant.network.soap_transport.enum_certificates",
            return_value=[b"\x30\x82\x01\x00"],
        ) as mock_enum,
        patch.object(
            cert_info,
            "extract_cert_info_from_x509",
            return_value=_MOCK_IDENTITY,
        ),
    ):
        result = cert_info.discover_identity_from_server(mock_transport, "user", "pass", 30)
        assert result["name"] == "Test User"
        mock_enum.assert_called_once_with("https://example.com/DSS.asmx", "user", "pass", 30)
        # Should NOT have called sign_hash (dummy-hash fallback)
        mock_transport.sign_hash.assert_not_called()


def test_discover_identity_fallback_to_dummy_hash():
    """Should fall back to dummy-hash signing if enum-certificates fails."""
    mock_transport = MagicMock()
    mock_transport.url = "https://example.com/DSS.asmx"
    mock_transport.sign_hash.return_value = b"\x30\x82\x01\x00"

    with (
        patch(
            "revenant.network.soap_transport.enum_certificates",
            side_effect=ServerError("Not supported"),
        ),
        patch.object(
            cert_info,
            "extract_cert_info_from_cms",
            return_value=_MOCK_IDENTITY,
        ),
    ):
        result = cert_info.discover_identity_from_server(mock_transport, "user", "pass", 30)
        assert result["name"] == "Test User"
        mock_transport.sign_hash.assert_called_once()


def test_discover_identity_auth_error_propagates():
    """Auth errors from enum-certificates must propagate, not fall back."""
    mock_transport = MagicMock()
    mock_transport.url = "https://example.com/DSS.asmx"

    with (
        patch(
            "revenant.network.soap_transport.enum_certificates",
            side_effect=AuthError("Invalid user name or password"),
        ),
        pytest.raises(AuthError, match="password"),
    ):
        cert_info.discover_identity_from_server(mock_transport, "user", "pass", 30)

    # Should NOT have attempted dummy-hash fallback
    mock_transport.sign_hash.assert_not_called()


def test_discover_identity_no_url_uses_dummy_hash():
    """Transport without url attribute should go straight to dummy-hash."""
    mock_transport = MagicMock(spec=[])  # no url attribute
    mock_transport.sign_hash = MagicMock(return_value=b"\x30\x82\x01\x00")

    with patch.object(
        cert_info,
        "extract_cert_info_from_cms",
        return_value=_MOCK_IDENTITY,
    ):
        result = cert_info.discover_identity_from_server(mock_transport, "user", "pass", 30)
        assert result["name"] == "Test User"
        mock_transport.sign_hash.assert_called_once()


def test_discover_identity_enum_empty_falls_back():
    """If enum-certificates returns empty list, should fall back to dummy-hash."""
    mock_transport = MagicMock()
    mock_transport.url = "https://example.com/DSS.asmx"
    mock_transport.sign_hash.return_value = b"\x30\x82\x01\x00"

    with (
        patch(
            "revenant.network.soap_transport.enum_certificates",
            return_value=[],
        ),
        patch.object(
            cert_info,
            "extract_cert_info_from_cms",
            return_value=_MOCK_IDENTITY,
        ),
    ):
        result = cert_info.discover_identity_from_server(mock_transport, "user", "pass", 30)
        assert result["name"] == "Test User"
        mock_transport.sign_hash.assert_called_once()


# ── extract_all_cert_info_from_pdf ───────────────────────────────────


def test_extract_all_cert_info_no_signature():
    """PDF without signature should raise error."""
    pdf_bytes = b"%PDF-1.4\nno signature here\n%%EOF"

    with pytest.raises(CertificateError, match="No embedded signature"):
        cert_info.extract_all_cert_info_from_pdf(pdf_bytes)


def test_extract_all_cert_info_with_signatures():
    """Should extract info from all signatures."""
    # Build a fake PDF with ByteRange pattern
    pdf_with_sig = (
        b"%PDF-1.4\n"
        b"/ByteRange [0000000000 0000000100 0000000200 0000000050]"
        b"/Contents <3082010000" + b"00" * 90 + b">\n"
        b"%%EOF"
    )

    mock_info = {"name": "User 1", "email": "u1@test.com", "organization": "Org", "dn": "CN=User 1"}

    with (
        patch.object(cert_info, "extract_cms_from_byterange_match", return_value=b"\x30\x82"),
        patch.object(cert_info, "extract_cert_info_from_cms", return_value=mock_info),
    ):
        results = cert_info.extract_all_cert_info_from_pdf(pdf_with_sig)
        assert len(results) == 1
        assert results[0]["name"] == "User 1"


def test_extract_all_cert_info_extraction_error_continues():
    """If CMS extraction fails for one signature, should continue to next."""
    pdf_with_sigs = (
        b"%PDF-1.4\n"
        b"/ByteRange [0000000000 0000000100 0000000200 0000000050]/Contents <3082>\n"
        b"/ByteRange [0000000000 0000000100 0000000200 0000000050]/Contents <3082>\n"
        b"%%EOF"
    )

    mock_info = {"name": "User", "email": "u@test.com", "organization": "Org", "dn": "CN=User"}

    # First extraction fails, second succeeds
    with (
        patch.object(
            cert_info,
            "extract_cms_from_byterange_match",
            side_effect=[RevenantError("bad CMS"), b"\x30\x82"],
        ),
        patch.object(cert_info, "extract_cert_info_from_cms", return_value=mock_info),
    ):
        results = cert_info.extract_all_cert_info_from_pdf(pdf_with_sigs)
        assert len(results) == 1
        assert results[0]["name"] == "User"


def test_extract_all_cert_info_all_fail():
    """If all CMS extractions fail, should raise RevenantError."""
    pdf_with_sig = (
        b"%PDF-1.4\n/ByteRange [0000000000 0000000100 0000000200 0000000050]/Contents <3082>\n%%EOF"
    )

    with (
        patch.object(
            cert_info,
            "extract_cms_from_byterange_match",
            side_effect=RevenantError("bad CMS"),
        ),
        pytest.raises(CertificateError, match="Could not extract any certificate"),
    ):
        cert_info.extract_all_cert_info_from_pdf(pdf_with_sig)


def test_extract_all_cert_info_deduplicates():
    """Same DN should be deduplicated."""
    pdf_with_sigs = (
        b"%PDF-1.4\n"
        b"/ByteRange [0000000000 0000000100 0000000200 0000000050]/Contents <3082>\n"
        b"/ByteRange [0000000000 0000000100 0000000200 0000000050]/Contents <3082>\n"
        b"%%EOF"
    )

    mock_info = {
        "name": "Same User",
        "email": "same@test.com",
        "organization": "Org",
        "dn": "CN=Same User",
    }

    with (
        patch.object(cert_info, "extract_cms_from_byterange_match", return_value=b"\x30\x82"),
        patch.object(cert_info, "extract_cert_info_from_cms", return_value=mock_info),
    ):
        results = cert_info.extract_all_cert_info_from_pdf(pdf_with_sigs)
        # Should be deduplicated to 1
        assert len(results) == 1


# ── extract_cert_info_from_pdf ───────────────────────────────────────


def test_extract_cert_info_from_pdf_returns_last():
    """Should return the last signature's info."""
    all_info = [
        {
            "name": "First User",
            "email": "first@test.com",
            "organization": "Org",
            "dn": "CN=First User",
        },
        {
            "name": "Last User",
            "email": "last@test.com",
            "organization": "Org",
            "dn": "CN=Last User",
        },
    ]

    with patch.object(cert_info, "extract_all_cert_info_from_pdf", return_value=all_info):
        result = cert_info.extract_cert_info_from_pdf(b"fake pdf")
        assert result["name"] == "Last User"
