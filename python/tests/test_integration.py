"""Integration tests — require live CoSign server and credentials.

These tests are NOT run by default. To run them:

    pytest -m integration

Credentials are resolved automatically from env vars or saved config
(keychain / config file). Set REVENANT_USER/REVENANT_PASS env vars
to override, or run ``revenant setup`` to save them.
"""

import hashlib
import os
from urllib.parse import urlparse

import pytest

from revenant import (
    AuthError,
    RevenantError,
    sign_hash,
    sign_pdf_detached,
    sign_pdf_embedded,
    verify_all_embedded_signatures,
)
from revenant.config.config import get_active_profile
from revenant.config.credentials import resolve_credentials
from revenant.core.cert_info import discover_identity_from_server
from revenant.core.pdf import verify_embedded_signature
from revenant.core.signing import sign_data
from revenant.network.discovery import ping_server
from revenant.network.soap_transport import SoapSigningTransport
from revenant.network.transport import register_host_tls

# ── Skip unless credentials are available ────────────────────────────

USER, PASS = resolve_credentials()
URL = os.environ.get("REVENANT_URL", "https://ca.gov.am:8080/SAPIWS/DSS.asmx")
TRANSPORT = SoapSigningTransport(URL)

# Pre-register TLS mode so transport uses the correct strategy.
# Saved profile takes priority; otherwise match URL against built-in profiles.
_profile = get_active_profile()
if not _profile:
    from revenant.config.profiles import BUILTIN_PROFILES

    _profile = next((p for p in BUILTIN_PROFILES.values() if p.url == URL), None)

if _profile:
    _host = urlparse(_profile.url).hostname
    if _host:
        register_host_tls(_host, _profile.legacy_tls)

pytestmark = pytest.mark.integration

requires_creds = pytest.mark.skipif(
    not USER or not PASS,
    reason="No credentials available (env vars, keychain, or config)",
)

# Check if PIL is available for image tests
try:
    from PIL import Image  # noqa: F401

    _pil_available = True
except ImportError:
    _pil_available = False

requires_pil = pytest.mark.skipif(
    not _pil_available,
    reason="Pillow not installed (pip install pillow)",
)

# ── Minimal valid PDF ────────────────────────────────────────────────

TINY_PDF = b"""%PDF-1.0
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj
xref
0 4
0000000000 65535 f\x20
0000000009 00000 n\x20
0000000058 00000 n\x20
0000000115 00000 n\x20
trailer<</Size 4/Root 1 0 R>>
startxref
190
%%EOF"""


# ── Detached signing ─────────────────────────────────────────────────


@requires_creds
def test_sign_pdf_detached():
    """Detached CMS signing should return a valid DER blob."""
    cms = sign_pdf_detached(TINY_PDF, TRANSPORT, USER, PASS, 120)
    assert isinstance(cms, bytes)
    assert len(cms) > 100
    # CMS/PKCS#7 starts with ASN.1 SEQUENCE tag
    assert cms[0] == 0x30


@requires_creds
def test_sign_pdf_detached_returns_different_for_different_pdfs():
    """Different PDFs should produce different CMS signatures."""
    pdf2 = TINY_PDF.replace(b"612 792", b"595 842")
    cms1 = sign_pdf_detached(TINY_PDF, TRANSPORT, USER, PASS, 120)
    cms2 = sign_pdf_detached(pdf2, TRANSPORT, USER, PASS, 120)
    assert cms1 != cms2


# ── Hash signing ─────────────────────────────────────────────────────


@requires_creds
def test_sign_hash_sha1():
    """SHA-1 hash signing should return a valid CMS blob."""
    digest = hashlib.sha1(b"test data for integration tests").digest()
    cms = sign_hash(digest, TRANSPORT, USER, PASS, 120)
    assert isinstance(cms, bytes)
    assert len(cms) > 100
    assert cms[0] == 0x30


@requires_creds
def test_sign_hash_different_hashes_produce_different_cms():
    """Different hashes must produce different CMS (server signs our hash, not re-hashes)."""
    h1 = hashlib.sha1(b"data one").digest()
    h2 = hashlib.sha1(b"data two").digest()
    cms1 = sign_hash(h1, TRANSPORT, USER, PASS, 120)
    cms2 = sign_hash(h2, TRANSPORT, USER, PASS, 120)
    assert cms1 != cms2


@requires_creds
def test_sign_hash_wrong_length_rejected():
    """Non-20-byte hash should be rejected locally (before hitting the server)."""
    with pytest.raises(RevenantError, match="20-byte"):
        sign_hash(b"short", TRANSPORT, USER, PASS, 120)


# ── Authentication ───────────────────────────────────────────────────


@requires_creds
def test_wrong_password_raises_auth_error():
    """Wrong password should raise AuthError."""
    with pytest.raises(AuthError):
        sign_pdf_detached(TINY_PDF, TRANSPORT, USER, "WRONG_PASSWORD_12345", 120)


@requires_creds
def test_wrong_username_raises_auth_error():
    """Wrong username should raise AuthError or ServerError."""
    with pytest.raises((AuthError, RevenantError)):
        sign_pdf_detached(TINY_PDF, TRANSPORT, "NONEXISTENT_USER_XYZ", PASS, 120)


# ── Embedded signing (requires pikepdf) ──────────────────────────────


@requires_creds
def test_sign_pdf_embedded_produces_valid_pdf():
    """Full embedded signing pipeline: prepare → hash → CMS → insert → verify."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        page=0,
        x=350,
        y=50,
        w=200,
        h=70,
        reason="Integration test",
        name="Test Signer",
    )

    assert isinstance(signed, bytes)
    assert signed[:5] == b"%PDF-"
    assert len(signed) > len(TINY_PDF)

    # Our own verification should pass
    result = verify_embedded_signature(signed)
    assert result["valid"], f"Verification failed: {result['details']}"


@requires_creds
def test_sign_pdf_embedded_contains_cms():
    """Embedded PDF should contain a CMS blob in /Contents."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        reason="CMS check",
        name="Test",
    )

    # The hex-encoded CMS should be present between angle brackets
    assert b"/ByteRange" in signed
    assert b"/Contents <" in signed


@requires_creds
def test_sign_pdf_embedded_without_name():
    """Embedded signing should work without a signer name."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        reason="No name test",
        name=None,
    )
    assert isinstance(signed, bytes)
    result = verify_embedded_signature(signed)
    assert result["valid"]


# ── CMS structure checks ────────────────────────────────────────────


@requires_creds
def test_cms_contains_sha1_with_rsa_quirk():
    """CoSign CMS should contain sha1WithRSA OID (known quirk)."""
    cms = sign_pdf_detached(TINY_PDF, TRANSPORT, USER, PASS, 120)
    # sha1WithRSAEncryption OID: 1.2.840.113549.1.1.5
    sha1_with_rsa_oid = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05])
    assert sha1_with_rsa_oid in cms, "Expected sha1WithRSA OID in CMS (known server quirk)"


@requires_creds
def test_cms_consistent_size():
    """CMS blobs should be consistently ~1867 bytes."""
    cms = sign_pdf_detached(TINY_PDF, TRANSPORT, USER, PASS, 120)
    assert abs(len(cms) - 1867) < 200, f"CMS size {len(cms)} is unexpectedly far from 1867"


# ── Embedded signing with images ─────────────────────────────────────


@requires_creds
@requires_pil
def test_sign_pdf_embedded_with_png_image(tmp_path):
    """Embedded signing with RGB PNG image should produce valid signature."""
    from PIL import Image

    # Create a simple RGB PNG
    img = Image.new("RGB", (100, 50), color=(255, 0, 0))
    img_path = tmp_path / "signature.png"
    img.save(img_path)

    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        name="Test Signer",
        image_path=str(img_path),
    )

    assert isinstance(signed, bytes)
    assert signed[:5] == b"%PDF-"
    result = verify_embedded_signature(signed)
    assert result["valid"], f"Verification failed: {result['details']}"


@requires_creds
@requires_pil
def test_sign_pdf_embedded_with_png_rgba_image(tmp_path):
    """Embedded signing with RGBA PNG (alpha channel) should work."""
    from PIL import Image

    # Create PNG with transparency
    img = Image.new("RGBA", (80, 40), color=(0, 0, 0, 128))
    img_path = tmp_path / "signature_alpha.png"
    img.save(img_path)

    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        name="Test Signer",
        image_path=str(img_path),
    )

    assert isinstance(signed, bytes)
    result = verify_embedded_signature(signed)
    assert result["valid"], f"Verification failed: {result['details']}"


@requires_creds
@requires_pil
def test_sign_pdf_embedded_with_jpeg_image(tmp_path):
    """Embedded signing with JPEG image should produce valid signature."""
    from PIL import Image

    # Create a JPEG (no alpha support)
    img = Image.new("RGB", (120, 60), color=(0, 128, 0))
    img_path = tmp_path / "signature.jpg"
    img.save(img_path, "JPEG", quality=90)

    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        name="Test Signer",
        image_path=str(img_path),
    )

    assert isinstance(signed, bytes)
    result = verify_embedded_signature(signed)
    assert result["valid"], f"Verification failed: {result['details']}"


@requires_creds
@requires_pil
def test_sign_pdf_embedded_with_large_image_downscaled(tmp_path):
    """Large images should be automatically downscaled to max 200px."""
    from PIL import Image

    # Create a large image (will be downscaled)
    img = Image.new("RGB", (1000, 500), color=(0, 0, 255))
    img_path = tmp_path / "large_signature.png"
    img.save(img_path)

    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        name="Test Signer",
        image_path=str(img_path),
    )

    assert isinstance(signed, bytes)
    result = verify_embedded_signature(signed)
    assert result["valid"], f"Verification failed: {result['details']}"


# ── Arbitrary data signing (sign_data) ─────────────────────────────


@requires_creds
def test_sign_data_basic():
    """sign_data() should sign arbitrary bytes and return valid CMS."""
    data = b"Hello, this is arbitrary data to sign!"
    cms = sign_data(data, TRANSPORT, USER, PASS, 120)
    assert isinstance(cms, bytes)
    assert len(cms) > 100
    assert cms[0] == 0x30  # ASN.1 SEQUENCE


@requires_creds
def test_sign_data_different_data_produces_different_cms():
    """Different data should produce different CMS signatures."""
    cms1 = sign_data(b"data one", TRANSPORT, USER, PASS, 120)
    cms2 = sign_data(b"data two", TRANSPORT, USER, PASS, 120)
    assert cms1 != cms2


@requires_creds
def test_sign_data_empty_rejected():
    """Empty data should be rejected."""
    with pytest.raises(RevenantError, match="empty"):
        sign_data(b"", TRANSPORT, USER, PASS, 120)


@requires_creds
def test_sign_data_large_payload():
    """sign_data() should handle larger payloads (1 MB)."""
    large_data = b"X" * (1024 * 1024)  # 1 MB
    cms = sign_data(large_data, TRANSPORT, USER, PASS, 180)
    assert isinstance(cms, bytes)
    assert cms[0] == 0x30


# ── Signature positions ────────────────────────────────────────────


@requires_creds
def test_sign_pdf_embedded_position_top_left():
    """Embedded signing with top-left position should work."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        position="top-left",
        name="Test Signer",
    )
    assert isinstance(signed, bytes)
    result = verify_embedded_signature(signed)
    assert result["valid"], f"Verification failed: {result['details']}"


@requires_creds
def test_sign_pdf_embedded_position_bottom_center():
    """Embedded signing with bottom-center position should work."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        position="bottom-center",
        name="Test Signer",
    )
    assert isinstance(signed, bytes)
    result = verify_embedded_signature(signed)
    assert result["valid"], f"Verification failed: {result['details']}"


@requires_creds
def test_sign_pdf_embedded_position_alias():
    """Position aliases (br, tl, etc.) should work."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        position="tl",  # alias for top-left
        name="Test Signer",
    )
    assert isinstance(signed, bytes)
    result = verify_embedded_signature(signed)
    assert result["valid"], f"Verification failed: {result['details']}"


@requires_creds
def test_sign_pdf_embedded_custom_xy():
    """Custom x/y coordinates should override position preset."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        x=100,
        y=100,
        w=150,
        h=50,
        name="Test Signer",
    )
    assert isinstance(signed, bytes)
    result = verify_embedded_signature(signed)
    assert result["valid"], f"Verification failed: {result['details']}"


# ── Page selection ─────────────────────────────────────────────────


@requires_creds
def test_sign_pdf_embedded_page_first():
    """Embedded signing on 'first' page should work."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        page="first",
        name="Test Signer",
    )
    assert isinstance(signed, bytes)
    result = verify_embedded_signature(signed)
    assert result["valid"], f"Verification failed: {result['details']}"


@requires_creds
def test_sign_pdf_embedded_page_last():
    """Embedded signing on 'last' page should work."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        page="last",
        name="Test Signer",
    )
    assert isinstance(signed, bytes)
    result = verify_embedded_signature(signed)
    assert result["valid"], f"Verification failed: {result['details']}"


@requires_creds
def test_sign_pdf_embedded_page_zero():
    """Embedded signing on page 0 (first page, 0-indexed) should work."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        page=0,
        name="Test Signer",
    )
    assert isinstance(signed, bytes)
    result = verify_embedded_signature(signed)
    assert result["valid"], f"Verification failed: {result['details']}"


# ── Verification (negative cases) ─────────────────────────────────


@requires_creds
def test_verify_detects_tampered_pdf_content():
    """Modifying PDF content after signing must invalidate the signature."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        name="Test Signer",
    )

    result = verify_embedded_signature(signed)
    assert result["valid"], f"Pre-check failed: {result['details']}"

    # Tamper: change MediaBox dimension (structurally valid PDF, different hash)
    tampered = signed.replace(b"612 792", b"613 792", 1)
    assert tampered != signed, "Tamper had no effect -- MediaBox not found"

    result = verify_embedded_signature(tampered)
    assert not result["valid"], f"Tampered PDF should fail verification: {result['details']}"
    assert not result["hash_ok"], "Hash check should detect content tampering"


@requires_creds
def test_verify_detects_corrupted_cms_blob():
    """Corrupting the CMS hex blob must invalidate the signature."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        name="Test Signer",
    )

    # Find the CMS hex blob and corrupt the ASN.1 header
    contents_idx = signed.find(b"/Contents <")
    assert contents_idx != -1, "/Contents not found in signed PDF"
    hex_start = contents_idx + len(b"/Contents <")

    tampered = bytearray(signed)
    tampered[hex_start : hex_start + 8] = b"DEADBEEF"
    tampered = bytes(tampered)

    result = verify_embedded_signature(tampered)
    assert not result["valid"], f"Corrupted CMS should fail verification: {result['details']}"


@requires_creds
def test_cms_info_from_real_signature():
    """Real CMS from server should contain parseable certificate info."""
    from asn1crypto import cms as asn1_cms

    cms = sign_pdf_detached(TINY_PDF, TRANSPORT, USER, PASS, 120)

    content_info = asn1_cms.ContentInfo.load(cms)
    signed_data = content_info["content"]
    certs = signed_data["certificates"]
    assert len(certs) >= 1, "CMS should contain at least one certificate"

    cert = certs[0].chosen
    subject = cert.subject.human_friendly
    issuer = cert.issuer.human_friendly
    assert subject, "Certificate subject must not be empty"
    assert issuer, "Certificate issuer must not be empty"
    assert cert.serial_number > 0, "Serial number must be positive"

    not_before = cert["tbs_certificate"]["validity"]["not_before"].native
    not_after = cert["tbs_certificate"]["validity"]["not_after"].native
    assert not_before is not None, "Validity not_before must be present"
    assert not_after is not None, "Validity not_after must be present"
    assert not_after > not_before, "Certificate validity range must be positive"


@requires_creds
def test_verify_all_on_single_signature():
    """verify_all_embedded_signatures should return one result with signer info."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        name="Test Signer",
    )

    results = verify_all_embedded_signatures(signed)
    assert len(results) == 1

    result = results[0]
    assert result["valid"], f"Verification failed: {result['details']}"
    assert result["signer"] is not None, "Signer info should be present"
    assert result["signer"]["name"], "Signer name should not be empty"


# ── Server discovery ───────────────────────────────────────────────


def test_ping_server_success():
    """ping_server() should return True for a valid CoSign endpoint."""
    ok, info = ping_server(URL, timeout=15)
    assert ok, f"ping_server failed: {info}"
    assert info  # Should contain version or endpoint info


def test_ping_server_invalid_url():
    """ping_server() should return False for an invalid URL."""
    ok, info = ping_server("https://invalid.example.com:9999/fake", timeout=5)
    assert not ok
    assert info  # Should contain error description


@requires_creds
def test_discover_identity_from_server():
    """discover_identity_from_server() should return signer certificate info."""
    transport = SoapSigningTransport(URL)
    info = discover_identity_from_server(transport, USER, PASS, timeout=30)
    assert info is not None
    assert "name" in info
    assert info["name"]  # Should have a CN


@requires_creds
def test_discover_identity_fields_are_readable():
    """Identity fields must be decoded readable text, not hex escapes or garbled."""
    transport = SoapSigningTransport(URL)
    info = discover_identity_from_server(transport, USER, PASS, timeout=30)

    # Name must not contain raw hex escapes
    name = info["name"]
    assert name is not None
    assert "\\x" not in name, f"Name contains raw hex escapes: {name}"

    # Email must be a valid email (no hex, no CJK garbage)
    email = info.get("email")
    if email:
        assert "@" in email, f"Email missing @: {email}"
        assert "\\x" not in email, f"Email contains raw hex escapes: {email}"
        # Reject CJK characters (U+4E00-U+9FFF) which indicate misaligned UTF-16BE decode
        assert not any("\u4e00" <= ch <= "\u9fff" for ch in email), (
            f"Email contains CJK garbage (misaligned UTF-16BE decode): {email}"
        )

    # Organization must not contain CJK garbage
    org = info.get("organization")
    if org:
        assert "\\x" not in org, f"Organization contains raw hex escapes: {org}"
        assert not any("\u4e00" <= ch <= "\u9fff" for ch in org), (
            f"Organization contains CJK garbage: {org}"
        )


# ── Invisible signature ───────────────────────────────────────────


@requires_creds
def test_sign_pdf_embedded_invisible():
    """Invisible signature: zero-rect annotation, no appearance stream."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        name="Invisible Signer",
        reason="Invisible test",
        visible=False,
    )

    assert isinstance(signed, bytes)
    assert signed[:5] == b"%PDF-"

    # Zero-rect annotation (invisible field)
    assert b"/Rect [0 0 0 0]" in signed

    # Incremental update should not contain appearance objects
    incremental = signed[len(TINY_PDF) :]
    assert b"/AP <<" not in incremental

    # Verification should still pass
    result = verify_embedded_signature(signed)
    assert result["valid"], f"Invisible signature verification failed: {result['details']}"


# ── Armenian font (GHEA Grapalat) ─────────────────────────────────


@requires_creds
def test_sign_pdf_embedded_armenian_font():
    """Embedded signing with Armenian GHEA Grapalat font."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        name="Test Signer",
        reason="Armenian font test",
        font="ghea-grapalat",
    )

    assert isinstance(signed, bytes)
    assert signed[:5] == b"%PDF-"
    assert b"/GHEAGrapalat" in signed

    result = verify_embedded_signature(signed)
    assert result["valid"], f"Armenian font verification failed: {result['details']}"


@requires_creds
def test_sign_pdf_embedded_mariam_font():
    """Embedded signing with Armenian GHEA Mariam font."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        name="Test Signer",
        reason="Mariam font test",
        font="ghea-mariam",
    )

    assert isinstance(signed, bytes)
    assert b"/GHEAMariam" in signed

    result = verify_embedded_signature(signed)
    assert result["valid"], f"Mariam font verification failed: {result['details']}"


# ── Custom display fields (adaptive sizing) ───────────────────────


@requires_creds
def test_sign_pdf_embedded_with_custom_fields():
    """Embedded signing with custom display fields triggers adaptive sizing."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        name="Test Signer",
        reason="Fields test",
        fields=["Full Name: John Doe", "ID: 1234567890", "Date: 2026-02-12"],
    )

    assert isinstance(signed, bytes)
    assert signed[:5] == b"%PDF-"

    result = verify_embedded_signature(signed)
    assert result["valid"], f"Custom fields verification failed: {result['details']}"


@requires_creds
def test_sign_pdf_embedded_with_fields_and_armenian_font():
    """Custom fields + Armenian font: adaptive sizing with non-Latin glyphs."""
    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        name="Test Signer",
        fields=["Line 1", "Line 2", "Line 3"],
        font="ghea-grapalat",
    )

    assert isinstance(signed, bytes)
    assert b"/GHEAGrapalat" in signed

    result = verify_embedded_signature(signed)
    assert result["valid"], f"Fields+font verification failed: {result['details']}"


# ── Double signing ────────────────────────────────────────────────


@requires_creds
def test_sign_pdf_embedded_double_sign():
    """Re-signing an already signed PDF should produce two valid signatures."""
    # First signature
    signed_once = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        page=0,
        position="br",
        name="First Signer",
        reason="First signature",
    )
    assert isinstance(signed_once, bytes)

    # Second signature on the already-signed PDF
    signed_twice = sign_pdf_embedded(
        signed_once,
        TRANSPORT,
        USER,
        PASS,
        120,
        page=0,
        position="bl",
        name="Second Signer",
        reason="Second signature",
    )
    assert isinstance(signed_twice, bytes)
    assert len(signed_twice) > len(signed_once)

    # Both signatures should be verifiable
    results = verify_all_embedded_signatures(signed_twice)
    assert len(results) == 2, f"Expected 2 signatures, got {len(results)}"
    for i, r in enumerate(results):
        assert r["valid"], f"Signature {i} verification failed: {r['details']}"


# ── Server-side DssVerify ─────────────────────────────────────────


@requires_creds
def test_verify_pdf_server_valid_signature():
    """Server-side DssVerify should confirm a valid signed PDF."""
    from revenant.network.soap_transport import verify_pdf_server

    signed = sign_pdf_embedded(
        TINY_PDF,
        TRANSPORT,
        USER,
        PASS,
        120,
        name="Verify Test",
        reason="Server verify",
    )

    result = verify_pdf_server(URL, signed, timeout=30)
    assert result.valid, f"Server verify failed: {result.error}"
    assert result.signer_name is not None


@requires_creds
def test_verify_pdf_server_unsigned_pdf():
    """Server-side DssVerify on unsigned PDF returns valid=True but no signer info."""
    from revenant.network.soap_transport import verify_pdf_server

    result = verify_pdf_server(URL, TINY_PDF, timeout=30)
    # CoSign considers unsigned PDFs as "valid" (no error), but without signer info
    assert result.error is None
    assert result.signer_name is None


# ── Certificate enumeration ───────────────────────────────────────


@requires_creds
def test_enum_certificates():
    """enum_certificates should return at least one DER-encoded certificate."""
    from revenant.network.soap_transport import enum_certificates

    certs = enum_certificates(URL, USER, PASS, timeout=30)
    assert isinstance(certs, list)
    assert len(certs) >= 1, "Expected at least one certificate"
    for cert_der in certs:
        assert isinstance(cert_der, bytes)
        # X.509 certificates start with ASN.1 SEQUENCE tag
        assert cert_der[0] == 0x30, "Certificate DER must start with SEQUENCE tag"
