"""Tests for revenant.core.signing — input validation and happy-path tests."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from revenant.constants import SHA1_DIGEST_SIZE
from revenant.core.signing import sign_data, sign_hash, sign_pdf_detached
from revenant.errors import PDFError, RevenantError, SigningResponseError

from .conftest import FAKE_CMS

# ── sign_pdf_detached validation ──────────────────────────────────────


def test_sign_pdf_detached_non_pdf(mock_transport):
    """Non-PDF input should raise PDFError."""
    with pytest.raises(PDFError, match="does not appear to be a PDF"):
        sign_pdf_detached(b"not a pdf", mock_transport, "user", "pass", 120)


def test_sign_pdf_detached_empty(mock_transport):
    """Empty input should raise PDFError."""
    with pytest.raises(PDFError, match="does not appear to be a PDF"):
        sign_pdf_detached(b"", mock_transport, "user", "pass", 120)


def test_sign_pdf_detached_happy_path(mock_transport, cms_signer):
    """Valid PDF should go through SOAP call and return the verified CMS."""
    fake_pdf = b"%PDF-1.4\nfake content\n%%EOF\n"
    signed_cms = cms_signer(fake_pdf)

    mock_transport.sign_pdf_detached = Mock(return_value=signed_cms)
    result = sign_pdf_detached(fake_pdf, mock_transport, "user", "pass", 120)
    assert result == signed_cms


def test_sign_pdf_detached_rejects_unverifiable_response(mock_transport):
    """A response that is not a signature must not be handed back as one."""
    fake_pdf = b"%PDF-1.4\nfake content\n%%EOF\n"

    mock_transport.sign_pdf_detached = Mock(return_value=FAKE_CMS)
    with pytest.raises(SigningResponseError, match="not a valid signature"):
        sign_pdf_detached(fake_pdf, mock_transport, "user", "pass", 120)


def test_sign_pdf_detached_rejects_signature_over_other_bytes(mock_transport, cms_signer):
    """A genuine signature over the wrong document is still the wrong answer."""
    fake_pdf = b"%PDF-1.4\nfake content\n%%EOF\n"
    elsewhere = cms_signer(b"a different document entirely")

    mock_transport.sign_pdf_detached = Mock(return_value=elsewhere)
    with pytest.raises(SigningResponseError, match="not a valid signature"):
        sign_pdf_detached(fake_pdf, mock_transport, "user", "pass", 120)


# ── sign_hash validation ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad_hash",
    [b"\x00" * 10, b"\x00" * 32, b""],
    ids=["short", "long", "empty"],
)
def test_sign_hash_wrong_size(mock_transport, bad_hash):
    """Hash with wrong size should raise RevenantError."""
    with pytest.raises(RevenantError, match="Expected 20-byte SHA-1 hash"):
        sign_hash(bad_hash, mock_transport, "user", "pass", 120)


def test_sha1_digest_size_constant():
    assert SHA1_DIGEST_SIZE == 20


def test_sign_hash_happy_path(mock_transport, cms_signer):
    """Valid 20-byte hash should go through SOAP call and return the CMS."""
    fake_hash = b"\xab" * 20
    signed_cms = cms_signer(fake_hash)

    mock_transport.sign_hash = Mock(return_value=signed_cms)
    result = sign_hash(fake_hash, mock_transport, "user", "pass", 120)
    assert result == signed_cms


def test_sign_hash_rejects_unverifiable_response(mock_transport):
    """Submitting a digest still requires a response that is a signature."""
    mock_transport.sign_hash = Mock(return_value=FAKE_CMS)
    with pytest.raises(SigningResponseError, match="verifiable signature"):
        sign_hash(b"\xab" * 20, mock_transport, "user", "pass", 120)


# ── sign_data validation ─────────────────────────────────────────────


def test_sign_data_empty(mock_transport):
    """Empty data should raise RevenantError."""
    with pytest.raises(RevenantError, match="Cannot sign empty data"):
        sign_data(b"", mock_transport, "user", "pass", 120)


def test_sign_data_happy_path(mock_transport, cms_signer):
    """Valid data should go through SOAP call and return the verified CMS."""
    signed_cms = cms_signer(b"hello world")

    mock_transport.sign_data = Mock(return_value=signed_cms)
    result = sign_data(b"hello world", mock_transport, "user", "pass", 120)
    assert result == signed_cms


def test_sign_data_rejects_unverifiable_response(mock_transport):
    """Filler bytes shaped like DER are not a signature over the data."""
    mock_transport.sign_data = Mock(return_value=FAKE_CMS)
    with pytest.raises(SigningResponseError, match="not a valid signature"):
        sign_data(b"hello world", mock_transport, "user", "pass", 120)


# ── sign_pdf_embedded ────────────────────────────────────────────────


def test_sign_pdf_embedded_non_pdf(mock_transport):
    """Non-PDF input should raise PDFError."""
    from revenant.core.signing import sign_pdf_embedded

    with pytest.raises(PDFError, match="does not appear to be a PDF"):
        sign_pdf_embedded(b"not a pdf", mock_transport, "user", "pass", 120)


def test_sign_pdf_embedded_happy_path(mock_transport, cms_signer):
    """Full embedded signing pipeline with mocked SOAP."""
    import io

    import pikepdf

    from revenant.core.signing import sign_pdf_embedded

    # Create a valid PDF
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    # The pipeline: prepare -> sign_data -> insert_cms -> verify
    # We mock sign_data (which calls SOAP) and return a genuine test CMS.
    # sign_data is called internally by sign_pdf_embedded

    # We need to let prepare_pdf_with_sig_field run for real (needs pikepdf),
    # then mock the SOAP call. sign_pdf_embedded calls sign_data internally.
    mock_transport.sign_data = Mock(side_effect=cms_signer)
    result = sign_pdf_embedded(
        pdf_bytes,
        mock_transport,
        "user",
        "pass",
        120,
        page=0,
        position="br",
        name="Test User",
        reason="Test",
    )
    assert isinstance(result, bytes)
    assert result[:5] == b"%PDF-"
    assert len(result) > len(pdf_bytes)


def test_sign_pdf_embedded_with_fields(mock_transport, cms_signer):
    """Embedded signing with custom fields exercises adaptive sizing."""
    import io

    import pikepdf

    from revenant.core.signing import sign_pdf_embedded

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    mock_transport.sign_data = Mock(side_effect=cms_signer)
    result = sign_pdf_embedded(
        pdf_bytes,
        mock_transport,
        "user",
        "pass",
        120,
        page="last",
        position="br",
        name="Test",
        fields=["Test User", "SSN: 12345", "Date: 2026-02-07"],
    )
    assert isinstance(result, bytes)


def test_sign_pdf_embedded_verification_failure(mock_transport, cms_signer):
    """Post-sign verification failure should raise RevenantError.

    The transport signs for real, so the response passes the arrival-time gate
    and the post-sign check is what this exercises -- the splice, not the
    answer.
    """
    import io

    import pikepdf

    from revenant.core.signing import sign_pdf_embedded

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    bad_result = {
        "valid": False,
        "structure_ok": False,
        "hash_ok": False,
        "details": ["Hash MISMATCH"],
    }

    mock_transport.sign_data = Mock(side_effect=cms_signer)
    with (
        patch("revenant.core.signing.verify_embedded_signature", return_value=bad_result),
        pytest.raises(PDFError, match="Post-sign verification FAILED"),
    ):
        sign_pdf_embedded(
            pdf_bytes,
            mock_transport,
            "user",
            "pass",
            120,
            page=0,
            position="br",
            name="Test",
        )


def test_sign_pdf_embedded_with_font(mock_transport, cms_signer):
    """Embedded signing with explicit font should produce valid PDF."""
    import io

    import pikepdf

    from revenant.core.signing import sign_pdf_embedded

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    mock_transport.sign_data = Mock(side_effect=cms_signer)
    result = sign_pdf_embedded(
        pdf_bytes,
        mock_transport,
        "user",
        "pass",
        120,
        page=0,
        position="br",
        name="Test User",
        font="ghea-grapalat",
    )
    assert isinstance(result, bytes)
    assert result[:5] == b"%PDF-"
    assert b"/GHEAGrapalat" in result


def test_sign_pdf_embedded_invisible(mock_transport, cms_signer):
    """Invisible embedded signing pipeline with mocked SOAP."""
    import io

    import pikepdf

    from revenant.core.signing import sign_pdf_embedded

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    mock_transport.sign_data = Mock(side_effect=cms_signer)
    result = sign_pdf_embedded(
        pdf_bytes,
        mock_transport,
        "user",
        "pass",
        120,
        page=0,
        name="Test User",
        reason="Test",
        visible=False,
    )
    assert isinstance(result, bytes)
    assert result[:5] == b"%PDF-"
    assert len(result) > len(pdf_bytes)

    # Should contain zero-rect annotation
    assert b"/Rect [0 0 0 0]" in result
    # Incremental update should not contain appearance objects
    incremental = result[len(pdf_bytes) :]
    assert b"/AP <<" not in incremental


# ── _resolve_options validation ──────────────────────────────────


def test_resolve_options_unknown_kwargs():
    """Unknown kwargs should raise TypeError."""
    from revenant.core.signing import _resolve_options

    with pytest.raises(TypeError, match="Unexpected keyword"):
        _resolve_options(None, {"bad_key": "value"})


def test_resolve_options_none_no_kwargs():
    """None options + no kwargs should return default options."""
    from revenant.core.signing import EmbeddedSignatureOptions, _resolve_options

    result = _resolve_options(None, {})
    assert isinstance(result, EmbeddedSignatureOptions)


# ── sign_pdf_embedded validation ────────────────────────────────


def test_sign_pdf_embedded_negative_width(mock_transport):
    """Negative width should raise PDFError."""
    from revenant.core.signing import sign_pdf_embedded

    pdf = b"%PDF-1.4\nfake\n%%EOF\n"
    with pytest.raises(PDFError, match="dimensions must be positive"):
        sign_pdf_embedded(pdf, mock_transport, "u", "p", 120, w=-1)


def test_sign_pdf_embedded_negative_x(mock_transport):
    """Negative x should raise PDFError."""
    from revenant.core.signing import sign_pdf_embedded

    pdf = b"%PDF-1.4\nfake\n%%EOF\n"
    with pytest.raises(PDFError, match="x-coordinate must be non-negative"):
        sign_pdf_embedded(pdf, mock_transport, "u", "p", 120, x=-10)


def test_sign_pdf_embedded_negative_y(mock_transport):
    """Negative y should raise PDFError."""
    from revenant.core.signing import sign_pdf_embedded

    pdf = b"%PDF-1.4\nfake\n%%EOF\n"
    with pytest.raises(PDFError, match="y-coordinate must be non-negative"):
        sign_pdf_embedded(pdf, mock_transport, "u", "p", 120, y=-5)
