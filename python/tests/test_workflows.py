"""Tests for revenant.ui.workflows -- shared signing and verification workflows."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

from revenant.errors import AuthError, RevenantError, TLSError
from revenant.ui.workflows import (
    _classify_error,
    format_verify_results,
    resolve_sig_fields,
    sign_one_detached,
    sign_one_embedded,
)

from .conftest import FAKE_CMS

if TYPE_CHECKING:
    from revenant.core.pdf import VerificationResult

# ── _classify_error tests ────────────────────────────────────────


def test_classify_auth_error():
    result = _classify_error(AuthError("bad creds"))
    assert not result.ok
    assert result.auth_failed
    assert not result.tls_error
    assert result.error_message == "bad creds"


def test_classify_tls_error():
    result = _classify_error(TLSError("cipher mismatch"))
    assert not result.ok
    assert not result.auth_failed
    assert result.tls_error
    assert result.error_message == "cipher mismatch"


def test_classify_revenant_error():
    result = _classify_error(RevenantError("general failure"))
    assert not result.ok
    assert not result.auth_failed
    assert not result.tls_error
    assert result.error_message == "general failure"


def test_classify_value_error():
    result = _classify_error(ValueError("bad input"))
    assert not result.ok
    assert result.error_message == "bad input"


def test_classify_unexpected_error():
    result = _classify_error(RuntimeError("boom"))
    assert not result.ok
    assert "unexpected" in (result.error_message or "").lower()


# ── sign_one_embedded tests ──────────────────────────────────────


def test_sign_embedded_happy_path(valid_pdf_bytes, mock_transport, tmp_path):
    """Valid PDF should produce ok=True with output file."""
    output = tmp_path / "signed.pdf"
    mock_transport.sign_data = Mock(return_value=FAKE_CMS)

    with (
        patch("revenant.ui.workflows.register_active_profile_tls"),
        patch("revenant.network.SoapSigningTransport", return_value=mock_transport),
    ):
        result = sign_one_embedded(
            valid_pdf_bytes,
            output,
            "https://example.com",
            "user",
            "pass",
            120,
            page=0,
            position="br",
            name="Test User",
            reason="Test",
        )

    assert result.ok
    assert result.output_path == output
    assert result.output_size > 0
    assert output.exists()
    assert output.read_bytes()[:5] == b"%PDF-"


def test_sign_embedded_auth_error(valid_pdf_bytes, tmp_path):
    """AuthError from signing should produce auth_failed=True."""
    output = tmp_path / "signed.pdf"
    mock_transport = Mock()
    mock_transport.sign_data = Mock(side_effect=AuthError("invalid credentials"))

    with (
        patch("revenant.ui.workflows.register_active_profile_tls"),
        patch("revenant.network.SoapSigningTransport", return_value=mock_transport),
    ):
        result = sign_one_embedded(
            valid_pdf_bytes,
            output,
            "https://example.com",
            "user",
            "pass",
            120,
            page=0,
        )

    assert not result.ok
    assert result.auth_failed
    assert "invalid credentials" in (result.error_message or "")
    assert not output.exists()


def test_sign_embedded_tls_error(valid_pdf_bytes, tmp_path):
    """TLSError should produce tls_error=True."""
    output = tmp_path / "signed.pdf"

    with (
        patch("revenant.ui.workflows.register_active_profile_tls"),
        patch(
            "revenant.network.SoapSigningTransport",
            side_effect=TLSError("connection refused"),
        ),
    ):
        result = sign_one_embedded(
            valid_pdf_bytes,
            output,
            "https://example.com",
            "user",
            "pass",
            120,
        )

    assert not result.ok
    assert result.tls_error
    assert "connection refused" in (result.error_message or "")


def test_sign_embedded_revenant_error(tmp_path):
    """RevenantError (e.g., non-PDF input) should produce generic failure."""
    output = tmp_path / "signed.pdf"

    with (
        patch("revenant.ui.workflows.register_active_profile_tls"),
        patch("revenant.network.SoapSigningTransport", return_value=Mock()),
    ):
        result = sign_one_embedded(
            b"not a pdf",
            output,
            "https://example.com",
            "user",
            "pass",
            120,
        )

    assert not result.ok
    assert not result.auth_failed
    assert result.error_message is not None


def test_sign_embedded_permission_error_on_write(valid_pdf_bytes, mock_transport, tmp_path):
    """PermissionError during atomic_write should produce failure."""
    output = tmp_path / "signed.pdf"
    mock_transport.sign_data = Mock(return_value=FAKE_CMS)

    with (
        patch("revenant.ui.workflows.register_active_profile_tls"),
        patch("revenant.network.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.ui.workflows.atomic_write", side_effect=PermissionError("denied")),
    ):
        result = sign_one_embedded(
            valid_pdf_bytes,
            output,
            "https://example.com",
            "user",
            "pass",
            120,
            page=0,
            position="br",
            name="Test",
        )

    assert not result.ok
    assert "Permission denied" in (result.error_message or "")


def test_sign_embedded_registers_tls(valid_pdf_bytes, mock_transport, tmp_path):
    """Workflow should call register_active_profile_tls."""
    output = tmp_path / "signed.pdf"
    mock_transport.sign_data = Mock(return_value=FAKE_CMS)

    with (
        patch("revenant.ui.workflows.register_active_profile_tls") as mock_tls,
        patch("revenant.network.SoapSigningTransport", return_value=mock_transport),
    ):
        sign_one_embedded(
            valid_pdf_bytes,
            output,
            "https://example.com",
            "user",
            "pass",
            120,
            page=0,
            position="br",
            name="Test",
        )

    mock_tls.assert_called_once()


# ── sign_one_detached tests ──────────────────────────────────────


def test_sign_detached_happy_path(valid_pdf_bytes, mock_transport, tmp_path):
    """Valid PDF should produce detached .p7s signature."""
    output = tmp_path / "doc.p7s"
    fake_cms = b"\x30\x82\x01\x00"
    mock_transport.sign_pdf_detached = Mock(return_value=fake_cms)

    with (
        patch("revenant.ui.workflows.register_active_profile_tls"),
        patch("revenant.network.SoapSigningTransport", return_value=mock_transport),
    ):
        result = sign_one_detached(
            valid_pdf_bytes, output, "https://example.com", "user", "pass", 120
        )

    assert result.ok
    assert result.output_path == output
    assert result.output_size == len(fake_cms)
    assert output.exists()
    assert output.read_bytes() == fake_cms


def test_sign_detached_auth_error(valid_pdf_bytes, tmp_path):
    """AuthError should produce auth_failed=True."""
    output = tmp_path / "doc.p7s"
    mock_transport = Mock()
    mock_transport.sign_pdf_detached = Mock(side_effect=AuthError("locked"))

    with (
        patch("revenant.ui.workflows.register_active_profile_tls"),
        patch("revenant.network.SoapSigningTransport", return_value=mock_transport),
    ):
        result = sign_one_detached(
            valid_pdf_bytes, output, "https://example.com", "user", "pass", 120
        )

    assert not result.ok
    assert result.auth_failed


def test_sign_detached_tls_error(valid_pdf_bytes, tmp_path):
    """TLSError should produce tls_error=True."""
    output = tmp_path / "doc.p7s"

    with (
        patch("revenant.ui.workflows.register_active_profile_tls"),
        patch(
            "revenant.network.SoapSigningTransport",
            side_effect=TLSError("timeout", retryable=True),
        ),
    ):
        result = sign_one_detached(
            valid_pdf_bytes, output, "https://example.com", "user", "pass", 120
        )

    assert not result.ok
    assert result.tls_error


def test_sign_detached_permission_error(valid_pdf_bytes, mock_transport, tmp_path):
    """PermissionError on write should produce failure."""
    output = tmp_path / "doc.p7s"
    fake_cms = b"\x30\x82\x01\x00"
    mock_transport.sign_pdf_detached = Mock(return_value=fake_cms)

    with (
        patch("revenant.ui.workflows.register_active_profile_tls"),
        patch("revenant.network.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.ui.workflows.atomic_write", side_effect=PermissionError("denied")),
    ):
        result = sign_one_detached(
            valid_pdf_bytes, output, "https://example.com", "user", "pass", 120
        )

    assert not result.ok
    assert "Permission denied" in (result.error_message or "")


def test_sign_detached_non_pdf(tmp_path):
    """Non-PDF input should produce failure result."""
    output = tmp_path / "doc.p7s"

    with (
        patch("revenant.ui.workflows.register_active_profile_tls"),
        patch("revenant.network.SoapSigningTransport", return_value=Mock()),
    ):
        result = sign_one_detached(b"not a pdf", output, "https://example.com", "user", "pass", 120)

    assert not result.ok
    assert result.error_message is not None


# ── format_verify_results tests ──────────────────────────────────


def test_format_verify_single_valid():
    results: list[VerificationResult] = [
        {
            "valid": True,
            "structure_ok": True,
            "hash_ok": True,
            "details": ["Hash OK", "Structure OK"],
            "signer": {"name": "John Doe", "email": "john@example.com"},
        }
    ]
    vr = format_verify_results(results)
    assert vr.all_valid
    assert vr.total_count == 1
    assert vr.failed_count == 0
    assert len(vr.entries) == 1
    assert vr.entries[0].valid
    assert vr.entries[0].signer_name == "John Doe"
    assert vr.entries[0].detail_lines == ["Hash OK", "Structure OK"]


def test_format_verify_single_failed():
    results: list[VerificationResult] = [
        {
            "valid": False,
            "structure_ok": True,
            "hash_ok": False,
            "details": ["Hash MISMATCH"],
            "signer": None,
        }
    ]
    vr = format_verify_results(results)
    assert not vr.all_valid
    assert vr.failed_count == 1
    assert not vr.entries[0].valid
    assert vr.entries[0].signer_name == "Unknown"


def test_format_verify_multi_mixed():
    results: list[VerificationResult] = [
        {
            "valid": True,
            "structure_ok": True,
            "hash_ok": True,
            "details": ["OK"],
            "signer": {"name": "Alice"},
        },
        {
            "valid": False,
            "structure_ok": False,
            "hash_ok": False,
            "details": ["FAILED"],
            "signer": {"name": "Bob"},
        },
    ]
    vr = format_verify_results(results)
    assert not vr.all_valid
    assert vr.total_count == 2
    assert vr.failed_count == 1
    assert vr.entries[0].valid
    assert vr.entries[0].signer_name == "Alice"
    assert not vr.entries[1].valid
    assert vr.entries[1].signer_name == "Bob"
    assert vr.entries[0].total == 2
    assert vr.entries[1].total == 2


def test_format_verify_no_signer_info():
    results: list[VerificationResult] = [
        {
            "valid": True,
            "structure_ok": True,
            "hash_ok": True,
            "details": ["OK"],
            "signer": None,
        }
    ]
    vr = format_verify_results(results)
    assert vr.entries[0].signer_name == "Unknown"


def test_format_verify_signer_no_name():
    """Signer dict exists but has no 'name' key."""
    results: list[VerificationResult] = [
        {
            "valid": True,
            "structure_ok": True,
            "hash_ok": True,
            "details": ["OK"],
            "signer": {"email": "test@example.com"},
        }
    ]
    vr = format_verify_results(results)
    assert vr.entries[0].signer_name == "Unknown"


def test_format_verify_multiline_details():
    """Multi-line detail strings should be split into separate lines."""
    results: list[VerificationResult] = [
        {
            "valid": True,
            "structure_ok": True,
            "hash_ok": True,
            "details": ["Line 1\nLine 2\nLine 3"],
            "signer": None,
        }
    ]
    vr = format_verify_results(results)
    assert vr.entries[0].detail_lines == ["Line 1", "Line 2", "Line 3"]


def test_format_verify_empty():
    """Empty results list should produce empty VerifyResult."""
    vr = format_verify_results([])
    assert vr.all_valid
    assert vr.total_count == 0
    assert vr.failed_count == 0
    assert vr.entries == []


# ── resolve_sig_fields tests ─────────────────────────────────────


def test_resolve_sig_fields_no_profile():
    with patch("revenant.ui.workflows.get_active_profile", return_value=None):
        assert resolve_sig_fields() is None


def test_resolve_sig_fields_no_sig_fields():
    profile = Mock()
    profile.sig_fields = ()
    with patch("revenant.ui.workflows.get_active_profile", return_value=profile):
        assert resolve_sig_fields() is None


def test_resolve_sig_fields_with_fields():
    profile = Mock()
    profile.cert_fields = ("cert1",)
    profile.sig_fields = ("field1",)  # truthy tuple
    signer_info = {"name": "John Doe 12345"}
    cert_values = {"name": "John Doe", "gov_id": "12345"}

    with (
        patch("revenant.ui.workflows.get_active_profile", return_value=profile),
        patch("revenant.ui.workflows.get_signer_info", return_value=signer_info),
        patch(
            "revenant.ui.workflows.extract_cert_fields",
            return_value=cert_values,
        ) as mock_cert,
        patch(
            "revenant.ui.workflows.extract_display_fields",
            return_value=["John Doe", "SSN: 12345"],
        ) as mock_display,
    ):
        result = resolve_sig_fields()

    assert result == ["John Doe", "SSN: 12345"]
    mock_cert.assert_called_once_with(("cert1",), signer_info)
    mock_display.assert_called_once_with(("field1",), cert_values)
