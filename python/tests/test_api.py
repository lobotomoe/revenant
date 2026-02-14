"""Tests for revenant.api -- high-level convenience API."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from revenant.api import sign, sign_detached
from revenant.config.profiles import BUILTIN_PROFILES
from revenant.errors import AuthError, ConfigError, TLSError

FAKE_PDF = b"%PDF-1.4\nfake\n%%EOF\n"
FAKE_SIGNED = b"%PDF-1.4\nsigned"
FAKE_CMS = b"\x30\x82\x01\x00"

EKENG_PROFILE = BUILTIN_PROFILES["ekeng"]


# ---------------------------------------------------------------------------
# _resolve_profile
# ---------------------------------------------------------------------------


def test_profile_and_url_mutually_exclusive():
    with pytest.raises(ConfigError, match="Cannot specify both"):
        sign(FAKE_PDF, "user", "pass", profile="ekeng", url="https://x")


def test_unknown_profile_raises():
    with pytest.raises(KeyError, match="Unknown profile"):
        sign(FAKE_PDF, "user", "pass", profile="nonexistent")


# ---------------------------------------------------------------------------
# URL resolution
# ---------------------------------------------------------------------------


def test_no_url_no_profile_no_config_raises():
    with (
        patch("revenant.api.get_active_profile", return_value=None),
        patch("revenant.api.get_server_config", return_value=(None, None, None)),
        pytest.raises(ConfigError, match="No server URL configured"),
    ):
        sign(FAKE_PDF, "user", "pass")


def test_url_from_saved_config():
    """Saved config URL is used when no profile or url given."""
    mock_transport = Mock()
    mock_transport.sign_data = Mock(return_value=FAKE_CMS)

    with (
        patch("revenant.api.get_active_profile", return_value=None),
        patch("revenant.api.get_server_config", return_value=("https://saved.com", 60, None)),
        patch("revenant.api.get_signer_name", return_value=None),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        result = sign(FAKE_PDF, "user", "pass")

    assert result == FAKE_SIGNED
    call_args = mock_sign.call_args
    assert call_args[0][1] == mock_transport
    assert call_args[0][4] == 60  # timeout from config


# ---------------------------------------------------------------------------
# sign() happy paths
# ---------------------------------------------------------------------------


def test_sign_with_profile():
    """sign(profile='ekeng') resolves URL, font, and TLS from the profile."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode") as mock_tls,
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport) as mock_ctor,
        patch("revenant.api.get_signer_name", return_value="Test User"),
        patch(
            "revenant.api.get_signer_info",
            return_value={"name": "Test 12345", "email": None, "organization": None, "dn": None},
        ),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        result = sign(FAKE_PDF, "user", "pass", profile="ekeng")

    assert result == FAKE_SIGNED
    mock_tls.assert_called_once_with(EKENG_PROFILE)
    mock_ctor.assert_called_once_with(EKENG_PROFILE.url)

    call_kwargs = mock_sign.call_args[1]
    assert call_kwargs["font"] == "ghea-grapalat"
    assert call_kwargs["name"] == "Test User"


def test_sign_with_url():
    """sign(url='...') creates a custom transport."""
    mock_transport = Mock()
    custom_url = "https://custom.example.com/DSS.asmx"

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport) as mock_ctor,
        patch("revenant.api.get_signer_name", return_value=None),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        result = sign(FAKE_PDF, "user", "pass", url=custom_url)

    assert result == FAKE_SIGNED
    mock_ctor.assert_called_once_with(custom_url)

    call_kwargs = mock_sign.call_args[1]
    assert call_kwargs["font"] == "noto-sans"  # custom profile default font


# ---------------------------------------------------------------------------
# Auto-resolution
# ---------------------------------------------------------------------------


def test_name_auto_resolved_from_config():
    """When name is not provided, it's resolved from get_signer_name()."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.get_signer_name", return_value="Config Name"),
        patch(
            "revenant.api.get_signer_info",
            return_value={"name": None, "email": None, "organization": None, "dn": None},
        ),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        sign(FAKE_PDF, "user", "pass", profile="ekeng")

    assert mock_sign.call_args[1]["name"] == "Config Name"


def test_name_explicit_overrides_config():
    """Explicit name= wins over auto-resolved config name."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.get_signer_name", return_value="Config Name"),
        patch(
            "revenant.api.get_signer_info",
            return_value={"name": None, "email": None, "organization": None, "dn": None},
        ),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        sign(FAKE_PDF, "user", "pass", profile="ekeng", name="Explicit Name")

    assert mock_sign.call_args[1]["name"] == "Explicit Name"


def test_font_auto_resolved_from_profile():
    """Font is auto-resolved from the profile when not explicitly provided."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.get_signer_name", return_value=None),
        patch(
            "revenant.api.get_signer_info",
            return_value={"name": None, "email": None, "organization": None, "dn": None},
        ),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        sign(FAKE_PDF, "user", "pass", profile="ekeng")

    assert mock_sign.call_args[1]["font"] == "ghea-grapalat"


def test_font_explicit_overrides_profile():
    """Explicit font= wins over profile default."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.get_signer_name", return_value=None),
        patch(
            "revenant.api.get_signer_info",
            return_value={"name": None, "email": None, "organization": None, "dn": None},
        ),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        sign(FAKE_PDF, "user", "pass", profile="ekeng", font="noto-sans")

    assert mock_sign.call_args[1]["font"] == "noto-sans"


def test_fields_auto_resolved_from_profile():
    """Signature fields are extracted from profile when not provided."""
    mock_transport = Mock()
    signer_info = {
        "name": "John Smith 12345",
        "email": "john@test.com",
        "organization": None,
        "dn": None,
    }

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.get_signer_name", return_value=None),
        patch("revenant.api.get_signer_info", return_value=signer_info),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        sign(FAKE_PDF, "user", "pass", profile="ekeng")

    resolved_fields = mock_sign.call_args[1]["fields"]
    assert resolved_fields is not None
    assert len(resolved_fields) >= 2  # at least name + SSN from ekeng profile
    assert any("John Smith" in f for f in resolved_fields)
    assert any("12345" in f for f in resolved_fields)


def test_fields_explicit_overrides_profile():
    """Explicit fields= wins over auto-resolved fields."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.get_signer_name", return_value=None),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        sign(FAKE_PDF, "user", "pass", profile="ekeng", fields=["Custom Field"])

    assert mock_sign.call_args[1]["fields"] == ["Custom Field"]


def test_fields_not_resolved_when_invisible():
    """Invisible signatures skip field resolution."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.get_signer_name", return_value=None),
        patch("revenant.api.get_signer_info") as mock_info,
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        sign(FAKE_PDF, "user", "pass", profile="ekeng", visible=False)

    mock_info.assert_not_called()
    assert mock_sign.call_args[1]["fields"] is None


# ---------------------------------------------------------------------------
# Timeout resolution
# ---------------------------------------------------------------------------


def test_timeout_explicit_overrides_profile():
    """Explicit timeout= wins over profile's timeout."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.get_signer_name", return_value=None),
        patch(
            "revenant.api.get_signer_info",
            return_value={"name": None, "email": None, "organization": None, "dn": None},
        ),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        sign(FAKE_PDF, "user", "pass", profile="ekeng", timeout=30)

    assert mock_sign.call_args[0][4] == 30  # 5th positional arg is timeout


def test_timeout_from_profile():
    """Profile timeout is used when no explicit timeout given."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.get_signer_name", return_value=None),
        patch(
            "revenant.api.get_signer_info",
            return_value={"name": None, "email": None, "organization": None, "dn": None},
        ),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        sign(FAKE_PDF, "user", "pass", profile="ekeng")

    assert mock_sign.call_args[0][4] == EKENG_PROFILE.timeout


# ---------------------------------------------------------------------------
# Geometry kwargs
# ---------------------------------------------------------------------------


def test_optional_geometry_not_passed_when_none():
    """x, y, w, h, image_path are not included in kwargs when None."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.get_signer_name", return_value=None),
        patch(
            "revenant.api.get_signer_info",
            return_value={"name": None, "email": None, "organization": None, "dn": None},
        ),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        sign(FAKE_PDF, "user", "pass", profile="ekeng")

    call_kwargs = mock_sign.call_args[1]
    assert "x" not in call_kwargs
    assert "y" not in call_kwargs
    assert "w" not in call_kwargs
    assert "h" not in call_kwargs
    assert "image_path" not in call_kwargs


def test_explicit_geometry_passed_through():
    """Explicit x, y, w, h values are forwarded to sign_pdf_embedded."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.get_signer_name", return_value=None),
        patch(
            "revenant.api.get_signer_info",
            return_value={"name": None, "email": None, "organization": None, "dn": None},
        ),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        sign(FAKE_PDF, "user", "pass", profile="ekeng", x=100, y=200, w=150, h=60)

    call_kwargs = mock_sign.call_args[1]
    assert call_kwargs["x"] == 100
    assert call_kwargs["y"] == 200
    assert call_kwargs["w"] == 150
    assert call_kwargs["h"] == 60


# ---------------------------------------------------------------------------
# Error propagation
# ---------------------------------------------------------------------------


def test_auth_error_propagates():
    """AuthError from the transport is not swallowed."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.get_signer_name", return_value=None),
        patch(
            "revenant.api.get_signer_info",
            return_value={"name": None, "email": None, "organization": None, "dn": None},
        ),
        patch("revenant.api.sign_pdf_embedded", side_effect=AuthError("bad creds")),
        pytest.raises(AuthError, match="bad creds"),
    ):
        sign(FAKE_PDF, "user", "pass", profile="ekeng")


def test_tls_error_propagates():
    """TLSError from the transport is not swallowed."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.get_signer_name", return_value=None),
        patch(
            "revenant.api.get_signer_info",
            return_value={"name": None, "email": None, "organization": None, "dn": None},
        ),
        patch("revenant.api.sign_pdf_embedded", side_effect=TLSError("connection refused")),
        pytest.raises(TLSError, match="connection refused"),
    ):
        sign(FAKE_PDF, "user", "pass", profile="ekeng")


# ---------------------------------------------------------------------------
# sign_detached
# ---------------------------------------------------------------------------


def test_sign_detached_with_profile():
    """sign_detached resolves profile and returns CMS bytes."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode") as mock_tls,
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport) as mock_ctor,
        patch("revenant.api.sign_pdf_detached", return_value=FAKE_CMS) as mock_sign,
    ):
        result = sign_detached(FAKE_PDF, "user", "pass", profile="ekeng")

    assert result == FAKE_CMS
    mock_tls.assert_called_once_with(EKENG_PROFILE)
    mock_ctor.assert_called_once_with(EKENG_PROFILE.url)
    mock_sign.assert_called_once()


def test_sign_detached_with_url():
    """sign_detached with explicit URL creates ad-hoc transport."""
    mock_transport = Mock()
    custom_url = "https://custom.com/DSS.asmx"

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport) as mock_ctor,
        patch("revenant.api.sign_pdf_detached", return_value=FAKE_CMS),
    ):
        result = sign_detached(FAKE_PDF, "user", "pass", url=custom_url)

    assert result == FAKE_CMS
    mock_ctor.assert_called_once_with(custom_url)


def test_sign_detached_no_url_raises():
    with (
        patch("revenant.api.get_active_profile", return_value=None),
        patch("revenant.api.get_server_config", return_value=(None, None, None)),
        pytest.raises(ConfigError, match="No server URL configured"),
    ):
        sign_detached(FAKE_PDF, "user", "pass")


def test_sign_detached_profile_and_url_raises():
    with pytest.raises(ConfigError, match="Cannot specify both"):
        sign_detached(FAKE_PDF, "user", "pass", profile="ekeng", url="https://x")


def test_timeout_fallback_to_default_when_config_has_none():
    """When saved config provides URL but no timeout, DEFAULT_TIMEOUT_SOAP is used."""
    mock_transport = Mock()

    with (
        patch("revenant.api.get_active_profile", return_value=None),
        patch("revenant.api.get_server_config", return_value=("https://saved.com", None, None)),
        patch("revenant.api.get_signer_name", return_value=None),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        result = sign(FAKE_PDF, "user", "pass")

    assert result == FAKE_SIGNED
    assert mock_sign.call_args[0][4] == 120  # DEFAULT_TIMEOUT_SOAP


def test_image_path_passed_through():
    """image_path should be forwarded to sign_pdf_embedded."""
    mock_transport = Mock()

    with (
        patch("revenant.api.register_profile_tls_mode"),
        patch("revenant.api.SoapSigningTransport", return_value=mock_transport),
        patch("revenant.api.get_signer_name", return_value=None),
        patch(
            "revenant.api.get_signer_info",
            return_value={"name": None, "email": None, "organization": None, "dn": None},
        ),
        patch("revenant.api.sign_pdf_embedded", return_value=FAKE_SIGNED) as mock_sign,
    ):
        sign(FAKE_PDF, "user", "pass", profile="ekeng", image_path="/tmp/sig.png")

    call_kwargs = mock_sign.call_args[1]
    assert call_kwargs["image_path"] == "/tmp/sig.png"
