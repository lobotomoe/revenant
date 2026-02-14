"""High-level convenience API for PDF signing.

Provides :func:`sign` and :func:`sign_detached` that handle profile
resolution, transport creation, TLS registration, and appearance defaults
automatically.

For lower-level control, use :func:`~revenant.core.signing.sign_pdf_embedded`
and :func:`~revenant.core.signing.sign_pdf_detached` directly with a
:class:`~revenant.network.soap_transport.SoapSigningTransport`.
"""

from __future__ import annotations

__all__ = ["sign", "sign_detached"]

import logging

from .config import (
    get_active_profile,
    get_server_config,
    get_signer_info,
    get_signer_name,
    register_profile_tls_mode,
)
from .config.profiles import ServerProfile, get_profile, make_custom_profile
from .constants import DEFAULT_TIMEOUT_SOAP
from .core.appearance import extract_cert_fields, extract_display_fields
from .core.signing import EmbeddedSignatureOptions, sign_pdf_detached, sign_pdf_embedded
from .errors import ConfigError
from .network.soap_transport import SoapSigningTransport

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Private resolution helpers
# ---------------------------------------------------------------------------


def _resolve_profile(
    profile: str | None,
    url: str | None,
) -> ServerProfile | None:
    """Resolve a ServerProfile from explicit args or saved config.

    Priority:
        1. ``profile`` name -> built-in profile lookup.
        2. ``url`` -> ad-hoc custom profile.
        3. Saved config via :func:`get_active_profile`.
    """
    if profile is not None and url is not None:
        raise ConfigError("Cannot specify both 'profile' and 'url'. Use one or the other.")

    if profile is not None:
        return get_profile(profile)

    if url is not None:
        return make_custom_profile(url)

    return get_active_profile()


def _resolve_url_and_timeout(
    profile_obj: ServerProfile | None,
    explicit_url: str | None,
    explicit_timeout: int | None,
) -> tuple[str, int]:
    """Resolve final URL and timeout values.

    Raises:
        ConfigError: If no URL can be determined from any source.
    """
    url: str | None = explicit_url
    if url is None and profile_obj is not None:
        url = profile_obj.url

    timeout = explicit_timeout
    if timeout is None and profile_obj is not None:
        timeout = profile_obj.timeout

    if not url:
        config_url, config_timeout, _ = get_server_config()
        if config_url:
            url = config_url
            if timeout is None:
                timeout = config_timeout
        else:
            raise ConfigError(
                "No server URL configured. "
                "Pass url='https://...' or profile='ekeng', "
                "or run `revenant setup` to save a profile."
            )

    if timeout is None:
        timeout = DEFAULT_TIMEOUT_SOAP

    return url, timeout


def _resolve_sig_fields(profile_obj: ServerProfile | None) -> list[str] | None:
    """Extract display fields from profile's sig_fields + signer info."""
    if profile_obj is None or not profile_obj.sig_fields:
        return None
    signer_info = get_signer_info()
    cert_values = extract_cert_fields(profile_obj.cert_fields, signer_info)
    return extract_display_fields(profile_obj.sig_fields, cert_values)


def _setup_transport(
    url: str,
    profile_obj: ServerProfile | None,
) -> SoapSigningTransport:
    """Register TLS mode and create transport."""
    if profile_obj is not None:
        register_profile_tls_mode(profile_obj)
    return SoapSigningTransport(url)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sign(
    pdf_bytes: bytes,
    username: str,
    password: str,
    *,
    profile: str | None = None,
    url: str | None = None,
    timeout: int | None = None,
    options: EmbeddedSignatureOptions | None = None,
    page: int | str = "last",
    position: str = "right-bottom",
    x: float | None = None,
    y: float | None = None,
    w: float | None = None,
    h: float | None = None,
    reason: str = "Signed with Revenant",
    name: str | None = None,
    image_path: str | None = None,
    fields: list[str] | None = None,
    visible: bool = True,
    font: str | None = None,
) -> bytes:
    """Sign a PDF with an embedded signature.

    High-level convenience function that handles profile resolution,
    transport creation, TLS registration, and appearance defaults
    automatically.

    Server resolution (first match wins):
        1. ``profile="ekeng"`` -- look up a built-in server profile.
        2. ``url="https://..."`` -- use a custom SOAP endpoint.
        3. Saved configuration from ``revenant setup``.

    When *name*, *font*, or *fields* are not provided explicitly they are
    auto-resolved from the server profile and saved signer identity.

    Args:
        pdf_bytes: Raw PDF file content.
        username: CoSign username.
        password: CoSign password.
        profile: Built-in profile name (e.g. ``"ekeng"``).
            Mutually exclusive with *url*.
        url: SOAP endpoint URL. Mutually exclusive with *profile*.
        timeout: Request timeout in seconds. Auto-resolved if ``None``.
        options: Reusable options object. Individual keyword arguments
            below override the corresponding fields in *options*.
        page: Target page -- 0-based ``int``, ``"first"``, or ``"last"``.
        position: Position preset (``"right-bottom"``, ``"left-top"``, etc.).
        x: Manual x-coordinate in PDF points (overrides *position*).
        y: Manual y-coordinate in PDF points (overrides *position*).
        w: Signature field width in PDF points.
        h: Signature field height in PDF points.
        reason: Signature reason string.
        name: Signer display name. Auto-resolved from config if ``None``.
        image_path: Path to a PNG/JPEG signature image.
        fields: Display strings for the signature appearance.
            Auto-resolved from profile if ``None``.
        visible: Set to ``False`` for an invisible signature.
        font: Font key (``"noto-sans"``, ``"ghea-grapalat"``, etc.).
            Auto-resolved from profile if ``None``.

    Returns:
        Complete PDF with embedded signature.

    Raises:
        ConfigError: If no server URL can be resolved.
        AuthError: If credentials are invalid.
        PDFError: If the input is not a valid PDF.
        TLSError: On connection or TLS issues.
        ServerError: If the server returned an error.
    """
    profile_obj = _resolve_profile(profile, url)
    resolved_url, resolved_timeout = _resolve_url_and_timeout(profile_obj, url, timeout)

    # Auto-resolve name from saved config
    resolved_name = name if name is not None else get_signer_name()

    # Auto-resolve font from profile
    resolved_font = font
    if resolved_font is None and profile_obj is not None:
        resolved_font = profile_obj.font

    # Auto-resolve signature fields from profile
    resolved_fields = fields
    if resolved_fields is None and visible:
        resolved_fields = _resolve_sig_fields(profile_obj)

    transport = _setup_transport(resolved_url, profile_obj)

    # Build kwargs -- only include optional geometry if explicitly provided
    signing_kwargs: dict[str, object] = {
        "page": page,
        "position": position,
        "reason": reason,
        "name": resolved_name,
        "fields": resolved_fields,
        "visible": visible,
        "font": resolved_font,
    }
    if x is not None:
        signing_kwargs["x"] = x
    if y is not None:
        signing_kwargs["y"] = y
    if w is not None:
        signing_kwargs["w"] = w
    if h is not None:
        signing_kwargs["h"] = h
    if image_path is not None:
        signing_kwargs["image_path"] = image_path

    return sign_pdf_embedded(
        pdf_bytes,
        transport,
        username,
        password,
        resolved_timeout,
        options=options,
        **signing_kwargs,
    )


def sign_detached(
    pdf_bytes: bytes,
    username: str,
    password: str,
    *,
    profile: str | None = None,
    url: str | None = None,
    timeout: int | None = None,
) -> bytes:
    """Sign a PDF and return a detached CMS/PKCS#7 signature.

    High-level convenience function that handles profile resolution,
    transport creation, and TLS registration automatically.

    Server resolution is identical to :func:`sign`.

    Args:
        pdf_bytes: Raw PDF file content.
        username: CoSign username.
        password: CoSign password.
        profile: Built-in profile name. Mutually exclusive with *url*.
        url: SOAP endpoint URL. Mutually exclusive with *profile*.
        timeout: Request timeout in seconds. Auto-resolved if ``None``.

    Returns:
        Detached CMS/PKCS#7 signature (DER-encoded).

    Raises:
        ConfigError: If no server URL can be resolved.
        AuthError: If credentials are invalid.
        PDFError: If the input is not a valid PDF.
        TLSError: On connection or TLS issues.
        ServerError: If the server returned an error.
    """
    profile_obj = _resolve_profile(profile, url)
    resolved_url, resolved_timeout = _resolve_url_and_timeout(profile_obj, url, timeout)
    transport = _setup_transport(resolved_url, profile_obj)

    return sign_pdf_detached(pdf_bytes, transport, username, password, resolved_timeout)
