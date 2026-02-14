"""Shared signing and verification workflows.

UI-agnostic orchestration of signing and verification operations.
CLI and GUI are thin wrappers around these functions.

Constraints:
- No stdout/stderr output (no print)
- No sys.exit()
- No tkinter imports
- No argparse imports
- No threading (caller's responsibility)
- Returns structured results, never raises on business errors
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..config import (
    get_active_profile,
    get_signer_info,
    register_active_profile_tls,
)
from ..constants import DEFAULT_POSITION
from ..core.appearance import extract_cert_fields, extract_display_fields
from ..errors import AuthError, RevenantError, TLSError
from .helpers import atomic_write

if TYPE_CHECKING:
    from pathlib import Path

    from ..core.pdf import VerificationResult

_logger = logging.getLogger(__name__)


# ── Result types ──────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SigningResult:
    """Result of a single signing operation."""

    ok: bool
    auth_failed: bool = False
    tls_error: bool = False
    error_message: str | None = None
    output_path: Path | None = None
    output_size: int = 0


@dataclass(frozen=True, slots=True)
class VerifyEntry:
    """Structured verification data for a single signature."""

    index: int
    total: int
    valid: bool
    signer_name: str
    detail_lines: list[str]


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Structured verification results for all signatures in a PDF."""

    all_valid: bool
    total_count: int
    failed_count: int
    entries: list[VerifyEntry]


# ── Error classification ──────────────────────────────────────────


def _classify_error(error: Exception) -> SigningResult:
    """Convert a caught exception into a SigningResult."""
    if isinstance(error, AuthError):
        return SigningResult(ok=False, auth_failed=True, error_message=str(error))

    if isinstance(error, TLSError):
        return SigningResult(ok=False, tls_error=True, error_message=str(error))

    if isinstance(error, (RevenantError, ValueError)):
        return SigningResult(ok=False, error_message=str(error))

    _logger.exception("Unexpected error during signing")
    return SigningResult(
        ok=False,
        error_message="An unexpected error occurred. Check logs for details.",
    )


# ── Signing workflows ────────────────────────────────────────────


def sign_one_embedded(
    pdf_bytes: bytes,
    output_path: Path,
    url: str,
    username: str,
    password: str,
    timeout: int,
    *,
    name: str | None = None,
    position: str = DEFAULT_POSITION,
    page: int | str = "last",
    image_path: str | None = None,
    visible: bool = True,
    font: str | None = None,
    reason: str = "Signed with Revenant",
    fields: list[str] | None = None,
) -> SigningResult:
    """Orchestrate embedded PDF signing.

    Creates transport, calls core signing, writes output atomically.
    Never raises on business errors -- all captured in the result.

    Args:
        pdf_bytes: Raw PDF file content (caller reads the file).
        output_path: Where to write the signed PDF.
        url: SOAP endpoint URL.
        username: Authentication username.
        password: Authentication password.
        timeout: Request timeout in seconds.
        name: Signer display name for the signature field.
        position: Signature position preset.
        page: Page for signature (0-based int, "first", or "last").
        image_path: Optional path to signature image.
        visible: If False, create invisible signature.
        font: Font registry key.
        reason: Signature reason string.
        fields: Pre-extracted display fields for the appearance.

    Returns:
        SigningResult with outcome, output path, and size.
    """
    try:
        from ..core.signing import sign_pdf_embedded
        from ..network import SoapSigningTransport

        register_active_profile_tls()
        transport = SoapSigningTransport(url)
        signed_pdf = sign_pdf_embedded(
            pdf_bytes,
            transport,
            username,
            password,
            timeout,
            name=name,
            position=position,
            page=page,
            reason=reason,
            image_path=image_path,
            fields=fields,
            visible=visible,
            font=font,
        )
    except Exception as e:
        return _classify_error(e)

    try:
        atomic_write(output_path, signed_pdf)
    except PermissionError:
        return SigningResult(
            ok=False,
            error_message=f"Permission denied: {output_path}",
        )

    return SigningResult(
        ok=True,
        output_path=output_path,
        output_size=len(signed_pdf),
    )


def sign_one_detached(
    pdf_bytes: bytes,
    output_path: Path,
    url: str,
    username: str,
    password: str,
    timeout: int,
) -> SigningResult:
    """Orchestrate detached PDF signing.

    Creates transport, calls core signing, writes output atomically.
    Never raises on business errors -- all captured in the result.

    Args:
        pdf_bytes: Raw PDF file content (caller reads the file).
        output_path: Where to write the .p7s signature.
        url: SOAP endpoint URL.
        username: Authentication username.
        password: Authentication password.
        timeout: Request timeout in seconds.

    Returns:
        SigningResult with outcome, output path, and size.
    """
    try:
        from ..core.signing import sign_pdf_detached
        from ..network import SoapSigningTransport

        register_active_profile_tls()
        transport = SoapSigningTransport(url)
        cms_signature = sign_pdf_detached(pdf_bytes, transport, username, password, timeout)
    except Exception as e:
        return _classify_error(e)

    try:
        atomic_write(output_path, cms_signature)
    except PermissionError:
        return SigningResult(
            ok=False,
            error_message=f"Permission denied: {output_path}",
        )

    return SigningResult(
        ok=True,
        output_path=output_path,
        output_size=len(cms_signature),
    )


# ── Verification workflow ─────────────────────────────────────────


def format_verify_results(results: list[VerificationResult]) -> VerifyResult:
    """Convert raw verification results into structured display data.

    Args:
        results: Raw verification results from verify_all_embedded_signatures.

    Returns:
        VerifyResult with structured entries for UI display.
    """
    total = len(results)
    entries: list[VerifyEntry] = []
    failed = 0

    for i, result in enumerate(results):
        signer = result.get("signer")
        signer_name = (signer.get("name") or "Unknown") if signer else "Unknown"
        valid = result["valid"]
        if not valid:
            failed += 1

        detail_lines: list[str] = []
        for detail in result["details"]:
            detail_lines.extend(detail.split("\n"))

        entries.append(
            VerifyEntry(
                index=i,
                total=total,
                valid=valid,
                signer_name=signer_name,
                detail_lines=detail_lines,
            )
        )

    return VerifyResult(
        all_valid=(failed == 0),
        total_count=total,
        failed_count=failed,
        entries=entries,
    )


# ── Field extraction helper ──────────────────────────────────────


def resolve_sig_fields() -> list[str] | None:
    """Extract display fields from the active profile's sig_fields config.

    Returns:
        Ordered list of display strings, or None if no sig_fields configured.
    """
    profile = get_active_profile()
    if not profile or not profile.sig_fields:
        return None
    signer_info = get_signer_info()
    cert_values = extract_cert_fields(profile.cert_fields, signer_info)
    return extract_display_fields(profile.sig_fields, cert_values)
