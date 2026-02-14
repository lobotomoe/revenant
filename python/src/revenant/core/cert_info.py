# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
"""
Certificate information extraction from CMS/PKCS#7 blobs, X.509 certs, and signed PDFs.

Includes identity discovery via enum-certificates (preferred) or dummy-hash
signing (fallback).  Pure data-parsing functions are used by any code that
needs signer info from an existing signature.
"""

from __future__ import annotations

__all__ = [
    "discover_identity_from_server",
    "extract_all_cert_info_from_pdf",
    "extract_cert_info_from_cms",
    "extract_cert_info_from_pdf",
    "extract_cert_info_from_x509",
]

import datetime
import logging
import re
from typing import TYPE_CHECKING

from asn1crypto import cms as asn1_cms
from asn1crypto import x509 as asn1_x509

from ..constants import SHA1_DIGEST_SIZE
from ..errors import AuthError, CertificateError, RevenantError
from .pdf import BYTERANGE_PATTERN, extract_cms_from_byterange_match

if TYPE_CHECKING:
    from ..network.protocol import SigningTransport

_logger = logging.getLogger(__name__)

# OIDs for common subject fields
_OID_CN = "2.5.4.3"
_OID_EMAIL = "1.2.840.113549.1.9.1"
_OID_ORG = "2.5.4.10"


def _extract_info_from_cert_object(cert: asn1_x509.Certificate) -> dict[str, str | None]:
    """Extract CN, email, org, dn from an asn1crypto certificate object.

    Also logs warnings for expired or not-yet-valid certificates.
    """
    subject = cert.subject

    # Warn about certificate validity issues
    try:
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
        now = datetime.datetime.now(datetime.timezone.utc)
        if not_before and now < not_before:
            _logger.warning("Certificate is not yet valid (notBefore: %s)", not_before)
        elif not_after and now > not_after:
            _logger.warning("Certificate has expired (notAfter: %s)", not_after)
    except (KeyError, TypeError, ValueError) as e:
        _logger.debug("Cannot check certificate validity dates: %s", e)

    # Extract individual fields by OID
    fields: dict[str, str | None] = {"name": None, "email": None, "organization": None}
    oid_map = {_OID_CN: "name", _OID_EMAIL: "email", _OID_ORG: "organization"}

    for rdn in subject.chosen:
        for attr in rdn:
            oid = attr["type"].dotted
            if oid in oid_map:
                fields[oid_map[oid]] = attr["value"].native

    fields["dn"] = subject.human_friendly
    return fields


def extract_cert_info_from_cms(cms_der: bytes) -> dict[str, str | None]:
    """
    Extract signer certificate info from a CMS/PKCS#7 DER blob.

    Uses ``asn1crypto`` for lenient PKCS#7 parsing — handles certificates
    with BMPString-encoded DN fields (e.g. EKENG's CA uses BMPString for CN/O).

    Args:
        cms_der: Raw DER-encoded CMS/PKCS#7 bytes.

    Returns:
        dict with keys: name (CN), email, organization, dn (full subject).

    Raises:
        RevenantError if parsing fails or no certificate found.
    """
    try:
        content_info = asn1_cms.ContentInfo.load(cms_der)
        signed_data = content_info["content"]
        certs = signed_data["certificates"]
    except (ValueError, TypeError, KeyError, OSError) as e:
        raise CertificateError(f"Failed to parse CMS/PKCS#7 blob: {e}") from e

    if not certs:
        raise CertificateError("No certificate subject found in CMS blob.")

    cert = certs[0].chosen
    return _extract_info_from_cert_object(cert)


def extract_cert_info_from_x509(cert_der: bytes) -> dict[str, str | None]:
    """
    Extract signer info from a raw DER-encoded X.509 certificate.

    Args:
        cert_der: Raw DER-encoded X.509 certificate bytes.

    Returns:
        dict with keys: name (CN), email, organization, dn (full subject).

    Raises:
        RevenantError if parsing fails.
    """
    try:
        cert = asn1_x509.Certificate.load(cert_der)
    except (ValueError, TypeError, OSError) as e:
        raise CertificateError(f"Failed to parse X.509 certificate: {e}") from e

    return _extract_info_from_cert_object(cert)


def extract_all_cert_info_from_pdf(pdf_bytes: bytes) -> list[dict[str, str | None]]:
    """
    Extract signer certificate info from ALL signatures in a signed PDF.

    Args:
        pdf_bytes: Raw bytes of a signed PDF.

    Returns:
        list[dict] — one dict per signature, each with keys:
            name (CN), email, organization, dn (full subject).
        Duplicates are removed (same DN).

    Raises:
        RevenantError: If the PDF has no signatures or extraction fails.
    """
    br_matches = list(re.finditer(BYTERANGE_PATTERN, pdf_bytes))
    if not br_matches:
        raise CertificateError("No embedded signature found in this PDF.")

    results = []
    seen_dns: set[str] = set()
    for br in br_matches:
        try:
            cms_der = extract_cms_from_byterange_match(pdf_bytes, br)
            info = extract_cert_info_from_cms(cms_der)
            dn = info.get("dn", "")
            if dn and dn not in seen_dns:
                seen_dns.add(dn)
                results.append(info)
        except RevenantError as exc:  # noqa: PERF203 -- each iteration parses independent CMS blobs; try-except must be per-item
            _logger.debug("Skipping signature (extraction failed): %s", exc)
            continue

    if not results:
        raise CertificateError("Could not extract any certificate info from PDF signatures.")

    return results


def extract_cert_info_from_pdf(pdf_bytes: bytes) -> dict[str, str | None]:
    """
    Extract signer certificate info from a signed PDF.

    If there are multiple signatures, returns the last one.
    Use extract_all_cert_info_from_pdf() to get all signers.

    Args:
        pdf_bytes: Raw bytes of a signed PDF.

    Returns:
        dict with keys: name (CN), email, organization, dn (full subject).

    Raises:
        RevenantError if the PDF has no signature or parsing fails.
    """
    all_info = extract_all_cert_info_from_pdf(pdf_bytes)
    return all_info[-1]


def discover_identity_from_server(
    transport: SigningTransport, username: str, password: str, timeout: int
) -> dict[str, str | None]:
    """
    Discover signer identity from the server.

    Tries enum-certificates first (cleaner, no dummy signing), falls back
    to signing a dummy SHA-1 hash if the server doesn't support it.

    Args:
        transport: Signing transport to use for the SOAP call.
        username: Revenant username.
        password: Revenant password.
        timeout: Request timeout in seconds.

    Returns:
        dict with keys: name (CN), email, organization, dn.

    Raises:
        AuthError: If credentials are wrong.
        RevenantError: If the server rejects the request.
        TLSError: On connection issues.
    """
    # Try enum-certificates (preferred: gets cert directly, no signing)
    url = getattr(transport, "url", None)
    if url:
        try:
            from ..network.soap_transport import enum_certificates

            certs = enum_certificates(url, username, password, timeout)
            if certs:
                _logger.debug("Identity discovered via enum-certificates")
                return extract_cert_info_from_x509(certs[0])
            _logger.debug("enum-certificates returned no certificates")
        except AuthError:
            raise  # Auth errors must propagate immediately
        except (RevenantError, ValueError, TypeError, KeyError, OSError):
            _logger.debug("enum-certificates not available, falling back to dummy-hash")

    # Fallback: sign dummy hash and extract cert from CMS
    _logger.debug("Discovering identity via dummy-hash signing")
    dummy_hash = b"\x00" * SHA1_DIGEST_SIZE
    cms_der = transport.sign_hash(dummy_hash, username, password, timeout)
    return extract_cert_info_from_cms(cms_der)
