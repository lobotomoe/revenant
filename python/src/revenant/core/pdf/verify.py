"""
Post-sign verification of embedded PDF signatures.

Extracts ByteRange data and CMS blobs, verifies hash consistency,
and checks structural validity.  Supports multi-signature PDFs.
"""

from __future__ import annotations

import hashlib
import io
import logging
import re
from typing import TypedDict

from ...errors import PDFError, RevenantError
from .. import require_pikepdf as _require_pikepdf
from .asn1 import ASN1_SEQUENCE_TAG, MIN_CMS_SIZE
from .cms_extraction import (
    BYTERANGE_PATTERN,
    extract_signature_data_from_match,
)
from .cms_info import extract_digest_info, extract_signer_info

_logger = logging.getLogger(__name__)


class VerificationResult(TypedDict):
    """Result of signature verification (single signature)."""

    valid: bool  # Overall result
    structure_ok: bool  # ByteRange and CMS structure valid
    hash_ok: bool  # Hash matches expected value
    details: list[str]  # Human-readable messages
    signer: dict[str, str | None] | None  # Certificate info (name, email, org, dn)


def _verify_signature_match(
    pdf_bytes: bytes,
    br_match: re.Match[bytes],
    expected_hash: bytes | None = None,
) -> VerificationResult:
    """Core verification logic for a single ByteRange match.

    Args:
        pdf_bytes: Complete PDF file bytes.
        br_match: Regex match from BYTERANGE_PATTERN.
        expected_hash: If provided, the exact hash sent for signing (SHA-1).

    Returns:
        Verification result for this signature.
    """
    details: list[str] = []
    structure_ok = True

    # ── 1. Extract signature data ────────────────────────────────
    try:
        signed_data, cms_der = extract_signature_data_from_match(pdf_bytes, br_match)
        details.append(f"ByteRange OK -- signed data: {len(signed_data)} bytes")
        details.append(f"CMS blob: {len(cms_der)} bytes")
    except RevenantError as e:
        return {
            "valid": False,
            "structure_ok": False,
            "hash_ok": False,
            "details": [f"Structure error: {e}"],
            "signer": None,
        }

    # ── 2. CMS structure check ───────────────────────────────────
    if len(cms_der) < MIN_CMS_SIZE:
        structure_ok = False
        details.append(f"CMS too small ({len(cms_der)} bytes) -- likely corrupt")
    elif cms_der[0] != ASN1_SEQUENCE_TAG:
        structure_ok = False
        details.append("CMS does not start with ASN.1 SEQUENCE tag (0x30)")
    else:
        details.append("CMS: valid ASN.1 structure")

    # ── 3. Signer info ───────────────────────────────────────────
    signer = extract_signer_info(cms_der)
    if signer and signer.get("name"):
        details.append(f"Signer: {signer['name']}")

    # ── 4. Hash verification ─────────────────────────────────────
    hash_ok = False

    if expected_hash is not None:
        # Post-sign path: we know the exact SHA-1 hash sent to CoSign
        actual_hash = hashlib.sha1(signed_data).digest()
        if actual_hash == expected_hash:
            hash_ok = True
            details.append(f"Hash OK -- SHA-1 matches expected: {actual_hash.hex()}")
        else:
            details.append(
                f"Hash MISMATCH!\n"
                f"  ByteRange SHA-1: {actual_hash.hex()}\n"
                f"  Expected:        {expected_hash.hex()}"
            )
    else:
        # Standalone verification: determine algorithm from CMS
        digest_info = extract_digest_info(cms_der)
        if digest_info is not None:
            algo_name, cms_digest = digest_info
            actual_hash = hashlib.new(algo_name, signed_data).digest()
            algo_upper = algo_name.upper().replace("_", "-")
            if actual_hash == cms_digest:
                hash_ok = True
                details.append(
                    f"Hash OK -- {algo_upper} matches CMS messageDigest: {actual_hash.hex()}"
                )
            else:
                details.append(
                    f"Hash MISMATCH!\n"
                    f"  ByteRange {algo_upper}:   {actual_hash.hex()}\n"
                    f"  CMS messageDigest:  {cms_digest.hex()}"
                )
        elif len(cms_der) >= MIN_CMS_SIZE and cms_der[0] == ASN1_SEQUENCE_TAG:
            # Could not extract digest info (non-standard CMS) -- hash cannot
            # be verified without a reference value to compare against.
            actual_hash = hashlib.sha1(signed_data).digest()
            details.append(
                f"Hash computed -- SHA-1: {actual_hash.hex()} "
                "(CMS digest info not available -- cannot verify)"
            )
        else:
            details.append("Hash: cannot verify without expected hash and CMS is suspect")

    valid = structure_ok and hash_ok
    return {
        "valid": valid,
        "structure_ok": structure_ok,
        "hash_ok": hash_ok,
        "details": details,
        "signer": signer,
    }


def verify_embedded_signature(
    pdf_bytes: bytes, expected_hash: bytes | None = None
) -> VerificationResult:
    """
    Verify the last embedded PDF signature.

    Checks:
    1. Structure -- ByteRange is valid, CMS is present, PDF readable by pikepdf
    2. Hash -- computed from ByteRange data, compared against CMS messageDigest
       (algorithm auto-detected) or expected_hash if provided
    3. CMS -- blob is non-empty and parseable

    For multi-signature PDFs, verifies only the last (most recent) signature.
    Use verify_all_embedded_signatures() to check all signatures.

    Args:
        pdf_bytes: The signed PDF.
        expected_hash: 20-byte SHA-1 hash that was sent to CoSign for signing.
            If provided, forces SHA-1 comparison against this exact value.

    Returns:
        VerificationResult with valid, structure_ok, hash_ok, details, signer.

    Never raises on verification failure -- returns valid=False with details.
    Raises RevenantError only on parse failures (not a signed PDF, etc.)
    """
    br_matches = list(re.finditer(BYTERANGE_PATTERN, pdf_bytes))
    if not br_matches:
        return {
            "valid": False,
            "structure_ok": False,
            "hash_ok": False,
            "details": ["Structure error: No /ByteRange found in PDF -- not a signed PDF?"],
            "signer": None,
        }

    result = _verify_signature_match(pdf_bytes, br_matches[-1], expected_hash)

    # pikepdf structural check (informational, does not override signature validity).
    # Some valid PDFs have non-standard page trees that pikepdf rejects.
    # The authoritative checks are ByteRange + hash above.
    pikepdf = _require_pikepdf()
    try:
        with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
            page_count = len(pdf.pages)
        result["details"].append(f"pikepdf: valid PDF, {page_count} page(s)")
    except (ValueError, RuntimeError, OSError, pikepdf.PdfError) as e:
        _logger.warning("pikepdf structural check failed (non-fatal): %s", e)
        result["details"].append(f"pikepdf: structural warning -- {e}")

    return result


def verify_all_embedded_signatures(pdf_bytes: bytes) -> list[VerificationResult]:
    """
    Verify ALL embedded signatures in a PDF.

    Iterates every /ByteRange in the PDF and verifies each signature
    independently.  The pikepdf structural check is performed once.

    Args:
        pdf_bytes: The signed PDF.

    Returns:
        List of VerificationResult, one per signature (ordered by position in PDF).

    Raises:
        RevenantError: If the PDF has no embedded signatures.
    """
    br_matches = list(re.finditer(BYTERANGE_PATTERN, pdf_bytes))
    if not br_matches:
        raise PDFError("No /ByteRange found in PDF -- not a signed PDF?")

    # pikepdf structural check (informational, does not override signature validity).
    pikepdf = _require_pikepdf()
    pikepdf_detail = ""
    try:
        with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
            pikepdf_detail = f"pikepdf: valid PDF, {len(pdf.pages)} page(s)"
    except (ValueError, RuntimeError, OSError, pikepdf.PdfError) as e:
        _logger.warning("pikepdf structural check failed (non-fatal): %s", e)
        pikepdf_detail = f"pikepdf: structural warning -- {e}"

    results: list[VerificationResult] = []
    for br in br_matches:
        result = _verify_signature_match(pdf_bytes, br)
        result["details"].append(pikepdf_detail)
        results.append(result)

    return results


# ── Detached signature verification ──────────────────────────────


def verify_detached_signature(
    data_bytes: bytes,
    cms_der: bytes,
) -> VerificationResult:
    """Verify a detached CMS/PKCS#7 signature against original data.

    Extracts the digest algorithm and messageDigest from the CMS blob,
    computes the hash of the original data, and compares.

    Args:
        data_bytes: The original data that was signed.
        cms_der: The detached CMS/PKCS#7 signature (DER-encoded).

    Returns:
        VerificationResult with valid, structure_ok, hash_ok, details, signer.
    """
    details: list[str] = []
    structure_ok = True

    # CMS structure check
    if len(cms_der) < MIN_CMS_SIZE:
        structure_ok = False
        details.append(f"CMS too small ({len(cms_der)} bytes) -- likely corrupt")
    elif cms_der[0] != ASN1_SEQUENCE_TAG:
        structure_ok = False
        details.append("CMS does not start with ASN.1 SEQUENCE tag (0x30)")
    else:
        details.append(f"CMS blob: {len(cms_der)} bytes, valid ASN.1 structure")

    # Signer info
    signer = extract_signer_info(cms_der)
    if signer and signer.get("name"):
        details.append(f"Signer: {signer['name']}")

    # Hash verification
    hash_ok = False
    digest_info = extract_digest_info(cms_der)
    if digest_info is not None:
        algo_name, cms_digest = digest_info
        actual_hash = hashlib.new(algo_name, data_bytes).digest()
        algo_upper = algo_name.upper().replace("_", "-")
        if actual_hash == cms_digest:
            hash_ok = True
            details.append(
                f"Hash OK -- {algo_upper} matches CMS messageDigest: {actual_hash.hex()}"
            )
        else:
            details.append(
                f"Hash MISMATCH!\n"
                f"  Data {algo_upper}:        {actual_hash.hex()}\n"
                f"  CMS messageDigest:  {cms_digest.hex()}"
            )
    else:
        details.append("Could not extract digest info -- hash verification unavailable")

    valid = structure_ok and hash_ok
    return {
        "valid": valid,
        "structure_ok": structure_ok,
        "hash_ok": hash_ok,
        "details": details,
        "signer": signer,
    }
