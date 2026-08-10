# SPDX-License-Identifier: Apache-2.0
"""
Post-sign verification of embedded PDF signatures.

Extracts ByteRange data and CMS blobs, verifies hash consistency and the CMS
signer signature, and checks structural validity. Supports multi-signature PDFs.
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
    byterange_coverage,
    extract_signature_data_from_match,
)
from .cms_info import extract_digest_info, extract_signer_info
from .cms_signature import SignatureVerification, verify_signer_signature

_logger = logging.getLogger(__name__)


class SignatureCoverage(TypedDict):
    """How much of the file one signature covers."""

    covers_whole_file: bool  # ByteRange reaches EOF; False = bytes follow it
    covered_bytes: int  # Bytes the ByteRange actually covers
    total_bytes: int  # Size of the whole file


class VerificationResult(TypedDict):
    """Result of signature verification (single signature)."""

    valid: bool  # Overall result
    structure_ok: bool  # ByteRange and CMS structure valid
    hash_ok: bool  # CMS digest matches data (and optional expected hash matches)
    signature_valid: bool | None  # None = cryptographic verification unavailable
    coverage: SignatureCoverage  # How much of the file this signature covers
    ltv_enabled: bool  # Contains embedded revocation data
    details: list[str]  # Human-readable messages
    signer: dict[str, str | None] | None  # Authenticated certificate info, or None
    chain_valid: bool | None  # None = not attempted, True/False = result
    trust_anchor: str | None  # CA name from TSL
    trust_status: str | None  # "trusted" | "untrusted" | "unknown"


def _verify_hash(
    data: bytes,
    cms_der: bytes,
    details: list[str],
    signature: SignatureVerification,
    *,
    data_label: str,
    expected_hash: bytes | None = None,
) -> bool:
    """Verify both an optional post-sign oracle and the signed CMS digest."""
    expected_ok = True
    if expected_hash is not None:
        actual_sha1 = hashlib.sha1(data).digest()
        expected_ok = actual_sha1 == expected_hash
        if expected_ok:
            details.append(f"Hash OK -- SHA-1 matches expected: {actual_sha1.hex()}")
        else:
            details.append(
                f"Hash MISMATCH!\n"
                f"  {data_label} SHA-1: {actual_sha1.hex()}\n"
                f"  Expected:        {expected_hash.hex()}"
            )

    digest_info = extract_digest_info(cms_der)
    if digest_info is None:
        if signature.covers_content:
            # RFC 5652 section 5.4: with no signed attributes there is no separate
            # messageDigest to compare -- the signature itself binds these bytes,
            # so integrity follows from the signature verdict alone.
            details.append(
                "Integrity: signature covers the signed bytes directly (no signed attributes)"
            )
            return expected_ok and signature.valid is True
        details.append("Could not extract CMS messageDigest -- hash verification unavailable")
        return False

    algo_name, cms_digest = digest_info
    try:
        actual_digest = hashlib.new(algo_name, data).digest()
    except (TypeError, ValueError):
        details.append(f"CMS digest algorithm {algo_name!r} is unsupported -- cannot verify hash")
        return False
    algo_upper = algo_name.upper().replace("_", "-")
    cms_digest_ok = actual_digest == cms_digest
    if cms_digest_ok:
        details.append(f"Hash OK -- {algo_upper} matches CMS messageDigest: {actual_digest.hex()}")
    else:
        details.append(
            f"Hash MISMATCH!\n"
            f"  {data_label} {algo_upper}:   {actual_digest.hex()}\n"
            f"  CMS messageDigest:  {cms_digest.hex()}"
        )
    return expected_ok and cms_digest_ok


def _authenticated_signer(
    candidate: dict[str, str | None] | None,
    signature: SignatureVerification,
    chain_valid: bool | None,
    details: list[str],
) -> dict[str, str | None] | None:
    """Expose certificate identity only when ESS or a trusted chain binds it."""
    if candidate is None:
        return None

    if signature.valid is True and (signature.signer_certificate_bound or chain_valid is True):
        if candidate.get("name"):
            details.append(f"Signer: {candidate['name']}")
        return candidate

    if signature.valid is True:
        details.append(
            "Signer identity not authenticated -- no matching ESS certificate binding "
            "or trusted certificate chain"
        )
    return None


def _verify_signature_match(
    pdf_bytes: bytes,
    br_match: re.Match[bytes],
    expected_hash: bytes | None = None,
    tsl_url: str | None = None,
) -> VerificationResult:
    """Core verification logic for a single ByteRange match.

    Args:
        pdf_bytes: Complete PDF file bytes.
        br_match: Regex match from BYTERANGE_PATTERN.
        expected_hash: Optional SHA-1 oracle checked in addition to CMS messageDigest.

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
            "signature_valid": None,
            "coverage": {"covers_whole_file": False, "covered_bytes": 0, "total_bytes": 0},
            "ltv_enabled": False,
            "details": [f"Structure error: {e}"],
            "signer": None,
            "chain_valid": None,
            "trust_anchor": None,
            "trust_status": None,
        }

    # ── 1a. Signature coverage ───────────────────────────────────
    # Bytes past the ByteRange are not signed by this signature. In an
    # incrementally updated PDF they are usually a later revision -- possibly
    # another signature, possibly an unsigned change. Reported, never inferred.
    coverage = byterange_coverage(pdf_bytes, br_match)
    if coverage.covers_to_eof:
        details.append(
            f"Coverage: whole file ({coverage.covered_bytes} of {coverage.total_bytes} bytes)"
        )
    else:
        details.append(
            f"Coverage: partial -- {coverage.trailing_bytes} of {coverage.total_bytes} bytes "
            "follow this signature and are outside it"
        )

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
    candidate_signer = extract_signer_info(cms_der)

    # ── 4. Cryptographic signature verification ─────────────────────
    signature = verify_signer_signature(cms_der, signed_data)

    # ── 5. Hash verification ─────────────────────────────────────
    hash_ok = _verify_hash(
        signed_data,
        cms_der,
        details,
        signature,
        data_label="ByteRange",
        expected_hash=expected_hash,
    )
    details.append(signature.describe())

    # ── 6. LTV status ────────────────────────────────────────────────
    from .ltv import check_ltv_status

    ltv = check_ltv_status(cms_der)
    ltv_label = "LTV enabled" if ltv.ltv_enabled else "Not LTV enabled"
    details.append(f"LTV: {ltv_label}")

    # ── 7. Chain validation (optional, best-effort) ────────────────────
    chain_valid: bool | None = None
    trust_anchor: str | None = None
    trust_status: str | None = "unknown"

    if tsl_url:
        try:
            from ..chain import validate_chain_for_profile

            chain_result = validate_chain_for_profile(cms_der, tsl_url)
            chain_valid = chain_result.chain_valid
            trust_anchor = chain_result.trust_anchor
            if chain_valid is True:
                trust_status = "trusted"
            elif chain_valid is False:
                trust_status = "untrusted"
            details.extend(chain_result.details)
        except Exception:
            _logger.debug("Chain validation failed (non-fatal)", exc_info=True)
            details.append("Chain: validation unavailable")

    signer = _authenticated_signer(candidate_signer, signature, chain_valid, details)
    valid = structure_ok and hash_ok and signature.valid is True
    return {
        "valid": valid,
        "structure_ok": structure_ok,
        "hash_ok": hash_ok,
        "signature_valid": signature.valid,
        "coverage": {
            "covers_whole_file": coverage.covers_to_eof,
            "covered_bytes": coverage.covered_bytes,
            "total_bytes": coverage.total_bytes,
        },
        "ltv_enabled": ltv.ltv_enabled,
        "details": details,
        "signer": signer,
        "chain_valid": chain_valid,
        "trust_anchor": trust_anchor,
        "trust_status": trust_status,
    }


def verify_embedded_signature(
    pdf_bytes: bytes,
    expected_hash: bytes | None = None,
    tsl_url: str | None = None,
) -> VerificationResult:
    """
    Verify the last embedded PDF signature.

    Checks:
    1. Structure -- ByteRange is valid, CMS is present, PDF readable by pikepdf
    2. Hash -- computed from ByteRange data and compared against CMS messageDigest
       (algorithm auto-detected); expected_hash is an additional check if provided
    3. Signature -- the CMS signer signature verifies against its certificate

    For multi-signature PDFs, verifies only the last (most recent) signature.
    Use verify_all_embedded_signatures() to check all signatures.

    Args:
        pdf_bytes: The signed PDF.
        expected_hash: Optional 20-byte SHA-1 hash that was sent to CoSign for
            signing. It is checked in addition to the signed CMS messageDigest.

    Returns:
        VerificationResult including hash, signer-signature, structure, and trust status.

    Never raises on verification failure -- returns valid=False with details.
    Raises RevenantError only on parse failures (not a signed PDF, etc.)
    """
    br_matches = list(re.finditer(BYTERANGE_PATTERN, pdf_bytes))
    if not br_matches:
        return {
            "valid": False,
            "structure_ok": False,
            "hash_ok": False,
            "signature_valid": None,
            "coverage": {"covers_whole_file": False, "covered_bytes": 0, "total_bytes": 0},
            "ltv_enabled": False,
            "details": ["Structure error: No /ByteRange found in PDF -- not a signed PDF?"],
            "signer": None,
            "chain_valid": None,
            "trust_anchor": None,
            "trust_status": None,
        }

    result = _verify_signature_match(pdf_bytes, br_matches[-1], expected_hash, tsl_url)

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


def verify_all_embedded_signatures(
    pdf_bytes: bytes,
    tsl_url: str | None = None,
) -> list[VerificationResult]:
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
        result = _verify_signature_match(pdf_bytes, br, tsl_url=tsl_url)
        result["details"].append(pikepdf_detail)
        results.append(result)

    # One signature covering an earlier revision is expected -- a later signature
    # covers the rest. Bytes past *every* signature are signed by nobody, which
    # is decided by arithmetic alone, without inspecting what they contain.
    if results and not any(r["coverage"]["covers_whole_file"] for r in results):
        furthest = max(byterange_coverage(pdf_bytes, br).coverage_end for br in br_matches)
        unsigned = len(pdf_bytes) - furthest
        results[-1]["details"].append(
            f"WARNING: {unsigned} trailing bytes are covered by no signature in this document"
        )

    return results


# ── Detached signature verification ──────────────────────────────


def verify_detached_signature(
    data_bytes: bytes,
    cms_der: bytes,
    tsl_url: str | None = None,
) -> VerificationResult:
    """Verify a detached CMS/PKCS#7 signature against original data.

    Extracts the digest algorithm and messageDigest from the CMS blob, compares
    it with the original data, and verifies the signer signature.

    Args:
        data_bytes: The original data that was signed.
        cms_der: The detached CMS/PKCS#7 signature (DER-encoded).

    Returns:
        VerificationResult including hash, signer-signature, structure, and trust status.
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
    candidate_signer = extract_signer_info(cms_der)

    # Cryptographic signature verification
    signature = verify_signer_signature(cms_der, data_bytes)

    # Hash verification
    hash_ok = _verify_hash(data_bytes, cms_der, details, signature, data_label="Data")
    details.append(signature.describe())

    # LTV status
    from .ltv import check_ltv_status

    ltv = check_ltv_status(cms_der)
    ltv_label = "LTV enabled" if ltv.ltv_enabled else "Not LTV enabled"
    details.append(f"LTV: {ltv_label}")

    # Chain validation (optional, best-effort)
    chain_valid: bool | None = None
    trust_anchor: str | None = None
    trust_status: str | None = "unknown"

    if tsl_url:
        try:
            from ..chain import validate_chain_for_profile

            chain_result = validate_chain_for_profile(cms_der, tsl_url)
            chain_valid = chain_result.chain_valid
            trust_anchor = chain_result.trust_anchor
            if chain_valid is True:
                trust_status = "trusted"
            elif chain_valid is False:
                trust_status = "untrusted"
            details.extend(chain_result.details)
        except Exception:
            _logger.debug("Chain validation failed (non-fatal)", exc_info=True)
            details.append("Chain: validation unavailable")

    signer = _authenticated_signer(candidate_signer, signature, chain_valid, details)
    valid = structure_ok and hash_ok and signature.valid is True
    return {
        "valid": valid,
        "structure_ok": structure_ok,
        "hash_ok": hash_ok,
        "signature_valid": signature.valid,
        # A detached signature covers exactly the data it was handed; there is
        # no surrounding file that could carry unsigned bytes.
        "coverage": {
            "covers_whole_file": True,
            "covered_bytes": len(data_bytes),
            "total_bytes": len(data_bytes),
        },
        "ltv_enabled": ltv.ltv_enabled,
        "details": details,
        "signer": signer,
        "chain_valid": chain_valid,
        "trust_anchor": trust_anchor,
        "trust_status": trust_status,
    }
