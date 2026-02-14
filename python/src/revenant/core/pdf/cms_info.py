# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
"""CMS metadata extraction -- digest info, signer identity, and blob inspection."""

from __future__ import annotations

import hashlib
import logging
from typing import TypedDict

from ...errors import RevenantError
from .asn1 import ASN1_SEQUENCE_TAG, MIN_CMS_SIZE

_logger = logging.getLogger(__name__)

# OID for messageDigest attribute in CMS SignerInfo
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

# Map non-standard CMS digest algorithm identifiers to hashlib names.
# CoSign puts sha1WithRSAEncryption in the digestAlgorithm field instead of sha1.
_DIGEST_ALGO_MAP: dict[str, str] = {
    "sha1_rsa": "sha1",
    "sha256_rsa": "sha256",
    "sha384_rsa": "sha384",
    "sha512_rsa": "sha512",
    "1.2.840.113549.1.1.5": "sha1",  # sha1WithRSAEncryption OID
    "1.2.840.113549.1.1.11": "sha256",  # sha256WithRSAEncryption OID
    "1.2.840.113549.1.1.12": "sha384",  # sha384WithRSAEncryption OID
    "1.2.840.113549.1.1.13": "sha512",  # sha512WithRSAEncryption OID
}


def resolve_hash_algo(algo_raw: str) -> str | None:
    """Resolve a CMS digest algorithm identifier to a hashlib-compatible name.

    Args:
        algo_raw: Algorithm name or OID from asn1crypto (.native or .dotted).

    Returns:
        hashlib algorithm name, or None if unrecognized.
    """
    if algo_raw in hashlib.algorithms_available:
        return algo_raw
    return _DIGEST_ALGO_MAP.get(algo_raw)


def extract_digest_info(cms_der: bytes) -> tuple[str, bytes] | None:
    """Extract digest algorithm and messageDigest from a CMS SignerInfo.

    Parses the CMS structure to get:
    1. The digest algorithm from SignerInfo.digestAlgorithm
    2. The messageDigest value from SignerInfo.signedAttrs

    Returns:
        (hashlib_algo_name, digest_bytes) if extraction succeeds, None otherwise.
    """
    try:
        from asn1crypto import cms as asn1_cms

        content_info = asn1_cms.ContentInfo.load(cms_der)
        signed_data = content_info["content"]
        signer_infos = signed_data["signer_infos"]
        if not signer_infos:
            return None

        signer_info = signer_infos[0]

        # Get digest algorithm
        algo_id = signer_info["digest_algorithm"]["algorithm"]
        # Try .native first (e.g. "sha256"), then .dotted OID as fallback
        algo_name = resolve_hash_algo(algo_id.native)
        if algo_name is None:
            algo_name = resolve_hash_algo(algo_id.dotted)
        if algo_name is None:
            _logger.debug("Unrecognized digest algorithm: %s (%s)", algo_id.native, algo_id.dotted)
            return None

        # Get messageDigest from signed attributes
        signed_attrs = signer_info["signed_attrs"]
        if signed_attrs is None:
            return None

        for attr in signed_attrs:
            if attr["type"].dotted == _OID_MESSAGE_DIGEST:
                values = attr["values"]
                if values:
                    return (algo_name, values[0].native)
        return None  # noqa: TRY300 -- not a try success path; this is the "no match found" fallback after the for loop
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        _logger.debug("Could not extract digest info from CMS", exc_info=True)
        return None


def extract_signer_info(cms_der: bytes) -> dict[str, str | None] | None:
    """Extract signer certificate info from a CMS blob.

    Returns:
        dict with name, email, organization, dn -- or None on failure.
    """
    try:
        from ..cert_info import extract_cert_info_from_cms

        return extract_cert_info_from_cms(cms_der)
    except (RevenantError, ValueError, TypeError, KeyError, AttributeError):
        _logger.debug("Could not extract signer info from CMS", exc_info=True)
        return None


class CmsInspection(TypedDict):
    """Result of inspecting a CMS/PKCS#7 blob (without original data)."""

    signer: dict[str, str | None] | None
    digest_algorithm: str | None
    cms_size: int
    details: list[str]


def inspect_cms_blob(cms_der: bytes) -> CmsInspection:
    """Inspect a CMS/PKCS#7 blob without verifying against original data.

    Extracts certificate info and digest algorithm. Use this when
    only the .p7s file is available (no original data to verify against).

    Args:
        cms_der: The CMS/PKCS#7 signature (DER-encoded).

    Returns:
        CmsInspection with signer info, digest algorithm, and details.
    """
    details: list[str] = []

    if len(cms_der) < MIN_CMS_SIZE:
        details.append(f"CMS too small ({len(cms_der)} bytes) -- likely corrupt")
        return {
            "signer": None,
            "digest_algorithm": None,
            "cms_size": len(cms_der),
            "details": details,
        }

    if cms_der[0] != ASN1_SEQUENCE_TAG:
        details.append("Not a valid CMS blob (expected ASN.1 SEQUENCE)")
        return {
            "signer": None,
            "digest_algorithm": None,
            "cms_size": len(cms_der),
            "details": details,
        }

    details.append(f"CMS blob: {len(cms_der)} bytes, valid ASN.1 structure")

    signer = extract_signer_info(cms_der)
    if signer:
        if signer.get("name"):
            details.append(f"Signer: {signer['name']}")
        if signer.get("organization"):
            details.append(f"Organization: {signer['organization']}")
        if signer.get("email"):
            details.append(f"Email: {signer['email']}")

    digest_algo = None
    digest_info = extract_digest_info(cms_der)
    if digest_info is not None:
        digest_algo = digest_info[0]
        details.append(f"Digest algorithm: {digest_algo.upper().replace('_', '-')}")

    return {
        "signer": signer,
        "digest_algorithm": digest_algo,
        "cms_size": len(cms_der),
        "details": details,
    }
