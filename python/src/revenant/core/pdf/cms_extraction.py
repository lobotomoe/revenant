"""ByteRange and CMS extraction from signed PDFs."""

from __future__ import annotations

import re

from ...errors import PDFError
from .asn1 import extract_der_from_padded_hex

# Regex pattern to find ByteRange arrays in PDF
BYTERANGE_PATTERN = rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]"


def extract_cms_from_byterange(
    pdf_bytes: bytes,
    len1: int,
    off2: int,
) -> bytes:
    """
    Extract CMS DER blob from a PDF given ByteRange parameters.

    This is the canonical low-level extraction function used by both
    signature verification and certificate discovery.

    Args:
        pdf_bytes: Complete PDF file bytes.
        len1: Length of first chunk (from ByteRange[1]).
        off2: Offset of second chunk (from ByteRange[2]).

    Returns:
        DER-encoded CMS/PKCS#7 blob.

    Raises:
        RevenantError: If the CMS blob cannot be located or parsed.
    """
    # Bounds validation
    if len1 <= 0:
        raise PDFError(f"Invalid ByteRange: len1 must be positive, got {len1}")
    if off2 <= len1:
        raise PDFError(f"Invalid ByteRange: off2 ({off2}) must be greater than len1 ({len1})")
    if off2 > len(pdf_bytes):
        raise PDFError(f"Invalid ByteRange: off2 ({off2}) exceeds PDF size ({len(pdf_bytes)})")

    # ByteRange structure: [0 len1 off2 len2]
    # chunk1 = pdf_bytes[0:len1], ends just before the hex content
    # chunk2 = pdf_bytes[off2:], starts just after the hex content
    # The hex is between "<" at position (len1-1) and ">" at position (off2-1)
    hex_start = len1  # First hex byte position (after "<")
    hex_end = off2 - 1  # Position of ">" (exclusive end for slice)

    # Verify angle brackets at expected positions
    if pdf_bytes[hex_start - 1 : hex_start] != b"<":
        raise PDFError(
            f"Expected '<' at offset {hex_start - 1}, got {pdf_bytes[hex_start - 1 : hex_start]!r}"
        )
    if pdf_bytes[hex_end : hex_end + 1] != b">":
        raise PDFError(
            f"Expected '>' at offset {hex_end}, got {pdf_bytes[hex_end : hex_end + 1]!r}"
        )

    hex_str = pdf_bytes[hex_start:hex_end].decode("ascii").strip()

    # Determine exact CMS length from ASN.1 SEQUENCE header rather than
    # using rstrip("0") which corrupts blobs ending in 0x00 bytes.
    try:
        cms_der = extract_der_from_padded_hex(hex_str)
    except ValueError as e:
        raise PDFError(f"Invalid hex in CMS blob: {e}") from e

    return cms_der


def extract_cms_from_byterange_match(
    pdf_bytes: bytes,
    br_match: re.Match[bytes],
) -> bytes:
    """
    Extract CMS DER blob from a regex ByteRange match.

    Convenience wrapper around extract_cms_from_byterange().

    Args:
        pdf_bytes: Complete PDF file bytes.
        br_match: Regex match from BYTERANGE_PATTERN.

    Returns:
        DER-encoded CMS/PKCS#7 blob.

    Raises:
        RevenantError: If the CMS blob cannot be located or parsed.
    """
    len1 = int(br_match.group(2))
    off2 = int(br_match.group(3))
    return extract_cms_from_byterange(pdf_bytes, len1, off2)


def extract_signature_data_from_match(
    pdf_bytes: bytes, br_match: re.Match[bytes]
) -> tuple[bytes, bytes]:
    """Extract ByteRange data and CMS blob from a specific ByteRange match.

    Args:
        pdf_bytes: Complete PDF file bytes.
        br_match: Regex match from BYTERANGE_PATTERN.

    Returns:
        (signed_data, cms_der) -- the concatenated ByteRange chunks and the CMS blob.

    Raises:
        RevenantError: If the ByteRange is invalid or CMS extraction fails.
    """
    off1 = int(br_match.group(1))
    len1 = int(br_match.group(2))
    off2 = int(br_match.group(3))
    len2 = int(br_match.group(4))

    if off1 != 0:
        raise PDFError(f"ByteRange offset1 should be 0, got {off1}")
    if off2 <= len1:
        raise PDFError(f"ByteRange offset2 ({off2}) <= len1 ({len1})")
    if off2 + len2 > len(pdf_bytes):
        raise PDFError(f"ByteRange extends beyond EOF: {off2}+{len2} > {len(pdf_bytes)}")

    chunk1 = pdf_bytes[off1 : off1 + len1]
    chunk2 = pdf_bytes[off2 : off2 + len2]
    signed_data = chunk1 + chunk2

    cms_der = extract_cms_from_byterange(pdf_bytes, len1, off2)
    return signed_data, cms_der


def extract_signature_data(pdf_bytes: bytes) -> tuple[bytes, bytes]:
    """
    Extract ByteRange data and CMS blob from the last signature in a signed PDF.

    For multi-signature PDFs, returns the last (most recent) signature.

    Returns:
        (signed_data, cms_der) -- the data that was signed and the CMS signature.

    Raises:
        RevenantError: If the PDF has no valid embedded signature.
    """
    br_matches = list(re.finditer(BYTERANGE_PATTERN, pdf_bytes))
    if not br_matches:
        raise PDFError("No /ByteRange found in PDF -- not a signed PDF?")
    return extract_signature_data_from_match(pdf_bytes, br_matches[-1])
