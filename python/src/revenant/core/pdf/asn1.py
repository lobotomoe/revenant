"""ASN.1/DER parsing utilities for CMS signature extraction."""

from __future__ import annotations

# ASN.1 SEQUENCE tag -- first byte of any valid CMS/PKCS#7 blob
ASN1_SEQUENCE_TAG = 0x30

# Maximum hex chars for a single CMS blob (16 MB DER = 32M hex chars).
# Protects against malformed length fields claiming absurd sizes.
_MAX_CMS_HEX_CHARS = 32 * 1024 * 1024

# Minimum plausible CMS blob size in bytes (header + basic content)
MIN_CMS_SIZE = 100


def extract_der_from_padded_hex(hex_str: str) -> bytes:
    """Extract exact DER blob from zero-padded hex string.

    Parses the ASN.1 TLV header to determine exact DER length, avoiding
    the rstrip("0") approach which corrupts blobs ending in 0x00 bytes.

    Args:
        hex_str: Hex-encoded DER data, potentially right-padded with zeros.

    Returns:
        Exact DER-encoded bytes without padding.

    Raises:
        ValueError: If the hex string is invalid or ASN.1 header is malformed.
    """
    if len(hex_str) < 4:
        raise ValueError("Hex string too short for ASN.1 TLV header")

    # Parse first two bytes (tag + length start) from hex
    tag = int(hex_str[0:2], 16)
    if tag != ASN1_SEQUENCE_TAG:
        raise ValueError(f"Expected ASN.1 SEQUENCE (0x30), got 0x{tag:02x}")

    length_byte = int(hex_str[2:4], 16)
    header_bytes = 2  # tag + initial length byte

    if length_byte < 0x80:
        # Short form: length_byte IS the length
        content_len = length_byte
    elif length_byte == 0x80:
        # Indefinite length -- not valid in DER
        raise ValueError("Indefinite length encoding is not valid in DER")
    else:
        # Long form: lower 7 bits = number of length bytes
        num_len_bytes = length_byte & 0x7F
        if num_len_bytes > 4:
            raise ValueError(f"ASN.1 length field too large: {num_len_bytes} bytes")
        header_bytes += num_len_bytes
        needed_hex = 4 + num_len_bytes * 2
        if len(hex_str) < needed_hex:
            raise ValueError("Hex string too short for ASN.1 length field")
        len_hex = hex_str[4 : 4 + num_len_bytes * 2]
        content_len = int(len_hex, 16)

    total_der_bytes = header_bytes + content_len
    total_hex_chars = total_der_bytes * 2

    if total_hex_chars > _MAX_CMS_HEX_CHARS:
        raise ValueError(
            f"ASN.1 claims {total_der_bytes} bytes, exceeds maximum "
            f"({_MAX_CMS_HEX_CHARS // 2} bytes)"
        )

    if total_hex_chars > len(hex_str):
        raise ValueError(
            f"ASN.1 length ({total_der_bytes} bytes) exceeds available hex data "
            f"({len(hex_str) // 2} bytes)"
        )

    return bytes.fromhex(hex_str[:total_hex_chars])
