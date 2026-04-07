# SPDX-License-Identifier: Apache-2.0
"""ASN.1/DER parsing utilities for CMS signature extraction."""

from __future__ import annotations

# ASN.1 SEQUENCE tag -- first byte of any valid CMS/PKCS#7 blob
ASN1_SEQUENCE_TAG = 0x30

# Maximum hex chars for a single CMS blob (16 MB DER = 32M hex chars).
# Protects against malformed length fields claiming absurd sizes.
_MAX_CMS_HEX_CHARS = 32 * 1024 * 1024

# Minimum plausible CMS blob size in bytes (header + basic content)
MIN_CMS_SIZE = 100

# End-of-contents octets that terminate BER indefinite-length encoding
_EOC_BYTES = b"\x00\x00"


def extract_der_from_padded_hex(hex_str: str) -> bytes:
    """Extract exact CMS blob from zero-padded hex string.

    Handles both DER (definite length) and BER (indefinite length)
    encodings.  The original EKENG cosign tool produces BER-encoded
    CMS blobs with indefinite length (0x30 0x80 ... 0x00 0x00).

    For DER: parses the ASN.1 TLV header to determine exact length.
    For BER indefinite: returns the full non-padding content, relying
    on asn1crypto to parse the BER structure downstream.

    Args:
        hex_str: Hex-encoded CMS data, potentially right-padded with zeros.

    Returns:
        CMS bytes without padding.

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

    if length_byte == 0x80:
        # BER indefinite length encoding (0x30 0x80 ... 0x00 0x00).
        # The blob ends with EOC (two zero bytes), but the hex placeholder
        # is also zero-padded, so we can't simply search for 0x0000.
        # Return the full non-padding content and let asn1crypto handle
        # the BER parsing.
        return _extract_ber_indefinite(hex_str)

    if length_byte < 0x80:
        # Short form: length_byte IS the length
        content_len = length_byte
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


def _extract_ber_indefinite(hex_str: str) -> bytes:
    """Extract a BER indefinite-length blob from zero-padded hex.

    Strategy: decode the full hex to bytes, then walk the TLV structure
    to find where the top-level SEQUENCE's EOC marker is.  Everything
    after that is zero-padding from the PDF placeholder.

    Raises:
        ValueError: If the BER structure is malformed.
    """
    raw = bytes.fromhex(hex_str)
    # Start after the top-level tag (0x30) and length (0x80)
    pos = 2
    end = len(raw)

    # Walk top-level children until we hit EOC (0x00 0x00)
    while pos < end:
        if raw[pos : pos + 2] == _EOC_BYTES:
            # Found EOC for the top-level SEQUENCE
            return raw[: pos + 2]
        # Skip one TLV element
        pos = _skip_tlv(raw, pos, end)

    raise ValueError("BER indefinite-length SEQUENCE: EOC marker not found")


def _skip_tlv(data: bytes, pos: int, end: int) -> int:
    """Skip a single TLV element and return the position after it.

    Handles both definite and indefinite length children.
    """
    if pos >= end:
        raise ValueError(f"BER parse: unexpected end at offset {pos}")

    # Skip tag byte(s) -- for simplicity, handle single-byte and
    # multi-byte (high-tag-number) tags
    tag_byte = data[pos]
    pos += 1
    if (tag_byte & 0x1F) == 0x1F:
        # Multi-byte tag: keep reading until a byte < 0x80
        while pos < end and data[pos] & 0x80:
            pos += 1
        pos += 1  # final tag byte

    if pos >= end:
        raise ValueError("BER parse: tag extends beyond data")

    # Read length
    length_byte = data[pos]
    pos += 1

    if length_byte == 0x80:
        # Indefinite length child -- walk its children until EOC
        while pos < end:
            if data[pos : pos + 2] == _EOC_BYTES:
                return pos + 2
            pos = _skip_tlv(data, pos, end)
        raise ValueError("BER parse: nested indefinite-length without EOC")

    if length_byte < 0x80:
        content_len = length_byte
    else:
        num_len_bytes = length_byte & 0x7F
        if pos + num_len_bytes > end:
            raise ValueError("BER parse: length field extends beyond data")
        content_len = int.from_bytes(data[pos : pos + num_len_bytes], byteorder="big")
        pos += num_len_bytes

    return pos + content_len
