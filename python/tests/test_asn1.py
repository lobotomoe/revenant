# SPDX-License-Identifier: Apache-2.0
"""Tests for revenant.core.pdf.asn1 -- BER/DER parsing edge cases."""

from __future__ import annotations

import pytest

from revenant.core.pdf.asn1 import _skip_tlv, extract_der_from_padded_hex

# ── _skip_tlv edge cases ───────────────────────────────────────────


def test_skip_tlv_short_form():
    """Simple TLV with short-form length."""
    # Tag=0x04 (OCTET STRING), Length=3, Content=0xABCDEF
    data = bytes([0x04, 0x03, 0xAB, 0xCD, 0xEF, 0x00])
    pos = _skip_tlv(data, 0, len(data))
    assert pos == 5  # tag(1) + len(1) + content(3)


def test_skip_tlv_long_form_length():
    """TLV with long-form length (2-byte length field)."""
    # Tag=0x04, Length=0x81 0x80 (= 128 bytes content)
    content = b"\xab" * 128
    data = bytes([0x04, 0x81, 0x80]) + content
    pos = _skip_tlv(data, 0, len(data))
    assert pos == 3 + 128


def test_skip_tlv_multi_byte_tag():
    """TLV with multi-byte (high-tag-number) tag."""
    # Tag = 0x1F 0x81 0x00 (multi-byte), Length=0x01, Content=0xAB
    data = bytes([0x1F, 0x81, 0x00, 0x01, 0xAB])
    pos = _skip_tlv(data, 0, len(data))
    assert pos == 5


def test_skip_tlv_indefinite_length_child():
    """TLV with indefinite-length encoding, containing children then EOC."""
    # Parent: tag=0x30 (SEQUENCE), length=0x80 (indefinite)
    # Child: tag=0x04, length=0x02, content=0xABCD
    # EOC: 0x00 0x00
    data = bytes([0x30, 0x80, 0x04, 0x02, 0xAB, 0xCD, 0x00, 0x00])
    # We call _skip_tlv starting at the child (pos=2), but actually
    # the caller is _extract_ber_indefinite which handles the outer 0x30 0x80
    # Test just the child skip
    pos = _skip_tlv(data, 2, len(data))
    assert pos == 6  # tag(1) + len(1) + content(2) = 4, so 2+4=6


def test_skip_tlv_depth_exceeded():
    """Exceeding max BER depth should raise ValueError."""
    data = bytes([0x04, 0x01, 0xAB])
    with pytest.raises(ValueError, match="nesting too deep"):
        _skip_tlv(data, 0, len(data), _depth=65)


def test_skip_tlv_unexpected_end():
    """pos >= end should raise ValueError."""
    with pytest.raises(ValueError, match="unexpected end"):
        _skip_tlv(b"\x04\x01\xab", 5, 3)


def test_skip_tlv_tag_extends_beyond():
    """Tag byte at boundary should raise ValueError."""
    # Single byte that is a start of multi-byte tag, but no continuation
    data = bytes([0x1F])
    with pytest.raises(ValueError, match="tag extends beyond"):
        _skip_tlv(data, 0, len(data))


def test_skip_tlv_length_extends_beyond():
    """Long-form length field extending beyond data should raise ValueError."""
    # Tag=0x04, Length=0x84 (4 bytes follow), but data ends
    data = bytes([0x04, 0x84, 0x00])
    with pytest.raises(ValueError, match="length field extends beyond"):
        _skip_tlv(data, 0, len(data))


def test_skip_tlv_nested_indefinite_without_eoc():
    """Nested indefinite-length without EOC should raise ValueError."""
    # Tag=0x30, Length=0x80 (indefinite), child with indefinite length but no EOC
    data = bytes([0x30, 0x80, 0x04, 0x02, 0xAB, 0xCD])  # no 0x00 0x00
    # _skip_tlv is called on this element starting at pos=0
    # It sees 0x30 tag, 0x80 length (indefinite), enters loop
    # Processes child 0x04 0x02 0xABCD (pos moves to 6)
    # Loop: pos=6 >= end=6, falls through
    with pytest.raises(ValueError, match="indefinite-length without EOC"):
        _skip_tlv(data, 0, len(data))


# ── extract_der_from_padded_hex ─────────────────────────────────────


def test_ber_indefinite_eoc_not_found():
    """BER indefinite-length without EOC should raise ValueError."""
    # 0x30 0x80 = SEQUENCE with indefinite length
    # Then some content but no 0x00 0x00 terminator
    hex_str = "3080" + "040203" * 10  # lots of children, no EOC
    with pytest.raises(ValueError, match="EOC marker not found"):
        extract_der_from_padded_hex(hex_str)


def test_ber_indefinite_with_eoc():
    """BER indefinite-length with proper EOC should work."""
    # 0x30 0x80 (SEQUENCE, indefinite)
    # 0x04 0x02 0xAB 0xCD (child: OCTET STRING, 2 bytes)
    # 0x00 0x00 (EOC)
    # followed by zero padding
    hex_str = "3080" + "0402abcd" + "0000" + "00" * 20
    result = extract_der_from_padded_hex(hex_str)
    assert result == bytes.fromhex("30800402abcd0000")


def test_long_form_length():
    """DER with long-form (multi-byte) length field."""
    # 0x30 0x81 0x04 = SEQUENCE, 1 length byte follows, content = 4 bytes
    content_hex = "aabbccdd"
    hex_str = "308104" + content_hex + "00" * 20
    result = extract_der_from_padded_hex(hex_str)
    assert result == bytes.fromhex("308104" + content_hex)
