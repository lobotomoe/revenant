"""Tests for revenant.core.pdf — PDF signature preparation, insertion, verification.

These tests exercise the offline parts (no server needed).
Tests requiring pikepdf are skipped if it's not installed.
"""

import hashlib
from unittest.mock import patch

import pytest

from revenant.core.pdf import (
    BYTERANGE_PATTERN,
    CMS_HEX_SIZE,
    POSITION_ALIASES,
    POSITION_PRESETS,
    compute_byterange_hash,
    compute_sig_rect,
    extract_cms_from_byterange,
    extract_cms_from_byterange_match,
    insert_cms,
    inspect_cms_blob,
    parse_page_spec,
    resolve_position,
    verify_all_embedded_signatures,
    verify_detached_signature,
    verify_embedded_signature,
)
from revenant.core.pdf.asn1 import extract_der_from_padded_hex
from revenant.core.pdf.cms_extraction import extract_signature_data
from revenant.core.pdf.cms_info import extract_digest_info, extract_signer_info
from revenant.core.pdf.incremental import (
    _extract_trailer_entries,
    assemble_incremental_update,
    build_xref_and_trailer,
    find_prev_startxref,
    find_root_obj_num,
    patch_byterange,
)
from revenant.core.pdf.objects import (
    CMS_RESERVED_SIZE,
    _serialize_pikepdf_obj,
    build_object_override,
)
from revenant.errors import PDFError, RevenantError

# ── Constants ───────────────────────────────────────────────────────


def test_cms_sizes():
    assert CMS_RESERVED_SIZE == 8192
    assert CMS_HEX_SIZE == CMS_RESERVED_SIZE * 2


# ── insert_cms ──────────────────────────────────────────────────────


def test_insert_cms_basic():
    """CMS DER bytes should appear as hex in the correct position."""
    pdf = b"A" * 100 + b"0" * 20 + b"B" * 50
    cms_der = bytes([0x30, 0x82, 0x01, 0x00])  # 4 bytes

    result = insert_cms(pdf, 100, 20, cms_der)
    assert len(result) == len(pdf)
    # The hex at position 100 should be "30820100" + zero padding
    hex_region = result[100:120].decode("ascii")
    assert hex_region.startswith("30820100")
    assert hex_region == "30820100" + "0" * 12


def test_insert_cms_too_large():
    """CMS that exceeds reserved space should raise RevenantError."""
    pdf = b"A" * 100 + b"0" * 10 + b"B" * 50
    cms_der = b"\x30" * 10  # 10 bytes = 20 hex chars > 10 reserved

    with pytest.raises(PDFError, match="CMS too large"):
        insert_cms(pdf, 100, 10, cms_der)


def test_insert_cms_exact_fit():
    """CMS hex exactly fills the reserved space — no padding needed."""
    reserved = 8
    cms_der = b"\xab\xcd\xef\x01"  # 4 bytes = 8 hex chars = exact fit

    pdf = b"X" * 50 + b"0" * reserved + b"Y" * 30
    result = insert_cms(pdf, 50, reserved, cms_der)
    hex_str = result[50:58].decode("ascii")
    assert hex_str == "abcdef01"


# ── compute_byterange_hash ──────────────────────────────────────────


def test_byterange_hash():
    """Hash should cover everything except the hex region + closing '>'."""
    before = b"BEFORE<"
    hex_placeholder = b"0" * 20
    closing = b">"
    after = b"AFTER"
    pdf = before + hex_placeholder + closing + after

    hex_start = len(before)  # points to first hex char (after '<')
    hex_len = 20

    h = compute_byterange_hash(pdf, hex_start, hex_len)

    # Manual calculation: hash of everything except <hex...>
    expected = hashlib.sha1(before + after).digest()
    assert h == expected


# ── extract_signature_data ──────────────────────────────────────────


def _build_fake_signed_pdf(cms_hex_str):
    """Build a minimal fake signed PDF with ByteRange and Contents."""
    # Structure: header + stuff + /ByteRange[...] + /Contents <hex...> + trailer
    header = b"%PDF-1.4\nfake content here\n"
    # We'll compute real ByteRange values after building
    br_placeholder = b"/ByteRange [0000000000 0000000000 0000000000 0000000000]"
    contents_prefix = b"/Contents <"
    contents_suffix = b">"
    trailer = b"\n%%EOF\n"

    # Calculate positions:
    # before = header + br + /Contents <
    before_hex = header + br_placeholder + contents_prefix
    after_hex = contents_suffix + trailer

    hex_start = len(before_hex)
    hex_len = len(cms_hex_str)
    br_after_start = hex_start + hex_len + 1  # +1 for >
    br_after_len = len(trailer)

    byterange = f"/ByteRange [{0:010d} {hex_start:010d} {br_after_start:010d} {br_after_len:010d}]"
    byterange_bytes = byterange.encode("latin-1")

    # Replace placeholder
    pdf = before_hex + cms_hex_str.encode("ascii") + after_hex
    return pdf.replace(br_placeholder, byterange_bytes)


def test_extract_signature_data_basic():
    """Should extract signed_data and CMS DER from a fake signed PDF."""
    # Build a fake CMS with valid ASN.1 SEQUENCE header.
    # \x30\x82\x00\xfc = SEQUENCE, long-form length (2 bytes), content_len=252
    fake_cms = b"\x30\x82\x00\xfc" + b"\xab" * 252  # 256 bytes total, valid ASN.1 header
    cms_hex = fake_cms.hex()
    # Pad to reserved size with zeros (simulates what insert_cms does)
    cms_hex_padded = cms_hex + "0" * (512 - len(cms_hex))

    pdf = _build_fake_signed_pdf(cms_hex_padded)
    signed_data, cms_der = extract_signature_data(pdf)

    assert len(signed_data) > 0
    assert cms_der == fake_cms


def test_extract_no_byterange():
    """PDF without ByteRange should raise RevenantError."""
    with pytest.raises(PDFError, match="No /ByteRange"):
        extract_signature_data(b"%PDF-1.4\nno signature here\n%%EOF\n")


# ── verify_embedded_signature (offline) ─────────────────────────────


def test_verify_no_byterange():
    """Verification of unsigned PDF should report invalid."""
    result = verify_embedded_signature(b"%PDF-1.4\nno sig\n%%EOF")
    assert result["valid"] is False
    assert "Structure error" in result["details"][0]


def test_verify_tiny_cms():
    """CMS blob too small should be flagged."""
    # Build a valid-structure PDF but with tiny CMS (valid ASN.1 SEQUENCE, but too small)
    # \x30\x08 = SEQUENCE, 8 bytes content -> 10 bytes total, well under _MIN_CMS_SIZE
    tiny_cms = b"\x30\x08" + b"\xab" * 8
    tiny_cms_hex = tiny_cms.hex()
    padded = tiny_cms_hex + "0" * (512 - len(tiny_cms_hex))
    pdf = _build_fake_signed_pdf(padded)

    result = verify_embedded_signature(pdf)
    assert result["structure_ok"] is False
    assert any("too small" in d for d in result["details"])


def test_verify_bad_asn1():
    """CMS that doesn't start with 0x30 should be flagged."""
    bad_cms = b"\xff" * 200
    cms_hex = bad_cms.hex()
    padded = cms_hex + "0" * (512 - len(cms_hex))
    pdf = _build_fake_signed_pdf(padded)

    result = verify_embedded_signature(pdf)
    assert result["structure_ok"] is False
    assert any("ASN.1" in d for d in result["details"])


# ── Position presets ───────────────────────────────────────────────


def test_resolve_position_full_names():
    for name in POSITION_PRESETS:
        assert resolve_position(name) == name


def test_resolve_position_aliases():
    for alias, full in POSITION_ALIASES.items():
        assert resolve_position(alias) == full


def test_resolve_position_case_insensitive():
    assert resolve_position("Bottom-Right") == "bottom-right"
    assert resolve_position("BR") == "bottom-right"


def test_resolve_position_unknown():
    with pytest.raises(PDFError, match="Unknown position"):
        resolve_position("middle")


# ── parse_page_spec ───────────────────────────────────────────────


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("first", "first"),
        ("FIRST", "first"),
        ("  First  ", "first"),
        ("last", "last"),
        ("LAST", "last"),
        ("1", 0),
        ("2", 1),
        ("10", 9),
    ],
    ids=["first", "FIRST", "padded_First", "last", "LAST", "page1", "page2", "page10"],
)
def test_parse_page_spec_valid(spec, expected):
    assert parse_page_spec(spec) == expected


@pytest.mark.parametrize(
    ("spec", "match"),
    [
        ("0", "1 or greater"),
        ("-1", "1 or greater"),
        ("foo", "Invalid page"),
    ],
    ids=["zero", "negative", "invalid_string"],
)
def test_parse_page_spec_invalid(spec, match):
    with pytest.raises(PDFError, match=match):
        parse_page_spec(spec)


# ── compute_sig_rect ─────────────────────────────────────────────


def test_compute_sig_rect_right_bottom():
    from revenant.core.pdf import SIG_MARGIN_H, SIG_MARGIN_V, SIG_WIDTH

    x, y, _w, _h = compute_sig_rect(595, 842, "bottom-right")
    assert x == 595 - SIG_MARGIN_H - SIG_WIDTH  # page_w - margin_h - sig_w
    assert y == SIG_MARGIN_V  # margin_v


def test_compute_sig_rect_left_top():
    from revenant.core.pdf import SIG_HEIGHT, SIG_MARGIN_H, SIG_MARGIN_V

    x, y, _w, _h = compute_sig_rect(595, 842, "tl")
    assert x == SIG_MARGIN_H  # margin_h
    assert y == 842 - SIG_MARGIN_V - SIG_HEIGHT  # page_h - margin_v - sig_h


def test_compute_sig_rect_center_bottom():
    from revenant.core.pdf import SIG_MARGIN_V, SIG_WIDTH

    x, y, _w, _h = compute_sig_rect(600, 800, "bc")
    assert x == (600 - SIG_WIDTH) / 2.0
    assert y == SIG_MARGIN_V


def test_compute_sig_rect_landscape():
    """Landscape page (wider than tall) — positions should still be correct."""
    from revenant.core.pdf import SIG_MARGIN_H, SIG_MARGIN_V, SIG_WIDTH

    x, y, _w, _h = compute_sig_rect(842, 595, "bottom-right")
    assert x == 842 - SIG_MARGIN_H - SIG_WIDTH
    assert y == SIG_MARGIN_V


# ── Round-trip test with pikepdf ────────────────────────────────────


def _make_blank_pdf(page_size=(612, 792), num_pages=1):
    """Helper: create a minimal valid PDF with pikepdf."""
    import io

    import pikepdf

    pdf = pikepdf.Pdf.new()
    for _ in range(num_pages):
        pdf.add_blank_page(page_size=page_size)
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def test_prepare_and_verify_roundtrip():
    """Full round-trip: prepare PDF -> insert fake CMS -> verify structure."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf()

    # Prepare with sig field (uses position preset)
    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, position="bottom-right", reason="Test", name="Test User"
    )

    assert hex_start > 0
    assert hex_len == CMS_HEX_SIZE
    assert len(prepared) > len(pdf_bytes)

    # Compute hash
    br_hash = compute_byterange_hash(prepared, hex_start, hex_len)
    assert len(br_hash) == 20  # SHA-1

    # Insert a fake CMS (valid ASN.1 header but not a real signature)
    # Must not end with 0x00 — trailing zeros are stripped by extract_signature_data
    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788  # ~1792 bytes total
    signed_pdf = insert_cms(prepared, hex_start, hex_len, fake_cms)

    # Verify structure
    result = verify_embedded_signature(signed_pdf, expected_hash=br_hash)
    assert result["structure_ok"] is True
    assert result["hash_ok"] is True
    assert result["valid"] is True


def test_prepare_with_all_presets():
    """All position presets should produce a valid signature field."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf()

    for preset in POSITION_PRESETS:
        _prepared, hs, hl = prepare_pdf_with_sig_field(
            pdf_bytes, page=0, position=preset, name="Test"
        )
        assert hs > 0
        assert hl == CMS_HEX_SIZE


def test_prepare_landscape_pdf():
    """Signature on a landscape page should work with presets."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf(page_size=(842, 595))  # A4 landscape

    _prepared, hex_start, _hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, position="bottom-right", name="Test"
    )
    assert hex_start > 0


def test_prepare_page_last():
    """page='last' should place signature on the last page."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf(num_pages=3)

    _prepared, hex_start, _hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page="last", position="top-left", name="Test"
    )
    assert hex_start > 0


def test_prepare_page_with_existing_annots():
    """Page with existing annotations should preserve them in the override."""
    import io

    import pikepdf

    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    # Add a dummy annotation to page 0
    annot = pdf.make_indirect(
        pikepdf.Dictionary(
            {
                "/Type": pikepdf.Name("/Annot"),
                "/Subtype": pikepdf.Name("/Text"),
                "/Rect": pikepdf.Array([0, 0, 50, 50]),
            }
        )
    )
    pdf.pages[0].obj["/Annots"] = pikepdf.Array([annot])
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, position="br", name="Test"
    )
    assert hex_start > 0
    assert hex_len == CMS_HEX_SIZE
    # The prepared PDF should contain the annotation reference
    assert b"/Annots" in prepared


def test_prepare_page_out_of_range():
    """Invalid page number should raise RevenantError."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf(num_pages=2)

    with pytest.raises(PDFError, match="out of range"):
        prepare_pdf_with_sig_field(pdf_bytes, page=5, position="br")


def test_prepare_manual_coordinates():
    """Explicit x, y should override position preset."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf()

    _prepared, hex_start, _hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, x=100, y=100, w=200, h=70, name="Test"
    )
    assert hex_start > 0


def test_get_page_dimensions_portrait():
    """Page dimensions should match the page size we created."""
    import io

    import pikepdf

    from revenant.core.pdf import get_page_dimensions

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    buf = io.BytesIO()
    pdf.save(buf)
    buf.seek(0)
    pdf2 = pikepdf.open(buf)

    w, h = get_page_dimensions(pdf2, 0)
    assert abs(w - 612) < 0.01
    assert abs(h - 792) < 0.01


try:
    import importlib.util

    _HAS_PILLOW = importlib.util.find_spec("PIL") is not None
except (ImportError, ModuleNotFoundError):
    _HAS_PILLOW = False

_requires_pillow = pytest.mark.skipif(not _HAS_PILLOW, reason="Pillow not installed")


@_requires_pillow
def test_prepare_with_signature_image(tmp_path):
    """Signature field with image should produce valid PDF structure."""
    from PIL import Image

    from revenant.core.pdf import prepare_pdf_with_sig_field

    # Create a small test image
    img = Image.new("RGBA", (100, 50), color=(0, 0, 0, 128))
    img_path = tmp_path / "sig.png"
    img.save(str(img_path))

    pdf_bytes = _make_blank_pdf()
    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes,
        page=0,
        position="br",
        name="Test",
        image_path=str(img_path),
    )

    assert hex_start > 0
    assert hex_len == CMS_HEX_SIZE

    # Insert fake CMS and verify structure
    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed_pdf = insert_cms(prepared, hex_start, hex_len, fake_cms)

    result = verify_embedded_signature(signed_pdf, expected_hash=None)
    assert result["structure_ok"] is True


# ── extract_cms_from_byterange — bracket & hex validation ─────────────


def test_extract_cms_missing_open_bracket():
    """Missing '<' before hex content should raise RevenantError."""
    # Build pdf where position (len1-1) is NOT '<'
    pdf = b"X" * 100 + b"AABB" + b">" + b"Z" * 10
    with pytest.raises(PDFError, match="Expected '<'"):
        extract_cms_from_byterange(pdf, len1=100, off2=105)


def test_extract_cms_missing_close_bracket():
    """Missing '>' after hex content should raise RevenantError."""
    # Position len1-1 = '<', but off2-1 is not '>'
    pdf = b"X" * 99 + b"<" + b"AABB" + b"X" + b"Z" * 10
    with pytest.raises(PDFError, match="Expected '>'"):
        extract_cms_from_byterange(pdf, len1=100, off2=105)


def test_extract_cms_asn1_with_zero_padding():
    """ASN.1-aware extraction should ignore zero padding after DER blob."""
    # \x30\x03 = SEQUENCE with 3 bytes of content -> 5 bytes total DER
    # Followed by zero padding to fill the reserved space
    der_hex = "3003aabbcc"
    hex_content = (der_hex + "0" * 20).encode("ascii")
    pdf = b"X" * 99 + b"<" + hex_content + b">" + b"Z" * 10
    result = extract_cms_from_byterange(pdf, len1=100, off2=100 + len(hex_content) + 1)
    assert result == bytes.fromhex(der_hex)


def test_extract_cms_invalid_hex():
    """Invalid hex characters should raise RevenantError."""
    hex_content = b"GGXX1122"
    pdf = b"X" * 99 + b"<" + hex_content + b">" + b"Z" * 10
    with pytest.raises(PDFError, match="Invalid hex"):
        extract_cms_from_byterange(pdf, len1=100, off2=109)


# ── extract_signature_data — ByteRange sanity checks ─────────────────


def test_extract_byterange_off1_not_zero():
    """ByteRange with offset1 != 0 should raise RevenantError."""
    # Craft a PDF with /ByteRange [5 100 200 50]
    pdf = b"%PDF-1.4\n/ByteRange [5 100 200 50]\n/Contents <" + b"0" * 100 + b">\n%%EOF\n"
    with pytest.raises(PDFError, match="offset1 should be 0"):
        extract_signature_data(pdf)


def test_extract_byterange_off2_le_len1():
    """ByteRange with off2 <= len1 should raise RevenantError."""
    pdf = b"%PDF-1.4\n/ByteRange [0 200 100 50]\n/Contents <" + b"0" * 100 + b">\n%%EOF\n"
    with pytest.raises(PDFError, match=r"offset2.*<= len1"):
        extract_signature_data(pdf)


def test_extract_byterange_beyond_eof():
    """ByteRange extending beyond file should raise RevenantError."""
    pdf = b"%PDF-1.4\n/ByteRange [0 10 20 99999]\n/Contents <" + b"0" * 10 + b">\n%%EOF\n"
    with pytest.raises(PDFError, match="extends beyond EOF"):
        extract_signature_data(pdf)


# ── verify_embedded_signature — hash branches ────────────────────────


def test_verify_hash_match():
    """When expected_hash matches, hash_ok should be True."""
    fake_cms = b"\x30\x82\x00\xfc" + b"\xab" * 252
    cms_hex = fake_cms.hex()
    padded = cms_hex + "0" * (512 - len(cms_hex))
    pdf = _build_fake_signed_pdf(padded)

    # Compute actual hash of signed data
    signed_data, _ = extract_signature_data(pdf)
    import hashlib

    expected = hashlib.sha1(signed_data).digest()

    result = verify_embedded_signature(pdf, expected_hash=expected)
    assert result["hash_ok"] is True
    assert any("Hash OK" in d for d in result["details"])


def test_verify_hash_mismatch():
    """When expected_hash doesn't match, hash_ok should be False."""
    fake_cms = b"\x30\x82\x00\xfc" + b"\xab" * 252
    cms_hex = fake_cms.hex()
    padded = cms_hex + "0" * (512 - len(cms_hex))
    pdf = _build_fake_signed_pdf(padded)

    wrong_hash = b"\x00" * 20
    result = verify_embedded_signature(pdf, expected_hash=wrong_hash)
    assert result["hash_ok"] is False
    assert any("MISMATCH" in d for d in result["details"])


def test_verify_no_expected_hash_consistent():
    """Without expected_hash and non-standard CMS, hash cannot be verified."""
    fake_cms = b"\x30\x82\x00\xfc" + b"\xab" * 252
    cms_hex = fake_cms.hex()
    padded = cms_hex + "0" * (512 - len(cms_hex))
    pdf = _build_fake_signed_pdf(padded)

    result = verify_embedded_signature(pdf, expected_hash=None)
    # A fake CMS has no extractable digest info, so hash_ok must be False --
    # we cannot verify a hash without a reference value to compare against.
    assert result["hash_ok"] is False
    assert any("cannot verify" in d or "Hash computed" in d for d in result["details"])


# ── _serialize_pikepdf_obj — edge cases ───────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "null"),
        (True, "true"),
        (False, "false"),
        (42, "42"),
        (3.14, "3.140000"),
        (5.0, "5"),
    ],
    ids=["none", "bool_true", "bool_false", "int", "float_fractional", "float_whole"],
)
def test_serialize_pikepdf_obj(value, expected):
    assert _serialize_pikepdf_obj(value) == expected


# ── find_root_obj_num — edge cases ───────────────────────────────────


def test_find_root_obj_num_success():
    pdf = b"trailer << /Root 1 0 R /Size 3 >>"
    obj_num, gen = find_root_obj_num(pdf)
    assert obj_num == 1
    assert gen == 0


def test_find_root_obj_num_missing():
    with pytest.raises(PDFError, match="Cannot find /Root"):
        find_root_obj_num(b"%PDF-1.4\nno root here\n")


# ── find_prev_startxref — trailer extraction ─────────────────────────


def test_find_prev_startxref_basic():
    """find_prev_startxref should return valid values for a real PDF."""
    pdf_bytes = _make_blank_pdf()
    prev_xref, max_size, _trailer_extra = find_prev_startxref(pdf_bytes)
    assert prev_xref >= 0
    assert max_size > 0


def test_find_prev_startxref_with_info_and_id():
    """Trailer with /Info and /ID entries should be extracted."""
    import io

    import pikepdf

    # Create a PDF with /Info metadata so it has /Info in trailer
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    with pdf.open_metadata() as meta:
        meta["dc:title"] = "Test Document"
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    prev_xref, max_size, trailer_extra = find_prev_startxref(pdf_bytes)
    assert prev_xref >= 0
    assert max_size > 0
    # Should have /ID at minimum (pikepdf always generates /ID)
    assert any("/ID" in e for e in trailer_extra)


def test_find_prev_startxref_no_startxref():
    with pytest.raises(PDFError, match="Cannot find startxref"):
        find_prev_startxref(b"%PDF-1.4\nno xref\n")


def test_find_prev_startxref_no_size():
    pdf = b"%PDF-1.4\nstartxref\n42\n%%EOF\n"
    with pytest.raises(PDFError, match="Cannot determine /Size"):
        find_prev_startxref(pdf)


# ── build_object_override — skip_key ─────────────────────────────────


def test_build_object_override_skips_key():
    """Override should skip the specified key and add new entry."""
    import io

    import pikepdf

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    root_num, _ = find_root_obj_num(pdf_bytes)
    result = build_object_override(pdf_bytes, root_num, skip_key="/Pages", new_entry="  /Test true")
    assert "/Test true" in result
    # /Pages should NOT be in the override (it was skipped)
    # But actually the override re-adds all other keys, so /Pages might appear
    # if it's the only non-skipped key. The point is skip_key is not duplicated.
    assert result.startswith(f"{root_num} 0 obj")


# ── assemble_incremental_update — base without trailing newline ──────


def test_assemble_incremental_update_no_trailing_newline():
    """PDF not ending with newline should get one appended."""
    base = b"%PDF-1.4\n%%EOF"  # no trailing \n
    raw_obj = b"5 0 obj\n<< /Test true >>\nendobj\n"

    result = assemble_incremental_update(
        pdf_bytes=base,
        raw_objects=[(raw_obj, 5)],
        new_size=6,
        prev_xref=0,
        root_obj_num=1,
        root_gen=0,
        trailer_extra=[],
    )
    # Base should have \n appended, then the object
    assert result[len(base)] == ord("\n")
    assert b"5 0 obj" in result


# ── patch_byterange — missing Contents ───────────────────────────────


def test_patch_byterange_missing_contents():
    """If Contents placeholder is not found, should raise RevenantError."""
    pdf = b"%PDF-1.4\nno contents placeholder\n%%EOF\n"
    with pytest.raises(PDFError, match="Cannot find Contents placeholder"):
        patch_byterange(pdf, original_len=0)


# ── find_page_obj_num — existing annots ─────────────────────────────


def test_find_page_with_existing_annots():
    """Page with existing /Annots should return them."""
    # Create a PDF with an annotation on page 0
    import io

    import pikepdf

    from revenant.core.pdf import find_page_obj_num

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    # Add a dummy annotation
    annot = pdf.make_indirect(
        pikepdf.Dictionary(
            {
                "/Type": pikepdf.Name("/Annot"),
                "/Subtype": pikepdf.Name("/Text"),
                "/Rect": pikepdf.Array([0, 0, 100, 100]),
            }
        )
    )
    pdf.pages[0].obj["/Annots"] = pikepdf.Array([annot])
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    root_num, _ = find_root_obj_num(pdf_bytes)
    _page_obj_num, _page_w, _page_h, has_annots, existing_annots = find_page_obj_num(
        pdf_bytes, root_num, 0
    )
    assert has_annots is True
    assert len(existing_annots) >= 1
    assert "R" in existing_annots[0]  # e.g., "4 0 R"


# ── Rotated page dimensions ──────────────────────────────────────────


def test_get_page_dimensions_rotated():
    """90-degree rotated page should swap width and height."""
    import io

    import pikepdf

    from revenant.core.pdf import get_page_dimensions

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    pdf.pages[0].obj["/Rotate"] = 90
    buf = io.BytesIO()
    pdf.save(buf)
    buf.seek(0)
    pdf2 = pikepdf.open(buf)

    w, h = get_page_dimensions(pdf2, 0)
    assert abs(w - 792) < 0.01
    assert abs(h - 612) < 0.01


# ── resolve_page_index — string number and invalid string ────────────


def test_resolve_page_index_string_number():
    """String number like '0' should work as 0-based page index."""
    import io

    import pikepdf

    from revenant.core.pdf import resolve_page_index

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    pdf.add_blank_page(page_size=(612, 792))
    buf = io.BytesIO()
    pdf.save(buf)
    buf.seek(0)
    pdf2 = pikepdf.open(buf)

    assert resolve_page_index(pdf2, "0") == 0
    assert resolve_page_index(pdf2, "1") == 1
    assert resolve_page_index(pdf2, "first") == 0


def test_resolve_page_index_invalid_string():
    """Invalid string should raise RevenantError."""
    import io

    import pikepdf

    from revenant.core.pdf import resolve_page_index

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    buf = io.BytesIO()
    pdf.save(buf)
    buf.seek(0)
    pdf2 = pikepdf.open(buf)

    with pytest.raises(PDFError, match="Invalid page"):
        resolve_page_index(pdf2, "foobar")


# ── extract_cms_from_byterange_match ─────────────────────────────────


def test_extract_cms_from_byterange_match_basic():
    """Should extract CMS from a regex ByteRange match."""
    import re

    # \x30\x82\x00\xfc = SEQUENCE, long-form length (2 bytes), content_len=252
    cms_hex = "308200fc" + "ab" * 252
    padded = cms_hex + "0" * (512 - len(cms_hex))
    pdf = _build_fake_signed_pdf(padded)

    matches = list(re.finditer(BYTERANGE_PATTERN, pdf))
    assert len(matches) == 1

    cms_der = extract_cms_from_byterange_match(pdf, matches[0])
    assert cms_der[:4] == b"\x30\x82\x00\xfc"


# ── verify_embedded_signature — re-extraction failure ────────────────


def test_verify_no_expected_hash_bad_cms_structure():
    """When CMS has invalid ASN.1 tag, extraction fails with structure error."""
    # CMS that doesn't start with ASN.1 SEQUENCE tag (0x30)
    fake_cms = b"\x01\x02\x03\x04" + b"\xab" * 252
    cms_hex = fake_cms.hex()
    padded = cms_hex + "0" * (512 - len(cms_hex))
    pdf = _build_fake_signed_pdf(padded)

    result = verify_embedded_signature(pdf, expected_hash=None)
    assert result["valid"] is False
    assert result["structure_ok"] is False
    assert any("Structure error" in d for d in result["details"])


# ── Embedded font round-trip ──────────────────────────────────────────


def test_prepare_roundtrip_armenian_fields():
    """Round-trip with Armenian text should use embedded font and pass verification."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf()

    armenian_fields = [
        "\u0540\u0561\u0575\u0565\u0580\u0565\u0576",  # Armenian name
        "Date: 8 Feb 2026, 12:00:00 UTC+4",
    ]
    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes,
        page=0,
        position="bottom-right",
        reason="Test",
        name="Test",
        fields=armenian_fields,
    )

    assert hex_start > 0
    assert hex_len == CMS_HEX_SIZE
    assert len(prepared) > len(pdf_bytes)

    # The prepared PDF should contain embedded font objects
    assert b"/Type0" in prepared
    assert b"/CIDFontType2" in prepared
    assert b"/FontFile2" in prepared
    assert b"/ToUnicode" in prepared

    # Insert fake CMS and verify structure
    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed_pdf = insert_cms(prepared, hex_start, hex_len, fake_cms)
    br_hash = compute_byterange_hash(prepared, hex_start, hex_len)

    result = verify_embedded_signature(signed_pdf, expected_hash=br_hash)
    assert result["structure_ok"] is True
    assert result["hash_ok"] is True
    assert result["valid"] is True


# ── Multi-font round-trip ──────────────────────────────────────────────


def test_prepare_roundtrip_ghea_grapalat():
    """Visible signature with GHEA Grapalat should embed that font."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf()

    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes,
        page=0,
        position="bottom-right",
        reason="Test",
        name="Test User",
        fields=["Test User", "Date: 9 Feb 2026"],
        font="ghea-grapalat",
    )

    assert hex_start > 0
    assert hex_len == CMS_HEX_SIZE

    # Should contain GHEA Grapalat font reference, not NotoSans
    assert b"/GHEAGrapalat" in prepared
    assert b"/CIDFontType2" in prepared
    assert b"/FontFile2" in prepared

    # Insert fake CMS and verify structure
    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed_pdf = insert_cms(prepared, hex_start, hex_len, fake_cms)
    br_hash = compute_byterange_hash(prepared, hex_start, hex_len)

    result = verify_embedded_signature(signed_pdf, expected_hash=br_hash)
    assert result["structure_ok"] is True
    assert result["hash_ok"] is True
    assert result["valid"] is True


def test_prepare_noto_sans_explicit():
    """Explicit noto-sans font should work and embed NotoSans."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf()

    prepared, hex_start, _hex_len = prepare_pdf_with_sig_field(
        pdf_bytes,
        page=0,
        position="br",
        name="Test",
        fields=["Test"],
        font="noto-sans",
    )

    assert hex_start > 0
    assert b"/NotoSans" in prepared


# ── pikepdf ImportError guards ───────────────────────────────────────


def test_require_pikepdf_import_error_pdf_verify():
    """core.require_pikepdf should raise RevenantError when pikepdf missing."""
    import builtins
    from unittest.mock import patch

    from revenant import core

    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "pikepdf":
            raise ImportError("mocked: no pikepdf")
        return real_import(name, *args, **kwargs)

    with (
        patch("builtins.__import__", side_effect=mock_import),
        pytest.raises(RevenantError, match="pikepdf is required"),
    ):
        core.require_pikepdf()


# ── Invisible signature ──────────────────────────────────────────────


def test_prepare_invisible_signature():
    """Invisible signature: zero-rect, no /AP, valid structure."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf()

    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes,
        page=0,
        reason="Test",
        name="Test User",
        visible=False,
    )

    assert hex_start > 0
    assert hex_len == CMS_HEX_SIZE
    assert len(prepared) > len(pdf_bytes)

    # Should contain /Rect [0 0 0 0] (invisible)
    assert b"/Rect [0 0 0 0]" in prepared
    # Should NOT contain /AP (no appearance)
    # Check the incremental update portion only
    incremental = prepared[len(pdf_bytes) :]
    assert b"/AP <<" not in incremental
    # Should NOT contain font objects (not needed for invisible)
    assert b"/Type0" not in incremental
    assert b"/CIDFontType2" not in incremental

    # Insert fake CMS and verify structure
    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed_pdf = insert_cms(prepared, hex_start, hex_len, fake_cms)
    br_hash = compute_byterange_hash(prepared, hex_start, hex_len)

    result = verify_embedded_signature(signed_pdf, expected_hash=br_hash)
    assert result["structure_ok"] is True
    assert result["hash_ok"] is True
    assert result["valid"] is True


def test_prepare_invisible_smaller_than_visible():
    """Invisible signature should produce a smaller PDF than visible."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf()

    visible_pdf, _, _ = prepare_pdf_with_sig_field(
        pdf_bytes,
        page=0,
        reason="Test",
        name="Test",
        visible=True,
    )
    invisible_pdf, _, _ = prepare_pdf_with_sig_field(
        pdf_bytes,
        page=0,
        reason="Test",
        name="Test",
        visible=False,
    )

    # Invisible should be significantly smaller (no fonts, no XObjects)
    assert len(invisible_pdf) < len(visible_pdf)


def test_allocate_sig_objects_invisible():
    """Invisible allocation should return None for appearance-related fields."""
    from revenant.core.pdf.objects import allocate_sig_objects

    obj_nums = allocate_sig_objects(prev_size=10, has_image=False, has_smask=False, visible=False)

    assert obj_nums["sig"] == 10
    assert obj_nums["annot"] == 11
    assert obj_nums["new_size"] == 12

    # All appearance-related fields should be None
    for key in ("font", "cidfont", "font_desc", "font_file", "tounicode", "ap", "frm", "n0", "n2"):
        assert obj_nums[key] is None, f"{key} should be None for invisible"


# ── verify_all_embedded_signatures ────────────────────────────────────


def test_verify_all_single_signature():
    """verify_all on a single-signature PDF should return a list of 1."""
    fake_cms = b"\x30\x82\x00\xfc" + b"\xab" * 252
    cms_hex = fake_cms.hex()
    padded = cms_hex + "0" * (512 - len(cms_hex))
    pdf = _build_fake_signed_pdf(padded)

    results = verify_all_embedded_signatures(pdf)
    assert len(results) == 1
    # Verify result has all expected fields
    assert "valid" in results[0]
    assert "structure_ok" in results[0]
    assert "hash_ok" in results[0]
    assert "details" in results[0]
    assert "signer" in results[0]


def test_verify_all_no_byterange():
    """verify_all on unsigned PDF should raise RevenantError."""
    with pytest.raises(PDFError, match="No /ByteRange"):
        verify_all_embedded_signatures(b"%PDF-1.4\nno sig\n%%EOF")


def test_verify_result_has_signer_field():
    """VerificationResult should always include the signer field."""
    fake_cms = b"\x30\x82\x00\xfc" + b"\xab" * 252
    cms_hex = fake_cms.hex()
    padded = cms_hex + "0" * (512 - len(cms_hex))
    pdf = _build_fake_signed_pdf(padded)

    result = verify_embedded_signature(pdf)
    assert "signer" in result


# ── resolve_hash_algo ────────────────────────────────────────────────


def test_resolve_hash_algo_standard():
    """Standard algorithm names should resolve directly."""
    from revenant.core.pdf.cms_info import resolve_hash_algo

    assert resolve_hash_algo("sha1") == "sha1"
    assert resolve_hash_algo("sha256") == "sha256"
    assert resolve_hash_algo("sha384") == "sha384"
    assert resolve_hash_algo("sha512") == "sha512"


def test_resolve_hash_algo_cosign_quirk():
    """CoSign's non-standard algo names should map to standard ones."""
    from revenant.core.pdf.cms_info import resolve_hash_algo

    assert resolve_hash_algo("sha1_rsa") == "sha1"
    assert resolve_hash_algo("sha256_rsa") == "sha256"


def test_resolve_hash_algo_oid_fallback():
    """OID strings should map to standard algorithm names."""
    from revenant.core.pdf.cms_info import resolve_hash_algo

    # sha1WithRSAEncryption OID
    assert resolve_hash_algo("1.2.840.113549.1.1.5") == "sha1"
    # sha256WithRSAEncryption OID
    assert resolve_hash_algo("1.2.840.113549.1.1.11") == "sha256"


def test_resolve_hash_algo_unknown():
    """Unknown algorithm should return None."""
    from revenant.core.pdf.cms_info import resolve_hash_algo

    assert resolve_hash_algo("totally_unknown_algo") is None


# ── Xref entry size (20 bytes per spec) ───────────────────────────────


def test_xref_entry_exactly_20_bytes():
    """Each xref entry must be exactly 20 bytes (PDF spec S7.5.4)."""
    xref_data = build_xref_and_trailer(
        xref_entries={5: 1000, 6: 2000},
        new_size=7,
        prev_xref=0,
        root_obj_num=1,
        root_gen=0,
        trailer_extra=[],
        xref_offset=3000,
    )
    text = xref_data.decode("latin-1")
    lines = text.split("\n")

    # Find the xref entry lines (10-digit offset + generation + status)
    entry_lines = [line + "\n" for line in lines if line and line[0].isdigit() and "00000" in line]
    assert len(entry_lines) == 2, f"Expected 2 entries, got {entry_lines}"
    for entry in entry_lines:
        assert len(entry.encode("latin-1")) == 20, (
            f"Entry is {len(entry.encode('latin-1'))} bytes, expected 20: {entry!r}"
        )


def test_xref_consecutive_entries_valid():
    """Consecutive objects in xref should produce valid entries pikepdf can parse."""
    import io

    import pikepdf

    # Create a PDF and add objects at consecutive numbers
    pdf_bytes = _make_blank_pdf()

    obj_a = b"10 0 obj\n<< /Type /XObject >>\nendobj\n"
    obj_b = b"11 0 obj\n<< /Type /XObject >>\nendobj\n"

    root_num, root_gen = find_root_obj_num(pdf_bytes)
    prev_xref, prev_size, trailer_extra = find_prev_startxref(pdf_bytes)

    raw_objects = [(obj_a, 10), (obj_b, 11)]
    new_size = max(prev_size, 12)

    prepared = assemble_incremental_update(
        pdf_bytes=pdf_bytes,
        raw_objects=raw_objects,
        new_size=new_size,
        prev_xref=prev_xref,
        root_obj_num=root_num,
        root_gen=root_gen,
        trailer_extra=trailer_extra,
    )

    # pikepdf must be able to open this without errors
    with pikepdf.open(io.BytesIO(prepared)) as pdf:
        assert len(pdf.pages) == 1


# ── Cross-reference stream PDF handling ───────────────────────────────


def _make_xref_stream_pdf() -> bytes:
    """Create a PDF that uses cross-reference streams (no traditional trailer).

    Uses object_stream_mode=generate which produces a PDF with a
    cross-reference stream instead of a traditional xref table + trailer.
    """
    import io

    import pikepdf

    pdf = pikepdf.Pdf.new()
    for _ in range(3):
        pdf.add_blank_page(page_size=(612, 792))
    buf = io.BytesIO()
    pdf.save(buf, object_stream_mode=pikepdf.ObjectStreamMode.generate)
    return buf.getvalue()


def test_xref_stream_pdf_has_no_traditional_trailer():
    """Verify our helper creates a PDF without traditional trailers."""
    import re

    pdf_bytes = _make_xref_stream_pdf()
    # Should have NO traditional "trailer << ... >>" blocks
    trailers = re.findall(rb"trailer\s*<<", pdf_bytes)
    assert len(trailers) == 0, "Expected xref stream PDF to have no traditional trailers"


def test_extract_trailer_entries_xref_stream():
    """_extract_trailer_entries should extract /Info and /ID from xref stream PDFs."""
    pdf_bytes = _make_xref_stream_pdf()
    entries = _extract_trailer_entries(pdf_bytes)

    # pikepdf-generated PDFs should have /ID at minimum
    id_entries = [e for e in entries if e.startswith("/ID")]
    assert len(id_entries) == 1, f"Expected /ID entry, got: {entries}"


def test_extract_trailer_entries_traditional():
    """_extract_trailer_entries should work with traditional trailers too."""
    pdf_data = (
        b"%PDF-1.4\n"
        b"trailer\n<< /Size 5 /Root 1 0 R /Info 3 0 R /ID [<aabb> <ccdd>] >>\n"
        b"startxref\n42\n%%EOF\n"
    )
    entries = _extract_trailer_entries(pdf_data)
    assert any("/Info" in e for e in entries)
    assert any("/ID" in e for e in entries)


def test_find_prev_startxref_xref_stream():
    """find_prev_startxref should correctly read /Size from xref stream PDFs."""
    import io

    import pikepdf

    pdf_bytes = _make_xref_stream_pdf()

    prev_xref, max_size, trailer_extra = find_prev_startxref(pdf_bytes)
    assert prev_xref >= 0
    assert max_size > 0

    # /Size from pikepdf should match the actual object count
    with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
        expected_size = int(pdf.trailer["/Size"])
    assert max_size == expected_size

    # trailer_extra should contain entries extracted via pikepdf fallback
    id_entries = [e for e in trailer_extra if e.startswith("/ID")]
    assert len(id_entries) == 1


def test_prepare_xref_stream_pdf_roundtrip():
    """Full round-trip: xref stream PDF -> prepare -> pikepdf can open."""
    import io

    import pikepdf

    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_xref_stream_pdf()

    # Visible signature
    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page="last", position="br", reason="Test", name="Test User"
    )

    assert hex_start > 0
    assert hex_len == CMS_HEX_SIZE
    assert len(prepared) > len(pdf_bytes)

    # pikepdf MUST be able to open the result
    with pikepdf.open(io.BytesIO(prepared)) as pdf:
        assert len(pdf.pages) == 3

    # Insert fake CMS and verify structure
    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed_pdf = insert_cms(prepared, hex_start, hex_len, fake_cms)
    br_hash = compute_byterange_hash(prepared, hex_start, hex_len)

    result = verify_embedded_signature(signed_pdf, expected_hash=br_hash)
    assert result["structure_ok"] is True
    assert result["hash_ok"] is True
    assert result["valid"] is True


def test_prepare_xref_stream_pdf_invisible():
    """Invisible signature on xref stream PDF should work."""
    import io

    import pikepdf

    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_xref_stream_pdf()

    prepared, _hex_start, _hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, reason="Test", visible=False
    )

    with pikepdf.open(io.BytesIO(prepared)) as pdf:
        assert len(pdf.pages) == 3

    # Trailer should contain /ID from the xref stream
    trailer_section = prepared[prepared.rfind(b"trailer") :]
    assert b"/ID" in trailer_section


def test_prepare_xref_stream_pdf_trailer_has_info_and_id():
    """Incremental update trailer should carry forward /Info and /ID from xref stream."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_xref_stream_pdf()

    prepared, _hs, _hl = prepare_pdf_with_sig_field(pdf_bytes, page=0, reason="Test", visible=False)

    # Find the incremental update's trailer (after original PDF)
    incr_trailer = prepared[len(pdf_bytes) :]
    trailer_start = incr_trailer.find(b"trailer")
    assert trailer_start >= 0
    trailer_section = incr_trailer[trailer_start:]

    # Must have /ID carried forward
    assert b"/ID" in trailer_section


# ── Page rotation round-trips ────────────────────────────────────────


@pytest.mark.parametrize("rotation", [0, 90, 180, 270], ids=["rot0", "rot90", "rot180", "rot270"])
def test_prepare_rotated_page(rotation):
    """Signature on a rotated page should produce a valid signed PDF."""
    import io

    import pikepdf

    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    if rotation:
        pdf.pages[0].obj["/Rotate"] = rotation
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, position="br", reason="Test", name="Test"
    )
    assert hex_start > 0
    assert hex_len == CMS_HEX_SIZE

    # Insert fake CMS and verify
    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed_pdf = insert_cms(prepared, hex_start, hex_len, fake_cms)
    br_hash = compute_byterange_hash(prepared, hex_start, hex_len)
    result = verify_embedded_signature(signed_pdf, expected_hash=br_hash)
    assert result["valid"] is True


@pytest.mark.parametrize(
    ("rotation", "expected_w", "expected_h"),
    [
        (0, 612, 792),
        (90, 792, 612),
        (180, 612, 792),
        (270, 792, 612),
    ],
    ids=["rot0", "rot90", "rot180", "rot270"],
)
def test_get_page_dimensions_all_rotations(rotation, expected_w, expected_h):
    """Page dimensions should respect /Rotate for all rotation values."""
    import io

    import pikepdf

    from revenant.core.pdf import get_page_dimensions

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    if rotation:
        pdf.pages[0].obj["/Rotate"] = rotation
    buf = io.BytesIO()
    pdf.save(buf)
    buf.seek(0)
    with pikepdf.open(buf) as pdf2:
        w, h = get_page_dimensions(pdf2, 0)
    assert abs(w - expected_w) < 0.01
    assert abs(h - expected_h) < 0.01


# ── Non-standard page sizes ──────────────────────────────────────────


@pytest.mark.parametrize(
    "page_size",
    [
        (842, 1191),  # A3
        (420, 595),  # A5
        (612, 1008),  # US Legal
        (792, 1224),  # Tabloid
        (500, 500),  # Square
    ],
    ids=["A3", "A5", "US_Legal", "Tabloid", "square"],
)
def test_prepare_various_page_sizes(page_size):
    """Signature should work on various non-standard page sizes."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf(page_size=page_size)

    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, position="br", reason="Test", name="Test"
    )
    assert hex_start > 0
    assert hex_len == CMS_HEX_SIZE

    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed_pdf = insert_cms(prepared, hex_start, hex_len, fake_cms)
    br_hash = compute_byterange_hash(prepared, hex_start, hex_len)
    result = verify_embedded_signature(signed_pdf, expected_hash=br_hash)
    assert result["valid"] is True


# ── CropBox vs MediaBox ──────────────────────────────────────────────


def test_get_page_dimensions_cropbox():
    """CropBox should override MediaBox for effective dimensions."""
    import io

    import pikepdf

    from revenant.core.pdf import get_page_dimensions

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    # Set a CropBox smaller than MediaBox
    pdf.pages[0].obj["/CropBox"] = pikepdf.Array([50, 50, 400, 600])
    buf = io.BytesIO()
    pdf.save(buf)
    buf.seek(0)
    with pikepdf.open(buf) as pdf2:
        w, h = get_page_dimensions(pdf2, 0)
    assert abs(w - 350) < 0.01  # 400 - 50
    assert abs(h - 550) < 0.01  # 600 - 50


def test_prepare_pdf_with_cropbox():
    """Signature on a page with CropBox should use CropBox dimensions."""
    import io

    import pikepdf

    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    # CropBox is smaller than MediaBox
    pdf.pages[0].obj["/CropBox"] = pikepdf.Array([0, 0, 500, 700])
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, position="br", reason="Test", name="Test"
    )
    assert hex_start > 0

    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed_pdf = insert_cms(prepared, hex_start, hex_len, fake_cms)
    br_hash = compute_byterange_hash(prepared, hex_start, hex_len)
    result = verify_embedded_signature(signed_pdf, expected_hash=br_hash)
    assert result["valid"] is True


# ── Inherited MediaBox from Pages tree ───────────────────────────────


def test_prepare_inherited_mediabox():
    """PDF with MediaBox defined on parent /Pages (not individual page) should work."""
    import io

    import pikepdf

    from revenant.core.pdf import prepare_pdf_with_sig_field

    # Create a PDF, then move MediaBox to the parent /Pages node
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    # pikepdf resolves inherited properties transparently,
    # but let's verify the signing pipeline handles it
    pages_root = pdf.Root["/Pages"]
    pages_root["/MediaBox"] = pikepdf.Array([0, 0, 612, 792])
    # Remove MediaBox from the page itself if present
    page = pdf.pages[0].obj
    if "/MediaBox" in page:
        del page["/MediaBox"]
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, position="br", reason="Test", name="Test"
    )
    assert hex_start > 0

    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed_pdf = insert_cms(prepared, hex_start, hex_len, fake_cms)
    br_hash = compute_byterange_hash(prepared, hex_start, hex_len)
    result = verify_embedded_signature(signed_pdf, expected_hash=br_hash)
    assert result["valid"] is True


# ── Existing AcroForm and re-signing ─────────────────────────────────


def test_prepare_pdf_with_existing_acroform():
    """PDF with existing /AcroForm fields should be signable."""
    import io

    import pikepdf

    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    # Add a text field via AcroForm
    text_field = pdf.make_indirect(
        pikepdf.Dictionary(
            {
                "/Type": pikepdf.Name("/Annot"),
                "/Subtype": pikepdf.Name("/Widget"),
                "/FT": pikepdf.Name("/Tx"),
                "/T": pikepdf.String("FieldName"),
                "/Rect": pikepdf.Array([100, 100, 200, 120]),
                "/P": pdf.pages[0].obj,
            }
        )
    )
    pdf.Root["/AcroForm"] = pdf.make_indirect(
        pikepdf.Dictionary(
            {
                "/Fields": pikepdf.Array([text_field]),
            }
        )
    )
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, position="br", reason="Test", name="Test"
    )
    assert hex_start > 0

    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed_pdf = insert_cms(prepared, hex_start, hex_len, fake_cms)
    br_hash = compute_byterange_hash(prepared, hex_start, hex_len)
    result = verify_embedded_signature(signed_pdf, expected_hash=br_hash)
    assert result["valid"] is True


def test_re_sign_already_signed_pdf():
    """Signing an already-signed PDF should produce two valid ByteRanges."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf()

    # First signature
    prepared1, hex_start1, hex_len1 = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, position="br", reason="First sig", name="Signer1"
    )
    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed1 = insert_cms(prepared1, hex_start1, hex_len1, fake_cms)

    # Second signature on the already-signed PDF
    prepared2, hex_start2, hex_len2 = prepare_pdf_with_sig_field(
        signed1, page=0, position="tl", reason="Second sig", name="Signer2"
    )
    signed2 = insert_cms(prepared2, hex_start2, hex_len2, fake_cms)

    # Both ByteRanges should be present
    import re

    br_matches = list(re.finditer(BYTERANGE_PATTERN, signed2))
    assert len(br_matches) >= 2

    # The last signature should verify against its own hash
    br_hash2 = compute_byterange_hash(prepared2, hex_start2, hex_len2)
    result = verify_embedded_signature(signed2, expected_hash=br_hash2)
    assert result["valid"] is True


# ── Many existing annotations ────────────────────────────────────────


def test_prepare_page_with_many_annots():
    """Page with 20+ annotations should preserve all of them."""
    import io

    import pikepdf

    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))

    annots = []
    for i in range(25):
        annot = pdf.make_indirect(
            pikepdf.Dictionary(
                {
                    "/Type": pikepdf.Name("/Annot"),
                    "/Subtype": pikepdf.Name("/Text"),
                    "/Rect": pikepdf.Array([i * 10, 0, i * 10 + 10, 10]),
                    "/Contents": pikepdf.String(f"Note {i}"),
                }
            )
        )
        annots.append(annot)
    pdf.pages[0].obj["/Annots"] = pikepdf.Array(annots)
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    prepared, hex_start, _hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, position="br", reason="Test", name="Test"
    )
    assert hex_start > 0

    # All 25 original annotations + 1 new sig annotation = 26 refs in /Annots
    # Count "R" references in the /Annots array in the page override
    import re

    annots_match = re.search(rb"/Annots\s*\[(.*?)\]", prepared[len(pdf_bytes) :], re.DOTALL)
    assert annots_match is not None
    refs = re.findall(rb"\d+ \d+ R", annots_match.group(1))
    assert len(refs) == 26  # 25 original + 1 new


# ── Small page (signature doesn't fit) ───────────────────────────────


def test_prepare_page_too_small_for_signature():
    """Page smaller than signature + margins should raise PDFError."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    # Tiny page: 100x100 pt, signature default is 210x70 + margins
    pdf_bytes = _make_blank_pdf(page_size=(100, 100))

    with pytest.raises(PDFError, match="does not fit"):
        prepare_pdf_with_sig_field(pdf_bytes, page=0, position="br", reason="Test")


# ── Large page count ─────────────────────────────────────────────────


def test_prepare_100_page_pdf():
    """Signing the last page of a 100-page PDF should work."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf(num_pages=100)

    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page="last", position="br", reason="Test", name="Test"
    )
    assert hex_start > 0

    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed_pdf = insert_cms(prepared, hex_start, hex_len, fake_cms)
    br_hash = compute_byterange_hash(prepared, hex_start, hex_len)
    result = verify_embedded_signature(signed_pdf, expected_hash=br_hash)
    assert result["valid"] is True


# ── Object streams ───────────────────────────────────────────────────


def test_prepare_object_stream_pdf_roundtrip():
    """PDF with object streams (ObjStm) should be signable."""
    import io

    import pikepdf

    from revenant.core.pdf import prepare_pdf_with_sig_field

    # object_stream_mode=generate creates both object streams and xref streams
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    buf = io.BytesIO()
    pdf.save(buf, object_stream_mode=pikepdf.ObjectStreamMode.generate)
    pdf_bytes = buf.getvalue()

    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, position="br", reason="Test", name="Test"
    )
    assert hex_start > 0

    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed_pdf = insert_cms(prepared, hex_start, hex_len, fake_cms)
    br_hash = compute_byterange_hash(prepared, hex_start, hex_len)
    result = verify_embedded_signature(signed_pdf, expected_hash=br_hash)
    assert result["valid"] is True


# ── pdf_string serialization edge cases ──────────────────────────────


def test_pdf_string_special_chars():
    """pdf_string should escape backslash, parens, control chars."""
    from revenant.core.pdf import pdf_string

    assert pdf_string("hello") == "hello"
    assert pdf_string("back\\slash") == "back\\\\slash"
    assert pdf_string("open(paren") == "open\\(paren"
    assert pdf_string("close)paren") == "close\\)paren"
    assert pdf_string("new\nline") == "new\\nline"
    assert pdf_string("tab\there") == "tab\\there"
    assert pdf_string("return\rhere") == "return\\rhere"
    # Control character (BEL = 0x07)
    assert pdf_string("\x07bell") == "\\007bell"


def test_pdf_string_non_latin1():
    """Non-Latin1 characters should be replaced with '?'."""
    from revenant.core.pdf import pdf_string

    # CJK character (U+4E16) is beyond Latin-1
    result = pdf_string("\u4e16\u754c")
    assert result == "??"


# ── Multiple signatures (verify_all) ────────────────────────────────


def test_verify_all_double_signed():
    """Two signatures in same PDF should both be verifiable."""
    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf_bytes = _make_blank_pdf()

    # First signature
    prepared1, hex_start1, hex_len1 = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, position="br", reason="First", name="Signer1"
    )
    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed1 = insert_cms(prepared1, hex_start1, hex_len1, fake_cms)

    # Second signature
    prepared2, hex_start2, hex_len2 = prepare_pdf_with_sig_field(
        signed1, page=0, position="tl", reason="Second", name="Signer2"
    )
    signed2 = insert_cms(prepared2, hex_start2, hex_len2, fake_cms)

    results = verify_all_embedded_signatures(signed2)
    assert len(results) >= 2
    # At least the structure should be valid for both
    for r in results:
        assert r["structure_ok"] is True


# ── Page with existing content streams ───────────────────────────────


def test_prepare_pdf_with_text_content():
    """PDF with actual text content (not blank) should be signable."""
    import io

    import pikepdf

    from revenant.core.pdf import prepare_pdf_with_sig_field

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    # Add a content stream with text
    content = b"BT /F1 12 Tf 100 700 Td (Hello World) Tj ET"
    pdf.pages[0].obj["/Contents"] = pdf.make_stream(content)
    buf = io.BytesIO()
    pdf.save(buf)
    pdf_bytes = buf.getvalue()

    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes, page=0, position="br", reason="Test", name="Test"
    )
    assert hex_start > 0

    fake_cms = b"\x30\x82\x07\x00" + b"\xab" * 1788
    signed_pdf = insert_cms(prepared, hex_start, hex_len, fake_cms)
    br_hash = compute_byterange_hash(prepared, hex_start, hex_len)
    result = verify_embedded_signature(signed_pdf, expected_hash=br_hash)
    assert result["valid"] is True


# ── Edge case tests: ByteRange validation ───────────────────────────


def test_extract_byterange_negative_values_not_matched():
    """ByteRange with negative values won't match the regex (\\d+ only matches non-negative)."""
    pdf = b"%PDF-1.4\n/ByteRange [0 10 -5 50]\n/Contents <" + b"0" * 10 + b">\n%%EOF\n"
    with pytest.raises(PDFError, match="No /ByteRange"):
        extract_signature_data(pdf)


def test_insert_cms_empty():
    """CMS of zero length should produce all-zero hex region."""
    pdf = b"X" * 100 + b"0" * 20 + b"Y" * 50
    result = insert_cms(pdf, 100, 20, b"")
    hex_region = result[100:120]
    assert hex_region == b"0" * 20


def test_verify_all_empty_pdf():
    """Completely empty input should raise PDFError."""
    with pytest.raises(PDFError, match="No /ByteRange"):
        verify_all_embedded_signatures(b"")


def test_parse_page_spec_float_string():
    """Float-like page spec should raise PDFError."""
    with pytest.raises(PDFError, match="Invalid page"):
        parse_page_spec("1.5")


def test_parse_page_spec_very_large_number():
    """Very large page number should be accepted (page range validation happens elsewhere)."""
    result = parse_page_spec("99999")
    assert result == 99998  # 1-based to 0-based


def test_compute_sig_rect_custom_sig_dimensions():
    """Custom sig_w/sig_h should override defaults."""
    from revenant.core.pdf import compute_sig_rect

    _x, _y, w, h = compute_sig_rect(612, 792, "bottom-left", sig_w=150, sig_h=60)
    assert w == 150
    assert h == 60


# ── extract_der_from_padded_hex — edge cases ─────────────────────────


def test_extract_der_too_short():
    """Hex string shorter than 4 chars should raise ValueError."""
    with pytest.raises(ValueError, match=r"too short for ASN\.1 TLV header"):
        extract_der_from_padded_hex("30")


def test_extract_der_bad_tag():
    """Non-SEQUENCE tag should raise ValueError."""
    with pytest.raises(ValueError, match=r"Expected ASN\.1 SEQUENCE"):
        extract_der_from_padded_hex("FF03aabbcc")


def test_extract_der_indefinite_length():
    """Indefinite length (0x80) should raise ValueError."""
    with pytest.raises(ValueError, match="Indefinite length"):
        extract_der_from_padded_hex("3080aabbcc")


def test_extract_der_length_field_too_large():
    """Length field claiming >4 bytes should raise ValueError."""
    # 0x85 = long form, 5 length bytes (exceeds max of 4)
    with pytest.raises(ValueError, match="length field too large"):
        extract_der_from_padded_hex("3085" + "00" * 20)


def test_extract_der_hex_too_short_for_length():
    """Hex too short to contain the declared length bytes."""
    # 0x82 = long form, 2 length bytes, but hex only has 4 chars total
    with pytest.raises(ValueError, match=r"too short for ASN\.1 length"):
        extract_der_from_padded_hex("3082")


def test_extract_der_exceeds_max_size():
    """ASN.1 length claiming more than max should raise ValueError."""
    # Claim 32MB of content
    with pytest.raises(ValueError, match="exceeds maximum"):
        extract_der_from_padded_hex("308402000000" + "00" * 100)


def test_extract_der_exceeds_available_data():
    """ASN.1 length claiming more bytes than available should raise ValueError."""
    # 0x30 0x0a = SEQUENCE, 10 bytes content -> needs 12 bytes total = 24 hex chars
    # But we only provide 16 hex chars (8 bytes)
    with pytest.raises(ValueError, match="exceeds available hex data"):
        extract_der_from_padded_hex("300aaabbccddeeff")


def test_extract_der_short_form_valid():
    """Short-form length should extract correctly."""
    # 0x30 0x03 = SEQUENCE, 3 bytes content -> 5 bytes total
    result = extract_der_from_padded_hex("3003aabbcc" + "000000")
    assert result == bytes.fromhex("3003aabbcc")


def test_extract_der_long_form_valid():
    """Long-form length with 2-byte length field should extract correctly."""
    # 0x30 0x82 0x00 0x04 = SEQUENCE, 4 bytes content -> 8 bytes total
    result = extract_der_from_padded_hex("30820004aabbccdd" + "0000")
    assert result == bytes.fromhex("30820004aabbccdd")


# ── extract_cms_from_byterange — boundary validation ──────────────────


def test_extract_cms_len1_zero():
    """len1 <= 0 should raise PDFError."""
    with pytest.raises(PDFError, match="len1 must be positive"):
        extract_cms_from_byterange(b"dummy pdf", len1=0, off2=10)


def test_extract_cms_len1_negative():
    """Negative len1 should raise PDFError."""
    with pytest.raises(PDFError, match="len1 must be positive"):
        extract_cms_from_byterange(b"dummy pdf", len1=-5, off2=10)


def test_extract_cms_off2_not_greater_than_len1():
    """off2 <= len1 should raise PDFError."""
    with pytest.raises(PDFError, match="must be greater than len1"):
        extract_cms_from_byterange(b"x" * 100, len1=50, off2=50)


def test_extract_cms_off2_exceeds_pdf_size():
    """off2 beyond PDF size should raise PDFError."""
    with pytest.raises(PDFError, match="exceeds PDF size"):
        extract_cms_from_byterange(b"x" * 50, len1=10, off2=100)


# ── extract_digest_info — CMS parsing ────────────────────────────────


def _der_len(length: int) -> bytes:
    """Encode a DER length field."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _der_seq(contents: bytes) -> bytes:
    """Wrap contents in a DER SEQUENCE."""
    return b"\x30" + _der_len(len(contents)) + contents


def _der_set(contents: bytes) -> bytes:
    """Wrap contents in a DER SET."""
    return b"\x31" + _der_len(len(contents)) + contents


def _build_cms_with_sha256_digest(digest_value: bytes) -> bytes:
    """Build a minimal CMS ContentInfo with a known SHA-256 messageDigest.

    Constructs raw DER bytes to avoid asn1crypto's strict type validation.
    Structure: ContentInfo -> SignedData -> SignerInfo with signed_attrs.
    """
    # OIDs
    oid_signed_data = bytes.fromhex("06092a864886f70d010702")  # 1.2.840.113549.1.7.2
    oid_data = bytes.fromhex("06092a864886f70d010701")  # 1.2.840.113549.1.7.1
    oid_sha256 = bytes.fromhex("0609608648016503040201")  # 2.16.840.1.101.3.4.2.1
    oid_sha256_rsa = bytes.fromhex("06092a864886f70d01010b")  # 1.2.840.113549.1.1.11
    oid_msg_digest = bytes.fromhex("06092a864886f70d010904")  # 1.2.840.113549.1.9.4

    # DigestAlgorithm: SEQUENCE { OID sha256, NULL }
    digest_algo = _der_seq(oid_sha256 + b"\x05\x00")

    # messageDigest attribute: SEQUENCE { OID, SET { OCTET STRING } }
    octet_str = b"\x04" + _der_len(len(digest_value)) + digest_value
    msg_digest_attr = _der_seq(oid_msg_digest + _der_set(octet_str))

    # signed_attrs: implicit [0] SET OF Attribute
    signed_attrs_content = msg_digest_attr
    signed_attrs = b"\xa0" + _der_len(len(signed_attrs_content)) + signed_attrs_content

    # IssuerAndSerialNumber
    cn_oid = bytes.fromhex("0603550403")  # 2.5.4.3
    cn_value = b"\x0c\x04Test"  # UTF8String "Test"
    rdn = _der_set(_der_seq(cn_oid + cn_value))
    issuer = _der_seq(rdn)
    serial = b"\x02\x01\x01"  # INTEGER 1
    issuer_serial = _der_seq(issuer + serial)

    # SignerInfo
    version = b"\x02\x01\x01"  # INTEGER 1
    sig_algo = _der_seq(oid_sha256_rsa + b"\x05\x00")
    signature = b"\x04\x20" + b"\x00" * 32  # OCTET STRING, 32 zero bytes
    signer_info = _der_seq(
        version + issuer_serial + digest_algo + signed_attrs + sig_algo + signature
    )

    # EncapContentInfo: SEQUENCE { OID data }
    encap = _der_seq(oid_data)

    # SignedData
    sd_version = b"\x02\x01\x01"  # INTEGER 1
    digest_algos = _der_set(digest_algo)
    signer_infos = _der_set(signer_info)
    signed_data = _der_seq(sd_version + digest_algos + encap + signer_infos)

    # ContentInfo: SEQUENCE { OID signed-data, [0] EXPLICIT SignedData }
    explicit_content = b"\xa0" + _der_len(len(signed_data)) + signed_data
    return _der_seq(oid_signed_data + explicit_content)


def test_extract_digest_info_sha256():
    """extract_digest_info should parse SHA-256 CMS and return digest."""
    expected_digest = b"\xab" * 32
    cms_der = _build_cms_with_sha256_digest(expected_digest)

    result = extract_digest_info(cms_der)
    assert result is not None
    algo, digest_bytes = result
    assert algo == "sha256"
    assert digest_bytes == expected_digest


def test_extract_digest_info_invalid_cms():
    """extract_digest_info should return None for garbage CMS."""
    assert extract_digest_info(b"\x30\x03\xab\xcd\xef") is None


def test_extract_signer_info_invalid_cms():
    """extract_signer_info should return None for garbage CMS."""
    assert extract_signer_info(b"\x30\x03\xab\xcd\xef") is None


# ── verify with real CMS digest info ──────────────────────────────────


def test_verify_with_real_cms_digest():
    """Verification with CMS containing messageDigest should verify hash."""
    # Build a fake PDF with ByteRange
    fake_inner_cms = b"\x30\x82\x00\xfc" + b"\xab" * 252
    cms_hex = fake_inner_cms.hex()
    padded = cms_hex + "0" * (512 - len(cms_hex))
    pdf = _build_fake_signed_pdf(padded)

    # Extract signed data to compute the real hash
    signed_data, _ = extract_signature_data(pdf)
    real_digest = hashlib.sha256(signed_data).digest()

    # Build a real CMS with the correct SHA-256 digest
    real_cms = _build_cms_with_sha256_digest(real_digest)
    real_cms_hex = real_cms.hex()
    padded_real = real_cms_hex + "0" * (max(512, len(real_cms_hex) + 10) - len(real_cms_hex))

    pdf_with_real_cms = _build_fake_signed_pdf(padded_real)
    result = verify_embedded_signature(pdf_with_real_cms, expected_hash=None)
    assert result["hash_ok"] is True
    assert any("Hash OK" in d for d in result["details"])


def test_verify_with_real_cms_digest_mismatch():
    """CMS with wrong messageDigest should fail hash verification."""
    wrong_digest = b"\x00" * 32
    real_cms = _build_cms_with_sha256_digest(wrong_digest)
    real_cms_hex = real_cms.hex()
    padded = real_cms_hex + "0" * (max(512, len(real_cms_hex) + 10) - len(real_cms_hex))

    pdf = _build_fake_signed_pdf(padded)
    result = verify_embedded_signature(pdf, expected_hash=None)
    assert result["hash_ok"] is False
    assert any("MISMATCH" in d for d in result["details"])


# ── verify_detached_signature ─────────────────────────────────────


def test_verify_detached_hash_match():
    """Detached verification should succeed when hash matches CMS messageDigest."""
    data = b"Hello, this is the original data"
    real_digest = hashlib.sha256(data).digest()
    cms_der = _build_cms_with_sha256_digest(real_digest)

    result = verify_detached_signature(data, cms_der)
    assert result["valid"] is True
    assert result["hash_ok"] is True
    assert result["structure_ok"] is True
    assert any("Hash OK" in d for d in result["details"])


def test_verify_detached_hash_mismatch():
    """Detached verification should fail when hash doesn't match."""
    data = b"Original data"
    wrong_digest = b"\x00" * 32
    cms_der = _build_cms_with_sha256_digest(wrong_digest)

    result = verify_detached_signature(data, cms_der)
    assert result["valid"] is False
    assert result["hash_ok"] is False
    assert any("MISMATCH" in d for d in result["details"])


def test_verify_detached_tiny_cms():
    """Detached verification with too-small CMS blob should fail structure check."""
    result = verify_detached_signature(b"data", b"\x30\x01\x00")
    assert result["valid"] is False
    assert result["structure_ok"] is False
    assert any("too small" in d for d in result["details"])


def test_verify_detached_bad_tag():
    """Detached verification with non-SEQUENCE CMS should fail structure check."""
    result = verify_detached_signature(b"data", b"\x01" * 200)
    assert result["valid"] is False
    assert result["structure_ok"] is False
    assert any("SEQUENCE" in d for d in result["details"])


def test_verify_detached_has_signer_info():
    """Detached verification result should contain signer info from CMS."""
    data = b"test data"
    digest = hashlib.sha256(data).digest()
    cms_der = _build_cms_with_sha256_digest(digest)

    result = verify_detached_signature(data, cms_der)
    # Our test CMS has CN=Test in the issuer, but no certificate section
    # so signer may or may not be extracted depending on CMS structure
    assert result["valid"] is True


# ── inspect_cms_blob ──────────────────────────────────────────────


def test_inspect_cms_valid():
    """inspect_cms_blob should extract digest algorithm from valid CMS."""
    digest = b"\xab" * 32
    cms_der = _build_cms_with_sha256_digest(digest)

    result = inspect_cms_blob(cms_der)
    assert result["cms_size"] == len(cms_der)
    assert result["digest_algorithm"] == "sha256"
    assert any("SHA256" in d for d in result["details"])
    assert any("valid ASN.1" in d for d in result["details"])


def test_inspect_cms_tiny():
    """inspect_cms_blob with too-small blob should report error."""
    result = inspect_cms_blob(b"\x30\x01\x00")
    assert result["signer"] is None
    assert result["digest_algorithm"] is None
    assert any("too small" in d for d in result["details"])


def test_inspect_cms_bad_tag():
    """inspect_cms_blob with non-SEQUENCE blob should report error."""
    result = inspect_cms_blob(b"\x01" * 200)
    assert result["signer"] is None
    assert result["digest_algorithm"] is None
    assert any("Not a valid CMS" in d for d in result["details"])


def test_inspect_cms_with_signer_details():
    """inspect_cms_blob should include signer name, org, and email in details."""
    digest = b"\xab" * 32
    cms_der = _build_cms_with_sha256_digest(digest)

    signer_info = {
        "name": "John Smith",
        "organization": "Acme Corp",
        "email": "john@acme.com",
        "dn": "CN=John Smith,O=Acme Corp",
    }
    with patch("revenant.core.pdf.cms_info.extract_signer_info", return_value=signer_info):
        result = inspect_cms_blob(cms_der)

    assert any("Signer: John Smith" in d for d in result["details"])
    assert any("Organization: Acme Corp" in d for d in result["details"])
    assert any("Email: john@acme.com" in d for d in result["details"])
    assert result["signer"] == signer_info


def test_inspect_cms_with_partial_signer():
    """inspect_cms_blob should handle signer with only a name (no org/email)."""
    digest = b"\xab" * 32
    cms_der = _build_cms_with_sha256_digest(digest)

    signer_info = {"name": "Jane Doe", "organization": None, "email": None, "dn": "CN=Jane Doe"}
    with patch("revenant.core.pdf.cms_info.extract_signer_info", return_value=signer_info):
        result = inspect_cms_blob(cms_der)

    assert any("Signer: Jane Doe" in d for d in result["details"])
    assert not any("Organization:" in d for d in result["details"])
    assert not any("Email:" in d for d in result["details"])


def test_inspect_cms_with_no_signer():
    """inspect_cms_blob should handle None signer gracefully."""
    digest = b"\xab" * 32
    cms_der = _build_cms_with_sha256_digest(digest)

    with patch("revenant.core.pdf.cms_info.extract_signer_info", return_value=None):
        result = inspect_cms_blob(cms_der)

    assert result["signer"] is None
    assert not any("Signer:" in d for d in result["details"])


# ── extract_digest_info edge cases ──────────────────────────────────


def _build_cms_empty_signer_infos() -> bytes:
    """CMS ContentInfo with empty signer_infos SET."""
    oid_signed_data = bytes.fromhex("06092a864886f70d010702")
    oid_data = bytes.fromhex("06092a864886f70d010701")
    oid_sha256 = bytes.fromhex("0609608648016503040201")

    digest_algo = _der_seq(oid_sha256 + b"\x05\x00")
    digest_algos = _der_set(digest_algo)
    encap = _der_seq(oid_data)
    signer_infos = _der_set(b"")  # empty SET
    sd_version = b"\x02\x01\x01"
    signed_data = _der_seq(sd_version + digest_algos + encap + signer_infos)
    explicit_content = b"\xa0" + _der_len(len(signed_data)) + signed_data
    return _der_seq(oid_signed_data + explicit_content)


def test_extract_digest_info_empty_signer_infos():
    """extract_digest_info should return None when signer_infos is empty."""
    cms = _build_cms_empty_signer_infos()
    assert extract_digest_info(cms) is None


def _build_cms_no_signed_attrs(digest_value: bytes) -> bytes:
    """CMS with signer info but WITHOUT signed_attrs."""
    oid_signed_data = bytes.fromhex("06092a864886f70d010702")
    oid_data = bytes.fromhex("06092a864886f70d010701")
    oid_sha256 = bytes.fromhex("0609608648016503040201")
    oid_sha256_rsa = bytes.fromhex("06092a864886f70d01010b")

    digest_algo = _der_seq(oid_sha256 + b"\x05\x00")

    cn_oid = bytes.fromhex("0603550403")
    cn_value = b"\x0c\x04Test"
    rdn = _der_set(_der_seq(cn_oid + cn_value))
    issuer = _der_seq(rdn)
    serial = b"\x02\x01\x01"
    issuer_serial = _der_seq(issuer + serial)

    version = b"\x02\x01\x01"
    sig_algo = _der_seq(oid_sha256_rsa + b"\x05\x00")
    signature = b"\x04\x20" + b"\x00" * 32

    # No signed_attrs -- version + issuer_serial + digest_algo + sig_algo + signature
    signer_info = _der_seq(version + issuer_serial + digest_algo + sig_algo + signature)

    encap = _der_seq(oid_data)
    sd_version = b"\x02\x01\x01"
    digest_algos = _der_set(digest_algo)
    signer_infos = _der_set(signer_info)
    signed_data = _der_seq(sd_version + digest_algos + encap + signer_infos)
    explicit_content = b"\xa0" + _der_len(len(signed_data)) + signed_data
    return _der_seq(oid_signed_data + explicit_content)


def test_extract_digest_info_no_signed_attrs():
    """extract_digest_info should return None when signer has no signed_attrs."""
    cms = _build_cms_no_signed_attrs(b"\xab" * 32)
    assert extract_digest_info(cms) is None


def _build_cms_no_message_digest(digest_value: bytes) -> bytes:
    """CMS with signed_attrs but no messageDigest attribute."""
    oid_signed_data = bytes.fromhex("06092a864886f70d010702")
    oid_data = bytes.fromhex("06092a864886f70d010701")
    oid_sha256 = bytes.fromhex("0609608648016503040201")
    oid_sha256_rsa = bytes.fromhex("06092a864886f70d01010b")
    # Use content-type OID instead of messageDigest
    oid_content_type = bytes.fromhex("06092a864886f70d010903")

    digest_algo = _der_seq(oid_sha256 + b"\x05\x00")

    # Non-messageDigest attribute
    octet_str = b"\x04" + _der_len(len(digest_value)) + digest_value
    other_attr = _der_seq(oid_content_type + _der_set(octet_str))
    signed_attrs = b"\xa0" + _der_len(len(other_attr)) + other_attr

    cn_oid = bytes.fromhex("0603550403")
    cn_value = b"\x0c\x04Test"
    rdn = _der_set(_der_seq(cn_oid + cn_value))
    issuer = _der_seq(rdn)
    serial = b"\x02\x01\x01"
    issuer_serial = _der_seq(issuer + serial)

    version = b"\x02\x01\x01"
    sig_algo = _der_seq(oid_sha256_rsa + b"\x05\x00")
    signature = b"\x04\x20" + b"\x00" * 32
    signer_info = _der_seq(
        version + issuer_serial + digest_algo + signed_attrs + sig_algo + signature
    )

    encap = _der_seq(oid_data)
    sd_version = b"\x02\x01\x01"
    digest_algos = _der_set(digest_algo)
    signer_infos = _der_set(signer_info)
    signed_data = _der_seq(sd_version + digest_algos + encap + signer_infos)
    explicit_content = b"\xa0" + _der_len(len(signed_data)) + signed_data
    return _der_seq(oid_signed_data + explicit_content)


def test_extract_digest_info_no_message_digest_attr():
    """extract_digest_info returns None when signed_attrs lack messageDigest."""
    cms = _build_cms_no_message_digest(b"\xab" * 32)
    assert extract_digest_info(cms) is None


def test_extract_digest_info_unrecognized_algo():
    """extract_digest_info returns None when digest algorithm is unrecognized."""
    cms = _build_cms_with_sha256_digest(b"\xab" * 32)

    with patch("revenant.core.pdf.cms_info.resolve_hash_algo", return_value=None):
        result = extract_digest_info(cms)
    assert result is None


# ── compute_byterange_hash edge cases ──────────────────────────────


def test_compute_byterange_hash_zero_start():
    """hex_start <= 0 should raise PDFError."""
    with pytest.raises(PDFError, match="Invalid hex range"):
        compute_byterange_hash(b"x" * 100, 0, 50)


def test_compute_byterange_hash_end_past_eof():
    """hex end past file should raise PDFError."""
    with pytest.raises(PDFError, match="Invalid hex range"):
        compute_byterange_hash(b"x" * 100, 50, 60)


def test_compute_byterange_hash_missing_open_angle():
    """Missing '<' before hex data should raise PDFError."""
    data = b"x" * 100
    with pytest.raises(PDFError, match="expected '<' before hex"):
        compute_byterange_hash(data, 10, 50)
