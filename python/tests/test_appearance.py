"""Tests for revenant.core.appearance — visual signature stream generation."""

import re

import pytest

from revenant.config.profiles import CertField, SigField
from revenant.core.appearance import (
    AVAILABLE_FONTS,
    DEFAULT_FONT,
    FontMetrics,
    build_appearance_stream,
    compute_optimal_height,
    compute_optimal_width,
    encode_text_hex,
    extract_cert_fields,
    extract_display_fields,
    format_utc_offset,
    get_font,
    load_signature_image,
    pdf_escape,
    text_width,
    wrap_lines,
)

# ── text_width ─────────────────────────────────────────────────────


def test_text_width_empty():
    assert text_width("", 12) == 0.0


def test_text_width_scales_with_font_size():
    w10 = text_width("Hello", 10)
    w20 = text_width("Hello", 20)
    assert w20 == pytest.approx(w10 * 2, rel=1e-6)


def test_text_width_armenian():
    """Armenian text should have non-zero width."""
    w = text_width("\u0540\u0561\u0575\u0565\u0580", 10)
    assert w > 0


# ── pdf_escape ─────────────────────────────────────────────────────


def test_pdf_escape_format():
    """Should produce PDF hex string format: <hex_glyph_ids>."""
    result = pdf_escape("AB")
    assert result.startswith("<")
    assert result.endswith(">")
    assert len(result) == 10  # <4hex><4hex>


# ── encode_text_hex ────────────────────────────────────────────────


def test_encode_text_hex_ascii():
    """ASCII chars should map to valid 4-hex-digit glyph IDs."""
    result = encode_text_hex("A")
    assert len(result) == 4
    # Should be a valid hex string
    int(result, 16)


def test_encode_text_hex_armenian():
    result = encode_text_hex("\u0540")
    assert len(result) == 4
    gid = int(result, 16)
    assert gid > 0  # Should map to a real glyph, not .notdef


# ── wrap_lines ─────────────────────────────────────────────────────


def test_wrap_short_text():
    lines = wrap_lines("Hi", 10, 200)
    assert lines == ["Hi"]


def test_wrap_long_text():
    text = "This is a fairly long sentence that should be wrapped into multiple lines"
    lines = wrap_lines(text, 10, 100)
    assert len(lines) > 1
    # All original words should be present
    assert " ".join(lines) == text


def test_wrap_single_long_word():
    lines = wrap_lines("Superlongwordthatcannotbewrapped", 10, 50)
    # Should still produce output (word goes on its own line)
    assert len(lines) >= 1
    assert "Superlongwordthatcannotbewrapped" in lines[0]


def test_wrap_empty():
    lines = wrap_lines("", 10, 200)
    assert lines == []


# ── format_utc_offset ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("tz", "expected"),
    [
        (None, "UTC"),
        ("utc", "UTC"),
        ("+4:00", "UTC+4"),
        ("-5:30", "UTC-5:30"),
        ("+5:45", "UTC+5:45"),
    ],
    ids=["naive", "utc", "positive", "negative_half", "positive_half"],
)
def test_format_utc_offset(tz, expected):
    from datetime import datetime, timedelta, timezone

    if tz is None or tz == "utc":
        dt = datetime(2026, 2, 7, 12, 0, tzinfo=timezone.utc)
    else:
        sign = -1 if tz.startswith("-") else 1
        parts = tz.lstrip("+-").split(":")
        hours = int(parts[0])
        minutes = int(parts[1]) if len(parts) > 1 else 0
        offset = timedelta(hours=sign * hours, minutes=sign * minutes)
        dt = datetime(2026, 2, 7, 12, 0, tzinfo=timezone(offset))
    assert format_utc_offset(dt) == expected


# ── extract_cert_fields ────────────────────────────────────────────

# EKENG-like cert_fields and sig_fields for testing
_EKENG_CERT_FIELDS = (
    CertField(id="name", label="Name", source="name", regex=r"^(.+?)\s+\d{5,}$"),
    CertField(id="gov_id", label="SSN", source="name", regex=r"(\d{5,})$"),
)
_EKENG_SIG_FIELDS = (
    SigField(cert_field="name"),
    SigField(cert_field="gov_id", label="SSN"),
    SigField(auto="date"),
)


def test_extract_cert_fields_basic():
    """CertField extraction should parse name and gov_id from signer name."""
    signer_info = {
        "name": "Aleksandr Kraiz 3105951040",
        "dn": None,
        "organization": None,
        "email": None,
    }
    extracted = extract_cert_fields(_EKENG_CERT_FIELDS, signer_info)
    assert extracted == {"name": "Aleksandr Kraiz", "gov_id": "3105951040"}


def test_extract_cert_fields_missing_source():
    """Fields with missing source values should be skipped."""
    cert_fields = (
        CertField(id="name", label="Name", source="name"),
        CertField(id="org", label="Org", source="organization"),
    )
    extracted = extract_cert_fields(cert_fields, {"name": "Alice", "organization": None})
    assert extracted == {"name": "Alice"}


def test_extract_cert_fields_regex_no_match():
    """Fields where regex doesn't match should be skipped."""
    cert_fields = (CertField(id="gov_id", label="SSN", source="name", regex=r"(\d{5,})$"),)
    extracted = extract_cert_fields(cert_fields, {"name": "John Smith"})
    assert extracted == {}


def test_extract_cert_fields_no_regex():
    """Without regex, the full source value is used."""
    cert_fields = (CertField(id="dn", label="DN", source="dn"),)
    extracted = extract_cert_fields(cert_fields, {"name": None, "dn": "cn=Bob, o=Acme"})
    assert extracted == {"dn": "cn=Bob, o=Acme"}


def test_extract_cert_fields_unknown_source():
    """CertField with unrecognized source should be skipped."""
    cert_fields = (CertField(id="foo", label="Foo", source="nonexistent"),)
    extracted = extract_cert_fields(cert_fields, {"name": "Alice"})
    assert extracted == {}


def test_extract_cert_fields_invalid_regex():
    """CertField with invalid regex should be skipped (logged, not raised)."""
    cert_fields = (CertField(id="bad", label="Bad", source="name", regex=r"(unclosed"),)
    extracted = extract_cert_fields(cert_fields, {"name": "Alice"})
    assert extracted == {}


def test_format_utc_offset_naive_datetime():
    """Naive datetime (no timezone) should return 'UTC'."""
    from datetime import datetime

    dt = datetime(2026, 2, 7, 12, 0)  # noqa: DTZ001 -- intentionally naive for test
    assert format_utc_offset(dt) == "UTC"


# ── extract_display_fields ──────────────────────────────────────────


def test_extract_ekeng_name_and_id():
    """EKENG flow: cert extraction + sig fields should produce display strings."""
    signer_info = {
        "name": "Aleksandr Kraiz 3105951040",
        "dn": None,
        "organization": None,
        "email": None,
    }
    cert_values = extract_cert_fields(_EKENG_CERT_FIELDS, signer_info)
    fields = extract_display_fields(_EKENG_SIG_FIELDS, cert_values)
    assert len(fields) == 3
    assert fields[0] == "Aleksandr Kraiz"
    assert fields[1] == "SSN: 3105951040"
    assert fields[2].startswith("Date: ")


def test_extract_auto_date_format():
    """Auto date field should produce a properly formatted date string."""
    sig_fields = (SigField(auto="date"),)
    fields = extract_display_fields(sig_fields, {})
    assert len(fields) == 1
    assert re.match(r"Date: \d{1,2} \w+ \d{4}, \d{2}:\d{2}:\d{2} UTC", fields[0])


def test_extract_auto_date_custom_label():
    """Auto date with custom label should use that label."""
    sig_fields = (SigField(auto="date", label="Signed"),)
    fields = extract_display_fields(sig_fields, {})
    assert fields[0].startswith("Signed: ")


def test_extract_display_with_label():
    """Label prefix should be prepended to cert field value."""
    sig_fields = (SigField(cert_field="id", label="ID"),)
    cert_values = {"id": "12345"}
    fields = extract_display_fields(sig_fields, cert_values)
    assert fields == ["ID: 12345"]


def test_extract_display_no_label():
    """Without label, raw cert field value is used."""
    sig_fields = (SigField(cert_field="dn"),)
    cert_values = {"dn": "cn=Bob, o=Acme"}
    fields = extract_display_fields(sig_fields, cert_values)
    assert fields == ["cn=Bob, o=Acme"]


def test_extract_display_missing_cert_field_skipped():
    """SigField referencing missing cert_values key should be skipped."""
    sig_fields = (SigField(cert_field="name"), SigField(cert_field="missing"))
    cert_values = {"name": "Alice"}
    fields = extract_display_fields(sig_fields, cert_values)
    assert fields == ["Alice"]


def test_extract_empty_sig_fields():
    """Empty sig_fields tuple should return empty list."""
    fields = extract_display_fields((), {"name": "Alice"})
    assert fields == []


# ── build_appearance_stream (stacked layout, no image) ─────────────


def test_build_basic():
    result = build_appearance_stream(
        width=200,
        height=70,
        fields=["Test User"],
    )
    assert "stream" in result
    assert "bbox" in result
    assert "resources" in result
    assert result["bbox"] == (0, 0, 200, 70)
    assert result["resources"]["font_name"] == "F1"
    assert result["resources"]["base_font"] == "NotoSans"


def test_build_stream_is_bytes():
    result = build_appearance_stream(width=200, height=70, fields=["Test"])
    assert isinstance(result["stream"], bytes)


def test_build_stream_contains_name():
    result = build_appearance_stream(width=200, height=70, fields=["Alice"])
    stream = result["stream"].decode("ascii")
    assert encode_text_hex("Alice") in stream


def test_build_with_multiple_fields():
    result = build_appearance_stream(
        width=200,
        height=70,
        fields=["Bob", "3105951040", "Date: 2026.01.30 12:00:00 +00'00'"],
    )
    stream = result["stream"].decode("ascii")
    assert encode_text_hex("Bob") in stream
    assert encode_text_hex("3105951040") in stream
    assert encode_text_hex("2026.01.30") in stream


def test_build_stacked_no_divider():
    """Stacked layout (no image) should not have a vertical divider line."""
    result = build_appearance_stream(
        width=200,
        height=70,
        fields=["Test", "Date: 2026.01.30 12:00:00 +00'00'"],
    )
    stream = result["stream"].decode("ascii")
    # The divider uses " m " and " l " for a vertical line — should not be present
    # (border rectangle uses "re S", not "m ... l")
    assert " m " not in stream


def test_build_stream_has_pdf_operators():
    result = build_appearance_stream(width=200, height=70, fields=["Test"])
    stream = result["stream"].decode("ascii")
    # Should contain basic PDF operators
    assert "BT" in stream  # begin text
    assert "ET" in stream  # end text
    assert "Tf" in stream  # set font
    assert "Tj" in stream  # show text
    assert "re" in stream  # rectangle


def test_build_tiny_field():
    """Very small field should still produce valid output."""
    result = build_appearance_stream(width=50, height=20, fields=["A Very Long Name Indeed"])
    assert isinstance(result["stream"], bytes)
    assert len(result["stream"]) > 0


def test_build_empty_fields():
    """Empty fields list should still produce valid output."""
    result = build_appearance_stream(width=200, height=70, fields=[])
    assert isinstance(result["stream"], bytes)
    assert result["needs_image"] is False


def test_build_first_field_large_rest_small():
    """First field should use larger font, detail fields smaller."""
    result = build_appearance_stream(
        width=200,
        height=70,
        fields=["Big Name", "small detail"],
    )
    stream = result["stream"].decode("ascii")
    # Both should be present (hex-encoded)
    assert encode_text_hex("Big Name") in stream
    assert encode_text_hex("small detail") in stream
    # Detail color (gray) should be set
    assert "0.35 g" in stream


# ── Image support ───────────────────────────────────────────────────


def test_build_with_image():
    """has_image=True should produce /Img1 Do and image column."""
    result = build_appearance_stream(width=200, height=70, fields=["Test"], has_image=True)
    stream = result["stream"].decode("ascii")
    assert "/Img1 Do" in stream
    assert result["needs_image"] is True
    assert encode_text_hex("Test") in stream


def test_build_without_image_no_img_ref():
    """Without has_image, stream should not reference /Img1."""
    result = build_appearance_stream(width=200, height=70, fields=["Test"], has_image=False)
    stream = result["stream"].decode("ascii")
    assert "/Img1" not in stream
    assert result["needs_image"] is False


def test_build_with_image_still_has_fields():
    """Image mode should still render all fields in the text column."""
    result = build_appearance_stream(
        width=200,
        height=70,
        fields=["Alice", "ID: 12345", "Date: 2026.01.30"],
        has_image=True,
    )
    stream = result["stream"].decode("ascii")
    assert encode_text_hex("Alice") in stream
    assert encode_text_hex("12345") in stream
    assert encode_text_hex("2026.01.30") in stream


# ── compute_optimal_width ───────────────────────────────────────────


def test_optimal_width_empty_fields():
    """Empty fields should return minimum width."""
    w = compute_optimal_width([], 70)
    assert w == 150.0  # _MIN_SIG_WIDTH


def test_optimal_width_short_name():
    """Short name should produce width within bounds."""
    w = compute_optimal_width(["Al"], 70)
    assert 150.0 <= w <= 300.0


def test_optimal_width_long_name():
    """Long name should produce wider result (up to max)."""
    w_short = compute_optimal_width(["Al"], 70)
    w_long = compute_optimal_width(["Aleksandr Kraiz Very Long Name"], 70)
    assert w_long >= w_short


def test_optimal_width_with_image():
    """Image mode should produce wider result to accommodate image column."""
    w_no_img = compute_optimal_width(["Alice"], 70, has_image=False)
    w_img = compute_optimal_width(["Alice"], 70, has_image=True)
    assert w_img >= w_no_img


def test_optimal_width_single_field():
    """Single field (no detail fields) should compute width from name only."""
    w = compute_optimal_width(["Alice"], 70)
    assert 150.0 <= w <= 300.0


def test_optimal_width_with_detail_fields():
    """Width with detail fields should be at least as wide as without."""
    w_one = compute_optimal_width(["Al"], 70)
    w_with_details = compute_optimal_width(["Al", "Extra detail field here", "Another detail"], 70)
    # More text content should produce equal or wider result
    assert w_one >= 150.0
    assert w_with_details >= w_one


# ── compute_optimal_height ──────────────────────────────────────────


def test_optimal_height_empty_fields():
    """Empty fields should return minimum height."""
    h = compute_optimal_height([], 200)
    assert h == 40.0  # _MIN_SIG_HEIGHT


def test_optimal_height_single_field():
    """Single field should produce a compact height."""
    h = compute_optimal_height(["Alice"], 200)
    assert 40.0 <= h <= 120.0


def test_optimal_height_multiple_fields():
    """More fields should produce taller result."""
    h1 = compute_optimal_height(["Alice"], 200)
    h3 = compute_optimal_height(["Alice", "SSN: 12345", "Date: 2026.01.30"], 200)
    assert h3 > h1


def test_optimal_height_with_image():
    """Image mode should not affect height (image scales to fit)."""
    h_no_img = compute_optimal_height(["Alice", "ID: 123"], 200, has_image=False)
    h_img = compute_optimal_height(["Alice", "ID: 123"], 200, has_image=True)
    # Image narrows text area -> may wrap -> could be taller
    assert h_img >= h_no_img


def test_optimal_height_clamped_to_max():
    """Many fields should not exceed max height."""
    fields = [f"Field {i}" for i in range(20)]
    h = compute_optimal_height(fields, 200)
    assert h <= 120.0


# ── Image loading ─────────────────────────────────────────────────


try:
    from PIL import Image

    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False

requires_pillow = pytest.mark.skipif(not HAS_PILLOW, reason="Pillow not installed")


@requires_pillow
def test_load_signature_image_png(tmp_path):
    """Load a simple RGB PNG image."""
    img = Image.new("RGB", (100, 50), color=(255, 0, 0))
    img_path = tmp_path / "sig.png"
    img.save(str(img_path))

    data = load_signature_image(str(img_path))
    assert data["width"] == 100
    assert data["height"] == 50
    assert data["bpc"] == 8
    assert data["smask"] is None
    assert len(data["samples"]) > 0


@requires_pillow
def test_load_signature_image_rgba(tmp_path):
    """Load a PNG with alpha channel — should produce smask."""
    img = Image.new("RGBA", (80, 40), color=(0, 0, 0, 128))
    img_path = tmp_path / "sig_alpha.png"
    img.save(str(img_path))

    data = load_signature_image(str(img_path))
    assert data["width"] == 80
    assert data["height"] == 40
    assert data["smask"] is not None
    assert len(data["smask"]) > 0


@requires_pillow
def test_load_signature_image_downscale(tmp_path):
    """Large images should be downscaled to max 200px."""
    img = Image.new("RGB", (1000, 500), color=(0, 128, 0))
    img_path = tmp_path / "big.png"
    img.save(str(img_path))

    data = load_signature_image(str(img_path))
    assert data["width"] <= 200
    assert data["height"] <= 200
    # Aspect ratio preserved
    assert abs(data["width"] / data["height"] - 2.0) < 0.1


@requires_pillow
def test_load_signature_image_jpeg(tmp_path):
    """JPEG images should work too (no alpha)."""
    img = Image.new("RGB", (60, 30), color=(0, 0, 255))
    img_path = tmp_path / "sig.jpg"
    img.save(str(img_path))

    data = load_signature_image(str(img_path))
    assert data["width"] == 60
    assert data["height"] == 30
    assert data["smask"] is None


# ── build_appearance_stream — font reduction ──────────────────────────


def test_build_tall_name_triggers_font_reduction():
    """Very short height with long name should trigger font size reduction."""
    result = build_appearance_stream(
        width=200,
        height=25,  # very short — forces font reduction
        fields=["This Is A Very Long Name That Needs Wrapping", "Detail 1", "Detail 2"],
    )
    assert isinstance(result["stream"], bytes)
    assert len(result["stream"]) > 0


def test_build_no_detail_fields():
    """Stream with only name field and no details should work."""
    result = build_appearance_stream(
        width=200,
        height=25,
        fields=["Alice"],
    )
    stream = result["stream"].decode("ascii")
    assert encode_text_hex("Alice") in stream


# ── Image loading — validation ────────────────────────────────────────


def test_load_signature_image_not_found():
    """Missing file should raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_signature_image("/nonexistent/path/sig.png")


@requires_pillow
def test_load_signature_image_empty_file(tmp_path):
    """Empty file should raise ValueError."""
    img_path = tmp_path / "empty.png"
    img_path.write_bytes(b"")

    with pytest.raises(ValueError, match="empty"):
        load_signature_image(str(img_path))


@requires_pillow
def test_load_signature_image_too_large(tmp_path):
    """File larger than 5 MB should raise ValueError."""
    img_path = tmp_path / "huge.png"
    img_path.write_bytes(b"\x00" * (6 * 1024 * 1024))

    with pytest.raises(ValueError, match="too large"):
        load_signature_image(str(img_path))


@requires_pillow
def test_load_signature_image_unsupported_format(tmp_path):
    """Unsupported image format should raise ValueError."""
    # Create a valid PPM image (not in _ALLOWED_FORMATS)
    img = Image.new("RGB", (10, 10), color=(255, 0, 0))
    img_path = tmp_path / "sig.ppm"
    img.save(str(img_path), format="PPM")

    with pytest.raises(ValueError, match="Unsupported image format"):
        load_signature_image(str(img_path))


@requires_pillow
def test_load_signature_image_grayscale(tmp_path):
    """Grayscale (mode 'L') image should be converted to RGB."""
    img = Image.new("L", (50, 50), color=128)
    img_path = tmp_path / "gray.png"
    img.save(str(img_path))

    data = load_signature_image(str(img_path))
    assert data["width"] == 50
    assert data["height"] == 50
    assert data["smask"] is None  # no alpha
    assert len(data["samples"]) > 0


@requires_pillow
def test_load_signature_image_la_mode(tmp_path):
    """LA (luminance + alpha) mode should extract smask and convert to RGB."""
    img = Image.new("LA", (30, 30), color=(128, 64))
    img_path = tmp_path / "la.png"
    img.save(str(img_path))

    data = load_signature_image(str(img_path))
    assert data["smask"] is not None
    assert data["width"] == 30


def test_load_signature_image_no_pillow(tmp_path):
    """Should raise ImportError when Pillow is not installed."""
    import builtins
    from unittest.mock import patch

    img_path = tmp_path / "test.png"
    img_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "PIL":
            raise ImportError("mocked: no Pillow")
        return real_import(name, *args, **kwargs)

    with (
        patch("builtins.__import__", side_effect=mock_import),
        pytest.raises(ImportError, match="Pillow is required"),
    ):
        load_signature_image(str(img_path))


# ── build_appearance_stream — embedded font ──────────────────────────


def test_build_armenian_fields():
    """Armenian text should use embedded font."""
    result = build_appearance_stream(
        width=200,
        height=70,
        fields=["\u0540\u0561\u0575\u0565\u0580\u0565\u0576"],
    )
    assert result["resources"]["base_font"] == "NotoSans"
    # Stream should contain hex string format
    stream = result["stream"].decode("ascii")
    assert "<" in stream
    assert ">" in stream


def test_build_mixed_latin_armenian():
    """Mixed Latin+Armenian should work with embedded font."""
    result = build_appearance_stream(
        width=200,
        height=70,
        fields=["Hello", "\u0540\u0561\u0575"],
    )
    # Both fields should be in the stream
    assert len(result["stream"]) > 0


def test_build_stream_is_ascii():
    """Embedded font streams should be pure ASCII (hex strings)."""
    result = build_appearance_stream(
        width=200,
        height=70,
        fields=["\u0540\u0561\u0575\u0565\u0580\u0565\u0576"],
    )
    # Should not raise — hex strings are pure ASCII
    result["stream"].decode("ascii")


# ── Font registry ─────────────────────────────────────────────────────


def test_available_fonts_tuple():
    """AVAILABLE_FONTS should be a non-empty tuple of strings."""
    assert isinstance(AVAILABLE_FONTS, tuple)
    assert len(AVAILABLE_FONTS) >= 2
    assert "noto-sans" in AVAILABLE_FONTS
    assert "ghea-grapalat" in AVAILABLE_FONTS


def test_default_font():
    assert DEFAULT_FONT == "noto-sans"


def test_get_font_default():
    """get_font() with no args should return default font."""
    f = get_font()
    assert f.name == "NotoSans"
    assert isinstance(f.metrics, FontMetrics)


def test_get_font_noto_sans():
    f = get_font("noto-sans")
    assert f.name == "NotoSans"
    assert f.metrics.units_per_em > 0
    assert len(f.metrics.cmap) > 0
    assert len(f.metrics.widths) > 0


def test_get_font_ghea_grapalat():
    f = get_font("ghea-grapalat")
    assert f.name == "GHEAGrapalat"
    assert f.metrics.units_per_em > 0
    assert len(f.metrics.cmap) > 0


def test_get_font_unknown():
    with pytest.raises(ValueError, match="Unknown font"):
        get_font("nonexistent-font")


def test_get_font_caching():
    """Same font key should return the same instance (cached)."""
    f1 = get_font("noto-sans")
    f2 = get_font("noto-sans")
    assert f1 is f2


def test_font_text_width():
    """Each font's text_width should return positive values for non-empty text."""
    for key in ("noto-sans", "ghea-grapalat"):
        f = get_font(key)
        w = f.text_width("Hello", 12)
        assert w > 0, f"{key}: text_width should be positive"


def test_font_pdf_escape():
    """Each font's pdf_escape should return hex-formatted strings."""
    for key in ("noto-sans", "ghea-grapalat"):
        f = get_font(key)
        result = f.pdf_escape("AB")
        assert result.startswith("<")
        assert result.endswith(">")


def test_font_metrics_ttf_resource():
    """FontMetrics should reference the correct TTF resource."""
    noto = get_font("noto-sans")
    assert noto.metrics.ttf_resource == "NotoSans-Subset.ttf"

    ghea = get_font("ghea-grapalat")
    assert ghea.metrics.ttf_resource == "GHEAGrapalat-Subset.ttf"


# ── build_appearance_stream with explicit font ────────────────────────


def test_build_with_ghea_grapalat_font():
    """Appearance stream with GHEA Grapalat should use that font's name."""
    f = get_font("ghea-grapalat")
    result = build_appearance_stream(
        width=200,
        height=70,
        fields=["Test User"],
        font=f,
    )
    assert result["resources"]["base_font"] == "GHEAGrapalat"


def test_build_with_noto_font():
    """Appearance stream with explicit Noto Sans should use NotoSans."""
    f = get_font("noto-sans")
    result = build_appearance_stream(
        width=200,
        height=70,
        fields=["Test User"],
        font=f,
    )
    assert result["resources"]["base_font"] == "NotoSans"


def test_optimal_width_with_font():
    """compute_optimal_width with a Font param should not raise."""
    f = get_font("ghea-grapalat")
    w = compute_optimal_width(["Test"], 70, font=f)
    assert 150.0 <= w <= 300.0


def test_optimal_height_with_font():
    """compute_optimal_height with a Font param should not raise."""
    f = get_font("ghea-grapalat")
    h = compute_optimal_height(["Test", "Detail"], 200, font=f)
    assert 40.0 <= h <= 120.0
