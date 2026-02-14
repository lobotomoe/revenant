"""
Visual appearance stream for PDF signature fields.

Generates the /AP /N content stream that Adobe Acrobat (and other readers)
display inside the signature widget rectangle.

Layout uses a stacked design — all fields are rendered vertically:

Without image:
  +----------------------------------------------+
  |  Signer Name                                 |
  |  3105951040                                  |
  |  Date: 7 Feb 2026, 09:51:42 UTC+4            |
  +----------------------------------------------+

With image — same stack, image on the left:
  +----------------------------------------------+
  |  [signature img]  |  Signer Name             |
  |                   |  3105951040              |
  |                   |  Date: 7 Feb 2026, ...   |
  +----------------------------------------------+

Fields are driven by the profile's ``sig_fields`` configuration.
First field is rendered large (name), rest are rendered smaller (detail).
"""

from __future__ import annotations

import logging
from functools import partial
from typing import TYPE_CHECKING, TypedDict

from .fonts import Font, get_default_font, text_width, wrap_lines

_logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Callable


class _FontResources(TypedDict):
    """Font resources for the appearance stream."""

    font_name: str  # e.g. "F1"
    base_font: str  # e.g. "NotoSans"


class AppearanceData(TypedDict):
    """Data returned by build_appearance."""

    stream: bytes  # Raw content stream for /AP /N
    bbox: tuple[float, float, float, float]  # BBox (x0, y0, x1, y1)
    resources: _FontResources  # Required font resources
    needs_image: bool  # True if stream references /Img1
    bg_opacity: float  # ExtGState /ca value for backdrop (0 = disabled)


# ── Appearance layout constants ────────────────────────────────────────

# Content padding from the border inward (PDF points).
_PAD_H = 8.0  # ~2.8mm each side
_PAD_V = 4.0  # ~1.4mm top/bottom

# Image column ratio (when has_image=True)
_IMAGE_COLUMN_RATIO = 0.40
_COLUMN_GAP = 4.0

# Name font sizing (fields[0])
_NAME_MAX_FONT_SIZE = 14.0
_NAME_MIN_FONT_SIZE = 5.0
_NAME_FONT_STEP = 0.5

# Detail text font sizing (fields[1:])
_DETAIL_MAX_FONT_SIZE = 8.0
_DETAIL_MIN_FONT_SIZE = 4.0
_DETAIL_FONT_STEP = 0.5
_DETAIL_HEIGHT_DIVISOR = 7.5
_DETAIL_COLOR = 0.35  # dark gray for detail fields

# Name-to-detail gap: ratio of name font size used as vertical gap
_NAME_DETAIL_GAP_RATIO = 1.0

# Name font takes at most 1/3 of content height
_NAME_HEIGHT_DIVISOR = 3.0

# Small horizontal margin added to widest text measurement
_TEXT_WIDTH_MARGIN = 4.0

# Line spacing multiplier
_LINE_LEADING = 1.4

# Border styling
_BORDER_COLOR = 0.70
_BORDER_WIDTH = 0.75

# Near-opaque backdrop behind signature content.
# Covers underlying page text/images so the signature is readable.
# Light gray tint so the field boundary is visible on white pages.
_BG_OPACITY = 0.90
_BG_COLOR = 0.97  # near-white with a hint of gray

# Adaptive size bounds
_MIN_SIG_WIDTH = 150.0
_MAX_SIG_WIDTH = 300.0
_MIN_SIG_HEIGHT = 40.0
_MAX_SIG_HEIGHT = 120.0


def _wrap_lines_with(font: Font | None) -> Callable[[str, float, float], list[str]]:
    """Return a wrap_lines function using the given font, or the default."""
    if font is None:
        return wrap_lines
    return partial(wrap_lines, measure=font.text_width)


# ── Layout computation ────────────────────────────────────────────────


def compute_optimal_width(
    fields: list[str],
    height: float,
    has_image: bool = False,
    font: Font | None = None,
) -> float:
    """Compute optimal signature field width so the first field fits on one line.

    Args:
        fields: Ordered display strings (first = name, rest = details).
        height: Signature field height in PDF points.
        has_image: If True, accounts for image column on the left.
        font: Font to measure with. If None, uses the default font.

    Returns:
        Optimal width in PDF points, clamped to [_MIN_SIG_WIDTH, _MAX_SIG_WIDTH].
    """
    if not fields:
        return _MIN_SIG_WIDTH

    tw = font.text_width if font else text_width

    content_h = height - 2 * _PAD_V
    name_font = min(_NAME_MAX_FONT_SIZE, content_h / _NAME_HEIGHT_DIVISOR)
    detail_font = min(_DETAIL_MAX_FONT_SIZE, content_h / _DETAIL_HEIGHT_DIVISOR)

    # Widest field determines text width
    widest = tw(fields[0], name_font)
    for field in fields[1:]:
        widest = max(widest, tw(field, detail_font))

    text_w = widest + _TEXT_WIDTH_MARGIN

    if has_image:
        # Image takes _IMAGE_COLUMN_RATIO of total content, text gets the rest.
        # Derived from: text_w equals content_w * (1 - ratio) minus gap,
        # so content_w equals (text_w + gap) / (1 - ratio).
        content_w = (text_w + _COLUMN_GAP) / (1 - _IMAGE_COLUMN_RATIO)
    else:
        content_w = text_w

    total_w = content_w + 2 * _PAD_H
    return max(_MIN_SIG_WIDTH, min(_MAX_SIG_WIDTH, total_w))


def compute_optimal_height(
    fields: list[str],
    width: float,
    has_image: bool = False,
    font: Font | None = None,
) -> float:
    """Compute optimal signature field height to fit all fields without cramming.

    Args:
        fields: Ordered display strings (first = name, rest = details).
        width: Signature field width in PDF points.
        has_image: If True, accounts for image column on the left.
        font: Font to measure with. If None, uses the default font.

    Returns:
        Optimal height in PDF points, clamped to [_MIN_SIG_HEIGHT, _MAX_SIG_HEIGHT].
    """
    if not fields:
        return _MIN_SIG_HEIGHT

    wl = _wrap_lines_with(font)

    # Compute text area width
    content_w = width - 2 * _PAD_H
    if has_image:
        img_w = content_w * _IMAGE_COLUMN_RATIO
        text_w = content_w - img_w - _COLUMN_GAP
    else:
        text_w = content_w

    # Use max font sizes for height estimation
    name_font = _NAME_MAX_FONT_SIZE
    detail_font = _DETAIL_MAX_FONT_SIZE

    name_text = fields[0]
    detail_texts = fields[1:]

    # Wrap all text at this width to count actual lines
    name_lines = wl(name_text, name_font, text_w)
    name_leading = name_font * _LINE_LEADING
    detail_leading = detail_font * _LINE_LEADING
    total_detail_lines = sum(len(wl(d, detail_font, text_w)) for d in detail_texts)

    name_section_h = len(name_lines) * name_leading
    name_detail_gap = name_font * _NAME_DETAIL_GAP_RATIO if detail_texts else 0
    detail_section_h = total_detail_lines * detail_leading

    content_h = name_section_h + name_detail_gap + detail_section_h
    total_h = content_h + 2 * _PAD_V

    return max(_MIN_SIG_HEIGHT, min(_MAX_SIG_HEIGHT, total_h))


# ── Appearance stream builder ─────────────────────────────────────────


def build_appearance_stream(
    width: float,
    height: float,
    fields: list[str],
    has_image: bool = False,
    font: Font | None = None,
    image_aspect: float | None = None,
) -> AppearanceData:
    """
    Build a PDF appearance stream (/AP /N) for a signature field.

    Uses a stacked layout — all fields rendered top-to-bottom.
    fields[0] is the "name" (large font, black).
    fields[1:] are "detail" fields (smaller font, gray).
    When has_image is True, an image column is added on the left.

    Args:
        width: Annotation rectangle width in PDF points.
        height: Annotation rectangle height in PDF points.
        fields: Ordered display strings. First = name, rest = details.
        has_image: If True, references /Img1 XObject on the left column.
        font: Font to render with. If None, uses the default font.
        image_aspect: Image width/height ratio for aspect-ratio-correct
            scaling. If None, the image stretches to fill the column.

    Returns:
        dict with keys:
            'stream': bytes -- the raw content stream for /AP /N
            'bbox': (x0, y0, x1, y1) -- BBox for the form XObject
            'resources': dict describing required font resources
            'needs_image': bool -- True if the stream references /Img1
    """
    f = font or get_default_font()
    pe = f.pdf_escape
    wl = _wrap_lines_with(f)

    # ── Layout geometry ──────────────────────────────────────────
    bw = _BORDER_WIDTH
    half_bw = bw / 2

    content_x = _PAD_H
    content_y = _PAD_V
    content_w = width - 2 * _PAD_H
    content_h = height - 2 * _PAD_V

    # Text area — full width or right portion if image is present
    img_w = 0.0
    if has_image:
        img_w = content_w * _IMAGE_COLUMN_RATIO
        text_x = content_x + img_w + _COLUMN_GAP
        text_w = content_w - img_w - _COLUMN_GAP
    else:
        text_x = content_x
        text_w = content_w

    # ── Font sizing ──────────────────────────────────────────────
    name_font = min(_NAME_MAX_FONT_SIZE, content_h / _NAME_HEIGHT_DIVISOR)
    detail_font = min(_DETAIL_MAX_FONT_SIZE, content_h / _DETAIL_HEIGHT_DIVISOR)

    # fields[0] = name (large), fields[1:] = details (small)
    name_text = fields[0] if fields else ""
    detail_texts = fields[1:] if len(fields) > 1 else []

    # Wrap name and compute total height; shrink if needed
    name_lines = wl(name_text, name_font, text_w) if name_text else []
    name_leading = name_font * _LINE_LEADING
    detail_leading = detail_font * _LINE_LEADING

    def _total_height() -> float:
        n_detail = sum(len(wl(d, detail_font, text_w)) for d in detail_texts)
        name_h = len(name_lines) * name_leading
        detail_h = n_detail * detail_leading
        gap = name_font * _NAME_DETAIL_GAP_RATIO if detail_texts else 0
        return name_h + gap + detail_h

    # Phase 1: shrink name font
    while name_font > _NAME_MIN_FONT_SIZE and name_lines:
        if _total_height() <= content_h:
            break
        name_font -= _NAME_FONT_STEP
        name_lines = wl(name_text, name_font, text_w)
        name_leading = name_font * _LINE_LEADING

    # Phase 2: shrink detail font if name is already at minimum
    while detail_font > _DETAIL_MIN_FONT_SIZE and detail_texts:
        if _total_height() <= content_h:
            break
        detail_font -= _DETAIL_FONT_STEP
        detail_leading = detail_font * _LINE_LEADING

    if _total_height() > content_h:
        _logger.warning(
            "Signature text (%.1f pt) exceeds field height (%.1f pt) "
            "at minimum font sizes (name=%.1f, detail=%.1f). "
            "Content will be clipped.",
            _total_height(),
            content_h,
            name_font,
            detail_font,
        )

    # ── Vertical centering offset ────────────────────────────────
    # Span from top of first glyph to last baseline:
    #   name_font (ascender of first line),
    #   plus (name_lines - 1) * name_leading (subsequent name baselines),
    #   plus name_gap and (total_detail_lines - 1) * detail_leading.
    total_detail_lines = sum(len(wl(d, detail_font, text_w)) for d in detail_texts)
    name_detail_gap = name_font * _NAME_DETAIL_GAP_RATIO if detail_texts else 0
    text_span = name_font + (len(name_lines) - 1) * name_leading
    if total_detail_lines > 0:
        text_span += name_detail_gap + (total_detail_lines - 1) * detail_leading
    v_offset = max(0, (content_h - text_span) / 2)

    # ── Build PDF content stream ─────────────────────────────────
    ops: list[str] = []

    # 0. Semi-transparent white backdrop
    ops.append("q")
    ops.append("/GS1 gs")
    ops.append(f"{_BG_COLOR} g")
    ops.append(f"0 0 {width:.2f} {height:.2f} re")
    ops.append("f")
    ops.append("Q")

    # 1. Border rectangle
    border_rgb = f"{_BORDER_COLOR} {_BORDER_COLOR} {_BORDER_COLOR}"
    ops.append("q")
    ops.append(f"{border_rgb} RG")
    ops.append(f"{bw} w")
    ops.append(f"{half_bw:.2f} {half_bw:.2f} {width - bw:.2f} {height - bw:.2f} re")
    ops.append("S")
    ops.append("Q")

    # 2. Image (if present) — fit within column, preserve aspect ratio
    if has_image:
        draw_w = img_w
        draw_h = content_h
        if image_aspect is not None and image_aspect > 0:
            space_aspect = img_w / content_h if content_h > 0 else 1.0
            if image_aspect > space_aspect:
                # Image wider than space -> fit to width
                draw_h = img_w / image_aspect
            else:
                # Image taller than space -> fit to height
                draw_w = content_h * image_aspect
        # Center within the image column
        draw_x = content_x + (img_w - draw_w) / 2
        draw_y = content_y + (content_h - draw_h) / 2
        ops.append("q")
        ops.append(f"{draw_w:.2f} 0 0 {draw_h:.2f} {draw_x:.2f} {draw_y:.2f} cm")
        ops.append("/Img1 Do")
        ops.append("Q")

    # 3. Text stack — clip to text area
    ops.append("q")
    ops.append(f"{text_x:.2f} {content_y:.2f} {text_w:.2f} {content_h:.2f} re W n")
    ops.append("BT")
    ops.append("0 Tc 0 Tw")

    # Name field (fields[0]) — large, black
    cursor_y = content_y + content_h - name_font - v_offset
    ops.append("0 g")
    ops.append(f"/F1 {name_font:.3f} Tf")
    ops.append(f"{text_x:.2f} {cursor_y:.2f} Td")
    for i, line in enumerate(name_lines):
        if i > 0:
            ops.append(f"0 {-name_leading:.2f} Td")
        ops.append(f"{pe(line)} Tj")

    # Detail fields (fields[1:]) — smaller, gray
    if detail_texts:
        # Gap between name baseline and first detail baseline.
        # Visual gap = name_gap - (name descent + detail ascent).
        # Use 0.5 * name_font for comfortable breathing room.
        name_gap = name_font * _NAME_DETAIL_GAP_RATIO
        ops.append(f"0 {-name_gap:.2f} Td")
        ops.append(f"{_DETAIL_COLOR} g")
        ops.append(f"/F1 {detail_font:.3f} Tf")

        for idx, detail in enumerate(detail_texts):
            detail_lines = wl(detail, detail_font, text_w)
            for i, line in enumerate(detail_lines):
                if i > 0 or idx > 0:
                    ops.append(f"0 {-detail_leading:.2f} Td")
                ops.append(f"{pe(line)} Tj")

    ops.append("ET")
    ops.append("Q")

    stream_str = "\n".join(ops)
    stream_bytes = stream_str.encode("ascii")

    return {
        "stream": stream_bytes,
        "bbox": (0, 0, width, height),
        "resources": {
            "font_name": "F1",
            "base_font": f.name,
        },
        "needs_image": has_image,
        "bg_opacity": _BG_OPACITY,
    }
