"""
Signature field positioning and page geometry helpers.

Computes where to place the signature rectangle on a PDF page,
given a preset name ("bottom-right", "br", etc.) or explicit coordinates.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...errors import PDFError

if TYPE_CHECKING:
    import pikepdf

# ── Signature position presets ────────────────────────────────────────

# Default signature field size in PDF points (3:1 aspect ratio, ~75x25 mm)
SIG_WIDTH = 210
SIG_HEIGHT = 70
SIG_MARGIN_H = 36  # horizontal margin from left/right edge (~13 mm)
SIG_MARGIN_V = 60  # vertical margin from top/bottom edge (~21 mm)

# Full names -> short aliases
POSITION_ALIASES = {
    "br": "bottom-right",
    "tr": "top-right",
    "bl": "bottom-left",
    "tl": "top-left",
    "bc": "bottom-center",
}

POSITION_PRESETS = {
    "bottom-right",
    "top-right",
    "bottom-left",
    "top-left",
    "bottom-center",
}


def resolve_position(position_name: str) -> str:
    """Normalize a position name, resolving aliases.

    >>> resolve_position("br")
    'bottom-right'
    >>> resolve_position("bottom-right")
    'bottom-right'

    Raises RevenantError for unknown positions.
    """
    name = position_name.lower().strip()
    name = POSITION_ALIASES.get(name, name)
    if name not in POSITION_PRESETS:
        valid = sorted(POSITION_PRESETS) + sorted(POSITION_ALIASES)
        raise PDFError(f"Unknown position {position_name!r}. Valid: {', '.join(valid)}")
    return name


def parse_page_spec(page_str: str) -> str | int:
    """Convert user-facing page specifier to internal format.

    Accepts "first", "last" (returned as-is), or 1-based page numbers
    (returned as 0-based integers).

    Args:
        page_str: User input -- "first", "last", or a 1-based number string.

    Returns:
        str ("first" or "last") or int (0-based page index).

    Raises:
        RevenantError: If the page specifier is invalid.
    """
    spec = page_str.strip().lower()
    if spec in ("first", "last"):
        return spec
    try:
        page_num = int(spec)
    except ValueError as exc:
        raise PDFError(
            f"Invalid page: {page_str!r}. Use 'first', 'last', or a page number."
        ) from exc
    if page_num < 1:
        raise PDFError(f"Page number must be 1 or greater, got {page_num}")
    return page_num - 1


def compute_sig_rect(
    page_width: float,
    page_height: float,
    position: str = "bottom-right",
    sig_w: float = SIG_WIDTH,
    sig_h: float = SIG_HEIGHT,
    margin_h: float = SIG_MARGIN_H,
    margin_v: float = SIG_MARGIN_V,
) -> tuple[float, float, float, float]:
    """Compute (x, y) for a signature field given page dimensions and a preset.

    Args:
        page_width: Page width in PDF points.
        page_height: Page height in PDF points.
        position: One of the preset names or aliases.
        sig_w: Signature field width.
        sig_h: Signature field height.
        margin_h: Horizontal margin from left/right edge.
        margin_v: Vertical margin from top/bottom edge.

    Returns:
        (x, y, sig_w, sig_h) tuple in PDF coordinate space (origin = bottom-left).

    Raises:
        RevenantError: If page dimensions or signature parameters are invalid.
    """
    if page_width <= 0 or page_height <= 0:
        raise PDFError(f"Invalid page dimensions: {page_width:.1f} x {page_height:.1f} pt")
    if sig_w <= 0 or sig_h <= 0:
        raise PDFError(f"Invalid signature dimensions: {sig_w:.1f} x {sig_h:.1f} pt")

    position = resolve_position(position)

    if "right" in position:
        x = page_width - margin_h - sig_w
    elif "left" in position:
        x = margin_h
    else:  # center
        x = (page_width - sig_w) / 2.0

    if "bottom" in position:
        y = margin_v
    else:  # top
        y = page_height - margin_v - sig_h

    if x < 0 or y < 0:
        raise PDFError(
            f"Signature does not fit on page: computed position ({x:.1f}, {y:.1f}) is negative. "
            f"Page: {page_width:.0f}x{page_height:.0f} pt, "
            f"signature: {sig_w:.0f}x{sig_h:.0f} pt, "
            f"margins: {margin_h:.0f}x{margin_v:.0f} pt"
        )

    return x, y, sig_w, sig_h


def get_page_dimensions(pdf: pikepdf.Pdf, page_index: int) -> tuple[float, float]:
    """Get effective (width, height) for a page, respecting CropBox and Rotate.

    Args:
        pdf: An open pikepdf.Pdf object.
        page_index: 0-based page index.

    Returns:
        (width, height) in PDF points.
    """
    page = pdf.pages[page_index]

    # CropBox takes priority over MediaBox for visible area
    crop_box = page.get("/CropBox")
    box = crop_box if crop_box is not None else page.MediaBox
    # pikepdf Array supports indexing; extract 4 values explicitly
    x0, y0, x1, y1 = float(box[0]), float(box[1]), float(box[2]), float(box[3])
    w = abs(x1 - x0)
    h = abs(y1 - y0)

    # /Rotate is clockwise degrees; 90 and 270 swap width/height
    rotate_val = page.get("/Rotate")
    rotate = (int(rotate_val) if rotate_val is not None else 0) % 360
    if rotate in (90, 270):
        w, h = h, w

    return w, h


def resolve_page_index(pdf: pikepdf.Pdf, page_spec: int | str) -> int:
    """Convert a page specifier to a 0-based index.

    Args:
        pdf: An open pikepdf.Pdf object.
        page_spec: "last", "first", or a 0-based integer / string.

    Returns:
        int -- validated 0-based page index.

    Raises:
        RevenantError on invalid page.
    """
    total = len(pdf.pages)

    if isinstance(page_spec, str):
        spec = page_spec.strip().lower()
        if spec == "last":
            return total - 1
        if spec == "first":
            return 0
        try:
            page_spec = int(spec)
        except ValueError as exc:
            raise PDFError(
                f"Invalid page: {page_spec!r}. Use 'first', 'last', or a 0-based number."
            ) from exc

    idx = int(page_spec)
    if idx < 0 or idx >= total:
        raise PDFError(f"Page {idx} out of range (PDF has {total} page(s), 0-based).")
    return idx
