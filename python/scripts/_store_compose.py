"""Store image composition for the screenshot gallery.

Composes raw window screenshots into store-ready images:
background + drop shadow + window + title text.

Not a standalone script -- imported by screenshot_gallery.py.
"""

# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false
from __future__ import annotations

import logging
import platform
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PIL.ImageFont import FreeTypeFont

_logger = logging.getLogger(__name__)

# ── Design reference (from Figma at 2880x1800) ──────────────────────

_REF_HEIGHT = 1800
_REF_TITLE_SIZE = 92
_REF_SHADOW_BLUR = 4
_REF_SHADOW_OFFSET_Y = 4
_SHADOW_ALPHA = 64  # 25% of 255

_MAX_WINDOW_W_RATIO = 0.72
_MAX_WINDOW_H_RATIO = 0.58
_WINDOW_TOP_RATIO = 0.38
_TITLE_GAP_PX = 40  # gap between title bottom and window top (at ref height)

# Title text shadow
_TITLE_SHADOW_OFFSET = 2
_TITLE_SHADOW_ALPHA = 80  # ~31% opacity

# ── Per-platform canvas sizes ────────────────────────────────────────

CANVAS_SIZES: dict[str, tuple[int, int]] = {
    "Darwin": (2880, 1800),   # Mac App Store (Retina 2.5x, exact)
    "Windows": (1920, 1080),  # Microsoft Store (min 1366x768, max 4K)
    "Linux": (1920, 1080),    # Snap Store recommended
}


def canvas_size() -> tuple[int, int]:
    """Return (width, height) for the current platform."""
    return CANVAS_SIZES.get(platform.system(), (1920, 1080))


# ── Font loading ─────────────────────────────────────────────────────

_FONT_CANDIDATES: dict[str, list[tuple[str, int]]] = {
    "Darwin": [
        ("/System/Library/Fonts/Helvetica.ttc", 1),  # Helvetica Bold
        ("/System/Library/Fonts/Supplemental/Arial Bold.ttf", 0),
    ],
    "Windows": [
        (r"C:\Windows\Fonts\arialbd.ttf", 0),
        (r"C:\Windows\Fonts\calibrib.ttf", 0),
    ],
    "Linux": [
        ("/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf", 0),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 0),
        ("/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf", 0),
    ],
}

_BUNDLED_FONT = (
    Path(__file__).parent.parent
    / "src/revenant/core/appearance/font_data/noto_sans/NotoSans-Subset.ttf"
)


def load_title_font(height: int) -> FreeTypeFont:
    """Load a bold sans-serif font, sized proportionally to *height*."""
    from PIL import ImageFont

    size = max(int(_REF_TITLE_SIZE * height / _REF_HEIGHT), 20)
    system = platform.system()

    for path, index in _FONT_CANDIDATES.get(system, []):
        if Path(path).exists():
            _logger.info("Title font: %s (index %d, %dpx)", path, index, size)
            return ImageFont.truetype(path, size, index=index)

    if _BUNDLED_FONT.exists():
        _logger.warning("Bold font not found, using bundled NotoSans-Subset")
        return ImageFont.truetype(str(_BUNDLED_FONT), size)

    _logger.warning("No font found, using Pillow default")
    return ImageFont.load_default(size=size)  # pyright: ignore[reportReturnType]


# ── Composition ──────────────────────────────────────────────────────


def compose(
    background: Path,
    window_path: Path,
    title: str,
    output: Path,
    size: tuple[int, int] | None = None,
    *,
    overlay_path: Path | None = None,
) -> None:
    """Compose a store-ready screenshot.

    Args:
        background: Path to background image (e.g. bg.png).
        window_path: Path to the main window screenshot.
        title: Title text rendered above the window.
        output: Where to save the result.
        size: Canvas (width, height). Defaults to platform size.
        overlay_path: Optional dialog screenshot to layer on top of the window.
    """
    from PIL import Image, ImageDraw, ImageFilter

    cw, ch = size or canvas_size()
    scale = ch / _REF_HEIGHT

    # Background: scale to fill canvas
    bg = Image.open(background).resize((cw, ch), Image.Resampling.LANCZOS).convert("RGBA")

    # Load main window
    window = Image.open(window_path).convert("RGBA")

    # If there's an overlay (dialog), composite it onto the window first
    if overlay_path is not None:
        overlay = Image.open(overlay_path).convert("RGBA")
        combined_w = max(window.width, overlay.width + 40)
        combined_h = max(window.height + 20, overlay.height + 60)
        combined = Image.new("RGBA", (combined_w, combined_h), (0, 0, 0, 0))
        # Main window in background
        wx_off = (combined_w - window.width) // 2
        combined.paste(window, (wx_off, 0))
        # Dialog centered on top
        ox = (combined_w - overlay.width) // 2
        oy = (combined_h - overlay.height) // 2
        combined.paste(overlay, (ox, oy), overlay)
        window = combined

    # Scale window to fit canvas
    max_w = int(cw * _MAX_WINDOW_W_RATIO)
    max_h = int(ch * _MAX_WINDOW_H_RATIO)
    ratio = min(max_w / window.width, max_h / window.height, 1.0)
    if ratio < 1.0:
        new_size = (int(window.width * ratio), int(window.height * ratio))
        window = window.resize(new_size, Image.Resampling.LANCZOS)

    # Position window
    wx = (cw - window.width) // 2
    wy = int(ch * _WINDOW_TOP_RATIO)

    # Drop shadow -- skip if image already has native shadow (macOS screencapture -l)
    has_native_shadow = window.mode == "RGBA" and window.split()[-1].getextrema()[0] == 0
    if not has_native_shadow:
        blur = max(int(_REF_SHADOW_BLUR * scale), 1)
        offset_y = max(int(_REF_SHADOW_OFFSET_Y * scale), 1)
        pad = blur * 4
        shadow = Image.new("RGBA", (window.width + pad * 2, window.height + pad * 2), (0, 0, 0, 0))
        shadow_fill = Image.new("RGBA", window.size, (0, 0, 0, _SHADOW_ALPHA))
        shadow.paste(shadow_fill, (pad, pad))
        shadow = shadow.filter(ImageFilter.GaussianBlur(radius=blur))
        bg.paste(shadow, (wx - pad, wy + offset_y - pad), shadow)

    # Window
    bg.paste(window, (wx, wy), window)

    # Title text with drop shadow
    font = load_title_font(ch)
    draw = ImageDraw.Draw(bg)
    bbox = draw.textbbox((0, 0), title, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]
    gap = int(_TITLE_GAP_PX * scale)
    tx = (cw - text_w) // 2
    ty = wy - text_h - gap
    ty = max(ty, gap)
    shadow_off = max(int(_TITLE_SHADOW_OFFSET * scale), 1)
    draw.text(
        (tx + shadow_off, ty + shadow_off), title, font=font, fill=(0, 0, 0, _TITLE_SHADOW_ALPHA)
    )
    draw.text((tx, ty), title, font=font, fill=(255, 255, 255, 255))

    output.parent.mkdir(parents=True, exist_ok=True)
    bg.convert("RGB").save(str(output), quality=95)
    _logger.info("  store: %s (%dx%d)", output.name, cw, ch)
