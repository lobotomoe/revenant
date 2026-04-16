"""Platform-specific window capture for the screenshot gallery.

macOS: native ``screencapture -l`` via Quartz CGWindowID (rounded corners,
native shadow preserved in alpha), region capture fallback.

Windows: ``PrintWindow`` + ``PW_RENDERFULLCONTENT`` via ctypes (title bar,
DWM content; no extra deps). Tight visible bounds from
``DwmGetWindowAttribute(DWMWA_EXTENDED_FRAME_BOUNDS)``.

Linux: Pillow ``ImageGrab`` (Xvfb provides the display).
"""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
from __future__ import annotations

import logging
import platform
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tkinter as tk
    from pathlib import Path

_logger = logging.getLogger(__name__)

_CAPTURE_SETTLE_MS = 200


def capture(window: tk.Tk | tk.Toplevel, output: Path, *, dry_run: bool = False) -> None:
    """Capture a tkinter window screenshot using the best platform method."""
    window.after(_CAPTURE_SETTLE_MS, window.quit)
    window.mainloop()

    w = window.winfo_width()
    h = window.winfo_height()

    if dry_run:
        _logger.info("  [dry-run] %s (%dx%d)", output.name, w, h)
        return

    output.parent.mkdir(parents=True, exist_ok=True)

    system = platform.system()
    if system == "Darwin":
        _macos(window, output)
    elif system == "Windows":
        _windows(window, output)
    else:
        _imagegrab(window, output)

    _logger.info("  captured: %s (%dx%d)", output.name, w, h)


# ── macOS ────────────────────────────────────────────────────────────


def _cg_window_id(title: str) -> int | None:
    """Find the CGWindowID matching *title* (requires pyobjc-framework-Quartz)."""
    try:
        import Quartz  # type: ignore[import-not-found]
    except ImportError:
        return None

    windows = Quartz.CGWindowListCopyWindowInfo(
        Quartz.kCGWindowListOptionOnScreenOnly,
        Quartz.kCGNullWindowID,
    )
    if windows is None:
        return None
    for w in windows:
        owner: str = w.get("kCGWindowOwnerName", "")
        name: str = w.get("kCGWindowName", "")
        if owner == "Python" and title and title in name:
            wid: object = w.get("kCGWindowNumber")
            if isinstance(wid, int):
                return wid
    return None


def _frame_bbox(window: tk.Tk | tk.Toplevel) -> tuple[int, int, int, int]:
    """Return (x, y, w, h) of the full window frame including title bar."""
    x = window.winfo_rootx()
    y = window.winfo_y()
    title_bar = window.winfo_rooty() - y
    w = window.winfo_width()
    h = title_bar + window.winfo_height()
    return x, y, w, h


def _macos(window: tk.Tk | tk.Toplevel, output: Path) -> None:
    """Native window capture via screencapture -l, region fallback."""
    wid = _cg_window_id(window.title())
    if wid is not None:
        result = subprocess.run(
            ["screencapture", "-x", "-l", str(wid), str(output)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and output.exists() and output.stat().st_size > 0:
            return

    # Fallback: region capture including title bar
    x, y, w, h = _frame_bbox(window)
    result = subprocess.run(
        ["screencapture", "-x", "-R", f"{x},{y},{w},{h}", str(output)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0 or not output.exists() or output.stat().st_size == 0:
        stderr = result.stderr.strip()
        msg = (
            f"screencapture failed for {output.name}: {stderr}\n"
            "Grant Screen Recording permission to your terminal:\n"
            "  System Settings > Privacy & Security > Screen Recording"
        )
        raise RuntimeError(msg)


# ── Windows ──────────────────────────────────────────────────────────


def _windows(window: tk.Tk | tk.Toplevel, output: Path) -> None:
    """Native capture via PrintWindow + PW_RENDERFULLCONTENT (ctypes)."""
    import ctypes
    from ctypes import wintypes

    from PIL import Image

    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32
    dwmapi = ctypes.windll.dwmapi

    PW_RENDERFULLCONTENT = 0x00000002
    DWMWA_EXTENDED_FRAME_BOUNDS = 9

    hwnd = int(window.wm_frame(), 0)

    # Full window rect (includes invisible DWM resize borders)
    full = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(full))
    full_w = full.right - full.left
    full_h = full.bottom - full.top

    # Visible bounds (tight, excludes invisible resize borders)
    visible = wintypes.RECT()
    hr = dwmapi.DwmGetWindowAttribute(
        hwnd, DWMWA_EXTENDED_FRAME_BOUNDS, ctypes.byref(visible), ctypes.sizeof(visible)
    )
    if hr != 0:
        visible = full

    # Crop offsets: how many pixels of invisible border on each side
    crop_left = visible.left - full.left
    crop_top = visible.top - full.top
    crop_right = full.right - visible.right
    crop_bottom = full.bottom - visible.bottom

    # Capture at FULL size (PrintWindow renders entire window including borders)
    hwnd_dc = user32.GetWindowDC(hwnd)
    mem_dc = gdi32.CreateCompatibleDC(hwnd_dc)
    bitmap = gdi32.CreateCompatibleBitmap(hwnd_dc, full_w, full_h)
    old = gdi32.SelectObject(mem_dc, bitmap)

    user32.PrintWindow(hwnd, mem_dc, PW_RENDERFULLCONTENT)

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [
            ("biSize", wintypes.DWORD),
            ("biWidth", wintypes.LONG),
            ("biHeight", wintypes.LONG),
            ("biPlanes", wintypes.WORD),
            ("biBitCount", wintypes.WORD),
            ("biCompression", wintypes.DWORD),
            ("biSizeImage", wintypes.DWORD),
            ("biXPelsPerMeter", wintypes.LONG),
            ("biYPelsPerMeter", wintypes.LONG),
            ("biClrUsed", wintypes.DWORD),
            ("biClrImportant", wintypes.DWORD),
        ]

    bmi = BITMAPINFOHEADER()
    bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.biWidth = full_w
    bmi.biHeight = -full_h  # top-down
    bmi.biPlanes = 1
    bmi.biBitCount = 32

    buf = ctypes.create_string_buffer(full_w * full_h * 4)
    gdi32.GetDIBits(mem_dc, bitmap, 0, full_h, buf, ctypes.byref(bmi), 0)

    gdi32.SelectObject(mem_dc, old)
    gdi32.DeleteObject(bitmap)
    gdi32.DeleteDC(mem_dc)
    user32.ReleaseDC(hwnd, hwnd_dc)

    img = Image.frombuffer("RGBA", (full_w, full_h), bytes(buf), "raw", "BGRA", 0, 1)

    # Crop to visible bounds (remove invisible DWM resize borders).
    # DWM reports bounds 1px inside the actual border line, so add 1px extra.
    img = img.crop(
        (
            crop_left + 1,
            crop_top,
            full_w - crop_right - 1,
            full_h - crop_bottom - 1,
        )
    )

    img.convert("RGB").save(str(output))


# ── Linux ────────────────────────────────────────────────────────────


def _imagegrab(window: tk.Tk | tk.Toplevel, output: Path) -> None:
    """Pillow ImageGrab with full frame bbox (Xvfb)."""
    from PIL import ImageGrab

    x, y, w, h = _frame_bbox(window)
    img = ImageGrab.grab(bbox=(x, y, x + w, y + h))
    img.save(str(output))
