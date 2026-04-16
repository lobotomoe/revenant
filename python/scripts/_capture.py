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

    # Tight visible bounds (excludes invisible resize borders)
    rect = wintypes.RECT()
    hr = dwmapi.DwmGetWindowAttribute(
        hwnd, DWMWA_EXTENDED_FRAME_BOUNDS, ctypes.byref(rect), ctypes.sizeof(rect)
    )
    if hr != 0:
        user32.GetWindowRect(hwnd, ctypes.byref(rect))

    width = rect.right - rect.left
    height = rect.bottom - rect.top

    hwnd_dc = user32.GetWindowDC(hwnd)
    mem_dc = gdi32.CreateCompatibleDC(hwnd_dc)
    bitmap = gdi32.CreateCompatibleBitmap(hwnd_dc, width, height)
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
    bmi.biWidth = width
    bmi.biHeight = -height  # top-down
    bmi.biPlanes = 1
    bmi.biBitCount = 32

    buf = ctypes.create_string_buffer(width * height * 4)
    gdi32.GetDIBits(mem_dc, bitmap, 0, height, buf, ctypes.byref(bmi), 0)

    gdi32.SelectObject(mem_dc, old)
    gdi32.DeleteObject(bitmap)
    gdi32.DeleteDC(mem_dc)
    user32.ReleaseDC(hwnd, hwnd_dc)

    img = Image.frombuffer("RGBA", (width, height), bytes(buf), "raw", "BGRA", 0, 1)

    # Trim DWM 1px borders (rendered as black by PrintWindow)
    img = img.crop((1, 0, img.width, img.height - 1))

    img.convert("RGB").save(str(output))


# ── Linux ────────────────────────────────────────────────────────────


def _imagegrab(window: tk.Tk | tk.Toplevel, output: Path) -> None:
    """Pillow ImageGrab with full frame bbox (Xvfb)."""
    from PIL import ImageGrab

    x, y, w, h = _frame_bbox(window)
    img = ImageGrab.grab(bbox=(x, y, x + w, y + h))
    img.save(str(output))
