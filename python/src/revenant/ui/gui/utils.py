"""GUI utility functions for Revenant.

Platform-specific helpers and tkinter availability checks.
Separated from gui.py to keep the main GUI module focused on
application logic.
"""

from __future__ import annotations

import logging
import platform
import subprocess
import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    import tkinter as tk
    from collections.abc import Callable

_T = TypeVar("_T")
_logger = logging.getLogger(__name__)

# Link color: light blue for dark backgrounds, standard blue for light.
# On macOS Aqua, "systemLinkColor" auto-adapts to dark/light mode.
_LINK_COLOR_LIGHT_BG = "#0066CC"
_LINK_COLOR_DARK_BG = "#58A6FF"

# Luminance threshold for distinguishing light/dark backgrounds
_LUMINANCE_DARK_THRESHOLD = 0.5

# Max RGB value in tkinter's winfo_rgb (16-bit per channel)
_RGB_MAX = 65535


def link_color(widget: tk.Widget) -> str:
    """Pick a link foreground color readable on the current background."""
    import tkinter as tk
    from tkinter import ttk

    # macOS: system color adapts to dark/light mode automatically
    try:
        widget.winfo_rgb("systemLinkColor")
    except tk.TclError:
        pass
    else:
        return "systemLinkColor"

    # Fallback: detect background luminance from theme
    try:
        bg = ttk.Style().lookup("TLabel", "background")
        if bg:
            r, g, b = widget.winfo_rgb(bg)
            luminance = (0.299 * r + 0.587 * g + 0.114 * b) / _RGB_MAX
            if luminance < _LUMINANCE_DARK_THRESHOLD:
                return _LINK_COLOR_DARK_BG
    except (tk.TclError, ValueError):
        pass

    return _LINK_COLOR_LIGHT_BG


def enable_dpi_awareness() -> None:
    """Enable system DPI awareness (call BEFORE creating tk.Tk).

    On Windows, the OS defaults to 96 DPI for unaware apps, making
    the UI tiny on HiDPI displays.  This tells Windows to report
    the real monitor DPI so tkinter can scale accordingly.

    No-op on macOS (Tk Aqua is natively Retina-aware) and Linux
    (tkinter on XWayland cannot scale window decorations, so
    adjusting content DPI alone looks disproportionate).
    """
    if platform.system() != "Windows":
        return
    try:
        import ctypes

        # System DPI aware -- good enough for single-monitor setups,
        # and the only mode tkinter can benefit from.
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # pyright: ignore[reportAttributeAccessIssue,reportUnknownMemberType]
    except (AttributeError, OSError):
        try:
            import ctypes

            ctypes.windll.user32.SetProcessDPIAware()  # pyright: ignore[reportAttributeAccessIssue,reportUnknownMemberType]
        except (AttributeError, OSError):
            pass


def check_tkinter() -> tuple[bool, str]:
    """Check if tkinter is available; return (ok, error_message)."""
    try:
        __import__("tkinter")
    except ImportError:
        pass
    else:
        return True, ""

    # Build a helpful install hint based on platform
    system = platform.system()
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"

    if system == "Darwin":
        hint = f"brew install python-tk@{py_ver}"
    elif system == "Linux":
        # Detect distro family
        distro = ""
        try:
            distro = Path("/etc/os-release").read_text(encoding="utf-8").lower()
        except OSError:
            pass
        if "ubuntu" in distro or "debian" in distro:
            hint = f"sudo apt install python{py_ver}-tk"
        elif "fedora" in distro or "rhel" in distro or "centos" in distro:
            hint = "sudo dnf install python3-tkinter"
        elif "arch" in distro:
            hint = "sudo pacman -S tk"
        else:
            hint = f"Install the python{py_ver}-tk package for your distribution"
    else:
        hint = "Reinstall Python with Tk/Tcl support enabled"

    msg = (
        "tkinter is not available in this Python installation.\n\n"
        f"To fix, run:\n  {hint}\n\n"
        f"Python: {sys.executable}\n"
        f"Version: {py_ver} ({system})"
    )
    return False, msg


def bind_macos_shortcuts(root: tk.Tk) -> None:
    """Fix Cmd+C/V/X/A/Z for non-Latin keyboard layouts on macOS.

    tkinter binds shortcuts by keysym (character), which changes with
    keyboard layout.  macOS keycodes are layout-independent (physical key),
    so we intercept Cmd+key, check the keycode, and generate the correct
    virtual event when the keysym doesn't match the expected Latin char.

    Tcl/Tk 9.0+ packs the macOS virtual keycode into the upper byte of
    event.keycode (e.g. V = 0x09000076 instead of just 9).  We handle
    both the old (raw) and new (packed) formats.

    See https://bugs.python.org/issue1794
    """
    # macOS virtual keycode -> (expected Latin keysym, virtual event)
    shortcuts = {
        0: ("a", None),  # Cmd+A -> Select All
        6: ("z", "<<Undo>>"),
        7: ("x", "<<Cut>>"),
        8: ("c", "<<Copy>>"),
        9: ("v", "<<Paste>>"),
    }

    def _extract_virtual_keycode(keycode: int) -> int:
        """Extract macOS virtual keycode from Tk event.keycode.

        Old Tk (8.x): keycode is the raw virtual keycode (0-127).
        New Tk (9.x): keycode = (virtual_keycode << 24) | char_info.
        """
        # Try raw value first (old Tk)
        if keycode in shortcuts:
            return keycode
        # Extract upper byte (new Tk 9.x format)
        return (keycode >> 24) & 0xFF

    def on_cmd_key(event: tk.Event[tk.Misc]) -> str | None:
        vk = _extract_virtual_keycode(event.keycode)
        pair = shortcuts.get(vk)
        if pair is None:
            return None
        latin, virtual = pair
        if event.keysym.lower() == latin:
            return None  # Latin layout active -- default binding handles it
        w = event.widget
        if virtual is not None:
            w.event_generate(virtual, when="tail")
        else:
            # Entry / ttk.Entry have select_range; base Misc does not,
            # so use getattr to call it dynamically.
            select_fn = getattr(w, "select_range", None)
            if select_fn is not None:
                select_fn(0, "end")
        return "break"

    root.bind_all("<Command-KeyPress>", on_cmd_key)


def run_in_thread(
    root: tk.Misc,
    task_fn: Callable[[], _T],
    on_success: Callable[[_T], None],
    on_error: Callable[[Exception], None],
) -> None:
    """Run task_fn in a daemon thread, dispatch result to main thread."""

    def _worker():
        try:
            result = task_fn()
            root.after(0, lambda r=result: on_success(r))
        except Exception as e:
            _logger.debug("Background task failed: %s", e, exc_info=True)
            root.after(0, lambda err=e: on_error(err))

    threading.Thread(target=_worker, daemon=True).start()


def reveal_file(path: str) -> None:
    """Open the file's parent folder and select it in the OS file manager."""
    p = Path(path)
    if not p.is_file():
        return
    system = platform.system()
    try:
        if system == "Darwin":
            cmd = ["open", "-R", str(p)]
        elif system == "Windows":
            cmd = ["explorer", "/select,", str(p.resolve())]
        else:
            # Linux -- best effort: open the containing directory
            cmd = ["xdg-open", str(p.parent)]
        subprocess.run(cmd, timeout=10, capture_output=True)
    except (OSError, subprocess.TimeoutExpired):
        pass  # non-critical -- silently ignore if file manager can't be launched
