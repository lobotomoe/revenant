# SPDX-License-Identifier: Apache-2.0
# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false
"""Platform-specific UI helpers (macOS menu bar, Windows icon)."""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tkinter as tk

from .i18n import _

_logger = logging.getLogger(__name__)


def set_windows_icon(root: tk.Tk) -> None:
    """Set the window icon on Windows from the bundled .ico file.

    Nuitka embeds the icon in the PE header (for Explorer/taskbar),
    but tkinter needs a separate .ico file for the window title bar.
    """
    import tkinter as tk
    from pathlib import Path

    # Bundled .ico next to the executable (Nuitka --include-data-files)
    ico = Path(sys.executable).parent / "icons" / "revenant.ico"
    if ico.exists():
        try:
            root.iconbitmap(default=str(ico))
        except tk.TclError:
            _logger.debug("Failed to set icon from bundled .ico")
        else:
            return

    # Fallback: try extracting from the PE header
    try:
        root.iconbitmap(default=sys.executable)
    except (tk.TclError, Exception):
        _logger.debug("Failed to set icon from PE header")


def build_macos_menubar(root: tk.Tk) -> None:
    """Build standard macOS menu bar (File, Edit) and Cmd+W binding."""
    import tkinter as tk

    def _send_virtual_event(event_name: str) -> None:
        widget = root.focus_get()
        if widget is not None:
            widget.event_generate(event_name)

    def _select_all() -> None:
        widget = root.focus_get()
        if widget is None:
            return
        select_fn = getattr(widget, "select_range", None)
        tag_add_fn = getattr(widget, "tag_add", None)
        if select_fn is not None:
            select_fn(0, "end")
        elif tag_add_fn is not None:
            tag_add_fn("sel", "1.0", "end")

    menubar = tk.Menu(root)

    # -- File --
    file_menu = tk.Menu(menubar, tearoff=0)
    file_menu.add_command(label=_("gui.close_window"), accelerator="Cmd+W", command=root.destroy)
    menubar.add_cascade(label=_("gui.file"), menu=file_menu)

    # -- Edit --
    edit_menu = tk.Menu(menubar, tearoff=0)
    edit_menu.add_command(
        label=_("gui.undo"),
        accelerator="Cmd+Z",
        command=lambda: _send_virtual_event("<<Undo>>"),
    )
    edit_menu.add_separator()
    edit_menu.add_command(
        label=_("gui.cut"),
        accelerator="Cmd+X",
        command=lambda: _send_virtual_event("<<Cut>>"),
    )
    edit_menu.add_command(
        label=_("gui.copy"),
        accelerator="Cmd+C",
        command=lambda: _send_virtual_event("<<Copy>>"),
    )
    edit_menu.add_command(
        label=_("gui.paste"),
        accelerator="Cmd+V",
        command=lambda: _send_virtual_event("<<Paste>>"),
    )
    edit_menu.add_separator()
    edit_menu.add_command(label=_("gui.select_all"), accelerator="Cmd+A", command=_select_all)
    menubar.add_cascade(label=_("gui.edit"), menu=edit_menu)

    root.config(menu=menubar)

    # Cmd+W: close the focused window (main or dialog)
    def _on_close_window(event: tk.Event[tk.Misc]) -> str:
        event.widget.winfo_toplevel().destroy()
        return "break"

    root.bind_all("<Command-w>", _on_close_window)
