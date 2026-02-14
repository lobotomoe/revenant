"""Revenant GUI -- tkinter-based graphical interface."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tkinter as tk

from .app import main

__all__ = ["main"]


def center_on_screen(window: tk.Tk | tk.Toplevel) -> None:
    """Center a window on screen and reveal it.

    Call ``window.withdraw()`` before building the UI, then call this
    function once layout is ready.  It positions the window and calls
    ``deiconify()`` so the user never sees the initial top-left flash.
    """
    window.update_idletasks()
    w = window.winfo_width()
    h = window.winfo_height()
    x = (window.winfo_screenwidth() - w) // 2
    y = (window.winfo_screenheight() - h) // 2
    window.geometry(f"+{x}+{y}")
    window.deiconify()


def center_on_parent(window: tk.Toplevel, parent: tk.Tk | tk.Toplevel) -> None:
    """Center a child window over its parent and reveal it.

    Call ``window.withdraw()`` before building the UI, then call this
    function once layout is ready.  It positions the window and calls
    ``deiconify()`` so the user never sees the initial top-left flash.
    """
    window.update_idletasks()
    pw = parent.winfo_width()
    ph = parent.winfo_height()
    px = parent.winfo_x()
    py = parent.winfo_y()
    w = window.winfo_reqwidth()
    h = window.winfo_reqheight()
    x = px + (pw - w) // 2
    y = py + (ph - h) // 2
    window.geometry(f"+{x}+{y}")
    window.deiconify()
