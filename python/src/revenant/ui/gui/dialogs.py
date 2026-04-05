# SPDX-License-Identifier: Apache-2.0
"""Modal dialogs -- About information and credential entry."""

from __future__ import annotations

import webbrowser
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tkinter as tk

from ...constants import __version__
from .i18n import _
from .utils import link_color

# Project URLs
_REPO_URL = "https://github.com/lobotomoe/revenant"
_ISSUES_URL = "https://github.com/lobotomoe/revenant/issues"
_TELEGRAM_URL = "https://t.me/m_surf"


def about_footer(parent: tk.Widget, root: tk.Tk, row: int) -> None:
    """Add 'Settings' and 'About' links at the bottom of a frame."""
    from tkinter import ttk

    footer = ttk.Frame(parent)
    footer.grid(row=row, column=0, columnspan=3, pady=(8, 0))

    settings_link = ttk.Label(footer, text=_("Settings"), foreground="gray", cursor="hand2")
    settings_link.pack(side="left", padx=(0, 12))
    settings_link.bind("<Button-1>", lambda _e: show_settings(root))

    about_link = ttk.Label(footer, text=_("About Revenant"), foreground="gray", cursor="hand2")
    about_link.pack(side="left")
    about_link.bind("<Button-1>", lambda _e: show_about(root))


def show_settings(root: tk.Tk) -> None:
    """Show a Settings dialog with language selector."""
    import tkinter as tk
    from tkinter import ttk

    from ...config import get_language, save_language
    from .i18n import SUPPORTED_LOCALES, SYSTEM_LOCALE

    dlg = tk.Toplevel(root)
    dlg.withdraw()
    dlg.title(_("Settings"))
    dlg.resizable(False, False)
    dlg.transient(root)
    dlg.grab_set()

    frame = ttk.Frame(dlg, padding=24)
    frame.grid(sticky="nsew")

    # Language selector
    lang_options = [_("System"), *SUPPORTED_LOCALES.values()]
    lang_keys = [SYSTEM_LOCALE, *SUPPORTED_LOCALES]

    current = get_language()
    try:
        current_idx = lang_keys.index(current)
    except ValueError:
        current_idx = 0

    lang_var = tk.StringVar(value=lang_options[current_idx])

    ttk.Label(frame, text=_("Language:")).grid(row=0, column=0, sticky="e", padx=(0, 8), pady=4)
    lang_combo = ttk.Combobox(
        frame, textvariable=lang_var, values=lang_options, state="readonly", width=18
    )
    lang_combo.grid(row=0, column=1, sticky="w", pady=4)

    restart_label = ttk.Label(frame, text="", foreground="gray", font=("", 9))
    restart_label.grid(row=1, column=0, columnspan=2, pady=(4, 0))

    def _on_lang_change(_event: object) -> None:
        selected = lang_var.get()
        idx = lang_options.index(selected)
        key = lang_keys[idx]
        save_language(key)
        restart_label.configure(text=_("Restart the app to apply the new language."))

    lang_combo.bind("<<ComboboxSelected>>", _on_lang_change)

    ttk.Button(frame, text=_("OK"), command=dlg.destroy).grid(
        row=2, column=0, columnspan=2, pady=(12, 0)
    )

    from . import center_on_parent

    center_on_parent(dlg, root)


def show_about(root: tk.Tk) -> None:
    """Show an About dialog with version, author, and project links."""
    import tkinter as tk
    from tkinter import ttk

    dlg = tk.Toplevel(root)
    dlg.withdraw()
    dlg.title(_("About Revenant"))
    dlg.resizable(False, False)
    dlg.transient(root)
    dlg.grab_set()

    frame = ttk.Frame(dlg, padding=24)
    frame.grid(sticky="nsew")

    ttk.Label(frame, text="Revenant", font=("", 16, "bold")).grid(row=0, column=0, pady=(0, 4))
    ttk.Label(frame, text=_("Version {version}").format(version=__version__)).grid(
        row=1, column=0, pady=(0, 12)
    )

    ttk.Label(
        frame,
        text=_("Cross-platform client for ARX CoSign\nelectronic signatures."),
        justify="center",
    ).grid(row=2, column=0, pady=(0, 12))

    ttk.Label(frame, text=_("Author: Aleksandr Kraiz"), foreground="gray").grid(
        row=3, column=0, pady=(0, 4)
    )
    ttk.Label(frame, text=_("License: Apache 2.0"), foreground="gray").grid(
        row=4, column=0, pady=(0, 12)
    )

    links = ttk.Frame(frame)
    links.grid(row=5, column=0, pady=(0, 12))

    link_fg = link_color(links)

    repo_link = ttk.Label(links, text=_("GitHub"), foreground=link_fg, cursor="hand2")
    repo_link.grid(row=0, column=0, padx=8)
    repo_link.bind("<Button-1>", lambda _e: webbrowser.open(_REPO_URL))

    issues_link = ttk.Label(links, text=_("Report a Bug"), foreground=link_fg, cursor="hand2")
    issues_link.grid(row=0, column=1, padx=8)
    issues_link.bind("<Button-1>", lambda _e: webbrowser.open(_ISSUES_URL))

    tg_link = ttk.Label(links, text=_("Telegram"), foreground=link_fg, cursor="hand2")
    tg_link.grid(row=0, column=2, padx=8)
    tg_link.bind("<Button-1>", lambda _e: webbrowser.open(_TELEGRAM_URL))

    ttk.Button(frame, text=_("OK"), command=dlg.destroy).grid(row=6, column=0, pady=(0, 0))

    from . import center_on_parent

    center_on_parent(dlg, root)


def login_dialog(root: tk.Tk) -> tuple[str, str] | None:
    """Show a login dialog that collects and saves credentials.

    Caches credentials in the session and optionally persists them
    (keyring or config file) if the user checks "Save credentials".

    Returns:
        (username, password) on success, or None if cancelled.
    """
    import tkinter as tk
    from tkinter import ttk

    from ...config import save_credentials, set_session_credentials
    from ...config._storage import load_config

    dlg = tk.Toplevel(root)
    dlg.withdraw()
    dlg.title(_("Login"))
    dlg.resizable(False, False)
    dlg.transient(root)
    dlg.grab_set()

    frame = ttk.Frame(dlg, padding=16)
    frame.grid(sticky="nsew")

    saved_username = load_config().get("username", "")
    user_var = tk.StringVar(value=saved_username)
    pass_var = tk.StringVar()
    save_var = tk.BooleanVar(value=False)
    result: list[tuple[str, str] | None] = [None]

    ttk.Label(frame, text=_("Username:")).grid(row=0, column=0, sticky="e", padx=(0, 8), pady=4)
    user_entry = ttk.Entry(frame, textvariable=user_var, width=30)
    user_entry.grid(row=0, column=1, sticky="w", pady=4)

    ttk.Label(frame, text=_("Password:")).grid(row=1, column=0, sticky="e", padx=(0, 8), pady=4)
    pass_entry = ttk.Entry(frame, textvariable=pass_var, width=30, show="\u2022")
    pass_entry.grid(row=1, column=1, sticky="w", pady=4)

    # Focus password field if username is pre-filled
    if saved_username:
        pass_entry.focus_set()

    ttk.Checkbutton(frame, text=_("Save credentials"), variable=save_var).grid(
        row=2, column=0, columnspan=2, sticky="w", pady=(8, 0)
    )

    def on_ok() -> None:
        u = user_var.get().strip()
        p = pass_var.get().strip()
        if not u or not p:
            return
        set_session_credentials(u, p)
        if save_var.get():
            save_credentials(u, p)
        result[0] = (u, p)
        dlg.destroy()

    btns = ttk.Frame(frame)
    btns.grid(row=3, column=0, columnspan=2, pady=(12, 0))
    ttk.Button(btns, text=_("Cancel"), command=dlg.destroy).pack(side="left", padx=(0, 8))
    ttk.Button(btns, text=_("OK"), command=on_ok, style="Accent.TButton").pack(side="left")

    from . import center_on_parent

    center_on_parent(dlg, root)
    dlg.wait_window()
    return result[0]
