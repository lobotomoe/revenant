# SPDX-License-Identifier: Apache-2.0
"""Server connection dialog for the Revenant GUI.

ConnectDialog: server selection and connection test (Layer 0 -> 1).
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ...config import (
    BUILTIN_PROFILES,
    ServerProfile,
    get_active_profile,
    make_custom_profile,
    register_profile_tls_mode,
    save_server_config,
)
from ...constants import DEFAULT_TIMEOUT_HTTP_GET
from ...network.discovery import ping_server
from ...network.transport import get_host_tls_info
from .i18n import _
from .utils import run_in_thread

if TYPE_CHECKING:
    import tkinter as tk
    from collections.abc import Callable


class ConnectDialog:
    """Single-screen modal dialog for server selection and connection test."""

    def __init__(
        self, parent: tk.Tk | tk.Toplevel, on_complete_action: Callable[[], None] | None = None
    ) -> None:
        import tkinter as tk
        from tkinter import ttk

        self._tk = tk
        self._ttk = ttk
        self._on_complete_action = on_complete_action
        # Identifies the ping currently being awaited. Cleared on cancel and on
        # completion, so a result that arrives afterwards is recognisably stale
        # and can be dropped instead of acted on (GHSA-285g).
        self._ping_token: object | None = None

        # Window
        self._win = tk.Toplevel(parent)
        self._win.withdraw()
        self._win.title(_("gui.connect_to_server"))
        self._win.resizable(False, False)
        self._win.transient(parent)
        self._win.grab_set()

        outer = ttk.Frame(self._win, padding=16)
        outer.grid(sticky="nsew")

        # Title
        ttk.Label(outer, text=_("gui.choose_server"), font=("", 14, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8)
        )

        # Profile selection
        self._content = ttk.Frame(outer)
        self._content.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=8)
        self._build_profile_selection()

        # Status area (for ping results)
        self._status_var = tk.StringVar()
        self._status_label = ttk.Label(
            outer, textvariable=self._status_var, foreground="gray", wraplength=380
        )
        self._status_label.grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        # Buttons
        nav = ttk.Frame(outer)
        nav.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        ttk.Button(nav, text=_("gui.cancel"), command=self._cancel).pack(side="right", padx=(8, 0))
        self._connect_btn = ttk.Button(nav, text=_("gui.connect"), command=self._on_connect)
        self._connect_btn.pack(side="right")

        # The title-bar close button destroys the window directly, which would
        # skip _cancel and leave a ping still owning the dialog.
        self._win.protocol("WM_DELETE_WINDOW", self._cancel)

        from . import center_on_parent

        center_on_parent(self._win, parent)

    def _build_profile_selection(self) -> None:
        """Build radio buttons for server profiles + custom URL entry."""
        tk, ttk, f = self._tk, self._ttk, self._content

        ttk.Label(f, text=_("gui.select_a_cosign_server_label")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8)
        )
        self._profile_var = tk.StringVar(value="ekeng")

        profiles = sorted(BUILTIN_PROFILES.values(), key=lambda p: p.name)
        for i, p in enumerate(profiles, 1):
            ttk.Radiobutton(f, text=p.display_name, variable=self._profile_var, value=p.name).grid(
                row=i, column=0, columnspan=2, sticky="w", padx=8, pady=2
            )

        custom_row = len(profiles) + 1
        ttk.Radiobutton(
            f, text=_("gui.custom_server"), variable=self._profile_var, value="custom"
        ).grid(row=custom_row, column=0, columnspan=2, sticky="w", padx=8, pady=2)

        url_row = custom_row + 1
        ttk.Label(f, text=_("gui.url_label_upper")).grid(
            row=url_row, column=0, sticky="e", padx=(16, 4), pady=4
        )
        self._custom_url_var = tk.StringVar()
        self._custom_url_entry = ttk.Entry(f, textvariable=self._custom_url_var, width=40)
        self._custom_url_entry.grid(row=url_row, column=1, sticky="w", pady=4)

        def _on_profile_change(*_args: object) -> None:
            is_custom = self._profile_var.get() == "custom"
            self._custom_url_entry.configure(state="normal" if is_custom else "disabled")

        self._profile_var.trace_add("write", _on_profile_change)
        _on_profile_change()

        # Pre-fill from current config
        current = get_active_profile()
        if current is not None:
            if current.name in BUILTIN_PROFILES:
                self._profile_var.set(current.name)
            else:
                self._profile_var.set("custom")
                self._custom_url_var.set(current.url)

    def _on_connect(self) -> None:
        """Validate selection and start connection test."""
        from tkinter import messagebox

        key = self._profile_var.get()
        if key == "custom":
            url = self._custom_url_var.get().strip()
            if not url:
                messagebox.showwarning(
                    _("gui.connect"), _("gui.enter_a_server_url"), parent=self._win
                )
                return
            try:
                profile = make_custom_profile(url)
            except ValueError as e:
                messagebox.showwarning(_("gui.connect"), str(e), parent=self._win)
                return
        else:
            profile = BUILTIN_PROFILES.get(key)
            if profile is None:
                messagebox.showwarning(_("gui.connect"), _("gui.select_a_server"), parent=self._win)
                return

        register_profile_tls_mode(profile)

        # Start ping. The token and the profile travel with the callbacks rather
        # than through the dialog, so a result can never be matched against one
        # attempt and applied to another.
        token = object()
        self._ping_token = token
        self._connect_btn.configure(state="disabled")
        self._status_var.set(_("gui.connecting_to_url_ellipsis").format(url=profile.url))

        run_in_thread(
            self._win,
            lambda: ping_server(profile.url, timeout=DEFAULT_TIMEOUT_HTTP_GET),
            lambda result: self._on_ping_ok(token, profile, result),
            lambda exc: self._on_ping_fail(token, exc),
        )

    def _awaiting(self, token: object) -> bool:
        """Whether `token` is still the ping this dialog is waiting for.

        Destroying the window does not cancel work already scheduled with
        ``after()``, so a cancelled dialog's callbacks still run and would
        otherwise persist a server the user declined.
        """
        if token is not self._ping_token:
            return False
        self._ping_token = None
        return True

    def _on_ping_ok(self, token: object, profile: ServerProfile, result: tuple[bool, str]) -> None:
        if not self._awaiting(token):
            return
        ok, info = result
        if ok:
            # Show TLS info
            host = urlparse(profile.url).hostname
            tls_info = get_host_tls_info(host) if host else None
            status = _("gui.connected_info").format(info=info)
            if tls_info:
                status += f" | TLS: {tls_info}"
            self._status_var.set(status)

            # Save and close
            save_server_config(profile)
            self._win.destroy()
            if self._on_complete_action is not None:
                self._on_complete_action()
        else:
            self._status_var.set(_("gui.failed_info").format(info=info))
            self._connect_btn.configure(state="normal")

    def _on_ping_fail(self, token: object, exc: Exception) -> None:
        if not self._awaiting(token):
            return
        self._status_var.set(_("gui.error_error").format(error=exc))
        self._connect_btn.configure(state="normal")

    def _cancel(self) -> None:
        # Abandon any ping in flight: dismissing the dialog is a decision not to
        # use that server, and a late success must not persist it anyway.
        self._ping_token = None
        self._win.destroy()
