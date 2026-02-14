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
        self._profile: ServerProfile | None = None

        # Window
        self._win = tk.Toplevel(parent)
        self._win.withdraw()
        self._win.title("Connect to Server")
        self._win.resizable(False, False)
        self._win.transient(parent)
        self._win.grab_set()

        outer = ttk.Frame(self._win, padding=16)
        outer.grid(sticky="nsew")

        # Title
        ttk.Label(outer, text="Choose Server", font=("", 14, "bold")).grid(
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
        ttk.Button(nav, text="Cancel", command=self._cancel).pack(side="right", padx=(8, 0))
        self._connect_btn = ttk.Button(nav, text="Connect", command=self._on_connect)
        self._connect_btn.pack(side="right")

        from . import center_on_parent

        center_on_parent(self._win, parent)

    def _build_profile_selection(self) -> None:
        """Build radio buttons for server profiles + custom URL entry."""
        tk, ttk, f = self._tk, self._ttk, self._content

        ttk.Label(f, text="Select a CoSign server:").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8)
        )
        self._profile_var = tk.StringVar(value="ekeng")

        profiles = sorted(BUILTIN_PROFILES.values(), key=lambda p: p.name)
        for i, p in enumerate(profiles, 1):
            ttk.Radiobutton(f, text=p.display_name, variable=self._profile_var, value=p.name).grid(
                row=i, column=0, columnspan=2, sticky="w", padx=8, pady=2
            )

        custom_row = len(profiles) + 1
        ttk.Radiobutton(f, text="Custom server", variable=self._profile_var, value="custom").grid(
            row=custom_row, column=0, columnspan=2, sticky="w", padx=8, pady=2
        )

        url_row = custom_row + 1
        ttk.Label(f, text="URL:").grid(row=url_row, column=0, sticky="e", padx=(16, 4), pady=4)
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
                messagebox.showwarning("Connect", "Enter a server URL.", parent=self._win)
                return
            try:
                profile = make_custom_profile(url)
            except ValueError as e:
                messagebox.showwarning("Connect", str(e), parent=self._win)
                return
        else:
            profile = BUILTIN_PROFILES.get(key)
            if profile is None:
                messagebox.showwarning("Connect", "Select a server.", parent=self._win)
                return

        self._profile = profile
        register_profile_tls_mode(profile)

        # Start ping
        self._connect_btn.configure(state="disabled")
        self._status_var.set(f"Connecting to {profile.url}...")

        run_in_thread(
            self._win,
            lambda: ping_server(profile.url, timeout=DEFAULT_TIMEOUT_HTTP_GET),
            self._on_ping_ok,
            self._on_ping_fail,
        )

    def _on_ping_ok(self, result: tuple[bool, str]) -> None:
        ok, info = result
        if ok:
            # Show TLS info
            host = urlparse(self._profile.url).hostname if self._profile else None
            tls_info = get_host_tls_info(host) if host else None
            status = f"Connected ({info})"
            if tls_info:
                status += f" | TLS: {tls_info}"
            self._status_var.set(status)

            # Save and close
            if self._profile is not None:
                save_server_config(self._profile)
            self._win.destroy()
            if self._on_complete_action is not None:
                self._on_complete_action()
        else:
            self._status_var.set(f"Failed: {info}")
            self._connect_btn.configure(state="normal")

    def _on_ping_fail(self, exc: Exception) -> None:
        self._status_var.set(f"Error: {exc}")
        self._connect_btn.configure(state="normal")

    def _cancel(self) -> None:
        self._win.destroy()
