# SPDX-License-Identifier: Apache-2.0
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
"""Sign tab placeholder panels and account info widget.

Extracted from sign_form.py to keep it under 400 lines.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tkinter as tk
    from collections.abc import Callable

from ...config import get_active_profile, get_credential_storage_info
from ...core.appearance import extract_cert_fields
from .i18n import _


def build_unconfigured(parent: tk.Widget, on_connect_action: Callable[[], None]) -> None:
    """Build the Sign tab for unconfigured state (Layer 0: connect prompt)."""
    from tkinter import ttk

    frame = ttk.Frame(parent, padding=40)
    frame.pack(fill="both", expand=True)
    frame.columnconfigure(0, weight=1)

    ttk.Label(
        frame,
        text=_("gui.connect_to_a_server_to_sign_documents"),
        justify="center",
        foreground="gray",
    ).grid(row=0, column=0, pady=(0, 20))
    ttk.Button(
        frame, text=_("gui.connect"), command=on_connect_action, style="Accent.TButton"
    ).grid(row=1, column=0, ipady=4, ipadx=16)


def build_server_only(parent: tk.Widget, on_login_action: Callable[[], None]) -> None:
    """Build the Sign tab for server-configured state (Layer 1: login prompt)."""
    from tkinter import ttk

    frame = ttk.Frame(parent, padding=40)
    frame.pack(fill="both", expand=True)
    frame.columnconfigure(0, weight=1)

    ttk.Label(
        frame,
        text=_("gui.server_connected_log_in_to_sign_documents"),
        justify="center",
        foreground="gray",
    ).grid(row=0, column=0, pady=(0, 20))
    ttk.Button(frame, text=_("gui.log_in"), command=on_login_action, style="Accent.TButton").grid(
        row=1, column=0, ipady=4, ipadx=16
    )


def build_account_panel(
    parent: tk.Widget,
    signer_info: dict[str, str | None],
    on_logout_action: Callable[[], None],
) -> tk.StringVar:
    """Build the Account info panel (right column of sign form).

    Returns:
        StringVar for credential storage label (for refresh_credential_status).
    """
    import tkinter as tk
    from tkinter import ttk

    profile = get_active_profile()
    info_row = 0

    if profile and profile.cert_fields:
        extracted = extract_cert_fields(profile.cert_fields, signer_info)
        for cf in profile.cert_fields:
            value = extracted.get(cf.id)
            if value:
                ttk.Label(parent, text=f"{cf.label}:", foreground="gray").grid(
                    row=info_row, column=0, sticky="e", padx=(0, 4), pady=1
                )
                ttk.Label(parent, text=value).grid(row=info_row, column=1, sticky="w", pady=1)
                info_row += 1
    else:
        for key, label in [
            ("name", _("gui.name")),
            ("organization", _("gui.org")),
            ("email", _("gui.email")),
        ]:
            val = signer_info.get(key)
            if val:
                ttk.Label(parent, text=f"{label}:", foreground="gray").grid(
                    row=info_row, column=0, sticky="e", padx=(0, 4), pady=1
                )
                ttk.Label(parent, text=val).grid(row=info_row, column=1, sticky="w", pady=1)
                info_row += 1

    if info_row == 0:
        ttk.Label(parent, text=_("gui.no_signer"), foreground="gray").grid(
            row=info_row, column=0, columnspan=2, sticky="w", pady=1
        )
        info_row += 1

    storage_var = tk.StringVar(value=get_credential_storage_info())
    ttk.Label(parent, textvariable=storage_var, foreground="gray").grid(
        row=info_row, column=0, columnspan=2, sticky="w", pady=1
    )

    ttk.Button(parent, text=_("gui.log_out"), command=on_logout_action).grid(
        row=info_row + 1, column=0, columnspan=2, sticky="w", pady=(6, 0)
    )

    return storage_var
